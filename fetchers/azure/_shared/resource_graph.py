"""Resource Graph paging for the Azure fetchers that enumerate a whole subscription."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from azure_common import Collector, arm_client_kwargs, model_attr

# The largest page Resource Graph serves; `$top` above it is rejected.
PAGE_SIZE = 1000

# A guard, not a cap: reaching it means the service kept handing back skip tokens.
MAX_PAGES = 1000


def resource_graph_client(cred):
    from azure.mgmt.resourcegraph import ResourceGraphClient  # lazy

    # Tenant-scoped client: the subscription goes in each request, not the client.
    return ResourceGraphClient(credential=cred, **arm_client_kwargs())


def query_all(client, subscription_id: Union[str, List[str], None], query: str) -> Dict[str, Any]:
    """Page `query` to the end; raise on truncation, non-termination or a short count.

    `query` must project `id` and order by it, or skip-token paging is unstable.
    `subscription_id` is one subscription, a list, or None to leave the request unscoped,
    which reads every subscription the credential can see (how a lookup resolves resources
    outside the target subscription).
    """
    from azure.mgmt.resourcegraph.models import (  # lazy
        QueryRequest,
        QueryRequestOptions,
    )

    if subscription_id is None:
        subscriptions = None
    elif isinstance(subscription_id, str):
        subscriptions = [subscription_id]
    else:
        subscriptions = list(subscription_id)
    rows: list[dict] = []
    total_records = None
    skip_token = None
    pages = 0
    seen_tokens = set()
    while True:
        response = client.resources(
            QueryRequest(
                subscriptions=subscriptions,
                query=query,
                options=QueryRequestOptions(
                    top=PAGE_SIZE, skip_token=skip_token, result_format="objectArray"
                ),
            )
        )
        pages += 1
        total_records = model_attr(response, "total_records")
        if str(model_attr(response, "result_truncated") or "").lower() == "true":
            raise RuntimeError("Resource Graph reported the result as truncated")
        rows.extend(model_attr(response, "data") or [])
        skip_token = model_attr(response, "skip_token")
        if not skip_token:
            break
        if skip_token in seen_tokens or pages >= MAX_PAGES:
            raise RuntimeError(f"Resource Graph paging did not terminate after {pages} page(s)")
        seen_tokens.add(skip_token)
    if total_records is not None and len(rows) != total_records:
        raise RuntimeError(
            f"Resource Graph reported {total_records} rows but paging returned {len(rows)}"
        )
    return {"rows": rows, "total_records": total_records, "pages": pages}


def quoted_ids(ids: List[str]) -> str:
    """KQL verbatim string literals: inside @'...' a doubled quote is the escape and a backslash is literal."""
    return ", ".join("@'" + i.replace("'", "''") + "'" for i in ids)


READABLE_RESOURCE_GROUPS_QUERY = (
    "ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' "
    "| project id = tolower(id) | order by id asc"
)


def readable_scopes(cred, collector: Collector) -> Optional[Dict[str, set]]:
    """The subscriptions and resource groups the credential can read; None when either listing failed.

    Both are needed to call a missing resource deleted: Reader on one resource group of
    another subscription still lists that subscription, and a resource in one of its
    other groups is unreadable, not gone.
    """

    def _subscriptions() -> set:
        from azure.mgmt.subscription import SubscriptionClient  # lazy

        client = SubscriptionClient(cred, **arm_client_kwargs())
        return {
            (model_attr(sub, "subscription_id") or "").lower()
            for sub in client.subscriptions.list()
        }

    subscriptions = collector.guard("subscription.subscriptions.list", _subscriptions)
    groups = collector.guard(
        "resourcegraph.resources (readable resource groups)",
        lambda: {
            r.get("id")
            for r in query_all(resource_graph_client(cred), None, READABLE_RESOURCE_GROUPS_QUERY)["rows"]
        },
    )
    if subscriptions is None or groups is None:
        return None
    return {"subscriptions": subscriptions, "resource_groups": groups}
