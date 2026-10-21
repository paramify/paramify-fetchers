"""Resource Graph paging for the Azure fetchers that enumerate a whole subscription."""

from __future__ import annotations

from typing import Any, Dict

from azure_common import arm_client_kwargs, model_attr

# The largest page Resource Graph serves; `$top` above it is rejected.
PAGE_SIZE = 1000

# A guard, not a cap: reaching it means the service kept handing back skip tokens.
MAX_PAGES = 1000

# Pass as query_all's subscription_id to read every subscription the credential can see.
ALL_SUBSCRIPTIONS = object()


def resource_graph_client(cred):
    from azure.mgmt.resourcegraph import ResourceGraphClient  # lazy

    # Tenant-scoped client: the subscription goes in each request, not the client.
    return ResourceGraphClient(credential=cred, **arm_client_kwargs())


def query_all(client, subscription_id, query: str) -> Dict[str, Any]:
    """Page `query` to the end; raise on truncation, non-termination or a short count.

    `query` must project `id` and order by it, or skip-token paging is unstable.
    `subscription_id` is one subscription, or ALL_SUBSCRIPTIONS.
    """
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions  # lazy

    rows: list[dict] = []
    total_records = None
    skip_token = None
    pages = 0
    seen_tokens = set()
    while True:
        response = client.resources(
            QueryRequest(
                subscriptions=None if subscription_id is ALL_SUBSCRIPTIONS else [subscription_id],
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
