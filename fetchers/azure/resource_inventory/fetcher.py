#!/usr/bin/env python3
"""Azure resource inventory for one subscription, from Azure Resource Graph.

One query over the `Resources` table instead of one list call per service, so the
inventory covers every resource type ARM knows about — including the ones no other
fetcher in this category reads. Resource Graph pages at most 1000 rows; the fetcher
follows `$skipToken` to the end and treats a truncated or short result as a
collection failure, never as a smaller inventory.

Resource Graph is eventually consistent with ARM (typically seconds, occasionally
minutes), and returns only what the caller can read, so a Reader gap reads as a
missing resource rather than an error.
"""

import logging
import os
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    arm_client_kwargs,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    model_attr,
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_resource_inventory")

# The largest page Resource Graph serves; `$top` above it is rejected.
PAGE_SIZE = 1000

# `order by id` keeps paging stable across skip tokens. The provisioning state lives
# in each type's own `properties` bag, so it is lifted out as a string.
INVENTORY_QUERY = (
    "Resources"
    " | project id, name, type, location, resourceGroup, tags, sku, kind,"
    " provisioningState = tostring(properties.provisioningState)"
    " | order by id asc"
)

# A guard, not a cap: 1000 pages is a million resources. Reaching it means the service
# kept handing back skip tokens, which is recorded as a failure.
MAX_PAGES = 1000


# --- pure transforms (Resource Graph rows are plain dicts already) ---

def resource_record(row: dict) -> dict:
    """Normalize one Resource Graph row into an evidence record.

    Resource Graph returns `type` and `resourceGroup` LOWERCASED and `kind` as "" on
    types without one; the empty string is read as absent so a validator does not have
    to match both. `tags` is null on an untagged resource and is emitted as {}.
    """
    tags, sku = row.get("tags"), row.get("sku")
    return {
        "id": row.get("id"),
        "name": row.get("name"),
        "type": row.get("type"),
        "location": row.get("location") or None,
        "resource_group": row.get("resourceGroup") or None,
        "tags": tags if isinstance(tags, dict) else {},
        "sku": sku if isinstance(sku, dict) and sku else None,
        "kind": row.get("kind") or None,
        "provisioning_state": row.get("provisioningState") or None,
    }


def _sorted_counts(counter: Counter) -> dict:
    return {key: counter[key] for key in sorted(counter)}


def summarize(resources: list[dict]) -> dict:
    """Total, by type, by location, and how many carry no tags."""
    by_type = Counter(r["type"] or "unknown" for r in resources)
    # Global resources (DNS zones, Front Door, some identity types) report "global".
    by_location = Counter(r["location"] or "unknown" for r in resources)
    untagged = sum(1 for r in resources if not r["tags"])
    return {
        "total_resources": len(resources),
        "resource_type_count": len(by_type),
        "resources_by_type": _sorted_counts(by_type),
        "location_count": len(by_location),
        "resources_by_location": _sorted_counts(by_location),
        "resource_group_count": len({r["resource_group"] for r in resources if r["resource_group"]}),
        "untagged_resources": untagged,
        "tagged_resources": len(resources) - untagged,
    }


# --- collection (lazy azure imports) ---

def collect_resources(subscription_id, cred, collector: Collector) -> dict:
    """Page the inventory query to the end.

    Returns the records plus Resource Graph's own `total_records`, so the evidence
    shows the count the service reported alongside the count collected.
    """

    def _client():
        from azure.mgmt.resourcegraph import ResourceGraphClient  # lazy

        # Tenant-scoped client: the subscription goes in each request, not the client.
        return ResourceGraphClient(credential=cred, **arm_client_kwargs())

    client = collector.guard("resourcegraph.ResourceGraphClient (init)", _client)
    if client is None:
        return {"resources": [], "total_records": None, "pages": 0}

    def _page_all() -> dict:
        from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions  # lazy

        rows: list[dict] = []
        total_records = None
        skip_token = None
        pages = 0
        seen_tokens = set()
        while True:
            response = client.resources(
                QueryRequest(
                    subscriptions=[subscription_id],
                    query=INVENTORY_QUERY,
                    options=QueryRequestOptions(
                        top=PAGE_SIZE, skip_token=skip_token, result_format="objectArray"
                    ),
                )
            )
            pages += 1
            total_records = model_attr(response, "total_records")
            # "true" only when the projection lacks `id`, which would make paging
            # impossible; this query projects it, so a truncation is a real failure.
            if str(model_attr(response, "result_truncated") or "").lower() == "true":
                raise RuntimeError(
                    "Resource Graph reported the inventory result as truncated"
                )
            rows.extend(model_attr(response, "data") or [])
            skip_token = model_attr(response, "skip_token")
            if not skip_token:
                break
            if skip_token in seen_tokens or pages >= MAX_PAGES:
                raise RuntimeError(
                    f"Resource Graph paging did not terminate after {pages} page(s)"
                )
            seen_tokens.add(skip_token)
        if total_records is not None and len(rows) != total_records:
            raise RuntimeError(
                f"Resource Graph reported {total_records} resources but paging returned "
                f"{len(rows)}"
            )
        return {"rows": rows, "total_records": total_records, "pages": pages}

    result = collector.guard("resourcegraph.resources (Resources)", _page_all)
    if result is None:
        return {"resources": [], "total_records": None, "pages": 0}
    resources = sorted(
        (resource_record(row) for row in result["rows"]), key=lambda r: r.get("id") or ""
    )
    return {
        "resources": resources,
        "total_records": result["total_records"],
        "pages": result["pages"],
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request header at INFO; warnings still get through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    collected = {"resources": [], "total_records": None, "pages": 0}
    if subscription_id and cred is not None:
        collected = collect_resources(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    resources = collected["resources"]
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "resources": resources,
            "inventory_source": "azure_resource_graph",
            "query": INVENTORY_QUERY,
            "pages_read": collected["pages"],
            "total_records_reported": collected["total_records"],
        },
        summary=summarize(resources),
    )

    filename = (
        f"azure_resource_inventory_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s (%d resources)", path, len(resources))
    return 0


if __name__ == "__main__":
    sys.exit(main())
