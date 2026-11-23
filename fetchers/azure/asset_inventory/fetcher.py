#!/usr/bin/env python3
"""Azure asset inventory for one subscription: every Resource Graph resource, one record each, for a Paramify
inventory pipeline.

This is the pipeline twin of azure_resource_inventory. It runs the same `Resources` query and the same row
projection, loaded from that fetcher (sibling_fetchers), and leaves out its Defender and Policy coverage. Paging
is _shared/resource_graph.query_all, which reads every page and raises on a truncated or short result.

unique_asset_identifier is the Azure resource id in lowercase (azure_common.arm_id_key). Azure resource ids are
case-insensitive, and Defender for Cloud, ARM and Resource Graph do not always agree on the casing, so
azure_defender_vulnerability_report puts the same lowercase id in its `Asset ID` column. The two match exactly.

THE ONE RULE: all or nothing. A failed call, a row without an id or two rows with one id withholds every record
(`data: []`, `records_included: false`) and exits non-zero.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
import sibling_fetchers  # noqa: E402
from azure_common import (  # noqa: E402
    Collector,
    arm_id_key,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    report_failure,
    resolve_subscription,
    sanitize_for_filename,
    subscription_of,
    write_evidence,
)
from resource_exclusions import ResourceExclusions  # noqa: E402
from resource_graph import query_all, resource_graph_client  # noqa: E402

NAME = "azure_asset_inventory"
logger = logging.getLogger(NAME)

_twin = sibling_fetchers.load("resource_inventory")
INVENTORY_QUERY = _twin.INVENTORY_QUERY

# Resource Graph always returns a type; this only keeps asset_type non-empty if a row ever comes back without one.
DEFAULT_ASSET_TYPE = "azure_resource"


class Incomplete(Exception):
    """The rows cannot stand for the whole subscription."""


def record(row: Dict[str, Any]) -> Dict[str, Any]:
    """One inventory record. Every record has the same keys, with None for a missing value."""
    resource = _twin.resource_record(row)
    resource_id = resource["id"]
    if not resource_id:
        raise Incomplete(f"Resource Graph returned a resource without an id (name {resource['name']!r})")
    sku = resource["sku"] or {}
    return {
        "unique_asset_identifier": arm_id_key(resource_id),
        "asset_type": resource["type"] or DEFAULT_ASSET_TYPE,
        "resource_id": resource_id,
        "name": resource["name"],
        "location": resource["location"],
        "resource_group": resource["resource_group"],
        "subscription_id": subscription_of(resource_id),
        "kind": resource["kind"],
        "sku_name": sku.get("name"),
        "sku_tier": sku.get("tier"),
        "provisioning_state": resource["provisioning_state"],
        "tags": resource["tags"],
    }


def records_from(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every row as a record, sorted by unique_asset_identifier. Raises Incomplete on a gap or a repeated id."""
    records = [record(row) for row in rows]
    ids = [r["unique_asset_identifier"] for r in records]
    repeated = len(ids) - len(set(ids))
    if repeated:
        raise Incomplete(f"{repeated} resource id(s) came back more than once (compared in lowercase)")
    return sorted(records, key=lambda r: r["unique_asset_identifier"])


def collect(subscription_id: str, cred, collector: Collector) -> Dict[str, Any] | None:
    """Every page of the Resources query as records; None when collection failed (the failure is recorded)."""
    client = collector.guard("resourcegraph.ResourceGraphClient (init)", lambda: resource_graph_client(cred))
    if client is None:
        return None
    result = collector.guard(
        "resourcegraph.resources (Resources)", lambda: query_all(client, subscription_id, INVENTORY_QUERY)
    )
    if result is None:
        return None
    try:
        records = records_from(result["rows"])
    except Incomplete as exc:
        collector.record("inventory records", exc)
        return None
    return {"records": records, "pages": result["pages"], "total_records": result["total_records"]}


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
    exclusions = ResourceExclusions.from_env()
    exclusions.record_invalid(collector)

    collected = None
    if not subscription_id:
        collector.record("resolve_subscription", RuntimeError(
            "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
            "ambient Azure credential that can list subscriptions)"))
    elif cred is not None and collector.ok:
        collected = collect(subscription_id, cred, collector)

    records: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []
    if collected is None:
        exclusions.mark_unread()
    else:
        records, excluded = exclusions.split(collected["records"], "resource", resource_id=lambda r: r["resource_id"])
    exclusions.warn_unmatched(logger)

    complete = collector.ok
    payload = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "inventory_source": "azure_resource_graph",
            "query": INVENTORY_QUERY,
            "asset_id_normalization": "lowercase",
            "pages_read": None if collected is None else collected["pages"],
            "total_records_reported": None if collected is None else collected["total_records"],
            "excluded": excluded if complete else [],
        },
        summary=exclusions.summary(excluded, ("resource",), {"resources": None if collected is None else len(records)}),
    )
    # The inventory contract (framework/schemas/inventory_schema.json): the records, withheld on any failure.
    payload["record_count"] = len(records)
    payload["records_included"] = complete
    payload["data"] = records if complete else []

    filename = f"{NAME}_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    try:
        path = write_evidence(output_dir, filename, payload)
    except OSError as exc:
        report_failure(f"could not write the inventory: {exc}", "internal_error")
        return 1

    if not complete:
        report_failure(
            "inventory incomplete, records withheld: " + failure_reason(collector.failures),
            classify_failure_code(collector.failures),
        )
        return 1
    if not records:
        logger.warning("Resource Graph returned no in-scope resources; without Reader on the subscription it returns "
                       "none, and the uploader does not send an empty inventory")
    logger.info("Inventory saved to %s (%d records)", path, len(records))
    return 0


if __name__ == "__main__":
    sys.exit(main())
