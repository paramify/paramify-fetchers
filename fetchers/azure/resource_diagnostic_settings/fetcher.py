#!/usr/bin/env python3
"""Per-resource diagnostic settings for every resource in a subscription, and whether each log-emitting resource exports its logs."""

import logging
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    provider_registration_status,
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)
from diagnostics import (  # noqa: E402
    CATEGORY_TYPE_LOGS,
    CATEGORY_TYPE_METRICS,
    DESTINATION_LOG_ANALYTICS,
    diagnostic_destinations,
    enabled_categories,
    enabled_category_groups,
    project_category,
    project_diagnostic_setting,
    resource_uri,
)
from resource_graph import query_all, resource_graph_client  # noqa: E402

logger = logging.getLogger("azure_resource_diagnostic_settings")

INVENTORY_QUERY = (
    "Resources | project id, name, type, kind, location, resourceGroup | order by id asc"
)

# Storage logs live only on these child services, which Resource Graph does not list.
STORAGE_ACCOUNT_TYPE = "microsoft.storage/storageaccounts"
STORAGE_CHILD_SERVICES = ("blobServices", "fileServices", "queueServices", "tableServices")
# Premium blob and file accounts have one service; an unrecognized kind gets all four.
STORAGE_SERVICES_BY_KIND = {
    "blobstorage": ("blobServices",),
    "blockblobstorage": ("blobServices",),
    "filestorage": ("fileServices",),
}

STATUS_ASSESSED = "assessed"
STATUS_UNSUPPORTED = "unsupported"
STATUS_NOT_FOUND = "not_found"
STATUS_ERROR = "error"

# Measured 2026-10-12 on 60+ types: 400 (ResourceTypeNotSupported) "The resource type '<type>' does not
# support diagnostic settings." It names the type, so one answer holds for every resource of that type.
UNSUPPORTED_MARKERS = ("resourcetypenotsupported", "does not support diagnostic settings")

# Measured ~14 resources/s on ~1,000 resources; ARM refills reads at ~25/s per principal, and 429s are retried.
WORKERS = 4


# --- pure transforms ---

def inventory_record(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "name": row.get("name"),
        "type": (row.get("type") or "").lower() or None,
        "kind": row.get("kind") or None,
        "location": row.get("location") or None,
        "resource_group": row.get("resourceGroup") or None,
        "parent_id": None,
        "synthesized_child": False,
    }


def with_storage_children(resources: list[dict]) -> list[dict]:
    """Add each storage account's blob/file/queue/table services that its kind has, unless already listed."""
    seen = {(r["id"] or "").lower() for r in resources}
    out = list(resources)
    for account in resources:
        if account["type"] != STORAGE_ACCOUNT_TYPE or not account["id"]:
            continue
        for service in STORAGE_SERVICES_BY_KIND.get((account["kind"] or "").lower(), STORAGE_CHILD_SERVICES):
            child_id = f"{account['id']}/{service}/default"
            if child_id.lower() in seen:
                continue
            seen.add(child_id.lower())
            out.append({
                **account,
                "id": child_id,
                "name": f"{account['name']}/{service}/default",
                "type": f"{STORAGE_ACCOUNT_TYPE}/{service.lower()}",
                "kind": None,
                "parent_id": account["id"],
                "synthesized_child": True,
            })
    return out


def setting_record(setting: dict) -> dict:
    logs = setting["logs"]
    sinks = diagnostic_destinations(setting)
    categories, groups = enabled_categories(logs), enabled_category_groups(logs)
    return {
        **setting,
        "destinations": sinks,
        "enabled_log_categories": categories,
        "enabled_log_category_groups": groups,
        "exports_logs": bool(sinks) and bool(categories or groups),
    }


def captured_categories(log_categories: list[dict], settings: list[dict]) -> list[str]:
    """Log categories some exporting setting selects, by name or through a category group."""
    captured = set()
    for setting in settings:
        if not setting["exports_logs"]:
            continue
        names = {c.lower() for c in setting["enabled_log_categories"]}
        groups = {g.lower() for g in setting["enabled_log_category_groups"]}
        for category in log_categories:
            member_of = {g.lower() for g in category["category_groups"]}
            if category["name"].lower() in names or "alllogs" in groups or member_of & groups:
                captured.add(category["name"])
    return sorted(captured)


def resource_record(base: dict, status: str, categories=None, settings=None) -> dict:
    categories = categories or []
    settings = [setting_record(s) for s in (settings or [])]
    logs = [c for c in categories if c["category_type"] == CATEGORY_TYPE_LOGS and c["name"]]
    log_names = sorted(c["name"] for c in logs)
    audit = sorted(c["name"] for c in logs if "audit" in {g.lower() for g in c["category_groups"]})
    captured = captured_categories(logs, settings)
    assessed = status == STATUS_ASSESSED
    sinks = sorted({d for s in settings if s["exports_logs"] for d in s["destinations"]})
    return {
        **base,
        "status": status,
        "supports_diagnostics": (bool(categories) if assessed else False if status == STATUS_UNSUPPORTED else None),
        "emits_resource_logs": (bool(logs) if assessed else False if status == STATUS_UNSUPPORTED else None),
        "log_categories": log_names,
        "audit_log_categories": audit,
        "metric_categories": sorted(
            c["name"] for c in categories if c["category_type"] == CATEGORY_TYPE_METRICS and c["name"]
        ),
        "diagnostic_settings": sorted(settings, key=lambda s: s.get("id") or ""),
        "has_enabled_log_setting": (any(s["exports_logs"] for s in settings) if assessed and logs else None),
        "destination_types": sinks,
        "sends_to_log_analytics": DESTINATION_LOG_ANALYTICS in sinks,
        "captured_log_categories": captured,
        "uncaptured_log_categories": [c for c in log_names if c not in captured],
        "captures_all_audit_categories": (all(c in captured for c in audit) if audit else None),
    }


def summarize(records: list[dict], enumerated: int, total_reported, pages: int) -> dict:
    status = Counter(r["status"] for r in records)
    emitting = [r for r in records if r["emits_resource_logs"]]
    covered = [r for r in emitting if r["has_enabled_log_setting"]]
    to_law = [r for r in emitting if r["sends_to_log_analytics"]]
    uncovered_by_type = Counter(r["type"] or "unknown" for r in emitting if not r["has_enabled_log_setting"])
    with_audit = [r for r in emitting if r["captures_all_audit_categories"] is not None]
    return {
        "resources_enumerated": enumerated,
        "resource_graph_total_records": total_reported,
        "resource_graph_pages": pages,
        "child_services_synthesized": sum(1 for r in records if r["synthesized_child"]),
        "resources_evaluated": len(records),
        "resources_assessed": status[STATUS_ASSESSED],
        "resources_unsupported": status[STATUS_UNSUPPORTED],
        "resources_not_found": status[STATUS_NOT_FOUND],
        "resources_errored": status[STATUS_ERROR],
        "resources_emitting_logs": len(emitting),
        "resources_with_enabled_log_setting": len(covered),
        "resources_emitting_logs_without_setting": len(emitting) - len(covered),
        "log_setting_coverage_percentage": coverage_percentage(len(covered), len(emitting)),
        "resources_sending_to_log_analytics": len(to_law),
        "log_analytics_coverage_percentage": coverage_percentage(len(to_law), len(emitting)),
        "resources_with_audit_categories": len(with_audit),
        "resources_capturing_all_audit_categories": sum(
            1 for r in with_audit if r["captures_all_audit_categories"]
        ),
        "uncovered_by_type": {t: uncovered_by_type[t] for t in sorted(uncovered_by_type)},
        "all_log_emitting_resources_covered": status[STATUS_ERROR] == 0 and len(covered) == len(emitting),
    }


def classify_error(exc: BaseException):
    """STATUS_UNSUPPORTED / STATUS_NOT_FOUND for an expected answer, None for a real failure."""
    message = str(exc).lower()
    if any(marker in message for marker in UNSUPPORTED_MARKERS):
        return STATUS_UNSUPPORTED
    if getattr(exc, "status_code", None) == 404 or "resourcenotfound" in message:
        return STATUS_NOT_FOUND
    return None


# --- collection (lazy azure imports) ---

def enumerate_resources(subscription_id, cred, collector: Collector) -> dict:
    client = collector.guard("resourcegraph.ResourceGraphClient (init)", lambda: resource_graph_client(cred))
    if client is None:
        return {"rows": [], "total_records": None, "pages": 0}
    result = collector.guard(
        "resourcegraph.resources (Resources)",
        lambda: query_all(client, subscription_id, INVENTORY_QUERY),
    )
    return result or {"rows": [], "total_records": None, "pages": 0}


def monitor_client(subscription_id, cred):
    from azure.mgmt.monitor import MonitorManagementClient  # lazy

    client = MonitorManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())
    for group in ("diagnostic_settings", "diagnostic_settings_category"):
        if getattr(client, group, None) is None:
            raise RuntimeError(
                f"installed azure-mgmt-monitor has no {group} operation group "
                "(removed in 7.0.0) — pin azure-mgmt-monitor>=6.0.2,<7"
            )
    return client


def assess(monitor, collector: Collector, base: dict, unsupported_types: set) -> dict:
    if base["type"] in unsupported_types:
        return resource_record(base, STATUS_UNSUPPORTED)
    uri = resource_uri(base["id"])

    def _read(operation, call):
        try:
            return None, call()
        except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
            status = classify_error(exc)
            if status is None:
                collector.record(f"{operation} ({base['id']})", exc)
                status = STATUS_ERROR
            return status, None

    status, categories = _read(
        "monitor.diagnostic_settings_category.list",
        lambda: [project_category(c) for c in monitor.diagnostic_settings_category.list(resource_uri=uri)],
    )
    if status:
        if status == STATUS_UNSUPPORTED and base["type"]:
            unsupported_types.add(base["type"])
        return resource_record(base, status)
    if not any(c["category_type"] == CATEGORY_TYPE_LOGS for c in categories):
        return resource_record(base, STATUS_ASSESSED, categories)
    # 6.0.2's pager drops nextLink on both lists; ARM caps a resource at a handful of settings.
    status, settings = _read(
        "monitor.diagnostic_settings.list",
        lambda: [project_diagnostic_setting(s) for s in monitor.diagnostic_settings.list(resource_uri=uri)],
    )
    if status:
        return resource_record(base, status, categories)
    return resource_record(base, STATUS_ASSESSED, categories, settings)


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

    records: list[dict] = []
    inventory = {"rows": [], "total_records": None, "pages": 0}
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Insights")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Insights is not registered on %s — no diagnostic setting can exist",
                subscription_id,
            )
        inventory = enumerate_resources(subscription_id, cred, collector)
        resources = with_storage_children([inventory_record(r) for r in inventory["rows"]])
        monitor = collector.guard(
            "monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred)
        )
        if monitor is not None and resources:
            unsupported_types: set = set()
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                records = list(pool.map(lambda r: assess(monitor, collector, r, unsupported_types), resources))
        elif resources:
            records = [resource_record(r, STATUS_ERROR) for r in resources]
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    records.sort(key=lambda r: (r["id"] or "").lower())
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "resources": records,
            "inventory_source": "azure_resource_graph",
            "query": INVENTORY_QUERY,
            "provider_registration_status": registration,
        },
        summary={
            **summarize(records, len(inventory["rows"]), inventory["total_records"], inventory["pages"]),
            "provider_registration_status": registration,
        },
    )

    filename = f"azure_resource_diagnostic_settings_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)
    logger.info("Evidence saved to %s (%d resources)", path, len(records))

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
