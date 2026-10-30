#!/usr/bin/env python3
"""Per-resource diagnostic settings for every resource in a subscription, whether each log-emitting resource exports its logs, and whether they arrive."""

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
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    sorted_counts,
    write_evidence,
)
from azure_rest import (  # noqa: E402
    LAW_API,
    AzureRestClient,
    int_config,
    iso_duration_days,
    parse_time,
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
from resource_exclusions import ResourceExclusions  # noqa: E402
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

INGESTION_LOOKBACK_ENV = "INGESTION_LOOKBACK_DAYS"
DEFAULT_INGESTION_LOOKBACK_DAYS = 7
APPROVED_WORKSPACES_ENV = "APPROVED_LOG_WORKSPACES"
# Written whatever a diagnostic setting says (the activity log, metrics, monitoring agents, Container Insights), so a
# row there does not show a resource's logs arriving. Application Insights tables stay: their rows are the component's own.
NOT_RESOURCE_LOG_TABLES = (
    "AzureActivity", "AzureMetrics", "InsightsMetrics", "Perf", "Heartbeat", "Syslog", "Event",
    "ContainerLog", "ContainerLogV2", "ContainerInventory", "ContainerNodeInventory", "ContainerImageInventory",
    "ContainerServiceLog", "KubePodInventory", "KubeNodeInventory", "KubeEvents", "KubeServices", "KubePVInventory",
    "KubeMonAgentEvents", "KubeHealth",
)
INGESTION_QUERY = (
    "union withsource=ParamifySourceTable * "
    "| where TimeGenerated > ago({days}d) "
    "| where _ResourceId startswith '/subscriptions/{subscription_id}/' "
    "| where ParamifySourceTable !in (" + ", ".join(f"'{t}'" for t in NOT_RESOURCE_LOG_TABLES) + ") "
    "| summarize LastIngested = max(TimeGenerated), Records = count() "
    "by ResourceId = tolower(_ResourceId), Table = ParamifySourceTable"
)
# Each storage service writes only its own resource-specific table.
STORAGE_LOG_TABLES = {
    "storagebloblogs": f"{STORAGE_ACCOUNT_TYPE}/blobservices",
    "storagefilelogs": f"{STORAGE_ACCOUNT_TYPE}/fileservices",
    "storagequeuelogs": f"{STORAGE_ACCOUNT_TYPE}/queueservices",
    "storagetablelogs": f"{STORAGE_ACCOUNT_TYPE}/tableservices",
}
AZURE_DIAGNOSTICS_MODE = "azurediagnostics"
_NOT_RESOURCE_LOG_KEYS = frozenset(t.lower() for t in NOT_RESOURCE_LOG_TABLES)
# union * skips Basic and Auxiliary tables; querying them bills per GB scanned, so it is off unless hours are set.
BASIC_LOOKBACK_ENV = "BASIC_LOGS_LOOKBACK_HOURS"
DEFAULT_BASIC_LOOKBACK_HOURS = 0
BASIC_TABLE_QUERY = (
    "['{table}'] "
    "| where TimeGenerated > ago({hours}h) "
    "| where _ResourceId startswith '/subscriptions/{subscription_id}/' "
    "| summarize LastIngested = max(TimeGenerated), Records = count() by ResourceId = tolower(_ResourceId) "
    "| extend Table = '{table}'"
)

INGESTION_QUERIED = "queried"
INGESTION_NOT_AUTHORIZED = "not_authorized"
INGESTION_NOT_FOUND = "not_found"
INGESTION_ERROR = "error"


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


def scoped_location(record: dict):
    """A subscription-level resource has no resource group and stays in scope unless an id: pattern names it."""
    return record["location"] if resource_group_from_id(record["id"]) else None


def classify_error(exc: BaseException):
    """STATUS_UNSUPPORTED / STATUS_NOT_FOUND for an expected answer, None for a real failure."""
    message = str(exc).lower()
    if any(marker in message for marker in UNSUPPORTED_MARKERS):
        return STATUS_UNSUPPORTED
    if getattr(exc, "status_code", None) == 404 or "resourcenotfound" in message:
        return STATUS_NOT_FOUND
    return None


# --- log ingestion and approved destinations ---

def workspace_key(workspace_id: str) -> str:
    return (workspace_id or "").lower().rstrip("/")


def approved_workspaces() -> list[str]:
    raw = os.environ.get(APPROVED_WORKSPACES_ENV) or ""
    return sorted({workspace_key(w.strip()) for w in raw.split(",") if w.strip()})


def workspace_approved(workspace_id, approved: list[str]):
    """Matched by resource id or bare name; None when no list is configured or there is no workspace."""
    if not approved or not workspace_id:
        return None
    key = workspace_key(workspace_id)
    return key in approved or key.rsplit("/", 1)[-1] in approved


def basic_lookback_hours() -> int:
    """0, the default, leaves the Basic and Auxiliary tables unqueried."""
    raw = (os.environ.get(BASIC_LOOKBACK_ENV) or "").strip()
    try:
        hours = int(raw) if raw else DEFAULT_BASIC_LOOKBACK_HOURS
    except ValueError:
        logger.warning("%s=%r is not an integer; using %d", BASIC_LOOKBACK_ENV, raw, DEFAULT_BASIC_LOOKBACK_HOURS)
        return DEFAULT_BASIC_LOOKBACK_HOURS
    return max(hours, 0)


def resource_log_table(name: str) -> bool:
    """Custom (_CL) and agent or platform tables never hold what a diagnostic setting exports."""
    return not name.lower().endswith("_cl") and name.lower() not in _NOT_RESOURCE_LOG_KEYS


def could_hold_logs(table: str, record: dict, settings: list[dict]) -> bool:
    """Whether an unqueried Basic or Auxiliary table could hold this resource's logs from these settings."""
    name, rtype = table.lower(), record["type"] or ""
    if not resource_log_table(table):
        return False
    if name in STORAGE_LOG_TABLES:
        return STORAGE_LOG_TABLES[name] == rtype
    if rtype in STORAGE_LOG_TABLES.values():
        return False
    # Most settings leave the mode unset, and many types write resource-specific tables anyway; only an explicit
    # AzureDiagnostics mode rules a resource-specific table out.
    modes = {(s.get("log_analytics_destination_type") or "").lower() for s in settings}
    return name == AZURE_DIAGNOSTICS_MODE or modes != {AZURE_DIAGNOSTICS_MODE}


def non_analytics_tables(tables: list[dict]) -> list[dict]:
    """Basic and Auxiliary plan tables, which union * leaves out."""
    out = []
    for table in tables:
        plan = (table.get("properties") or {}).get("plan")
        if plan and plan.lower() != "analytics" and table.get("name"):
            out.append({"name": table["name"], "plan": plan})
    return sorted(out, key=lambda t: t["name"].lower())


def exporting_workspaces(record: dict) -> list[str]:
    """Distinct Log Analytics destinations of the settings that export logs."""
    seen: dict = {}
    for setting in record["diagnostic_settings"]:
        if setting["exports_logs"] and setting.get("workspace_id"):
            seen.setdefault(workspace_key(setting["workspace_id"]), setting["workspace_id"])
    return [seen[k] for k in sorted(seen)]


def ingestion_status(exc: BaseException) -> str:
    message = str(exc).lower()
    status = getattr(exc, "status", None)
    # ARM answers SubscriptionNotFound (404) for a subscription the caller holds no role in.
    if "subscriptionnotfound" in message:
        return INGESTION_NOT_AUTHORIZED
    if status == 404 or "resourcenotfound" in message or "workspacenotfound" in message:
        return INGESTION_NOT_FOUND
    if status in (401, 403) or any(
        m in message for m in ("(401)", "(403)", "authorizationfailed", "insufficientaccess", "forbidden")
    ):
        return INGESTION_NOT_AUTHORIZED
    return INGESTION_ERROR


def _latest(times) -> str | None:
    parsed = [(parse_time(t), t) for t in times if t]
    parsed = [p for p in parsed if p[0] is not None]
    return max(parsed)[1] if parsed else None


def ingestion_by_resource(rows: list[dict]) -> dict:
    """Query rows (one per resource and table) folded per lower-cased resource id."""
    grouped: dict = {}
    for row in rows:
        rid = (row.get("ResourceId") or "").lower()
        if rid:
            grouped.setdefault(rid, []).append(row)
    return {
        rid: {
            "last_ingested": _latest(r.get("LastIngested") for r in group),
            "records": sum(r.get("Records") or 0 for r in group),
            "tables": sorted({r["Table"] for r in group if r.get("Table")}),
        }
        for rid, group in grouped.items()
    }


def with_ingestion(record: dict, workspaces: dict, approved: list[str]) -> dict:
    """ingested_in_window: True once any destination holds records; False only when every destination was read in full or is gone."""
    settings = [
        {**s, "workspace_approved": workspace_approved(s.get("workspace_id"), approved)}
        for s in record["diagnostic_settings"]
    ]
    rid = (record["id"] or "").lower()
    destinations = []
    for workspace_id in exporting_workspaces(record):
        ws = workspaces.get(workspace_key(workspace_id)) or {}
        status = ws.get("status")
        seen = (ws.get("resources") or {}).get(rid) or {}
        to_ws = [s for s in record["diagnostic_settings"]
                 if s["exports_logs"] and workspace_key(s.get("workspace_id")) == workspace_key(workspace_id)]
        skipped = [t for t in ws.get("unqueried_tables") or [] if could_hold_logs(t, record, to_ws)]
        destinations.append({
            "workspace_id": workspace_id,
            "status": status,
            "read_in_full": not skipped if status == INGESTION_QUERIED else None,
            "unqueried_tables": skipped if status == INGESTION_QUERIED else None,
            "last_ingested": seen.get("last_ingested"),
            "records": seen.get("records", 0) if status == INGESTION_QUERIED else None,
            "tables": seen.get("tables", []),
        })
    if not destinations:
        ingested = None
    elif any(d["records"] for d in destinations):
        ingested = True
    elif all(d["status"] == INGESTION_NOT_FOUND or d["read_in_full"] for d in destinations):
        ingested = False
    else:
        ingested = None
    exporting = [s for s in settings if s["exports_logs"]]
    return {
        **record,
        "diagnostic_settings": settings,
        "log_analytics_ingestion": destinations,
        "last_ingested": _latest(d["last_ingested"] for d in destinations),
        "ingested_in_window": ingested,
        "sends_to_approved_workspace": (
            any(s["workspace_approved"] for s in exporting)
            if approved and record["has_enabled_log_setting"] is not None else None
        ),
    }


def destination_records(workspaces: dict, records: list[dict], approved: list[str]) -> list[dict]:
    out = []
    for key in sorted(workspaces):
        ws = workspaces[key]
        reads = [
            d for r in records for d in r["log_analytics_ingestion"] if workspace_key(d["workspace_id"]) == key
        ]
        out.append({
            "workspace_id": ws["workspace_id"],
            "name": ws["name"],
            "customer_id": ws["customer_id"],
            "status": ws["status"],
            "error": ws["error"],
            "non_analytics_tables": ws["non_analytics_tables"],
            "unqueried_tables": ws.get("unqueried_tables", []) if ws["status"] == INGESTION_QUERIED else None,
            "table_errors": ws.get("table_errors", []),
            "all_tables_queried": ws["all_tables_queried"] if ws["status"] == INGESTION_QUERIED else None,
            "approved": workspace_approved(ws["workspace_id"], approved),
            "resources_exporting": len(reads),
            "resources_with_records": sum(1 for d in reads if d["records"]),
        })
    return out


def summarize_ingestion(
    records: list[dict], destinations: list[dict], days: int, hours: int, approved: list[str]
) -> dict:
    sending = [r for r in records if r["emits_resource_logs"] and r["sends_to_log_analytics"]]
    recent = [r for r in sending if r["ingested_in_window"] is True]
    stale = [r for r in sending if r["ingested_in_window"] is False]
    status = Counter(d["status"] for d in destinations)
    emitting = [r for r in records if r["emits_resource_logs"]]
    exporting = [s for r in records for s in r["diagnostic_settings"] if s["exports_logs"] and s.get("workspace_id")]
    return {
        "ingestion_lookback_days": days,
        "basic_logs_lookback_hours": hours,
        "log_analytics_destinations": len(destinations),
        "log_analytics_destinations_queried": status[INGESTION_QUERIED],
        "log_analytics_destinations_not_authorized": status[INGESTION_NOT_AUTHORIZED],
        "log_analytics_destinations_not_found": status[INGESTION_NOT_FOUND],
        "log_analytics_destinations_errored": status[INGESTION_ERROR],
        "log_analytics_destinations_with_unqueried_tables": sum(
            1 for d in destinations if d["all_tables_queried"] is False
        ),
        "resources_with_recent_ingestion": len(recent),
        "resources_without_recent_ingestion": len(stale),
        "resources_ingestion_unknown": len(sending) - len(recent) - len(stale),
        "recent_ingestion_percentage": coverage_percentage(len(recent), len(sending)),
        "no_recent_ingestion_by_type": sorted_counts(Counter(r["type"] or "unknown" for r in stale)),
        "all_log_analytics_resources_ingesting": len(recent) == len(sending) if sending else None,
        "approved_workspaces_configured": bool(approved),
        "settings_exporting_to_unapproved_workspace": (
            sum(1 for s in exporting if s["workspace_approved"] is False) if approved else None
        ),
        "resources_sending_to_approved_workspace": (
            sum(1 for r in emitting if r["sends_to_approved_workspace"]) if approved else None
        ),
        "resources_exporting_to_unapproved_workspace": (
            sum(1 for r in records if any(
                s["exports_logs"] and s["workspace_approved"] is False for s in r["diagnostic_settings"]
            )) if approved else None
        ),
    }


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


def read_workspace_ingestion(
    client, workspace_id: str, subscription_id: str, days: int, hours: int, collector: Collector
) -> dict:
    """A refused or deleted destination is evidence, any other destination failure fails the run; a failing Basic table only stays unqueried."""
    out = {"workspace_id": workspace_id, "name": basename(workspace_id), "customer_id": None,
           "status": INGESTION_QUERIED, "error": None, "non_analytics_tables": [], "unqueried_tables": [],
           "table_errors": [], "all_tables_queried": False, "resources": {}}
    try:
        out["customer_id"] = ((client.get(workspace_id, LAW_API) or {}).get("properties") or {}).get("customerId")
        if not out["customer_id"]:
            raise LookupError(f"no customerId on workspace {workspace_id}")
        out["non_analytics_tables"] = non_analytics_tables(client.list(f"{workspace_id}/tables", LAW_API))
        query = INGESTION_QUERY.format(days=days, subscription_id=subscription_id)
        rows = client.query(out["customer_id"], query, iso_duration_days(days))
    except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
        status = ingestion_status(exc)
        if status == INGESTION_ERROR:
            collector.record(f"loganalytics.query(ingestion, {workspace_id})", exc)
        else:
            logger.warning("Log Analytics destination %s: %s (%s)", workspace_id, status, exc)
        return {**out, "status": status, "error": " ".join(str(exc).split())[:300]}
    unqueried = [t["name"] for t in out["non_analytics_tables"] if resource_log_table(t["name"])]
    for name in list(unqueried) if hours else []:
        query = BASIC_TABLE_QUERY.format(table=name, hours=hours, subscription_id=subscription_id)
        try:
            rows += client.search(out["customer_id"], query, f"PT{hours}H")
            unqueried.remove(name)
        except Exception as exc:  # noqa: BLE001 — one table's failure leaves it unqueried, not the run failed
            logger.warning("Basic table %s in %s not queried: %s", name, workspace_id, exc)
            out["table_errors"].append({"table": name, "error": " ".join(str(exc).split())[:300]})
    return {**out, "unqueried_tables": unqueried, "all_tables_queried": not unqueried,
            "resources": ingestion_by_resource(rows)}


def collect_ingestion(cred, subscription_id: str, records: list[dict], days: int, hours: int, collector) -> dict:
    wanted: dict = {}
    for record in records:
        for workspace_id in exporting_workspaces(record):
            wanted.setdefault(workspace_key(workspace_id), workspace_id)
    if not wanted:
        return {}
    client = AzureRestClient(cred)
    return {
        key: read_workspace_ingestion(client, wanted[key], subscription_id, days, hours, collector)
        for key in sorted(wanted)
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

    records: list[dict] = []
    inventory = {"rows": [], "total_records": None, "pages": 0}
    registration = REGISTRATION_UNKNOWN
    days = int_config(INGESTION_LOOKBACK_ENV, DEFAULT_INGESTION_LOOKBACK_DAYS)
    hours = basic_lookback_hours()
    approved = approved_workspaces()
    workspaces: dict = {}
    exclusions = ResourceExclusions.from_env()
    exclusions.record_invalid(collector)
    excluded: list[dict] = []
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Insights")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Insights is not registered on %s — no diagnostic setting can exist",
                subscription_id,
            )
        inventory = enumerate_resources(subscription_id, cred, collector)
        # Excluded resources (a storage account's services with it) are never read, and only in-scope ones pick destinations.
        resources, excluded = exclusions.split(
            with_storage_children([inventory_record(r) for r in inventory["rows"]]), "resource", location=scoped_location)
        monitor = collector.guard(
            "monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred)
        )
        if monitor is not None and resources:
            unsupported_types: set = set()
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                records = list(pool.map(lambda r: assess(monitor, collector, r, unsupported_types), resources))
        elif resources:
            records = [resource_record(r, STATUS_ERROR) for r in resources]
        workspaces = collect_ingestion(cred, subscription_id, records, days, hours, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    exclusions.warn_unmatched(logger)
    records = sorted((with_ingestion(r, workspaces, approved) for r in records), key=lambda r: (r["id"] or "").lower())
    destinations = destination_records(workspaces, records, approved)
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "resources": records,
            "inventory_source": "azure_resource_graph",
            "query": INVENTORY_QUERY,
            "provider_registration_status": registration,
            "log_analytics_destinations": destinations,
            "ingestion_query": INGESTION_QUERY,
            "basic_table_query": BASIC_TABLE_QUERY,
            "approved_log_workspaces": approved or None,
            "excluded": excluded,
        },
        summary={
            **summarize(records, len(inventory["rows"]), inventory["total_records"], inventory["pages"]),
            "provider_registration_status": registration,
            **summarize_ingestion(records, destinations, days, hours, approved),
            **exclusions.summary(excluded, ("resource",), {"resources": len(records)}),
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
