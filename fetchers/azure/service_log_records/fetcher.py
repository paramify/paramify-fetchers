#!/usr/bin/env python3
"""App Service HTTP logs, SQL Managed Instance audit events and app dependencies as they arrive in Log Analytics."""

import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import basename, coverage_percentage, sorted_counts  # noqa: E402
from azure_rest import (  # noqa: E402
    DIAG_API,
    LAW_API,
    ArmError,
    QueryError,
    dig,
    int_config,
    iso_duration_days,
    parse_time,
    run_subscription,
    table_missing,
)

NAME = "azure_service_log_records"
WEB_API = "2023-12-01"
SQL_API = "2023-08-01"
LOOKBACK_ENV = "SERVICE_LOGS_LOOKBACK_DAYS"
DEFAULT_LOOKBACK_DAYS = 7
SAMPLE_ENV = "SERVICE_LOGS_SAMPLE_SIZE"
DEFAULT_SAMPLE_SIZE = 10

HTTP_TABLE = "AppServiceHTTPLogs"
AUDIT_TABLE = "AzureDiagnostics"
DEPENDENCY_TABLE = "AppDependencies"
HTTP_CATEGORY = "AppServiceHTTPLogs"
AUDIT_CATEGORY = "SQLSecurityAuditEvents"
HTTP_GROUPS = frozenset({"alllogs"})
AUDIT_GROUPS = frozenset({"audit", "alllogs"})

_SCOPE = "| where TimeGenerated > ago({days}d) | where _ResourceId startswith '/subscriptions/{subscription_id}/' "
HTTP_QUERY = (
    f"{HTTP_TABLE} " + _SCOPE
    + "| summarize Records = count(), LastRecord = max(TimeGenerated), ClientIps = dcount(CIp), "
    "Status2xx = countif(ScStatus between (200 .. 299)), Status3xx = countif(ScStatus between (300 .. 399)), "
    "Status4xx = countif(ScStatus between (400 .. 499)), Status5xx = countif(ScStatus >= 500), "
    "Hosts = make_set(CsHost, {sample}) by ResourceId = tolower(_ResourceId)"
)
HTTP_LATEST_QUERY = (
    f"{HTTP_TABLE} " + _SCOPE
    + "| summarize arg_max(TimeGenerated, CIp, CsHost, CsMethod, ScStatus) by ResourceId = tolower(_ResourceId)"
)
HTTP_CLIENTS_QUERY = (
    f"{HTTP_TABLE} " + _SCOPE
    + "| top-nested of ResourceId = tolower(_ResourceId) by Ignore = max(1), "
    "top-nested {sample} of CIp by Requests = count()"
)
# AzureDiagnostics gains the SQL audit columns only with the first audit event, so each is read through column_ifexists.
_AUDIT = (
    f"{AUDIT_TABLE} " + _SCOPE + f"| where Category == '{AUDIT_CATEGORY}' "
    "| extend Succeeded = tostring(column_ifexists('succeeded_s', '')), "
    "Database = tostring(column_ifexists('database_name_s', '')), Action = tostring(column_ifexists('action_name_s', '')), "
    "Principal = tostring(column_ifexists('server_principal_name_s', '')), "
    "ClientIp = tostring(column_ifexists('client_ip_s', '')) "
)
AUDIT_QUERY = (
    _AUDIT + "| summarize Records = count(), LastRecord = max(TimeGenerated), Failed = countif(Succeeded =~ 'false'), "
    "SucceededEvents = countif(Succeeded =~ 'true') by ResourceId = tolower(_ResourceId), Database, Action"
)
PRINCIPAL_QUERY = (
    _AUDIT + "| summarize Records = count(), Failed = countif(Succeeded =~ 'false'), "
    "SucceededEvents = countif(Succeeded =~ 'true'), LastSeen = max(TimeGenerated), "
    "ClientIps = make_set(ClientIp, {sample}) by ResourceId = tolower(_ResourceId), Principal"
)
DEPENDENCY_QUERY = (
    f"{DEPENDENCY_TABLE} " + _SCOPE
    + "| summarize Calls = sum(ItemCount), Failed = sumif(ItemCount, Success == false), LastCall = max(TimeGenerated) "
    "by Component = tolower(_ResourceId), AppRole = AppRoleName, Target, DependencyType"
)
QUERIES = (
    (HTTP_TABLE, "http", HTTP_QUERY), (HTTP_TABLE, "http_latest", HTTP_LATEST_QUERY),
    (HTTP_TABLE, "http_clients", HTTP_CLIENTS_QUERY), (AUDIT_TABLE, "audit", AUDIT_QUERY),
    (AUDIT_TABLE, "principals", PRINCIPAL_QUERY), (DEPENDENCY_TABLE, "dependencies", DEPENDENCY_QUERY),
)
# Dependencies span every App Insights component in the subscription, so they are the likeliest to hit the
# query row or size cap; a failure there leaves the table unread without failing the run.
BEST_EFFORT = frozenset({"dependencies"})
# The Host header is the client's to set; a probe's text there can make the evidence upload refuse the file.
HOST_NAME = re.compile(r"^[A-Za-z0-9.-]+(:[0-9]+)?$")
QUERY_CODE = re.compile(r"^\((\d{3})\)\s*(\S*)")
# A failed login carries whatever principal and database the client sent, and CsMethod is the client's too.
PLAIN_NAME = re.compile(r"^[\w .@\\$#-]{1,128}$")
HTTP_METHOD = re.compile(r"^[A-Z]{1,20}$")

WS_QUERIED = "queried"
WS_NOT_AUTHORIZED = "not_authorized"
WS_NOT_FOUND = "not_found"
WS_ERROR = "error"
ANALYTICS = "analytics"
TOTAL_RETENTION = "total_retention_in_days"
ENTRA = "entra"
SQL_LOGIN = "sql_login"
STOPPED = "stopped"

logger = logging.getLogger(NAME)


# --- pure transforms ---

def id_key(resource_id) -> str:
    return (resource_id or "").lower().rstrip("/")


def exporting_workspaces(settings: list[dict], category: str, groups: frozenset) -> list[str]:
    """Workspaces of the settings that send `category` to Log Analytics, by name or through a group."""
    seen: dict = {}
    for setting in settings or []:
        props = setting.get("properties") or {}
        workspace = props.get("workspaceId")
        if not workspace:
            continue
        for log in props.get("logs") or []:
            named = (log.get("category") or "").lower() == category.lower()
            grouped = (log.get("categoryGroup") or "").lower() in groups
            if log.get("enabled") is True and (named or grouped):
                seen.setdefault(id_key(workspace), workspace)
    return [seen[k] for k in sorted(seen)]


def principal_kind(name) -> str | None:
    """Entra users sign in by UPN and apps or managed identities as <client id>@<tenant id>; SQL logins have no @."""
    if not name:
        return None
    return ENTRA if "@" in name else SQL_LOGIN


def _status_and_code(exc: BaseException) -> tuple:
    """ArmError carries both; QueryError's code reads '(403) InsufficientAccessError'."""
    status, code = getattr(exc, "status", None), str(getattr(exc, "code", None) or "")
    match = QUERY_CODE.match(code)
    if match:
        status, code = int(match.group(1)), match.group(2)
    return status, code.lower()


def ws_status(exc: BaseException) -> str:
    """Classified on the status and error code only: messages can carry workspace names and query text."""
    status, code = _status_and_code(exc)
    # ARM answers SubscriptionNotFound (404) for a subscription the caller holds no role in.
    if code == "subscriptionnotfound":
        return WS_NOT_AUTHORIZED
    if status == 404:
        return WS_NOT_FOUND
    if status in (401, 403):
        return WS_NOT_AUTHORIZED
    return WS_ERROR


def host_name(value):
    return value if isinstance(value, str) and HOST_NAME.match(value) else None


def plain_name(value):
    return value if isinstance(value, str) and PLAIN_NAME.match(value) else None


def http_method(value):
    return value if isinstance(value, str) and HTTP_METHOD.match(value) else None


def filled_queries(subscription_id: str, days: int, sample: int) -> dict:
    return {key: kql.format(days=days, subscription_id=subscription_id, sample=sample) for _, key, kql in QUERIES}


def dynamic_list(value) -> list:
    """make_set columns arrive as JSON text from the query API."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return [value]
    return [v for v in value if v] if isinstance(value, list) else []


def table_record(name: str, raw) -> dict:
    """raw None: the table does not exist in the workspace yet."""
    props = (raw or {}).get("properties") or {}
    return {
        "name": name,
        "exists": raw is not None,
        "plan": props.get("plan"),
        "retention_in_days": props.get("retentionInDays"),
        "total_retention_in_days": props.get("totalRetentionInDays"),
    }


def readable(table: dict) -> bool:
    """A missing table holds no records; Basic and Auxiliary tables bill per GB scanned, so they are not queried."""
    return not table["exists"] or (table["plan"] or "Analytics").lower() == ANALYTICS


def _latest(times):
    parsed = [(parse_time(t), t) for t in times if t]
    parsed = [p for p in parsed if p[0] is not None]
    return max(parsed)[1] if parsed else None


def _answered(wids: list[str], workspaces: dict, table: str) -> bool:
    """Every workspace answered every query on the table, or no longer exists."""
    for wid in wids:
        ws = workspaces.get(id_key(wid)) or {}
        if ws.get("status") != WS_NOT_FOUND and table not in ws.get("read_tables", ()):
            return False
    return True


def _arriving(records, destinations: list[str], workspaces: dict, table: str):
    """True once records arrived; False only when every destination's table was read (or the destination is gone)."""
    if not destinations:
        return None
    if records:
        return True
    return False if _answered(destinations, workspaces, table) else None


def _known(settings, destinations: list[str], counted: list[str], arriving, workspaces: dict, table: str) -> bool:
    """Counts stand once the settings were read and the copy they come from answered every query on the table."""
    if settings is None:
        return False
    return not destinations or (arriving is not None and _answered(counted, workspaces, table))


def _total(values) -> int:
    """Resources whose counts are null (records not readable) are left out."""
    return sum(v for v in values if v is not None)


def _rows_for(rid: str, destinations: list[str], workspaces: dict, key: str, nested: str = "") -> list[dict]:
    """Rows stamped with the resource, or with a child under `nested` (a slot is its own resource, so none for apps)."""
    prefix = f"{rid}/{nested}/" if nested else None
    rows: list[dict] = []
    for wid in destinations:
        ws = workspaces.get(id_key(wid)) or {}
        for r in ws.get(key) or []:
            row_id = (r.get("ResourceId") or "").lower()
            if row_id == rid or (prefix and row_id.startswith(prefix)):
                rows.append(r)
    return rows


def _fullest(rid: str, destinations: list[str], workspaces: dict, key: str, nested: str = "") -> list[str]:
    """Each destination keeps its own copy of the records, so counts come from the one holding the most, not a sum."""
    totals = {wid: sum(r.get("Records") or 0 for r in _rows_for(rid, [wid], workspaces, key, nested))
              for wid in destinations}
    return [max(totals, key=lambda wid: totals[wid])] if totals else []


def app_record(site: dict, settings, workspaces: dict, sample: int) -> dict:
    destinations = exporting_workspaces(settings, HTTP_CATEGORY, HTTP_GROUPS)
    rid = (site.get("id") or "").lower()
    counted = _fullest(rid, destinations, workspaces, "http")
    summary = _rows_for(rid, counted, workspaces, "http")
    latest = _rows_for(rid, counted, workspaces, "http_latest")
    clients = _rows_for(rid, counted, workspaces, "http_clients")
    records = sum(r.get("Records") or 0 for r in summary)
    arriving = _arriving(records, destinations, workspaces, HTTP_TABLE)
    known = _known(settings, destinations, counted, arriving, workspaces, HTTP_TABLE)
    newest_time = _latest(r.get("TimeGenerated") for r in latest)
    newest = next((r for r in latest if r.get("TimeGenerated") == newest_time), None)
    return {
        "id": site.get("id"),
        "name": site.get("name"),
        "kind": site.get("kind"),
        "state": dig(site, "properties", "state"),
        "is_slot": "/slots/" in rid,
        "diagnostic_settings_read": settings is not None,
        "http_logs_exported": bool(destinations) if settings is not None else None,
        "http_log_workspaces": destinations,
        "http_log_records": records if known else None,
        "last_http_log": _latest(r.get("LastRecord") for r in summary),
        "distinct_client_ips": max((r.get("ClientIps") or 0 for r in summary), default=0) if known else None,
        "status_classes": {
            k: sum(r.get(f"Status{k}") or 0 for r in summary) for k in ("2xx", "3xx", "4xx", "5xx")
        } if known else None,
        "hosts": sorted({h for r in summary for h in dynamic_list(r.get("Hosts")) if host_name(h)})[:sample],
        "top_clients": sorted(
            ({"client_ip": c.get("CIp"), "requests": c.get("Requests")} for c in clients),
            key=lambda c: (-(c["requests"] or 0), c["client_ip"] or ""),
        )[:sample],
        "latest_request": {
            "time": newest.get("TimeGenerated"), "client_ip": newest.get("CIp"), "host": host_name(newest.get("CsHost")),
            "method": http_method(newest.get("CsMethod")), "status": newest.get("ScStatus"),
        } if newest else None,
        "http_logs_arriving": arriving,
    }


def instance_record(mi: dict, settings, databases, workspaces: dict, sample: int) -> dict:
    destinations = exporting_workspaces(settings, AUDIT_CATEGORY, AUDIT_GROUPS)
    rid = (mi.get("id") or "").lower()
    # SQL audit events can carry the database's id rather than the instance's.
    counted = _fullest(rid, destinations, workspaces, "audit", "databases")
    rows = _rows_for(rid, counted, workspaces, "audit", "databases")
    principal_rows = _rows_for(rid, counted, workspaces, "principals", "databases")
    records = sum(r.get("Records") or 0 for r in rows)
    arriving = _arriving(records, destinations, workspaces, AUDIT_TABLE)
    known = _known(settings, destinations, counted, arriving, workspaces, AUDIT_TABLE)
    listed = {(d.get("name") or "").lower(): d["name"] for d in databases or [] if d.get("name")}
    dbs: dict = {}
    for r in rows:
        name = r.get("Database")
        if not name:
            continue
        db = dbs.setdefault(name.lower(), {"name": listed.get(name.lower(), name), "times": [], "records": 0, "failed": 0,
                                           "succeeded": 0})
        db["records"] += r.get("Records") or 0
        db["failed"] += r.get("Failed") or 0
        db["succeeded"] += r.get("SucceededEvents") or 0
        db["times"].append(r.get("LastRecord"))
    for key, name in listed.items():
        dbs.setdefault(key, {"name": name, "times": [], "records": 0, "failed": 0, "succeeded": 0})
    # A database the instance doesn't list is named by the events alone, so it shows only once one succeeded.
    db_records = [
        {"name": db["name"] if key in listed else plain_name(db["name"]), "listed": key in listed,
         "audit_records": db["records"] if known else None, "failed_events": db["failed"] if known else None,
         "last_audit_record": _latest(db["times"])}
        for key, db in sorted(dbs.items()) if key in listed or db["succeeded"]
    ]
    principals: dict = {}
    for r in principal_rows:
        name = r.get("Principal") or ""
        p = principals.setdefault(name, {"records": 0, "failed": 0, "succeeded": 0, "times": [], "ips": set()})
        p["records"] += r.get("Records") or 0
        p["failed"] += r.get("Failed") or 0
        p["succeeded"] += r.get("SucceededEvents") or 0
        p["times"].append(r.get("LastSeen"))
        p["ips"].update(dynamic_list(r.get("ClientIps")))
    # A principal counts once it has signed in; a name seen only in failed events counts as a number.
    principal_records = sorted(
        (
            {"principal": plain_name(name), "kind": principal_kind(name), "events": p["records"],
             "failed_events": p["failed"], "last_seen": _latest(p["times"]), "client_ips": sorted(p["ips"])[:sample]}
            for name, p in principals.items() if not name or p["succeeded"]
        ),
        key=lambda p: (-p["events"], p["principal"] or ""),
    )
    kinds = Counter(p["kind"] for p in principal_records)
    actions: Counter = Counter()
    for r in rows:
        actions[r.get("Action") or "unknown"] += r.get("Records") or 0
    counts = {
        "audit_records": records,
        "failed_audit_events": sum(r.get("Failed") or 0 for r in rows),
        "audit_records_without_database": sum(r.get("Records") or 0 for r in rows if not r.get("Database")),
        "principals_total": sum(1 for p in principal_records if p["kind"]),
        "entra_principals": kinds[ENTRA],
        "sql_login_principals": kinds[SQL_LOGIN],
        "failed_only_principals": sum(1 for name, p in principals.items() if name and not p["succeeded"]),
        "unnamed_principal_events": sum(p["events"] for p in principal_records if p["kind"] is None),
        "failed_only_database_names": sum(1 for key, db in dbs.items() if key not in listed and not db["succeeded"]),
    }
    if not known:
        counts = dict.fromkeys(counts)
    return {
        "id": mi.get("id"),
        "name": mi.get("name"),
        "diagnostic_settings_read": settings is not None,
        "audit_exported": bool(destinations) if settings is not None else None,
        "audit_workspaces": destinations,
        "audit_records": counts["audit_records"],
        "failed_audit_events": counts["failed_audit_events"],
        "last_audit_record": _latest(r.get("LastRecord") for r in rows),
        "audit_actions": sorted_counts(actions) if known else None,
        "databases": db_records,
        "audit_records_without_database": counts["audit_records_without_database"],
        "principals": principal_records[:sample],
        "principals_total": counts["principals_total"],
        "entra_principals": counts["entra_principals"],
        "sql_login_principals": counts["sql_login_principals"],
        "failed_only_principals": counts["failed_only_principals"],
        "unnamed_principal_events": counts["unnamed_principal_events"],
        "failed_only_database_names": counts["failed_only_database_names"],
        "audit_arriving": arriving,
    }


def dependency_records(workspaces: dict, sample: int) -> list[dict]:
    roles: dict = {}
    for ws in workspaces.values():
        for r in ws.get("dependencies") or []:
            key = (r.get("Component") or "", r.get("AppRole") or "")
            role = roles.setdefault(key, {})
            target = role.setdefault((r.get("Target") or "", r.get("DependencyType") or ""), {"calls": 0, "failed": 0, "times": []})
            target["calls"] += r.get("Calls") or 0
            target["failed"] += r.get("Failed") or 0
            target["times"].append(r.get("LastCall"))
    out = []
    for (component, app_role), targets in sorted(roles.items()):
        ranked = sorted(
            ({"target": t or None, "type": kind or None, "calls": v["calls"], "failed_calls": v["failed"],
              "last_call": _latest(v["times"])} for (t, kind), v in targets.items()),
            key=lambda t: (-t["calls"], t["target"] or ""),
        )
        out.append({
            "app_role": app_role or None,
            "component_id": component or None,
            "targets_total": len(ranked),
            "dependency_types": sorted({t["type"] for t in ranked if t["type"]}),
            "targets": ranked[:sample],
        })
    return out


def _min_retention(workspaces: list[dict], table: str, key: str = "retention_in_days"):
    days = [
        t[key] for w in workspaces for t in w.get("tables") or []
        if t["name"] == table and t["exists"] and isinstance(t.get(key), int) and t[key] > 0
    ]
    return min(days) if days else None


def _receiving(workspaces: list[dict], destinations) -> list[dict]:
    """A workspace that gets only the other log type still lists this table, at its default retention."""
    wanted = {id_key(w) for w in destinations}
    return [w for w in workspaces if id_key(w.get("workspace_id")) in wanted]


def summarize(apps: list[dict], instances: list[dict], dependencies: list[dict], workspaces: list[dict], days: int) -> dict:
    http_workspaces = _receiving(workspaces, (w for a in apps for w in a["http_log_workspaces"]))
    audit_workspaces = _receiving(workspaces, (w for m in instances for w in m["audit_workspaces"]))
    exporting_apps = [a for a in apps if a["http_logs_exported"]]
    exporting_mis = [m for m in instances if m["audit_exported"]]
    status = Counter(w["status"] for w in workspaces)
    databases = [d for m in instances for d in m["databases"] if d["listed"]]
    with_http = sum(1 for a in exporting_apps if a["http_logs_arriving"] is True)
    # A stopped app serves no requests, so it has no HTTP logs to send.
    running = [a for a in exporting_apps if (a.get("state") or "").lower() != STOPPED]
    with_audit = sum(1 for m in exporting_mis if m["audit_arriving"] is True)
    return {
        "lookback_days": days,
        "apps": len(apps),
        "apps_exporting_http_logs": len(exporting_apps),
        "apps_with_http_log_records": with_http,
        "apps_without_http_log_records": sum(1 for a in running if a["http_logs_arriving"] is False),
        "apps_http_logs_unknown": sum(1 for a in exporting_apps if a["http_logs_arriving"] is None),
        "stopped_apps_exporting_http_logs": len(exporting_apps) - len(running),
        "http_log_arrival_percentage": coverage_percentage(
            sum(1 for a in running if a["http_logs_arriving"] is True), len(running)),
        "http_log_records": _total(a["http_log_records"] for a in apps),
        "managed_instances": len(instances),
        "instances_exporting_audit": len(exporting_mis),
        "instances_with_audit_records": with_audit,
        "instances_without_audit_records": sum(1 for m in exporting_mis if m["audit_arriving"] is False),
        "instances_audit_unknown": sum(1 for m in exporting_mis if m["audit_arriving"] is None),
        "audit_records": _total(m["audit_records"] for m in instances),
        "failed_audit_events": _total(m["failed_audit_events"] for m in instances),
        "audit_actions": sorted_counts(sum((Counter(m["audit_actions"] or {}) for m in instances), Counter())),
        "audit_principals": _total(m["principals_total"] for m in instances),
        "entra_principals": _total(m["entra_principals"] for m in instances),
        "sql_login_principals": _total(m["sql_login_principals"] for m in instances),
        "failed_only_principals": _total(m["failed_only_principals"] for m in instances),
        "unnamed_principal_events": _total(m["unnamed_principal_events"] for m in instances),
        "managed_databases": len(databases),
        "managed_databases_with_audit_records": sum(1 for d in databases if d["audit_records"]),
        "app_roles_with_dependencies": len(dependencies),
        "dependency_targets": sum(d["targets_total"] for d in dependencies),
        "dependency_types": sorted({t for d in dependencies for t in d["dependency_types"]}),
        "dependency_query_failures": sum(1 for w in workspaces if "dependencies" in w.get("failed_queries", ())),
        "log_workspaces": len(workspaces),
        "log_workspaces_queried": status[WS_QUERIED],
        "log_workspaces_not_authorized": status[WS_NOT_AUTHORIZED],
        "log_workspaces_not_found": status[WS_NOT_FOUND],
        "http_log_retention_days": _min_retention(http_workspaces, HTTP_TABLE),
        "audit_log_retention_days": _min_retention(audit_workspaces, AUDIT_TABLE),
        "dependency_retention_days": _min_retention(workspaces, DEPENDENCY_TABLE),
        "http_log_total_retention_days": _min_retention(http_workspaces, HTTP_TABLE, TOTAL_RETENTION),
        "audit_log_total_retention_days": _min_retention(audit_workspaces, AUDIT_TABLE, TOTAL_RETENTION),
        "dependency_total_retention_days": _min_retention(workspaces, DEPENDENCY_TABLE, TOTAL_RETENTION),
    }


# --- collection ---

def _optional_table(client, workspace_id: str, table: str):
    try:
        return client.get(f"{workspace_id}/tables/{table}", LAW_API)
    except ArmError as exc:
        if exc.status == 404:
            return None
        raise


def _query(client, customer_id: str, table: str, kql: str, timespan: str) -> list:
    """A table the tables API lists but no record ever reached answers 'Failed to resolve table': no rows."""
    try:
        return client.query(customer_id, kql, timespan)
    except QueryError as exc:
        if table_missing(exc, table):
            return []
        raise


def _error_text(exc: BaseException) -> str:
    return " ".join(str(exc).split())[:300]


def _unread(out: dict, workspace_id: str, exc: BaseException, collector) -> dict:
    """A refused or deleted workspace is evidence; any other failure here fails the run."""
    status = ws_status(exc)
    if status == WS_ERROR:
        collector.record(f"loganalytics.query(service logs, {workspace_id})", exc)
    else:
        logger.warning("Log Analytics workspace %s: %s (%s)", workspace_id, status, exc)
    return {**out, "status": status, "error": _error_text(exc), "read_tables": []}


def read_workspace(client, workspace_id: str, subscription_id: str, days: int, sample: int, collector) -> dict:
    """Each query stands alone: a failed one leaves only its own table unread."""
    out: dict = {"workspace_id": workspace_id, "name": basename(workspace_id), "status": WS_QUERIED, "error": None,
                 "tables": [], "read_tables": [], "failed_queries": [], **{key: [] for _, key, _ in QUERIES}}
    kql = filled_queries(subscription_id, days, sample)
    try:
        customer_id = dig(client.get(workspace_id, LAW_API), "properties", "customerId")
        if not customer_id:
            raise LookupError(f"no customerId on workspace {workspace_id}")
        out["tables"] = [table_record(t, _optional_table(client, workspace_id, t))
                         for t in (HTTP_TABLE, AUDIT_TABLE, DEPENDENCY_TABLE)]
    except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
        return _unread(out, workspace_id, exc, collector)
    ready = {t["name"] for t in out["tables"] if t["exists"] and readable(t)}
    timespan = iso_duration_days(days)
    unread = set()
    for table, key, _ in QUERIES:
        if table not in ready:
            continue
        try:
            out[key] = _query(client, customer_id, table, kql[key], timespan)
        except Exception as exc:  # noqa: BLE001 — a refusal covers the workspace; anything else only this query
            # A best-effort query runs last, so even a refusal there (table-level access) leaves the rest read.
            if ws_status(exc) != WS_ERROR and key not in BEST_EFFORT:
                return _unread(out, workspace_id, exc, collector)
            unread.add(table)
            out["failed_queries"].append(key)
            if key in BEST_EFFORT:
                logger.warning("Log Analytics workspace %s: %s query failed (%s)", workspace_id, key, exc)
            else:
                collector.record(f"loganalytics.query({key}, {workspace_id})", exc)
                out["status"], out["error"] = WS_ERROR, out["error"] or _error_text(exc)
    out["read_tables"] = sorted(t["name"] for t in out["tables"] if readable(t) and t["name"] not in unread)
    return out


def _settings(client, resource_id: str, collector):
    return collector.guard(
        f"insights.diagnosticSettings.list({resource_id})",
        lambda: client.list(f"{resource_id}/providers/Microsoft.Insights/diagnosticSettings", DIAG_API),
    )


def collect(client, subscription_id: str, collector) -> tuple:
    days = int_config(LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS)
    sample = int_config(SAMPLE_ENV, DEFAULT_SAMPLE_SIZE)
    base = f"/subscriptions/{subscription_id}/providers"
    sites = collector.guard("web.sites.list", lambda: client.list(f"{base}/Microsoft.Web/sites", WEB_API)) or []
    for site in list(sites):
        slots = collector.guard(f"web.sites.slots.list({site.get('name')})",
                                lambda site=site: client.list(f"{site['id']}/slots", WEB_API))
        sites.extend(slots or [])
    instances = collector.guard(
        "sql.managedInstances.list", lambda: client.list(f"{base}/Microsoft.Sql/managedInstances", SQL_API)
    ) or []
    databases = {
        id_key(mi["id"]): collector.guard(
            f"sql.managedDatabases.list({mi.get('name')})",
            lambda mi=mi: client.list(f"{mi['id']}/databases", SQL_API),
        )
        for mi in instances
    }
    site_settings = {id_key(s["id"]): _settings(client, s["id"], collector) for s in sites}
    mi_settings = {id_key(m["id"]): _settings(client, m["id"], collector) for m in instances}

    wanted: dict = {}
    for settings in site_settings.values():
        for w in exporting_workspaces(settings, HTTP_CATEGORY, HTTP_GROUPS):
            wanted.setdefault(id_key(w), w)
    for settings in mi_settings.values():
        for w in exporting_workspaces(settings, AUDIT_CATEGORY, AUDIT_GROUPS):
            wanted.setdefault(id_key(w), w)
    workspaces = {k: read_workspace(client, wanted[k], subscription_id, days, sample, collector) for k in sorted(wanted)}

    apps = sorted(
        (app_record(s, site_settings[id_key(s["id"])], workspaces, sample) for s in sites),
        key=lambda a: (a["id"] or "").lower(),
    )
    mis = sorted(
        (instance_record(m, mi_settings[id_key(m["id"])], databases[id_key(m["id"])], workspaces, sample)
         for m in instances),
        key=lambda m: (m["id"] or "").lower(),
    )
    dependencies = dependency_records(workspaces, sample)
    workspace_records = [
        {k: ws[k] for k in ("workspace_id", "name", "status", "error", "tables", "read_tables", "failed_queries")}
        for ws in workspaces.values()
    ]
    results = {
        "apps": apps,
        "managed_instances": mis,
        "app_dependencies": dependencies,
        "workspaces": workspace_records,
        "lookback_days": days,
        "sample_size": sample,
        "queries": filled_queries(subscription_id, days, sample),
    }
    return results, summarize(apps, mis, dependencies, workspace_records, days)


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
