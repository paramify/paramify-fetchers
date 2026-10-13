#!/usr/bin/env python3
"""Azure DevOps auditing: whether it is on, each audit stream's state, and whether Azure Monitor streams deliver rows."""

import logging
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import dig, sorted_counts  # noqa: E402
from azure_rest import (  # noqa: E402
    LAW_API,
    AzureRestClient,
    int_config,
    iso_duration_days,
    pinned_credential,
    table_missing,
)
from devops_rest import iso, parse_time, run_org  # noqa: E402

NAME = "azure_devops_audit_streams"
WINDOW_ENV = "AZURE_DEVOPS_AUDIT_WINDOW_DAYS"
DEFAULT_WINDOW_DAYS = 7
AUDIT_API = "7.1-preview.1"
POLICY_API = "5.0-preview"
AUDIT_SERVICE = "auditservice"
LOG_AUDIT_EVENTS = "Policy.LogAuditEvents"
RETENTION_DAYS = 90
AUDIT_PAGE_SIZE = 200
MAX_AUDIT_PAGES = 10
# Streams send batches every half hour or less, so a newer event may not have landed yet.
STREAM_DELAY = timedelta(hours=1)
TABLE = "AzureDevOpsAuditing"
AZURE_MONITOR = "Azure Monitor Logs"
# Reading the audit log or its streams is itself audited; this collector's own reads are not activity.
READ_ACTIONS = frozenset({"auditlog.accesslog", "auditlog.downloadlog", "auditlog.streamread"})
# Integer wire values follow the AuditStreamStatus enum order.
STATUSES = ("unknown", "enabled", "disabledByUser", "disabledBySystem", "deleted", "backfilling")
DELIVERING = frozenset({"enabled", "backfilling"})
TARGET_TYPES = {
    "azuremonitorlogs": AZURE_MONITOR,
    "splunk": "Splunk",
    "azureeventgrid": "Azure Event Grid",
    "eventgrid": "Azure Event Grid",
}
_SECRET_MARKERS = ("key", "token", "secret", "password", "sas", "connection", "credential", "signature")
_DESTINATION_MARKERS = ("url", "uri", "host", "endpoint", "workspace", "resourceid", "tenant", "topic")
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_MS_DATE = re.compile(r"/Date\((-?\d+)\)/")
INGESTION_QUERY = (
    f"{TABLE} | where TimeGenerated > ago({{days}}d) "
    "| extend ScopeType = tostring(column_ifexists('ScopeType', '')) "
    "| summarize Rows = count(), LastEvent = max(TimeGenerated) by ScopeId, ScopeDisplayName, ScopeType"
)

logger = logging.getLogger(NAME)


def when_of(value: Any) -> Optional[datetime]:
    """UTC datetime from ISO-8601 or the legacy /Date(ms)/ form the docs' samples show."""
    if value in (None, ""):
        return None
    match = _MS_DATE.fullmatch(str(value).strip())
    if match:
        return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc)
    parsed = parse_time(value)
    return parsed.astimezone(timezone.utc) if parsed else None


def ado_time(value: Any) -> Optional[str]:
    when = when_of(value)
    return iso(when) if when else (str(value) if value not in (None, "") else None)


def stream_status(raw: Any) -> str:
    if isinstance(raw, int) and not isinstance(raw, bool) and 0 <= raw < len(STATUSES):
        return STATUSES[raw]
    text = str(raw if raw is not None else "").strip()
    if text.isdigit() and int(text) < len(STATUSES):
        return STATUSES[int(text)]
    return next((s for s in STATUSES if s.lower() == text.lower()), text or "unknown")


def scrub_url(value: str) -> str:
    """Userinfo, query and fragment can carry credentials; a destination needs scheme, host and path only."""
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return value
    return urlunsplit((parts.scheme, parts.netloc.rpartition("@")[2], parts.path, "", ""))


def destination(inputs: Any) -> Dict[str, str]:
    """Where a stream sends events; consumerInputs' tokens and keys never leave this function."""
    out: Dict[str, str] = {}
    for key, value in (inputs.items() if isinstance(inputs, dict) else ()):
        low = str(key).lower()
        if any(m in low for m in _SECRET_MARKERS) or not any(m in low for m in _DESTINATION_MARKERS):
            continue
        if isinstance(value, str) and value.strip().strip("*"):
            out[str(key)] = scrub_url(value.strip())
    return dict(sorted(out.items()))


def workspace_ref(dest: Dict[str, str]) -> Optional[Dict[str, str]]:
    """An Azure Monitor Logs stream's workspace: its ARM resource id, else its workspace (customer) id."""
    for value in dest.values():
        if "/providers/microsoft.operationalinsights/workspaces/" in value.lower():
            return {"resource_id": value.rstrip("/")}
    for key, value in dest.items():
        if "workspace" in key.lower() and _GUID.fullmatch(value):
            return {"customer_id": value.lower()}
    return None


def stream_items(body: Any) -> List[Dict[str, Any]]:
    """ADO lists come as {count, value}; the docs also show a bare array and a bare object."""
    if isinstance(body, dict) and isinstance(body.get("value"), list):
        body = body["value"]
    if isinstance(body, dict):
        body = [body] if body.get("id") is not None or body.get("consumerType") else []
    return [s for s in body or [] if isinstance(s, dict)]


def stream_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    consumer = raw.get("consumerType") or ""
    status = stream_status(raw.get("status"))
    name = raw.get("displayName")
    return {
        "id": raw.get("id"),
        "display_name": scrub_url(name) if isinstance(name, str) else name,
        "consumer_type": consumer or None,
        "target_type": TARGET_TYPES.get(consumer.lower(), consumer or None),
        "status": status,
        "status_reason": raw.get("statusReason") or None,
        "delivering": status in DELIVERING,
        "created_time": ado_time(raw.get("createdTime")),
        "updated_time": ado_time(raw.get("updatedTime")),
        "destination": destination(raw.get("consumerInputs")),
    }


def policy_value(body: Any) -> Optional[bool]:
    """The policy's on/off; the endpoint is undocumented, so any other shape reads as unknown."""
    if not isinstance(body, dict):
        return None
    for key in ("effectiveValue", "value"):
        value = body.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in ("true", "false"):
            return value.strip().lower() == "true"
    return None


def organization_scoped(entry: Dict[str, Any]) -> bool:
    """An organization-level audit entry or table row; one with no scope type can't be told apart, so it counts."""
    kind = str(entry.get("scopeType") or entry.get("ScopeType") or "").strip().lower()
    return kind in ("", "organization")


def _event(found: Optional[tuple]) -> Optional[Dict[str, Any]]:
    if not found:
        return None
    when, entry = found
    return {"timestamp": iso(when), "action_id": entry.get("actionId"), "area": entry.get("area"),
            "category": entry.get("category")}


def newest_events(client, now: datetime) -> Dict[str, Any]:
    """Newest audit event that is not a read of the log, the newest old enough to have been streamed, and the
    newest organization-level one old enough: project events carry the project's scopeId, not the organization's."""
    params = {"startTime": iso(now - timedelta(days=RETENTION_DAYS)), "endTime": iso(now),
              "batchSize": str(AUDIT_PAGE_SIZE)}
    newest = settled = settled_org = None
    scope_id = None
    read = pages = 0
    complete = True
    # Paged here rather than with client.iter: stopping early depends on each page's order.
    while True:
        body = client.get("_apis/audit/auditlog", AUDIT_API, params=params, service=AUDIT_SERVICE)
        # The docs' sample wraps the result in "value"; the client libraries read it bare.
        page = body.get("value") if isinstance(body, dict) and isinstance(body.get("value"), dict) else body
        page = page if isinstance(page, dict) else {}
        pages += 1
        entries = [e for e in page.get("decoratedAuditLogEntries") or [] if isinstance(e, dict)]
        read += len(entries)
        stamps = []
        for entry in entries:
            org_level = organization_scoped(entry)
            if org_level:
                scope_id = scope_id or entry.get("scopeId")
            when = when_of(entry.get("timestamp"))
            if when is None:
                continue
            stamps.append(when)
            if (entry.get("actionId") or "").lower() in READ_ACTIONS:
                continue
            if newest is None or when > newest[0]:
                newest = (when, entry)
            if when <= now - STREAM_DELAY and (settled is None or when > settled[0]):
                settled = (when, entry)
            if org_level and when <= now - STREAM_DELAY and (settled_org is None or when > settled_org[0]):
                settled_org = (when, entry)
        token = page.get("continuationToken")
        newest_first = stamps == sorted(stamps, reverse=True)
        if (settled_org and newest_first) or not page.get("hasMore") or not token:
            break
        if pages >= MAX_AUDIT_PAGES:
            complete = False
            break
        params = {**params, "continuationToken": token}
    return {
        "searched_days": RETENTION_DAYS,
        "entries_read": read,
        "complete": complete,
        "newest_event": _event(newest),
        "newest_event_older_than_1h": _event(settled),
        "newest_organization_event_older_than_1h": _event(settled_org),
        "organization_scope_id": scope_id,
    }


def auditing_state(policy: Optional[bool], newest: Optional[datetime], now: datetime, days: int) -> tuple:
    if policy is not None:
        return policy, LOG_AUDIT_EVENTS
    if newest and newest >= now - timedelta(days=days):
        return True, "audit_log"
    return None, None


def subscription_of(resource_id: Optional[str]) -> Optional[str]:
    parts = (resource_id or "").strip("/").split("/")
    return parts[1] if len(parts) > 1 and parts[0].lower() == "subscriptions" else None


def azure_client(subscription_id: Optional[str]) -> AzureRestClient:
    return AzureRestClient(pinned_credential(subscription_id))


def matches_org(row: Dict[str, Any], org: str, scope_id: Optional[str]) -> bool:
    if scope_id:
        return (row.get("ScopeId") or "").lower() == scope_id.lower()
    name = (row.get("ScopeDisplayName") or "").lower()
    return name == org.lower() or name.startswith(f"{org.lower()} (")


def ingestion(az, ref: Dict[str, str], org: str, scope_id: Optional[str], days: int) -> Dict[str, Any]:
    """This organization's AzureDevOpsAuditing rows in the window; one workspace can hold several organizations."""
    customer_id = ref.get("customer_id")
    if not customer_id:
        customer_id = dig(az.get(ref["resource_id"], LAW_API), "properties", "customerId")
        if not customer_id:
            raise LookupError(f"no customerId for workspace {ref['resource_id']}")
    result: Dict[str, Any] = {"table": TABLE, "workspace_resource_id": ref.get("resource_id"),
                              "workspace_customer_id": customer_id, "notes": []}
    try:
        rows = az.query(customer_id, INGESTION_QUERY.format(days=days), iso_duration_days(days))
    except Exception as exc:  # noqa: BLE001
        if not table_missing(exc, TABLE):
            raise
        rows = []
        result["notes"].append(f"{TABLE} table does not exist in the workspace")
    mine = [r for r in rows if matches_org(r, org, scope_id)]
    others = [r for r in rows if not matches_org(r, org, scope_id)]
    last = max((w for w in (when_of(r.get("LastEvent")) for r in mine) if w), default=None)
    result["rows_in_window"] = sum(int(r.get("Rows") or 0) for r in mine)
    result["received_rows"] = result["rows_in_window"] > 0
    result["last_event"] = iso(last) if last else None
    result["other_organizations"] = sorted(
        {r.get("ScopeDisplayName") or r.get("ScopeId") or "" for r in others if organization_scoped(r)}
    )
    # A project's rows carry its own ScopeId, and the table does not say which organization owns the project.
    result["project_rows_unattributed"] = sum(int(r.get("Rows") or 0) for r in others if not organization_scoped(r))
    return result


def _short(exc: BaseException) -> str:
    text = " ".join(str(exc).split())
    return f"{type(exc).__name__}: {text[:200]}"


def summarize(enabled: Optional[bool], streams: Optional[List[Dict[str, Any]]], audit_log: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    listed = streams or []
    checked = [s["ingestion"] for s in listed if s.get("ingestion")]
    return {
        "auditing_enabled": enabled,
        "streams": None if streams is None else len(listed),
        "streams_delivering": sum(1 for s in listed if s["delivering"]),
        "streams_not_delivering": [s["display_name"] or str(s["id"]) for s in listed if not s["delivering"]],
        "streams_by_target": sorted_counts(Counter(s["target_type"] or "unknown" for s in listed)),
        "azure_monitor_streams_with_rows": sum(1 for i in checked if i["received_rows"]),
        "azure_monitor_streams_missing_rows": sum(1 for i in checked if i["missing_rows"]),
        "newest_audit_event": dig(audit_log, "newest_event", "timestamp"),
    }


def collect(client, collector) -> tuple:
    now = datetime.now(timezone.utc)
    days = int_config(WINDOW_ENV, DEFAULT_WINDOW_DAYS)
    org = client.org
    notes: List[str] = []

    policy = None
    try:
        policy = policy_value(client.get(f"_apis/OrganizationPolicy/Policies/{LOG_AUDIT_EVENTS}", POLICY_API,
                                         params={"defaultValue": "false"}))
        if policy is None:
            notes.append(f"{LOG_AUDIT_EVENTS} answered in an unrecognised shape; auditing is judged from the audit log")
    except Exception as exc:  # noqa: BLE001
        notes.append(f"{LOG_AUDIT_EVENTS} could not be read ({_short(exc)}); auditing is judged from the audit log")

    def audit_call(operation: str, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            status = getattr(exc, "status", None)
            # With the policy off, the audit service refusing is the answer, not a collection failure.
            if policy is False and isinstance(status, int) and 400 <= status < 500 and status not in (401, 408, 429):
                notes.append(f"{operation} refused with auditing off ({_short(exc)})")
            else:
                collector.record(operation, exc)
            return None

    raw_streams = audit_call("audit.streams.list",
                             lambda: client.get("_apis/audit/streams", AUDIT_API, service=AUDIT_SERVICE))
    streams = None if raw_streams is None else sorted(
        (stream_record(s) for s in stream_items(raw_streams)),
        key=lambda s: (s["target_type"] or "", s["display_name"] or "", str(s["id"])),
    )
    audit_log = audit_call("audit.auditlog.query", lambda: newest_events(client, now))
    enabled, source = auditing_state(policy, when_of(dig(audit_log, "newest_event", "timestamp")), now, days)

    # Compared with the organization's own rows, so the event must be organization-level too.
    settled = when_of(dig(audit_log, "newest_organization_event_older_than_1h", "timestamp"))
    expected = bool(settled and settled >= now - timedelta(days=days))
    scope_id = dig(audit_log, "organization_scope_id")
    clients: Dict[Optional[str], AzureRestClient] = {}
    checked: Dict[str, Optional[Dict[str, Any]]] = {}

    def check(ref: Dict[str, str]) -> Dict[str, Any]:
        sub = subscription_of(ref.get("resource_id"))
        if sub not in clients:
            clients[sub] = azure_client(sub)
        return ingestion(clients[sub], ref, org, scope_id, days)

    for stream in streams or []:
        if stream["target_type"] != AZURE_MONITOR:
            continue
        ref = workspace_ref(stream["destination"])
        if ref is None:
            stream["ingestion"] = None
            notes.append(f"stream {stream['id']} names no workspace in its inputs; ingestion not checked")
            continue
        key = (ref.get("resource_id") or ref["customer_id"]).lower()
        if key not in checked:
            checked[key] = collector.guard(f"loganalytics.query({TABLE}, {key})", lambda ref=ref: check(ref))
        found = checked[key]
        # An event from before the stream existed was never streamed.
        created = when_of(stream["created_time"])
        stream_expected = expected and (created is None or (settled is not None and settled >= created))
        stream["ingestion"] = None if found is None else {
            **found,
            "window_days": days,
            "rows_expected": stream_expected,
            "missing_rows": stream["delivering"] and stream_expected and not found["received_rows"],
        }

    results = {
        "organization": org,
        "window_days": days,
        "auditing": {"enabled": enabled, "source": source, "log_audit_events_policy": policy},
        "streams": streams,
        "audit_log": audit_log,
        "notes": notes,
    }
    return results, summarize(enabled, streams, audit_log)


def main() -> int:
    return run_org(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
