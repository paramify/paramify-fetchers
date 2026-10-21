#!/usr/bin/env python3
"""Microsoft Sentinel incidents per workspace: status, owner, response timeline, entities, and monthly detection, acknowledgement and close times."""

import json
import logging
import re
import statistics
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import (  # noqa: E402
    SI_API,
    int_config,
    iso_duration_days,
    parse_time,
    run_workspaces,
    table_missing,
    table_retention_days,
)

NAME = "azure_sentinel_incidents"
LOOKBACK_ENV = "SENTINEL_INCIDENT_LOOKBACK_DAYS"
DEFAULT_LOOKBACK_DAYS = 90
PAGE_SIZE = "1000"
OPEN_STATUSES = frozenset({"New", "Active"})
MAX_ENTITIES_PER_KIND = 25
MAX_RECURRING = 25
# ModifiedBy values (any case) of system updates, as Microsoft's docs and workbooks name them: exact names, then
# prefixes. What a person's update writes isn't documented, so any other modifier counts as a person.
SYSTEM_MODIFIER_NAMES = frozenset({"incident created from alert", "alert grouping", "fusion"})
SYSTEM_MODIFIER_PREFIXES = ("automation rule", "playbook", "microsoft xdr", "microsoft defender xdr", "microsoft 365 defender")

# The ARM incident has no close time or change history; SecurityIncident holds one row per update.
# Bounded by an explicit time so the rows read start exactly where the lookback does.
CLOSED_TIME_QUERY = (
    "SecurityIncident "
    "| where TimeGenerated > datetime({since}) "
    "| summarize arg_max(TimeGenerated, Status, ClosedTime, CreatedTime, Tasks) by IncidentName "
    "| project IncidentName, Status, ClosedTime, CreatedTime, Tasks"
)
# Every update row. Keeping only rows that change status, severity or owner (serialize, prev()) would shrink it
# on busy workspaces, but needs checking on a real workspace first.
HISTORY_QUERY = (
    "SecurityIncident "
    "| where TimeGenerated > datetime({since}) "
    "| project TimeGenerated, IncidentName, Status, Severity, ClosedTime, ModifiedBy, CreatedTime, LastModifiedTime, "
    "OwnerId = tostring(Owner.objectId), "
    "Owner = coalesce(tostring(Owner.userPrincipalName), tostring(Owner.assignedTo), tostring(Owner.email))"
)
ENTITIES_QUERY = (
    "SecurityIncident "
    "| where TimeGenerated > datetime({since}) "
    "| summarize arg_max(TimeGenerated, AlertIds) by IncidentName "
    "| mv-expand AlertId = AlertIds to typeof(string) "
    "| join kind=inner (SecurityAlert | where TimeGenerated > datetime({since}) "
    "| summarize arg_max(TimeGenerated, Entities) by SystemAlertId) on $left.AlertId == $right.SystemAlertId "
    "| project IncidentName, AlertId, Entities"
)

# The fields that name each entity kind, most specific first.
ENTITY_ID_FIELDS = {
    "account": ("UserPrincipalName", "AadUserId", "Sid", "Name"),
    "host": ("FQDN", "HostName", "AadDeviceId", "MdatpDeviceId"),
    "ip": ("Address",),
    "file": ("Name",),
    "filehash": ("Value",),
    "mailbox": ("MailboxPrimaryAddress", "Upn"),
    "mailMessage": ("NetworkMessageId", "InternetMessageId"),
    "mailCluster": ("ClusterSourceIdentifier",),
    "cloud-application": ("Name", "AppId"),
    "azure-resource": ("ResourceId",),
    "dns": ("DomainName",),
    "registry-key": ("Key",),
    "registry-value": ("Name",),
    "malware": ("Name",),
    "security-group": ("DistinguishedName", "ObjectGuid"),
}
GENERIC_ID_FIELDS = ("Name", "DisplayName")
# Anything else in a host (a backslash, a percent escape) can carry a path or token.
URL_HOST = re.compile(r"[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]")

logger = logging.getLogger(NAME)


def hours_between(start: Optional[datetime], end: Optional[datetime]) -> Optional[float]:
    if not start or not end:
        return None
    return round((end - start).total_seconds() / 3600, 2)


def mean_hours(values: List[Optional[float]]) -> Optional[float]:
    kept = [v for v in values if v is not None]
    return round(statistics.mean(kept), 2) if kept else None


def as_list(value: Any) -> List[Any]:
    """Dynamic columns arrive as JSON text."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return value if isinstance(value, list) else []


def project_incident(incident: Dict[str, Any], closed: Dict[str, Any]) -> Dict[str, Any]:
    props = incident.get("properties") or {}
    owner = props.get("owner") or {}
    extra = props.get("additionalData") or {}
    created = props.get("createdTimeUtc")
    closed_time = closed.get(incident.get("name")) if props.get("status") == "Closed" else None
    return {
        "name": incident.get("name"),
        "incident_number": props.get("incidentNumber"),
        "title": props.get("title"),
        "severity": props.get("severity"),
        "status": props.get("status"),
        "classification": props.get("classification"),
        "classification_reason": props.get("classificationReason"),
        "classification_comment": props.get("classificationComment"),
        "owner_assigned_to": owner.get("assignedTo"),
        "owner_user_principal_name": owner.get("userPrincipalName"),
        "created_time_utc": created,
        "first_activity_time_utc": props.get("firstActivityTimeUtc"),
        "last_modified_time_utc": props.get("lastModifiedTimeUtc"),
        "closed_time_utc": closed_time,
        "hours_to_detect": hours_between(parse_time(props.get("firstActivityTimeUtc")), parse_time(created)),
        "hours_to_close": hours_between(parse_time(created), parse_time(closed_time)),
        "provider_name": props.get("providerName"),
        # Defender XDR's own incident id and link for incidents synced from it; Graph alerts carry the same id.
        "provider_incident_id": props.get("providerIncidentId"),
        "provider_incident_url": extra.get("providerIncidentUrl"),
        "related_analytic_rules": len(props.get("relatedAnalyticRuleIds") or []),
        "related_analytic_rule_ids": props.get("relatedAnalyticRuleIds") or [],
        "alerts_count": extra.get("alertsCount"),
        "comments_count": extra.get("commentsCount"),
    }


def created_in(incident: Dict[str, Any], cutoff: datetime) -> bool:
    created = parse_time(incident.get("created_time_utc"))
    return created is not None and created >= cutoff


def in_scope(incident: Dict[str, Any], cutoff: datetime) -> bool:
    """Created inside the lookback, or still open however old it is."""
    return incident.get("status") in OPEN_STATUSES or created_in(incident, cutoff)


def close_time_status(incident: Dict[str, Any], retained_from: datetime, read: bool) -> Optional[str]:
    """found, missing, not_retained (last touched before SecurityIncident's retention, so its close record is gone),
    or unknown when the close times couldn't be read."""
    if incident.get("status") != "Closed":
        return None
    if not read:
        return "unknown"
    if incident.get("closed_time_utc"):
        return "found"
    touched = parse_time(incident.get("last_modified_time_utc")) or parse_time(incident.get("created_time_utc"))
    return "not_retained" if touched is not None and touched < retained_from else "missing"


def changes(rows: List[Dict[str, Any]], field: str) -> List[Dict[str, Any]]:
    """Each update that changed `field`, between consecutive retained rows."""
    out = []
    for before, after in zip(rows, rows[1:]):
        if (before.get(field) or None) != (after.get(field) or None):
            out.append({"time": after.get("TimeGenerated"), "from": before.get(field) or None,
                        "to": after.get(field) or None, "modified_by": after.get("ModifiedBy")})
    return out


def owned(row: Dict[str, Any]) -> bool:
    return bool(row.get("OwnerId") or row.get("Owner"))


def by_person(row: Dict[str, Any]) -> bool:
    modifier = (row.get("ModifiedBy") or "").strip().lower()
    return bool(modifier) and modifier not in SYSTEM_MODIFIER_NAMES and not modifier.startswith(SYSTEM_MODIFIER_PREFIXES)


def acknowledged_time(rows: List[Dict[str, Any]], complete: bool) -> Optional[str]:
    """First update by a person that changes the status (to Active or Closed) or the owner, up to the first close,
    so a reopen never counts. Unknown unless every update since creation was read."""
    if not complete or not rows or rows[0].get("Status") == "Closed":
        return None
    for before, row in zip(rows, rows[1:]):
        status = row.get("Status")
        moved = status != before.get("Status") and status in ("Active", "Closed")
        assigned = owned(row) and (row.get("OwnerId"), row.get("Owner")) != (before.get("OwnerId"), before.get("Owner"))
        if (moved or assigned) and by_person(row):
            return row.get("TimeGenerated")
        if status == "Closed":
            return None
    return None


def project_tasks(row: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {"title": t.get("title"), "status": t.get("status"), "created_time_utc": t.get("createdTimeUtc"),
         "completed_time_utc": t.get("lastCompletedTimeUtc") if t.get("status") == "Completed" else None}
        for t in as_list((row or {}).get("Tasks")) if isinstance(t, dict)
    ]


def history_complete(incident: Dict[str, Any], rows: List[Dict[str, Any]], history_from: datetime) -> bool:
    """Every update was read: created inside the history, the first row read is its creation row (LastModifiedTime
    equal to CreatedTime, as Microsoft's workbooks tell it apart), and the last is no older than the incident's
    lastModifiedTimeUtc, so an update still being ingested leaves it incomplete."""
    created = parse_time(incident.get("created_time_utc"))
    if created is None or created < history_from or not rows:
        return False
    first_modified = parse_time(rows[0].get("LastModifiedTime"))
    if first_modified is None or first_modified != parse_time(rows[0].get("CreatedTime")):
        return False
    modified = parse_time(incident.get("last_modified_time_utc"))
    last = parse_time(rows[-1].get("LastModifiedTime"))
    # A second's slack for the two sources' fractional digits.
    return modified is None or (last is not None and last >= modified - timedelta(seconds=1))


def timeline(incident: Dict[str, Any], rows: Optional[List[Dict[str, Any]]], history_from: datetime) -> Dict[str, Any]:
    """From the updates read since history_from; all None when no history could be read."""
    if rows is None:
        return {k: None for k in ("acknowledged_time_utc", "hours_to_acknowledge", "status_changes", "owner_changes",
                                  "severity_changes", "updates_retained", "history_complete")}
    created = parse_time(incident.get("created_time_utc"))
    complete = history_complete(incident, rows, history_from)
    ack = acknowledged_time(rows, complete)
    return {
        "acknowledged_time_utc": ack,
        "hours_to_acknowledge": hours_between(created, parse_time(ack)),
        "status_changes": changes(rows, "Status"),
        "owner_changes": changes(rows, "Owner"),
        "severity_changes": changes(rows, "Severity"),
        "updates_retained": len(rows),
        "history_complete": complete,
    }


def url_host(url: str) -> Optional[str]:
    """Scheme and host only, since paths and queries can carry tokens; "//host/a" and "host/a" give the bare host.
    None unless the host is letters, digits, dots and hyphens or a bracketed IPv6 address."""
    try:
        parts = urlsplit(url)
        if not parts.scheme and not parts.netloc:
            parts = urlsplit(f"//{url}")
        host = parts.hostname
    except ValueError:
        return None
    if host and "[" in parts.netloc:
        host = f"[{host}]"
    # Browsers read a backslash as a path separator, so "https://evil.com\@good.com" goes to evil.com.
    if not host or not URL_HOST.fullmatch(host) or "\\" in parts.netloc:
        return None
    return f"{parts.scheme}://{host}" if parts.scheme else host


def entity_id(entity: Dict[str, Any], by_ref: Optional[Dict[str, Dict[str, Any]]] = None) -> Optional[str]:
    """A short identifier; never a process's command line or a URL's query string."""
    kind = entity.get("Type")
    if kind == "account" and entity.get("Name") and entity.get("UPNSuffix") and not entity.get("UserPrincipalName"):
        return f"{entity['Name']}@{entity['UPNSuffix']}"
    if kind == "process":
        image = entity.get("ImageFile") or {}
        image = (by_ref or {}).get(str(image.get("$ref")), image) if isinstance(image, dict) else {}
        name, pid = image.get("Name"), entity.get("ProcessId")
        return f"{name} ({pid})" if name and pid else (name or (f"process {pid}" if pid else None))
    if kind == "url":
        return url_host(str(entity["Url"])) if entity.get("Url") else None
    for field in ENTITY_ID_FIELDS.get(kind or "", GENERIC_ID_FIELDS):
        if entity.get(field) not in (None, ""):
            return str(entity[field])
    return None


def walk_entities(node: Any, found: List[Dict[str, Any]]) -> None:
    """Alerts define an entity once, often nested inside another (a process's file and account), and refer back with $ref."""
    if isinstance(node, dict):
        if node.get("Type"):
            found.append(node)
        for value in node.values():
            walk_entities(value, found)
    elif isinstance(node, list):
        for value in node:
            walk_entities(value, found)


def incident_entities(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Per incident: its alerts still in SecurityAlert, and their entities as kind and identifier, deduplicated and capped per kind."""
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        entry = out.setdefault(row.get("IncidentName"), {"alerts": set(), "entities": {}})
        entry["alerts"].add(row.get("AlertId"))
        found: List[Dict[str, Any]] = []
        walk_entities(as_list(row.get("Entities")), found)
        by_ref = {str(e["$id"]): e for e in found if e.get("$id") is not None}
        for e in found:
            ident = entity_id(e, by_ref)
            if ident:
                entry["entities"].setdefault(e["Type"], set()).add(ident)
    return {
        name: {
            "alerts_found": len(v["alerts"]),
            "entities": [
                {"kind": kind, "id": i} for kind in sorted(v["entities"]) for i in sorted(v["entities"][kind])[:MAX_ENTITIES_PER_KIND]
            ],
            "entities_truncated": any(len(ids) > MAX_ENTITIES_PER_KIND for ids in v["entities"].values()),
        }
        for name, v in out.items()
    }


def state_at(incident: Dict[str, Any], rows: List[Dict[str, Any]], at: datetime) -> Optional[Dict[str, Any]]:
    """Status, severity and owner at `at` from the retained updates, or None if the incident didn't exist yet."""
    created = parse_time(incident.get("created_time_utc"))
    if created is None or created > at:
        return None
    before = [r for r in rows if (parse_time(r.get("TimeGenerated")) or at) <= at]
    if before:
        r = before[-1]
        return {"open": r.get("Status") in OPEN_STATUSES, "severity": r.get("Severity"), "owner": r.get("Owner") or None}
    current = {"open": incident.get("status") in OPEN_STATUSES, "severity": incident.get("severity"),
               "owner": incident.get("owner_user_principal_name") or incident.get("owner_assigned_to")}
    modified = parse_time(incident.get("last_modified_time_utc"))
    if not rows or (modified is not None and modified <= at):
        return current
    # Untouched from before the history until after `at`: the next update shows whether it had closed by then,
    # but its severity and owner are the values after that update.
    closed = parse_time(rows[0].get("ClosedTime"))
    return {"open": not (closed is not None and closed <= at), "severity": None, "owner": "unknown"}


def month_starts(start: datetime, end: datetime) -> List[datetime]:
    month = start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    out = []
    while month <= end:
        out.append(month)
        month = (month + timedelta(days=32)).replace(day=1)
    return out


def tally(values: List[Optional[str]], empty: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for v in values:
        counts[v or empty] = counts.get(v or empty, 0) + 1
    return dict(sorted(counts.items()))


def monthly_metrics(
    everything: List[Dict[str, Any]], scoped: List[Dict[str, Any]], rows_by: Dict[str, List[Dict[str, Any]]],
    cutoff: datetime, now: datetime, history_from: datetime,
) -> List[Dict[str, Any]]:
    """Per calendar month of the lookback: MTTD by month created, MTTA by month acknowledged and MTTR by month closed
    over the in-scope incidents, and the open backlog at month end over every incident."""
    times = {
        field: [(parse_time(i.get(field)), i) for i in scoped]
        for field in ("created_time_utc", "acknowledged_time_utc", "closed_time_utc")
    }
    months = []
    for start in month_starts(cutoff, now):
        end = (start + timedelta(days=32)).replace(day=1)
        lo, hi = max(start, cutoff), min(end, now)
        created, acked, closed = (
            [i for t, i in times[field] if t is not None and lo <= t < hi]
            for field in ("created_time_utc", "acknowledged_time_utc", "closed_time_utc")
        )
        as_of = min(end, now)
        backlog = None
        if as_of >= history_from:
            states = [state_at(i, rows_by.get(i["name"]) or [], as_of) for i in everything]
            backlog = [s for s in states if s and s["open"]]
        months.append({
            "month": start.strftime("%Y-%m"),
            "from": lo.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "to": hi.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "updates_retained": lo >= history_from,
            "incidents_created": len(created),
            "mttd_hours": mean_hours([i.get("hours_to_detect") for i in created]),
            "incidents_acknowledged": len(acked),
            "mtta_hours": mean_hours([i.get("hours_to_acknowledge") for i in acked]),
            "incidents_closed": len(closed),
            "mttr_hours": mean_hours([i.get("hours_to_close") for i in closed]),
            "open_at_end": len(backlog) if backlog is not None else None,
            "open_at_end_by_severity": tally([s["severity"] for s in backlog], "unknown") if backlog is not None else None,
            "open_at_end_by_owner": tally([s["owner"] for s in backlog], "unassigned") if backlog is not None else None,
        })
    return months


def recurrence(incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Titles and analytic rules behind two or more incidents in the lookback, most frequent first."""
    by_title: Dict[str, List[str]] = {}
    by_rule: Dict[str, int] = {}
    for i in incidents:
        if i.get("title"):
            by_title.setdefault(i["title"], []).append(i.get("created_time_utc") or "")
        for rule in set(i.get("related_analytic_rule_ids") or []):
            by_rule[rule] = by_rule.get(rule, 0) + 1
    titles = sorted(((t, sorted(c)) for t, c in by_title.items() if len(c) > 1), key=lambda tc: (-len(tc[1]), tc[0]))
    rules = sorted(((r, n) for r, n in by_rule.items() if n > 1), key=lambda rn: (-rn[1], rn[0]))
    return {
        "recurring_titles": len(titles),
        "recurrence_by_title": [
            {"title": t, "incidents": len(c), "first_created": c[0], "last_created": c[-1]} for t, c in titles[:MAX_RECURRING]
        ],
        "recurrence_by_rule": [{"rule_id": r, "incidents": n} for r, n in rules[:MAX_RECURRING]],
    }


def incident_summary(
    incidents: List[Dict[str, Any]], now: datetime, cutoff: datetime, history_from: datetime, history_read: bool,
    closes_read: bool,
) -> Dict[str, Any]:
    open_ = [i for i in incidents if i.get("status") in OPEN_STATUSES]
    closed = [i for i in incidents if i.get("status") == "Closed"]
    recent = [i for i in incidents if created_in(i, cutoff)]
    hours = [i["hours_to_close"] for i in closed if i.get("hours_to_close") is not None]
    ages = [now - c for c in (parse_time(i.get("created_time_utc")) for i in open_) if c]
    return {
        "incidents_in_scope": len(incidents),
        "open_incidents": len(open_),
        "open_by_severity": tally([i.get("severity") for i in open_], "unknown"),
        "closed_incidents": len(closed),
        "closed_undetermined": sum(1 for i in closed if (i.get("classification") or "Undetermined") == "Undetermined"),
        "closed_missing_close_time": sum(1 for i in closed if i.get("close_time_status") == "missing") if closes_read else None,
        "closed_close_time_not_retained": (
            sum(1 for i in closed if i.get("close_time_status") == "not_retained") if closes_read else None
        ),
        "median_hours_to_close": round(statistics.median(hours), 2) if hours else None,
        "max_hours_to_close": max(hours) if hours else None,
        "oldest_open_age_days": round(max(ages).total_seconds() / 86400, 1) if ages else None,
        "acknowledged_incidents": sum(1 for i in incidents if i.get("acknowledged_time_utc")) if history_read else None,
        # Only incidents whose whole history was read can be known to be unacknowledged.
        "open_unacknowledged": (
            sum(1 for i in open_ if i.get("history_complete") and not i.get("acknowledged_time_utc")) if history_read else None
        ),
        # The backlog older than the history, which open_unacknowledged can't cover: still New and nobody owns it.
        "open_new_unowned_before_history": sum(
            1 for i in open_ if i.get("status") == "New" and not created_in(i, history_from)
            and not (i.get("owner_user_principal_name") or i.get("owner_assigned_to"))
        ),
        "mttd_hours": mean_hours([i.get("hours_to_detect") for i in recent]),
        "mtta_hours": mean_hours([i.get("hours_to_acknowledge") for i in recent]),
        "mttr_hours": mean_hours([i.get("hours_to_close") for i in closed]),
    }


def query_since(client, ws: Dict[str, Any], kql: str, cutoff: datetime) -> List[Dict[str, Any]]:
    """The query's own datetime() bound is cutoff; the API timespan only has to cover it."""
    days = (datetime.now(timezone.utc) - cutoff).days + 1
    return client.query(ws["customer_id"], kql.format(since=cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")), iso_duration_days(days))


def security_incident_query(client, ws: Dict[str, Any], kql: str, cutoff: datetime, label: str, collector, notes: List[str]):
    """(rows, table_exists): rows None when the query failed or the table doesn't exist."""
    try:
        if not ws.get("customer_id"):
            raise LookupError("workspace has no customerId to query")
        return query_since(client, ws, kql, cutoff), True
    except Exception as exc:  # noqa: BLE001
        if table_missing(exc, "SecurityIncident"):
            notes.append("SecurityIncident table does not exist in this workspace; closed times and history unavailable")
            return None, False
        collector.record(f"loganalytics.query({label}, {ws['name']})", exc)
        return None, True


def collect(client, ws: Dict[str, Any], collector) -> Dict[str, Any]:
    days = int_config(LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    listed = collector.guard(
        f"securityinsights.incidents.list({ws['name']})",
        lambda: client.list(
            f"{ws['id']}/providers/Microsoft.SecurityInsights/incidents",
            SI_API,
            {"$top": PAGE_SIZE, "$orderby": "properties/createdTimeUtc desc"},
        ),
    )
    notes: List[str] = []
    if listed is None:
        return {"lookback_days": days, "incidents": None, "notes": notes}
    latest_rows, table_exists = security_incident_query(client, ws, CLOSED_TIME_QUERY, cutoff, "SecurityIncident", collector, notes)
    # No SecurityIncident table means no incident was ever written: close times and history were read and are empty.
    closes_read = latest_rows is not None or not table_exists
    history: Optional[List[Dict[str, Any]]] = None if table_exists else []
    entity_rows: Optional[List[Dict[str, Any]]] = None
    if latest_rows is not None:
        rows, exists = security_incident_query(client, ws, HISTORY_QUERY, cutoff, "SecurityIncident history", collector, notes)
        history = rows if exists else []
    if latest_rows:
        try:
            entity_rows = query_since(client, ws, ENTITIES_QUERY, cutoff)
        except Exception as exc:  # noqa: BLE001
            if table_missing(exc, "SecurityAlert"):
                notes.append("SecurityAlert table does not exist in this workspace; entities unavailable")
            else:
                collector.record(f"loganalytics.query(SecurityAlert entities, {ws['name']})", exc)

    latest = {r.get("IncidentName"): r for r in latest_rows or []}
    closed = {name: r.get("ClosedTime") for name, r in latest.items() if r.get("ClosedTime")}
    rows_by: Dict[str, List[Dict[str, Any]]] = {}
    for r in sorted(history or [], key=lambda r: parse_time(r.get("TimeGenerated")) or now):
        rows_by.setdefault(r.get("IncidentName"), []).append(r)
    retention = collector.guard(
        f"operationalinsights.tables.get(SecurityIncident, {ws['name']})",
        lambda: table_retention_days(client, ws["id"], "SecurityIncident", ws.get("retention_in_days")),
    )
    retained_from = now - timedelta(days=retention) if retention else cutoff
    # The history query reads only the lookback, however long the table keeps rows.
    history_from = max(cutoff, retained_from)
    if retention and retention < days:
        notes.append(
            f"SecurityIncident keeps {retention} days, less than the {days}-day lookback: "
            "close times and update history for incidents last updated before then are not retained"
        )
    entities = incident_entities(entity_rows) if entity_rows is not None else None
    everything = []
    for raw in listed:
        incident = project_incident(raw, closed)
        rows = (rows_by.get(incident["name"]) or []) if history is not None else None
        incident.update(timeline(incident, rows, history_from))
        # Untouched in the lookback: no row says what its tasks are.
        incident["tasks"] = project_tasks(latest[incident["name"]]) if incident["name"] in latest else None
        everything.append(incident)
    incidents = []
    for incident in everything:
        if in_scope(incident, cutoff):
            incident["close_time_status"] = close_time_status(incident, retained_from, closes_read)
            found = (entities or {}).get(incident["name"])
            if found is None and incident.get("alerts_count") == 0:
                found = {"alerts_found": 0, "entities": [], "entities_truncated": False}
            # Alerts older than the lookback, or a refused or missing SecurityAlert, leave entities unknown.
            incident.update(found or {"alerts_found": None, "entities": None, "entities_truncated": None})
            incidents.append(incident)
    incidents.sort(key=lambda i: i.get("created_time_utc") or "", reverse=True)

    # Only the span both sources still hold is comparable.
    compare_from = max(cutoff, retained_from)
    arm_created = sum(1 for i in incidents if (parse_time(i.get("created_time_utc")) or cutoff) >= compare_from)
    kql_rows = latest_rows if latest_rows is not None else ([] if not table_exists else None)
    kql_created = (
        sum(1 for r in kql_rows if (parse_time(r.get("CreatedTime")) or cutoff) >= compare_from) if kql_rows is not None else None
    )
    return {
        "lookback_days": days,
        "security_incident_retention_days": retention,
        "updates_retained_from": history_from.strftime("%Y-%m-%dT%H:%M:%SZ") if history is not None else None,
        "incidents_listed_total": len(listed),
        "incidents": incidents,
        **incident_summary(incidents, now, cutoff, history_from, history is not None, closes_read),
        "monthly": monthly_metrics(everything, incidents, rows_by, cutoff, now, history_from) if history is not None else None,
        **recurrence([i for i in incidents if created_in(i, cutoff)]),
        "completeness": {
            "compared_from": compare_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "arm_created": arm_created,
            "kql_created": kql_created,
            "counts_agree": kql_created == arm_created if kql_created is not None else None,
        },
        "notes": notes,
    }


def _total(workspaces: List[Dict[str, Any]], field: str) -> Optional[int]:
    """Sum over every workspace; None if none was collected or any workspace's value is unknown, its list failing
    included, so a partial count never passes for a whole one."""
    values = [w.get(field) for w in workspaces]
    return None if not values or any(v is None for v in values) else sum(values)


def summarize(workspaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    collected = [w for w in workspaces if w.get("incidents") is not None]
    return {
        "incidents_in_scope": sum(w.get("incidents_in_scope") or 0 for w in collected),
        "open_incidents": sum(w.get("open_incidents") or 0 for w in collected),
        "closed_incidents": sum(w.get("closed_incidents") or 0 for w in collected),
        "closed_missing_close_time": _total(workspaces, "closed_missing_close_time"),
        "closed_close_time_not_retained": _total(workspaces, "closed_close_time_not_retained"),
        "acknowledged_incidents": _total(workspaces, "acknowledged_incidents"),
        "open_unacknowledged": _total(workspaces, "open_unacknowledged"),
        "open_new_unowned_before_history": _total(workspaces, "open_new_unowned_before_history"),
        "recurring_titles": sum(w.get("recurring_titles") or 0 for w in collected),
    }


def main() -> int:
    return run_workspaces(fetcher=NAME, logger=logger, collect=collect, summarize=summarize)


if __name__ == "__main__":
    sys.exit(main())
