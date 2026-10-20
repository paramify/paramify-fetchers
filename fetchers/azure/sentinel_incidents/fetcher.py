#!/usr/bin/env python3
"""Microsoft Sentinel incidents per workspace: status, owner, response timeline, entities, and monthly detection, acknowledgement and close times."""

import json
import logging
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
# Changes an automation rule or the Defender XDR sync made: not a person acknowledging the incident.
SYSTEM_MODIFIERS = ("Automation rule", "Microsoft XDR", "Microsoft Defender XDR", "Microsoft 365 Defender")

# The ARM incident has no close time or change history; SecurityIncident holds one row per update.
CLOSED_TIME_QUERY = (
    "SecurityIncident "
    "| where TimeGenerated > ago({days}d) "
    "| summarize arg_max(TimeGenerated, Status, ClosedTime, CreatedTime, Tasks) by IncidentName "
    "| project IncidentName, Status, ClosedTime, CreatedTime, Tasks"
)
HISTORY_QUERY = (
    "SecurityIncident "
    "| where TimeGenerated > ago({days}d) "
    "| project TimeGenerated, IncidentName, Status, Severity, ClosedTime, ModifiedBy, "
    "OwnerId = tostring(Owner.objectId), "
    "Owner = coalesce(tostring(Owner.userPrincipalName), tostring(Owner.assignedTo), tostring(Owner.email))"
)
ENTITIES_QUERY = (
    "SecurityIncident "
    "| where TimeGenerated > ago({days}d) "
    "| summarize arg_max(TimeGenerated, AlertIds) by IncidentName "
    "| mv-expand AlertId = AlertIds to typeof(string) "
    "| join kind=inner (SecurityAlert | where TimeGenerated > ago({days}d) "
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
    "mailCluster": ("ClusterByValue", "Query"),
    "cloud-application": ("Name", "AppId"),
    "azure-resource": ("ResourceId",),
    "dns": ("DomainName",),
    "registry-key": ("Key",),
    "registry-value": ("Name",),
    "malware": ("Name",),
    "security-group": ("DistinguishedName", "ObjectGuid"),
}
GENERIC_ID_FIELDS = ("Name", "DisplayName", "Address", "Value", "Id")

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
        "provider_incident_url": strip_url(extra["providerIncidentUrl"]) if extra.get("providerIncidentUrl") else None,
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


def close_time_status(incident: Dict[str, Any], retained_from: datetime) -> Optional[str]:
    """found, missing, or not_retained: last touched before SecurityIncident's retention, so its close record is gone."""
    if incident.get("status") != "Closed":
        return None
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


def acknowledged_time(rows: List[Dict[str, Any]], complete: bool) -> Optional[str]:
    """First update by a person that moved the incident to Active or gave it an owner; never the creation row."""
    if not complete and rows and (rows[0].get("Status") == "Active" or owned(rows[0])):
        return None  # already acknowledged before the oldest retained update, at an unknown time
    for before, row in zip(rows, rows[1:]):
        if (row.get("ModifiedBy") or "").startswith(SYSTEM_MODIFIERS):
            continue
        activated = row.get("Status") == "Active" and before.get("Status") != "Active"
        assigned = owned(row) and (row.get("OwnerId"), row.get("Owner")) != (before.get("OwnerId"), before.get("Owner"))
        if activated or assigned:
            return row.get("TimeGenerated")
    return None


def project_tasks(row: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {"title": t.get("title"), "status": t.get("status"), "created_time_utc": t.get("createdTimeUtc"),
         "completed_time_utc": t.get("lastCompletedTimeUtc") if t.get("status") == "Completed" else None}
        for t in as_list((row or {}).get("Tasks")) if isinstance(t, dict)
    ]


def timeline(incident: Dict[str, Any], rows: Optional[List[Dict[str, Any]]], history_from: datetime) -> Dict[str, Any]:
    """From the updates read since history_from; all None when no history could be read."""
    if rows is None:
        return {k: None for k in ("acknowledged_time_utc", "hours_to_acknowledge", "status_changes", "owner_changes",
                                  "severity_changes", "updates_retained", "history_complete")}
    created = parse_time(incident.get("created_time_utc"))
    complete = created is not None and created >= history_from
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


def strip_url(url: str) -> str:
    """Scheme, host and path only, so query strings (SAS tokens) and user:password@ never reach the evidence."""
    parts = urlsplit(url)
    host = parts.netloc.rsplit("@", 1)[-1]
    if parts.scheme and host:
        return f"{parts.scheme}://{host}{parts.path}"
    return url.split("#", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1]


def entity_id(entity: Dict[str, Any], by_ref: Optional[Dict[str, Dict[str, Any]]] = None) -> Optional[str]:
    """A short identifier; never a process's command line or a URL's query string."""
    kind = entity.get("Type")
    if kind == "account" and entity.get("Name") and entity.get("UPNSuffix") and not entity.get("UserPrincipalName"):
        return f"{entity['Name']}@{entity['UPNSuffix']}"
    if kind == "process":
        image = entity.get("ImageFile") or {}
        image = (by_ref or {}).get(image.get("$ref"), image) if isinstance(image, dict) else {}
        name, pid = image.get("Name"), entity.get("ProcessId")
        return f"{name} ({pid})" if name and pid else (name or (f"process {pid}" if pid else None))
    if kind == "url":
        return strip_url(str(entity["Url"])) if entity.get("Url") else None
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
    everything: List[Dict[str, Any]], rows_by: Dict[str, List[Dict[str, Any]]],
    cutoff: datetime, now: datetime, history_from: datetime,
) -> List[Dict[str, Any]]:
    """Per calendar month of the lookback: MTTD by month created, MTTA by month acknowledged, MTTR by month closed, and the open backlog at month end."""
    times = {
        field: [(parse_time(i.get(field)), i) for i in everything]
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


def incident_summary(incidents: List[Dict[str, Any]], now: datetime, cutoff: datetime, history_read: bool) -> Dict[str, Any]:
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
        "closed_missing_close_time": sum(1 for i in closed if i.get("close_time_status") == "missing"),
        "closed_close_time_not_retained": sum(1 for i in closed if i.get("close_time_status") == "not_retained"),
        "median_hours_to_close": round(statistics.median(hours), 2) if hours else None,
        "max_hours_to_close": max(hours) if hours else None,
        "oldest_open_age_days": round(max(ages).total_seconds() / 86400, 1) if ages else None,
        "acknowledged_incidents": sum(1 for i in incidents if i.get("acknowledged_time_utc")) if history_read else None,
        "open_unacknowledged": sum(
            1 for i in open_ if i.get("status") == "New" and not (i.get("owner_user_principal_name") or i.get("owner_assigned_to"))
        ),
        "mttd_hours": mean_hours([i.get("hours_to_detect") for i in recent]),
        "mtta_hours": mean_hours([i.get("hours_to_acknowledge") for i in recent]),
        "mttr_hours": mean_hours([i.get("hours_to_close") for i in closed]),
    }


def security_incident_query(client, ws: Dict[str, Any], kql: str, days: int, label: str, collector, notes: List[str]):
    """(rows, table_exists): rows None when the query failed or the table doesn't exist."""
    try:
        if not ws.get("customer_id"):
            raise LookupError("workspace has no customerId to query")
        return client.query(ws["customer_id"], kql.format(days=days), iso_duration_days(days)), True
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
    latest_rows, table_exists = security_incident_query(client, ws, CLOSED_TIME_QUERY, days, "SecurityIncident", collector, notes)
    history: Optional[List[Dict[str, Any]]] = None
    entity_rows: Optional[List[Dict[str, Any]]] = None
    if latest_rows is not None:
        history, _ = security_incident_query(client, ws, HISTORY_QUERY, days, "SecurityIncident history", collector, notes)
    if latest_rows and listed is not None:
        try:
            entity_rows = client.query(ws["customer_id"], ENTITIES_QUERY.format(days=days), iso_duration_days(days))
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
    if listed is None:
        return {"lookback_days": days, "incidents": None, "notes": notes}
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
            incident["close_time_status"] = close_time_status(incident, retained_from)
            found = (entities or {}).get(incident["name"])
            if found is None and entities is not None and incident.get("alerts_count") == 0:
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
        **incident_summary(incidents, now, cutoff, history is not None),
        "monthly": monthly_metrics(everything, rows_by, cutoff, now, history_from) if history is not None else None,
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
    """Sum over the workspaces that have the field; None when none does, so an unread history never reads as zero."""
    values = [w[field] for w in workspaces if w.get(field) is not None]
    return sum(values) if values else None


def summarize(workspaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    collected = [w for w in workspaces if w.get("incidents") is not None]
    return {
        "incidents_in_scope": sum(w.get("incidents_in_scope") or 0 for w in collected),
        "open_incidents": sum(w.get("open_incidents") or 0 for w in collected),
        "closed_incidents": sum(w.get("closed_incidents") or 0 for w in collected),
        "closed_missing_close_time": sum(w.get("closed_missing_close_time") or 0 for w in collected),
        "closed_close_time_not_retained": sum(w.get("closed_close_time_not_retained") or 0 for w in collected),
        "acknowledged_incidents": _total(collected, "acknowledged_incidents"),
        "open_unacknowledged": sum(w.get("open_unacknowledged") or 0 for w in collected),
        "recurring_titles": sum(w.get("recurring_titles") or 0 for w in collected),
    }


def main() -> int:
    return run_workspaces(fetcher=NAME, logger=logger, collect=collect, summarize=summarize)


if __name__ == "__main__":
    sys.exit(main())
