#!/usr/bin/env python3
"""Microsoft Sentinel incidents per workspace: status, classification, owner, and how long closed ones took to close."""

import logging
import statistics
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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

# The ARM incident has no close timestamp; SecurityIncident carries one per update.
CLOSED_TIME_QUERY = (
    "SecurityIncident "
    "| where TimeGenerated > ago({days}d) "
    "| summarize arg_max(TimeGenerated, Status, ClosedTime, CreatedTime) by IncidentName "
    "| project IncidentName, Status, ClosedTime, CreatedTime"
)

logger = logging.getLogger(NAME)


def hours_between(start: Optional[datetime], end: Optional[datetime]) -> Optional[float]:
    if not start or not end:
        return None
    return round((end - start).total_seconds() / 3600, 2)


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
        "owner_assigned_to": owner.get("assignedTo"),
        "owner_user_principal_name": owner.get("userPrincipalName"),
        "created_time_utc": created,
        "first_activity_time_utc": props.get("firstActivityTimeUtc"),
        "last_modified_time_utc": props.get("lastModifiedTimeUtc"),
        "closed_time_utc": closed_time,
        "hours_to_close": hours_between(parse_time(created), parse_time(closed_time)),
        "provider_name": props.get("providerName"),
        "related_analytic_rules": len(props.get("relatedAnalyticRuleIds") or []),
        "alerts_count": extra.get("alertsCount"),
    }


def in_scope(incident: Dict[str, Any], cutoff: datetime) -> bool:
    """Created inside the lookback, or still open however old it is."""
    created = parse_time(incident.get("created_time_utc"))
    return incident.get("status") in OPEN_STATUSES or (created is not None and created >= cutoff)


def close_time_status(incident: Dict[str, Any], retained_from: datetime) -> Optional[str]:
    """found, missing, or not_retained: last touched before SecurityIncident's retention, so its close record is gone."""
    if incident.get("status") != "Closed":
        return None
    if incident.get("closed_time_utc"):
        return "found"
    touched = parse_time(incident.get("last_modified_time_utc")) or parse_time(incident.get("created_time_utc"))
    return "not_retained" if touched is not None and touched < retained_from else "missing"


def incident_summary(incidents: List[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    open_ = [i for i in incidents if i.get("status") in OPEN_STATUSES]
    closed = [i for i in incidents if i.get("status") == "Closed"]
    hours = [i["hours_to_close"] for i in closed if i.get("hours_to_close") is not None]
    open_by_severity: Dict[str, int] = {}
    for i in open_:
        open_by_severity[i.get("severity") or "unknown"] = open_by_severity.get(i.get("severity") or "unknown", 0) + 1
    ages = [now - c for c in (parse_time(i.get("created_time_utc")) for i in open_) if c]
    return {
        "incidents_in_scope": len(incidents),
        "open_incidents": len(open_),
        "open_by_severity": dict(sorted(open_by_severity.items())),
        "closed_incidents": len(closed),
        "closed_undetermined": sum(1 for i in closed if (i.get("classification") or "Undetermined") == "Undetermined"),
        "closed_missing_close_time": sum(1 for i in closed if i.get("close_time_status") == "missing"),
        "closed_close_time_not_retained": sum(1 for i in closed if i.get("close_time_status") == "not_retained"),
        "median_hours_to_close": round(statistics.median(hours), 2) if hours else None,
        "max_hours_to_close": max(hours) if hours else None,
        "oldest_open_age_days": round(max(ages).total_seconds() / 86400, 1) if ages else None,
    }


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
    rows: Optional[List[Dict[str, Any]]] = None
    try:
        if not ws.get("customer_id"):
            raise LookupError("workspace has no customerId to query")
        rows = client.query(ws["customer_id"], CLOSED_TIME_QUERY.format(days=days), iso_duration_days(days))
    except Exception as exc:  # noqa: BLE001
        if table_missing(exc, "SecurityIncident"):
            rows = []
            notes.append("SecurityIncident table does not exist in this workspace; closed times unavailable")
        else:
            collector.record(f"loganalytics.query(SecurityIncident, {ws['name']})", exc)

    closed = {r.get("IncidentName"): r.get("ClosedTime") for r in rows or [] if r.get("ClosedTime")}
    if listed is None:
        return {"lookback_days": days, "incidents": None, "notes": notes}
    retention = collector.guard(
        f"operationalinsights.tables.get(SecurityIncident, {ws['name']})",
        lambda: table_retention_days(client, ws["id"], "SecurityIncident", ws.get("retention_in_days")),
    )
    retained_from = now - timedelta(days=retention) if retention else cutoff
    if retention and retention < days:
        notes.append(
            f"SecurityIncident keeps {retention} days, less than the {days}-day lookback: "
            "close times for incidents last updated before then are not retained"
        )
    incidents = []
    for raw in listed:
        incident = project_incident(raw, closed)
        if in_scope(incident, cutoff):
            incident["close_time_status"] = close_time_status(incident, retained_from)
            incidents.append(incident)
    incidents.sort(key=lambda i: i.get("created_time_utc") or "", reverse=True)

    # Only the span both sources still hold is comparable.
    compare_from = max(cutoff, retained_from)
    arm_created = sum(1 for i in incidents if (parse_time(i.get("created_time_utc")) or cutoff) >= compare_from)
    kql_created = (
        sum(1 for r in rows if (parse_time(r.get("CreatedTime")) or cutoff) >= compare_from) if rows is not None else None
    )
    return {
        "lookback_days": days,
        "security_incident_retention_days": retention,
        "incidents_listed_total": len(listed),
        "incidents": incidents,
        **incident_summary(incidents, now),
        "completeness": {
            "compared_from": compare_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "arm_created": arm_created,
            "kql_created": kql_created,
            "counts_agree": kql_created == arm_created if kql_created is not None else None,
        },
        "notes": notes,
    }


def summarize(workspaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    collected = [w for w in workspaces if w.get("incidents") is not None]
    return {
        "incidents_in_scope": sum(w.get("incidents_in_scope") or 0 for w in collected),
        "open_incidents": sum(w.get("open_incidents") or 0 for w in collected),
        "closed_incidents": sum(w.get("closed_incidents") or 0 for w in collected),
        "closed_missing_close_time": sum(w.get("closed_missing_close_time") or 0 for w in collected),
        "closed_close_time_not_retained": sum(w.get("closed_close_time_not_retained") or 0 for w in collected),
    }


def main() -> int:
    return run_workspaces(fetcher=NAME, logger=logger, collect=collect, summarize=summarize)


if __name__ == "__main__":
    sys.exit(main())
