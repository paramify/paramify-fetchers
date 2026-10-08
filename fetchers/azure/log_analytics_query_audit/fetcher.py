#!/usr/bin/env python3
"""Log Analytics query auditing per workspace: whether it is on, and who queried the logs in which weeks."""

import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import (  # noqa: E402
    CLIENT_APP,
    DIAG_API,
    LAW_API,
    int_config,
    iso_duration_days,
    parse_time,
    run_workspaces,
    table_missing,
    table_retention_days,
)

NAME = "azure_log_analytics_query_audit"
LOOKBACK_ENV = "QUERY_AUDIT_LOOKBACK_DAYS"
DEFAULT_LOOKBACK_DAYS = 90
AUDIT_GROUPS = frozenset({"audit", "alllogs"})

_BASE = (
    "LAQueryLogs "
    "| where TimeGenerated > ago({days}d) "
    "| where _ResourceId =~ '{workspace_id}' "
    f"| where RequestClientApp != '{CLIENT_APP}' "
)
WEEKLY_QUERY = _BASE + (
    "| extend Actor = iff(isnotempty(AADEmail), 'human', 'application') "
    "| summarize Queries = count(), Users = dcount(AADEmail) by Week = startofweek(TimeGenerated), Actor"
)
USERS_QUERY = _BASE + (
    "| where isnotempty(AADEmail) "
    "| summarize Queries = count(), LastQuery = max(TimeGenerated) by User = AADEmail"
)

logger = logging.getLogger(NAME)


def audit_settings(settings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Diagnostic settings on the workspace that export its Audit category."""
    out = []
    for setting in settings:
        props = setting.get("properties") or {}
        audits = any(
            log.get("enabled") is True
            and ((log.get("category") or "").lower() == "audit" or (log.get("categoryGroup") or "").lower() in AUDIT_GROUPS)
            for log in props.get("logs") or []
        )
        if audits:
            out.append({
                "name": setting.get("name"),
                "workspace_id": props.get("workspaceId"),
                "storage_account_id": props.get("storageAccountId"),
                "event_hub_authorization_rule_id": props.get("eventHubAuthorizationRuleId"),
            })
    return sorted(out, key=lambda s: s["name"] or "")


def week_starts(now: datetime, days: int) -> List[str]:
    """Sunday-midnight week starts covering the window, matching KQL startofweek()."""
    def sunday(d: datetime) -> datetime:
        d = d.replace(hour=0, minute=0, second=0, microsecond=0)
        return d - timedelta(days=(d.weekday() + 1) % 7)

    week, last, out = sunday(now - timedelta(days=days)), sunday(now), []
    while week <= last:
        out.append(week.strftime("%Y-%m-%d"))
        week += timedelta(days=7)
    return out


def weekly_activity(rows: List[Dict[str, Any]], weeks: List[str], retained_from: str) -> List[Dict[str, Any]]:
    """Weeks starting before LAQueryLogs' retention read as unknown, not as weeks nobody queried."""
    by_week = {
        w: {"week_start": w, "retained": w >= retained_from, "human_queries": 0, "human_users": 0, "application_queries": 0}
        for w in weeks
    }
    for row in rows:
        start = parse_time(row.get("Week"))
        key = start.strftime("%Y-%m-%d") if start else None
        if key not in by_week:
            continue
        if row.get("Actor") == "human":
            by_week[key]["human_queries"] = row.get("Queries") or 0
            by_week[key]["human_users"] = row.get("Users") or 0
        else:
            by_week[key]["application_queries"] = row.get("Queries") or 0
    for week in by_week.values():
        if not week["retained"] and not (week["human_queries"] or week["application_queries"]):
            week.update(human_queries=None, human_users=None, application_queries=None)
    return [by_week[w] for w in weeks]


def _destination(client, ws: Dict[str, Any], destination: str) -> Dict[str, Any]:
    if destination.lower() == (ws.get("id") or "").lower():
        return {"customer_id": ws.get("customer_id"), "retention_in_days": ws.get("retention_in_days")}
    props = (client.get(destination, LAW_API) or {}).get("properties") or {}
    return {"customer_id": props.get("customerId"), "retention_in_days": props.get("retentionInDays")}


def collect(client, ws: Dict[str, Any], collector) -> Dict[str, Any]:
    days = int_config(LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS)
    settings = collector.guard(
        f"insights.diagnosticSettings.list({ws['name']})",
        lambda: client.list(f"{ws['id']}/providers/Microsoft.Insights/diagnosticSettings", DIAG_API),
    )
    if settings is None:
        return {"lookback_days": days, "query_auditing_enabled": None}
    audits = audit_settings(settings)
    result: Dict[str, Any] = {
        "lookback_days": days,
        "query_auditing_enabled": bool(audits),
        "audit_settings": audits,
        "weeks": None,
        "users": None,
        "notes": [],
    }
    destination = next((a["workspace_id"] for a in audits if a.get("workspace_id")), None)
    if not destination:
        if audits:
            result["notes"].append("Audit is exported only to storage or Event Hubs; LAQueryLogs is not queryable here")
        return result

    # Rows carry the queried workspace's resource id; a central destination also holds other workspaces' audit.
    scope = {"days": days, "workspace_id": ws["id"]}
    result["audit_destination_workspace_id"] = destination
    weekly = users = retention = None
    try:
        target = _destination(client, ws, destination)
        if not target["customer_id"]:
            raise LookupError(f"no customerId for audit destination {destination}")
        retention = table_retention_days(client, destination, "LAQueryLogs", target["retention_in_days"])
        weekly = client.query(target["customer_id"], WEEKLY_QUERY.format(**scope), iso_duration_days(days))
        users = client.query(target["customer_id"], USERS_QUERY.format(**scope), iso_duration_days(days))
    except Exception as exc:  # noqa: BLE001
        if table_missing(exc, "LAQueryLogs"):
            weekly, users = [], []
            result["notes"].append("LAQueryLogs table does not exist yet in the audit destination workspace")
        else:
            collector.record(f"loganalytics.query(LAQueryLogs, {ws['name']})", exc)
            return result

    now = datetime.now(timezone.utc)
    retained_from = (now - timedelta(days=retention)).strftime("%Y-%m-%d") if retention else "0000-00-00"
    if retention and retention < days:
        result["notes"].append(
            f"LAQueryLogs keeps {retention} days, less than the {days}-day lookback: earlier weeks are not retained"
        )
    weeks = weekly_activity(weekly, week_starts(now, days), retained_from)
    retained = [w for w in weeks if w["retained"]]
    result["laquerylogs_retention_days"] = retention
    result["weeks"] = weeks
    result["users"] = sorted(
        ({"user": u.get("User"), "queries": u.get("Queries"), "last_query": u.get("LastQuery")} for u in users),
        key=lambda u: u["user"] or "",
    )
    result["weeks_in_window"] = len(weeks)
    result["weeks_retained"] = len(retained)
    result["weeks_with_human_queries"] = sum(1 for w in weeks if (w["human_queries"] or 0) > 0)
    result["weeks_without_human_queries"] = [w["week_start"] for w in retained if w["human_queries"] == 0]
    result["weeks_not_retained"] = [w["week_start"] for w in weeks if not w["retained"]]
    result["distinct_human_users"] = len(result["users"])
    return result


def summarize(workspaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "workspaces_with_query_auditing": sum(1 for w in workspaces if w.get("query_auditing_enabled") is True),
        "workspaces_without_query_auditing": sum(1 for w in workspaces if w.get("query_auditing_enabled") is False),
        "sentinel_workspaces": sum(1 for w in workspaces if w.get("sentinel_onboarded") is True),
    }


def main() -> int:
    return run_workspaces(fetcher=NAME, logger=logger, collect=collect, summarize=summarize, sentinel_only=False)


if __name__ == "__main__":
    sys.exit(main())
