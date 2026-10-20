#!/usr/bin/env python3
"""Every Azure Monitor alert fired in the last 30 days, who acknowledged and closed it, and how often each alert rule fired."""

import logging
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from statistics import median

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    basename,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    sanitize_for_filename,
    sorted_counts,
    write_evidence,
)
from azure_rest import AzureRestClient, parse_time  # noqa: E402

logger = logging.getLogger("azure_monitor_fired_alerts")

ALERTS_API = "2019-05-05-preview"
# Azure keeps fired alerts for 30 days; the list defaults to 1 day when timeRange is omitted.
TIME_RANGE = "30d"
WINDOW_DAYS = 30
PAGE_COUNT = "250"
WORKERS = 4

RULE_SOURCES = (
    ("metric", "Microsoft.Insights", "Microsoft.Insights/metricAlerts", "2018-03-01"),
    ("log_search", "Microsoft.Insights", "Microsoft.Insights/scheduledQueryRules", "2023-12-01"),
    ("smart_detector", "Microsoft.AlertsManagement", "Microsoft.AlertsManagement/smartDetectorAlertRules", "2021-04-01"),
    ("activity_log", "Microsoft.Insights", "Microsoft.Insights/activityLogAlerts", "2020-10-01"),
)
RULE_TYPE_BY_PROVIDER = {path.lower(): rule_type for rule_type, _, path, _ in RULE_SOURCES}

HISTORY_READ = "read"
HISTORY_NOT_FOUND = "not_found"
HISTORY_NOT_AUTHORIZED = "not_authorized"
HISTORY_ERROR = "error"
STATE_CLOSED = "closed"
STATE_ACKNOWLEDGED = "acknowledged"
SYSTEM_ACTOR = "system"
# Unknown, not 0, when the alert list was not read.
ALERT_COUNTS = (
    "alerts_fired", "all_alerts_listed", "alerts_by_state", "alerts_by_monitor_condition", "alerts_by_severity",
    "alerts_by_monitor_service", "alerts_by_rule_type", "alerts_open", "alerts_acknowledged", "alerts_closed",
    "alerts_closed_by_person", "alerts_with_notifications", "alerts_with_failed_notifications",
    "alerts_with_actions_suppressed", "median_hours_to_close", "max_hours_to_close", "oldest_open_alert_fired_at",
    "alert_histories_read", "alert_histories_unread",
)


# --- pure transforms ---

def rule_type_of(rule_id):
    """metric / log_search / smart_detector / activity_log from the rule id's provider type; None without a rule."""
    if not rule_id:
        return None
    parts = rule_id.split("/")
    lowered = [p.lower() for p in parts]
    if "providers" not in lowered:
        return "other"
    i = len(lowered) - 1 - lowered[::-1].index("providers")
    return RULE_TYPE_BY_PROVIDER.get("/".join(lowered[i + 1:i + 3]), "other")


def alert_record(raw: dict) -> dict:
    e = (raw.get("properties") or {}).get("essentials") or {}
    rule_id = e.get("alertRule") or None
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "alert_rule_id": rule_id,
        "alert_rule_name": basename(rule_id) if rule_id else None,
        "rule_type": rule_type_of(rule_id),
        "severity": e.get("severity"),
        "signal_type": e.get("signalType"),
        "monitor_service": e.get("monitorService"),
        "monitor_condition": e.get("monitorCondition"),
        "alert_state": e.get("alertState"),
        "target_resource": e.get("targetResource"),
        "target_resource_name": e.get("targetResourceName"),
        "target_resource_type": (e.get("targetResourceType") or "").lower() or None,
        "target_resource_group": e.get("targetResourceGroup"),
        "fired_at": e.get("startDateTime"),
        "resolved_at": e.get("monitorConditionResolvedDateTime"),
        "last_modified_at": e.get("lastModifiedDateTime"),
        "last_modified_by": e.get("lastModifiedUserName"),
        "actions_suppressed": (e.get("actionStatus") or {}).get("isSuppressed"),
        "description": e.get("description") or None,
    }


def modification(raw: dict) -> dict:
    return {
        "event": raw.get("modificationEvent"),
        "old_value": raw.get("oldValue") or None,
        "new_value": raw.get("newValue") or None,
        "at": raw.get("modifiedAt"),
        "by": raw.get("modifiedBy") or None,
        "comments": raw.get("comments") or None,
        "description": raw.get("description") or None,
    }


def _hours(start, end):
    a, b = parse_time(start), parse_time(end)
    return round((b - a).total_seconds() / 3600, 2) if a and b else None


def _by_person(actor):
    return None if not actor else actor.lower() != SYSTEM_ACTOR


def _state_changes(mods: list[dict], state: str) -> list[dict]:
    return [m for m in mods if m["event"] == "StateChange" and (m["new_value"] or "").lower() == state]


def with_history(alert: dict, status: str, raw_mods=None) -> dict:
    """Unread history leaves every derived field null, never "nobody acknowledged"."""
    read = status == HISTORY_READ
    mods = sorted(
        (modification(m) for m in raw_mods or []),
        key=lambda m: (parse_time(m["at"]) is None, parse_time(m["at"]) or 0, m["event"] or ""),
    ) if read else None
    acks = _state_changes(mods, STATE_ACKNOWLEDGED) if read else []
    # A reopened alert's earlier close does not count; only the close that left it Closed.
    closes = _state_changes(mods, STATE_CLOSED) if read and (alert["alert_state"] or "").lower() == STATE_CLOSED else []
    ack, close = (acks[0] if acks else None), (closes[-1] if closes else None)

    def count(event):
        return sum(1 for m in mods if m["event"] == event) if read else None

    return {
        **alert,
        "history_status": status,
        "history": mods,
        "acknowledged_at": ack["at"] if ack else None,
        "acknowledged_by": ack["by"] if ack else None,
        "closed_at": close["at"] if close else None,
        "closed_by": close["by"] if close else None,
        "closed_by_person": _by_person(close["by"]) if close else None,
        "hours_to_acknowledge": _hours(alert["fired_at"], ack["at"]) if ack else None,
        "hours_to_close": _hours(alert["fired_at"], close["at"]) if close else None,
        "actions_triggered": count("ActionsTriggered"),
        "actions_failed": count("ActionsFailed"),
    }


def rule_record(rule_type: str, raw: dict) -> dict:
    props = raw.get("properties") or {}
    enabled = (
        (props.get("state") or "").lower() == "enabled" if rule_type == "smart_detector" and props.get("state")
        else props.get("enabled")
    )
    return {
        "id": raw.get("id"),
        "name": raw.get("name") or basename(raw.get("id")),
        "rule_type": rule_type,
        "enabled": enabled if isinstance(enabled, bool) else None,
    }


def _latest(times):
    parsed = [(parse_time(t), t) for t in times if t]
    parsed = [p for p in parsed if p[0] is not None]
    return max(parsed)[1] if parsed else None


def _fires(alerts: list[dict], read: bool = True) -> dict:
    if not read:
        return {"fire_count": None, "last_fired_at": None, "open_alerts": None}
    return {
        "fire_count": len(alerts),
        "last_fired_at": _latest(a["fired_at"] for a in alerts),
        "open_alerts": sum(1 for a in alerts if (a["alert_state"] or "").lower() != STATE_CLOSED),
    }


def rule_activity(rules: list[dict], alerts: list[dict], alerts_read: bool = True) -> list[dict]:
    """Every listed rule with its fires, plus rules that fired but are not in the subscription's lists."""
    fired: dict = {}
    for a in alerts:
        if a["alert_rule_id"]:
            fired.setdefault(a["alert_rule_id"].lower(), []).append(a)
    out, listed = [], set()
    for rule in rules:
        key = (rule["id"] or "").lower()
        listed.add(key)
        out.append({**rule, "listed": True, **_fires(fired.get(key, []), alerts_read)})
    for key, group in fired.items():
        if key not in listed:
            first = group[0]
            out.append({
                "id": first["alert_rule_id"], "name": first["alert_rule_name"], "rule_type": first["rule_type"],
                "enabled": None, "listed": False, **_fires(group),
            })
    return sorted(out, key=lambda r: (r["id"] or "").lower())


def summarize(alerts: list[dict], rules: list[dict], summary_total, alerts_read: bool = True) -> dict:
    closed = [a for a in alerts if (a["alert_state"] or "").lower() == STATE_CLOSED]
    # A count over histories is unknown, never a partial number, while any history is unread.
    histories_read = all(a["history_status"] == HISTORY_READ for a in alerts)

    def from_histories(n):
        return n if histories_read else None

    open_alerts = [a for a in alerts if (a["alert_state"] or "").lower() != STATE_CLOSED]
    close_hours = [a["hours_to_close"] for a in closed if a["hours_to_close"] is not None]
    listed = [r for r in rules if r["listed"]]
    summary = {
        "window_days": WINDOW_DAYS,
        "alerts_fired": len(alerts),
        "alerts_summary_total": summary_total,
        "all_alerts_listed": (len(alerts) >= summary_total) if summary_total is not None else None,
        "alerts_by_state": sorted_counts(Counter(a["alert_state"] or "unknown" for a in alerts)),
        "alerts_by_monitor_condition": sorted_counts(Counter(a["monitor_condition"] or "unknown" for a in alerts)),
        "alerts_by_severity": sorted_counts(Counter(a["severity"] or "unknown" for a in alerts)),
        "alerts_by_monitor_service": sorted_counts(Counter(a["monitor_service"] or "unknown" for a in alerts)),
        "alerts_by_rule_type": sorted_counts(Counter(a["rule_type"] or "none" for a in alerts)),
        "alerts_open": len(open_alerts),
        "alerts_acknowledged": from_histories(sum(
            1 for a in alerts if a["acknowledged_at"] or (a["alert_state"] or "").lower() == STATE_ACKNOWLEDGED
        )),
        "alerts_closed": len(closed),
        "alerts_closed_by_person": from_histories(sum(1 for a in closed if a["closed_by_person"])),
        "alerts_with_notifications": from_histories(sum(1 for a in alerts if a["actions_triggered"])),
        "alerts_with_failed_notifications": from_histories(sum(1 for a in alerts if a["actions_failed"])),
        "alerts_with_actions_suppressed": sum(1 for a in alerts if a["actions_suppressed"]),
        "median_hours_to_close": round(median(close_hours), 2) if close_hours else None,
        "max_hours_to_close": max(close_hours) if close_hours else None,
        "oldest_open_alert_fired_at": min(
            (a["fired_at"] for a in open_alerts if parse_time(a["fired_at"])), key=parse_time, default=None
        ),
        "alert_histories_read": sum(1 for a in alerts if a["history_status"] == HISTORY_READ),
        "alert_histories_unread": sum(1 for a in alerts if a["history_status"] != HISTORY_READ),
        "alert_rules_listed": len(listed),
        "alert_rules_by_type": sorted_counts(Counter(r["rule_type"] for r in listed)),
        "enabled_alert_rules": sum(1 for r in listed if r["enabled"]),
        "rules_that_fired": sum(1 for r in rules if r["fire_count"]) if alerts_read else None,
        "enabled_rules_never_fired": (
            sum(1 for r in listed if r["enabled"] and not r["fire_count"]) if alerts_read else None
        ),
        "rules_fired_not_listed": sum(1 for r in rules if not r["listed"]) if alerts_read else None,
    }
    return summary if alerts_read else {**summary, **dict.fromkeys(ALERT_COUNTS, None)}


def history_status(exc: BaseException) -> str:
    message = str(exc).lower()
    status = getattr(exc, "status", None)
    if status == 404 or "notfound" in message:
        return HISTORY_NOT_FOUND
    if status in (401, 403) or "authorizationfailed" in message or "forbidden" in message:
        return HISTORY_NOT_AUTHORIZED
    return HISTORY_ERROR


# --- collection ---

def read_history(client, alert: dict, collector: Collector) -> dict:
    try:
        body = client.get(f"{alert['id']}/history", ALERTS_API)
    except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
        status = history_status(exc)
        if status == HISTORY_ERROR:
            collector.record(f"alertsManagement.alerts.history ({alert['id']})", exc)
        else:
            logger.warning("alert history %s: %s (%s)", alert["id"], status, exc)
        return with_history(alert, status)
    return with_history(alert, HISTORY_READ, (body.get("properties") or {}).get("modifications"))


def collect_alerts(client, subscription_id: str, collector: Collector) -> tuple:
    base = f"/subscriptions/{subscription_id}/providers/Microsoft.AlertsManagement"
    summary = collector.guard(
        "alertsManagement.alertsSummary",
        lambda: client.get(f"{base}/alertsSummary?groupby=alertState&timeRange={TIME_RANGE}", ALERTS_API),
    )
    total = ((summary or {}).get("properties") or {}).get("total")
    raw = collector.guard(
        "alertsManagement.alerts.list",
        lambda: client.list(f"{base}/alerts", ALERTS_API, {"timeRange": TIME_RANGE, "pageCount": PAGE_COUNT}),
    )
    alerts = [alert_record(a) for a in raw or []]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        alerts = list(pool.map(lambda a: read_history(client, a, collector), alerts))
    return alerts, total if isinstance(total, int) else None, raw is not None


def collect_rules(client, subscription_id: str, registration: dict, collector: Collector) -> list[dict]:
    rules = []
    for rule_type, namespace, path, api in RULE_SOURCES:
        if registration[namespace] == NOT_REGISTERED:
            continue
        listed = collector.guard(
            f"{path} list",
            lambda path=path, api=api: client.list(f"/subscriptions/{subscription_id}/providers/{path}", api),
        )
        rules.extend(rule_record(rule_type, r) for r in listed or [])
    return rules


def collect(client, subscription_id: str, registration: dict, collector: Collector) -> tuple:
    """(alerts, rules, summary total, whether the alert list was read)."""
    alerts: list[dict] = []
    total, alerts_read = None, False
    if registration["Microsoft.AlertsManagement"] != NOT_REGISTERED:
        alerts, total, alerts_read = collect_alerts(client, subscription_id, collector)
    rules = rule_activity(collect_rules(client, subscription_id, registration, collector), alerts, alerts_read)
    return alerts, rules, total, alerts_read


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

    alerts: list[dict] = []
    rules: list[dict] = []
    total, alerts_read = None, False
    registration = {ns: REGISTRATION_UNKNOWN for ns in ("Microsoft.AlertsManagement", "Microsoft.Insights")}
    if subscription_id and cred is not None:
        for ns in registration:
            registration[ns] = provider_registration_status(collector, subscription_id, cred, ns)
        alerts, rules, total, alerts_read = collect(AzureRestClient(cred), subscription_id, registration, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    alerts.sort(key=lambda a: (a["fired_at"] or "", (a["id"] or "").lower()))
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "alerts": alerts,
            "alert_rules": rules,
            "time_range": TIME_RANGE,
            "provider_registration_status": registration,
        },
        summary={**summarize(alerts, rules, total, alerts_read), "provider_registration_status": registration},
    )

    filename = f"azure_monitor_fired_alerts_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)
    logger.info("Evidence saved to %s (%d alerts)", path, len(alerts))

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
