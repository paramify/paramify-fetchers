"""azure_monitor_fired_alerts: alert projection, state history, rule fire counts. Synthetic payloads, no SDK or network."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_monitor_fired_alerts_under_test", AZURE / "monitor_fired_alerts" / "fetcher.py")
fa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fa)
azure_rest = sys.modules["azure_rest"]

SUB = "/subscriptions/s1"
RG = f"{SUB}/resourceGroups/rg1"
METRIC_RULE = f"{RG}/providers/Microsoft.Insights/metricAlerts/cpu-high"
LOG_RULE = f"{RG}/providers/microsoft.insights/scheduledqueryrules/failed-logins"
SMART_RULE = f"{RG}/providers/microsoft.alertsmanagement/smartDetectorAlertRules/Failure Anomalies - app"
ACTIVITY_RULE = f"{RG}/providers/microsoft.insights/activityLogAlerts/nsg-change"
FAR_RULE = "/subscriptions/s2/resourceGroups/rg/providers/Microsoft.Insights/metricAlerts/elsewhere"


def raw_alert(n, rule=METRIC_RULE, state="New", condition="Fired", fired="2026-10-10T10:00:00Z", **extra):
    essentials = {
        "severity": "Sev2", "signalType": "Metric", "monitorService": "Platform", "monitorCondition": condition,
        "alertState": state, "targetResource": f"{RG}/providers/Microsoft.Web/sites/app1", "targetResourceName": "app1",
        "targetResourceType": "Microsoft.Web/sites", "targetResourceGroup": "rg1", "startDateTime": fired,
        "lastModifiedDateTime": fired, "lastModifiedUserName": "System", "actionStatus": {"isSuppressed": False},
        "description": "", **extra,
    }
    if rule:
        essentials["alertRule"] = rule
    return {"id": f"{SUB}/providers/Microsoft.AlertsManagement/alerts/a{n}", "name": f"alert {n}",
            "properties": {"essentials": essentials}}


def mod(event, at, by="System", old="", new=""):
    return {"modificationEvent": event, "oldValue": old, "newValue": new, "modifiedAt": at, "modifiedBy": by,
            "comments": "", "description": f"{event}"}


def alert(n=1, status=fa.HISTORY_READ, mods=(), **kwargs):
    return fa.with_history(fa.alert_record(raw_alert(n, **kwargs)), status, list(mods))


@pytest.mark.parametrize("rule_id, rule_type", [
    (METRIC_RULE, "metric"),
    (LOG_RULE, "log_search"),
    (SMART_RULE, "smart_detector"),
    (ACTIVITY_RULE, "activity_log"),
    (f"{RG}/providers/Microsoft.AlertsManagement/prometheusRuleGroups/g", "other"),
    ("Backup", "builtin"),
    ("ServiceHealth", "builtin"),
    (None, None),
    ("", None),
])
def test_rule_type_comes_from_the_rule_ids_provider(rule_id, rule_type):
    assert fa.rule_type_of(rule_id) == rule_type


def test_alert_projection_reads_essentials():
    record = fa.alert_record(raw_alert(1, condition="Resolved", monitorConditionResolvedDateTime="2026-10-10T11:00:00Z"))
    assert {k: record[k] for k in ("alert_rule_name", "rule_type", "severity", "monitor_condition", "alert_state",
                                   "target_resource_type", "fired_at", "resolved_at", "actions_suppressed",
                                   "description")} == {
        "alert_rule_name": "cpu-high", "rule_type": "metric", "severity": "Sev2", "monitor_condition": "Resolved",
        "alert_state": "New", "target_resource_type": "microsoft.web/sites", "fired_at": "2026-10-10T10:00:00Z",
        "resolved_at": "2026-10-10T11:00:00Z", "actions_suppressed": False, "description": None}


def test_built_in_alert_has_no_rule():
    record = fa.alert_record(raw_alert(1, rule=None))
    assert (record["alert_rule_id"], record["alert_rule_name"], record["rule_type"]) == (None, None, None)


def test_history_gives_who_acknowledged_and_closed_and_when():
    record = alert(state="Closed", mods=[
        mod("AlertCreated", "2026-10-10T10:00:00Z"),
        mod("ActionsTriggered", "2026-10-10T10:00:01Z"),
        mod("StateChange", "2026-10-10T12:30:00.1234567Z", by="ops@example.com", old="New", new="Acknowledged"),
        mod("StateChange", "2026-10-11T10:00:00Z", by="lead@example.com", old="Acknowledged", new="Closed"),
    ])
    assert {k: record[k] for k in ("acknowledged_at", "acknowledged_by", "closed_at", "closed_by", "closed_by_person",
                                   "hours_to_acknowledge", "hours_to_close", "actions_triggered", "actions_failed")} == {
        "acknowledged_at": "2026-10-10T12:30:00.1234567Z", "acknowledged_by": "ops@example.com",
        "closed_at": "2026-10-11T10:00:00Z", "closed_by": "lead@example.com", "closed_by_person": True,
        "hours_to_acknowledge": 2.5, "hours_to_close": 24.0, "actions_triggered": 1, "actions_failed": 0}
    assert [m["event"] for m in record["history"]][0] == "AlertCreated"


def test_history_is_ordered_oldest_first_whatever_the_api_order():
    record = alert(state="Closed", mods=[
        mod("StateChange", "2026-10-11T10:00:00Z", by="b@example.com", new="Closed"),
        mod("StateChange", "2026-10-10T11:00:00Z", by="a@example.com", new="Closed"),
        mod("StateChange", "2026-10-10T12:00:00Z", by="a@example.com", new="New"),
    ])
    assert (record["closed_by"], record["closed_at"]) == ("b@example.com", "2026-10-11T10:00:00Z")


def test_close_does_not_count_once_the_alert_is_reopened():
    record = alert(state="New", mods=[mod("StateChange", "2026-10-10T11:00:00Z", by="a@example.com", new="Closed"),
                                      mod("StateChange", "2026-10-10T12:00:00Z", by="a@example.com", new="New")])
    assert (record["closed_at"], record["closed_by_person"], record["hours_to_close"]) == (None, None, None)


def test_close_by_system_is_not_a_person():
    record = alert(state="Closed", mods=[mod("StateChange", "2026-10-10T11:00:00Z", by="System", new="Closed")])
    assert (record["closed_by"], record["closed_by_person"]) == ("System", False)


def test_failed_and_missing_notifications_are_counted():
    record = alert(mods=[mod("AlertCreated", "2026-10-10T10:00:00Z"), mod("ActionsFailed", "2026-10-10T10:00:01Z")])
    assert (record["actions_triggered"], record["actions_failed"], record["acknowledged_at"]) == (0, 1, None)


@pytest.mark.parametrize("status", [fa.HISTORY_NOT_FOUND, fa.HISTORY_NOT_AUTHORIZED, fa.HISTORY_ERROR])
def test_unread_history_leaves_the_derived_fields_unknown(status):
    record = alert(status=status, state="Closed")
    assert (record["history"], record["closed_by"], record["closed_by_person"], record["actions_triggered"]) == (
        None, None, None, None)


@pytest.mark.parametrize("exc, status", [
    (azure_rest.ArmError(404, "AlertNotFound", "gone"), fa.HISTORY_NOT_FOUND),
    (azure_rest.ArmError(403, "AuthorizationFailed", "no"), fa.HISTORY_NOT_AUTHORIZED),
    (azure_rest.ArmError(500, "InternalServerError", "boom"), fa.HISTORY_ERROR),
])
def test_history_status(exc, status):
    assert fa.history_status(exc) == status


class _Collector:
    def __init__(self):
        self.failures = []

    def record(self, operation, exc):
        self.failures.append(operation)


class _Client:
    def __init__(self, error=None):
        self.error, self.paths = error, []

    def get(self, path, api_version):
        self.paths.append((path, api_version))
        if self.error:
            raise self.error
        return {"properties": {"modifications": [mod("ActionsTriggered", "2026-10-10T10:00:01Z")]}}


@pytest.mark.parametrize("error, status, failed", [
    (None, fa.HISTORY_READ, False),
    (azure_rest.ArmError(404, "NotFound", "gone"), fa.HISTORY_NOT_FOUND, False),
    (azure_rest.ArmError(403, "AuthorizationFailed", "no"), fa.HISTORY_NOT_AUTHORIZED, False),
    (azure_rest.ArmError(500, "InternalServerError", "boom"), fa.HISTORY_ERROR, True),
])
def test_only_unexpected_history_failures_fail_the_run(error, status, failed):
    client, collector = _Client(error), _Collector()
    record = fa.read_history(client, fa.alert_record(raw_alert(7)), collector)
    assert client.paths == [(f"{SUB}/providers/Microsoft.AlertsManagement/alerts/a7/history", fa.ALERTS_API)]
    assert (record["history_status"], bool(collector.failures)) == (status, failed)


class _ListClient:
    def __init__(self, alerts, total):
        self.alerts, self.total, self.calls = alerts, total, []

    def get(self, path, api_version):
        self.calls.append(("get", path))
        if path.endswith("/history"):
            return {"properties": {"modifications": []}}
        return {"properties": {"total": self.total}}

    def list(self, path, api_version, params=None):
        self.calls.append(("list", path, params))
        return self.alerts


def test_alerts_are_listed_over_thirty_days_and_checked_against_the_summary_total():
    client = _ListClient([raw_alert(1), raw_alert(2)], 3)
    collector = sys.modules["azure_common"].Collector(fa.logger)
    alerts, total, read = fa.collect_alerts(client, "s1", collector)
    assert ("list", f"{SUB}/providers/Microsoft.AlertsManagement/alerts", {"timeRange": "30d", "pageCount": "250"}) in client.calls
    assert ("get", f"{SUB}/providers/Microsoft.AlertsManagement/alertsSummary?groupby=alertState&timeRange=30d") in client.calls
    assert (len(alerts), total, read, collector.ok) == (2, 3, True, True)
    assert fa.summarize(alerts, [], total)["all_alerts_listed"] is False


@pytest.mark.parametrize("rule_type, props, enabled", [
    ("metric", {"enabled": True}, True),
    ("log_search", {"enabled": False}, False),
    ("smart_detector", {"state": "Enabled"}, True),
    ("smart_detector", {"state": "Disabled"}, False),
    ("activity_log", {}, None),
])
def test_rule_enabled_state(rule_type, props, enabled):
    assert fa.rule_record(rule_type, {"id": METRIC_RULE, "name": "r", "properties": props})["enabled"] is enabled


def test_rule_fire_counts_and_rules_that_never_fired():
    rules = [fa.rule_record("metric", {"id": METRIC_RULE, "properties": {"enabled": True}}),
             fa.rule_record("log_search", {"id": LOG_RULE, "name": "failed-logins", "properties": {"enabled": True}}),
             fa.rule_record("activity_log", {"id": ACTIVITY_RULE, "properties": {"enabled": False}})]
    alerts = [
        alert(1, rule=METRIC_RULE.lower(), fired="2026-10-01T00:00:00Z"),
        alert(2, rule=METRIC_RULE, fired="2026-10-09T00:00:00Z", state="Closed",
              mods=[mod("StateChange", "2026-10-09T06:00:00Z", by="a@example.com", new="Closed")]),
        alert(3, rule=FAR_RULE),
        alert(4, rule=None),
    ]
    activity = {r["name"]: r for r in fa.rule_activity(rules, alerts)}
    assert {n: (r["listed"], r["fire_count"], r["last_fired_at"], r["open_alerts"]) for n, r in activity.items()} == {
        "cpu-high": (True, 2, "2026-10-09T00:00:00Z", 1),
        "failed-logins": (True, 0, None, 0),
        "nsg-change": (True, 0, None, 0),
        "elsewhere": (False, 1, "2026-10-10T10:00:00Z", 1),
    }
    summary = fa.summarize(alerts, list(activity.values()), 4)
    assert {k: summary[k] for k in (
        "alerts_fired", "all_alerts_listed", "alerts_open", "alerts_closed", "alerts_closed_by_person",
        "alerts_by_rule_type", "median_hours_to_close", "oldest_open_alert_fired_at", "alert_rules_listed",
        "enabled_alert_rules", "rules_that_fired", "enabled_rules_never_fired", "rules_fired_not_listed",
    )} == {
        "alerts_fired": 4, "all_alerts_listed": True, "alerts_open": 3, "alerts_closed": 1,
        "alerts_closed_by_person": 1, "alerts_by_rule_type": {"metric": 3, "none": 1}, "median_hours_to_close": 6.0,
        "oldest_open_alert_fired_at": "2026-10-01T00:00:00Z", "alert_rules_listed": 3, "enabled_alert_rules": 2,
        "rules_that_fired": 2, "enabled_rules_never_fired": 1, "rules_fired_not_listed": 1,
    }


def test_summary_without_alerts_or_a_summary_total():
    summary = fa.summarize([], [], None)
    assert (summary["alerts_fired"], summary["all_alerts_listed"], summary["median_hours_to_close"],
            summary["oldest_open_alert_fired_at"]) == (0, None, None, None)


def test_rule_fires_are_unknown_when_the_alerts_were_not_read():
    rules = [fa.rule_record("metric", {"id": METRIC_RULE, "properties": {"enabled": True}})]
    [rule] = fa.rule_activity(rules, [], alerts_read=False)
    assert (rule["fire_count"], rule["last_fired_at"], rule["open_alerts"]) == (None, None, None)
    summary = fa.summarize([], [rule], None, alerts_read=False)
    assert (summary["rules_that_fired"], summary["enabled_rules_never_fired"], summary["rules_fired_not_listed"],
            summary["enabled_alert_rules"]) == (None, None, None, 1)


def test_history_counts_are_unknown_while_any_history_is_unread():
    alerts = [alert(n, status=fa.HISTORY_NOT_AUTHORIZED, state="Closed") for n in (1, 2, 3)]
    summary = fa.summarize(alerts, [], 3)
    assert {k: summary[k] for k in ("alert_histories_unread", "alerts_closed", "alerts_acknowledged",
                                    "alerts_closed_by_person", "alerts_with_notifications",
                                    "alerts_with_failed_notifications")} == {
        "alert_histories_unread": 3, "alerts_closed": 3, "alerts_acknowledged": None, "alerts_closed_by_person": None,
        "alerts_with_notifications": None, "alerts_with_failed_notifications": None}


class _Subscription:
    """Alert lists and rule lists for one subscription; `failing` paths answer the given error."""

    def __init__(self, failing=None, error=None):
        self.failing, self.error, self.lists = failing, error, []

    def get(self, path, api_version):
        if path.endswith("/history"):
            return {"properties": {"modifications": []}}
        return {"properties": {"total": 1}}

    def list(self, path, api_version, params=None):
        self.lists.append(path.split("/providers/", 1)[1])
        if self.failing and path.endswith(self.failing):
            raise self.error
        if path.endswith("/Microsoft.AlertsManagement/alerts"):
            return [raw_alert(1)]
        if path.endswith("/metricAlerts"):
            return [{"id": METRIC_RULE, "name": "cpu-high", "properties": {"enabled": True}}]
        return []


def registered(alerts_management=fa.REGISTRATION_UNKNOWN, insights=fa.REGISTRATION_UNKNOWN):
    return {"Microsoft.AlertsManagement": alerts_management, "Microsoft.Insights": insights}


def test_collect_rules_skips_an_unregistered_provider_and_records_a_failed_list():
    client, collector = _Subscription("/smartDetectorAlertRules", azure_rest.ArmError(500, "InternalServerError", "x")), \
        sys.modules["azure_common"].Collector(fa.logger)
    rules, read = fa.collect_rules(client, "s1", registered(insights=fa.NOT_REGISTERED), collector)
    assert (client.lists, rules, read, collector.ok) == (
        ["Microsoft.AlertsManagement/smartDetectorAlertRules"], [], False, False)


def test_collect_rules_counts_an_unregistered_provider_as_read():
    client, collector = _Subscription(), sys.modules["azure_common"].Collector(fa.logger)
    rules, read = fa.collect_rules(client, "s1", registered(insights=fa.NOT_REGISTERED), collector)
    assert (rules, read, collector.ok) == ([], True, True)


def test_collect_reads_alerts_then_counts_each_rules_fires():
    client, collector = _Subscription(), sys.modules["azure_common"].Collector(fa.logger)
    alerts, rules, total, read, rules_read = fa.collect(client, "s1", registered(), collector)
    assert (len(alerts), total, read, rules_read, collector.ok) == (1, 1, True, True, True)
    assert [(r["name"], r["fire_count"]) for r in rules] == [("cpu-high", 1)]


def test_rule_counts_are_unknown_when_a_rule_list_failed():
    client = _Subscription("/scheduledQueryRules", azure_rest.ArmError(500, "InternalServerError", "x"))
    collector = sys.modules["azure_common"].Collector(fa.logger)
    alerts, rules, total, read, rules_read = fa.collect(client, "s1", registered(), collector)
    summary = fa.summarize(alerts, rules, total, read, rules_read)
    assert (rules_read, collector.ok) == (False, False)
    assert {k: summary[k] for k in fa.RULE_COUNTS} == dict.fromkeys(fa.RULE_COUNTS, None)
    assert (summary["alerts_fired"], summary["rules_that_fired"]) == (1, 1)


@pytest.mark.parametrize("registration, failing, total, ok", [
    (registered(alerts_management=fa.NOT_REGISTERED), None, None, True),
    (registered(), "/Microsoft.AlertsManagement/alerts", 1, False),
])
def test_collect_leaves_rule_fires_unknown_when_the_alerts_were_not_read(registration, failing, total, ok):
    client = _Subscription(failing, azure_rest.ArmError(403, "AuthorizationFailed", "no"))
    collector = sys.modules["azure_common"].Collector(fa.logger)
    alerts, rules, summary_total, read, rules_read = fa.collect(client, "s1", registration, collector)
    assert (alerts, summary_total, read, rules_read, collector.ok) == ([], total, False, True, ok)
    assert [(r["name"], r["fire_count"]) for r in rules] == [("cpu-high", None)]
    assert fa.summarize(alerts, rules, summary_total, read, rules_read)["enabled_rules_never_fired"] is None


@pytest.mark.parametrize("summary_total", [None, 0])
def test_alert_counts_are_unknown_when_the_alert_list_was_not_read(summary_total):
    summary = fa.summarize([], [], summary_total, alerts_read=False)
    assert {k: summary[k] for k in fa.ALERT_COUNTS} == dict.fromkeys(fa.ALERT_COUNTS, None)
    assert (summary["window_days"], summary["alerts_summary_total"]) == (30, summary_total)
    read = fa.summarize([], [], 0)
    assert (read["alerts_fired"], read["all_alerts_listed"], read["alerts_by_state"], read["alerts_acknowledged"]) == (
        0, True, {}, 0)


def listed_metric_rule():
    return fa.rule_record("metric", {"id": METRIC_RULE, "properties": {"enabled": True}})


@pytest.mark.parametrize("rule_id", ["Backup", "ServiceHealth"])
def test_a_built_in_rule_name_is_not_an_unlisted_rule(rule_id):
    alerts = [alert(1, rule=rule_id), alert(2)]
    rules = fa.rule_activity([listed_metric_rule()], alerts)
    assert [(r["name"], r["listed"]) for r in rules] == [("cpu-high", True)]
    summary = fa.summarize(alerts, rules, 2)
    assert (summary["rules_fired_not_listed"], summary["rules_that_fired"], summary["alerts_by_rule_type"]) == (
        0, 1, {"builtin": 1, "metric": 1})


def test_a_trailing_slash_or_other_case_on_the_alert_rule_is_the_same_rule():
    alerts = [alert(1, rule=f"{METRIC_RULE}/"), alert(2, rule=METRIC_RULE.upper())]
    assert alerts[0]["alert_rule_id"] == METRIC_RULE
    [rule] = fa.rule_activity([listed_metric_rule()], alerts)
    assert (rule["listed"], rule["fire_count"]) == (True, 2)


def test_close_times_are_unknown_while_any_history_is_unread():
    alerts = [alert(1, state="Closed", mods=[mod("StateChange", "2026-10-10T12:00:00Z", by="a@example.com", new="Closed")]),
              alert(2, status=fa.HISTORY_NOT_AUTHORIZED, state="Closed")]
    summary = fa.summarize(alerts, [], 2)
    assert (summary["median_hours_to_close"], summary["max_hours_to_close"], summary["alerts_closed_by_person"]) == (
        None, None, None)


def test_a_change_logged_before_the_alert_fired_has_no_hours():
    record = alert(state="Closed", mods=[
        mod("StateChange", "2026-10-10T09:59:00Z", by="a@example.com", new="Acknowledged"),
        mod("StateChange", "2026-10-10T09:59:30Z", by="a@example.com", new="Closed")])
    assert (record["hours_to_acknowledge"], record["hours_to_close"], record["closed_at"]) == (
        None, None, "2026-10-10T09:59:30Z")
    assert fa.summarize([record], [], 1)["median_hours_to_close"] is None


def test_an_unparsable_change_time_is_not_reported_as_a_time():
    record = alert(state="Closed", mods=[mod("StateChange", "yesterday", by="a@example.com", new="Acknowledged"),
                                         mod("StateChange", "not a time", by="b@example.com", new="Closed")])
    assert {k: record[k] for k in ("acknowledged_at", "acknowledged_by", "closed_at", "closed_by", "hours_to_close")} == {
        "acknowledged_at": None, "acknowledged_by": "a@example.com", "closed_at": None, "closed_by": "b@example.com",
        "hours_to_close": None}
    assert fa.summarize([record], [], 1)["alerts_acknowledged"] == 1


def test_free_text_is_capped_and_marked():
    long = "x" * 5000
    record = alert(description=long, mods=[{**mod("StateChange", "2026-10-10T11:00:00Z", new="Acknowledged"),
                                            "comments": long, "description": long}])
    [change] = record["history"]
    for text in (record["description"], change["comments"], change["description"]):
        assert text.startswith("x" * fa.MAX_TEXT) and len(text) < fa.MAX_TEXT + 40 and "truncated" in text
    assert alert(description="short")["description"] == "short"
