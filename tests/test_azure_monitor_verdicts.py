"""Azure Monitor verdict logic: alert routing, processing rules, resource log coverage. Pure functions, no SDK or network."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rds = _load("resource_diagnostic_settings")
ala = _load("activity_log_alerts")
rules_fetcher = _load("alert_rules")
routing = sys.modules["alert_routing"]
arm_rest = sys.modules["arm_rest"]

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)
SUB = "/subscriptions/s1"
RG = f"{SUB}/resourceGroups/rg1"
VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/kv1"
AG_EMAIL = f"{RG}/providers/microsoft.insights/actionGroups/ag-email"
AG_HOOK = f"{RG}/providers/microsoft.insights/actionGroups/ag-hook"
AG_OTHER_SUB = "/subscriptions/s2/resourceGroups/rg/providers/microsoft.insights/actionGroups/ag-far"


def iso(delta_hours: float) -> str:
    return (NOW + timedelta(hours=delta_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def action_group(gid, enabled=True, **receivers):
    return {"id": gid, "name": gid.rsplit("/", 1)[-1], "properties": {"enabled": enabled, **receivers}}


def email(status="Enabled"):
    return {"name": "ops", "emailAddress": "ops@example.com", "status": status}


def groups(*raw):
    return {g["id"].lower(): routing.action_group_record(g) for g in raw}


def processing_rule(scopes, action="RemoveAllActionGroups", conditions=None, schedule=None, enabled=True, add=()):
    actions = [{"actionType": action, **({"actionGroupIds": list(add)} if add else {})}]
    raw = {
        "id": f"{SUB}/providers/Microsoft.AlertsManagement/actionRules/apr",
        "name": "apr",
        "properties": {"enabled": enabled, "scopes": scopes, "conditions": conditions or [],
                       "schedule": schedule, "actions": actions},
    }
    return routing.processing_rule_record(raw, NOW)


EMAIL_GROUP = action_group(AG_EMAIL, emailReceivers=[email()])


# --- route ---

def test_direct_route_to_an_enabled_email_reaches_a_person():
    r = routing.route(True, [AG_EMAIL], [VAULT], groups(EMAIL_GROUP), [])
    assert (r["routes_to_enabled_receiver"], r["routes_to_person"], r["suppressed"], r["reaches_human"]) == (
        True, True, False, True)


def test_disabled_alert_reaches_nobody():
    r = routing.route(False, [AG_EMAIL], [VAULT], groups(EMAIL_GROUP), [])
    assert (r["routes_to_enabled_receiver"], r["reaches_human"]) == (False, False)


@pytest.mark.parametrize("status", ["Disabled", "NotSpecified"])
def test_email_receiver_not_enabled_is_not_deliverable(status):
    group = action_group(AG_EMAIL, emailReceivers=[email(status)])
    r = routing.route(True, [AG_EMAIL], [VAULT], groups(group), [])
    assert (r["routes_to_enabled_receiver"], r["reaches_human"]) == (False, False)


def test_disabled_group_is_not_deliverable_even_with_enabled_receivers():
    group = action_group(AG_EMAIL, enabled=False, emailReceivers=[email()])
    assert routing.route(True, [AG_EMAIL], [VAULT], groups(group), [])["reaches_human"] is False


@pytest.mark.parametrize("key, receiver", [
    ("logicAppReceivers", {"name": "la", "resourceId": "/x/la", "callbackUrl": "https://la/secret"}),
    ("eventHubReceivers", {"name": "eh", "eventHubNameSpace": "ns", "eventHubName": "eh"}),
    ("webhookReceivers", {"name": "hook", "serviceUri": "https://hooks.example.com/t/secret?k=v"}),
    ("automationRunbookReceivers", {"name": "rb", "automationAccountId": "/x/aa", "runbookName": "r"}),
    ("azureFunctionReceivers", {"name": "fn", "functionAppResourceId": "/x/fa", "functionName": "f"}),
])
def test_receiver_that_only_hands_off_to_code_is_unknown_not_a_person(key, receiver):
    group = action_group(AG_HOOK, **{key: [receiver]})
    r = routing.route(True, [AG_HOOK], [VAULT], groups(group), [])
    assert (r["routes_to_enabled_receiver"], r["routes_to_person"], r["reaches_human"]) == (True, False, None)


@pytest.mark.parametrize("key, receiver", [
    ("smsReceivers", {"name": "s", "countryCode": "1", "phoneNumber": "5551234567", "status": "Enabled"}),
    ("voiceReceivers", {"name": "v", "countryCode": "1", "phoneNumber": "5551234567"}),
    ("azureAppPushReceivers", {"name": "p", "emailAddress": "ops@example.com"}),
    ("armRoleReceivers", {"name": "owner", "roleId": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}),
    ("itsmReceivers", {"name": "snow", "workspaceId": "w", "connectionId": "c"}),
])
def test_person_facing_receivers_reach_a_person(key, receiver):
    group = action_group(AG_EMAIL, **{key: [receiver]})
    assert routing.route(True, [AG_EMAIL], [VAULT], groups(group), [])["reaches_human"] is True


def test_unresolved_group_is_unknown_not_off():
    r = routing.route(True, [AG_OTHER_SUB], [VAULT], {}, [])
    assert r["unresolved_action_group_ids"] == [AG_OTHER_SUB]
    assert (r["routes_to_enabled_receiver"], r["routes_to_person"], r["reaches_human"]) == (None, None, None)


def test_unresolved_group_does_not_hide_a_resolved_route():
    r = routing.route(True, [AG_EMAIL, AG_OTHER_SUB], [VAULT], groups(EMAIL_GROUP), [])
    assert r["reaches_human"] is True


def test_rule_without_action_groups_is_off():
    r = routing.route(True, [], [VAULT], {}, [])
    assert (r["routes_to_enabled_receiver"], r["reaches_human"]) == (False, False)


def test_same_group_in_two_casings_resolves_once():
    r = routing.route(True, [AG_EMAIL, AG_EMAIL.upper()], [VAULT], groups(EMAIL_GROUP), [])
    assert [g["id"] for g in r["resolved_action_groups"]] == [AG_EMAIL]


def test_full_scope_suppression_stops_the_alert():
    r = routing.route(True, [AG_EMAIL], [VAULT], groups(EMAIL_GROUP), [processing_rule([RG])])
    assert (r["suppressed"], r["reaches_human"]) == (True, False)
    assert r["processing_rule_matches"][0]["scope_match"] == routing.SCOPE_FULL


def test_suppression_with_conditions_is_possible_not_certain():
    rule = processing_rule([RG], conditions=[{"field": "Severity", "operator": "Equals", "values": ["Sev4"]}])
    r = routing.route(True, [AG_EMAIL], [VAULT], groups(EMAIL_GROUP), [rule])
    assert (r["suppressed"], r["reaches_human"]) == (None, None)


def test_suppression_narrower_than_the_alert_is_partial():
    # A subscription-wide alert, silenced only for what fires in one resource group.
    r = routing.route(True, [AG_EMAIL], [SUB], groups(EMAIL_GROUP), [processing_rule([RG])])
    assert r["processing_rule_matches"][0]["scope_match"] == routing.SCOPE_PARTIAL
    assert (r["suppressed"], r["reaches_human"]) == (None, None)


def test_suppression_covering_one_of_several_alert_scopes_is_partial():
    other = "/subscriptions/s1/resourceGroups/rg2/providers/Microsoft.KeyVault/vaults/kv2"
    r = routing.route(True, [AG_EMAIL], [VAULT, other], groups(EMAIL_GROUP), [processing_rule([RG])])
    assert r["suppressed"] is None


def test_suppression_elsewhere_does_not_touch_the_alert():
    rule = processing_rule(["/subscriptions/s1/resourceGroups/rg2"])
    r = routing.route(True, [AG_EMAIL], [VAULT], groups(EMAIL_GROUP), [rule])
    assert (r["processing_rule_matches"], r["suppressed"], r["reaches_human"]) == ([], False, True)


def test_suppression_scope_match_ignores_case_and_trailing_slash():
    r = routing.route(True, [AG_EMAIL], [VAULT], groups(EMAIL_GROUP), [processing_rule([RG.upper() + "/"])])
    assert r["suppressed"] is True


@pytest.mark.parametrize("enabled, schedule", [
    (False, None),
    (True, {"timeZone": "UTC", "effectiveUntil": iso(-2)}),
])
def test_disabled_or_expired_suppression_is_ignored(enabled, schedule):
    rule = processing_rule([RG], enabled=enabled, schedule=schedule)
    assert routing.route(True, [AG_EMAIL], [VAULT], groups(EMAIL_GROUP), [rule])["suppressed"] is False


def test_group_added_by_processing_rule_routes_the_alert():
    rule = processing_rule([RG], action="AddActionGroups", add=[AG_EMAIL])
    r = routing.route(True, [], [VAULT], groups(EMAIL_GROUP), [rule])
    added = r["resolved_action_groups"][0]
    assert (added["added_by_processing_rule"], added["applies_to_every_fire"]) == (True, True)
    assert r["reaches_human"] is True


def test_group_added_for_only_part_of_the_alert_is_unknown():
    rule = processing_rule([RG], action="AddActionGroups", add=[AG_EMAIL])
    r = routing.route(True, [], [SUB], groups(EMAIL_GROUP), [rule])
    assert (r["routes_to_enabled_receiver"], r["reaches_human"]) == (None, None)


# --- schedule_active ---

@pytest.mark.parametrize("schedule, expected", [
    (None, True),
    ({"timeZone": "UTC", "effectiveFrom": iso(-1), "effectiveUntil": iso(1)}, True),
    ({"timeZone": "UTC", "effectiveUntil": iso(-1)}, False),
    ({"timeZone": "UTC", "effectiveFrom": iso(1)}, False),
    ({"timeZone": "Pacific Standard Time", "effectiveFrom": iso(-48), "effectiveUntil": iso(48)}, True),
    ({"timeZone": "Pacific Standard Time", "effectiveUntil": iso(3)}, None),
    ({"timeZone": "Pacific Standard Time", "effectiveFrom": iso(-3)}, None),
    ({"timeZone": "Pacific Standard Time", "effectiveUntil": iso(-15)}, False),
    ({"timeZone": "UTC", "recurrences": [{"recurrenceType": "Daily", "startTime": "09:00:00"}]}, None),
    ({"timeZone": "UTC", "effectiveUntil": iso(-1), "recurrences": [{"recurrenceType": "Daily"}]}, False),
])
def test_schedule_active(schedule, expected):
    assert routing.schedule_active(schedule, NOW) is expected


# --- action_group_record ---

def test_receiver_targets_drop_secrets():
    record = routing.action_group_record(action_group(
        AG_EMAIL,
        smsReceivers=[{"name": "s", "countryCode": "44", "phoneNumber": "7700900123", "status": "Enabled"}],
        webhookReceivers=[{"name": "h", "serviceUri": "https://hooks.example.com/services/T0/B0/secret?x=1"}],
    ))
    targets = {r["type"]: r["target"] for r in record["receivers"]}
    assert targets == {"sms": "+44 ***0123", "webhook": "hooks.example.com"}


def test_unrecognized_receiver_array_is_reported():
    record = routing.action_group_record(action_group(AG_EMAIL, emailReceivers=[email()], pagerReceivers=[{"n": 1}]))
    assert record["unrecognized_receiver_arrays"] == ["pagerReceivers"]
    assert record["deliverable"] is True


def test_group_with_no_receivers_is_not_deliverable():
    record = routing.action_group_record(action_group(AG_EMAIL))
    assert (record["deliverable"], record["notifies_people"]) == (False, False)


# --- referenced groups and the ARM token ---

class _Collector:
    def __init__(self):
        self.failures = []

    def record(self, operation, exc):
        self.failures.append(operation)


@pytest.mark.parametrize("gid", [
    "https://attacker.example/subscriptions/s/resourceGroups/rg/providers/microsoft.insights/actionGroups/ag",
    "//attacker.example/subscriptions/s/resourceGroups/rg/providers/microsoft.insights/actionGroups/ag",
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
])
def test_only_action_group_paths_are_fetched(monkeypatch, gid):
    fetched = []
    monkeypatch.setattr(routing, "fetch_action_group", lambda rest, g: fetched.append(g))
    found: dict = {}
    routing.add_referenced_groups(None, [gid], found, _Collector())
    assert (fetched, found) == ([], {})


@pytest.mark.parametrize("url", ["https://attacker.example/x", "//attacker.example/x", "http://management.azure.com/x"])
def test_arm_rest_refuses_urls_off_the_management_endpoint(monkeypatch, url):
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    with pytest.raises(ValueError):
        arm_rest.get_json(None, url)


# --- summaries: unknown is counted apart ---

def test_alert_rule_summary_keeps_unknown_apart():
    rules = [
        {"is_alerting_rule": True, "enabled": True, "rule_type": "metric", "resolved_action_groups": [{}],
         "routes_to_enabled_receiver": True, "routes_to_person": True, "suppressed": False, "reaches_human": True},
        {"is_alerting_rule": True, "enabled": True, "rule_type": "metric", "resolved_action_groups": [{}],
         "routes_to_enabled_receiver": None, "routes_to_person": None, "suppressed": False, "reaches_human": None},
    ]
    summary = rules_fetcher.summarize(rules, [], [])
    assert (summary["enabled_rules_reaching_human"], summary["enabled_rules_reaching_human_unknown"],
            summary["enabled_rules_not_reaching_human"], summary["all_enabled_rules_reach_human"]) == (1, 1, 0, None)


@pytest.mark.parametrize("reaches, expected", [(True, True), (None, None), (False, False)])
def test_slot_write_counts_for_change_coverage(reaches, expected):
    alert = {"enabled": True, "monitored_operations": ["microsoft.web/sites/slots/write"], "reaches_human": reaches}
    assert ala.coverage_reaching_human([alert], ala.CHANGE_OPERATIONS)["create_update_web_app"] is expected


# --- resource_diagnostic_settings ---

LOGS = [
    {"name": "AuditEvent", "category_type": "Logs", "category_groups": ["audit", "allLogs"]},
    {"name": "AzurePolicyEvaluationDetails", "category_type": "Logs", "category_groups": ["allLogs"]},
    {"name": "AllMetrics", "category_type": "Metrics", "category_groups": []},
]
BASE = {"id": VAULT, "name": "kv1", "type": "microsoft.keyvault/vaults", "kind": None, "location": "eastus",
        "resource_group": "rg1", "parent_id": None, "synthesized_child": False}


def setting(workspace="/x/law", category=None, group=None, enabled=True):
    return {"id": "/x/setting", "name": "s", "storage_account_id": None, "workspace_id": workspace,
            "event_hub_name": None, "event_hub_authorization_rule_id": None, "marketplace_partner_id": None,
            "log_analytics_destination_type": None,
            "logs": [{"category": category, "category_group": group, "enabled": enabled}]}


@pytest.mark.parametrize("kwargs, captured, all_audit", [
    ({"category": "AuditEvent"}, ["AuditEvent"], True),
    ({"group": "audit"}, ["AuditEvent"], True),
    ({"group": "allLogs"}, ["AuditEvent", "AzurePolicyEvaluationDetails"], True),
    ({"category": "AzurePolicyEvaluationDetails"}, ["AzurePolicyEvaluationDetails"], False),
    ({"category": "AuditEvent", "enabled": False}, [], False),
])
def test_captured_categories(kwargs, captured, all_audit):
    record = rds.resource_record(BASE, rds.STATUS_ASSESSED, LOGS, [setting(**kwargs)])
    assert record["captured_log_categories"] == captured
    assert record["captures_all_audit_categories"] is all_audit
    assert record["has_enabled_log_setting"] is bool(captured)


@pytest.mark.parametrize("workspace", [None, ""])
def test_setting_with_no_destination_captures_nothing(workspace):
    record = rds.resource_record(BASE, rds.STATUS_ASSESSED, LOGS, [setting(workspace=workspace, group="allLogs")])
    assert (record["has_enabled_log_setting"], record["captured_log_categories"], record["destination_types"]) == (
        False, [], [])


def test_metrics_only_resource_is_outside_the_denominator():
    record = rds.resource_record(BASE, rds.STATUS_ASSESSED, [LOGS[2]])
    assert (record["supports_diagnostics"], record["emits_resource_logs"], record["has_enabled_log_setting"]) == (
        True, False, None)


def test_unsupported_resource_neither_supports_nor_emits():
    record = rds.resource_record(BASE, rds.STATUS_UNSUPPORTED)
    assert (record["supports_diagnostics"], record["emits_resource_logs"], record["has_enabled_log_setting"]) == (
        False, False, None)


class _HttpError(Exception):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


@pytest.mark.parametrize("exc, expected", [
    (_HttpError("(ResourceTypeNotSupported) The resource type 'microsoft.network/routetables' does not support "
                "diagnostic settings.", 400), rds.STATUS_UNSUPPORTED),
    (_HttpError("(ResourceNotFound) The Resource was not found.", 404), rds.STATUS_NOT_FOUND),
    (_HttpError("(AuthorizationFailed) The client does not have authorization.", 403), None),
    (_HttpError("(BadRequest) Something else.", 400), None),
])
def test_classify_error(exc, expected):
    assert rds.classify_error(exc) == expected


def test_unsupported_type_is_asked_once():
    calls = []

    class _Categories:
        def list(self, resource_uri):
            calls.append(resource_uri)
            raise _HttpError("(ResourceTypeNotSupported) The resource type 'x' does not support diagnostic settings.")

    monitor = type("M", (), {"diagnostic_settings_category": _Categories()})()
    seen: set = set()
    first = rds.assess(monitor, _Collector(), {**BASE, "type": "x"}, seen)
    second = rds.assess(monitor, _Collector(), {**BASE, "id": VAULT + "2", "type": "x"}, seen)
    assert (first["status"], second["status"], len(calls)) == (rds.STATUS_UNSUPPORTED, rds.STATUS_UNSUPPORTED, 1)


def account(kind, name="sa"):
    return {**BASE, "id": f"{RG}/providers/Microsoft.Storage/storageAccounts/{name}", "name": name,
            "type": rds.STORAGE_ACCOUNT_TYPE, "kind": kind}


@pytest.mark.parametrize("kind, services", [
    ("StorageV2", ["blobServices", "fileServices", "queueServices", "tableServices"]),
    ("Storage", ["blobServices", "fileServices", "queueServices", "tableServices"]),
    ("BlobStorage", ["blobServices"]),
    ("BlockBlobStorage", ["blobServices"]),
    ("FileStorage", ["fileServices"]),
    (None, ["blobServices", "fileServices", "queueServices", "tableServices"]),
])
def test_storage_children_follow_account_kind(kind, services):
    out = rds.with_storage_children([account(kind)])
    assert [r["id"].split("/")[-2] for r in out if r["synthesized_child"]] == services


def test_listed_child_is_not_added_twice_and_other_types_get_none():
    sa = account("StorageV2")
    listed_blob = {**sa, "id": sa["id"] + "/blobServices/default", "type": "microsoft.storage/storageaccounts/blobservices"}
    out = rds.with_storage_children([sa, listed_blob, BASE])
    ids = [r["id"].lower() for r in out]
    assert len(ids) == len(set(ids)) == 6
