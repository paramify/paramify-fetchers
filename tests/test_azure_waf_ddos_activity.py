"""azure_waf_ddos_activity: WAF resources and activity, WAF and DDoS alerts, DDoS unknowns, workspace reads. Synthetic, no network."""

from __future__ import annotations

import importlib.util
import logging
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_waf_ddos_activity_under_test", AZURE / "waf_ddos_activity" / "fetcher.py")
wda = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wda)
azure_rest = sys.modules["azure_rest"]
Collector = sys.modules["azure_common"].Collector

SUB_ID = "00000000-0000-0000-0000-000000000001"
SUB = f"/subscriptions/{SUB_ID}"
RG = f"{SUB}/resourceGroups/rg1"
LAW = f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law"
LAW2 = f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law2"
PROFILE = f"{RG}/providers/Microsoft.Cdn/profiles/fd1"
FD_POLICY = f"{RG}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/wafpolicy1"
AGW = f"{RG}/providers/Microsoft.Network/applicationGateways/agw1"
AGW_POLICY = f"{RG}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/agwpolicy"
IP = f"{RG}/providers/Microsoft.Network/publicIPAddresses/ip1"
GROUP = f"{RG}/providers/microsoft.insights/actionGroups/ops"


def collector():
    return Collector(logging.getLogger("test"))


def setting(workspace=LAW, category=None, group=None, enabled=True, dedicated=False):
    props = {"workspaceId": workspace, "logs": [{"category": category, "categoryGroup": group, "enabled": enabled}]}
    if dedicated:
        props["logAnalyticsDestinationType"] = "Dedicated"
    return {"name": "s", "properties": props}


# --- pure transforms ---

def test_exported_categories_by_name_and_all_logs():
    settings = [setting(category="DDoSProtectionNotifications"), setting(workspace=LAW2, group="allLogs"),
                setting(category="DDoSMitigationReports", enabled=False), setting(workspace=None, group="allLogs")]
    out = wda.exported_categories(settings, wda.DDOS_CATEGORIES)
    assert out == {"DDoSProtectionNotifications": [LAW, LAW2], "DDoSMitigationFlowLogs": [LAW2], "DDoSMitigationReports": [LAW2]}
    assert wda.exported_categories(None, ["x"]) == {"x": []}


def test_dedicated_destination():
    settings = [setting(group="allLogs", dedicated=True), setting(workspace=LAW2, group="allLogs")]
    assert wda.dedicated(settings, LAW.upper()) is True
    assert wda.dedicated(settings, LAW2) is False


@pytest.mark.parametrize("value, expected", [
    ("wafpolicy1", "wafpolicy1"),
    (AGW_POLICY, "agwpolicy"),
    ("<script>alert(1)</script>", None),
    ("a b", None),
    ("", None),
])
def test_policy_name(value, expected):
    assert wda.policy_name(value) == expected


@pytest.mark.parametrize("props, expected", [
    ({"sku": {"tier": "Standard_v2", "name": "Standard_v2"}}, None),
    ({"sku": {"tier": "WAF_v2", "name": "WAF_v2"}}, None),
    ({"sku": {"tier": "WAF_v2", "name": "WAF_v2"}, "firewallPolicy": {"id": AGW_POLICY}}, ([AGW_POLICY], None)),
    ({"sku": {"tier": "WAF", "name": "WAF_Medium"}, "webApplicationFirewallConfiguration": {"enabled": True, "firewallMode": "Detection"}},
     ([], "Detection")),
])
def test_gateway_waf_resource(props, expected):
    record = wda.gateway_waf_resource({"id": AGW, "name": "agw1", "properties": props})
    assert (record if record is None else (record["waf_policy_ids"], record["legacy_waf_mode"])) == expected


def test_front_door_waf_resource_reads_attached_policies():
    sps = [{"properties": {"parameters": {"wafPolicy": {"id": FD_POLICY}}}}, {"properties": {"parameters": {}}}]
    assert wda.front_door_waf_resource({"id": PROFILE, "name": "fd1"}, sps)["waf_policy_ids"] == [FD_POLICY]
    assert wda.front_door_waf_resource({"id": PROFILE, "name": "fd1"}, None)["waf_policy_ids"] is None


def metric_alert(metric, scopes=(PROFILE,), enabled=True, groups=(GROUP,)):
    return {"id": f"{RG}/providers/Microsoft.Insights/metricAlerts/m-{metric}", "name": f"m-{metric}",
            "properties": {"enabled": enabled, "scopes": list(scopes),
                           "criteria": {"allOf": [{"metricName": metric}]},
                           "actions": [{"actionGroupId": g} for g in groups]}}


def log_alert(query, scopes=(LAW,), kind="LogAlert", enabled=True):
    return {"id": f"{RG}/providers/Microsoft.Insights/scheduledQueryRules/q", "name": "q", "kind": kind,
            "properties": {"enabled": enabled, "scopes": list(scopes), "criteria": {"allOf": [{"query": query}]},
                           "actions": {"actionGroups": [GROUP]}}}


@pytest.mark.parametrize("rule_type, raw, waf, ddos, enabled", [
    ("metric", metric_alert("WebApplicationFirewallRequestCount"), True, False, True),
    ("metric", metric_alert("AzwafSecRule"), True, False, True),
    ("metric", metric_alert("IfUnderDDoSAttack"), False, True, True),
    ("metric", metric_alert("Percentage4XX"), False, False, True),
    ("log_search", log_alert("AzureDiagnostics | where Category == 'FrontDoorWebApplicationFirewallLog'"), True, False, True),
    ("log_search", log_alert("AGWFirewallLogs | where Action == 'Blocked'"), True, False, True),
    ("log_search", log_alert("AzureDiagnostics | where Category == 'DDoSProtectionNotifications'"), False, True, True),
    ("log_search", log_alert("AzureDiagnostics | where Category == 'FrontDoorWebApplicationFirewallLog'", kind="LogToMetric"),
     True, False, False),
])
def test_alert_rule_record(rule_type, raw, waf, ddos, enabled):
    record = wda.alert_rule_record(rule_type, raw)
    assert (record["watches_waf"], record["watches_ddos_attack"], record["enabled"]) == (waf, ddos, enabled)


def rule(scopes, rule_type="metric", enabled=True, waf=True, reaches=True):
    return {"name": "r", "rule_type": rule_type, "enabled": enabled, "watches_waf": waf, "watches_ddos_attack": not waf,
            "_scopes": scopes, "routes_to_enabled_receiver": reaches, "reaches_human": reaches}


def test_covering_rules_by_scope_parent_and_workspace():
    rules = [rule([PROFILE.upper()]), rule([RG]), rule([LAW], rule_type="log_search"), rule([LAW]), rule([PROFILE], enabled=False),
             rule([f"{RG}2"])]
    covered = wda.covering_rules(rules, PROFILE, [LAW], "watches_waf")
    assert len(covered) == 3


# --- WAF activity ---

def fd_resource(policy_ids=(FD_POLICY,)):
    return wda.front_door_waf_resource({"id": PROFILE, "name": "fd1", "sku": {"name": "Premium_AzureFrontDoor"}},
                                       [{"properties": {"parameters": {"wafPolicy": {"id": p}}}} for p in policy_ids])


def requests_row(rid=PROFILE, policy="wafpolicy1", mode="detection", events=10, requests=6, blocked=0, logged=6,
                 last="2026-01-09T00:00:00Z"):
    return {"ResourceId": rid.lower(), "Policy": policy, "Mode": mode, "Events": events, "Requests": requests,
            "RequestsBlocked": blocked, "RequestsLoggedOnly": logged, "RequestsAllowed": 0, "RequestsChallenged": 0,
            "FirstEvent": "2026-01-01T00:00:00Z", "LastEvent": last}


POLICIES = {FD_POLICY.lower(): {"id": FD_POLICY, "name": "wafpolicy1", "mode": "Detection", "enabled": True}}


def test_waf_activity_from_the_fuller_copy():
    rid = PROFILE.lower()
    workspaces = {
        LAW.lower(): {"status": wda.WS_QUERIED, "read_tables": [wda.DIAG_TABLE],
                      "fd:requests": [requests_row()],
                      "fd:rules": [{"ResourceId": rid, "Rule": "Microsoft_DefaultRuleSet-2.1-SQLI-942100", "Events": 8, "Blocked": 0},
                                   {"ResourceId": rid, "Rule": "' or 1=1 --", "Events": 2, "Blocked": 0}]},
        LAW2.lower(): {"status": wda.WS_QUERIED, "read_tables": [wda.DIAG_TABLE], "fd:requests": [requests_row(events=3, requests=2)]},
    }
    alerts = [rule([PROFILE])]
    rec = wda.waf_activity(fd_resource(), [setting(category="FrontDoorWebApplicationFirewallLog"), setting(workspace=LAW2, group="allLogs")],
                           workspaces, POLICIES, alerts, sample=5)
    assert rec["waf_log_workspaces"] == [LAW, LAW2]
    assert (rec["waf_events"], rec["requests_matched"], rec["requests_blocked"], rec["requests_logged_only"]) == (10, 6, 0, 6)
    assert rec["detection_mode"] is True
    assert rec["waf_policies"] == [{"name": "wafpolicy1", "mode": "Detection", "enabled": True}]
    assert rec["activity_by_policy"][0]["logged_modes"] == ["detection"]
    assert rec["top_rules"] == [{"rule": "Microsoft_DefaultRuleSet-2.1-SQLI-942100", "events": 8, "blocked_events": 0}]
    assert rec["waf_logs_arriving"] is True
    assert rec["waf_alert_rules"] == ["r"] and rec["waf_alert_reaches_person"] is True


@pytest.mark.parametrize("settings, workspaces, arriving, events", [
    ([], {}, None, None),
    (None, {}, None, None),
    ([setting(category="FrontDoorWebApplicationFirewallLog")],
     {LAW.lower(): {"status": wda.WS_QUERIED, "read_tables": [wda.DIAG_TABLE], "fd:requests": []}}, False, 0),
    ([setting(category="FrontDoorWebApplicationFirewallLog")],
     {LAW.lower(): {"status": wda.WS_NOT_AUTHORIZED, "read_tables": []}}, None, None),
    ([setting(category="FrontDoorWebApplicationFirewallLog")],
     {LAW.lower(): {"status": wda.WS_QUERIED, "read_tables": [], "skipped_tables": [wda.DIAG_TABLE]}}, None, None),
])
def test_waf_activity_unknown_unless_read(settings, workspaces, arriving, events):
    rec = wda.waf_activity(fd_resource(), settings, workspaces, POLICIES, [], sample=5)
    assert rec["waf_logs_arriving"] is arriving
    assert rec["waf_events"] == events
    assert rec["waf_alert_rules"] == [] and rec["waf_alert_reaches_person"] is False


def test_gateway_with_dedicated_tables_reads_agw_firewall_logs():
    gateway = wda.gateway_waf_resource({"id": AGW, "name": "agw1", "properties": {
        "sku": {"tier": "WAF_v2", "name": "WAF_v2"}, "firewallPolicy": {"id": AGW_POLICY}}})
    workspaces = {LAW.lower(): {"status": wda.WS_QUERIED, "read_tables": [wda.AGW_DEDICATED_TABLE],
                                "agw_dedicated:requests": [requests_row(rid=AGW, policy=AGW_POLICY, mode="", blocked=4, logged=2)],
                                "agw:requests": [requests_row(rid=AGW, events=99)]}}
    rec = wda.waf_activity(gateway, [setting(group="allLogs", dedicated=True)], workspaces, {}, [], sample=5)
    assert (rec["waf_events"], rec["requests_blocked"]) == (10, 4)
    assert rec["activity_by_policy"][0]["policy"] == "agwpolicy"
    assert rec["waf_policies"] == [{"name": "agwpolicy", "mode": None, "enabled": None}]


# --- DDoS ---

def public_ip(mode=None, attached=True):
    props = {"ipAddress": "203.0.113.10"}
    if mode:
        props["ddosSettings"] = {"protectionMode": mode}
    if attached:
        props["ipConfiguration"] = {"id": f"{RG}/providers/Microsoft.Network/applicationGateways/agw1/frontendIPConfigurations/f"}
    return {"id": IP, "name": "ip1", "properties": props}


@pytest.mark.parametrize("mode, expected", [
    ("Enabled", wda.IP_PROTECTION),
    ("Disabled", wda.DISABLED),
    ("VirtualNetworkInherited", wda.INHERITED),
    (None, wda.INHERITED),
])
def test_protection(mode, expected):
    assert wda.protection(public_ip(mode)) == expected


def test_internet_facing():
    assert wda.internet_facing(public_ip()) is True
    assert wda.internet_facing(public_ip(attached=False)) is False
    assert wda.internet_facing({"properties": {"natGateway": {"id": "x"}}}) is True


def test_attack_hours():
    metrics = [{"timeseries": [{"data": [{"maximum": 0}, {"maximum": 1}, {}, {"maximum": 1.0}]}]}]
    assert wda.attack_hours(metrics) == 2
    assert wda.attack_hours([]) == 0
    assert wda.attack_hours(None) is None


DDOS_SETTINGS = [setting(group="allLogs")]


def ddos_ws(rows=()):
    return {LAW.lower(): {"status": wda.WS_QUERIED, "read_tables": [wda.DIAG_TABLE], "ddos": list(rows)}}


def test_unprotected_ip_reads_unknown_not_zero():
    alerts = [rule([IP], waf=False)]
    rec = wda.ddos_record(public_ip("Disabled"), DDOS_SETTINGS, ddos_ws(), alerts, [], {LAW.lower(): True})
    assert rec["ddos_protection_known_on"] is None
    assert rec["ddos_logs_exported"] is True
    assert rec["attack_alert_rules"] == ["r"] and rec["attack_alert_reaches_person"] is True
    assert rec["attack_alert_can_fire"] is None
    assert rec["attack_hours"] is None
    assert rec["mitigations_started"] is None and rec["mitigation_reports"] is None


def test_records_found_count_even_without_known_protection():
    rows = [{"ResourceId": IP.lower(), "Notifications": 2, "MitigationsStarted": 1, "Reports": 3, "FlowLogRecords": 40,
             "LastEvent": "2026-01-05T00:00:00Z"}]
    metric = [{"timeseries": [{"data": [{"maximum": 1}]}]}]
    rec = wda.ddos_record(public_ip(), DDOS_SETTINGS, ddos_ws(rows), [], metric, {LAW.lower(): True})
    assert (rec["mitigations_started"], rec["mitigation_reports"], rec["attack_hours"]) == (1, 3, 1)
    assert rec["last_ddos_event"] == "2026-01-05T00:00:00Z"


def test_protected_ip_reads_zero_once_its_logs_are_read():
    rec = wda.ddos_record(public_ip("Enabled"), DDOS_SETTINGS, ddos_ws(), [], [], {LAW.lower(): True})
    assert rec["ddos_protection_known_on"] is True
    assert (rec["attack_hours"], rec["mitigations_started"]) == (0, 0)
    assert rec["attack_alert_can_fire"] is False
    unread = wda.ddos_record(public_ip("Enabled"), DDOS_SETTINGS, ddos_ws(), [], None, {LAW.lower(): False})
    assert (unread["attack_hours"], unread["mitigations_started"]) == (None, None)
    no_export = wda.ddos_record(public_ip("Enabled"), [], {}, [], [], {})
    assert no_export["ddos_logs_exported"] is False and no_export["mitigations_started"] is None


def test_summary_ddos_figures_are_null_without_protected_ips():
    ip = wda.ddos_record(public_ip("Disabled"), DDOS_SETTINGS, ddos_ws(), [], [], {LAW.lower(): True})
    summary = wda.summarize([], [ip], [], [], 30, 0, total_ips=3)
    assert (summary["public_ips"], summary["internet_facing_public_ips"]) == (3, 1)
    assert summary["public_ips_with_ip_protection"] == 0
    assert summary["protected_ips_without_attack_alert"] is None
    assert summary["protected_ips_with_attack_alert_reaching_receiver"] is None
    assert summary["public_ips_attacked"] is None
    assert summary["ddos_mitigations_started"] is None
    assert summary["public_ips_exporting_ddos_logs"] == 1


# --- workspace reads and collection ---

class FakeClient:
    def __init__(self, tables=None, lists=None, arm=None, fail=None):
        self.tables = tables or {}
        self.lists = lists or {}
        self.arm = arm or {}
        self.fail = fail or {}
        self.queries, self.searches, self.list_params = [], [], {}

    def get(self, path, api_version):
        value = self.arm.get(path)
        if isinstance(value, Exception):
            raise value
        if value is not None:
            return value
        if "/tables/" in path:
            name = path.rsplit("/", 1)[-1]
            if name not in self.tables:
                raise azure_rest.ArmError(404, "ResourceNotFound", "no table")
            return {"properties": {"plan": self.tables[name], "retentionInDays": 30}}
        if "/workspaces/" in path:
            return {"properties": {"customerId": "cid-" + path.rsplit("/", 1)[-1]}}
        raise azure_rest.ArmError(404, "NotFound", path)

    def list(self, path, api_version, params=None):
        self.list_params[path] = params
        value = self.lists.get(path, [])
        if isinstance(value, Exception):
            raise value
        return value

    def query(self, customer_id, kql, timespan):
        self.queries.append((customer_id, kql, timespan))
        for marker, exc in self.fail.items():
            if marker in kql:
                raise exc
        return []

    def search(self, customer_id, kql, timespan):
        self.searches.append((customer_id, kql, timespan))
        return []


def test_basic_plan_tables_are_skipped_unless_opted_in():
    jobs = [(wda.AGW_DEDICATED_TABLE, "agw_dedicated:requests", "AGWFirewallLogs | count"), (wda.DIAG_TABLE, "ddos", "x")]
    client = FakeClient(tables={wda.AGW_DEDICATED_TABLE: "Basic", wda.DIAG_TABLE: "Analytics"})
    out = wda.read_workspace(client, LAW, jobs, False, 30, collector())
    assert out["skipped_tables"] == [wda.AGW_DEDICATED_TABLE] and out["read_tables"] == [wda.DIAG_TABLE]
    client = FakeClient(tables={wda.AGW_DEDICATED_TABLE: "Basic", wda.DIAG_TABLE: "Analytics"})
    wda.read_workspace(client, LAW, jobs, True, 30, collector())
    assert [s[2] for s in client.searches] == ["P30D"]


def test_a_refused_workspace_does_not_fail_the_run():
    client = FakeClient(tables={wda.DIAG_TABLE: "Analytics"},
                        fail={"AzureDiagnostics": azure_rest.QueryError("(403) InsufficientAccessError", "no")})
    c = collector()
    out = wda.read_workspace(client, LAW, [(wda.DIAG_TABLE, "ddos", "AzureDiagnostics | count")], False, 30, c)
    assert out["status"] == wda.WS_NOT_AUTHORIZED and c.ok


@pytest.mark.parametrize("exc, failed", [
    (azure_rest.ArmError(400, "BadRequest", "metric not supported"), False),
    (azure_rest.ArmError(403, "AuthorizationFailed", "no"), False),
    (azure_rest.ArmError(500, "InternalServerError", "boom"), True),
])
def test_metric_read_failures(exc, failed):
    c = collector()
    client = FakeClient(lists={f"{IP}/providers/Microsoft.Insights/metrics": exc})
    assert wda._metric(client, IP, "t", c) is None
    assert c.ok is not failed


def _lists():
    base = f"{SUB}/providers"
    return {
        f"{base}/Microsoft.Cdn/profiles": [{"id": PROFILE, "name": "fd1", "sku": {"name": "Premium_AzureFrontDoor"}},
                                          {"id": f"{PROFILE}2", "name": "fd2", "sku": {"name": "Standard_AzureFrontDoor"}}],
        f"{PROFILE}/securityPolicies": [{"properties": {"parameters": {"wafPolicy": {"id": FD_POLICY}}}}],
        f"{PROFILE}2/securityPolicies": [],
        f"{base}/Microsoft.Network/applicationGateways": [
            {"id": AGW, "name": "agw1", "properties": {"sku": {"tier": "Standard_v2", "name": "Standard_v2"}}}],
        f"{base}/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies": [
            {"id": FD_POLICY, "name": "wafpolicy1", "properties": {"policySettings": {"mode": "Prevention", "enabledState": "Enabled"}}}],
        f"{base}/Microsoft.Network/publicIPAddresses": [public_ip("VirtualNetworkInherited"), {"id": f"{IP}-spare", "name": "spare", "properties": {}}],
        f"{PROFILE}/providers/Microsoft.Insights/diagnosticSettings": [setting(group="allLogs")],
        f"{IP}/providers/Microsoft.Insights/diagnosticSettings": [setting(category="DDoSProtectionNotifications")],
        f"{IP}/providers/Microsoft.Insights/metrics": [{"timeseries": [{"data": [{"maximum": 0}]}]}],
        f"{base}/Microsoft.Insights/metricAlerts": [metric_alert("WebApplicationFirewallRequestCount"),
                                                    metric_alert("IfUnderDDoSAttack", scopes=(RG,)),
                                                    metric_alert("Http5xx")],
        f"{base}/Microsoft.Insights/scheduledQueryRules": [],
        f"{base}/Microsoft.Insights/actionGroups": [{"id": GROUP, "name": "ops", "properties": {
            "enabled": True, "emailReceivers": [{"name": "e", "emailAddress": "ops@example.com", "status": "Enabled"}]}}],
        f"{base}/Microsoft.AlertsManagement/actionRules": [],
    }


def test_collect_wires_waf_ddos_and_alerts(monkeypatch):
    monkeypatch.setenv(wda.LOOKBACK_ENV, "14")
    client = FakeClient(tables={wda.DIAG_TABLE: "Analytics"}, lists=_lists())
    c = collector()
    results, summary = wda.collect(client, SUB_ID, c)
    assert c.ok, c.failures
    assert summary["waf_resources"] == 1 and summary["front_door_profiles_without_waf"] == 1
    assert summary["app_gateway_waf_resources"] == 0
    assert summary["waf_resources_without_waf_events"] == 1 and summary["waf_events"] == 0
    assert summary["waf_alert_rules"] == 1 and summary["waf_resources_with_alert_reaching_person"] == 1
    assert (summary["public_ips"], summary["internet_facing_public_ips"]) == (2, 1)
    assert summary["public_ips_with_attack_alert"] == 1 and summary["ddos_attack_alert_rules"] == 1
    assert summary["public_ips_attacked"] is None and summary["ddos_mitigations_started"] is None
    assert results["waf_resources"][0]["waf_policies"] == [{"name": "wafpolicy1", "mode": "Prevention", "enabled": True}]
    assert all("_scopes" not in r for r in results["alert_rules"])
    kql = [q[1] for q in client.queries]
    assert sum("FrontDoorWebApplicationFirewallLog" in k for k in kql) == len(wda.WAF_QUERIES)
    assert sum("DDoSProtectionNotifications" in k for k in kql) == 1
    assert all("ago(14d)" in k and f"/subscriptions/{SUB_ID}/" in k for k in kql)
    for k in kql:
        assert not re.search(r"\{[a-z_]+\}", k), k
    params = client.list_params[f"{IP}/providers/Microsoft.Insights/metrics"]
    assert params["metricnames"] == wda.ATTACK_METRIC and params["aggregation"] == "Maximum"
    assert params["timespan"].endswith("Z") and "+00:00" not in params["timespan"]


def test_collect_treats_unregistered_providers_as_empty():
    unregistered = azure_rest.ArmError(409, "MissingSubscriptionRegistration", "not registered")
    lists = {f"{SUB}/providers/Microsoft.Cdn/profiles": unregistered}
    c = collector()
    results, summary = wda.collect(FakeClient(lists=lists), SUB_ID, c)
    assert c.ok
    assert summary["waf_resources"] == 0 and summary["public_ips"] == 0 and results["workspaces"] == []


def test_filled_queries_have_no_stray_placeholders():
    for key, kql in wda.filled_queries({"days": 30, "subscription_id": SUB_ID, "sample": 10}).items():
        assert not re.search(r"\{[a-z_]+\}", kql), key
