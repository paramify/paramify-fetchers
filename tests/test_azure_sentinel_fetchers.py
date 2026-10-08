"""Microsoft Sentinel fetchers, driven without Azure.

FakeAzure stands in for requests.Session and serves one subscription with a
Sentinel workspace and a plain Log Analytics workspace. Resource bodies follow the
azure-rest-api-specs examples for SecurityInsights 2025-09-01 (NRT from
2025-10-01-preview). The tests pin the ways these APIs return short or misleading
data without an HTTP error: a second page behind nextLink, rule kinds only a
preview api-version lists, a query's partial result, and a table that does not
exist yet.
"""

from __future__ import annotations

import importlib.util
import base64
import json
import os
import sys
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
FETCHERS = [
    "sentinel_data_sources",
    "sentinel_analytics_rules",
    "sentinel_incidents",
    "sentinel_automation_rules",
    "log_analytics_query_audit",
    "entra_diagnostic_settings",
    "log_analytics_deletion_rights",
    "log_storage_immutability",
    "sentinel_playbooks",
    "entra_risky_users",
]
TENANT_FETCHERS = {"entra_diagnostic_settings", "entra_risky_users"}


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODS = {name: _load(name) for name in FETCHERS}
azure_rest = sys.modules["azure_rest"]

SUB = "00000000-0000-0000-0000-000000000001"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-sec"
WS_A = f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law-sentinel"
WS_B = f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law-plain"
SI_A = f"{WS_A}/providers/Microsoft.SecurityInsights"
NOW = datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def rule(name, kind, enabled, template=None, **props):
    return {"id": f"{SI_A}/alertRules/{name}", "name": name, "kind": kind,
            "properties": {"displayName": name, "enabled": enabled, "alertRuleTemplateName": template,
                           "severity": "High", "tactics": ["Persistence"], **props}}


def incident(name, status, created, classification=None):
    return {"id": f"{SI_A}/incidents/{name}", "name": name,
            "properties": {"title": f"incident {name}", "status": status, "severity": "High",
                           "createdTimeUtc": iso(created), "classification": classification,
                           "owner": {"assignedTo": "john doe", "userPrincipalName": "john@contoso.com"},
                           "relatedAnalyticRuleIds": [f"{SI_A}/alertRules/r1"], "providerName": "Azure Sentinel",
                           "additionalData": {"alertsCount": 2}}}


def table(columns, rows):
    return {"tables": [{"name": "PrimaryResult", "columns": [{"name": c, "type": "string"} for c in columns],
                        "rows": rows}]}


class Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body
        self.reason = "OK" if status < 400 else "Error"
        self.text = json.dumps(body)

    def json(self):
        return self._body


class FakeAzure:
    """ARM GETs keyed by (path, api-version); queries answered by the first matching KQL fragment."""

    def __init__(self):
        self.arm = {
            (f"/subscriptions/{SUB}/providers/Microsoft.OperationalInsights/workspaces", "2023-09-01"): {"value": [
                {"id": WS_A, "name": "law-sentinel", "location": "eastus",
                 "properties": {"customerId": "cust-a", "retentionInDays": 90}},
                {"id": WS_B, "name": "law-plain", "location": "eastus",
                 "properties": {"customerId": "cust-b", "retentionInDays": 90}},
            ]},
            (f"{SI_A}/onboardingStates", "2025-09-01"): {"value": [{"name": "default", "properties": {}}]},
            (f"{WS_B}/providers/Microsoft.SecurityInsights/onboardingStates", "2025-09-01"): {"value": []},
            (f"{SI_A}/dataConnectors", "2025-09-01"): {"value": [
                {"name": "asc", "kind": "AzureSecurityCenter",
                 "properties": {"subscriptionId": SUB, "dataTypes": {"alerts": {"state": "Enabled"}}}},
                {"name": "o365", "kind": "Office365",
                 "properties": {"tenantId": "t", "dataTypes": {"exchange": {"state": "Enabled"},
                                                               "teams": {"state": "Disabled"}}}},
            ]},
            (f"{SI_A}/alertRules", "2025-09-01"): {
                "value": [rule("fusion", "Fusion", True, "f71aba3d-28fb-450b-b192-4e76a83015c8")],
                "nextLink": f"https://management.azure.com{SI_A}/alertRules?api-version=2025-09-01&$skipToken=p2"},
            (f"{SI_A}/alertRules", "2025-09-01", "p2"): {"value": [
                rule("sched", "Scheduled", True, "65360bb0-8986-4ade-a89d-af3cf44d28aa",
                     queryFrequency="PT1H", incidentConfiguration={"createIncident": True}),
                rule("off", "Scheduled", False)]},
            (f"{SI_A}/alertRules", "2025-10-01-preview"): {"value": [
                rule("fusion", "Fusion", True, "f71aba3d-28fb-450b-b192-4e76a83015c8"),
                rule("nrt", "NRT", True)]},
            (f"{SI_A}/alertRuleTemplates", "2025-09-01"): {"value": [
                {"name": "65360bb0-8986-4ade-a89d-af3cf44d28aa", "kind": "Scheduled"},
                {"name": "f71aba3d-28fb-450b-b192-4e76a83015c8", "kind": "Fusion"},
                {"name": "b3cfc7c0-092c-481c-a55b-34a3979758cb", "kind": "MicrosoftSecurityIncidentCreation"}]},
            (f"{SI_A}/incidents", "2025-09-01"): {"value": [
                incident("i-new", "New", NOW - timedelta(days=200)),
                incident("i-closed", "Closed", NOW - timedelta(days=3), "TruePositive"),
                incident("i-old-closed", "Closed", NOW - timedelta(days=200), "FalsePositive")]},
            (f"{SI_A}/automationRules", "2025-09-01"): {"value": [
                {"name": "a1", "properties": {"displayName": "notify", "order": 1,
                 "triggeringLogic": {"isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created",
                                     "conditions": [{"conditionType": "Property", "conditionProperties": {
                                         "propertyName": "IncidentSeverity", "operator": "Equals",
                                         "propertyValues": ["High"]}}]},
                 "actions": [{"order": 1, "actionType": "RunPlaybook",
                              "actionConfiguration": {"logicAppResourceId": f"{RG}/providers/Microsoft.Logic/workflows/pb"}}],
                 "createdBy": {"userPrincipalName": "john@contoso.com"}}},
                {"name": "a2", "properties": {"displayName": "expired", "order": 2,
                 "triggeringLogic": {"isEnabled": True, "expirationTimeUtc": iso(NOW - timedelta(days=1))},
                 "actions": [{"order": 1, "actionType": "ModifyProperties",
                              "actionConfiguration": {"status": "Closed", "classification": "BenignPositive"}}]}}]},
            (f"{WS_A}/providers/Microsoft.Insights/diagnosticSettings", "2021-05-01-preview"): {"value": [
                {"name": "audit", "properties": {"workspaceId": WS_A,
                                                 "logs": [{"category": "Audit", "enabled": True}]}}]},
            (f"{WS_B}/providers/Microsoft.Insights/diagnosticSettings", "2021-05-01-preview"): {"value": []},
        }
        sunday = (NOW - timedelta(days=(NOW.weekday() + 1) % 7)).replace(hour=0, minute=0, second=0, microsecond=0)
        self.queries = [
            ("union withsource=ParamifySourceTable", table(["ParamifySourceTable", "LastIngested", "Records"], [
                ["AzureActivity", iso(NOW), 10], ["SecurityAlert", iso(NOW), 2], ["Usage", iso(NOW), 5]])),
            ("SecurityIncident", table(["IncidentName", "Status", "ClosedTime", "CreatedTime"], [
                ["i-closed", "Closed", iso(NOW - timedelta(days=2)), iso(NOW - timedelta(days=3))],
                ["i-new", "New", None, iso(NOW - timedelta(days=200))]])),
            ("by Week", table(["Week", "Actor", "Queries", "Users"], [
                [iso(sunday), "human", 4, 2], [iso(sunday), "application", 9, 0]])),
            ("by User", table(["User", "Queries", "LastQuery"], [["alice@contoso.com", 4, iso(NOW)]])),
        ]
        self.calls = []
        self.graph_post_response = Resp(200, {"value": [
            {"id": "u-purger", "displayName": "Pat Purger", "userPrincipalName": "pat@contoso.com"},
            {"id": "sp-la", "displayName": "la-automation", "appId": "app-1"}]})
        self.arm.update(EXTRA_ARM)

    def get(self, url, params=None, headers=None, timeout=None):
        parsed = urlparse(url)
        query = dict(p.split("=", 1) for p in parsed.query.split("&") if p) if parsed.query else {}
        query.update(params or {})
        self.calls.append(("GET", parsed.path, query.get("api-version")))
        key = (parsed.path, query.get("api-version"))
        token = query.get("$skipToken") or query.get("$skiptoken")
        if token:
            key = (*key, token)
        if key not in self.arm:
            return Resp(404, {"error": {"code": "ResourceNotFound", "message": f"no {key}"}})
        body = self.arm[key]
        if isinstance(body, Resp):
            return body
        return Resp(200, body)

    def post(self, url, json=None, headers=None, timeout=None):
        if url.endswith("/directoryObjects/getByIds"):
            self.calls.append(("POST", url, ",".join(json["ids"])))
            return self.graph_post_response
        self.calls.append(("POST", url, json["query"]))
        assert headers["x-ms-app"] == "paramify-fetchers"
        for fragment, body in self.queries:
            if fragment in json["query"]:
                return body if isinstance(body, Resp) else Resp(200, body)
        return Resp(400, {"error": {"code": "BadArgumentError", "message": "unrouted query"}})


class FakeCred:
    def get_token(self, scope):
        return namedtuple("T", "token expires_on")("tok", 9_999_999_999)


@pytest.fixture
def azure(monkeypatch, tmp_path):
    fake = FakeAzure()
    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: FakeCred())
    monkeypatch.setattr("requests.Session", lambda: fake)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    for env in ("SENTINEL_WORKSPACES", "AZURE_AUTHORITY_HOST", "AZURE_TENANT_ID"):
        monkeypatch.delenv(env, raising=False)
    return fake


def run(name, tmp_path):
    code = MODS[name].main()
    files = list(tmp_path.glob(f"azure_{name}_*.json"))
    assert len(files) == 1
    return code, json.loads(files[0].read_text())


def ws_a(evidence):
    return next(w for w in evidence["results"]["workspaces"] if w["name"] == "law-sentinel")


# --- shape ----------------------------------------------------------------------

@pytest.mark.parametrize("name", FETCHERS)
def test_every_fetcher_follows_the_shape(name):
    spec = yaml.safe_load((AZURE / name / "fetcher.yaml").read_text())
    assert MODS[name].NAME == spec["name"] == f"azure_{name}"
    if name in TENANT_FETCHERS:
        assert spec["target_schema"]["tenant_id"]["env"] == "AZURE_TENANT_ID"
    elif name != "log_storage_immutability":
        assert spec["target_schema"]["workspaces"]["env"] == azure_rest.WORKSPACES_ENV
    assert spec["evidence_set"]["reference_id"].startswith("EVD-AZURE-")
    assert len(spec["evidence_set"]["instructions"].split()) <= 80
    declared = {f["env"] for f in (spec.get("config_schema") or {}).values()}
    used = {getattr(MODS[name], a) for a in ("WINDOW_ENV", "LOOKBACK_ENV") if hasattr(MODS[name], a)}
    assert used <= declared


# --- the client -----------------------------------------------------------------

def test_list_follows_next_link(azure):
    client = azure_rest.AzureRestClient(FakeCred(), azure)
    rules = client.list(f"{SI_A}/alertRules", "2025-09-01")
    assert [r["name"] for r in rules] == ["fusion", "sched", "off"]


def test_partial_query_result_raises(azure):
    azure.queries.insert(0, ("union withsource=ParamifySourceTable", Resp(200, {
        **table(["ParamifySourceTable"], [["AzureActivity"]]),
        "error": {"code": "PartialError", "innererror": {"message": "query exceeded the row limit"}}})))
    client = azure_rest.AzureRestClient(FakeCred(), azure)
    with pytest.raises(azure_rest.QueryError, match="row limit"):
        client.query("cust-a", "union withsource=ParamifySourceTable *", "P14D")


def test_missing_table_is_recognised():
    exc = azure_rest.QueryError("(400) BadArgumentError",
                              "'where' operator: Failed to resolve table or column expression named 'LAQueryLogs'")
    assert azure_rest.table_missing(exc, "LAQueryLogs")
    assert not azure_rest.table_missing(exc, "SecurityIncident")


def test_logs_endpoint_follows_the_cloud(monkeypatch):
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.us")
    assert azure_rest.logs_endpoint() == "https://api.loganalytics.us"
    monkeypatch.delenv("AZURE_AUTHORITY_HOST")
    assert azure_rest.logs_endpoint() == "https://api.loganalytics.io"


def test_unregistered_provider_reads_as_not_onboarded(azure):
    azure.arm[(f"{SI_A}/onboardingStates", "2025-09-01")] = Resp(
        409, {"error": {"code": "MissingSubscriptionRegistration", "message": "not registered"}})
    assert azure_rest.sentinel_onboarded(azure_rest.AzureRestClient(FakeCred(), azure), WS_A) is False


def test_forbidden_onboarding_check_is_a_failure(azure):
    azure.arm[(f"{SI_A}/onboardingStates", "2025-09-01")] = Resp(
        403, {"error": {"code": "AuthorizationFailed", "message": "no access"}})
    with pytest.raises(azure_rest.ArmError, match=r"\(403\) AuthorizationFailed"):
        azure_rest.sentinel_onboarded(azure_rest.AzureRestClient(FakeCred(), azure), WS_A)


def test_parse_time_takes_seven_fractional_digits():
    assert azure_rest.parse_time("2026-10-01T12:00:00.1234567Z") == datetime(2026, 10, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)


def test_parse_time_short_fractions_and_offsets():
    # Python 3.10's fromisoformat takes only 3 or 6 fractional digits.
    assert azure_rest.parse_time("2026-10-01T12:00:00.12Z") == datetime(2026, 10, 1, 12, 0, 0, 120000, tzinfo=timezone.utc)
    assert azure_rest.parse_time("2026-10-01T17:30:00.5+05:30") == datetime(2026, 10, 1, 12, 0, 0, 500000, tzinfo=timezone.utc)


# --- each fetcher, end to end ---------------------------------------------------

def test_data_sources(azure, tmp_path):
    code, ev = run("sentinel_data_sources", tmp_path)
    assert code == 0 and ev["metadata"]["partial_failure"] is False
    ws = ws_a(ev)
    assert ws["source_tables"] == ["AzureActivity", "SecurityAlert"]
    assert ws["sources_ingesting"] == 2 and ws["self_telemetry_tables"] == ["Usage"]
    o365 = next(c for c in ws["data_connectors"] if c["kind"] == "Office365")
    assert o365["enabled_data_types"] == ["exchange"]
    assert ev["results"]["workspaces_without_sentinel"] == ["law-plain"]
    assert ev["summary"]["workspaces_with_2plus_sources"] == 1


def test_analytics_rules_merge_preview_kinds(azure, tmp_path):
    code, ev = run("sentinel_analytics_rules", tmp_path)
    assert code == 0
    ws = ws_a(ev)
    by_name = {r["name"]: r for r in ws["rules"]}
    assert by_name["nrt"]["seen_in"] == ["preview"] and by_name["fusion"]["seen_in"] == ["stable", "preview"]
    assert ws["enabled_rules"] == 3 and ws["disabled_rules"] == 1
    assert ws["enabled_by_kind"] == {"Fusion": 1, "NRT": 1, "Scheduled": 1}
    assert ws["fusion_enabled"] is True and ws["rules_only_in_preview"] == 1
    assert ws["templates_available"] == 3 and ws["templates_in_use"] == 2


def test_analytics_rules_preview_failure_is_a_note(azure, tmp_path):
    azure.arm[(f"{SI_A}/alertRules", "2025-10-01-preview")] = Resp(
        400, {"error": {"code": "InvalidApiVersionParameter", "message": "retired"}})
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and ws["enabled_rules"] == 2
    assert "NRT" in ws["notes"][0]


def test_analytics_rules_forbidden_fails_the_run(azure, tmp_path):
    azure.arm[(f"{SI_A}/alertRules", "2025-09-01")] = Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
    code, ev = run("sentinel_analytics_rules", tmp_path)
    assert code == 1 and ev["metadata"]["partial_failure"] is True
    assert ws_a(ev)["rules"] is None
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


def test_incidents(azure, tmp_path):
    code, ev = run("sentinel_incidents", tmp_path)
    assert code == 0
    ws = ws_a(ev)
    names = [i["name"] for i in ws["incidents"]]
    assert names == ["i-closed", "i-new"]  # the old closed one is outside the lookback
    closed = ws["incidents"][0]
    assert closed["closed_time_utc"] and closed["hours_to_close"] == pytest.approx(24, abs=0.1)
    assert ws["open_incidents"] == 1 and ws["oldest_open_age_days"] == pytest.approx(200, abs=0.1)
    assert ws["closed_missing_close_time"] == 0
    assert {k: ws["completeness"][k] for k in ("arm_created", "kql_created", "counts_agree")} == {
        "arm_created": 1, "kql_created": 1, "counts_agree": True}
    assert ws["security_incident_retention_days"] == 90 and ws["notes"] == []


def test_incidents_without_the_table(azure, tmp_path):
    azure.queries = [q for q in azure.queries if q[0] != "SecurityIncident"]
    azure.queries.insert(0, ("SecurityIncident", Resp(400, {"error": {"code": "BadArgumentError", "innererror": {
        "message": "'where' operator: Failed to resolve table or column expression named 'SecurityIncident'"}}})))
    code, ev = run("sentinel_incidents", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and ws["closed_missing_close_time"] == 1 and "SecurityIncident" in ws["notes"][0]


def test_automation_rules(azure, tmp_path):
    code, ev = run("sentinel_automation_rules", tmp_path)
    assert code == 0
    ws = ws_a(ev)
    assert ws["active_rules"] == 1 and ws["expired_rules"] == 1
    assert ws["active_actions_by_type"] == {"RunPlaybook": 1}
    assert ws["playbooks_run"] == [f"{RG}/providers/Microsoft.Logic/workflows/pb"]
    assert ws["rules"][0]["conditions"] == [{"type": "Property", "property": "IncidentSeverity",
                                             "operator": "Equals", "values": 1}]


def test_query_audit(azure, tmp_path):
    code, ev = run("log_analytics_query_audit", tmp_path)
    assert code == 0
    by_name = {w["name"]: w for w in ev["results"]["workspaces"]}
    a, b = by_name["law-sentinel"], by_name["law-plain"]
    assert a["query_auditing_enabled"] is True and b["query_auditing_enabled"] is False
    assert a["weeks"][-1]["human_queries"] == 4 and a["weeks"][-1]["application_queries"] == 9
    assert a["weeks_with_human_queries"] == 1 and a["weeks_in_window"] >= 13
    assert a["users"] == [{"user": "alice@contoso.com", "queries": 4, "last_query": a["users"][0]["last_query"]}]
    queried = [c[2] for c in azure.calls if c[0] == "POST"]
    assert all("RequestClientApp != 'paramify-fetchers'" in q for q in queried)
    assert not any("cust-b" in c[1] for c in azure.calls if c[0] == "POST")


def test_workspace_filter_naming_a_missing_workspace_fails(azure, tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_WORKSPACES", "law-sentinel, law-typo")
    code, ev = run("sentinel_automation_rules", tmp_path)
    assert code == 1
    assert [w["name"] for w in ev["results"]["workspaces"]] == ["law-sentinel"]
    assert "law-typo" in ev["metadata"]["api_failures"][0]["message"]


def test_week_starts_are_sundays():
    weeks = MODS["log_analytics_query_audit"].week_starts(datetime(2026, 10, 7, tzinfo=timezone.utc), 14)
    assert weeks == ["2026-09-20", "2026-09-27", "2026-10-04"]


def test_dotenv_in_the_working_folder_is_read(azure, tmp_path, monkeypatch):
    run_dir = tmp_path / "client"
    run_dir.mkdir()
    (run_dir / ".env").write_text("SENTINEL_WORKSPACES=law-typo\n")
    monkeypatch.chdir(run_dir)
    try:
        code, ev = run("sentinel_automation_rules", tmp_path)
    finally:
        os.environ.pop("SENTINEL_WORKSPACES", None)
    assert code == 1 and ev["results"]["workspace_filter"] == ["law-typo"]


def test_incidents_older_than_table_retention_are_not_missing(azure, tmp_path):
    """Measured on a real 30-day workspace: closed incidents older than SecurityIncident's
    retention have no close record left, which is not the same as one never written."""
    azure.arm[(f"{WS_A}/tables/SecurityIncident", "2023-09-01")] = {"properties": {"retentionInDays": 30}}
    stale = incident("i-stale", "Closed", NOW - timedelta(days=60), "TruePositive")
    stale["properties"]["lastModifiedTimeUtc"] = iso(NOW - timedelta(days=59))
    azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"].append(stale)
    code, ev = run("sentinel_incidents", tmp_path)
    ws = ws_a(ev)
    by_name = {i["name"]: i for i in ws["incidents"]}
    assert code == 0 and by_name["i-stale"]["close_time_status"] == "not_retained"
    assert by_name["i-closed"]["close_time_status"] == "found"
    assert ws["closed_missing_close_time"] == 0 and ws["closed_close_time_not_retained"] == 1
    assert ws["completeness"]["counts_agree"] is True and "30 days" in ws["notes"][0]


def test_query_audit_weeks_older_than_retention_are_unknown(azure, tmp_path):
    azure.arm[(f"{WS_A}/tables/LAQueryLogs", "2023-09-01")] = {"properties": {"retentionInDays": 30}}
    code, ev = run("log_analytics_query_audit", tmp_path)
    a = next(w for w in ev["results"]["workspaces"] if w["name"] == "law-sentinel")
    assert code == 0 and a["laquerylogs_retention_days"] == 30
    assert a["weeks_retained"] in (4, 5) and len(a["weeks_not_retained"]) == a["weeks_in_window"] - a["weeks_retained"]
    assert set(a["weeks_without_human_queries"]).isdisjoint(a["weeks_not_retained"])
    assert all(w["human_queries"] is None for w in a["weeks"] if not w["retained"])


# --- the gap-closing fetchers ---------------------------------------------------

RD = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions"
PB = f"{RG}/providers/Microsoft.Logic/workflows/pb"
SA = f"{RG}/providers/Microsoft.Storage/storageAccounts"


def role_def(guid, name, actions, not_actions=()):
    return {"id": f"{RD}/{guid}", "properties": {"roleName": name, "type": "BuiltInRole",
                                                  "permissions": [{"actions": list(actions), "notActions": list(not_actions)}]}}


def assignment(principal, kind, guid, scope):
    return {"properties": {"principalId": principal, "principalType": kind,
                           "roleDefinitionId": f"{RD}/{guid}", "scope": scope}}


def container(name, policy=None, legal_hold=False):
    props = {"hasImmutabilityPolicy": policy is not None, "hasLegalHold": legal_hold}
    if policy:
        props["immutabilityPolicy"] = {"properties": policy}
    return {"name": name, "properties": props}


PLAYBOOK = {"id": PB, "name": "pb", "properties": {
    "state": "Enabled",
    "parameters": {"$connections": {"value": {
        "azuresentinel": {"id": "/subscriptions/x/providers/Microsoft.Web/locations/eastus/managedApis/azuresentinel"},
        "office365": {"id": "/subscriptions/x/providers/Microsoft.Web/locations/eastus/managedApis/office365"},
        "azuread": {"id": "/subscriptions/x/providers/Microsoft.Web/locations/eastus/managedApis/azuread"}}}},
    "definition": {
        "triggers": {"Microsoft_Sentinel_incident": {"type": "ApiConnectionWebhook", "inputs": {
            "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
            "path": "/incident-creation"}}},
        "actions": {"Condition": {"type": "If", "actions": {
            "Send_an_email_(V2)": {"type": "ApiConnection", "inputs": {
                "host": {"connection": {"name": "@parameters('$connections')['office365']['connectionId']"}},
                "method": "post", "path": "/v2/Mail",
                "body": {"To": "SecOps@Contoso.com; @{triggerBody()?['owner']}", "Subject": "incident"}}}},
            "else": {"actions": {
                "Disable_user": {"type": "ApiConnection", "inputs": {
                    "host": {"connection": {"name": "@parameters('$connections')['azuread']['connectionId']"}},
                    "method": "patch", "path": "/v1.0/users/@{encodeURIComponent('x')}",
                    "body": {"accountEnabled": False}}}}}}}}}}
NOT_A_PLAYBOOK = {"id": f"{RG}/providers/Microsoft.Logic/workflows/etl", "name": "etl",
                  "properties": {"state": "Enabled", "definition": {"triggers": {"Recurrence": {"type": "Recurrence"}},
                                                                     "actions": {}}}}

EXTRA_ARM = {
    ("/providers/microsoft.aadiam/diagnosticSettings", "2017-04-01"): {"value": [
        {"name": "to-sentinel", "properties": {"workspaceId": WS_A, "logs": [
            {"category": "AuditLogs", "enabled": True}, {"category": "SignInLogs", "enabled": True},
            {"category": "ProvisioningLogs", "enabled": False}]}},
        {"name": "archive", "properties": {"storageAccountId": f"{SA}/starchive", "logs": [
            {"category": "NonInteractiveUserSignInLogs", "enabled": True}]}}]},
    ("/providers/microsoft.aadiam/diagnosticSettingsCategories", "2017-04-01"): {"value": [
        {"name": n} for n in ("AuditLogs", "SignInLogs", "NonInteractiveUserSignInLogs", "ProvisioningLogs")]},
    (f"{WS_A}/providers/Microsoft.Authorization/roleAssignments", "2022-04-01"): {"value": [
        assignment("u-purger", "User", "purger", WS_A),
        assignment("sp-la", "ServicePrincipal", "lacontrib", f"/subscriptions/{SUB}"),
        assignment("u-reader", "User", "reader", f"/subscriptions/{SUB}"),
        assignment("g-ops", "Group", "nopurge", RG)]},
    (f"{WS_B}/providers/Microsoft.Authorization/roleAssignments", "2022-04-01"): {"value": []},
    (f"{RD}/purger", "2022-04-01"): role_def("purger", "Data Purger", ["Microsoft.OperationalInsights/workspaces/purge/action"]),
    (f"{RD}/lacontrib", "2022-04-01"): role_def("lacontrib", "Log Analytics Contributor", ["*/read", "Microsoft.OperationalInsights/*"]),
    (f"{RD}/reader", "2022-04-01"): role_def("reader", "Reader", ["*/read"]),
    (f"{RD}/nopurge", "2022-04-01"): role_def("nopurge", "Ops Custom", ["*"], ["Microsoft.OperationalInsights/workspaces/purge/action"]),
    (f"/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts", "2023-05-01"): {"value": [
        {"id": f"{SA}/stlogs", "name": "stlogs", "kind": "StorageV2", "properties": {}},
        {"id": f"{SA}/stfiles", "name": "stfiles", "kind": "FileStorage", "properties": {}},
        {"id": f"{SA}/stapp", "name": "stapp", "kind": "StorageV2", "properties": {}}]},
    (f"{SA}/stlogs/blobServices/default/containers", "2023-05-01"): {"value": [
        container("insights-logs-auditevent", {"state": "Locked", "immutabilityPeriodSinceCreationInDays": 365}),
        container("insights-activity-logs"),
        container("am-securityevent", {"state": "Unlocked", "immutabilityPeriodSinceCreationInDays": 30}),
        container("uploads")]},
    (f"{SA}/stlogs/blobServices/default", "2023-05-01"): {"properties": {
        "deleteRetentionPolicy": {"enabled": True, "days": 14}, "isVersioningEnabled": True}},
    (f"{SA}/stapp/blobServices/default/containers", "2023-05-01"): {"value": [container("images")]},
    (f"/subscriptions/{SUB}/providers/Microsoft.Logic/workflows", "2019-05-01"): {"value": [PLAYBOOK, NOT_A_PLAYBOOK]},
    ("/v1.0/identityProtection/riskyUsers", None): {"value": [
        {"id": "u-admin", "userPrincipalName": "admin@contoso.com", "riskLevel": "high", "riskState": "atRisk",
         "riskLastUpdatedDateTime": iso(NOW - timedelta(days=10))}],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$skiptoken=p2"},
    ("/v1.0/identityProtection/riskyUsers", None, "p2"): {"value": [
        {"id": "u-staff", "userPrincipalName": "staff@contoso.com", "riskLevel": "medium", "riskState": "remediated",
         "riskLastUpdatedDateTime": iso(NOW - timedelta(days=3))}]},
    ("/v1.0/directoryRoles", None): {"value": [
        {"displayName": "Global Administrator", "members": [{"id": "u-admin"}]}]},
    ("/v1.0/users/u-admin", None): {"id": "u-admin", "accountEnabled": True},
}


def test_entra_diagnostic_settings(azure, tmp_path):
    code, ev = run("entra_diagnostic_settings", tmp_path)
    assert code == 0
    s = ev["summary"]
    assert s["key_categories_to_sentinel"] == {"AuditLogs": True, "SignInLogs": True}
    assert s["audit_and_signin_logs_to_sentinel"] is True and s["categories_not_exported"] == ["ProvisioningLogs"]
    coverage = {c["category"]: c for c in ev["results"]["category_coverage"]}
    assert coverage["NonInteractiveUserSignInLogs"]["to_storage"] is True
    assert coverage["NonInteractiveUserSignInLogs"]["to_sentinel_workspace"] is False


def test_entra_diagnostic_settings_wrong_tenant_fails(azure, tmp_path, monkeypatch):
    claims = base64.urlsafe_b64encode(json.dumps({"tid": "other-tenant"}).encode()).decode().rstrip("=")
    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: type("C", (), {
        "get_token": lambda self, scope: namedtuple("T", "token expires_on")(f"h.{claims}.s", 9_999_999_999)})())
    monkeypatch.setenv("AZURE_TENANT_ID", "target-tenant")
    code, ev = run("entra_diagnostic_settings", tmp_path)
    assert code == 1 and "not the target tenant" in ev["metadata"]["api_failures"][0]["message"]
    assert not any("aadiam" in c[1] for c in azure.calls)


def test_deletion_rights(azure, tmp_path):
    code, ev = run("log_analytics_deletion_rights", tmp_path)
    assert code == 0
    ws = ws_a(ev)
    grants = {g["principal_id"]: g for g in ws["deletion_grants"]}
    assert set(grants) == {"u-purger", "sp-la", "g-ops"}
    assert grants["u-purger"]["granted"]["purge"]["kind"] == "explicit" and not grants["u-purger"]["can_delete_data"]
    assert grants["sp-la"]["granted"]["purge"]["via"] == "Microsoft.OperationalInsights/*"
    assert grants["sp-la"]["can_delete_data"] and grants["sp-la"]["scope_level"] == "subscription"
    assert grants["g-ops"]["can_purge"] is False and grants["g-ops"]["can_delete_data"] is True
    assert grants["u-purger"]["principal_name"] == "Pat Purger"
    assert ws["principals_with_purge"] == 2 and ws["principals_with_explicit_grant"] == 1


def test_deletion_rights_names_are_optional(azure, tmp_path):
    azure.graph_post_response = Resp(403, {"error": {"code": "Authorization_RequestDenied", "message": "no"}})
    code, ev = run("log_analytics_deletion_rights", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and ws["principals_with_deletion_rights"] == 3 and "not resolved" in ws["notes"][0]


def test_log_storage_immutability(azure, tmp_path):
    code, ev = run("log_storage_immutability", tmp_path)
    assert code == 0
    accounts = ev["results"]["accounts"]
    assert [a["account"] for a in accounts] == ["stlogs"]
    by_name = {c["container"]: c for c in accounts[0]["log_containers"]}
    assert set(by_name) == {"insights-logs-auditevent", "insights-activity-logs", "am-securityevent"}
    assert by_name["insights-logs-auditevent"]["locked"] and by_name["insights-logs-auditevent"]["retention_days"] == 365
    assert by_name["am-securityevent"]["protected"] and not by_name["am-securityevent"]["locked"]
    assert by_name["insights-activity-logs"]["protected"] is False
    assert accounts[0]["blob_soft_delete_days"] == 14
    assert ev["summary"] == {"storage_accounts_scanned": 3, "accounts_with_log_containers": 1, "log_containers": 3,
                             "locked_policy": 1, "unlocked_policy_only": 1, "legal_hold": 0, "unprotected": 1,
                             "min_retention_days": 30}
    assert not any("stfiles" in c[1] for c in azure.calls)


def test_sentinel_playbooks(azure, tmp_path):
    code, ev = run("sentinel_playbooks", tmp_path)
    assert code == 0
    (pb,) = ev["results"]["playbooks"]
    assert pb["name"] == "pb" and pb["triggers"][0]["kind"] == "incident"
    assert pb["capabilities"] == {"account_containment": True, "device_isolation": False, "email": True,
                                  "teams": False, "incident_update": False}
    assert pb["email_recipients"] == ["secops@contoso.com"] and pb["dynamic_recipient_fields"] == 1
    assert pb["automation_rules"] == [{"workspace": "law-sentinel", "rule": "notify", "active": True}]
    s = ev["summary"]
    assert s["run_by_active_automation_rule"] == 1 and s["live_account_containment_playbooks"] == 1
    assert s["notification_recipients"] == ["secops@contoso.com"] and s["logic_apps_scanned"] == 2


def test_entra_risky_users(azure, tmp_path):
    code, ev = run("entra_risky_users", tmp_path)
    assert code == 0
    users = {u["user_principal_name"]: u for u in ev["results"]["risky_users"]}
    assert users["admin@contoso.com"]["privileged_roles"] == ["Global Administrator"]
    assert users["admin@contoso.com"]["account_enabled"] is True and "account_enabled" not in users["staff@contoso.com"]
    s = ev["summary"]
    assert s["risky_users_total"] == 2 and s["by_risk_state"] == {"atRisk": 1, "remediated": 1}
    assert s["privileged_open_risk_users"] == 1 and s["privileged_open_risk_users_enabled"] == 1


def test_entra_risky_users_without_p2_is_a_state(azure, tmp_path):
    azure.arm[("/v1.0/identityProtection/riskyUsers", None)] = Resp(
        403, {"error": {"code": "Forbidden", "message": "Your tenant is not licensed for this feature."}})
    code, ev = run("entra_risky_users", tmp_path)
    assert code == 0 and ev["summary"] == {"identity_protection_available": False}
