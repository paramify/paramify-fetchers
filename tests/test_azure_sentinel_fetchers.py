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

import base64
import importlib.util
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


def law_tables(names, basic=()):
    return {"value": [{"name": n, "properties": {"plan": "Analytics"}} for n in names]
            + [{"name": n, "properties": {"plan": "Basic"}} for n in basic]}


class Resp:
    def __init__(self, status, body, headers=None):
        self.status_code, self._body = status, body
        self.reason = "OK" if status < 400 else "Error"
        self.text = json.dumps(body)
        self.headers = headers or {}

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
            (f"{SI_A}/dataConnectors", "2025-10-01-preview"): {"value": []},
            (f"{SI_A}/dataConnectorDefinitions", "2025-09-01"): {"value": []},
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
                {"name": "f71aba3d-28fb-450b-b192-4e76a83015c8", "kind": "Fusion", "properties": {"requiredDataConnectors": [
                    {"connectorId": "AzureActiveDirectoryIdentityProtection", "dataTypes": ["SecurityAlert (IPC)"]},
                    {"connectorId": "Syslog", "dataTypes": ["Syslog"]}]}},
                {"name": "b3cfc7c0-092c-481c-a55b-34a3979758cb", "kind": "MicrosoftSecurityIncidentCreation"}]},
            (f"{SI_A}/alertRuleTemplates", "2025-10-01-preview"): {"value": [
                {"name": "f71aba3d-28fb-450b-b192-4e76a83015c8", "kind": "Fusion"},
                {"name": "tpl-nrt", "kind": "NRT", "properties": {"requiredDataConnectors": [
                    {"connectorId": "AzureActivity", "dataTypes": ["AzureActivity"]}]}}]},
            (f"{SI_A}/alertRuleTemplates/tpl-nrt", "2025-10-01-preview"): {
                "name": "tpl-nrt", "kind": "NRT", "properties": {"requiredDataConnectors": [
                    {"connectorId": "AzureActivity", "dataTypes": ["AzureActivity"]}]}},
            (f"{WS_A}/tables", "2023-09-01"): {"value": WORKSPACE_TABLES + EXTRA_TABLES["value"]},
            (f"{WS_A}/savedSearches", "2023-09-01"): {"value": [
                {"name": "parser", "properties": {"category": "Security", "functionAlias": "CiscoASA", "query": "Syslog"}},
                {"name": "hunt", "properties": {"category": "Hunting Queries", "query": "SigninLogs | take 1"}}]},
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
                ["AzureActivity", iso(NOW), 10], ["SecurityAlert", iso(NOW), 2], ["Usage", iso(NOW), 5],
                ["Heartbeat", iso(NOW), 50]])),
            (HISTORY_ROUTE, history_table(incident_history())),
            ("SystemAlertId", table(["IncidentName", "AlertId", "Entities"], INCIDENT_ALERT_ENTITIES)),
            ("arg_max(Order, Status, ClosedTime", table(["IncidentName", "Status", "ClosedTime", "CreatedTime", "Tasks"], [
                ["i-closed", "Closed", iso(NOW - timedelta(days=2)), iso(NOW - timedelta(days=3)), INCIDENT_TASKS],
                ["i-new", "New", None, iso(NOW - timedelta(days=200)), "[]"]])),
            ("by ProductName", table(["ProductName", "LastIngested", "Records"], [
                ["Microsoft Defender Advanced Threat Protection", iso(NOW), 1], ["Azure Sentinel", iso(NOW), 1]])),
            ("ParamifyIndex", table(["Time", "ParamifyIndex"], [])),
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
        if isinstance(body, list):  # answered in turn, the last one repeating
            body = body.pop(0) if len(body) > 1 else body[0]
        if isinstance(body, Resp):
            return body
        return Resp(200, body)

    def post(self, url, json=None, headers=None, timeout=None):
        if url.endswith("/directoryObjects/getByIds"):
            self.calls.append(("POST", url, ",".join(json["ids"])))
            return self.graph_post_response
        self.calls.append(("POST", url, json["query"]))
        assert headers["x-ms-app"] == "paramify-fetchers"
        for fragment, body in self.queries:  # a fragment matches the query text or the workspace's query URL
            if fragment in json["query"] or fragment in url:
                if isinstance(body, list):
                    body = body.pop(0) if len(body) > 1 else body[0]
                return body if isinstance(body, Resp) else Resp(200, body)
        return Resp(400, {"error": {"code": "BadArgumentError", "message": "unrouted query"}})


class FakeCred:
    def get_token(self, scope):
        return namedtuple("T", "token expires_on")("tok", 9_999_999_999)


@pytest.fixture
def azure(monkeypatch, tmp_path):
    fake = FakeAzure()
    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: FakeCred())
    monkeypatch.setattr(azure_rest, "REPO_ROOT", tmp_path / "repo")
    fake.sleeps = []
    monkeypatch.setattr(azure_rest.time, "sleep", fake.sleeps.append)
    monkeypatch.setattr("requests.Session", lambda: fake)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    for env in ("SENTINEL_WORKSPACES", "AZURE_AUTHORITY_HOST", "AZURE_TENANT_ID", "SENTINEL_RULE_QUERY_TEXT"):
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
    instructions = spec["evidence_set"]["instructions"]
    if not instructions.startswith(f"Script: azure/{name}/fetcher.py\n"):  # the plain-text layout has no word limit
        assert len(instructions.split()) <= 80
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
    # SecurityAlert counts once per other product; Sentinel's own alerts and agent Heartbeat don't count.
    assert ws["source_tables"] == ["AzureActivity", "SecurityAlert (Microsoft Defender Advanced Threat Protection)"]
    assert ws["sources_ingesting"] == 2 and ws["non_source_tables"] == ["Heartbeat", "Usage"]
    assert [p["product"] for p in ws["alert_products"] if not p["counts_as_source"]] == ["Azure Sentinel"]
    o365 = next(c for c in ws["data_connectors"] if c["kind"] == "Office365")
    assert o365["enabled_data_types"] == ["exchange"]
    assert ev["results"]["workspaces_without_sentinel"] == ["law-plain"]
    assert ev["summary"]["workspaces_with_2plus_sources"] == 1


def ui_connector(name, data_types, criteria=None):
    return {"id": f"{SI_A}/dataConnectors/{name}", "name": name, "kind": "StaticUI", "properties": {"connectorUiConfig": {
        "title": name, "connectivityCriterias": criteria or [],
        "dataTypes": [{"name": n, "lastDataReceivedQuery": f"{q}\n | summarize Time = max(TimeGenerated)\n | where isnotempty(Time)"}
                      for n, q in data_types]}}}


def connectors_workspace(azure):
    """Content Hub definitions, a codeless one, and connections only the preview listing returns."""
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")] = {"value": [
        ui_connector("AzureActiveDirectory", [("SigninLogs", "SigninLogs"), ("AuditLogs", "AuditLogs")]),
        ui_connector("MicrosoftDefenderAdvancedThreatProtection",
                     [("SecurityAlert (MDATP)", 'SecurityAlert\u200b | where ProviderName == "MDATP"')],
                     [{"type": "MtpAlerts", "value": ["MicrosoftDefenderAdvancedThreatProtection"]}]),
        ui_connector("Office365", [("OfficeActivity (Exchange)", 'OfficeActivity | where OfficeWorkload == "Exchange"'),
                                   ("OfficeActivity (Teams)", 'OfficeActivity | where OfficeWorkload == "MicrosoftTeams"')]),
        {"id": f"{SI_A}/dataConnectors/o365", "name": "o365", "kind": "Office365",
         "properties": {"dataTypes": {"exchange": {"state": "Enabled"}}}},
        {"id": f"{SI_A}/dataConnectors/mtp", "name": "mtp", "kind": "MicrosoftThreatProtection",
         "properties": {"dataTypes": {"alerts": {"state": "enabled"}, "incidents": {"state": "enabled"}}}},
        {"id": f"{SI_A}/dataConnectors/ccp1", "name": "ccp1", "kind": "RestApiPoller",
         "properties": {"connectorDefinitionName": "MyCcp"}}]}
    azure.arm[(f"{SI_A}/dataConnectorDefinitions", "2025-09-01")] = {"value": [
        {"name": "MyCcp", "kind": "Customizable", "properties": {"connectorUiConfig": {
            "title": "My codeless connector", "graphQueriesTableName": "MyCcp_CL",
            "dataTypes": [{"name": "{{graphQueriesTableName}}",
                           "lastDataReceivedQuery": "{{graphQueriesTableName}}\n | summarize Time = max(TimeGenerated)\n | where isnotempty(Time)"}],
            "connectivityCriteria": [{"type": "HasDataConnectors"}]}}}]}
    azure.queries[0] = ("union withsource=ParamifySourceTable", table(["ParamifySourceTable", "LastIngested", "Records"], [
        ["SigninLogs", iso(NOW - timedelta(hours=1)), 9], ["SecurityAlert", iso(NOW), 2], ["OfficeActivity", iso(NOW), 4],
        ["SentinelHealth", iso(NOW), 1], ["Usage", iso(NOW), 5]]))
    azure.queries.insert(0, ("SentinelResourceType", table(
        ["SentinelResourceId", "TimeGenerated", "Status", "Reason", "Description", "SentinelResourceKind", "SentinelResourceName"],
        [[f"{SI_A}/dataConnectors/CCP1", iso(NOW), "Failure", "Unauthorized", "token expired", "RestApiPoller", "ccp1"]])))


def test_data_sources_last_data_per_connector(azure, tmp_path):
    connectors_workspace(azure)
    # Filtered data types on tables with data, in catalog order: ASC alerts, MDATP alerts, Defender XDR alerts, Exchange, Teams.
    azure.queries.insert(0, ("ParamifyIndex", table(["Time", "ParamifyIndex"], [[iso(NOW), 1], [iso(NOW), 2], [iso(NOW), 3]])))
    code, ev = run("sentinel_data_sources", tmp_path)
    assert code == 0 and ev["metadata"]["partial_failure"] is False
    ws = ws_a(ev)
    union = next(q for _, _, q in azure.calls if "ParamifyIndex" in q)
    # Bare tables come from the ingestion query; listed tables with no data aren't queried.
    assert "\u200b" not in union and union.count("ParamifyIndex =") == 5
    assert "AuditLogs" not in union and "MyCcp_CL" not in union
    # Sentinel's own analytics alerts in SecurityAlert don't count for Defender XDR.
    assert 'SecurityAlert | where ProductName in ("Microsoft Defender Advanced Threat Protection"' in union
    assert [(c["name"], c["seen_in"]) for c in ws["data_connectors"]] == [
        ("asc", ["stable"]), ("mtp", ["preview"]), ("o365", ["stable", "preview"]), ("ccp1", ["preview"])]
    by_id = {c["id"]: c for c in ws["connectors"]}
    assert list(by_id) == ["AzureActiveDirectory", "AzureSecurityCenter", "MicrosoftDefenderAdvancedThreatProtection",
                           "MicrosoftThreatProtection", "MyCcp", "Office365"]
    aad = by_id["AzureActiveDirectory"]
    assert [d["last_data_received"] is not None for d in aad["data_types"]] == [True, False]
    assert aad["connected"] is True and aad["definition"] == "content_hub" and aad["connections"] == []
    asc = by_id["AzureSecurityCenter"]
    assert (asc["definition"], asc["alert_only"], asc["connected"]) == ("built_in", True, False)
    assert by_id["MicrosoftDefenderAdvancedThreatProtection"]["connections"] == ["mtp"]
    mtp = by_id["MicrosoftThreatProtection"]
    assert [d["table"] for d in mtp["data_types"]] == ["SecurityIncident", "SecurityAlert"] and mtp["connected"] is True
    assert mtp["alert_only"] is False and by_id["MicrosoftDefenderAdvancedThreatProtection"]["alert_only"] is True
    ccp = by_id["MyCcp"]
    assert (ccp["definition"], ccp["connections"], ccp["data_types"][0]["table"]) == ("codeless", ["ccp1"], "MyCcp_CL")
    assert ccp["connected"] is False and ccp["health_status"] == "Failure"
    office = by_id["Office365"]
    assert office["connections"] == ["o365"] and office["last_data_received"] == iso(NOW)
    assert [d["last_data_received"] is not None for d in office["data_types"]] == [True, False]
    assert ws["connectors_connected"] == 4 and ws["connectors_not_connected"] == ["MyCcp"]
    assert ws["connectors_quiet"] == ["AzureSecurityCenter"]
    assert ws["connectors_configured_without_data"] == ["MyCcp"]
    assert ws["health_monitoring"] is True and ws["connector_health"][0]["reason"] == "Unauthorized"
    assert {k: ev["summary"][k] for k in ("connectors_connected", "connectors_not_connected", "connectors_quiet",
                                          "connectors_configured_without_data", "workspaces_with_health_monitoring",
                                          "connectors_unhealthy")} == {
        "connectors_connected": 4, "connectors_not_connected": 1, "connectors_quiet": 1,
        "connectors_configured_without_data": 1, "workspaces_with_health_monitoring": 1, "connectors_unhealthy": 1}


def alert_only_workspace(azure, discovery_logs):
    """Alert-only connectors fed by their own connection, by Defender XDR, by a connection with alerts off, and by nothing."""
    azure.arm[(f"{SI_A}/dataConnectors", "2025-09-01")] = {"value": [
        {"id": f"{SI_A}/dataConnectors/mcas", "name": "mcas", "kind": "MicrosoftCloudAppSecurity", "properties": {
            "dataTypes": {"alerts": {"state": "Enabled"}, "discoveryLogs": {"state": discovery_logs}}}},
        {"id": f"{SI_A}/dataConnectors/oatp", "name": "oatp", "kind": "OfficeATP",
         "properties": {"dataTypes": {"alerts": {"state": "Disabled"}}}},
        {"id": f"{SI_A}/dataConnectors/o365", "name": "o365", "kind": "Office365",
         "properties": {"dataTypes": {"exchange": {"state": "Enabled"}}}}]}
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")] = {"value": [
        ui_connector("MicrosoftCloudAppSecurity", [
            ("SecurityAlert (MCAS)", 'SecurityAlert | where ProductName == "Microsoft Cloud App Security"'),
            ("McasShadowItReporting", "McasShadowItReporting")]),
        ui_connector("AzureAdvancedThreatProtection",
                     [("SecurityAlert (AATP)", 'SecurityAlert | where ProductName == "Azure Advanced Threat Protection"')],
                     [{"type": "MtpAlerts", "value": ["AzureAdvancedThreatProtection"]}]),
        ui_connector("AzureSecurityCenter", [("SecurityAlert (ASC)", 'SecurityAlert | where ProductName == "Azure Security Center"')]),
        ui_connector("Office365", [("OfficeActivity (Exchange)", 'OfficeActivity | where OfficeWorkload == "Exchange"')]),
        {"id": f"{SI_A}/dataConnectors/mtp", "name": "mtp", "kind": "MicrosoftThreatProtection",
         "properties": {"dataTypes": {"alerts": {"state": "enabled"}, "incidents": {"state": "enabled"}}}}]}


def test_data_sources_alert_only_connectors_read_quiet(azure, tmp_path):
    alert_only_workspace(azure, "Disabled")
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    by_id = {c["id"]: c for c in ws["connectors"]}
    assert code == 0 and {i: c["alert_only"] for i, c in by_id.items()} == {
        "AzureAdvancedThreatProtection": True, "AzureSecurityCenter": True, "MicrosoftCloudAppSecurity": True,
        "MicrosoftThreatProtection": False, "Office365": False, "OfficeATP": True}
    # Quiet needs a linked connection sending alerts, its own or Defender XDR's; Cloud Discovery logs are off on MCAS.
    assert ws["connectors_quiet"] == ["AzureAdvancedThreatProtection", "MicrosoftCloudAppSecurity"]
    assert by_id["AzureAdvancedThreatProtection"]["connections"] == ["mtp"]
    assert by_id["MicrosoftCloudAppSecurity"]["connected"] is False
    # Never connected, or its connection's alerts are Disabled: not connected.
    assert (by_id["AzureSecurityCenter"]["connections"], by_id["OfficeATP"]["connections"]) == ([], ["oatp"])
    assert ws["connectors_not_connected"] == ["AzureSecurityCenter", "MicrosoftThreatProtection", "Office365", "OfficeATP"]
    assert ws["connectors_connected"] == 0
    assert (ev["summary"]["connectors_quiet"], ev["summary"]["connectors_not_connected"]) == (2, 4)


@pytest.mark.parametrize("own", [False, True])
def test_data_sources_defender_xdr_links_only_the_products_it_carries(azure, tmp_path, own):
    alert_only_workspace(azure, "Disabled")
    # Tenant-based Defender for Cloud's MtpAlerts value isn't in Defender XDR's list; IoT has no MtpAlerts criterion.
    preview = azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")]["value"]
    preview += [
        ui_connector("MicrosoftDefenderForCloudTenantBased",
                     [("SecurityAlert(ASC)", 'SecurityAlert | where ProductName == "Azure Security Center"')],
                     [{"type": "MtpAlerts", "value": ["MicrosoftDefenderForCloudTenantBased"]}]),
        ui_connector("IoT", [("SecurityAlert (ASC for IoT)", 'SecurityAlert | where ProductName == "Azure Security Center for IoT"')],
                     [{"type": "SentinelKinds", "value": ["IOT"]}])]
    if own:
        preview.append({"id": f"{SI_A}/dataConnectors/mdc", "name": "mdc", "kind": "RestApiPoller", "properties": {
            "connectorDefinitionName": "MicrosoftDefenderForCloudTenantBased", "dataTypes": {"alerts": {"state": "Disabled"}}}})
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    by_id = {c["id"]: c for c in ws["connectors"]}
    # Defender XDR still makes Defender for Identity quiet, but not Defender for Cloud or IoT.
    assert code == 0 and ws["connectors_quiet"] == ["AzureAdvancedThreatProtection", "MicrosoftCloudAppSecurity"]
    assert {"IoT", "MicrosoftDefenderForCloudTenantBased"} <= set(ws["connectors_not_connected"])
    assert ("MicrosoftDefenderForCloudTenantBased" in ws["connectors_configured_without_data"]) is own
    mdc = by_id["MicrosoftDefenderForCloudTenantBased"]
    assert (mdc["alert_only"], mdc["connected"]) == (True, False)
    assert (mdc["connections"], by_id["IoT"]["connections"]) == ((["mdc"] if own else []), [])


def test_data_sources_defender_xdr_link_needs_every_mtp_alerts_value_carried(azure, tmp_path):
    alert_only_workspace(azure, "Disabled")
    alert = 'SecurityAlert | where ProductName == "{}"'
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")]["value"] += [
        ui_connector("AzureActiveDirectoryIdentityProtection",
                     [("SecurityAlert (IPC)", alert.format("Azure Active Directory Identity Protection"))],
                     [{"type": "MtpAlerts", "value": ["AzureActiveDirectory"]}]),
        ui_connector("OfficeATP", [("SecurityAlert(OATP)", 'SecurityAlert | where ProviderName == "OATP"')],
                     [{"type": "MtpAlerts", "value": ["OfficeATP"]}]),
        ui_connector("OfficeIRM", [("SecurityAlert (OfficeIRM)", alert.format("Microsoft 365 Insider Risk Management"))],
                     [{"type": "MtpAlerts", "value": ["OfficeIRM"]}]),
        ui_connector("Mixed", [("SecurityAlert", alert.format("Azure Security Center"))],
                     [{"type": "MtpAlerts", "value": ["AzureAdvancedThreatProtection", "MicrosoftDefenderForCloudTenantBased"]}])]
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    by_id = {c["id"]: c for c in ws["connectors"]}
    # OfficeATP's own connection has alerts Disabled, so only Defender XDR makes it quiet.
    assert code == 0 and ws["connectors_quiet"] == [
        "AzureActiveDirectoryIdentityProtection", "AzureAdvancedThreatProtection", "MicrosoftCloudAppSecurity",
        "OfficeATP", "OfficeIRM"]
    assert [by_id[i]["connections"] for i in ("AzureActiveDirectoryIdentityProtection", "OfficeATP", "OfficeIRM")] == [
        ["mtp"], ["mtp", "oatp"], ["mtp"]]
    # One value Defender XDR doesn't carry is enough to leave it unlinked.
    assert by_id["Mixed"]["connections"] == [] and "Mixed" in ws["connectors_not_connected"]


def test_data_sources_configured_without_data_leaves_out_unconnected_and_quiet(azure, tmp_path):
    alert_only_workspace(azure, "Disabled")
    # Installed from Content Hub with no connection, and not alert-only; and one connected to a Basic-plan table.
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")]["value"] += [
        ui_connector("AzureActiveDirectory", [("AuditLogs", "AuditLogs")]),
        ui_connector("AzureStorage", [("StorageBlobLogs", "StorageBlobLogs")])]
    azure.arm[(f"{SI_A}/dataConnectors", "2025-09-01")]["value"].append(
        {"id": f"{SI_A}/dataConnectors/storage", "name": "storage", "kind": "AzureStorage", "properties": {}})
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    by_id = {c["id"]: c for c in ws["connectors"]}
    assert code == 0 and (by_id["AzureActiveDirectory"]["connections"], by_id["AzureActiveDirectory"]["connected"]) == ([], False)
    # Configured but unmeasured isn't listed.
    assert (by_id["AzureStorage"]["connections"], by_id["AzureStorage"]["connected"]) == (["storage"], None)
    assert {"AzureActiveDirectory", "AzureSecurityCenter"} <= set(ws["connectors_not_connected"])
    # OfficeATP's connection has alerts Disabled; AATP (via Defender XDR) and MCAS are quiet.
    assert ws["connectors_configured_without_data"] == ["MicrosoftThreatProtection", "Office365", "OfficeATP"]
    assert ev["summary"]["connectors_configured_without_data"] == 3


def test_data_sources_configured_without_data_reads_null_when_any_workspace_is_unmeasured(azure, tmp_path):
    onboard_second_workspace(azure)
    si_b = f"{WS_B}/providers/Microsoft.SecurityInsights"
    for api in ("2025-09-01", "2025-10-01-preview"):
        azure.arm[(f"{si_b}/dataConnectors", api)] = {"value": []}
    azure.arm[(f"{si_b}/dataConnectorDefinitions", "2025-09-01")] = {"value": []}
    azure.arm[(f"{WS_B}/tables", "2023-09-01")] = law_tables(["AzureActivity", "SecurityAlert", "Usage", "Heartbeat"])
    # A failed preview listing is only a note, so the run still exits 0.
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")] = Resp(
        400, {"error": {"code": "InvalidApiVersionParameter", "message": "retired"}})
    code, ev = run("sentinel_data_sources", tmp_path)
    by_name = {w["name"]: w for w in ev["results"]["workspaces"]}
    assert code == 0 and ev["metadata"]["partial_failure"] is False
    assert (by_name["law-sentinel"]["connectors_configured_without_data"],
            by_name["law-plain"]["connectors_configured_without_data"]) == (None, [])
    # The siblings still sum the measured workspaces.
    assert (ev["summary"]["connectors_configured_without_data"], ev["summary"]["connectors_not_connected"]) == (None, 0)


def test_data_sources_configured_without_data_is_null_without_a_sentinel_workspace(azure, tmp_path):
    azure.arm[(f"{SI_A}/onboardingStates", "2025-09-01")] = {"value": []}
    code, ev = run("sentinel_data_sources", tmp_path)
    # Nothing measured can't read as none configured without data.
    assert code == 0 and ev["summary"]["workspaces_without_sentinel"] == 2
    assert ev["summary"]["connectors_configured_without_data"] is None


def test_data_sources_mcas_with_cloud_discovery_on_isnt_alert_only(azure, tmp_path):
    alert_only_workspace(azure, "Enabled")
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    mcas = next(c for c in ws["connectors"] if c["id"] == "MicrosoftCloudAppSecurity")
    assert code == 0 and mcas["alert_only"] is False and mcas["connected"] is False
    assert ws["connectors_quiet"] == ["AzureAdvancedThreatProtection"]
    assert "MicrosoftCloudAppSecurity" in ws["connectors_not_connected"]


def test_data_sources_bad_connector_query_is_isolated(azure, tmp_path):
    connectors_workspace(azure)
    bad = Resp(400, {"error": {"code": "BadArgumentError", "innererror": {"message": "Syntax error"}}})
    # The batch fails, then each data type runs alone, as written: ASC answers, MDATP is malformed, the rest are empty.
    azure.queries[:0] = [("ParamifyIndex", bad), ('"Azure Security Center"', table(["Time"], [[iso(NOW)]])),
                         ('"MDATP"', bad), ("Time = max(TimeGenerated)", table(["Time"], []))]
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    by_id = {c["id"]: c for c in ws["connectors"]}
    alone = [q for _, _, q in azure.calls if q and "Time = max(TimeGenerated)" in q and "ParamifyIndex" not in q]
    assert len(alone) == 5 and not any(q.startswith("union") for q in alone)
    assert code == 0 and by_id["AzureSecurityCenter"]["connected"] is True
    assert by_id["MicrosoftDefenderAdvancedThreatProtection"]["connected"] is None
    assert "MicrosoftDefenderAdvancedThreatProtection: SecurityAlert (MDATP)" in ws["notes"][0]


def test_data_sources_let_query_runs_alone(azure, tmp_path):
    connectors_workspace(azure)
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")]["value"].append(
        ui_connector("Okta", [("Okta_CL", 'let events = Okta_CL;\nevents | where eventType_s != ""')]))
    # As in Log Analytics, a let statement inside a union operand is a syntax error.
    bad = Resp(400, {"error": {"code": "BadArgumentError", "innererror": {"message": "Syntax error"}}})
    azure.queries[:0] = [("(let ", bad), ("let events", table(["Time"], [[iso(NOW)]]))]
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    okta = next(c for c in ws["connectors"] if c["id"] == "Okta")
    assert code == 0 and okta["connected"] is True and okta["last_data_received"] == iso(NOW)
    assert not ws["notes"]
    # The let query stays out of the union, so the rest still run as one batch.
    unions = [q for _, _, q in azure.calls if q and "ParamifyIndex" in q]
    assert len(unions) == 1 and "let " not in unions[0] and unions[0].count("ParamifyIndex =") == 5


def test_data_sources_without_health_monitoring(azure, tmp_path):
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and ws["health_monitoring"] is False and ws["connector_health"] is None
    assert [c["id"] for c in ws["connectors"]] == ["AzureSecurityCenter", "Office365"]
    assert all(c["definition"] == "built_in" for c in ws["connectors"])
    assert not any("SentinelHealth" in q for _, _, q in azure.calls if q)
    # No health data is unknown, not zero unhealthy.
    assert ws["connectors_unhealthy"] is None and ev["summary"]["connectors_unhealthy"] is None


def test_data_sources_parser_union_and_basic_table_queries(azure, tmp_path):
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")] = {"value": [
        ui_connector("SophosXGFirewall", [("Syslog (SophosXGFirewall)", "SophosXGFirewall ")]),
        ui_connector("Wiz", [("WizIssues_CL", "union isfuzzy=true \n(WizIssues_CL),\n(WizIssuesV2_CL)")]),
        ui_connector("AzureStorage", [("StorageBlobLogs", "StorageBlobLogs")]),
        ui_connector("Broken", [("x", "{{tableName}}")])]}
    # Pending, in catalog order: ASC alerts (no data), then the parser function and the union, which both have data.
    azure.queries.insert(0, ("ParamifyIndex", table(["Time", "ParamifyIndex"], [[iso(NOW), 1], [iso(NOW), 2]])))
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    by_id = {c["id"]: c for c in ws["connectors"]}
    union = next(q for _, _, q in azure.calls if "ParamifyIndex" in q)
    assert code == 0 and "SophosXGFirewall" in union and "WizIssues_CL" in union and "StorageBlobLogs" not in union
    assert by_id["SophosXGFirewall"]["connected"] is True and by_id["Wiz"]["connected"] is True
    assert by_id["Wiz"]["data_types"][0]["table"] is None
    # A Basic-plan table can't be read with /query, so it is unmeasured rather than empty.
    assert by_id["AzureStorage"]["connected"] is None and ws["tables_not_measured"] == ["StorageBlobLogs"]
    assert by_id["Broken"]["connected"] is None and any("connector Broken" in n for n in ws["notes"])
    assert "Broken" not in ws["connectors_not_connected"] and "AzureStorage" not in ws["connectors_not_connected"]


def test_data_sources_entra_id_protection_and_grouped_built_ins(azure, tmp_path):
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")] = {"value": [
        ui_connector("AzureActiveDirectory", [("SigninLogs", "SigninLogs")])]}
    azure.arm[(f"{SI_A}/dataConnectors", "2025-09-01")]["value"] += [
        {"id": f"{SI_A}/dataConnectors/ipc", "name": "ipc", "kind": "AzureActiveDirectory",
         "properties": {"dataTypes": {"alerts": {"state": "Enabled"}}}},
        {"id": f"{SI_A}/dataConnectors/o365-b", "name": "o365-b", "kind": "Office365", "properties": {}}]
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    by_id = {c["id"]: c for c in ws["connectors"]}
    # The AzureActiveDirectory connection kind is Entra ID Protection, not the Entra ID logs connector.
    assert by_id["AzureActiveDirectory"]["connections"] == []
    ipc = by_id["AzureActiveDirectoryIdentityProtection"]
    assert (ipc["definition"], ipc["connections"], [d["name"] for d in ipc["data_types"]]) == (
        "built_in", ["ipc"], ["SecurityAlert (IPC)"])
    assert [c["id"] for c in ws["connectors"]].count("Office365") == 1 and by_id["Office365"]["connections"] == ["o365", "o365-b"]


def test_data_sources_health_shows_the_worst_connection(azure, tmp_path):
    connectors_workspace(azure)
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")]["value"] += [
        {"id": f"{SI_A}/dataConnectors/{n}", "name": n, "kind": "RestApiPoller", "properties": {"connectorDefinitionName": "MyCcp"}}
        for n in ("ccp2", "ccp3")]
    # A Warning listed first doesn't hide a Failure.
    azure.queries.insert(0, ("SentinelResourceType", table(
        ["SentinelResourceId", "TimeGenerated", "Status", "Reason", "Description", "SentinelResourceKind", "SentinelResourceName"],
        [[f"{SI_A}/dataConnectors/ccp1", iso(NOW), "Success", None, None, "RestApiPoller", "ccp1"],
         [f"{SI_A}/dataConnectors/ccp2", iso(NOW), "Warning", "Throttled", "slow", "RestApiPoller", "ccp2"],
         [f"{SI_A}/dataConnectors/ccp3", iso(NOW), "Failure", "Unauthorized", "token expired", "RestApiPoller", "ccp3"]])))
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    ccp = next(c for c in ws["connectors"] if c["id"] == "MyCcp")
    assert ccp["connections"] == ["ccp1", "ccp2", "ccp3"] and ccp["health_status"] == "Failure"
    assert ws["connectors_unhealthy"] == 2 and ev["summary"]["connectors_unhealthy"] == 2
    # The hourly Informational failure summary, written only after polling errors, mustn't hide a Failure.
    health = next(q for _, _, q in azure.calls if q and "SentinelResourceType" in q)
    assert "OperationName == 'Data fetch status change'" in health


def test_data_sources_batches_map_rows_back(azure, tmp_path, monkeypatch):
    monkeypatch.setattr(MODS["sentinel_data_sources"], "QUERY_BATCH", 2)
    connectors_workspace(azure)
    # Batches: [ASC, MDATP], [Defender XDR alerts, Exchange], [Teams]; ParamifyIndex is per batch.
    azure.queries.insert(0, ("ParamifyIndex", [table(["Time", "ParamifyIndex"], [[iso(NOW), 1]]),
                                               table(["Time", "ParamifyIndex"], [[iso(NOW), 1]]),
                                               table(["Time", "ParamifyIndex"], [])]))
    code, ev = run("sentinel_data_sources", tmp_path)
    by_id = {c["id"]: c for c in ws_a(ev)["connectors"]}
    assert code == 0 and sum("ParamifyIndex" in q for _, _, q in azure.calls if q) == 3
    assert by_id["MicrosoftDefenderAdvancedThreatProtection"]["connected"] is True
    assert by_id["AzureSecurityCenter"]["connected"] is False
    assert [d["last_data_received"] is not None for d in by_id["Office365"]["data_types"]] == [True, False]


def test_data_sources_failed_last_data_query_keeps_ingestion_answers(azure, tmp_path):
    connectors_workspace(azure)
    azure.queries.insert(0, ("ParamifyIndex", Resp(403, {"error": {"code": "Forbidden", "message": "no"}})))
    code, ev = run("sentinel_data_sources", tmp_path)
    by_id = {c["id"]: c for c in ws_a(ev)["connectors"]}
    assert code == 1 and ev["metadata"]["partial_failure"] is True
    assert by_id["AzureActiveDirectory"]["connected"] is True  # SigninLogs, from the ingestion query
    assert by_id["AzureSecurityCenter"]["connected"] is None
    # The counts are unknown, not partial.
    for counts in (ws_a(ev), ev["summary"]):
        assert [counts[k] for k in ("connectors_connected", "connectors_not_connected", "connectors_quiet",
                                    "connectors_configured_without_data")] == [None] * 4


def test_data_sources_incomplete_listings_read_null(azure, tmp_path):
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")] = Resp(
        400, {"error": {"code": "InvalidApiVersionParameter", "message": "retired"}})
    azure.arm[(f"{WS_A}/tables", "2023-09-01")] = Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    assert code == 1 and ws["notes"][0].startswith("preview listing")
    assert (ws["connectors_total"], ws["connectors_connected"], ws["connectors_not_connected"], ws["connectors_quiet"],
            ws["connectors_configured_without_data"]) == (None, None, None, None, None)
    assert ws["data_connectors_total"] is None and ws["tables_not_measured"] is None
    # Without the table plans, no data can't be told from a Basic table.
    assert all(c["connected"] is None for c in ws["connectors"])
    assert {k: ev["summary"][k] for k in ("data_connectors_total", "connectors_connected", "connectors_not_connected",
                                          "connectors_quiet", "connectors_configured_without_data")} == {
        "data_connectors_total": None, "connectors_connected": None, "connectors_not_connected": None, "connectors_quiet": None,
        "connectors_configured_without_data": None}


def test_data_sources_unknown_ingestion_reads_null(azure, tmp_path):
    azure.queries[0] = ("union withsource=ParamifySourceTable", Resp(403, {"error": {"code": "Forbidden", "message": "no"}}))
    code, ev = run("sentinel_data_sources", tmp_path)
    ws = ws_a(ev)
    assert code == 1 and ws["health_monitoring"] is None and ws["connectors_unhealthy"] is None
    assert {k: ev["summary"][k] for k in ("connectors_connected", "connectors_not_connected", "connectors_quiet",
                                          "connectors_configured_without_data", "connectors_unhealthy")} == {
        "connectors_connected": None, "connectors_not_connected": None, "connectors_quiet": None,
        "connectors_configured_without_data": None, "connectors_unhealthy": None}


def test_analytics_rules_merge_preview_kinds(azure, tmp_path):
    code, ev = run("sentinel_analytics_rules", tmp_path)
    assert code == 0
    ws = ws_a(ev)
    by_name = {r["name"]: r for r in ws["rules"]}
    assert by_name["nrt"]["seen_in"] == ["preview"] and by_name["fusion"]["seen_in"] == ["stable", "preview"]
    assert ws["enabled_rules"] == 3 and ws["disabled_rules"] == 1
    assert ws["enabled_by_kind"] == {"Fusion": 1, "NRT": 1, "Scheduled": 1}
    assert ws["fusion_enabled"] is True and ws["rules_only_in_preview"] == 1
    # No rule uses a template only the preview API has, so none is read from it.
    assert ws["templates_available"] == 3 and ws["templates_in_use"] == 2
    assert not any(c[1].startswith(f"{SI_A}/alertRuleTemplates") and c[2] == "2025-10-01-preview" for c in azure.calls)


def test_analytics_rules_nrt_rule_falls_back_to_a_preview_only_template(azure, tmp_path):
    azure.arm[(f"{SI_A}/alertRules", "2025-10-01-preview")] = {"value": [
        rule("nrt", "NRT", True, "tpl-nrt", query="_ASim_AuditEvent | take 1")]}
    code, ev = run("sentinel_analytics_rules", tmp_path)
    nrt = next(r for r in ws_a(ev)["rules"] if r["name"] == "nrt")
    assert code == 0 and ws_a(ev)["notes"] == []
    assert (nrt["tables_read"], nrt["tables_from"], nrt["tables_without_data"]) == (["AzureActivity"], "template", [])
    preview = [c[1] for c in azure.calls if c[1].startswith(f"{SI_A}/alertRuleTemplates") and c[2] == "2025-10-01-preview"]
    assert preview == [f"{SI_A}/alertRuleTemplates/tpl-nrt"]
    assert ws_a(ev)["templates_available"] == 4 and ws_a(ev)["templates_in_use"] == 3


@pytest.mark.parametrize("status, notes", [(404, 0), (403, 1)])
def test_analytics_rules_preview_template_lookup(azure, tmp_path, status, notes):
    azure.arm[(f"{SI_A}/alertRules", "2025-10-01-preview")] = {"value": [
        rule("nrt", "NRT", True, "tpl-nrt", query="_ASim_AuditEvent | take 1")]}
    azure.arm[(f"{SI_A}/alertRuleTemplates/tpl-nrt", "2025-10-01-preview")] = Resp(
        status, {"error": {"code": "NotFound" if status == 404 else "AuthorizationFailed", "message": "no"}})
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    nrt = next(r for r in ws["rules"] if r["name"] == "nrt")
    assert code == 0 and nrt["tables_read"] is None and ws["templates_available"] == 3
    assert len(ws["notes"]) == notes and all("tpl-nrt" in n for n in ws["notes"])


def test_analytics_rules_preview_failure_is_a_note(azure, tmp_path):
    azure.arm[(f"{SI_A}/alertRules", "2025-10-01-preview")] = Resp(
        400, {"error": {"code": "InvalidApiVersionParameter", "message": "retired"}})
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and ws["enabled_rules"] == 2 and ws["templates_available"] == 3
    assert len(ws["notes"]) == 1 and "NRT" in ws["notes"][0]


def test_analytics_rules_forbidden_fails_the_run(azure, tmp_path):
    azure.arm[(f"{SI_A}/alertRules", "2025-09-01")] = Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
    code, ev = run("sentinel_analytics_rules", tmp_path)
    assert code == 1 and ev["metadata"]["partial_failure"] is True
    assert ws_a(ev)["rules"] is None
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


# OfficeActivity has an Operation column, so the name Operation counts only where a table can stand.
WORKSPACE_TABLES = [
    {"name": n, "properties": {"plan": "Analytics", "schema": {
        "standardColumns": [{"name": "TimeGenerated"}], "columns": [{"name": c} for c in cols]}}}
    for n, cols in (("AzureActivity", []), ("SigninLogs", []), ("SecurityAlert", []), ("Syslog", []),
                    ("CommonSecurityLog", []), ("OfficeActivity", ["Operation"]), ("Operation", []),
                    ("Event", []), ("Usage", []), ("Heartbeat", []), ("SecurityEvent", []),
                    ("AzureDiagnostics", []), ("AuditLogs", []))]
# The data-source fetcher's additions to the default listing; StorageBlobLogs is Basic.
EXTRA_TABLES = law_tables(["SentinelHealth", "SecurityIncident", "McasShadowItReporting", "MyCcp_CL"], basic=["StorageBlobLogs"])
TABLES = {t["name"] for t in WORKSPACE_TABLES}
AMBIGUOUS = {"Operation"}


@pytest.mark.parametrize("query, expected", [
    ("SigninLogs | where ResultType != '0'", ["SigninLogs"]),
    ("// SigninLogs | take 1\nAzureActivity | take 1", ["AzureActivity"]),
    ("let f = (t:string) { table(t) | take 1 };\nunion f('SigninLogs'), f(\"OfficeActivity\")", ["OfficeActivity", "SigninLogs"]),
    ("OfficeActivity | where Operation == 'x' | summarize make_set(Operation) by Operation", ["OfficeActivity"]),
    ("OfficeActivity | project UserId, Operation | where true", ["OfficeActivity"]),
    ("Operation | where OperationStatus == 'Failed'", ["Operation"]),
    ("union isfuzzy=true Syslog, Operation | take 1", ["Operation", "Syslog"]),
    ("Syslog | join kind=inner (Operation | take 1) on Computer", ["Operation", "Syslog"]),
    ("let x = Operation; x | where Detail has 'url // not a comment'", ["Operation"]),
    ("MyApp_CL | where msg has \"AzureActivity\"", ["MyApp_CL"]),
    ("OfficeActivity | extend p = pack(\"Operation\", Operation)", ["OfficeActivity"]),
    ("_Im_NetworkSession | take 1", []),
    (r'SecurityEvent | where P startswith @"C:\Windows\Temp\" | join (SigninLogs) on X | where y == "z"',
     ["SecurityEvent", "SigninLogs"]),
    (r"SecurityEvent | where FilePath == @'C:\SigninLogs\' | take 1", ["SecurityEvent"]),
    ('SecurityEvent | where M has @"say ""SigninLogs"" now" | take 1', ["SecurityEvent"]),
    ('Usage | where DataType in ("SecurityEvent", "Syslog")', ["Usage"]),
    ("AzureDiagnostics | where Category in ('AuditLogs')", ["AzureDiagnostics"]),
    ('workspace("other").SecurityEvent | take 1', []),
    ("SigninLogs | extend e = parse_json(Props).Event | take 1", ["SigninLogs"]),
    ("Syslog | lookup kind=leftouter (Operation | take 1) on Computer", ["Operation", "Syslog"]),
    ("Syslog | lookup Operation on Computer", ["Operation", "Syslog"]),
    ("let n = toscalar(SigninLogs | count);\nAzureActivity | where Count > n", ["AzureActivity", "SigninLogs"]),
    ("let m = materialize(Operation | take 1);\nm | take 1", ["Operation"]),
    ('search in (SigninLogs, AuditLogs) "admin"', ["AuditLogs", "SigninLogs"]),
    ('find in (SecurityEvent, Syslog) where Computer == "x"', ["SecurityEvent", "Syslog"]),
    ('find in (SecurityEvent, Operation) where Computer == "x"', ["Operation", "SecurityEvent"]),
    ("union Signin* | take 1", []),  # wildcards aren't resolved, so the rule falls back to its template
    ('table("Operation") | take 1', ["Operation"]),
    # Names the query assigns or declares are columns or variables, not tables.
    ("SigninLogs | extend Event = tostring(Props.x) | where isnotempty(Event)", ["SigninLogs"]),
    ("let Heartbeat = 5; SigninLogs | where X > Heartbeat", ["SigninLogs"]),
    ("datatable(Event:string)['a'] | join (SigninLogs) on Event", ["SigninLogs"]),
    ("SigninLogs | parse Msg with * 'x' Event:string | summarize Usage = count() by Event", ["SigninLogs"]),
    ("SigninLogs | mv-expand Event = Props | project-rename Usage = Event", ["SigninLogs"]),
    ("SigninLogs | extend Event = 1 | join (Event | take 1) on Computer", ["Event", "SigninLogs"]),
])
def test_analytics_rules_tables_named_in_a_query(query, expected):
    assert MODS["sentinel_analytics_rules"].query_tables(query, TABLES, AMBIGUOUS) == expected


@pytest.mark.parametrize("query, expected", [
    # Names that mv-expand, mv-apply, `as` and withsource= bind are columns or results, not tables.
    ("SigninLogs | mv-expand Event | where isnotempty(Event)", ["SigninLogs"]),
    ("SigninLogs | mv-expand kind=array Event, Usage to typeof(string) | where isnotempty(Event)", ["SigninLogs"]),
    ("SigninLogs | mv-apply Event on (take 1) | project Event", ["SigninLogs"]),
    ("SigninLogs | as Event | where isnotempty(Event)", ["SigninLogs"]),
    ("SigninLogs | as hint.materialized=true Event | project Event", ["SigninLogs"]),
    ("union withsource=Event SigninLogs, AuditLogs | where isnotempty(Event)", ["AuditLogs", "SigninLogs"]),
    ("find withsource=Event in (SigninLogs) where X == 1 | project Event", ["SigninLogs"]),
    # Bracket-quoted names, and table() with a custom table.
    ("['SigninLogs'] | take 1", ["SigninLogs"]),
    ('union ["AuditLogs"], Syslog', ["AuditLogs", "Syslog"]),
    ("SigninLogs | extend x = Props['AuditLogs'] | take 1", ["SigninLogs"]),
    ('table("Other_CL") | take 1', ["Other_CL"]),
])
def test_analytics_rules_names_a_query_binds_and_quoted_tables(query, expected):
    assert MODS["sentinel_analytics_rules"].query_tables(query, TABLES, AMBIGUOUS) == expected


def test_analytics_rules_carry_a_hash_and_length_of_each_query():
    import hashlib

    mod = MODS["sentinel_analytics_rules"]
    query = "SigninLogs | where ResultType != '0' // ü"
    with_query = mod.project_rule(rule("q", "Scheduled", True, query=query))
    without = mod.project_rule(rule("f", "Fusion", True))
    assert (with_query["query_sha256"], with_query["query_length"]) == (
        hashlib.sha256(query.encode("utf-8")).hexdigest(), len(query))
    assert (without["query_sha256"], without["query_length"]) == (None, None)


def test_analytics_rules_query_text_is_opt_in(azure, tmp_path, monkeypatch):
    query = "SigninLogs | where AppDisplayName has '; unset $(id)'"
    azure.arm[(f"{SI_A}/alertRules", "2025-09-01")] = {"value": [rule("signins", "Scheduled", True, query=query)]}
    azure.arm[(f"{SI_A}/alertRules", "2025-10-01-preview")] = {"value": []}
    _, ev = run("sentinel_analytics_rules", tmp_path)
    [default] = ws_a(ev)["rules"]
    assert "query" not in default and "unset" not in json.dumps(ev)
    assert (default["query_length"], default["tables_read"], ws_a(ev)["query_text_included"]) == (
        len(query), ["SigninLogs"], False)
    for f in tmp_path.glob("azure_sentinel_analytics_rules_*.json"):
        f.unlink()
    monkeypatch.setenv("SENTINEL_RULE_QUERY_TEXT", "true")
    _, ev = run("sentinel_analytics_rules", tmp_path)
    [opted] = ws_a(ev)["rules"]
    assert (opted["query"], opted["query_sha256"], ws_a(ev)["query_text_included"]) == (
        query, default["query_sha256"], True)


FUNCTIONS = {"CiscoASA"}


@pytest.mark.parametrize("query, expected", [
    # A name the workspace doesn't list, where only a table can stand, is a table it never provisioned.
    ("AWSCloudTrail | where EventName == 'x'", ["AWSCloudTrail"]),
    ("let x = AWSCloudTrail; x | take 1", ["AWSCloudTrail"]),
    ("union isfuzzy=true AWSCloudTrail, GCPAuditLogs", ["AWSCloudTrail", "GCPAuditLogs"]),
    ("SigninLogs | join kind=inner (AWSCloudTrail | take 1) on X", ["AWSCloudTrail", "SigninLogs"]),
    ('search in (AWSCloudTrail, SigninLogs) "admin"', ["AWSCloudTrail", "SigninLogs"]),
    ("let n = toscalar(AWSCloudTrail | count); SigninLogs | where C > n", ["AWSCloudTrail", "SigninLogs"]),
    ('table("AWSCloudTrail") | take 1', ["AWSCloudTrail"]),
    # Workspace functions, built-in parsers, the query's own names, literals and value lists are not tables.
    ("CiscoASA | where x == 1", []),
    ("_Im_Dns | take 1", []),
    ("let Base = SigninLogs | take 1; Base | take 1", ["SigninLogs"]),
    ("let f = (t:string) { table(t) }; f('Unlisted')", []),
    ("let enabled = true; SigninLogs | where E == enabled", ["SigninLogs"]),
    ("SigninLogs | where Category in (Foo, Bar)", ["SigninLogs"]),
    ("SigninLogs | extend x = (Foo) | take 1", ["SigninLogs"]),
    ("SigninLogs | mv-expand Foo | take 1", ["SigninLogs"]),
    ('workspace("other").AWSCloudTrail | take 1', []),
])
def test_analytics_rules_unlisted_tables(query, expected):
    mod = MODS["sentinel_analytics_rules"]
    assert mod.query_tables(query, TABLES, AMBIGUOUS, FUNCTIONS) == expected
    # Without the workspace's functions, an unlisted name could be one, so only listed tables count.
    assert mod.query_tables(query, TABLES, AMBIGUOUS) == [t for t in expected if t in TABLES]


def test_analytics_rules_unprovisioned_tables_read_as_missing_data(azure, tmp_path):
    azure.arm[(f"{SI_A}/alertRules", "2025-09-01")] = {"value": [
        rule("aws", "Scheduled", True, query="AWSCloudTrail | where EventName == 'ConsoleLogin'"),
        rule("asa", "Scheduled", True, query="CiscoASA | where x == 1"),
        rule("gcp", "Scheduled", True, "tpl-gcp", query="_Im_Authentication | take 1")]}
    azure.arm[(f"{SI_A}/alertRules", "2025-10-01-preview")] = {"value": []}
    azure.arm[(f"{SI_A}/alertRuleTemplates", "2025-09-01")] = {"value": [
        {"name": "tpl-gcp", "kind": "Scheduled", "properties": {"requiredDataConnectors": [
            {"connectorId": "GCPAudit", "dataTypes": ["GCPAuditLogs"]}]}}]}
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    by_name = {r["name"]: r for r in ws["rules"]}
    assert code == 0 and ws["notes"] == []
    assert [(by_name[n]["tables_read"], by_name[n]["tables_from"], by_name[n]["tables_without_data"])
            for n in ("aws", "asa", "gcp")] == [
        (["AWSCloudTrail"], "query", ["AWSCloudTrail"]), (None, None, None),
        (["GCPAuditLogs"], "template", ["GCPAuditLogs"])]
    assert ws["enabled_rules_tables_unknown"] == 1
    assert sorted(r["name"] for r in ws["enabled_rules_missing_data"]) == ["aws", "gcp"]


def test_analytics_rules_template_parsers_are_not_tables():
    template = {"properties": {"requiredDataConnectors": [
        {"connectorId": "DNS", "dataTypes": ["_Im_Dns"]}, {"connectorId": "SyslogAma", "dataTypes": ["Syslog"]}]}}
    assert MODS["sentinel_analytics_rules"].template_tables(template) == ["Syslog"]


def test_analytics_rules_without_the_workspace_functions_unlisted_names_stay_unknown(azure, tmp_path):
    azure.arm[(f"{SI_A}/alertRules", "2025-09-01")] = {"value": [
        rule("aws", "Scheduled", True, query="AWSCloudTrail | where EventName == 'ConsoleLogin'")]}
    azure.arm[(f"{SI_A}/alertRules", "2025-10-01-preview")] = {"value": []}
    azure.arm[(f"{WS_A}/savedSearches", "2023-09-01")] = Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and len(ws["notes"]) == 1 and "saved search" in ws["notes"][0]
    assert (ws["rules"][0]["tables_read"], ws["enabled_rules_tables_unknown"]) == (None, 1)


def test_analytics_rules_tables_and_data(azure, tmp_path):
    azure.arm[(f"{SI_A}/alertRules", "2025-09-01")] = {"value": [
        rule("signins", "Scheduled", True, query="SigninLogs | where ResultType != '0'",
             suppressionEnabled=True, suppressionDuration="PT5H"),
        rule("parser", "Scheduled", True, "tpl-net", query="_Im_NetworkSession | where DstPortNumber == 4444"),
        rule("dns", "Scheduled", True, "tpl-dns", query="_Im_Dns | take 1"),
        rule("custom", "Scheduled", True, query="MyApp_CL | where Level == 'Error'"),
        rule("off", "Scheduled", False, query="OfficeActivity | take 1"),
        rule("mde", "MicrosoftSecurityIncidentCreation", True,
             productFilter="microsoft defender advanced threat protection"),
        rule("mcas", "MicrosoftSecurityIncidentCreation", True, productFilter="Microsoft Cloud App Security"),
        rule("fusion", "Fusion", True, "f71aba3d-28fb-450b-b192-4e76a83015c8")]}
    azure.arm[(f"{SI_A}/alertRules", "2025-10-01-preview")] = {"value": [
        rule("nrt", "NRT", True, query="AzureActivity | where OperationNameValue has 'delete'")]}
    fusion_template = azure.arm[(f"{SI_A}/alertRuleTemplates", "2025-09-01")]["value"][1]
    azure.arm[(f"{SI_A}/alertRuleTemplates", "2025-09-01")] = {"value": [
        fusion_template,
        {"name": "tpl-net", "kind": "Scheduled", "properties": {"requiredDataConnectors": [
            {"connectorId": "PaloAltoNetworks", "dataTypes": ["CommonSecurityLog (PaloAlto)"]},
            {"connectorId": "SyslogAma", "dataTypes": ["Syslog"]}]}},
        {"name": "tpl-dns", "kind": "Scheduled", "properties": {"requiredDataConnectors": [
            {"connectorId": "DNS", "dataTypes": ["Event"]},
            {"connectorId": "Fortinet", "dataTypes": ["CommonSecurityLog (Fortinet)"]}]}}]}
    azure.queries.insert(0, ("union withsource=ParamifySourceTable", table(
        ["ParamifySourceTable", "LastIngested", "Records"],
        [["AzureActivity", iso(NOW), 10], ["SecurityAlert", iso(NOW), 2], ["Syslog", iso(NOW), 7], ["Usage", iso(NOW), 5],
         ["OfficeActivity", iso(NOW), 3]])))
    code, ev = run("sentinel_analytics_rules", tmp_path)
    assert code == 0 and ev["metadata"]["partial_failure"] is False
    ws = ws_a(ev)
    by_name = {r["name"]: r for r in ws["rules"]}
    signins = by_name["signins"]
    assert "query" not in signins and signins["query_length"] == len("SigninLogs | where ResultType != '0'")
    assert signins["suppression_enabled"] is True and ws["query_text_included"] is False
    assert signins["suppression_duration"] == "PT5H" and ws["enabled_rules_suppressed"] == 1
    assert (signins["tables_read"], signins["tables_from"], signins["tables_without_data"]) == (
        ["SigninLogs"], "query", ["SigninLogs"])
    # A template's connectors are alternatives: Syslog ingests, so the parser rule has data.
    assert (by_name["parser"]["tables_read"], by_name["parser"]["tables_from"], by_name["parser"]["tables_without_data"]) == (
        ["CommonSecurityLog", "Syslog"], "template", [])
    assert by_name["dns"]["tables_without_data"] == ["CommonSecurityLog", "Event"]
    assert (by_name["custom"]["tables_from"], by_name["custom"]["tables_without_data"]) == ("query", ["MyApp_CL"])
    assert by_name["nrt"]["tables_without_data"] == [] and by_name["nrt"]["seen_in"] == ["preview"]
    assert (by_name["mde"]["tables_from"], by_name["mde"]["tables_without_data"]) == ("alert_product", [])
    assert by_name["mcas"]["tables_without_data"] == ["SecurityAlert"]
    fusion = by_name["fusion"]
    assert (fusion["tables_read"], fusion["tables_from"], fusion["tables_without_data"]) == (None, None, None)
    assert ws["enabled_rules_tables_unknown"] == 1
    assert ws["ingesting_tables_not_read"] == ["OfficeActivity"]  # its only rule is disabled; Usage is workspace telemetry
    assert {r["name"]: r["tables_without_data"] for r in ws["enabled_rules_missing_data"]} == {
        "custom": ["MyApp_CL"], "dns": ["CommonSecurityLog", "Event"], "mcas": ["SecurityAlert"], "signins": ["SigninLogs"]}
    assert [(t["table"], t["enabled_rules"], t["last_ingested"] is not None) for t in ws["tables_read_by_enabled_rules"]] == [
        ("AzureActivity", 1, True), ("CommonSecurityLog", 2, False), ("Event", 1, False), ("MyApp_CL", 1, False),
        ("SecurityAlert", 2, True), ("SigninLogs", 1, False), ("Syslog", 1, True)]
    assert ws["workspace_tables_listed"] == len(WORKSPACE_TABLES) + len(EXTRA_TABLES["value"]) and ws["ingestion_window_days"] == 14
    assert ev["summary"]["enabled_rules_missing_data"] == 4 and ev["summary"]["ingesting_tables_not_read"] == 1
    # A template's data types are what the rule may read, so tables read only that way are labelled.
    assert {t["table"]: t["enabled_rules_by_template"] for t in ws["tables_read_by_enabled_rules"]} == {
        "AzureActivity": 0, "CommonSecurityLog": 2, "Event": 1, "MyApp_CL": 0, "SecurityAlert": 0, "SigninLogs": 0,
        "Syslog": 1}
    assert ws["ingesting_tables_read_only_by_templates"] == ["Syslog"]
    assert ev["summary"]["ingesting_tables_read_only_by_templates"] == 1


def test_analytics_rules_disabled_incident_rule_still_gets_its_product_checked(azure, tmp_path):
    azure.arm[(f"{SI_A}/alertRules", "2025-09-01")] = {"value": [
        rule("mde", "MicrosoftSecurityIncidentCreation", False, productFilter="Microsoft Defender Advanced Threat Protection")]}
    azure.arm[(f"{SI_A}/alertRules", "2025-10-01-preview")] = {"value": []}
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and ws["rules"][0]["tables_without_data"] == []
    # SecurityAlert also holds Sentinel's own alerts, so it never counts as an unread source.
    assert ws["ingesting_tables_not_read"] == ["AzureActivity"]


def connection(name, kind, alerts="Enabled"):
    return {"id": f"{SI_A}/dataConnectors/{name}", "name": name, "kind": kind,
            "properties": {"tenantId": "t", "dataTypes": {"alerts": {"state": alerts}}}}


def incident_rule(name, product, enabled=True):
    return rule(name, "MicrosoftSecurityIncidentCreation", enabled, productFilter=product)


def incident_rules_workspace(azure, rules, stable=(), preview=()):
    """Incident-creation rules for products that sent no alert (the products query finds only Defender for Endpoint)."""
    azure.arm[(f"{SI_A}/alertRules", "2025-09-01")] = {"value": list(rules)}
    azure.arm[(f"{SI_A}/alertRules", "2025-10-01-preview")] = {"value": []}
    azure.arm[(f"{SI_A}/dataConnectors", "2025-09-01")] = stable if isinstance(stable, Resp) else {"value": list(stable)}
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")] = (
        preview if isinstance(preview, Resp) else {"value": list(preview)})


def test_analytics_rules_alert_only_rule_is_quiet_through_its_own_connection(azure, tmp_path):
    incident_rules_workspace(azure, [incident_rule("ipc", "Azure Active Directory Identity Protection")],
                         stable=[connection("aad", "AzureActiveDirectory")])
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and ws["notes"] == []
    assert [r["name"] for r in ws["enabled_rules_missing_data"]] == ["ipc"]
    assert ws["enabled_rules_quiet"] == [{
        "name": "ipc", "display_name": "ipc", "product_filter": "Azure Active Directory Identity Protection",
        "alerts_enabled_on": ["AzureActiveDirectory"],
        "reason": "its product sent no alert in the window, and its own connection has alerts enabled"}]
    assert (ev["summary"]["enabled_rules_missing_data"], ev["summary"]["enabled_rules_quiet"]) == (1, 1)


def test_analytics_rules_alert_only_rule_is_quiet_through_defender_xdr(azure, tmp_path):
    # Only the preview listing returns the Defender XDR connection.
    incident_rules_workspace(azure, [incident_rule("mdi", "Azure Advanced Threat Protection")],
                         stable=[connection("o365", "Office365")],
                         preview=[connection("o365", "Office365"), connection("xdr", "MicrosoftThreatProtection")])
    code, ev = run("sentinel_analytics_rules", tmp_path)
    [quiet] = ws_a(ev)["enabled_rules_quiet"]
    assert code == 0 and quiet["alerts_enabled_on"] == ["MicrosoftThreatProtection"]
    assert "Defender XDR, which carries that product's alerts," in quiet["reason"]
    assert (ev["summary"]["enabled_rules_missing_data"], ev["summary"]["enabled_rules_quiet"]) == (1, 1)


def test_analytics_rules_unknown_product_is_never_quiet(azure, tmp_path):
    # A product the API may add later has no known connection, so even Defender XDR and every own kind sending
    # alerts don't make it quiet.
    kinds = ["AzureActiveDirectory", "AzureAdvancedThreatProtection", "AzureSecurityCenter", "IOT",
             "MicrosoftCloudAppSecurity", "MicrosoftDefenderAdvancedThreatProtection", "OfficeATP", "MicrosoftThreatProtection"]
    incident_rules_workspace(azure, [incident_rule("new", "Microsoft Defender for Something New")],
                         preview=[connection(k.lower(), k) for k in kinds])
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and [r["name"] for r in ws["enabled_rules_missing_data"]] == ["new"]
    assert ws["enabled_rules_quiet"] == []
    assert (ev["summary"]["enabled_rules_missing_data"], ev["summary"]["enabled_rules_quiet"]) == (1, 0)


def test_analytics_rules_alert_only_rules_not_wired_are_not_quiet(azure, tmp_path):
    # Defender for Office 365's alerts are Disabled on its own connection and on Defender XDR's; Defender for Cloud
    # was never connected, and Defender XDR doesn't carry its alerts.
    incident_rules_workspace(
        azure,
        [incident_rule("mdo", "Office 365 Advanced Threat Protection"), incident_rule("mdc", "Azure Security Center"),
         incident_rule("off", "Azure Advanced Threat Protection", enabled=False)],
        stable=[connection("atp", "OfficeATP", "Disabled")],
        preview=[connection("atp", "OfficeATP", "Disabled"), connection("xdr", "MicrosoftThreatProtection", "Disabled")])
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and ws["enabled_rules_quiet"] == []
    assert sorted(r["name"] for r in ws["enabled_rules_missing_data"]) == ["mdc", "mdo"]
    assert (ev["summary"]["enabled_rules_missing_data"], ev["summary"]["enabled_rules_quiet"]) == (2, 0)
    azure.arm[(f"{SI_A}/dataConnectors", "2025-10-01-preview")] = {"value": [connection("xdr", "MicrosoftThreatProtection")]}
    for f in tmp_path.glob("azure_sentinel_analytics_rules_*.json"):
        f.unlink()
    _, ev = run("sentinel_analytics_rules", tmp_path)
    assert [r["name"] for r in ws_a(ev)["enabled_rules_quiet"]] == ["mdo"]  # Defender XDR now sends alerts; not for mdc


def test_analytics_rules_only_incident_rules_read_quiet(azure, tmp_path):
    # SecurityAlert got nothing at all; a scheduled rule reading it and SigninLogs stays missing data.
    incident_rules_workspace(
        azure,
        [incident_rule("mdi", "Azure Advanced Threat Protection"),
         rule("mixed", "Scheduled", True, query="SecurityAlert | join (SigninLogs) on $left.CompromisedEntity == $right.UserPrincipalName")],
        preview=[connection("xdr", "MicrosoftThreatProtection")])
    azure.queries.insert(0, ("union withsource=ParamifySourceTable", table(
        ["ParamifySourceTable", "LastIngested", "Records"], [["AzureActivity", iso(NOW), 10]])))
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and [r["name"] for r in ws["enabled_rules_quiet"]] == ["mdi"]
    assert {r["name"]: r["tables_without_data"] for r in ws["enabled_rules_missing_data"]} == {
        "mdi": ["SecurityAlert"], "mixed": ["SecurityAlert", "SigninLogs"]}
    assert (ev["summary"]["enabled_rules_missing_data"], ev["summary"]["enabled_rules_quiet"]) == (2, 1)
    assert not any(c[0] == "POST" and "by ProductName" in c[2] for c in azure.calls)


def test_analytics_rules_unreadable_connector_listing_leaves_quiet_unknown(azure, tmp_path):
    incident_rules_workspace(azure, [incident_rule("mdi", "Azure Advanced Threat Protection")],
                         stable=Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}}),
                         preview=[connection("o365", "Office365")])
    code, ev = run("sentinel_analytics_rules", tmp_path)
    assert code == 1 and ev["metadata"]["partial_failure"] is True
    assert ws_a(ev)["enabled_rules_quiet"] is None
    assert (ev["summary"]["enabled_rules_missing_data"], ev["summary"]["enabled_rules_quiet"]) == (1, None)


def test_analytics_rules_failed_preview_connector_listing_is_a_note(azure, tmp_path):
    retired = Resp(400, {"error": {"code": "InvalidApiVersionParameter", "message": "retired"}})
    incident_rules_workspace(azure, [incident_rule("mdi", "Azure Advanced Threat Protection")], preview=retired)
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and ws["enabled_rules_quiet"] is None and ev["summary"]["enabled_rules_quiet"] is None
    assert len(ws["notes"]) == 1 and "Defender XDR" in ws["notes"][0]
    # A rule its own stable-listed connection makes quiet stays quiet without the preview listing.
    incident_rules_workspace(azure, [incident_rule("mdi", "Azure Advanced Threat Protection")],
                         stable=[connection("aatp", "AzureAdvancedThreatProtection")], preview=retired)
    for f in tmp_path.glob("azure_sentinel_analytics_rules_*.json"):
        f.unlink()
    _, ev = run("sentinel_analytics_rules", tmp_path)
    assert [r["name"] for r in ws_a(ev)["enabled_rules_quiet"]] == ["mdi"] and ev["summary"]["enabled_rules_quiet"] == 1


def test_analytics_rules_without_alert_only_rules_missing_data_skip_the_connector_listing(azure, tmp_path):
    incident_rules_workspace(azure, [incident_rule("mde", "Microsoft Defender Advanced Threat Protection")])
    code, ev = run("sentinel_analytics_rules", tmp_path)
    assert code == 0 and ws_a(ev)["enabled_rules_quiet"] == [] and ev["summary"]["enabled_rules_quiet"] == 0
    assert not any(c[1] == f"{SI_A}/dataConnectors" for c in azure.calls)


def test_analytics_rules_quiet_total_is_null_if_any_measured_workspace_is_unknown():
    summarize = MODS["sentinel_analytics_rules"].summarize
    quiet = [{"name": "mdi"}]
    known = {"rules": [], "enabled_rules_missing_data": quiet, "enabled_rules_quiet": quiet}
    unknown = {"rules": [], "enabled_rules_missing_data": quiet, "enabled_rules_quiet": None}
    unmeasured = {"rules": [], "enabled_rules_missing_data": None, "enabled_rules_quiet": None}
    assert summarize([known, unmeasured])["enabled_rules_quiet"] == 1
    assert summarize([known, unknown])["enabled_rules_quiet"] is None
    assert summarize([unmeasured])["enabled_rules_quiet"] is None


def test_analytics_rules_workspace_without_customer_id(azure, tmp_path):
    workspaces = azure.arm[(f"/subscriptions/{SUB}/providers/Microsoft.OperationalInsights/workspaces", "2023-09-01")]
    del workspaces["value"][0]["properties"]["customerId"]
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 1 and ev["metadata"]["partial_failure"] is True
    assert ws["rules"] and all(r["tables_without_data"] is None for r in ws["rules"])
    assert ws["enabled_rules_missing_data"] is None and ev["summary"]["enabled_rules_missing_data"] is None
    assert ws["enabled_rules_quiet"] is None and ev["summary"]["enabled_rules_quiet"] is None
    assert not any(c[0] == "POST" for c in azure.calls)


def test_analytics_rules_without_ingestion_leave_data_unknown(azure, tmp_path):
    azure.queries.insert(0, ("union withsource=ParamifySourceTable", Resp(403, {"error": {
        "code": "InsufficientAccessError", "message": "no query access"}})))
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 1 and json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"
    assert ws["rules"] and all(r["tables_without_data"] is None for r in ws["rules"])
    assert ws["ingesting_tables_not_read"] is None and ws["enabled_rules_missing_data"] is None
    assert ws["enabled_rules_quiet"] is None
    summary = ev["summary"]
    assert summary["enabled_rules_missing_data"] is None and summary["ingesting_tables_not_read"] is None
    assert summary["enabled_rules_quiet"] is None
    assert summary["enabled_rules_tables_unknown"] == 3


def test_analytics_rules_without_the_table_list_still_list_rules(azure, tmp_path):
    azure.arm[(f"{WS_A}/tables", "2023-09-01")] = Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
    code, ev = run("sentinel_analytics_rules", tmp_path)
    ws = ws_a(ev)
    assert code == 1 and ws["enabled_rules"] == 3
    assert all(r["tables_read"] is None for r in ws["rules"]) and "ingesting_tables_not_read" not in ws
    assert ev["summary"]["enabled_rules_tables_unknown"] is None


def test_incidents(azure, tmp_path):
    xdr = azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"][0]["properties"]
    xdr.update(providerName="Microsoft XDR", providerIncidentId="4521")
    xdr["additionalData"]["providerIncidentUrl"] = "https://security.microsoft.com/incidents/4521?tid=t-1"
    code, ev = run("sentinel_incidents", tmp_path)
    assert code == 0
    ws = ws_a(ev)
    names = [i["name"] for i in ws["incidents"]]
    assert names == ["i-closed", "i-new"]  # the old closed one is outside the lookback
    assert {k: ws["incidents"][1][k] for k in ("provider_name", "provider_incident_id", "provider_incident_url")} == {
        "provider_name": "Microsoft XDR", "provider_incident_id": "4521",
        "provider_incident_url": "https://security.microsoft.com/incidents/4521?tid=t-1"}  # Microsoft's own link, kept whole
    assert ws["incidents"][0]["provider_incident_id"] is None
    closed = ws["incidents"][0]
    assert closed["closed_time_utc"] and closed["hours_to_close"] == pytest.approx(24, abs=0.1)
    assert ws["open_incidents"] == 1 and ws["oldest_open_age_days"] == pytest.approx(200, abs=0.1)
    assert ws["closed_missing_close_time"] == 0
    assert {k: ws["completeness"][k] for k in ("arm_created", "kql_created", "counts_agree")} == {
        "arm_created": 1, "kql_created": 1, "counts_agree": True}
    assert ws["security_incident_retention_days"] == 90 and ws["notes"] == []
    assert "but not when an incident was first activated or assigned" in ws["limitations"][0]


def test_incidents_without_the_table(azure, tmp_path):
    azure.queries = [q for q in azure.queries if q[0] != "SecurityIncident"]
    azure.queries.insert(0, ("SecurityIncident", Resp(400, {"error": {"code": "BadArgumentError", "innererror": {
        "message": "'where' operator: Failed to resolve table or column expression named 'SecurityIncident'"}}})))
    code, ev = run("sentinel_incidents", tmp_path)
    ws = ws_a(ev)
    # A workspace listing incidents always has the table, so here it was refused, like a 403.
    assert code == 1 and ev["metadata"]["partial_failure"] is True and ws["notes"] == []
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"
    assert "table-level access" in ev["metadata"]["api_failures"][0]["message"]
    assert ws["closed_missing_close_time"] is None and ws["completeness"]["counts_agree"] is None
    assert ws["monthly"] is None and ws["acknowledged_incidents"] is None and ws["open_unacknowledged"] is None
    assert ev["summary"]["acknowledged_incidents"] is None
    assert all(i["status_changes"] is None and i["history_complete"] is None and i["tasks"] is None for i in ws["incidents"])
    assert all(i["entities"] is None for i in ws["incidents"])
    assert next(i for i in ws["incidents"] if i["name"] == "i-closed")["close_time_status"] == "unknown"


def onboard_second_workspace(azure, incidents=None):
    """law-plain becomes a Sentinel workspace too; its queries are routed by its customerId."""
    azure.arm[(f"{WS_B}/providers/Microsoft.SecurityInsights/onboardingStates", "2025-09-01")] = {
        "value": [{"name": "default", "properties": {}}]}
    azure.arm[(f"{WS_B}/providers/Microsoft.SecurityInsights/incidents", "2025-09-01")] = (
        incidents if incidents is not None else {"value": []})


def test_incidents_idle_workspace_keeps_the_totals(azure, tmp_path):
    onboard_second_workspace(azure)
    azure.queries.insert(0, ("cust-b/query", Resp(400, {"error": {"code": "BadArgumentError", "innererror": {
        "message": "'where' operator: Failed to resolve table or column expression named 'SecurityIncident'"}}})))
    code, ev = run("sentinel_incidents", tmp_path)
    idle = next(w for w in ev["results"]["workspaces"] if w["name"] == "law-plain")
    assert code == 0 and idle["acknowledged_incidents"] == 0 and idle["open_unacknowledged"] == 0
    assert idle["notes"] == ["SecurityIncident table does not exist in this workspace: no incident has been written"]
    a = ws_a(ev)
    assert ev["summary"]["acknowledged_incidents"] == a["acknowledged_incidents"] == 1
    assert ev["summary"]["open_unacknowledged"] == a["open_unacknowledged"]
    assert ev["summary"]["closed_missing_close_time"] == a["closed_missing_close_time"] == 0


def test_incidents_failed_workspace_nulls_the_totals(azure, tmp_path):
    onboard_second_workspace(azure, Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}}))
    code, ev = run("sentinel_incidents", tmp_path)
    assert code == 1 and ws_a(ev)["acknowledged_incidents"] == 1
    assert all(ev["summary"][k] is None for k in (
        "incidents_in_scope", "open_incidents", "closed_incidents", "acknowledged_incidents", "open_unacknowledged",
        "closed_missing_close_time", "closed_close_time_not_retained", "open_new_unowned_history_incomplete",
        "recurring_titles"))
    # No Sentinel workspace at all is a known nothing, which workspaces_collected 0 already says; unless discovery failed.
    assert set(MODS["sentinel_incidents"].summarize([], True).values()) == {0}
    assert set(MODS["sentinel_incidents"].summarize([], False).values()) == {None}


@pytest.mark.parametrize("failure", ["workspaces", "onboarding", "unknown name"])
def test_incidents_failed_discovery_nulls_the_totals(azure, tmp_path, monkeypatch, failure):
    refused = Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
    if failure == "workspaces":
        azure.arm[(f"/subscriptions/{SUB}/providers/Microsoft.OperationalInsights/workspaces", "2023-09-01")] = refused
    elif failure == "onboarding":
        azure.arm[(f"{SI_A}/onboardingStates", "2025-09-01")] = refused
    else:
        monkeypatch.setenv("SENTINEL_WORKSPACES", "law-missing")
    code, ev = run("sentinel_incidents", tmp_path)
    # Finding no Sentinel workspace isn't knowing there are none.
    assert code == 1 and ev["summary"]["workspaces_collected"] == 0
    assert ev["summary"]["incidents_in_scope"] is None and ev["summary"]["acknowledged_incidents"] is None


def test_incidents_no_sentinel_workspace_counts_zero(azure, tmp_path):
    azure.arm[(f"{SI_A}/onboardingStates", "2025-09-01")] = {"value": []}
    code, ev = run("sentinel_incidents", tmp_path)
    assert code == 0 and ev["summary"]["workspaces_without_sentinel"] == 2
    assert ev["summary"]["incidents_in_scope"] == 0 and ev["summary"]["acknowledged_incidents"] == 0


@pytest.mark.parametrize("arm_table", ["listed", "refused"])
def test_incidents_quiet_workspace_the_query_cant_find_is_empty(azure, tmp_path, arm_table):
    onboard_second_workspace(azure)
    azure.arm[(f"{WS_B}/tables/SecurityIncident", "2023-09-01")] = (
        {"properties": {"retentionInDays": 90}} if arm_table == "listed"
        else Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}}))
    azure.queries.insert(0, ("cust-b/query", Resp(400, {"error": {"code": "BadArgumentError", "innererror": {
        "message": "'where' operator: Failed to resolve table or column expression named 'SecurityIncident'"}}})))
    code, ev = run("sentinel_incidents", tmp_path)
    quiet = next(w for w in ev["results"]["workspaces"] if w["name"] == "law-plain")
    # No incidents listed, so there's nothing to read, whatever ARM says of the table; only a refused GET fails the run.
    assert code == (0 if arm_table == "listed" else 1) and quiet["acknowledged_incidents"] == 0
    assert quiet["notes"] == ["SecurityIncident table wasn't found, and the workspace lists no incidents"]
    assert ev["summary"]["acknowledged_incidents"] == ws_a(ev)["acknowledged_incidents"]


# Fragments only the history query has; the closed-time query also names ModifiedBy, for its ordering.
HISTORY_ROUTE = "ModifiedBy, CreatedTime, LastModifiedTime"
HISTORY_COLUMNS = ["TimeGenerated", "IncidentName", "Status", "Severity", "ClosedTime", "ModifiedBy", "OwnerId", "Owner",
                   "CreatedTime", "LastModifiedTime"]


def update(name, at, status, severity, closed=None, owner="", by="Incident created from alert", created=None, owner_id=None):
    """Each owner name has its own object id unless owner_id gives one."""
    if owner_id is None:
        owner_id = f"u-{owner.split('@')[0].lower()}" if owner else ""
    return [iso(at), name, status, severity, iso(closed) if closed else None, by, owner_id, owner,
            iso(created) if created else None, iso(at)]


def history_table(rows):
    """An incident's first row is its creation row unless it says otherwise; later rows keep its CreatedTime."""
    first = {}
    for r in rows:
        r[8] = r[8] or first.setdefault(r[1], r[9])
    return table(HISTORY_COLUMNS, rows)


def incident_history():
    """i-closed is triaged, escalated and closed inside the window; i-new was last touched ten days ago."""
    created = NOW - timedelta(days=3)
    return [
        update("i-closed", created, "New", "Medium"),
        update("i-closed", created + timedelta(hours=12), "Active", "High", owner="john@contoso.com", by="john@contoso.com"),
        update("i-closed", NOW - timedelta(days=2), "Closed", "High", NOW - timedelta(days=2),
               owner="john@contoso.com", by="john@contoso.com"),
        update("i-new", NOW - timedelta(days=10), "New", "High", owner="john@contoso.com", by="Microsoft XDR",
               created=NOW - timedelta(days=200)),
    ]


# Microsoft's documented Tasks keys; a reopened task keeps its lastCompletedTimeUtc.
INCIDENT_TASKS = json.dumps([
    {"taskId": "t-1", "title": "Contain host", "status": "Completed", "createdTimeUtc": iso(NOW - timedelta(days=3)),
     "lastCompletedTimeUtc": iso(NOW - timedelta(days=2))},
    {"taskId": "t-2", "title": "Reset password", "status": "New", "createdTimeUtc": iso(NOW - timedelta(days=3)),
     "lastCompletedTimeUtc": iso(NOW - timedelta(days=2, hours=12))}])


# A process entity defines its host, account and file inline; the top level refers back with $ref.
INCIDENT_ALERT_ENTITIES = [["i-closed", "a-1", json.dumps([
    {"$id": "2", "Type": "process", "ProcessId": "4242", "CommandLine": "powershell -enc c2VjcmV0", "ImageFile": {
        "$id": "3", "Type": "file", "Name": "powershell.exe", "FileHashes": [{"$id": "4", "Type": "filehash", "Value": "abc123"}]},
     "Account": {"$id": "5", "Type": "account", "Name": "john", "UPNSuffix": "contoso.com"}},
    {"$ref": "5"},
    {"$id": "6", "Type": "host", "HostName": "vm1", "FQDN": "vm1.contoso.com"},
    {"$id": "7", "Type": "ip", "Address": "203.0.113.7"},
    {"$id": "8", "Type": "ip", "Address": "203.0.113.7"},
    {"$id": "9", "Type": "url", "Url": "https://user:pw@files.example.com/share/a.zip?sv=2024&sig=abc#x"}])]]


def test_incidents_response_timeline_and_entities(azure, tmp_path):
    arm = azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"]
    arm[1]["properties"].update(firstActivityTimeUtc=iso(NOW - timedelta(days=3, hours=6)),
                                classificationComment="phishing confirmed, mailbox purged",
                                additionalData={"alertsCount": 1, "commentsCount": 2})
    code, ev = run("sentinel_incidents", tmp_path)
    assert code == 0 and ev["metadata"]["partial_failure"] is False
    ws = ws_a(ev)
    by_name = {i["name"]: i for i in ws["incidents"]}
    closed = by_name["i-closed"]
    assert closed["hours_to_detect"] == pytest.approx(6, abs=0.01)
    assert closed["hours_to_acknowledge"] == pytest.approx(12, abs=0.01) and closed["hours_to_close"] == pytest.approx(24, abs=0.1)
    assert [(c["from"], c["to"]) for c in closed["status_changes"]] == [("New", "Active"), ("Active", "Closed")]
    assert closed["owner_changes"] == [{"time": iso(NOW - timedelta(days=2, hours=12)), "from": None,
                                        "to": "john@contoso.com", "modified_by": "john@contoso.com"}]
    assert [(c["from"], c["to"]) for c in closed["severity_changes"]] == [("Medium", "High")]
    assert closed["tasks"] == [
        {"title": "Contain host", "status": "Completed", "created_time_utc": iso(NOW - timedelta(days=3)),
         "completed_time_utc": iso(NOW - timedelta(days=2))},
        {"title": "Reset password", "status": "New", "created_time_utc": iso(NOW - timedelta(days=3)), "completed_time_utc": None}]
    assert closed["comments_count"] == 2 and closed["classification_comment"].startswith("phishing")
    assert closed["related_analytic_rule_ids"] == [f"{SI_A}/alertRules/r1"]
    assert closed["alerts_found"] == 1 and closed["history_complete"] is True and closed["updates_read"] == 3
    # No command line, query string or credentials reach the evidence.
    assert closed["entities"] == [
        {"kind": "account", "id": "john@contoso.com"}, {"kind": "file", "id": "powershell.exe"},
        {"kind": "filehash", "id": "abc123"}, {"kind": "host", "id": "vm1.contoso.com"},
        {"kind": "ip", "id": "203.0.113.7"}, {"kind": "process", "id": "powershell.exe (4242)"},
        {"kind": "url", "id": "https://files.example.com"}]
    old = by_name["i-new"]
    # Its alerts are older than the lookback, so its entities are unknown, not empty.
    assert old["history_complete"] is False and old["acknowledged_time_utc"] is None and old["entities"] is None
    assert ws["acknowledged_incidents"] == 1 and ws["mtta_hours"] == pytest.approx(12, abs=0.01)
    assert ws["recurrence_by_rule"] == []  # i-new shares the rule but was created before the lookback
    assert ws["recurrence_by_title"] == [] and ev["summary"]["acknowledged_incidents"] == 1


def test_incidents_monthly_metrics(azure, tmp_path):
    arm = azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"]
    arm.append(incident("i-repeat", "New", NOW - timedelta(days=1)))
    arm[-1]["properties"]["title"] = "incident i-closed"
    code, ev = run("sentinel_incidents", tmp_path)
    ws = ws_a(ev)
    months = ws["monthly"]
    assert [m["month"] for m in months] == sorted({(NOW - timedelta(days=d)).strftime("%Y-%m") for d in range(91)})
    assert sum(m["incidents_created"] for m in months) == 2 and sum(m["incidents_closed"] for m in months) == 1
    closed_in = next(m for m in months if m["incidents_closed"])
    assert closed_in["mttr_hours"] == pytest.approx(24, abs=0.1) and closed_in["month"] == (NOW - timedelta(days=2)).strftime("%Y-%m")
    current = months[-1]
    # Now: i-new (from its last update) and i-repeat (from the incident itself, which has no retained update) are open.
    assert current["open_at_end"] == 2 and current["open_at_end_by_severity"] == {"High": 2}
    assert current["open_at_end_by_owner"] == {"john@contoso.com": 2}
    assert all(m["updates_retained"] for m in months)
    assert ws["recurrence_by_title"][0]["title"] == "incident i-closed" and ws["recurrence_by_title"][0]["incidents"] == 2


def test_incidents_backlog_before_retention_is_unknown(azure, tmp_path):
    azure.arm[(f"{WS_A}/tables/SecurityIncident", "2023-09-01")] = {"properties": {"retentionInDays": 30}}
    code, ev = run("sentinel_incidents", tmp_path)
    months = ws_a(ev)["monthly"]
    retained_from = NOW - timedelta(days=30)
    for m in months:
        end = azure_rest.parse_time(m["to"])
        assert (m["open_at_end"] is None) == (end < retained_from)
        assert m["updates_retained"] == (azure_rest.parse_time(m["from"]) >= retained_from)


def test_incidents_history_starts_at_the_lookback_when_retention_is_longer(azure, tmp_path):
    azure.arm[(f"{WS_A}/tables/SecurityIncident", "2023-09-01")] = {"properties": {"retentionInDays": 365}}
    azure.queries.insert(0, (HISTORY_ROUTE, history_table(incident_history()[:3] + [
        update("i-new", NOW - timedelta(days=10), "Active", "High", owner="pat@contoso.com", by="pat@contoso.com",
               created=NOW - timedelta(days=200))])))
    code, ev = run("sentinel_incidents", tmp_path)
    ws = ws_a(ev)
    old = next(i for i in ws["incidents"] if i["name"] == "i-new")
    # Created 200 days ago, before the 90 days read: its first update in the window isn't its acknowledgement.
    assert old["history_complete"] is False and old["hours_to_acknowledge"] is None
    assert ws["mtta_hours"] == pytest.approx(12, abs=0.01)
    assert azure_rest.parse_time(ws["updates_retained_from"]) == pytest.approx(NOW - timedelta(days=90), abs=timedelta(minutes=5))


def test_incidents_refused_history_keeps_close_times(azure, tmp_path):
    azure.queries.insert(0, (HISTORY_ROUTE, Resp(403, {"error": {"code": "InsufficientAccessError", "message": "no"}})))
    code, ev = run("sentinel_incidents", tmp_path)
    ws = ws_a(ev)
    closed = next(i for i in ws["incidents"] if i["name"] == "i-closed")
    assert code == 1 and closed["closed_time_utc"] and closed["close_time_status"] == "found" and closed["tasks"]
    assert closed["acknowledged_time_utc"] is None and closed["status_changes"] is None and closed["history_complete"] is None
    assert ws["monthly"] is None and ws["acknowledged_incidents"] is None and ws["mtta_hours"] is None
    assert ws["updates_retained_from"] is None and ev["summary"]["acknowledged_incidents"] is None


def test_incidents_automation_and_xdr_changes_are_not_acknowledgements(azure, tmp_path):
    created = NOW - timedelta(days=3)
    azure.queries.insert(0, (HISTORY_ROUTE, history_table([
        update("i-closed", created, "New", "High", owner="tier1@contoso.com", by="Automation rule - assign tier 1"),
        update("i-closed", created + timedelta(hours=1), "New", "High", owner="tier2@contoso.com",
               by="Automation rule - escalate"),
        update("i-closed", created + timedelta(hours=2), "Active", "High", owner="tier2@contoso.com", by="Microsoft XDR"),
        update("i-closed", created + timedelta(hours=30), "Closed", "High", NOW - timedelta(days=2),
               owner="pat@contoso.com", by="pat@contoso.com")])))
    code, ev = run("sentinel_incidents", tmp_path)
    closed = next(i for i in ws_a(ev)["incidents"] if i["name"] == "i-closed")
    # Neither the creation row, the automation rule nor the XDR sync counts; the analyst taking it over does.
    assert closed["hours_to_acknowledge"] == pytest.approx(30, abs=0.01)


def freeze_now(monkeypatch, at):
    """collect's clock, so a test's "minutes ago" stays minutes ago however long the run takes."""
    class Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return at
    monkeypatch.setattr(MODS["sentinel_incidents"], "datetime", Frozen)


def run_with_history(azure, tmp_path, rows):
    azure.queries.insert(0, (HISTORY_ROUTE, history_table(rows)))
    code, ev = run("sentinel_incidents", tmp_path)
    return code, ev, {i["name"]: i for i in ws_a(ev)["incidents"]}


def test_incidents_closing_straight_from_new_is_an_acknowledgement(azure, tmp_path):
    created = NOW - timedelta(days=3)
    _, _, by_name = run_with_history(azure, tmp_path, [
        update("i-closed", created, "New", "Low"),
        update("i-closed", created + timedelta(hours=5), "Closed", "Low", NOW - timedelta(days=2), by="pat@contoso.com")])
    assert by_name["i-closed"]["hours_to_acknowledge"] == pytest.approx(5, abs=0.01)


def test_incidents_person_closing_after_automation_assigned_it(azure, tmp_path):
    created = NOW - timedelta(days=3)
    _, _, by_name = run_with_history(azure, tmp_path, [
        update("i-closed", created, "New", "High"),
        update("i-closed", created + timedelta(hours=1), "Active", "High", owner="tier1@contoso.com",
               by="AUTOMATION RULE - triage"),
        update("i-closed", created + timedelta(hours=20), "Closed", "High", NOW - timedelta(days=2),
               owner="tier1@contoso.com", by="tier1@contoso.com")])
    assert by_name["i-closed"]["hours_to_acknowledge"] == pytest.approx(20, abs=0.01)


def test_incidents_reopen_is_not_an_acknowledgement(azure, tmp_path):
    created = NOW - timedelta(days=3)
    _, _, by_name = run_with_history(azure, tmp_path, [
        update("i-closed", created, "New", "Low"),
        update("i-closed", created + timedelta(hours=1), "Closed", "Low", created + timedelta(hours=1),
               by="Automation rule - close benign"),
        update("i-closed", created + timedelta(hours=9), "Active", "Low", owner="pat@contoso.com", by="pat@contoso.com"),
        update("i-closed", NOW - timedelta(days=2), "Closed", "Low", NOW - timedelta(days=2), owner="pat@contoso.com",
               by="pat@contoso.com")])
    assert by_name["i-closed"]["acknowledged_time_utc"] is None


@pytest.mark.parametrize("status, owner, by, acknowledged", [
    ("Active", "pat@contoso.com", "pat@contoso.com", True),
    ("New", "pat@contoso.com", "pat@contoso.com", True),
    ("Active", "", "pat@contoso.com", True),
    ("New", "", "pat@contoso.com", False),
    ("Active", "tier1@contoso.com", "Automation rule - triage", False),
])
def test_incidents_created_by_a_person_active_or_owned_is_acknowledged(azure, tmp_path, status, owner, by, acknowledged):
    created = NOW - timedelta(days=1)
    manual = incident("i-manual", status, created)
    manual["properties"]["owner"] = {"userPrincipalName": owner} if owner else {}
    azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"].append(manual)
    _, ev, by_name = run_with_history(azure, tmp_path, incident_history() + [
        update("i-manual", created, status, "High", owner=owner, by=by)])
    # A person creating an incident already Active or owned has taken it up; its creation row is the only row.
    assert by_name["i-manual"]["history_complete"] is True
    assert by_name["i-manual"]["acknowledged_time_utc"] == (iso(created) if acknowledged else None)
    assert ws_a(ev)["open_unacknowledged"] == (0 if acknowledged else 1)


def test_incidents_owner_rename_is_not_an_assignment(azure, tmp_path):
    created = NOW - timedelta(days=3)
    _, _, by_name = run_with_history(azure, tmp_path, [
        update("i-closed", created, "New", "High", owner="pat@contoso.com", by="Automation rule - assign"),
        # The same object id under a new UPN: Pat's update hours later only renames the owner.
        update("i-closed", created + timedelta(hours=2), "New", "High", owner="pat.doe@contoso.com", owner_id="u-pat",
               by="pat.doe@contoso.com"),
        update("i-closed", created + timedelta(hours=6), "Active", "High", owner="pat.doe@contoso.com", owner_id="u-pat",
               by="pat.doe@contoso.com"),
        update("i-closed", NOW - timedelta(days=2), "Closed", "High", NOW - timedelta(days=2), owner="pat.doe@contoso.com",
               owner_id="u-pat", by="pat.doe@contoso.com")])
    assert by_name["i-closed"]["hours_to_acknowledge"] == pytest.approx(6, abs=0.01)


def test_incidents_owner_changes_follow_the_object_id(azure, tmp_path):
    created = NOW - timedelta(days=3)
    _, _, by_name = run_with_history(azure, tmp_path, [
        update("i-closed", created, "New", "High"),
        update("i-closed", created + timedelta(hours=1), "New", "High", owner="", owner_id="u-9", by="Automation rule - assign"),
        update("i-closed", created + timedelta(hours=2), "New", "High", owner="pat@contoso.com", owner_id="u-9",
               by="Microsoft XDR"),
        update("i-closed", created + timedelta(hours=3), "New", "High", owner="pat.doe@contoso.com", owner_id="u-9",
               by="Microsoft XDR"),
        update("i-closed", created + timedelta(hours=4), "Active", "High", owner="sam@contoso.com", by="sam@contoso.com"),
        update("i-closed", NOW - timedelta(days=2), "Closed", "High", NOW - timedelta(days=2), owner="", owner_id="",
               by="sam@contoso.com")])
    # Set by object id alone, then named and renamed under that id, then reassigned, then unassigned.
    assert [(c["from"], c["to"]) for c in by_name["i-closed"]["owner_changes"]] == [
        (None, "u-9"), ("pat.doe@contoso.com", "sam@contoso.com"), ("sam@contoso.com", None)]


def test_incidents_older_than_the_history_have_no_acknowledgement(azure, tmp_path):
    old = NOW - timedelta(days=200)
    rows = incident_history()[:3] + [
        update("i-new", NOW - timedelta(days=10), "New", "High", created=old),
        update("i-new", NOW - timedelta(days=9), "Active", "High", owner="pat@contoso.com", by="pat@contoso.com", created=old)]
    _, ev, by_name = run_with_history(azure, tmp_path, rows)
    assert by_name["i-new"]["acknowledged_time_utc"] is None and by_name["i-new"]["hours_to_acknowledge"] is None
    assert ws_a(ev)["acknowledged_incidents"] == 1
    assert all((m["mtta_hours"] or 12) == pytest.approx(12, abs=0.01) for m in ws_a(ev)["monthly"])


def test_incidents_monthly_counts_only_in_scope_incidents(azure, tmp_path):
    rows = azure.queries[[q[0] for q in azure.queries].index("arg_max(Order, Status, ClosedTime")][1]["tables"][0]["rows"]
    rows.append(["i-old-closed", "Closed", iso(NOW - timedelta(days=5)), iso(NOW - timedelta(days=200)), "[]"])
    code, ev = run("sentinel_incidents", tmp_path)
    # i-old-closed closed in the lookback but was created before it, so it's not listed and not counted.
    assert sum(m["incidents_closed"] for m in ws_a(ev)["monthly"]) == 1


def test_incidents_open_unacknowledged_means_no_person_acknowledged_it(azure, tmp_path):
    recent = NOW - timedelta(days=1)
    azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"] += [
        incident("i-recent", "New", recent), incident("i-unread", "New", recent)]
    _, ev, by_name = run_with_history(azure, tmp_path, incident_history() + [
        update("i-recent", recent, "New", "High"),
        update("i-recent", recent + timedelta(minutes=1), "New", "High", owner="john@contoso.com",
               by="Automation rule - assign")])
    # i-recent has an owner but no person acknowledged it. i-unread has no rows read yet, and i-new is older than
    # the history, so neither can be known.
    assert by_name["i-recent"]["history_complete"] is True and by_name["i-unread"]["history_complete"] is False
    assert ws_a(ev)["open_unacknowledged"] == 1 and ev["summary"]["open_unacknowledged"] == 1


def history_rows(rows):
    return [dict(zip(HISTORY_COLUMNS, r)) for r in history_table(rows)["tables"][0]["rows"]]


def complete(incident_, rows, since, now):
    return MODS["sentinel_incidents"].timeline(incident_, rows, since, now)["history_complete"]


def test_incident_history_is_complete_only_from_its_creation_row_to_its_last_change():
    created, changed, since = NOW - timedelta(hours=2), NOW - timedelta(minutes=10), NOW - timedelta(days=30)
    incident_ = {"created_time_utc": iso(created), "last_modified_time_utc": iso(changed), "status": "Active",
                 "severity": "Low", "owner_user_principal_name": "pat@contoso.com"}
    rows = history_rows([
        update("x", created, "New", "Low"),
        update("x", changed, "Active", "low", owner="Pat@contoso.com", by="pat@contoso.com")])
    assert complete(incident_, rows, since, NOW)  # severity and owner in any case
    assert not complete(incident_, [], since, NOW)
    assert not complete(incident_, rows[1:], since, NOW)  # its creation row wasn't read
    assert not complete(incident_, rows, NOW - timedelta(hours=1), NOW)
    # The latest row read isn't the incident as it is now: an update was dropped or is still being ingested.
    assert not complete(incident_, rows[:1], since, NOW + timedelta(days=2))
    # A lastModifiedTimeUtc moved over an hour ago with the state unchanged is Defender XDR sync bookkeeping.
    synced = {**incident_, "status": "New", "owner_user_principal_name": None,
              "last_modified_time_utc": iso(created + timedelta(seconds=10))}
    assert complete(synced, rows[:1], since, created + timedelta(hours=2))
    assert not complete(synced, rows[:1], since, created + timedelta(minutes=30))  # within the hour, so maybe lag


def test_incidents_dropped_row_leaves_the_history_incomplete(azure, tmp_path):
    created = NOW - timedelta(days=2)
    azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"].append(incident("i-dropped", "Active", created))
    # A person set it Active and took it yesterday, but only its creation row arrived.
    _, ev, by_name = run_with_history(azure, tmp_path, incident_history() + [update("i-dropped", created, "New", "High")])
    assert by_name["i-dropped"]["history_complete"] is False and ws_a(ev)["open_unacknowledged"] == 0


@pytest.mark.parametrize("arm_owner, row_owner", [
    ({"email": "pat@contoso.com", "objectId": "u-pat"}, "pat@contoso.com"),  # email only, matched by object id
    ({"email": "pat@contoso.com"}, "pat@contoso.com"),  # email only, no id on the ARM side: by name
    ({"userPrincipalName": "pat@contoso.com", "assignedTo": "Pat Doe"}, "Pat Doe"),  # display name vs UPN
    ({"userPrincipalName": "renamed@contoso.com", "objectId": "u-pat"}, "pat@contoso.com"),  # renamed, same id
])
def test_incident_owner_matches_by_id_then_any_name(arm_owner, row_owner):
    created = NOW - timedelta(days=2)
    mod = MODS["sentinel_incidents"]
    arm = incident("x", "Active", created)
    arm["properties"]["owner"] = arm_owner
    incident_ = mod.project_incident(arm, {})
    rows = history_rows([update("x", created, "New", "High"),
                         update("x", created + timedelta(hours=1), "Active", "High", owner=row_owner, by="pat@contoso.com")])
    assert complete(incident_, rows, NOW - timedelta(days=30), NOW)
    if "objectId" in arm_owner:  # with ids on both sides, the id decides
        rows[-1]["OwnerId"] = "u-2"
        assert not complete(incident_, rows, NOW - timedelta(days=30), NOW)


def test_incident_closed_time_order_sorts_like_update_order():
    mod = MODS["sentinel_incidents"]
    assert "strcat_delim(unicode_codepoints_to_string(1)," in mod.CLOSED_TIME_QUERY
    at = iso(NOW)
    rows = [{"TimeGenerated": at, "LastModifiedTime": at, "ModifiedBy": by, "Status": "Active", "Owner": ""}
            for by in ("Automation rule - a", "Automation rule", "Automation rule\tb")]
    # The query's Order string, emulated: joined by U+0001, a modifier that is a prefix of another sorts first.
    keys = ("LastModifiedTime", "TimeGenerated", "ModifiedBy", "Status", "Owner")
    assert sorted(rows, key=lambda r: "\x01".join(r[k] for k in keys)) == sorted(rows, key=mod.update_order)


@pytest.mark.parametrize("person", ["Alice@contoso.com", "pat@contoso.com"])
def test_incident_rows_tied_for_the_latest_time_each_count(person):
    created = NOW - timedelta(days=2)
    at = created + timedelta(hours=1)
    incident_ = MODS["sentinel_incidents"].project_incident(incident("x", "New", created), {})
    incident_.update(owner_user_principal_name=person, owner_assigned_to=None)
    rows = history_rows([update("x", created, "New", "High"),
                         update("x", at, "New", "High", owner="tier1@contoso.com", by="Automation rule - assign", created=created),
                         update("x", at, "New", "High", owner=person, by=person, created=created)])
    rows.sort(key=MODS["sentinel_incidents"].update_order)
    # "Alice" sorts before "Automation rule" and "pat" after it; either way one of the tied rows is the incident now.
    assert complete(incident_, rows, NOW - timedelta(days=30), NOW)


def test_incidents_acknowledgement_found_survives_a_missing_later_row(azure, tmp_path, monkeypatch):
    freeze_now(monkeypatch, NOW)
    created = NOW - timedelta(days=3)
    arm = azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"][1]["properties"]
    arm.update(status="Active", closedTime=None, lastModifiedTimeUtc=iso(NOW - timedelta(minutes=5)))
    _, _, by_name = run_with_history(azure, tmp_path, [
        update("i-closed", created, "New", "High"),
        update("i-closed", created + timedelta(hours=4), "Active", "High", owner="john@contoso.com", by="john@contoso.com")])
    # Changed 5 minutes ago with no row yet: incomplete, but that can't change which update came first.
    closed = by_name["i-closed"]
    assert closed["history_complete"] is False and closed["hours_to_acknowledge"] == pytest.approx(4, abs=0.01)


@pytest.mark.parametrize("flip", [False, True])
def test_incidents_same_instant_rows_always_sort_alike(azure, tmp_path, flip):
    created = NOW - timedelta(days=3)
    at = created + timedelta(hours=1)
    pair = [update("i-closed", at, "New", "High", owner="tier1@contoso.com", by="Automation rule - assign", created=created),
            update("i-closed", at, "New", "High", owner="pat@contoso.com", by="pat@contoso.com", created=created)]
    _, _, by_name = run_with_history(azure, tmp_path, [update("i-closed", created, "New", "High")] + pair[::-1 if flip else 1])
    assert [(c["from"], c["to"]) for c in by_name["i-closed"]["owner_changes"]] == [
        (None, "tier1@contoso.com"), ("tier1@contoso.com", "pat@contoso.com")]


def test_incidents_history_is_ordered_by_the_modification_each_row_records(azure, tmp_path):
    created = NOW - timedelta(days=3)
    rows = [update("i-closed", created, "New", "High", created=created),
            update("i-closed", created + timedelta(seconds=1), "Active", "High", owner="tier1@contoso.com",
                   by="Automation rule - triage", created=created),
            update("i-closed", NOW - timedelta(days=2), "Closed", "High", NOW - timedelta(days=2), owner="john@contoso.com",
                   by="pat@contoso.com", created=created)]
    rows[1][0] = rows[0][0]  # written in the same second as the creation row, and returned first
    _, _, by_name = run_with_history(azure, tmp_path, [rows[1], rows[0], rows[2]])
    closed = by_name["i-closed"]
    assert closed["history_complete"] is True and closed["hours_to_acknowledge"] == pytest.approx(24, abs=0.01)
    assert [(c["from"], c["to"]) for c in closed["status_changes"]] == [("New", "Active"), ("Active", "Closed")]


def test_incidents_open_counts_split_on_whether_the_history_was_read(azure, tmp_path, monkeypatch):
    freeze_now(monkeypatch, NOW)
    created = NOW - timedelta(days=3)
    synced = incident("i-synced", "New", created)
    synced["properties"].update(owner={}, providerName="Microsoft XDR", lastModifiedTimeUtc=iso(created + timedelta(seconds=10)))
    fresh = incident("i-fresh", "New", NOW - timedelta(minutes=30))
    fresh["properties"].update(owner={}, lastModifiedTimeUtc=iso(NOW - timedelta(minutes=5)))
    azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"] += [synced, fresh]
    _, ev, by_name = run_with_history(azure, tmp_path, incident_history() + [
        update("i-synced", created, "New", "High", by="Microsoft XDR"),
        update("i-fresh", NOW - timedelta(minutes=30), "New", "High")])
    # i-synced's lastModifiedTimeUtc moved 10 s after creation, days ago, with no row: its history is still whole.
    # i-fresh changed 5 minutes ago and that update isn't in yet, so only the incident list speaks for it.
    assert by_name["i-synced"]["history_complete"] is True and by_name["i-fresh"]["history_complete"] is False
    ws = ws_a(ev)
    assert ws["open_unacknowledged"] == 1 and ws["open_new_unowned_history_incomplete"] == 1


@pytest.mark.parametrize("owner, label", [({"email": "pat@contoso.com"}, "pat@contoso.com"), ({"objectId": "u-9"}, "u-9")])
def test_incidents_owner_known_only_by_email_or_id_is_an_owner(azure, tmp_path, owner, label):
    created = NOW - timedelta(days=1)
    stale, assigned = incident("i-stale-new", "New", NOW - timedelta(days=120)), incident("i-assigned", "New", created)
    stale["properties"]["owner"] = assigned["properties"]["owner"] = owner
    azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"] += [stale, assigned]
    row = update("i-assigned", created + timedelta(minutes=1), "New", "High", owner=label, by="Automation rule - assign")
    row[6], row[7] = owner.get("objectId", ""), owner.get("email", "")  # OwnerId, and Owner from the names only
    _, ev, by_name = run_with_history(azure, tmp_path, incident_history() + [update("i-assigned", created, "New", "High"), row])
    ws = ws_a(ev)
    # Neither is unowned or unassigned, from its rows or from the incident list.
    assert by_name["i-assigned"]["history_complete"] is True and ws["open_new_unowned_history_incomplete"] == 0
    assert ws["monthly"][-1]["open_at_end_by_owner"] == {"john@contoso.com": 1, label: 2}


def test_incidents_backlog_older_than_the_history_still_new_and_unowned(azure, tmp_path):  # history incomplete
    stale = incident("i-stale-new", "New", NOW - timedelta(days=120))
    stale_active = incident("i-stale-active", "Active", NOW - timedelta(days=120))
    for i in (stale, stale_active):
        i["properties"]["owner"] = {}
    azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"] += [stale, stale_active]
    code, ev = run("sentinel_incidents", tmp_path)
    # i-new is as old but owned; i-stale-active has been taken up.
    assert ws_a(ev)["open_new_unowned_history_incomplete"] == 1 and ev["summary"]["open_new_unowned_history_incomplete"] == 1


@pytest.mark.parametrize("by", ["", "  ", None, "Incident created from alert", "Alert Grouping", "Playbook - close benign"])
def test_incidents_blank_or_system_modifier_is_not_a_person(azure, tmp_path, by):
    created = NOW - timedelta(days=3)
    _, _, by_name = run_with_history(azure, tmp_path, [
        update("i-closed", created, "New", "High"),
        update("i-closed", created + timedelta(hours=2), "Active", "High", owner="tier1@contoso.com", by=by),
        update("i-closed", created + timedelta(hours=3), "Closed", "High", created + timedelta(hours=3), by=by)])
    assert by_name["i-closed"]["acknowledged_time_utc"] is None


def test_incidents_refused_close_times_are_unknown(azure, tmp_path):
    azure.queries.insert(0, ("arg_max(Order, Status, ClosedTime", Resp(403, {"error": {
        "code": "InsufficientAccessError", "message": "no"}})))
    code, ev = run("sentinel_incidents", tmp_path)
    ws = ws_a(ev)
    closed = next(i for i in ws["incidents"] if i["name"] == "i-closed")
    assert code == 1 and closed["close_time_status"] == "unknown"
    assert ws["closed_missing_close_time"] is None and ws["closed_close_time_not_retained"] is None
    assert ev["summary"]["closed_missing_close_time"] is None


def test_incidents_queries_skip_when_the_list_fails_and_use_explicit_bounds(azure, tmp_path):
    run("sentinel_incidents", tmp_path)
    kql = [c[2] for c in azure.calls if c[0] == "POST" and "SecurityIncident" in c[2]]
    assert kql and all("TimeGenerated > datetime(" in q and "ago(" not in q for q in kql)
    azure.calls.clear()
    azure.arm[(f"{SI_A}/incidents", "2025-09-01")] = Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
    code, ev = run("sentinel_incidents", tmp_path)
    # The entities query reads SecurityIncident too.
    assert code == 1 and ws_a(ev)["incidents"] is None
    assert not any(c[0] == "POST" and "SecurityIncident" in c[2] for c in azure.calls)


def test_incident_with_no_alerts_reads_empty_when_entities_are_skipped(azure, tmp_path):
    azure.queries.insert(0, ("arg_max(Order, Status, ClosedTime", table(
        ["IncidentName", "Status", "ClosedTime", "CreatedTime", "Tasks"], [])))
    azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"][0]["properties"]["additionalData"]["alertsCount"] = 0
    code, ev = run("sentinel_incidents", tmp_path)
    new = next(i for i in ws_a(ev)["incidents"] if i["name"] == "i-new")
    assert (new["alerts_found"], new["entities"]) == (0, [])
    assert not any(c[0] == "POST" and "SystemAlertId" in c[2] for c in azure.calls)


def test_incident_entities_are_capped_per_kind():
    files = [{"$id": str(n), "Type": "file", "Name": f"f{n:02}.dll"} for n in range(30)]
    rows = [{"IncidentName": "x", "AlertId": "a", "Entities": json.dumps(
        files + [{"Type": "host", "HostName": "vm1"}, {"Type": "ip", "Address": "203.0.113.7"}])}]
    out = MODS["sentinel_incidents"].incident_entities(rows)["x"]
    kinds = [e["kind"] for e in out["entities"]]
    assert kinds.count("file") == 25 and "host" in kinds and "ip" in kinds and out["entities_truncated"] is True


def test_incident_entities_query_reads_only_the_incidents_alerts():
    kql = MODS["sentinel_incidents"].ENTITIES_QUERY
    alerts = kql[kql.index("SecurityAlert"):]
    # SecurityAlert is cut to the incidents' alert ids before anything is aggregated or joined.
    assert alerts.index("| where SystemAlertId in (") < alerts.index("summarize") < alerts.index("join")


# The Log Analytics API's answer to a result over 64 MB or 500,000 rows: the rows so far, flagged partial.
RESULT_TOO_LARGE = Resp(200, {"tables": [], "error": {
    "code": "PartialError", "message": "There were some errors when processing your query.",
    "details": [{"code": "EngineError", "innererror": {
        "code": "E_QUERY_RESULT_SET_TOO_LARGE",
        "message": "Query result set has exceeded the internal data size limit 67108864 bytes"}}]}})


def history_posts(azure):
    return [c[2] for c in azure.calls if c[0] == "POST" and HISTORY_ROUTE in c[2]]


def test_incidents_query_too_large_is_read_in_halves_by_incident(azure, tmp_path):
    rows = history_table(incident_history())["tables"][0]["rows"]
    # Every i-closed row hashes to one half and the i-new row to the other.
    azure.queries.insert(0, (HISTORY_ROUTE, [RESULT_TOO_LARGE, table(HISTORY_COLUMNS, rows[:3]),
                                             table(HISTORY_COLUMNS, rows[3:])]))
    code, ev = run("sentinel_incidents", tmp_path)
    closed = next(i for i in ws_a(ev)["incidents"] if i["name"] == "i-closed")
    assert code == 0 and closed["hours_to_acknowledge"] == pytest.approx(12, abs=0.01) and closed["updates_read"] == 3
    whole, *halves = history_posts(azure)
    assert "hash(" not in whole and len(halves) == 2
    assert [q.count("hash(IncidentName)") for q in halves] == [1, 1] and halves[0] != halves[1]


def test_incidents_query_still_too_large_when_split_fails_the_history(azure, tmp_path):
    azure.queries.insert(0, (HISTORY_ROUTE, RESULT_TOO_LARGE))
    code, ev = run("sentinel_incidents", tmp_path)
    # One query at each split down to the most parts, then the history is unknown rather than short.
    assert code == 1 and ws_a(ev)["acknowledged_incidents"] is None
    assert len(history_posts(azure)) == MODS["sentinel_incidents"].MAX_QUERY_PARTS.bit_length()


SECURITY_ALERT_MISSING = Resp(400, {"error": {"code": "BadArgumentError", "innererror": {
    "message": "'join' operator: Failed to resolve table or column expression named 'SecurityAlert'"}}})


def test_incidents_hidden_security_alert_is_refused(azure, tmp_path):
    azure.queries.insert(0, ("SystemAlertId", SECURITY_ALERT_MISSING))
    arm = azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"]
    arm[1]["properties"]["additionalData"]["alertsCount"] = 0
    code, ev = run("sentinel_incidents", tmp_path)
    ws = ws_a(ev)
    by_name = {i["name"]: i for i in ws["incidents"]}
    # i-new has alerts, so SecurityAlert must be there: the query not finding it is table-level access.
    assert code == 1 and json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"
    assert by_name["i-new"]["entities"] is None and not any("SecurityAlert" in n for n in ws["notes"])
    assert by_name["i-closed"]["entities"] == []  # no alerts, so no entities whether or not they could be read


@pytest.mark.parametrize("minutes", [20, 120])
def test_incidents_security_alert_refused_only_once_an_alerted_incident_is_an_hour_old(azure, tmp_path, minutes):
    azure.queries.insert(0, ("SystemAlertId", SECURITY_ALERT_MISSING))
    arm = azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"]
    for i in arm:
        i["properties"]["additionalData"]["alertsCount"] = 0
    arm.append(incident("i-first", "New", NOW - timedelta(minutes=minutes)))
    code, ev = run("sentinel_incidents", tmp_path)
    ws = ws_a(ev)
    if minutes < 60:  # its alerts may not be ingested yet
        assert code == 0 and "under an hour old" in ws["notes"][-1]
    else:
        assert code == 1 and json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


SECURITY_INCIDENT_MISSING = Resp(400, {"error": {"code": "BadArgumentError", "innererror": {
    "message": "'where' operator: Failed to resolve table or column expression named 'SecurityIncident'"}}})


@pytest.mark.parametrize("minutes", [20, 120])
def test_incidents_security_incident_refused_only_once_an_incident_is_an_hour_old(azure, tmp_path, minutes):
    azure.arm[(f"{SI_A}/incidents", "2025-09-01")] = {"value": [incident("i-first", "New", NOW - timedelta(minutes=minutes))]}
    azure.queries.insert(0, ("SecurityIncident", SECURITY_INCIDENT_MISSING))
    code, ev = run("sentinel_incidents", tmp_path)
    ws = ws_a(ev)
    if minutes < 60:  # a brand-new workspace's first incident may not be ingested yet
        assert code == 0 and ws["notes"] == [
            "SecurityIncident table wasn't found, and every incident listed is under an hour old, so may not be ingested yet"]
        assert ws["incidents"][0]["history_complete"] is False and ev["summary"]["acknowledged_incidents"] == 0
    else:
        assert code == 1 and json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"
        assert ws["acknowledged_incidents"] is None


def test_incidents_without_security_alert_and_no_alerts(azure, tmp_path):
    azure.queries.insert(0, ("SystemAlertId", SECURITY_ALERT_MISSING))
    for i in azure.arm[(f"{SI_A}/incidents", "2025-09-01")]["value"]:
        i["properties"]["additionalData"]["alertsCount"] = 0
    code, ev = run("sentinel_incidents", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and "SecurityAlert" in ws["notes"][-1] and all(i["entities"] == [] for i in ws["incidents"])


@pytest.mark.parametrize("url, expected", [
    ("https://user:pw@host.example.com/a?b=c#d", "https://host.example.com"),
    ("https://hooks.slack.com/services/T0/B0/SECRETTOKEN", "https://hooks.slack.com"),
    ("https://app.example.com/login;jsessionid=abc", "https://app.example.com"),
    ("host.example.com/users/@john/x?sig=abc", "host.example.com"),
    ("http://[evil.example/x", None),
    ("http://evil.example\\reset\\TOKEN123", None),
    ("https:\\\\evil.com\\path\\SECRET?sig=x", None),
    ("https://evil.com%2Fpath%3Fsig%3DSECRET", None),
    ("\\\\server\\share\\secret.docx", None),
    ("file:C:\\Users\\bob\\secret.txt", None),
    ("javascript:fetch('x", None),
    ("https://evil.com\\@good.com/", None),
    ("http://[::1]:8080/x", "http://[::1]"),
    ("//evil.com/a", "evil.com"),
    ("host.example.com:8443/x", "host.example.com"),
    ("localhost:8080", "localhost"),
    ("http://a_b.example/x", None),
    ("https://bücher.example/x", None),
    ("tel:5551234", None),
    ("urn:123", None),
    ("mailto:12345", None),
    ("sip:5060", None),
    ("server01:8080/x", "server01"),
    ("intranet:80/path?tok=1", "intranet"),
    ("my-host:8443", "my-host"),
    ("host.example.com:99999/x", None),
    ("https:443", None),
    ("http:8080/x", None),
    ("sips:5061", None),
    ("sms:911", None),
    ("javascript:1", None),
])
def test_incident_url_entities_keep_scheme_and_host_only(url, expected):
    assert MODS["sentinel_incidents"].url_host(url) == expected


def test_incidents_malformed_alert_url_keeps_the_workspace(azure, tmp_path):
    azure.queries.insert(0, ("SystemAlertId", table(["IncidentName", "AlertId", "Entities"], [["i-closed", "a-1", json.dumps([
        {"$id": "1", "Type": "url", "Url": "http://[evil.example/x"}, {"$id": "2", "Type": "ip", "Address": "203.0.113.7"}])]])))
    code, ev = run("sentinel_incidents", tmp_path)
    closed = next(i for i in ws_a(ev)["incidents"] if i["name"] == "i-closed")
    assert code == 0 and closed["entities"] == [{"kind": "ip", "id": "203.0.113.7"}]


@pytest.mark.parametrize("entity, expected", [
    ({"Type": "mailCluster", "ClusterSourceIdentifier": "c-1", "Query": "from:ceo subject:payroll"}, "c-1"),
    ({"Type": "mailCluster", "Query": "from:ceo subject:payroll"}, None),
    ({"Type": "something-new", "Value": "secret-token"}, None),
    ({"Type": "process", "ProcessId": "7", "ImageFile": {"$ref": 3}}, "cmd.exe (7)"),
])
def test_incident_entity_fields_are_allowlisted(entity, expected):
    assert MODS["sentinel_incidents"].entity_id(entity, {"3": {"Type": "file", "Name": "cmd.exe"}}) == expected


def test_incident_state_at_a_past_time():
    state_at = MODS["sentinel_incidents"].state_at
    at = NOW - timedelta(days=10)
    base = {"name": "x", "created_time_utc": iso(NOW - timedelta(days=60)), "status": "Closed", "severity": "Low",
            "owner_user_principal_name": None, "last_modified_time_utc": iso(NOW - timedelta(days=5))}
    assert state_at({**base, "created_time_utc": iso(NOW)}, [], at) is None
    row = dict(zip(HISTORY_COLUMNS, update("x", NOW - timedelta(days=12), "Active", "Medium", owner="pat@contoso.com")))
    assert state_at(base, [row], at) == {"open": True, "severity": "Medium", "owner": "pat@contoso.com"}
    assert state_at({**base, "last_modified_time_utc": iso(NOW - timedelta(days=40))}, [], at)["open"] is False
    later = dict(zip(HISTORY_COLUMNS, update("x", NOW - timedelta(days=5), "Closed", "Low", NOW - timedelta(days=5))))
    # Closed only after `at`; the update's severity and owner are values after it, so unknown at `at`.
    assert state_at(base, [later], at) == {"open": True, "severity": None, "owner": "unknown"}
    later["ClosedTime"] = iso(NOW - timedelta(days=20))
    assert state_at(base, [later], at)["open"] is False


@pytest.mark.parametrize("entity, expected", [
    ({"Type": "account", "UserPrincipalName": "a@contoso.com", "Name": "a"}, "a@contoso.com"),
    ({"Type": "account", "Name": "a", "UPNSuffix": "contoso.com"}, "a@contoso.com"),
    ({"Type": "host", "HostName": "vm1"}, "vm1"),
    ({"Type": "mailbox", "MailboxPrimaryAddress": "m@contoso.com"}, "m@contoso.com"),
    ({"Type": "something-new", "DisplayName": "thing"}, "thing"),
    ({"Type": "ip"}, None),
])
def test_incident_entity_identifiers(entity, expected):
    assert MODS["sentinel_incidents"].entity_id(entity) == expected


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
    # Always scoped: a central destination also holds other workspaces' audit rows.
    assert all(f"_ResourceId =~ '{WS_A}'" in q for q in queried)
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


def assignment(principal, kind, guid, scope, **extra):
    return {"properties": {"principalId": principal, "principalType": kind,
                           "roleDefinitionId": f"{RD}/{guid}", "scope": scope, **extra}}


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
                                                                     "actions": {"Compose": {"type": "Compose", "inputs": "noop"}}}}}

EXTRA_ARM = {
    ("/providers/microsoft.aadiam/diagnosticSettings", "2017-04-01"): {"value": [
        {"name": "to-sentinel", "properties": {"workspaceId": WS_A, "logs": [
            {"category": "AuditLogs", "enabled": True}, {"category": "SignInLogs", "enabled": True},
            {"category": "ProvisioningLogs", "enabled": False}]}},
        {"name": "archive", "properties": {"storageAccountId": f"{SA}/starchive", "logs": [
            {"category": "NonInteractiveUserSignInLogs", "enabled": True}]}}]},
    ("/providers/microsoft.aadiam/diagnosticSettingsCategories", "2017-04-01-preview"): {"value": [
        {"name": n} for n in ("AuditLogs", "SignInLogs", "NonInteractiveUserSignInLogs", "ProvisioningLogs")]},
    (f"{WS_A}/providers/Microsoft.Authorization/roleAssignments", "2022-04-01"): {"value": [
        assignment("u-purger", "User", "purger", WS_A),
        assignment("sp-la", "ServicePrincipal", "lacontrib", f"/subscriptions/{SUB}"),
        assignment("u-reader", "User", "reader", f"/subscriptions/{SUB}"),
        assignment("g-ops", "Group", "nopurge", RG),
        assignment("u-monitor", "User", "moncontrib", RG),
        assignment("g-mg-owners", "Group", "owner", "/providers/Microsoft.Management/managementGroups/mg-root"),
        assignment("u-no-oi", "User", "nooi", f"/subscriptions/{SUB}")]},
    (f"{WS_B}/providers/Microsoft.Authorization/roleAssignments", "2022-04-01"): {"value": []},
    (f"{WS_A}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances", "2020-10-01"): {"value": [
        assignment("u-eligible", "User", "purger", WS_A, status="Provisioned", endDateTime="2027-01-01T00:00:00Z"),
        assignment("u-lapsed", "User", "purger", WS_A, status="Expired")]},
    (f"{WS_B}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances", "2020-10-01"): {"value": []},
    (f"{RD}/purger", "2022-04-01"): role_def("purger", "Data Purger", ["Microsoft.OperationalInsights/workspaces/purge/action"]),
    (f"{RD}/lacontrib", "2022-04-01"): role_def("lacontrib", "Log Analytics Contributor", ["*/read", "Microsoft.OperationalInsights/*"]),
    (f"{RD}/reader", "2022-04-01"): role_def("reader", "Reader", ["*/read"]),
    (f"{RD}/nopurge", "2022-04-01"): role_def("nopurge", "Ops Custom", ["*"], ["Microsoft.OperationalInsights/workspaces/purge/action"]),
    (f"{RD}/moncontrib", "2022-04-01"): role_def("moncontrib", "Monitoring Contributor", [
        "*/read", "Microsoft.OperationalInsights/workspaces/write", "Microsoft.OperationalInsights/workspaces/search/action"]),
    (f"{RD}/owner", "2022-04-01"): role_def("owner", "Owner", ["*"]),
    (f"{RD}/nooi", "2022-04-01"): role_def("nooi", "Everything But Logs", ["*"], ["Microsoft.OperationalInsights/*"]),
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
         "riskLastUpdatedDateTime": iso(NOW - timedelta(days=3))},
        {"id": "u-reader", "userPrincipalName": "reader@contoso.com", "riskLevel": "low", "riskState": "atRisk",
         "riskLastUpdatedDateTime": iso(NOW - timedelta(days=1))}]},
    ("/v1.0/directoryRoles", None): {"value": [
        {"id": "role-ga", "displayName": "Company Admin", "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10"},
        {"id": "role-dr", "displayName": "Directory Readers", "roleTemplateId": "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"}]},
    # More members than $expand would return: the role's member list is paged.
    ("/v1.0/directoryRoles/role-ga/members", None): {
        "value": [{"id": f"u-filler-{i}"} for i in range(20)],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/directoryRoles/role-ga/members?$skiptoken=p2"},
    ("/v1.0/directoryRoles/role-ga/members", None, "p2"): {"value": [{"id": "u-admin"}]},
    ("/v1.0/directoryRoles/role-dr/members", None): {"value": [{"id": "u-reader"}, {"id": "u-admin"}]},
    # v1.0's members list leaves service principals out; only the cast returns them.
    ("/v1.0/directoryRoles/role-ga/members/microsoft.graph.servicePrincipal", None): {"value": [{"id": "sp-deploy"}]},
    ("/v1.0/directoryRoles/role-dr/members/microsoft.graph.servicePrincipal", None): {"value": []},
    ("/v1.0/directoryRoles/role-ga/members/microsoft.graph.group", None): {"value": []},
    ("/v1.0/directoryRoles/role-dr/members/microsoft.graph.group", None): {"value": []},
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


def test_entra_diagnostic_settings_unread_categories_leave_not_exported_unknown(azure, tmp_path):
    azure.arm[("/providers/microsoft.aadiam/diagnosticSettingsCategories", "2017-04-01-preview")] = Resp(
        400, {"Message": "Invalid api-version query string value."})
    code, ev = run("entra_diagnostic_settings", tmp_path)
    s = ev["summary"]
    assert code == 1 and ev["metadata"]["partial_failure"] is True and ev["results"]["categories_available"] is None
    assert s["categories_not_exported"] is None and s["categories_exported"] == 3
    assert s["audit_and_signin_logs_to_sentinel"] is True


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
    # u-reader reads only; u-no-oi's wildcard notActions removes every Log Analytics right; u-lapsed's eligibility expired.
    assert set(grants) == {"u-purger", "sp-la", "g-ops", "u-monitor", "g-mg-owners", "u-eligible"}
    assert grants["u-purger"]["granted"]["purge"]["kind"] == "explicit" and not grants["u-purger"]["can_delete_data"]
    assert grants["sp-la"]["granted"]["purge"]["via"] == "Microsoft.OperationalInsights/*"
    assert grants["sp-la"]["can_delete_data"] and grants["sp-la"]["scope_level"] == "subscription"
    assert grants["g-ops"]["can_purge"] is False and grants["g-ops"]["can_delete_data"] is True
    assert grants["u-purger"]["principal_name"] == "Pat Purger"
    monitor = grants["u-monitor"]
    assert monitor["can_shorten_retention"] and not (monitor["can_purge"] or monitor["can_delete_workspace"])
    assert grants["g-mg-owners"]["scope_level"] == "management_group" and grants["g-mg-owners"]["can_delete_workspace"]
    assert grants["u-eligible"]["assignment_type"] == "eligible" and grants["u-eligible"]["can_purge"]
    assert grants["u-purger"]["assignment_type"] == "active" and grants["u-eligible"]["eligibility_end"]
    assert ws["principals_with_purge"] == 4 and ws["principals_with_explicit_grant"] == 3
    assert ws["principals_eligible_only"] == 1 and ws["eligible_assignments_at_scope"] == 1
    assert ws["principals_who_can_delete_workspace"] == 3 and ws["principals_who_can_shorten_retention"] == 4


def test_deletion_rights_names_are_optional(azure, tmp_path):
    azure.graph_post_response = Resp(403, {"error": {"code": "Authorization_RequestDenied", "message": "no"}})
    code, ev = run("log_analytics_deletion_rights", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and ws["principals_with_deletion_rights"] == 6 and "not resolved" in ws["notes"][0]


def test_log_storage_immutability(azure, tmp_path):
    code, ev = run("log_storage_immutability", tmp_path)
    assert code == 0
    accounts = ev["results"]["accounts"]
    assert [a["account"] for a in accounts] == ["stlogs"]
    by_name = {c["container"]: c for c in accounts[0]["log_containers"]}
    assert set(by_name) == {"insights-logs-auditevent", "insights-activity-logs", "am-securityevent"}
    assert by_name["insights-logs-auditevent"]["locked"] and by_name["insights-logs-auditevent"]["retention_days"] == 365
    # An Unlocked policy can still be deleted, so it doesn't protect.
    assert not by_name["am-securityevent"]["protected"] and by_name["am-securityevent"]["time_based_policy_state"] == "Unlocked"
    assert by_name["insights-activity-logs"]["protected"] is False
    assert accounts[0]["blob_soft_delete_days"] == 14
    assert ev["summary"] == {"storage_accounts_scanned": 3, "accounts_with_log_containers": 1, "log_containers": 3,
                             "locked_policy": 1, "unlocked_policy_only": 1, "legal_hold": 0, "unprotected": 2,
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
    assert s["live_playbooks_without_definition"] == 0 and ev["results"]["notes"] == []


def test_entra_risky_users(azure, tmp_path):
    code, ev = run("entra_risky_users", tmp_path)
    assert code == 0
    users = {u["user_principal_name"]: u for u in ev["results"]["risky_users"]}
    # Global Administrator found by template id past the first 20 members; Directory Readers isn't privileged.
    assert users["admin@contoso.com"]["privileged_roles"] == ["Company Admin"]
    assert users["admin@contoso.com"]["directory_roles"] == ["Company Admin", "Directory Readers"]
    assert users["reader@contoso.com"]["privileged_roles"] == [] and "account_enabled" not in users["reader@contoso.com"]
    assert users["admin@contoso.com"]["account_enabled"] is True and "account_enabled" not in users["staff@contoso.com"]
    s = ev["summary"]
    assert s["risky_users_total"] == 3 and s["by_risk_state"] == {"atRisk": 2, "remediated": 1}
    assert s["privileged_open_risk_users"] == 1 and s["privileged_open_risk_users_enabled"] == 1
    # 20 fillers, the admin and the service principal only the cast returns.
    assert s["privileged_principals"] == 22
    assert s["privileged_role_groups"] == 0 and ev["results"]["privileged_role_groups"] == []


def test_entra_risky_users_counts_groups_holding_a_privileged_role(azure, tmp_path):
    # Members of a role-assignable group hold its roles but aren't expanded, so the summary shows the group.
    azure.arm[("/v1.0/directoryRoles/role-ga/members/microsoft.graph.group", None)] = {"value": [
        {"id": "g-admins", "displayName": "Tier 0 admins"}]}
    azure.arm[("/v1.0/directoryRoles/role-dr/members/microsoft.graph.group", None)] = {"value": [
        {"id": "g-readers", "displayName": "Readers"}]}
    code, ev = run("entra_risky_users", tmp_path)
    s = ev["summary"]
    assert code == 0 and s["privileged_role_groups"] == 1 and s["privileged_principals"] == 23
    assert ev["results"]["privileged_role_groups"] == [
        {"id": "g-admins", "display_name": "Tier 0 admins", "privileged_roles": ["Company Admin"]}]


def test_entra_risky_users_failed_group_read_leaves_privileged_figures_unknown(azure, tmp_path):
    azure.arm[("/v1.0/directoryRoles/role-dr/members/microsoft.graph.group", None)] = Resp(
        403, {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges to complete the operation."}})
    code, ev = run("entra_risky_users", tmp_path)
    s = ev["summary"]
    assert code == 1 and s["privileged_role_groups"] is None and s["privileged_open_risk_users"] is None
    assert ev["results"]["privileged_role_groups"] is None


def test_entra_risky_users_refused_account_read_is_unknown(azure, tmp_path):
    azure.arm[("/v1.0/users/u-admin", None)] = Resp(
        403, {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges to complete the operation."}})
    code, ev = run("entra_risky_users", tmp_path)
    admin = next(u for u in ev["results"]["risky_users"] if u["user_principal_name"] == "admin@contoso.com")
    assert code == 0 and ev["metadata"]["partial_failure"] is False and admin["account_enabled"] is None
    assert ev["summary"]["privileged_open_risk_users_enabled"] == 1


def test_entra_risky_users_other_account_read_errors_fail(azure, tmp_path):
    azure.arm[("/v1.0/users/u-admin", None)] = Resp(400, {"error": {"code": "BadRequest", "message": "bad"}})
    code, ev = run("entra_risky_users", tmp_path)
    assert code == 1 and ev["metadata"]["partial_failure"] is True


def test_entra_risky_users_unread_roles_leave_privileged_figures_unknown(azure, tmp_path):
    azure.arm[("/v1.0/directoryRoles", None)] = Resp(
        403, {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges to complete the operation."}})
    code, ev = run("entra_risky_users", tmp_path)
    s = ev["summary"]
    assert code == 1 and ev["metadata"]["partial_failure"] is True and s["open_risk_users"] == 2
    assert s["privileged_open_risk_users"] is None and s["privileged_open_risk_users_enabled"] is None
    assert s["privileged_principals"] is None
    assert all(u["privileged_roles"] is None and "account_enabled" not in u for u in ev["results"]["risky_users"])


def test_entra_risky_users_failed_service_principal_read_leaves_privileged_figures_unknown(azure, tmp_path):
    azure.arm[("/v1.0/directoryRoles/role-ga/members/microsoft.graph.servicePrincipal", None)] = Resp(
        403, {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges to complete the operation."}})
    code, ev = run("entra_risky_users", tmp_path)
    assert code == 1 and ev["summary"]["privileged_principals"] is None


def test_entra_risky_users_without_p2_is_a_state(azure, tmp_path):
    azure.arm[("/v1.0/identityProtection/riskyUsers", None)] = Resp(
        403, {"error": {"code": "Forbidden", "message": "Your tenant is not licensed for this feature."}})
    code, ev = run("entra_risky_users", tmp_path)
    assert code == 0 and ev["summary"] == {"identity_protection_available": False}


def test_entra_diagnostic_settings_unreadable_destination_is_unknown(azure, tmp_path):
    other = "/subscriptions/other/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law-elsewhere"
    azure.arm[("/providers/microsoft.aadiam/diagnosticSettings", "2017-04-01")]["value"].append(
        {"name": "elsewhere", "properties": {"workspaceId": other, "logs": [{"category": "ProvisioningLogs", "enabled": True}]}})
    azure.arm[(f"{other}/providers/Microsoft.SecurityInsights/onboardingStates", "2025-09-01")] = Resp(
        403, {"error": {"code": "AuthorizationFailed", "message": "no access"}})
    code, ev = run("entra_diagnostic_settings", tmp_path)
    coverage = {c["category"]: c for c in ev["results"]["category_coverage"]}
    assert code == 0 and coverage["ProvisioningLogs"]["to_sentinel_workspace"] is None
    assert coverage["AuditLogs"]["to_sentinel_workspace"] is True and ev["summary"]["audit_and_signin_logs_to_sentinel"] is True
    assert "1 destination workspace" in ev["results"]["notes"][0]


def test_entra_key_category_only_to_an_unreadable_workspace_is_unknown(azure, tmp_path):
    settings = azure.arm[("/providers/microsoft.aadiam/diagnosticSettings", "2017-04-01")]["value"]
    other = "/subscriptions/other/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law-elsewhere"
    settings[0]["properties"]["workspaceId"] = other
    azure.arm[(f"{other}/providers/Microsoft.SecurityInsights/onboardingStates", "2025-09-01")] = Resp(
        404, {"error": {"code": "SubscriptionNotFound", "message": "not in this tenant"}})
    code, ev = run("entra_diagnostic_settings", tmp_path)
    assert code == 0 and ev["summary"]["key_categories_to_sentinel"] == {"AuditLogs": None, "SignInLogs": None}
    assert ev["summary"]["audit_and_signin_logs_to_sentinel"] is None


def test_deletion_rights_without_pim_is_a_note(azure, tmp_path):
    azure.arm[(f"{WS_A}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances", "2020-10-01")] = Resp(
        400, {"error": {"code": "AadPremiumLicenseRequired", "message": "The tenant needs an AAD Premium P2 license."}})
    code, ev = run("log_analytics_deletion_rights", tmp_path)
    ws = ws_a(ev)
    assert code == 0 and ws["eligible_assignments_at_scope"] == 0
    assert any("PIM-eligible assignments not read" in n for n in ws["notes"])


def test_log_storage_account_default_version_policy(azure, tmp_path):
    azure.arm[(f"/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts", "2023-05-01")]["value"].append(
        {"id": f"{SA}/stworm", "name": "stworm", "kind": "StorageV2", "properties": {"immutableStorageWithVersioning": {
            "enabled": True, "immutabilityPolicy": {"state": "Locked", "immutabilityPeriodSinceCreationInDays": 180}}}})
    azure.arm[(f"{SA}/stworm/blobServices/default/containers", "2023-05-01")] = {"value": [
        container("insights-logs-signinlogs"),
        container("insights-logs-auditlogs", {"state": "Unlocked", "immutabilityPeriodSinceCreationInDays": 7})]}
    azure.arm[(f"{SA}/stworm/blobServices/default", "2023-05-01")] = {"properties": {}}
    code, ev = run("log_storage_immutability", tmp_path)
    worm = next(a for a in ev["results"]["accounts"] if a["account"] == "stworm")
    by_name = {c["container"]: c for c in worm["log_containers"]}
    inherited = by_name["insights-logs-signinlogs"]
    assert code == 0 and inherited["protected"] and inherited["policy_source"] == "account_default"
    assert inherited["retention_days"] == 180 and inherited["version_level_immutability"]
    # The container's own Unlocked policy overrides the account default, and doesn't protect.
    assert by_name["insights-logs-auditlogs"]["policy_source"] == "container"
    assert not by_name["insights-logs-auditlogs"]["protected"]


STD = f"{RG}/providers/Microsoft.Web/sites/la-std/workflows/contain"


OTHER_SUB_PB = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/rg-soc/providers/Microsoft.Logic/workflows/contain"


def _rule_runs(azure, playbook_id):
    rules = azure.arm[(f"{SI_A}/automationRules", "2025-09-01")]["value"]
    rules[0]["properties"]["actions"].append(
        {"order": 2, "actionType": "RunPlaybook", "actionConfiguration": {"logicAppResourceId": playbook_id}})


def _run_standard_playbook(azure, envelope):
    _rule_runs(azure, STD)
    azure.arm[(STD, "2024-04-01")] = envelope


def test_sentinel_playbooks_standard_workflow(azure, tmp_path):
    _run_standard_playbook(azure, {"id": STD, "name": "la-std/contain", "properties": {
        "flowState": "Enabled", "files": {"workflow.json": {"kind": "Stateful", "definition": {
            "triggers": {"incident": {"type": "ApiConnectionWebhook", "inputs": {
                "host": {"connection": {"referenceName": "azuresentinel"}}, "path": "/incident-creation"}}},
            "actions": {"Disable_user": {"type": "ApiConnection", "inputs": {
                "host": {"connection": {"referenceName": "azuread"}}, "method": "patch",
                "path": "/v1.0/users/x", "body": {"accountEnabled": False}}}}}}}}})
    code, ev = run("sentinel_playbooks", tmp_path)
    std = next(p for p in ev["results"]["playbooks"] if p["id"] == STD)
    assert code == 0 and std["plan"] == "standard" and std["definition_read"] and std["enabled"]
    assert std["triggers"][0]["kind"] == "incident" and std["capabilities"]["account_containment"]
    assert ("GET", STD, "2024-04-01") in azure.calls and ev["summary"]["standard_playbooks"] == 1


def test_sentinel_playbooks_standard_workflow_without_definition(azure, tmp_path):
    _run_standard_playbook(azure, {"id": STD, "name": "la-std/contain", "properties": {"flowState": "Enabled"}})
    code, ev = run("sentinel_playbooks", tmp_path)
    std = next(p for p in ev["results"]["playbooks"] if p["id"] == STD)
    s = ev["summary"]
    assert code == 0 and s["playbooks_without_definition"] == [STD]
    assert std["definition_read"] is False and std["capabilities"] is None and std["email_recipients"] is None
    # It is live, so the counts it could change read unknown rather than leaving it out.
    assert s["run_by_active_automation_rule"] == 2 and s["live_playbooks_without_definition"] == 1
    assert s["live_account_containment_playbooks"] is None and s["live_notifying_playbooks"] is None
    assert s["notification_recipients"] is None


@pytest.mark.parametrize("status, error", [
    (401, "InvalidAuthenticationToken"), (403, "AuthorizationFailed"), (404, "ResourceNotFound"), (404, "SubscriptionNotFound")])
def test_sentinel_playbooks_unreadable_playbook_is_unresolved(azure, tmp_path, status, error):
    _rule_runs(azure, OTHER_SUB_PB)
    azure.arm[(OTHER_SUB_PB, "2019-05-01")] = Resp(status, {"error": {"code": error, "message": "no"}})
    code, ev = run("sentinel_playbooks", tmp_path)
    s = ev["summary"]
    assert code == 0 and ev["metadata"]["partial_failure"] is False
    assert s["automation_rule_references_unresolved"] == [OTHER_SUB_PB.lower()]
    assert OTHER_SUB_PB in ev["results"]["notes"][0] and s["run_by_active_automation_rule"] == 1


def test_sentinel_playbooks_other_playbook_read_errors_fail(azure, tmp_path):
    _rule_runs(azure, OTHER_SUB_PB)
    azure.arm[(OTHER_SUB_PB, "2019-05-01")] = Resp(400, {"error": {"code": "BadRequest", "message": "bad"}})
    code, ev = run("sentinel_playbooks", tmp_path)
    assert code == 1 and ev["metadata"]["partial_failure"] is True and ev["results"]["notes"] == []
    assert ev["summary"]["automation_rule_references_unresolved"] == [OTHER_SUB_PB.lower()]


def test_throttling_is_retried_after_retry_after(azure, tmp_path):
    body = azure.arm[(f"{SI_A}/automationRules", "2025-09-01")]
    azure.arm[(f"{SI_A}/automationRules", "2025-09-01")] = [
        Resp(429, {"error": {"code": "TooManyRequests", "message": "slow down"}}, {"Retry-After": "7"}),
        Resp(503, {"error": {"code": "ServiceUnavailable", "message": "busy"}}),
        body]
    code, ev = run("sentinel_automation_rules", tmp_path)
    assert code == 0 and ws_a(ev)["active_rules"] == 1
    assert azure.sleeps == [7.0, 2.0]


def test_query_throttling_is_retried(azure, tmp_path):
    first = azure.queries[0]
    azure.queries[0] = (first[0], [Resp(429, {"error": {"code": "Throttled", "message": "x"}}, {"Retry-After": "3"}), first[1]])
    code, ev = run("sentinel_data_sources", tmp_path)
    assert code == 0 and ws_a(ev)["sources_ingesting"] == 2 and azure.sleeps == [3.0]


def test_persistent_server_errors_give_up_and_fail(azure, tmp_path):
    azure.arm[(f"{SI_A}/automationRules", "2025-09-01")] = Resp(500, {"error": {"code": "InternalServerError", "message": "x"}})
    code, ev = run("sentinel_automation_rules", tmp_path)
    assert code == 1 and len(azure.sleeps) == azure_rest.MAX_RETRIES


def test_dotenv_in_a_parent_folder_is_not_read(azure, tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("SENTINEL_WORKSPACES=law-typo\n")
    child = tmp_path / "client"
    child.mkdir()
    monkeypatch.chdir(child)
    try:
        code, ev = run("sentinel_automation_rules", tmp_path)
    finally:
        os.environ.pop("SENTINEL_WORKSPACES", None)
    assert code == 0 and ev["results"]["workspace_filter"] is None


def test_retry_wait_reads_the_service_hint():
    wait = azure_rest.retry_wait
    assert wait(Resp(429, {}, {"x-ms-retry-after-ms": "1500"}), 0) == 1.5
    assert wait(Resp(429, {}, {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}), 0) == 0.0
    assert wait(Resp(429, {}, {"Retry-After": "9999"}), 0) == azure_rest.MAX_RETRY_WAIT
    assert wait(Resp(503, {}), 3) == 8.0
