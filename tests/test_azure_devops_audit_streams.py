"""azure_devops_audit_streams, driven without Azure DevOps or Azure.

FakeDevOps stands in for the shared Azure DevOps client and FakeLogs for the
Log Analytics session behind azure_rest. Bodies follow the Audit 7.1-preview.1
REST reference, including the shapes its samples show besides the usual one: a
bare stream object, integer statuses, /Date(ms)/ times and a "value"-wrapped
audit-log page.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_DIR = REPO_ROOT / "fetchers" / "azure" / "devops_audit_streams"

_spec = importlib.util.spec_from_file_location("azure_devops_audit_streams_under_test", FETCHER_DIR / "fetcher.py")
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)
azure_common = sys.modules["azure_common"]
azure_rest = sys.modules["azure_rest"]
devops_rest = sys.modules["devops_rest"]

ORG = "contoso"
SCOPE = "73638cd5-0dda-4128-9fd6-48c16d4e4de3"
SUB = "00000000-0000-0000-0000-000000000001"
WS = f"/subscriptions/{SUB}/resourceGroups/rg-logs/providers/Microsoft.OperationalInsights/workspaces/law-ado"
WS_GUID = "5b7a0f1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b"
NOW = datetime.now(timezone.utc)
SPLUNK_TOKEN = "11111111-2222-3333-4444-555555555555"
GRID_KEY = "c2VjcmV0LWtleS1kby1ub3Qtd3JpdGU="
LAW_KEY = "bGF3LXNoYXJlZC1rZXktZG8tbm90LXdyaXRl"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def entry(action, when, area="Project", scope_type="organization", scope_id=SCOPE):
    name = f"{ORG} (Organization)" if scope_type == "organization" else "Payments (Project)"
    return {"id": f"{action}-{when.timestamp()}", "actionId": action, "area": area, "category": "modify",
            "timestamp": iso(when), "scopeType": scope_type, "scopeId": scope_id, "scopeDisplayName": name}


PROJECT_SCOPE = "9f1c2d3e-4b5a-6978-8a9b-0c1d2e3f4a5b"
SCOPED_COLUMNS = ["ScopeId", "ScopeDisplayName", "ScopeType", "Rows", "LastEvent"]


def page(entries, token=None, has_more=False):
    return {"decoratedAuditLogEntries": entries, "continuationToken": token, "hasMore": has_more}


def streams_body():
    return {"count": 3, "value": [
        {"id": 1, "consumerType": "Splunk", "displayName": "https://splunk.contoso.com:8088",
         "consumerInputs": {"SplunkUrl": "https://splunk.contoso.com:8088",
                            "SplunkEventCollectorToken": SPLUNK_TOKEN},
         "status": "disabledBySystem", "statusReason": "Invalid credentials",
         "createdTime": "2026-01-02T03:04:05.1234567Z", "updatedTime": "2026-09-30T10:00:00Z"},
        {"id": 2, "consumerType": "AzureMonitorLogs", "displayName": "law-ado",
         "consumerInputs": {"ResourceId": WS, "TenantId": "tenant-guid", "SharedKey": LAW_KEY},
         "status": 1, "statusReason": None, "createdTime": "2026-01-02T03:04:05Z",
         "updatedTime": "/Date(1565715592526)/"},
        {"id": 3, "consumerType": "AzureEventGrid", "displayName": "grid",
         "consumerInputs": {"EventGridTopicHostname": "https://topic.eastus-1.eventgrid.azure.net/api/events?code=x",
                            "EventGridTopicAccessKey": GRID_KEY},
         "status": "Enabled", "createdTime": "2026-01-02T03:04:05Z", "updatedTime": "2026-01-02T03:04:05Z"},
    ]}


def ado_error(status, message="error"):
    return devops_rest.DevOpsError(status, "Error", message)


class FakeDevOps:
    """The shared client's get(path, api_version, params, service), routed by path."""

    org = ORG

    def __init__(self):
        self.routes = {
            "_apis/OrganizationPolicy/Policies/Policy.LogAuditEvents": {"name": "Policy.LogAuditEvents",
                                                                       "value": True, "effectiveValue": True},
            "_apis/audit/streams": streams_body(),
            "_apis/audit/auditlog": [page([
                entry("AuditLog.AccessLog", NOW - timedelta(minutes=1), area="Auditing"),
                entry("Git.RepositoryCreated", NOW - timedelta(minutes=20)),
                entry("Project.CreateCompleted", NOW - timedelta(days=2)),
            ])],
        }
        self.calls = []

    def get(self, path, api_version, params=None, service=None):
        self.calls.append((path, api_version, dict(params or {}), service))
        body = self.routes[path]
        if isinstance(body, list):  # answered in turn, the last one repeating
            body = body.pop(0) if len(body) > 1 else body[0]
        if isinstance(body, Exception):
            raise body
        return body


class Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body
        self.reason = "OK" if status < 400 else "Error"
        self.text = json.dumps(body)
        self.headers = {}

    def json(self):
        return self._body


def table(columns, rows):
    return {"tables": [{"name": "PrimaryResult", "columns": [{"name": c, "type": "string"} for c in columns],
                        "rows": rows}]}


class FakeLogs:
    """The requests.Session behind AzureRestClient: the workspace GET and AzureDevOpsAuditing queries."""

    def __init__(self):
        self.workspaces = {WS: {"id": WS, "properties": {"customerId": "cust-ado"}}}
        self.query = Resp(200, table(["ScopeId", "ScopeDisplayName", "Rows", "LastEvent"], [
            [SCOPE, f"{ORG} (Organization)", 42, iso(NOW - timedelta(minutes=30))],
            ["other-scope", "fabrikam (Organization)", 7, iso(NOW - timedelta(hours=3))],
        ]))
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        path = url.split("management.azure.com", 1)[-1]
        self.calls.append(("GET", path))
        if path in self.workspaces:
            return Resp(200, self.workspaces[path])
        return Resp(404, {"error": {"code": "ResourceNotFound", "message": path}})

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append(("POST", url, json["query"]))
        return self.query


class FakeCred:
    def get_token(self, scope):
        return namedtuple("T", "token expires_on")("tok", 9_999_999_999)


@pytest.fixture
def fakes(monkeypatch):
    devops, logs, subs = FakeDevOps(), FakeLogs(), []

    def client(sub):
        subs.append(sub)
        return azure_rest.AzureRestClient(FakeCred(), logs)

    monkeypatch.setattr(mod, "azure_client", client)
    monkeypatch.setattr(azure_rest.time, "sleep", lambda s: None)
    monkeypatch.delenv(mod.WINDOW_ENV, raising=False)
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    return devops, logs, subs


def run(devops):
    collector = azure_common.Collector(logging.getLogger("test"))
    results, summary = mod.collect(devops, collector)
    return results, summary, collector


def stream(results, sid):
    return next(s for s in results["streams"] if s["id"] == sid)


# --- shape ----------------------------------------------------------------------

def test_fetcher_yaml_follows_the_shape():
    spec = yaml.safe_load((FETCHER_DIR / "fetcher.yaml").read_text())
    assert spec["name"] == mod.NAME == "azure_devops_audit_streams"
    assert spec["category"] == "azure" and spec["version"] == "0.1.0"
    assert spec["evidence_set"]["reference_id"] == "EVD-AZURE-DEVOPS-AUDIT-STREAMS"
    assert len(spec["evidence_set"]["instructions"].split()) <= 80
    assert spec["config_schema"]["audit_window_days"]["env"] == mod.WINDOW_ENV
    assert spec["config_schema"]["audit_window_days"]["default"] == mod.DEFAULT_WINDOW_DAYS
    assert spec["output"]["aggregation"] == "per_target"
    assert [s["env"] for s in spec["secrets"]] == ["AZURE_DEVOPS_PAT"] and spec["secrets"][0]["per_target"]


# --- transforms -----------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    (1, "enabled"), (3, "disabledBySystem"), (5, "backfilling"), ("2", "disabledByUser"),
    ("Enabled", "enabled"), ("disabledbyuser", "disabledByUser"), (None, "unknown"), (9, "9"), ("paused", "paused"),
])
def test_stream_status(raw, expected):
    assert mod.stream_status(raw) == expected


def test_times_take_the_legacy_form_and_seven_digits():
    assert mod.ado_time("/Date(1565715592526)/") == "2019-08-13T16:59:52Z"
    assert mod.ado_time("2026-01-02T03:04:05.1234567Z") == "2026-01-02T03:04:05Z"
    assert mod.ado_time("2026-01-02T05:04:05+02:00") == "2026-01-02T03:04:05Z"
    assert mod.ado_time(None) is None and mod.ado_time("soon") == "soon"


def test_destination_keeps_identifiers_and_drops_credentials():
    dest = mod.destination({
        "SplunkUrl": "https://user:pw@splunk.contoso.com:8088/services?token=abc#x",
        "SplunkEventCollectorToken": SPLUNK_TOKEN,
        "EventGridTopicAccessKey": GRID_KEY,
        "WorkspaceId": WS_GUID,
        "SharedKey": LAW_KEY,
        "ConnectionString": "Endpoint=sb://x;SharedAccessKey=y",
        "TenantId": "tenant-guid",
        "WorkspaceResourceId": "************",
        "Unrelated": "value",
    })
    assert dest == {"SplunkUrl": "https://splunk.contoso.com:8088/services", "TenantId": "tenant-guid",
                    "WorkspaceId": WS_GUID}
    assert mod.destination(None) == {} and mod.destination(["x"]) == {}


def test_workspace_ref_prefers_the_resource_id():
    assert mod.workspace_ref({"ResourceId": WS + "/", "WorkspaceId": WS_GUID}) == {"resource_id": WS}
    assert mod.workspace_ref({"WorkspaceId": WS_GUID.upper()}) == {"customer_id": WS_GUID}
    assert mod.workspace_ref({"WorkspaceId": "law-ado", "TenantId": WS_GUID}) is None


@pytest.mark.parametrize("body, ids", [
    ({"count": 2, "value": [{"id": 1}, {"id": 2}]}, [1, 2]),
    ([{"id": 1}], [1]),
    ({"id": 1, "consumerType": "Splunk", "status": 1}, [1]),
    ({"count": 0, "value": []}, []),
    ({}, []),
    (None, []),
])
def test_stream_items_reads_every_documented_shape(body, ids):
    assert [s["id"] for s in mod.stream_items(body)] == ids


@pytest.mark.parametrize("body, expected", [
    ({"value": True}, True), ({"effectiveValue": False, "value": True}, False), ({"value": "false"}, False),
    ({"Value": "True"}, None), ({"value": None}, None), ([], None),
])
def test_policy_value(body, expected):
    assert mod.policy_value(body) is expected


def test_stream_record_maps_status_target_and_times():
    record = mod.stream_record(streams_body()["value"][1])
    assert record["target_type"] == "Azure Monitor Logs" and record["status"] == "enabled"
    assert record["delivering"] is True and record["updated_time"] == "2019-08-13T16:59:52Z"
    assert record["destination"] == {"ResourceId": WS, "TenantId": "tenant-guid"}


# --- the audit log --------------------------------------------------------------

def test_newest_event_ignores_reads_of_the_log(fakes):
    devops, _, _ = fakes
    log = mod.newest_events(devops, NOW)
    assert log["newest_event"]["action_id"] == "Git.RepositoryCreated"
    assert log["newest_event_older_than_1h"]["action_id"] == "Project.CreateCompleted"
    assert log["organization_scope_id"] == SCOPE and log["complete"] is True
    path, api, params, service = devops.calls[0]
    assert (path, api, service) == ("_apis/audit/auditlog", "7.1-preview.1", "auditservice")
    assert params["batchSize"] == "200" and params["startTime"] < params["endTime"]


def test_newest_event_pages_until_one_old_enough_to_stream(fakes):
    devops, _, _ = fakes
    devops.routes["_apis/audit/auditlog"] = [
        {"value": page([entry("Git.RepositoryCreated", NOW - timedelta(minutes=5))], token="t2", has_more=True)},
        page([entry("Library.AgentAdded", NOW - timedelta(days=3))], token="t3", has_more=True),
        page([entry("Project.CreateCompleted", NOW - timedelta(days=4))]),
    ]
    log = mod.newest_events(devops, NOW)
    assert log["newest_event"]["action_id"] == "Git.RepositoryCreated"
    assert log["newest_event_older_than_1h"]["action_id"] == "Library.AgentAdded"
    assert [c[2].get("continuationToken") for c in devops.calls] == [None, "t2"]


def test_an_oldest_first_page_does_not_stop_the_search(fakes):
    devops, _, _ = fakes
    devops.routes["_apis/audit/auditlog"] = [
        page([entry("Project.CreateCompleted", NOW - timedelta(days=4)),
              entry("Library.AgentAdded", NOW - timedelta(days=3))], token="t2", has_more=True),
        page([entry("Git.RepositoryCreated", NOW - timedelta(days=1))]),
    ]
    log = mod.newest_events(devops, NOW)
    assert log["newest_event_older_than_1h"]["action_id"] == "Git.RepositoryCreated"
    assert len(devops.calls) == 2


def test_a_project_event_does_not_set_the_organization_scope(fakes):
    devops, _, _ = fakes
    devops.routes["_apis/audit/auditlog"] = [page([
        entry("Git.RefUpdatePoliciesBypassed", NOW - timedelta(hours=2), scope_type="project", scope_id=PROJECT_SCOPE),
        entry("Policy.PolicyValueUpdated", NOW - timedelta(hours=3)),
    ])]
    log = mod.newest_events(devops, NOW)
    assert log["organization_scope_id"] == SCOPE
    assert log["newest_event_older_than_1h"]["action_id"] == "Git.RefUpdatePoliciesBypassed"
    assert log["newest_organization_event_older_than_1h"]["action_id"] == "Policy.PolicyValueUpdated"


def test_an_entry_without_a_scope_type_counts_as_the_organization(fakes):
    devops, _, _ = fakes
    bare = {k: v for k, v in entry("Project.CreateCompleted", NOW - timedelta(days=2)).items() if k != "scopeType"}
    devops.routes["_apis/audit/auditlog"] = [page([bare])]
    log = mod.newest_events(devops, NOW)
    assert log["organization_scope_id"] == SCOPE
    assert log["newest_organization_event_older_than_1h"]["action_id"] == "Project.CreateCompleted"


def test_the_page_cap_marks_the_search_incomplete(fakes):
    devops, _, _ = fakes
    devops.routes["_apis/audit/auditlog"] = [page([entry("AuditLog.AccessLog", NOW, area="Auditing")],
                                                  token="t", has_more=True)]
    log = mod.newest_events(devops, NOW)
    assert log["complete"] is False and log["newest_event"] is None
    assert len(devops.calls) == mod.MAX_AUDIT_PAGES


# --- collect() ------------------------------------------------------------------

def test_collect_reports_streams_and_ingestion(fakes):
    devops, logs, subs = fakes
    results, summary, collector = run(devops)
    assert collector.ok and results["notes"] == []
    assert results["auditing"] == {"enabled": True, "source": "Policy.LogAuditEvents", "log_audit_events_policy": True}
    assert [s["target_type"] for s in results["streams"]] == ["Azure Event Grid", "Azure Monitor Logs", "Splunk"]

    splunk = stream(results, 1)
    assert splunk["status"] == "disabledBySystem" and splunk["status_reason"] == "Invalid credentials"
    assert splunk["delivering"] is False and "ingestion" not in splunk
    grid = stream(results, 3)
    assert grid["destination"] == {"EventGridTopicHostname": "https://topic.eastus-1.eventgrid.azure.net/api/events"}

    ingestion = stream(results, 2)["ingestion"]
    assert ingestion["workspace_customer_id"] == "cust-ado" and ingestion["workspace_resource_id"] == WS
    assert ingestion["rows_in_window"] == 42 and ingestion["received_rows"] is True
    assert ingestion["other_organizations"] == ["fabrikam (Organization)"]
    assert ingestion["rows_expected"] is True and ingestion["missing_rows"] is False
    assert subs == [SUB]
    query = next(c for c in logs.calls if c[0] == "POST")
    assert "/v1/workspaces/cust-ado/query" in query[1] and query[2].startswith("AzureDevOpsAuditing")
    assert "ago(7d)" in query[2]

    assert summary == {
        "auditing_enabled": True,
        "streams": 3,
        "streams_delivering": 2,
        "streams_not_delivering": ["https://splunk.contoso.com:8088"],
        "streams_by_target": {"Azure Event Grid": 1, "Azure Monitor Logs": 1, "Splunk": 1},
        "azure_monitor_streams_with_rows": 1,
        "azure_monitor_streams_missing_rows": 0,
        "newest_audit_event": results["audit_log"]["newest_event"]["timestamp"],
    }


def test_no_stream_credential_reaches_the_evidence(fakes):
    devops, _, _ = fakes
    results, summary, _ = run(devops)
    written = json.dumps({"results": results, "summary": summary})
    for secret in (SPLUNK_TOKEN, GRID_KEY, LAW_KEY, "code=x", "consumerInputs", "SharedKey"):
        assert secret not in written


def test_an_enabled_stream_that_delivers_nothing_is_visible(fakes):
    devops, logs, _ = fakes
    logs.query = Resp(200, table(["ScopeId", "ScopeDisplayName", "Rows", "LastEvent"],
                                 [["other-scope", "fabrikam (Organization)", 7, iso(NOW)]]))
    results, summary, collector = run(devops)
    ingestion = stream(results, 2)["ingestion"]
    assert collector.ok and ingestion["received_rows"] is False and ingestion["missing_rows"] is True
    assert summary["azure_monitor_streams_missing_rows"] == 1


def test_no_rows_is_not_missing_when_nothing_happened_in_the_window(fakes):
    devops, logs, _ = fakes
    devops.routes["_apis/audit/auditlog"] = [page([entry("Project.CreateCompleted", NOW - timedelta(days=30))])]
    logs.query = Resp(200, table(["ScopeId", "ScopeDisplayName", "Rows", "LastEvent"], []))
    results, summary, _ = run(devops)
    ingestion = stream(results, 2)["ingestion"]
    assert ingestion["rows_expected"] is False and ingestion["missing_rows"] is False
    assert summary["azure_monitor_streams_missing_rows"] == 0


def test_project_rows_are_not_other_organizations(fakes):
    devops, logs, _ = fakes
    logs.query = Resp(200, table(SCOPED_COLUMNS, [
        [SCOPE, f"{ORG} (Organization)", "Organization", 40, iso(NOW - timedelta(hours=3))],
        [PROJECT_SCOPE, "Payments (Project)", "Project", 25, iso(NOW - timedelta(hours=2))],
        ["other-scope", "fabrikam (Organization)", "Organization", 7, iso(NOW - timedelta(hours=3))],
    ]))
    results, _, collector = run(devops)
    ingestion = stream(results, 2)["ingestion"]
    assert collector.ok and ingestion["rows_in_window"] == 40 and ingestion["received_rows"] is True
    assert ingestion["other_organizations"] == ["fabrikam (Organization)"]
    assert ingestion["project_rows_unattributed"] == 25
    query = next(c for c in logs.calls if c[0] == "POST")[2]
    assert "column_ifexists('ScopeType', '')" in query and query.rstrip().endswith("ScopeDisplayName, ScopeType")


def test_only_project_activity_does_not_make_organization_rows_expected(fakes):
    devops, logs, _ = fakes
    devops.routes["_apis/audit/auditlog"] = [page([
        entry("Git.RefUpdatePoliciesBypassed", NOW - timedelta(hours=2), scope_type="project", scope_id=PROJECT_SCOPE),
    ])]
    logs.query = Resp(200, table(SCOPED_COLUMNS, [
        [PROJECT_SCOPE, "Payments (Project)", "Project", 25, iso(NOW - timedelta(hours=2))],
    ]))
    results, summary, _ = run(devops)
    ingestion = stream(results, 2)["ingestion"]
    assert ingestion["rows_expected"] is False and ingestion["missing_rows"] is False
    assert ingestion["other_organizations"] == [] and summary["azure_monitor_streams_missing_rows"] == 0


def test_a_stream_newer_than_the_last_event_expects_no_rows(fakes):
    devops, logs, _ = fakes
    body = streams_body()["value"][1]
    devops.routes["_apis/audit/streams"] = {"value": [{**body, "createdTime": iso(NOW - timedelta(days=1))}]}
    logs.query = Resp(200, table(["ScopeId", "ScopeDisplayName", "Rows", "LastEvent"], []))
    results, summary, _ = run(devops)
    ingestion = stream(results, 2)["ingestion"]
    assert ingestion["rows_expected"] is False and ingestion["missing_rows"] is False
    assert summary["azure_monitor_streams_missing_rows"] == 0


def test_a_missing_table_reads_as_no_rows(fakes):
    devops, logs, _ = fakes
    logs.query = Resp(400, {"error": {"code": "BadArgumentError", "message": "query failed", "innererror": {
        "message": "'where' operator: Failed to resolve table or column expression named 'AzureDevOpsAuditing'"}}})
    results, _, collector = run(devops)
    ingestion = stream(results, 2)["ingestion"]
    assert collector.ok and ingestion["received_rows"] is False and ingestion["missing_rows"] is True
    assert ingestion["notes"] == ["AzureDevOpsAuditing table does not exist in the workspace"]


def test_a_refused_workspace_query_fails_the_run(fakes):
    devops, logs, _ = fakes
    logs.query = Resp(403, {"error": {"code": "InsufficientAccessError", "message": "no access"}})
    results, summary, collector = run(devops)
    assert not collector.ok and "AzureDevOpsAuditing" in collector.failures[0]["operation"]
    assert stream(results, 2)["ingestion"] is None
    assert summary["azure_monitor_streams_with_rows"] == 0


def test_a_workspace_id_only_stream_queries_it_directly(fakes):
    devops, logs, subs = fakes
    devops.routes["_apis/audit/streams"] = [{"id": 7, "consumerType": "AzureMonitorLogs", "status": 1,
                                            "consumerInputs": {"WorkspaceId": WS_GUID, "SharedKey": LAW_KEY}}]
    results, _, collector = run(devops)
    assert collector.ok and subs == [None]
    assert [c[0] for c in logs.calls] == ["POST"] and f"/workspaces/{WS_GUID}/query" in logs.calls[0][1]
    assert stream(results, 7)["ingestion"]["workspace_resource_id"] is None


def test_streams_to_one_workspace_query_it_once(fakes):
    devops, logs, _ = fakes
    body = streams_body()["value"][1]
    devops.routes["_apis/audit/streams"] = {"value": [body, {**body, "id": 4, "status": "disabledByUser"}]}
    results, _, _ = run(devops)
    assert sum(1 for c in logs.calls if c[0] == "POST") == 1
    assert stream(results, 4)["ingestion"]["received_rows"] is True
    assert stream(results, 4)["ingestion"]["missing_rows"] is False


def test_a_stream_naming_no_workspace_is_a_note(fakes):
    devops, logs, _ = fakes
    devops.routes["_apis/audit/streams"] = [{"id": 8, "consumerType": "AzureMonitorLogs", "status": 1,
                                            "consumerInputs": {"SharedKey": LAW_KEY}}]
    results, _, collector = run(devops)
    assert collector.ok and logs.calls == [] and stream(results, 8)["ingestion"] is None
    assert results["notes"] == ["stream 8 names no workspace in its inputs; ingestion not checked"]


def test_an_unreadable_policy_falls_back_to_the_audit_log(fakes):
    devops, _, _ = fakes
    devops.routes["_apis/OrganizationPolicy/Policies/Policy.LogAuditEvents"] = ado_error(403, "forbidden")
    results, summary, collector = run(devops)
    assert collector.ok
    assert results["auditing"] == {"enabled": True, "source": "audit_log", "log_audit_events_policy": None}
    assert "could not be read" in results["notes"][0] and summary["auditing_enabled"] is True


def policy_change(value, when, name="Policy.LogAuditEvents"):
    return {**entry("OrganizationPolicy.PolicyValueUpdated", when, area="OrganizationPolicy"),
            "data": {"PolicyName": name, "PolicyValue": value}}


@pytest.mark.parametrize("value, enabled", [("OFF", False), ("ON", True)])
def test_the_newest_policy_change_decides_when_the_policy_is_unreadable(fakes, value, enabled):
    devops, _, _ = fakes
    devops.routes["_apis/OrganizationPolicy/Policies/Policy.LogAuditEvents"] = ado_error(401, "unauthorized")
    devops.routes["_apis/audit/auditlog"] = [page([
        entry("AuditLog.StreamRead", NOW - timedelta(minutes=1), area="Auditing"),
        policy_change(value, NOW - timedelta(minutes=5)),
        policy_change("ON" if value == "OFF" else "OFF", NOW - timedelta(days=1)),
        entry("Git.RepositoryCreated", NOW - timedelta(days=2)),
    ])]
    results, summary, _ = run(devops)
    assert results["auditing"] == {"enabled": enabled, "source": "audit_log_policy_change",
                                   "log_audit_events_policy": None}
    assert results["audit_log"]["log_audit_events_change"]["value"] is enabled
    assert summary["auditing_enabled"] is enabled


def test_another_policys_change_and_a_readable_policy_leave_the_answer_alone(fakes):
    devops, _, _ = fakes
    devops.routes["_apis/audit/auditlog"] = [page([
        policy_change("OFF", NOW - timedelta(minutes=5), name="Policy.AllowAnonymousAccess"),
        policy_change("OFF", NOW - timedelta(days=1)),
    ])]
    results, _, _ = run(devops)
    assert results["audit_log"]["log_audit_events_change"]["value"] is False
    assert results["auditing"]["enabled"] is True and results["auditing"]["source"] == "Policy.LogAuditEvents"


def test_no_policy_and_no_recent_event_leaves_auditing_unknown(fakes):
    devops, _, _ = fakes
    devops.routes["_apis/OrganizationPolicy/Policies/Policy.LogAuditEvents"] = {"unexpected": 1}
    devops.routes["_apis/audit/auditlog"] = [page([entry("Project.CreateCompleted", NOW - timedelta(days=30))])]
    results, _, _ = run(devops)
    assert results["auditing"]["enabled"] is None and "unrecognised shape" in results["notes"][0]


def test_auditing_off_is_evidence_not_a_failure(fakes):
    devops, logs, _ = fakes
    devops.routes["_apis/OrganizationPolicy/Policies/Policy.LogAuditEvents"] = {"value": False}
    devops.routes["_apis/audit/streams"] = ado_error(403, "auditing is not enabled")
    devops.routes["_apis/audit/auditlog"] = ado_error(404, "auditing is not enabled")
    results, summary, collector = run(devops)
    assert collector.ok and logs.calls == []
    assert results["auditing"]["enabled"] is False and results["streams"] is None
    assert [n.split(" refused")[0] for n in results["notes"]] == ["audit.streams.list", "audit.auditlog.query"]
    assert summary["auditing_enabled"] is False and summary["streams"] is None


def test_audit_api_failures_fail_the_run_when_auditing_is_on(fakes):
    devops, _, _ = fakes
    devops.routes["_apis/audit/streams"] = ado_error(403, "VS403436: view audit log permission")
    results, summary, collector = run(devops)
    assert [f["operation"] for f in collector.failures] == ["audit.streams.list"]
    assert results["streams"] is None and summary["streams"] is None


def test_an_auth_failure_fails_the_run_even_with_auditing_off(fakes):
    devops, _, _ = fakes
    devops.routes["_apis/OrganizationPolicy/Policies/Policy.LogAuditEvents"] = {"value": False}
    devops.routes["_apis/audit/streams"] = ado_error(401, "unauthorized")
    _, _, collector = run(devops)
    assert [f["operation"] for f in collector.failures] == ["audit.streams.list"]


def test_window_comes_from_config(fakes, monkeypatch):
    devops, logs, _ = fakes
    monkeypatch.setenv(mod.WINDOW_ENV, "30")
    results, _, _ = run(devops)
    assert results["window_days"] == 30 and "ago(30d)" in logs.calls[-1][2]
    assert stream(results, 2)["ingestion"]["window_days"] == 30


# --- main(), through the shared client ------------------------------------------

class FakeAdoSession:
    """requests.Session behind DevOpsClient, answering FakeDevOps's routes by host and path."""

    def __init__(self):
        self.routes = {
            (f"dev.azure.com/{ORG}/" if "Policy" in path else f"auditservice.dev.azure.com/{ORG}/") + path: body
            for path, body in FakeDevOps().routes.items()
        }
        self.routes[f"dev.azure.com/{ORG}/_apis/connectionData"] = {
            "authenticatedUser": {"id": "u1", "providerDisplayName": "Audit Reader"}}
        self.calls = []

    def request(self, method, url, headers=None, params=None, timeout=None, allow_redirects=True, json=None):
        self.calls.append((method, url, dict(params or {})))
        parts = urlsplit(url)
        answer = self.routes[parts.netloc + parts.path]
        if isinstance(answer, list):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        return answer if isinstance(answer, Resp) else Resp(200, answer)


@pytest.fixture
def ado(fakes, monkeypatch, tmp_path):
    session = FakeAdoSession()
    monkeypatch.setattr("requests.Session", lambda: session)
    monkeypatch.setattr(devops_rest, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.setattr(devops_rest.time, "sleep", lambda s: None)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_DEVOPS_ORG_URL", f"https://dev.azure.com/{ORG}")
    monkeypatch.setenv("AZURE_DEVOPS_PAT", "pat-do-not-write")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    return session


def run_main(tmp_path):
    code = mod.main()
    files = list((tmp_path / "evidence").glob("azure_devops_audit_streams_*.json"))
    assert [f.name for f in files] == [f"azure_devops_audit_streams_{ORG}.json"]
    return code, files[0].read_text()


def test_main_writes_evidence_for_the_organization(ado, tmp_path):
    code, text = run_main(tmp_path)
    evidence = json.loads(text)
    assert code == 0 and evidence["metadata"]["partial_failure"] is False
    assert evidence["metadata"]["organization"] == ORG
    assert evidence["metadata"]["collecting_identity"]["display_name"] == "Audit Reader"
    assert evidence["summary"]["streams"] == 3 and evidence["summary"]["azure_monitor_streams_with_rows"] == 1
    for secret in ("pat-do-not-write", SPLUNK_TOKEN, GRID_KEY, LAW_KEY):
        assert secret not in text
    assert {(u, p["api-version"]) for _, u, p in ado.calls} == {
        (f"https://dev.azure.com/{ORG}/_apis/connectionData", "7.1-preview.1"),
        (f"https://dev.azure.com/{ORG}/_apis/OrganizationPolicy/Policies/Policy.LogAuditEvents", "5.0-preview"),
        (f"https://auditservice.dev.azure.com/{ORG}/_apis/audit/streams", "7.1-preview.1"),
        (f"https://auditservice.dev.azure.com/{ORG}/_apis/audit/auditlog", "7.1-preview.1"),
    }


def test_main_fails_with_the_reason_when_the_pat_is_refused(ado, tmp_path):
    ado.routes[f"auditservice.dev.azure.com/{ORG}/_apis/audit/streams"] = Resp(
        401, {"message": "TF400813: The user is not authorized to access this resource.", "typeKey": "Unauthorized"})
    code, text = run_main(tmp_path)
    status = json.loads((tmp_path / "status.json").read_text())
    assert code == 1 and json.loads(text)["metadata"]["partial_failure"] is True
    assert status["code"] == "auth_failed" and "audit.streams.list" in status["error"]


def test_main_reports_a_refused_workspace_as_not_authorized(ado, fakes, tmp_path):
    _, logs, _ = fakes
    logs.query = Resp(403, {"error": {"code": "InsufficientAccessError", "message": "no access"}})
    code, _ = run_main(tmp_path)
    status = json.loads((tmp_path / "status.json").read_text())
    assert code == 1 and status["code"] == "not_authorized" and "AzureDevOpsAuditing" in status["error"]


def test_main_treats_a_sign_in_page_as_a_failure(ado, tmp_path):
    ado.routes[f"auditservice.dev.azure.com/{ORG}/_apis/audit/auditlog"] = Resp(203, "<html>sign in</html>")
    code, _ = run_main(tmp_path)
    assert code == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "auth_failed"
