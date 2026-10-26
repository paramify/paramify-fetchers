"""azure_service_log_records: export detection, record folding, arrival verdicts, principal split. Synthetic, no network."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_service_log_records_under_test", AZURE / "service_log_records" / "fetcher.py")
slr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(slr)
azure_rest = sys.modules["azure_rest"]
Collector = sys.modules["azure_common"].Collector

SUB = "/subscriptions/s1"
RG = f"{SUB}/resourceGroups/rg1"
LAW = f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law"
LAW_FAR = "/subscriptions/s2/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/far"
SITE = f"{RG}/providers/Microsoft.Web/sites/app1"
SLOT = f"{SITE}/slots/staging"
MI = f"{RG}/providers/Microsoft.Sql/managedInstances/mi1"


def setting(workspace=LAW, category=None, group=None, enabled=True):
    return {"name": "s", "properties": {"workspaceId": workspace,
                                        "logs": [{"category": category, "categoryGroup": group, "enabled": enabled}]}}


def ws(status=slr.WS_QUERIED, read=("AppServiceHTTPLogs", "AzureDiagnostics", "AppDependencies"), **rows):
    return {"status": status, "read_tables": list(read), **rows}


@pytest.mark.parametrize("settings, category, groups, expected", [
    ([setting(category="AppServiceHTTPLogs")], slr.HTTP_CATEGORY, slr.HTTP_GROUPS, [LAW]),
    ([setting(group="allLogs")], slr.HTTP_CATEGORY, slr.HTTP_GROUPS, [LAW]),
    ([setting(group="audit")], slr.HTTP_CATEGORY, slr.HTTP_GROUPS, []),
    ([setting(group="audit")], slr.AUDIT_CATEGORY, slr.AUDIT_GROUPS, [LAW]),
    ([setting(category="sqlsecurityauditevents")], slr.AUDIT_CATEGORY, slr.AUDIT_GROUPS, [LAW]),
    ([setting(category="AppServiceHTTPLogs", enabled=False)], slr.HTTP_CATEGORY, slr.HTTP_GROUPS, []),
    ([setting(workspace=None, category="AppServiceHTTPLogs")], slr.HTTP_CATEGORY, slr.HTTP_GROUPS, []),
    ([setting(category="AppServiceHTTPLogs"), setting(workspace=LAW.upper(), group="allLogs")],
     slr.HTTP_CATEGORY, slr.HTTP_GROUPS, [LAW]),
    (None, slr.HTTP_CATEGORY, slr.HTTP_GROUPS, []),
])
def test_exporting_workspaces(settings, category, groups, expected):
    assert slr.exporting_workspaces(settings, category, groups) == expected


@pytest.mark.parametrize("name, kind", [
    ("ops@example.com", slr.ENTRA),
    ("11111111-2222-3333-4444-555555555555@66666666-7777-8888-9999-000000000000", slr.ENTRA),
    ("app_login", slr.SQL_LOGIN),
    ("", None),
    (None, None),
])
def test_principal_kind(name, kind):
    assert slr.principal_kind(name) == kind


@pytest.mark.parametrize("table, readable", [
    ({"exists": True, "plan": "Analytics"}, True),
    ({"exists": True, "plan": None}, True),
    ({"exists": True, "plan": "Basic"}, False),
    ({"exists": True, "plan": "Auxiliary"}, False),
    ({"exists": False, "plan": None}, True),
])
def test_basic_tables_are_not_read_and_missing_ones_count_as_empty(table, readable):
    assert slr.readable(table) is readable


@pytest.mark.parametrize("value, expected", [
    ('["10.0.0.4","10.0.0.5"]', ["10.0.0.4", "10.0.0.5"]),
    (["a.example.net", ""], ["a.example.net"]),
    ("not json", ["not json"]),
    ('"one"', []),
    (None, []),
])
def test_dynamic_list_reads_make_set_columns_sent_as_json_text(value, expected):
    assert slr.dynamic_list(value) == expected


def http_row(rid=SITE, records=10, last="2026-10-12T10:00:00Z", **extra):
    return {"ResourceId": rid.lower(), "Records": records, "LastRecord": last, "ClientIps": 3, "Status2xx": 7,
            "Status3xx": 0, "Status4xx": 2, "Status5xx": 1, "Hosts": ["app1.example.net"], **extra}


def test_app_with_records_is_arriving_and_carries_its_sample():
    workspaces = {slr.id_key(LAW): ws(
        http=[http_row(Hosts='["app1.example.net","www.example.net"]')],
        http_latest=[{"ResourceId": SITE.lower(), "TimeGenerated": "2026-10-12T10:00:00Z", "CIp": "203.0.113.5",
                      "CsHost": "app1.example.net", "CsMethod": "GET", "CsUriStem": "/", "ScStatus": 200}],
        http_clients=[{"ResourceId": SITE.lower(), "CIp": "203.0.113.5", "Requests": 6},
                      {"ResourceId": SITE.lower(), "CIp": "198.51.100.7", "Requests": 4},
                      {"ResourceId": SLOT.lower(), "CIp": "192.0.2.1", "Requests": 99}],
    )}
    record = slr.app_record({"id": SITE, "name": "app1", "kind": "app"}, [setting(group="allLogs")], workspaces, 1)
    assert {k: record[k] for k in ("http_logs_exported", "http_log_records", "last_http_log", "distinct_client_ips",
                                   "status_classes", "top_clients", "http_logs_arriving", "is_slot")} == {
        "http_logs_exported": True, "http_log_records": 10, "last_http_log": "2026-10-12T10:00:00Z",
        "distinct_client_ips": 3, "status_classes": {"2xx": 7, "3xx": 0, "4xx": 2, "5xx": 1},
        "top_clients": [{"client_ip": "203.0.113.5", "requests": 6}], "http_logs_arriving": True, "is_slot": False}
    assert record["latest_request"] == {"time": "2026-10-12T10:00:00Z", "client_ip": "203.0.113.5",
                                        "host": "app1.example.net", "method": "GET", "status": 200}
    assert record["hosts"] == ["app1.example.net"]


def test_host_values_that_are_not_host_names_are_left_out():
    workspaces = {slr.id_key(LAW): ws(
        http=[http_row(Hosts='["app1.example.net","<script>x</script>","../../etc/passwd","app1.example.net:443"]')],
        http_latest=[{"ResourceId": SITE.lower(), "TimeGenerated": "2026-10-12T10:00:00Z", "CIp": "203.0.113.5",
                      "CsHost": "/bin/sh", "CsMethod": "GET", "ScStatus": 404}],
    )}
    record = slr.app_record({"id": SITE}, [setting(group="allLogs")], workspaces, 10)
    assert record["hosts"] == ["app1.example.net", "app1.example.net:443"]
    assert (record["latest_request"]["host"], record["latest_request"]["status"]) == (None, 404)


def test_logs_sent_to_two_workspaces_count_once():
    def both(**rows):
        return {slr.id_key(LAW): ws(**rows), slr.id_key(LAW_FAR): ws(**rows)}

    def two(category):
        return [setting(category=category), setting(workspace=LAW_FAR, category=category)]

    http = both(http=[http_row()], http_clients=[{"ResourceId": SITE.lower(), "CIp": "203.0.113.5", "Requests": 6}])
    http[slr.id_key(LAW_FAR)]["http"] = [http_row(records=4, last="2026-10-12T12:00:00Z")]
    app = slr.app_record({"id": SITE}, two("AppServiceHTTPLogs"), http, 10)
    assert (app["http_log_records"], app["status_classes"]["2xx"], app["top_clients"], app["last_http_log"]) == (
        10, 7, [{"client_ip": "203.0.113.5", "requests": 6}], "2026-10-12T12:00:00Z")

    audit = both(audit=[audit_row("Orders")], principals=[principal_row("ops@example.com", 5, 5)])
    mi = slr.instance_record({"id": MI}, two("SQLSecurityAuditEvents"), [{"name": "Orders"}], audit, 10)
    assert (mi["audit_records"], mi["failed_audit_events"], mi["databases"][0]["audit_records"],
            mi["principals"][0]["events"]) == (5, 5, 5, 5)


@pytest.mark.parametrize("workspace, arriving", [
    (ws(), False),
    (ws(read=("AzureDiagnostics",)), None),
    (ws(status=slr.WS_NOT_AUTHORIZED, read=()), None),
    (ws(status=slr.WS_NOT_FOUND, read=()), False),
    (ws(status=slr.WS_ERROR, read=()), None),
])
def test_app_without_records(workspace, arriving):
    record = slr.app_record({"id": SLOT, "name": "app1/staging"}, [setting(category="AppServiceHTTPLogs")],
                            {slr.id_key(LAW): workspace}, 10)
    assert (record["http_log_records"], record["http_logs_arriving"], record["latest_request"], record["is_slot"]) == (
        0, arriving, None, True)


def test_app_that_exports_nothing_or_whose_settings_failed():
    unexported = slr.app_record({"id": SITE}, [], {}, 10)
    unread = slr.app_record({"id": SITE}, None, {}, 10)
    assert (unexported["http_logs_exported"], unexported["http_logs_arriving"]) == (False, None)
    assert (unread["http_logs_exported"], unread["diagnostic_settings_read"]) == (None, False)


def test_records_only_count_from_the_apps_own_destinations():
    workspaces = {slr.id_key(LAW): ws(http=[]), slr.id_key(LAW_FAR): ws(http=[http_row()])}
    record = slr.app_record({"id": SITE}, [setting(category="AppServiceHTTPLogs")], workspaces, 10)
    assert (record["http_log_records"], record["http_logs_arriving"]) == (0, False)


def audit_row(database, action="LOGIN FAILED", records=5, failed=5, last="2026-10-12T09:00:00Z"):
    return {"ResourceId": MI.lower(), "Database": database, "Action": action, "Records": records, "Failed": failed,
            "LastRecord": last}


def principal_row(name, records, failed, ips=("10.0.0.4",), last="2026-10-12T09:00:00Z"):
    return {"ResourceId": MI.lower(), "Principal": name, "Records": records, "Failed": failed, "LastSeen": last,
            "ClientIps": list(ips)}


def test_instance_audit_folds_databases_actions_and_principals():
    workspaces = {slr.id_key(LAW): ws(
        audit=[audit_row(""), audit_row("Orders", action="SCHEMA_OBJECT_ACCESS_GROUP", records=3, failed=0,
                                        last="2026-10-12T11:00:00Z"),
               audit_row("master", action="LOGIN SUCCEEDED", records=2, failed=0)],
        principals=[principal_row("ops@example.com", 3, 0), principal_row("app_login", 2, 0, ips=("10.0.0.5", "10.0.0.6")) | {"ClientIps": '["10.0.0.5","10.0.0.6"]'},
                    principal_row("", 5, 5)],
    )}
    databases = [{"name": "Orders"}, {"name": "Reports"}]
    record = slr.instance_record({"id": MI, "name": "mi1"}, [setting(group="audit")], databases, workspaces, 1)
    assert {k: record[k] for k in ("audit_exported", "audit_records", "failed_audit_events", "last_audit_record",
                                   "audit_actions", "principals_total", "entra_principals", "sql_login_principals",
                                   "unnamed_principal_events", "audit_records_without_database",
                                   "audit_arriving")} == {
        "audit_exported": True, "audit_records": 10, "failed_audit_events": 5,
        "last_audit_record": "2026-10-12T11:00:00Z",
        "audit_actions": {"LOGIN FAILED": 5, "LOGIN SUCCEEDED": 2, "SCHEMA_OBJECT_ACCESS_GROUP": 3},
        "principals_total": 2, "entra_principals": 1, "sql_login_principals": 1, "unnamed_principal_events": 5,
        "audit_records_without_database": 5, "audit_arriving": True}
    assert [(d["name"], d["listed"], d["audit_records"]) for d in record["databases"]] == [
        ("master", False, 2), ("Orders", True, 3), ("Reports", True, 0)]
    assert record["principals"] == [{"principal": None, "kind": None, "events": 5, "failed_events": 5,
                                     "last_seen": "2026-10-12T09:00:00Z", "client_ips": ["10.0.0.4"]}]
    wide = slr.instance_record({"id": MI}, [setting(group="audit")], databases, workspaces, 10)
    assert [p["client_ips"] for p in wide["principals"] if p["principal"] == "app_login"] == [["10.0.0.5", "10.0.0.6"]]


def test_instance_whose_workspace_lacks_the_table_reads_not_arriving():
    record = slr.instance_record({"id": MI}, [setting(category="SQLSecurityAuditEvents")], [],
                                 {slr.id_key(LAW): ws(read=("AzureDiagnostics",))}, 10)
    assert (record["audit_records"], record["audit_arriving"]) == (0, False)


def test_dependencies_fold_per_role_and_target():
    workspaces = {slr.id_key(LAW): ws(dependencies=[
        {"Component": "c1", "AppRole": "app1", "Target": "db.example.net", "DependencyType": "SQL", "Calls": 10,
         "Failed": 1, "LastCall": "2026-10-12T10:00:00Z"},
        {"Component": "c1", "AppRole": "app1", "Target": "store.blob.example.net", "DependencyType": "Azure blob",
         "Calls": 40, "Failed": 0, "LastCall": "2026-10-12T11:00:00Z"},
    ])}
    [role] = slr.dependency_records(workspaces, 1)
    assert (role["app_role"], role["targets_total"], role["dependency_types"], role["targets"][0]["target"]) == (
        "app1", 2, ["Azure blob", "SQL"], "store.blob.example.net")


class _Client:
    def __init__(self, tables=None, get_error=None):
        self.tables, self.get_error, self.queries = tables or {}, get_error, []

    def get(self, path, api_version):
        if self.get_error:
            raise self.get_error
        if "/tables/" in path:
            name = path.rsplit("/", 1)[-1]
            if name not in self.tables:
                raise azure_rest.ArmError(404, "ResourceNotFound", "no table")
            return {"properties": {"plan": self.tables[name], "retentionInDays": 30, "totalRetentionInDays": 90}}
        return {"properties": {"customerId": "cust"}}

    def query(self, customer_id, kql, timespan):
        self.queries.append((kql.split(" ")[0], timespan, kql))
        return []


def test_workspace_reads_only_analytics_tables_scoped_to_the_subscription():
    client = _Client({"AppServiceHTTPLogs": "Basic", "AzureDiagnostics": "Analytics"})
    out = slr.read_workspace(client, LAW, "s1", 7, 10, Collector(slr.logger))
    assert sorted({q[0] for q in client.queries}) == ["AzureDiagnostics"]
    assert all(q[1] == "P7D" and "ago(7d)" in q[2] and "startswith '/subscriptions/s1/'" in q[2] for q in client.queries)
    assert all("Category == 'SQLSecurityAuditEvents'" in q[2] for q in client.queries)
    assert out["read_tables"] == ["AppDependencies", "AzureDiagnostics"]
    assert [(t["name"], t["exists"], t["plan"]) for t in out["tables"]] == [
        ("AppServiceHTTPLogs", True, "Basic"), ("AzureDiagnostics", True, "Analytics"), ("AppDependencies", False, None)]


@pytest.mark.parametrize("error, status, failed", [
    (azure_rest.ArmError(403, "AuthorizationFailed", "no"), slr.WS_NOT_AUTHORIZED, False),
    (azure_rest.ArmError(404, "ResourceNotFound", "gone"), slr.WS_NOT_FOUND, False),
    (azure_rest.QueryError("(403) InsufficientAccessError", "no access"), slr.WS_NOT_AUTHORIZED, False),
    (azure_rest.ArmError(500, "InternalServerError", "boom"), slr.WS_ERROR, True),
])
def test_only_unexpected_workspace_failures_fail_the_run(error, status, failed):
    collector = Collector(slr.logger)
    out = slr.read_workspace(_Client(get_error=error), LAW, "s1", 7, 10, collector)
    assert (out["status"], out["read_tables"], collector.ok) == (status, [], not failed)


def test_summary_counts():
    workspaces = {slr.id_key(LAW): ws(http=[http_row()], audit=[audit_row("Orders")])}
    apps = [slr.app_record({"id": SITE}, [setting(category="AppServiceHTTPLogs")], workspaces, 10),
            slr.app_record({"id": SLOT}, [setting(category="AppServiceHTTPLogs")], workspaces, 10),
            slr.app_record({"id": SITE + "2"}, [], workspaces, 10)]
    mis = [slr.instance_record({"id": MI}, [setting(group="audit")], [{"name": "Orders"}, {"name": "Other"}],
                               workspaces, 10)]
    tables = [{"name": "AppServiceHTTPLogs", "exists": True, "retention_in_days": 30},
              {"name": "AzureDiagnostics", "exists": True, "retention_in_days": 90},
              {"name": "AppDependencies", "exists": False, "retention_in_days": None}]
    summary = slr.summarize(apps, mis, [], [{"workspace_id": LAW, "status": slr.WS_QUERIED, "tables": tables}], 7)
    assert {k: summary[k] for k in (
        "apps", "apps_exporting_http_logs", "apps_with_http_log_records", "apps_without_http_log_records",
        "http_log_arrival_percentage", "instances_exporting_audit", "instances_with_audit_records",
        "managed_databases", "managed_databases_with_audit_records", "http_log_retention_days",
        "audit_log_retention_days", "dependency_retention_days", "log_workspaces_queried",
    )} == {
        "apps": 3, "apps_exporting_http_logs": 2, "apps_with_http_log_records": 1, "apps_without_http_log_records": 1,
        "http_log_arrival_percentage": 50, "instances_exporting_audit": 1, "instances_with_audit_records": 1,
        "managed_databases": 2, "managed_databases_with_audit_records": 1, "http_log_retention_days": 30,
        "audit_log_retention_days": 90, "dependency_retention_days": None, "log_workspaces_queried": 1,
    }


def test_retention_counts_only_the_workspaces_that_receive_each_log_type():
    def tables(http, audit):
        return [{"name": "AppServiceHTTPLogs", "exists": True, "retention_in_days": http, "total_retention_in_days": http},
                {"name": "AzureDiagnostics", "exists": True, "retention_in_days": audit, "total_retention_in_days": audit}]

    apps = [slr.app_record({"id": SITE}, [setting(category="AppServiceHTTPLogs")], {}, 10)]
    mis = [slr.instance_record({"id": MI}, [setting(workspace=LAW_FAR, group="audit")], [], {}, 10)]
    workspaces = [{"workspace_id": LAW, "status": slr.WS_QUERIED, "tables": tables(365, 30)},
                  {"workspace_id": LAW_FAR, "status": slr.WS_QUERIED, "tables": tables(30, 365)}]
    summary = slr.summarize(apps, mis, [], workspaces, 7)
    assert [summary[k] for k in ("http_log_retention_days", "http_log_total_retention_days", "audit_log_retention_days",
                                 "audit_log_total_retention_days")] == [365, 365, 365, 365]


@pytest.mark.parametrize("column", ["succeeded_s", "database_name_s", "action_name_s", "server_principal_name_s",
                                    "client_ip_s"])
def test_audit_columns_are_read_only_through_column_ifexists(column):
    for kql in (slr.AUDIT_QUERY, slr.PRINCIPAL_QUERY):
        assert kql.count(column) == kql.count(f"column_ifexists('{column}', '')") == 1


class _MissingTable(_Client):
    def query(self, customer_id, kql, timespan):
        table = kql.split(" ")[0]
        if table == "AppDependencies":
            raise azure_rest.QueryError("(400) BadArgumentError",
                                        "'where' operator: Failed to resolve table expression named 'AppDependencies'")
        return super().query(customer_id, kql, timespan)


def test_a_listed_table_without_records_reads_as_no_rows():
    collector = Collector(slr.logger)
    out = slr.read_workspace(_MissingTable({t: "Analytics" for t in ("AppServiceHTTPLogs", "AzureDiagnostics",
                                                                     "AppDependencies")}), LAW, "s1", 7, 10, collector)
    assert (out["status"], out["dependencies"], collector.ok) == (slr.WS_QUERIED, [], True)
    assert "AppDependencies" in out["read_tables"]


class _QueryFails(_Client):
    def query(self, customer_id, kql, timespan):
        raise azure_rest.QueryError("(500) InternalServerError", "boom")


def test_a_query_failure_after_the_tables_were_read_fails_the_run_and_keeps_the_tables():
    collector = Collector(slr.logger)
    out = slr.read_workspace(_QueryFails({"AzureDiagnostics": "Analytics"}), LAW, "s1", 7, 10, collector)
    assert (out["status"], out["read_tables"], collector.ok) == (slr.WS_ERROR, [], False)
    assert [t["name"] for t in out["tables"] if t["exists"]] == ["AzureDiagnostics"]


@pytest.mark.parametrize("error, status", [
    (azure_rest.QueryError("(404) WorkspaceNotFoundError", "The workspace could not be found"), slr.WS_NOT_FOUND),
    (azure_rest.ArmError(404, "SubscriptionNotFound", "The subscription 's2' could not be found."),
     slr.WS_NOT_AUTHORIZED),
    (azure_rest.QueryError("(400) BadArgumentError", "Failed to resolve scalar expression named 'x'"), slr.WS_ERROR),
])
def test_ws_status(error, status):
    assert slr.ws_status(error) == status


class _Subscription:
    """ARM and query answers for one subscription: an app with a slot and a managed instance sharing one workspace."""

    def __init__(self, failing_settings=()):
        self.failing_settings, self.gets, self.queries = set(failing_settings), [], []

    def list(self, path, api_version):
        if path.endswith("/Microsoft.Web/sites"):
            return [{"id": SITE, "name": "app1", "kind": "app"}]
        if path == f"{SITE}/slots":
            return [{"id": SLOT, "name": "app1/staging", "kind": "app"}]
        if path.endswith("/Microsoft.Sql/managedInstances"):
            return [{"id": MI, "name": "mi1"}]
        if path == f"{MI}/databases":
            return [{"name": "Orders"}]
        resource = path.split("/providers/Microsoft.Insights/")[0]
        if resource in self.failing_settings:
            raise azure_rest.ArmError(500, "InternalServerError", "boom")
        return [setting(group="allLogs")]

    def get(self, path, api_version):
        self.gets.append(path)
        if "/tables/" in path:
            return {"properties": {"plan": "Analytics", "retentionInDays": 30, "totalRetentionInDays": 365}}
        return {"properties": {"customerId": "cust"}}

    def query(self, customer_id, kql, timespan):
        self.queries.append(kql)
        if kql.startswith("AppServiceHTTPLogs") and "summarize Records" in kql:
            return [http_row(SITE)]
        if kql.startswith("AzureDiagnostics") and "by ResourceId = tolower(_ResourceId), Database" in kql:
            return [audit_row("")]
        return []


def test_collect_reads_slots_and_a_shared_workspace_once():
    client, collector = _Subscription(), Collector(slr.logger)
    results, summary = slr.collect(client, "s1", collector)
    assert collector.ok
    assert [a["is_slot"] for a in results["apps"]] == [False, True]
    assert [g for g in client.gets if "/tables/" not in g] == [LAW]
    assert len(results["workspaces"]) == 1
    assert set(results["queries"].values()) == set(client.queries)
    assert all("{" not in q and "ago(7d)" in q for q in results["queries"].values())
    assert {k: summary[k] for k in ("apps", "apps_with_http_log_records", "apps_without_http_log_records",
                                    "instances_with_audit_records", "managed_databases",
                                    "http_log_total_retention_days", "audit_log_total_retention_days")} == {
        "apps": 2, "apps_with_http_log_records": 1, "apps_without_http_log_records": 1,
        "instances_with_audit_records": 1, "managed_databases": 1,
        "http_log_total_retention_days": 365, "audit_log_total_retention_days": 365}


def test_collect_records_a_diagnostic_settings_failure():
    collector = Collector(slr.logger)
    results, summary = slr.collect(_Subscription(failing_settings={SLOT}), "s1", collector)
    slot = next(a for a in results["apps"] if a["is_slot"])
    assert (slot["diagnostic_settings_read"], slot["http_logs_exported"], collector.ok) == (False, None, False)
    assert summary["apps_exporting_http_logs"] == 1


def test_retention_ignores_missing_and_non_positive_values():
    tables = [{"name": "AppServiceHTTPLogs", "exists": True, "retention_in_days": d, "total_retention_in_days": d}
              for d in (0, -1, None, 45)]
    assert slr._min_retention([{"tables": tables}], "AppServiceHTTPLogs") == 45
    assert slr._min_retention([{"tables": tables[:2]}], "AppServiceHTTPLogs", slr.TOTAL_RETENTION) is None
