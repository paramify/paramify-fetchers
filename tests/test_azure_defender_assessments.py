"""azure_defender_assessments: each assessment's own severity from Resource Graph, the catalogue only as fallback."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location(
    "azure_defender_assessments_under_test", AZURE / "defender_assessments" / "fetcher.py"
)
da = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(da)
Collector = sys.modules["azure_common"].Collector

SUB_ID = "00000000-0000-0000-0000-000000000000"
APP = f"/subscriptions/{SUB_ID}/resourceGroups/rg-example/providers/Microsoft.Web/sites/app-example"
AUTH = "00000001-aaaa-bbbb-cccc-000000000000"
TLS = "00000002-aaaa-bbbb-cccc-000000000000"
CUSTOM = "00000003-aaaa-bbbb-cccc-000000000000"


def assessment(check, status="Unhealthy", resource=APP):
    return SimpleNamespace(
        id=f"{resource}/providers/Microsoft.Security/assessments/{check}",
        name=check,
        display_name=f"check {check[:8]}",
        resource_details=SimpleNamespace(source="Azure", id=resource, additional_properties={}),
        status=SimpleNamespace(code=status, cause=None, description=None, status_change_date=None,
                               first_evaluation_date=None),
        metadata=None,
    )


def catalogue_entry(check, severity):
    return SimpleNamespace(name=check, severity=severity, categories=["AppServices"], threats=[],
                           assessment_type="BuiltIn", user_impact=None, implementation_effort=None,
                           policy_definition_id=None)


CATALOGUE = {AUTH: catalogue_entry(AUTH, "Low"), TLS: catalogue_entry(TLS, "Medium")}


def own(check, resource=APP):
    return da._id_key(f"{resource}/providers/Microsoft.Security/assessments/{check}")


def test_the_assessments_own_severity_beats_the_catalogue():
    record = da.project_assessment(assessment(AUTH), CATALOGUE, {own(AUTH): "High"})
    assert (record["severity"], record["severity_source"]) == ("High", "assessment")
    assert record["categories"] == ["AppServices"]


def test_the_id_join_ignores_case():
    upper = SimpleNamespace(**{**vars(assessment(AUTH)), "id": assessment(AUTH).id.upper()})
    assert da.project_assessment(upper, CATALOGUE, {own(AUTH): "High"})["severity"] == "High"


@pytest.mark.parametrize("by_id,expected", [
    ({}, ("Medium", "catalogue")),
    ({own(TLS): ""}, ("Medium", "catalogue")),
])
def test_the_catalogue_is_only_the_fallback(by_id, expected):
    record = da.project_assessment(assessment(TLS), CATALOGUE, by_id)
    assert (record["severity"], record["severity_source"]) == expected


def test_no_severity_anywhere_is_unknown():
    record = da.project_assessment(assessment(CUSTOM), CATALOGUE, {})
    assert (record["severity"], record["severity_source"]) == (None, None)


def test_summary_counts_unhealthy_by_own_severity_and_the_fallbacks():
    records = [
        da.project_assessment(assessment(AUTH), CATALOGUE, {own(AUTH): "High"}),
        da.project_assessment(assessment(TLS), CATALOGUE, {}),
        da.project_assessment(assessment(CUSTOM), CATALOGUE, {}),
        da.project_assessment(assessment(AUTH, "Healthy", f"{APP}-two"), CATALOGUE, {}),
    ]
    s = da.summarize(records, da.REGISTERED)
    assert s["unhealthy_by_severity"] == {"High": 1, "Medium": 1}
    assert (s["severity_from_catalogue_count"], s["severity_unknown_count"]) == (2, 1)
    assert {"total_assessments", "healthy_count", "unhealthy_count", "not_applicable_count",
            "healthy_percentage", "provider_registration_status"} < set(s)


def test_unhealthy_records_on_the_fallback_or_unknown_are_counted_apart():
    unknown_unhealthy = da.project_assessment(assessment(CUSTOM), CATALOGUE, {})
    unknown_healthy = da.project_assessment(assessment(CUSTOM, "Healthy", f"{APP}-two"), CATALOGUE, {})
    catalogue_unhealthy = da.project_assessment(assessment(TLS), CATALOGUE, {})
    s = da.summarize([unknown_unhealthy, unknown_healthy, catalogue_unhealthy], da.REGISTERED)
    assert (s["unhealthy_severity_unknown_count"], s["unhealthy_severity_from_catalogue_count"]) == (1, 1)
    assert (s["severity_unknown_count"], s["severity_from_catalogue_count"]) == (2, 1)
    healthy_only = da.summarize([unknown_healthy], da.REGISTERED)
    assert (healthy_only["severity_unknown_count"], healthy_only["unhealthy_severity_unknown_count"]) == (1, 0)


class FakeGraph:
    """Serves `rows` `page_size` at a time by skip token; `fail`, `truncate` or `overcount` break the result."""

    def __init__(self, rows=None, fail=False, truncate=False, overcount=False, page_size=1000):
        self.rows, self.fail, self.truncate, self.overcount = rows or [], fail, truncate, overcount
        self.page_size, self.requests = page_size, []

    @property
    def queries(self):
        return [r.query for r in self.requests]

    def resources(self, request):
        self.requests.append(request)
        if self.fail:
            raise RuntimeError("AuthorizationFailed")
        start = int(request.options.skip_token or 0)
        end = start + self.page_size
        return SimpleNamespace(total_records=len(self.rows) + int(self.overcount),
                               result_truncated="true" if self.truncate else "false",
                               data=self.rows[start:end], skip_token=str(end) if end < len(self.rows) else None)


@pytest.fixture
def fake_models(monkeypatch):
    models = ModuleType("azure.mgmt.resourcegraph.models")
    models.QueryRequest = lambda **kw: SimpleNamespace(**kw)
    models.QueryRequestOptions = lambda **kw: SimpleNamespace(**kw)
    monkeypatch.setitem(sys.modules, "azure.mgmt.resourcegraph.models", models)


def _security_module(monkeypatch, assessments=None, list_error=None, catalogue_error=None):
    def listing(scope):
        yield from assessments or []
        if list_error:
            raise list_error

    def catalogue():
        if catalogue_error:
            raise catalogue_error
        return CATALOGUE.values()

    client = SimpleNamespace(assessments=SimpleNamespace(list=listing),
                             assessments_metadata=SimpleNamespace(list_by_subscription=catalogue))
    security = ModuleType("azure.mgmt.security")
    security.SecurityCenter = lambda **kw: client
    monkeypatch.setitem(sys.modules, "azure.mgmt.security", security)


def _collect(monkeypatch, graph, assessments=None, list_error=None, catalogue_error=None):
    _security_module(monkeypatch, assessments, list_error, catalogue_error)
    monkeypatch.setattr(da, "resource_graph_client", lambda cred: graph)
    collector = Collector(logging.getLogger("test"))
    return da.collect_assessments(SUB_ID, object(), collector), collector


def test_collect_reads_each_assessments_severity_from_resource_graph(monkeypatch, fake_models):
    graph = FakeGraph([{"id": assessment(AUTH).id.lower(), "severity": "High"}])
    (records, status), collector = _collect(monkeypatch, graph, [assessment(AUTH), assessment(TLS)])
    assert collector.ok and status == da.REGISTERED
    assert graph.queries == [da.SEVERITY_QUERY]
    by_check = {r["name"]: (r["severity"], r["severity_source"]) for r in records}
    assert by_check == {AUTH: ("High", "assessment"), TLS: ("Medium", "catalogue")}


def test_a_failed_severity_query_is_recorded_and_falls_back(monkeypatch, fake_models):
    (records, status), collector = _collect(monkeypatch, FakeGraph(fail=True), [assessment(AUTH)])
    assert [(f["operation"], f["message"]) for f in collector.failures] == [
        ("resourcegraph.resources (SecurityResources)", "AuthorizationFailed")]
    assert status == da.REGISTERED
    assert (records[0]["severity"], records[0]["severity_source"]) == ("Low", "catalogue")


def test_an_unregistered_provider_runs_no_severity_query(monkeypatch, fake_models):
    graph = FakeGraph()
    (records, status), collector = _collect(
        monkeypatch, graph, list_error=RuntimeError("The subscription not registered to use Microsoft.Security"))
    assert (records, status, collector.ok) == ([], da.NOT_REGISTERED, True)
    assert graph.queries == []


def test_the_severity_query_is_scoped_to_the_subscription(monkeypatch, fake_models):
    graph = FakeGraph([{"id": assessment(AUTH).id, "severity": "High"}])
    _collect(monkeypatch, graph, [assessment(AUTH)])
    assert [r.subscriptions for r in graph.requests] == [[SUB_ID]]


@pytest.mark.parametrize("graph,message", [
    (FakeGraph([{"id": "x", "severity": "High"}], truncate=True), "reported the result as truncated"),
    (FakeGraph([{"id": "x", "severity": "High"}], overcount=True), "reported 2 rows but paging returned 1"),
], ids=["truncated", "short_count"])
def test_a_truncated_or_short_severity_query_is_a_failure_that_falls_back(monkeypatch, fake_models, graph, message):
    (records, _), collector = _collect(monkeypatch, graph, [assessment(AUTH)])
    assert [f["operation"] for f in collector.failures] == ["resourcegraph.resources (SecurityResources)"]
    assert message in collector.failures[0]["message"]
    assert (records[0]["severity"], records[0]["severity_source"]) == ("Low", "catalogue")


def test_main_exits_1_with_catalogue_severities_when_the_severity_query_is_truncated(monkeypatch, fake_models, tmp_path):
    _security_module(monkeypatch, [assessment(AUTH)])
    graph = FakeGraph([{"id": assessment(AUTH).id, "severity": "High"}], truncate=True)
    failures = []
    monkeypatch.setattr(da, "resource_graph_client", lambda cred: graph)
    monkeypatch.setattr(da, "credential", lambda: object())
    monkeypatch.setattr(da, "load_dotenv", lambda: None)
    monkeypatch.setattr(da, "report_failure", lambda reason, code: failures.append(reason))
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB_ID)

    assert da.main() == 1

    assert len(failures) == 1
    evidence = json.loads((tmp_path / f"azure_defender_assessments_{SUB_ID}.json").read_text())
    assert evidence["summary"]["unhealthy_severity_from_catalogue_count"] == 1
    (failure,) = evidence["metadata"]["api_failures"]
    assert failure["operation"] == "resourcegraph.resources (SecurityResources)"
    assert "truncated" in failure["message"]


def test_severities_on_every_page_are_joined(monkeypatch, fake_models):
    graph = FakeGraph([{"id": assessment(AUTH).id, "severity": "High"},
                       {"id": assessment(TLS).id, "severity": "High"}], page_size=1)
    (records, _), collector = _collect(monkeypatch, graph, [assessment(AUTH), assessment(TLS)])
    assert collector.ok and len(graph.requests) == 2
    assert {r["name"]: r["severity_source"] for r in records} == {AUTH: "assessment", TLS: "assessment"}


SUB = f"/subscriptions/{SUB_ID}"


@pytest.mark.parametrize("graph_id", [
    f"{assessment(AUTH).id}/",
    f"  {assessment(AUTH).id.upper()}  ",
])
def test_resource_graph_ids_are_normalised_before_the_join(monkeypatch, fake_models, graph_id):
    (records, _), _ = _collect(monkeypatch, FakeGraph([{"id": graph_id, "severity": "High"}]), [assessment(AUTH)])
    assert (records[0]["severity"], records[0]["severity_source"]) == ("High", "assessment")


def test_a_subscription_scoped_assessment_is_joined(monkeypatch, fake_models):
    graph = FakeGraph([{"id": assessment(AUTH, resource=SUB).id, "severity": "High"}])
    (records, _), _ = _collect(monkeypatch, graph, [assessment(AUTH, resource=SUB)])
    assert (records[0]["resource_id"], records[0]["severity"], records[0]["severity_source"]) == (
        SUB, "High", "assessment")


def test_a_failed_catalogue_keeps_resource_graph_severities(monkeypatch, fake_models):
    graph = FakeGraph([{"id": assessment(AUTH).id, "severity": "High"}])
    (records, _), collector = _collect(monkeypatch, graph, [assessment(AUTH)],
                                       catalogue_error=RuntimeError("throttled"))
    assert [f["operation"] for f in collector.failures] == ["security.assessments_metadata.list_by_subscription"]
    assert (records[0]["severity"], records[0]["severity_source"], records[0]["categories"]) == (
        "High", "assessment", [])


def test_a_list_that_fails_mid_page_keeps_earlier_records(monkeypatch, fake_models):
    graph = FakeGraph()
    (records, status), collector = _collect(monkeypatch, graph, [assessment(AUTH)],
                                            list_error=RuntimeError("connection reset"))
    assert [f["operation"] for f in collector.failures] == ["security.assessments.list"]
    assert (status, [r["name"] for r in records]) == (da.UNKNOWN, [AUTH])
    assert (records[0]["severity"], records[0]["severity_source"]) == (None, None)
    assert graph.requests == []


# --- days open and past-SLA counts ---

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def aged(severity, days=None, status="Unhealthy"):
    when = None if days is None else (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"status_code": status, "severity": severity, "status_change_date": when}


def _summary(records, readable=True, sla=None):
    sla = sla or da.DEFAULT_SLA_DAYS
    da.apply_sla(records, sla, NOW)
    return da.sla_summary(records, sla, readable)


def test_days_open_counts_whole_days_from_the_status_change_and_only_for_unhealthy():
    records = [aged("High", 31), aged("Low", 5, status="Healthy"), aged("Medium")]
    da.apply_sla(records, da.DEFAULT_SLA_DAYS, NOW)
    assert (records[0]["days_open"], records[0]["sla_days"], records[0]["past_sla"]) == (31, 30, True)
    assert (records[1]["days_open"], records[1]["past_sla"]) == (None, None)
    assert (records[2]["days_open"], records[2]["sla_days"], records[2]["past_sla"]) == (None, 90, None)


def test_exactly_at_the_sla_is_not_past_it_and_a_future_date_is_zero_days():
    records = [aged("High", 30), aged("High", -3)]
    da.apply_sla(records, da.DEFAULT_SLA_DAYS, NOW)
    assert [r["past_sla"] for r in records] == [False, False]
    assert records[1]["days_open"] == 0


def test_past_sla_counts_per_severity_and_in_total():
    s = _summary([aged("High", 40), aged("High", 10), aged("Medium", 100), aged("Low", 100), aged("Low", 200)])
    assert s["unhealthy_past_sla_by_severity"] == {"High": 1, "Medium": 1, "Low": 1}
    assert s["unhealthy_past_sla_count"] == 3
    assert s["unhealthy_days_open_unknown_count"] == 0


def test_no_unhealthy_findings_is_zero_not_null():
    s = _summary([aged("High", 400, status="Healthy")])
    assert s["unhealthy_past_sla_by_severity"] == {"High": 0, "Medium": 0, "Low": 0}
    assert s["unhealthy_past_sla_count"] == 0


def test_a_missing_date_nulls_that_severity_and_the_total_only():
    s = _summary([aged("High"), aged("Medium", 100)])
    assert s["unhealthy_past_sla_by_severity"] == {"High": None, "Medium": 1, "Low": 0}
    assert s["unhealthy_past_sla_count"] is None
    assert s["unhealthy_days_open_unknown_count"] == 1


def test_an_unhealthy_finding_with_no_severity_nulls_the_total_only():
    s = _summary([aged(None, 500), aged("High", 40)])
    assert s["unhealthy_past_sla_by_severity"] == {"High": 1, "Medium": 0, "Low": 0}
    assert s["unhealthy_past_sla_count"] is None


def test_an_unreadable_list_is_all_null_never_zero():
    s = _summary([], readable=False)
    assert s["unhealthy_past_sla_by_severity"] == {"High": None, "Medium": None, "Low": None}
    assert s["unhealthy_past_sla_count"] is None
    assert s["unhealthy_days_open_unknown_count"] is None


def test_sla_days_are_configurable_and_defaults_are_30_90_180(monkeypatch):
    assert da.sla_days_from_env() == ({"High": 30, "Medium": 90, "Low": 180}, True)
    monkeypatch.setenv("AZURE_DEFENDER_SLA_DAYS_HIGH", "7")
    days, ok = da.sla_days_from_env()
    assert (days["High"], ok) == (7, True)
    assert _summary([aged("High", 10)], sla=days)["unhealthy_past_sla_count"] == 1


@pytest.mark.parametrize("bad", ["0", "-5", "soon", "1.5"])
def test_a_bad_sla_value_is_recorded_keeps_the_default_and_flags_the_config(monkeypatch, bad):
    monkeypatch.setenv("AZURE_DEFENDER_SLA_DAYS_LOW", bad)
    collector = Collector(logging.getLogger("test"))
    days, ok = da.sla_days_from_env(collector)
    assert (days["Low"], ok) == (180, False)
    assert collector.failures[0]["operation"] == "config AZURE_DEFENDER_SLA_DAYS_LOW"


def _run_main(monkeypatch, tmp_path, rows=()):
    monkeypatch.setattr(da, "resource_graph_client", lambda cred: FakeGraph(list(rows)))
    monkeypatch.setattr(da, "credential", lambda: object())
    monkeypatch.setattr(da, "load_dotenv", lambda: None)
    monkeypatch.setattr(da, "report_failure", lambda reason, code: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB_ID)
    code = da.main()
    return code, json.loads((tmp_path / f"azure_defender_assessments_{SUB_ID}.json").read_text())


def test_main_a_failed_list_gives_null_counts(monkeypatch, fake_models, tmp_path):
    _security_module(monkeypatch, [], list_error=RuntimeError("AuthorizationFailed"))
    code, evidence = _run_main(monkeypatch, tmp_path)
    assert code == 1
    assert evidence["summary"]["unhealthy_past_sla_count"] is None
    assert evidence["summary"]["unhealthy_past_sla_by_severity"]["High"] is None


def test_main_reports_days_open_and_counts_on_a_registered_subscription(monkeypatch, fake_models, tmp_path):
    old = assessment(AUTH)
    old.status.status_change_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
    undated = assessment(TLS)
    _security_module(monkeypatch, [old, undated])
    rows = [{"id": old.id, "severity": "High"}, {"id": undated.id, "severity": "Medium"}]
    code, evidence = _run_main(monkeypatch, tmp_path, rows)
    assert code == 0
    by_name = {r["name"]: r for r in evidence["results"]["assessments"]}
    assert by_name[AUTH]["past_sla"] is True and by_name[AUTH]["days_open"] > 365
    assert by_name[TLS]["days_open"] is None
    s = evidence["summary"]
    assert s["unhealthy_past_sla_by_severity"] == {"High": 1, "Medium": None, "Low": 0}
    assert s["unhealthy_past_sla_count"] is None


def test_main_an_unregistered_subscription_counts_zero(monkeypatch, fake_models, tmp_path):
    _security_module(monkeypatch, [], list_error=RuntimeError("Subscription not registered"))
    code, evidence = _run_main(monkeypatch, tmp_path)
    assert code == 0
    assert evidence["summary"]["unhealthy_past_sla_count"] == 0
