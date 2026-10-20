"""azure_defender_assessments: each assessment's own severity from Resource Graph, the catalogue only as fallback."""

from __future__ import annotations

import importlib.util
import logging
import sys
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


class FakeGraph:
    def __init__(self, rows=None, fail=False):
        self.rows, self.fail, self.queries = rows or [], fail, []

    def resources(self, request):
        self.queries.append(request.query)
        if self.fail:
            raise RuntimeError("AuthorizationFailed")
        return SimpleNamespace(total_records=len(self.rows), result_truncated="false", data=self.rows,
                               skip_token=None)


def _collect(monkeypatch, graph, assessments=None, list_error=None):
    def listing(scope):
        if list_error:
            raise list_error
        return iter(assessments or [])

    client = SimpleNamespace(assessments=SimpleNamespace(list=listing),
                             assessments_metadata=SimpleNamespace(list_by_subscription=lambda: CATALOGUE.values()))
    security = ModuleType("azure.mgmt.security")
    security.SecurityCenter = lambda **kw: client
    monkeypatch.setitem(sys.modules, "azure.mgmt.security", security)
    monkeypatch.setattr(da, "resource_graph_client", lambda cred: graph)
    collector = Collector(logging.getLogger("test"))
    return da.collect_assessments(SUB_ID, object(), collector), collector


def test_collect_reads_each_assessments_severity_from_resource_graph(monkeypatch):
    graph = FakeGraph([{"id": assessment(AUTH).id.lower(), "severity": "High"}])
    (records, status), collector = _collect(monkeypatch, graph, [assessment(AUTH), assessment(TLS)])
    assert collector.ok and status == da.REGISTERED
    assert graph.queries == [da.SEVERITY_QUERY]
    by_check = {r["name"]: (r["severity"], r["severity_source"]) for r in records}
    assert by_check == {AUTH: ("High", "assessment"), TLS: ("Medium", "catalogue")}


def test_a_failed_severity_query_is_recorded_and_falls_back(monkeypatch):
    (records, status), collector = _collect(monkeypatch, FakeGraph(fail=True), [assessment(AUTH)])
    assert [f["operation"] for f in collector.failures] == ["resourcegraph.resources (SecurityResources)"]
    assert status == da.REGISTERED
    assert (records[0]["severity"], records[0]["severity_source"]) == ("Low", "catalogue")


def test_an_unregistered_provider_runs_no_severity_query(monkeypatch):
    graph = FakeGraph()
    (records, status), collector = _collect(
        monkeypatch, graph, list_error=RuntimeError("The subscription not registered to use Microsoft.Security"))
    assert (records, status, collector.ok) == ([], da.NOT_REGISTERED, True)
    assert graph.queries == []
