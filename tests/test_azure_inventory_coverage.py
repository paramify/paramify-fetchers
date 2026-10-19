"""Resource inventory coverage: Defender assessments and Policy states joined to each resource. Pure functions, no SDK or network."""

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


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inv = _load("resource_inventory")
Collector = sys.modules["azure_common"].Collector

SUB_ID = "00000000-0000-0000-0000-000000000000"
SUB = f"/subscriptions/{SUB_ID}"
RG = f"{SUB}/resourceGroups/rg-example"
SA1 = f"{RG}/providers/Microsoft.Storage/storageAccounts/saone"
SA2 = f"{RG}/providers/Microsoft.Storage/storageAccounts/satwo"
SITE = f"{RG}/providers/Microsoft.Web/sites/app-example"
VNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/vnet-example"
GROUP = f"{RG}/providers/microsoft.insights/actionGroups/ag-example"


def row(rid, rtype):
    return {"id": rid, "name": rid.rsplit("/", 1)[-1], "type": rtype, "location": "eastus",
            "resourceGroup": "rg-example", "tags": {"owner": "x"}, "sku": None, "kind": "", "provisioningState": ""}


RESOURCES = [inv.resource_record(r) for r in (
    row(SA1, "microsoft.storage/storageaccounts"),
    row(SA2, "microsoft.storage/storageaccounts"),
    row(SITE, "microsoft.web/sites"),
    row(VNET, "microsoft.network/virtualnetworks"),
    row(GROUP, "microsoft.insights/actiongroups"),
)]
KEYS = {r["id"].lower() for r in RESOURCES}


def assessment(target, status="Healthy", severity="Medium", n=1, via_id=False):
    aid = f"{target}/providers/Microsoft.Security/assessments/0000000{n}-aaaa-bbbb-cccc-000000000000"
    details = {} if via_id else {"Source": "Azure", "Id": target}
    return {"id": aid, "resourceDetails": details, "status": status, "severity": severity}


def state(target, compliance="Compliant", n=1):
    return {"id": f"{target}/providers/Microsoft.PolicyInsights/policyStates/latest/{n}",
            "resourceId": target, "complianceState": compliance}


ASSESSMENTS = [
    assessment(SA1, n=1),
    assessment(SA1, "Unhealthy", "High", n=2),
    assessment(SA1, "Unhealthy", "Critical", n=3),
    assessment(SITE, "Unhealthy", "", n=4, via_id=True),
    assessment(SITE, "NotApplicable", "Low", n=5),
    assessment(f"{VNET}/subnets/snet-example", "Unhealthy", "Low", n=6),
    assessment(SUB, "Unhealthy", "High", n=7),
]
STATES = [
    state(SA1, n=1),
    state(SA1, "NonCompliant", n=2),
    state(SA2.upper(), n=3),
    state(SITE, "Exempt", n=4),
    state(RG, "NonCompliant", n=5),
]


def covered(defender_rows=ASSESSMENTS, policy_rows=STATES):
    defender = None if defender_rows is None else inv.tally_defender(defender_rows, KEYS, SUB_ID)
    policy = None if policy_rows is None else inv.tally_policy(policy_rows, KEYS, SUB_ID)
    resources = inv.with_coverage(RESOURCES, defender, policy)
    return {r["id"]: r for r in resources}, inv.summarize(resources, defender, policy)


def test_assessment_target_prefers_resource_details_then_its_own_id():
    assert inv.assessment_target(assessment(SA1)) == SA1
    assert inv.assessment_target(assessment(SITE, via_id=True)) == SITE
    assert inv.assessment_target({"id": "", "resourceDetails": None}) is None


@pytest.mark.parametrize("target,expected", [
    (SA1.upper(), SA1.lower()),
    (f"{SA1}/", SA1.lower()),
    (f"{VNET}/subnets/snet-example", VNET.lower()),
    (f"{SA1}/blobServices/default", SA1.lower()),
    (RG, None),
    (SUB, None),
    (None, None),
])
def test_results_on_children_count_for_the_inventoried_parent(target, expected):
    assert inv.inventory_key(target, KEYS) == expected


def test_each_resource_carries_its_counts():
    by_id, _ = covered()
    assert {k: by_id[SA1][k] for k in ("defender_assessments", "defender_unhealthy",
                                       "defender_unhealthy_high_severity", "policy_evaluations",
                                       "policy_non_compliant")} == {
        "defender_assessments": 3, "defender_unhealthy": 2, "defender_unhealthy_high_severity": 2,
        "policy_evaluations": 2, "policy_non_compliant": 1}
    assert (by_id[VNET]["defender_assessments"], by_id[VNET]["defender_unhealthy"]) == (1, 1)
    assert (by_id[SA2]["defender_assessments"], by_id[SA2]["policy_evaluations"]) == (0, 1)


def test_gaps_are_only_resources_of_types_the_service_covers_elsewhere():
    _, s = covered()
    assert s["resources_without_defender_assessment"] == [SA2]
    assert s["types_without_defender_assessment"] == {"microsoft.insights/actiongroups": 1}
    assert (s["defender_assessable_resources"], s["resources_assessed_by_defender"], s["defender_assessed_percentage"]) == (
        4, 3, 75)
    assert s["all_assessable_resources_assessed_by_defender"] is False


def test_summary_counts_high_severity_and_what_fell_outside_the_inventory():
    _, s = covered()
    assert (s["resources_with_unhealthy_high_severity"], s["unhealthy_high_severity_assessments"]) == (1, 2)
    assert s["unhealthy_assessments_without_severity"] == 1
    assert (s["defender_assessments_total"], s["defender_assessments_outside_inventory"]) == (7, 1)


def test_policy_coverage_and_non_compliance():
    _, s = covered()
    assert s["resources_without_policy_evaluation"] == []
    assert s["types_without_policy_evaluation"] == {
        "microsoft.insights/actiongroups": 1, "microsoft.network/virtualnetworks": 1}
    assert s["all_evaluable_resources_evaluated_by_policy"] is True
    assert (s["resources_with_non_compliant_policy"], s["non_compliant_policy_evaluations"]) == (1, 1)
    assert (s["policy_evaluations_total"], s["policy_evaluations_outside_inventory"]) == (5, 1)


def test_resources_covered_by_neither_are_counted_by_type():
    _, s = covered()
    assert s["resources_covered_by_neither_by_type"] == {"microsoft.insights/actiongroups": 1}
    assert "types_covered_by_neither" not in s


def test_failing_results_outside_the_inventory_are_counted_apart():
    _, s = covered()
    assert (s["defender_unhealthy_outside_inventory"], s["policy_non_compliant_outside_inventory"]) == (1, 1)
    all_non_compliant = sum(1 for r in STATES if r["complianceState"] == "NonCompliant")
    assert s["non_compliant_policy_evaluations"] + s["policy_non_compliant_outside_inventory"] == all_non_compliant


@pytest.mark.parametrize("target,expected", [
    (SUB, "subscription"),
    (f"{SUB}/", "subscription"),
    (RG.upper(), "resource_group"),
    (f"{SUB}/providers/Microsoft.Security/pricings/VirtualMachines", "subscription > microsoft.security/pricings"),
    (f"{RG}/providers/Microsoft.Web/sites/deleted-app", "microsoft.web/sites"),
    (f"{RG}/providers/Microsoft.KeyVault/vaults/kv-gone/keys/k1", "microsoft.keyvault/vaults/keys"),
    (f"{RG}/providers/Microsoft.Storage/storageAccounts/sagone/providers/Microsoft.Security/"
     "advancedThreatProtectionSettings/current",
     "microsoft.storage/storageaccounts > microsoft.security/advancedthreatprotectionsettings"),
    ("/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg", "other_subscription"),
    ("/providers/Microsoft.Management/managementGroups/mg-example", "management_group"),
    ("", "no_target"),
    (None, "no_target"),
    ("not-an-arm-id", "unparsed"),
])
def test_targets_outside_the_inventory_are_described_by_id_shape(target, expected):
    assert inv.target_kind(target, SUB_ID) == expected


def test_outside_breakdown_by_target():
    rows = [assessment(SUB, "Unhealthy", n=1), assessment(SUB, n=2),
            assessment(f"{RG}/providers/Microsoft.Web/sites/deleted-app", "Unhealthy", n=3)]
    tally = inv.tally_defender(rows, KEYS, SUB_ID)
    assert tally["outside_by_target"] == {
        "microsoft.web/sites": {"total": 1, "unhealthy": 1},
        "subscription": {"total": 2, "unhealthy": 1},
    }
    assert (tally["outside_inventory"], tally["outside_failing"]) == (3, 2)


def test_a_service_that_covers_nothing_does_not_pass():
    _, s = covered(defender_rows=[], policy_rows=[])
    assert s["resources_without_defender_assessment"] == []
    assert s["all_assessable_resources_assessed_by_defender"] is False
    assert s["all_evaluable_resources_evaluated_by_policy"] is False
    assert s["types_without_defender_assessment"]["microsoft.storage/storageaccounts"] == 2


def test_failed_query_leaves_coverage_unknown():
    by_id, s = covered(policy_rows=None)
    assert by_id[SA1]["policy_evaluations"] is None
    assert by_id[SA1]["defender_assessments"] == 3
    assert s["policy_coverage_complete"] is False
    assert all(s[k] is None for k in (
        "policy_evaluations_total", "resources_without_policy_evaluation", "policy_evaluated_percentage",
        "all_evaluable_resources_evaluated_by_policy", "resources_covered_by_neither_by_type",
        "policy_non_compliant_outside_inventory"))
    assert s["defender_coverage_complete"] is True


def test_empty_inventory_has_nothing_to_cover():
    s = inv.summarize([], inv.tally_defender([], set()), inv.tally_policy([], set()))
    assert (s["all_assessable_resources_assessed_by_defender"], s["defender_assessed_percentage"]) == (True, 0)


def test_inventory_summary_keys_are_unchanged():
    s = inv.summarize(RESOURCES)
    assert (s["total_resources"], s["resource_type_count"], s["untagged_resources"]) == (5, 4, 0)
    assert s["defender_coverage_complete"] is False


class FakeGraph:
    """Serves each query's rows as one page; `truncate` marks one query's result truncated."""

    def __init__(self, rows_by_table, truncate=None):
        self.rows_by_table, self.truncate, self.queries = rows_by_table, truncate, []

    def resources(self, request):
        table = request.query.split(" ", 1)[0]
        self.queries.append(table)
        rows = self.rows_by_table[table]
        return SimpleNamespace(total_records=len(rows), result_truncated="true" if table == self.truncate else "false",
                               data=rows, skip_token=None)


@pytest.fixture
def fake_models(monkeypatch):
    models = ModuleType("azure.mgmt.resourcegraph.models")
    models.QueryRequest = lambda **kw: SimpleNamespace(**kw)
    models.QueryRequestOptions = lambda **kw: SimpleNamespace(**kw)
    monkeypatch.setitem(sys.modules, "azure.mgmt.resourcegraph.models", models)


def _collect(monkeypatch, graph):
    monkeypatch.setattr(inv, "resource_graph_client", lambda cred: graph)
    collector = Collector(logging.getLogger("test"))
    return inv.collect(SUB_ID, object(), collector), collector


def test_collect_joins_three_queries(monkeypatch, fake_models):
    graph = FakeGraph({"Resources": [row(SA1, "microsoft.storage/storageaccounts")],
                       "SecurityResources": [assessment(SA1)], "PolicyResources": [state(SA1)]})
    out, collector = _collect(monkeypatch, graph)
    assert collector.ok
    assert graph.queries == ["Resources", "SecurityResources", "PolicyResources"]
    assert (out["resources"][0]["defender_assessments"], out["resources"][0]["policy_evaluations"]) == (1, 1)
    assert out["coverage_queries"]["defender_assessments"]["complete"] is True
    assert out["coverage_queries"]["policy_states"]["outside_inventory_by_target"] == {}


def test_truncated_coverage_query_is_a_failure_not_a_gap(monkeypatch, fake_models):
    graph = FakeGraph({"Resources": [row(SA1, "microsoft.storage/storageaccounts")],
                       "SecurityResources": [], "PolicyResources": [state(SA1)]}, truncate="SecurityResources")
    out, collector = _collect(monkeypatch, graph)
    assert [f["operation"] for f in collector.failures] == ["resourcegraph.resources (SecurityResources)"]
    assert out["defender"] is None
    assert out["resources"][0]["defender_assessments"] is None
    assert out["resources"][0]["policy_evaluations"] == 1
    assert out["coverage_queries"]["defender_assessments"]["complete"] is False
