"""azure_policy_compliance: evaluation details, recurrence and remediation deployments. No network."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location(
    "azure_policy_compliance_under_test", AZURE / "policy_compliance" / "fetcher.py"
)
fx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fx)

needs_sdk = pytest.mark.skipif(
    importlib.util.find_spec("azure.mgmt.policyinsights") is None, reason="azure extra not installed"
)

SUB = "/subscriptions/s1"
RG = f"{SUB}/resourceGroups/rg1"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm1"
NSG = f"{RG}/providers/Microsoft.Network/networkSecurityGroups/nsg1"
ASSIGN = f"{SUB}/providers/Microsoft.Authorization/policyAssignments/a1"
DEF = "/providers/Microsoft.Authorization/policyDefinitions/d1"
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def state(resource_id, ref="r1", assignment=ASSIGN, definition=DEF):
    return {"resource_id": resource_id, "policy_assignment_id": assignment,
            "policy_definition_id": definition, "policy_definition_reference_id": ref}


def expression(actual="Allow", target="Deny", operator="Equals", path="properties.x"):
    return NS(expression="Microsoft.Foo/x", expression_kind="Field", path=path, operator=operator,
              expression_value=actual, target_value=target, result="True")


# --- projections ---

def test_evaluation_details_keep_actual_and_target_values():
    details = fx.project_evaluation_details(
        NS(evaluated_expressions=[expression()], if_not_exists_details=None)
    )
    (row,) = details["evaluated_expressions"]
    assert (row["path"], row["operator"], row["actual_value"], row["target_value"], row["result"]) == (
        "properties.x", "Equals", "Allow", "Deny", "True")
    assert row["value_truncated"] is False
    assert details["evaluated_expressions_truncated"] is False
    assert details["if_not_exists_total_resources"] is None


def test_evaluation_details_bound_long_values_and_many_expressions():
    long_list = [f"10.0.0.{i}" for i in range(200)]
    raw = [expression(actual=long_list)] + [expression() for _ in range(fx.MAX_EXPRESSIONS_PER_STATE)]
    details = fx.project_evaluation_details(NS(evaluated_expressions=raw, if_not_exists_details=None))
    first = details["evaluated_expressions"][0]
    assert first["value_truncated"] is True
    assert isinstance(first["actual_value"], str) and len(first["actual_value"]) == fx.MAX_VALUE_CHARS
    assert len(details["evaluated_expressions"]) == fx.MAX_EXPRESSIONS_PER_STATE
    assert details["evaluated_expressions_truncated"] is True


def test_evaluation_details_carry_if_not_exists_lookup():
    details = fx.project_evaluation_details(NS(
        evaluated_expressions=[], if_not_exists_details=NS(resource_id=f"{VM}/extensions/x", total_resources=1)))
    assert (details["if_not_exists_resource_id"], details["if_not_exists_total_resources"]) == (
        f"{VM}/extensions/x", 1)


def test_history_group_reads_the_apply_count():
    row = NS(resource_id=VM, policy_assignment_id=ASSIGN, policy_definition_id=DEF,
             policy_definition_reference_id="r1", compliance_state="noncompliant",
             additional_properties={"evaluations": 7})
    assert fx.project_history_group(row)["evaluations"] == 7


def test_remediation_deployment_keeps_the_error():
    d = fx.project_remediation_deployment(NS(
        remediated_resource_id=VM, deployment_id="dep", status="Failed", resource_location="eastus",
        error=NS(code="AuthorizationFailed", message="no   access\n here"),
        created_on=NOW, last_updated_on=None))
    assert (d["status"], d["error_code"], d["error_message"], d["created_on"]) == (
        "Failed", "AuthorizationFailed", "no access here", "2026-10-19T12:00:00Z")


# --- evaluation details ---

def test_only_resource_scopes_can_be_expanded():
    assert fx.is_resource_scope(VM)
    assert not fx.is_resource_scope(SUB)
    assert not fx.is_resource_scope(RG)


def test_detail_resources_dedupe_case_and_rank_by_listed_states():
    states = [state(VM), state(NSG), state(NSG.upper(), ref="r2"), state(SUB)]
    assert fx.detail_resources(states) == [NSG, VM]


def test_attach_evaluation_details_says_why_a_state_has_none():
    states = [state(VM), state(VM, ref="gone"), state(NSG), state(SUB),
              state(f"{RG}/providers/Microsoft.Web/sites/app")]
    details = fx.project_evaluation_details(NS(evaluated_expressions=[expression()], if_not_exists_details=None))
    fx.attach_evaluation_details(states, {
        VM.lower(): [{**state(None), "evaluation_details": details}],
        NSG.lower(): None,
    })
    assert [s["evaluation_details_status"] for s in states] == [
        "collected", "not_returned", "failed", "unsupported_scope", "not_requested"]
    assert states[0]["evaluation_details"] is details
    summary = fx.summarize_evaluation_details(states, eligible=3, requested=2)
    assert summary["non_compliant_states_with_evaluation_details"] == 1
    assert summary["evaluation_details_truncated"] is True


# A state the per-resource query returns with no details, or with an empty details object.
@pytest.mark.parametrize("raw", [None, NS(evaluated_expressions=[], if_not_exists_details=None),
                                 NS(evaluated_expressions=None, if_not_exists_details=NS(resource_id=None,
                                                                                          total_resources=None))],
                         ids=["null", "no_expressions", "empty_if_not_exists"])
def test_state_returned_without_details_is_not_returned(raw):
    states = [state(VM), state(VM, ref="r2")]
    with_details = fx.project_evaluation_details(NS(evaluated_expressions=[expression()], if_not_exists_details=None))
    fx.attach_evaluation_details(states, {VM.lower(): [
        {**state(None), "evaluation_details": with_details},
        {**state(None, ref="r2"), "evaluation_details": fx.project_evaluation_details(raw)},
    ]})
    assert [s["evaluation_details_status"] for s in states] == ["collected", "not_returned"]
    assert states[1]["evaluation_details"] is None
    summary = fx.summarize_evaluation_details(states, eligible=1, requested=1)
    assert summary["non_compliant_states_with_evaluation_details"] == 1
    assert summary["non_compliant_states_by_evaluation_details_status"] == {"collected": 1, "not_returned": 1}


def test_if_not_exists_lookup_alone_counts_as_details():
    details = fx.project_evaluation_details(NS(evaluated_expressions=[],
                                               if_not_exists_details=NS(resource_id=None, total_resources=0)))
    states = [state(VM)]
    fx.attach_evaluation_details(states, {VM.lower(): [{**state(None), "evaluation_details": details}]})
    assert states[0]["evaluation_details_status"] == "collected"


def fake_client(**operations):
    return NS(policy_states=NS(**operations.get("policy_states", {})),
              remediations=NS(**operations.get("remediations", {})))


@needs_sdk
def test_collect_evaluation_details_queries_each_resource_up_to_the_limit():
    calls = []

    def per_resource(resource, resource_id, query_options):
        calls.append((resource, resource_id, query_options.expand, query_options.filter))
        if "nsg1" in resource_id:
            raise RuntimeError("throttled")
        return [NS(policy_assignment_id=ASSIGN, policy_definition_id=DEF, policy_definition_reference_id="r1",
                   policy_evaluation_details=NS(evaluated_expressions=[expression()], if_not_exists_details=None))]

    client = fake_client(policy_states={"list_query_results_for_resource": per_resource})
    collector = fx.Collector(logging.getLogger("test"))
    states = [state(VM), state(VM, ref="r2"), state(NSG), state(f"{RG}/providers/Microsoft.Web/sites/app")]
    out = fx.collect_evaluation_details(client, states, 2, collector)
    assert out == {"eligible": 3, "requested": 2}
    assert calls[0] == ("latest", VM.lstrip("/"), "PolicyEvaluationDetails", "ComplianceState eq 'NonCompliant'")
    assert [s["evaluation_details_status"] for s in states] == ["collected", "not_returned", "failed", "not_requested"]
    assert states[0]["evaluation_details"]["evaluated_expressions"][0]["actual_value"] == "Allow"
    assert len(collector.failures) == 1


# --- recurrence ---

def point(day, compliance):
    return {"timestamp": f"2026-10-{day:02d}T00:00:00Z", "compliance_state": compliance}


@pytest.mark.parametrize("sequence, episodes, fell", [
    (["NonCompliant", "NonCompliant", "Compliant", "NonCompliant"], 2, 1),
    (["Compliant", "NonCompliant", "Compliant"], 1, 1),
    (["NonCompliant", "Compliant"], 1, 0),
    (["NonCompliant", "Compliant", "NonCompliant", "Compliant", "NonCompliant"], 3, 2),
])
def test_recurrence_counts_separate_episodes(sequence, episodes, fell):
    timeline = [point(i + 1, s) for i, s in enumerate(sequence)]
    record = fx.recurrence_record(state(VM), list(reversed(timeline)))
    assert (record["non_compliant_episodes"], record["times_fell_non_compliant"]) == (episodes, fell)
    assert record["recurring"] is (episodes > 1)
    assert record["latest_compliance_state"] == sequence[-1]


def test_history_pairs_split_persistent_from_intermittent():
    rows = [
        {**state(VM), "compliance_state": "noncompliant", "evaluations": 30},
        {**state(VM.upper()), "compliance_state": "compliant", "evaluations": 5},
        {**state(NSG), "compliance_state": "noncompliant", "evaluations": 90},
        {**state(NSG, ref="r2"), "compliance_state": "compliant", "evaluations": 90},
    ]
    pairs = fx.history_pairs(rows)
    assert len(pairs) == 3
    (flipping,) = fx.intermittent_pairs(pairs)
    assert (flipping["non_compliant_evaluations"], flipping["compliant_evaluations"]) == (30, 5)
    summary = fx.summarize_recurrence(pairs, [], history_truncated=False, pairs_truncated=False)
    assert (summary["history_non_compliant_pairs"], summary["history_persistently_non_compliant_pairs"],
            summary["history_intermittently_non_compliant_pairs"], summary["max_non_compliant_episodes"]) == (
        2, 1, 1, 1)


def test_timeline_filter_names_the_pair_and_escapes_quotes():
    f = fx.timeline_filter(state("/subscriptions/s1/resourceGroups/o'k/providers/x/y/z"))
    assert "ResourceId eq '/subscriptions/s1/resourceGroups/o''k/providers/x/y/z'" in f
    assert "PolicyDefinitionReferenceId eq 'r1'" in f
    assert f.endswith("(ComplianceState eq 'NonCompliant' or ComplianceState eq 'Compliant')")
    assert "PolicyDefinitionReferenceId" not in fx.timeline_filter(state(VM, ref=None))


@needs_sdk
def test_collect_recurrence_reads_history_once_then_each_flipping_pair(monkeypatch):
    seen = []
    groups = [
        NS(**state(VM), compliance_state="noncompliant", additional_properties={"evaluations": 3}),
        NS(**state(VM), compliance_state="compliant", additional_properties={"evaluations": 2}),
        NS(**state(NSG), compliance_state="noncompliant", additional_properties={"evaluations": 4}),
        NS(**state(NSG), compliance_state="compliant", additional_properties={"evaluations": 1}),
        NS(**state(VM, ref="r9"), compliance_state="noncompliant", additional_properties={"evaluations": 9}),
    ]
    series = [NS(timestamp=datetime(2026, 10, d, tzinfo=timezone.utc), compliance_state=s)
              for d, s in ((1, "NonCompliant"), (2, "Compliant"), (3, "NonCompliant"))]

    reported = {"n": 5}

    def query(resource, subscription_id, query_options):
        seen.append((resource, query_options.apply, query_options.order_by, query_options.from_property))
        if (query_options.apply or "").endswith("/aggregate($count as n)"):
            return [NS(additional_properties=dict(reported))]
        return groups if query_options.apply else series

    client = fake_client(policy_states={"list_query_results_for_subscription": query})
    out = fx.collect_recurrence(client, "s1", 1, fx.Collector(logging.getLogger("t")), now=NOW)
    assert seen[0][0] == "default" and seen[0][1] == f"groupby(({fx.HISTORY_GROUP_KEYS}))/aggregate($count as n)"
    assert "aggregate($count as evaluations)" in seen[1][1]
    assert seen[1][3] == datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)
    assert len(seen) == 3 and seen[2][2] == "Timestamp asc"
    (record,) = out["records"]
    assert record["resource_id"] == NSG and record["non_compliant_episodes"] == 2
    assert out["pairs_truncated"] is True and out["history_truncated"] is False
    assert out["window"] == {"from": "2026-09-19T12:00:00Z", "to": "2026-10-19T12:00:00Z", "days": 30}
    summary = fx.summarize_recurrence(out["pairs"], out["records"], False, True)
    assert (summary["recurring_non_compliant_pairs"], summary["max_non_compliant_episodes"]) == (1, 2)

    # The service counts more groups than came back: pages were dropped.
    reported["n"] = 6
    assert fx.collect_recurrence(client, "s1", 0, fx.Collector(logging.getLogger("t")), now=NOW)[
        "history_truncated"] is True

    monkeypatch.setattr(fx, "MAX_HISTORY_ROWS", 2)
    assert fx.collect_recurrence(client, "s1", 0, fx.Collector(logging.getLogger("t")), now=NOW)[
        "history_truncated"] is True


@needs_sdk
def test_history_group_landing_between_the_queries_is_not_truncation():
    world = [NS(**state(VM), compliance_state="noncompliant", additional_properties={"evaluations": 3})]
    late = NS(**state(NSG), compliance_state="noncompliant", additional_properties={"evaluations": 1})

    def query(resource, subscription_id, query_options):
        counting = query_options.apply.endswith("/aggregate($count as n)")
        result = [NS(additional_properties={"n": len(world)})] if counting else list(world)
        if len(world) == 1:
            world.append(late)  # evaluated late, it lands after the first query
        return result

    client = fake_client(policy_states={"list_query_results_for_subscription": query})
    out = fx.collect_recurrence(client, "s1", 0, fx.Collector(logging.getLogger("t")), now=NOW)
    assert out["history_truncated"] is False and len(out["pairs"]) == 2


def test_episode_floor_counts_unread_intermittent_pairs():
    rows = [
        {**state(VM), "compliance_state": "noncompliant", "evaluations": 3},
        {**state(VM), "compliance_state": "compliant", "evaluations": 2},
    ]
    summary = fx.summarize_recurrence(fx.history_pairs(rows), [], False, True)
    assert (summary["history_persistently_non_compliant_pairs"], summary["max_non_compliant_episodes"]) == (0, 1)
    assert fx.summarize_recurrence({}, [], False, False)["max_non_compliant_episodes"] == 0


# --- remediation deployments ---

@pytest.mark.parametrize("remediation_id, expected", [
    (f"{SUB}/providers/Microsoft.PolicyInsights/remediations/t1", ("subscription", None)),
    (f"{RG}/providers/Microsoft.PolicyInsights/remediations/t1", ("resource_group", "rg1")),
    (f"{VM}/providers/Microsoft.PolicyInsights/remediations/t1", ("resource", VM)),
    ("/providers/Microsoft.Management/managementGroups/mg1/providers/Microsoft.PolicyInsights/remediations/t1",
     ("management_group", "mg1")),
    ("/nonsense", ("unknown", None)),
])
def test_remediation_scope_picks_the_lister(remediation_id, expected):
    assert fx.remediation_scope(remediation_id) == expected


def test_deployment_is_checked_against_the_latest_state():
    current = fx.latest_states_by_resource([
        {"resource_id": VM, "compliance_state": "Compliant"},
        {"resource_id": NSG, "compliance_state": "Compliant"},
        {"resource_id": NSG.upper(), "compliance_state": "NonCompliant"},
    ])
    assert current[NSG.lower()]["compliance_state"] == "NonCompliant"
    task = {"id": "t", "policy_assignment_id": ASSIGN, "policy_definition_reference_id": "r1"}
    rows = [fx.deployment_record({"remediated_resource_id": rid, "status": status}, task, current)
            for rid, status in ((VM, "Succeeded"), (NSG, "Succeeded"), (f"{RG}/x/y/gone", "Failed"))]
    assert [r["now_compliant"] for r in rows] == [True, False, None]
    summary = fx.summarize_remediation_deployments(rows, truncated=False)
    assert (summary["remediated_resources_now_compliant"], summary["remediated_resources_now_non_compliant"],
            summary["succeeded_remediations_now_non_compliant"],
            summary["remediated_resources_compliance_unknown"]) == (1, 1, 1, 1)
    assert summary["remediation_deployments_by_status"] == {"Failed": 1, "Succeeded": 2}


def test_state_evaluated_before_the_deployment_is_not_yet_reevaluated():
    current = fx.latest_states_by_resource([
        {"resource_id": VM, "compliance_state": "NonCompliant", "timestamp": "2026-10-18T09:00:00Z"},
        {"resource_id": NSG, "compliance_state": "NonCompliant", "timestamp": "2026-10-19T09:00:00Z"},
        {"resource_id": f"{RG}/x/y/z", "compliance_state": "Compliant", "timestamp": None},
    ])
    task = {"id": "t", "policy_assignment_id": ASSIGN}
    deployed = {"status": "Succeeded", "created_on": "2026-10-18T10:00:00Z", "last_updated_on": "2026-10-18T10:05:00Z"}
    rows = [fx.deployment_record({**deployed, "remediated_resource_id": rid}, task, current)
            for rid in (VM, NSG, f"{RG}/x/y/z", f"{RG}/x/y/gone")]
    assert [(r["reevaluated_since_deployment"], r["now_compliant"]) for r in rows] == [
        (False, None), (True, False), (None, True), (None, None)]
    assert rows[0]["current_compliance_state"] == "NonCompliant"
    assert rows[0]["current_state_evaluated_at"] == "2026-10-18T09:00:00Z"
    summary = fx.summarize_remediation_deployments(rows, truncated=False)
    assert (summary["remediated_resources_not_yet_reevaluated"], summary["succeeded_remediations_now_non_compliant"],
            summary["remediated_resources_now_compliant"], summary["remediated_resources_compliance_unknown"]) == (
        1, 1, 1, 1)


@needs_sdk
def test_collect_remediation_deployments_uses_the_task_scope_and_the_limit():
    listed = []

    def deployment(rid):
        return NS(remediated_resource_id=rid, deployment_id=None, status="Succeeded", resource_location=None,
                  error=None, created_on=None, last_updated_on=None)

    def at_subscription(name):
        listed.append(("subscription", name))
        return [deployment(VM), deployment(NSG)]

    def at_resource_group(rg, name):
        listed.append(("resource_group", rg, name))
        return [deployment(f"{RG}/providers/x/y/z")]

    filters = []

    def latest(resource, subscription_id, query_options):
        assert query_options.apply is None
        assert query_options.select == "ResourceId, ComplianceState, Timestamp"
        filters.append(query_options.filter)
        return [NS(resource_id=VM, compliance_state="Compliant", timestamp=datetime(2026, 10, 19, tzinfo=timezone.utc))]

    client = fake_client(
        policy_states={"list_query_results_for_subscription": latest},
        remediations={"list_deployments_at_subscription": at_subscription,
                      "list_deployments_at_resource_group": at_resource_group},
    )
    tasks = [
        {"id": f"{SUB}/providers/Microsoft.PolicyInsights/remediations/t1", "name": "t1",
         "policy_assignment_id": ASSIGN, "policy_definition_reference_id": "R1", "total_deployments": 2},
        {"id": f"{RG}/providers/Microsoft.PolicyInsights/remediations/t2", "name": "t2",
         "policy_assignment_id": ASSIGN, "policy_definition_reference_id": "r1", "total_deployments": 1},
        {"id": f"{SUB}/providers/Microsoft.PolicyInsights/remediations/t3", "name": "t3",
         "policy_assignment_id": ASSIGN, "policy_definition_reference_id": "r2", "total_deployments": 2},
    ]
    rows, truncated = fx.collect_remediation_deployments(client, "s1", tasks, 10, fx.Collector(logging.getLogger("t")))
    assert listed == [("subscription", "t1"), ("resource_group", "rg1", "t2"), ("subscription", "t3")]
    # t1 and t2 remediate one policy (their reference ids differ only in case): one state query.
    assert filters == [f"PolicyAssignmentId eq '{ASSIGN.lower()}' and PolicyDefinitionReferenceId eq '{ref}'"
                       for ref in ("r1", "r2")]
    assert [(r["remediated_resource_id"], r["now_compliant"]) for r in rows][:2] == [(VM, True), (NSG, None)]
    assert truncated is False

    listed.clear()
    rows, truncated = fx.collect_remediation_deployments(client, "s1", tasks, 1, fx.Collector(logging.getLogger("t")))
    assert len(rows) == 1 and truncated is True
    assert listed == [("subscription", "t1")]


@needs_sdk
def test_collect_remediation_deployments_at_management_group_and_resource():
    listed = []

    def deployment(rid):
        return NS(remediated_resource_id=rid, deployment_id=None, status="Failed", resource_location=None,
                  error=NS(code="Denied", message="no"), created_on=None, last_updated_on=None)

    def at_management_group(group, name):
        listed.append(("management_group", group, name))
        return [deployment(VM)]

    def at_resource(resource_id, name):
        listed.append(("resource", resource_id, name))
        return [deployment(NSG)]

    client = fake_client(
        policy_states={"list_query_results_for_subscription": lambda *a, **k: []},
        remediations={"list_deployments_at_management_group": at_management_group,
                      "list_deployments_at_resource": at_resource},
    )
    tasks = [
        {"id": "/providers/Microsoft.Management/managementGroups/mg1/providers/Microsoft.PolicyInsights/"
               "remediations/t3", "name": "t3", "policy_assignment_id": ASSIGN},
        {"id": f"{NSG}/providers/Microsoft.PolicyInsights/remediations/t4", "name": "t4",
         "policy_assignment_id": ASSIGN},
    ]
    collector = fx.Collector(logging.getLogger("t"))
    rows, truncated = fx.collect_remediation_deployments(client, "s1", tasks, 10, collector)
    assert listed == [("management_group", "mg1", "t3"), ("resource", NSG.lstrip("/"), "t4")]
    assert [(r["remediation_task_id"].rsplit("/", 1)[-1], r["error_code"], r["now_compliant"]) for r in rows] == [
        ("t3", "Denied", None), ("t4", "Denied", None)]
    assert truncated is False and collector.ok


# --- wiring ---

def test_main_writes_the_new_results_and_summary(monkeypatch, tmp_path):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_POLICY_MAX_RECURRENCE_PAIRS", "7")
    monkeypatch.setattr(fx, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(fx, "credential", lambda: object())
    monkeypatch.setattr(fx, "provider_registration_status", lambda *a: "registered")
    seen = {}

    def collect(subscription_id, cred, collector, limits):
        seen.update(limits)
        return fx.empty_collection()

    monkeypatch.setattr(fx, "collect_compliance", collect)
    assert fx.main() == 0
    assert seen == {"non_compliant": 1000, "detail_resources": 100, "recurrence_pairs": 7,
                    "remediation_deployments": 1000}
    payload = json.loads((tmp_path / "azure_policy_compliance_s1.json").read_text())
    results, summary = payload["results"], payload["summary"]
    for key in ("remediation_deployments", "non_compliance_recurrence", "recurrence_window",
                "evaluation_details_resource_limit", "recurrence_pair_limit", "remediation_deployment_limit"):
        assert key in results
    for key in ("evaluation_details_truncated", "recurring_non_compliant_pairs", "history_truncated",
                "remediation_deployments_truncated", "succeeded_remediations_now_non_compliant"):
        assert key in summary
