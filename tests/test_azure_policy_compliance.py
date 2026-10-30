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


def _has_sdk() -> bool:
    try:
        return importlib.util.find_spec("azure.mgmt.policyinsights") is not None
    except ModuleNotFoundError:  # find_spec imports the parent package, and the test job has no azure
        return False


needs_sdk = pytest.mark.skipif(not _has_sdk(), reason="azure extra not installed")

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
        "collected", "not_in_detail_result", "failed", "unsupported_scope", "not_requested"]
    assert states[0]["evaluation_details"] is details
    summary = fx.summarize_evaluation_details(
        states, {"eligible": 3, "requested": 2, "truncated": True, "not_authorized": 0})
    assert summary["non_compliant_states_with_evaluation_details"] == 1
    assert summary["evaluation_details_truncated"] is True


def test_nested_resource_rows_keep_their_own_resource_id():
    ext = f"{VM}/extensions/ext1"
    mine = fx.project_evaluation_details(NS(evaluated_expressions=[expression(actual="vm")], if_not_exists_details=None))
    nested = fx.project_evaluation_details(NS(evaluated_expressions=[expression(actual="ext")],
                                              if_not_exists_details=None))
    states = [state(VM)]
    fx.attach_evaluation_details(states, {VM.lower(): [
        {**state(VM), "evaluation_details": mine},
        {**state(ext), "evaluation_details": nested},
    ]})
    assert states[0]["evaluation_details"] is mine


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
    summary = fx.summarize_evaluation_details(
        states, {"eligible": 1, "requested": 1, "truncated": False, "not_authorized": 0})
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
    assert out == {"eligible": 3, "requested": 2, "truncated": True, "not_authorized": 0}
    assert calls[0] == ("latest", VM.lstrip("/"), "PolicyEvaluationDetails", "ComplianceState eq 'NonCompliant'")
    assert [s["evaluation_details_status"] for s in states] == [
        "collected", "not_in_detail_result", "failed", "not_requested"]
    assert states[0]["evaluation_details"]["evaluated_expressions"][0]["actual_value"] == "Allow"
    assert len(collector.failures) == 1

    # 0 skips them: nothing is queried and nothing reads as truncated.
    calls.clear()
    assert fx.collect_evaluation_details(client, states, 0, collector) == {
        "eligible": 3, "requested": 0, "truncated": False, "not_authorized": 0}
    assert calls == []


GUID = "11111111-2222-3333-4444-555555555555"
APP = f"{RG}/providers/Microsoft.Web/sites/app"


class _ArmError(Exception):
    """An azure-core HttpResponseError as the fetcher sees it: status, the parsed ARM error, the message."""

    def __init__(self, status_code, code, message):
        super().__init__(f"({code}) {message}" if code else message)
        self.status_code = status_code
        self.error = NS(code=code) if code else None


# ARM's AuthorizationFailed bodies, with a made-up principal and scope.
REFUSALS = {
    "standard_403": (403, "AuthorizationFailed",
                     f"The client 'jane.doe@contoso.com' with object id '{GUID}' does not have authorization to "
                     f"perform action 'Microsoft.Web/sites/read' over scope '/subscriptions/{GUID}/resourceGroups/rg1/"
                     "providers/Microsoft.Web/sites/app' or the scope is invalid."),
    "deny_assignment_403": (403, "AuthorizationFailed",
                            f"The client 'jane.doe@contoso.com' with object id '{GUID}' has permission to perform "
                            f"action 'Microsoft.Web/sites/read' on scope '/subscriptions/{GUID}/resourceGroups/rg1'; "
                            f"however, the access is denied because of the deny assignment with name 'deny' and Id "
                            f"'{GUID}' at scope '/subscriptions/{GUID}'."),
    "policy_insights_409": (409, "AuthorizationFailed",
                            f"Encountered an error while authorizing the client 'jane.doe@contoso.com' with object id "
                            f"'{GUID}' on action 'Microsoft.Web/sites/config/read' over scope '/subscriptions/{GUID}/"
                            "resourceGroups/rg1/providers/Microsoft.Web/sites/app/config/web'. If the issue persists, "
                            "make sure the subscription is registered to 'Microsoft.PolicyInsights'."),
    "no_action_403": (403, "AuthorizationFailed",
                      f"The client 'jane.doe@contoso.com' with object id '{GUID}' is not authorized."),
    "unparsed_403": (403, None, f"Forbidden: client 'jane.doe@contoso.com' object id '{GUID}' /subscriptions/{GUID}"),
    "scope_in_action_slot": (403, "AuthorizationFailed",
                             f"The client 'jane.doe@contoso.com' does not have authorization to perform action "
                             f"'subscriptions/{GUID}/resourceGroups/rg/read'."),
}


@pytest.mark.parametrize("kind, reason", [
    ("standard_403", "Policy Insights refused the read (AuthorizationFailed) on Microsoft.Web/sites/read"),
    ("deny_assignment_403", "Policy Insights refused the read (AuthorizationFailed) on Microsoft.Web/sites/read"),
    ("policy_insights_409", "Policy Insights refused the read (AuthorizationFailed) on Microsoft.Web/sites/config/read"),
    ("no_action_403", "Policy Insights refused the read (AuthorizationFailed)"),
    ("unparsed_403", "Policy Insights refused the read (HTTP 403)"),
    ("scope_in_action_slot", "Policy Insights refused the read (AuthorizationFailed)"),
])
def test_refusal_reason_names_the_code_and_action_never_the_principal(kind, reason):
    exc = _ArmError(*REFUSALS[kind])
    assert fx.is_not_authorized(exc)
    assert fx.refusal_reason(exc) == reason
    for leak in ("client '", "object id", "jane", "/subscriptions/", GUID):
        assert leak not in fx.refusal_reason(exc)


@pytest.mark.parametrize("exc", [
    _ArmError(404, "ResourceNotFound", "The Resource 'Microsoft.Web/sites/forbidden-zone' under resource group "
                                       "'forbidden-rg' was not found."),
    _ArmError(500, "InternalServerError", "Failed for /resourceGroups/forbidden-rg: AuthorizationFailed upstream (403)"),
    _ArmError(429, "TooManyRequests", "Throttled."),
    _ArmError(503, "ServiceUnavailable", "Try again."),
    _ArmError(409, "Conflict", "(AuthorizationFailed) in a resource name is not a refusal"),
], ids=["not_found_404", "server_error_500", "throttled_429", "unavailable_503", "conflict_409"])
def test_customer_text_never_makes_a_refusal(exc):
    assert not fx.is_not_authorized(exc)


def _detail_rows(resource_id):
    return [NS(resource_id=resource_id, policy_assignment_id=ASSIGN, policy_definition_id=DEF,
               policy_definition_reference_id="r1",
               policy_evaluation_details=NS(evaluated_expressions=[expression()], if_not_exists_details=None))]


@needs_sdk
def test_refused_detail_read_is_retried_once_then_marks_its_states(monkeypatch):
    monkeypatch.setattr(fx, "REFUSAL_RETRY_SECONDS", 0)
    calls = []

    def per_resource(resource, resource_id, query_options):
        calls.append(resource_id.rsplit("/", 1)[-1])
        if resource_id.endswith("/app"):
            raise _ArmError(*REFUSALS["policy_insights_409"])
        if "nsg1" in resource_id:
            raise _ArmError(503, "ServiceUnavailable", "Try again.")
        return _detail_rows(VM)

    client = fake_client(policy_states={"list_query_results_for_resource": per_resource})
    collector = fx.Collector(logging.getLogger("test"))
    states = [state(APP), state(APP, ref="r2"), state(VM), state(NSG)]
    out = fx.collect_evaluation_details(client, states, 10, collector)
    # The refusal is read twice; the 503 is not retried here.
    assert sorted(calls) == ["app", "app", "nsg1", "vm1"]
    assert out["not_authorized"] == 1
    refused = "Policy Insights refused the read (AuthorizationFailed) on Microsoft.Web/sites/config/read"
    assert [(s["evaluation_details_status"], s["evaluation_details_reason"]) for s in states] == [
        ("not_authorized", refused), ("not_authorized", refused), ("collected", None), ("failed", None)]
    assert [f["operation"] for f in collector.failures] == [
        "policyinsights.policy_states.list_query_results_for_resource(nsg1)"]
    assert "jane" not in json.dumps(states)
    summary = fx.summarize_evaluation_details(states, out)
    assert summary["evaluation_details_not_authorized_resources"] == 1
    assert summary["non_compliant_states_by_evaluation_details_status"] == {
        "collected": 1, "failed": 1, "not_authorized": 2}


@needs_sdk
def test_refusal_that_clears_on_the_retry_is_collected(monkeypatch):
    monkeypatch.setattr(fx, "REFUSAL_RETRY_SECONDS", 0)
    answers = [_ArmError(*REFUSALS["policy_insights_409"]), _detail_rows(APP)]

    def per_resource(resource, resource_id, query_options):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    client = fake_client(policy_states={"list_query_results_for_resource": per_resource})
    collector = fx.Collector(logging.getLogger("test"))
    states = [state(APP)]
    out = fx.collect_evaluation_details(client, states, 10, collector)
    assert (states[0]["evaluation_details_status"], out["not_authorized"], collector.ok) == ("collected", 0, True)


class _Arm409:
    """Just enough of an HTTP response for azure-core to parse an ARM error body."""
    status_code, reason, headers, request = 409, "Conflict", {}, None

    def __init__(self, body):
        self._body = json.dumps(body)

    def text(self, encoding=None):
        return self._body

    def body(self):
        return self._body.encode()


@needs_sdk
def test_azure_core_parses_the_refusal_code_the_classifier_reads():
    from azure.core.exceptions import ResourceExistsError

    status, code, message = REFUSALS["policy_insights_409"]
    exc = ResourceExistsError(response=_Arm409({"error": {"code": code, "message": message}}))
    assert (exc.status_code, exc.error.code) == (409, "AuthorizationFailed")
    assert fx.is_not_authorized(exc)
    assert fx.refusal_reason(exc) == (
        "Policy Insights refused the read (AuthorizationFailed) on Microsoft.Web/sites/config/read")


def _refused_reads(answers, calls):
    def per_resource(resource, resource_id, query_options):
        calls.append(resource_id.rsplit("/", 1)[-1])
        answer = answers[resource_id.rsplit("/", 1)[-1]].pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer
    return per_resource


@needs_sdk
def test_systematic_refusal_stops_the_retries(monkeypatch):
    sleeps = []
    monkeypatch.setattr(fx.time, "sleep", sleeps.append)
    refusal = REFUSALS["standard_403"]
    apps = [f"{RG}/providers/Microsoft.Web/sites/app{i}" for i in range(4)]
    # app0 is refused on its retry too, so app1..app3 are marked without a retry or a sleep.
    answers = {f"app{i}": [_ArmError(*refusal), _ArmError(*refusal)] for i in range(4)}
    calls = []
    client = fake_client(policy_states={"list_query_results_for_resource": _refused_reads(answers, calls)})
    states = [state(app) for app in apps]
    out = fx.collect_evaluation_details(client, states, 10, fx.Collector(logging.getLogger("t")))
    assert sorted(calls) == ["app0", "app0", "app1", "app2", "app3"]
    assert sleeps == [fx.REFUSAL_RETRY_SECONDS]
    assert out["not_authorized"] == 4


@needs_sdk
def test_refusal_retries_are_capped_per_run(monkeypatch):
    sleeps = []
    monkeypatch.setattr(fx.time, "sleep", sleeps.append)
    refusal = REFUSALS["policy_insights_409"]
    apps = [f"{RG}/providers/Microsoft.Web/sites/app{i}" for i in range(5)]
    # Every first read is refused and every retry succeeds: after the cap, a refusal is not retried.
    answers = {f"app{i}": [_ArmError(*refusal), _detail_rows(app)] for i, app in enumerate(apps)}
    calls = []
    client = fake_client(policy_states={"list_query_results_for_resource": _refused_reads(answers, calls)})
    states = [state(app) for app in apps]
    out = fx.collect_evaluation_details(client, states, 10, fx.Collector(logging.getLogger("t")))
    assert len(sleeps) == fx.MAX_REFUSAL_RETRIES == 3
    assert [s["evaluation_details_status"] for s in states] == [
        "collected", "collected", "collected", "not_authorized", "not_authorized"]
    assert out["not_authorized"] == 2


@needs_sdk
@pytest.mark.parametrize("answers, exit_code, expected", [
    (lambda: [_ArmError(*REFUSALS["standard_403"]), _ArmError(*REFUSALS["standard_403"])], 0, "not_authorized"),
    (lambda: [_ArmError(503, "ServiceUnavailable", "Try again.")], 1, "failed"),
    (lambda: [_ArmError(*REFUSALS["standard_403"]), _ArmError(503, "ServiceUnavailable", "Try again.")], 1,
     "failed"),
], ids=["refusal_alone", "server_error", "refusal_then_server_error"])
def test_main_exit_code_for_a_refused_or_failed_detail_read(monkeypatch, tmp_path, answers, exit_code, expected):
    monkeypatch.setattr(fx, "load_dotenv", lambda: None)
    monkeypatch.setattr(fx, "REFUSAL_RETRY_SECONDS", 0)
    for env in (fx.MAX_NON_COMPLIANT_ENV, fx.MAX_DETAIL_RESOURCES_ENV, fx.MAX_RECURRENCE_PAIRS_ENV,
                fx.MAX_REMEDIATION_DEPLOYMENTS_ENV):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setattr(fx, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(fx, "credential", lambda: object())
    monkeypatch.setattr(fx, "provider_registration_status", lambda *a: "registered")

    queued = answers()

    def refused_read(resource, resource_id, query_options):
        raise queued.pop(0)

    def collect(subscription_id, cred, collector, limits, exclusions=None):
        collected = fx.empty_collection()
        collected["states"] = [state(APP)]
        collected["details"] = fx.collect_evaluation_details(
            fake_client(policy_states={"list_query_results_for_resource": refused_read}),
            collected["states"], limits["detail_resources"], collector)
        return collected

    monkeypatch.setattr(fx, "collect_compliance", collect)
    assert fx.main() == exit_code
    payload = json.loads((tmp_path / "azure_policy_compliance_s1.json").read_text())
    assert payload["metadata"]["partial_failure"] is bool(exit_code)
    assert (tmp_path / "status.json").exists() is bool(exit_code)
    assert payload["results"]["non_compliant_states"][0]["evaluation_details_status"] == expected
    assert queued == []


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
    out = fx.collect_recurrence(client, "s1", 0, fx.Collector(logging.getLogger("t")), now=NOW)
    # 0 reads no pair, which is not truncation.
    assert out["history_truncated"] is True and out["pairs_truncated"] is False


@needs_sdk
def test_failed_history_read_is_null_not_zero():
    def query(resource, subscription_id, query_options):
        if (query_options.apply or "").endswith("/aggregate($count as n)"):
            return [NS(additional_properties={"n": 3})]
        raise RuntimeError("throttled")

    client = fake_client(policy_states={"list_query_results_for_subscription": query})
    collector = fx.Collector(logging.getLogger("t"))
    out = fx.collect_recurrence(client, "s1", 5, collector, now=NOW)
    assert out["history_collected"] is False and len(collector.failures) == 1
    summary = fx.summarize_recurrence(out["pairs"], out["records"], out["history_truncated"],
                                      out["pairs_truncated"], out["history_collected"])
    assert summary["history_collected"] is False
    for key in ("history_non_compliant_pairs", "history_persistently_non_compliant_pairs",
                "history_intermittently_non_compliant_pairs", "history_truncated", "recurrence_pairs_read",
                "recurrence_pairs_truncated", "recurring_non_compliant_pairs", "max_non_compliant_episodes"):
        assert summary[key] is None, key
    assert summary["recurrence_window_days"] == 30


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


def test_remediated_counts_are_per_resource_and_the_latest_deployment_decides():
    current = fx.latest_states_by_resource([
        {"resource_id": VM, "compliance_state": "NonCompliant", "timestamp": "2026-10-19T09:00:00Z"},
        {"resource_id": NSG, "compliance_state": "NonCompliant", "timestamp": "2026-10-19T09:00:00Z"},
    ])
    task = {"id": "t", "policy_assignment_id": ASSIGN}
    deployed = [
        (VM, "Failed", "2026-10-01T00:00:00Z"), (VM.upper(), "Succeeded", "2026-10-05T00:00:00Z"),
        (VM, "Succeeded", "2026-10-10T00:00:00Z"),
        (NSG, "Succeeded", "2026-10-02T00:00:00Z"), (NSG, "Failed", "2026-10-12T00:00:00Z"),
    ]
    rows = [fx.deployment_record({"remediated_resource_id": rid, "status": status, "last_updated_on": at},
                                 task, current) for rid, status, at in deployed]
    summary = fx.summarize_remediation_deployments(rows, truncated=False)
    assert (summary["remediation_deployments_listed"], summary["remediated_resources_listed"]) == (5, 2)
    assert summary["remediation_deployments_by_status"] == {"Failed": 2, "Succeeded": 3}
    # Both resources are non-compliant now; only the VM's latest deployment succeeded.
    assert (summary["remediated_resources_now_non_compliant"],
            summary["succeeded_remediations_now_non_compliant"]) == (2, 1)


@needs_sdk
def test_collect_remediation_deployments_uses_the_task_scope_and_the_limit(monkeypatch):
    listed = []

    def deployment(rid):
        return NS(remediated_resource_id=rid, deployment_id=None, status="Succeeded", resource_location=None,
                  error=None, created_on=None, last_updated_on=None)

    def at_subscription(name):
        listed.append(("subscription", name))
        return [deployment(VM), deployment(NSG)]

    def at_resource_group(rg, name):
        listed.append(("resource_group", rg, name))
        return [deployment(VM.upper())]

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
    monkeypatch.setattr(fx, "RESOURCE_FILTER_BATCH", 1)
    collector = fx.Collector(logging.getLogger("t"))
    rows, truncated, _ = fx.collect_remediation_deployments(client, "s1", tasks, 10, collector)
    assert listed == [("subscription", "t1"), ("resource_group", "rg1", "t2"), ("subscription", "t3")]

    def query(ref, *resources):
        return (f"PolicyAssignmentId eq '{ASSIGN.lower()}' and PolicyDefinitionReferenceId eq '{ref}' and ("
                + " or ".join(f"ResourceId eq '{r.lower()}'" for r in resources) + ")")

    # One batch per resource here. t2 re-remediates t1's VM on the same policy (its reference id
    # differs only in case), so it reads nothing new; t3's policy is read again.
    assert filters == [query("r1", VM), query("r1", NSG), query("r2", VM), query("r2", NSG)]
    assert [(r["remediated_resource_id"], r["now_compliant"]) for r in rows][:2] == [(VM, True), (NSG, None)]
    assert truncated is False

    filters.clear()
    monkeypatch.setattr(fx, "RESOURCE_FILTER_BATCH", 20)
    fx.collect_remediation_deployments(client, "s1", tasks[:1], 10, fx.Collector(logging.getLogger("t")))
    assert filters == [query("r1", VM, NSG)]

    listed.clear()
    rows, truncated, _ = fx.collect_remediation_deployments(client, "s1", tasks, 1, collector)
    assert len(rows) == 1 and truncated is True
    assert listed == [("subscription", "t1")]

    # 0 skips them: nothing is listed and nothing reads as truncated.
    listed.clear()
    assert fx.collect_remediation_deployments(client, "s1", tasks, 0, fx.Collector(logging.getLogger("t"))) == (
        [], False, [])
    assert listed == []


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
    rows, truncated, _ = fx.collect_remediation_deployments(client, "s1", tasks, 10, collector)
    assert listed == [("management_group", "mg1", "t3"), ("resource", NSG.lstrip("/"), "t4")]
    assert [(r["remediation_task_id"].rsplit("/", 1)[-1], r["error_code"], r["now_compliant"]) for r in rows] == [
        ("t3", "Denied", None), ("t4", "Denied", None)]
    assert truncated is False and collector.ok


# --- in-scope recount ---

def test_in_scope_compliance_recounts_initiative_members_and_falls_back_to_the_evaluated_effect():
    record = fx.assignment_record({
        "policy_assignment_id": ASSIGN, "policy_set_definition_id": "/providers/x/policySetDefinitions/s1",
        "results": {"non_compliant_resources": 3, "non_compliant_policies": 2,
                    "resource_details": {"NonCompliant": 3, "Compliant": 1}},
        "policy_definitions": [
            {"policy_definition_id": DEF, "policy_definition_reference_id": "R1", "effect": "deny",
             "results": {"non_compliant_resources": 3}},
            {"policy_definition_id": DEF, "policy_definition_reference_id": "r2", "effect": "audit",
             "results": {"non_compliant_resources": 1}},
        ],
    })
    rows = [{**state(VM, assignment=ASSIGN.upper()), "policy_definition_action": "deny"},
            {**state(NSG), "policy_definition_action": "deny"},
            {**state(NSG, ref="r3"), "policy_definition_action": "modify"}]
    service = {"non_compliant_resources": 3, "non_compliant_policies": 2, "resource_details": {"NonCompliant": 3}}
    results, (rebuilt,) = fx.in_scope_compliance(service, [record], rows, known=True)
    # r2's only non-compliant resource is out of scope; r3 is not in the service's list, so its evaluated effect is used.
    assert [(m["policy_definition_reference_id"], m["effect"], m["non_compliant_resources"])
            for m in rebuilt["non_compliant_member_policies"]] == [("R1", "deny", 2), ("r3", "modify", 1)]
    assert (rebuilt["non_compliant_resources"], rebuilt["non_compliant_policies"], rebuilt["is_compliant"],
            rebuilt["member_policy_count"], rebuilt["compliance_percentage"]) == (2, 2, False, 2, None)
    assert (results["non_compliant_resources"], results["non_compliant_policies"], results["resource_details"]) == (
        2, 2, {"NonCompliant": 2})
    results, (unknown,) = fx.in_scope_compliance(service, [record], rows, known=False)
    assert (results["non_compliant_resources"], unknown["is_compliant"], unknown["non_compliant_member_policies"]) == (
        None, None, None)


# --- wiring ---

def test_main_writes_the_new_results_and_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(fx, "load_dotenv", lambda: None)
    for env in (fx.MAX_NON_COMPLIANT_ENV, fx.MAX_DETAIL_RESOURCES_ENV, fx.MAX_REMEDIATION_DEPLOYMENTS_ENV):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv(fx.MAX_RECURRENCE_PAIRS_ENV, "7")
    monkeypatch.setattr(fx, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(fx, "credential", lambda: object())
    monkeypatch.setattr(fx, "provider_registration_status", lambda *a: "registered")
    seen = {}

    def collect(subscription_id, cred, collector, limits, exclusions=None):
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
                "remediation_deployments_truncated", "succeeded_remediations_now_non_compliant",
                "remediated_resources_listed", "evaluation_details_not_authorized_resources"):
        assert key in summary
    # Nothing was read, so the history counts are unknown rather than 0.
    assert summary["history_collected"] is False and summary["history_non_compliant_pairs"] is None
