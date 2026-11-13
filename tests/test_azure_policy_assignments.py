"""azure_policy_assignments effect resolution and summary. Pure functions, no SDK or network."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location(
    "azure_policy_assignments_under_test", AZURE / "policy_assignments" / "fetcher.py"
)
fx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fx)

from azure_common import classify_failure_code  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402

BUILT_IN_DEF = "/providers/Microsoft.Authorization/policyDefinitions/def-1"
BUILT_IN_SET = "/providers/Microsoft.Authorization/policySetDefinitions/set-1"
PARAM_EFFECT = "[parameters('effect')]"


def definition(effect_expression, defaults=None, members=None):
    return {"display_name": "d", "policy_type": "BuiltIn", "effect_expression": effect_expression,
            "parameter_defaults": defaults or {}, "members": members or []}


def assignment(params=None, mode="Default", definition_id=BUILT_IN_DEF, name="a1"):
    return fx.assignment_record({
        "id": f"/subscriptions/s1/providers/Microsoft.Authorization/policyAssignments/{name}",
        "name": name, "policy_definition_id": definition_id, "scope": "/subscriptions/s1",
        "enforcement_mode": mode, "parameters": params or {},
    })


def resolved(record, definition_, members=None):
    reference = fx.parse_definition_reference(record["policy_definition_id"])
    fx.apply_effects(record, fx.effects_block(record, reference, definition_, members))
    return record


def only_member(record):
    (member,) = record["policy_effects"]["members"]
    return member


# --- AuditAction ---

def test_audit_action_literal_resolves_audit_only():
    record = resolved(assignment(), definition("AuditAction"))
    member = only_member(record)
    assert (member["effect"], member["effect_source"], member["reason"]) == ("auditAction", "literal", None)
    assert record["effect_class"] == "audit_only"
    assert record["actually_enforces"] is False
    assert record["policy_effects"]["audit_member_count"] == 1


def test_audit_action_from_assignment_parameter_resolves_audit_only():
    record = resolved(
        assignment(params={"effect": "AuditAction"}),
        definition(PARAM_EFFECT, defaults={"effect": "DenyAction"}),
    )
    member = only_member(record)
    assert (member["effect"], member["effect_source"]) == ("auditAction", "assignment_parameter")
    assert record["effect_class"] == "audit_only"
    assert record["policy_effects"]["status"] == "resolved"


def test_audit_action_definition_default_resolves():
    record = resolved(assignment(), definition(PARAM_EFFECT, defaults={"effect": "auditaction"}))
    assert (only_member(record)["effect"], only_member(record)["effect_source"]) == (
        "auditAction", "definition_default")


def test_audit_action_assignment_is_not_counted_unresolved():
    record = resolved(assignment(params={"effect": "AuditAction"}), definition(PARAM_EFFECT))
    summary = fx.summarize([record])
    assert summary["unresolved_effect_assignments"] == 0
    assert summary["audit_effect_only_assignments"] == 1
    assert summary["member_policy_effect_counts"]["auditAction"] == 1
    assert summary["member_policy_effect_counts"]["unresolved"] == 0


def test_audit_action_initiative_member_through_initiative_parameter():
    member_def = definition(PARAM_EFFECT)
    initiative = definition(None, defaults={"memberEffect": "AuditAction"}, members=[
        {"reference_id": "r1", "policy_definition_id": BUILT_IN_DEF,
         "parameters": {"effect": "[parameters('memberEffect')]"}},
    ])
    members = [{**initiative["members"][0], "definition": member_def}]
    record = resolved(assignment(definition_id=BUILT_IN_SET), initiative, members)
    assert (only_member(record)["effect"], only_member(record)["effect_source"]) == (
        "auditAction", "initiative_default")


# Direct when `passed` is None; otherwise an initiative member the initiative passes `passed` to.
@pytest.mark.parametrize("params, effect_expression, passed, expected", [
    ({}, PARAM_EFFECT, {"effect": "AuditAction"}, ("auditAction", "initiative_reference", None)),
    ({}, PARAM_EFFECT, {"effect": "[if(true,'deny','audit')]"},
     ("unresolved", None, "initiative passes an expression, not a parameter")),
    ({"memberEffect": "AuditAction"}, PARAM_EFFECT, {"effect": "[parameters('memberEffect')]"},
     ("auditAction", "assignment_parameter", None)),
    ({}, None, None, ("unresolved", None, "effect is not a literal or a parameter reference")),
    ({"Effect": "AuditAction"}, "[Parameters('EFFECT')]", None, ("auditAction", "assignment_parameter", None)),
], ids=["initiative_passes_literal", "initiative_passes_expression", "initiative_parameter_from_assignment",
        "no_effect_expression", "mixed_case_parameter_names"])
def test_resolution_paths(params, effect_expression, passed, expected):
    if passed is None:
        record = resolved(assignment(params=params), definition(effect_expression))
    else:
        initiative = definition(None, members=[
            {"reference_id": "r1", "policy_definition_id": BUILT_IN_DEF, "parameters": passed},
        ])
        members = [{**initiative["members"][0], "definition": definition(effect_expression)}]
        record = resolved(assignment(params=params, definition_id=BUILT_IN_SET), initiative, members)
    member = only_member(record)
    assert (member["effect"], member["effect_source"], member["reason"]) == expected


# --- unknown values carry a reason ---

def test_unknown_assignment_value_is_unresolved_with_reason():
    record = resolved(assignment(params={"effect": "SomethingNew"}), definition(PARAM_EFFECT))
    member = only_member(record)
    assert member["effect"] == "unresolved"
    assert member["effect_source"] is None
    assert member["reason"] == "unknown effect value 'SomethingNew'"
    assert record["effect_class"] == "unresolved"


def test_unknown_literal_is_unresolved_with_reason():
    member = only_member(resolved(assignment(), definition("EnforceRegoPolicy")))
    assert (member["effect"], member["reason"]) == ("unresolved", "unknown effect value 'EnforceRegoPolicy'")


def test_unknown_value_passed_by_initiative_is_unresolved_with_reason():
    initiative = definition(None, members=[
        {"reference_id": "r1", "policy_definition_id": BUILT_IN_DEF, "parameters": {"effect": "Bogus"}},
    ])
    members = [{**initiative["members"][0], "definition": definition(PARAM_EFFECT)}]
    member = only_member(resolved(assignment(definition_id=BUILT_IN_SET), initiative, members))
    assert (member["effect"], member["reason"]) == ("unresolved", "unknown effect value 'Bogus'")


def test_non_string_value_is_unresolved_with_reason():
    member = only_member(resolved(assignment(params={"effect": None}), definition(PARAM_EFFECT)))
    assert (member["effect"], member["reason"]) == ("unresolved", "unknown effect value None")


def test_expression_effect_keeps_its_own_reason():
    member = only_member(resolved(assignment(), definition("[if(true, 'deny', 'audit')]")))
    assert member["reason"] == "effect is not a literal or a parameter reference"


# --- other effects: from Microsoft's effects reference or used by built-in definitions ---

@pytest.mark.parametrize("raw, canonical, klass", [
    ("Mutate", "mutate", "enforcing"),
    ("addToNetworkGroup", "addToNetworkGroup", "enforcing"),
    ("enforceSetting", "enforceSetting", "enforcing"),
    ("DenyAction", "denyAction", "enforcing"),
    ("Manual", "manual", "audit_only"),
])
def test_other_effects_resolve(raw, canonical, klass):
    record = resolved(assignment(), definition(raw))
    assert only_member(record)["effect"] == canonical
    assert record["effect_class"] == klass


# --- unresolved members in the summary ---

def _initiative_with(effects, mode):
    initiative = definition(None, members=[
        {"reference_id": f"r{i}", "policy_definition_id": BUILT_IN_DEF, "parameters": {}}
        for i in range(len(effects))
    ])
    members = [{**m, "definition": definition(e)} for m, e in zip(initiative["members"], effects)]
    return resolved(assignment(mode=mode, definition_id=BUILT_IN_SET, name=f"a-{mode}"), initiative, members)


def test_summary_counts_unresolved_members_and_those_under_do_not_enforce():
    held_back = _initiative_with(["audit", "Unknown1", "Unknown2"], "DoNotEnforce")
    enforced = _initiative_with(["deny", "Unknown3"], "Default")
    assert held_back["effect_class"] == "audit_only"
    assert held_back["policy_effects"]["status"] == "partial"
    summary = fx.summarize([held_back, enforced])
    assert summary["unresolved_effect_assignments"] == 0
    assert summary["unresolved_member_policies"] == 3
    assert summary["member_policy_effect_counts"]["unresolved"] == 3
    assert summary["unresolved_member_policies_not_enforced"] == 2
    # The per-assignment fields still read as holding nothing back; only the summary key shows the gap.
    assert held_back["enforcing_effects_not_enforced"] is False
    assert summary["enforcing_effects_not_enforced_assignments"] == 0


def test_unreadable_do_not_enforce_initiative_counts_no_members():
    record = resolved(assignment(mode="DoNotEnforce", definition_id=BUILT_IN_SET), None, [])
    assert (record["effect_class"], record["policy_effects"]["member_count"]) == ("unresolved", 0)
    summary = fx.summarize([record])
    assert summary["unresolved_effect_assignments"] == 1
    assert (summary["unresolved_member_policies"], summary["unresolved_member_policies_not_enforced"]) == (0, 0)


def test_summary_with_no_assignments_reports_zero_unresolved_members():
    summary = fx.summarize([])
    assert (summary["unresolved_member_policies"], summary["unresolved_member_policies_not_enforced"]) == (0, 0)


def test_unlisted_assignments_summarize_as_null_not_zero():
    summary = fx.summarize(None)
    assert summary.keys() == fx.summarize([]).keys()
    assert all(v is None for v in summary.values())


# --- policy exemptions ---

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
SUB = "/subscriptions/s1"
EXEMPT = "/providers/Microsoft.Authorization/policyExemptions"
RG_OUT = f"{SUB}/resourceGroups/rg-out"
ACCOUNT = f"{SUB}/resourceGroups/rg-in/providers/Microsoft.Storage/storageAccounts/sa1"
MG = "/providers/Microsoft.Management/managementGroups/mg1"


def wire_exemption(name="e1", scope=SUB, assignment_name="a1", category="Waiver", expires=None, references=None,
                   **extra):
    return {
        "id": f"{scope}{EXEMPT}/{name}", "name": name, "type": "Microsoft.Authorization/policyExemptions",
        "properties": {
            "policyAssignmentId": f"{SUB}/providers/Microsoft.Authorization/policyAssignments/{assignment_name}",
            "policyDefinitionReferenceIds": references or [], "exemptionCategory": category,
            "displayName": f"Exempt {name}", "description": "approved", "expiresOn": expires,
            "metadata": {"ticketRef": "T-1"}, **extra,
        },
        "systemData": {"createdBy": "user@example.com", "createdByType": "User",
                       "createdAt": "2026-05-01T00:00:00Z"},
    }


def initiative_assignment(effects, mode="Default", name="a1"):
    record = _initiative_with(effects, mode)
    record.update(id=f"{SUB}/providers/Microsoft.Authorization/policyAssignments/{name}", name=name)
    return record


def exemption(wire, assignments=(), unread=False, now=NOW):
    by_id = None if unread else {a["id"].lower(): a for a in assignments}
    return fx.exemption_record(fx.project_policy_exemption(wire), by_id, now)


def test_projection_reads_the_wire_shape():
    projected = fx.project_policy_exemption(wire_exemption(
        references=["r1"], resourceSelectors=[{"name": "s", "selectors": []}], assignmentScopeValidation="Default"))
    assert projected["policy_definition_reference_ids"] == ["r1"]
    assert projected["exemption_category"] == "Waiver"
    assert projected["metadata"] == {"ticketRef": "T-1"}
    assert projected["resource_selectors"] == [{"name": "s", "selectors": []}]
    assert (projected["created_by"], projected["created_by_type"]) == ("user@example.com", "User")


@pytest.mark.parametrize("scope, kind", [
    (SUB, "subscription"), (RG_OUT, "resource_group"), (ACCOUNT, "resource"), (MG, "management_group"),
])
def test_scope_comes_from_the_exemption_id(scope, kind):
    record = exemption(wire_exemption(scope=scope))
    assert (record["scope"], record["scope_kind"]) == (scope, kind)
    assert record["inherited_from_management_group"] is (kind == "management_group")


def test_scope_split_ignores_case():
    assert fx.exemption_scope(f"{RG_OUT}/providers/microsoft.authorization/POLICYEXEMPTIONS/e1") == RG_OUT
    assert fx.exemption_scope("/not/an/exemption") is None


@pytest.mark.parametrize("expires, expired, no_expiry, days", [
    ("2026-06-11T00:00:00Z", False, False, 10),
    ("2026-05-31T00:00:00.0000000Z", True, False, -1),
    (None, False, True, None),
    ("not a date", None, False, None),
], ids=["active", "expired_seven_digit_fraction", "no_expiry", "unreadable"])
def test_expiry_flags(expires, expired, no_expiry, days):
    record = exemption(wire_exemption(expires=expires))
    assert (record["expired"], record["no_expiry"], record["days_until_expiry"]) == (expired, no_expiry, days)


def test_partial_exemption_joins_members_and_lifts_a_deny():
    target = initiative_assignment(["deny", "audit"])
    record = exemption(wire_exemption(references=["R0"]), [target])
    assert record["exempts_whole_assignment"] is False
    assert record["exempted_member_count"] == 1
    (member,) = record["exempted_members"]
    assert (member["reference_id"], member["effect"]) == ("R0", "deny")
    assert record["lifts_enforcement"] is True


def test_partial_exemption_of_an_audit_member_lifts_nothing():
    record = exemption(wire_exemption(references=["r1"]), [initiative_assignment(["deny", "audit"])])
    assert record["lifts_enforcement"] is False


def test_unknown_member_reference_leaves_the_lift_unknown():
    record = exemption(wire_exemption(references=["r1", "gone"]), [initiative_assignment(["deny", "audit"])])
    assert record["exempted_members"][1]["effect"] is None
    assert record["lifts_enforcement"] is None


def test_do_not_enforce_assignment_has_nothing_to_lift():
    record = exemption(wire_exemption(), [initiative_assignment(["deny"], mode="DoNotEnforce")])
    assert record["lifts_enforcement"] is False


def test_whole_assignment_exemption_counts_every_member():
    record = exemption(wire_exemption(), [initiative_assignment(["deny", "audit", "audit"])])
    assert (record["exempts_whole_assignment"], record["exempted_member_count"]) == (True, 3)
    assert record["exempted_members"] == []
    assert record["lifts_enforcement"] is True


def test_assignment_not_listed_is_false_and_unread_is_unknown():
    missing = exemption(wire_exemption(assignment_name="other"), [initiative_assignment(["deny"])])
    assert (missing["assignment_found"], missing["lifts_enforcement"]) == (False, None)
    unread = exemption(wire_exemption(), unread=True)
    assert (unread["assignment_found"], unread["lifts_enforcement"]) == (None, None)


def test_defender_benchmark_exemption_is_flagged():
    record = exemption(wire_exemption(assignment_name="SecurityCenterBuiltIn"))
    assert record["on_defender_benchmark_assignment"] is True
    assert exemption(wire_exemption())["on_defender_benchmark_assignment"] is False


def test_summary_counts_exemptions():
    target = initiative_assignment(["deny", "audit"])
    records = [
        exemption(wire_exemption("e1", expires="2026-06-11T00:00:00Z", references=["r0"]), [target]),
        exemption(wire_exemption("e2", category="Mitigated", scope=RG_OUT), [target]),
        exemption(wire_exemption("e3", expires="2026-01-01T00:00:00Z", scope=MG), [target]),
        exemption(wire_exemption("e4", assignment_name="SecurityCenterBuiltIn", expires="2027-01-01T00:00:00Z"),
                  [target]),
    ]
    summary = fx.summarize_exemptions(records, fx.EXEMPTIONS_READ)
    assert summary["exemptions_read_status"] == "read"
    assert summary["exemptions_api_version"] == "2024-12-01-preview"
    assert (summary["total_policy_exemptions"], summary["waiver_exemptions"], summary["mitigated_exemptions"]) == (
        4, 3, 1)
    assert (summary["active_exemptions"], summary["expired_exemptions"], summary["exemptions_without_expiry"]) == (
        3, 1, 1)
    assert summary["exemptions_expiring_within_30_days"] == 1
    assert summary["whole_assignment_exemptions"] == 3
    assert summary["inherited_exemptions"] == 1
    assert summary["exemptions_by_scope_kind"] == {
        "management_group": 1, "subscription": 2, "resource_group": 1, "resource": 0, "unknown": 0}
    assert summary["defender_benchmark_exemptions"] == 1
    # e1 (the deny member) and e2 (whole) are active and lift the deny; e3 expired; e4's assignment isn't listed.
    assert summary["active_exemptions_lifting_enforcement"] == 2
    assert summary["exemptions_lifting_enforcement_unknown"] == 1
    assert summary["exemptions_of_unlisted_assignments"] == 1
    assert summary["unlisted_assignments_with_exemptions"] == 1
    assert summary["assignments_with_exemptions"] == 1
    assert summary["exemptions_naming_members_not_in_initiative"] == 0


@pytest.mark.parametrize("raw, canonical", [("waiver", "Waiver"), ("MITIGATED", "Mitigated"), ("Other", "Other")])
def test_category_is_matched_without_regard_to_case(raw, canonical):
    record = exemption(wire_exemption(category=raw))
    assert record["exemption_category"] == canonical
    summary = fx.summarize_exemptions([record], fx.EXEMPTIONS_READ)
    assert (summary["waiver_exemptions"], summary["mitigated_exemptions"]) == (
        int(canonical == "Waiver"), int(canonical == "Mitigated"))


def test_member_missing_from_the_initiative_is_flagged_and_leaves_the_lift_unknown():
    record = exemption(wire_exemption(references=["retired-member"]), [initiative_assignment(["deny", "audit"])])
    (member,) = record["exempted_members"]
    assert (member["in_initiative"], member["effect"]) == (False, None)
    assert record["names_members_not_in_initiative"] is True
    assert (record["lifts_enforcement"], record["lifts_enforcement_unknown_reason"]) == (
        None, "member_not_in_initiative")
    summary = fx.summarize_exemptions([record], fx.EXEMPTIONS_READ)
    assert summary["exemptions_naming_members_not_in_initiative"] == 1


def test_member_found_in_the_initiative_is_marked_so():
    record = exemption(wire_exemption(references=["r1"]), [initiative_assignment(["deny", "audit"])])
    assert record["exempted_members"][0]["in_initiative"] is True
    assert (record["lifts_enforcement"], record["lifts_enforcement_unknown_reason"]) == (False, None)


def test_unreadable_initiative_leaves_membership_unknown():
    target = resolved(assignment(definition_id=BUILT_IN_SET), None, [])
    record = exemption(wire_exemption(references=["r0"]), [target])
    assert record["exempted_members"][0]["in_initiative"] is None
    assert record["names_members_not_in_initiative"] is False
    assert (record["lifts_enforcement"], record["lifts_enforcement_unknown_reason"]) == (
        None, "initiative_members_unread")


def test_unresolved_member_effect_gives_its_reason():
    record = exemption(wire_exemption(references=["r0"]), [initiative_assignment(["SomethingNew"])])
    assert (record["lifts_enforcement"], record["lifts_enforcement_unknown_reason"]) == (None, "effect_unresolved")


def test_unknown_lift_names_the_missing_assignment():
    missing = exemption(wire_exemption(assignment_name="gone"), [initiative_assignment(["deny"])])
    assert missing["lifts_enforcement_unknown_reason"] == "assignment_not_listed"
    unread = exemption(wire_exemption(), unread=True)
    assert unread["lifts_enforcement_unknown_reason"] == "assignments_unread"


def test_unlisted_assignments_are_counted_once_each():
    target = initiative_assignment(["deny"])
    records = [exemption(wire_exemption(f"e{i}", assignment_name=name), [target])
               for i, name in enumerate(["gone1", "gone1", "GONE1", "gone2", "a1"])]
    summary = fx.summarize_exemptions(records, fx.EXEMPTIONS_READ)
    assert (summary["exemptions_of_unlisted_assignments"], summary["unlisted_assignments_with_exemptions"]) == (4, 2)


@pytest.mark.parametrize("status", ["failed", "api_version_unavailable", "not_read"])
def test_unread_exemptions_summarize_as_null_not_zero(status):
    summary = fx.summarize_exemptions(None, status)
    assert summary["exemptions_read_status"] == status
    counts = {k: v for k, v in summary.items() if k not in ("exemptions_read_status", "exemptions_api_version")}
    assert counts and all(v is None for v in counts.values())


def test_unlisted_assignment_count_is_null_when_assignments_were_unread():
    summary = fx.summarize_exemptions([exemption(wire_exemption(), unread=True)], fx.EXEMPTIONS_READ)
    assert summary["total_policy_exemptions"] == 1
    assert (summary["exemptions_of_unlisted_assignments"], summary["assignments_with_exemptions"],
            summary["unlisted_assignments_with_exemptions"]) == (None, None, None)


def test_lifting_count_is_null_when_assignments_were_unread():
    records = [exemption(wire_exemption(f"e{i}", expires="2026-06-11T00:00:00Z"), unread=True) for i in range(2)]
    summary = fx.summarize_exemptions(records, fx.EXEMPTIONS_READ)
    assert (summary["active_exemptions"], summary["exemptions_lifting_enforcement_unknown"]) == (2, 2)
    assert summary["active_exemptions_lifting_enforcement"] is None


def test_assignment_exemption_count_is_null_when_unread():
    target = initiative_assignment(["deny"])
    other = initiative_assignment(["deny"], name="a2")
    fx.apply_exemption_counts([target, other], [exemption(wire_exemption("e1"), [target]),
                                                exemption(wire_exemption("e2"), [target])])
    assert (target["exemption_count"], other["exemption_count"]) == (2, 0)
    fx.apply_exemption_counts([target], None)
    assert target["exemption_count"] is None


# --- resource_exclusions: an exemption follows the scope it was made at ---

def _split(patterns, wires):
    exclusions = ResourceExclusions(patterns)
    projected = [fx.project_policy_exemption(w) for w in wires]
    records, excluded = fx.exemption_results(projected, [], exclusions, NOW)
    return exclusions, records, excluded


def test_rg_pattern_excludes_an_exemption_made_in_that_group_only():
    exclusions, records, excluded = _split(["rg:RG-OUT"], [
        wire_exemption("in-sub"), wire_exemption("in-rg", scope=RG_OUT)])
    assert [r["name"] for r in records] == ["in-sub"]
    (entry,) = excluded
    assert (entry["kind"], entry["name"], entry["pattern"], entry["resource_group"]) == (
        "policy_exemption", "in-rg", "rg:RG-OUT", "rg-out")
    summary = fx.boundary_summary(exclusions, excluded, records)
    assert (summary["excluded_policy_exemptions"], summary["in_scope_policy_exemptions"]) == (1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == []


def test_id_pattern_excludes_an_exemption_on_that_resource():
    _, records, excluded = _split([f"id:{ACCOUNT}"], [wire_exemption("on-sa", scope=ACCOUNT), wire_exemption("sub")])
    assert [r["name"] for r in records] == ["sub"]
    assert [e["name"] for e in excluded] == ["on-sa"]


def test_location_pattern_never_matches_an_exemption():
    exclusions, records, excluded = _split(["location:*"], [wire_exemption("e1", scope=RG_OUT)])
    assert (len(records), excluded) == (1, [])
    assert fx.boundary_summary(exclusions, excluded, records)["resource_exclusion_patterns_unmatched"] == [
        "location:*"]


def test_no_patterns_keep_every_exemption():
    exclusions, records, excluded = _split([], [wire_exemption("e1", scope=RG_OUT), wire_exemption("e2")])
    assert (len(records), excluded) == (2, [])
    summary = fx.boundary_summary(exclusions, excluded, records)
    assert (summary["resource_exclusion_patterns"], summary["excluded_policy_exemptions"]) == ([], 0)


def test_unread_exemptions_leave_the_boundary_counts_null():
    exclusions = ResourceExclusions(["rg:rg-out"])
    records, excluded = fx.exemption_results(None, [], exclusions, NOW)
    summary = fx.boundary_summary(exclusions, excluded, records)
    assert (records, summary["excluded_policy_exemptions"], summary["in_scope_policy_exemptions"]) == (
        None, None, None)


def test_bad_pattern_fails_the_run_as_bad_config():
    collector = fx.Collector(fx.logger)
    ResourceExclusions(["rg-out"]).record_invalid(collector)
    assert not collector.ok
    assert classify_failure_code(collector.failures) == "bad_config"


# --- reading the list ---

class _HttpError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status_code = status


def _collect(monkeypatch, outcome):
    def list_all(client, path, api_version):
        assert (path, api_version) == (f"{SUB}{EXEMPT}", "2024-12-01-preview")
        if isinstance(outcome, Exception):
            raise outcome
        return {"items": outcome, "pages": 1}

    monkeypatch.setattr(fx, "arm_rest_client", lambda cred: object())
    monkeypatch.setattr(fx, "list_all", list_all)
    collector = fx.Collector(fx.logger)
    return fx.collect_policy_exemptions("s1", object(), collector), collector


def test_list_reads_every_exemption(monkeypatch):
    (projected, status), collector = _collect(monkeypatch, [wire_exemption("e1"), wire_exemption("e2")])
    assert (status, [p["name"] for p in projected], collector.ok) == ("read", ["e1", "e2"], True)


@pytest.mark.parametrize("status_code, message", [
    (400, "(InvalidApiVersionParameter) The api-version is invalid."),
    (400, "(NoRegisteredProviderFound) No registered resource provider found for this api version."),
    (404, "(InvalidResourceType) The resource type could not be found for api version."),
])
def test_refused_api_version_is_unavailable_and_a_recorded_failure(monkeypatch, status_code, message):
    (projected, status), collector = _collect(monkeypatch, _HttpError(status_code, message))
    assert (projected, status, collector.ok) == (None, "api_version_unavailable", False)
    assert classify_failure_code(collector.failures) == "partial_failure"


def test_refusal_code_is_read_from_the_arm_error_body(monkeypatch):
    exc = _HttpError(400, "Operation returned an invalid status 'Bad Request'")
    exc.error = type("Err", (), {"code": "InvalidApiVersionParameter"})()
    (projected, status), collector = _collect(monkeypatch, exc)
    assert (projected, status, collector.ok) == (None, "api_version_unavailable", False)


@pytest.mark.parametrize("status_code, message", [
    (400, "(BadRequest) The request is malformed."),
    (400, "Operation returned an invalid status 'Bad Request'"),
    (404, "(SubscriptionNotFound) The subscription could not be found."),
])
def test_other_400_or_404_is_a_recorded_failure(monkeypatch, status_code, message):
    (projected, status), collector = _collect(monkeypatch, _HttpError(status_code, message))
    assert (projected, status, collector.ok) == (None, "failed", False)


def test_denied_list_is_a_recorded_failure(monkeypatch):
    (projected, status), collector = _collect(monkeypatch, _HttpError(403, "(AuthorizationFailed) denied"))
    assert (projected, status) == (None, "failed")
    assert classify_failure_code(collector.failures) == "not_authorized"


def test_failed_assignment_list_leaves_the_summary_null_and_fails_the_run(monkeypatch, tmp_path):
    def failed_list(subscription_id, cred, collector):
        collector.record("policy.policy_assignments.list", RuntimeError("list failed"))
        return None

    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.delenv("AZURE_RESOURCE_EXCLUSIONS", raising=False)
    monkeypatch.setattr(fx, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(fx, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(fx, "credential", lambda: object())
    monkeypatch.setattr(fx, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(fx, "collect_policy_assignments", failed_list)
    monkeypatch.setattr(fx, "collect_policy_exemptions", lambda *a: ([], fx.EXEMPTIONS_READ))
    assert fx.main() == 1
    evidence = json.loads((tmp_path / "azure_policy_assignments_s1.json").read_text())
    summary = evidence["summary"]
    assert all(summary[key] is None for key in fx.summarize([]))
    assert (evidence["metadata"]["partial_failure"], evidence["results"]["policy_assignments"]) == (True, [])


def test_refused_api_version_fails_the_run_and_keeps_the_reason(monkeypatch, tmp_path):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.delenv("AZURE_RESOURCE_EXCLUSIONS", raising=False)
    monkeypatch.setattr(fx, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(fx, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(fx, "credential", lambda: object())
    monkeypatch.setattr(fx, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(fx, "collect_policy_assignments", lambda *a: [])
    monkeypatch.setattr(fx, "arm_rest_client", lambda cred: object())

    def refused(*a):
        raise _HttpError(400, "(InvalidApiVersionParameter) The api-version is invalid.")

    monkeypatch.setattr(fx, "list_all", refused)
    assert fx.main() == 1
    evidence = json.loads((tmp_path / "azure_policy_assignments_s1.json").read_text())
    assert evidence["summary"]["exemptions_read_status"] == "api_version_unavailable"
    assert evidence["summary"]["active_exemptions_lifting_enforcement"] is None
    assert evidence["metadata"]["partial_failure"] is True


def test_unread_exemptions_leave_unmatched_patterns_null(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(fx, "load_dotenv", lambda: None)
    monkeypatch.setattr(fx, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(fx, "credential", lambda: object())
    monkeypatch.setattr(fx, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(fx, "collect_policy_assignments", lambda *a: [])
    monkeypatch.setattr(fx, "collect_policy_exemptions", lambda *a: (None, fx.EXEMPTIONS_NOT_READ))
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "rg:typo")
    fx.main()
    summary = json.loads((tmp_path / "azure_policy_assignments_s1.json").read_text())["summary"]
    assert summary["resource_exclusion_patterns_unmatched"] is None
    assert "matched nothing" not in caplog.text


def test_summary_fields_match_the_instructions(assert_summary_documented):
    target = initiative_assignment(["deny", "audit"])
    records = [exemption(wire_exemption("e1", references=["r0"]), [target])]
    summary = {
        **fx.summarize([target]),
        **fx.summarize_exemptions(records, fx.EXEMPTIONS_READ),
        "provider_registration_status": "registered",
        **fx.boundary_summary(ResourceExclusions([]), [], records),
    }
    assert_summary_documented("azure/policy_assignments", summary)
