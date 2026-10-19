"""azure_policy_assignments effect resolution and summary. Pure functions, no SDK or network."""

from __future__ import annotations

import importlib.util
import sys
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


# --- the rest of Microsoft's effect list ---

@pytest.mark.parametrize("raw, canonical, klass", [
    ("Mutate", "mutate", "enforcing"),
    ("addToNetworkGroup", "addToNetworkGroup", "enforcing"),
    ("enforceSetting", "enforceSetting", "enforcing"),
    ("DenyAction", "denyAction", "enforcing"),
    ("Manual", "manual", "audit_only"),
])
def test_documented_effects_resolve(raw, canonical, klass):
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


def test_summary_with_no_assignments_reports_zero_unresolved_members():
    summary = fx.summarize([])
    assert (summary["unresolved_member_policies"], summary["unresolved_member_policies_not_enforced"]) == (0, 0)
