"""azure_rbac_role_assignments PIM additions: standing per grant, eligibility, activation rules, and the unlicensed and denied paths."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import types
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "rbac_role_assignments" / "fetcher.py"

spec = importlib.util.spec_from_file_location("azure_rbac_role_assignments_under_test", FETCHER)
rbac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rbac)

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
OWNER = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{rbac.OWNER_ROLE_ID}"
CONTRIBUTOR = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{rbac.CONTRIBUTOR_ROLE_ID}"
UAA = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{rbac.USER_ACCESS_ADMINISTRATOR_ROLE_ID}"
RBAC_ADMIN = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{rbac.ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID}"
READER_GUID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
READER = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{READER_GUID}"
ROLE_NAMES = {
    rbac.OWNER_ROLE_ID: {"role_name": "Owner", "role_type": "BuiltInRole"},
    rbac.CONTRIBUTOR_ROLE_ID: {"role_name": "Contributor", "role_type": "BuiltInRole"},
    READER_GUID: {"role_name": "Reader", "role_type": "BuiltInRole"},
}
LATER = datetime(2027, 1, 1, tzinfo=timezone.utc)


def _grant(name, role, principal_type="User", scope=SUB):
    return rbac.assignment_record(
        rbac.project_role_assignment(ns(
            id=f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}",
            name=name, scope=scope, principal_id=f"p-{name}", principal_type=principal_type, role_definition_id=role,
        )),
        ROLE_NAMES,
    )


def _schedule(grant, assignment_type="Assigned", end=None, status="Provisioned"):
    return rbac.project_schedule_instance(ns(
        id=f"{grant['id']}-schedule", scope=grant["scope"], principal_id=grant["principal_id"],
        principal_type=grant["principal_type"], role_definition_id=grant["role_definition_id"],
        origin_role_assignment_id=grant["id"].upper(), assignment_type=assignment_type, member_type="Direct",
        status=status, start_date_time=datetime(2026, 10, 1, tzinfo=timezone.utc), end_date_time=end,
    ))


def _rule(rule_type, rule_id, **fields):
    return ns(rule_type=rule_type, id=rule_id, **fields)


def _policy(role, *, mfa=False, approval=False, permanent_active=False):
    enabled = ["Justification"] + (["MultiFactorAuthentication"] if mfa else [])
    return rbac.project_policy_assignment(ns(
        scope=SUB,
        role_definition_id=role,
        policy_id=f"{SUB}/providers/Microsoft.Authorization/roleManagementPolicies/p-{role[-4:]}",
        effective_rules=[
            _rule("RoleManagementPolicyExpirationRule", "Expiration_EndUser_Assignment",
                  is_expiration_required=True, maximum_duration="PT8H"),
            _rule("RoleManagementPolicyEnablementRule", "Enablement_EndUser_Assignment", enabled_rules=enabled),
            _rule("RoleManagementPolicyApprovalRule", "Approval_EndUser_Assignment", setting=ns(
                is_approval_required=approval, is_requestor_justification_required=True, approval_mode="SingleStage",
                approval_stages=[ns(primary_approvers=[ns()] if approval else [])],
            )),
            _rule("RoleManagementPolicyAuthenticationContextRule", "AuthenticationContext_EndUser_Assignment", is_enabled=False),
            _rule("RoleManagementPolicyExpirationRule", "Expiration_Admin_Eligibility",
                  is_expiration_required=True, maximum_duration="P365D"),
            _rule("RoleManagementPolicyExpirationRule", "Expiration_Admin_Assignment",
                  is_expiration_required=not permanent_active, maximum_duration="P180D"),
            _rule("RoleManagementPolicyNotificationRule", "Notification_Admin_Admin_Assignment"),
        ],
    ))


def test_each_grant_is_marked_from_its_schedule():
    permanent, activated, timed, outside, reader = (
        _grant("a1", OWNER), _grant("a2", OWNER), _grant("a3", CONTRIBUTOR),
        _grant("a4", OWNER, principal_type="ServicePrincipal"), _grant("a5", READER),
    )
    schedules = [_schedule(permanent), _schedule(activated, "Activated", LATER), _schedule(timed, end=LATER), _schedule(reader)]
    grants = [permanent, activated, timed, outside, reader]
    rbac.add_pim_fields(grants, schedules)

    assert [g["standing"] for g in grants] == ["permanent", "pim_activated", "time_bound", "permanent", "permanent"]
    assert outside["pim_schedule_found"] is False
    assert activated["pim_assignment_type"] == "Activated"
    assert timed["pim_end_date_time"] == LATER.isoformat()

    summary = rbac.summarize_pim(grants, True, [], None, True)
    assert summary["assignments_by_standing"] == {"permanent": 3, "pim_activated": 1, "time_bound": 1}
    assert summary["over_broad_assignments_by_standing"] == {"permanent": 2, "pim_activated": 1, "time_bound": 1}
    assert summary["permanent_over_broad_assignments"] == 2
    assert summary["permanent_over_broad_user_assignments"] == 1
    assert summary["principals_with_permanent_over_broad_access"] == 2
    assert summary["assignments_without_pim_schedule"] == 1


def test_unread_schedules_leave_standing_unknown():
    grant = _grant("a1", OWNER)
    rbac.add_pim_fields([grant], None)
    assert grant["standing"] is None
    assert grant["pim_schedule_found"] is None
    summary = rbac.summarize_pim([grant], False, None, None, None)
    assert summary["pim_available"] is None
    assert summary["permanent_over_broad_assignments"] is None
    assert summary["eligible_role_assignments"] is None
    assert summary["over_broad_roles_activation_without_mfa_or_auth_context"] is None


def test_eligible_assignments_carry_the_over_broad_flags():
    eligible = [
        rbac.eligibility_record(rbac.project_schedule_instance(ns(
            id="e1", scope=SUB, principal_id="p1", principal_type="User", role_definition_id=OWNER,
            member_type="Direct", status="Provisioned", end_date_time=LATER,
        )), ROLE_NAMES),
        rbac.eligibility_record(rbac.project_schedule_instance(ns(
            id="e2", scope=f"{SUB}/resourceGroups/rg1", principal_id="p2", principal_type="Group",
            role_definition_id=CONTRIBUTOR, member_type="Direct", status="Provisioned", end_date_time=None,
        )), ROLE_NAMES),
    ]
    assert eligible[0]["over_broad_role"] == "Owner"
    assert eligible[0]["can_grant_roles"] is True
    assert eligible[1]["scope_level"] == "resource_group"
    assert eligible[1]["is_permanent"] is True

    summary = rbac.summarize_pim([], True, eligible, [], True)
    assert summary["eligible_over_broad_assignments"] == 2
    assert summary["permanently_eligible_over_broad_assignments"] == 1
    assert summary["principals_eligible_for_over_broad_roles"] == 2


def test_activation_rules_are_read_per_over_broad_role():
    owner, contributor = rbac.policy_record(_policy(OWNER, mfa=True, approval=True)), rbac.policy_record(
        _policy(CONTRIBUTOR, permanent_active=True))
    others = [rbac.policy_record(_policy(role, mfa=True, approval=True)) for role in (UAA, RBAC_ADMIN)]
    policies = [owner, contributor, *others]

    assert owner["role_name"] == "Owner"
    assert owner["activation_requires_mfa"] is True
    assert owner["activation_requires_approval"] is True
    assert owner["activation_approver_sets"] == 1
    assert owner["activation_maximum_hours"] == 8
    assert owner["permanent_active_assignment_allowed"] is False
    assert owner["eligible_assignment_maximum_duration"] == "P365D"
    assert not any(r["id"].startswith("Notification_") for r in owner["rules"])
    assert contributor["activation_requires_mfa"] is False
    assert contributor["permanent_active_assignment_allowed"] is True

    summary = rbac.summarize_pim([], True, [], policies, True)
    assert summary["over_broad_role_policies_read"] == [
        "Contributor", "Owner", "Role Based Access Control Administrator", "User Access Administrator",
    ]
    assert summary["over_broad_roles_activation_without_mfa_or_auth_context"] == ["Contributor"]
    assert summary["over_broad_roles_activation_without_approval"] == ["Contributor"]
    assert summary["over_broad_roles_activation_without_justification"] == []
    assert summary["over_broad_roles_allowing_permanent_active_assignment"] == ["Contributor"]
    assert summary["max_over_broad_activation_hours"] == 8


def test_a_missing_over_broad_policy_leaves_the_policy_lists_unknown():
    policies = [rbac.policy_record(_policy(OWNER, mfa=True)), rbac.policy_record(_policy(CONTRIBUTOR))]
    summary = rbac.summarize_pim([], True, [], policies, True)
    assert summary["over_broad_role_policies_read"] == ["Contributor", "Owner"]
    assert summary["over_broad_roles_activation_without_mfa_or_auth_context"] is None
    assert summary["over_broad_roles_allowing_permanent_active_assignment"] is None
    assert summary["max_over_broad_activation_hours"] is None


def test_schedules_match_grants_inherited_from_above_and_made_below():
    root = _grant("r1", OWNER, scope="/")
    group = _grant("m1", CONTRIBUTOR, scope="/providers/Microsoft.Management/managementGroups/mg1")
    resource = _grant("x1", OWNER, scope=f"{SUB}/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/st1")
    grants = [root, group, resource]
    rbac.add_pim_fields(grants, [_schedule(root), _schedule(group, "Activated", LATER), _schedule(resource, end=LATER)])
    assert [g["scope_level"] for g in grants] == ["root", "management_group", "resource"]
    assert [g["standing"] for g in grants] == ["permanent", "pim_activated", "time_bound"]
    assert all(g["pim_schedule_found"] for g in grants)


def test_durations_in_hours():
    assert rbac.duration_hours("PT8H") == 8
    assert rbac.duration_hours("PT30M") == 0.5
    assert rbac.duration_hours("P1DT12H") == 36
    assert rbac.duration_hours("P1W") == 168
    assert rbac.duration_hours("P1Y2D") == (365 + 2) * 24
    assert rbac.duration_hours("eight hours") is None
    assert rbac.duration_hours(None) is None


class _Pages:
    def __init__(self, exc=None, items=()):
        self.exc, self.items = exc, list(items)

    def list_for_scope(self, scope):
        if self.exc:
            raise self.exc
        return iter(self.items)


def _fake_sdk(monkeypatch, schedules, eligible, policies):
    client = ns(role_assignment_schedule_instances=schedules, role_eligibility_schedule_instances=eligible,
                role_management_policy_assignments=policies)
    module = types.ModuleType("azure.mgmt.authorization")
    module.AuthorizationManagementClient = lambda **kwargs: client
    monkeypatch.setitem(sys.modules, "azure.mgmt.authorization", module)


class HttpResponseError(Exception):
    """Stands in for azure-core's, whose str() leads with '(<code>) <message>'."""


UNLICENSED = HttpResponseError("(AadPremiumLicenseRequired) The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.")
NOT_ONBOARDED = HttpResponseError("(TenantNotOnboarded) The tenant has not onboarded to PIM.")
DENIED = HttpResponseError("(AuthorizationFailed) The client does not have authorization to perform action.")


def test_a_tenant_without_p2_is_a_state_not_a_failure(monkeypatch):
    _fake_sdk(monkeypatch, _Pages(UNLICENSED), _Pages(UNLICENSED), _Pages(NOT_ONBOARDED))
    collector = rbac.Collector(logging.getLogger("test"))
    pim = rbac.collect_pim("sub", object(), collector, ROLE_NAMES)

    assert collector.ok
    assert pim["available"] is False
    assert pim["schedules"] == [] and pim["eligible"] == [] and pim["policies"] is None
    assert len(pim["notes"]) == 3

    grant = _grant("a1", OWNER)
    rbac.add_pim_fields([grant], pim["schedules"])
    assert grant["standing"] == "permanent"


def test_a_denied_pim_read_is_recorded_not_authorized(monkeypatch):
    owner = _grant("a1", OWNER)
    policy = ns(scope=SUB, role_definition_id=OWNER, policy_id="p", effective_rules=[])
    reader_policy = ns(scope=SUB, role_definition_id=READER, policy_id="r", effective_rules=[])
    _fake_sdk(monkeypatch, _Pages(items=[ns(**{**_schedule(owner), "status": "Provisioned"})]), _Pages(DENIED),
              _Pages(items=[policy, reader_policy]))
    collector = rbac.Collector(logging.getLogger("test"))
    pim = rbac.collect_pim("sub", object(), collector, ROLE_NAMES)

    assert not collector.ok
    assert rbac.classify_failure_code(collector.failures) == "not_authorized"
    assert pim["available"] is None
    assert pim["eligible"] is None
    assert len(pim["schedules"]) == 1
    assert [p["role_name"] for p in pim["policies"]] == ["Owner"]


@pytest.mark.parametrize("status,kept", [("Provisioned", True), (None, True), ("PendingRevocation", False)])
def test_only_provisioned_instances_count(status, kept):
    assert rbac.provisioned({"status": status}) is kept


def test_one_licence_refusal_keeps_the_reads_that_succeeded(monkeypatch):
    owner = _grant("a1", OWNER)
    timed = ns(**{**_schedule(owner, end=LATER), "status": "Provisioned"})
    _fake_sdk(monkeypatch, _Pages(items=[timed]), _Pages(UNLICENSED), _Pages(NOT_ONBOARDED))
    collector = rbac.Collector(logging.getLogger("test"))
    pim = rbac.collect_pim("sub", object(), collector, ROLE_NAMES)

    assert collector.ok
    assert pim["available"] is False
    assert len(pim["schedules"]) == 1
    assert pim["eligible"] == [] and pim["policies"] is None
    rbac.add_pim_fields([owner], pim["schedules"])
    assert owner["standing"] == "time_bound"


def test_a_licence_refusal_and_a_denial_fail_the_run(monkeypatch):
    _fake_sdk(monkeypatch, _Pages(UNLICENSED), _Pages(DENIED), _Pages(NOT_ONBOARDED))
    collector = rbac.Collector(logging.getLogger("test"))
    pim = rbac.collect_pim("sub", object(), collector, ROLE_NAMES)

    assert pim["available"] is False
    assert pim["schedules"] == [] and pim["eligible"] is None
    assert rbac.classify_failure_code(collector.failures) == "not_authorized"


def _run_main(monkeypatch, tmp_path, schedules, eligible, policies):
    _fake_sdk(monkeypatch, schedules, eligible, policies)
    owner = _grant("a1", OWNER)
    monkeypatch.setattr(rbac, "resolve_subscription", lambda collector: {
        "subscription_id": "00000000-0000-0000-0000-000000000000", "subscription_source": "env"})
    monkeypatch.setattr(rbac, "credential", lambda: object())
    monkeypatch.setattr(rbac, "provider_registration_status", lambda *args: "registered")
    monkeypatch.setattr(rbac, "collect_role_assignments", lambda *args: ([owner], [], ROLE_NAMES))
    monkeypatch.setattr(rbac, "load_dotenv", lambda: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    code = rbac.main()
    evidence = json.loads((tmp_path / "azure_rbac_role_assignments_00000000-0000-0000-0000-000000000000.json").read_text())
    return code, evidence


def test_main_without_p2_succeeds_with_pim_unavailable(monkeypatch, tmp_path):
    code, evidence = _run_main(monkeypatch, tmp_path, _Pages(UNLICENSED), _Pages(UNLICENSED), _Pages(NOT_ONBOARDED))
    assert code == 0
    assert evidence["summary"]["pim_available"] is False
    assert evidence["summary"]["assignments_by_standing"] == {"permanent": 1, "pim_activated": 0, "time_bound": 0}
    assert evidence["summary"]["over_broad_roles_activation_without_approval"] is None
    assert evidence["summary"]["total_role_assignments"] == 1


def test_main_with_a_denied_pim_read_fails_but_writes_the_evidence(monkeypatch, tmp_path):
    code, evidence = _run_main(monkeypatch, tmp_path, _Pages(DENIED), _Pages(items=[]), _Pages(items=[]))
    assert code == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"
    summary = evidence["summary"]
    assert summary["pim_available"] is None
    assert summary["assignments_by_standing"] is None
    assert summary["permanent_over_broad_assignments"] is None
    assert summary["total_role_assignments"] == 1
    assert evidence["results"]["role_assignments"][0]["standing"] is None
