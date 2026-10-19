"""azure_entra_pim_assignments: standing vs just-in-time access, activation rules, and the unlicensed and denied paths."""

from __future__ import annotations

import asyncio
import importlib.util
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as ns

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "entra_pim_assignments" / "fetcher.py"

spec = importlib.util.spec_from_file_location("azure_entra_pim_assignments_under_test", FETCHER)
pim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pim)


GA = "62e90394-69f5-4237-9190-012177145e10"
PRA = "e8611ab8-c189-46e8-94e1-60213ab1f814"
READER = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
LATER = datetime(2027, 1, 1, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)

DEFINITIONS = [
    {"id": GA, "template_id": GA, "display_name": "Global Administrator", "is_built_in": True},
    {"id": PRA, "template_id": PRA, "display_name": "Privileged Role Administrator", "is_built_in": True},
    {"id": READER, "template_id": READER, "display_name": "Directory Readers", "is_built_in": True},
]


def _instance(role, principal_id, odata="#microsoft.graph.user", upn=None, assignment_type=None, end=None, scope="/"):
    return pim.project_instance(ns(
        id=f"{role}-{principal_id}",
        principal_id=principal_id,
        principal=ns(odata_type=odata, display_name=principal_id, user_principal_name=upn),
        role_definition_id=role,
        directory_scope_id=scope,
        app_scope_id=None,
        member_type="Direct",
        assignment_type=assignment_type,
        start_date_time=NOW,
        end_date_time=end,
    ))


def _rule(odata, rule_id, **fields):
    return ns(odata_type=f"#microsoft.graph.{odata}", id=rule_id, **fields)


def _policy(role, *, mfa=True, justification=True, approval=False, max_activation=timedelta(hours=8),
            permanent_eligible=False, permanent_active=False, context=None):
    enabled = [r for r, on in (("MultiFactorAuthentication", mfa), ("Justification", justification)) if on]
    rules = [
        _rule("unifiedRoleManagementPolicyExpirationRule", "Expiration_EndUser_Assignment",
              is_expiration_required=True, maximum_duration=max_activation),
        _rule("unifiedRoleManagementPolicyEnablementRule", "Enablement_EndUser_Assignment", enabled_rules=enabled),
        _rule("unifiedRoleManagementPolicyApprovalRule", "Approval_EndUser_Assignment", setting=ns(
            is_approval_required=approval, is_approval_required_for_extension=False,
            is_requestor_justification_required=True, approval_mode="SingleStage",
            approval_stages=[ns(primary_approvers=[ns(), ns()] if approval else [], is_escalation_enabled=False,
                                approval_stage_time_out_in_days=1)],
        )),
        _rule("unifiedRoleManagementPolicyAuthenticationContextRule", "AuthenticationContext_EndUser_Assignment",
              is_enabled=context is not None, claim_value=context),
        _rule("unifiedRoleManagementPolicyExpirationRule", "Expiration_Admin_Eligibility",
              is_expiration_required=not permanent_eligible, maximum_duration=timedelta(days=365)),
        _rule("unifiedRoleManagementPolicyExpirationRule", "Expiration_Admin_Assignment",
              is_expiration_required=not permanent_active, maximum_duration=timedelta(days=180)),
        _rule("unifiedRoleManagementPolicyEnablementRule", "Enablement_Admin_Assignment",
              enabled_rules=["MultiFactorAuthentication", "Justification"]),
        _rule("unifiedRoleManagementPolicyNotificationRule", "Notification_Admin_Admin_Eligibility"),
    ]
    return pim.project_policy_assignment(ns(
        role_definition_id=role,
        policy_id=f"DirectoryRole_tenant_{role}",
        policy=ns(is_organization_default=False, last_modified_date_time=NOW, rules=rules),
    ))


def test_durations_round_trip_to_iso_and_hours():
    assert pim.iso_duration(timedelta(hours=8)) == "PT8H"
    assert pim.iso_duration(timedelta(days=365)) == "P365D"
    assert pim.iso_duration(timedelta(days=1, hours=2, minutes=30)) == "P1DT2H30M"
    assert pim.iso_duration(timedelta(0)) == "PT0S"
    assert pim.duration_hours("PT8H") == 8
    assert pim.duration_hours("PT30M") == 0.5
    assert pim.duration_hours("P1DT2H30M") == 26.5
    assert pim.duration_hours(None) is None


def test_active_grants_are_marked_permanent_time_bound_or_activated():
    active = [
        _instance(GA, "u-break-glass", upn="bg@contoso.test"),
        _instance(GA, "u-jit", upn="jit@contoso.test", assignment_type="Activated", end=LATER),
        _instance(PRA, "u-temp", upn="temp@contoso.test", assignment_type="Assigned", end=LATER),
        _instance(PRA, "sp-automation", odata="#microsoft.graph.servicePrincipal"),
        _instance(READER, "u-reader", upn="reader@contoso.test"),
    ]
    eligible = [
        _instance(GA, "u-jit", upn="jit@contoso.test", end=LATER),
        _instance(PRA, "u-forever", upn="forever@contoso.test"),
    ]
    results, summary = pim.build(DEFINITIONS, eligible, active, [_policy(GA), _policy(PRA)], [])

    by_principal = {a["principal_id"]: a for a in results["active_assignments"]}
    assert by_principal["u-break-glass"]["standing"] == "permanent"
    assert by_principal["u-jit"]["standing"] == "pim_activated"
    assert by_principal["u-temp"]["standing"] == "time_bound"
    assert by_principal["sp-automation"]["principal_type"] == "ServicePrincipal"
    assert by_principal["u-reader"]["is_privileged"] is False
    assert by_principal["u-break-glass"]["is_global_administrator"] is True
    assert all("assignment_type" not in e for e in results["eligible_assignments"])

    assert summary["collection_complete"] is True
    assert summary["pim_available"] is True
    assert summary["active_privileged_assignments"] == 4
    assert summary["active_privileged_by_standing"] == {"permanent": 2, "pim_activated": 1, "time_bound": 1}
    assert summary["permanent_active_privileged_assignments"] == 2
    assert summary["permanent_active_privileged_user_assignments"] == 1
    assert summary["privileged_roles_with_permanent_active_holders"] == [
        "Global Administrator", "Privileged Role Administrator",
    ]
    assert summary["global_administrator_permanent_active"] == 1
    assert summary["global_administrator_eligible"] == 1
    assert summary["eligible_privileged_assignments"] == 2
    assert summary["permanently_eligible_privileged_assignments"] == 1
    assert summary["principals_eligible_for_privileged_roles"] == 2


def test_activation_rules_are_read_per_role():
    policies = [
        _policy(GA, approval=True, context="c1"),
        _policy(PRA, mfa=False, justification=False, max_activation=timedelta(hours=24), permanent_active=True),
    ]
    results, summary = pim.build(DEFINITIONS, [], [], policies, [])
    by_role = {p["role_name"]: p for p in results["role_policies"]}

    ga = by_role["Global Administrator"]
    assert ga["activation_requires_mfa"] is True
    assert ga["activation_requires_approval"] is True
    assert ga["activation_approver_count"] == 2
    assert ga["activation_authentication_context"] == "c1"
    assert ga["activation_maximum_duration"] == "PT8H"
    assert ga["activation_maximum_hours"] == 8
    assert ga["permanent_eligible_assignment_allowed"] is False
    assert ga["eligible_assignment_maximum_duration"] == "P365D"
    assert ga["active_assignment_requires_mfa"] is True
    assert not any(r["id"].startswith("Notification_") for r in ga["rules"])

    pra = by_role["Privileged Role Administrator"]
    assert pra["activation_requires_mfa"] is False
    assert pra["permanent_active_assignment_allowed"] is True

    assert summary["privileged_roles_activation_without_mfa_or_auth_context"] == ["Privileged Role Administrator"]
    assert summary["privileged_roles_activation_without_justification"] == ["Privileged Role Administrator"]
    assert summary["privileged_roles_activation_without_approval"] == ["Privileged Role Administrator"]
    assert summary["privileged_roles_allowing_permanent_active_assignment"] == ["Privileged Role Administrator"]
    assert summary["max_privileged_activation_hours"] == 24


def test_policies_of_unassigned_unprivileged_roles_are_dropped():
    results, _ = pim.build(DEFINITIONS, [], [], [_policy(GA), _policy(READER)], [])
    assert [p["role_name"] for p in results["role_policies"]] == ["Global Administrator"]

    results, _ = pim.build(DEFINITIONS, [], [_instance(READER, "u-reader")], [_policy(GA), _policy(READER)], [])
    assert [p["role_name"] for p in results["role_policies"]] == ["Directory Readers", "Global Administrator"]


def test_a_missing_rule_reads_as_unknown_not_false():
    bare = pim.project_policy_assignment(ns(role_definition_id=GA, policy_id="p", policy=ns(rules=[])))
    record = pim.policy_record(bare, pim.role_index(DEFINITIONS))
    assert record["activation_requires_mfa"] is None
    assert record["permanent_active_assignment_allowed"] is None
    assert record["activation_requires_approval"] is None


class _Builder:
    def __init__(self, exc=None, items=()):
        self.exc, self.items = exc, list(items)

    async def get(self, request_configuration=None):
        if self.exc:
            raise self.exc
        return ns(value=self.items, odata_next_link=None)


class _ODataError(Exception):
    """Stands in for msgraph's ODataError, whose str() is '<message> (status <code>)'."""


def _read(builder):
    collector, unlicensed = pim.Collector(logging.getLogger("test")), []
    items = asyncio.run(pim._read(collector, unlicensed, "graph.op", builder))
    return items, collector, unlicensed


def test_a_licence_refusal_is_a_state_not_a_failure():
    items, collector, unlicensed = _read(_Builder(_ODataError(
        "The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license. (status 400)"
    )))
    assert collector.ok
    assert items == []
    assert len(unlicensed) == 1

    results, summary = pim.build(DEFINITIONS, [], [], [], unlicensed)
    assert summary == {"pim_available": False}
    assert results["pim_available"] is False


def test_a_graph_403_is_recorded_and_classified_not_authorized():
    items, collector, unlicensed = _read(_Builder(_ODataError(
        '{"errorCode":"PermissionScopeNotGranted","message":"Authorization failed due to missing permission '
        'scope RoleManagement.Read.Directory."} (status 403)'
    )))
    assert items is None
    assert unlicensed == []
    assert not collector.ok
    assert pim.classify_failure_code(collector.failures) == "not_authorized"


def test_a_failed_read_gives_no_figures():
    results, summary = pim.build(DEFINITIONS, None, [_instance(GA, "u1")], [_policy(GA)], [])
    assert summary == {"pim_available": None, "collection_complete": False}
    assert results["pim_available"] is None
    assert results["eligible_assignments"] is None
    assert results["active_assignments"][0]["standing"] == "permanent"
