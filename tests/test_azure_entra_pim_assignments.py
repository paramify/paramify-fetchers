"""azure_entra_pim_assignments: standing vs just-in-time access, activation rules, and the unlicensed and denied paths."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

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


def _instance(role, principal_id, odata="#microsoft.graph.user", upn=None, assignment_type=None, end=None, scope="/",
              member_type="Direct"):
    return pim.project_instance(ns(
        id=f"{role}-{principal_id}",
        principal_id=principal_id,
        principal=ns(odata_type=odata, display_name=principal_id, user_principal_name=upn),
        role_definition_id=role,
        directory_scope_id=scope,
        app_scope_id=None,
        member_type=member_type,
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
    assert ga["activation_approver_sets"] == 2
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


def test_a_privileged_policy_missing_a_rule_makes_its_lists_unknown():
    bare = pim.project_policy_assignment(ns(role_definition_id=PRA, policy_id="p", policy=ns(rules=None)))
    _, summary = pim.build(DEFINITIONS, [], [], [_policy(GA, mfa=False), bare], [])
    assert summary["privileged_role_policies"] == 2
    for field in (
        "privileged_roles_activation_without_mfa_or_auth_context",
        "privileged_roles_activation_without_justification",
        "privileged_roles_activation_without_approval",
        "privileged_roles_allowing_permanent_active_assignment",
        "privileged_roles_allowing_permanent_eligible_assignment",
    ):
        assert summary[field] is None, field
    assert summary["max_privileged_activation_hours"] is None

    # An authentication context covers activation whatever the MFA rule says; the other lists stay known.
    gated = _policy(GA, context="c1")
    gated["rules"] = [r for r in gated["rules"] if r["id"] != "Enablement_EndUser_Assignment"]
    _, summary = pim.build(DEFINITIONS, [], [], [gated], [])
    assert summary["privileged_roles_activation_without_mfa_or_auth_context"] == []
    assert summary["privileged_roles_activation_without_justification"] is None
    assert summary["privileged_roles_activation_without_approval"] == ["Global Administrator"]
    assert summary["privileged_roles_allowing_permanent_active_assignment"] == []


POLICY_LISTS = (
    "privileged_roles_activation_without_mfa_or_auth_context",
    "privileged_roles_activation_without_justification",
    "privileged_roles_activation_without_approval",
    "privileged_roles_allowing_permanent_active_assignment",
    "privileged_roles_allowing_permanent_eligible_assignment",
)


def test_a_held_privileged_role_without_a_policy_makes_the_policy_fields_unknown():
    active = [_instance(GA, "u-ga"), _instance(PRA, "u-pra")]
    _, summary = pim.build(DEFINITIONS, [], active, [_policy(GA)], [])
    assert summary["privileged_roles_without_policy"] == ["Privileged Role Administrator"]
    for field in POLICY_LISTS:
        assert summary[field] is None, field
    assert summary["max_privileged_activation_hours"] is None

    # Held through a group or below the tenant still counts: the role's rules are in its tenant-wide policy.
    eligible = [_instance(PRA, "u-in-group", member_type="Group", scope="/administrativeUnits/au-1")]
    _, summary = pim.build(DEFINITIONS, eligible, [_instance(GA, "u-ga")], [_policy(GA)], [])
    assert summary["privileged_roles_without_policy"] == ["Privileged Role Administrator"]

    _, summary = pim.build(DEFINITIONS, [], active, [_policy(GA), _policy(PRA)], [])
    assert summary["privileged_roles_without_policy"] == []
    assert all(summary[field] is not None for field in POLICY_LISTS)
    assert summary["max_privileged_activation_hours"] == 8


def test_an_untyped_permanent_holder_makes_the_user_count_unknown():
    active = [_instance(GA, "u-ga"), _instance(GA, "p-untyped", odata=None)]
    _, summary = pim.build(DEFINITIONS, [], active, [_policy(GA)], [])
    assert summary["permanent_active_privileged_assignments"] == 2
    assert summary["permanent_active_privileged_user_assignments"] is None

    active[1] = _instance(GA, "p-untyped", odata=None, assignment_type="Activated", end=LATER)
    _, summary = pim.build(DEFINITIONS, [], active, [_policy(GA)], [])
    assert summary["permanent_active_privileged_user_assignments"] == 1


def test_privileged_counts_take_only_tenant_wide_direct_grants():
    active = [
        _instance(GA, "u-ga"),
        _instance(PRA, "u-au-admin", scope="/administrativeUnits/au-1"),
        _instance(PRA, "g-admins", odata="#microsoft.graph.group"),
        _instance(PRA, "u-in-group", member_type="Group"),
    ]
    eligible = [_instance(PRA, "u-au-eligible", scope="/administrativeUnits/au-1")]
    results, summary = pim.build(DEFINITIONS, eligible, active, [_policy(GA), _policy(PRA)], [])

    assert len(results["active_assignments"]) == 4
    assert summary["active_assignments"] == 3
    assert summary["active_privileged_assignments"] == 2
    assert summary["permanent_active_privileged_assignments"] == 2
    assert summary["principals_with_permanent_privileged_access"] == 2
    assert summary["eligible_assignments"] == 1
    assert summary["eligible_privileged_assignments"] == 0
    assert summary["privileged_roles_with_eligible_holders"] == []
    assert summary["privileged_assignments_scoped_below_tenant"] == 2


def test_member_type_is_compared_without_case():
    assert pim.counted({"member_type": "direct"}) and pim.counted({"member_type": None})
    assert not pim.counted({"member_type": "group"})


def test_a_licence_refusal_of_role_definitions_is_a_failure():
    collector = pim.Collector(logging.getLogger("test"))
    assert asyncio.run(pim._read(collector, "graph.roleDefinitions", _Builder(_unlicensed()))) is None
    assert not collector.ok


class _Builder:
    def __init__(self, exc=None, items=(), pages=None):
        self.exc, self.items, self.pages = exc, list(items), pages

    async def get(self, request_configuration=None):
        if self.exc:
            raise self.exc
        if self.pages:
            return self.pages.pop(0)
        return ns(value=self.items, odata_next_link=None)

    def with_url(self, url):
        return self


class _ODataError(Exception):
    """Stands in for msgraph's ODataError: str() is '<message> (status <code>)', the error code is on .error."""

    def __init__(self, message, status=403, code="Authorization_RequestDenied"):
        super().__init__(f"{message} (status {status})")
        self.response_status_code, self.error = status, ns(code=code, message=message)


def _unlicensed(status=400):
    return _ODataError("The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.",
                       status, "AadPremiumLicenseRequired")


def _read(builder):
    collector, unlicensed = pim.Collector(logging.getLogger("test")), []
    items = asyncio.run(pim._read(collector, "graph.op", builder, unlicensed=unlicensed))
    return items, collector, unlicensed


@pytest.mark.parametrize("status", [400, 403])
def test_a_licence_refusal_is_a_state_not_a_failure(status):
    items, collector, unlicensed = _read(_Builder(_unlicensed(status)))
    assert collector.ok
    assert items is None
    assert len(unlicensed) == 1

    active = [_instance(GA, "u-ga")]
    results, summary = pim.build(DEFINITIONS, None, active, None, unlicensed)
    assert summary == {"pim_available": False, "collection_complete": False}
    assert results["pim_available"] is False
    assert results["eligible_assignments"] is None
    assert results["active_assignments"][0]["standing"] == "permanent"
    assert results["notes"][1].startswith("graph.op:")


def test_a_licence_refusal_and_a_403_elsewhere_keep_both_outcomes():
    collector, unlicensed = pim.Collector(logging.getLogger("test")), []
    denied = _Builder(_ODataError("Insufficient privileges to complete the operation."))
    assert asyncio.run(pim._read(collector, "graph.eligible", _Builder(_unlicensed()), unlicensed=unlicensed)) is None
    assert asyncio.run(pim._read(collector, "graph.policies", denied)) is None
    assert len(unlicensed) == 1
    assert pim.classify_failure_code(collector.failures) == "not_authorized"

    _, summary = pim.build(DEFINITIONS, None, [], None, unlicensed)
    assert summary == {"pim_available": False, "collection_complete": False}


@pytest.mark.parametrize("error", [
    _ODataError("Insufficient privileges to complete the operation: no license for this feature."),
    _ODataError("This tenant isn't licensed for this feature.", 403, "Forbidden"),
    _ODataError("Too many requests; licensed tenants get a higher limit.", 429, "TooManyRequests"),
    _ODataError("The tenant has not onboarded to PIM.", 400, "BadRequest"),
], ids=["permission-403", "forbidden-403", "throttled-429", "not-onboarded-400"])
def test_licence_wording_without_the_licence_code_is_a_failure(error):
    items, collector, unlicensed = _read(_Builder(error))
    assert items is None
    assert unlicensed == []
    assert len(collector.failures) == 1


def _client(monkeypatch, eligible, active):
    roles = ns(
        role_definitions=_Builder(items=[ns(id=GA, template_id=GA, display_name="Global Administrator",
                                            is_built_in=True, is_enabled=True)]),
        role_eligibility_schedule_instances=eligible,
        role_assignment_schedule_instances=active,
    )
    policies = _Builder(items=[])
    client = ns(role_management=ns(directory=roles), policies=ns(role_management_policy_assignments=policies))

    async def fake_with_graph_client(collector, cred, work, default=None):
        return await work(client)

    async def fake_tenant(collector, client):
        return {"tenant_id": "t-1", "tenant_source": "env"}

    monkeypatch.setattr(pim, "with_graph_client", fake_with_graph_client)
    monkeypatch.setattr(pim, "resolve_tenant", fake_tenant)
    monkeypatch.setattr(pim, "_query", lambda builder, **params: None)
    return policies


def test_an_unlicensed_tenant_skips_the_other_pim_reads(monkeypatch):
    active = _Builder(_unlicensed())
    _client(monkeypatch, _Builder(_unlicensed()), active)
    collector = pim.Collector(logging.getLogger("test"))
    _, definitions, eligible, active_read, policies, unlicensed = asyncio.run(pim._collect(collector, object()))
    assert collector.ok
    assert len(unlicensed) == 1 and unlicensed[0].startswith("graph.roleManagement.directory.roleEligibilityScheduleInstances")
    assert definitions and eligible is None and active_read is None and policies is None
    _, summary = pim.build(definitions, eligible, active_read, policies, unlicensed)
    assert summary == {"pim_available": False, "collection_complete": False}


def test_a_licence_refusal_after_the_first_pim_read_is_a_failure(monkeypatch):
    _client(monkeypatch, _Builder(items=[]), _Builder(_unlicensed()))
    collector = pim.Collector(logging.getLogger("test"))
    _, definitions, eligible, active, policies, unlicensed = asyncio.run(pim._collect(collector, object()))
    assert unlicensed == []
    assert eligible == [] and active is None
    assert len(collector.failures) == 1
    _, summary = pim.build(definitions, eligible, active, policies, unlicensed)
    assert summary == {"pim_available": None, "collection_complete": False}


def test_a_failure_on_a_later_page_fails_the_read():
    first = ns(value=[ns(id="d1")], odata_next_link="https://graph.microsoft.com/next")
    builder = _Builder(pages=[first])
    builder.with_url = lambda url: _Builder(_ODataError("Too many requests", 429, "TooManyRequests"))
    items, collector, unlicensed = _read(builder)
    assert items is None
    assert unlicensed == []
    assert pim.classify_failure_code(collector.failures) == "rate_limited"


def test_a_graph_403_is_recorded_and_classified_not_authorized():
    items, collector, unlicensed = _read(_Builder(_ODataError(
        '{"errorCode":"PermissionScopeNotGranted","message":"Authorization failed due to missing permission '
        'scope RoleManagement.Read.Directory."}', 403, "UnknownError"
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


def test_empty_role_definitions_are_a_failed_read(monkeypatch):
    roles = ns(
        role_definitions=_Builder(items=[]),
        role_eligibility_schedule_instances=_Builder(items=[]),
        role_assignment_schedule_instances=_Builder(items=[]),
    )
    client = ns(role_management=ns(directory=roles), policies=ns(role_management_policy_assignments=_Builder(items=[])))

    async def fake_with_graph_client(collector, cred, work, default=None):
        return await work(client)

    async def fake_tenant(collector, client):
        return {"tenant_id": "t-1", "tenant_source": "env"}

    monkeypatch.setattr(pim, "with_graph_client", fake_with_graph_client)
    monkeypatch.setattr(pim, "resolve_tenant", fake_tenant)
    monkeypatch.setattr(pim, "_query", lambda builder, **params: None)
    collector = pim.Collector(logging.getLogger("test"))
    _, definitions, *_ = asyncio.run(pim._collect(collector, object()))
    assert definitions is None
    assert not collector.ok


def test_a_failed_graph_client_gives_no_figures(monkeypatch):
    async def failed_client(collector, cred, work, default=None):
        collector.record("msgraph.GraphServiceClient (init)", RuntimeError("could not build the Graph client"))
        return default

    monkeypatch.setattr(pim, "with_graph_client", failed_client)
    collector = pim.Collector(logging.getLogger("test"))
    tenant, *reads, unlicensed = asyncio.run(pim._collect(collector, object()))
    assert tenant == {"tenant_source": "unresolved"}
    assert not collector.ok

    _, summary = pim.build(*reads, unlicensed)
    assert summary == {"pim_available": None, "collection_complete": False}


def test_a_credential_failure_writes_null_figures_and_fails_the_run(tmp_path, monkeypatch):
    def no_credential():
        raise RuntimeError("DefaultAzureCredential failed to retrieve a token")

    monkeypatch.setattr(pim, "credential", no_credential)
    monkeypatch.setattr(pim, "load_dotenv", lambda: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_TENANT_ID", "t-1")
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))

    assert pim.main() == 1
    evidence = json.loads((tmp_path / "azure_entra_pim_assignments_t-1.json").read_text())
    assert evidence["summary"] == {"pim_available": None, "collection_complete": False}
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "auth_failed"
