"""The IAM statement parser, and each case Prowler's substring matching gets wrong."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "iam_policies" / "fetcher.py"
TENANCY = "ocid1.tenancy.oc1..root"


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_iam_policies", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


iam = _load()


def _policy(name, statements, compartment=TENANCY):
    return iam.policy_record({"id": f"ocid1.policy.oc1..{name}", "name": name, "compartment_id": compartment,
                              "lifecycle_state": "ACTIVE", "statements": statements}, tenancy_id=TENANCY)


def test_any_user_manage_all_is_caught_where_prowler_requires_allow_group():
    out = iam.summarize([_policy("open", ["allow any-user to manage all-resources in tenancy"])], [])
    assert out["manage_all_resources_in_tenancy_outside_default_admin_policy"] == 1
    assert out["unconditional_any_principal_statements"] == 1
    assert out["iam_management_statements_without_administrators_guard"] == 1


def test_uppercase_where_guard_is_honoured():
    guarded = iam.parse_statement(
        "Allow group IAMAdmins to manage groups in tenancy WHERE target.group.name != 'Administrators'")
    assert guarded["parsed"] and not guarded["manages_iam_without_administrators_guard"]
    unguarded = iam.parse_statement("Allow group IAMAdmins to manage groups in tenancy")
    assert unguarded["manages_iam_without_administrators_guard"]


def test_renaming_a_policy_does_not_exempt_it():
    impostor = _policy("Tenant Admin Policy", ["allow group Contractors to manage all-resources in tenancy"])
    wrong_place = _policy("Tenant Admin Policy", ["ALLOW GROUP Administrators to manage all-resources IN TENANCY"],
                          compartment="ocid1.compartment.oc1..child")
    real = _policy("Tenant Admin Policy", ["ALLOW GROUP Administrators to manage all-resources IN TENANCY"])
    assert not impostor["is_default_tenant_admin_policy"]
    assert not wrong_place["is_default_tenant_admin_policy"]
    assert real["is_default_tenant_admin_policy"]
    out = iam.summarize([impostor, real], [])
    assert out["manage_all_resources_in_tenancy_outside_default_admin_policy"] == 1


def test_oracles_own_conditioned_any_user_grants_are_not_unconditional():
    """Verbatim from the CloudGuardPolicies Oracle created on the live tenancy."""
    policy = _policy("CloudGuardPolicies", [
        "Allow any-user to { WLP_BOM_READ } in tenancy where all { request.principal.id = target.agent.id, "
        "request.principal.type = 'workloadprotectionagent'}",
        "Endorse any-user to { WLP_LOG_CREATE } in any-tenancy where all { request.principal.id = "
        "target.agent.id, request.principal.type = 'workloadprotectionagent' }",
        "allow service cloudguard to manage cloudevents-rules in tenancy where target.rule.type='managed'",
    ])
    assert all(s["parsed"] for s in policy["statements"])
    out = iam.summarize([policy], [])
    assert out["unconditional_any_principal_statements"] == 0
    assert out["conditional_any_principal_statements"] == 2
    assert out["cross_tenancy_statements"] == 1
    assert out["policies_with_broad_grants"] == []


def test_compartment_scoped_manage_all_counts_for_service_admins_not_tenancy():
    out = iam.summarize([_policy("app", ["allow group AppAdmins to manage all-resources in compartment app"])], [])
    assert out["manage_all_resources_in_tenancy_outside_default_admin_policy"] == 0
    assert out["manage_all_resources_statements_outside_default_admin_policy"] == 1


def test_unrecognised_statements_are_counted_and_never_narrow():
    policy = _policy("odd", ["define tenancy Acme as ocid1.tenancy.oc1..x"])
    assert policy["statements"][0]["parsed"] is False
    assert iam.summarize([policy], [])["unparsed_statements"] == 1


def test_dynamic_groups_matching_workloads():
    assert iam.dynamic_group_record({"matching_rule": "ANY {instance.compartment.id = 'ocid1..x'}"})["matches_workloads"]
    assert not iam.dynamic_group_record({"matching_rule": "tag.team.value = 'x'"})["matches_workloads"]
