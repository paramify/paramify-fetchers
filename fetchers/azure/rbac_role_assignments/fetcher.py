#!/usr/bin/env python3
"""
Azure RBAC role assignments on one subscription

Who holds what, where: each assignment with its scope classified, its principal, and its
role definition with the NAME resolved from the GUID, flagged for the four over-broad
built-ins.

Two sets, kept apart. `role_assignments` is the subscription scope and above — the
`atScope()` list every existing summary key is computed over, unchanged. Grants made on
a resource group or a single resource are in `role_assignments_below_subscription`,
with their own `below_subscription_*` / `all_scopes_*` summary keys, so a count a
validator already reads never changes meaning.

PIM adds keys, never changes one: each grant's standing, the eligible assignments, and
the over-broad roles' activation rules.

Projections ported from Prowler's
prowler/providers/azure/services/iam/iam_service.py `_get_role_assignments` and
`_get_roles` (Apache-2.0) — same SDK, same two calls, same `atScope()` filter. The
below-subscription listing is ours. The four role GUIDs are theirs verbatim, from
prowler/providers/azure/config.py.
"""

import logging
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)

logger = logging.getLogger("azure_rbac_role_assignments")

# Built-in role definition GUIDs, verbatim from Prowler's
# prowler/providers/azure/config.py. Azure-wide constants — the same GUID identifies
# the role in every tenant — which is why matching on them is safe where matching on a
# display name would not be.
OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR_ROLE_ID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
USER_ACCESS_ADMINISTRATOR_ROLE_ID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID = "f58310d9-a9f6-439a-9e8d-f62e7b41a168"

# A mapping rather than a set, so the evidence can say WHICH role was matched: Owner
# and User Access Administrator are over-broad for different reasons and are remediated
# differently.
OVER_BROAD_BUILTIN_ROLES = {
    OWNER_ROLE_ID: "Owner",
    CONTRIBUTOR_ROLE_ID: "Contributor",
    USER_ACCESS_ADMINISTRATOR_ROLE_ID: "User Access Administrator",
    ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID: "Role Based Access Control Administrator",
}

# The subset that can grant access — the escalation path, distinct from merely holding
# broad access. Owner is in both: it can do anything AND delegate it.
ROLE_GRANTING_ROLES = frozenset(
    {
        OWNER_ROLE_ID,
        USER_ACCESS_ADMINISTRATOR_ROLE_ID,
        ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID,
    }
)

SCOPE_MANAGEMENT_GROUP = "management_group"
SCOPE_SUBSCRIPTION = "subscription"
SCOPE_RESOURCE_GROUP = "resource_group"
SCOPE_RESOURCE = "resource"
SCOPE_ROOT = "root"
SCOPE_UNKNOWN = "unknown"

# Every level `scope_level` can return, widest first — the keys of the by-level counts,
# always all present so a zero reads as zero rather than as a missing key.
SCOPE_LEVELS = (
    SCOPE_ROOT,
    SCOPE_MANAGEMENT_GROUP,
    SCOPE_SUBSCRIPTION,
    SCOPE_RESOURCE_GROUP,
    SCOPE_RESOURCE,
    SCOPE_UNKNOWN,
)


# --- projections: the only code here that touches an azure-mgmt model ---

def project_role_assignment(assignment) -> dict:
    """Read a `RoleAssignment` model's attributes into a flat snake_case dict.

    Timestamps are `str()`-rendered here rather than left to `json.dump`'s
    `default=str`.
    """
    created_on = model_attr(assignment, "created_on")
    updated_on = model_attr(assignment, "updated_on")
    return {
        "id": model_attr(assignment, "id"),
        "name": model_attr(assignment, "name"),
        "scope": model_attr(assignment, "scope"),
        "principal_id": model_attr(assignment, "principal_id"),
        "principal_type": model_attr(assignment, "principal_type"),
        "role_definition_id": model_attr(assignment, "role_definition_id"),
        "description": model_attr(assignment, "description"),
        # An over-broad role WITH an ABAC condition is a different finding.
        "condition": model_attr(assignment, "condition"),
        "condition_version": model_attr(assignment, "condition_version"),
        "created_on": str(created_on) if created_on is not None else None,
        "updated_on": str(updated_on) if updated_on is not None else None,
        "delegated_managed_identity_resource_id": model_attr(
            assignment, "delegated_managed_identity_resource_id"
        ),
    }


def project_role_definition(definition) -> dict:
    """Read a `RoleDefinition` model into the flat dict the name lookup needs.

    Identity fields only. The permission bodies are the rbac_custom_roles fetcher's
    evidence; duplicating them would put the same large arrays in two evidence sets.
    """
    return {
        "id": model_attr(definition, "id"),
        "name": model_attr(definition, "name"),
        "role_name": model_attr(definition, "role_name"),
        "role_type": model_attr(definition, "role_type"),
        "description": model_attr(definition, "description"),
    }


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def project_schedule_instance(instance) -> dict:
    """A PIM `RoleAssignmentScheduleInstance` or `RoleEligibilityScheduleInstance`; absent fields read None."""
    return {
        "id": model_attr(instance, "id"),
        "scope": model_attr(instance, "scope"),
        "principal_id": model_attr(instance, "principal_id"),
        "principal_type": model_attr(instance, "principal_type"),
        "role_definition_id": model_attr(instance, "role_definition_id"),
        "origin_role_assignment_id": model_attr(instance, "origin_role_assignment_id"),
        "assignment_type": model_attr(instance, "assignment_type"),
        "member_type": model_attr(instance, "member_type"),
        "status": model_attr(instance, "status"),
        "start_date_time": _iso(model_attr(instance, "start_date_time")),
        "end_date_time": _iso(model_attr(instance, "end_date_time")),
        "condition": model_attr(instance, "condition"),
    }


def project_policy_rule(rule) -> dict:
    setting = model_attr(rule, "setting")
    projected = {
        "id": model_attr(rule, "id"),
        "rule_type": model_attr(rule, "rule_type"),
        "is_expiration_required": model_attr(rule, "is_expiration_required"),
        "maximum_duration": model_attr(rule, "maximum_duration"),
        "enabled_rules": model_attr(rule, "enabled_rules"),
        "is_enabled": model_attr(rule, "is_enabled"),
        "claim_value": model_attr(rule, "claim_value"),
        "approval": None if setting is None else {
            "is_approval_required": model_attr(setting, "is_approval_required"),
            "is_requestor_justification_required": model_attr(setting, "is_requestor_justification_required"),
            "approval_mode": model_attr(setting, "approval_mode"),
            "primary_approver_count": sum(
                len(model_attr(stage, "primary_approvers") or []) for stage in model_attr(setting, "approval_stages") or []
            ),
        },
    }
    return {k: v for k, v in projected.items() if v is not None}


def project_policy_assignment(assignment) -> dict:
    """A PIM `RoleManagementPolicyAssignment`; its effective rules are the policy as it applies at this scope."""
    return {
        "scope": model_attr(assignment, "scope"),
        "role_definition_id": model_attr(assignment, "role_definition_id"),
        "policy_id": model_attr(assignment, "policy_id"),
        "rules": [project_policy_rule(r) for r in model_attr(assignment, "effective_rules") or []],
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def role_definition_guid(role_definition_id: str | None) -> str | None:
    """The trailing GUID of a role definition's ARM id.

    The full id is scope-qualified, so the SAME built-in role arrives under a different
    id per scope while the GUID is invariant: comparing full ids against the constants
    above would silently never match. Prowler splits on "/" for the same reason.
    """
    return basename(role_definition_id)


def scope_level(scope: str | None) -> str:
    """Classify an ARM scope by how much it covers.

    Tests run widest-first because a resource scope CONTAINS the resource-group
    segment, so narrowest-first cannot discriminate.
    """
    if not scope:
        return SCOPE_UNKNOWN
    normalized = scope.rstrip("/") or "/"
    lowered = normalized.lower()
    if normalized == "/":
        return SCOPE_ROOT
    if "/providers/microsoft.management/managementgroups/" in lowered:
        return SCOPE_MANAGEMENT_GROUP
    if resource_group_from_id(normalized) and "/resourcegroups/" in lowered:
        # A resource group scope ends at the group; anything past it is one resource.
        tail = lowered.split("/resourcegroups/", 1)[1]
        return SCOPE_RESOURCE if "/providers/" in tail else SCOPE_RESOURCE_GROUP
    if lowered.startswith("/subscriptions/"):
        return SCOPE_SUBSCRIPTION
    return SCOPE_UNKNOWN


def assignment_record(assignment: dict, role_names: dict[str, dict]) -> dict:
    """Normalize one projected assignment, resolving its role definition.

    The lookup can legitimately miss — an assignment inherited from a management group
    can reference a custom role defined ABOVE this subscription, which
    `role_definitions.list(scope=/subscriptions/<sub>)` does not return — so
    `role_name_resolved` records that. The over-broad determination reads the GUID, NOT
    the resolved name, so it holds anyway. (Prowler's
    iam_role_user_access_admin_restricted compares the resolved NAME, and so reports a
    clean pass for exactly the inherited assignments it could not resolve.)
    """
    scope = assignment.get("scope")
    guid = role_definition_guid(assignment.get("role_definition_id"))
    definition = role_names.get(str(guid).lower()) if guid else None
    over_broad = OVER_BROAD_BUILTIN_ROLES.get(str(guid).lower()) if guid else None
    level = scope_level(scope)

    return {
        "id": assignment.get("id"),
        "name": assignment.get("name"),
        # --- where ---
        "scope": scope,
        "scope_level": level,
        "at_subscription_scope": level == SCOPE_SUBSCRIPTION,
        "inherited_from_above_subscription": level in (SCOPE_MANAGEMENT_GROUP, SCOPE_ROOT),
        "scope_resource_group": resource_group_from_id(scope),
        # --- who ---
        "principal_id": assignment.get("principal_id"),
        # Absent principalType means the assignment predates the field or the caller
        # could not expand it; left None rather than guessed, since guessing "User"
        # would misreport a service principal.
        "principal_type": assignment.get("principal_type"),
        # --- what ---
        "role_definition_id": assignment.get("role_definition_id"),
        "role_definition_guid": guid,
        "role_name": (definition or {}).get("role_name"),
        "role_name_resolved": definition is not None,
        "role_type": (definition or {}).get("role_type"),
        "is_custom_role": str((definition or {}).get("role_type") or "") == "CustomRole",
        # --- the flags ---
        "is_over_broad_builtin": over_broad is not None,
        "over_broad_role": over_broad,
        "can_grant_roles": str(guid).lower() in ROLE_GRANTING_ROLES if guid else False,
        # --- narrowing / provenance ---
        "has_condition": bool(assignment.get("condition")),
        "condition": assignment.get("condition"),
        "condition_version": assignment.get("condition_version"),
        "description": assignment.get("description"),
        "created_on": assignment.get("created_on"),
        "updated_on": assignment.get("updated_on"),
    }


def summarize(assignments: list[dict]) -> dict:
    """Over-broad built-in assignments are the headline, distinct principals second.

    One service principal holding Contributor on four scopes is one identity to review,
    not four, so both counts are reported.
    """
    over_broad = [a for a in assignments if a["is_over_broad_builtin"]]
    by_type: dict[str, int] = {}
    for assignment in assignments:
        key = assignment["principal_type"] or "Unknown"
        by_type[key] = by_type.get(key, 0) + 1

    def _count_role(role_id: str) -> int:
        return sum(1 for a in assignments if str(a["role_definition_guid"] or "").lower() == role_id)

    return {
        "total_role_assignments": len(assignments),
        "distinct_principals": len({a["principal_id"] for a in assignments if a["principal_id"]}),
        # --- the headline ---
        "over_broad_builtin_assignments": len(over_broad),
        "distinct_principals_with_over_broad_roles": len(
            {a["principal_id"] for a in over_broad if a["principal_id"]}
        ),
        "over_broad_percentage": coverage_percentage(len(over_broad), len(assignments)),
        "least_privilege_assignments": len(assignments) - len(over_broad),
        # --- per over-broad role ---
        "owner_assignments": _count_role(OWNER_ROLE_ID),
        "contributor_assignments": _count_role(CONTRIBUTOR_ROLE_ID),
        "user_access_administrator_assignments": _count_role(USER_ACCESS_ADMINISTRATOR_ROLE_ID),
        "rbac_administrator_assignments": _count_role(
            ROLE_BASED_ACCESS_CONTROL_ADMINISTRATOR_ROLE_ID
        ),
        # Broader than the Owner count alone: a principal that can write role
        # assignments can make itself an Owner.
        "role_granting_assignments": sum(1 for a in assignments if a["can_grant_roles"]),
        # --- by scope ---
        "assignments_at_root_scope": sum(
            1 for a in assignments if a["scope_level"] == SCOPE_ROOT
        ),
        "assignments_at_management_group_scope": sum(
            1 for a in assignments if a["scope_level"] == SCOPE_MANAGEMENT_GROUP
        ),
        "assignments_at_subscription_scope": sum(1 for a in assignments if a["at_subscription_scope"]),
        "assignments_at_resource_group_scope": sum(
            1 for a in assignments if a["scope_level"] == SCOPE_RESOURCE_GROUP
        ),
        "assignments_at_resource_scope": sum(
            1 for a in assignments if a["scope_level"] == SCOPE_RESOURCE
        ),
        "assignments_inherited_from_above_subscription": sum(
            1 for a in assignments if a["inherited_from_above_subscription"]
        ),
        "over_broad_at_subscription_scope_or_above": sum(
            1
            for a in over_broad
            if a["at_subscription_scope"] or a["inherited_from_above_subscription"]
        ),
        # --- by role kind and principal kind ---
        "custom_role_assignments": sum(1 for a in assignments if a["is_custom_role"]),
        "builtin_role_assignments": sum(
            1 for a in assignments if a["role_name_resolved"] and not a["is_custom_role"]
        ),
        "unresolved_role_definitions": sum(1 for a in assignments if not a["role_name_resolved"]),
        "assignments_by_principal_type": by_type,
        "assignments_with_conditions": sum(1 for a in assignments if a["has_condition"]),
    }


def assignments_by_scope_level(assignments: list[dict]) -> dict[str, int]:
    """Count per scope level, every level present."""
    counts = {level: 0 for level in SCOPE_LEVELS}
    for assignment in assignments:
        level = assignment.get("scope_level") or SCOPE_UNKNOWN
        counts[level] = counts.get(level, 0) + 1
    return counts


def summarize_all_scopes(at_scope: list[dict], below: list[dict]) -> dict:
    """The keys that count resource-group and resource grants too.

    New keys rather than a widened `summarize`: every key it returns has always meant
    "at the subscription scope or above", and a validator comparing
    `total_role_assignments` or `over_broad_builtin_assignments` must keep reading that.
    A resource-scoped Owner is the same escalation path as a subscription-scoped one,
    only over less, which is why the over-broad and role-granting counts are repeated
    for this set.
    """
    everything = at_scope + below
    below_over_broad = [a for a in below if a["is_over_broad_builtin"]]
    by_type: dict[str, int] = {}
    for assignment in below:
        key = assignment["principal_type"] or "Unknown"
        by_type[key] = by_type.get(key, 0) + 1

    def _principals(records: list[dict]) -> int:
        return len({a["principal_id"] for a in records if a["principal_id"]})

    return {
        # --- the widened set ---
        "all_scopes_total_role_assignments": len(everything),
        "all_scopes_distinct_principals": _principals(everything),
        "all_scopes_over_broad_builtin_assignments": sum(
            1 for a in everything if a["is_over_broad_builtin"]
        ),
        "all_scopes_role_granting_assignments": sum(1 for a in everything if a["can_grant_roles"]),
        "all_scopes_assignments_by_scope_level": assignments_by_scope_level(everything),
        # --- below the subscription only ---
        "below_subscription_role_assignments": len(below),
        "below_subscription_distinct_principals": _principals(below),
        "below_subscription_resource_group_assignments": sum(
            1 for a in below if a["scope_level"] == SCOPE_RESOURCE_GROUP
        ),
        "below_subscription_resource_assignments": sum(
            1 for a in below if a["scope_level"] == SCOPE_RESOURCE
        ),
        "below_subscription_over_broad_builtin_assignments": len(below_over_broad),
        "below_subscription_role_granting_assignments": sum(1 for a in below if a["can_grant_roles"]),
        "below_subscription_custom_role_assignments": sum(1 for a in below if a["is_custom_role"]),
        "below_subscription_unresolved_role_definitions": sum(
            1 for a in below if not a["role_name_resolved"]
        ),
        "below_subscription_assignments_by_principal_type": by_type,
    }


# --- PIM: eligibility, standing and activation rules ---

STANDING_PERMANENT = "permanent"
STANDING_TIME_BOUND = "time_bound"
STANDING_PIM_ACTIVATED = "pim_activated"
STANDINGS = (STANDING_PERMANENT, STANDING_PIM_ACTIVATED, STANDING_TIME_BOUND)
# Without Entra ID P2 (or ID Governance) the PIM lists answer 400 with one of these, which is a state, not a failure.
PIM_UNAVAILABLE_MARKERS = ("aadpremiumlicenserequired", "tenantnotonboarded")
MFA, JUSTIFICATION, TICKETING = "MultiFactorAuthentication", "Justification", "Ticketing"


def provisioned(instance: dict) -> bool:
    return (instance.get("status") or "Provisioned") == "Provisioned"


def standing(schedule: dict | None) -> str:
    """PIM lists most grants, including ones made outside it, as Assigned; a grant it lists no schedule for reads permanent."""
    if schedule is None:
        return STANDING_PERMANENT
    if (schedule.get("assignment_type") or "").lower() == "activated":
        return STANDING_PIM_ACTIVATED
    return STANDING_TIME_BOUND if schedule.get("end_date_time") else STANDING_PERMANENT


def add_pim_fields(records: list[dict], schedules: list[dict] | None) -> None:
    """Mark each active grant permanent, time_bound or pim_activated from its PIM schedule; None when unread."""
    by_origin = {
        str(s.get("origin_role_assignment_id") or "").lower(): s
        for s in sorted(schedules or [], key=lambda s: s.get("id") or "")
    }
    for record in records:
        schedule = by_origin.get(str(record.get("id") or "").lower())
        record.update(
            standing=None if schedules is None else standing(schedule),
            pim_schedule_found=None if schedules is None else schedule is not None,
            pim_assignment_type=(schedule or {}).get("assignment_type"),
            pim_member_type=(schedule or {}).get("member_type"),
            pim_start_date_time=(schedule or {}).get("start_date_time"),
            pim_end_date_time=(schedule or {}).get("end_date_time"),
        )


def eligibility_record(instance: dict, role_names: dict[str, dict]) -> dict:
    guid = role_definition_guid(instance.get("role_definition_id"))
    definition = role_names.get(str(guid).lower()) if guid else None
    over_broad = OVER_BROAD_BUILTIN_ROLES.get(str(guid).lower()) if guid else None
    level = scope_level(instance.get("scope"))
    return {
        "id": instance.get("id"),
        "scope": instance.get("scope"),
        "scope_level": level,
        "inherited_from_above_subscription": level in (SCOPE_MANAGEMENT_GROUP, SCOPE_ROOT),
        "principal_id": instance.get("principal_id"),
        "principal_type": instance.get("principal_type"),
        "role_definition_id": instance.get("role_definition_id"),
        "role_definition_guid": guid,
        "role_name": (definition or {}).get("role_name"),
        "role_name_resolved": definition is not None,
        "is_over_broad_builtin": over_broad is not None,
        "over_broad_role": over_broad,
        "can_grant_roles": str(guid).lower() in ROLE_GRANTING_ROLES if guid else False,
        "member_type": instance.get("member_type"),
        "start_date_time": instance.get("start_date_time"),
        "end_date_time": instance.get("end_date_time"),
        "is_permanent": not instance.get("end_date_time"),
        "has_condition": bool(instance.get("condition")),
    }


_NUMBER = r"(\d+(?:\.\d+)?)"
ISO_DURATION = re.compile(
    rf"^P(?:{_NUMBER}Y)?(?:{_NUMBER}M)?(?:{_NUMBER}W)?(?:{_NUMBER}D)?(?:T(?:{_NUMBER}H)?(?:{_NUMBER}M)?(?:{_NUMBER}S)?)?$"
)
# Hours per unit; a year and a month have no fixed length, so they count as 365 and 30 days.
DURATION_HOURS = (365 * 24, 30 * 24, 7 * 24, 24, 1, 1 / 60, 1 / 3600)


def duration_hours(value: str | None) -> float | None:
    """Hours in an ISO-8601 duration such as PT8H, P1DT12H or P1W; None when absent or unparseable."""
    match = ISO_DURATION.match(value or "")
    if not match or not any(match.groups()):
        return None
    return round(sum(float(n) * h for n, h in zip(match.groups(), DURATION_HOURS) if n), 2)


def policy_record(assignment: dict) -> dict:
    """One over-broad role's PIM settings at this scope, read from its effective rules."""
    rules = {r.get("id"): r for r in assignment["rules"]}

    def enabled(rule_id: str, value: str) -> bool | None:
        rule = rules.get(rule_id)
        return None if rule is None else value in (rule.get("enabled_rules") or [])

    def allows_permanent(rule_id: str) -> bool | None:
        required = (rules.get(rule_id) or {}).get("is_expiration_required")
        return None if required is None else not required

    activation = rules.get("Expiration_EndUser_Assignment") or {}
    approval = (rules.get("Approval_EndUser_Assignment") or {}).get("approval") or {}
    context = rules.get("AuthenticationContext_EndUser_Assignment") or {}
    guid = role_definition_guid(assignment.get("role_definition_id"))
    return {
        "role_name": OVER_BROAD_BUILTIN_ROLES.get(str(guid).lower()),
        "role_definition_guid": guid,
        "scope": assignment.get("scope"),
        "policy_id": assignment.get("policy_id"),
        "activation_maximum_duration": activation.get("maximum_duration"),
        "activation_maximum_hours": duration_hours(activation.get("maximum_duration")),
        "activation_requires_mfa": enabled("Enablement_EndUser_Assignment", MFA),
        "activation_requires_justification": enabled("Enablement_EndUser_Assignment", JUSTIFICATION),
        "activation_requires_ticket": enabled("Enablement_EndUser_Assignment", TICKETING),
        "activation_requires_approval": approval.get("is_approval_required"),
        # Users and groups named as approvers: a group counts once, however many members it has.
        "activation_approver_sets": approval.get("primary_approver_count"),
        "activation_authentication_context": context.get("claim_value") if context.get("is_enabled") else None,
        "permanent_eligible_assignment_allowed": allows_permanent("Expiration_Admin_Eligibility"),
        "eligible_assignment_maximum_duration": (rules.get("Expiration_Admin_Eligibility") or {}).get("maximum_duration"),
        "permanent_active_assignment_allowed": allows_permanent("Expiration_Admin_Assignment"),
        "active_assignment_maximum_duration": (rules.get("Expiration_Admin_Assignment") or {}).get("maximum_duration"),
        "active_assignment_requires_mfa": enabled("Enablement_Admin_Assignment", MFA),
        "active_assignment_requires_justification": enabled("Enablement_Admin_Assignment", JUSTIFICATION),
        "rules": sorted(
            (r for r in assignment["rules"] if not str(r.get("id") or "").startswith("Notification_")),
            key=lambda r: r.get("id") or "",
        ),
    }


def summarize_pim(
    active: list[dict], schedules_read: bool, eligible: list[dict] | None, policies: list[dict] | None, pim_available: bool | None
) -> dict:
    """PIM keys over every scope; null where the PIM read they depend on failed."""
    over_broad = [a for a in active if a["is_over_broad_builtin"]]
    permanent = [a for a in over_broad if a.get("standing") == STANDING_PERMANENT]
    eligible_over_broad = [e for e in eligible or [] if e["is_over_broad_builtin"]]

    read_roles = None if policies is None else sorted({p["role_name"] for p in policies if p["role_name"]})
    # A role whose settings weren't read would read as compliant, so the lists need all four.
    all_read = read_roles is not None and set(read_roles) == set(OVER_BROAD_BUILTIN_ROLES.values())

    def roles(pred) -> list[str] | None:
        return sorted({p["role_name"] for p in policies or [] if pred(p)}) if all_read else None

    def standing_figure(value):
        return value if schedules_read else None

    def eligible_figure(value):
        return None if eligible is None else value

    return {
        "pim_available": pim_available,
        "assignments_by_standing": standing_figure({s: sum(1 for a in active if a.get("standing") == s) for s in STANDINGS}),
        "over_broad_assignments_by_standing": standing_figure(
            {s: sum(1 for a in over_broad if a["standing"] == s) for s in STANDINGS}
        ),
        "permanent_over_broad_assignments": standing_figure(len(permanent)),
        "permanent_over_broad_user_assignments": standing_figure(sum(1 for a in permanent if a["principal_type"] == "User")),
        "principals_with_permanent_over_broad_access": standing_figure(
            len({a["principal_id"] for a in permanent if a["principal_id"]})
        ),
        "assignments_without_pim_schedule": standing_figure(sum(1 for a in active if a.get("pim_schedule_found") is False)),
        "eligible_role_assignments": eligible_figure(len(eligible or [])),
        "eligible_over_broad_assignments": eligible_figure(len(eligible_over_broad)),
        "permanently_eligible_over_broad_assignments": eligible_figure(sum(1 for e in eligible_over_broad if e["is_permanent"])),
        "principals_eligible_for_over_broad_roles": eligible_figure(
            len({e["principal_id"] for e in eligible_over_broad if e["principal_id"]})
        ),
        "over_broad_roles_activation_without_mfa_or_auth_context": roles(
            lambda p: p["activation_requires_mfa"] is False and not p["activation_authentication_context"]
        ),
        "over_broad_roles_activation_without_justification": roles(lambda p: p["activation_requires_justification"] is False),
        "over_broad_roles_activation_without_approval": roles(lambda p: p["activation_requires_approval"] is False),
        "over_broad_roles_allowing_permanent_active_assignment": roles(lambda p: p["permanent_active_assignment_allowed"] is True),
        "over_broad_roles_allowing_permanent_eligible_assignment": roles(
            lambda p: p["permanent_eligible_assignment_allowed"] is True
        ),
        "over_broad_role_policies_read": read_roles,
        "max_over_broad_activation_hours": None if not all_read else max(
            (p["activation_maximum_hours"] for p in policies or [] if p["activation_maximum_hours"] is not None), default=None
        ),
    }


# --- collection (lazy azure imports) ---

def collect_role_assignments(
    subscription_id, cred, collector: Collector
) -> tuple[list[dict], list[dict], dict]:
    """One role_definitions.list() to name the roles, two role_assignments lists.

    The definitions call comes first because an assignment references its role only by
    GUID. Prowler builds the same lookup.

    `filter="atScope()"` is Prowler's and is deliberate: without it the call also
    returns every assignment made at every resource group and individual resource,
    burying the subscription-wide grants this evidence is about. With it, the response
    is the assignments applying at the subscription scope and above.

    Those buried grants are evidence too — a resource-level Owner on a Key Vault or a
    Log Analytics workspace is exactly who can read or change it — so a second,
    UNFILTERED list collects them. It returns the atScope() set again as well; the
    second set is what it returns minus the first, by assignment id, rather than a
    re-classification by scope string, so the two sets partition the listing exactly
    whatever a scope string looks like. Returns (at_scope, below_subscription,
    role_names).
    """
    from azure.mgmt.authorization import AuthorizationManagementClient

    def _client():
        return AuthorizationManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("authorization.AuthorizationManagementClient (init)", _client)
    if client is None:
        return [], [], {}

    scope = f"/subscriptions/{subscription_id}"

    def _list_definitions():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        definitions = {}
        for definition in client.role_definitions.list(scope=scope):
            projected = project_role_definition(definition)
            # Lower-cased: ARM is inconsistent about GUID casing across API versions,
            # so a case-sensitive key would miss.
            guid = str(projected.get("name") or "").lower()
            if guid:
                definitions[guid] = projected
        return definitions

    role_names = collector.guard(
        "authorization.role_definitions.list", _list_definitions, default={}
    )

    def _list_assignments():
        return [
            assignment_record(project_role_assignment(a), role_names)
            for a in client.role_assignments.list_for_subscription(filter="atScope()")
        ]

    assignments = collector.guard(
        "authorization.role_assignments.list_for_subscription", _list_assignments, default=[]
    )

    at_scope_ids = {str(a.get("id") or "").lower() for a in assignments}

    def _list_below_subscription():
        # ItemPaged, like the call above. No filter: every assignment in the
        # subscription, down to individual resources.
        return [
            record
            for record in (
                assignment_record(project_role_assignment(a), role_names)
                for a in client.role_assignments.list_for_subscription()
            )
            if str(record.get("id") or "").lower() not in at_scope_ids
        ]

    below = collector.guard(
        "authorization.role_assignments.list_for_subscription(unfiltered)",
        _list_below_subscription,
        default=[],
    )
    logger.info(
        "Collected %d role assignment(s) at subscription scope or above and %d below it, "
        "against %d role definition(s)",
        len(assignments),
        len(below),
        len(role_names),
    )
    # Sorted by ARM id so a re-run against unchanged access is byte-stable.
    return (
        sorted(assignments, key=lambda a: a.get("id") or ""),
        sorted(below, key=lambda a: a.get("id") or ""),
        role_names,
    )


def pim_unavailable(exc: BaseException) -> bool:
    return any(m in str(exc).lower() for m in PIM_UNAVAILABLE_MARKERS)


def collect_pim(subscription_id, cred, collector: Collector, role_names: dict[str, dict]) -> dict:
    """PIM schedule instances and eligibilities at, above and below the subscription; the over-broad roles' policies at it."""
    from azure.mgmt.authorization import AuthorizationManagementClient

    out: dict = {"available": None, "schedules": None, "eligible": None, "policies": None, "notes": []}
    client = collector.guard(
        "authorization.AuthorizationManagementClient (init, PIM)",
        lambda: AuthorizationManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
    )
    if client is None:
        return out
    scope = f"/subscriptions/{subscription_id}"
    reads = {
        "schedules": (
            "authorization.role_assignment_schedule_instances.list_for_scope",
            lambda: [project_schedule_instance(i) for i in client.role_assignment_schedule_instances.list_for_scope(scope=scope)],
        ),
        "eligible": (
            "authorization.role_eligibility_schedule_instances.list_for_scope",
            lambda: [project_schedule_instance(i) for i in client.role_eligibility_schedule_instances.list_for_scope(scope=scope)],
        ),
        "policies": (
            "authorization.role_management_policy_assignments.list_for_scope",
            lambda: [
                project_policy_assignment(a)
                for a in client.role_management_policy_assignments.list_for_scope(scope=scope)
                if str(role_definition_guid(model_attr(a, "role_definition_id"))).lower() in OVER_BROAD_BUILTIN_ROLES
            ],
        ),
    }
    refused, failed = [], False
    for key, (operation, read) in reads.items():
        try:
            out[key] = read()
        except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
            if pim_unavailable(exc):
                refused.append(key)
                out["notes"].append(f"{operation}: {' '.join(str(exc).split())[:300]}")
            else:
                collector.record(operation, exc)
                failed = True
    # No PIM in the tenant: a refused list means nothing eligible and no schedule; reads that succeeded are kept.
    for key in refused:
        out[key] = {"schedules": [], "eligible": [], "policies": None}[key]
    out["available"] = False if refused else (None if failed else True)
    out["schedules"] = None if out["schedules"] is None else [s for s in out["schedules"] if provisioned(s)]
    if out["eligible"] is not None:
        out["eligible"] = sorted(
            (eligibility_record(e, role_names) for e in out["eligible"] if provisioned(e)),
            key=lambda e: (e["scope"] or "", e["role_name"] or "", e["principal_id"] or ""),
        )
    if out["policies"] is not None:
        out["policies"] = sorted((policy_record(p) for p in out["policies"]), key=lambda p: p["role_name"] or "")
    return out


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request and response header at INFO, which would
    # dominate the runner's stderr tail. Warnings and errors still come through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    assignments: list[dict] = []
    below_subscription: list[dict] = []
    pim: dict = {"available": None, "schedules": None, "eligible": None, "policies": None, "notes": []}
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list calls: Azure returns an empty list, not an error, for an
        # unregistered provider, so a zero result would otherwise be ambiguous.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Authorization"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Authorization is not registered on subscription %s — "
                "reporting status not_registered",
                subscription_id,
            )
        assignments, below_subscription, role_names = collect_role_assignments(
            subscription_id, cred, collector
        )
        pim = collect_pim(subscription_id, cred, collector, role_names)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    add_pim_fields(assignments + below_subscription, pim["schedules"])
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "role_assignments": assignments,
            # Resource-group and resource grants: the unfiltered listing minus the
            # atScope() set above. Same record shape.
            "role_assignments_below_subscription": below_subscription,
            "provider_registration_status": registration,
            # In the evidence so a reader knows which GUIDs decided the flags.
            "over_broad_builtin_roles_checked": dict(sorted(OVER_BROAD_BUILTIN_ROLES.items())),
            "assignment_scope_filter": "atScope()",
            "pim_available": pim["available"],
            "eligible_role_assignments": pim["eligible"],
            "pim_role_policies": pim["policies"],
            "pim_notes": pim["notes"],
        },
        summary={
            **summarize(assignments),
            **summarize_all_scopes(assignments, below_subscription),
            "provider_registration_status": registration,
            **summarize_pim(
                assignments + below_subscription, pim["schedules"] is not None, pim["eligible"], pim["policies"], pim["available"]
            ),
        },
    )

    filename = (
        f"azure_rbac_role_assignments_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
