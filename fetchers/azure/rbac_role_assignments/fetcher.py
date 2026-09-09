#!/usr/bin/env python3
"""
Azure RBAC role assignments on one subscription

Who holds what, where: each assignment with its scope classified, its principal, and its
role definition with the NAME resolved from the GUID, flagged for the four over-broad
built-ins.

Projections ported from Prowler's
prowler/providers/azure/services/iam/iam_service.py `_get_role_assignments` and
`_get_roles` (Apache-2.0) — same SDK, same two calls, same `atScope()` filter. The
four role GUIDs are theirs verbatim, from prowler/providers/azure/config.py.
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    report_failure,
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


# --- collection (lazy azure imports) ---

def collect_role_assignments(subscription_id, cred, collector: Collector) -> tuple[list[dict], dict]:
    """One role_definitions.list() to name the roles, one role_assignments.list().

    The definitions call comes first because an assignment references its role only by
    GUID. Prowler builds the same lookup.

    `filter="atScope()"` is Prowler's and is deliberate: without it the call also
    returns every assignment made at every resource group and individual resource,
    burying the subscription-wide grants this evidence is about. With it, the response
    is the assignments applying at the subscription scope and above.
    """
    from azure.mgmt.authorization import AuthorizationManagementClient

    def _client():
        return AuthorizationManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("authorization.AuthorizationManagementClient (init)", _client)
    if client is None:
        return [], {}

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
    logger.info(
        "Collected %d role assignment(s) against %d role definition(s)",
        len(assignments),
        len(role_names),
    )
    # Sorted by ARM id so a re-run against unchanged access is byte-stable.
    return sorted(assignments, key=lambda a: a.get("id") or ""), role_names


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
        assignments, _ = collect_role_assignments(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "role_assignments": assignments,
            "provider_registration_status": registration,
            # In the evidence so a reader knows which GUIDs decided the flags.
            "over_broad_builtin_roles_checked": dict(sorted(OVER_BROAD_BUILTIN_ROLES.items())),
            "assignment_scope_filter": "atScope()",
        },
        summary={**summarize(assignments), "provider_registration_status": registration},
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
