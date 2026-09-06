#!/usr/bin/env python3
"""
Azure RBAC custom role definitions on one subscription

Every custom role with its assignable scopes and permissions, flagged for wildcard
breadth and for the permissions that let a holder escalate its own privileges.
Projections ported from Prowler's
prowler/providers/azure/services/iam/iam_service.py `_get_roles` (Apache-2.0);
wildcard and resource-lock breadth from their
iam_subscription_roles_owner_custom_not_created and
iam_custom_role_has_permissions_to_administer_resource_locks checks. The
privilege-escalation classification has no upstream ancestor. Deviation: wildcards are
expanded with Azure's semantics and `not_actions` subtracted — see `action_matches()`.
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
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_rbac_custom_roles")

CUSTOM_ROLE = "CustomRole"

# Escalation itself: a principal that can write role assignments can assign itself
# Owner, however narrow the rest of the role looks.
ROLE_ASSIGNMENT_WRITE = "Microsoft.Authorization/roleAssignments/write"

# The same escalation one step removed — rewrite a role you already hold.
ROLE_DEFINITION_WRITE = "Microsoft.Authorization/roleDefinitions/write"

DENY_ASSIGNMENT_WRITE = "Microsoft.Authorization/denyAssignments/write"

# A mapping rather than a set, so the evidence can name WHICH permission matched.
PRIVILEGE_ESCALATION_ACTIONS = {
    ROLE_ASSIGNMENT_WRITE: "can assign any role to any principal, including Owner",
    ROLE_DEFINITION_WRITE: "can rewrite the permissions of a role it already holds",
    DENY_ASSIGNMENT_WRITE: "can write deny assignments that shield resources from others",
}

# Prowler's iam_custom_role_has_permissions_to_administer_resource_locks: lock
# administration can strip the locks protecting production resources from deletion.
RESOURCE_LOCK_ACTION_PREFIX = "Microsoft.Authorization/locks/"

# Prowler's iam_subscription_roles_owner_custom_not_created tests for exactly this
# literal in a custom role's actions.
WILDCARD_ACTION = "*"

# A role assignable at "/" may be granted anywhere in the tenant.
ROOT_SCOPE = "/"


# --- projections: the only code here that touches an azure-mgmt model ---

def project_permission(permission) -> dict:
    """Read a `Permission` model's four action lists into a flat dict.

    All four are kept: actions/not_actions govern the CONTROL plane, data_actions/
    not_data_actions the DATA plane, and a role can be modest on one and grant `*` on
    the other. Each is `or []` because the SDK leaves an unset action list as None.
    """
    return {
        "actions": list(model_attr(permission, "actions") or []),
        "not_actions": list(model_attr(permission, "not_actions") or []),
        "data_actions": list(model_attr(permission, "data_actions") or []),
        "not_data_actions": list(model_attr(permission, "not_data_actions") or []),
    }


def project_role_definition(definition) -> dict:
    """Read a `RoleDefinition` model's attributes into a flat snake_case dict.

    The SDK's naming is inverted: `name` is the role's GUID, `role_name` its display
    name. Both are kept. Timestamps are `str()`-rendered here rather than left to
    `json.dump`'s `default=str`.
    """
    created_on = model_attr(definition, "created_on")
    updated_on = model_attr(definition, "updated_on")
    return {
        "id": model_attr(definition, "id"),
        "name": model_attr(definition, "name"),
        "role_name": model_attr(definition, "role_name"),
        "role_type": model_attr(definition, "role_type"),
        "description": model_attr(definition, "description"),
        "assignable_scopes": list(model_attr(definition, "assignable_scopes") or []),
        "permissions": [
            project_permission(p) for p in (model_attr(definition, "permissions") or [])
        ],
        "created_on": str(created_on) if created_on is not None else None,
        "updated_on": str(updated_on) if updated_on is not None else None,
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def action_matches(pattern: str, action: str) -> bool:
    """Whether an Azure RBAC action `pattern` grants the concrete `action`.

    Azure's action wildcards are NOT path globs: `*` matches any sequence INCLUDING
    `/`, so `*/write` and `Microsoft.Authorization/*` both grant
    `Microsoft.Authorization/roleAssignments/write`. Prowler's checks compare action
    strings literally and therefore recognise none of those forms; this expands them,
    which is why the escalation check cannot be a literal `in` test.

    Case-insensitive because ARM treats action strings that way.
    """
    if not pattern or not action:
        return False
    regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return re.match(regex, action, re.IGNORECASE) is not None


def grants_action(permission: dict, action: str, data_plane: bool = False) -> bool:
    """Whether one permission block grants `action` after `not_actions` is subtracted.

    Ignoring `not_actions` would report every "grant `*`, deny the dangerous bits" role
    as an escalation path — a false positive on the most widespread least-privilege
    idiom there is. The same wildcard semantics apply on the deny side.
    """
    allow_key, deny_key = ("data_actions", "not_data_actions") if data_plane else (
        "actions",
        "not_actions",
    )
    allowed = any(action_matches(p, action) for p in (permission.get(allow_key) or []))
    if not allowed:
        return False
    return not any(action_matches(p, action) for p in (permission.get(deny_key) or []))


def role_grants_action(role: dict, action: str) -> bool:
    """Whether ANY of a role's permission blocks grants the CONTROL-plane `action`.

    Blocks are independent: Azure unions the allow lists across blocks and each block's
    `not_actions` subtracts only from its own, so one permissive block is enough.

    Control plane only, deliberately: `data_actions` is a separate permission space that
    cannot confer a management operation, so testing it here would report a
    `data_actions: ["*"]` role as an escalation path. Data-plane breadth is reported on
    its own, as `has_data_actions` and `wildcard_actions.data_plane`.
    """
    return any(grants_action(p, action) for p in (role.get("permissions") or []))


def _wildcard_actions(role: dict) -> dict:
    """The literal wildcard entries in a role, split by plane.

    The exact strings rather than a boolean: `*` is Owner-equivalent while
    `Microsoft.Compute/*` is scoped to one provider.
    """
    control, data = [], []
    for permission in role.get("permissions") or []:
        control.extend(a for a in (permission.get("actions") or []) if "*" in str(a))
        data.extend(a for a in (permission.get("data_actions") or []) if "*" in str(a))
    return {"control_plane": sorted(set(control)), "data_plane": sorted(set(data))}


def custom_role_record(role: dict) -> dict:
    """Normalize one projected custom role definition into an evidence record.

    `is_owner_equivalent` is Prowler's iam_subscription_roles_owner_custom_not_created
    condition — an assignable scope of the form `/...` AND an action of exactly `*` —
    with `not_actions` honored.
    """
    assignable_scopes = list(role.get("assignable_scopes") or [])
    permissions = role.get("permissions") or []
    wildcards = _wildcard_actions(role)

    escalation = sorted(
        action for action in PRIVILEGE_ESCALATION_ACTIONS if role_grants_action(role, action)
    )
    # Prowler matches `^/.*` against each assignable scope — every real ARM scope
    # satisfies it, so the `*` action is the clause that decides the finding.
    has_bare_wildcard = any(
        WILDCARD_ACTION in (p.get("actions") or []) for p in permissions
    )
    # One permission separates Owner from Contributor: both grant `*`, and Contributor
    # subtracts `Microsoft.Authorization/*/write`.
    can_assign_roles = role_grants_action(role, ROLE_ASSIGNMENT_WRITE)

    return {
        "id": role.get("id"),
        # The SDK's naming is inverted: `name` is the GUID, `role_name` the label.
        "role_definition_guid": role.get("name"),
        "role_name": role.get("role_name"),
        "role_type": role.get("role_type"),
        "description": role.get("description"),
        # --- where it may be assigned ---
        "assignable_scopes": assignable_scopes,
        "has_root_assignable_scope": ROOT_SCOPE in [str(s).strip() for s in assignable_scopes],
        "assignable_scope_count": len(assignable_scopes),
        # --- what it grants ---
        "permissions": permissions,
        "action_count": sum(len(p.get("actions") or []) for p in permissions),
        "data_action_count": sum(len(p.get("data_actions") or []) for p in permissions),
        "has_data_actions": any(p.get("data_actions") for p in permissions),
        "has_not_actions": any(p.get("not_actions") or p.get("not_data_actions") for p in permissions),
        # --- wildcard breadth ---
        "wildcard_actions": wildcards,
        "has_wildcard_action": bool(wildcards["control_plane"] or wildcards["data_plane"]),
        "has_all_actions_wildcard": has_bare_wildcard,
        # Prowler's owner-equivalent test, with not_actions honored.
        "is_owner_equivalent": has_bare_wildcard and can_assign_roles,
        "is_contributor_equivalent": has_bare_wildcard and not can_assign_roles,
        # --- privilege escalation ---
        "privilege_escalation_actions": escalation,
        "can_escalate_privileges": bool(escalation),
        "can_assign_roles": can_assign_roles,
        "can_write_role_definitions": role_grants_action(role, ROLE_DEFINITION_WRITE),
        # --- other administrative powers ---
        # Prowler matches the literal prefix; the wildcard matcher also catches the `*`
        # and `Microsoft.Authorization/*` forms, and honors not_actions.
        "can_administer_resource_locks": role_grants_action(
            role, f"{RESOURCE_LOCK_ACTION_PREFIX}delete"
        ),
        "created_on": role.get("created_on"),
        "updated_on": role.get("updated_on"),
    }


def summarize(custom_roles: list[dict], total_definitions: int) -> dict:
    """Escalation-capable custom roles are the headline.

    `total_role_definitions` and `builtin_role_definitions` are reported alongside so
    `custom_role_definitions: 0` is legible: a non-zero built-in count proves the list
    call worked rather than returning nothing.
    """
    escalating = [r for r in custom_roles if r["can_escalate_privileges"]]
    return {
        "total_role_definitions": total_definitions,
        "builtin_role_definitions": total_definitions - len(custom_roles),
        "custom_role_definitions": len(custom_roles),
        # --- the headline ---
        "custom_roles_with_privilege_escalation": len(escalating),
        "custom_roles_that_can_assign_roles": sum(1 for r in custom_roles if r["can_assign_roles"]),
        "custom_roles_that_can_write_role_definitions": sum(
            1 for r in custom_roles if r["can_write_role_definitions"]
        ),
        "custom_roles_with_escalation_names": sorted(
            r["role_name"] or "" for r in escalating
        ),
        # --- wildcard breadth ---
        "custom_roles_with_wildcard_actions": sum(
            1 for r in custom_roles if r["has_wildcard_action"]
        ),
        "custom_roles_with_all_actions_wildcard": sum(
            1 for r in custom_roles if r["has_all_actions_wildcard"]
        ),
        "owner_equivalent_custom_roles": sum(1 for r in custom_roles if r["is_owner_equivalent"]),
        "contributor_equivalent_custom_roles": sum(
            1 for r in custom_roles if r["is_contributor_equivalent"]
        ),
        # --- data plane and scope breadth ---
        "custom_roles_with_data_actions": sum(1 for r in custom_roles if r["has_data_actions"]),
        "custom_roles_with_root_assignable_scope": sum(
            1 for r in custom_roles if r["has_root_assignable_scope"]
        ),
        "custom_roles_with_not_actions": sum(1 for r in custom_roles if r["has_not_actions"]),
        "custom_roles_administering_resource_locks": sum(
            1 for r in custom_roles if r["can_administer_resource_locks"]
        ),
        # --- neither wildcard-broad nor escalation-capable ---
        "least_privilege_custom_roles": sum(
            1
            for r in custom_roles
            if not r["has_wildcard_action"] and not r["can_escalate_privileges"]
        ),
        "least_privilege_percentage": coverage_percentage(
            sum(
                1
                for r in custom_roles
                if not r["has_wildcard_action"] and not r["can_escalate_privileges"]
            ),
            len(custom_roles),
        ),
    }


# --- collection (lazy azure imports) ---

def collect_custom_roles(subscription_id, cred, collector: Collector) -> tuple[list[dict], int]:
    """One role_definitions.list(), split into custom and built-in in Python.

    Listing unfiltered rather than passing `filter="type eq 'CustomRole'"` is Prowler's
    approach and buys the total and built-in counts from the same call.

    The scope is the subscription, so custom roles defined at a management group above
    it and assignable here are NOT returned — a known limitation of a per-subscription
    read, not a failure.
    """
    from azure.mgmt.authorization import AuthorizationManagementClient

    def _client():
        return AuthorizationManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("authorization.AuthorizationManagementClient (init)", _client)
    if client is None:
        return [], 0

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        custom, total = [], 0
        for definition in client.role_definitions.list(scope=f"/subscriptions/{subscription_id}"):
            projected = project_role_definition(definition)
            total += 1
            if str(projected.get("role_type") or "") == CUSTOM_ROLE:
                custom.append(custom_role_record(projected))
        return custom, total

    custom_roles, total = collector.guard(
        "authorization.role_definitions.list", _list, default=([], 0)
    )
    logger.info(
        "Collected %d custom role definition(s) out of %d total", len(custom_roles), total
    )
    # Sorted by ARM id so a re-run against unchanged roles is byte-stable.
    return sorted(custom_roles, key=lambda r: r.get("id") or ""), total


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

    custom_roles: list[dict] = []
    total_definitions = 0
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call: Azure returns an empty list, not an error, for an
        # unregistered provider, so a zero-role result would otherwise be ambiguous.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Authorization"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Authorization is not registered on subscription %s — "
                "reporting status not_registered",
                subscription_id,
            )
        custom_roles, total_definitions = collect_custom_roles(subscription_id, cred, collector)
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
            "custom_roles": custom_roles,
            "provider_registration_status": registration,
            # In the evidence so a reader knows which permissions decided the flags.
            "privilege_escalation_actions_checked": dict(
                sorted(PRIVILEGE_ESCALATION_ACTIONS.items())
            ),
        },
        summary={
            **summarize(custom_roles, total_definitions),
            "provider_registration_status": registration,
        },
    )

    filename = (
        f"azure_rbac_custom_roles_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
