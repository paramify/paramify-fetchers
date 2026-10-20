#!/usr/bin/env python3
"""Dormant, never-used, guest and deleted identities that still hold an Entra directory role or an Azure role in one subscription."""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import int_config, parse_time, run_subscription  # noqa: E402
from entra_graph import is_privileged_role  # noqa: E402

NAME = "azure_entra_dormant_identities"
AUTHZ_API = "2022-04-01"
DORMANT_DAYS_ENV = "ENTRA_DORMANT_DAYS"
DEFAULT_DORMANT_DAYS = 90
GRAPH_BATCH = 1000

USER_SELECT = (
    "id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,externalUserState"
)
ODATA_USER = "#microsoft.graph.user"
ODATA_GROUP = "#microsoft.graph.group"
ODATA_SP = "#microsoft.graph.servicePrincipal"
# Groups from another tenant (CSP/GDAP partners); this tenant's directory can never return them.
FOREIGN_PRINCIPAL_TYPES = frozenset({"foreigngroup"})
# The 403 Graph sends a tenant with no Entra ID P1/P2 for sign-in activity.
NOT_LICENSED_MARKER = "nonpremiumtenant"
# appOwnerOrganizationId of Microsoft's first-party apps.
MICROSOFT_OWNER_TENANTS = frozenset({"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"})

READ = "read"
NOT_LICENSED = "not_licensed"
NOT_READ = "not_read"

logger = logging.getLogger(NAME)


def _guid(resource_id) -> str:
    return (resource_id or "").rstrip("/").rsplit("/", 1)[-1].lower()


def _days_since(value, now: datetime) -> Optional[int]:
    parsed = parse_time(value)
    return None if parsed is None else (now - parsed).days


def _latest(*values) -> Optional[str]:
    parsed = [(parse_time(v), v) for v in values if parse_time(v) is not None]
    return max(parsed)[1] if parsed else None


def read_status(collector, before: int) -> str:
    """read, not_licensed (no Entra ID P1/P2) or not_read, from the failures since `before`."""
    failures = collector.failures[before:]
    if not failures:
        return READ
    if any(NOT_LICENSED_MARKER in (f.get("message") or "").lower() for f in failures):
        return NOT_LICENSED
    return NOT_READ


# --- role holdings (flat dicts in, {principal id: [holdings]} out) ---

def directory_role_holdings(roles: List[dict], group_members: Dict[str, List[dict]]) -> Dict[str, List[dict]]:
    """Each active directory role a principal holds, directly or through a role-assignable group."""
    held: Dict[str, List[dict]] = {}
    for role in roles:
        entry = {"role": role.get("displayName") or role.get("roleTemplateId"), "privileged": is_privileged_role(
            {"display_name": role.get("displayName"), "role_template_id": role.get("roleTemplateId")}
        )}
        for member in role.get("members") or []:
            mid = (member.get("id") or "").lower()
            if member.get("@odata.type") == ODATA_GROUP:
                for inner in group_members.get(mid) or []:
                    held.setdefault((inner.get("id") or "").lower(), []).append({**entry, "via_group_id": mid})
            elif mid:
                held.setdefault(mid, []).append({**entry, "via_group_id": None})
    return held


def azure_role_holdings(assignments: List[dict], role_names: Dict[str, str],
                        group_members: Dict[str, List[dict]]) -> Dict[str, List[dict]]:
    """Each Azure role assignment a principal holds, directly or through a group."""
    held: Dict[str, List[dict]] = {}
    for a in assignments:
        props = a.get("properties") or {}
        pid = (props.get("principalId") or "").lower()
        entry = {
            "role": role_names.get(_guid(props.get("roleDefinitionId"))),
            "role_definition_id": props.get("roleDefinitionId"),
            "scope": props.get("scope"),
            "assignment_id": a.get("id"),
        }
        if (props.get("principalType") or "").lower() == "group":
            for inner in group_members.get(pid) or []:
                held.setdefault((inner.get("id") or "").lower(), []).append({**entry, "via_group_id": pid})
        if pid:
            held.setdefault(pid, []).append({**entry, "via_group_id": None})
    return held


# --- identity records ---

def user_record(user: dict, activity_ok: bool, directory: list, azure: list, days: int, now: datetime) -> dict:
    activity = user.get("signInActivity") or {}
    enabled = user.get("accountEnabled")
    enabled = True if enabled is None else bool(enabled)
    last_success = activity.get("lastSuccessfulSignInDateTime")
    attempts = [activity.get("lastSignInDateTime"), activity.get("lastNonInteractiveSignInDateTime")]
    since = _days_since(last_success, now)
    created = _days_since(user.get("createdDateTime"), now)
    if not activity_ok:
        never = dormant = None
    else:
        never = not last_success and not any(attempts)
        stale = since > days if since is not None else (created is None or created > days)
        dormant = enabled and stale
    return {
        "id": user.get("id"),
        "kind": "user",
        "display_name": user.get("displayName"),
        "user_principal_name": user.get("userPrincipalName"),
        "user_type": user.get("userType"),
        "is_guest": (user.get("userType") or "") == "Guest",
        "external_user_state": user.get("externalUserState"),
        "account_enabled": enabled,
        "created_date_time": user.get("createdDateTime"),
        "last_successful_sign_in_date_time": last_success if activity_ok else None,
        "last_interactive_sign_in_attempt": attempts[0] if activity_ok else None,
        "last_non_interactive_sign_in_attempt": attempts[1] if activity_ok else None,
        "days_since_last_successful_sign_in": since if activity_ok else None,
        "never_signed_in": never,
        "dormant": dormant,
        **_roles(directory, azure),
    }


def service_principal_record(sp: dict, activity: Optional[dict], activity_ok: bool,
                             directory: list, azure: list, days: int, now: datetime) -> dict:
    """A principal holding a role; dormancy is judged on its sign-ins as a client, the way it uses a role."""
    enabled = sp.get("accountEnabled")
    enabled = True if enabled is None else bool(enabled)
    in_report = activity is not None
    activity = activity or {}
    last_client = _latest(
        (activity.get("applicationAuthenticationClientSignInActivity") or {}).get("lastSignInDateTime"),
        (activity.get("delegatedClientSignInActivity") or {}).get("lastSignInDateTime"),
    )
    since = _days_since(last_client, now)
    # Microsoft doesn't document the report covering managed identities or its own apps, so no entry is no evidence.
    unknown = not in_report and (
        sp.get("servicePrincipalType") == "ManagedIdentity"
        or (sp.get("appOwnerOrganizationId") or "").lower() in MICROSOFT_OWNER_TENANTS
    )
    if not activity_ok or unknown:
        dormant = None
    else:
        dormant = enabled and (since is None or since > days)
    return {
        "id": sp.get("id"),
        "kind": "service_principal",
        "app_id": sp.get("appId"),
        "display_name": sp.get("displayName"),
        "service_principal_type": sp.get("servicePrincipalType"),
        "app_owner_organization_id": sp.get("appOwnerOrganizationId"),
        "account_enabled": enabled,
        "in_sign_in_activity_report": in_report if activity_ok else None,
        "last_client_sign_in_date_time": last_client if activity_ok else None,
        "last_sign_in_date_time": (
            (activity.get("lastSignInActivity") or {}).get("lastSignInDateTime") if activity_ok else None
        ),
        "days_since_last_client_sign_in": since if activity_ok else None,
        "no_recorded_client_sign_in": (last_client is None) if activity_ok else None,
        "dormant": dormant,
        **_roles(directory, azure),
    }


def _roles(directory: list, azure: list) -> dict:
    directory = sorted(directory, key=lambda r: (r["role"] or "", r["via_group_id"] or ""))
    azure = sorted(azure, key=lambda r: (r["scope"] or "", r["role"] or "", r["via_group_id"] or ""))
    return {
        "directory_roles": directory,
        "azure_roles": azure,
        "holds_directory_role": bool(directory),
        "holds_privileged_directory_role": any(r["privileged"] for r in directory),
        "holds_azure_role": bool(azure),
        "holds_role": bool(directory or azure),
    }


def deleted_principal_record(pid: str, assignments: List[dict], azure: list) -> dict:
    types = sorted({(a.get("properties") or {}).get("principalType") or "Unknown" for a in assignments})
    return {"id": pid, "kind": "deleted", "principal_types_recorded": types, **_roles([], azure)}


# --- summary ---

def summarize(users: List[dict], sps: List[dict], deleted: List[dict], status: Dict[str, Any], days: int) -> dict:
    def n(rows, predicate):
        return sum(1 for r in rows if predicate(r))

    def when(ok, value):
        return value if ok else None

    users_ok = status["user_sign_in_activity"] == READ
    sps_ok = status["service_principal_sign_in_activity"] == READ
    roles_ok = status["directory_roles"] == READ and status["azure_roles"] == READ
    lookup_ok = status["principal_lookup"] == READ
    holders = [u for u in users if u["holds_role"]]
    sp_holders = [s for s in sps if s["holds_role"]]
    figures = {
        # --- what was checked ---
        "dormant_after_days": days,
        "user_sign_in_activity": status["user_sign_in_activity"],
        "service_principal_sign_in_activity": status["service_principal_sign_in_activity"],
        "directory_roles_readable": status["directory_roles"] == READ,
        "azure_roles_readable": status["azure_roles"] == READ,
        "principal_lookup_readable": lookup_ok,
        "users_checked": len(users),
        "service_principals_holding_roles": len(sp_holders),
        # --- who holds a role ---
        "users_holding_roles": len(holders),
        "users_holding_directory_roles": n(users, lambda u: u["holds_directory_role"]),
        "users_holding_privileged_directory_roles": n(users, lambda u: u["holds_privileged_directory_role"]),
        "users_holding_azure_roles": n(users, lambda u: u["holds_azure_role"]),
        "service_principals_holding_directory_roles": n(sps, lambda s: s["holds_directory_role"]),
        "service_principals_holding_azure_roles": n(sps, lambda s: s["holds_azure_role"]),
        # --- are enabled accounts in use ---
        "enabled_users": n(users, lambda u: u["account_enabled"]),
        "guest_users": n(users, lambda u: u["is_guest"]),
        "dormant_users": when(users_ok, n(users, lambda u: u["dormant"])),
        "users_never_signed_in": when(users_ok, n(users, lambda u: u["never_signed_in"])),
        "dormant_service_principals_holding_roles": when(sps_ok, n(sp_holders, lambda s: s["dormant"])),
        "service_principals_holding_roles_without_recorded_sign_in": when(
            sps_ok, n(sp_holders, lambda s: s["no_recorded_client_sign_in"])
        ),
        "service_principals_holding_roles_dormancy_unknown": when(
            sps_ok, n(sp_holders, lambda s: s["dormant"] is None)
        ),
        # --- does any dormant, unused, guest or deleted identity hold a role ---
        "dormant_users_holding_roles": when(users_ok and roles_ok, n(holders, lambda u: u["dormant"])),
        "never_signed_in_users_holding_roles": when(
            users_ok and roles_ok, n(holders, lambda u: u["never_signed_in"])
        ),
        "guest_users_holding_roles": when(roles_ok, n(holders, lambda u: u["is_guest"])),
        "disabled_users_holding_roles": when(roles_ok, n(holders, lambda u: not u["account_enabled"])),
        "deleted_principals_holding_azure_roles": when(roles_ok and lookup_ok, len(deleted)),
        "azure_role_assignments_to_deleted_principals": when(
            roles_ok and lookup_ok, sum(len(d["azure_roles"]) for d in deleted)
        ),
    }
    flagged = [
        figures["dormant_users_holding_roles"],
        figures["never_signed_in_users_holding_roles"],
        figures["guest_users_holding_roles"],
        figures["dormant_service_principals_holding_roles"],
        figures["deleted_principals_holding_azure_roles"],
    ]
    if any(v for v in flagged if v):
        clean: Optional[bool] = False
    elif any(v is None for v in flagged) or figures["service_principals_holding_roles_dormancy_unknown"]:
        clean = None
    else:
        clean = True
    figures["no_inactive_identity_holds_a_role"] = clean
    return figures


# --- collection ---

def _graph_list(client, collector, operation: str, path: str, version: str = "v1.0"):
    return collector.guard(operation, lambda: client.graph_list(path, version), default=None)


def _group_members(client, collector, group_ids) -> Dict[str, List[dict]]:
    # v1.0 /members leaves out service principals; beta includes them.
    out = {}
    for gid in sorted(group_ids):
        members = _graph_list(
            client, collector, f"graph.groups({gid}).transitiveMembers.get(beta)",
            f"/groups/{gid}/transitiveMembers?$select=id", "beta",
        )
        out[gid] = [m for m in members or [] if m.get("@odata.type") in (ODATA_USER, ODATA_SP)]
    return out


def _lookup(client, collector, ids: List[str]) -> Optional[Dict[str, dict]]:
    """Directory objects by id, or None if the lookup failed."""
    found: Dict[str, dict] = {}
    for start in range(0, len(ids), GRAPH_BATCH):
        body = collector.guard(
            "graph.directoryObjects.getByIds",
            lambda start=start: client.graph_post("/directoryObjects/getByIds", {"ids": ids[start:start + GRAPH_BATCH]}),
        )
        if body is None:
            return None
        found.update({(o.get("id") or "").lower(): o for o in body.get("value") or []})
    return found


def collect(client, subscription_id: str, collector) -> tuple:
    now = datetime.now(timezone.utc)
    days = int_config(DORMANT_DAYS_ENV, DEFAULT_DORMANT_DAYS)
    status: Dict[str, Any] = {}

    before = len(collector.failures)
    users = _graph_list(client, collector, "graph.users.get(signInActivity)",
                        f"/users?$select={USER_SELECT},signInActivity")
    status["user_sign_in_activity"] = read_status(collector, before)
    if users is None:
        # Sign-in activity needs AuditLog.Read.All and P1; still list the users and their roles.
        users = _graph_list(client, collector, "graph.users.get", f"/users?$select={USER_SELECT}") or []

    before = len(collector.failures)
    activities = _graph_list(client, collector, "graph.reports.servicePrincipalSignInActivities.get(beta)",
                             "/reports/servicePrincipalSignInActivities", "beta")
    status["service_principal_sign_in_activity"] = read_status(collector, before)
    by_app = {(a.get("appId") or "").lower(): a for a in activities or []}

    before = len(collector.failures)
    roles = _graph_list(client, collector, "graph.directoryRoles.get", "/directoryRoles") or []
    for role in roles:
        role["members"] = _graph_list(
            client, collector, f"graph.directoryRoles({role.get('displayName')}).members.get",
            f"/directoryRoles/{role.get('id')}/members?$select=id",
        ) or []
    status["directory_roles"] = READ if len(collector.failures) == before else NOT_READ

    before = len(collector.failures)
    scope = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization"
    role_names = {
        _guid(d.get("id")): (d.get("properties") or {}).get("roleName")
        for d in collector.guard("authorization.roleDefinitions.list",
                                 lambda: client.list(f"{scope}/roleDefinitions", AUTHZ_API), default=[])
    }
    # Unfiltered: every assignment that applies, inherited from management groups or made below.
    assignments = collector.guard("authorization.roleAssignments.list",
                                  lambda: client.list(f"{scope}/roleAssignments", AUTHZ_API), default=[])
    status["azure_roles"] = READ if len(collector.failures) == before else NOT_READ

    groups = {(m.get("id") or "").lower() for r in roles for m in r["members"] if m.get("@odata.type") == ODATA_GROUP}
    groups |= {
        ((a.get("properties") or {}).get("principalId") or "").lower()
        for a in assignments if ((a.get("properties") or {}).get("principalType") or "").lower() == "group"
    }
    before = len(collector.failures)
    group_members = _group_members(client, collector, groups)
    if len(collector.failures) > before:
        status["directory_roles"] = status["azure_roles"] = NOT_READ

    directory = directory_role_holdings(roles, group_members)
    azure = azure_role_holdings(assignments, role_names, group_members)
    user_ids = {(u.get("id") or "").lower() for u in users}
    rbac_ids = {
        ((a.get("properties") or {}).get("principalId") or "").lower(): a for a in assignments
        if (a.get("properties") or {}).get("principalId")
        and ((a.get("properties") or {}).get("principalType") or "").lower() not in FOREIGN_PRINCIPAL_TYPES
    }
    foreign = {
        ((a.get("properties") or {}).get("principalId") or "").lower() for a in assignments
        if ((a.get("properties") or {}).get("principalType") or "").lower() in FOREIGN_PRINCIPAL_TYPES
    }
    lookup_ids = sorted((set(directory) | set(azure)) - user_ids - foreign - {""})
    before = len(collector.failures)
    found = _lookup(client, collector, lookup_ids) if lookup_ids else {}
    status["principal_lookup"] = READ if len(collector.failures) == before else NOT_READ

    user_records = sorted(
        (user_record(u, status["user_sign_in_activity"] == READ, directory.get((u.get("id") or "").lower(), []),
                     azure.get((u.get("id") or "").lower(), []), days, now) for u in users),
        key=lambda r: ((r["user_principal_name"] or "").lower(), r["id"] or ""),
    )
    sp_records, deleted = [], []
    for pid in lookup_ids:
        obj = (found or {}).get(pid)
        if obj is not None and obj.get("@odata.type") == ODATA_SP:
            sp_records.append(service_principal_record(
                obj, by_app.get((obj.get("appId") or "").lower()),
                status["service_principal_sign_in_activity"] == READ,
                directory.get(pid, []), azure.get(pid, []), days, now,
            ))
        elif found is not None and obj is None and pid in rbac_ids:
            deleted.append(deleted_principal_record(
                pid, [a for a in assignments if ((a.get("properties") or {}).get("principalId") or "").lower() == pid],
                azure.get(pid, []),
            ))
    sp_records.sort(key=lambda r: ((r["display_name"] or "").lower(), r["id"] or ""))
    logger.info("Collected %d user(s), %d role-holding service principal(s), %d deleted principal(s)",
                len(user_records), len(sp_records), len(deleted))
    results = {
        "users": user_records,
        "service_principals": sp_records,
        "deleted_principals": deleted,
        "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return results, summarize(user_records, sp_records, deleted, status, days)


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
