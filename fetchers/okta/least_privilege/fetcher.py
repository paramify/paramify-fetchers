#!/usr/bin/env python3
"""KSI-IAM-05: Least Privilege.

Configure IAM so users/devices can only access the resources they need. Collects
the org's administrators (with how each was detected), regular-user counts, and a
sample of group memberships as evidence of privilege scoping.

Related controls: AC-2.5, AC-6, IA-2, PS-2.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List

# Import the category-shared client + run scaffolding from _shared/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))

from okta_client import OktaAPIClient  # noqa: E402
from okta_runner import run  # noqa: E402

logger = logging.getLogger("okta_least_privilege")

# How far back to scan the system log for privileged activity (a corroborating
# admin signal). Overridable via env for orgs with longer/shorter retention.
ADMIN_ACTIVITY_LOOKBACK_DAYS = int(os.environ.get("OKTA_ADMIN_ACTIVITY_LOOKBACK_DAYS", "90"))

# Fallback group-name heuristics, used ONLY to corroborate the authoritative
# role-assignment check below. No org-specific data — override per org if needed.
_DEFAULT_ADMIN_GROUP_NAMES = ["Okta Administrators", "Administrators", "Super Admin", "Org Admin", "Admin"]

# Okta system-log events that only an administrator can generate. Kept broad so
# the log scan corroborates admins whose privilege isn't currently role-assigned
# (e.g. granted-then-revoked, or acting via a service integration).
_ADMIN_EVENT_TYPES = [
    "user.admin.privilege.grant",
    "user.admin.privilege.revoke",
    "user.admin.role.assign",
    "user.admin.role.unassign",
    "system.config.create",
    "system.config.update",
    "system.config.delete",
    "policy.rule.create",
    "policy.rule.update",
    "policy.rule.delete",
    "policy.lifecycle.create",
    "user.lifecycle.create",
    "group.lifecycle.create",
]


def _admin_group_names() -> List[str]:
    override = os.environ.get("OKTA_ADMIN_GROUP_NAMES", "").strip()
    if override:
        return [n.strip() for n in override.split(",") if n.strip()]
    return _DEFAULT_ADMIN_GROUP_NAMES


def _profile(user: Dict) -> Dict:
    return user.get("profile", {}) or {}


def _full_name(user: Dict) -> str:
    p = _profile(user)
    return f"{p.get('firstName', '')} {p.get('lastName', '')}".strip()


def _admin_entry(user: Dict, detection_method: str, **extra) -> Dict:
    p = _profile(user)
    entry = {
        "id": user["id"],
        "login": p.get("login"),
        "email": p.get("email"),
        "name": _full_name(user),
        "detection_method": detection_method,
    }
    entry.update(extra)
    return entry


def collect(client: OktaAPIClient) -> Dict:
    evidence: Dict = {
        "ksi": "KSI-IAM-05",
        "name": "Least Privilege",
        "related_controls": ["AC-2.5", "AC-6", "IA-2", "PS-2"],
        "data": {},
    }

    logger.info("Identifying admin users...")
    all_users = client.list_users(filter_query='status eq "ACTIVE"')
    admins: List[Dict] = []
    admin_user_ids: set = set()

    # --- Methods 1-2 (authoritative): admin ROLE assignments ----------------
    # Okta's role API is the source of truth for who holds admin privilege, and
    # roles are assigned two non-overlapping ways — the endpoints must be unioned
    # or group-assigned admins are missed entirely:
    #   * directly to a user          -> GET /users/{id}/roles
    #   * to a group (members inherit) -> GET /groups/{id}/roles
    # This replaces the previous hard-coded email/name allowlists.
    role_map: Dict[str, Dict] = {}  # user_id -> {"roles": [...], "sources": [...]}

    def _record_roles(user_id: str, roles: List[Dict], source: str) -> None:
        slot = role_map.setdefault(user_id, {"roles": [], "sources": []})
        slot["roles"].extend(roles)
        slot["sources"].append(source)

    logger.info("Checking directly-assigned admin roles for %d active users...", len(all_users))
    for user in all_users:
        try:
            roles = client.list_user_roles(user["id"])
        except Exception as exc:
            logger.warning("Could not read roles for %s: %s", _profile(user).get("login"), exc)
            continue
        if roles:
            _record_roles(user["id"], roles, "direct")

    logger.info("Checking group-assigned admin roles...")
    groups = client.list_groups()
    for group in groups:
        try:
            group_roles = client.list_group_roles(group["id"])
        except Exception as exc:
            logger.warning("Could not read roles for group %s: %s", _profile(group).get("name"), exc)
            continue
        if not group_roles:
            continue
        group_name = _profile(group).get("name", "")
        try:
            members = client.list_group_members(group["id"])
        except Exception as exc:
            logger.warning("Could not read members of %s: %s", group_name, exc)
            continue
        for member in members:
            _record_roles(member["id"], group_roles, f"group:{group_name}")

    # One admin entry per user holding any admin role (direct or group-inherited).
    users_by_id = {u["id"]: u for u in all_users}
    for user_id, info in role_map.items():
        user = users_by_id.get(user_id)
        if user is None:  # group member who isn't in the active-user list
            try:
                user = client.get_user(user_id)
            except Exception:
                user = {"id": user_id, "profile": {}}
        role_types = [r.get("type") for r in info["roles"] if r.get("type")]
        is_super = "SUPER_ADMIN" in role_types
        admin_type = "SUPER_ADMIN" if is_super else (role_types[0] if role_types else "ADMIN")
        admin_user_ids.add(user_id)
        admins.append(_admin_entry(
            user,
            "assigned_admin_role",
            roles=[{"type": r.get("type"), "label": r.get("label"), "status": r.get("status")} for r in info["roles"]],
            role_sources=info["sources"],
            is_super_admin=is_super,
            admin_type=admin_type,
        ))

    # --- Method 3 (fallback): membership in admin-named groups --------------
    # Weaker heuristic; still catches admin groups when the role API is
    # restricted for this token. Reuses the groups already fetched above.
    logger.info("Checking admin-named groups (fallback)...")
    admin_group_names = _admin_group_names()
    for group in groups:
        group_name = _profile(group).get("name", "")
        group_type = group.get("type", "")
        is_admin_group = any(a.lower() in group_name.lower() for a in admin_group_names)
        is_builtin_admin = group_type == "BUILT_IN" and "admin" in group_name.lower()
        if not (is_admin_group or is_builtin_admin):
            continue
        try:
            members = client.list_group_members(group["id"])
        except Exception as exc:
            logger.warning("Could not read members of %s: %s", group_name, exc)
            continue
        for member in members:
            if member["id"] in admin_user_ids:
                continue
            admin_user_ids.add(member["id"])
            try:
                detail = client.get_user(member["id"])
            except Exception:
                detail = member
            admins.append(_admin_entry(detail, f"admin_group={group_name}"))

    # --- Method 3: API-token owners (typically read-only admins) ------------
    logger.info("Checking API-token owners...")
    try:
        for token in client.list_api_tokens():
            user_id = token.get("userId")
            if not user_id or user_id in admin_user_ids:
                continue
            try:
                detail = client.get_user(user_id)
            except Exception:
                continue
            admin_user_ids.add(user_id)
            admins.append(_admin_entry(detail, "api_token_owner", api_token_name=token.get("name")))
    except Exception as exc:
        logger.warning("Could not read API tokens: %s", exc)

    # --- Method 4: users assigned to the Okta Admin Console app -------------
    logger.info("Checking Okta Admin Console assignments...")
    try:
        admin_console_app = None
        for app in client.list_applications():
            name = f"{app.get('name', '')} {app.get('label', '')}".lower()
            if "okta admin" in name or "admin console" in name:
                admin_console_app = app
                break
        if admin_console_app:
            for app_user in client.list_app_users(admin_console_app["id"]):
                user_id = app_user.get("id")
                if not user_id or user_id in admin_user_ids:
                    continue
                try:
                    detail = client.get_user(user_id)
                except Exception:
                    continue
                admin_user_ids.add(user_id)
                admins.append(_admin_entry(detail, "admin_console_app_assignment"))
    except Exception as exc:
        logger.warning("Could not check admin console app: %s", exc)

    # --- Method 5: privileged activity in the system log --------------------
    logger.info("Checking system log for privileged activity (last %d days)...", ADMIN_ACTIVITY_LOOKBACK_DAYS)
    try:
        since = (datetime.utcnow() - timedelta(days=ADMIN_ACTIVITY_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        actor_ids: set = set()
        for event_type in _ADMIN_EVENT_TYPES:
            for log in client.get_system_logs(since=since, filter_query=f'eventType eq "{event_type}"', limit=50):
                actor = log.get("actor", {})
                if actor.get("type") == "User" and actor.get("id"):
                    actor_ids.add(actor["id"])
        for user_id in actor_ids:
            if user_id in admin_user_ids:
                continue
            try:
                detail = client.get_user(user_id)
            except Exception:
                continue
            admin_user_ids.add(user_id)
            admins.append(_admin_entry(detail, "admin_activity_in_logs"))
    except Exception as exc:
        logger.warning("Could not scan system log for admin activity: %s", exc)

    evidence["data"]["admin_users"] = admins

    # Regular (non-admin) active users.
    regular_users = [
        {"email": _profile(u).get("email"), "name": _full_name(u), "status": u.get("status")}
        for u in all_users
        if u["id"] not in admin_user_ids
    ]
    evidence["data"]["regular_users"] = regular_users

    # Group-membership sample (privilege-scoping evidence).
    logger.info("Sampling group memberships...")
    group_sizes = []
    for group in groups[:50]:
        members = client.list_group_members(group["id"])
        group_sizes.append({
            "id": group["id"],
            "name": _profile(group).get("name"),
            "type": group.get("type"),
            "member_count": len(members),
        })
    evidence["data"]["group_memberships"] = group_sizes

    # --- Summary: categorize admins ----------------------------------------
    total_users = len(all_users)
    admin_count = len(admins)
    super_admins, read_only_admins, other_admins = [], [], []
    for admin in admins:
        summary = {"email": admin.get("email"), "name": admin.get("name")}
        is_super = admin.get("is_super_admin") or admin.get("admin_type") == "SUPER_ADMIN"
        is_read_only = admin.get("detection_method") == "api_token_owner" or admin.get("admin_type") == "READ_ONLY_ADMIN"
        if is_super:
            super_admins.append(summary)
        elif is_read_only:
            read_only_admins.append(summary)
        else:
            other_admins.append(summary)

    regular_user_count = len(regular_users)
    evidence["summary"] = {
        "total_active_users": total_users,
        "admin_users_count": admin_count,
        "regular_users_count": regular_user_count,
        "admin_percentage": round((admin_count / total_users * 100), 2) if total_users else 0,
        "regular_user_percentage": round((regular_user_count / total_users * 100), 2) if total_users else 0,
        "super_admin_count": len(super_admins),
        "super_admins": super_admins,
        "read_only_admin_count": len(read_only_admins),
        "read_only_admins": read_only_admins,
        "other_admin_count": len(other_admins),
        "other_admins": other_admins,
        "groups_analyzed": len(group_sizes),
    }
    logger.info(
        "Least privilege: %d active users, %d admins (%d super, %d read-only, %d other)",
        total_users, admin_count, len(super_admins), len(read_only_admins), len(other_admins),
    )
    return evidence


def main() -> int:
    return run(collect, output_filename="okta_least_privilege.json", logger_name="okta_least_privilege")


if __name__ == "__main__":
    sys.exit(main())
