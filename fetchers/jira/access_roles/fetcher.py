#!/usr/bin/env python3
"""Jira privileged access: admin groups and members, product access, and per-project privileged grants and roles."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from jira_common import (  # noqa: E402
    NOT_FOUND,
    Abort,
    Counts,
    JiraClient,
    collector_info,
    connection_settings,
    counts,
    int_env,
    list_env,
    name_of,
    null_summary,
    report_failure,
    utc_now,
    write_and_finish,
)

logger = logging.getLogger("jira_access_roles")

OUTPUT_FILE = "jira_access_roles.json"

ADMIN_ACCESS_TYPES = ("site-admin", "admin")
APPLICATION_KEYS = ("jira-software", "jira-servicedesk", "jira-core", "jira-product-discovery")

# Project permissions that let the holder administer the project or destroy or
# rewrite its records.
PRIVILEGED_PERMISSIONS = {
    "ADMINISTER_PROJECTS",
    "DELETE_ISSUES",
    "DELETE_ALL_COMMENTS",
    "DELETE_ALL_ATTACHMENTS",
    "DELETE_ALL_WORKLOGS",
    "EDIT_ALL_COMMENTS",
    "SET_ISSUE_SECURITY",
    "MODIFY_REPORTER",
}
# Holder types that grant a permission to everyone (or every licensed user).
BROAD_HOLDERS = {"anyone", "applicationRole"}
# Holder types whose members this fetcher can resolve to accounts. Any other type
# (reporter, assignee, userCustomField, groupCustomField, ...) is listed per
# project as an unresolved grant so the summary never silently undercounts.
RESOLVABLE_HOLDERS = {"user", "group", "projectRole", "projectLead"}


def _section(ok: bool, values: dict) -> dict:
    return values if ok else null_summary(values)


def _user(u: dict) -> dict:
    return {
        "account_id": u.get("accountId"),
        "display_name": u.get("displayName"),
        "account_type": u.get("accountType"),
        "active": u.get("active"),
    }


def _group_members(client: JiraClient, group_id: str, label: str):
    values, complete = client.paged_values(
        "/rest/api/3/group/member",
        f"GET /rest/api/3/group/member ({label})",
        params={"groupId": group_id, "includeInactiveUsers": "true"},
    )
    return [_user(u) for u in values], complete


def _admin_groups(client: JiraClient):
    """({group_id: {name, access_types}} for groups with site-admin or admin access, complete).

    complete is False when any listing failed, so a partial list is never
    reported as the whole admin population.
    """
    found: dict = {}
    complete = True
    for access_type in ADMIN_ACCESS_TYPES:
        page = client.request(
            "GET",
            "/rest/api/3/group/bulk",
            f"GET /rest/api/3/group/bulk (accessType={access_type})",
            params={"accessType": access_type, "maxResults": 50},
            quiet_400=True,
        )
        if page is NOT_FOUND:
            # The API refused accessType without an applicationKey; ask per product.
            for app_key in APPLICATION_KEYS:
                # A product the site does not have may answer 400 or 404: not a failure.
                values, ok = client.paged_values(
                    "/rest/api/3/group/bulk",
                    f"GET /rest/api/3/group/bulk (accessType={access_type}, applicationKey={app_key})",
                    params={"accessType": access_type, "applicationKey": app_key},
                    quiet_400=True,
                    allow_404=True,
                )
                complete = complete and ok
                for g in values:
                    found.setdefault(g.get("groupId"), {"name": g.get("name"), "access_types": set()})[
                        "access_types"
                    ].add(access_type)
            continue
        if page is None:
            complete = False
            continue
        values = list(page.get("values") or [])
        if not page.get("isLast", True) and values:
            more, ok = client.paged_values(
                "/rest/api/3/group/bulk",
                f"GET /rest/api/3/group/bulk (accessType={access_type})",
                params={"accessType": access_type},
            )
            complete = complete and ok
            values = more
        for g in values:
            found.setdefault(g.get("groupId"), {"name": g.get("name"), "access_types": set()})[
                "access_types"
            ].add(access_type)
    return found, complete


def _named_groups(client: JiraClient, names: list):
    """({group_id: {...}} for the configured admin groups, complete)."""
    found: dict = {}
    complete = True
    for name in names:
        page = client.request(
            "GET",
            "/rest/api/3/group/bulk",
            f"GET /rest/api/3/group/bulk (groupName={name})",
            params={"groupName": name},
        )
        if page is None:
            complete = False
        for g in (page or {}).get("values") or []:
            found[g.get("groupId")] = {"name": g.get("name"), "access_types": {"configured"}}
        if page is not None and not (page.get("values") or []):
            client.fail(
                f"GET /rest/api/3/group/bulk (groupName={name})",
                "NotFound",
                f"configured admin group {name!r} does not exist or is not visible",
                "bad_config",
            )
    return found, complete


def _holder(h: dict) -> dict:
    htype = h.get("type")
    out = {"type": htype, "parameter": h.get("parameter"), "value": h.get("value")}
    if htype == "group":
        out["group_name"] = name_of(h.get("group")) or h.get("parameter")
        out["group_id"] = name_of(h.get("group"), "groupId") or h.get("value")
    elif htype == "projectRole":
        out["role_id"] = str(h.get("parameter") or h.get("value") or "")
        out["role_name"] = name_of(h.get("projectRole"))
    elif htype == "user":
        out["account_id"] = name_of(h.get("user"), "accountId") or h.get("parameter")
        out["display_name"] = name_of(h.get("user"), "displayName")
    return out


def _role_actor(a: dict) -> dict:
    if a.get("type") == "atlassian-group-role-actor":
        group = a.get("actorGroup") or {}
        return {
            "type": "group",
            "group_name": group.get("name") or a.get("name"),
            "group_id": group.get("groupId"),
            "display_name": a.get("displayName"),
        }
    user = a.get("actorUser") or {}
    return {"type": "user", "account_id": user.get("accountId"), "display_name": a.get("displayName")}


def _project_roles(client: JiraClient, key: str, role_ids=None):
    """(roles of a project with their actors, complete).

    By default only the roles in `role_ids` (those named in a privileged grant) are
    read, one call each. With role_ids=None the role index is read and every role
    follows, which is 2 + R calls per project. complete is False when the index or
    any role could not be read: the project's privileged users are then unknown.
    """
    complete = True
    if role_ids is None:
        index = client.request(
            "GET", f"/rest/api/3/project/{key}/role", f"GET /rest/api/3/project/{key}/role"
        )
        if index is None:
            complete = False
        wanted = {str(url).rstrip("/").rsplit("/", 1)[-1]: name for name, url in (index or {}).items()}
    else:
        wanted = {rid: None for rid in role_ids if rid}
    roles = []
    for role_id, role_name in sorted(wanted.items()):
        role = client.request(
            "GET",
            f"/rest/api/3/project/{key}/role/{role_id}",
            f"GET /rest/api/3/project/{key}/role/{role_id}",
        )
        if role is None:
            complete = False
            continue
        roles.append(
            {
                "id": role_id,
                "name": role.get("name") or role_name,
                "actors": [_role_actor(a) for a in role.get("actors") or []],
            }
        )
    return roles, complete


def _privileged_users(grants: list, roles: list, lead_id, group_members: dict) -> list:
    """Account ids that hold a privileged permission on the project, with how."""
    holders: dict = {}

    def add(account_id, display, via):
        if not account_id:
            return
        entry = holders.setdefault(account_id, {"account_id": account_id, "display_name": display, "via": set()})
        entry["via"].add(via)
        entry["display_name"] = entry["display_name"] or display

    roles_by_id = {r["id"]: r for r in roles}
    for g in grants:
        h = g["holder"]
        if h["type"] == "user":
            add(h.get("account_id"), h.get("display_name"), f"user:{g['permission']}")
        elif h["type"] == "projectLead":
            add(lead_id, None, f"projectLead:{g['permission']}")
        elif h["type"] == "group":
            for m in group_members.get(h.get("group_id")) or []:
                add(m["account_id"], m["display_name"], f"group {h.get('group_name')}:{g['permission']}")
        elif h["type"] == "projectRole":
            role = roles_by_id.get(h.get("role_id"))
            for actor in (role or {}).get("actors") or []:
                if actor["type"] == "user":
                    add(actor["account_id"], actor["display_name"], f"role {role['name']}:{g['permission']}")
                else:
                    for m in group_members.get(actor.get("group_id")) or []:
                        add(
                            m["account_id"],
                            m["display_name"],
                            f"role {role['name']} via group {actor['group_name']}:{g['permission']}",
                        )
    return [
        {**v, "via": sorted(v["via"])} for v in sorted(holders.values(), key=lambda v: v["account_id"])
    ]


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    settings = connection_settings()
    if isinstance(settings, str):
        report_failure(settings, "bad_config")
        return 1
    base_url, email, api_token = settings

    max_projects = int_env("JIRA_ACCESS_MAX_PROJECTS", 200)
    if max_projects is None:
        report_failure("JIRA_ACCESS_MAX_PROJECTS must be a positive integer", "bad_config")
        return 1
    project_keys = list_env("JIRA_PROJECT_KEYS")
    extra_admin_groups = list_env("JIRA_ADMIN_GROUPS")
    all_roles = os.environ.get("JIRA_ACCESS_ALL_ROLES", "").strip().lower() in ("1", "true", "yes")

    client = JiraClient(base_url, email, api_token)
    now = utc_now()
    collector = None
    admin_groups: list = []
    application_roles: list = []
    projects: list = []
    schemes: dict = {}
    group_members: dict = {}
    group_names: dict = {}
    group_complete: dict = {}
    # Groups whose membership read failed, by the summary section that uses them:
    # a failed project-grant group leaves the admin counts valid, and the reverse.
    incomplete_groups: dict = {"admin": set(), "projects": set()}
    projects_truncated = False
    admin_section_ok = False
    project_search_complete = False
    schemes_unread = 0
    roles_unread = 0
    collection_finished = False

    def members_of(group_id, label, section):
        if not group_id:
            return
        if group_id not in group_members:
            members, complete = _group_members(client, group_id, label)
            group_members[group_id] = members
            group_names[group_id] = label
            group_complete[group_id] = complete
        if not group_complete[group_id]:
            incomplete_groups[section].add(label or group_id)

    try:
        collector = collector_info(client)

        groups, groups_complete = _admin_groups(client)
        if not groups:
            # Every Jira Cloud site has at least one admin group; none read means the
            # calls were refused or the API changed, never that nobody is an admin.
            client.fail(
                "GET /rest/api/3/group/bulk", "NoAdminGroups",
                "no site-admin or admin group could be read for any product", "partial_failure",
            )
        named, named_complete = _named_groups(client, extra_admin_groups)
        groups.update(named)
        # A partly read admin list is not the admin population.
        admin_section_ok = bool(groups) and groups_complete and named_complete
        for gid, g in sorted(groups.items(), key=lambda kv: kv[1]["name"] or ""):
            members_of(gid, g["name"], "admin")
            members = group_members.get(gid) or []
            known = group_complete.get(gid, False)
            admin_groups.append(
                {
                    "group_id": gid,
                    "name": g["name"],
                    "access_types": sorted(g["access_types"]),
                    # Null, not zero, when the membership read failed or stopped early.
                    "membership_complete": known,
                    "member_count": len(members) if known else None,
                    "inactive_member_count": sum(1 for m in members if m["active"] is False) if known else None,
                    "members": members,
                }
            )

        roles = client.request("GET", "/rest/api/3/applicationrole", "GET /rest/api/3/applicationrole")
        application_roles = [
            {
                "key": r.get("key"),
                "name": r.get("name"),
                "groups": sorted(r.get("groups") or []),
                "default_groups": sorted(r.get("defaultGroups") or []),
                "user_count": r.get("userCount"),
                "number_of_seats": r.get("numberOfSeats"),
            }
            for r in roles or []
        ]

        raw_projects = []
        project_search_complete = True
        # project/search takes at most 50 keys per call.
        for chunk in [project_keys[i : i + 50] for i in range(0, len(project_keys), 50)] or [[]]:
            values, ok = client.paged_values(
                "/rest/api/3/project/search",
                "GET /rest/api/3/project/search",
                params={"expand": "lead", **({"keys": chunk} if chunk else {})},
            )
            project_search_complete = project_search_complete and ok
            raw_projects.extend(values)
        if project_keys:
            missing = sorted(set(project_keys) - {p.get("key") for p in raw_projects})
            if missing:
                client.fail(
                    "GET /rest/api/3/project/search",
                    "NotFound",
                    f"configured project keys not visible to the collector: {', '.join(missing)}",
                    "bad_config",
                )
        if len(raw_projects) > max_projects:
            projects_truncated = True
            raw_projects = raw_projects[:max_projects]

        for p in raw_projects:
            key = p.get("key")
            scheme = client.request(
                "GET",
                f"/rest/api/3/project/{key}/permissionscheme",
                f"GET /rest/api/3/project/{key}/permissionscheme",
                params={"expand": "all"},
            )
            grants = []
            if not scheme:
                schemes_unread += 1
            if scheme:
                schemes.setdefault(scheme.get("id"), {"id": scheme.get("id"), "name": scheme.get("name")})
                grants = [
                    {"permission": g.get("permission"), "holder": _holder(g.get("holder") or {})}
                    for g in scheme.get("permissions") or []
                    if g.get("permission") in PRIVILEGED_PERMISSIONS
                ]
            granted_roles = sorted({g["holder"].get("role_id") for g in grants if g["holder"]["type"] == "projectRole"})
            roles, roles_complete = _project_roles(client, key, None if all_roles else granted_roles)
            if not roles_complete:
                roles_unread += 1
            unresolved = [
                {"permission": g["permission"], "holder_type": g["holder"]["type"], "parameter": g["holder"].get("parameter")}
                for g in grants
                if g["holder"]["type"] not in RESOLVABLE_HOLDERS | BROAD_HOLDERS
            ]
            for g in grants:
                if g["holder"]["type"] == "group":
                    members_of(g["holder"].get("group_id"), g["holder"].get("group_name"), "projects")
            for r in roles:
                for a in r["actors"]:
                    if a["type"] == "group":
                        members_of(a.get("group_id"), a.get("group_name"), "projects")
            lead = p.get("lead") or {}
            projects.append(
                {
                    "key": key,
                    "name": p.get("name"),
                    "project_type": p.get("projectTypeKey"),
                    "lead": {"account_id": lead.get("accountId"), "display_name": lead.get("displayName")},
                    "permission_scheme": {"id": (scheme or {}).get("id"), "name": (scheme or {}).get("name")},
                    "privileged_grants": grants,
                    "broad_privileged_grants": [g for g in grants if g["holder"]["type"] in BROAD_HOLDERS],
                    "unresolved_privileged_grants": unresolved,
                    "roles": roles,
                    "privileged_users": _privileged_users(grants, roles, lead.get("accountId"), group_members),
                    "roles_read_completely": roles_complete,
                }
            )
        collection_finished = True
    except Abort:
        pass
    except Exception as e:  # unexpected response shape: keep what was collected and say why
        client.fail("collection", type(e).__name__, str(e)[:200], "internal_error")

    # A section whose fetch failed is reported as not measured (null), never as a
    # zero that would read as "no admins" or "no privileged grants". An unexpected
    # error stopped the collection somewhere, so then neither section is trusted.
    admin_section_ok = admin_section_ok and collection_finished and not incomplete_groups["admin"]
    projects_section_ok = (
        collection_finished
        and project_search_complete
        and schemes_unread == 0
        and roles_unread == 0
        and not projects_truncated
        and not incomplete_groups["projects"]
    )
    admin_users = {m["account_id"]: m for g in admin_groups for m in g["members"] if m["account_id"]}
    project_admins = {
        u["account_id"]
        for p in projects
        for u in p["privileged_users"]
        if any(v.endswith(":ADMINISTER_PROJECTS") for v in u["via"])
    }
    evidence = {
        "metadata": {
            "collected_at": now.isoformat(),
            "base_url": base_url,
            "project_keys": project_keys or None,
            "extra_admin_groups": extra_admin_groups or None,
            "all_roles_read": all_roles,
            "organization_admins_included": False,
            "projects_collected": len(projects),
            "projects_truncated": projects_truncated,
            "project_search_complete": project_search_complete,
            "permission_schemes_unread": schemes_unread,
            "projects_with_unread_roles": roles_unread,
            "groups_with_incomplete_membership": sorted(incomplete_groups["admin"] | incomplete_groups["projects"]),
            "partial_failure": bool(client.api_failures),
            "api_failures": client.api_failures,
        },
        "collector": collector,
        "summary": {
            **_section(admin_section_ok, {
                "admin_groups": len(admin_groups),
                "distinct_admin_users": len(admin_users),
                "inactive_admin_users": sum(1 for u in admin_users.values() if u["active"] is False),
                "admin_users_by_account_type": counts(u["account_type"] for u in admin_users.values()),
            }),
            **_section(projects_section_ok, {
                "projects_scanned": len(projects),
                "permission_schemes": len(schemes),
                "projects_with_broad_privileged_grants": sorted(
                    p["key"] for p in projects if p["broad_privileged_grants"]
                ),
                "projects_with_unresolved_privileged_grants": sorted(
                    p["key"] for p in projects if p["unresolved_privileged_grants"]
                ),
                "distinct_project_admin_users": len(project_admins),
                "privileged_users_per_project": Counts((p["key"], len(p["privileged_users"])) for p in projects),
            }),
        },
        "admin_groups": admin_groups,
        "application_roles": application_roles,
        "permission_schemes": sorted(schemes.values(), key=lambda s: str(s["id"])),
        "projects": projects,
        "group_memberships": {
            group_names.get(gid) or gid: {"complete": group_complete.get(gid, False), "members": members}
            for gid, members in sorted(group_members.items())
        },
    }
    incomplete = ""
    if projects_truncated:
        incomplete = f"projects truncated at JIRA_ACCESS_MAX_PROJECTS={max_projects}"
    elif incomplete_groups["admin"] or incomplete_groups["projects"]:
        n = len(incomplete_groups["admin"] | incomplete_groups["projects"])
        incomplete = f"membership incomplete for {n} group(s)"
    elif roles_unread:
        incomplete = f"project roles could not be read for {roles_unread} project(s)"
    return write_and_finish(logger, client, evidence, OUTPUT_FILE, incomplete)


if __name__ == "__main__":
    sys.exit(main())
