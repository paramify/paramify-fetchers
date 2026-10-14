#!/usr/bin/env python3
"""Who can reach an organization's code and with what rights: owners, members, outside collaborators, invitations,
teams, organization roles (security manager, all-repository admin and custom roles), and each repository's admins."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import PLAN_UNAVAILABLE, run  # noqa: E402

NAME = "github_access_review"
CONFIG = {"include_organization_roles": ("GITHUB_INCLUDE_ORGANIZATION_ROLES", True)}
WRITE = ("admin", "maintain", "push", "write")


def logins(items):
    return sorted(i.get("login") for i in items or [] if i.get("login"))


def role_of(collaborator):
    """GitHub's role_name, falling back to the highest flag in permissions."""
    if collaborator.get("role_name"):
        return collaborator["role_name"]
    perms = collaborator.get("permissions") or {}
    return next((p for p in ("admin", "maintain", "push", "triage", "pull") if perms.get(p)), None)


def repo_record(client, org, repo, owners, outsiders):
    name = repo["name"]
    base = f"repos/{org}/{name}"
    collaborators = client.paginate_required(f"{base}/collaborators", {"affiliation": "all"})
    teams = client.paginate_required(f"{base}/teams")
    if collaborators is None or teams is None:
        return {"repository": name, "collected": False}
    people = [{"login": c.get("login"), "role": role_of(c), "outside": c.get("login") in outsiders,
               "owner": c.get("login") in owners} for c in collaborators]
    return {
        "repository": name,
        "visibility": repo.get("visibility"),
        "collected": True,
        # Owners are admins of every repository; listed apart so a per-repository grant stands out.
        "admins": sorted(p["login"] for p in people if p["role"] == "admin" and not p["owner"]),
        "writers": sorted(p["login"] for p in people if p["role"] in ("maintain", "push", "write")),
        "outside_collaborators": [{"login": p["login"], "role": p["role"]} for p in people if p["outside"]],
        "teams": [{"team": t.get("slug"), "permission": t.get("permission")} for t in teams],
        "collaborators_total": len(people),
    }


def organization_roles(client, login):
    """Each organization role with the users (directly or through a team) and teams holding it.

    ([] , False) where the plan has none; (None, None) when unreadable (recorded). Organization roles replace the
    security-manager endpoints GitHub closed down on 2026-01-01.
    """
    state, found = client.paginate(f"orgs/{login}/organization-roles", key="roles")
    if state == PLAN_UNAVAILABLE:
        return [], False
    if state is not None:
        if state != "failed":
            client.fail(f"GET orgs/{login}/organization-roles", "UnexpectedState", f"{state}: {client.last_message}",
                        "not_authorized")
        return None, None
    roles = []
    for role in found or []:
        path = f"orgs/{login}/organization-roles/{role.get('id')}"
        users = client.paginate_required(f"{path}/users")
        teams = client.paginate_required(f"{path}/teams")
        if users is None or teams is None:
            return None, None
        roles.append({"role": role.get("name"), "source": role.get("source"), "base_role": role.get("base_role"),
                      "permissions": sorted(role.get("permissions") or []),
                      "users": [{"login": u.get("login"), "assignment": u.get("assignment"),
                                 "via_teams": sorted(t.get("slug") for t in u.get("inherited_from") or []
                                                     if t.get("slug"))} for u in users],
                      "teams": [{"team": t.get("slug"), "assignment": t.get("assignment")} for t in teams]})
    return roles, True


def collect(client, org, repos, config):
    login = org["login"]
    owners = client.paginate_required(f"orgs/{login}/members", {"role": "admin"})
    members = client.paginate_required(f"orgs/{login}/members", {"role": "all"})
    outsiders = client.paginate_required(f"orgs/{login}/outside_collaborators")
    state, invitations = client.paginate(f"orgs/{login}/invitations")
    teams = client.paginate_required(f"orgs/{login}/teams")
    roles, roles_available = organization_roles(client, login) if config["include_organization_roles"] else \
        (None, None)
    if owners is None or members is None or outsiders is None or teams is None:
        return None
    owner_set, outsider_set = set(logins(owners)), set(logins(outsiders))
    records = [repo_record(client, login, r, owner_set, outsider_set) for r in repos]
    done = [r for r in records if r["collected"]]
    team_rows = []
    for t in teams:
        team_members = client.paginate_required(f"orgs/{login}/teams/{t['slug']}/members")
        team_rows.append({"team": t.get("slug"), "privacy": t.get("privacy"),
                          "members": None if team_members is None else logins(team_members),
                          "admin_on": sorted(r["repository"] for r in done
                                             if any(x["team"] == t.get("slug") and x["permission"] == "admin"
                                                    for x in r["teams"])),
                          "write_on": sorted(r["repository"] for r in done
                                             if any(x["team"] == t.get("slug") and x["permission"] in WRITE
                                                    and x["permission"] != "admin" for x in r["teams"]))})
    pending = None if state is not None else [
        {"login": i.get("login"), "email_domain": (i.get("email") or "@").split("@")[-1] or None,
         "role": i.get("role"), "created_at": i.get("created_at"),
         "inviter": (i.get("inviter") or {}).get("login")} for i in invitations]
    held = None if roles is None else [r for r in roles if r["users"] or r["teams"]]
    return {
        "metadata": {"organization_roles_available": roles_available},
        "summary": {
            "owners": sorted(owner_set),
            "owners_total": len(owner_set),
            "members_total": len(logins(members)),
            "outside_collaborators_total": len(outsider_set),
            "outside_collaborators_with_write": sorted({o["login"] for r in done for o in r["outside_collaborators"]
                                                        if o["role"] in WRITE}),
            "pending_invitations": None if pending is None else len(pending),
            "teams_total": len(team_rows),
            "teams_with_admin": sorted(t["team"] for t in team_rows if t["admin_on"]),
            "repositories_with_direct_admins": sorted(r["repository"] for r in done if r["admins"]),
            # Users holding a role, directly or through a team, by role name; null when roles were not read.
            "organization_role_holders": None if held is None else {
                r["role"]: sorted(u["login"] for u in r["users"]) for r in held},
            # An organization role on a base role of write or more reaches every repository in the organization.
            "organization_wide_write_or_admin": None if held is None else sorted(
                {u["login"] for r in held if r["base_role"] in ("write", "maintain", "admin") for u in r["users"]}),
            "not_collected": [r["repository"] for r in records if not r["collected"]],
        },
        "members": logins(members),
        "outside_collaborators": sorted(outsider_set),
        "pending_invitations": pending,
        "teams": team_rows,
        "organization_roles": roles,
        "repositories": records,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
