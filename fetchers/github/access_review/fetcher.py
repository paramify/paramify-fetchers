#!/usr/bin/env python3
"""Who can reach the organization's code and with what rights: owners, members, outside collaborators, invitations, teams, roles and repository admins."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import PLAN_UNAVAILABLE, run  # noqa: E402

NAME = "github_access_review"
CONFIG = {"include_organization_roles": ("GITHUB_INCLUDE_ORGANIZATION_ROLES", True),
          "scope_to_repositories": ("GITHUB_SCOPE_TO_REPOSITORIES", False),
          "include_members": ("GITHUB_INCLUDE_MEMBERS", True)}


def logins(items):
    return sorted(i.get("login") for i in items or [] if i.get("login"))


def role_of(collaborator):
    """GitHub's role_name, falling back to the highest flag in permissions. For display only: see access_of."""
    if collaborator.get("role_name"):
        return collaborator["role_name"]
    perms = collaborator.get("permissions") or {}
    return next((p for p in ("admin", "maintain", "push", "triage", "pull") if perms.get(p)), None)


def access_of(grantee, name_key="role_name"):
    """"admin", "write" or "read" from the permissions flags, else from a built-in role name; None when unknown.

    A custom repository role (Enterprise Cloud) reports its own name, such as "release-manager", in role_name. GitHub
    sets the permissions flags from the role's base role, so the flags classify it and the name cannot.
    """
    perms = grantee.get("permissions") or {}
    if any(perms.values()):
        return "admin" if perms.get("admin") else "write" if perms.get("maintain") or perms.get("push") else "read"
    name = grantee.get(name_key)
    if name == "admin":
        return "admin"
    if name in ("maintain", "push", "write"):
        return "write"
    return "read" if name in ("triage", "pull", "read") else None


def repo_record(client, org, repo, owners, outsiders):
    name = repo["name"]
    base = f"repos/{org}/{name}"
    collaborators = client.paginate_required(f"{base}/collaborators", {"affiliation": "all"})
    teams = client.paginate_required(f"{base}/teams")
    if collaborators is None or teams is None:
        return {"repository": name, "collected": False}
    people = [{"login": c.get("login"), "role": role_of(c), "access": access_of(c),
               "outside": c.get("login") in outsiders, "owner": c.get("login") in owners} for c in collaborators]
    return {
        "repository": name,
        "visibility": repo.get("visibility"),
        "collected": True,
        # Owners are admins of every repository; listed apart so a per-repository grant stands out.
        "admins": sorted(p["login"] for p in people if p["access"] == "admin" and not p["owner"]),
        "writers": sorted(p["login"] for p in people if p["access"] == "write"),
        "outside_collaborators": [{"login": p["login"], "role": p["role"], "access": p["access"]}
                                  for p in people if p["outside"]],
        "teams": [{"team": t.get("slug"), "permission": t.get("permission"), "access": access_of(t, "permission")}
                  for t in teams],
        "collaborators_total": len(people),
        # Every account with access, for scoping organization roles; removed before the evidence is written.
        "_logins": sorted(p["login"] for p in people if p["login"]),
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


def teams_in_scope(teams, done, roles):
    """Slugs of the teams that reach a collected repository: granted on one, holding an organization role with a base
    role (which reaches every repository), or nested under such a team (nested teams inherit both)."""
    kept = {x["team"] for r in done for x in r["teams"]}
    kept |= {t["team"] for r in roles or [] if r["base_role"] for t in r["teams"]}
    parent = {t.get("slug"): (t.get("parent") or {}).get("slug") for t in teams}
    changed = True
    while changed:
        changed = False
        for slug, up in parent.items():
            if up in kept and slug not in kept:
                kept.add(slug)
                changed = True
    return kept


def roles_in_scope(roles, people, team_slugs):
    """Held roles that reach the repositories: a base role reaches every repository in the organization; any other
    role is kept when an account with access to a collected repository, or a kept team, holds it."""
    return [r for r in roles if (r["users"] or r["teams"]) and (
        r["base_role"] or any(u["login"] in people for u in r["users"])
        or any(t["team"] in team_slugs for t in r["teams"]))]


def token_user_is_owner(client, owners):
    """True only when the token's own user is in the owner list that was read. Unknown is not an owner."""
    if owners is None:
        return False
    found, user = client.lookup("user")
    return bool(found and isinstance(user, dict) and user.get("login") in logins(owners))


def collect(client, org, repos, config):
    login = org["login"]
    if config["scope_to_repositories"] and not config["include_organization_roles"]:
        # Scoping needs the roles: a team holding a role with a base role (all_repo_admin, all_repo_write...) reaches
        # every repository with no grant on any of them. Without the roles it would be left out unseen.
        client.fail("config scope_to_repositories", "BadConfig",
                    "scope_to_repositories needs include_organization_roles: without the organization roles, a team "
                    "that reaches every repository through a role would be left out", "bad_config")
        return None
    owners = client.paginate_required(f"orgs/{login}/members", {"role": "admin"})
    members = client.paginate_required(f"orgs/{login}/members", {"role": "all"})
    outsiders = client.paginate_required(f"orgs/{login}/outside_collaborators")
    failures_before = len(client.failures)
    state, invitations = client.paginate(f"orgs/{login}/invitations")
    invitation_failures = client.failures[failures_before:]
    teams = client.paginate_required(f"orgs/{login}/teams")
    # GitHub answers a bare 404 for the invitation list of an organization that has none to give, such as one whose
    # accounts an identity provider provisions (measured on an Enterprise Managed Users organization), and the same
    # 404 to a caller that may not read it. Outside collaborators and teams need the same members: read permission,
    # so when both were read the permission is not what is missing. That settles it for a GitHub App installation
    # token, whose rights are its permissions alone (the README's measurement has one reading this fetcher's
    # evidence in full on an ordinary organization). Any other token also carries its user's role, and whether a
    # non-owner's token gets this 404 on an ordinary organization is not measured, so for those the 404 is accepted
    # only when the token's user is an owner. Otherwise the 404 stays a failure, as before.
    invitations_available = None if state is not None else True
    if state == "failed" and outsiders is not None and teams is not None \
            and [f["type"] for f in invitation_failures] == ["HTTP 404"] \
            and (client.installation_token or token_user_is_owner(client, owners)):
        del client.failures[failures_before:failures_before + 1]
        del client.codes[failures_before:failures_before + 1]
        invitations_available = False
    roles, roles_available = organization_roles(client, login) if config["include_organization_roles"] else \
        (None, None)
    if owners is None or members is None or outsiders is None or teams is None:
        return None
    owner_set, outsider_set = set(logins(owners)), set(logins(outsiders))
    records = [repo_record(client, login, r, owner_set, outsider_set) for r in repos]
    done = [r for r in records if r["collected"]]
    people = {name for r in done for name in r.pop("_logins")}
    # Scoping leaves out teams and roles with no reach into the collected repositories. It needs every repository's
    # grants: with one unread, a team or role could reach it unseen, so nothing is left out (and the run fails).
    # Roles asked for but unread could hold a team that reaches every repository, so they also leave scope unknown.
    scoped = None
    if config["scope_to_repositories"] and len(done) == len(records) and roles is not None:
        scoped = True
    team_slugs = teams_in_scope(teams, done, roles) if scoped else {t.get("slug") for t in teams}
    teams_out = [t for t in teams if t.get("slug") not in team_slugs]
    teams = [t for t in teams if t.get("slug") in team_slugs]
    roles_out = 0
    if scoped and roles is not None:
        kept_roles = roles_in_scope(roles, people, team_slugs)
        roles_out, roles = len(roles) - len(kept_roles), kept_roles
    team_rows = []
    for t in teams:
        team_members = client.paginate_required(f"orgs/{login}/teams/{t['slug']}/members")
        team_rows.append({"team": t.get("slug"), "privacy": t.get("privacy"),
                          "members": None if team_members is None else logins(team_members),
                          "admin_on": sorted(r["repository"] for r in done
                                             if any(x["team"] == t.get("slug") and x["access"] == "admin"
                                                    for x in r["teams"])),
                          "write_on": sorted(r["repository"] for r in done
                                             if any(x["team"] == t.get("slug") and x["access"] == "write"
                                                    for x in r["teams"]))})
    pending = None if state is not None else [
        {"login": i.get("login"), "email_domain": (i.get("email") or "@").split("@")[-1] or None,
         "role": i.get("role"), "created_at": i.get("created_at"),
         "inviter": (i.get("inviter") or {}).get("login")} for i in invitations]
    held = None if roles is None else [r for r in roles if r["users"] or r["teams"]]
    return {
        "metadata": {"organization_roles_available": roles_available,
                     # True: teams and organization roles are limited to those reaching the collected repositories.
                     # None: asked for, not applied because a repository's grants were not read. False: not asked.
                     "scoped_to_repositories": scoped if config["scope_to_repositories"] else False,
                     "teams_left_out": len(teams_out) if scoped else 0,
                     "organization_roles_left_out": roles_out,
                     # True: read. False: the organization has no invitation list (pending_invitations stays null).
                     # None: the read failed, and the failure is listed.
                     "pending_invitations_available": invitations_available},
        "summary": {
            "owners": sorted(owner_set),
            "owners_total": len(owner_set),
            "members_total": len(logins(members)),
            "outside_collaborators_total": len(outsider_set),
            "outside_collaborators_with_write": sorted({o["login"] for r in done for o in r["outside_collaborators"]
                                                        if o["access"] in ("admin", "write")}),
            "pending_invitations": None if pending is None else len(pending),
            "teams_total": len(team_rows),
            "teams_with_admin": sorted(t["team"] for t in team_rows if t["admin_on"]),
            "repositories_with_non_owner_admins": sorted(r["repository"] for r in done if r["admins"]),
            # Users holding a role, directly or through a team, by role name; null when roles were not read.
            "organization_role_holders": None if held is None else {
                r["role"]: sorted(u["login"] for u in r["users"]) for r in held},
            # An organization role on a base role of write or more reaches every repository in the organization.
            "organization_wide_write_or_admin": None if held is None else sorted(
                {u["login"] for r in held if r["base_role"] in ("write", "maintain", "admin") for u in r["users"]}),
            "not_collected": [r["repository"] for r in records if not r["collected"]],
        },
        # The member list itself; members_total stays when it is left out.
        "members": logins(members) if config["include_members"] else None,
        "outside_collaborators": sorted(outsider_set),
        "pending_invitations": pending,
        "teams": team_rows,
        "organization_roles": roles,
        "repositories": records,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
