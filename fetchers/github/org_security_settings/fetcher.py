#!/usr/bin/env python3
"""Organization security settings: two-factor enforcement and its gaps, member defaults, Actions token rights, and security configuration coverage."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import run  # noqa: E402

NAME = "github_org_security_settings"
ORG_FIELDS = ("two_factor_requirement_enabled", "default_repository_permission", "members_can_create_repositories",
              "members_can_create_public_repositories", "members_can_create_private_repositories",
              "members_can_fork_private_repositories", "members_can_delete_repositories",
              "members_can_change_repo_visibility", "members_can_invite_outside_collaborators",
              "web_commit_signoff_required", "deploy_keys_enabled_for_repositories")
REPO_SETTINGS = ("secret_scanning", "secret_scanning_push_protection", "dependabot_security_updates",
                 "secret_scanning_validity_checks", "secret_scanning_non_provider_patterns")
CONFIG_SETTINGS = ("advanced_security", "dependency_graph", "dependabot_alerts", "dependabot_security_updates",
                   "code_scanning_default_setup", "secret_scanning", "secret_scanning_push_protection",
                   "private_vulnerability_reporting")


def two_factor(client, login, org):
    """Members without two-factor authentication. Only owners can list them; None when the token cannot."""
    if org.get("two_factor_requirement_enabled") is None:
        return None
    state, members = client.paginate(f"orgs/{login}/members", {"filter": "2fa_disabled"})
    return None if state is not None else sorted(m.get("login") for m in members)


def configurations(client, login):
    """Code security configurations with the repositories each is attached to. Defined is not applied."""
    state, configs = client.paginate(f"orgs/{login}/code-security/configurations")
    if state is not None:
        return None
    _, defaults = client.read(f"orgs/{login}/code-security/configurations/defaults")
    default_ids = {d.get("configuration", {}).get("id"): d.get("default_for_new_repos") for d in defaults or []}
    out = []
    for c in configs:
        attached = client.paginate_required(f"orgs/{login}/code-security/configurations/{c['id']}/repositories")
        out.append({
            "id": c["id"],
            "name": c.get("name"),
            "target_type": c.get("target_type"),
            "enforcement": c.get("enforcement"),
            "default_for_new_repos": default_ids.get(c["id"]),
            "settings": {k: c.get(k) for k in CONFIG_SETTINGS if k in c},
            "repositories": None if attached is None else sorted(
                (a.get("repository") or {}).get("name") for a in attached if a.get("status") in (None, "attached",
                                                                                                    "enforced")),
        })
    return out


def collect(client, org, repos, config):
    login = org["login"]
    settings = {k: org.get(k) for k in ORG_FIELDS}
    actions = client.get(f"orgs/{login}/actions/permissions") or {}
    workflow = client.get(f"orgs/{login}/actions/permissions/workflow") or {}
    without_2fa = two_factor(client, login, org)
    configs = configurations(client, login)
    coverage = {r["name"]: None if r.get("security_and_analysis") is None else {
        k: (r["security_and_analysis"].get(k) or {}).get("status") for k in REPO_SETTINGS} for r in repos}
    attached = set() if configs is None else {n for c in configs for n in c["repositories"] or []}
    readable = {n: c for n, c in coverage.items() if c is not None}
    return {
        "summary": {
            "two_factor_required": settings["two_factor_requirement_enabled"],
            "members_without_two_factor": None if without_2fa is None else len(without_2fa),
            "default_repository_permission": settings["default_repository_permission"],
            "members_can_create_public_repositories": settings["members_can_create_public_repositories"],
            "members_can_invite_outside_collaborators": settings["members_can_invite_outside_collaborators"],
            "actions_enabled_repositories": actions.get("enabled_repositories"),
            "actions_allowed_actions": actions.get("allowed_actions"),
            "actions_sha_pinning_required": actions.get("sha_pinning_required"),
            "actions_default_token_permissions": workflow.get("default_workflow_permissions"),
            "actions_can_approve_pull_requests": workflow.get("can_approve_pull_request_reviews"),
            "security_configurations": None if configs is None else len(configs),
            "repositories_without_security_configuration": None if configs is None else sorted(
                n for n in coverage if n not in attached),
            "repositories_settings_unreadable": sorted(n for n, c in coverage.items() if c is None),
            **{f"repositories_{k}_off": sorted(n for n, c in readable.items() if c.get(k) != "enabled")
               for k in ("secret_scanning", "secret_scanning_push_protection", "dependabot_security_updates")},
        },
        "organization": {"login": login, "plan": (org.get("plan") or {}).get("name"), **settings},
        "members_without_two_factor": without_2fa,
        "actions": {**{k: actions.get(k) for k in ("enabled_repositories", "allowed_actions", "sha_pinning_required")},
                    **{k: workflow.get(k) for k in ("default_workflow_permissions",
                                                    "can_approve_pull_request_reviews")}},
        "security_configurations": configs,
        "repositories": [{"repository": n, "security_and_analysis": c, "security_configuration_attached":
                          None if configs is None else n in attached} for n, c in coverage.items()],
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect))
