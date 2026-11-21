#!/usr/bin/env python3
"""Organization security settings: two-factor enforcement and its gaps, member defaults, Actions token rights, and security configuration coverage."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import run  # noqa: E402

NAME = "github_org_security_settings"
# "auto" decides from the member list; "true" or "false" states it for an organization where that list is unreadable.
CONFIG = {"managed_user_accounts": ("GITHUB_MANAGED_USER_ACCOUNTS", "auto")}
MANAGED_NOTE = ("The organization's members are managed user accounts (Enterprise Managed Users). They sign in through "
                "the identity provider, which handles two-factor authentication; GitHub keeps no two-factor method "
                "for them and has no two-factor requirement setting for the organization, so the two-factor fields "
                "do not apply and are null. This evidence does not read the identity provider.")
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


def managed_user_accounts(client, login, setting):
    """(managed, source). True when every member is a managed user account; None when it cannot be told.

    A managed user account's login is the identity provider's handle, an underscore and the enterprise's short code
    (measured: every member of an Enterprise Managed Users organization). A personal account's login may hold only
    letters, digits and hyphens, so one login without an underscore proves the organization is not managed. An
    unreadable or empty member list proves nothing, and the two-factor fields are then collected as before.
    """
    if setting in ("true", "false"):
        return setting == "true", "configured"
    before = len(client.failures)
    state, members = client.paginate(f"orgs/{login}/members", {"role": "all"})
    if state is not None or not members:
        # Detection is a hint, not evidence: a refused list (403 or 404) leaves it unknown and does not fail the run,
        # which collected nothing from this list before. Any other failure (network, server, pagination) stands.
        new = client.failures[before:]
        if new and all(f["type"] in ("HTTP 403", "HTTP 404") for f in new):
            del client.failures[before:]
            del client.codes[before:]
        return None, "detected"
    return all("_" in (m.get("login") or "") for m in members), "detected"


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
    setting = str(config["managed_user_accounts"]).strip().lower()
    if setting not in ("auto", "true", "false"):
        client.fail("config managed_user_accounts", "BadConfig",
                    f"managed_user_accounts must be auto, true or false, got {config['managed_user_accounts']!r}",
                    "bad_config")
        return None
    settings = {k: org.get(k) for k in ORG_FIELDS}
    managed, managed_source = managed_user_accounts(client, login, setting)
    if managed:
        # GitHub answers false for the requirement and lists every member under 2fa_disabled: neither is a finding.
        settings["two_factor_requirement_enabled"] = None
    actions = client.get(f"orgs/{login}/actions/permissions") or {}
    workflow = client.get(f"orgs/{login}/actions/permissions/workflow") or {}
    without_2fa = None if managed else two_factor(client, login, org)
    configs = configurations(client, login)
    coverage = {r["name"]: None if r.get("security_and_analysis") is None else {
        k: (r["security_and_analysis"].get(k) or {}).get("status") for k in REPO_SETTINGS} for r in repos}
    attached = set() if configs is None else {n for c in configs for n in c["repositories"] or []}
    # A configuration whose repository list failed (recorded) may hold any repository: a readable list can prove a
    # repository attached, but none can prove it unattached. Unreadable is not absent.
    lists_known = configs is not None and all(c["repositories"] is not None for c in configs)
    readable = {n: c for n, c in coverage.items() if c is not None}
    return {
        # The setting itself ("auto", "true" or "false") is in metadata as managed_user_accounts; the result is in the
        # summary, and this says whether it was detected from the member list or stated in the configuration.
        "metadata": {"managed_user_accounts_source": managed_source},
        "summary": {
            "managed_user_accounts": managed,
            **({"two_factor_note": MANAGED_NOTE} if managed else {}),
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
            "repositories_without_security_configuration": None if not lists_known else sorted(
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
                          True if n in attached else False if lists_known else None}
                         for n, c in coverage.items()],
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG))
