#!/usr/bin/env python3
"""
KSI-CMT-03 / KSI-IAM-03 / KSI-IAM-04: GitHub Actions CI/CD supply-chain
configuration.

Reports the organization's (and each repository's) GitHub Actions posture: which
actions are allowed to run at all, whether workflows may approve their own pull
requests, the default GITHUB_TOKEN permission granted to every workflow (read vs
write), self-hosted runner presence and runner-group exposure, and the NAMES and
counts of Actions secrets.

Why these fields: a workflow is a privileged, automatically-triggered build
identity. `default_workflow_permissions: write` hands every workflow in the org a
token that can push code; `can_approve_pull_request_reviews: true` lets a
workflow satisfy the very review requirement the branch-protection fetcher
measures; `allowed_actions: all` means any third-party action, at any tag, runs
inside that context; and a self-hosted runner group visible to public
repositories exposes your own infrastructure to fork pull requests.

**Secret values are never collected.** GitHub's API does not return them, and
this fetcher additionally projects secret entries through an explicit field
allowlist (name, timestamps, visibility) so a future API change cannot leak a
value into evidence. Names and counts are the evidence; values would be a
finding, not evidence.

Prowler source note: Prowler's `githubactions_service.py` is NOT a configuration
model — it shells out to the `zizmor` binary and wraps per-workflow-file
findings (`GithubActionsWorkflowFinding`). That is a static analyzer of workflow
YAML, not the Actions settings this evidence set needs, and it would add a
non-Python dependency. So the intent (Actions as the supply-chain attack surface)
is carried over from Prowler while the field projection comes from GitHub's
Actions REST API. See fetchers/github/README.md.

Single-organization per invocation; fanout across organizations happens at the
runner layer (see fetcher.yaml: supports_targets: true).
"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from github_common import (  # noqa: E402
    Collector,
    ConfigError,
    GitHubAPIError,
    bool_env,
    build_payload,
    get_env,
    github_get,
    int_env,
    register_redaction,
    resolve_organization,
    sanitize_for_filename,
    write_evidence,
    write_status,
)

logger = logging.getLogger("github_actions_workflow_config")

# The ONLY fields copied from an Actions secret. GitHub's list endpoints return
# no secret value (there is no API that does), and this allowlist makes that
# guarantee ours rather than the API's: anything not named here is dropped.
SECRET_FIELDS = ("name", "created_at", "updated_at", "visibility")

# An allowed-actions policy other than "all" restricts which third-party actions
# may run: "local_only" = only actions in this repo/org, "selected" = an explicit
# allowlist of creators/patterns.
RESTRICTED_ACTION_POLICIES = {"local_only", "selected"}


# --- pure transforms (operate on REST response dicts; unit-tested from fixtures) ---

def secret_records(raw: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Secret NAMES and metadata only, through an explicit allowlist."""
    records = [
        {field: entry.get(field) for field in SECRET_FIELDS}
        for entry in (raw or [])
        if isinstance(entry, dict)
    ]
    return sorted(records, key=lambda r: r.get("name") or "")


def runner_record(runner: Dict[str, Any]) -> Dict[str, Any]:
    """One self-hosted runner. Labels matter: they are how a workflow targets it."""
    return {
        "id": runner.get("id"),
        "name": runner.get("name"),
        "os": runner.get("os"),
        "status": runner.get("status"),
        "busy": runner.get("busy"),
        "ephemeral": runner.get("ephemeral"),
        "labels": sorted(
            label.get("name")
            for label in (runner.get("labels") or [])
            if isinstance(label, dict) and label.get("name")
        ),
    }


def runner_group_record(group: Dict[str, Any]) -> Dict[str, Any]:
    """One runner group. `allows_public_repositories` is the dangerous one:
    a public repo's fork pull request can then execute on your infrastructure."""
    return {
        "id": group.get("id"),
        "name": group.get("name"),
        "visibility": group.get("visibility"),
        "default": group.get("default"),
        "inherited": group.get("inherited"),
        "allows_public_repositories": group.get("allows_public_repositories"),
        "restricted_to_workflows": group.get("restricted_to_workflows"),
        "selected_workflows": sorted(group.get("selected_workflows") or []),
        "runners_count": group.get("runners_count"),
    }


def actions_policy_record(
    permissions: Optional[Dict[str, Any]],
    selected_actions: Optional[Dict[str, Any]],
    workflow_permissions: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Merge the three Actions policy endpoints into one record.

    Split across endpoints by GitHub: `/actions/permissions` (is Actions on, and
    which actions may run), `/actions/permissions/selected-actions` (the
    allowlist, only meaningful when allowed_actions == "selected"), and
    `/actions/permissions/workflow` (the default GITHUB_TOKEN grant).
    """
    permissions = permissions or {}
    selected = selected_actions or {}
    workflow = workflow_permissions or {}
    allowed_actions = permissions.get("allowed_actions")

    return {
        # Org shape uses enabled_repositories; repo shape uses enabled.
        "enabled_repositories": permissions.get("enabled_repositories"),
        "actions_enabled": permissions.get("enabled"),
        "allowed_actions": allowed_actions,
        "allowed_actions_restricted": (
            allowed_actions in RESTRICTED_ACTION_POLICIES
            if isinstance(allowed_actions, str)
            else None
        ),
        "github_owned_actions_allowed": selected.get("github_owned_allowed"),
        "verified_actions_allowed": selected.get("verified_allowed"),
        "allowed_action_patterns": sorted(selected.get("patterns_allowed") or []),
        "default_workflow_permissions": workflow.get("default_workflow_permissions"),
        "default_workflow_permissions_read_only": (
            workflow.get("default_workflow_permissions") == "read"
            if workflow.get("default_workflow_permissions") is not None
            else None
        ),
        "can_approve_pull_request_reviews": workflow.get("can_approve_pull_request_reviews"),
    }


def summarize(
    org: Dict[str, Any],
    repositories: List[Dict[str, Any]],
    *,
    repository_settings_collected: bool,
    truncated: bool,
) -> Dict[str, Any]:
    policy = org.get("policy") or {}
    runners = org.get("self_hosted_runners") or []
    groups = org.get("runner_groups") or []
    org_secrets = org.get("secrets") or []

    def repo_count(predicate) -> Optional[int]:
        if not repository_settings_collected:
            return None
        return sum(1 for r in repositories if predicate(r))

    return {
        # --- org-level Actions policy ---------------------------------------
        "actions_enabled_repositories": policy.get("enabled_repositories"),
        "allowed_actions": policy.get("allowed_actions"),
        "allowed_actions_restricted": policy.get("allowed_actions_restricted"),
        "github_owned_actions_allowed": policy.get("github_owned_actions_allowed"),
        "verified_actions_allowed": policy.get("verified_actions_allowed"),
        "allowed_action_pattern_count": len(policy.get("allowed_action_patterns") or []),
        # --- the default workflow identity (KSI-IAM-03 / KSI-IAM-04) --------
        "default_workflow_permissions": policy.get("default_workflow_permissions"),
        "default_workflow_permissions_read_only": policy.get(
            "default_workflow_permissions_read_only"
        ),
        "workflows_can_approve_pull_requests": policy.get("can_approve_pull_request_reviews"),
        # --- runner exposure ------------------------------------------------
        "self_hosted_runner_count": len(runners),
        "self_hosted_runners_online": sum(1 for r in runners if r.get("status") == "online"),
        "runner_group_count": len(groups),
        "runner_groups_allowing_public_repositories": sum(
            1 for g in groups if g.get("allows_public_repositories") is True
        ),
        "runner_groups_restricted_to_workflows": sum(
            1 for g in groups if g.get("restricted_to_workflows") is True
        ),
        # --- secrets: counts and names only, never values -------------------
        "organization_secret_count": len(org_secrets),
        "repository_secret_count": (
            sum(len(r.get("secrets") or []) for r in repositories)
            if repository_settings_collected
            else None
        ),
        # --- per-repository rollup ------------------------------------------
        "repository_settings_collected": repository_settings_collected,
        "repositories_examined": len(repositories) if repository_settings_collected else 0,
        "repositories_truncated": truncated,
        "repositories_with_actions_enabled": repo_count(
            lambda r: (r.get("policy") or {}).get("actions_enabled") is True
        ),
        "repositories_with_unrestricted_actions": repo_count(
            lambda r: (r.get("policy") or {}).get("allowed_actions_restricted") is False
        ),
        "repositories_with_write_default_token": repo_count(
            lambda r: (r.get("policy") or {}).get("default_workflow_permissions") == "write"
        ),
        "repositories_allowing_workflow_pr_approval": repo_count(
            lambda r: (r.get("policy") or {}).get("can_approve_pull_request_reviews") is True
        ),
        "repositories_with_self_hosted_runners": repo_count(
            lambda r: bool(r.get("self_hosted_runners"))
        ),
    }


# --- collection ------------------------------------------------------------ #

def _get_optional(path: str, token: str, collector: Collector, **kwargs) -> Any:
    """GET a resource whose absence (404) is a state, not a failure.

    Several Actions sub-resources 404 rather than returning a default: the
    selected-actions allowlist does not exist unless allowed_actions ==
    "selected", and repository-level Actions settings 404 on a repo with Actions
    switched off entirely.
    """
    def _get() -> Any:
        try:
            return github_get(path, token=token, **kwargs)
        except GitHubAPIError as exc:
            if exc.status == 404:
                logger.info("%s returned 404; reporting as not configured", path)
                return None
            raise

    return collector.guard(f"GET {path}", _get, default=None)


def collect_actions_policy(scope: str, token: str, collector: Collector) -> Dict[str, Any]:
    """The three policy endpoints for one scope ("/orgs/x" or "/repos/x/y")."""
    permissions = _get_optional(f"{scope}/actions/permissions", token, collector)
    selected = None
    if isinstance(permissions, dict) and permissions.get("allowed_actions") == "selected":
        selected = _get_optional(f"{scope}/actions/permissions/selected-actions", token, collector)
    workflow = _get_optional(f"{scope}/actions/permissions/workflow", token, collector)
    return actions_policy_record(permissions, selected, workflow)


def collect_runners(scope: str, token: str, collector: Collector) -> List[Dict[str, Any]]:
    path = f"{scope}/actions/runners"
    raw = _get_optional(path, token, collector, items_key="runners") or []
    return sorted(
        (runner_record(r) for r in raw if isinstance(r, dict)),
        key=lambda r: (r.get("name") or "", r.get("id") or 0),
    )


def collect_secrets(scope: str, token: str, collector: Collector) -> List[Dict[str, Any]]:
    path = f"{scope}/actions/secrets"
    raw = _get_optional(path, token, collector, items_key="secrets") or []
    return secret_records(raw)


def collect_runner_groups(scope: str, token: str, collector: Collector) -> List[Dict[str, Any]]:
    path = f"{scope}/actions/runner-groups"
    raw = _get_optional(path, token, collector, items_key="runner_groups") or []
    return sorted(
        (runner_group_record(g) for g in raw if isinstance(g, dict)),
        key=lambda g: (g.get("name") or "", g.get("id") or 0),
    )


def collect_organization(org: str, token: str, collector: Collector) -> Dict[str, Any]:
    # Sequenced explicitly rather than inside a dict literal, so the request
    # order matches the order these appear in the evidence and in the README.
    scope = f"/orgs/{org}"
    policy = collect_actions_policy(scope, token, collector)
    runners = collect_runners(scope, token, collector)
    groups = collect_runner_groups(scope, token, collector)
    secrets = collect_secrets(scope, token, collector)
    return {
        "login": org,
        "policy": policy,
        "self_hosted_runners": runners,
        "runner_groups": groups,
        "secrets": secrets,
    }


def collect_repository(repo: Dict[str, Any], token: str, collector: Collector) -> Dict[str, Any]:
    full_name = repo.get("full_name") or f"{(repo.get('owner') or {}).get('login')}/{repo.get('name')}"
    scope = f"/repos/{full_name}"
    return {
        "full_name": full_name,
        "name": repo.get("name"),
        "private": bool(repo.get("private")),
        "archived": bool(repo.get("archived")),
        "policy": collect_actions_policy(scope, token, collector),
        "self_hosted_runners": collect_runners(scope, token, collector),
        "secrets": collect_secrets(scope, token, collector),
    }


def collect_repositories(org: str, token: str, collector: Collector) -> Dict[str, Any]:
    path = f"/orgs/{org}/repos"
    repos = collector.guard(
        f"GET {path}",
        lambda: github_get(path, token=token, params={"type": "all", "sort": "full_name"}),
        default=[],
    ) or []

    # Archived repositories cannot run a workflow that changes anything, so they
    # are skipped rather than spending four requests each.
    active = [r for r in repos if not r.get("archived")]

    truncated = False
    limit = int_env("GITHUB_MAX_REPOSITORIES", 0)
    if limit > 0 and len(active) > limit:
        logger.warning(
            "GITHUB_MAX_REPOSITORIES=%d truncates %d repositories; evidence is a SUBSET "
            "and summary.repositories_truncated is true",
            limit,
            len(active),
        )
        active = sorted(active, key=lambda r: r.get("full_name") or "")[:limit]
        truncated = True

    records = [collect_repository(repo, token, collector) for repo in active]
    return {
        "records": sorted(records, key=lambda r: r.get("full_name") or ""),
        "truncated": truncated,
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself. The framework's runner + secret
    # resolver will pass resolved values in and this block goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    org_info = resolve_organization(collector)
    organization = org_info["organization"]

    token = None
    try:
        token = get_env("GITHUB_TOKEN")
        register_redaction(token)
    except ConfigError as exc:
        collector.record("resolve_github_token", exc)

    include_repositories = bool_env("GITHUB_INCLUDE_REPOSITORY_SETTINGS", True)
    org_record: Dict[str, Any] = {"login": organization, "policy": actions_policy_record(None, None, None)}
    repositories: List[Dict[str, Any]] = []
    truncated = False

    if organization and token:
        org_record = collect_organization(organization, token, collector)
        if include_repositories:
            collected = collect_repositories(organization, token, collector)
            repositories = collected["records"]
            truncated = collected["truncated"]
        else:
            logger.info(
                "GITHUB_INCLUDE_REPOSITORY_SETTINGS is false; collecting organization-level "
                "Actions configuration only"
            )

    evidence = build_payload(
        organization=organization,
        organization_source=org_info["organization_source"],
        collector=collector,
        results={"organization": org_record, "repositories": repositories},
        summary=summarize(
            org_record,
            repositories,
            repository_settings_collected=include_repositories,
            truncated=truncated,
        ),
    )

    filename = (
        f"github_actions_workflow_config_{sanitize_for_filename(organization or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        logger.error(
            "Encountered %d GitHub API failure(s) during collection; partial evidence written to %s",
            len(collector.failures),
            path,
        )
        write_status(collector.status_error, collector.status_code)
        return 1

    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
