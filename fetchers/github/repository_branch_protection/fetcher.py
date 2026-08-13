#!/usr/bin/env python3
"""
KSI-CMT-03 / KSI-CMT-04 / KSI-SVC-05 / KSI-MLA-03: GitHub default-branch
protection posture.

For every repository in one GitHub organization, reports the protection rules in
force on the DEFAULT branch — required pull-request reviews and approving review
count, required status checks, enforce-admins, signed commits, force-push and
deletion restrictions, linear history, conversation resolution — plus the
repository's own posture (private / archived / default branch) and its code
security services (secret scanning, push protection, Dependabot alerts).

The default branch is the one that matters: it is what releases are cut from, so
"can an unreviewed commit reach production?" is answered here and nowhere else.

Field projection ported from Prowler (Apache-2.0), master:
  prowler/providers/github/services/repository/repository_service.py
    -> the `Repo` and `Branch` pydantic models, and the "404 means unprotected"
       / "any other error means we cannot know" split in _process_repository().
  prowler/providers/github/services/repository/repository_*/ (18 checks)
    -> which of those fields a control actually turns on.
Collected over the REST API with `requests` (Prowler uses PyGithub; this category
adds no dependency).

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
    build_payload,
    coverage_percentage,
    enabled,
    get_env,
    github_get,
    int_env,
    register_redaction,
    resolve_organization,
    sanitize_for_filename,
    write_evidence,
    write_status,
)

logger = logging.getLogger("github_repository_branch_protection")

# security_and_analysis feature -> evidence field. GitHub reports each as
# {"status": "enabled"|"disabled"}; the block is absent entirely when the token
# cannot read repository administration, which is why `*_visible` is recorded.
SECURITY_FEATURES = {
    "advanced_security": "advanced_security_enabled",
    "secret_scanning": "secret_scanning_enabled",
    "secret_scanning_push_protection": "secret_scanning_push_protection_enabled",
    "secret_scanning_non_provider_patterns": "secret_scanning_non_provider_patterns_enabled",
    "secret_scanning_validity_checks": "secret_scanning_validity_checks_enabled",
    "dependabot_security_updates": "dependabot_security_updates_enabled",
}


# --- pure transforms (operate on REST response dicts; unit-tested from fixtures) ---

def _status_bool(value: Any) -> Optional[bool]:
    """"enabled"/"disabled" -> True/False; anything else -> None (unknown)."""
    if value == "enabled":
        return True
    if value == "disabled":
        return False
    return None


def branch_record(branch_name: str, protection: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Normalize `GET /repos/{o}/{r}/branches/{b}/protection` into a record.

    `protection is None` means the endpoint returned 404 — the branch carries no
    protection rule at all (or does not exist yet, in an empty repo). That is a
    real, reportable state, not a failure: an unprotected branch permits force
    pushes and deletion, which is why those two default to True here while every
    positive control defaults to False. Mirrors Prowler's defaults so the two
    tools agree on what "unprotected" means.
    """
    if protection is None:
        return {
            "name": branch_name,
            "protection_state": "unprotected",
            "protected": False,
            "require_pull_request": False,
            "approval_count": 0,
            "dismiss_stale_reviews": False,
            "require_code_owner_reviews": False,
            "require_last_push_approval": False,
            "required_status_checks": False,
            "required_status_check_contexts": [],
            "required_status_checks_strict": False,
            "enforce_admins": False,
            "require_signed_commits": False,
            "required_linear_history": False,
            "allow_force_pushes": True,
            "allow_deletions": True,
            "required_conversation_resolution": False,
            "lock_branch": False,
            "restricts_push_access": False,
        }

    reviews = protection.get("required_pull_request_reviews")
    has_reviews = isinstance(reviews, dict)
    checks = protection.get("required_status_checks")
    has_checks = isinstance(checks, dict)

    contexts = []
    if has_checks:
        contexts = list(checks.get("contexts") or [])
        if not contexts:
            # Newer API shape: [{"context": "...", "app_id": N}, ...]
            contexts = [
                c.get("context")
                for c in (checks.get("checks") or [])
                if isinstance(c, dict) and c.get("context")
            ]

    return {
        "name": branch_name,
        "protection_state": "protected",
        "protected": True,
        "require_pull_request": has_reviews,
        "approval_count": (reviews.get("required_approving_review_count") or 0) if has_reviews else 0,
        "dismiss_stale_reviews": bool(reviews.get("dismiss_stale_reviews")) if has_reviews else False,
        "require_code_owner_reviews": bool(reviews.get("require_code_owner_reviews")) if has_reviews else False,
        "require_last_push_approval": bool(reviews.get("require_last_push_approval")) if has_reviews else False,
        "required_status_checks": has_checks,
        "required_status_check_contexts": sorted(contexts),
        "required_status_checks_strict": bool(checks.get("strict")) if has_checks else False,
        "enforce_admins": bool(enabled(protection.get("enforce_admins"))),
        "require_signed_commits": bool(enabled(protection.get("required_signatures"))),
        "required_linear_history": bool(enabled(protection.get("required_linear_history"))),
        "allow_force_pushes": bool(enabled(protection.get("allow_force_pushes"))),
        "allow_deletions": bool(enabled(protection.get("allow_deletions"))),
        "required_conversation_resolution": bool(
            enabled(protection.get("required_conversation_resolution"))
        ),
        "lock_branch": bool(enabled(protection.get("lock_branch"))),
        "restricts_push_access": isinstance(protection.get("restrictions"), dict),
    }


def unknown_branch_record(branch_name: str, state: str = "unknown") -> Dict[str, Any]:
    """Every protection field null: the call failed, so we cannot know.

    Deliberately NOT the same as `branch_record(name, None)`. Reporting an
    inaccessible branch as "unprotected" would manufacture a finding; reporting
    it as protected would hide one. Prowler makes the same distinction.
    """
    record: Dict[str, Any] = {
        key: None
        for key in branch_record(branch_name, None)
        if key not in {"name", "protection_state"}
    }
    record["name"] = branch_name
    record["protection_state"] = state
    return record


def security_and_analysis_record(repo: Dict[str, Any]) -> Dict[str, Any]:
    """Project the repo's code-security services.

    The `security_and_analysis` block needs Administration:Read; without it
    GitHub omits the block rather than erroring, so absence must read as
    "not visible", never as "disabled".
    """
    block = repo.get("security_and_analysis")
    if not isinstance(block, dict):
        record: Dict[str, Any] = {field: None for field in SECURITY_FEATURES.values()}
        record["security_and_analysis_visible"] = False
        return record

    record = {}
    for feature, field in SECURITY_FEATURES.items():
        entry = block.get(feature)
        record[field] = _status_bool(entry.get("status") if isinstance(entry, dict) else None)
    record["security_and_analysis_visible"] = True
    return record


def repo_record(
    repo: Dict[str, Any],
    branch: Dict[str, Any],
    *,
    dependabot_alerts_enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    """Normalize one repository plus its default-branch protection record."""
    record = {
        "id": repo.get("id"),
        "name": repo.get("name"),
        "owner": (repo.get("owner") or {}).get("login"),
        "full_name": repo.get("full_name"),
        "private": bool(repo.get("private")),
        "visibility": repo.get("visibility"),
        "archived": bool(repo.get("archived")),
        "disabled": bool(repo.get("disabled")),
        "fork": bool(repo.get("fork")),
        "default_branch": branch,
        "default_branch_name": branch.get("name"),
        "pushed_at": repo.get("pushed_at"),
        "created_at": repo.get("created_at"),
        "allow_forking": repo.get("allow_forking"),
        "delete_branch_on_merge": repo.get("delete_branch_on_merge"),
        "web_commit_signoff_required": repo.get("web_commit_signoff_required"),
        "dependabot_alerts_enabled": dependabot_alerts_enabled,
    }
    record.update(security_and_analysis_record(repo))
    return record


def summarize(records: List[Dict[str, Any]], *, truncated: bool = False) -> Dict[str, Any]:
    """Coverage across NON-ARCHIVED repositories.

    An archived repository is read-only — nothing can be pushed to it, so
    counting it as an unprotected branch would drag the coverage percentage down
    for a risk that does not exist. Archived repos are still inventoried
    (`archived_repositories`), just kept out of the denominator.
    """
    active = [r for r in records if not r["archived"]]
    total_active = len(active)

    def count(predicate) -> int:
        return sum(1 for r in active if predicate(r))

    def branch_true(field: str):
        return lambda r: r["default_branch"].get(field) is True

    protected = count(branch_true("protected"))
    requires_pr = count(branch_true("require_pull_request"))

    return {
        "total_repositories": len(records),
        "active_repositories": total_active,
        "archived_repositories": len(records) - total_active,
        "private_repositories": sum(1 for r in records if r["private"]),
        "public_repositories": sum(1 for r in records if not r["private"]),
        "repositories_truncated": truncated,
        # The headline control: protected-branch coverage across live repos.
        "protected_default_branches": protected,
        "protected_default_branch_percentage": coverage_percentage(protected, total_active),
        "unprotected_default_branches": count(
            lambda r: r["default_branch"].get("protected") is False
        ),
        "unknown_protection_state": sum(
            1 for r in active if r["default_branch"].get("protection_state") in {"unknown", None}
        ),
        "repositories_requiring_pull_request": requires_pr,
        "pull_request_required_percentage": coverage_percentage(requires_pr, total_active),
        "repositories_requiring_two_or_more_approvals": count(
            lambda r: (r["default_branch"].get("approval_count") or 0) >= 2
        ),
        "repositories_requiring_code_owner_review": count(branch_true("require_code_owner_reviews")),
        "repositories_dismissing_stale_reviews": count(branch_true("dismiss_stale_reviews")),
        "repositories_with_required_status_checks": count(branch_true("required_status_checks")),
        "repositories_enforcing_admins": count(branch_true("enforce_admins")),
        "repositories_requiring_signed_commits": count(branch_true("require_signed_commits")),
        "repositories_requiring_linear_history": count(branch_true("required_linear_history")),
        "repositories_requiring_conversation_resolution": count(
            branch_true("required_conversation_resolution")
        ),
        "repositories_allowing_force_push": count(branch_true("allow_force_pushes")),
        "repositories_allowing_branch_deletion": count(branch_true("allow_deletions")),
        "repositories_with_secret_scanning": count(lambda r: r["secret_scanning_enabled"] is True),
        "secret_scanning_percentage": coverage_percentage(
            count(lambda r: r["secret_scanning_enabled"] is True), total_active
        ),
        "repositories_with_push_protection": count(
            lambda r: r["secret_scanning_push_protection_enabled"] is True
        ),
        "repositories_with_dependabot_alerts": count(
            lambda r: r["dependabot_alerts_enabled"] is True
        ),
        "repositories_without_visible_security_settings": count(
            lambda r: r["security_and_analysis_visible"] is False
        ),
    }


# --- collection ------------------------------------------------------------ #

def fetch_protection(full_name: str, branch: str, token: str, collector: Collector) -> Dict[str, Any]:
    """Default-branch protection, distinguishing "unprotected" from "unknown".

    404 is the API's way of saying the branch has no protection rule (or does not
    exist), so it is handled inside the guarded call and never recorded as a
    failure. Anything else IS a failure and drives the exit code.
    """
    path = f"/repos/{full_name}/branches/{branch}/protection"

    def _get() -> Dict[str, Any]:
        try:
            return {"state": "protected", "protection": github_get(path, token=token)}
        except GitHubAPIError as exc:
            if exc.status == 404:
                return {"state": "unprotected", "protection": None}
            raise

    return collector.guard(
        f"GET {path}", _get, default={"state": "unknown", "protection": None}
    )


def fetch_required_signatures(full_name: str, branch: str, token: str, collector: Collector) -> Optional[bool]:
    """Signed-commit requirement, when the protection payload omitted it.

    Older API versions expose this only on its own sub-resource (Prowler calls
    `branch.get_required_signatures()` for the same reason). Called only as a
    fallback, so the common path stays at one request per repository.
    """
    path = f"/repos/{full_name}/branches/{branch}/protection/required_signatures"

    def _get() -> Optional[bool]:
        try:
            return enabled(github_get(path, token=token))
        except GitHubAPIError as exc:
            if exc.status == 404:
                return False
            raise

    return collector.guard(f"GET {path}", _get, default=None)


def probe_dependabot_alerts(full_name: str, token: str, collector: Collector) -> Optional[bool]:
    """Whether Dependabot alerts are switched on for this repository.

    There is no "is it enabled" field, so this asks for one alert: a 200 means
    the service is on (even with zero alerts) and GitHub's specific
    403 "Dependabot alerts are disabled for this repository" means it is off.
    Ported from Prowler's identical probe. A 403 that is really a rate limit or a
    missing scope carries no "disabled" text and is re-raised as a failure.
    """
    path = f"/repos/{full_name}/dependabot/alerts"

    def _get() -> Optional[bool]:
        try:
            github_get(path, token=token, params={"per_page": 1})
            return True
        except GitHubAPIError as exc:
            if exc.status == 403 and "disabled" in str(exc).lower():
                return False
            if exc.status == 404:
                # Alerts unavailable for this repository (e.g. a fork).
                return None
            raise

    return collector.guard(f"GET {path}", _get, default=None)


def fetch_full_repository(full_name: str, token: str, collector: Collector) -> Optional[Dict[str, Any]]:
    """Full repository representation, for the `security_and_analysis` block.

    `GET /orgs/{org}/repos` returns the *minimal* repository shape, which may
    omit that block; this fills it in. Called only when the list response did not
    already carry it, so a token that gets the richer list response costs one
    request per organization instead of one per repository.
    """
    path = f"/repos/{full_name}"
    return collector.guard(f"GET {path}", lambda: github_get(path, token=token), default=None)


def collect_repository(repo: Dict[str, Any], token: str, collector: Collector) -> Dict[str, Any]:
    full_name = repo.get("full_name") or f"{(repo.get('owner') or {}).get('login')}/{repo.get('name')}"
    branch_name = repo.get("default_branch") or "main"

    if repo.get("archived"):
        # Read-only: nothing can be pushed, and it is out of the coverage
        # denominator, so skip its four extra requests entirely.
        return repo_record(repo, unknown_branch_record(branch_name, state="skipped_archived"))

    detail = repo
    if not isinstance(repo.get("security_and_analysis"), dict):
        full = fetch_full_repository(full_name, token, collector)
        if isinstance(full, dict):
            detail = {**repo, **full}

    result = fetch_protection(full_name, branch_name, token, collector)
    protection = result.get("protection")
    state = result.get("state")

    if state == "unknown":
        branch = unknown_branch_record(branch_name)
    else:
        branch = branch_record(branch_name, protection)
        if state == "protected" and "required_signatures" not in (protection or {}):
            signed = fetch_required_signatures(full_name, branch_name, token, collector)
            branch["require_signed_commits"] = bool(signed)

    return repo_record(
        detail,
        branch,
        dependabot_alerts_enabled=probe_dependabot_alerts(full_name, token, collector),
    )


def collect_repositories(org: str, token: str, collector: Collector) -> Dict[str, Any]:
    path = f"/orgs/{org}/repos"
    repos = collector.guard(
        f"GET {path}",
        lambda: github_get(path, token=token, params={"type": "all", "sort": "full_name"}),
        default=[],
    ) or []

    truncated = False
    limit = int_env("GITHUB_MAX_REPOSITORIES", 0)
    if limit > 0 and len(repos) > limit:
        logger.warning(
            "GITHUB_MAX_REPOSITORIES=%d truncates %d repositories; evidence is a SUBSET "
            "and summary.repositories_truncated is true",
            limit,
            len(repos),
        )
        repos = sorted(repos, key=lambda r: r.get("full_name") or "")[:limit]
        truncated = True

    records = [collect_repository(repo, token, collector) for repo in repos]
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

    collected: Dict[str, Any] = {"records": [], "truncated": False}
    if organization and token:
        collected = collect_repositories(organization, token, collector)

    records = collected["records"]
    evidence = build_payload(
        organization=organization,
        organization_source=org_info["organization_source"],
        collector=collector,
        results={"repositories": records},
        summary=summarize(records, truncated=collected["truncated"]),
    )

    filename = (
        f"github_repository_branch_protection_{sanitize_for_filename(organization or 'unknown')}.json"
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
