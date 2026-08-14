#!/usr/bin/env python3
"""GitHub repository hygiene and lifecycle posture.

The three shipped GitHub fetchers answer "can an unreviewed commit reach the
default branch?" and "what does the org require?". This one answers the five
repository-level questions none of them cover — the hygiene that sits *around*
the branch rule rather than inside it:

  1. Is code ownership declared?      CODEOWNERS in one of GitHub's three
                                      recognized locations, and does it parse?
  2. Can a vulnerability be reported? SECURITY.md on public repositories.
  3. Can a published release change?  the repository's immutable-releases switch.
  4. Is a dead repository still live?  no activity for N days and not archived.
  5. Do merged branches linger?        delete-branch-on-merge.

Field projection ported from Prowler (Apache-2.0, master):
  prowler/providers/github/services/repository/repository_service.py
    -> `_file_exists()` ("404 means the file is absent, any other error means we
       cannot know"), the three CODEOWNERS locations, the
       `/repos/{o}/{r}/immutable-releases` probe and its 404/403 handling, and
       the `Repo` model's securitymd / codeowners_exists / delete_branch_on_merge
       / pushed_at fields.
  repository_has_codeowners_file, repository_public_has_securitymd_file,
  repository_immutable_releases_enabled, repository_inactive_not_archived,
  repository_branch_delete_on_merge_enabled
    -> which field each control actually turns on, and the population each one
       is scoped to (non-archived; public-only for SECURITY.md).
Collected over the REST API with `requests` (Prowler uses PyGithub; this category
adds no dependency).

Two deliberate divergences from Prowler, both recorded in the evidence rather
than assumed by it:

- **SECURITY.md is probed in all three locations GitHub honors** (root,
  `.github/`, `docs/`), not just the root. Prowler checks the root only, which
  reports a policy that GitHub itself is serving as missing. Because the record
  carries `security_policy_path`, a validator that wants Prowler's stricter
  root-only reading can still assert it.
- **A 403 on the immutable-releases endpoint is "not visible", not a failure.**
  That endpoint is feature-gated, and its 403 does not distinguish "your token
  may not read this" from "this repository cannot have the feature" — so raising
  would make an unfixable finding out of an ambiguity. It is reported as
  `immutable_releases_enabled: null` beside `immutable_releases_visible: false`,
  which the category's rules already forbid reading as "disabled". A rate-limit
  403 is NOT swallowed; `github_common` classifies those separately.

A missing file returns 404, and that is a legitimate negative result — the whole
point of the check. It never lands in `api_failures` and never flips the exit
code, exactly as the sibling fetcher treats a 404 from the branch-protection
endpoint as "unprotected" rather than as an error.

Single-organization per invocation; fanout across organizations happens at the
runner layer (see fetcher.yaml: supports_targets: true).
"""

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from github_common import (  # noqa: E402
    Collector,
    ConfigError,
    GitHubAPIError,
    build_payload,
    coverage_percentage,
    get_env,
    github_get,
    int_env,
    register_redaction,
    resolve_organization,
    sanitize_for_filename,
    write_evidence,
    write_status,
)

logger = logging.getLogger("github_repository_hygiene")

# GitHub honors a CODEOWNERS file in exactly three locations, and the first one
# found wins. Probed in Prowler's order.
# https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners#codeowners-file-location
CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")

# The same three locations serve a security policy. Root first: it is the most
# common, and it is the only one Prowler looks at.
# https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository
SECURITY_POLICY_PATHS = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")

# Prowler's `inactive_not_archived_days_threshold` default. Six months of no
# pushes is long enough that a live repository is not swept up by a quiet
# quarter, and short enough that an abandoned one is still caught inside an
# annual assessment window.
DEFAULT_INACTIVE_DAYS = 180

# Nothing was probed: the repository is archived (read-only, so none of these
# settings can change) and it is out of every coverage denominator.
UNPROBED = "skipped_archived"


# --- pure transforms (operate on REST response dicts; unit-tested from fixtures) ---

def parse_timestamp(value: Any) -> Optional[datetime]:
    """GitHub's ISO-8601 "2026-08-01T10:00:00Z" -> an aware datetime, or None.

    Returns None for a null/absent/malformed value rather than raising: a
    repository with no commits has a null `pushed_at`, and that is "we cannot
    compute inactivity", not a collection failure.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        logger.warning("could not parse timestamp %r; reporting age as null", value)
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def days_since(value: Any, now: datetime) -> Optional[int]:
    """Whole days between `value` and `now`; None when `value` is unusable."""
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    return (now - parsed).days


def file_presence(probes: Dict[str, Optional[bool]], order: Sequence[str]) -> Dict[str, Any]:
    """Reduce per-path probe results into "does this file exist, and where?".

    Each probe is True (200), False (404 — genuinely absent) or None (the call
    failed, so we do not know). Prowler's reduction, kept exactly: any hit means
    the file exists; *every* probe unknown means the answer is unknown; anything
    else means absent. Collapsing unknown into absent would fabricate a finding
    out of a permissions gap, which is the one thing this category never does.
    """
    for path in order:
        if probes.get(path) is True:
            return {"exists": True, "path": path}
    if all(probes.get(path) is None for path in order):
        return {"exists": None, "path": None}
    return {"exists": False, "path": None}


def codeowners_record(
    probes: Dict[str, Optional[bool]],
    *,
    errors: Optional[List[Dict[str, Any]]] = None,
    errors_visible: bool = False,
) -> Dict[str, Any]:
    """CODEOWNERS presence, location, and whether GitHub can parse it.

    Presence and path come from the contents probes (Prowler's method). Validity
    comes from `GET /repos/{o}/{r}/codeowners/errors`, which is queried only when
    a file was found — a file that exists but does not parse assigns no
    reviewers, so "present" alone overstates the control. Only error *kinds* and
    a count are recorded; the errors payload echoes the offending source lines
    and evidence does not need repository content.
    """
    presence = file_presence(probes, CODEOWNERS_PATHS)
    record: Dict[str, Any] = {
        "codeowners_exists": presence["exists"],
        "codeowners_path": presence["path"],
        "codeowners_paths_checked": list(CODEOWNERS_PATHS),
        "codeowners_valid": None,
        "codeowners_error_count": None,
        "codeowners_error_kinds": [],
        "codeowners_errors_visible": bool(errors_visible),
    }
    if errors_visible and errors is not None:
        record["codeowners_error_count"] = len(errors)
        record["codeowners_valid"] = not errors
        record["codeowners_error_kinds"] = sorted(
            {e["kind"] for e in errors if isinstance(e, dict) and e.get("kind")}
        )
    return record


def security_policy_record(probes: Dict[str, Optional[bool]]) -> Dict[str, Any]:
    """SECURITY.md presence and location.

    Reported for every repository regardless of visibility; the control it
    serves applies to PUBLIC repositories only, and scoping that is the
    validator's job using `private` / `visibility` from the same record.
    """
    presence = file_presence(probes, SECURITY_POLICY_PATHS)
    return {
        "security_policy_exists": presence["exists"],
        "security_policy_path": presence["path"],
        "security_policy_paths_checked": list(SECURITY_POLICY_PATHS),
    }


def immutable_releases_record(payload: Any, *, visible: bool) -> Dict[str, Any]:
    """`GET /repos/{o}/{r}/immutable-releases` -> {"enabled", "enforced_by_owner"}.

    Absent or unreadable is null + `immutable_releases_visible: false`, never
    false: "we could not ask" and "the switch is off" are different findings.
    """
    if not visible or not isinstance(payload, dict):
        return {
            "immutable_releases_enabled": None,
            "immutable_releases_enforced_by_owner": None,
            "immutable_releases_visible": False,
        }
    raw_enabled = payload.get("enabled")
    raw_enforced = payload.get("enforced_by_owner")
    return {
        "immutable_releases_enabled": None if raw_enabled is None else bool(raw_enabled),
        "immutable_releases_enforced_by_owner": (
            None if raw_enforced is None else bool(raw_enforced)
        ),
        "immutable_releases_visible": True,
    }


def activity_record(
    repo: Dict[str, Any], *, now: datetime, threshold_days: int
) -> Dict[str, Any]:
    """Age of the repository's last activity, and whether that makes it stale.

    `days_since_activity` is measured from `pushed_at`, which is Prowler's
    definition and the honest one: `updated_at` moves when someone renames the
    repository or edits its description, so an `updated_at`-based age would call
    a dead repository live. `updated_at` is recorded alongside it so a reviewer
    can see metadata churn on a repository with no commits.

    An archived repository is never `inactive_not_archived` — archiving IS the
    remediation, and Prowler passes archived repositories unconditionally.
    """
    archived = bool(repo.get("archived"))
    age = days_since(repo.get("pushed_at"), now)
    inactive = None if age is None else age >= threshold_days
    return {
        "pushed_at": repo.get("pushed_at"),
        "updated_at": repo.get("updated_at"),
        "created_at": repo.get("created_at"),
        "days_since_activity": age,
        "days_since_update": days_since(repo.get("updated_at"), now),
        "inactivity_threshold_days": threshold_days,
        "inactive": inactive,
        "inactive_not_archived": None if inactive is None else (inactive and not archived),
    }


def repo_record(
    repo: Dict[str, Any],
    *,
    codeowners: Dict[str, Any],
    security_policy: Dict[str, Any],
    immutable_releases: Dict[str, Any],
    now: datetime,
    threshold_days: int,
    probe_state: str = "probed",
) -> Dict[str, Any]:
    """One repository's hygiene posture.

    `delete_branch_on_merge` needs repository Administration read; GitHub omits
    the key rather than erroring when the token lacks it, so its absence is
    recorded as null beside `delete_branch_on_merge_visible: false` (Prowler
    reports the same case as MANUAL, not FAIL).
    """
    record: Dict[str, Any] = {
        "id": repo.get("id"),
        "name": repo.get("name"),
        "owner": (repo.get("owner") or {}).get("login"),
        "full_name": repo.get("full_name"),
        "private": bool(repo.get("private")),
        "visibility": repo.get("visibility"),
        "archived": bool(repo.get("archived")),
        "disabled": bool(repo.get("disabled")),
        "fork": bool(repo.get("fork")),
        "is_template": bool(repo.get("is_template")),
        "default_branch": repo.get("default_branch"),
        "probe_state": probe_state,
        "delete_branch_on_merge": repo.get("delete_branch_on_merge"),
        "delete_branch_on_merge_visible": "delete_branch_on_merge" in repo,
    }
    record.update(codeowners)
    record.update(security_policy)
    record.update(immutable_releases)
    record.update(activity_record(repo, now=now, threshold_days=threshold_days))
    return record


# Every probed field null — used for an archived repository, whose four-to-eight
# requests are skipped entirely. Deliberately not a False anywhere: nothing was
# asked, so nothing is known.

def unknown_codeowners() -> Dict[str, Any]:
    return codeowners_record({path: None for path in CODEOWNERS_PATHS})


def unknown_security_policy() -> Dict[str, Any]:
    return security_policy_record({path: None for path in SECURITY_POLICY_PATHS})


def unknown_immutable_releases() -> Dict[str, Any]:
    return immutable_releases_record(None, visible=False)


def summarize(
    records: List[Dict[str, Any]],
    *,
    threshold_days: int = DEFAULT_INACTIVE_DAYS,
    truncated: bool = False,
) -> Dict[str, Any]:
    """Coverage across the NON-ARCHIVED, NON-FORK population.

    Both exclusions change the number materially and both are honest:
    - **Archived** repositories are read-only. Nothing can be pushed to them and
      none of these settings can be changed, so counting them would drag every
      percentage down for a risk that does not exist.
    - **Forks** carry the upstream project's files and the upstream's release
      configuration. Reporting a fork of someone else's repository as "missing
      CODEOWNERS" is a finding against a project the organization does not own.

    Templates are counted but NOT excluded — a template repository is authored
    and maintained by the organization, and its CODEOWNERS is inherited by every
    repository generated from it. `is_template` is on each record so a validator
    that disagrees can scope around it.

    Both populations stay in the inventory (`archived_repositories`,
    `fork_repositories`); they are just out of the denominator.
    """
    active = [r for r in records if not r["archived"]]
    assessed = [r for r in active if not r["fork"]]
    total = len(assessed)

    def count(predicate) -> int:
        return sum(1 for r in assessed if predicate(r))

    public = [r for r in assessed if not r["private"]]
    public_with_policy = sum(1 for r in public if r["security_policy_exists"] is True)

    with_codeowners = count(lambda r: r["codeowners_exists"] is True)
    with_immutable = count(lambda r: r["immutable_releases_enabled"] is True)
    deleting_branches = count(lambda r: r["delete_branch_on_merge"] is True)

    return {
        "total_repositories": len(records),
        "active_repositories": len(active),
        "archived_repositories": len(records) - len(active),
        "fork_repositories": sum(1 for r in records if r["fork"]),
        "template_repositories": sum(1 for r in records if r["is_template"]),
        "private_repositories": sum(1 for r in records if r["private"]),
        "public_repositories": sum(1 for r in records if not r["private"]),
        # The denominator for every percentage below.
        "assessed_repositories": total,
        "repositories_truncated": truncated,
        "inactivity_threshold_days": threshold_days,

        # repository_has_codeowners_file
        "repositories_with_codeowners": with_codeowners,
        "codeowners_percentage": coverage_percentage(with_codeowners, total),
        "repositories_without_codeowners": count(lambda r: r["codeowners_exists"] is False),
        "repositories_with_unknown_codeowners": count(lambda r: r["codeowners_exists"] is None),
        # A CODEOWNERS that does not parse assigns no reviewers, so "present" on
        # its own overstates the control.
        "repositories_with_invalid_codeowners": count(lambda r: r["codeowners_valid"] is False),

        # repository_public_has_securitymd_file — public repositories only
        "public_assessed_repositories": len(public),
        "public_repositories_with_security_policy": public_with_policy,
        "public_security_policy_percentage": coverage_percentage(
            public_with_policy, len(public)
        ),
        "public_repositories_without_security_policy": sum(
            1 for r in public if r["security_policy_exists"] is False
        ),

        # repository_immutable_releases_enabled
        "repositories_with_immutable_releases": with_immutable,
        "immutable_releases_percentage": coverage_percentage(with_immutable, total),
        "repositories_without_immutable_releases": count(
            lambda r: r["immutable_releases_enabled"] is False
        ),
        "repositories_with_unknown_immutable_releases": count(
            lambda r: r["immutable_releases_visible"] is False
        ),

        # repository_branch_delete_on_merge_enabled
        "repositories_deleting_branch_on_merge": deleting_branches,
        "delete_branch_on_merge_percentage": coverage_percentage(deleting_branches, total),
        "repositories_not_deleting_branch_on_merge": count(
            lambda r: r["delete_branch_on_merge"] is False
        ),
        "repositories_with_unknown_branch_deletion_setting": count(
            lambda r: r["delete_branch_on_merge"] is None
        ),

        # repository_inactive_not_archived — the finding is "stale AND still live"
        "inactive_repositories_not_archived": count(
            lambda r: r["inactive_not_archived"] is True
        ),
        "inactive_repository_names": sorted(
            r["full_name"] or r["name"] or "" for r in assessed if r["inactive_not_archived"] is True
        ),
        "repositories_with_unknown_activity": count(lambda r: r["inactive"] is None),
    }


# --- collection ------------------------------------------------------------ #

def probe_paths(
    full_name: str,
    paths: Sequence[str],
    token: str,
    collector: Collector,
    label: str,
) -> Dict[str, Optional[bool]]:
    """Ask the contents API whether each candidate path exists, first hit wins.

    A 404 is the answer, not an error: it means the file genuinely is not there.
    Anything else (a permission denial, a rate limit, a 5xx) IS a failure and is
    recorded, which leaves the paths it never reached as None so the reduction in
    `file_presence` reports "unknown" instead of "absent".

    One guard wraps the whole sequence rather than each request, so a token
    without Contents read produces one recorded failure per file per repository
    instead of three.
    """
    results: Dict[str, Optional[bool]] = {path: None for path in paths}

    def _probe() -> Dict[str, Optional[bool]]:
        for path in paths:
            try:
                github_get(f"/repos/{full_name}/contents/{path}", token=token)
            except GitHubAPIError as exc:
                if exc.status == 404:
                    results[path] = False
                    continue
                raise
            results[path] = True
            return results
        return results

    # `default` is the same dict `_probe` mutates, so a mid-sequence failure
    # keeps the answers already obtained.
    return collector.guard(
        f"GET /repos/{full_name}/contents/{label}", _probe, default=results
    )


def fetch_codeowners_errors(
    full_name: str, token: str, collector: Collector
) -> Dict[str, Any]:
    """CODEOWNERS syntax errors, when GitHub will tell us.

    404 means there is no CODEOWNERS file to check (this is only called when a
    probe already found one, so it means GitHub disagrees about the location);
    403 means the token cannot read it. Neither is a collection failure — both
    leave `codeowners_valid` null.
    """
    path = f"/repos/{full_name}/codeowners/errors"

    def _get() -> Dict[str, Any]:
        try:
            data = github_get(path, token=token)
        except GitHubAPIError as exc:
            if exc.status == 404 or exc.code == "not_authorized":
                return {"errors": None, "visible": False}
            raise
        errors = data.get("errors") if isinstance(data, dict) else None
        return {"errors": list(errors or []), "visible": True}

    return collector.guard(
        f"GET {path}", _get, default={"errors": None, "visible": False}
    )


def fetch_immutable_releases(
    full_name: str, token: str, collector: Collector
) -> Dict[str, Any]:
    """The repository's immutable-releases switch.

    404 = the endpoint is not available for this repository; 403 = the token may
    not read it, OR the feature is not offered here (the response does not
    distinguish them). Both report "not visible" rather than a failure, matching
    Prowler — see the module docstring for why. A rate-limit 403 arrives with
    code `rate_limited`, not `not_authorized`, so it still raises.
    """
    path = f"/repos/{full_name}/immutable-releases"

    def _get() -> Dict[str, Any]:
        try:
            return {"payload": github_get(path, token=token), "visible": True}
        except GitHubAPIError as exc:
            if exc.status == 404:
                return {"payload": None, "visible": False}
            if exc.code == "not_authorized":
                logger.warning(
                    "%s: immutable-releases returned 403 — either the token lacks the read "
                    "permission or the feature is not available for this repository; "
                    "reported as immutable_releases_visible: false",
                    full_name,
                )
                return {"payload": None, "visible": False}
            raise

    return collector.guard(
        f"GET {path}", _get, default={"payload": None, "visible": False}
    )


def collect_repository(
    repo: Dict[str, Any],
    token: str,
    collector: Collector,
    *,
    now: datetime,
    threshold_days: int,
) -> Dict[str, Any]:
    full_name = (
        repo.get("full_name") or f"{(repo.get('owner') or {}).get('login')}/{repo.get('name')}"
    )

    if repo.get("archived"):
        return repo_record(
            repo,
            codeowners=unknown_codeowners(),
            security_policy=unknown_security_policy(),
            immutable_releases=unknown_immutable_releases(),
            now=now,
            threshold_days=threshold_days,
            probe_state=UNPROBED,
        )

    codeowners_probes = probe_paths(
        full_name, CODEOWNERS_PATHS, token, collector, "{CODEOWNERS}"
    )
    errors: Dict[str, Any] = {"errors": None, "visible": False}
    if file_presence(codeowners_probes, CODEOWNERS_PATHS)["exists"] is True:
        errors = fetch_codeowners_errors(full_name, token, collector)

    security_probes = probe_paths(
        full_name, SECURITY_POLICY_PATHS, token, collector, "{SECURITY.md}"
    )
    immutable = fetch_immutable_releases(full_name, token, collector)

    return repo_record(
        repo,
        codeowners=codeowners_record(
            codeowners_probes,
            errors=errors["errors"],
            errors_visible=bool(errors["visible"]),
        ),
        security_policy=security_policy_record(security_probes),
        immutable_releases=immutable_releases_record(
            immutable["payload"], visible=bool(immutable["visible"])
        ),
        now=now,
        threshold_days=threshold_days,
    )


def collect_repositories(
    org: str,
    token: str,
    collector: Collector,
    *,
    now: datetime,
    threshold_days: int,
) -> Dict[str, Any]:
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

    records = [
        collect_repository(repo, token, collector, now=now, threshold_days=threshold_days)
        for repo in repos
    ]
    return {
        "records": sorted(records, key=lambda r: r.get("full_name") or ""),
        "truncated": truncated,
    }


def resolve_threshold_days() -> int:
    """Inactivity threshold in days, from config, defaulting to Prowler's 180.

    A non-positive value would make every repository inactive, so it degrades to
    the default rather than emitting a summary where every repository is a
    finding.
    """
    threshold = int_env("GITHUB_INACTIVE_DAYS_THRESHOLD", DEFAULT_INACTIVE_DAYS)
    if threshold <= 0:
        logger.warning(
            "GITHUB_INACTIVE_DAYS_THRESHOLD=%d is not a positive number of days; using %d",
            threshold,
            DEFAULT_INACTIVE_DAYS,
        )
        return DEFAULT_INACTIVE_DAYS
    return threshold


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
    threshold_days = resolve_threshold_days()
    now = datetime.now(timezone.utc)

    token = None
    try:
        token = get_env("GITHUB_TOKEN")
        register_redaction(token)
    except ConfigError as exc:
        collector.record("resolve_github_token", exc)

    collected: Dict[str, Any] = {"records": [], "truncated": False}
    if organization and token:
        collected = collect_repositories(
            organization, token, collector, now=now, threshold_days=threshold_days
        )

    records = collected["records"]
    evidence = build_payload(
        organization=organization,
        organization_source=org_info["organization_source"],
        collector=collector,
        results={"repositories": records},
        summary=summarize(
            records, threshold_days=threshold_days, truncated=collected["truncated"]
        ),
    )

    filename = f"github_repository_hygiene_{sanitize_for_filename(organization or 'unknown')}.json"
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
