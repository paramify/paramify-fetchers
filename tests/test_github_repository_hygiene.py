"""Fixture-based tests for the github_repository_hygiene fetcher.

No live API calls and no credentials. Two layers, matching
`tests/test_github_fetchers.py`: the pure transforms against fixtures shaped like
the GitHub REST API's documented payloads, and one end-to-end run with
`requests.get` monkeypatched.

The three things most worth pinning down here:
  - **A 404 is the answer, not an error.** "This repository has no CODEOWNERS
    file" arrives as a 404 from the contents API. It must produce
    `codeowners_exists: false` with an empty `api_failures` and exit 0 — the
    inverse mistake (recording it as a collection failure) would make every
    honest negative finding look like a broken run.
  - **Unknown is never false.** A probe that failed for any *other* reason leaves
    the field null, so a permissions gap cannot fabricate a finding.
  - **Coverage excludes archived and forked repositories.** Both are in the
    inventory and out of the denominator; a fork of someone else's project is not
    a finding against this organization.

Run: pytest tests/test_github_repository_hygiene.py  (needs `pip install -e .`)
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GITHUB_ROOT = REPO_ROOT / "fetchers" / "github"

# The fetcher adds _shared to sys.path itself at import time; the test needs it up
# front to import the shared module directly.
sys.path.insert(0, str(GITHUB_ROOT / "_shared"))

import github_common as gh  # noqa: E402


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = GITHUB_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"github_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def hyg():
    return _load("repository_hygiene")


# --------------------------------------------------------------------------- #
# Fake transport
# --------------------------------------------------------------------------- #

class FakeResponse:
    def __init__(self, status_code=200, json_data=None, headers=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.headers = headers or {}
        self.text = text or (json.dumps(json_data) if json_data is not None else "")

    @property
    def content(self) -> bytes:
        return self.text.encode()

    def json(self):
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json


class RoutedGet:
    """Stand-in for requests.get that answers by URL suffix.

    The hygiene fetcher issues up to eight requests per repository in an order
    that depends on what it finds, so a positional queue would make the tests
    assert the order rather than the behavior.
    """

    def __init__(self, routes, default=None):
        self.routes = routes
        self.default = default or FakeResponse(404, {"message": "Not Found"})
        self.calls = []

    def __call__(self, url, headers=None, params=None, timeout=None):
        self.calls.append(url)
        for suffix, response in self.routes.items():
            if url.endswith(suffix):
                if isinstance(response, Exception):
                    raise response
                return response
        return self.default

    def paths(self):
        return [url.replace("https://api.github.com", "") for url in self.calls]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """No ambient GitHub env, and no leftover redactions, between tests."""
    for var in (
        "GITHUB_TOKEN",
        "GITHUB_ORG",
        "GITHUB_ORGANIZATION",
        "GITHUB_API_URL",
        "GITHUB_HTTP_TIMEOUT",
        "GITHUB_MAX_REPOSITORIES",
        "GITHUB_INACTIVE_DAYS_THRESHOLD",
        "FETCHER_STATUS_FILE",
        "EVIDENCE_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    gh._REDACTIONS.clear()
    yield
    gh._REDACTIONS.clear()


def _collector():
    return gh.Collector(logging.getLogger("test"))


NOW = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)


def _ago(days: int) -> str:
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Repository fixtures (GET /orgs/{org}/repos shape)
# --------------------------------------------------------------------------- #

REPO_TIDY = {
    "id": 1,
    "name": "app",
    "full_name": "acme/app",
    "owner": {"login": "acme"},
    "private": True,
    "visibility": "private",
    "archived": False,
    "fork": False,
    "is_template": False,
    "default_branch": "main",
    "delete_branch_on_merge": True,
    "pushed_at": _ago(3),
    "updated_at": _ago(2),
    "created_at": _ago(900),
}

REPO_PUBLIC_STALE = {
    "id": 2,
    "name": "sdk",
    "full_name": "acme/sdk",
    "owner": {"login": "acme"},
    "private": False,
    "visibility": "public",
    "archived": False,
    "fork": False,
    "is_template": False,
    "default_branch": "main",
    "delete_branch_on_merge": False,
    # Renamed recently, but no commits for well over the threshold: the case an
    # updated_at-based age would call "active".
    "pushed_at": _ago(400),
    "updated_at": _ago(1),
    "created_at": _ago(1500),
}

REPO_ARCHIVED = {
    "id": 3,
    "name": "legacy",
    "full_name": "acme/legacy",
    "owner": {"login": "acme"},
    "private": False,
    "visibility": "public",
    "archived": True,
    "fork": False,
    "is_template": False,
    "default_branch": "master",
    "pushed_at": _ago(1200),
    "updated_at": _ago(1200),
}

REPO_FORK = {
    "id": 4,
    "name": "upstream-tool",
    "full_name": "acme/upstream-tool",
    "owner": {"login": "acme"},
    "private": False,
    "visibility": "public",
    "archived": False,
    "fork": True,
    "is_template": False,
    "default_branch": "main",
    "delete_branch_on_merge": False,
    "pushed_at": _ago(500),
    "updated_at": _ago(500),
}

# No delete_branch_on_merge key at all: the token lacks Administration:Read, and
# GitHub omits the field rather than erroring.
REPO_NO_ADMIN_VIEW = {
    "id": 5,
    "name": "scratch",
    "full_name": "acme/scratch",
    "owner": {"login": "acme"},
    "private": False,
    "visibility": "public",
    "archived": False,
    "fork": False,
    "is_template": True,
    "default_branch": "main",
    "pushed_at": _ago(10),
    "updated_at": _ago(10),
}


def _record(hyg, repo, *, codeowners_at=None, security_at=None, immutable=None,
            codeowners_errors=None, threshold_days=180):
    """Build one record the way collect_repository would, without any transport."""
    co_probes = {path: False for path in hyg.CODEOWNERS_PATHS}
    if codeowners_at:
        co_probes[codeowners_at] = True
    sec_probes = {path: False for path in hyg.SECURITY_POLICY_PATHS}
    if security_at:
        sec_probes[security_at] = True
    return hyg.repo_record(
        repo,
        codeowners=hyg.codeowners_record(
            co_probes,
            errors=codeowners_errors,
            errors_visible=codeowners_errors is not None,
        ),
        security_policy=hyg.security_policy_record(sec_probes),
        immutable_releases=hyg.immutable_releases_record(
            immutable, visible=immutable is not None
        ),
        now=NOW,
        threshold_days=threshold_days,
    )


# --------------------------------------------------------------------------- #
# file_presence — the 404-is-an-answer reduction
# --------------------------------------------------------------------------- #

def test_file_presence_reports_the_location_that_was_found(hyg):
    probes = {".github/CODEOWNERS": False, "CODEOWNERS": True, "docs/CODEOWNERS": False}
    assert hyg.file_presence(probes, hyg.CODEOWNERS_PATHS) == {
        "exists": True,
        "path": "CODEOWNERS",
    }


def test_file_presence_prefers_the_first_configured_location(hyg):
    """GitHub honors the first location it finds; the record must say the same."""
    probes = dict.fromkeys(hyg.CODEOWNERS_PATHS, True)
    assert hyg.file_presence(probes, hyg.CODEOWNERS_PATHS)["path"] == ".github/CODEOWNERS"


def test_file_presence_all_404_is_absent_not_unknown(hyg):
    probes = dict.fromkeys(hyg.CODEOWNERS_PATHS, False)
    assert hyg.file_presence(probes, hyg.CODEOWNERS_PATHS) == {"exists": False, "path": None}


def test_file_presence_all_probes_failed_is_unknown_not_absent(hyg):
    """A permissions gap must not manufacture a "missing CODEOWNERS" finding."""
    probes = dict.fromkeys(hyg.CODEOWNERS_PATHS, None)
    assert hyg.file_presence(probes, hyg.CODEOWNERS_PATHS) == {"exists": None, "path": None}


def test_file_presence_partial_failure_after_a_confirmed_404_is_absent(hyg):
    """One real 404 is enough to know the file is not in that location.

    Prowler's reduction: only when EVERY probe is unknown is the answer unknown.
    """
    probes = {".github/CODEOWNERS": False, "CODEOWNERS": None, "docs/CODEOWNERS": None}
    assert hyg.file_presence(probes, hyg.CODEOWNERS_PATHS)["exists"] is False


# --------------------------------------------------------------------------- #
# codeowners_record — presence, path, and validity
# --------------------------------------------------------------------------- #

def test_codeowners_record_valid_file(hyg):
    rec = hyg.codeowners_record(
        {".github/CODEOWNERS": True, "CODEOWNERS": False, "docs/CODEOWNERS": False},
        errors=[],
        errors_visible=True,
    )
    assert rec["codeowners_exists"] is True
    assert rec["codeowners_path"] == ".github/CODEOWNERS"
    assert rec["codeowners_valid"] is True
    assert rec["codeowners_error_count"] == 0
    assert rec["codeowners_error_kinds"] == []
    assert rec["codeowners_paths_checked"] == list(hyg.CODEOWNERS_PATHS)


def test_codeowners_record_present_but_unparseable(hyg):
    """A CODEOWNERS that does not parse assigns no reviewers.

    "Present" on its own overstates the control, so validity is reported next to
    it — and only the error KINDS, never the offending source lines.
    """
    rec = hyg.codeowners_record(
        {".github/CODEOWNERS": True},
        errors=[
            {"kind": "Unknown owner", "line": 3, "source": "* @acme/ghost-team"},
            {"kind": "Unknown owner", "line": 4, "source": "docs/ @nobody"},
            {"kind": "Invalid pattern", "line": 9, "source": "[["},
        ],
        errors_visible=True,
    )
    assert rec["codeowners_exists"] is True
    assert rec["codeowners_valid"] is False
    assert rec["codeowners_error_count"] == 3
    assert rec["codeowners_error_kinds"] == ["Invalid pattern", "Unknown owner"]
    assert "ghost-team" not in json.dumps(rec)


def test_codeowners_record_validity_unknown_when_errors_not_visible(hyg):
    rec = hyg.codeowners_record({"CODEOWNERS": True}, errors=None, errors_visible=False)
    assert rec["codeowners_exists"] is True
    assert rec["codeowners_valid"] is None
    assert rec["codeowners_errors_visible"] is False


def test_unknown_helpers_are_all_null(hyg):
    """Archived repositories are not probed; nothing asked means nothing known."""
    assert hyg.unknown_codeowners()["codeowners_exists"] is None
    assert hyg.unknown_security_policy()["security_policy_exists"] is None
    assert hyg.unknown_immutable_releases() == {
        "immutable_releases_enabled": None,
        "immutable_releases_enforced_by_owner": None,
        "immutable_releases_visible": False,
    }


# --------------------------------------------------------------------------- #
# security_policy_record — all three locations, path recorded
# --------------------------------------------------------------------------- #

def test_security_policy_found_outside_the_root_records_its_path(hyg):
    """GitHub serves a policy from .github/ too; Prowler only looks at the root.

    Recording the path keeps both readings available: this evidence says the
    policy exists, and a validator wanting Prowler's root-only rule can assert
    on security_policy_path.
    """
    rec = hyg.security_policy_record(
        {"SECURITY.md": False, ".github/SECURITY.md": True, "docs/SECURITY.md": False}
    )
    assert rec["security_policy_exists"] is True
    assert rec["security_policy_path"] == ".github/SECURITY.md"


def test_security_policy_absent(hyg):
    rec = hyg.security_policy_record(dict.fromkeys(hyg.SECURITY_POLICY_PATHS, False))
    assert rec["security_policy_exists"] is False
    assert rec["security_policy_path"] is None


# --------------------------------------------------------------------------- #
# immutable_releases_record
# --------------------------------------------------------------------------- #

def test_immutable_releases_enabled_and_enforced(hyg):
    rec = hyg.immutable_releases_record(
        {"enabled": True, "enforced_by_owner": True}, visible=True
    )
    assert rec["immutable_releases_enabled"] is True
    assert rec["immutable_releases_enforced_by_owner"] is True
    assert rec["immutable_releases_visible"] is True


def test_immutable_releases_disabled_is_false_not_null(hyg):
    rec = hyg.immutable_releases_record(
        {"enabled": False, "enforced_by_owner": False}, visible=True
    )
    assert rec["immutable_releases_enabled"] is False


def test_immutable_releases_not_visible_is_null_not_false(hyg):
    """404/403 on a feature-gated endpoint must not read as "switched off"."""
    assert hyg.immutable_releases_record(None, visible=False)[
        "immutable_releases_enabled"
    ] is None
    # visible=True but a body without `enabled` is still unknown.
    assert hyg.immutable_releases_record({}, visible=True)[
        "immutable_releases_enabled"
    ] is None


# --------------------------------------------------------------------------- #
# activity — days since last push, and the inactivity judgment
# --------------------------------------------------------------------------- #

def test_days_since_parses_github_timestamps(hyg):
    assert hyg.days_since(_ago(45), NOW) == 45
    assert hyg.days_since("2026-08-01T10:00:00+00:00", NOW) == 13
    # A naive timestamp is read as UTC rather than crashing on tz comparison.
    assert hyg.days_since("2026-08-01T10:00:00", NOW) == 13


def test_days_since_unusable_value_is_null(hyg):
    """An empty repository has a null pushed_at: unknown age, not age zero."""
    assert hyg.days_since(None, NOW) is None
    assert hyg.days_since("", NOW) is None
    assert hyg.days_since("not-a-date", NOW) is None


def test_activity_measures_pushes_not_metadata_edits(hyg):
    """updated_at moves on a rename; only pushed_at means the code is alive."""
    rec = hyg.activity_record(REPO_PUBLIC_STALE, now=NOW, threshold_days=180)
    assert rec["days_since_activity"] == 400
    assert rec["days_since_update"] == 1
    assert rec["inactive"] is True
    assert rec["inactive_not_archived"] is True
    assert rec["inactivity_threshold_days"] == 180


def test_activity_archived_repository_is_never_a_finding(hyg):
    """Archiving IS the remediation, so an archived repo cannot fail this check."""
    rec = hyg.activity_record(REPO_ARCHIVED, now=NOW, threshold_days=180)
    assert rec["inactive"] is True
    assert rec["inactive_not_archived"] is False


def test_activity_threshold_is_configurable(hyg):
    """The threshold is a policy judgment, so the same repo flips with it."""
    repo = dict(REPO_TIDY, pushed_at=_ago(120))
    assert hyg.activity_record(repo, now=NOW, threshold_days=180)["inactive"] is False
    assert hyg.activity_record(repo, now=NOW, threshold_days=90)["inactive"] is True


def test_activity_unknown_age_is_null_not_active(hyg):
    repo = dict(REPO_TIDY, pushed_at=None)
    rec = hyg.activity_record(repo, now=NOW, threshold_days=180)
    assert rec["inactive"] is None
    assert rec["inactive_not_archived"] is None


def test_resolve_threshold_days_default_and_override(hyg, monkeypatch):
    assert hyg.resolve_threshold_days() == hyg.DEFAULT_INACTIVE_DAYS == 180
    monkeypatch.setenv("GITHUB_INACTIVE_DAYS_THRESHOLD", "90")
    assert hyg.resolve_threshold_days() == 90


def test_resolve_threshold_days_rejects_nonsense(hyg, monkeypatch):
    """0 would make every repository a finding; garbage must not crash the run."""
    monkeypatch.setenv("GITHUB_INACTIVE_DAYS_THRESHOLD", "0")
    assert hyg.resolve_threshold_days() == 180
    monkeypatch.setenv("GITHUB_INACTIVE_DAYS_THRESHOLD", "-30")
    assert hyg.resolve_threshold_days() == 180
    monkeypatch.setenv("GITHUB_INACTIVE_DAYS_THRESHOLD", "six months")
    assert hyg.resolve_threshold_days() == 180


# --------------------------------------------------------------------------- #
# repo_record
# --------------------------------------------------------------------------- #

def test_repo_record_projects_the_exclusion_flags(hyg):
    rec = _record(hyg, REPO_FORK)
    assert rec["fork"] is True
    assert rec["is_template"] is False
    assert rec["archived"] is False
    assert rec["visibility"] == "public"
    assert rec["private"] is False


def test_repo_record_missing_admin_field_is_null_not_false(hyg):
    """GitHub omits delete_branch_on_merge without Administration:Read.

    Prowler reports that case as MANUAL, not FAIL; here it is null with a
    visibility flag, because "we could not see it" is not "it is off".
    """
    rec = _record(hyg, REPO_NO_ADMIN_VIEW)
    assert rec["delete_branch_on_merge"] is None
    assert rec["delete_branch_on_merge_visible"] is False

    visible = _record(hyg, REPO_PUBLIC_STALE)
    assert visible["delete_branch_on_merge"] is False
    assert visible["delete_branch_on_merge_visible"] is True


# --------------------------------------------------------------------------- #
# summarize — the denominator is the whole argument
# --------------------------------------------------------------------------- #

def _population(hyg):
    return [
        _record(
            hyg,
            REPO_TIDY,
            codeowners_at=".github/CODEOWNERS",
            security_at="SECURITY.md",
            immutable={"enabled": True, "enforced_by_owner": False},
            codeowners_errors=[],
        ),
        _record(
            hyg,
            REPO_PUBLIC_STALE,
            codeowners_at=None,
            security_at=None,
            immutable={"enabled": False, "enforced_by_owner": False},
            codeowners_errors=None,
        ),
        hyg.repo_record(
            REPO_ARCHIVED,
            codeowners=hyg.unknown_codeowners(),
            security_policy=hyg.unknown_security_policy(),
            immutable_releases=hyg.unknown_immutable_releases(),
            now=NOW,
            threshold_days=180,
            probe_state=hyg.UNPROBED,
        ),
        _record(hyg, REPO_FORK, codeowners_at=None, security_at=None, immutable=None),
    ]


def test_summary_denominator_excludes_archived_and_forks(hyg):
    summary = hyg.summarize(_population(hyg))

    assert summary["total_repositories"] == 4
    assert summary["archived_repositories"] == 1
    assert summary["active_repositories"] == 3
    assert summary["fork_repositories"] == 1
    # 4 repos, minus 1 archived, minus 1 fork == 2 assessed.
    assert summary["assessed_repositories"] == 2
    # 1 of 2 == 50%, not 25%.
    assert summary["repositories_with_codeowners"] == 1
    assert summary["codeowners_percentage"] == 50
    assert summary["repositories_without_codeowners"] == 1


def test_summary_security_policy_is_scoped_to_public_repositories(hyg):
    """A private repository has nobody to publish a policy to.

    Of the two assessed repos one is private, so the SECURITY.md denominator is
    1 — and that one is missing its policy.
    """
    summary = hyg.summarize(_population(hyg))

    assert summary["public_assessed_repositories"] == 1
    assert summary["public_repositories_with_security_policy"] == 0
    assert summary["public_security_policy_percentage"] == 0
    assert summary["public_repositories_without_security_policy"] == 1


def test_summary_counts_immutable_releases_and_branch_deletion(hyg):
    summary = hyg.summarize(_population(hyg))

    assert summary["repositories_with_immutable_releases"] == 1
    assert summary["immutable_releases_percentage"] == 50
    assert summary["repositories_without_immutable_releases"] == 1
    assert summary["repositories_deleting_branch_on_merge"] == 1
    assert summary["delete_branch_on_merge_percentage"] == 50
    assert summary["repositories_not_deleting_branch_on_merge"] == 1


def test_summary_names_the_inactive_unarchived_repositories(hyg):
    """The actionable output: which live repositories should be archived."""
    summary = hyg.summarize(_population(hyg))

    assert summary["inactive_repositories_not_archived"] == 1
    assert summary["inactive_repository_names"] == ["acme/sdk"]
    # The fork is 500 days stale too, but it is out of scope by construction.
    assert "acme/upstream-tool" not in summary["inactive_repository_names"]
    assert summary["inactivity_threshold_days"] == 180


def test_summary_unknowns_are_counted_separately_from_negatives(hyg):
    """A permissions gap shows up as "unknown", never in the failing count."""
    unknown = hyg.repo_record(
        REPO_NO_ADMIN_VIEW,
        codeowners=hyg.unknown_codeowners(),
        security_policy=hyg.unknown_security_policy(),
        immutable_releases=hyg.unknown_immutable_releases(),
        now=NOW,
        threshold_days=180,
    )
    summary = hyg.summarize([unknown])

    assert summary["assessed_repositories"] == 1
    assert summary["repositories_with_unknown_codeowners"] == 1
    assert summary["repositories_without_codeowners"] == 0
    assert summary["codeowners_percentage"] == 0
    assert summary["repositories_with_unknown_immutable_releases"] == 1
    assert summary["repositories_without_immutable_releases"] == 0
    assert summary["repositories_with_unknown_branch_deletion_setting"] == 1


def test_summary_counts_invalid_codeowners(hyg):
    rec = _record(
        hyg,
        REPO_TIDY,
        codeowners_at="CODEOWNERS",
        codeowners_errors=[{"kind": "Unknown owner", "line": 1}],
    )
    summary = hyg.summarize([rec])
    assert summary["repositories_with_codeowners"] == 1
    assert summary["repositories_with_invalid_codeowners"] == 1


def test_summary_of_empty_organization_is_zero_not_a_crash(hyg):
    summary = hyg.summarize([])
    assert summary["total_repositories"] == 0
    assert summary["assessed_repositories"] == 0
    assert summary["codeowners_percentage"] == 0
    assert summary["public_security_policy_percentage"] == 0
    assert summary["inactive_repository_names"] == []


# --------------------------------------------------------------------------- #
# probe_paths — where "404 is not a failure" is actually enforced
# --------------------------------------------------------------------------- #

def test_probe_paths_404s_are_results_not_failures(hyg, monkeypatch):
    monkeypatch.setattr(gh.requests, "get", RoutedGet({}))
    collector = _collector()

    probes = hyg.probe_paths("acme/app", hyg.CODEOWNERS_PATHS, "t", collector, "{CO}")

    assert probes == dict.fromkeys(hyg.CODEOWNERS_PATHS, False)
    # The whole point: an absent file does not make the run look broken.
    assert collector.ok
    assert collector.failures == []


def test_probe_paths_stops_at_the_first_hit(hyg, monkeypatch):
    fake = RoutedGet({"/contents/.github/CODEOWNERS": FakeResponse(json_data={"name": "CODEOWNERS"})})
    monkeypatch.setattr(gh.requests, "get", fake)
    collector = _collector()

    probes = hyg.probe_paths("acme/app", hyg.CODEOWNERS_PATHS, "t", collector, "{CO}")

    assert probes[".github/CODEOWNERS"] is True
    assert len(fake.calls) == 1
    assert collector.ok


def test_probe_paths_non_404_is_a_failure_and_leaves_unreached_paths_unknown(hyg, monkeypatch):
    """A 403 on the contents API is a real failure, and it must not read as absent.

    The first location genuinely 404s, the second is refused, the third is never
    reached — so the reduction reports "absent" only because of that confirmed
    404, and the run still exits non-zero via the collector.
    """
    fake = RoutedGet(
        {
            "/contents/.github/CODEOWNERS": FakeResponse(404, {"message": "Not Found"}),
            "/contents/CODEOWNERS": FakeResponse(
                403,
                {"message": "Resource not accessible by personal access token"},
                headers={"X-RateLimit-Remaining": "4998"},
            ),
        }
    )
    monkeypatch.setattr(gh.requests, "get", fake)
    collector = _collector()

    probes = hyg.probe_paths("acme/app", hyg.CODEOWNERS_PATHS, "t", collector, "{CO}")

    assert probes[".github/CODEOWNERS"] is False
    assert probes["CODEOWNERS"] is None
    assert probes["docs/CODEOWNERS"] is None
    assert len(fake.calls) == 2
    assert collector.ok is False
    assert collector.failures[0]["code"] == "not_authorized"


# --------------------------------------------------------------------------- #
# immutable-releases and codeowners/errors probes
# --------------------------------------------------------------------------- #

def test_fetch_immutable_releases_404_and_403_are_not_failures(hyg, monkeypatch):
    """Feature-gated endpoint: neither response distinguishes "off" from "n/a"."""
    monkeypatch.setattr(gh.requests, "get", RoutedGet({}))
    collector = _collector()
    assert hyg.fetch_immutable_releases("acme/app", "t", collector) == {
        "payload": None,
        "visible": False,
    }
    assert collector.ok

    monkeypatch.setattr(
        gh.requests,
        "get",
        RoutedGet(
            {
                "/immutable-releases": FakeResponse(
                    403, {"message": "Forbidden"}, headers={"X-RateLimit-Remaining": "4998"}
                )
            }
        ),
    )
    collector = _collector()
    assert hyg.fetch_immutable_releases("acme/app", "t", collector)["visible"] is False
    assert collector.ok


def test_fetch_immutable_releases_rate_limit_403_still_fails(hyg, monkeypatch):
    """The 403 split matters here: a rate limit must not be swallowed as "n/a"."""
    monkeypatch.setattr(
        gh.requests,
        "get",
        RoutedGet(
            {
                "/immutable-releases": FakeResponse(
                    403,
                    {"message": "API rate limit exceeded for user"},
                    headers={"X-RateLimit-Remaining": "0"},
                )
            }
        ),
    )
    collector = _collector()

    hyg.fetch_immutable_releases("acme/app", "t", collector)

    assert collector.ok is False
    assert collector.failures[0]["code"] == "rate_limited"


def test_fetch_codeowners_errors_reads_the_errors_list(hyg, monkeypatch):
    monkeypatch.setattr(
        gh.requests,
        "get",
        RoutedGet(
            {
                "/codeowners/errors": FakeResponse(
                    json_data={"errors": [{"kind": "Unknown owner", "line": 2}]}
                )
            }
        ),
    )
    collector = _collector()

    result = hyg.fetch_codeowners_errors("acme/app", "t", collector)

    assert result["visible"] is True
    assert result["errors"] == [{"kind": "Unknown owner", "line": 2}]
    assert collector.ok


def test_fetch_codeowners_errors_404_is_not_a_failure(hyg, monkeypatch):
    monkeypatch.setattr(gh.requests, "get", RoutedGet({}))
    collector = _collector()
    assert hyg.fetch_codeowners_errors("acme/app", "t", collector) == {
        "errors": None,
        "visible": False,
    }
    assert collector.ok


# --------------------------------------------------------------------------- #
# collect_repository
# --------------------------------------------------------------------------- #

def test_collect_repository_archived_issues_no_requests(hyg, monkeypatch):
    """Archived repos are read-only and out of the denominator: don't pay for them."""
    fake = RoutedGet({})
    monkeypatch.setattr(gh.requests, "get", fake)
    collector = _collector()

    rec = hyg.collect_repository(
        REPO_ARCHIVED, "t", collector, now=NOW, threshold_days=180
    )

    assert fake.calls == []
    assert rec["probe_state"] == hyg.UNPROBED
    assert rec["codeowners_exists"] is None
    assert rec["archived"] is True
    # The activity fields still come from the list response.
    assert rec["days_since_activity"] == 1200
    assert collector.ok


def test_collect_repository_skips_the_errors_probe_when_no_codeowners(hyg, monkeypatch):
    """The syntax check costs a request, so only ask when a file was found."""
    fake = RoutedGet({})
    monkeypatch.setattr(gh.requests, "get", fake)
    collector = _collector()

    rec = hyg.collect_repository(REPO_TIDY, "t", collector, now=NOW, threshold_days=180)

    assert rec["codeowners_exists"] is False
    assert rec["codeowners_valid"] is None
    assert not any("/codeowners/errors" in url for url in fake.calls)
    assert collector.ok


def test_collect_repository_full_pass(hyg, monkeypatch):
    fake = RoutedGet(
        {
            "/contents/.github/CODEOWNERS": FakeResponse(json_data={"name": "CODEOWNERS"}),
            "/codeowners/errors": FakeResponse(json_data={"errors": []}),
            "/contents/SECURITY.md": FakeResponse(json_data={"name": "SECURITY.md"}),
            "/immutable-releases": FakeResponse(
                json_data={"enabled": True, "enforced_by_owner": True}
            ),
        }
    )
    monkeypatch.setattr(gh.requests, "get", fake)
    collector = _collector()

    rec = hyg.collect_repository(
        REPO_PUBLIC_STALE, "t", collector, now=NOW, threshold_days=180
    )

    assert rec["probe_state"] == "probed"
    assert rec["codeowners_path"] == ".github/CODEOWNERS"
    assert rec["codeowners_valid"] is True
    assert rec["security_policy_path"] == "SECURITY.md"
    assert rec["immutable_releases_enabled"] is True
    assert rec["inactive_not_archived"] is True
    assert collector.ok


# --------------------------------------------------------------------------- #
# End-to-end (the contract's exit-code + status-file clause)
# --------------------------------------------------------------------------- #

def test_missing_files_everywhere_still_exits_zero(hyg, tmp_path, monkeypatch):
    """The headline behavior: an org with no hygiene files is a clean run.

    Every probe 404s, so the evidence is full of `false` — and the exit code is
    0 with an empty api_failures and no status file, because a negative finding
    is not a collection failure.
    """
    evidence_dir = tmp_path / "evidence"
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.setenv("GITHUB_ORG", "acme")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_valid_looking_token")
    monkeypatch.setattr(
        gh.requests,
        "get",
        RoutedGet({"/orgs/acme/repos": FakeResponse(json_data=[REPO_PUBLIC_STALE])}),
    )

    assert hyg.main() == 0
    assert not status_file.exists()

    evidence = json.loads(
        (evidence_dir / "github_repository_hygiene_acme.json").read_text()
    )
    assert evidence["metadata"]["partial_failure"] is False
    assert evidence["metadata"]["api_failures"] == []
    repo = evidence["results"]["repositories"][0]
    assert repo["codeowners_exists"] is False
    assert repo["security_policy_exists"] is False
    assert repo["immutable_releases_visible"] is False
    assert evidence["summary"]["codeowners_percentage"] == 0
    assert evidence["summary"]["inactive_repositories_not_archived"] == 1


def test_bad_token_exits_nonzero_writes_evidence_and_auth_failed_status(
    hyg, tmp_path, monkeypatch
):
    """A dead credential: exit 1, still valid JSON, and `auth_failed` — not
    internal_error. The operator's fix is the token, and metadata.error has to
    say so instead of echoing the tail of stderr."""
    evidence_dir = tmp_path / "evidence"
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.setenv("GITHUB_ORG", "acme")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_totally_bogus_token")
    monkeypatch.setattr(
        gh.requests,
        "get",
        RoutedGet({}, default=FakeResponse(401, {"message": "Bad credentials"})),
    )

    assert hyg.main() == 1

    evidence = json.loads(
        (evidence_dir / "github_repository_hygiene_acme.json").read_text()
    )
    assert evidence["metadata"]["partial_failure"] is True
    assert evidence["metadata"]["organization"] == "acme"
    assert evidence["results"]["repositories"] == []
    assert evidence["metadata"]["api_failures"][0]["code"] == "auth_failed"
    # The token must not survive into the evidence file.
    assert "ghp_totally_bogus_token" not in json.dumps(evidence)

    status = json.loads(status_file.read_text())
    assert status["code"] == "auth_failed"
    assert status["error"]
    assert "\n" not in status["error"]
    assert "ghp_totally_bogus_token" not in status_file.read_text()


def test_missing_organization_exits_nonzero_with_bad_config(hyg, tmp_path, monkeypatch):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_whatever_value_here")

    assert hyg.main() == 1

    status = json.loads((tmp_path / "status.json").read_text())
    assert status["code"] == "bad_config"
    assert "GITHUB_ORG" in status["error"]


def test_max_repositories_marks_the_evidence_as_a_subset(hyg, tmp_path, monkeypatch):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("GITHUB_ORG", "acme")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_valid_looking_token")
    monkeypatch.setenv("GITHUB_MAX_REPOSITORIES", "1")
    monkeypatch.setattr(
        gh.requests,
        "get",
        RoutedGet(
            {"/orgs/acme/repos": FakeResponse(json_data=[REPO_PUBLIC_STALE, REPO_TIDY])}
        ),
    )

    assert hyg.main() == 0

    evidence = json.loads(
        (tmp_path / "evidence" / "github_repository_hygiene_acme.json").read_text()
    )
    assert evidence["summary"]["repositories_truncated"] is True
    assert evidence["summary"]["total_repositories"] == 1
    assert [r["full_name"] for r in evidence["results"]["repositories"]] == ["acme/app"]


def test_configured_threshold_reaches_the_evidence(hyg, tmp_path, monkeypatch):
    """The threshold is a judgment call, so evidence must state which one ran."""
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("GITHUB_ORG", "acme")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_valid_looking_token")
    monkeypatch.setenv("GITHUB_INACTIVE_DAYS_THRESHOLD", "1000")
    monkeypatch.setattr(
        gh.requests,
        "get",
        RoutedGet({"/orgs/acme/repos": FakeResponse(json_data=[REPO_PUBLIC_STALE])}),
    )

    assert hyg.main() == 0

    evidence = json.loads(
        (tmp_path / "evidence" / "github_repository_hygiene_acme.json").read_text()
    )
    assert evidence["summary"]["inactivity_threshold_days"] == 1000
    # 400 days stale, but under a 1000-day policy that is not a finding.
    assert evidence["summary"]["inactive_repositories_not_archived"] == 0
    assert evidence["results"]["repositories"][0]["inactivity_threshold_days"] == 1000
