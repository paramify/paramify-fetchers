"""Fixture-based tests for the GitHub evidence fetchers.

Two layers, no live API calls and no credentials:

1. The PURE transforms in each fetcher (`branch_record`, `organization_record`,
   `actions_policy_record`, `summarize`, …) against fixture responses shaped like
   the GitHub REST API's documented payloads.
2. The shared transport in `_shared/github_common.py` with `requests.get`
   monkeypatched — Link-header pagination, the 403-rate-limit vs
   403-permission-denied split, and the $FETCHER_STATUS_FILE channel.

The two things most worth pinning down here:
  - **403 is overloaded.** GitHub returns it both for "you are rate limited" and
    for "your token may not read this". Mislabelling one as the other sends an
    operator hunting a permission bug during a rate-limit window.
  - **No secret value ever reaches evidence.** `secret_records` projects through
    an explicit allowlist; the test feeds it a payload carrying a `value` key and
    asserts it is dropped.

Run: pytest tests/test_github_fetchers.py  (needs `pip install -e .`)
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
GITHUB_ROOT = REPO_ROOT / "fetchers" / "github"

# The fetchers add _shared to sys.path themselves at import time; the test needs
# it up front to import the shared module directly.
sys.path.insert(0, str(GITHUB_ROOT / "_shared"))

import github_common as gh  # noqa: E402


def _load(short_name: str):
    """Load a fetcher module by path (fetchers aren't an importable package)."""
    path = GITHUB_ROOT / short_name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"github_{short_name}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


class FakeGet:
    """Stand-in for requests.get that replays a queued list of responses."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers=None, params=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "params": params})
        if not self.responses:
            raise AssertionError(f"unexpected extra request to {url}")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


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
        "GITHUB_INCLUDE_REPOSITORY_SETTINGS",
        "FETCHER_STATUS_FILE",
        "EVIDENCE_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    gh._REDACTIONS.clear()
    yield
    gh._REDACTIONS.clear()


# --------------------------------------------------------------------------- #
# Shared transport: Link-header pagination
# --------------------------------------------------------------------------- #

def test_parse_next_link_picks_rel_next():
    header = (
        '<https://api.github.com/orgs/acme/repos?page=2>; rel="next", '
        '<https://api.github.com/orgs/acme/repos?page=5>; rel="last"'
    )
    assert gh.parse_next_link(header) == "https://api.github.com/orgs/acme/repos?page=2"


def test_parse_next_link_absent_or_last_page():
    assert gh.parse_next_link(None) is None
    assert gh.parse_next_link("") is None
    assert (
        gh.parse_next_link('<https://api.github.com/orgs/acme/repos?page=1>; rel="prev"') is None
    )


def test_github_get_follows_next_link_and_concatenates(monkeypatch):
    page1 = FakeResponse(
        json_data=[{"full_name": "acme/one"}],
        headers={"Link": '<https://api.github.com/orgs/acme/repos?page=2>; rel="next"'},
    )
    page2 = FakeResponse(json_data=[{"full_name": "acme/two"}])
    fake = FakeGet(page1, page2)
    monkeypatch.setattr(gh.requests, "get", fake)

    items = gh.github_get("/orgs/acme/repos", token="t")

    assert [i["full_name"] for i in items] == ["acme/one", "acme/two"]
    assert fake.calls[0]["url"] == "https://api.github.com/orgs/acme/repos"
    # The `next` link already carries page/per_page; re-sending params would fight it.
    assert fake.calls[1]["url"] == "https://api.github.com/orgs/acme/repos?page=2"
    assert fake.calls[1]["params"] is None


def test_github_get_sends_pinned_version_and_bearer_auth(monkeypatch):
    fake = FakeGet(FakeResponse(json_data={"login": "acme"}))
    monkeypatch.setattr(gh.requests, "get", fake)

    gh.github_get("/orgs/acme", token="ghp_secret_token_value")

    headers = fake.calls[0]["headers"]
    assert headers["Authorization"] == "Bearer ghp_secret_token_value"
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["X-GitHub-Api-Version"] == gh.API_VERSION


def test_github_get_items_key_paginates_counted_collection(monkeypatch):
    page1 = FakeResponse(
        json_data={"total_count": 3, "secrets": [{"name": "A"}, {"name": "B"}]},
        headers={"Link": '<https://api.github.com/orgs/acme/actions/secrets?page=2>; rel="next"'},
    )
    page2 = FakeResponse(json_data={"total_count": 3, "secrets": [{"name": "C"}]})
    monkeypatch.setattr(gh.requests, "get", FakeGet(page1, page2))

    items = gh.github_get("/orgs/acme/actions/secrets", token="t", items_key="secrets")
    assert [i["name"] for i in items] == ["A", "B", "C"]


def test_github_get_single_object_is_not_paginated(monkeypatch):
    fake = FakeGet(FakeResponse(json_data={"login": "acme", "two_factor_requirement_enabled": True}))
    monkeypatch.setattr(gh.requests, "get", fake)

    data = gh.github_get("/orgs/acme", token="t")
    assert data["login"] == "acme"
    assert len(fake.calls) == 1


def test_github_api_url_override_targets_ghes(monkeypatch):
    monkeypatch.setenv("GITHUB_API_URL", "https://ghe.example.com/api/v3/")
    fake = FakeGet(FakeResponse(json_data={"login": "acme"}))
    monkeypatch.setattr(gh.requests, "get", fake)

    gh.github_get("/orgs/acme", token="t")
    assert fake.calls[0]["url"] == "https://ghe.example.com/api/v3/orgs/acme"


# --------------------------------------------------------------------------- #
# Shared transport: error classification (the 403 split)
# --------------------------------------------------------------------------- #

def test_401_is_auth_failed(monkeypatch):
    monkeypatch.setattr(
        gh.requests, "get", FakeGet(FakeResponse(401, {"message": "Bad credentials"}))
    )
    with pytest.raises(gh.GitHubAPIError) as excinfo:
        gh.github_get("/orgs/acme", token="bogus")
    assert excinfo.value.code == "auth_failed"
    assert excinfo.value.status == 401


def test_403_with_exhausted_rate_limit_is_rate_limited(monkeypatch):
    reset_at = int(time.time()) + 812
    monkeypatch.setattr(
        gh.requests,
        "get",
        FakeGet(
            FakeResponse(
                403,
                {"message": "API rate limit exceeded for user"},
                headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset_at)},
            )
        ),
    )
    with pytest.raises(gh.GitHubAPIError) as excinfo:
        gh.github_get("/orgs/acme/repos", token="t")

    assert excinfo.value.code == "rate_limited"
    # Within a second of 812 — the point is that the reset is surfaced at all.
    assert 800 <= excinfo.value.resets_in <= 812
    assert "rate limit exceeded" in str(excinfo.value)
    assert "resets in" in str(excinfo.value)


def test_secondary_rate_limit_via_retry_after_is_rate_limited(monkeypatch):
    monkeypatch.setattr(
        gh.requests,
        "get",
        FakeGet(
            FakeResponse(
                403,
                {"message": "You have exceeded a secondary rate limit"},
                headers={"Retry-After": "60", "X-RateLimit-Remaining": "4321"},
            )
        ),
    )
    with pytest.raises(gh.GitHubAPIError) as excinfo:
        gh.github_get("/orgs/acme/repos", token="t")
    assert excinfo.value.code == "rate_limited"
    assert excinfo.value.resets_in == 60


def test_403_without_rate_limit_headers_is_not_authorized(monkeypatch):
    """The distinction that matters: a genuine permission denial.

    Same status code as a rate limit, no rate-limit signals, so it must map to
    not_authorized — the operator's fix is a token scope, not waiting.
    """
    monkeypatch.setattr(
        gh.requests,
        "get",
        FakeGet(
            FakeResponse(
                403,
                {"message": "Resource not accessible by personal access token"},
                headers={"X-RateLimit-Remaining": "4998"},
            )
        ),
    )
    with pytest.raises(gh.GitHubAPIError) as excinfo:
        gh.github_get("/orgs/acme/actions/secrets", token="t")
    assert excinfo.value.code == "not_authorized"
    assert excinfo.value.status == 403


def test_404_is_target_unreachable(monkeypatch):
    monkeypatch.setattr(gh.requests, "get", FakeGet(FakeResponse(404, {"message": "Not Found"})))
    with pytest.raises(gh.GitHubAPIError) as excinfo:
        gh.github_get("/orgs/nope", token="t")
    assert excinfo.value.code == "target_unreachable"
    assert excinfo.value.status == 404


def test_500_and_transport_failure_are_target_unreachable(monkeypatch):
    monkeypatch.setattr(gh.requests, "get", FakeGet(FakeResponse(502, {"message": "Bad gateway"})))
    with pytest.raises(gh.GitHubAPIError) as excinfo:
        gh.github_get("/orgs/acme", token="t")
    assert excinfo.value.code == "target_unreachable"

    monkeypatch.setattr(
        gh.requests, "get", FakeGet(requests.ConnectionError("name resolution failed"))
    )
    with pytest.raises(gh.GitHubAPIError) as excinfo:
        gh.github_get("/orgs/acme", token="t")
    assert excinfo.value.code == "target_unreachable"
    assert excinfo.value.status is None


def test_no_retry_on_rate_limit(monkeypatch):
    """The contract forbids retry logic: exactly one request, then raise."""
    fake = FakeGet(
        FakeResponse(403, {"message": "API rate limit exceeded"}, headers={"X-RateLimit-Remaining": "0"})
    )
    monkeypatch.setattr(gh.requests, "get", fake)
    with pytest.raises(gh.GitHubAPIError):
        gh.github_get("/orgs/acme/repos", token="t")
    assert len(fake.calls) == 1


# --------------------------------------------------------------------------- #
# Failure accumulation and the status-file channel
# --------------------------------------------------------------------------- #

def _collector():
    import logging

    return gh.Collector(logging.getLogger("test"))


def test_collector_guard_records_without_raising():
    collector = _collector()
    result = collector.guard("op", lambda: (_ for _ in ()).throw(RuntimeError("boom")), default=[])
    assert result == []
    assert collector.ok is False
    assert collector.failures[0]["operation"] == "op"


def test_collector_status_code_auth_failed_when_nothing_worked():
    collector = _collector()
    collector.record("GET /orgs/acme", gh.GitHubAPIError("bad creds", status=401, code="auth_failed"))
    assert collector.status_code == "auth_failed"


def test_collector_status_code_partial_failure_when_some_calls_worked():
    collector = _collector()
    collector.guard("GET /orgs/acme", lambda: {"login": "acme"})
    collector.record(
        "GET /repos/acme/one", gh.GitHubAPIError("nope", status=403, code="not_authorized")
    )
    assert collector.successes == 1
    assert collector.status_code == "partial_failure"


def test_collector_status_code_rate_limited_outranks_partial_failure():
    collector = _collector()
    collector.guard("GET /orgs/acme", lambda: {"login": "acme"})
    collector.record("GET /orgs/acme/repos", gh.GitHubAPIError("limit", status=403, code="rate_limited"))
    assert collector.status_code == "rate_limited"


def test_collector_status_code_bad_config_wins():
    collector = _collector()
    collector.guard("GET /orgs/acme", lambda: {"login": "acme"})
    collector.record("resolve_organization", gh.ConfigError("GITHUB_ORG is not set"))
    assert collector.status_code == "bad_config"


def test_write_status_is_a_no_op_when_env_var_unset():
    """Backward compatible: a runner that predates the clause sets nothing."""
    assert gh.write_status("something failed", "auth_failed") is None


def test_write_status_writes_error_and_code(tmp_path, monkeypatch):
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))

    gh.write_status("GitHub API rate limit exceeded, resets in 812s", "rate_limited")

    payload = json.loads(status_file.read_text())
    assert payload == {
        "error": "GitHub API rate limit exceeded, resets in 812s",
        "code": "rate_limited",
    }


def test_write_status_collapses_multiline_reason(tmp_path, monkeypatch):
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))

    gh.write_status("first line\n  second line\n\nthird", "internal_error")

    assert json.loads(status_file.read_text())["error"] == "first line second line third"


def test_write_status_rejects_invented_codes(tmp_path, monkeypatch):
    """The contract's code list is closed; an unknown code must not pass through."""
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))

    gh.write_status("something odd", "github_exploded")

    assert json.loads(status_file.read_text())["code"] == "internal_error"


def test_write_status_redacts_the_token(tmp_path, monkeypatch):
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    gh.register_redaction("ghp_supersecrettokenvalue")

    gh.write_status("auth failed for ghp_supersecrettokenvalue", "auth_failed")

    assert "ghp_supersecrettokenvalue" not in status_file.read_text()
    assert "***" in json.loads(status_file.read_text())["error"]


def test_collector_redacts_the_token_in_recorded_messages():
    gh.register_redaction("ghp_supersecrettokenvalue")
    collector = _collector()
    collector.record("op", RuntimeError("bad token ghp_supersecrettokenvalue"))
    assert "ghp_supersecrettokenvalue" not in collector.failures[0]["message"]


def test_resolve_organization_missing_is_bad_config():
    collector = _collector()
    result = gh.resolve_organization(collector)
    assert result == {"organization": None, "organization_source": "unresolved"}
    assert collector.status_code == "bad_config"


def test_resolve_organization_from_target(monkeypatch):
    monkeypatch.setenv("GITHUB_ORG", "acme-inc")
    collector = _collector()
    assert gh.resolve_organization(collector) == {
        "organization": "acme-inc",
        "organization_source": "target",
    }
    assert collector.ok


# --------------------------------------------------------------------------- #
# repository_branch_protection — Prowler's Repo/Branch projection
# --------------------------------------------------------------------------- #

PROTECTED = {  # GET /repos/{o}/{r}/branches/{b}/protection — fully locked down
    "required_status_checks": {"strict": True, "contexts": ["ci/build", "ci/test"]},
    "enforce_admins": {"enabled": True},
    "required_pull_request_reviews": {
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": True,
        "required_approving_review_count": 2,
        "require_last_push_approval": True,
    },
    "required_signatures": {"enabled": True},
    "required_linear_history": {"enabled": True},
    "allow_force_pushes": {"enabled": False},
    "allow_deletions": {"enabled": False},
    "required_conversation_resolution": {"enabled": True},
    "lock_branch": {"enabled": False},
    "restrictions": {"users": [], "teams": ["platform"]},
}

WEAK_PROTECTION = {  # protection exists but requires nothing meaningful
    "enforce_admins": {"enabled": False},
    "required_pull_request_reviews": {
        "dismiss_stale_reviews": False,
        "require_code_owner_reviews": False,
        "required_approving_review_count": 0,
    },
    "required_signatures": {"enabled": False},
    "required_linear_history": {"enabled": False},
    "allow_force_pushes": {"enabled": True},
    "allow_deletions": {"enabled": False},
    "required_conversation_resolution": {"enabled": False},
}

REPO_SECURE = {
    "id": 1,
    "name": "app",
    "full_name": "acme/app",
    "owner": {"login": "acme"},
    "private": True,
    "archived": False,
    "default_branch": "main",
    "pushed_at": "2026-08-01T10:00:00Z",
    "delete_branch_on_merge": True,
    "security_and_analysis": {
        "advanced_security": {"status": "enabled"},
        "secret_scanning": {"status": "enabled"},
        "secret_scanning_push_protection": {"status": "enabled"},
        "dependabot_security_updates": {"status": "enabled"},
    },
}

REPO_ARCHIVED = {
    "id": 2,
    "name": "legacy",
    "full_name": "acme/legacy",
    "owner": {"login": "acme"},
    "private": False,
    "archived": True,
    "default_branch": "master",
}

REPO_NO_ADMIN_VIEW = {  # no security_and_analysis block: token lacks Administration:Read
    "id": 3,
    "name": "scratch",
    "full_name": "acme/scratch",
    "owner": {"login": "acme"},
    "private": False,
    "archived": False,
    "default_branch": "main",
}


def test_branch_record_protected_projects_every_control():
    bp = _load("repository_branch_protection")
    rec = bp.branch_record("main", PROTECTED)

    assert rec["protection_state"] == "protected"
    assert rec["protected"] is True
    assert rec["require_pull_request"] is True
    assert rec["approval_count"] == 2
    assert rec["require_code_owner_reviews"] is True
    assert rec["required_status_checks"] is True
    assert rec["required_status_check_contexts"] == ["ci/build", "ci/test"]
    assert rec["required_status_checks_strict"] is True
    assert rec["enforce_admins"] is True
    assert rec["require_signed_commits"] is True
    assert rec["required_linear_history"] is True
    assert rec["allow_force_pushes"] is False
    assert rec["allow_deletions"] is False
    assert rec["required_conversation_resolution"] is True
    assert rec["restricts_push_access"] is True


def test_branch_record_reads_newer_status_check_shape():
    bp = _load("repository_branch_protection")
    protection = {
        "required_status_checks": {
            "strict": False,
            "contexts": [],
            "checks": [{"context": "ci/test", "app_id": 1}, {"context": "ci/lint", "app_id": 1}],
        }
    }
    rec = bp.branch_record("main", protection)
    assert rec["required_status_checks"] is True
    assert rec["required_status_check_contexts"] == ["ci/lint", "ci/test"]


def test_branch_record_unprotected_allows_force_push_and_deletion():
    """404 from the protection endpoint is a STATE, not a failure.

    An unprotected branch really does permit force pushes and deletion, so those
    default True while every positive control defaults False — Prowler's
    convention, so the two tools agree on what "unprotected" means.
    """
    bp = _load("repository_branch_protection")
    rec = bp.branch_record("main", None)

    assert rec["protection_state"] == "unprotected"
    assert rec["protected"] is False
    assert rec["require_pull_request"] is False
    assert rec["approval_count"] == 0
    assert rec["allow_force_pushes"] is True
    assert rec["allow_deletions"] is True


def test_unknown_branch_record_is_all_null_not_unprotected():
    """A failed call must not manufacture a finding, nor hide one."""
    bp = _load("repository_branch_protection")
    rec = bp.unknown_branch_record("main")

    assert rec["protection_state"] == "unknown"
    assert rec["protected"] is None
    assert rec["allow_force_pushes"] is None
    assert rec["approval_count"] is None
    assert rec["name"] == "main"


def test_security_and_analysis_absent_reads_as_not_visible():
    bp = _load("repository_branch_protection")
    visible = bp.security_and_analysis_record(REPO_SECURE)
    assert visible["security_and_analysis_visible"] is True
    assert visible["secret_scanning_enabled"] is True
    assert visible["secret_scanning_push_protection_enabled"] is True

    invisible = bp.security_and_analysis_record(REPO_NO_ADMIN_VIEW)
    assert invisible["security_and_analysis_visible"] is False
    # Absent must never read as "disabled" — that would be a fabricated finding.
    assert invisible["secret_scanning_enabled"] is None


def test_security_and_analysis_disabled_status():
    bp = _load("repository_branch_protection")
    repo = {"security_and_analysis": {"secret_scanning": {"status": "disabled"}}}
    rec = bp.security_and_analysis_record(repo)
    assert rec["secret_scanning_enabled"] is False
    assert rec["advanced_security_enabled"] is None  # key absent from the block


def test_summary_coverage_excludes_archived_repositories():
    """Archived repos are read-only: counting them would understate coverage."""
    bp = _load("repository_branch_protection")
    records = [
        bp.repo_record(REPO_SECURE, bp.branch_record("main", PROTECTED), dependabot_alerts_enabled=True),
        bp.repo_record(REPO_NO_ADMIN_VIEW, bp.branch_record("main", None), dependabot_alerts_enabled=False),
        bp.repo_record(REPO_ARCHIVED, bp.unknown_branch_record("master", state="skipped_archived")),
    ]
    summary = bp.summarize(records)

    assert summary["total_repositories"] == 3
    assert summary["archived_repositories"] == 1
    assert summary["active_repositories"] == 2
    # 1 protected of 2 non-archived == 50%, not 33%.
    assert summary["protected_default_branches"] == 1
    assert summary["protected_default_branch_percentage"] == 50
    assert summary["unprotected_default_branches"] == 1
    assert summary["repositories_requiring_two_or_more_approvals"] == 1
    assert summary["repositories_allowing_force_push"] == 1
    assert summary["repositories_with_secret_scanning"] == 1
    assert summary["repositories_with_dependabot_alerts"] == 1
    assert summary["repositories_without_visible_security_settings"] == 1
    assert summary["private_repositories"] == 1


def test_summary_weak_protection_counts_as_protected_but_not_reviewed():
    bp = _load("repository_branch_protection")
    records = [bp.repo_record(REPO_SECURE, bp.branch_record("main", WEAK_PROTECTION))]
    summary = bp.summarize(records)

    assert summary["protected_default_branch_percentage"] == 100
    # Protection exists but requires zero approvals and permits force pushes:
    # exactly the case a "is it protected?" validator would wave through.
    assert summary["repositories_requiring_two_or_more_approvals"] == 0
    assert summary["repositories_enforcing_admins"] == 0
    assert summary["repositories_allowing_force_push"] == 1


def test_summary_of_empty_organization_is_zero_not_a_crash():
    bp = _load("repository_branch_protection")
    summary = bp.summarize([])
    assert summary["total_repositories"] == 0
    assert summary["protected_default_branch_percentage"] == 0


# --------------------------------------------------------------------------- #
# organization_security_settings — Prowler's Org projection
# --------------------------------------------------------------------------- #

ORG_STRICT = {  # GET /orgs/{org} as an org owner
    "login": "acme",
    "id": 99,
    "name": "Acme Inc",
    "two_factor_requirement_enabled": True,
    "default_repository_permission": "read",
    "members_can_create_repositories": False,
    "members_can_create_public_repositories": False,
    "members_can_create_private_repositories": True,
    "members_allowed_repository_creation_type": "none",
    "members_can_delete_repositories": False,
    "members_can_fork_private_repositories": False,
    "web_commit_signoff_required": True,
    "advanced_security_enabled_for_new_repositories": True,
    "secret_scanning_enabled_for_new_repositories": True,
    "secret_scanning_push_protection_enabled_for_new_repositories": True,
    "dependabot_alerts_enabled_for_new_repositories": True,
    "is_verified": True,
    "plan": {"name": "enterprise", "seats": 100, "filled_seats": 42},
}

ORG_LOOSE = {
    "login": "acme",
    "id": 99,
    "two_factor_requirement_enabled": False,
    "default_repository_permission": "WRITE",  # GitHub has returned this cased
    "members_can_create_repositories": True,
    "members_can_create_public_repositories": True,
    "members_allowed_repository_creation_type": "all",
    "members_can_delete_repositories": True,
    "members_can_fork_private_repositories": True,
    "secret_scanning_enabled_for_new_repositories": False,
}

ORG_PUBLIC_VIEW = {"login": "acme", "id": 99, "public_repos": 3}  # token lacks admin:org read


def test_organization_record_normalizes_base_permission_case():
    org = _load("organization_security_settings")
    assert org.organization_record(ORG_LOOSE)["default_repository_permission"] == "write"
    assert org.organization_record(ORG_STRICT)["default_repository_permission"] == "read"


def test_organization_settings_visibility_sentinel():
    org = _load("organization_security_settings")
    assert org.organization_record(ORG_STRICT)["settings_visible"] is True
    # Without Administration:Read GitHub omits the settings rather than erroring.
    invisible = org.organization_record(ORG_PUBLIC_VIEW)
    assert invisible["settings_visible"] is False
    assert invisible["two_factor_requirement_enabled"] is None
    assert invisible["default_repository_permission"] is None


def test_repository_creation_restricted_reads_both_spellings():
    org = _load("organization_security_settings")
    assert org.repository_creation_restricted({"members_allowed_repository_creation_type": "none"}) is True
    assert org.repository_creation_restricted({"members_allowed_repository_creation_type": "all"}) is False
    # Older orgs expose only the boolean.
    assert org.repository_creation_restricted({"members_can_create_repositories": False}) is True
    assert org.repository_creation_restricted({"members_can_create_repositories": True}) is False
    assert org.repository_creation_restricted({}) is None


def test_organization_summary_strict_posture():
    org = _load("organization_security_settings")
    summary = org.summarize(
        org.organization_record(ORG_STRICT),
        member_count=42,
        outside_collaborator_count=3,
        members_without_2fa=0,
        sso={"state": "configured", "authorized_credentials": 40},
    )

    assert summary["two_factor_required_for_all_members"] is True
    assert summary["default_repository_permission_is_strict"] is True
    assert summary["repository_creation_restricted"] is True
    assert summary["repository_deletion_restricted"] is True
    assert summary["private_repository_forking_allowed"] is False
    assert summary["member_count"] == 42
    assert summary["outside_collaborator_count"] == 3
    assert summary["sso_state"] == "configured"
    assert summary["secret_scanning_default_enabled"] is True


def test_organization_summary_loose_posture():
    org = _load("organization_security_settings")
    summary = org.summarize(
        org.organization_record(ORG_LOOSE),
        member_count=200,
        outside_collaborator_count=None,
        members_without_2fa=17,
        sso={"state": "not_configured", "authorized_credentials": None},
    )

    assert summary["two_factor_required_for_all_members"] is False
    assert summary["members_without_two_factor"] == 17
    # "write" as the org-wide default means every member can push to every repo.
    assert summary["default_repository_permission_is_strict"] is False
    assert summary["repository_creation_restricted"] is False
    assert summary["repository_deletion_restricted"] is False
    assert summary["sso_state"] == "not_configured"


def test_organization_summary_unknown_stays_null_not_false():
    org = _load("organization_security_settings")
    summary = org.summarize(
        org.organization_record(ORG_PUBLIC_VIEW),
        member_count=None,
        outside_collaborator_count=None,
        members_without_2fa=None,
        sso={"state": "not_visible", "authorized_credentials": None},
    )

    assert summary["settings_visible"] is False
    assert summary["two_factor_required_for_all_members"] is None
    assert summary["default_repository_permission_is_strict"] is None
    assert summary["repository_deletion_restricted"] is None


# --------------------------------------------------------------------------- #
# actions_workflow_config — Actions REST projection
# --------------------------------------------------------------------------- #

ORG_ACTIONS_PERMISSIONS = {
    "enabled_repositories": "all",
    "allowed_actions": "selected",
    "selected_actions_url": "https://api.github.com/organizations/99/actions/permissions/selected-actions",
}
ORG_SELECTED_ACTIONS = {
    "github_owned_allowed": True,
    "verified_allowed": False,
    "patterns_allowed": ["acme/*@v1", "docker/login-action@*"],
}
ORG_WORKFLOW_PERMISSIONS = {
    "default_workflow_permissions": "read",
    "can_approve_pull_request_reviews": False,
}


def test_actions_policy_record_merges_three_endpoints():
    act = _load("actions_workflow_config")
    rec = act.actions_policy_record(
        ORG_ACTIONS_PERMISSIONS, ORG_SELECTED_ACTIONS, ORG_WORKFLOW_PERMISSIONS
    )

    assert rec["enabled_repositories"] == "all"
    assert rec["allowed_actions"] == "selected"
    assert rec["allowed_actions_restricted"] is True
    assert rec["github_owned_actions_allowed"] is True
    assert rec["verified_actions_allowed"] is False
    assert rec["allowed_action_patterns"] == ["acme/*@v1", "docker/login-action@*"]
    assert rec["default_workflow_permissions"] == "read"
    assert rec["default_workflow_permissions_read_only"] is True
    assert rec["can_approve_pull_request_reviews"] is False


def test_actions_policy_record_unrestricted_and_write_token():
    act = _load("actions_workflow_config")
    rec = act.actions_policy_record(
        {"enabled_repositories": "all", "allowed_actions": "all"},
        None,
        {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": True},
    )
    assert rec["allowed_actions_restricted"] is False
    assert rec["default_workflow_permissions_read_only"] is False
    assert rec["can_approve_pull_request_reviews"] is True


def test_actions_policy_record_all_absent_is_null_not_false():
    act = _load("actions_workflow_config")
    rec = act.actions_policy_record(None, None, None)
    assert rec["allowed_actions"] is None
    assert rec["allowed_actions_restricted"] is None
    assert rec["default_workflow_permissions_read_only"] is None


def test_secret_records_keep_names_and_drop_anything_else():
    """The hard rule: names and counts are evidence, values never are.

    GitHub's API returns no secret value today. This asserts the fetcher's own
    allowlist, so a future API change (or a proxy that adds fields) still cannot
    put one in an evidence file.
    """
    act = _load("actions_workflow_config")
    records = act.secret_records(
        [
            {
                "name": "DEPLOY_KEY",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-06-01T00:00:00Z",
                "visibility": "selected",
                "value": "super-secret-do-not-store",
                "encrypted_value": "AAAA",
            },
            {"name": "AWS_ROLE", "visibility": "all"},
        ]
    )

    assert [r["name"] for r in records] == ["AWS_ROLE", "DEPLOY_KEY"]  # sorted
    assert set(records[0]) == set(act.SECRET_FIELDS)
    blob = json.dumps(records)
    assert "super-secret-do-not-store" not in blob
    assert "value" not in records[1]


def test_runner_and_group_records():
    act = _load("actions_workflow_config")
    runner = act.runner_record(
        {
            "id": 7,
            "name": "build-01",
            "os": "linux",
            "status": "online",
            "busy": False,
            "labels": [{"name": "self-hosted"}, {"name": "linux"}],
        }
    )
    assert runner["status"] == "online"
    assert runner["labels"] == ["linux", "self-hosted"]

    group = act.runner_group_record(
        {
            "id": 1,
            "name": "prod-runners",
            "visibility": "selected",
            "allows_public_repositories": True,
            "restricted_to_workflows": False,
            "runners_count": 2,
        }
    )
    assert group["allows_public_repositories"] is True


def test_actions_summary_rolls_up_repositories():
    act = _load("actions_workflow_config")
    org_record = {
        "login": "acme",
        "policy": act.actions_policy_record(
            ORG_ACTIONS_PERMISSIONS, ORG_SELECTED_ACTIONS, ORG_WORKFLOW_PERMISSIONS
        ),
        "self_hosted_runners": [
            {"id": 1, "name": "a", "status": "online"},
            {"id": 2, "name": "b", "status": "offline"},
        ],
        "runner_groups": [
            {"id": 1, "name": "public-ok", "allows_public_repositories": True},
            {"id": 2, "name": "locked", "allows_public_repositories": False, "restricted_to_workflows": True},
        ],
        "secrets": [{"name": "ORG_TOKEN"}],
    }
    repositories = [
        {
            "full_name": "acme/app",
            "policy": act.actions_policy_record(
                {"enabled": True, "allowed_actions": "all"},
                None,
                {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": True},
            ),
            "self_hosted_runners": [{"id": 9, "name": "repo-runner", "status": "online"}],
            "secrets": [{"name": "REPO_A"}, {"name": "REPO_B"}],
        },
        {
            "full_name": "acme/lib",
            "policy": act.actions_policy_record(
                {"enabled": True, "allowed_actions": "selected"},
                {"github_owned_allowed": True},
                {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
            ),
            "self_hosted_runners": [],
            "secrets": [],
        },
    ]

    summary = act.summarize(
        org_record, repositories, repository_settings_collected=True, truncated=False
    )

    assert summary["allowed_actions"] == "selected"
    assert summary["default_workflow_permissions_read_only"] is True
    assert summary["workflows_can_approve_pull_requests"] is False
    assert summary["self_hosted_runner_count"] == 2
    assert summary["self_hosted_runners_online"] == 1
    assert summary["runner_groups_allowing_public_repositories"] == 1
    assert summary["organization_secret_count"] == 1
    assert summary["repositories_examined"] == 2
    assert summary["repository_secret_count"] == 2
    assert summary["repositories_with_write_default_token"] == 1
    assert summary["repositories_allowing_workflow_pr_approval"] == 1
    assert summary["repositories_with_unrestricted_actions"] == 1
    assert summary["repositories_with_self_hosted_runners"] == 1


def test_actions_summary_org_only_run_reports_null_not_zero():
    """With repository collection switched off, per-repo counts must not read as 0."""
    act = _load("actions_workflow_config")
    summary = act.summarize(
        {"login": "acme", "policy": act.actions_policy_record(None, None, None)},
        [],
        repository_settings_collected=False,
        truncated=False,
    )
    assert summary["repository_settings_collected"] is False
    assert summary["repositories_with_write_default_token"] is None
    assert summary["repository_secret_count"] is None


# --------------------------------------------------------------------------- #
# End-to-end failure behavior (the contract's exit-code + status-file clause)
# --------------------------------------------------------------------------- #

def test_bad_token_exits_nonzero_writes_evidence_and_auth_failed_status(tmp_path, monkeypatch):
    """A dead credential: exit 1, still valid JSON, and a well-formed status file.

    `auth_failed` rather than a generic internal_error is the whole point — the
    operator's fix is the token, and metadata.error has to say so instead of
    echoing the tail of stderr.
    """
    bp = _load("repository_branch_protection")
    evidence_dir = tmp_path / "evidence"
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.setenv("GITHUB_ORG", "acme")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_totally_bogus_token")
    monkeypatch.setattr(
        gh.requests, "get", FakeGet(FakeResponse(401, {"message": "Bad credentials"}))
    )

    assert bp.main() == 1

    evidence = json.loads((evidence_dir / "github_repository_branch_protection_acme.json").read_text())
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


def test_missing_organization_exits_nonzero_with_bad_config(tmp_path, monkeypatch):
    org = _load("organization_security_settings")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_whatever_value_here")

    assert org.main() == 1

    status = json.loads((tmp_path / "status.json").read_text())
    assert status["code"] == "bad_config"
    assert "GITHUB_ORG" in status["error"]


def test_successful_run_exits_zero_and_writes_no_status(tmp_path, monkeypatch):
    """The happy path leaves $FETCHER_STATUS_FILE untouched."""
    act = _load("actions_workflow_config")
    evidence_dir = tmp_path / "evidence"
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(evidence_dir))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.setenv("GITHUB_ORG", "acme")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_valid_looking_token")
    monkeypatch.setenv("GITHUB_INCLUDE_REPOSITORY_SETTINGS", "false")
    monkeypatch.setattr(
        gh.requests,
        "get",
        # Request order: permissions, workflow permissions, runners, runner
        # groups, secrets. (allowed_actions is "all", so selected-actions is not
        # fetched at all.)
        FakeGet(
            FakeResponse(json_data={"enabled_repositories": "all", "allowed_actions": "all"}),
            FakeResponse(json_data=ORG_WORKFLOW_PERMISSIONS),
            FakeResponse(json_data={"total_count": 0, "runners": []}),
            FakeResponse(json_data={"total_count": 1, "runner_groups": [{"id": 1, "name": "g"}]}),
            FakeResponse(json_data={"total_count": 0, "secrets": []}),
        ),
    )

    assert act.main() == 0
    assert not status_file.exists()

    evidence = json.loads((evidence_dir / "github_actions_workflow_config_acme.json").read_text())
    assert evidence["metadata"]["partial_failure"] is False
    assert evidence["summary"]["default_workflow_permissions"] == "read"
    assert evidence["summary"]["repository_settings_collected"] is False
