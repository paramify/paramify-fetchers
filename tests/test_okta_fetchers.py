"""Tests for the decomposed okta category fetchers.

After the okta refactor, each fetcher owns its collect logic in its own
``fetcher.py`` and shares only ``_shared/okta_client.py`` (the HTTP client) and
``_shared/okta_runner.py`` (run scaffolding). These tests exercise that wiring
with NO network and NO token:

  * every fetcher's ``collect(client)`` runs against a stub client and returns a
    well-formed evidence dict (proves the decomposition imports + executes), and
  * no okta source file carries hard-coded org data / PII (the refactor's
    security fix — guards against a regression re-introducing an email allowlist).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
OKTA_ROOT = REPO_ROOT / "fetchers" / "okta"

# The eight okta fetchers (dir name -> output basename it must produce).
OKTA_FETCHERS = [
    "authenticators",
    "automated_account_management",
    "just_in_time_authorization",
    "least_privilege",
    "non_user_accounts_authentication",
    "passwordless_authentication",
    "phishing_resistant_mfa",
    "suspicious_activity_management",
]


class _StubOktaClient:
    """Stand-in for OktaAPIClient: every call returns empty, network-free data.

    Fetchers should run to completion against an org that returns nothing, so a
    stub of empty lists/dicts is enough to prove each collect() is wired up and
    handles the no-data path without raising.
    """

    api_failures: list = []
    feature_availability: dict = {}
    unavailable_features: list = []

    # A few endpoints return a single object (dict); everything else — the
    # list_*/get_system_logs/get_authenticator_methods/_paginated_get calls —
    # returns a collection (list).
    _DICT_METHODS = {"get_user", "get_authenticator", "get_threat_insight_settings", "_request"}

    def _list(self, *args, **kwargs):
        return []

    def _obj(self, *args, **kwargs):
        return {}

    def __getattr__(self, name):
        return self._obj if name in self._DICT_METHODS else self._list


def _load_fetcher_module(dirname: str):
    """Import fetchers/okta/<dirname>/fetcher.py under a unique module name."""
    # _shared must be importable (the fetcher's own sys.path.insert also does this).
    import sys
    sys.path.insert(0, str(OKTA_ROOT / "_shared"))
    path = OKTA_ROOT / dirname / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"okta_{dirname}_fetcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("dirname", OKTA_FETCHERS)
def test_collect_runs_and_returns_evidence(dirname):
    module = _load_fetcher_module(dirname)
    assert hasattr(module, "collect"), f"{dirname}/fetcher.py must expose collect(client)"

    evidence = module.collect(_StubOktaClient())
    assert isinstance(evidence, dict) and evidence, "collect() must return a non-empty dict"

    if dirname == "authenticators":
        # Bespoke evidence shape: results -> four buckets.
        assert set(evidence["results"]) >= {
            "applications", "enrollment_policies", "simulation_results", "fido2_config"
        }
    else:
        # The seven KSI fetchers share the ksi/name/data/summary shape.
        assert {"ksi", "name", "data"} <= set(evidence), f"{dirname} evidence missing core keys"
        assert evidence["ksi"].startswith("KSI-IAM-")


@pytest.mark.parametrize("dirname", OKTA_FETCHERS)
def test_main_and_run_are_wired(dirname):
    module = _load_fetcher_module(dirname)
    assert hasattr(module, "main"), f"{dirname}/fetcher.py must expose main()"


# --- security regression guard: no hard-coded org data / PII in okta sources ---

_FORBIDDEN_SUBSTRINGS = ["@paramify.com", "isaac.teuscher", "known_super_admin", "known_service_account"]


def _okta_python_sources():
    return list(OKTA_ROOT.rglob("*.py"))


class _GroupRoleStub(_StubOktaClient):
    """Stub org: one active user who is Super Admin ONLY via a group role
    assignment (no directly-assigned role, group not named 'admin')."""

    _USER = {"id": "u1", "status": "ACTIVE", "profile": {"login": "a@example.com", "email": "a@example.com", "firstName": "A", "lastName": "B"}}
    _GROUP = {"id": "g1", "type": "OKTA_GROUP", "profile": {"name": "Platform Team"}}

    def list_users(self, *a, **k):
        return [self._USER]

    def list_user_roles(self, *a, **k):
        return []  # no DIRECT role — the whole point

    def list_groups(self, *a, **k):
        return [self._GROUP]

    def list_group_roles(self, group_id, *a, **k):
        return [{"type": "SUPER_ADMIN", "label": "Super Administrator", "status": "ACTIVE"}] if group_id == "g1" else []

    def list_group_members(self, group_id, *a, **k):
        return [self._USER] if group_id == "g1" else []

    def get_user(self, user_id, *a, **k):
        return self._USER


def test_least_privilege_detects_group_assigned_super_admin():
    """Regression guard: a super admin assigned via GROUP role (invisible to
    the per-user /roles endpoint) must still be detected and bucketed."""
    module = _load_fetcher_module("least_privilege")
    evidence = module.collect(_GroupRoleStub())

    admins = evidence["data"]["admin_users"]
    assert any(a["id"] == "u1" for a in admins), "group-assigned super admin was not detected"
    u1 = next(a for a in admins if a["id"] == "u1")
    assert u1["is_super_admin"] is True and u1["admin_type"] == "SUPER_ADMIN"
    assert u1["detection_method"] == "assigned_admin_role"
    assert any(s.startswith("group:") for s in u1["role_sources"])
    assert evidence["summary"]["super_admin_count"] >= 1


def test_no_hardcoded_pii_in_okta_sources():
    offenders = []
    for py in _okta_python_sources():
        text = py.read_text().lower()
        for needle in _FORBIDDEN_SUBSTRINGS:
            if needle.lower() in text:
                offenders.append(f"{py.relative_to(REPO_ROOT)} contains '{needle}'")
    assert not offenders, "Hard-coded org data / PII found:\n" + "\n".join(offenders)
