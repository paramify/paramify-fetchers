"""keycloak_users_and_roles, against Admin REST API responses in tests/fixtures/keycloak_users_and_roles.

The fixture is built from Keycloak's documented representations (UserRepresentation, CredentialRepresentation,
RoleRepresentation, FederatedIdentityRepresentation, EventRepresentation) with placeholder IDs. The realm holds:
alice, an admin through realm-admin with OTP; bob, with a password only and no sign-in for 120 days; carol, brokered
from an external identity provider and holding a designated privileged realm role; dave, disabled; erin, created
10 days ago with WebAuthn and no sign-in yet; frank, with manage-users and a password only; grace, from LDAP with OTP;
and one service-account user. No network.
"""

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = json.loads((REPO_ROOT / "tests" / "fixtures" / "keycloak_users_and_roles" / "realm.json").read_text())
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "keycloak" / "_shared"))
spec = importlib.util.spec_from_file_location("keycloak_users_and_roles_under_test",
                                              REPO_ROOT / "fetchers" / "keycloak" / "users_and_roles" / "fetcher.py")
ur = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ur)
client_mod = sys.modules["keycloak_client"]

BASE = "https://keycloak.admin.example.com"
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.text = status, body, json.dumps(body)

    def json(self):
        return self._body


class _Keycloak:
    """A client-credentials token, then GETs answered from the fixture; `refused` paths (or path endings) answer 403."""

    def __init__(self, refused=(), overrides=None):
        self.refused = tuple(refused)
        self.data = {**FIXTURE, **(overrides or {})}
        self.gets = []

    def post(self, url, data=None, timeout=None):
        return _Resp(200, {"access_token": "tok", "expires_in": 300})

    def get(self, url, params=None, timeout=None, allow_redirects=True, headers=None):
        tail = urlparse(url).path[len("/admin/realms/example-realm"):]
        params = dict(params or {})
        self.gets.append((tail, params))
        if any(tail == r or tail.endswith(r) for r in self.refused):
            return _Resp(403, {"error": "unknown_error"})
        body = self.data[tail]
        if tail == "/events":
            body = [e for e in body if e["type"] == params.get("type", e["type"])]
        if isinstance(body, list) and "first" in params:
            first, size = int(params["first"]), int(params["max"])
            body = body[first:first + size]
        return _Resp(200, body)


@pytest.fixture
def keycloak(monkeypatch, tmp_path):
    def serve(**kwargs):
        session = _Keycloak(**kwargs)
        monkeypatch.setattr(client_mod.requests, "Session", lambda: session)
        return session

    monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(ur, "datetime", type("FrozenDatetime", (datetime,), {"now": classmethod(lambda cls, tz=None: NOW)}))
    for name, value in (("EVIDENCE_DIR", str(tmp_path)), ("FETCHER_STATUS_FILE", str(tmp_path / "status.json")),
                        ("KEYCLOAK_BASE_URL", BASE), ("KEYCLOAK_REALM", "example-realm"),
                        ("KEYCLOAK_CLIENT_ID", "paramify-reader"), ("KEYCLOAK_CLIENT_SECRET", "client-secret-value"),
                        (ur.PRIVILEGED_ENV, "platform-admin")):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(ur.INACTIVE_ENV, raising=False)
    return serve


def _evidence(tmp_path):
    return json.loads((tmp_path / "keycloak_users_and_roles.json").read_text())


def test_realm_users_give_privilege_second_factor_and_inactivity_counts(keycloak, tmp_path, assert_summary_documented):
    keycloak()
    assert ur.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert (s["users_total"], s["users_enabled"], s["users_disabled"], s["service_accounts_skipped"]) == (7, 6, 1, 1)
    assert (s["users_ldap_federated"], s["users_brokered"]) == (1, 1)
    assert (s["users_with_second_factor"], s["users_with_phishing_resistant_authenticator"]) == (3, 1)
    # bob and frank: local, enabled, password only. carol is brokered and counted apart.
    assert s["enabled_local_users_without_second_factor"] == 2
    assert s["users_with_required_actions"] == 1
    # alice (realm-admin), frank (manage-users) and carol (the designated platform-admin); disabled dave doesn't count.
    assert (s["privileged_users"], s["privileged_local_users_without_second_factor"], s["privileged_brokered_users"]) == (3, 1, 1)
    assert s["privileged_realm_roles_checked"] == ["platform-admin"]
    # bob's newest sign-in is 120 days old; erin is newer than the window; grace signed in 60 days ago.
    assert (s["sign_in_history_covers_window"], s["enabled_users_inactive"]) == (True, 1)
    assert_summary_documented("keycloak/users_and_roles", s)


def test_records_name_roles_and_recency_per_user(keycloak, tmp_path):
    keycloak()
    ur.main()
    users = {u["username"]: u for u in _evidence(tmp_path)["results"]["users"]}
    assert "service-account-ci-deployer" not in users
    assert users["alice"]["privileged_roles"] == ["manage-realm", "manage-users", "realm-admin"]
    assert users["carol"]["privileged_roles"] == ["platform-admin"] and users["carol"]["identity_providers"] == ["entra"]
    assert users["bob"]["inactive"] is True and users["bob"]["last_sign_in"] is None
    assert users["erin"]["inactive"] is False and users["erin"]["phishing_resistant"] is True
    assert users["dave"]["inactive"] is None  # disabled accounts aren't judged


def test_no_personal_details_or_credential_data_reach_the_evidence(keycloak, tmp_path):
    keycloak()
    ur.main()
    text = (tmp_path / "keycloak_users_and_roles.json").read_text()
    for value in ("@example.com", "Example", "engineering", "argon2", "hashIterations", "203.0.113.7", "entra-object-id"):
        assert value in json.dumps(FIXTURE) and value not in text, value


def test_a_refused_per_user_call_is_made_once_and_nulls_what_depends_on_it(keycloak, tmp_path):
    session = keycloak(refused=("/credentials",))
    assert ur.main() == 1
    ev = _evidence(tmp_path)
    s = ev["summary"]
    assert sum(1 for t, _ in session.gets if t.endswith("/credentials")) == 1
    assert len(ev["metadata"]["api_failures"]) == 1 and "view-users" in ev["metadata"]["api_failures"][0]["message"]
    assert s["users_with_second_factor"] is None and s["enabled_local_users_without_second_factor"] is None
    assert s["privileged_local_users_without_second_factor"] is None
    # Counts that don't need authenticators still stand.
    assert (s["privileged_users"], s["enabled_users_inactive"]) == (3, 1)


def test_unread_users_leave_every_count_null(keycloak, tmp_path, assert_summary_documented):
    keycloak(refused=("/users",))
    assert ur.main() == 1
    s = _evidence(tmp_path)["summary"]
    assert s["users_read"] is False
    assert all(v is None for k, v in s.items() if k not in ("users_read", "inactive_days", "privileged_realm_roles_checked"))
    assert_summary_documented("keycloak/users_and_roles", s)


@pytest.mark.parametrize("config, covers", [
    ({"eventsEnabled": False, "enabledEventTypes": ["LOGIN"]}, False),
    ({"eventsEnabled": True, "enabledEventTypes": ["LOGIN_ERROR"]}, False),
    ({"eventsEnabled": True, "enabledEventTypes": ["LOGIN"], "eventsExpiration": 30 * 86400}, False),
    ({"eventsEnabled": True, "enabledEventTypes": ["LOGIN"]}, True),
])
def test_inactivity_is_judged_only_when_sign_ins_are_kept_for_the_window(keycloak, tmp_path, config, covers):
    session = keycloak(overrides={"/events/config": config})
    ur.main()
    s = _evidence(tmp_path)["summary"]
    assert s["sign_in_history_covers_window"] is covers
    assert (s["enabled_users_inactive"] is None) is (not covers)
    assert any(t == "/events" for t, _ in session.gets) is covers


def test_unread_event_settings_leave_inactivity_null(keycloak, tmp_path):
    keycloak(refused=("/events/config",))
    assert ur.main() == 1
    s = _evidence(tmp_path)["summary"]
    assert (s["sign_in_history_covers_window"], s["enabled_users_inactive"]) == (None, None)
    assert s["privileged_users"] == 3


def test_without_the_designated_role_only_admin_roles_are_privileged(keycloak, tmp_path, monkeypatch):
    keycloak()
    monkeypatch.delenv(ur.PRIVILEGED_ENV)
    ur.main()
    s = _evidence(tmp_path)["summary"]
    assert (s["privileged_users"], s["privileged_brokered_users"], s["privileged_realm_roles_checked"]) == (2, 0, [])


@pytest.mark.parametrize("raw", ["0", "366", "ninety", "-5"])
def test_a_bad_inactive_days_fails_as_bad_config(keycloak, tmp_path, monkeypatch, raw):
    keycloak()
    monkeypatch.setenv(ur.INACTIVE_ENV, raw)
    assert ur.main() == 1
    ev = _evidence(tmp_path)
    assert ev["summary"]["inactive_days"] == ur.DEFAULT_INACTIVE_DAYS
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"


def test_users_are_read_page_by_page(keycloak, tmp_path, monkeypatch):
    original = client_mod.KeycloakClient.get_all
    monkeypatch.setattr(client_mod.KeycloakClient, "get_all", lambda self, op, path, role=None, page=100: original(self, op, path, role, 3))
    session = keycloak()
    assert ur.main() == 0
    assert [int(p["first"]) for t, p in session.gets if t == "/users"] == [0, 3, 6]
    assert _evidence(tmp_path)["summary"]["users_total"] == 7
