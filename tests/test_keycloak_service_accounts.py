"""keycloak_service_accounts, against Admin REST API responses in tests/fixtures/keycloak_service_accounts.

The fixture is built from Keycloak's documented representations (ClientRepresentation with its secret attributes,
UserRepresentation, RoleRepresentation) with placeholder IDs. The realm holds Keycloak's built-in clients; this
fetcher's own reader (a 30-day-old secret, owned); ci-deployer (a 400-day-old secret, no owner, manage-clients);
platform-operator (a signed key, realm-admin); legacy-sync (no recorded secret creation time, a rotated secret, password
and browser flows on); a disabled batch client; and a public web client. No network.
"""

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = json.loads((REPO_ROOT / "tests" / "fixtures" / "keycloak_service_accounts" / "realm.json").read_text())
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "keycloak" / "_shared"))
spec = importlib.util.spec_from_file_location("keycloak_service_accounts_under_test",
                                              REPO_ROOT / "fetchers" / "keycloak" / "service_accounts" / "fetcher.py")
sa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sa)
client_mod = sys.modules["keycloak_client"]

BASE = "https://keycloak.admin.example.com"
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.text = status, body, json.dumps(body)

    def json(self):
        return self._body


class _Keycloak:
    def __init__(self, refused=(), clients=None):
        self.refused = tuple(refused)
        self.data = dict(FIXTURE)
        if clients is not None:
            self.data["/clients"] = clients
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
        if isinstance(body, list) and "first" in params:
            body = body[int(params["first"]):int(params["first"]) + int(params["max"])]
        return _Resp(200, body)


@pytest.fixture
def keycloak(monkeypatch, tmp_path):
    def serve(**kwargs):
        session = _Keycloak(**kwargs)
        monkeypatch.setattr(client_mod.requests, "Session", lambda: session)
        return session

    monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(sa, "datetime", type("FrozenDatetime", (datetime,), {"now": classmethod(lambda cls, tz=None: NOW)}))
    for name, value in (("EVIDENCE_DIR", str(tmp_path)), ("FETCHER_STATUS_FILE", str(tmp_path / "status.json")),
                        ("KEYCLOAK_BASE_URL", BASE), ("KEYCLOAK_REALM", "example-realm"),
                        ("KEYCLOAK_CLIENT_ID", "paramify-reader"), ("KEYCLOAK_CLIENT_SECRET", "client-secret-value"),
                        (sa.MAX_AGE_ENV, "365"), (sa.OWNER_ENV, "owner")):
        monkeypatch.setenv(name, value)
    return serve


def _evidence(tmp_path):
    return json.loads((tmp_path / "keycloak_service_accounts.json").read_text())


def _with_creation_time(days):
    clients = json.loads(json.dumps(FIXTURE["/clients"]))
    legacy = next(c for c in clients if c["clientId"] == "legacy-sync")
    legacy["attributes"]["client.secret.creation.time"] = str(int(NOW.timestamp()) - days * 86400)
    return clients


def test_service_accounts_give_authenticator_age_owner_and_role_counts(keycloak, tmp_path, assert_summary_documented):
    keycloak()
    assert sa.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert (s["clients_total"], s["confidential_clients"], s["service_account_clients"], s["service_account_clients_disabled"]) == (9, 5, 4, 1)
    assert s["service_accounts_by_authenticator"] == {"client-jwt": 1, "client-secret": 3}
    assert (s["service_accounts_using_shared_secret"], s["service_accounts_using_key_or_certificate"]) == (3, 1)
    # legacy-sync's secret has no recorded creation time, so the over-age count can't be settled.
    assert (s["service_account_secrets_age_unknown"], s["oldest_service_account_secret_days"]) == (1, 400.0)
    assert (s["service_account_secrets_over_max_age"], s["service_account_secrets_expiring"]) == (None, 1)
    assert (s["owner_attribute"], s["service_accounts_without_owner"]) == ("owner", 1)
    assert (s["service_accounts_with_other_flows"], s["privileged_service_accounts"], s["service_accounts_with_realm_admin"]) == (1, 2, 1)
    assert_summary_documented("keycloak/service_accounts", s)


def test_secret_age_is_judged_once_every_age_is_known(keycloak, tmp_path):
    keycloak(clients=_with_creation_time(10))
    sa.main()
    s = _evidence(tmp_path)["summary"]
    assert (s["service_account_secrets_age_unknown"], s["service_account_secrets_over_max_age"]) == (0, 1)


def test_records_hold_no_secret_or_key(keycloak, tmp_path):
    keycloak()
    sa.main()
    ev = _evidence(tmp_path)
    text = json.dumps(ev)
    for value in ("secret-value-", "rotated-secret-value", "MIIC-certificate-body"):
        assert value in json.dumps(FIXTURE) and value not in text, value
    records = {r["client_id"]: r for r in ev["results"]["service_accounts"]}
    assert set(records) == {"paramify-reader", "ci-deployer", "platform-operator", "legacy-sync", "old-batch"}
    assert records["legacy-sync"]["rotated_secret_present"] is True
    assert records["legacy-sync"]["other_flows"] == ["direct_access_grants", "standard"]
    assert records["platform-operator"]["secret_over_max_age"] is False and records["platform-operator"]["realm_admin"] is True
    assert records["ci-deployer"]["owned"] is False and records["ci-deployer"]["secret_over_max_age"] is True


def test_without_settings_age_and_owner_stay_unjudged(keycloak, tmp_path, monkeypatch):
    keycloak(clients=_with_creation_time(10))
    monkeypatch.delenv(sa.MAX_AGE_ENV)
    monkeypatch.delenv(sa.OWNER_ENV)
    assert sa.main() == 0
    s = _evidence(tmp_path)["summary"]
    assert (s["max_secret_age_days"], s["service_account_secrets_over_max_age"]) == (None, None)
    assert (s["owner_attribute"], s["service_accounts_without_owner"]) == (None, None)
    assert s["oldest_service_account_secret_days"] == 400.0


def test_refused_role_reads_are_made_once_and_null_the_role_counts(keycloak, tmp_path):
    session = keycloak(refused=("/clients/c0/composite",))
    assert sa.main() == 1
    ev = _evidence(tmp_path)
    assert sum(1 for t, _ in session.gets if t.endswith("/clients/c0/composite")) == 1
    assert len(ev["metadata"]["api_failures"]) == 1 and "view-users" in ev["metadata"]["api_failures"][0]["message"]
    s = ev["summary"]
    assert (s["privileged_service_accounts"], s["service_accounts_with_realm_admin"]) == (None, None)
    assert s["service_accounts_without_owner"] == 1


def test_unread_clients_leave_every_count_null(keycloak, tmp_path, assert_summary_documented):
    keycloak(refused=("/clients",))
    assert sa.main() == 1
    s = _evidence(tmp_path)["summary"]
    assert s["clients_read"] is False
    assert all(v is None for k, v in s.items() if k not in ("clients_read", "max_secret_age_days", "owner_attribute"))
    assert_summary_documented("keycloak/service_accounts", s)


@pytest.mark.parametrize("raw", ["0", "3651", "a year"])
def test_a_bad_maximum_age_fails_as_bad_config(keycloak, tmp_path, monkeypatch, raw):
    keycloak()
    monkeypatch.setenv(sa.MAX_AGE_ENV, raw)
    assert sa.main() == 1
    assert _evidence(tmp_path)["summary"]["service_account_secrets_over_max_age"] is None
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"


@pytest.mark.parametrize("authenticator", ["federated-jwt", "custom-spiffe"])
def test_an_unrecognized_authenticator_leaves_secret_age_unknown(keycloak, tmp_path, authenticator, assert_summary_documented):
    # Every known secret's age is set, so only the unfamiliar authenticator can leave the count unjudged.
    clients = _with_creation_time(10)
    jwt = next(c for c in clients if c.get("clientAuthenticatorType") == "client-jwt")
    jwt["clientAuthenticatorType"] = authenticator
    keycloak(clients=clients)
    assert sa.main() == 0
    ev = _evidence(tmp_path)
    s = ev["summary"]
    assert (s["service_accounts_unrecognized_authenticator"], s["service_account_secrets_over_max_age"]) == (1, None)
    assert (s["service_accounts_using_shared_secret"], s["service_accounts_using_key_or_certificate"]) == (3, 0)
    record = next(r for r in ev["results"]["service_accounts"] if r["authenticator"] == authenticator)
    assert (record["shared_secret"], record["authenticator_recognized"], record["secret_over_max_age"]) == (None, False, None)
    assert_summary_documented("keycloak/service_accounts", s)
