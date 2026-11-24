"""keycloak_realm_security: effective flow requirements, password policy parsing, null-not-zero summaries, secrets kept out
of the evidence, and full runs against synthetic Keycloak Admin REST API responses. No network."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "keycloak" / "realm_security" / "fetcher.py"
_spec = importlib.util.spec_from_file_location("keycloak_realm_security_under_test", FETCHER)
kc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kc)
client_mod = sys.modules["keycloak_client"]

BASE = "https://keycloak.admin.example.com"


def ex(provider, requirement, level=0, subflow=False, name=None):
    return {"providerId": provider, "requirement": requirement, "level": level, "authenticationFlow": subflow,
            "displayName": name or provider}


# A browser flow shaped like a typical hardened realm: cookie OR a forms subflow; the forms subflow requires a
# username form, then a conditional MFA subflow, plus an X.509 certificate step.
BROWSER = [
    ex("auth-cookie", "ALTERNATIVE"),
    ex(None, "ALTERNATIVE", subflow=True, name="forms"),
    ex("auth-username-password-form", "REQUIRED", level=1),
    ex(None, "CONDITIONAL", level=1, subflow=True, name="mfa"),
    ex("conditional-user-configured", "REQUIRED", level=2),
    ex("auth-otp-form", "ALTERNATIVE", level=2),
    ex("webauthn-authenticator", "ALTERNATIVE", level=2),
]
STRICT = [ex("auth-x509-client-username-form", "REQUIRED"), ex(None, "REQUIRED", subflow=True, name="second factor"),
          ex("webauthn-authenticator", "REQUIRED", level=1), ex("auth-otp-form", "DISABLED", level=1)]
RESET = [ex("reset-credentials-choose-user", "REQUIRED"), ex("reset-credential-email", "REQUIRED"), ex("reset-otp", "DISABLED")]
REALM = {"realm": "example-realm", "enabled": True, "sslRequired": "all", "registrationAllowed": False, "rememberMe": False,
         "ssoSessionIdleTimeout": 900, "ssoSessionMaxLifespan": 36000, "accessTokenLifespan": 60,
         "bruteForceProtected": True, "failureFactor": 3, "permanentLockout": True, "maxFailureWaitSeconds": 900,
         "passwordPolicy": "length(15) and passwordHistory(24) and notUsername(undefined) and forceExpiredPasswordChange(60)",
         "browserFlow": "Example Authentication", "resetCredentialsFlow": "reset credentials"}
ACTIONS = [{"alias": "TERMS_AND_CONDITIONS", "name": "Terms and Conditions", "enabled": True, "defaultAction": True},
           {"alias": "webauthn-register", "name": "Webauthn Register", "enabled": True, "defaultAction": True},
           {"alias": "CONFIGURE_TOTP", "name": "Configure OTP", "enabled": True, "defaultAction": False}]
IDPS = [{"alias": "azure-ad", "providerId": "oidc", "enabled": True, "config": {"clientSecret": "s3cr3t-value", "clientId": "abc"}},
        {"alias": "old-saml", "providerId": "saml", "enabled": False, "config": {}}]
STORAGE = [{"name": "corp-ldap", "providerId": "ldap", "config": {"editMode": ["READ_ONLY"], "enabled": ["true"], "bindCredential": ["ldap-pw"]}}]
EVENTS = {"eventsEnabled": True, "eventsExpiration": 7776000, "eventsListeners": ["jboss-logging"],
          "adminEventsEnabled": True, "adminEventsDetailsEnabled": True, "enabledEventTypes": ["LOGIN", "LOGIN_ERROR"]}


# --- pure transforms ---

def test_flow_steps_keep_their_requirement_and_nesting():
    flow = {e["provider"] or e["alias"]: e for e in kc.effective_requirements(BROWSER)}
    assert flow["auth-cookie"]["requirement"] == "ALTERNATIVE" and flow["auth-username-password-form"]["level"] == 1
    assert all("always" not in e for e in flow.values())  # no per-step verdict: paths are judged as a whole

def test_password_policy_string_becomes_rules():
    assert kc.password_rules(REALM["passwordPolicy"]) == {"length": 15, "passwordHistory": 24, "notUsername": None,
                                                          "forceExpiredPasswordChange": 60}
    assert kc.password_rules(None) == {} and kc.password_rules("") == {}


def test_summary_reads_sessions_lockout_passwords_and_the_browser_flow():
    s = kc.summarize(REALM, BROWSER, RESET, ACTIONS, IDPS, STORAGE, EVENTS)
    assert (s["sso_session_idle_timeout_minutes"], s["sso_session_max_lifespan_minutes"], s["access_token_lifespan_minutes"]) == (15.0, 600.0, 1.0)
    assert (s["brute_force_protected"], s["lockout_failure_threshold"], s["permanent_lockout"]) == (True, 3, True)
    assert (s["password_min_length"], s["password_history"], s["password_expiry_days"]) == (15, 24, 60)
    assert s["local_sign_in_requires_phishing_resistant"] is False  # WebAuthn is one ALTERNATIVE among OTP
    assert s["browser_flow_alternative_authenticators"] == ["auth-cookie", "auth-otp-form", "webauthn-authenticator"]
    assert s["browser_flow_conditional_authenticators"] == ["conditional-user-configured"]
    assert s["reset_credentials_authenticators"] == ["reset-credential-email", "reset-credentials-choose-user"]
    assert (s["terms_and_conditions_enabled"], s["terms_and_conditions_default_action"]) == (True, True)
    assert (s["identity_providers_enabled"], s["identity_provider_types"], s["user_federation_providers"]) == (1, ["oidc"], 1)
    assert (s["login_events_enabled"], s["login_events_expiration_days"], s["admin_events_details_enabled"]) == (True, 90.0, True)


def test_a_required_certificate_and_security_key_count_as_phishing_resistant():
    s = kc.summarize(REALM, STRICT, RESET, ACTIONS, IDPS, STORAGE, EVENTS)
    assert s["local_sign_in_requires_phishing_resistant"] is True
    assert "auth-otp-form" not in s["browser_flow_alternative_authenticators"]  # DISABLED steps are left out


def test_lockout_details_are_null_while_brute_force_detection_is_off():
    s = kc.summarize({**REALM, "bruteForceProtected": False}, BROWSER, RESET, ACTIONS, IDPS, STORAGE, EVENTS)
    assert (s["brute_force_protected"], s["lockout_failure_threshold"], s["permanent_lockout"], s["lockout_max_wait_minutes"]) == (False, None, None, None)


def test_each_group_is_null_not_empty_when_its_call_failed():
    s = kc.summarize(REALM, None, None, None, None, None, None)
    assert s["sso_session_idle_timeout_minutes"] == 15.0
    for field in ("local_sign_in_requires_phishing_resistant", "reset_credentials_authenticators", "terms_and_conditions_enabled",
                  "identity_providers_enabled", "user_federation_providers", "login_events_enabled", "admin_events_enabled"):
        assert s[field] is None, field
    assert kc.summarize(None, None, None, None, None, None, None)["realm_enabled"] is None


# --- full runs against synthetic Keycloak responses ---

class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.text = status, body, json.dumps(body)

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not JSON")
        return self._body


class _Keycloak:
    """requests.Session for one Keycloak: a client-credentials token, then the realm's admin GETs."""

    def __init__(self, token_status=200, refused=(), browser=None, realm=None, admin_status=None, realm_status=None,
                 idps=None, token_body=None, html=()):
        self.token_status, self.refused, self.browser = token_status, set(refused), browser or STRICT
        self.realm, self.admin_status, self.realm_status = realm, admin_status, realm_status
        self.idps, self.token_body, self.html = IDPS if idps is None else idps, token_body, set(html)
        self.posts, self.gets = [], []

    def post(self, url, data=None, timeout=None):
        self.posts.append((url, dict(data or {})))
        if self.token_body is not None:
            return _Resp(self.token_status, self.token_body)
        return _Resp(self.token_status, {"access_token": "tok", "expires_in": 300} if self.token_status == 200 else {"error": "unauthorized_client"})

    def get(self, url, params=None, timeout=None, allow_redirects=True, headers=None):
        path = unquote(urlparse(url).path)
        self.gets.append((path, dict(params or {})))
        assert path.startswith("/admin/realms/example-realm")
        tail = path[len("/admin/realms/example-realm"):]
        if self.admin_status:
            return _Resp(self.admin_status, {"error": "HTTP 401 Unauthorized"})
        if tail == "" and self.realm_status:
            return _Resp(self.realm_status, {"error": "unavailable"})
        if tail in self.html:
            return _Resp(200, "<html>proxy sign-in page</html>")
        for key in self.refused:
            if tail.startswith(key):
                return _Resp(403, {"error": "unknown_error"})
        if tail == "/identity-provider/instances":
            first, size = int((params or {}).get("first", 0)), int((params or {}).get("max", 100))
            return _Resp(200, self.idps[first:first + size])
        bodies = {"": self.realm or REALM, "/authentication/flows/Example Authentication/executions": self.browser,
                  "/authentication/flows/reset credentials/executions": RESET, "/authentication/required-actions": ACTIONS,
                  "/identity-provider/instances": IDPS, "/components": STORAGE, "/events/config": EVENTS}
        return _Resp(200, bodies[tail]) if tail in bodies else _Resp(404, {"error": "not found"})


@pytest.fixture
def keycloak(monkeypatch, tmp_path):
    def serve(**kwargs):
        session = _Keycloak(**kwargs)
        monkeypatch.setattr(client_mod.requests, "Session", lambda: session)
        return session

    monkeypatch.setattr(client_mod.time, "sleep", lambda s: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv("KEYCLOAK_BASE_URL", BASE + "/")
    monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "paramify-reader")
    monkeypatch.setenv("KEYCLOAK_CLIENT_SECRET", "client-secret-value")
    monkeypatch.setenv("KEYCLOAK_REALM", "example-realm")
    monkeypatch.delenv("KEYCLOAK_AUTH_REALM", raising=False)
    return serve


def _evidence(tmp_path):
    return json.loads((tmp_path / "keycloak_realm_security.json").read_text())


def test_main_reads_the_realm_and_writes_the_summary(keycloak, tmp_path, assert_summary_documented):
    session = keycloak()
    assert kc.main() == 0
    ev = _evidence(tmp_path)
    assert ev["summary"]["local_sign_in_requires_phishing_resistant"] is True
    assert ev["metadata"]["partial_failure"] is False and ev["metadata"]["realm"] == "example-realm"
    assert session.posts[0][0] == f"{BASE}/realms/example-realm/protocol/openid-connect/token"
    assert session.posts[0][1]["grant_type"] == "client_credentials"
    assert ("/admin/realms/example-realm/components", {"type": kc.USER_STORAGE}) in session.gets
    assert_summary_documented("keycloak/realm_security", ev["summary"])


def test_no_client_secret_or_bind_credential_reaches_the_evidence(keycloak, tmp_path):
    keycloak()
    assert kc.main() == 0
    text = (tmp_path / "keycloak_realm_security.json").read_text()
    for secret in ("s3cr3t-value", "ldap-pw", "client-secret-value", "tok"):
        assert f'"{secret}"' not in text, secret


def test_an_unreadable_section_fails_the_run_and_leaves_only_that_section_null(keycloak, tmp_path):
    keycloak(refused=("/events/config",))
    assert kc.main() == 1
    ev = _evidence(tmp_path)
    assert (ev["summary"]["login_events_enabled"], ev["summary"]["admin_events_enabled"]) == (None, None)
    assert ev["summary"]["brute_force_protected"] is True and ev["metadata"]["partial_failure"] is True
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


def test_a_refused_token_fails_the_run_as_auth_failed(keycloak, tmp_path):
    keycloak(token_status=401)
    assert kc.main() == 1
    assert _evidence(tmp_path)["summary"]["realm_enabled"] is None
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "auth_failed"


def test_missing_settings_fail_the_run_as_bad_config(keycloak, tmp_path, monkeypatch):
    keycloak()
    monkeypatch.delenv("KEYCLOAK_BASE_URL")
    assert kc.main() == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"


def test_a_separate_auth_realm_is_used_only_for_the_token(keycloak, tmp_path, monkeypatch):
    monkeypatch.setenv("KEYCLOAK_AUTH_REALM", "master")
    session = keycloak()
    assert kc.main() == 0
    assert session.posts[0][0] == f"{BASE}/realms/master/protocol/openid-connect/token"
    assert all(path.startswith("/admin/realms/example-realm") for path, _ in session.gets)


def test_a_missing_realm_is_bad_config_not_a_default(monkeypatch):
    for name, value in (("KEYCLOAK_BASE_URL", BASE), ("KEYCLOAK_CLIENT_ID", "paramify-reader"), ("KEYCLOAK_CLIENT_SECRET", "x")):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("KEYCLOAK_REALM", raising=False)
    with pytest.raises(client_mod.KeycloakAuthError) as err:
        client_mod.settings_from_env()
    assert err.value.code == "bad_config" and "KEYCLOAK_REALM" in str(err.value)


# --- sign-in paths, judged by Keycloak's flow rules ---

def _e(provider, req, level=0, subflow=False):
    return {"providerId": provider, "requirement": req, "level": level, "authenticationFlow": subflow}


def test_local_path_judged_apart_from_session_cookie_and_federation():
    # A standard browser flow: cookie, IdP redirector and the forms subflow are alternatives at the top.
    passkey_only = [_e("auth-cookie", "ALTERNATIVE"), _e("identity-provider-redirector", "ALTERNATIVE"),
                    _e(None, "ALTERNATIVE", 0, True), _e("auth-username-form", "REQUIRED", 1),
                    _e("webauthn-authenticator-passwordless", "REQUIRED", 1)]
    assert kc.requires_phishing_resistant(passkey_only, kc.NOT_LOCAL_SIGN_IN) is True
    # Without the exclusions, the federated alternative alone fails the check.
    assert kc.requires_phishing_resistant(passkey_only) is False


def test_a_password_alternative_or_a_conditional_otp_does_not_count():
    password_or_passkey = [_e(None, "ALTERNATIVE", 0, True), _e("auth-username-password-form", "ALTERNATIVE", 1),
                           _e("webauthn-authenticator-passwordless", "ALTERNATIVE", 1)]
    assert kc.requires_phishing_resistant(password_or_passkey, kc.NOT_LOCAL_SIGN_IN) is False
    conditional_webauthn = [_e(None, "ALTERNATIVE", 0, True), _e("auth-username-password-form", "REQUIRED", 1),
                            _e(None, "CONDITIONAL", 1, True), _e("conditional-user-configured", "REQUIRED", 2),
                            _e("webauthn-authenticator", "REQUIRED", 2)]
    assert kc.requires_phishing_resistant(conditional_webauthn, kc.NOT_LOCAL_SIGN_IN) is False
    certificate = [_e("auth-x509-client-username-form", "REQUIRED"), _e("auth-otp-form", "ALTERNATIVE")]
    assert kc.requires_phishing_resistant(certificate) is True  # REQUIRED present, so the ALTERNATIVE is ignored


def test_recovery_by_email_link_is_not_phishing_resistant():
    email_reset = [_e("reset-credentials-choose-user", "REQUIRED"), _e("reset-credential-email", "REQUIRED"),
                   _e("reset-password", "REQUIRED")]
    s = kc.summarize({"enabled": True, "browserFlow": "f"}, [], email_reset, [], [], [], {})
    assert (s["recovery_requires_phishing_resistant"], s["federated_sign_in_available"]) == (False, False)


def test_idle_timeout_is_judged_only_against_an_adopted_maximum():
    realm = {"enabled": True, "ssoSessionIdleTimeout": 1800}
    assert kc.summarize(realm, [], [], [], [], [], {})["sso_session_idle_within_max"] is None
    assert kc.summarize(realm, [], [], [], [], [], {}, 15)["sso_session_idle_within_max"] is False
    s = kc.summarize(realm, [], [], [], [], [], {}, 30)
    assert (s["sso_session_idle_within_max"], s["sso_session_idle_timeout_minutes"], s["max_idle_timeout_minutes"]) == (True, 30.0, 30)


def test_an_invalid_idle_maximum_is_bad_config(monkeypatch):
    monkeypatch.setenv(kc.MAX_IDLE_ENV, "fifteen")
    value, failure = kc.max_idle_setting()
    assert value is None and "whole number of minutes" in failure["message"]
    monkeypatch.setenv(kc.MAX_IDLE_ENV, "15")
    assert kc.max_idle_setting() == (15, None)


def test_a_refused_call_names_the_role_it_needs(keycloak, tmp_path):
    keycloak(refused=("/events/config", "/identity-provider"))
    assert kc.main() != 0
    failures = {f["operation"]: f["message"] for f in _evidence(tmp_path)["metadata"]["api_failures"]}
    assert "needs the role view-events of the realm-management client" in failures["events configuration"]
    assert "needs the role view-identity-providers of the realm-management client" in failures["identity providers"]
    s = _evidence(tmp_path)["summary"]
    assert (s["login_events_enabled"], s["identity_providers_enabled"], s["federated_sign_in_available"]) == (None, None, None)


# The reduced view a real Keycloak 26.8.2 returned to a service account without view-realm.
REDUCED_REALM = {"realm": "example-realm", "bruteForceProtected": True, "supportedLocales": [], "organizationsEnabled": False}


def test_a_reduced_realm_view_is_a_failure_not_settings_read_as_off(keycloak, tmp_path):
    keycloak(realm=REDUCED_REALM)
    assert kc.main() == 1
    ev = _evidence(tmp_path)
    s = ev["summary"]
    # Absent settings are never read as false: registration and remember me would otherwise look turned off.
    assert (s["realm_enabled"], s["registration_allowed"], s["remember_me_enabled"], s["brute_force_protected"]) == (None, None, None, None)
    failure = next(f for f in ev["metadata"]["api_failures"] if f["operation"] == "realm settings")
    assert "needs the role view-realm of the realm-management client" in failure["message"]


def test_a_401_names_the_kc_admin_api_scope(keycloak, tmp_path):
    keycloak(admin_status=401)
    assert kc.main() == 1
    messages = " ".join(f["message"] for f in _evidence(tmp_path)["metadata"]["api_failures"])
    assert "kc-admin-api" in messages



# --- review fixes ---

def _flow_paths(session):
    return [p for p, _ in session.gets if "/authentication/flows/" in p]


def test_the_built_in_browser_flow_with_webauthn_required_counts_as_phishing_resistant():
    # Keycloak's built-in shape: cookie, Kerberos off, redirector, and the forms subflow as alternatives.
    built_in = [ex("auth-cookie", "ALTERNATIVE"), ex("auth-spnego", "DISABLED"), ex("identity-provider-redirector", "ALTERNATIVE"),
                ex(None, "ALTERNATIVE", subflow=True, name="forms"), ex("auth-username-password-form", "REQUIRED", level=1),
                ex("webauthn-authenticator", "REQUIRED", level=1)]
    assert kc.requires_phishing_resistant(built_in, kc.NOT_LOCAL_SIGN_IN) is True
    with_kerberos = [dict(e, requirement="ALTERNATIVE") if e["providerId"] == "auth-spnego" else e for e in built_in]
    assert kc.requires_phishing_resistant(with_kerberos, kc.NOT_LOCAL_SIGN_IN) is False


def test_an_unread_realm_leaves_the_flows_unknown_without_reading_default_names(keycloak, tmp_path):
    session = keycloak(realm_status=503)
    assert kc.main() == 1
    s = _evidence(tmp_path)["summary"]
    assert _flow_paths(session) == []  # never falls back to "browser" or "reset credentials"
    assert (s["browser_flow"], s["local_sign_in_requires_phishing_resistant"], s["recovery_requires_phishing_resistant"]) == (None, None, None)


def test_a_reduced_realm_view_reads_no_flows(keycloak, tmp_path):
    session = keycloak(realm=REDUCED_REALM)
    kc.main()
    assert _flow_paths(session) == [] and _evidence(tmp_path)["summary"]["local_sign_in_requires_phishing_resistant"] is None


def test_a_realm_without_a_reset_flow_binding_is_a_failure(keycloak, tmp_path):
    keycloak(realm={k: v for k, v in REALM.items() if k != "resetCredentialsFlow"})
    assert kc.main() == 1
    ev = _evidence(tmp_path)
    assert ev["summary"]["recovery_requires_phishing_resistant"] is None
    assert any(f["type"] == "Missing flow binding" for f in ev["metadata"]["api_failures"])


@pytest.mark.parametrize("saved, expected", [(["LOGIN", "LOGIN_ERROR"], True), (["LOGIN"], False), (["UPDATE_PASSWORD"], False), (None, None)])
def test_login_events_count_as_enabled_only_when_both_types_are_saved(saved, expected):
    events = dict(EVENTS, enabledEventTypes=saved) if saved is not None else {k: v for k, v in EVENTS.items() if k != "enabledEventTypes"}
    s = kc.summarize(REALM, [], [], [], [], [], events)
    assert s["login_events_enabled"] is expected
    assert kc.summarize(REALM, [], [], [], [], [], dict(EVENTS, eventsEnabled=False))["login_events_enabled"] is False


def test_identity_providers_are_read_past_the_first_page(keycloak, tmp_path):
    many = [{"alias": f"idp-{i}", "providerId": "oidc" if i % 2 else "saml", "enabled": True} for i in range(150)]
    session = keycloak(idps=many)
    assert kc.main() == 0
    assert _evidence(tmp_path)["summary"]["identity_providers_enabled"] == 150
    assert [p.get("first") for path, p in session.gets if path.endswith("/identity-provider/instances")] == ["0", "100"]


@pytest.mark.parametrize("idps, expected", [([], False), ([{"providerId": "oidc", "enabled": False}], False),
                                            ([{"providerId": "oidc", "enabled": True}], True), (None, None)])
def test_federation_needs_an_enabled_provider_not_just_a_redirector(idps, expected):
    redirector = [ex("identity-provider-redirector", "ALTERNATIVE"), ex("auth-username-password-form", "ALTERNATIVE")]
    s = kc.summarize(REALM, redirector, [], [], idps, [], EVENTS)
    assert (s["federated_sign_in_available"], s["identity_provider_redirector_enabled"]) == (expected, True)


@pytest.mark.parametrize("seconds, within", [(0, False), (1, True), (899, True), (900, True), (901, False), (902, False), (903, False)])
def test_the_idle_timeout_is_compared_in_seconds(seconds, within):
    assert kc.summarize(dict(REALM, ssoSessionIdleTimeout=seconds), [], [], [], [], [], {}, 15)["sso_session_idle_within_max"] is within


def test_a_token_endpoint_404_is_bad_config(keycloak, tmp_path):
    keycloak(token_status=404)
    assert kc.main() == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"


def test_a_token_response_without_a_token_fails_cleanly(keycloak, tmp_path):
    keycloak(token_body="<html>proxy sign-in page</html>")
    assert kc.main() == 1
    assert "no access token" in _evidence(tmp_path)["metadata"]["api_failures"][0]["message"]


def test_a_200_that_is_not_json_is_a_failure_not_a_traceback(keycloak, tmp_path):
    keycloak(html=("/events/config",))
    assert kc.main() == 1
    ev = _evidence(tmp_path)
    assert ev["summary"]["login_events_enabled"] is None
    assert any(f["operation"] == "events configuration" and f["type"] == "ValueError" for f in ev["metadata"]["api_failures"])


def test_an_account_in_master_is_told_to_use_the_realm_specific_client(keycloak, tmp_path, monkeypatch):
    monkeypatch.setenv("KEYCLOAK_AUTH_REALM", "master")
    keycloak(refused=("/events/config",))
    kc.main()
    failure = next(f for f in _evidence(tmp_path)["metadata"]["api_failures"] if f["operation"] == "events configuration")
    assert "the role view-events of the example-realm-realm client in the master realm" in failure["message"]


# Keycloak 26 adds an Organization subflow to the built-in browser flow of every new realm but master. Its organization
# step reuses an SSO session or routes to an identity provider or the forms; it never signs a user in by itself.
ORGANIZATION = [ex(None, "ALTERNATIVE", subflow=True, name="Organization"),
                ex(None, "CONDITIONAL", level=1, subflow=True, name="Browser - Conditional Organization"),
                ex("conditional-user-configured", "REQUIRED", level=2), ex("organization", "ALTERNATIVE", level=2)]


def _kc26(*forms, extra=()):
    return [ex("auth-cookie", "ALTERNATIVE"), ex("auth-spnego", "DISABLED"), ex("identity-provider-redirector", "ALTERNATIVE"),
            *ORGANIZATION, *extra, ex(None, "ALTERNATIVE", subflow=True, name="forms"), *forms]


def test_the_keycloak_26_built_in_browser_flow_with_webauthn_required_counts_as_phishing_resistant():
    webauthn = _kc26(ex("auth-username-password-form", "REQUIRED", level=1), ex("webauthn-authenticator", "REQUIRED", level=1))
    assert kc.requires_phishing_resistant(webauthn, kc.NOT_LOCAL_SIGN_IN) is True
    s = kc.summarize(dict(REALM, browserFlow="browser"), webauthn, RESET, ACTIONS, IDPS, STORAGE, EVENTS)
    assert s["local_sign_in_requires_phishing_resistant"] is True


@pytest.mark.parametrize("flow", [
    # Kerberos enabled as another way in.
    _kc26(ex("auth-username-password-form", "REQUIRED", level=1), ex("webauthn-authenticator", "REQUIRED", level=1),
          extra=(ex("auth-spnego", "ALTERNATIVE"),)),
    # A password or a passkey.
    _kc26(ex("auth-username-password-form", "ALTERNATIVE", level=1), ex("webauthn-authenticator-passwordless", "ALTERNATIVE", level=1)),
    # The flow as shipped: WebAuthn off, OTP only when configured.
    _kc26(ex("auth-username-password-form", "REQUIRED", level=1), ex("webauthn-authenticator", "DISABLED", level=1),
          ex(None, "CONDITIONAL", level=1, subflow=True, name="Browser - Conditional OTP"),
          ex("conditional-user-configured", "REQUIRED", level=2), ex("auth-otp-form", "REQUIRED", level=2)),
], ids=["kerberos", "password-or-passkey", "as-shipped"])
def test_the_keycloak_26_flow_still_fails_when_a_local_path_skips_phishing_resistance(flow):
    assert kc.requires_phishing_resistant(flow, kc.NOT_LOCAL_SIGN_IN) is False


def test_a_condition_only_subflow_without_a_routing_step_is_still_a_way_in():
    # Only a subflow that wraps a left-out step (such as organization) is dropped: an unknown condition-only subflow
    # is kept as a path, so it still fails the check.
    unknown = [ex(None, "ALTERNATIVE", subflow=True, name="custom"), ex("conditional-user-role", "REQUIRED", level=1),
               ex(None, "ALTERNATIVE", subflow=True, name="forms"), ex("webauthn-authenticator", "REQUIRED", level=1)]
    assert kc.requires_phishing_resistant(unknown, kc.NOT_LOCAL_SIGN_IN) is False


@pytest.mark.parametrize("realm, auth_realm, holder", [
    ("example-realm", "example-realm", "of the realm-management client"),
    ("example-realm", "master", "of the example-realm-realm client in the master realm"),
    # Keycloak creates no realm-management client in master; master's own admin roles are on master-realm.
    ("master", "master", "of the master-realm client in the master realm"),
])
def test_a_refusal_names_the_client_that_holds_the_role(realm, auth_realm, holder):
    assert client_mod.KeycloakClient(BASE, realm, auth_realm, "id", "secret", session=object()).role_holder() == holder
