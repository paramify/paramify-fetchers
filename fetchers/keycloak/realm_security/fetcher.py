#!/usr/bin/env python3
"""Keycloak realm security settings: sessions, lockout, password policy, the browser and reset-credentials flows,
required actions, federation and event logging, read from the Keycloak Admin REST API."""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from fetcher_status import report_failure  # noqa: E402
from keycloak_client import KeycloakAuthError, KeycloakClient, settings_from_env  # noqa: E402

NAME = "keycloak_realm_security"
OUTPUT = "keycloak_realm_security.json"
logger = logging.getLogger(NAME)

# Authenticators that bind sign-in to the origin or to a key the user holds: WebAuthn (security keys, passkeys)
# and X.509 client certificates such as a CAC or PIV card.
PHISHING_RESISTANT = frozenset({"webauthn-authenticator", "webauthn-authenticator-passwordless", "auth-x509-client-username-form",
                                "direct-grant-auth-x509-username"})
TERMS_ACTION = "terms_and_conditions"
# Settings only the full realm view (view-realm) carries. The reduced view keeps the realm name and a few flags
# (bruteForceProtected among them, on Keycloak 26.8), so a full view is one with every one of these.
REALM_FULL_VIEW_KEYS = frozenset({"browserFlow", "ssoSessionIdleTimeout", "registrationAllowed", "rememberMe"})
# Not a new sign-in: session reuse (auth-cookie), the federated path that the external identity provider governs
# (identity-provider-redirector), and Keycloak 26's organization step, which reuses a session or routes to an
# identity provider or to the forms but never signs a user in by itself.
NOT_LOCAL_SIGN_IN = frozenset({"auth-cookie", "identity-provider-redirector", "organization"})
MAX_IDLE_ENV = "KEYCLOAK_MAX_IDLE_TIMEOUT_MINUTES"
USER_STORAGE = "org.keycloak.storage.UserStorageProvider"


# --- pure transforms ---

def effective_requirements(executions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Each execution's provider, nesting level and requirement, depth first as Keycloak lists them. Whether a sign-in
    must pass a step is judged over paths by requires_phishing_resistant, not per step."""
    return [{"provider": e.get("providerId"), "alias": e.get("displayName") or e.get("alias"), "level": int(e.get("level") or 0),
             "requirement": (e.get("requirement") or "").upper(), "subflow": bool(e.get("authenticationFlow"))}
            for e in executions or []]


def _login_events_saved(events: Dict[str, Any]) -> Optional[bool]:
    """True if event storage is on and LOGIN and LOGIN_ERROR are saved types; null when the saved types are missing."""
    if not events.get("eventsEnabled"):
        return False
    saved = events.get("enabledEventTypes")
    if not isinstance(saved, list):
        return None
    return {"LOGIN", "LOGIN_ERROR"}.issubset(saved)


def _tree(executions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Nest the depth-first execution list by `level`: each node gets its subflow's executions as `children`."""
    root: List[Dict[str, Any]] = []
    stack: List[tuple] = [(-1, root)]
    for e in executions or []:
        level = int(e.get("level") or 0)
        node = {"provider": e.get("providerId"), "requirement": (e.get("requirement") or "").upper(),
                "subflow": bool(e.get("authenticationFlow")), "children": []}
        while stack[-1][0] >= level:
            stack.pop()
        stack[-1][1].append(node)
        if node["subflow"]:
            stack.append((level, node["children"]))
    return root


def requires_phishing_resistant(executions: List[Dict[str, Any]], exclude: frozenset = frozenset()) -> bool:
    """True if every way through the flow passes a phishing-resistant authenticator, by Keycloak's rules: where a flow
    has REQUIRED or CONDITIONAL executions its ALTERNATIVE ones are ignored, every REQUIRED one must pass and a
    CONDITIONAL one may be skipped; where it has only ALTERNATIVE executions, any one is enough, so each must require
    it. Executions whose provider is in `exclude` (and DISABLED ones) are left out, and so is a subflow that only wraps
    excluded steps in conditions, such as Keycloak 26's Organization subflow."""
    def node_requires(n):
        if not n["subflow"]:
            return n["provider"] in PHISHING_RESISTANT
        return flow_requires(n["children"])

    def wraps_only_excluded(n):
        # A subflow with nothing left once its conditions and excluded steps are removed, and at least one excluded
        # step in it. Any other subflow, even one of conditions only, stays a way in.
        live = [c for c in n["children"] if c["requirement"] != "DISABLED"]
        excluded = [c for c in live if not c["subflow"] and c["provider"] in exclude]
        nested = [c for c in live if c["subflow"]]
        rest = [c for c in live if not c["subflow"] and c["provider"] not in exclude
                and not (c["provider"] or "").startswith("conditional-")]
        return not rest and all(wraps_only_excluded(c) for c in nested) and bool(excluded or nested)

    def flow_requires(nodes):
        live = [n for n in nodes if n["requirement"] != "DISABLED" and n["provider"] not in exclude
                and not (n["subflow"] and wraps_only_excluded(n))]
        firm = [n for n in live if n["requirement"] in ("REQUIRED", "CONDITIONAL")]
        if firm:
            return any(n["requirement"] == "REQUIRED" and node_requires(n) for n in firm)
        alternatives = [n for n in live if n["requirement"] == "ALTERNATIVE"]
        return bool(alternatives) and all(node_requires(n) for n in alternatives)

    return flow_requires(_tree(executions))


def password_rules(policy: Optional[str]) -> Dict[str, Optional[int]]:
    """Keycloak's passwordPolicy string, such as "length(15) and passwordHistory(24)", as rule -> number (None when the
    rule takes no number)."""
    rules: Dict[str, Optional[int]] = {}
    for part in re.split(r"\s+and\s+", policy or ""):
        found = re.match(r"\s*([A-Za-z]+)(?:\((\d*)\))?", part)
        if found and found.group(1):
            rules[found.group(1)] = int(found.group(2)) if found.group(2) else None
    return rules


def _minutes(seconds: Any) -> Optional[float]:
    return round(int(seconds) / 60, 1) if isinstance(seconds, (int, float)) else None


def summarize(realm: Optional[Dict[str, Any]], browser: Optional[List[Dict[str, Any]]], reset: Optional[List[Dict[str, Any]]],
              actions: Optional[List[Dict[str, Any]]], idps: Optional[List[Dict[str, Any]]],
              storage: Optional[List[Dict[str, Any]]], events: Optional[Dict[str, Any]],
              max_idle_minutes: Optional[int] = None) -> Dict[str, Any]:
    """What is configured, never a verdict. Each group is null when the call behind it could not be read."""
    r = realm or {}
    rules = password_rules(r.get("passwordPolicy")) if realm is not None else {}
    flow = effective_requirements(browser) if browser is not None else None
    steps = [e for e in flow or [] if not e["subflow"] and e["requirement"] != "DISABLED"]
    by_alias = {(a.get("alias") or "").lower(): a for a in actions or []}
    terms = by_alias.get(TERMS_ACTION)
    rs = realm is not None

    def realm_value(value):
        return value if rs else None

    return {
        "realm_enabled": realm_value(bool(r.get("enabled"))),
        "ssl_required": realm_value(r.get("sslRequired")),
        "registration_allowed": realm_value(bool(r.get("registrationAllowed"))),
        # Sessions
        "sso_session_idle_timeout_minutes": realm_value(_minutes(r.get("ssoSessionIdleTimeout"))),
        "sso_session_max_lifespan_minutes": realm_value(_minutes(r.get("ssoSessionMaxLifespan"))),
        "access_token_lifespan_minutes": realm_value(_minutes(r.get("accessTokenLifespan"))),
        "remember_me_enabled": realm_value(bool(r.get("rememberMe"))),
        "max_idle_timeout_minutes": max_idle_minutes,
        # Compared in seconds: rounding first would let 902 seconds pass as 15.0 minutes.
        "sso_session_idle_within_max": (isinstance(r.get("ssoSessionIdleTimeout"), int)
                                        and 0 < r["ssoSessionIdleTimeout"] <= max_idle_minutes * 60)
        if rs and max_idle_minutes is not None else None,
        # Lockout
        "brute_force_protected": realm_value(bool(r.get("bruteForceProtected"))),
        "lockout_failure_threshold": realm_value(r.get("failureFactor") if r.get("bruteForceProtected") else None),
        "permanent_lockout": realm_value(bool(r.get("permanentLockout")) if r.get("bruteForceProtected") else None),
        "lockout_max_wait_minutes": realm_value(_minutes(r.get("maxFailureWaitSeconds")) if r.get("bruteForceProtected") else None),
        # Passwords
        "password_policy_rules": realm_value(sorted(rules)),
        "password_min_length": realm_value(rules.get("length")),
        "password_history": realm_value(rules.get("passwordHistory")),
        "password_expiry_days": realm_value(rules.get("forceExpiredPasswordChange")),
        # Browser flow
        "browser_flow": realm_value(r.get("browserFlow")),
        "browser_flow_alternative_authenticators": sorted({e["provider"] for e in steps if e["requirement"] == "ALTERNATIVE"})
        if flow is not None else None,
        "browser_flow_conditional_authenticators": sorted({e["provider"] for e in steps if (e["provider"] or "").startswith("conditional-")})
        if flow is not None else None,
        "local_sign_in_requires_phishing_resistant": requires_phishing_resistant(browser, NOT_LOCAL_SIGN_IN) if browser is not None else None,
        # A redirector alone sends nobody anywhere: federation needs an enabled identity provider.
        "federated_sign_in_available": any(i.get("enabled") for i in idps or []) if idps is not None else None,
        "identity_provider_redirector_enabled": (any(e["provider"] == "identity-provider-redirector" and e["requirement"] != "DISABLED"
                                                     for e in flow or []) if flow is not None else None),
        "recovery_requires_phishing_resistant": requires_phishing_resistant(reset) if reset is not None else None,
        "reset_credentials_authenticators": sorted({e["provider"] for e in effective_requirements(reset)
                                                    if not e["subflow"] and e["requirement"] != "DISABLED"}) if reset is not None else None,
        # Required actions
        "terms_and_conditions_enabled": bool(terms and terms.get("enabled")) if actions is not None else None,
        "terms_and_conditions_default_action": bool(terms and terms.get("enabled") and terms.get("defaultAction")) if actions is not None else None,
        "default_required_actions": sorted(a.get("alias") for a in actions or [] if a.get("enabled") and a.get("defaultAction"))
        if actions is not None else None,
        # Federation
        "identity_providers_enabled": sum(1 for i in idps or [] if i.get("enabled")) if idps is not None else None,
        "identity_provider_types": sorted({i.get("providerId") for i in idps or [] if i.get("enabled")}) if idps is not None else None,
        "user_federation_providers": len(storage) if storage is not None else None,
        # Events
        # Keycloak stores only the saved event types, so storage being on isn't enough: LOGIN and LOGIN_ERROR must be saved.
        "login_events_enabled": _login_events_saved(events) if events is not None else None,
        "saved_event_types": sorted(events["enabledEventTypes"]) if events is not None and isinstance(events.get("enabledEventTypes"), list) else None,
        "login_events_expiration_days": (round(int(events["eventsExpiration"]) / 86400, 1) if events and events.get("eventsExpiration") else None)
        if events is not None else None,
        "admin_events_enabled": bool((events or {}).get("adminEventsEnabled")) if events is not None else None,
        "admin_events_details_enabled": bool((events or {}).get("adminEventsDetailsEnabled")) if events is not None else None,
        "event_listeners": sorted((events or {}).get("eventsListeners") or []) if events is not None else None,
    }


REALM_KEYS = ("realm", "enabled", "sslRequired", "registrationAllowed", "verifyEmail", "loginWithEmailAllowed", "rememberMe",
              "ssoSessionIdleTimeout", "ssoSessionMaxLifespan", "ssoSessionIdleTimeoutRememberMe", "ssoSessionMaxLifespanRememberMe",
              "offlineSessionIdleTimeout", "accessTokenLifespan", "revokeRefreshToken", "bruteForceProtected", "failureFactor",
              "permanentLockout", "maxFailureWaitSeconds", "waitIncrementSeconds", "minimumQuickLoginWaitSeconds",
              "passwordPolicy", "otpPolicyType", "otpPolicyAlgorithm", "otpPolicyDigits", "browserFlow", "resetCredentialsFlow",
              "directGrantFlow", "firstBrokerLoginFlow")


def collect(client: KeycloakClient, max_idle_minutes: Optional[int] = None) -> Dict[str, Any]:
    realm = client.get("realm settings", "", role="view-realm")
    if realm is not None and not REALM_FULL_VIEW_KEYS.issubset(realm):
        # Without view-realm, Keycloak answers 200 with a reduced view (name and a few flags). Reading absent settings
        # as false would report lockout, registration and remember me as configured when nothing was read.
        client._fail("realm settings", "Reduced realm view",
                     f"needs the role view-realm {client.role_holder()}: Keycloak returned only the reduced realm view", "not_authorized")
        realm = None
    # The bound flows are known only from the realm: never fall back to the default names, which may be unused flows.
    browser_alias = realm.get("browserFlow") if realm is not None else None
    reset_alias = realm.get("resetCredentialsFlow") if realm is not None else None
    if realm is not None and not reset_alias:
        client._fail("realm settings", "Missing flow binding", "the realm settings have no reset-credentials flow binding",
                     "partial_failure")
    browser = client.flow_executions(browser_alias) if browser_alias else None
    reset = client.flow_executions(reset_alias) if reset_alias else None
    actions = client.get("required actions", "/authentication/required-actions", role="view-realm")
    idps = client.get_all("identity providers", "/identity-provider/instances", role="view-identity-providers")
    storage = client.get("user federation providers", "/components", {"type": USER_STORAGE}, role="view-realm")
    events = client.get("events configuration", "/events/config", role="view-events")
    results = {
        "realm_settings": {k: realm.get(k) for k in REALM_KEYS} if realm is not None else None,
        "browser_flow": {"alias": browser_alias, "executions": effective_requirements(browser) if browser is not None else None},
        "reset_credentials_flow": {"alias": reset_alias, "executions": effective_requirements(reset) if reset is not None else None},
        "required_actions": [{k: a.get(k) for k in ("alias", "name", "enabled", "defaultAction", "priority")} for a in actions]
        if actions is not None else None,
        # Identity provider and user federation configs hold client secrets and bind credentials: never copied.
        "identity_providers": [{k: i.get(k) for k in ("alias", "displayName", "providerId", "enabled", "trustEmail", "firstBrokerLoginFlowAlias")}
                               for i in idps] if idps is not None else None,
        "user_federation_providers": [{"name": c.get("name"), "provider": c.get("providerId"),
                                       "edit_mode": ((c.get("config") or {}).get("editMode") or [None])[0],
                                       "enabled": ((c.get("config") or {}).get("enabled") or [None])[0]} for c in storage]
        if storage is not None else None,
        "events_configuration": {k: events.get(k) for k in ("eventsEnabled", "eventsExpiration", "eventsListeners", "enabledEventTypes",
                                                             "adminEventsEnabled", "adminEventsDetailsEnabled")} if events is not None else None,
    }
    return {"results": results, "summary": summarize(realm, browser, reset, actions, idps, storage, events, max_idle_minutes)}


def max_idle_setting() -> tuple:
    """The adopted maximum idle timeout in whole minutes, or None when unset; anything else is a
    recorded bad_config failure and is left unset."""
    raw = (os.environ.get(MAX_IDLE_ENV) or "").strip()
    if not raw:
        return None, None
    if raw.isdigit() and int(raw) > 0:
        return int(raw), None
    return None, {"operation": f"config {MAX_IDLE_ENV}", "type": "ValueError",
                  "message": f"{MAX_IDLE_ENV}={raw!r} must be a whole number of minutes above 0; left unset"}


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    out_dir.mkdir(parents=True, exist_ok=True)
    metadata: Dict[str, Any] = {"datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "api_failures": []}
    code, evidence = None, {"results": {}, "summary": summarize(None, None, None, None, None, None, None)}
    try:
        settings = settings_from_env()
        metadata.update(realm=settings["realm"], base_url=settings["base_url"])
        client = KeycloakClient(settings["base_url"], settings["realm"], settings["auth_realm"],
                                os.environ["KEYCLOAK_CLIENT_ID"], os.environ["KEYCLOAK_CLIENT_SECRET"])
        max_idle, bad = max_idle_setting()
        evidence = collect(client, max_idle)
        metadata["api_failures"] = client.api_failures + ([bad] if bad else [])
        if bad and not client.failure_codes:
            client.failure_codes.append("bad_config")
        code = client.failure_codes[0] if client.failure_codes else None
    except KeycloakAuthError as exc:
        metadata["api_failures"] = [{"operation": "authenticate", "type": "KeycloakAuthError", "message": str(exc)}]
        code = exc.code
    metadata["partial_failure"] = bool(metadata["api_failures"])
    path = out_dir / OUTPUT
    path.write_text(json.dumps({"metadata": metadata, **evidence}, indent=2, sort_keys=True))
    logger.info("Evidence saved to %s", path)
    if metadata["api_failures"]:
        first = metadata["api_failures"][0]
        report_failure(f"Keycloak {first['operation']} failed: {first['type']}", code)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
