"""Keycloak users and roles: every user in a realm with their state, authenticators, groups and effective roles.

GET only, with the realm-management roles view-users, view-clients and view-events. For each user it copies the
username, enabled state, creation time, required actions, whether the account is federated (LDAP) or brokered from
an external identity provider, the types of authenticator registered, group paths and effective roles. Email
addresses, first and last names, user attributes and credential data are never copied.

Keycloak keeps no last sign-in time on a user, so sign-in recency comes from stored LOGIN events, and is left null
when those events aren't stored or expire before the window ends.
"""

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
from fetcher_status import report_failure  # noqa: E402
from keycloak_client import (  # noqa: E402
    KeycloakAuthError,
    KeycloakClient,
    settings_from_env,
)

NAME = "keycloak_users_and_roles"
OUTPUT = "keycloak_users_and_roles.json"
INACTIVE_ENV = "KEYCLOAK_INACTIVE_DAYS"
PRIVILEGED_ENV = "KEYCLOAK_PRIVILEGED_ROLES"
DEFAULT_INACTIVE_DAYS = 90
MAX_INACTIVE_DAYS = 365
EVENT_PAGE = 500
MAX_LOGIN_EVENTS = 50000
MAX_USERS = 5000
SERVICE_ACCOUNT_PREFIX = "service-account-"
# realm-management client roles that change users, clients, the realm or its sign-in, or act as another user.
ADMIN_ROLES = frozenset({"realm-admin", "manage-users", "manage-realm", "manage-clients", "manage-authorization",
                         "manage-identity-providers", "manage-events", "impersonation", "create-client"})
SECOND_FACTOR_TYPES = frozenset({"otp", "webauthn", "webauthn-passwordless"})
PHISHING_RESISTANT_TYPES = frozenset({"webauthn", "webauthn-passwordless"})

logger = logging.getLogger(NAME)


# --- settings ---

def inactive_days_setting() -> Tuple[int, Optional[Dict[str, str]]]:
    raw = (os.environ.get(INACTIVE_ENV) or "").strip()
    if not raw:
        return DEFAULT_INACTIVE_DAYS, None
    if raw.isdigit() and 0 < int(raw) <= MAX_INACTIVE_DAYS:
        return int(raw), None
    return DEFAULT_INACTIVE_DAYS, {"operation": f"config {INACTIVE_ENV}", "type": "ValueError",
                                   "message": f"{INACTIVE_ENV}={raw!r} must be a whole number from 1 to {MAX_INACTIVE_DAYS}"}


def privileged_roles_setting() -> List[str]:
    """Realm roles the organization designates as privileged, comma-separated; matched by exact name."""
    return sorted({r.strip() for r in (os.environ.get(PRIVILEGED_ENV) or "").split(",") if r.strip()})


# --- pure transforms ---

def _iso(ms: Optional[int]) -> Optional[str]:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ms else None


def is_service_account(user: Dict[str, Any]) -> bool:
    """Keycloak leaves service-account users out of user search; this guards against a version that doesn't."""
    return bool(user.get("serviceAccountClientId")) or str(user.get("username") or "").startswith(SERVICE_ACCOUNT_PREFIX)


def history_covers_window(config: Optional[Dict[str, Any]], inactive_days: int) -> Optional[bool]:
    """True if successful sign-ins are stored and kept for the whole window; null when the event settings are unread."""
    if config is None:
        return None
    saved = config.get("enabledEventTypes")
    if not config.get("eventsEnabled") or not isinstance(saved, list) or "LOGIN" not in saved:
        return False
    expiration = config.get("eventsExpiration")  # seconds; unset keeps events until removed
    return not expiration or int(expiration) >= inactive_days * 86400


def _names(items: Optional[List[Dict[str, Any]]], key: str) -> Optional[List[str]]:
    """The distinct values of `key`, sorted; null when the list could not be read."""
    return sorted({str(i[key]) for i in items if i.get(key)}) if items is not None else None


def user_record(user: Dict[str, Any], credentials: Optional[List[Dict[str, Any]]], groups: Optional[List[Dict[str, Any]]],
                realm_roles: Optional[List[Dict[str, Any]]], admin_roles: Optional[List[Dict[str, Any]]],
                identity_links: Optional[List[Dict[str, Any]]], last_sign_in: Optional[int], privileged_realm_roles: Iterable[str],
                window_start: datetime, history: Optional[bool]) -> Dict[str, Any]:
    """One user. A part that could not be read is null, and so is anything judged from it."""
    types = _names(credentials, "type")
    realm_names = _names(realm_roles, "name")
    admin_names = _names(admin_roles, "name")
    providers = _names(identity_links, "identityProvider")
    held_admin = sorted(ADMIN_ROLES.intersection(admin_names)) if admin_names is not None else None
    held_realm = sorted(set(privileged_realm_roles).intersection(realm_names)) if realm_names is not None else None
    privileged = None if held_admin is None or held_realm is None else bool(held_admin or held_realm)
    created = user.get("createdTimestamp")
    inactive = None
    if history and user.get("enabled"):
        older = created is None or datetime.fromtimestamp(created / 1000, tz=timezone.utc) < window_start
        inactive = bool(older and not last_sign_in)
    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "enabled": bool(user.get("enabled")),
        "created": _iso(created),
        "required_actions": sorted(user.get("requiredActions") or []),
        "ldap_federated": bool(user.get("federationLink")),
        "identity_providers": providers,
        "brokered": bool(providers) if providers is not None else None,
        "credential_types": types,
        "second_factor": bool(SECOND_FACTOR_TYPES.intersection(types)) if types is not None else None,
        "phishing_resistant": bool(PHISHING_RESISTANT_TYPES.intersection(types)) if types is not None else None,
        "groups": sorted({g.get("path") or g.get("name") for g in groups or []}) if groups is not None else None,
        "realm_roles": realm_names,
        "admin_roles": admin_names,
        "privileged_roles": (held_admin or []) + (held_realm or []) if privileged is not None else None,
        "privileged": privileged,
        "last_sign_in": _iso(last_sign_in) if history else None,
        "inactive": inactive,
    }


def _count(records: List[Dict[str, Any]], keep: Callable[[Dict[str, Any]], bool], needs: Iterable[str]) -> Optional[int]:
    """Users that `keep` selects; null if any user's needed field is null, since that user can't be judged."""
    if any(r.get(n) is None for r in records for n in needs):
        return None
    return sum(1 for r in records if keep(r))


def summarize(records: Optional[List[Dict[str, Any]]], privileged_realm_roles: List[str], inactive_days: int,
              history: Optional[bool], service_accounts_skipped: Optional[int]) -> Dict[str, Any]:
    """Counts over human users; every count is null when the users could not be read."""
    read = records is not None
    rs = records or []
    enabled = [r for r in rs if r["enabled"]]
    local = lambda r: r["brokered"] is False  # noqa: E731

    def c(keep: Callable[[Dict[str, Any]], bool], needs: Iterable[str] = (), pool: Optional[List[Dict[str, Any]]] = None) -> Optional[int]:
        return _count(rs if pool is None else pool, keep, needs) if read else None

    return {
        "users_read": read,
        "users_total": len(rs) if read else None,
        "users_enabled": len(enabled) if read else None,
        "users_disabled": len(rs) - len(enabled) if read else None,
        "service_accounts_skipped": service_accounts_skipped,
        # How do users sign in?
        "users_ldap_federated": c(lambda r: r["ldap_federated"], pool=enabled),
        "users_brokered": c(lambda r: r["brokered"], ("brokered",), enabled),
        "users_with_second_factor": c(lambda r: r["second_factor"], ("second_factor",), enabled),
        "users_with_phishing_resistant_authenticator": c(lambda r: r["phishing_resistant"], ("phishing_resistant",), enabled),
        "enabled_local_users_without_second_factor": c(lambda r: local(r) and not r["second_factor"], ("brokered", "second_factor"), enabled),
        "users_with_required_actions": c(lambda r: bool(r["required_actions"]), pool=enabled),
        # Who holds privileged roles?
        "privileged_realm_roles_checked": privileged_realm_roles,
        "privileged_users": c(lambda r: r["privileged"], ("privileged",), enabled),
        "privileged_local_users_without_second_factor": c(lambda r: r["privileged"] and local(r) and not r["second_factor"],
                                                          ("privileged", "brokered", "second_factor"), enabled),
        "privileged_brokered_users": c(lambda r: r["privileged"] and r["brokered"], ("privileged", "brokered"), enabled),
        # Are accounts in use?
        "inactive_days": inactive_days,
        "sign_in_history_covers_window": history,
        "enabled_users_inactive": c(lambda r: r["inactive"], ("inactive",), enabled) if history else None,
    }


# --- collection ---

class _PerUser:
    """Reads one per-user endpoint for every user. Once Keycloak refuses it for a missing role, it isn't called again,
    and every user's value for it is null: one failure is recorded, not one per user."""

    def __init__(self, client: KeycloakClient, operation: str, role: str):
        self.client, self.operation, self.role, self.refused = client, operation, role, False

    def read(self, path: str) -> Optional[Any]:
        if self.refused:
            return None
        before = len(self.client.failure_codes)
        value = self.client.get(self.operation, path, role=self.role)
        if value is None and self.client.failure_codes[before:] and self.client.failure_codes[-1] in ("not_authorized", "auth_failed"):
            self.refused = True
        return value


def realm_management_id(client: KeycloakClient) -> Optional[str]:
    found = client.get("realm-management client", "/clients", {"clientId": "realm-management"}, role="view-clients")
    if found is None:
        return None
    if not found:
        client._fail("realm-management client", "NotFound", "the realm has no realm-management client", "partial_failure")
        return None
    return found[0].get("id")


def last_sign_ins(client: KeycloakClient, since: datetime) -> Optional[Dict[str, int]]:
    """Newest LOGIN time per user id since `since`; None when a page can't be read or there are too many events."""
    newest: Dict[str, int] = {}
    seen, cutoff = 0, since.timestamp() * 1000
    while True:
        page = client.get("sign-in events", "/events", {"type": "LOGIN", "dateFrom": since.strftime("%Y-%m-%d"),
                                                         "first": str(seen), "max": str(EVENT_PAGE)}, role="view-events")
        if page is None:
            return None
        seen += len(page)
        for e in page:
            uid, t = e.get("userId"), e.get("time") or 0
            if uid and t >= cutoff and t > newest.get(uid, 0):
                newest[uid] = t
        if len(page) < EVENT_PAGE:
            return newest
        if seen >= MAX_LOGIN_EVENTS:
            client._fail("sign-in events", "Too many events", f"more than {MAX_LOGIN_EVENTS} sign-ins in the window; "
                         "recency left null rather than guessed. Shorten the inactive_days window.", "partial_failure")
            return None


def collect(client: KeycloakClient, inactive_days: int, privileged_realm_roles: List[str],
            now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    window_start = now - timedelta(days=inactive_days)
    users = client.get_all("users", "/users", role="view-users")
    if users is not None and len(users) > MAX_USERS:
        client._fail("users", "Too many users", f"more than {MAX_USERS} users; nothing judged rather than reading part of the realm",
                     "partial_failure")
        users = None
    rm_id = realm_management_id(client) if users is not None else None
    config = client.get("events configuration", "/events/config", role="view-events") if users is not None else None
    history = history_covers_window(config, inactive_days)
    signs = last_sign_ins(client, window_start) if history else None
    if history and signs is None:
        history = None
    readers = {k: _PerUser(client, op, "view-users") for k, op in (
        ("cred", "user credentials"), ("groups", "user groups"), ("realm", "user realm roles"),
        ("admin", "user realm-management roles"), ("idp", "user identity provider links"))}
    records: Optional[List[Dict[str, Any]]] = None
    skipped: Optional[int] = None
    if users is not None:
        humans = [u for u in users if not is_service_account(u)]
        skipped = len(users) - len(humans)
        records = []
        for u in humans:
            base = f"/users/{quote(str(u.get('id')), safe='')}"
            records.append(user_record(
                u, readers["cred"].read(f"{base}/credentials"), readers["groups"].read(f"{base}/groups"),
                readers["realm"].read(f"{base}/role-mappings/realm/composite"),
                readers["admin"].read(f"{base}/role-mappings/clients/{quote(rm_id, safe='')}/composite") if rm_id else None,
                readers["idp"].read(f"{base}/federated-identity"),
                (signs or {}).get(str(u.get("id"))), privileged_realm_roles, window_start, history))
    results = {"window_start": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"), "users": records}
    return {"results": results, "summary": summarize(records, privileged_realm_roles, inactive_days, history, skipped)}


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    out_dir.mkdir(parents=True, exist_ok=True)
    metadata: Dict[str, Any] = {"datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "api_failures": []}
    inactive_days, bad = inactive_days_setting()
    privileged = privileged_roles_setting()
    evidence = {"results": {}, "summary": summarize(None, privileged, inactive_days, None, None)}
    code = None
    try:
        settings = settings_from_env()
        metadata.update(realm=settings["realm"], base_url=settings["base_url"])
        client = KeycloakClient(settings["base_url"], settings["realm"], settings["auth_realm"],
                                os.environ["KEYCLOAK_CLIENT_ID"], os.environ["KEYCLOAK_CLIENT_SECRET"])
        evidence = collect(client, inactive_days, privileged)
        metadata["api_failures"] = client.api_failures + ([bad] if bad else [])
        code = client.failure_codes[0] if client.failure_codes else ("bad_config" if bad else None)
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
