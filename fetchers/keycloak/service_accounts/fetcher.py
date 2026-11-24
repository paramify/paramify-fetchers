"""Keycloak service accounts: every client that signs in as itself, how it authenticates, how old its secret is, who
owns it and which roles it holds.

GET only, with the realm-management roles view-clients and view-users. Client secrets, rotated secrets and signing
keys are never copied: only the secret's creation and expiry times, which Keycloak keeps as client attributes.
"""

import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
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

NAME = "keycloak_service_accounts"
OUTPUT = "keycloak_service_accounts.json"
MAX_AGE_ENV = "KEYCLOAK_MAX_SECRET_AGE_DAYS"
OWNER_ENV = "KEYCLOAK_OWNER_ATTRIBUTE"
MAX_SECRET_AGE_DAYS = 3650
MAX_CLIENTS = 2000
# Authenticators that rest on a secret shared with Keycloak, against a private key or certificate the client keeps.
SHARED_SECRET = frozenset({"client-secret", "client-secret-jwt"})
KEY_OR_CERTIFICATE = frozenset({"client-jwt", "client-x509"})
ADMIN_ROLES = frozenset({"realm-admin", "manage-users", "manage-realm", "manage-clients", "manage-authorization",
                         "manage-identity-providers", "manage-events", "impersonation", "create-client"})
CREATED_ATTR = "client.secret.creation.time"
EXPIRES_ATTR = "client.secret.expiration.time"
ROTATED_ATTR = "client.secret.rotated"

logger = logging.getLogger(NAME)


# --- settings ---

def max_age_setting() -> Tuple[Optional[int], Optional[Dict[str, str]]]:
    """No default: while unset, secrets aren't judged against an age nobody adopted."""
    raw = (os.environ.get(MAX_AGE_ENV) or "").strip()
    if not raw:
        return None, None
    if raw.isdigit() and 0 < int(raw) <= MAX_SECRET_AGE_DAYS:
        return int(raw), None
    return None, {"operation": f"config {MAX_AGE_ENV}", "type": "ValueError",
                  "message": f"{MAX_AGE_ENV}={raw!r} must be a whole number from 1 to {MAX_SECRET_AGE_DAYS}"}


def owner_attribute_setting() -> Optional[str]:
    return (os.environ.get(OWNER_ENV) or "").strip() or None


# --- pure transforms ---

def _epoch(value: Any) -> Optional[int]:
    """A client attribute holding epoch seconds, as Keycloak stores it; None if absent or not a number."""
    try:
        return int(str(value).strip()) if value not in (None, "") else None
    except ValueError:
        return None


def _iso(seconds: Optional[int]) -> Optional[str]:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if seconds else None


def _attr(client: Dict[str, Any], name: str) -> Any:
    value = (client.get("attributes") or {}).get(name)
    return value[0] if isinstance(value, list) and value else value


def _names(items: Optional[List[Dict[str, Any]]]) -> Optional[List[str]]:
    return sorted({str(i["name"]) for i in items if i.get("name")}) if items is not None else None


def service_account_record(client: Dict[str, Any], realm_roles: Optional[List[Dict[str, Any]]],
                           admin_roles: Optional[List[Dict[str, Any]]], owner_attribute: Optional[str],
                           max_age_days: Optional[int], now: datetime) -> Dict[str, Any]:
    """One service-account client. Never the secret: only its type, age and expiry."""
    authenticator = client.get("clientAuthenticatorType") or "client-secret"
    # True for a secret shared with Keycloak, False for a key or certificate only the client holds, and None for an
    # authenticator this fetcher doesn't know (a newer or custom one), which is never assumed to have no secret.
    shared = True if authenticator in SHARED_SECRET else False if authenticator in KEY_OR_CERTIFICATE else None
    created = _epoch(_attr(client, CREATED_ATTR)) if shared else None
    expires = _epoch(_attr(client, EXPIRES_ATTR)) if shared else None
    age = round((now.timestamp() - created) / 86400, 1) if created else None
    admin_names, realm_names = _names(admin_roles), _names(realm_roles)
    owner = str(_attr(client, owner_attribute) or "").strip() if owner_attribute else None
    over: Optional[bool] = None  # unjudged while no maximum is set, the secret's age is unknown, or the authenticator is
    if max_age_days and shared is False:
        over = False
    elif max_age_days and age is not None:
        over = age > max_age_days
    other_flows = sorted(f for f, on in (("standard", client.get("standardFlowEnabled")),
                                         ("implicit", client.get("implicitFlowEnabled")),
                                         ("direct_access_grants", client.get("directAccessGrantsEnabled"))) if on)
    return {
        "client_id": client.get("clientId"),
        "enabled": bool(client.get("enabled", True)),
        "authenticator": authenticator,
        "shared_secret": shared,
        "secret_created": _iso(created),
        "secret_age_days": age,
        "secret_expires": _iso(expires),
        "rotated_secret_present": bool(_attr(client, ROTATED_ATTR)) if shared else None,
        "authenticator_recognized": shared is not None,
        "secret_over_max_age": over,
        "owner": owner if owner else None,
        "owned": bool(owner) if owner_attribute else None,
        "other_flows": other_flows,
        "realm_roles": realm_names,
        "admin_roles": admin_names,
        "realm_admin": "realm-admin" in admin_names if admin_names is not None else None,
        "privileged": bool(ADMIN_ROLES.intersection(admin_names)) if admin_names is not None else None,
    }


def _count(records: List[Dict[str, Any]], field: str, value: Any = True) -> Optional[int]:
    """Records whose `field` equals `value`; null if any record's field is null."""
    if any(r.get(field) is None for r in records):
        return None
    return sum(1 for r in records if r[field] == value)


def summarize(clients: Optional[List[Dict[str, Any]]], records: Optional[List[Dict[str, Any]]],
              max_age_days: Optional[int], owner_attribute: Optional[str]) -> Dict[str, Any]:
    """Counts over enabled service-account clients; null when the clients could not be read."""
    read = clients is not None and records is not None
    cs, rs = clients or [], [r for r in records or [] if r["enabled"]]
    shared = [r for r in rs if r["shared_secret"]]
    unrecognized = [r for r in rs if r["shared_secret"] is None]
    ages = [r["secret_age_days"] for r in shared if r["secret_age_days"] is not None]
    return {
        "clients_read": read,
        "clients_total": len(cs) if read else None,
        "confidential_clients": sum(1 for c in cs if not c.get("publicClient") and not c.get("bearerOnly")) if read else None,
        "service_account_clients": len(rs) if read else None,
        "service_account_clients_disabled": len(records or []) - len(rs) if read else None,
        # How do they authenticate?
        "service_accounts_by_authenticator": dict(sorted(Counter(r["authenticator"] for r in rs).items())) if read else None,
        "service_accounts_using_shared_secret": len(shared) if read else None,
        "service_accounts_using_key_or_certificate": sum(1 for r in rs if r["authenticator"] in KEY_OR_CERTIFICATE) if read else None,
        "service_accounts_unrecognized_authenticator": len(unrecognized) if read else None,
        # How old are the secrets?
        "max_secret_age_days": max_age_days,
        "service_account_secrets_age_unknown": sum(1 for r in shared if r["secret_age_days"] is None) if read else None,
        "oldest_service_account_secret_days": max(ages) if read and ages else None,
        # An unrecognized authenticator may rest on a secret of unknown age, so it leaves this unjudged.
        "service_account_secrets_over_max_age": _count(shared + unrecognized, "secret_over_max_age") if read and max_age_days else None,
        "service_account_secrets_expiring": sum(1 for r in shared if r["secret_expires"]) if read else None,
        # Who owns them?
        "owner_attribute": owner_attribute,
        "service_accounts_without_owner": _count(rs, "owned", False) if read and owner_attribute else None,
        # What can they do?
        "service_accounts_with_other_flows": sum(1 for r in rs if r["other_flows"]) if read else None,
        "privileged_service_accounts": _count(rs, "privileged") if read else None,
        "service_accounts_with_realm_admin": _count(rs, "realm_admin") if read else None,
    }


# --- collection ---

def collect(client: KeycloakClient, max_age_days: Optional[int], owner_attribute: Optional[str],
            now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    clients = client.get_all("clients", "/clients", role="view-clients")
    if clients is not None and len(clients) > MAX_CLIENTS:
        client._fail("clients", "Too many clients", f"more than {MAX_CLIENTS} clients; nothing judged rather than reading "
                     "part of the realm", "partial_failure")
        clients = None
    records: Optional[List[Dict[str, Any]]] = None
    if clients is not None:
        rm = next((c.get("id") for c in clients if c.get("clientId") == "realm-management"), None)
        refused = {"user": False, "realm": False, "admin": False}

        def read(kind: str, operation: str, path: str, role: str) -> Optional[Any]:
            """A per-client read; once refused for a missing role it isn't repeated for the other clients."""
            if refused[kind]:
                return None
            before = len(client.failure_codes)
            value = client.get(operation, path, role=role)
            if value is None and client.failure_codes[before:] and client.failure_codes[-1] in ("not_authorized", "auth_failed"):
                refused[kind] = True
            return value

        records = []
        for c in clients:
            if not c.get("serviceAccountsEnabled"):
                continue
            cid = quote(str(c.get("id")), safe="")
            user = read("user", "service account user", f"/clients/{cid}/service-account-user", "view-clients")
            uid = quote(str(user.get("id")), safe="") if isinstance(user, dict) and user.get("id") else None
            realm_roles = read("realm", "service account realm roles", f"/users/{uid}/role-mappings/realm/composite",
                               "view-users") if uid else None
            admin_roles = read("admin", "service account realm-management roles",
                               f"/users/{uid}/role-mappings/clients/{quote(rm, safe='')}/composite", "view-users") if uid and rm else None
            records.append(service_account_record(c, realm_roles, admin_roles, owner_attribute, max_age_days, now))
        records.sort(key=lambda r: str(r["client_id"]))
    return {"results": {"service_accounts": records},
            "summary": summarize(clients, records, max_age_days, owner_attribute)}


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    out_dir.mkdir(parents=True, exist_ok=True)
    metadata: Dict[str, Any] = {"datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "api_failures": []}
    max_age, bad = max_age_setting()
    owner_attribute = owner_attribute_setting()
    evidence = {"results": {}, "summary": summarize(None, None, max_age, owner_attribute)}
    code = None
    try:
        settings = settings_from_env()
        metadata.update(realm=settings["realm"], base_url=settings["base_url"])
        client = KeycloakClient(settings["base_url"], settings["realm"], settings["auth_realm"],
                                os.environ["KEYCLOAK_CLIENT_ID"], os.environ["KEYCLOAK_CLIENT_SECRET"])
        evidence = collect(client, max_age, owner_attribute)
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
