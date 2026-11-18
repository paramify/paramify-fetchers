"""Keycloak events: whether sign-in and admin events are actually stored, and what they show over a window.

keycloak_realm_security reports whether event storage is enabled; this fetcher reads the stored events themselves,
GET only, with the realm-management role view-events. It copies only event types, times, client IDs and error codes.
Usernames, user IDs, IP addresses, token IDs and admin-event representations (which can hold credentials and personal
details) are never copied; the one field read from a representation is `enabled`, to count users disabled.

Stored in Keycloak is not delivered to a SIEM: that needs its own evidence.
"""

import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
from fetcher_status import report_failure  # noqa: E402
from keycloak_client import KeycloakAuthError, KeycloakClient, settings_from_env  # noqa: E402

NAME = "keycloak_admin_events"
OUTPUT = "keycloak_admin_events.json"
LOOKBACK_ENV = "KEYCLOAK_EVENTS_LOOKBACK_DAYS"
DEFAULT_LOOKBACK_DAYS = 7
MAX_LOOKBACK_DAYS = 90
PAGE = 500
MAX_EVENTS = 20000  # per stream; more in the window leaves that stream's counts null rather than undercounted
# A sign-in refused because the account is locked or disabled, not because the credentials were wrong.
BLOCKED_ERRORS = frozenset({"user_temporarily_disabled", "user_disabled"})
LOCKOUT_TYPES = frozenset({"USER_DISABLED_BY_TEMPORARY_LOCKOUT", "USER_DISABLED_BY_PERMANENT_LOCKOUT"})
# Admin changes to access, clients, realm settings, identity providers, sign-in flows and federation.
PRIVILEGED_RESOURCES = frozenset({"REALM_ROLE_MAPPING", "CLIENT_ROLE_MAPPING", "GROUP_MEMBERSHIP", "REALM_ROLE", "CLIENT_ROLE",
                                  "CLIENT", "CLIENT_SCOPE", "REALM", "IDENTITY_PROVIDER", "IDENTITY_PROVIDER_MAPPER",
                                  "AUTH_FLOW", "AUTH_EXECUTION", "AUTH_EXECUTION_FLOW", "REQUIRED_ACTION", "COMPONENT",
                                  "USER_FEDERATION_PROVIDER", "REALM_SCOPE_MAPPING", "CLIENT_SCOPE_MAPPING"})

logger = logging.getLogger(NAME)


# --- pure transforms ---

def _login_events_saved(config: Dict[str, Any]) -> Optional[bool]:
    """True if event storage is on and LOGIN and LOGIN_ERROR are saved types; null when the saved types are missing."""
    if not config.get("eventsEnabled"):
        return False
    saved = config.get("enabledEventTypes")
    return {"LOGIN", "LOGIN_ERROR"}.issubset(saved) if isinstance(saved, list) else None


def _iso(ms: Optional[int]) -> Optional[str]:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ms else None


def _hours_since(ms: Optional[int], now: datetime) -> Optional[float]:
    return max(0.0, round((now - datetime.fromtimestamp(ms / 1000, tz=timezone.utc)).total_seconds() / 3600, 1)) if ms else None


def login_record(e: Dict[str, Any]) -> Dict[str, Any]:
    """Type, time, client and error only: never the user, IP address, session or token details."""
    return {"time": _iso(e.get("time")), "type": e.get("type"), "client_id": e.get("clientId"), "error": e.get("error")}


def _disables_user(e: Dict[str, Any]) -> bool:
    """An UPDATE to a user whose representation sets enabled to false; `enabled` is the only field read from it."""
    if e.get("operationType") != "UPDATE" or e.get("resourceType") != "USER" or not e.get("representation"):
        return False
    try:
        return json.loads(e["representation"]).get("enabled") is False
    except (ValueError, AttributeError):
        return False


def admin_record(e: Dict[str, Any]) -> Dict[str, Any]:
    """Operation, resource type, time and the acting client only: never the representation, user or IP address."""
    return {"time": _iso(e.get("time")), "operation": e.get("operationType"), "resource_type": e.get("resourceType"),
            "acting_client_id": (e.get("authDetails") or {}).get("clientId"),
            "privileged": e.get("resourceType") in PRIVILEGED_RESOURCES, "user_disabled": _disables_user(e)}


def summarize(config: Optional[Dict[str, Any]], logins: Optional[List[Dict[str, Any]]], admins: Optional[List[Dict[str, Any]]],
              lookback_days: int, now: datetime, own_client_id: Optional[str] = None) -> Dict[str, Any]:
    """Counts over the window; a stream that could not be read (or was too large to read whole) is null, not 0.
    Each run's own token request is a CLIENT_LOGIN event, so recency leaves out this fetcher's client: otherwise the
    newest event would always be the fetcher itself."""
    lg, ad = logins is not None, admins is not None
    logins, admins = logins or [], admins or []
    failed = [e for e in logins if e.get("type") == "LOGIN_ERROR"]
    others = [e for e in logins if not (own_client_id and e.get("clientId") == own_client_id)]
    newest_login = max((e.get("time") or 0 for e in others), default=0) or None
    newest_admin = max((e.get("time") or 0 for e in admins), default=0) or None
    return {
        "lookback_days": lookback_days,
        # Is storage on?
        # Keycloak stores only saved event types: sign-ins are stored only if LOGIN and LOGIN_ERROR are saved.
        "login_events_storage_enabled": _login_events_saved(config) if config is not None else None,
        "admin_events_storage_enabled": bool(config.get("adminEventsEnabled")) if config is not None else None,
        "admin_events_details_enabled": bool(config.get("adminEventsDetailsEnabled")) if config is not None else None,
        # Sign-ins
        "login_events": len(logins) if lg else None,
        "logins_succeeded": sum(1 for e in logins if e.get("type") == "LOGIN") if lg else None,
        "logins_failed": sum(1 for e in failed if e.get("error") not in BLOCKED_ERRORS) if lg else None,
        "logins_blocked": sum(1 for e in failed if e.get("error") in BLOCKED_ERRORS) if lg else None,
        "lockouts": sum(1 for e in logins if e.get("type") in LOCKOUT_TYPES) if lg else None,
        "collector_token_requests": len(logins) - len(others) if lg else None,
        "login_event_types": dict(sorted(Counter(e.get("type") for e in logins).items())) if lg else None,
        "newest_login_event": _iso(newest_login) if lg else None,
        "hours_since_newest_login_event": _hours_since(newest_login, now) if lg else None,
        # Admin changes
        "admin_events": len(admins) if ad else None,
        "admin_privileged_changes": sum(1 for e in admins if e.get("resourceType") in PRIVILEGED_RESOURCES) if ad else None,
        "users_created": sum(1 for e in admins if (e.get("operationType"), e.get("resourceType")) == ("CREATE", "USER")) if ad else None,
        "users_disabled": sum(1 for e in admins if _disables_user(e)) if ad else None,
        "credential_resets": sum(1 for e in admins if e.get("resourceType") == "USER" and e.get("operationType") == "ACTION"
                                 and str(e.get("resourcePath") or "").endswith("/reset-password")) if ad else None,
        "role_grants": sum(1 for e in admins if e.get("operationType") == "CREATE"
                           and e.get("resourceType") in ("REALM_ROLE_MAPPING", "CLIENT_ROLE_MAPPING")) if ad else None,
        "admin_operations": dict(sorted(Counter(f"{e.get('operationType')} {e.get('resourceType')}" for e in admins).items())) if ad else None,
        "newest_admin_event": _iso(newest_admin) if ad else None,
        "hours_since_newest_admin_event": _hours_since(newest_admin, now) if ad else None,
    }


# --- collection ---

def read_stream(client: KeycloakClient, operation: str, path: str, since: datetime) -> Optional[List[Dict[str, Any]]]:
    """Every event since `since`, newest first, page by page; None when a page can't be read or the window is too large."""
    out: List[Dict[str, Any]] = []
    cutoff = since.timestamp() * 1000
    while True:
        page = client.get(operation, path, {"dateFrom": since.strftime("%Y-%m-%d"), "first": str(len(out)), "max": str(PAGE)},
                          role="view-events")
        if page is None:
            return None
        out.extend(e for e in page if (e.get("time") or 0) >= cutoff)
        if len(page) < PAGE:
            return out
        if len(out) >= MAX_EVENTS:
            client._fail(operation, "Too many events", f"more than {MAX_EVENTS} events in the window; counts left null rather "
                         "than undercounted. Shorten the lookback.", "partial_failure")
            return None


def lookback_setting() -> Tuple[int, Optional[Dict[str, str]]]:
    raw = (os.environ.get(LOOKBACK_ENV) or "").strip()
    if not raw:
        return DEFAULT_LOOKBACK_DAYS, None
    if raw.isdigit() and 0 < int(raw) <= MAX_LOOKBACK_DAYS:
        return int(raw), None
    return DEFAULT_LOOKBACK_DAYS, {"operation": f"config {LOOKBACK_ENV}", "type": "ValueError",
                                   "message": f"{LOOKBACK_ENV}={raw!r} must be a whole number from 1 to {MAX_LOOKBACK_DAYS}"}


def collect(client: KeycloakClient, lookback_days: int, now: Optional[datetime] = None, own_client_id: Optional[str] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=lookback_days)
    config = client.get("events configuration", "/events/config", role="view-events")
    logins = read_stream(client, "login events", "/events", since)
    admins = read_stream(client, "admin events", "/admin-events", since)
    results = {"window_start": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "login_events": [login_record(e) for e in logins] if logins is not None else None,
               "admin_events": [admin_record(e) for e in admins] if admins is not None else None}
    return {"results": results, "summary": summarize(config, logins, admins, lookback_days, now, own_client_id)}


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    out_dir.mkdir(parents=True, exist_ok=True)
    metadata: Dict[str, Any] = {"datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "api_failures": []}
    lookback, bad = lookback_setting()
    evidence = {"results": {}, "summary": summarize(None, None, None, lookback, datetime.now(timezone.utc))}
    code = None
    try:
        settings = settings_from_env()
        metadata.update(realm=settings["realm"], base_url=settings["base_url"])
        client = KeycloakClient(settings["base_url"], settings["realm"], settings["auth_realm"],
                                os.environ["KEYCLOAK_CLIENT_ID"], os.environ["KEYCLOAK_CLIENT_SECRET"])
        evidence = collect(client, lookback, own_client_id=os.environ["KEYCLOAK_CLIENT_ID"])
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
