#!/usr/bin/env python3
"""Read-only Keycloak Admin REST API client shared by the keycloak fetchers.

Authenticates with the OAuth2 client-credentials grant against the auth realm's token endpoint, then issues GETs
under /admin/realms/{realm}. Only GET is exposed: the fetchers read configuration and never change it.

Collection-failure convention (docs/authoring_fetcher_guide.md, step 3): a failed GET is recorded in `api_failures`
and returns None, so one bad endpoint does not lose the rest of the evidence; the fetcher exits non-zero when
`api_failures` is non-empty. A failed token request raises, since nothing can be read without a token.
"""

import logging
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
MAX_RETRIES = 3
TIMEOUT = 30
CODES = {401: "auth_failed", 403: "not_authorized", 429: "rate_limited"}

logger = logging.getLogger("keycloak_client")


class KeycloakAuthError(RuntimeError):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


def settings_from_env() -> Dict[str, str]:
    """base_url, realm and auth_realm from the category config; client credentials from the declared secrets."""
    missing = [n for n in ("KEYCLOAK_BASE_URL", "KEYCLOAK_REALM", "KEYCLOAK_CLIENT_ID", "KEYCLOAK_CLIENT_SECRET") if not os.environ.get(n)]
    if missing:
        raise KeycloakAuthError(f"Missing required setting: {', '.join(missing)}", "bad_config")
    realm = os.environ["KEYCLOAK_REALM"]
    return {"base_url": os.environ["KEYCLOAK_BASE_URL"].rstrip("/"), "realm": realm,
            "auth_realm": os.environ.get("KEYCLOAK_AUTH_REALM") or realm}


class KeycloakClient:
    def __init__(self, base_url: str, realm: str, auth_realm: str, client_id: str, client_secret: str, session: Any = None):
        self.base_url, self.realm, self.auth_realm = base_url.rstrip("/"), realm, auth_realm
        self._client_id, self._client_secret = client_id, client_secret
        self.session = session or requests.Session()
        self.api_failures: List[Dict[str, Any]] = []
        self.failure_codes: List[str] = []
        self._token: Optional[str] = None
        self._expires = 0.0

    def _authenticate(self) -> str:
        if self._token and time.time() < self._expires - 30:
            return self._token
        url = f"{self.base_url}/realms/{quote(self.auth_realm, safe='')}/protocol/openid-connect/token"
        try:
            response = self.session.post(url, data={"grant_type": "client_credentials", "client_id": self._client_id,
                                                    "client_secret": self._client_secret}, timeout=TIMEOUT)
        except requests.RequestException as exc:
            raise KeycloakAuthError(f"Keycloak token request failed: {type(exc).__name__}", "target_unreachable") from exc
        if response.status_code == 404:
            # Keycloak answers 404 when the realm doesn't exist: a wrong realm or base URL, not bad credentials.
            raise KeycloakAuthError(f"Keycloak token endpoint answered 404: check the base URL and that realm "
                                    f"{self.auth_realm!r} exists", "bad_config")
        if response.status_code != 200:
            raise KeycloakAuthError(f"Keycloak token request answered {response.status_code}", CODES.get(response.status_code, "auth_failed"))
        try:
            body = response.json()
            token = body["access_token"]
        except (ValueError, KeyError, TypeError) as exc:
            # Such as an HTML page from a proxy in front of Keycloak.
            raise KeycloakAuthError(f"Keycloak token response had no access token ({type(exc).__name__}); "
                                    "check the base URL", "auth_failed") from exc
        self._token, self._expires = token, time.time() + float(body.get("expires_in") or 60)
        return self._token

    def get(self, operation: str, path: str, params: Optional[Dict[str, str]] = None, role: Optional[str] = None) -> Any:
        """GET /admin/realms/{realm}{path}; None (and a recorded failure) when it cannot be read. `role` is the
        realm-management role Keycloak checks for this call; a 403 names it, so a run shows which role is missing."""
        url = f"{self.base_url}/admin/realms/{quote(self.realm, safe='')}{path}"
        response = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.get(url, params=params, timeout=TIMEOUT, allow_redirects=False,
                                            headers={"Authorization": f"Bearer {self._authenticate()}", "Accept": "application/json"})
            except requests.RequestException as exc:
                if attempt == MAX_RETRIES:
                    return self._fail(operation, type(exc).__name__, str(exc), "target_unreachable")
                time.sleep(min(2 ** attempt, 30))
                continue
            if response.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                time.sleep(min(2 ** attempt, 30))
                continue
            break
        if response.status_code != 200:
            detail = (response.text or "")[:300]
            if response.status_code == 403 and role:
                detail = f"needs the role {role} {self.role_holder()}. {detail}".strip()
            elif response.status_code == 401:
                # Keycloak 26.8.2 (CVE-2026-19688) accepts admin API tokens only with the admin API audience, which the
                # built-in kc-admin-api client scope adds; a client created for a service account doesn't get it.
                detail = ("Keycloak refused the token. On Keycloak 26.8.2 and later, assign the built-in kc-admin-api client "
                          f"scope to this client as a default scope. {detail}").strip()
            return self._fail(operation, f"HTTP {response.status_code}", detail, CODES.get(response.status_code, "partial_failure"))
        try:
            return response.json()
        except ValueError:
            # A 200 that isn't JSON, such as an HTML page from a proxy in front of Keycloak.
            return self._fail(operation, "ValueError", "response was not JSON; check the base URL", "partial_failure")

    def role_holder(self) -> str:
        """Where the needed role lives: realm-management in the target realm, or <realm>-realm in master for an account
        in master (Keycloak's realm-specific admin roles)."""
        if self.auth_realm == self.realm:
            return "of the realm-management client"
        return f"of the {self.realm}-realm client in the {self.auth_realm} realm"

    def get_all(self, operation: str, path: str, role: Optional[str] = None, page: int = 100) -> Optional[List[Any]]:
        """Every item of a list endpoint, page by page with first and max; None when any page can't be read."""
        items: List[Any] = []
        while True:
            batch = self.get(operation, path, {"first": str(len(items)), "max": str(page)}, role=role)
            if batch is None:
                return None
            items.extend(batch)
            if len(batch) < page:
                return items

    def flow_executions(self, alias: str) -> Optional[List[Dict[str, Any]]]:
        return self.get(f"authentication flow executions ({alias})", f"/authentication/flows/{quote(alias, safe='')}/executions",
                        role="view-realm")

    def _fail(self, operation: str, kind: str, message: str, code: str) -> None:
        self.api_failures.append({"operation": operation, "type": kind, "message": message})
        self.failure_codes.append(code)
        logger.error("%s failed: %s", operation, kind)
        return None
