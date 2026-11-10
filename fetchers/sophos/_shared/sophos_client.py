"""Sophos Central REST client: OAuth, tenant resolution, paging and retries."""

from __future__ import annotations

import ipaddress
import os
import random
import re
import time
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

import requests

AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token"
GLOBAL_URL = "https://api.central.sophos.com"
TIMEOUT = 60
# Sophos allows 100 calls a minute per credential, so the retries must wait out
# a full minute: 5 + 10 + 20 + 40 + 60 seconds at most, never less than half.
MAX_ATTEMPTS = 6
BACKOFF_BASE_S = 5.0
BACKOFF_CAP_S = 60.0
RETRY_STATUSES = {429, 500, 502, 503, 504}
# Key-based paging stops at this many pages (50 endpoints a page by default).
MAX_PAGES = 10_000
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class SophosError(Exception):
    """A failed Sophos call. `code` is one of fetcher_status.STATUS_CODES."""

    def __init__(self, message: str, code: str = "partial_failure", operation: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.operation = operation


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def sophos_url(raw: str, name: str) -> str:
    """The URL, if it is https on sophos.com or a subdomain of it; http only on loopback, for a test double.

    The client secret and the bearer token go to these hosts, so any other value is bad_config.
    """
    parts = urlsplit((raw or "").strip())
    host = (parts.hostname or "").lower()
    if not host:
        raise SophosError(f"{name} {raw!r} is not a URL", "bad_config", "configuration")
    if parts.username or parts.password:
        raise SophosError(f"{name} must not carry credentials", "bad_config", "configuration")
    if parts.scheme == "http" and _loopback(host):
        return raw.strip().rstrip("/")
    if parts.scheme != "https":
        raise SophosError(f"{name} must use https", "bad_config", "configuration")
    if host != "sophos.com" and not host.endswith(".sophos.com"):
        raise SophosError(f"{name} host {host} is not a Sophos host (sophos.com)", "bad_config", "configuration")
    return raw.strip().rstrip("/")


class SophosClient:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: Optional[str] = None,
        auth_url: str = AUTH_URL,
        global_url: str = GLOBAL_URL,
        session: Optional[requests.Session] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        if tenant_id and not UUID.match(tenant_id):
            raise SophosError(f"SOPHOS_TENANT_ID {tenant_id!r} is not a tenant id (a UUID)", "bad_config",
                              "configuration")
        self.requested_tenant_id = tenant_id or None
        self.auth_url = sophos_url(auth_url, "SOPHOS_AUTH_URL")
        self.global_url = sophos_url(global_url, "SOPHOS_GLOBAL_URL")
        self.session = session or requests.Session()
        self.sleep = sleep
        self.token: Optional[str] = None
        self.id_type: Optional[str] = None
        self.tenant_id: Optional[str] = None
        self.api_host: Optional[str] = None
        self.data_region: Optional[str] = None

    @classmethod
    def from_env(cls) -> "SophosClient":
        client_id = os.environ.get("SOPHOS_CLIENT_ID", "").strip()
        client_secret = os.environ.get("SOPHOS_CLIENT_SECRET", "").strip()
        missing = [n for n, v in (("SOPHOS_CLIENT_ID", client_id), ("SOPHOS_CLIENT_SECRET", client_secret)) if not v]
        if missing:
            raise SophosError(f"{' and '.join(missing)} not set", "bad_config", "configuration")
        return cls(
            client_id,
            client_secret,
            tenant_id=os.environ.get("SOPHOS_TENANT_ID", "").strip() or None,
            auth_url=os.environ.get("SOPHOS_AUTH_URL") or AUTH_URL,
            global_url=os.environ.get("SOPHOS_GLOBAL_URL") or GLOBAL_URL,
        )

    def connect(self) -> None:
        """Get a token, then find the tenant and the data-region host to call."""
        self._authenticate()
        who = self._request("GET", f"{self.global_url}/whoami/v1", "whoami")
        self.id_type = who.get("idType")
        if self.id_type == "tenant":
            self.tenant_id = who.get("id")
            self.api_host = (who.get("apiHosts") or {}).get("dataRegion")
            if self.requested_tenant_id and self.requested_tenant_id != self.tenant_id:
                raise SophosError(
                    f"the credential belongs to tenant {self.tenant_id}, not SOPHOS_TENANT_ID {self.requested_tenant_id}",
                    "bad_config", "whoami",
                )
        elif self.id_type in ("partner", "organization"):
            if not self.requested_tenant_id:
                raise SophosError(
                    f"the credential is {self.id_type}-level; set tenant_id on the target to pick a tenant",
                    "bad_config", "whoami",
                )
            header = "X-Partner-ID" if self.id_type == "partner" else "X-Organization-ID"
            tenant = self._request(
                "GET", f"{self.global_url}/{self.id_type}/v1/tenants/{self.requested_tenant_id}",
                f"{self.id_type}_tenant_lookup", headers={header: who.get("id", "")},
            )
            self.tenant_id = tenant.get("id") or self.requested_tenant_id
            self.api_host = tenant.get("apiHost")
            self.data_region = tenant.get("dataRegion")
        else:
            raise SophosError(f"unsupported Sophos credential type {self.id_type!r}", "bad_config", "whoami")
        if not self.tenant_id or not self.api_host:
            raise SophosError("Sophos did not return a tenant id and data-region host", "internal_error", "whoami")
        # The bearer token goes to this host, and it comes from a response, so check it as the config URLs are.
        self.api_host = sophos_url(self.api_host, "the data-region host from Sophos")

    def get(self, path: str, operation: str, params: Optional[dict] = None) -> dict:
        """GET a tenant API path on the tenant's data-region host."""
        return self._request(
            "GET", f"{self.api_host}{path}", operation,
            params=params, headers={"X-Tenant-ID": self.tenant_id or ""},
        )

    def list_endpoints(self) -> tuple[list[dict], Optional[int]]:
        """Every endpoint, full view, all pages. Returns (endpoints, Sophos's own total)."""
        params: dict[str, Any] = {"view": "full", "pageTotal": "true"}
        endpoints: list[dict] = []
        reported_total: Optional[int] = None
        used_keys: set = set()
        while True:
            page = self.get("/endpoint/v1/endpoints", "list_endpoints", params)
            endpoints.extend(page.get("items") or [])
            pages = page.get("pages") or {}
            if reported_total is None and isinstance(pages.get("items"), int):
                reported_total = pages["items"]
            next_key = pages.get("nextKey")
            if not next_key:
                break
            if next_key in used_keys:
                raise SophosError(f"list_endpoints: Sophos returned the page key {next_key!r} twice; paging stopped",
                                  "partial_failure", "list_endpoints")
            if len(used_keys) + 1 >= MAX_PAGES:
                raise SophosError(f"list_endpoints: more than {MAX_PAGES} pages; paging stopped",
                                  "partial_failure", "list_endpoints")
            used_keys.add(next_key)
            params = {"view": "full", "pageFromKey": next_key}
            if isinstance(pages.get("maxSize"), int):
                params["pageSize"] = pages["maxSize"]
        return _dedupe(endpoints), reported_total

    def list_policies(self, policy_type: str) -> tuple[list[dict], Optional[int]]:
        """Every policy of one type, all pages. Returns (policies, Sophos's own total)."""
        policies: list[dict] = []
        reported_total: Optional[int] = None
        last_page: Optional[int] = None  # None: Sophos gave no page total, so read until a short or empty page
        page_no = 1
        while last_page is None or page_no <= last_page:
            if page_no > MAX_PAGES:
                raise SophosError(f"list_policies:{policy_type}: more than {MAX_PAGES} pages; paging stopped",
                                  "partial_failure", f"list_policies:{policy_type}")
            params: dict[str, Any] = {"policyType": policy_type, "page": page_no}
            if page_no == 1:
                params["pageTotal"] = "true"
            page = self.get("/endpoint/v1/policies", f"list_policies:{policy_type}", params)
            items = page.get("items") or []
            policies.extend(items)
            pages = page.get("pages") or {}
            if page_no == 1:
                last_page = pages.get("total") if isinstance(pages.get("total"), int) else None
                reported_total = pages.get("items") if isinstance(pages.get("items"), int) else None
            if last_page is None:
                max_size = pages.get("maxSize")
                if not items or (isinstance(max_size, int) and len(items) < max_size):
                    break
            page_no += 1
        return _dedupe(policies), reported_total

    def _authenticate(self) -> None:
        resp = self._send(
            "POST", self.auth_url, "oauth_token",
            data={"grant_type": "client_credentials", "client_id": self.client_id,
                  "client_secret": self.client_secret, "scope": "token"},
        )
        if resp.status_code in (400, 401):
            # Sophos removes expired credentials without warning, so name that cause.
            raise SophosError(
                f"Sophos rejected the API credential (HTTP {resp.status_code}); it may be wrong or expired",
                "auth_failed", "oauth_token",
            )
        if resp.status_code != 200:
            raise SophosError(f"oauth_token: the Sophos token service returned HTTP {resp.status_code}",
                              "target_unreachable", "oauth_token")
        self.token = (resp.json() or {}).get("access_token")
        if not self.token:
            raise SophosError("the Sophos token response had no access_token", "auth_failed", "oauth_token")

    def _request(self, method: str, url: str, operation: str, *, params: Optional[dict] = None,
                 headers: Optional[dict] = None, _reauthed: bool = False) -> dict:
        resp = self._send(
            method, url, operation, params=params,
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json", **(headers or {})},
        )
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 401 and not _reauthed:
            self._authenticate()
            return self._request(method, url, operation, params=params, headers=headers, _reauthed=True)
        if resp.status_code == 401:
            raise SophosError(f"{operation}: Sophos rejected the token (HTTP 401)", "auth_failed", operation)
        if resp.status_code == 403:
            raise SophosError(
                f"{operation}: the API credential is not allowed this read (HTTP 403); it needs the Service Principal Read-Only role",
                "not_authorized", operation,
            )
        raise SophosError(f"{operation}: Sophos returned HTTP {resp.status_code}: {resp.text[:300]}",
                          "partial_failure", operation)

    def _send(self, method: str, url: str, operation: str, **kwargs: Any) -> Any:
        """One call, retried on a network error, 429 or 5xx. Returns the first other response."""
        last_error = ""
        for attempt in range(MAX_ATTEMPTS):
            try:
                resp = self.session.request(method, url, timeout=TIMEOUT, **kwargs)
            except requests.RequestException as e:
                last_error = f"could not reach Sophos: {e}"
                self._backoff(attempt)
                continue
            if resp.status_code not in RETRY_STATUSES:
                return resp
            last_error = f"HTTP {resp.status_code}"
            self._backoff(attempt)
        code = "rate_limited" if last_error == "HTTP 429" else "target_unreachable"
        raise SophosError(f"{operation}: gave up after {MAX_ATTEMPTS} attempts ({last_error})", code, operation)

    def _backoff(self, attempt: int) -> None:
        if attempt < MAX_ATTEMPTS - 1:
            delay = min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2 ** attempt)
            self.sleep(delay / 2 + random.uniform(0, delay / 2))


def _dedupe(items: list[dict]) -> list[dict]:
    """Drop repeats by id; key-based paging can return an item twice while data changes."""
    seen: set = set()
    out = []
    for item in items:
        key = item.get("id")
        if key is not None:
            if key in seen:
                continue
            seen.add(key)
        out.append(item)
    return out
