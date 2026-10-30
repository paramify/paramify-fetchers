"""Sophos Central REST client: OAuth, tenant resolution, paging and retries."""

from __future__ import annotations

import os
import random
import time
from typing import Any, Callable, Optional

import requests

AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token"
GLOBAL_URL = "https://api.central.sophos.com"
TIMEOUT = 60
MAX_ATTEMPTS = 5
BACKOFF_BASE_S = 1.0
BACKOFF_CAP_S = 30.0
RETRY_STATUSES = {429, 500, 502, 503, 504}


class SophosError(Exception):
    """A failed Sophos call. `code` is one of fetcher_status.STATUS_CODES."""

    def __init__(self, message: str, code: str = "partial_failure", operation: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.operation = operation


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
        self.requested_tenant_id = tenant_id or None
        self.auth_url = auth_url
        self.global_url = global_url.rstrip("/")
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
        self.api_host = self.api_host.rstrip("/")

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
        while True:
            page = self.get("/endpoint/v1/endpoints", "list_endpoints", params)
            endpoints.extend(page.get("items") or [])
            pages = page.get("pages") or {}
            if reported_total is None and isinstance(pages.get("items"), int):
                reported_total = pages["items"]
            next_key = pages.get("nextKey")
            if not next_key:
                break
            params = {"view": "full", "pageFromKey": next_key}
            if isinstance(pages.get("maxSize"), int):
                params["pageSize"] = pages["maxSize"]
        return _dedupe(endpoints), reported_total

    def list_policies(self, policy_type: str) -> tuple[list[dict], Optional[int]]:
        """Every policy of one type, all pages. Returns (policies, Sophos's own total)."""
        policies: list[dict] = []
        reported_total: Optional[int] = None
        page_no, last_page = 1, 1
        while page_no <= last_page:
            params: dict[str, Any] = {"policyType": policy_type, "page": page_no}
            if page_no == 1:
                params["pageTotal"] = "true"
            page = self.get("/endpoint/v1/policies", f"list_policies:{policy_type}", params)
            policies.extend(page.get("items") or [])
            pages = page.get("pages") or {}
            if page_no == 1:
                last_page = pages.get("total") if isinstance(pages.get("total"), int) else 1
                reported_total = pages.get("items") if isinstance(pages.get("items"), int) else None
            page_no += 1
        return _dedupe(policies), reported_total

    def _authenticate(self) -> None:
        try:
            resp = self.session.post(
                self.auth_url,
                data={"grant_type": "client_credentials", "client_id": self.client_id,
                      "client_secret": self.client_secret, "scope": "token"},
                timeout=TIMEOUT,
            )
        except requests.RequestException as e:
            raise SophosError(f"could not reach the Sophos token service: {e}", "target_unreachable", "oauth_token") from e
        if resp.status_code != 200:
            # Sophos removes expired credentials without warning, so name that cause.
            raise SophosError(
                f"Sophos rejected the API credential (HTTP {resp.status_code}); it may be wrong or expired",
                "auth_failed", "oauth_token",
            )
        self.token = (resp.json() or {}).get("access_token")
        if not self.token:
            raise SophosError("the Sophos token response had no access_token", "auth_failed", "oauth_token")

    def _request(self, method: str, url: str, operation: str, *, params: Optional[dict] = None,
                 headers: Optional[dict] = None, _reauthed: bool = False) -> dict:
        last_error = ""
        for attempt in range(MAX_ATTEMPTS):
            try:
                resp = self.session.request(
                    method, url, params=params, timeout=TIMEOUT,
                    headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json", **(headers or {})},
                )
            except requests.RequestException as e:
                last_error = f"could not reach Sophos: {e}"
                self._backoff(attempt)
                continue
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
            if resp.status_code in RETRY_STATUSES:
                last_error = f"HTTP {resp.status_code}"
                self._backoff(attempt)
                continue
            raise SophosError(f"{operation}: Sophos returned HTTP {resp.status_code}: {resp.text[:300]}",
                              "partial_failure", operation)
        code = "rate_limited" if last_error == "HTTP 429" else "target_unreachable"
        raise SophosError(f"{operation}: gave up after {MAX_ATTEMPTS} attempts ({last_error})", code, operation)

    def _backoff(self, attempt: int) -> None:
        if attempt < MAX_ATTEMPTS - 1:
            self.sleep(random.uniform(0, min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2 ** attempt)))


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
