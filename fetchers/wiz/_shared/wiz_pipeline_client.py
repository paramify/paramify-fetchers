#!/usr/bin/env python3
"""
Shared Wiz API client for the wiz fetcher category.

Ported from paramify/legacy-evidence-fetchers fetchers/wiz/. What changed in the
port, and why:

- The fetchers no longer upload. They write the report into EVIDENCE_DIR
  (<run>/issue-reports/) and exit; uploaders/paramify_issues sends it into the
  assessment's pipeline.
- DELTA_MODE is gone. A delta file lists only rows that changed since the last
  run, and a pipeline cycle that closes after it auto-closes every open issue the
  delta did not mention — i.e. nearly all of them. Every run is a full export.
- No state.json beside the script. The Reports fetcher finds its Wiz report by
  name instead (or takes report_id from config), so a fresh checkout or a CI
  runner behaves the same as the machine that created the report.
- Hosts are checked before the bearer token or client secret is sent anywhere:
  the auth URL must be one of Wiz's token endpoints, and the GraphQL endpoint and
  report download URL must be https on a Wiz domain. http is allowed for
  localhost only, for a test double.

Auth: OAuth2 client credentials (WIZ_CLIENT_ID / WIZ_CLIENT_SECRET) exchanged at
WIZ_AUTH_URL for a bearer token used against WIZ_API_ENDPOINT (GraphQL).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger("wiz_client")

# Wiz token endpoints (commercial, legacy gov, and Wiz for Gov). Same list the
# legacy fetchers enforced.
AUTH_URLS = frozenset({
    "https://auth.app.wiz.io/oauth/token",
    "https://auth.gov.wiz.io/oauth/token",
    "https://auth.app.wiz.us/oauth/token",
})
_WIZ_DOMAINS = (".wiz.io", ".wiz.us")
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")

RETRYABLE_STATUS = (429, 500, 502, 503, 504)
MAX_RETRIES = int(os.environ.get("WIZ_MAX_RETRIES", "5"))
RETRY_SECONDS = float(os.environ.get("WIZ_RETRY_SECONDS", "2"))
MAX_BACKOFF = 60.0
TIMEOUT = (
    float(os.environ.get("WIZ_CONNECT_TIMEOUT", "10")),
    float(os.environ.get("WIZ_READ_TIMEOUT", "120")),
)
USER_AGENT = "Paramify-WizIntegration-0.2"


class WizError(RuntimeError):
    """A Wiz call failed. `code` is a fetcher_status code."""

    def __init__(self, message: str, code: str = "internal_error"):
        super().__init__(message)
        self.code = code


def _is_local(url: str) -> bool:
    p = urlparse(url)
    return p.scheme in ("http", "https") and (p.hostname or "") in _LOCAL_HOSTS


def check_auth_url(url: str) -> None:
    if url in AUTH_URLS or _is_local(url):
        return
    raise WizError(
        f"WIZ_AUTH_URL {url!r} is not a Wiz token endpoint "
        f"(expected one of {', '.join(sorted(AUTH_URLS))})", "bad_config")


def check_wiz_url(url: str, what: str) -> None:
    """https on a Wiz domain, or localhost (test double). Called before any
    credential goes to the URL."""
    if _is_local(url):
        return
    p = urlparse(url)
    host = p.hostname or ""
    if p.scheme != "https" or not host.endswith(_WIZ_DOMAINS):
        raise WizError(f"{what} {url!r} must be https on a Wiz domain", "bad_config")


def check_download_url(url: str) -> None:
    """The report's presigned URL. Wiz hands back an S3 (or Wiz) https URL; the
    bearer token is never sent to it, but refuse plaintext all the same."""
    if _is_local(url):
        return
    if urlparse(url).scheme != "https":
        raise WizError("Wiz returned a non-https report download URL", "internal_error")


class WizClient:
    def __init__(self, client_id: str, client_secret: str, auth_url: str, api_endpoint: str):
        check_auth_url(auth_url)
        check_wiz_url(api_endpoint, "WIZ_API_ENDPOINT")
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_url = auth_url
        self.api_endpoint = api_endpoint
        self.session = requests.Session()
        self.token: Optional[str] = None

    @classmethod
    def from_env(cls) -> "WizClient":
        missing = [v for v in ("WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET", "WIZ_AUTH_URL",
                               "WIZ_API_ENDPOINT") if not os.environ.get(v)]
        if missing:
            raise WizError(f"{', '.join(missing)} not set", "bad_config")
        return cls(os.environ["WIZ_CLIENT_ID"], os.environ["WIZ_CLIENT_SECRET"],
                   os.environ["WIZ_AUTH_URL"], os.environ["WIZ_API_ENDPOINT"])

    # -- transport ------------------------------------------------------- #
    def _post(self, url: str, what: str, **kwargs) -> requests.Response:
        """POST with exponential backoff on network errors and transient statuses."""
        attempt = 0
        while True:
            try:
                r = self.session.post(url, timeout=TIMEOUT, **kwargs)
            except requests.RequestException as e:
                problem = f"network error ({e.__class__.__name__})"
            else:
                if r.status_code not in RETRYABLE_STATUS:
                    return r
                problem = f"HTTP {r.status_code}"
            if attempt >= MAX_RETRIES:
                code = "rate_limited" if problem == "HTTP 429" else "target_unreachable"
                raise WizError(f"{what}: gave up after {attempt + 1} attempts ({problem})", code)
            delay = min(RETRY_SECONDS * (2 ** attempt), MAX_BACKOFF)
            logger.warning("%s failed (%s); retrying in %.1fs", what, problem, delay)
            time.sleep(delay)
            attempt += 1

    def authenticate(self) -> None:
        r = self._post(
            self.auth_url, "Wiz authentication",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"grant_type": "client_credentials", "audience": "wiz-api",
                  "client_id": self.client_id, "client_secret": self.client_secret},
        )
        if r.status_code in (400, 401, 403):
            # Body is not echoed: an auth error body can repeat the client id.
            raise WizError(f"Wiz rejected the client credentials (HTTP {r.status_code})",
                           "auth_failed")
        if r.status_code != 200:
            raise WizError(f"Wiz authentication failed (HTTP {r.status_code})", "auth_failed")
        token = (r.json() or {}).get("access_token")
        if not token:
            raise WizError("Wiz authentication returned no access_token", "auth_failed")
        self.token = token

    def query(self, gql: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        if not self.token:
            self.authenticate()
        r = self._post(
            self.api_endpoint, "Wiz GraphQL query",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.token}", "User-Agent": USER_AGENT},
            json={"query": gql, "variables": variables},
        )
        if r.status_code in (401, 403):
            raise WizError(f"Wiz refused the query (HTTP {r.status_code}) — check the "
                           f"service account's scopes", "not_authorized")
        if r.status_code != 200:
            raise WizError(f"Wiz query failed (HTTP {r.status_code}): {r.text[:300]}",
                           "partial_failure")
        body = r.json() or {}
        if body.get("errors"):
            # GraphQL errors with data present still mean an incomplete answer.
            raise WizError(f"Wiz GraphQL errors: {str(body['errors'])[:500]}", "partial_failure")
        data = body.get("data")
        if not data:
            raise WizError("Wiz returned no data", "partial_failure")
        return data
