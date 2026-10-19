#!/usr/bin/env python3
"""
Shared Cornerstone Reporting API (RAPI) client for the cornerstone category.

Cornerstone exposes its Real-time Data Warehouse through read-only OData v4
views under ``https://<corpname>.csod.com/services/api/x/odata/api/views/``
(``vw_rpt_transcript``, ``vw_rpt_training``, ``vw_rpt_user``, ...). Access is an
OAuth 2.0 client-credentials token from ``/services/api/oauth2/token``; each
view needs its own ``<view name>:read`` scope, and the user bound to the OAuth
application needs the 'Reporting API - Read Only' security permission.

Sources (csod.dev, read 2026-10-16): Getting Started > Authentication (token
request body ``clientId`` / ``clientSecret`` / ``grantType`` / ``scope`` as
JSON), Supplements > List of Scopes (RAPI path and the ``{viewname}:read``
scope pattern), Reporting > Paging (``Prefer: odata.maxpagesize``, opaque
``@odata.nextLink``, ``$count=true&$top=0`` for a record count, rows that can
shift and repeat between pages, the 400 requests/minute RAPI throttle), and the
Training and Transcript RTDW technical spec v26.03 (view and column names).

What has NOT been verified: a live run against a real portal. Field names come
from Cornerstone's published RTDW spec; a column a portal does not expose fails
the call with an HTTP 400, which is recorded as a failure, never skipped.

Read-only by construction:
  - the only POST is the token request;
  - every other request is a GET to a path under the RAPI views root;
  - a ``@odata.nextLink`` is followed only if it stays on the same https host
    and under that same root.

Collection-failure convention (same as wiz/_shared/wiz_client.py): a failed
call appends to ``api_failures`` and returns None rather than raising, so one
bad view does not lose evidence already collected. Any entry in
``api_failures`` makes the fetcher exit non-zero. Authentication and config
failures raise, because nothing can proceed without them.

Completeness: Cornerstone warns that rows can shift between pages while a view
is being read. So each read first asks the view for its record count, then
de-duplicates the rows it collected on the view's unique key, and records a
failure if it ended up with fewer unique rows than the count said exist.
Truncated evidence published as complete is the failure nobody sees.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

# Re-export the one report_failure implementation (docs/fetcher_contract_guide.md, step 6).
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402,F401

logger = logging.getLogger("cornerstone._shared")

TOKEN_PATH = "/services/api/oauth2/token"
VIEWS_ROOT = "/services/api/x/odata/api/views/"

DEFAULT_TIMEOUT = 120
# RAPI's default throttle is 400 requests per minute per portal, shared with the
# portal's other integrations. 0.25 s between requests stays well under it.
DEFAULT_MIN_INTERVAL = 0.25
# Cornerstone's default page is 1,000 rows; the documented maximum is 10,000.
DEFAULT_PAGE_SIZE = 1000
MAX_PAGE_SIZE = 10000
# A hard ceiling on pages per view read, so a misbehaving nextLink cannot spin
# until the runner kills the process. Hitting it is a recorded failure.
DEFAULT_MAX_PAGES = 500

RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 4
BACKOFF_BASE_SECONDS = 2
MAX_BACKOFF_SECONDS = 60

# One DNS label directly under csod.com: corpname, corpname-pilot, corpname-stg.
_CSOD_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.csod\.com$")
_URL_SAFE = re.compile(r"^[A-Za-z0-9:/._~-]+$")
_VIEW_NAME = re.compile(r"^vw_rpt_[a-z0-9_]+$")


class CsodConfigError(RuntimeError):
    """A required setting is missing or malformed."""


class CsodAuthError(RuntimeError):
    """The OAuth 2.0 token request failed. Fatal: nothing can proceed."""


# --- small helpers -----------------------------------------------------------


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: Any) -> Optional[datetime]:
    """RTDW datetimes come back as ISO 8601, with or without an offset; treat naive as UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(text)
    except ValueError:
        # Fractional seconds longer than six digits (SQL Server datetime2) trip fromisoformat.
        m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", text)
        if not m:
            return None
        frac = (m.group(2) or "")[:7]
        try:
            ts = datetime.fromisoformat(m.group(1) + frac + (m.group(3) or ""))
        except ValueError:
            return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def days_between(earlier: Optional[datetime], later: datetime) -> Optional[int]:
    if earlier is None:
        return None
    return (later - earlier).days


def env_int(name: str, default: int, minimum: Optional[int] = None) -> int:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        raise CsodConfigError(f"{name} must be a whole number (got {raw!r})") from None
    if minimum is not None and value < minimum:
        raise CsodConfigError(f"{name} must be at least {minimum} (got {value})")
    return value


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        raise CsodConfigError(f"{name} must be a number (got {raw!r})") from None
    if not math.isfinite(value) or value < 0:
        raise CsodConfigError(f"{name} must be a non-negative number (got {raw!r})")
    return value


def env_names(name: str) -> List[str]:
    """Comma-separated list, whitespace trimmed, empties and exact duplicates dropped, order kept."""
    seen: List[str] = []
    for part in os.environ.get(name, "").split(","):
        part = part.strip()
        if part and part not in seen:
            seen.append(part)
    return seen


def odata_string(value: str) -> str:
    """An OData v4 string literal: single-quoted, embedded quotes doubled."""
    return "'" + value.replace("'", "''") + "'"


def _allow_custom_endpoints() -> bool:
    return os.environ.get("CSOD_ALLOW_CUSTOM_ENDPOINTS", "").strip().lower() in {"true", "1", "yes"}


def normalize_portal_url(value: str) -> str:
    """
    Refuse to send a Cornerstone credential anywhere but a Cornerstone portal.

    The raw value must use only URL-safe characters (a backslash or an ``@``
    can make a suffix check pass while the HTTP library connects elsewhere),
    use https, carry no user info, query or fragment, and name a host that is
    exactly one DNS label under csod.com. CSOD_ALLOW_CUSTOM_ENDPOINTS=true
    relaxes only the host rule, for a trusted test double; https still holds.
    """
    raw = (value or "").strip()
    if not raw:
        raise CsodConfigError("CSOD_PORTAL_URL is empty")
    if not _URL_SAFE.match(raw):
        raise CsodConfigError("CSOD_PORTAL_URL contains characters that are not allowed in a portal URL")
    parsed = urlparse(raw)
    if parsed.scheme != "https":
        raise CsodConfigError("CSOD_PORTAL_URL must use https://")
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.params:
        raise CsodConfigError("CSOD_PORTAL_URL must be just the portal address, e.g. https://<corpname>.csod.com")
    if parsed.path not in ("", "/"):
        raise CsodConfigError("CSOD_PORTAL_URL must not include a path, e.g. https://<corpname>.csod.com")
    host = (parsed.hostname or "").lower()
    if parsed.port not in (None, 443):
        if not _allow_custom_endpoints():
            raise CsodConfigError("CSOD_PORTAL_URL must not set a port")
    if not _allow_custom_endpoints() and not _CSOD_HOST.match(host):
        raise CsodConfigError(
            "CSOD_PORTAL_URL host must be <corpname>.csod.com (one label under csod.com). "
            "Set CSOD_ALLOW_CUSTOM_ENDPOINTS=true only for a trusted test double.")
    netloc = host if parsed.port in (None, 443) else f"{host}:{parsed.port}"
    return f"https://{netloc}"


# --- client ------------------------------------------------------------------


class CsodClient:
    """Minimal read-only Cornerstone RAPI client with failure tracking and throttling."""

    def __init__(
        self,
        portal_url: str,
        client_id: str,
        client_secret: str,
        scopes: Sequence[str],
        timeout: int = DEFAULT_TIMEOUT,
        min_interval: float = DEFAULT_MIN_INTERVAL,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = DEFAULT_MAX_PAGES,
    ) -> None:
        self.portal_url = normalize_portal_url(portal_url)
        self._host = urlparse(self.portal_url).netloc
        self.token_url = self.portal_url + TOKEN_PATH
        self.views_url = self.portal_url + VIEWS_ROOT
        if len(scopes) > 20:
            raise CsodConfigError("Cornerstone accepts at most 20 scopes in one token request")
        self.scopes = list(scopes)
        self.timeout = timeout
        self.min_interval = max(min_interval, 0.0)
        self.page_size = max(1, min(page_size, MAX_PAGE_SIZE))
        self.max_pages = max(1, max_pages)
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: Optional[str] = None
        self._token_expires_at = 0.0
        self._last_request_at = 0.0
        self.api_failures: List[Dict[str, Any]] = []
        self.request_count = 0
        self.token_lifetime_seconds: Optional[int] = None

    # --- auth -------------------------------------------------------------

    def authenticate(self) -> None:
        body = {
            "clientId": self._client_id,
            "clientSecret": self._client_secret,
            "grantType": "client_credentials",
            "scope": " ".join(self.scopes),
        }
        try:
            response = requests.post(
                self.token_url,
                json=body,
                headers={"Content-Type": "application/json", "Accept": "application/json",
                         "cache-control": "no-cache"},
                timeout=30,
                # A redirect would re-send the body, secret included, to whatever
                # host the Location header names.
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            # Only the type: some requests errors quote the request, and so the secret.
            raise CsodAuthError(f"token request to {self.token_url} failed: {type(e).__name__}") from e
        if response.status_code != 200:
            # Never echo the body: an error page can reflect the request.
            raise CsodAuthError(
                f"token request to {self.token_url} returned HTTP {response.status_code}; "
                "check CSOD_CLIENT_ID / CSOD_CLIENT_SECRET, that the OAuth 2.0 application is enabled, "
                f"and that it was granted these scopes: {' '.join(self.scopes)}")
        try:
            payload = response.json()
        except ValueError as e:
            raise CsodAuthError(f"token response from {self.token_url} was not JSON") from e
        if not isinstance(payload, dict):
            raise CsodAuthError(f"token response from {self.token_url} was not a JSON object")
        token = payload.get("access_token")
        if not isinstance(token, str) or not token.strip():
            raise CsodAuthError(f"token response from {self.token_url} contained no access_token")
        token = token.strip()
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in token):
            # requests would quote the whole header, token included, in its error.
            raise CsodAuthError(f"token response from {self.token_url} contained a malformed access_token")
        try:
            expires_in = int(payload.get("expires_in") or 3600)
        except (TypeError, ValueError):
            expires_in = 3600
        self.token_lifetime_seconds = expires_in
        self._token = token
        # Renew a minute early so a long paged read never sends an expired token.
        self._token_expires_at = time.monotonic() + max(expires_in - 60, 30)
        logger.info("Authenticated to %s (token valid %ss)", self.portal_url, expires_in)

    def _headers(self, page_size: int) -> Dict[str, str]:
        if self._token is None or time.monotonic() >= self._token_expires_at:
            self.authenticate()
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Prefer": f"odata.maxpagesize={page_size}",
        }

    # --- requests ---------------------------------------------------------

    def _throttle(self) -> None:
        wait = self.min_interval - (time.monotonic() - self._last_request_at)
        if wait > 0:
            time.sleep(wait)
        self._last_request_at = time.monotonic()

    @staticmethod
    def _retry_delay(response: Any, attempt: int) -> float:
        retry_after = None
        if response is not None:
            retry_after = (getattr(response, "headers", {}) or {}).get("Retry-After")
        if retry_after:
            try:
                delay = float(retry_after)
            except (TypeError, ValueError):
                delay = None
            if delay is not None and math.isfinite(delay):
                return max(0.0, min(delay, MAX_BACKOFF_SECONDS))
        return float(min(BACKOFF_BASE_SECONDS ** (attempt + 1), MAX_BACKOFF_SECONDS))

    def _check_next_link(self, link: str) -> bool:
        parsed = urlparse(link)
        try:
            port = parsed.port
        except ValueError:
            return False
        host = (parsed.hostname or "").lower()
        netloc = host if port in (None, 443) else f"{host}:{port}"
        return (parsed.scheme == "https" and netloc == self._host.lower()
                and not parsed.username and not parsed.password and "@" not in parsed.netloc
                and _is_views_path(parsed.path))

    def get_json(self, operation: str, url: str, params: Optional[Dict[str, str]] = None,
                 page_size: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """One read-only GET. Returns the JSON object, or None after recording the failure."""
        parsed_url = urlparse(url)
        # Compare the host case-insensitively (a nextLink may capitalize it) and
        # the path exactly; a mismatch is a bug in the caller, not a run failure.
        if not (parsed_url.scheme == "https" and parsed_url.netloc.lower() == self._host.lower()
                and not parsed_url.username and not parsed_url.password
                and _is_views_path(parsed_url.path)):
            raise ValueError("csod_client only reads Reporting API views")
        size = page_size or self.page_size
        last_response: Any = None
        last_error: Optional[str] = None
        reauthed = False
        for attempt in range(MAX_RETRIES + 1):
            try:
                headers = self._headers(size)
            except CsodAuthError as e:
                # A failed renewal mid-run is one failed call, not a lost run.
                self._record(operation, "AuthError", str(e), None)
                return None
            self._throttle()
            self.request_count += 1
            try:
                response = requests.get(url, headers=headers, params=params, timeout=self.timeout,
                                        allow_redirects=False)
            except requests.exceptions.RequestException as e:
                last_error, last_response = type(e).__name__, None
                if attempt < MAX_RETRIES:
                    time.sleep(self._retry_delay(None, attempt))
                    continue
                break
            if response.status_code == 401 and not reauthed:
                # Token expired or revoked: one fresh token, then give up. A 401
                # that survives a fresh token means a missing scope or permission.
                reauthed = True
                self._token = None
                continue
            if response.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                delay = self._retry_delay(response, attempt)
                logger.warning("%s returned HTTP %s; retrying in %.1fs", operation, response.status_code, delay)
                time.sleep(delay)
                continue
            last_response = response
            if 300 <= response.status_code < 400:
                last_error = f"HTTP {response.status_code} redirect refused (credentials are never re-sent)"
                break
            if response.status_code != 200:
                last_error = f"HTTP {response.status_code}" + _odata_error_hint(response)
                break
            try:
                payload = response.json()
            except ValueError:
                last_error = "response was not JSON"
                break
            if not isinstance(payload, dict):
                last_error = "response was not a JSON object"
                break
            return payload
        self._record(operation, "HTTPError" if last_response is not None else "ConnectionError",
                     last_error or "request failed", getattr(last_response, "status_code", None))
        return None

    def view_count(self, view: str, odata_filter: Optional[str]) -> Optional[int]:
        """``$count=true&$top=0``: how many rows the filter matches right now."""
        params = {"$count": "true", "$top": "0"}
        if odata_filter:
            params["$filter"] = odata_filter
        payload = self.get_json(f"{view} count", self._view_url(view), params=params)
        if payload is None:
            return None
        count = payload.get("@odata.count")
        if isinstance(count, str) and count.strip().isdigit():
            # OData allows a count serialized as a string (IEEE754Compatible).
            count = int(count.strip())
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            self._record(f"{view} count", "UnexpectedResponse", "no @odata.count in the count response", 200)
            return None
        return count

    def read_view(self, view: str, select: Sequence[str], key: Sequence[str],
                  odata_filter: Optional[str] = None) -> Tuple[Optional[List[Dict[str, Any]]], Dict[str, Any]]:
        """
        Every row of ``view`` matching ``odata_filter``, de-duplicated on ``key``.

        Returns (rows or None, stats). ``rows`` is None when the read failed or
        came back incomplete; the failure is in ``api_failures``. ``stats``
        carries the expected count, the pages read and the duplicates dropped,
        so the evidence shows how complete it is.
        """
        if not _VIEW_NAME.match(view):
            raise ValueError(f"unexpected Reporting API view name {view!r}")
        operation = view
        stats: Dict[str, Any] = {"view": view, "filter": odata_filter, "expected_count": None,
                                 "rows_received": 0, "unique_rows": 0, "duplicates_dropped": 0,
                                 "pages": 0, "complete": False}
        expected = self.view_count(view, odata_filter)
        stats["expected_count"] = expected
        if expected is None:
            return None, stats
        params: Optional[Dict[str, str]] = {"$select": ",".join(select)}
        if odata_filter:
            params["$filter"] = odata_filter
        url = self._view_url(view)
        unique: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        seen_links: set = set()
        while True:
            if stats["pages"] >= self.max_pages:
                self._record(operation, "PageCap",
                             f"stopped after {self.max_pages} pages (CSOD_MAX_PAGES); evidence would be incomplete",
                             None)
                return None, stats
            payload = self.get_json(operation, url, params=params)
            if payload is None:
                return None, stats
            stats["pages"] += 1
            rows = payload.get("value")
            if not isinstance(rows, list):
                self._record(operation, "UnexpectedResponse", "response had no 'value' list", 200)
                return None, stats
            for row in rows:
                if not isinstance(row, dict):
                    self._record(operation, "UnexpectedResponse", "a row was not a JSON object", 200)
                    return None, stats
                stats["rows_received"] += 1
                unique[tuple(row.get(k) for k in key)] = row
            link = payload.get("@odata.nextLink") or payload.get("@odata.nextlink")
            if not link:
                break
            if not isinstance(link, str) or not self._check_next_link(link):
                self._record(operation, "UnexpectedResponse",
                             "@odata.nextLink left the portal or the Reporting API views; not followed", 200)
                return None, stats
            if link in seen_links:
                self._record(operation, "UnexpectedResponse", "@odata.nextLink repeated; paging stalled", 200)
                return None, stats
            if not rows:
                self._record(operation, "UnexpectedResponse", "empty page that still links to a next page", 200)
                return None, stats
            seen_links.add(link)
            # nextLink is opaque (Cornerstone: do not parse or edit it); it already
            # carries the query, so no params are added to it.
            url, params = link, None
        stats["unique_rows"] = len(unique)
        stats["duplicates_dropped"] = stats["rows_received"] - len(unique)
        if len(unique) < expected:
            self._record(operation, "Incomplete",
                         f"collected {len(unique)} unique rows but the view reported {expected}", 200)
            return None, stats
        stats["complete"] = True
        return list(unique.values()), stats

    def _view_url(self, view: str) -> str:
        if not _VIEW_NAME.match(view):
            raise ValueError(f"unexpected Reporting API view name {view!r}")
        return self.views_url + view

    def _record(self, operation: str, kind: str, message: str, status_code: Optional[int]) -> None:
        failure: Dict[str, Any] = {"operation": operation, "type": kind, "message": str(message)[:500]}
        if status_code is not None:
            failure["status_code"] = status_code
        self.api_failures.append(failure)


def _is_views_path(path: str) -> bool:
    """
    True only for a path under the views root with no dot segments. requests
    (urllib3) resolves "..", including percent-encoded "%2e%2e", before it
    sends, so ".../views/../../oauth2/token" would pass a plain prefix check
    and reach another endpoint with the bearer token.
    """
    if not path.startswith(VIEWS_ROOT):
        return False
    lowered = path.lower()
    if "%2e" in lowered or "%2f" in lowered or "%5c" in lowered or "\\" in path:
        return False
    return not any(seg in (".", "..") for seg in path.split("/"))


def _odata_error_hint(response: Any) -> str:
    """The OData error message, if the body has one. Bounded, never the whole body."""
    try:
        body = response.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    err = body.get("error")
    message = None
    if isinstance(err, dict):
        message = err.get("message") or err.get("description")
    elif isinstance(err, str):
        message = err
    if not isinstance(message, str) or not message.strip():
        return ""
    return ": " + " ".join(message.split())[:200]


# --- building, evidence and the run wrapper ----------------------------------


def build_client(scopes: Sequence[str]) -> CsodClient:
    """Construct and authenticate a client from the declared env vars."""
    client_id = os.environ.get("CSOD_CLIENT_ID", "").strip()
    client_secret = os.environ.get("CSOD_CLIENT_SECRET", "").strip()
    portal_url = os.environ.get("CSOD_PORTAL_URL", "").strip()
    missing = [n for n, v in (("CSOD_CLIENT_ID", client_id), ("CSOD_CLIENT_SECRET", client_secret),
                              ("CSOD_PORTAL_URL", portal_url)) if not v]
    if missing:
        raise CsodConfigError(f"Missing required env var(s): {', '.join(missing)}")
    client = CsodClient(
        portal_url=portal_url,
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes,
        timeout=env_int("CSOD_HTTP_TIMEOUT", DEFAULT_TIMEOUT, minimum=1),
        min_interval=env_float("CSOD_MIN_REQUEST_INTERVAL", DEFAULT_MIN_INTERVAL),
        page_size=env_int("CSOD_PAGE_SIZE", DEFAULT_PAGE_SIZE, minimum=1),
        max_pages=env_int("CSOD_MAX_PAGES", DEFAULT_MAX_PAGES, minimum=1),
    )
    client.authenticate()
    return client


def provenance(client: CsodClient) -> Dict[str, Any]:
    """Where this evidence came from."""
    host = urlparse(client.portal_url).hostname or ""
    environment = "unknown"
    label = host.split(".")[0]
    if host.endswith(".csod.com"):
        environment = ("pilot" if label.endswith("-pilot") else
                       "stage" if label.endswith(("-stg", "-stage")) else "production")
    return {
        "portal_url": client.portal_url,
        "environment": environment,
        "api": "Cornerstone Reporting API (OData v4, Real-time Data Warehouse views)",
        "scopes_requested": client.scopes,
        "token_lifetime_seconds": client.token_lifetime_seconds,
        "request_count": client.request_count,
        # True when CSOD_ALLOW_CUSTOM_ENDPOINTS relaxed the host allowlist, so a
        # reviewer can tell evidence from a test double apart from a real portal.
        "custom_endpoint_override": _allow_custom_endpoints(),
    }


def evidence_error(message: str, code: str = "internal_error") -> Dict[str, Any]:
    """Evidence body for a run that could not collect. Still written to disk."""
    return {
        "status": "error",
        "error_code": code,
        "message": message,
        "api_failures": [],
        "metadata": {"partial_failure": False, "api_failures": [], "complete": False,
                     "incomplete_reason": message},
        "retrieved_at": current_timestamp(),
    }


def _failure_code(failure: Dict[str, Any]) -> str:
    status = failure.get("status_code")
    kind = failure.get("type")
    if kind == "AuthError" or status == 401:
        # 401 after a fresh token: the scope or the 'Reporting API - Read Only'
        # permission is missing for this view.
        return "not_authorized" if kind != "AuthError" else "auth_failed"
    if status == 403:
        return "not_authorized"
    if status == 429:
        return "rate_limited"
    if kind == "ConnectionError":
        return "target_unreachable"
    return "partial_failure"


def run_fetcher(collect: Callable[[], Dict[str, Any]], output_name: str, log: logging.Logger) -> int:
    """
    Run one fetcher and write its evidence. Returns the process exit code.

    - The evidence file is always written, including on a fault.
    - Any entry in ``api_failures`` exits non-zero, even when rows came back.
    - An unexpected exception becomes an error body, not a traceback.
    """
    level = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
    # An unknown LOG_LEVEL must not crash the run before it can report anything.
    logging.basicConfig(
        level=level if level in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"} else "INFO",
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = collect()
    except Exception as e:  # noqa: BLE001 - evidence must be written even on an unexpected fault
        log.error("Collection failed: %s", type(e).__name__)
        result = evidence_error(f"{type(e).__name__}: {e}")

    output_path = output_dir / output_name
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    log.info("Evidence saved to %s", output_path)

    failures = result.get("api_failures") or []
    if failures:
        first = failures[0]
        report_failure(
            f"{len(failures)} Cornerstone API failure(s); first: {first.get('operation')}: {first.get('message')}",
            code=_failure_code(first),
        )
        return 1
    if result.get("status") not in {"success", "partial_or_empty"}:
        report_failure(str(result.get("message") or "collection did not complete"),
                       code=str(result.get("error_code") or "internal_error"))
        return 1
    return 0


def collect_guarded(scopes: Sequence[str],
                    fn: Callable[[CsodClient], Dict[str, Any]]) -> Callable[[], Dict[str, Any]]:
    """Wrap a fetcher body so config and auth errors become clean error evidence."""
    def _collect() -> Dict[str, Any]:
        try:
            client = build_client(scopes)
        except CsodConfigError as e:
            return evidence_error(str(e), code="bad_config")
        except CsodAuthError as e:
            return evidence_error(str(e), code="auth_failed")
        try:
            return fn(client)
        except CsodConfigError as e:
            return evidence_error(str(e), code="bad_config")
    return _collect


__all__ = [
    "CsodClient", "CsodConfigError", "CsodAuthError", "build_client", "collect_guarded", "run_fetcher",
    "provenance", "evidence_error", "current_timestamp", "parse_ts", "days_between", "env_int", "env_names",
    "odata_string", "report_failure",
]
