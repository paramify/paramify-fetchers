#!/usr/bin/env python3
"""
Shared Wiz GraphQL client for the wiz fetcher category.

Wiz exposes one GraphQL endpoint per tenant (``https://api.<dc>.app.wiz.us/graphql``
for Wiz for Government, ``https://api.<dc>.app.wiz.io/graphql`` for commercial).
Authentication is an OAuth2 client_credentials exchange with a Wiz service
account. Every fetcher here needs the same exchange, the same cursor paging and
the same failure handling, so it lives in this module.

What was verified against a live Wiz for Gov tenant (2026-09-22, read-only
service account) and what was not:

  verified   auth URL https://auth.app.wiz.us/oauth/token, audience "wiz-api",
             token lifetime 900 s (NOT the 24 h that public docs describe),
             root queries issuesV2 / vulnerabilityFindings / cloudAccounts /
             connectors / configurationFindings exist, and the node fields the
             fetchers select on issuesV2, vulnerabilityFindings and cloudAccounts.
  not yet    the exact filter input fields; filters used here are the ones
             public integrations (Elastic, XSOAR, Cribl) send, and each fetcher
             keeps them minimal so a wrong guess fails loudly, not silently.

Read-only by construction: this client only ever sends GraphQL *queries*. It
refuses to send a document that contains a mutation (see ``_assert_read_only``),
so a fetcher bug cannot change anything in the tenant even if the service
account were over-scoped.

Collection-failure convention (same as crowdstrike/_shared/falcon_client.py):
a failed call appends to ``api_failures`` and returns None rather than raising,
so one bad query does not lose evidence already collected. Any entry in
``api_failures`` makes the fetcher exit non-zero. Authentication failure is the
one exception: nothing can proceed without a token, so it raises.

Two rules carried over from the crowdstrike category because they are
load-bearing:

- **No fetcher decides pass or fail.** Summaries report what Wiz shows and name
  what a reviewer should look at. The verdict is Paramify's, downstream.
- **An empty result and a broken collection must never look alike.** ``status``
  is ``success`` or ``partial_or_empty`` (both exit 0). A fault is
  ``api_failures`` being non-empty, which exits non-zero.
"""

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

# Re-export the one report_failure implementation (docs/fetcher_contract.md § Output).
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402,F401

logger = logging.getLogger("wiz._shared")

# Wiz for Government is the FedRAMP offering, so it is the default. Commercial
# tenants must set WIZ_AUTH_URL explicitly; guessing commercial for a FedRAMP
# customer would send the credential to the wrong authority.
DEFAULT_AUTH_URL = "https://auth.app.wiz.us/oauth/token"
KNOWN_AUTH_URLS = {
    "https://auth.app.wiz.us/oauth/token": "gov",
    "https://auth.app.wiz.io/oauth/token": "commercial",
    "https://auth.wiz.io/oauth/token": "commercial-legacy",
    "https://auth.gov.wiz.io/oauth/token": "commercial-govcloud",
}
DEFAULT_AUDIENCE = "wiz-api"

# Wiz's gateway cuts a request at ~120 s; stay under it so the timeout is ours.
DEFAULT_TIMEOUT = 115
# Public guidance is "no more than 3 requests per second" per tenant, and the
# tenant's other integrations share that budget. One request per second keeps
# a fetcher well clear of it; override with WIZ_MIN_REQUEST_INTERVAL.
DEFAULT_MIN_INTERVAL = 1.0
# Wiz's maximum page size is 500; 100 keeps heavy nested queries under the
# gateway timeout.
DEFAULT_PAGE_SIZE = 100

RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 4
BACKOFF_BASE_SECONDS = 2
MAX_BACKOFF_SECONDS = 60
MAX_PAGES = 2000

_MUTATION = re.compile(r"^\s*mutation\b", re.IGNORECASE | re.MULTILINE)


class WizAuthError(RuntimeError):
    """The OAuth2 exchange failed. Fatal: nothing can proceed."""


class WizConfigError(RuntimeError):
    """A required setting is missing or malformed."""


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: Any) -> Optional[datetime]:
    """Wiz emits RFC3339 with a trailing Z; datetime wants +00:00."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def age_days(value: Any, now: Optional[datetime] = None) -> Optional[int]:
    ts = parse_ts(value)
    if ts is None:
        return None
    return max(((now or datetime.now(timezone.utc)) - ts).days, 0)


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("%s is not an integer (%r); using %s", name, raw, default)
        return default


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("%s is not a number (%r); using %s", name, raw, default)
        return default


def env_list(name: str, default: List[str]) -> List[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return list(default)
    return [part.strip().upper() for part in raw.split(",") if part.strip()]


def normalize_api_url(value: str) -> str:
    """Accept the Tenant Info value with or without the /graphql suffix."""
    url = value.strip().rstrip("/")
    if not url:
        raise WizConfigError("WIZ_API_ENDPOINT_URL is empty")
    if not url.startswith("https://"):
        raise WizConfigError("WIZ_API_ENDPOINT_URL must start with https://")
    if not url.endswith("/graphql"):
        url += "/graphql"
    return url


def tenant_environment(api_url: str) -> str:
    """gov / commercial, from the endpoint host. 'unknown' for a test double."""
    host = urlparse(api_url).hostname or ""
    if host.endswith(".wiz.us"):
        return "gov"
    if host.endswith(".wiz.io"):
        return "commercial"
    return "unknown"


def data_center(api_url: str) -> Optional[str]:
    """'us2' from https://api.us2.app.wiz.us/graphql."""
    host = urlparse(api_url).hostname or ""
    m = re.match(r"^api\.([a-z0-9-]+)\.", host)
    return m.group(1) if m else None


class WizClient:
    """Minimal read-only Wiz GraphQL client with failure tracking and throttling."""

    def __init__(
        self,
        api_url: str,
        auth_url: str,
        client_id: str,
        client_secret: str,
        audience: str = DEFAULT_AUDIENCE,
        timeout: int = DEFAULT_TIMEOUT,
        min_interval: float = DEFAULT_MIN_INTERVAL,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> None:
        self.api_url = normalize_api_url(api_url)
        self.auth_url = auth_url.strip()
        self.audience = audience
        self.timeout = timeout
        self.min_interval = max(min_interval, 0.0)
        self.page_size = max(1, min(page_size, 500))
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: Optional[str] = None
        self._token_expires_at = 0.0
        self._last_request_at = 0.0
        self.api_failures: List[Dict[str, Any]] = []
        self.request_count = 0
        self.token_lifetime_seconds: Optional[int] = None

        env = KNOWN_AUTH_URLS.get(self.auth_url)
        api_env = tenant_environment(self.api_url)
        if env == "gov" and api_env == "commercial" or env and env.startswith("commercial") and api_env == "gov":
            logger.warning(
                "Auth URL (%s) and API endpoint (%s) point at different Wiz environments; "
                "authentication will likely fail", self.auth_url, self.api_url,
            )

    # --- auth -------------------------------------------------------------

    def authenticate(self) -> None:
        try:
            response = requests.post(
                self.auth_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "audience": self.audience,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            raise WizAuthError(f"token request to {self.auth_url} failed: {type(e).__name__}") from e

        if response.status_code != 200:
            # Never echo the body verbatim: some IdPs reflect the request.
            raise WizAuthError(
                f"token request to {self.auth_url} returned HTTP {response.status_code}; "
                "check WIZ_CLIENT_ID / WIZ_CLIENT_SECRET and that WIZ_AUTH_URL matches the tenant"
            )
        try:
            payload = response.json()
        except ValueError as e:
            raise WizAuthError(f"token response from {self.auth_url} was not JSON") from e

        token = payload.get("access_token")
        if not token:
            raise WizAuthError(f"token response from {self.auth_url} contained no access_token")

        # Our gov tenant issues 900 s tokens. Renew a minute early so a long
        # paginated pull never sends an expired token mid-walk.
        expires_in = int(payload.get("expires_in") or 900)
        self.token_lifetime_seconds = expires_in
        self._token = token
        self._token_expires_at = time.monotonic() + max(expires_in - 60, 30)
        logger.info("Authenticated to %s (token valid %ss)", self.auth_url, expires_in)

    def _headers(self) -> Dict[str, str]:
        if self._token is None or time.monotonic() >= self._token_expires_at:
            self.authenticate()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # --- requests ---------------------------------------------------------

    @staticmethod
    def _assert_read_only(query: str) -> None:
        if _MUTATION.search(query):
            raise ValueError("wiz_client only sends GraphQL queries; refusing a mutation")

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
                return min(float(retry_after), MAX_BACKOFF_SECONDS)
            except (TypeError, ValueError):
                pass
        return min(BACKOFF_BASE_SECONDS ** (attempt + 1), MAX_BACKOFF_SECONDS)

    def graphql(self, operation: str, query: str, variables: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        One GraphQL call. Returns ``data`` or None after recording the failure.

        GraphQL reports most faults as HTTP 200 with ``errors[]`` (a missing
        scope, a bad filter field). Those are recorded as failures even when
        ``data`` came back, because partial data presented as complete is the
        failure this category guards against hardest.
        """
        self._assert_read_only(query)
        body = {"query": query, "variables": variables or {}}
        last_response: Any = None
        last_error: Optional[str] = None
        reauthed = False

        for attempt in range(MAX_RETRIES + 1):
            headers = self._headers()
            self._throttle()
            self.request_count += 1
            try:
                response = requests.post(self.api_url, headers=headers, json=body, timeout=self.timeout)
            except requests.exceptions.RequestException as e:
                last_error, last_response = f"{type(e).__name__}: {e}", None
                if attempt < MAX_RETRIES:
                    time.sleep(self._retry_delay(None, attempt))
                    continue
                break

            if response.status_code == 401 and not reauthed:
                # Token revoked or clock skew: one fresh token, then give up.
                reauthed = True
                self._token = None
                continue

            if response.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                delay = self._retry_delay(response, attempt)
                logger.warning("%s returned HTTP %s; retrying in %.1fs", operation, response.status_code, delay)
                time.sleep(delay)
                continue

            last_response = response
            if response.status_code != 200:
                last_error = f"HTTP {response.status_code}"
                break

            try:
                payload = response.json()
            except ValueError:
                last_error = "response was not JSON"
                break

            errors = payload.get("errors") or []
            if errors:
                self._record(operation, "GraphQLError", "; ".join(
                    str(e.get("message", e)) for e in errors[:3]), response.status_code,
                    partial=payload.get("data") is not None)
            return payload.get("data")

        self._record(operation, "HTTPError" if last_response is not None else "ConnectionError",
                     last_error or "request failed", getattr(last_response, "status_code", None))
        return None

    def _record(self, operation: str, kind: str, message: str, status_code: Optional[int], partial: bool = False) -> None:
        failure: Dict[str, Any] = {"operation": operation, "type": kind, "message": message[:500]}
        if status_code is not None:
            failure["status_code"] = status_code
        if partial:
            failure["partial"] = True
        self.api_failures.append(failure)
        logger.warning("Wiz %s failed: %s", operation, message[:200])

    # --- pagination -------------------------------------------------------

    def paginate(
        self,
        operation: str,
        query: str,
        root: str,
        variables: Optional[Dict[str, Any]] = None,
        max_records: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Walk a Relay connection (``first``/``after`` + ``pageInfo``) and return
        every node. The query must declare ``$first: Int`` and ``$after: String``.

        A cursor that repeats, the page cap, and ``max_records`` are all recorded
        as failures: a truncated list that reports success looks exactly like a
        small healthy estate, which is the most dangerous shape a compliance
        error can take.
        """
        nodes: List[Dict[str, Any]] = []
        after: Optional[str] = None
        seen: set = set()

        for _ in range(MAX_PAGES):
            page_vars = dict(variables or {})
            page_vars["first"] = self.page_size
            page_vars["after"] = after
            data = self.graphql(operation, query, page_vars)
            if data is None:
                return nodes
            conn = data.get(root) or {}
            page = conn.get("nodes") or []
            nodes.extend(page)

            if max_records is not None and len(nodes) >= max_records:
                self.api_failures.append({
                    "operation": operation, "type": "RecordCapReached",
                    "message": f"stopped at {len(nodes)} records (cap {max_records}); evidence is incomplete. "
                               "Raise WIZ_MAX_RECORDS or narrow the filter.",
                })
                return nodes

            info = conn.get("pageInfo") or {}
            if not info.get("hasNextPage") or not page:
                return nodes
            after = info.get("endCursor")
            if not after:
                self.api_failures.append({"operation": operation, "type": "PaginationCursorMissing",
                                          "message": f"hasNextPage without endCursor after {len(nodes)} records"})
                return nodes
            if after in seen:
                self.api_failures.append({"operation": operation, "type": "PaginationCursorStalled",
                                          "message": f"cursor repeated after {len(nodes)} records"})
                return nodes
            seen.add(after)

        self.api_failures.append({"operation": operation, "type": "PaginationLimitExceeded",
                                  "message": f"stopped after {MAX_PAGES} pages; evidence may be incomplete"})
        return nodes


def build_client() -> WizClient:
    """Construct and authenticate a client from the declared env vars."""
    client_id = os.environ.get("WIZ_CLIENT_ID", "").strip()
    client_secret = os.environ.get("WIZ_CLIENT_SECRET", "").strip()
    api_url = os.environ.get("WIZ_API_ENDPOINT_URL", "").strip()
    missing = [n for n, v in (("WIZ_CLIENT_ID", client_id), ("WIZ_CLIENT_SECRET", client_secret),
                              ("WIZ_API_ENDPOINT_URL", api_url)) if not v]
    if missing:
        raise WizConfigError(f"Missing required env var(s): {', '.join(missing)}")

    client = WizClient(
        api_url=api_url,
        auth_url=os.environ.get("WIZ_AUTH_URL", "").strip() or DEFAULT_AUTH_URL,
        client_id=client_id,
        client_secret=client_secret,
        audience=os.environ.get("WIZ_AUDIENCE", "").strip() or DEFAULT_AUDIENCE,
        timeout=env_int("WIZ_HTTP_TIMEOUT", DEFAULT_TIMEOUT),
        min_interval=env_float("WIZ_MIN_REQUEST_INTERVAL", DEFAULT_MIN_INTERVAL),
        page_size=env_int("WIZ_PAGE_SIZE", DEFAULT_PAGE_SIZE),
    )
    client.authenticate()
    return client


def provenance(client: WizClient) -> Dict[str, Any]:
    """Where this evidence came from. An assessor needs gov vs commercial."""
    return {
        "api_endpoint_url": client.api_url,
        "auth_url": client.auth_url,
        "environment": tenant_environment(client.api_url),
        "data_center": data_center(client.api_url),
        "token_lifetime_seconds": client.token_lifetime_seconds,
        "request_count": client.request_count,
    }


def evidence_error(message: str, code: str = "internal_error") -> Dict[str, Any]:
    """Evidence body for a run that could not collect. Still written to disk."""
    return {
        "status": "error",
        "error_code": code,
        "message": message,
        "api_failures": [],
        "metadata": {"partial_failure": False, "api_failures": []},
        "retrieved_at": current_timestamp(),
    }


def evidence(
    *,
    client: WizClient,
    operations: List[str],
    records: List[Any],
    analysis: Dict[str, Any],
    empty_message: str,
    include_records: bool = True,
    **extra: Any,
) -> Dict[str, Any]:
    """One evidence shape for the whole category. See module docstring."""
    body: Dict[str, Any] = {
        "status": "success" if records else "partial_or_empty",
        "source": "wiz",
        "operations": operations,
        "record_count": len(records),
        "analysis": analysis,
        "data": records if include_records else [],
        "records_included": include_records,
        "api_failures": client.api_failures,
        "metadata": {
            "partial_failure": bool(client.api_failures),
            "api_failures": client.api_failures,
        },
        "tenant": provenance(client),
        "retrieved_at": current_timestamp(),
    }
    if not records:
        body["message"] = empty_message
    body.update(extra)
    return body


def _failure_code(failure: Dict[str, Any]) -> str:
    status = failure.get("status_code")
    if status == 401:
        return "auth_failed"
    if status == 403:
        return "not_authorized"
    if status == 429:
        return "rate_limited"
    if failure.get("type") == "ConnectionError":
        return "target_unreachable"
    message = str(failure.get("message", "")).lower()
    if "not authorized" in message or "unauthorized" in message or "permission" in message:
        return "not_authorized"
    return "partial_failure"


def run_fetcher(collect: Callable[[], Dict[str, Any]], output_name: str, log: logging.Logger) -> int:
    """
    Run one fetcher and write its evidence. Returns the process exit code.

    - The evidence file is always written, including on a fault.
    - Any entry in ``api_failures`` exits non-zero, even when records came back.
    - An unexpected exception becomes an error body, not a traceback.
    """
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
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
            f"{len(failures)} Wiz API failure(s); first: {first.get('operation')}: {first.get('message')}",
            code=_failure_code(first),
        )
        return 1

    if result.get("status") not in {"success", "partial_or_empty"}:
        report_failure(str(result.get("message") or "collection did not complete"),
                       code=str(result.get("error_code") or "internal_error"))
        return 1
    return 0


def collect_guarded(fn: Callable[[WizClient], Dict[str, Any]]) -> Callable[[], Dict[str, Any]]:
    """Wrap a fetcher body so config and auth errors become clean error evidence."""
    def _collect() -> Dict[str, Any]:
        try:
            client = build_client()
        except WizConfigError as e:
            return evidence_error(str(e), code="bad_config")
        except WizAuthError as e:
            return evidence_error(str(e), code="auth_failed")
        return fn(client)
    return _collect
