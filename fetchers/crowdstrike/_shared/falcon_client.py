#!/usr/bin/env python3
"""
Shared CrowdStrike Falcon API client for the crowdstrike fetcher category.

Falcon authenticates with OAuth2 client credentials: a client ID and secret are
exchanged at POST /oauth2/token for a bearer token valid ~30 minutes. Every
fetcher in this category needs that exchange, so it lives here.

Endpoint paths and parameter names in this module are taken from CrowdStrike's
own SDK (github.com/CrowdStrike/falconpy, src/falconpy/_endpoint/), not from
prose documentation.

Falcon has three pagination styles and this module covers all three:
  - offset token ("scroll")  — /devices/queries/devices-scroll/v1
  - after token              — /spotlight/combined/vulnerabilities/v1
  - integer offset           — /alerts/queries/alerts/v2, /policy/combined/*

Collection-failure convention (see docs/authoring_fetcher_guide.md, step 3): a failed call
appends to `api_failures` and returns None rather than raising, so one bad
endpoint does not lose the evidence already collected. The caller exits
non-zero when `api_failures` is non-empty. Authentication failure is the one
exception — no call can succeed without a token, so it raises.

How this category is put together
---------------------------------
Read this first if you are picking the category up.

    fetchers/crowdstrike/
      _shared/falcon_client.py     <- you are here: API client + the shared entry point
      <evidence_set>/
        fetcher.py         <- collect() + summarize(), one evidence set each
        fetcher.yaml       <- the manifest the runner reads

Every fetcher is the same three pieces, and only the middle one is interesting:

1. **collect()** — build the client, call the endpoints, hand the records to
   summarize(), return `evidence(...)`. Usually under 30 lines, because
   everything generic lives here in _shared.
2. **summarize()** — turn raw API records into the numbers an assessor reads.
   This is where the judgement is, and where every bug this category has ever
   had was found.
3. **`sys.exit(run_fetcher(collect, "<name>.json", logger))`** — the whole entry
   point. Logging, .env, the output directory, the catch-all and the exit code
   are all in `run_fetcher` below.

Two rules that are not obvious and are load-bearing:

- **No fetcher decides pass or fail.** These report what is configured and name
  what a reviewer should look at. The verdict is Paramify's, downstream. If you
  find yourself writing `compliant: True`, stop.
- **An empty result and a broken collection must never look alike.** `status` is
  `success` or `partial_or_empty` — both are healthy, exit 0. A *fault* is
  `api_failures` being non-empty, which exits non-zero even if records came
  back. Most of the bugs found here were a partial collection reporting success,
  so this distinction is the thing to preserve when changing anything.

Adding a fetcher to this category: copy the smallest existing one, keep
collect() thin, put the thinking in summarize(), and add a test that fails if
your summary is wrong. Then break your own fix on purpose and check the test
actually catches it — that pass has caught three tests here that asserted
nothing.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import requests
from dotenv import load_dotenv

# One implementation per runtime lives in fetchers/_lib; a category-shared module
# may RE-EXPORT it and must not reimplement it (docs/fetcher_contract_guide.md, step 6).
# Same mechanism a fetcher uses, one directory further up: this file is
# fetchers/crowdstrike/_shared/, so fetchers/_lib is parents[2] / "_lib".
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402,F401

logger = logging.getLogger("crowdstrike._shared")

# Falcon has a different API host per cloud. GovCloud is the relevant one for
# FedRAMP workloads, and its hostname is not derivable from the others.
# Hosts confirmed against gofalcon's falcon/cloud.go, which is CrowdStrike's own
# cloud table. Note us-gov-2 is .mil, not .com.
CLOUD_REGIONS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "us-3": "https://api.us-3.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}

# gov1/gov2 are the aliases gofalcon accepts for the two GovCloud regions; the
# Falcon console and its own docs use both spellings.
REGION_ALIASES = {"gov1": "us-gov-1", "gov2": "us-gov-2"}

DEFAULT_BASE_URL = CLOUD_REGIONS["us-1"]
DEFAULT_TIMEOUT = 30

# Falcon rejects an ids[] batch larger than 100 on most entity endpoints.
ENTITY_BATCH_SIZE = 100

# Falcon rate-limits per API client and answers 429 with a Retry-After header.
# A collection sweeping a large estate will hit it, so a bounded retry is not
# optional — without it a big tenant simply fails to produce evidence.
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 4
BACKOFF_BASE_SECONDS = 2
MAX_BACKOFF_SECONDS = 60

# A malformed or hostile pagination cursor that never advances would otherwise
# loop forever. These caps bound every paginator; hitting one is recorded as a
# collection failure rather than silently truncating the evidence.
MAX_PAGES = 1000


class FalconAuthError(RuntimeError):
    """Raised when the OAuth2 token exchange fails. Fatal — nothing can proceed."""


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def normalize_region(value: str) -> str:
    """
    Fold a region string to a CLOUD_REGIONS key the way gofalcon does — strip
    whitespace and hyphens, lowercase, then resolve aliases. This accepts
    'us-gov-1', 'usgov1' and 'US_GOV_1' alike, which matters because the Falcon
    console, the docs and the SDKs each spell GovCloud differently and a user
    who copies the wrong one would otherwise land on commercial us-1.
    """
    stripped = value.strip().lower().replace("-", "").replace("_", "").replace(" ", "")
    if stripped in REGION_ALIASES:
        return REGION_ALIASES[stripped]
    for key in CLOUD_REGIONS:
        if key.replace("-", "") == stripped:
            return key
    raise RuntimeError(
        f"Unknown CROWDSTRIKE_CLOUD_REGION '{value}'. "
        f"Expected one of: {', '.join(sorted(CLOUD_REGIONS))}"
    )


def resolve_base_url() -> str:
    """
    CROWDSTRIKE_API_BASE_URL wins when set (it is also how the local mock is
    pointed at). Otherwise CROWDSTRIKE_CLOUD_REGION names one of the known
    clouds. Neither set falls back to the commercial US-1 cloud.
    """
    explicit = os.environ.get("CROWDSTRIKE_API_BASE_URL", "").strip()
    if explicit:
        return explicit.rstrip("/")

    region = os.environ.get("CROWDSTRIKE_CLOUD_REGION", "").strip()
    if region:
        return CLOUD_REGIONS[normalize_region(region)]

    return DEFAULT_BASE_URL


def region_for_base_url(base_url: str) -> Optional[str]:
    """The CLOUD_REGIONS key a base URL belongs to, or None for a test double."""
    normalized = base_url.rstrip("/")
    for region, url in CLOUD_REGIONS.items():
        if url == normalized:
            return region
    return None


class FalconClient:
    """Minimal read-only Falcon REST client with failure tracking."""

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self.timeout = timeout
        self.api_failures: List[Dict[str, Any]] = []
        # The cloud the tenant itself reports at auth, from the X-CS-Region
        # response header. Independent of what was configured, so it is the
        # honest answer to "was this evidence collected from GovCloud?".
        self.reported_region: Optional[str] = None
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0

    # --- auth -------------------------------------------------------------

    def authenticate(self) -> None:
        """Exchange client credentials for a bearer token."""
        endpoint = f"{self.base_url}/oauth2/token"
        try:
            response = requests.post(
                endpoint,
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.exceptions.RequestException as e:
            raise FalconAuthError(f"OAuth2 token request to {endpoint} failed: {e}") from e
        except ValueError as e:
            raise FalconAuthError(f"OAuth2 token response from {endpoint} was not JSON: {e}") from e

        token = payload.get("access_token")
        if not token:
            raise FalconAuthError(f"OAuth2 token response from {endpoint} contained no access_token")

        # Renew a minute early so a long run never sends an expired token.
        expires_in = int(payload.get("expires_in", 1800))
        self._token = token
        self._token_expires_at = time.monotonic() + max(expires_in - 60, 60)

        self._record_reported_region(response)
        logger.info("Authenticated to %s (token valid %ss)", self.base_url, expires_in)

    def _record_reported_region(self, response: Any) -> None:
        """
        Falcon echoes the tenant's own cloud in X-CS-Region on the token
        response. A tenant reached on the wrong cloud host usually just fails to
        authenticate, but a mismatch that does authenticate would silently
        collect from a different cloud than the manifest claims — which in a
        FedRAMP package is the difference between GovCloud and commercial
        evidence. Warn rather than fail: the header is informational and an
        unexpected value should not stop a collection.
        """
        header = (getattr(response, "headers", {}) or {}).get("X-CS-Region", "")
        if not header:
            return
        try:
            self.reported_region = normalize_region(header)
        except RuntimeError:
            self.reported_region = header.strip()
            logger.warning("Falcon reported an unrecognized cloud region: %s", header)
            return

        configured = region_for_base_url(self.base_url)
        if configured is not None and configured != self.reported_region:
            logger.warning(
                "Configured cloud region %s but the tenant reports %s — "
                "evidence was collected from %s",
                configured,
                self.reported_region,
                self.reported_region,
            )

    def _headers(self) -> Dict[str, str]:
        if self._token is None or time.monotonic() >= self._token_expires_at:
            self.authenticate()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # --- requests ---------------------------------------------------------

    def _retry_delay(self, response: Any, attempt: int) -> float:
        """
        Honour Retry-After when Falcon sends it, else exponential backoff.
        Falcon's 429 carries a Retry-After in seconds; guessing shorter than it
        asks just burns the next attempt.
        """
        retry_after = None
        if response is not None:
            retry_after = (getattr(response, "headers", {}) or {}).get("Retry-After")

        if retry_after:
            try:
                return min(float(retry_after), MAX_BACKOFF_SECONDS)
            except (TypeError, ValueError):
                pass

        return min(BACKOFF_BASE_SECONDS**attempt, MAX_BACKOFF_SECONDS)

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        One API call, with bounded retry on rate limiting and transient server
        errors. Returns the decoded body, or None after recording the failure.

        Auth failures propagate rather than returning None: no subsequent call
        can succeed without a token, so continuing would produce a run of
        identical failures instead of one clear one.
        """
        endpoint = f"{self.base_url}{path}"
        last_error: Optional[Exception] = None
        last_response: Any = None

        for attempt in range(MAX_RETRIES + 1):
            headers = self._headers()

            try:
                response = requests.request(
                    method,
                    endpoint,
                    headers=headers,
                    params=params,
                    json=json_body,
                    timeout=self.timeout,
                )
            except requests.exceptions.RequestException as e:
                # Connection-level faults are worth one more try; a genuinely
                # unreachable host fails the same way on the last attempt.
                last_error, last_response = e, None
                if attempt < MAX_RETRIES:
                    time.sleep(self._retry_delay(None, attempt))
                    continue
                break

            if response.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                delay = self._retry_delay(response, attempt)
                logger.warning(
                    "%s %s returned %s; retrying in %.1fs (attempt %d/%d)",
                    method,
                    path,
                    response.status_code,
                    delay,
                    attempt + 1,
                    MAX_RETRIES,
                )
                time.sleep(delay)
                continue

            try:
                response.raise_for_status()
                body = response.json()
                self._record_partial_errors(endpoint, body)
                return body
            except requests.exceptions.RequestException as e:
                last_error, last_response = e, response
                break
            except ValueError as e:
                last_error, last_response = e, response
                break

        if last_error is not None:
            self._record_failure(endpoint, last_error, last_response)
        return None

    def _record_partial_errors(self, endpoint: str, body: Any) -> None:
        """
        Surface errors returned inside a successful response.

        Falcon reports *partial* failures as HTTP 200 with a populated
        `errors[]` — some requested entities came back, others did not, and the
        reason is in the body. `raise_for_status()` sees nothing wrong, so
        without this the run reports success over evidence that is quietly
        incomplete. For a compliance fetcher that is the worst outcome: fewer
        findings than the tenant actually has, presented as a clean result.

        Recorded in `api_failures` like any other fault, so the fetcher exits
        non-zero and the reason travels with the evidence rather than being
        discarded.
        """
        if not isinstance(body, dict):
            return

        errors = body.get("errors")
        if not errors or not isinstance(errors, list):
            return

        logger.error("%s returned HTTP 200 with %d error(s): %s", endpoint, len(errors), errors)
        self.api_failures.append(
            {
                "endpoint": endpoint,
                "error": "partial success: response returned errors alongside resources",
                "api_errors": errors,
                "partial": True,
            }
        )

    def _record_failure(self, endpoint: str, error: Exception, response: Any) -> None:
        failure: Dict[str, Any] = {
            "endpoint": endpoint,
            "type": type(error).__name__,
            "message": str(error),
        }
        if response is not None:
            failure["status_code"] = getattr(response, "status_code", None)
            # Falcon returns structured errors; keep them, they name missing scopes.
            try:
                body = response.json()
                if isinstance(body, dict) and body.get("errors"):
                    failure["api_errors"] = body["errors"]
            except Exception:  # noqa: BLE001 - a non-JSON error body is not itself a failure
                pass
        self.api_failures.append(failure)
        logger.warning("API call to %s failed: %s", endpoint, error)

    # --- pagination -------------------------------------------------------

    def _page_cap_reached(self, path: str, collected: int) -> None:
        """A cap hit means the evidence is truncated, so it must be recorded."""
        self.api_failures.append(
            {
                "endpoint": f"{self.base_url}{path}",
                "type": "PaginationLimitExceeded",
                "message": (
                    f"Stopped after {MAX_PAGES} pages with {collected} records collected; "
                    "the cursor did not terminate. Evidence may be incomplete."
                ),
            }
        )
        logger.error("Pagination cap hit on %s after %d records", path, collected)

    def _cursor_stalled(self, path: str, cursor: Any, collected: int) -> None:
        """
        A pagination cursor that repeats itself.

        Breaking the loop is correct, but it must not be mistaken for reaching
        the end of the data. Recorded as a failure so the run exits non-zero:
        a truncated host list or vulnerability list that reports success is
        indistinguishable from a genuinely small, healthy estate — which is the
        most dangerous shape a compliance error can take.
        """
        self.api_failures.append(
            {
                "endpoint": f"{self.base_url}{path}",
                "type": "PaginationCursorStalled",
                "message": (
                    f"Cursor {cursor!r} repeated after {collected} records; stopped to avoid "
                    "an endless loop. Evidence may be incomplete."
                ),
            }
        )
        logger.error("Pagination cursor stalled on %s after %d records", path, collected)

    def paginate_scroll(
        self, path: str, params: Optional[Dict[str, Any]] = None, limit: int = 5000
    ) -> List[str]:
        """
        Opaque offset-token pagination (devices-scroll). Collects resource IDs.

        The token is echoed back verbatim; a server that keeps returning the
        same one would loop forever, so repeats are treated as the end.
        """
        collected: List[str] = []
        offset: Optional[str] = None
        seen_offsets: set = set()

        for _ in range(MAX_PAGES):
            page_params = dict(params or {})
            page_params["limit"] = limit
            if offset:
                page_params["offset"] = offset

            body = self.request("GET", path, params=page_params)
            if body is None:
                return collected

            resources = body.get("resources") or []
            collected.extend(resources)

            offset = ((body.get("meta") or {}).get("pagination") or {}).get("offset")

            # Normal termination: the server says there is no more, or gave us
            # nothing on this page.
            if not offset or not resources:
                return collected

            # Anomalous termination: a cursor we have already used. Stopping is
            # right — continuing would loop forever — but it is NOT the same as
            # reaching the end, and returning quietly here would present
            # truncated evidence as a complete collection.
            if offset in seen_offsets:
                self._cursor_stalled(path, offset, len(collected))
                return collected

            seen_offsets.add(offset)

        self._page_cap_reached(path, len(collected))
        return collected

    # Response keys carrying a search-after cursor, most specific first. See
    # `paginate_after` for why there is more than one.
    CURSOR_KEYS = ("after", "next", "offset")

    @staticmethod
    def _next_cursor(body: Dict[str, Any]) -> Optional[str]:
        pagination = (body.get("meta") or {}).get("pagination") or {}
        for key in FalconClient.CURSOR_KEYS:
            value = pagination.get(key)
            # String only: `offset` is an integer on the endpoints
            # `paginate_offset` serves, and feeding one back as a search-after
            # token would silently restart the walk from the beginning.
            if isinstance(value, str) and value:
                return value
        return None

    def paginate_after(
        self, path: str, params: Optional[Dict[str, Any]] = None, limit: int = 400
    ) -> List[Any]:
        """
        `after` cursor pagination. These return full entities, not IDs, so no
        second lookup is needed.

        The cursor is *sent* as `after` everywhere, but it comes back under
        different names, which is asymmetric enough to be worth spelling out:

            Spotlight   meta.pagination.after   (DomainAPIQueryPagingV1)
            Zero Trust  meta.pagination.next    (DomainSearchAfterPaging)

        Reading only `after` — which this did — meant the Zero Trust host query
        found no cursor, stopped after one page, and reported success. On any
        estate over one page that is a truncated collection presented as a
        complete one.

        `offset` is last and accepted only as a string: `DomainSearchAfterPaging`
        types it as one, while the integer-offset endpoints handled by
        `paginate_offset` use the same name for a number.

        NOTE: `DomainSearchAfterPaging` carries both `next` and `offset` and the
        spec does not say which is the token to echo back. `next` is taken as
        the more conventional of the two. **Confirm against a live tenant** — if
        Zero Trust host collection ever comes back capped at exactly one page,
        this is the first thing to check.
        """
        collected: List[Any] = []
        after: Optional[str] = None
        seen_cursors: set = set()

        for _ in range(MAX_PAGES):
            page_params = dict(params or {})
            page_params["limit"] = limit
            if after:
                page_params["after"] = after

            body = self.request("GET", path, params=page_params)
            if body is None:
                return collected

            resources = body.get("resources") or []
            collected.extend(resources)

            after = self._next_cursor(body)
            if not after or not resources:
                return collected
            if after in seen_cursors:
                self._cursor_stalled(path, after, len(collected))
                return collected
            seen_cursors.add(after)

        self._page_cap_reached(path, len(collected))
        return collected

    def paginate_offset(
        self, path: str, params: Optional[Dict[str, Any]] = None, limit: int = 500
    ) -> List[Any]:
        """
        Integer offset pagination (alerts queries, policy combined).

        Stops on an empty page even when `total` disagrees — an offset that
        stops advancing is the reliable terminator, not the reported count.

        A missing `total` is NOT a terminator. `meta.pagination` is `omitempty`
        on all three endpoints this serves (`MsaPaging` under `MsaMetaInfo`), so
        a response may legitimately arrive with no pagination block at all.
        Treating that as the end returned the first page and reported success —
        silent truncation, the failure this client has hit four times now. When
        the count is unknown the empty page is the only honest terminator, so
        the walk continues to it; a server that ignores `offset` then hits the
        page cap and is recorded as a failure, which is loud rather than quiet.
        """
        collected: List[Any] = []
        offset = 0

        for _ in range(MAX_PAGES):
            page_params = dict(params or {})
            page_params["limit"] = limit
            page_params["offset"] = offset

            body = self.request("GET", path, params=page_params)
            if body is None:
                return collected

            resources = body.get("resources") or []
            collected.extend(resources)

            total = ((body.get("meta") or {}).get("pagination") or {}).get("total")
            offset += len(resources)

            if not resources:
                return collected
            if isinstance(total, int) and offset >= total:
                return collected

        self._page_cap_reached(path, len(collected))
        return collected

    # --- entity lookup ----------------------------------------------------

    def get_entities(
        self,
        path: str,
        ids: List[str],
        method: str = "POST",
        body_key: str = "ids",
        query_key: str = "ids",
        batch_size: int = ENTITY_BATCH_SIZE,
    ) -> List[Any]:
        """
        Resolve IDs to full records in batches. POST endpoints take the batch in
        a JSON body keyed by `body_key` (`ids`, or `composite_ids` for alerts);
        GET endpoints take a repeated `ids` query param.

        IDs are de-duplicated first: a paginated query can return the same ID
        twice when records change underneath the cursor, and paying for a
        duplicate lookup also duplicates the record in the evidence.
        """
        collected: List[Any] = []
        unique_ids = list(dict.fromkeys(ids))

        for start in range(0, len(unique_ids), batch_size):
            batch = unique_ids[start : start + batch_size]
            if method.upper() == "POST":
                body = self.request("POST", path, json_body={body_key: batch})
            else:
                body = self.request("GET", path, params={query_key: batch})

            if body is None:
                continue
            collected.extend(body.get("resources") or [])

        return collected


def build_client() -> FalconClient:
    """Construct a client from the declared env vars and authenticate it."""
    client = FalconClient(
        base_url=resolve_base_url(),
        client_id=get_env("CROWDSTRIKE_CLIENT_ID"),
        client_secret=get_env("CROWDSTRIKE_CLIENT_SECRET"),
        timeout=int(os.environ.get("CROWDSTRIKE_HTTP_TIMEOUT", DEFAULT_TIMEOUT)),
    )
    client.authenticate()
    return client


def cloud_provenance(client: "FalconClient") -> Dict[str, Any]:
    """
    Which Falcon cloud this evidence came from. `cloud_region` is what the base
    URL resolves to (None for a test double); `reported_cloud_region` is what
    the tenant said at auth. An assessor reading a FedRAMP package needs to know
    the evidence came from GovCloud rather than commercial, and the reported
    value is the one that is not just a restatement of the config.
    """
    return {
        "api_base_url": client.base_url,
        "cloud_region": region_for_base_url(client.base_url),
        "reported_cloud_region": client.reported_region,
    }


def evidence_error(message: str, api_failures: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Evidence body for a run that could not collect. Still written to disk — an
    empty file is indistinguishable from a fetcher that never ran.
    """
    return {
        "status": "error",
        "message": message,
        "api_failures": api_failures or [],
        "retrieved_at": current_timestamp(),
    }

# --- the fetcher entry point, shared -----------------------------------------
#
# All seven fetchers in this category ended with the same 32 lines, differing by
# exactly one string: the output filename. That is now here, so a change to the
# failure contract happens once instead of seven times — and once more for every
# fetcher added later.
#
# Precedent for putting it in _shared: okta/_shared/okta_iam_core.py does the
# same for its category.


def evidence(
    *,
    client: "FalconClient",
    endpoint: str,
    records: List[Any],
    analysis: Dict[str, Any],
    empty_message: str,
    **extra: Any,
) -> Dict[str, Any]:
    """
    Build the evidence body every fetcher in this category returns.

    One shape, one place. `status` is `success` when anything was collected and
    `partial_or_empty` when nothing was — **both are exit-code 0 states**. A
    *fault* is signalled by `api_failures` being non-empty, never by the status.
    That separation is deliberate: an estate with no findings and a collection
    that failed must not look alike, and neither should be confused with a crash.

    `analysis` is always present, including on an empty collection. Some
    fetchers used to omit it in that branch, so a consumer reading
    `payload["analysis"]` would work on one evidence file and raise KeyError on
    another. Uniform shape is worth more than the few bytes saved.

    `**extra` carries fetcher-specific top-level keys — `filter`,
    `queried_id_count`, the firewall fetcher's containers/rule groups/rules —
    and can override a default (Zero Trust passes `data` as a dict rather than
    the usual list) because it is applied last.
    """
    body: Dict[str, Any] = {
        "status": "success" if records else "partial_or_empty",
        "api_endpoint": f"{client.base_url}{endpoint}",
        "record_count": len(records),
        "api_failures": client.api_failures,
        "data": records,
        "analysis": analysis,
        "cloud": cloud_provenance(client),
        "retrieved_at": current_timestamp(),
    }
    if not records:
        body["message"] = empty_message
    body.update(extra)
    return body


def run_fetcher(
    collect: Callable[[], Dict[str, Any]],
    output_name: str,
    logger: logging.Logger,
) -> int:
    """
    Run one fetcher and write its evidence. Returns the process exit code.

    The failure contract, in one place:

    - **The evidence file is always written**, including on a fault. A missing
      file is indistinguishable from a fetcher that never ran, which is the
      difference between "we have no evidence" and "we collected nothing".
    - **Any entry in `api_failures` exits non-zero**, even when records were
      collected. A partial collection reported as success is the failure this
      category guards against hardest — see the pagination and partial-error
      handling above for how many ways there are to hit it.
    - An unexpected exception is caught and written as an error body rather than
      escaping as a traceback, so the runner still gets a readable artifact.

    Usage, at the bottom of a fetcher:

        if __name__ == "__main__":
            sys.exit(run_fetcher(collect, "crowdstrike_hosts.json", logger))
    """
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: the fetcher loads .env itself. Once the framework's runner
    # and secret resolver pass resolved values in, this goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = collect()
    except Exception as e:  # noqa: BLE001 - evidence must be written even on an unexpected fault
        logger.error("Collection failed: %s", e)
        result = evidence_error(str(e))

    output_path = output_dir / output_name
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)

    # The reason must be reported AFTER the "Evidence saved" line above, because
    # the runner's fallback takes the tail of stderr. `report_failure` is the whole
    # failure path — it logs at error level as well as writing the status file, so
    # no caller-side logger.error is needed (or wanted: it double-logs).
    failures = result.get("api_failures") or []
    if failures:
        first = failures[0]
        detail = first.get("message") or first.get("error") or "see api_failures"
        message = (
            f"{len(failures)} API failure(s) during collection; first: "
            f"{first.get('endpoint', 'unknown endpoint')}: {detail}"
        )
        # Falcon's own exception type / HTTP status, which is NOT one of the
        # contract's categories, so report_failure drops it and metadata.error_code
        # stays empty. Passed through rather than invented: mapping these onto the
        # closed set is a behaviour change, not part of a de-duplication.
        raw_code = first.get("type") or first.get("status_code")
        report_failure(message, code=str(raw_code) if raw_code else None)
        return 1

    if result.get("status") not in {"success", "partial_or_empty"}:
        message = str(result.get("message") or "collection did not complete")
        # Not one of the contract's categories either, so it is dropped the same
        # way. Left verbatim: picking a replacement is a behaviour change.
        report_failure(message, code="collection_error")
        return 1

    return 0
