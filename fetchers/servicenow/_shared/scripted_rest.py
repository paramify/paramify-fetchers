"""Shared engine for the servicenow fetchers: one GET (or one paged walk) of a
Scripted REST endpoint, checked and written as evidence.

A fetcher in this category is an `Endpoint`: which env var holds the endpoint
URL, which query parameter takes the optional watermark, and, for an endpoint
that pages, the page size and where the records sit in each response. `run()`
does the rest, so every fetcher gets the same auth, retries, failure codes and
response checks.

A Scripted REST API is written by the instance owner, so its path, paging and
response shape differ per endpoint. That is why the URL is a whole URL and not a
path assembled from a base URL, and why paging is declared per endpoint.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import requests
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("servicenow")

USERNAME_ENV = "SERVICENOW_USERNAME"
PASSWORD_ENV = "SERVICENOW_PASSWORD"

TIMEOUT = 60
# ServiceNow answers 429 when the account's rate-limit rule trips, and an
# instance that is upgrading or waking from hibernation answers 5xx for a while.
# Retry those with the Retry-After header when present, else an increasing wait.
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 4
# A request that raises (timeout, connection reset) is retried fewer times: each
# attempt can already take the full TIMEOUT.
MAX_EXCEPTION_RETRIES = 2
BACKOFF_BASE_SECONDS = 2.0
MAX_BACKOFF_SECONDS = 60.0
# A safety stop for an endpoint that never returns a short page.
MAX_PAGES = 10_000


@dataclass(frozen=True)
class LimitOffset:
    """Paging by a page-size parameter and a record-offset parameter.

    The walk stops at the first page shorter than `limit`. Set `limit` at or
    below the endpoint's documented maximum: an endpoint that silently clamps a
    larger value returns a short first page, and the walk would stop there.
    """

    limit: int
    limit_param: str = "limit"
    offset_param: str = "offset"


@dataclass(frozen=True)
class Endpoint:
    label: str
    """What the endpoint returns, for messages: "cases", "change records"."""
    output: str
    """Evidence file name, written to $EVIDENCE_DIR."""
    url_env: str
    """Env var that holds the full endpoint URL."""
    since_env: Optional[str] = None
    """Env var that holds the optional watermark, sent as `since_param`."""
    since_param: Optional[str] = None
    paging: Optional[LimitOffset] = None
    records_path: tuple[str, ...] = ()
    """Keys from the response body to the list of records. Paged endpoints only."""

    def __post_init__(self) -> None:
        if bool(self.since_env) != bool(self.since_param):
            raise ValueError("since_env and since_param go together")
        if self.paging and not self.records_path:
            raise ValueError("a paged endpoint needs records_path")


class Abort(Exception):
    """A failure that ends the run. Nothing is written."""

    def __init__(self, reason: str, code: Optional[str] = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


def run(endpoint: Endpoint) -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    try:
        url, auth, params = _settings(endpoint)
        session = requests.Session()
        session.auth = auth
        session.headers.update({"Accept": "application/json"})
        if endpoint.paging:
            body: Any = _walk(session, url, params, endpoint)
        else:
            body = _get_json(session, url, params, endpoint.label)
    except Abort as e:
        report_failure(e.reason, e.code)
        return 1

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_path = output_dir / endpoint.output
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(body, indent=2))
    except OSError as e:
        report_failure(f"could not write evidence file: {e}", "internal_error")
        return 1

    logger.info("Evidence saved to %s", output_path)
    return 0


def _settings(endpoint: Endpoint) -> tuple[str, tuple[str, str], dict[str, Any]]:
    values = {}
    for env in (USERNAME_ENV, PASSWORD_ENV, endpoint.url_env):
        values[env] = os.environ.get(env, "").strip()
        if not values[env]:
            raise Abort(f"{env} is not set", "bad_config")

    url = values[endpoint.url_env].rstrip("/")
    # Basic auth sends the password with every request.
    if not url.startswith("https://"):
        raise Abort(f"{endpoint.url_env} must be an https:// URL", "bad_config")

    params: dict[str, Any] = {}
    if endpoint.since_env and endpoint.since_param:
        since = os.environ.get(endpoint.since_env, "").strip()
        if since:
            params[endpoint.since_param] = since

    return url, (values[USERNAME_ENV], values[PASSWORD_ENV]), params


def _walk(session: requests.Session, url: str, params: dict[str, Any], endpoint: Endpoint) -> dict:
    paging = endpoint.paging
    assert paging is not None
    records: list[Any] = []
    previous: Optional[list[Any]] = None
    for page_number in range(MAX_PAGES):
        page_params = {**params, paging.limit_param: paging.limit, paging.offset_param: len(records)}
        body = _get_json(session, url, page_params, endpoint.label)
        page = _dig(body, endpoint.records_path)
        if not isinstance(page, list):
            raise Abort(
                f"ServiceNow {endpoint.label} endpoint returned no record list at "
                f"{'.'.join(endpoint.records_path)} (offset {len(records)})",
                "bad_config",
            )
        # An endpoint that ignores the offset parameter returns the same full
        # page forever. Without this check the walk duplicates it MAX_PAGES times.
        if page and page == previous:
            raise Abort(
                f"ServiceNow {endpoint.label} endpoint returned the same page for offset "
                f"{len(records) - len(page)} and {len(records)}; it does not appear to "
                f"support the {paging.offset_param!r} parameter",
                "bad_config",
            )
        records.extend(page)
        previous = page
        if len(page) < paging.limit:
            return {"record_count": len(records), "page_count": page_number + 1, "records": records}
    raise Abort(
        f"ServiceNow {endpoint.label} endpoint still had records after {MAX_PAGES} pages",
        "internal_error",
    )


def _dig(body: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(body, dict):
            return None
        body = body.get(key)
    return body


def _get_json(session: requests.Session, url: str, params: dict[str, Any], label: str) -> Any:
    resp = _request(session, url, params, label)
    _check_status(resp, label)

    try:
        body = resp.json()
    except ValueError:
        # A 200 that is not JSON is usually an SSO, login or instance
        # hibernation page. Saving it would report a failed collection as success.
        raise Abort(
            f"ServiceNow {label} endpoint did not return JSON "
            f"(Content-Type: {resp.headers.get('Content-Type')})",
            "bad_config",
        ) from None

    # Scripted REST endpoints in this category report their own outcome in
    # result.status. An endpoint that has no such field is not checked.
    result = body.get("result") if isinstance(body, dict) else None
    if not isinstance(result, dict):
        return body
    status = result.get("status")
    if status is not None and status != "success":
        detail = result.get("message") or result.get("error") or ""
        raise Abort(f"ServiceNow {label} endpoint reported status {status!r}: {detail}".rstrip(": "))
    return body


def _request(
    session: requests.Session, url: str, params: dict[str, Any], label: str
) -> requests.Response:
    retries = exception_retries = 0
    while True:
        try:
            # Never follow a redirect: it is a login page, not the data, and
            # following it would send the credential to wherever it points.
            resp = session.request("GET", url, params=params, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException as e:
            if exception_retries < MAX_EXCEPTION_RETRIES:
                time.sleep(_backoff(exception_retries))
                exception_retries += 1
                continue
            raise Abort(f"could not reach ServiceNow {label} endpoint: {e}", "target_unreachable") from None
        if resp.status_code in RETRY_STATUS and retries < MAX_RETRIES:
            time.sleep(_retry_after(resp) or _backoff(retries))
            retries += 1
            continue
        return resp


def _check_status(resp: requests.Response, label: str) -> None:
    status = resp.status_code
    if status == 200:
        return
    if status == 401:
        raise Abort("ServiceNow rejected the credential (HTTP 401)", "auth_failed")
    if status == 403:
        raise Abort(f"ServiceNow denied access to {label} endpoint (HTTP 403)", "not_authorized")
    if 300 <= status < 400:
        raise Abort(
            f"ServiceNow {label} endpoint redirected (HTTP {status}) to "
            f"{resp.headers.get('Location')}; check the URL, and that the account "
            "can use basic auth and is not sent to a single sign-on page",
            "bad_config",
        )
    if status == 429:
        code = "rate_limited"
    elif status >= 500:
        code = "target_unreachable"
    else:
        # 400 and 404 usually mean a wrong URL or a parameter the endpoint does
        # not accept.
        code = "bad_config"
    raise Abort(f"ServiceNow {label} endpoint returned HTTP {status}: {resp.text[:300]}", code)


def _retry_after(resp: requests.Response) -> Optional[float]:
    value = resp.headers.get("Retry-After", "")
    try:
        return min(float(value), MAX_BACKOFF_SECONDS)
    except ValueError:
        return None


def _backoff(attempt: int) -> float:
    return min(BACKOFF_BASE_SECONDS * 2**attempt, MAX_BACKOFF_SECONDS)
