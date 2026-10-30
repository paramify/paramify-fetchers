"""Paging for the Datadog fetchers, in one place.

Import it from a fetcher the same way as the other categories' `_shared` code:

    sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
    from datadog_paging import PagingError, paginate_page_number  # noqa: E402

The rule this module enforces: a failed request never ends a walk quietly.

- A request error on the FIRST page raises `PagingError` with nothing
  collected. The fetcher reports that as a failure, so a 401 or 403 can never
  read as "no monitors" or "no hosts".
- A request error on a LATER page does not raise. The walk returns the records
  it has, as a `PagedRecords` list whose `.error` holds the `PagingError` (the
  page reached, the pages completed and the cause). The fetcher passes the list
  to `with_paging_status`, which marks the evidence `partial_failure`, never
  `success`.

A 403 or 404 that means "this product is not enabled" (Cloud SIEM, for
example) is the fetcher's call to make, on the first page only. It reads
`PagingError.status_code` and decides; this module treats every error the same.

Pagination schemes, as the Datadog API reference documents them:

- `paginate_page_number`: `page[size]` + `page[number]` (service definitions,
  security rules) and `page_size` + `page` (monitors). Pages are counted from 0.
  The walk stops on an empty page or a page shorter than the page size.
- `paginate_offset`: `page[size]` + `page[offset]` (incidents) and
  `count` + `start` (hosts). The offset moves by the number of records
  returned. The walk stops on an empty or short page.
- `paginate_cursor`: a POST body with `page.limit` + `page.cursor`, with the
  next cursor read from `meta.page.after` (security signals search). The walk
  stops when the cursor is absent or a page is empty.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import requests

logger = logging.getLogger("datadog_paging")

DEFAULT_TIMEOUT = 30
# A guard against a server that ignores the paging parameters and returns the
# same full page forever. 10,000 pages of 100 is a million records, far above
# any real estate; reaching it is reported as a partial failure, not success.
MAX_PAGES = 10_000

# `report_failure` codes (fetchers/_lib/fetcher_status.py) for a failed request.
_HTTP_CODES = {401: "auth_failed", 403: "not_authorized", 429: "rate_limited"}

Records = List[Dict[str, Any]]
# One page request: takes the paging state, returns the page's records and the
# next state, or None when this was the last page.
PageFetch = Callable[[Any], Tuple[Records, Any]]


class PagingError(Exception):
    """A page request failed. Carries where the walk stopped and what it had."""

    def __init__(
        self,
        operation: str,
        page: str,
        pages_completed: int,
        records: Records,
        cause: BaseException,
    ) -> None:
        self.operation = operation
        self.page = page
        self.pages_completed = pages_completed
        self.records = records
        self.cause = cause
        response = getattr(cause, "response", None)
        self.status_code: Optional[int] = getattr(response, "status_code", None)
        super().__init__(
            f"{operation} failed at {page} after {pages_completed} complete "
            f"page(s) and {len(records)} record(s): {type(cause).__name__}: {cause}"
        )

    @property
    def code(self) -> Optional[str]:
        """The `report_failure` code that fits the cause, if one does."""
        if self.status_code in _HTTP_CODES:
            return _HTTP_CODES[self.status_code]
        if isinstance(self.cause, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            return "target_unreachable"
        return None

    def api_failure(self) -> Dict[str, Any]:
        """One `api_failures[]` entry, in the contract's shape."""
        return {
            "operation": self.operation,
            "type": type(self.cause).__name__,
            "message": str(self.cause),
            "status_code": self.status_code,
            "page": self.page,
            "pages_completed": self.pages_completed,
        }


class PagedRecords(List[Dict[str, Any]]):
    """The records a walk collected. `.error` is set when the walk stopped early."""

    error: Optional[PagingError] = None


def request_json(
    method: str,
    url: str,
    headers: Dict[str, str],
    *,
    params: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Any:
    """One request. Raises on a transport error, an HTTP error or a body that is not JSON."""
    response = requests.request(method, url, headers=headers, params=params, json=body, timeout=timeout)
    response.raise_for_status()
    return response.json()


def walk(operation: str, fetch: PageFetch, start: Any, describe: Callable[[Any], str]) -> PagedRecords:
    """Follow pages from `start` until `fetch` says there are no more.

    Raises `PagingError` if the first page fails. A later failure stops the walk
    and is returned on `.error` with the records collected so far.
    """
    records = PagedRecords()
    state: Any = start
    pages = 0
    while state is not None:
        if pages >= MAX_PAGES:
            records.error = PagingError(
                operation, describe(state), pages, list(records),
                RuntimeError(f"stopped after {MAX_PAGES} pages; the server may be ignoring the paging parameters"),
            )
            break
        try:
            page_records, next_state = fetch(state)
        except (requests.exceptions.RequestException, ValueError) as exc:
            error = PagingError(operation, describe(state), pages, list(records), exc)
            if pages == 0:
                raise error from exc
            logger.warning("%s", error)
            records.error = error
            break
        records.extend(page_records)
        pages += 1
        state = next_state
    return records


def _records_at(payload: Any, key: Optional[str]) -> Records:
    """The record list from a page body: `payload[key]`, or the body itself when key is None."""
    found = payload if key is None else (payload.get(key) if isinstance(payload, dict) else None)
    if found is None:
        return []
    if not isinstance(found, list):
        raise ValueError(f"expected a list at {key or 'the response body'}, got {type(found).__name__}")
    return found


def paginate_page_number(
    url: str,
    headers: Dict[str, str],
    *,
    operation: str,
    page_size: int,
    size_param: str = "page[size]",
    number_param: str = "page[number]",
    records_key: Optional[str] = "data",
    params: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> PagedRecords:
    """Pages counted from 0. Stops on an empty page or one shorter than `page_size`."""

    def fetch(page: int) -> Tuple[Records, Optional[int]]:
        query = dict(params or {})
        query[size_param] = page_size
        query[number_param] = page
        data = _records_at(request_json("GET", url, headers, params=query, timeout=timeout), records_key)
        return data, (page + 1 if len(data) >= page_size else None)

    return walk(operation, fetch, 0, lambda page: f"page {page}")


def paginate_offset(
    url: str,
    headers: Dict[str, str],
    *,
    operation: str,
    page_size: int,
    size_param: str = "page[size]",
    offset_param: str = "page[offset]",
    records_key: Optional[str] = "data",
    params: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> PagedRecords:
    """Offsets from 0, moved by the records returned. Stops on an empty or short page."""

    def fetch(offset: int) -> Tuple[Records, Optional[int]]:
        query = dict(params or {})
        query[size_param] = page_size
        query[offset_param] = offset
        data = _records_at(request_json("GET", url, headers, params=query, timeout=timeout), records_key)
        return data, (offset + len(data) if len(data) >= page_size else None)

    return walk(operation, fetch, 0, lambda offset: f"{offset_param}={offset}")


def paginate_cursor(
    url: str,
    headers: Dict[str, str],
    *,
    operation: str,
    body: Dict[str, Any],
    page_size: int,
    records_key: str = "data",
    timeout: int = DEFAULT_TIMEOUT,
) -> PagedRecords:
    """POST search pages: `page.limit` / `page.cursor` in, `meta.page.after` out."""
    counter = {"page": 0}

    def fetch(cursor: str) -> Tuple[Records, Optional[str]]:
        request_body = dict(body)
        page: Dict[str, Any] = {"limit": page_size}
        if cursor:
            page["cursor"] = cursor
        request_body["page"] = page
        payload = request_json("POST", url, headers, body=request_body, timeout=timeout)
        data = _records_at(payload, records_key)
        counter["page"] += 1
        after = ((payload.get("meta") or {}).get("page") or {}).get("after") if isinstance(payload, dict) else None
        return data, (after if after and data else None)

    # "" is the first page (no cursor); None ends the walk.
    return walk(operation, fetch, "", lambda _cursor: f"page {counter['page']}")


def with_paging_status(result: Dict[str, Any], *walks: Iterable[Any]) -> Dict[str, Any]:
    """Record the paging outcome on a fetcher's result.

    Adds `metadata.partial_failure` and `metadata.api_failures` to every result.
    If any walk stopped early, the status becomes `partial_failure` and the
    message names the page reached, whatever status the fetcher computed.
    """
    errors = [w.error for w in walks if isinstance(w, PagedRecords) and w.error is not None]
    metadata = dict(result.get("metadata") or {})
    metadata["partial_failure"] = bool(errors)
    metadata["api_failures"] = [e.api_failure() for e in errors]
    result["metadata"] = metadata
    if errors:
        result["status"] = "partial_failure"
        result["error_code"] = "partial_failure"
        result["message"] = "Incomplete collection: " + "; ".join(str(e) for e in errors)
    return result


def failure_result(error: PagingError, endpoint: str, timestamp: str) -> Dict[str, Any]:
    """The result for a walk that failed on its first page: nothing was collected."""
    return {
        "status": "error",
        "error_code": error.code,
        "message": str(error),
        "api_endpoint": endpoint,
        "metadata": {"partial_failure": False, "api_failures": [error.api_failure()]},
        "retrieved_at": timestamp,
    }
