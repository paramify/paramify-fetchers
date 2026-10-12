"""The shared engine behind every `kind: discovery` fetcher.

A discovery fetcher answers one question: what can these credentials see? Every
platform answers it the same way — page through a list of collection
endpoints, note which could be read, keep a few identifying fields per record —
so that loop lives here once, and a platform's fetcher.py is a table of
`Resource`s plus the one thing that really differs between platforms: how its
API pages (a `pages` function).

The document it writes is framework/schemas/discovery_schema.json. The rules
this module exists to enforce:

- A resource that could not be read is never written as an empty list. Its
  status is `denied`, `error` or `not_enabled`, its count is null, and it says
  why. A listing that failed partway is `truncated` with a lower-bound count.
- People are counted, never listed. A `count_only` resource writes `items: null`
  and only aggregate summaries.
- A call that fails for a reason other than a refusal (`error`) fails the run
  (exit 1, `partial_failure`), so a scheduled discovery that silently lost half
  its answers shows up red. A refusal (`denied`) is an answer, and exits 0.

Import it the same way as fetcher_status:

    SCRIPT_DIR = Path(__file__).resolve().parent
    sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
    from discovery import Resource, HttpClient, ...   # noqa: E402

See docs/discovery.md.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

import requests
from fetcher_status import report_failure

__all__ = [
    "SCHEMA_VERSION",
    "CallFailed",
    "HttpClient",
    "Resource",
    "by",
    "enumerate_resource",
    "failure_code",
    "run",
    "setup_logging",
    "write",
]

SCHEMA_VERSION = "0.1"

logger = logging.getLogger("discovery")

Pages = Callable[["Resource"], Iterable[List[Any]]]


class CallFailed(Exception):
    """A call that did not return what was asked for.

    `status` is the document status it maps to (denied / error / not_enabled);
    `http_status` is kept so a fetcher can pick the right failure code when the
    call that failed is the one the whole run depends on.
    """

    def __init__(self, status: str, reason: str, http_status: Optional[int] = None):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.http_status = http_status


def failure_code(http_status: Optional[int]) -> Optional[str]:
    """The fetcher_status code for a failed call, or None when none fits."""
    return {
        401: "auth_failed",
        403: "not_authorized",
        429: "rate_limited",
        None: "target_unreachable",
    }.get(http_status)


def _reason_from_body(resp: requests.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        for key in ("message", "error", "errors", "detail"):
            if body.get(key):
                return str(body[key])[:300]
    return " ".join((resp.text or "").split())[:200] or "no body"


class HttpClient:
    """GET-only JSON client: base URL, fixed headers, pacing and 429 retries.

    `pace` is the pause before every request, for APIs with a per-second cap.
    `retry_waits` is the backoff schedule for a 429, one entry per retry. Both
    can be overridden from the environment (DISCOVERY_PACE_SECONDS,
    DISCOVERY_RETRY_WAITS) so a test or a slow tenant does not need a code change.
    """

    def __init__(
        self,
        base_url: str,
        headers: Mapping[str, str],
        *,
        pace: float = 0.0,
        retry_waits: Sequence[float] = (10, 20, 30),
        timeout: float = 60,
        session: Optional[requests.Session] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = dict(headers)
        self.pace = float(os.environ.get("DISCOVERY_PACE_SECONDS", pace))
        env_waits = os.environ.get("DISCOVERY_RETRY_WAITS")
        self.retry_waits = [float(w) for w in env_waits.split()] if env_waits is not None else list(retry_waits)
        self.timeout = timeout
        self.session = session or requests.Session()

    def get_json(self, path: str, params: Optional[Mapping[str, Any]] = None) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        for wait in [*self.retry_waits, None]:
            if self.pace:
                time.sleep(self.pace)
            try:
                resp = self.session.get(url, headers=self.headers, params=params, timeout=self.timeout)
            except requests.RequestException as e:
                raise CallFailed("error", f"request failed: {e}") from e
            if resp.status_code == 429 and wait is not None:
                logger.warning("throttled on GET %s; retrying in %ss", path, wait)
                time.sleep(wait)
                continue
            break
        if resp.status_code == 429:
            raise CallFailed("error", "HTTP 429: throttled, gave up after retries", 429)
        if resp.status_code in (401, 403):
            raise CallFailed("denied", f"HTTP {resp.status_code}: {_reason_from_body(resp)}", resp.status_code)
        if resp.status_code != 200:
            raise CallFailed("error", f"HTTP {resp.status_code}: {_reason_from_body(resp)}", resp.status_code)
        try:
            return resp.json()
        except ValueError as e:
            raise CallFailed("error", "response was not JSON", 200) from e


@dataclass
class Resource:
    """One resource type a platform can list.

    `type` is the stable singular name the document uses. `path` and `params`
    are whatever the platform's `pages` function needs to make the call — a URL
    path for a REST API, a CLI command for one driven through a CLI. `source`
    is how the call is shown to a reader; it defaults to `GET <path>?<params>`,
    so a platform that is not a REST GET sets it.

    `id` and `name` name the record fields that identify an item; `fields` are
    the extra attributes worth showing; `extra` adds computed ones. A record
    that is a bare string (a name, an ARN) is its own id and name. `count_only`
    keeps every record out of the document — use it for anything about people,
    and for types too numerous to list. `summary` aggregates over all records
    (see `by`). `label` is the singular name a person reads ("EC2 instance");
    without one a reader falls back to the type name. `note` says how to read the
    count when the general rules would mislead.
    """

    type: str
    path: str
    params: Dict[str, Any] = field(default_factory=dict)
    id: str = "id"
    name: str = "name"
    fields: Sequence[str] = ()
    extra: Optional[Callable[[dict], Dict[str, Any]]] = None
    count_only: bool = False
    summary: Optional[Callable[[List[dict]], Dict[str, Any]]] = None
    source: Optional[str] = None
    label: Optional[str] = None
    note: Optional[str] = None

    def __post_init__(self) -> None:
        if self.source is None:
            query = "&".join(f"{k}={v}" for k, v in self.params.items())
            self.source = f"GET {self.path}" + (f"?{query}" if query else "")

    def project(self, record: Any) -> dict:
        if not isinstance(record, dict):
            return {"id": str(record), "name": str(record)}
        item = {
            "id": str(record.get(self.id)),
            "name": record.get(self.name),
        }
        for f in self.fields:
            item[f] = record.get(f)
        if self.extra:
            item.update(self.extra(record))
        return item


def by(*fields: str) -> Callable[[List[dict]], Dict[str, Any]]:
    """Summary: a count per value of each field, e.g. {"by_status": {"active": 88}}."""

    def bucket(value: Any) -> str:
        if value is None:
            return "unknown"
        if isinstance(value, bool):
            return "yes" if value else "no"
        return str(value)

    def summarize(records: List[dict]) -> Dict[str, Any]:
        return {f"by_{f}": dict(Counter(bucket(r.get(f)) for r in records)) for f in fields}

    return summarize


def enumerate_resource(
    resource: Resource, pages: Pages, scope: Optional[Mapping[str, Any]] = None
) -> dict:
    """List one resource type and return its resources[] entry. Never raises
    for a failed call: the failure is the entry's status.

    `scope` qualifies the entry when a platform lists the same type in several
    places (an AWS region, an Azure subscription). Each (type, scope) pair is
    its own entry with its own status, so "denied in one region" never becomes
    "denied" for the whole type.
    """
    records: List[Any] = []
    pages_read = 0
    status, reason = "ok", None
    try:
        for page in pages(resource):
            records.extend(page)
            pages_read += 1
    except CallFailed as e:
        status, reason = e.status, e.reason

    read_any = status == "ok" or pages_read > 0
    entry: Dict[str, Any] = {"type": resource.type}
    if resource.label:
        entry["label"] = resource.label
    if resource.note:
        entry["note"] = resource.note
    if scope:
        entry["scope"] = dict(scope)
    entry.update({
        "status": status,
        "count": len(records) if read_any else None,
        "truncated": status != "ok" and pages_read > 0,
        "items": None if resource.count_only or not read_any else [resource.project(r) for r in records],
        "source": resource.source,
    })
    if reason:
        entry["reason"] = reason
    if resource.summary and records and all(isinstance(r, dict) for r in records):
        entry["summary"] = resource.summary(records)

    where = f" ({_scope_text(scope)})" if scope else ""
    if entry["truncated"]:
        logger.warning("%s%s: %s (partial: %d listed)", resource.type, where, reason, len(records))
    elif status not in ("ok", "denied", "not_enabled"):
        logger.warning("%s%s: %s", resource.type, where, reason)
    return entry


def _scope_text(scope: Optional[Mapping[str, Any]]) -> str:
    return ", ".join(str(v) for v in (scope or {}).values())


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# How many failures the status-file reason names before summarizing the rest.
_MAX_NAMED_ERRORS = 8


def write(
    *,
    platform: str,
    output_name: str,
    entries: List[dict],
    identity: Optional[str] = None,
    scope: Optional[Mapping[str, Any]] = None,
) -> int:
    """Write the document to $EVIDENCE_DIR and return the exit code.

    For a fetcher that builds its entries itself (in parallel across regions,
    say); `run` is the sequential shortcut that calls this.
    """
    doc = {
        "schema_version": SCHEMA_VERSION,
        "platform": platform,
        "identity": identity,
        "scope": dict(scope or {}),
        "collected_at": _utc_now(),
        "resources": entries,
    }
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / output_name
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False))

    # One line per type, however many scopes it was listed in.
    totals: Dict[str, List[Any]] = {}
    for e in entries:
        t = totals.setdefault(e["type"], [0, 0, 0])
        t[0] += e["count"] or 0
        t[1] += 1
        t[2] += e["status"] != "ok"
    logger.info(" ".join(
        f"{name}={n}" + (f"({bad}/{scopes} unread)" if bad else "")
        for name, (n, scopes, bad) in totals.items()
    ))

    errors = [e for e in entries if e["status"] == "error"]
    if errors:
        named = [
            f"{e['type']}" + (f" ({_scope_text(e.get('scope'))})" if e.get("scope") else "") + f": {e['reason']}"
            for e in errors[:_MAX_NAMED_ERRORS]
        ]
        more = len(errors) - len(named)
        reason = "some resource types could not be listed: " + "; ".join(named)
        if more:
            reason += f"; and {more} more"
        report_failure(reason, "partial_failure")
        return 1
    logger.info("discovery saved to %s", out)
    return 0


def run(
    *,
    platform: str,
    output_name: str,
    resources: Iterable[Resource],
    pages: Pages,
    identity: Optional[str] = None,
    scope: Optional[Mapping[str, Any]] = None,
    leading: Iterable[dict] = (),
) -> int:
    """Enumerate every resource in order, write the document, and return the
    exit code. `leading` entries (an account record the fetcher already read to
    establish identity, say) go first, as-is."""
    entries = list(leading) + [enumerate_resource(r, pages) for r in resources]
    return write(platform=platform, output_name=output_name, entries=entries,
                 identity=identity, scope=scope)


def setup_logging(name: str) -> None:
    """The stderr format the other fetchers use, so run logs read the same."""
    logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s %(levelname)s {name} %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

