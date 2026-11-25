"""Loki log ingestion: whether each expected log source is arriving in Loki, and how recently.

Each expected source is a name and a LogQL stream selector, optionally followed by line filters, such as
falco={namespace="falco"}. For each one the fetcher counts the lines that arrived in a recent window, finds the newest
line within a longer search window, and counts the streams carrying it, through Loki's query API, GET only. Log lines
are never copied: only counts, timestamps and the number of streams.

A source whose silence is normal, such as an alerting tool that logs only when something happens, can be marked
quiet and paired with a heartbeat: another expected source, such as that tool's periodic health or metrics lines,
that must keep arriving. A quiet source is judged by its heartbeat, so silence is told apart from a broken
collection path; a quiet source with no heartbeat leaves the overall verdict unknown.

Collection-failure convention (docs/authoring_fetcher_guide.md, step 3): a failed GET, or a response that is not the
shape Loki documents, is recorded in `api_failures` and leaves that source unread; the run exits non-zero when
`api_failures` is non-empty. A well-formed empty response means no matching lines, which is 0, not unknown.
"""

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

NAME = "loki_log_ingestion"
OUTPUT = "loki_log_ingestion.json"
SOURCES_ENV = "LOKI_EXPECTED_SOURCES"
WINDOW_ENV = "LOKI_WINDOW_MINUTES"
SEARCH_ENV = "LOKI_SEARCH_HOURS"
MAX_AGE_ENV = "LOKI_MAX_AGE_MINUTES"
QUIET_ENV = "LOKI_QUIET_SOURCES"
DEFAULT_WINDOW_MINUTES = 60
DEFAULT_SEARCH_HOURS = 24
TIMEOUT = 60
MAX_RETRIES = 3
RETRY_STATUS = {429, 500, 502, 503, 504}
CODES = {400: "bad_config", 401: "auth_failed", 403: "not_authorized", 404: "bad_config", 429: "rate_limited"}
SOURCE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
# Line filters only (|= != |~ !~ with a quoted or backticked string): no parsers, formatters or label filters.
LINE_FILTERS = re.compile(r'^(?:\s*(?:\|=|!=|\|~|!~)\s*(?:"(?:[^"\\]|\\.)*"|`[^`]*`))*\s*$')

logger = logging.getLogger(NAME)


# --- settings ---

def _whole(env: str, default: Optional[int], low: int, high: int, failures: List[Dict[str, str]]) -> Optional[int]:
    raw = (os.environ.get(env) or "").strip()
    if not raw:
        return default
    if raw.isdigit() and low <= int(raw) <= high:
        return int(raw)
    failures.append({"operation": f"config {env}", "type": "ValueError",
                     "message": f"{env}={raw!r} must be a whole number from {low} to {high}"})
    return default


def split_selector(query: str) -> Optional[Tuple[str, str]]:
    """(stream selector, line filters) of a query, or None when it is not a braced selector followed only by line
    filters. Braces and quotes inside label values are respected."""
    query = query.strip()
    if not query.startswith("{"):
        return None
    quote = None
    for i, ch in enumerate(query):
        if quote:
            if ch == "\\" and quote == '"':
                continue
            if ch == quote and query[i - 1] != "\\":
                quote = None
        elif ch in "\"`":
            quote = ch
        elif ch == "}":
            stream, filters = query[:i + 1], query[i + 1:].strip()
            return (stream, filters) if LINE_FILTERS.match(filters) else None
    return None


def parse_sources(raw: Optional[str]) -> Tuple[List[Dict[str, str]], List[str]]:
    """(sources, invalid entries) from name=query entries separated by semicolons. A query is a LogQL stream selector
    in braces, optionally followed by line filters (|= != |~ !~), so a source can be one kind of line in a stream."""
    sources: List[Dict[str, str]] = []
    invalid: List[str] = []
    seen = set()
    for entry in (raw or "").split(";"):
        entry = entry.strip()
        if not entry:
            continue
        name, sep, query = entry.partition("=")
        name, query = name.strip(), query.strip()
        parts = split_selector(query) if sep else None
        if parts is None or not SOURCE_NAME.match(name) or name.lower() in seen:
            invalid.append(entry)
            continue
        seen.add(name.lower())
        sources.append({"name": name, "selector": query, "stream_selector": parts[0]})
    return sources, invalid


def parse_quiet(raw: Optional[str], sources: List[Dict[str, str]]) -> Tuple[Dict[str, Optional[str]], List[str]]:
    """({quiet source: heartbeat source or None}, problems) from comma-separated quiet[:heartbeat] entries. Both names
    must be expected sources, and a heartbeat can't itself be quiet."""
    names = {s["name"].lower(): s["name"] for s in sources}
    quiet: Dict[str, Optional[str]] = {}
    problems: List[str] = []
    for entry in (raw or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        q, _, hb = (p.strip() for p in entry.partition(":"))
        if q.lower() not in names or (hb and hb.lower() not in names) or (hb and hb.lower() == q.lower()):
            problems.append(f"{entry!r}: each name must be an expected source, and a source can't be its own heartbeat")
            continue
        quiet[names[q.lower()]] = names[hb.lower()] if hb else None
    for q, hb in quiet.items():
        if hb in quiet:
            problems.append(f"{q}:{hb}: a heartbeat can't itself be a quiet source")
    return quiet, problems


# --- pure transforms ---

class Malformed(ValueError):
    """A success response that is not the shape Loki documents: the read failed, so the result stays unknown."""


def _data(body: Dict[str, Any], result_type: str) -> List[Any]:
    data = body.get("data")
    if not isinstance(data, dict) or data.get("resultType") != result_type or not isinstance(data.get("result"), list):
        raise Malformed(f"expected data.resultType {result_type!r} with a data.result list")
    return data["result"]


def vector_value(body: Dict[str, Any]) -> int:
    """The single number of an instant vector query; a well-formed empty vector means no lines, so 0."""
    result = _data(body, "vector")
    if not result:
        return 0
    if len(result) != 1:
        raise Malformed(f"expected one sample from sum(), got {len(result)}")
    try:
        value = float(result[0]["value"][1])
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise Malformed(f"sample value unreadable: {exc}") from exc
    if value < 0 or value != int(value):
        raise Malformed(f"a line count must be a whole number, got {value}")
    return int(value)


def newest_timestamp(body: Dict[str, Any]) -> Optional[int]:
    """The newest entry time, in nanoseconds, of a streams result; None when a well-formed result has no entries."""
    stamps = []
    for stream in _data(body, "streams"):
        values = stream.get("values") if isinstance(stream, dict) else None
        if not isinstance(values, list):
            raise Malformed("a stream has no values list")
        for v in values:
            if not isinstance(v, list) or not v or not str(v[0]).isdigit():
                raise Malformed("an entry has no nanosecond timestamp")
            stamps.append(int(v[0]))
    return max(stamps) if stamps else None


def stream_count(body: Dict[str, Any]) -> int:
    data = body.get("data")
    if not isinstance(data, list) or not all(isinstance(d, dict) for d in data):
        raise Malformed("expected data to be a list of label sets")
    return len(data)


def source_record(source: Dict[str, str], lines: Optional[int], newest_read: bool, newest_ns: Optional[int],
                  streams: Optional[int], now: datetime, max_age_minutes: Optional[int]) -> Dict[str, Any]:
    read = lines is not None and newest_read and streams is not None
    exact = (now.timestamp() - newest_ns / 1e9) / 60 if newest_ns else None
    stale = None
    if read and max_age_minutes:
        # The exact age is compared, so a line 60.04 minutes old is stale against 60; it is rounded only for display.
        stale = exact is None or exact > max_age_minutes
    return {
        "name": source["name"],
        "selector": source["selector"],
        "read": read,
        "lines_in_window": lines,
        "streams_in_window": streams,
        "newest_entry": datetime.fromtimestamp(newest_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        if newest_ns else None,
        "minutes_since_newest": round(exact, 1) if exact is not None and newest_read else None,
        "seen_in_search_window": bool(newest_ns) if newest_read else None,
        "ingesting": lines > 0 if lines is not None else None,
        "stale": stale,
    }


def apply_quiet(records: List[Dict[str, Any]], quiet: Dict[str, Optional[str]], max_age_minutes: Optional[int]) -> None:
    """Mark quiet sources and judge each by its heartbeat: live when the heartbeat is read, ingesting and (once a
    maximum age is set) not stale. Without a heartbeat, or with it unread, a quiet source's path is unknown."""
    by_name = {r["name"]: r for r in records}
    for r in records:
        hb_name = quiet.get(r["name"]) if r["name"] in quiet else None
        r["quiet"] = r["name"] in quiet
        r["heartbeat"] = hb_name
        if not r["quiet"]:
            r["collection_path_live"] = r["ingesting"]
            continue
        hb = by_name.get(hb_name) if hb_name else None
        if hb is None or not hb["read"]:
            r["collection_path_live"] = None
        else:
            r["collection_path_live"] = bool(hb["ingesting"]) and not (max_age_minutes and hb["stale"])


def summarize(records: List[Dict[str, Any]], window_minutes: int, search_hours: int,
              max_age_minutes: Optional[int]) -> Dict[str, Any]:
    """Counts over the expected sources; a count needing a source that was not read is null, not 0. Quiet sources are
    left out of the ingesting and staleness counts and judged by their heartbeat instead."""
    any_unread = any(not r["read"] for r in records)
    judged = bool(records) and not any_unread
    steady = [r for r in records if not r.get("quiet")]
    quiet = [r for r in records if r.get("quiet")]
    not_ingesting = [r["name"] for r in steady if r["ingesting"] is False]
    ages = [r["minutes_since_newest"] for r in steady if r["minutes_since_newest"] is not None]
    no_heartbeat = [r["name"] for r in quiet if not r.get("heartbeat")]
    quiet_dead = [r["name"] for r in quiet if r.get("collection_path_live") is False]
    verdict = None
    if judged and not no_heartbeat:
        verdict = not not_ingesting and not quiet_dead
    return {
        "expected_sources": [r["name"] for r in records],
        "expected_sources_count": len(records),
        "window_minutes": window_minutes,
        "search_hours": search_hours,
        "max_age_minutes": max_age_minutes,
        "sources_unread": sum(1 for r in records if not r["read"]),
        "sources_ingesting": sum(1 for r in steady if r["ingesting"]) if judged else None,
        "sources_not_ingesting": len(not_ingesting) if judged else None,
        "sources_not_ingesting_names": sorted(not_ingesting) if judged else None,
        "sources_not_seen_in_search_window": sum(1 for r in steady if r["seen_in_search_window"] is False) if judged else None,
        "longest_minutes_since_newest_entry": max(ages) if judged and ages else None,
        "sources_stale": sum(1 for r in steady if r["stale"]) if judged and max_age_minutes else None,
        "quiet_sources": sorted(r["name"] for r in quiet),
        "quiet_sources_without_heartbeat": sorted(no_heartbeat),
        "quiet_sources_heartbeat_not_live": sorted(quiet_dead) if judged else None,
        "all_expected_sources_ingesting": verdict,
    }


# --- collection ---

class LokiClient:
    def __init__(self, base_url: str, token: Optional[str] = None, tenant: Optional[str] = None, session: Any = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.headers = {"Accept": "application/json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        if tenant:
            self.headers["X-Scope-OrgID"] = tenant
        self.api_failures: List[Dict[str, Any]] = []
        self.failure_codes: List[str] = []

    def get(self, operation: str, path: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """GET only; None (and a recorded failure) when it cannot be read or Loki answers anything but success."""
        response = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.get(f"{self.base_url}{path}", params=params, timeout=TIMEOUT,
                                            allow_redirects=False, headers=self.headers)
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
            return self._fail(operation, f"HTTP {response.status_code}", (response.text or "")[:300],
                              CODES.get(response.status_code, "partial_failure"))
        try:
            body = response.json()
        except ValueError as exc:
            return self._fail(operation, "ValueError", f"response was not JSON: {exc}; check the base URL", "partial_failure")
        if not isinstance(body, dict):
            return self._fail(operation, "MalformedResponse", "response body is not a JSON object; the result is left "
                              "unknown", "partial_failure")
        if body.get("status") != "success":
            return self._fail(operation, "QueryError", str(body.get("error") or body)[:300], "partial_failure")
        return body

    def _fail(self, operation: str, kind: str, message: str, code: str) -> None:
        self.api_failures.append({"operation": operation, "type": kind, "message": message})
        self.failure_codes.append(code)
        logger.error("%s failed: %s", operation, kind)
        return None


def _ns(when: datetime) -> str:
    return str(int(when.timestamp() * 1e9))


def _read(client: LokiClient, operation: str, path: str, params: Dict[str, Any], parse) -> Tuple[bool, Any]:
    """(read, value): a failed GET or a malformed body is recorded as a failure and reads as not read."""
    body = client.get(operation, path, params)
    if body is None:
        return False, None
    try:
        return True, parse(body)
    except Malformed as exc:
        client._fail(operation, "MalformedResponse", f"{exc}; the result is left unknown", "partial_failure")
        return False, None


def collect_source(client: LokiClient, source: Dict[str, str], now: datetime, window_minutes: int, search_hours: int,
                   max_age_minutes: Optional[int]) -> Dict[str, Any]:
    name, selector = source["name"], source["selector"]
    stream = source.get("stream_selector") or selector
    _, lines = _read(client, f"lines in window ({name})", "/loki/api/v1/query", {
        "query": f"sum(count_over_time({selector} [{window_minutes}m]))", "time": _ns(now)}, vector_value)
    newest_read, newest = _read(client, f"newest entry ({name})", "/loki/api/v1/query_range", {
        "query": selector, "start": _ns(now - timedelta(hours=search_hours)), "end": _ns(now),
        "limit": "1", "direction": "backward"}, newest_timestamp)
    # The series API takes only a stream selector, so streams are counted before any line filter.
    _, streams = _read(client, f"streams in window ({name})", "/loki/api/v1/series", {
        "match[]": stream, "start": _ns(now - timedelta(minutes=window_minutes)), "end": _ns(now)}, stream_count)
    return source_record(source, lines, newest_read, newest, streams, now, max_age_minutes)


def collect(client: LokiClient, sources: List[Dict[str, str]], window_minutes: int, search_hours: int,
            max_age_minutes: Optional[int], now: Optional[datetime] = None,
            quiet: Optional[Dict[str, Optional[str]]] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    records = [collect_source(client, s, now, window_minutes, search_hours, max_age_minutes) for s in sources]
    apply_quiet(records, quiet or {}, max_age_minutes)
    return {"results": {"sources": records, "as_of": now.strftime("%Y-%m-%dT%H:%M:%SZ")},
            "summary": summarize(records, window_minutes, search_hours, max_age_minutes)}


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    out_dir.mkdir(parents=True, exist_ok=True)
    metadata: Dict[str, Any] = {"datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "api_failures": []}
    failures: List[Dict[str, str]] = []
    window = _whole(WINDOW_ENV, DEFAULT_WINDOW_MINUTES, 1, 1440, failures)
    search = _whole(SEARCH_ENV, DEFAULT_SEARCH_HOURS, 1, 720, failures)
    max_age = _whole(MAX_AGE_ENV, None, 1, 43200, failures)
    sources, invalid = parse_sources(os.environ.get(SOURCES_ENV))
    failures += [{"operation": f"config {SOURCES_ENV}", "type": "ValueError",
                  "message": f"{entry!r} is not name={{stream selector}} with only line filters after it, or repeats "
                             "a name"} for entry in invalid]
    quiet, quiet_problems = parse_quiet(os.environ.get(QUIET_ENV), sources)
    failures += [{"operation": f"config {QUIET_ENV}", "type": "ValueError", "message": m} for m in quiet_problems]
    if not sources and not invalid:
        failures.append({"operation": f"config {SOURCES_ENV}", "type": "ValueError",
                         "message": "no expected sources set: nothing to judge"})
    base_url = (os.environ.get("LOKI_BASE_URL") or "").strip()
    if not base_url:
        failures.append({"operation": "config", "type": "ValueError", "message": "Missing required setting: LOKI_BASE_URL"})
    evidence: Dict[str, Any] = {"results": {}, "summary": summarize([], window or 0, search or 0, max_age)}
    code = "bad_config" if failures else None
    if base_url:
        metadata["base_url"] = base_url.rstrip("/")
        metadata["tenant_id"] = (os.environ.get("LOKI_TENANT_ID") or "").strip() or None
        client = LokiClient(base_url, os.environ.get("LOKI_TOKEN") or None, metadata["tenant_id"])
        evidence = collect(client, sources, window or DEFAULT_WINDOW_MINUTES, search or DEFAULT_SEARCH_HOURS, max_age,
                           quiet=quiet)
        failures += client.api_failures
        code = code or (client.failure_codes[0] if client.failure_codes else None)
    metadata["api_failures"] = failures
    metadata["partial_failure"] = bool(failures)
    path = out_dir / OUTPUT
    path.write_text(json.dumps({"metadata": metadata, **evidence}, indent=2, sort_keys=True))
    logger.info("Evidence saved to %s", path)
    if failures:
        first = failures[0]
        report_failure(f"Loki {first['operation']} failed: {first['type']}", code)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
