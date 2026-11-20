"""Loki log ingestion: whether each expected log source is arriving in Loki, and how recently.

Each expected source is a name and a LogQL stream selector, such as falco={namespace="falco"}. For each one the
fetcher counts the lines that arrived in a recent window, finds the newest line within a longer search window, and
counts the streams carrying it, through Loki's query API, GET only. Log lines are never copied: only counts,
timestamps and the number of streams.

Collection-failure convention (docs/authoring_fetcher_guide.md, step 3): a failed GET is recorded in `api_failures`
and leaves that source's fields null; the run exits non-zero when `api_failures` is non-empty.
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
DEFAULT_WINDOW_MINUTES = 60
DEFAULT_SEARCH_HOURS = 24
TIMEOUT = 60
MAX_RETRIES = 3
RETRY_STATUS = {429, 500, 502, 503, 504}
CODES = {400: "bad_config", 401: "auth_failed", 403: "not_authorized", 404: "bad_config", 429: "rate_limited"}
SOURCE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")

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


def parse_sources(raw: Optional[str]) -> Tuple[List[Dict[str, str]], List[str]]:
    """(sources, invalid entries) from name=selector entries separated by semicolons. A selector is a LogQL stream
    selector in braces, with no pipeline after it, so the counts are of the stream as stored."""
    sources: List[Dict[str, str]] = []
    invalid: List[str] = []
    seen = set()
    for entry in (raw or "").split(";"):
        entry = entry.strip()
        if not entry:
            continue
        name, sep, selector = entry.partition("=")
        name, selector = name.strip(), selector.strip()
        if not sep or not SOURCE_NAME.match(name) or not (selector.startswith("{") and selector.endswith("}")) \
                or name.lower() in seen:
            invalid.append(entry)
            continue
        seen.add(name.lower())
        sources.append({"name": name, "selector": selector})
    return sources, invalid


# --- pure transforms ---

def vector_value(data: Optional[Dict[str, Any]]) -> Optional[int]:
    """The single number of an instant vector query; an empty vector means no lines, so 0."""
    if data is None:
        return None
    result = (data.get("data") or {}).get("result")
    if not isinstance(result, list):
        return None
    if not result:
        return 0
    try:
        return int(float(result[0]["value"][1]))
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def newest_timestamp(data: Optional[Dict[str, Any]]) -> Tuple[bool, Optional[int]]:
    """(read, newest entry time in nanoseconds or None when there is none) from a streams result."""
    if data is None:
        return False, None
    result = (data.get("data") or {}).get("result")
    if not isinstance(result, list):
        return False, None
    stamps = [int(v[0]) for s in result for v in s.get("values") or [] if v and str(v[0]).isdigit()]
    return True, max(stamps) if stamps else None


def source_record(source: Dict[str, str], lines: Optional[int], newest_read: bool, newest_ns: Optional[int],
                  streams: Optional[int], now: datetime, max_age_minutes: Optional[int]) -> Dict[str, Any]:
    read = lines is not None and newest_read and streams is not None
    minutes = round((now.timestamp() - newest_ns / 1e9) / 60, 1) if newest_ns else None
    stale = None
    if read and max_age_minutes:
        stale = minutes is None or minutes > max_age_minutes
    return {
        "name": source["name"],
        "selector": source["selector"],
        "read": read,
        "lines_in_window": lines,
        "streams_in_window": streams,
        "newest_entry": datetime.fromtimestamp(newest_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        if newest_ns else None,
        "minutes_since_newest": minutes if newest_read else None,
        "seen_in_search_window": bool(newest_ns) if newest_read else None,
        "ingesting": lines > 0 if lines is not None else None,
        "stale": stale,
    }


def summarize(records: List[Dict[str, Any]], window_minutes: int, search_hours: int,
              max_age_minutes: Optional[int]) -> Dict[str, Any]:
    """Counts over the expected sources; a count needing a source that was not read is null, not 0."""
    any_unread = any(not r["read"] for r in records)
    judged = bool(records) and not any_unread
    not_ingesting = [r["name"] for r in records if r["ingesting"] is False]
    ages = [r["minutes_since_newest"] for r in records if r["minutes_since_newest"] is not None]
    return {
        "expected_sources": [r["name"] for r in records],
        "expected_sources_count": len(records),
        "window_minutes": window_minutes,
        "search_hours": search_hours,
        "max_age_minutes": max_age_minutes,
        "sources_unread": sum(1 for r in records if not r["read"]),
        "sources_ingesting": sum(1 for r in records if r["ingesting"]) if judged else None,
        "sources_not_ingesting": len(not_ingesting) if judged else None,
        "sources_not_ingesting_names": sorted(not_ingesting) if judged else None,
        "sources_not_seen_in_search_window": sum(1 for r in records if r["seen_in_search_window"] is False) if judged else None,
        "longest_minutes_since_newest_entry": max(ages) if judged and ages else None,
        "sources_stale": sum(1 for r in records if r["stale"]) if judged and max_age_minutes else None,
        "all_expected_sources_ingesting": (not not_ingesting) if judged else None,
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


def collect_source(client: LokiClient, source: Dict[str, str], now: datetime, window_minutes: int, search_hours: int,
                   max_age_minutes: Optional[int]) -> Dict[str, Any]:
    name, selector = source["name"], source["selector"]
    lines = vector_value(client.get(f"lines in window ({name})", "/loki/api/v1/query", {
        "query": f"sum(count_over_time({selector}[{window_minutes}m]))", "time": _ns(now)}))
    newest_read, newest = newest_timestamp(client.get(f"newest entry ({name})", "/loki/api/v1/query_range", {
        "query": selector, "start": _ns(now - timedelta(hours=search_hours)), "end": _ns(now),
        "limit": "1", "direction": "backward"}))
    series = client.get(f"streams in window ({name})", "/loki/api/v1/series", {
        "match[]": selector, "start": _ns(now - timedelta(minutes=window_minutes)), "end": _ns(now)})
    streams = len(series.get("data") or []) if series is not None else None
    return source_record(source, lines, newest_read, newest, streams, now, max_age_minutes)


def collect(client: LokiClient, sources: List[Dict[str, str]], window_minutes: int, search_hours: int,
            max_age_minutes: Optional[int], now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    records = [collect_source(client, s, now, window_minutes, search_hours, max_age_minutes) for s in sources]
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
                  "message": f"{entry!r} is not name={{stream selector}}, or repeats a name"} for entry in invalid]
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
        evidence = collect(client, sources, window or DEFAULT_WINDOW_MINUTES, search or DEFAULT_SEARCH_HOURS, max_age)
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
