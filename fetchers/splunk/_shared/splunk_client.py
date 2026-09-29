"""The shared client and entry point for every Splunk fetcher.

A fetcher is a `collect(client, config)` function that returns
`{"summary": {...}, "<records>": [...]}`, plus a line that hands it to `run`:

    if __name__ == "__main__":
        sys.exit(run(NAME, collect, CAPABILITIES, CONFIG))

`run` does everything else. It reads the target from the environment, checks
the token's capabilities, calls `collect`, writes the evidence file, and
reports any failure to the runner.

Failure handling, in two rules:
  - A call that fails returns None and is recorded on the client. A fetcher
    that needs it returns None, and the evidence carries no records.
  - A completeness check that fails keeps the records and marks the evidence
    partial. Either way the run exits non-zero and says why.

Splunk returns partial data without an error in several ways. Each is handled
here, once, so no fetcher has to:
  - list() reads with count=0 (the default is 30) and fails unless
    paging.total matches.
  - search() fails on any WARN or ERROR message. A search the token may not
    run comes back as zero rows plus a WARN.
  - list_indexes() reads datatype=all (the default omits metric indexes) and
    cross-checks indexes.conf and the indexes every search peer can search.
  - run() fails before collecting when the token lacks a capability, because
    Splunk filters lists by capability and reports the filtered count as the
    total.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import requests
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("splunk")

TIMEOUT_SECONDS = 120
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RETRIES = 4
MAX_BACKOFF_SECONDS = 30
HTTP_CODES = {401: "auth_failed", 403: "not_authorized", 429: "rate_limited"}
FAILING_MESSAGES = {"WARN", "ERROR", "FATAL"}
SEARCHABLE_INDEXES_SPL = "| eventcount summarize=false index=* index=_* | stats values(index) as indexes"
# Stock alert actions that only record results. Any other action (email, webhook, script, app-supplied) notifies.
NON_NOTIFYING_ACTIONS = {"logevent", "lookup", "outputtelemetry", "populate_lookup", "rss",
                         "studio_snapshot", "summary_index", "summary_metric_index"}

# A fetcher's CONFIG: {metadata key: (env var, default)}. Every value is an integer and is recorded in metadata.
Config = Dict[str, Tuple[str, int]]


# --- values --------------------------------------------------------------------
# Under output_mode=json one response mixes native and stringified values
# (currentDBSizeMB arrives as "0", which is truthy), so flags and numbers are
# read through as_bool and as_int.

def as_bool(value: Any) -> Optional[bool]:
    """A Splunk boolean in any rendering (True, 1, "0", "true" ...); None when unrecognised."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    folded = value.strip().lower() if isinstance(value, str) else None
    if folded in ("1", "true", "t", "yes", "y", "on"):
        return True
    if folded in ("0", "false", "f", "no", "n", "off"):
        return False
    return None


def as_int(value: Any) -> Optional[int]:
    """A Splunk number sent as an int or a string; None when it is not one."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(float(str(value).strip()))
    except ValueError:
        return None


def as_list(value: Any) -> List[Any]:
    """A multi-valued field, which Splunk sends as a bare string when it holds one value."""
    if value in (None, ""):
        return []
    return [value] if isinstance(value, str) else list(value)


def split_list(value: Optional[str]) -> List[str]:
    """A comma- or space-separated setting such as `actions` or `action.email.to`."""
    return [v for v in re.split(r"[,;\s]+", value or "") if v]


def now_epoch() -> float:
    return datetime.now(timezone.utc).timestamp()


def to_epoch(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def iso(epoch: Optional[float]) -> Optional[str]:
    return None if epoch is None else datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def silence(epoch: Optional[float], now: float, window: int) -> Tuple[Optional[int], bool]:
    """Minutes since `epoch`, and whether that falls outside `window` in either direction. No time at all is silent."""
    if epoch is None:
        return None, True
    minutes = int((now - epoch) // 60)
    return minutes, abs(minutes) > window


# --- the client ------------------------------------------------------------------

class SplunkClient:
    """Read-only access to one deployment's management API (port 8089)."""

    def __init__(self, base_url: str, token: str, verify_ssl: bool = True, ca_bundle: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"
        # A CA bundle verifies against that CA and overrides verify_ssl.
        self.session.verify = ca_bundle or verify_ssl
        self.tls_verified = bool(ca_bundle) or verify_ssl
        if not self.tls_verified:
            requests.packages.urllib3.disable_warnings()
        self.failures: List[Dict[str, str]] = []
        self.codes: List[str] = []
        self.info: Dict[str, Any] = {}  # services/server/info, read by run()
        self.user: Dict[str, Any] = {}  # the token's user and capabilities, read by run()

    def fail(self, operation: str, type_: str, message: str, code: str) -> None:
        self.failures.append({"operation": operation, "type": type_, "message": message})
        self.codes.append(code)

    def failure_code(self) -> str:
        return self.codes[0] if len(set(self.codes)) == 1 else "partial_failure"

    def _send(self, method: str, path: str, operation: str, **kwargs: Any) -> Optional[requests.Response]:
        """One request. 429, 5xx and connections that fail to open are retried with backoff; TLS errors are not."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = self.session.request(method, url, timeout=TIMEOUT_SECONDS, **kwargs)
            except requests.exceptions.RequestException as exc:
                retryable = (isinstance(exc, requests.exceptions.ConnectionError)
                             and not isinstance(exc, requests.exceptions.SSLError))
                if retryable and attempt < MAX_RETRIES:
                    time.sleep(_backoff(None, attempt))
                    continue
                self.fail(operation, type(exc).__name__, str(exc), "target_unreachable")
                return None
            if resp.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                time.sleep(_backoff(resp, attempt))
                continue
            break
        if resp.status_code >= 400:
            self.fail(operation, f"HTTP {resp.status_code}", _message_text(resp),
                      HTTP_CODES.get(resp.status_code, "internal_error"))
            return None
        return resp

    def _json(self, method: str, path: str, operation: str, **kwargs: Any) -> Optional[dict]:
        resp = self._send(method, path, operation, **kwargs)
        if resp is None:
            return None
        try:
            return resp.json()
        except ValueError:
            self.fail(operation, "InvalidJSON", resp.text[:300], "internal_error")
            return None

    def get(self, path: str, **params: Any) -> Optional[dict]:
        return self._json("GET", path, f"GET {path}", params={"output_mode": "json", **params})

    def get_text(self, path: str) -> Optional[str]:
        """A plain-text endpoint, such as one conf key from services/properties/<conf>/<stanza>/<key>."""
        resp = self._send("GET", path, f"GET {path}", params={"output_mode": "json"})
        return None if resp is None else resp.text

    def first_entry(self, path: str) -> Dict[str, Any]:
        """The content of a single-entry endpoint such as services/server/info; {} when the call fails."""
        entries = (self.get(path) or {}).get("entry") or []
        return (entries[0].get("content") or {}) if entries else {}

    def list(self, path: str, **params: Any) -> Optional[List[dict]]:
        """Every entry of a collection. Fails unless the entries match paging.total."""
        body = self.get(path, count=0, **params)
        if body is None:
            return None
        entries = body.get("entry") or []
        total = as_int((body.get("paging") or {}).get("total"))
        if total is not None and len(entries) != total:
            self.fail(f"GET {path}", "IncompleteCollection",
                      f"collected {len(entries)} of paging.total {total}", "partial_failure")
            return None
        return entries

    def search(self, spl: str, earliest: str = "0", latest: str = "now") -> Optional[List[dict]]:
        """Every result row of a oneshot search. Fails on any WARN or ERROR message."""
        operation = f"search {spl}"
        body = self._json("POST", "services/search/jobs", operation, data={
            "search": spl, "exec_mode": "oneshot", "output_mode": "json", "count": 0,
            "earliest_time": earliest, "latest_time": latest})
        if body is None:
            return None
        bad = [m for m in body.get("messages") or [] if m.get("type") in FAILING_MESSAGES]
        if bad:
            self.fail(operation, "SearchMessage",
                      "; ".join(f"{m['type']}: {m.get('text', '')}" for m in bad), "not_authorized")
            return None
        return body.get("results") or []

    def expect(self, what: str, collected: int, expected: Optional[int]) -> None:
        """Record a failure when a collection's size disagrees with an independent count of it."""
        if collected != expected:
            self.fail(f"count {what}", "IncompleteCollection",
                      f"collected {collected} {what}, an independent count says {expected}", "partial_failure")

    def require_capabilities(self, required: Iterable[str]) -> bool:
        if not self.user:
            return False  # the current-context call failed and is already recorded
        missing = sorted(set(required) - set(as_list(self.user.get("capabilities"))))
        if missing:
            self.fail("GET services/authentication/current-context", "MissingCapability",
                      f"the token's role lacks: {', '.join(missing)}", "not_authorized")
        return not missing

    def searchable_indexes(self) -> Optional[set]:
        """Every index the token can search, across all search peers."""
        rows = self.search(SEARCHABLE_INDEXES_SPL)
        return None if rows is None else set(as_list(rows[0].get("indexes")) if rows else [])

    def require_searchable_indexes(self, required: Iterable[str], searchable: Optional[set] = None) -> bool:
        """Fails unless the token can search every named index, so an empty result means none rather than hidden."""
        searchable = self.searchable_indexes() if searchable is None else searchable
        if searchable is None:
            return False
        missing = sorted(set(required) - searchable)
        if missing:
            self.fail("search | eventcount", "MissingIndexAccess",
                      f"the token cannot search: {', '.join(missing)}", "not_authorized")
        return not missing

    def list_indexes(self, require_searchable: bool = False) -> Optional[List[dict]]:
        """Every index, event and metric. Fails unless it matches indexes.conf and every index the peers can search.

        With require_searchable, also fails unless the token can search every enabled index.
        """
        path = "services/data/indexes"
        entries = self.list(path, datatype="all")
        stanzas = self.get("services/properties/indexes")  # merged indexes.conf, not scoped by search access
        searchable = self.searchable_indexes()
        if entries is None:
            return None
        listed = {e["name"] for e in entries}
        if stanzas is not None:
            # Not indexes: [default], and volume: / provider: stanzas.
            configured = {e["name"] for e in stanzas.get("entry") or [] if e["name"] != "default" and ":" not in e["name"]}
            if configured != listed:
                self.fail(f"GET {path}", "IncompleteCollection",
                          f"in indexes.conf but not listed: {sorted(configured - listed)}; "
                          f"listed but not in indexes.conf: {sorted(listed - configured)}", "partial_failure")
        if searchable is not None:
            if searchable - listed:
                self.fail(f"GET {path}", "IncompleteCollection",
                          f"searchable on the search peers but not listed here: {sorted(searchable - listed)}",
                          "partial_failure")
            if require_searchable:
                enabled = [e["name"] for e in entries if not as_bool(e["content"].get("disabled"))]
                self.require_searchable_indexes(enabled, searchable)
        return entries


def _backoff(resp: Optional[requests.Response], attempt: int) -> float:
    """Retry-After when the server sends one, else exponential; capped either way."""
    retry_after = resp.headers.get("Retry-After") if resp is not None else None
    try:
        if retry_after:
            return min(float(retry_after), MAX_BACKOFF_SECONDS)
    except ValueError:
        pass
    return min(2 ** attempt, MAX_BACKOFF_SECONDS)


def _message_text(resp: requests.Response) -> str:
    try:
        return "; ".join(m.get("text", "") for m in resp.json().get("messages", [])) or resp.reason
    except ValueError:
        return resp.text[:300] or resp.reason


# --- the entry point --------------------------------------------------------------

def run(name: str, collect: Callable[[SplunkClient, Dict[str, int]], Optional[dict]],
        capabilities: Iterable[str], config: Optional[Config] = None) -> int:
    """Run one fetcher against the target in the environment and write its evidence. Returns the exit code."""
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    try:
        target = _target_from_env()
        settings = {key: _env_int(env, default) for key, (env, default) in (config or {}).items()}
    except ValueError as exc:
        report_failure(str(exc), "bad_config")
        return 1

    client = SplunkClient(target["base_url"], target["token"], target["verify_ssl"], target["ca_bundle"])
    result: Dict[str, Any] = {}
    try:
        client.info = client.first_entry("services/server/info")
        client.user = client.first_entry("services/authentication/current-context")
        if client.require_capabilities(capabilities):
            result = collect(client, settings) or {}
    except Exception as exc:  # noqa: BLE001 - an unexpected response must still leave evidence and a reason
        logger.exception("collection failed")
        client.fail("collect", type(exc).__name__, str(exc), "internal_error")
        result = {}

    evidence = {
        "metadata": {
            "collected_at": iso(now_epoch()),
            "target": target["name"],
            "base_url": target["base_url"],
            "tls_verified": client.tls_verified,
            "splunk_version": client.info.get("version"),
            **settings,
            **result.pop("metadata", {}),
            "partial_failure": bool(client.failures),
            "api_failures": client.failures,
        },
        "summary": result.pop("summary", {}),
        **result,
    }
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{name}_{re.sub(r'[^a-zA-Z0-9_-]', '_', target['name']) or 'unknown'}.json"
    path.write_text(json.dumps(evidence, indent=2))
    logger.info("Evidence saved to %s", path)

    if client.failures:
        reason = "; ".join(f"{f['operation']}: {f['message']}" for f in client.failures)
        report_failure(f"{len(client.failures)} collection failure(s): {reason}", client.failure_code())
        return 1
    return 0


def _target_from_env() -> Dict[str, Any]:
    missing = [v for v in ("SPLUNK_BASE_URL", "SPLUNK_TOKEN") if not os.environ.get(v)]
    if missing:
        raise ValueError(f"missing required env var(s): {', '.join(missing)}")
    return {
        "name": os.environ.get("SPLUNK_TARGET_NAME") or os.environ["SPLUNK_BASE_URL"],
        "base_url": os.environ["SPLUNK_BASE_URL"],
        "token": os.environ["SPLUNK_TOKEN"],
        "verify_ssl": as_bool(os.environ.get("SPLUNK_VERIFY_SSL") or "true") is not False,
        "ca_bundle": os.environ.get("SPLUNK_CA_BUNDLE", "").strip() or None,
    }


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None
