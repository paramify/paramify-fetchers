"""Shared Splunk REST and search client for the splunk fetchers."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

TIMEOUT_SECONDS = 120
_FAILING_MESSAGE_TYPES = {"WARN", "ERROR", "FATAL"}
_HTTP_CODES = {401: "auth_failed", 403: "not_authorized", 429: "rate_limited"}
# Stock alert actions that only record results; any other action (email, webhook, script, app-supplied) notifies.
NON_NOTIFYING_ACTIONS = {"logevent", "lookup", "outputtelemetry", "populate_lookup", "rss",
                         "studio_snapshot", "summary_index", "summary_metric_index"}


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
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def minutes_since(epoch: Optional[float], now: float) -> Optional[int]:
    return None if epoch is None else int((now - epoch) // 60)


def env_bool(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw not in {"false", "0", "no", "off"}


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw else default


def split_list(value: Optional[str]) -> List[str]:
    return [v for v in re.split(r"[,;\s]+", value or "") if v]


def truthy(value: Any) -> bool:
    """A Splunk .conf boolean as read raw from properties/ or configs/."""
    return str(value).strip().lower() in ("1", "true", "t", "yes", "y")


def sanitize_for_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", (value or "").strip()) or "unknown"


class SplunkClient:
    def __init__(self, base_url: str, token: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.session.verify = verify_ssl
        if not verify_ssl:
            requests.packages.urllib3.disable_warnings()
        self.failures: List[Dict[str, str]] = []
        self.codes: List[str] = []

    def fail(self, operation: str, type_: str, message: str, code: str) -> None:
        self.failures.append({"operation": operation, "type": type_, "message": message})
        self.codes.append(code)

    def _send(self, method: str, path: str, operation: str, **kwargs) -> Optional[requests.Response]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            resp = self.session.request(method, url, timeout=TIMEOUT_SECONDS, **kwargs)
        except requests.exceptions.RequestException as exc:
            self.fail(operation, type(exc).__name__, str(exc), "target_unreachable")
            return None
        if resp.status_code >= 400:
            self.fail(operation, f"HTTP {resp.status_code}", _message_text(resp), _HTTP_CODES.get(resp.status_code, "internal_error"))
            return None
        return resp

    def _request(self, method: str, path: str, operation: str, **kwargs) -> Optional[dict]:
        resp = self._send(method, path, operation, **kwargs)
        if resp is None:
            return None
        try:
            return resp.json()
        except ValueError:
            self.fail(operation, "InvalidJSON", resp.text[:300], "internal_error")
            return None

    def get(self, path: str, **params) -> Optional[dict]:
        return self._request("GET", path, f"GET {path}", params={"output_mode": "json", **params})

    def get_text(self, path: str) -> Optional[str]:
        """A plain-text endpoint, e.g. one conf key from services/properties/<conf>/<stanza>/<key>."""
        resp = self._send("GET", path, f"GET {path}", params={"output_mode": "json"})
        return None if resp is None else resp.text

    def list(self, path: str, **params) -> Optional[List[dict]]:
        """Every entry of a collection; fails when fewer arrive than paging.total reports."""
        body = self.get(path, count=0, **params)
        if body is None:
            return None
        entries = body.get("entry", [])
        total = (body.get("paging") or {}).get("total")
        if total is not None and len(entries) != int(total):
            self.fail(f"GET {path}", "IncompleteCollection", f"collected {len(entries)} of paging.total {total}", "partial_failure")
            return None
        return entries

    def search(self, spl: str, earliest: str = "0", latest: str = "now") -> Optional[List[dict]]:
        """Oneshot search; any WARN/ERROR message fails it, since Splunk reports denied searches as empty results."""
        operation = f"search {spl}"
        body = self._request(
            "POST", "services/search/jobs", operation,
            data={"search": spl, "exec_mode": "oneshot", "output_mode": "json", "count": 0,
                  "earliest_time": earliest, "latest_time": latest},
        )
        if body is None:
            return None
        bad = [m for m in body.get("messages", []) if m.get("type") in _FAILING_MESSAGE_TYPES]
        if bad:
            self.fail(operation, "SearchMessage", "; ".join(f"{m['type']}: {m.get('text', '')}" for m in bad), "not_authorized")
            return None
        return body.get("results", [])

    def capabilities(self) -> Optional[set]:
        body = self.get("services/authentication/current-context")
        if body is None:
            return None
        return set(body["entry"][0]["content"].get("capabilities", []))

    def require_capabilities(self, required: Iterable[str]) -> bool:
        caps = self.capabilities()
        if caps is None:
            return False
        missing = sorted(set(required) - caps)
        if missing:
            self.fail("GET services/authentication/current-context", "MissingCapability",
                      f"token's role lacks required capabilities: {', '.join(missing)}", "not_authorized")
            return False
        return True

    def searchable_indexes(self) -> Optional[set]:
        """Every index the token's role can search, across all search peers."""
        rows = self.search("| eventcount summarize=false index=* index=_* | stats values(index) as indexes")
        if rows is None:
            return None
        values = rows[0].get("indexes", []) if rows else []
        return set([values] if isinstance(values, str) else values)

    def require_searchable_indexes(self, required: Iterable[str], searchable: Optional[set] = None) -> bool:
        """Fails unless the token's role can search every named index, so an empty search result means none rather than hidden."""
        if searchable is None:
            searchable = self.searchable_indexes()
        if searchable is None:
            return False
        missing = sorted(set(required) - searchable)
        if missing:
            self.fail("search | eventcount", "MissingIndexAccess",
                      f"token's role cannot search required indexes: {', '.join(missing)}", "not_authorized")
            return False
        return True

    def list_indexes(self, searchable: Optional[set] = None) -> Optional[List[dict]]:
        """Every index (datatype=all); fails unless it equals the indexes.conf stanzas and holds every index searchable on the peers."""
        path = "services/data/indexes"
        entries = self.list(path, datatype="all")
        # Merged indexes.conf; unlike data/indexes it is not scoped by what the caller may search.
        stanzas = self.get("services/properties/indexes")
        if searchable is None:
            searchable = self.searchable_indexes()
        if entries is None:
            return None
        listed = {e["name"] for e in entries}
        if stanzas is not None:
            configured = {e["name"] for e in stanzas.get("entry", []) if e["name"] != "default" and ":" not in e["name"]}
            if configured != listed:
                self.fail(f"GET {path}", "IncompleteCollection",
                          f"indexes.conf stanzas not listed: {sorted(configured - listed)}; "
                          f"listed but not in indexes.conf: {sorted(listed - configured)}", "partial_failure")
        if searchable is not None and searchable - listed:
            self.fail(f"GET {path}", "IncompleteCollection",
                      f"indexes searchable on search peers but not listed on this instance: {sorted(searchable - listed)}",
                      "partial_failure")
        return entries

    def server_version(self) -> Optional[str]:
        body = self.get("services/server/info")
        return body["entry"][0]["content"].get("version") if body else None

    def failure_metadata(self) -> Dict[str, Any]:
        return {"partial_failure": bool(self.failures), "api_failures": list(self.failures)}

    def failure_code(self) -> str:
        return self.codes[0] if len(set(self.codes)) == 1 else "partial_failure"


def _message_text(resp: requests.Response) -> str:
    try:
        return "; ".join(m.get("text", "") for m in resp.json().get("messages", [])) or resp.reason
    except ValueError:
        return resp.text[:300] or resp.reason


def target_from_env() -> Dict[str, Any]:
    missing = [v for v in ("SPLUNK_BASE_URL", "SPLUNK_TOKEN") if not os.environ.get(v)]
    if missing:
        raise ValueError(f"missing required env var(s): {', '.join(missing)}")
    base_url = os.environ["SPLUNK_BASE_URL"]
    return {
        "name": os.environ.get("SPLUNK_TARGET_NAME") or base_url,
        "base_url": base_url,
        "token": os.environ["SPLUNK_TOKEN"],
        "verify_ssl": env_bool("SPLUNK_VERIFY_SSL", True),
    }


def write_evidence(fetcher_name: str, target_name: str, evidence: dict) -> Path:
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{fetcher_name}_{sanitize_for_filename(target_name)}.json"
    path.write_text(json.dumps(evidence, indent=2, sort_keys=False))
    return path


def finish(logger: logging.Logger, path: Path, client: SplunkClient) -> int:
    logger.info("Evidence saved to %s", path)
    if client.failures:
        reason = "; ".join(f"{f['operation']}: {f['message']}" for f in client.failures)
        report_failure(f"{len(client.failures)} collection failure(s): {reason}", client.failure_code())
        return 1
    return 0
