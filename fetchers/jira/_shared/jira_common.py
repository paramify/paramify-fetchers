"""Shared Jira Cloud REST client and run plumbing for the jira fetchers."""

import json
import logging
import os
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

PAGE_SIZE = 100
TIMEOUT = 60
NONE_LABEL = "(none)"
NOT_FOUND = object()
# POST /rest/api/3/changelog/bulkfetch accepts at most 1000 issues and 10 field ids.
CHANGELOG_ISSUE_BATCH = 1000


class Abort(Exception):
    """A failure no further call can get past (bad credential, host unreachable)."""


class JiraClient:
    def __init__(self, base_url: str, email: str, api_token: str) -> None:
        self.base_url = base_url
        self.session = requests.Session()
        self.session.auth = (email, api_token)
        self.session.headers.update({"Accept": "application/json"})
        self.api_failures: list[dict] = []
        self.failure_codes: list[str] = []

    def fail(self, operation: str, type_: str, message: str, code: str) -> None:
        self.api_failures.append(
            {"operation": operation, "type": type_, "message": message[:500]}
        )
        self.failure_codes.append(code)

    def request(self, method, path, operation, *, params=None, body=None, allow_404=False, quiet_400=False):
        """Return the decoded JSON body, NOT_FOUND (when allowed), or None on failure."""
        try:
            resp = self.session.request(
                method, f"{self.base_url}{path}", params=params, json=body, timeout=TIMEOUT
            )
        except requests.RequestException as e:
            self.fail(operation, type(e).__name__, str(e), "target_unreachable")
            raise Abort from e

        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                self.fail(operation, "InvalidJSON", resp.text[:300], "partial_failure")
                return None
        if resp.status_code == 404 and allow_404:
            return NOT_FOUND
        if resp.status_code == 400 and quiet_400:
            return NOT_FOUND

        message = error_message(resp)
        if resp.status_code == 401:
            self.fail(operation, "HTTP401", message, "auth_failed")
            raise Abort
        code = {403: "not_authorized", 429: "rate_limited", 400: "bad_config"}.get(
            resp.status_code, "partial_failure"
        )
        self.fail(operation, f"HTTP{resp.status_code}", message, code)
        return None

    def paged_values(self, path, operation, params=None, page_size=50):
        """Page a `startAt`/`isLast` list endpoint. Returns (values, complete)."""
        values: list = []
        start_at = 0
        while True:
            page = self.request(
                "GET",
                path,
                operation,
                params={**(params or {}), "startAt": start_at, "maxResults": page_size},
            )
            if page is None:
                return values, False
            batch = page.get("values") or []
            values.extend(batch)
            start_at += len(batch)
            if page.get("isLast", True) or not batch:
                return values, True

    def search_issues(self, jql: str, fields: list, max_issues: int):
        """Page POST /rest/api/3/search/jql. Returns (issues, truncated, complete)."""
        issues: list = []
        token = None
        while True:
            body = {
                "jql": jql,
                "fields": fields,
                "maxResults": min(PAGE_SIZE, max_issues - len(issues)),
            }
            if token:
                body["nextPageToken"] = token
            page = self.request(
                "POST", "/rest/api/3/search/jql", "POST /rest/api/3/search/jql", body=body
            )
            if page is None:
                return issues, False, False
            issues.extend(page.get("issues") or [])
            token = page.get("nextPageToken")
            more = bool(token) and not page.get("isLast", False)
            if not more:
                return issues, False, True
            if len(issues) >= max_issues:
                return issues, True, True

    def bulk_changelogs(self, issue_ids: list, field_ids: list):
        """Full change history per issue id via POST /rest/api/3/changelog/bulkfetch.

        Returns ({issue_id: [history, ...]}, complete). Histories are de-duplicated
        by id because the endpoint has repeated entries across pages before.
        """
        out: dict = {}
        seen: set = set()
        complete = True
        for i in range(0, len(issue_ids), CHANGELOG_ISSUE_BATCH):
            chunk = issue_ids[i : i + CHANGELOG_ISSUE_BATCH]
            token = None
            while True:
                body = {"issueIdsOrKeys": chunk, "fieldIds": field_ids[:10], "maxResults": 1000}
                if token:
                    body["nextPageToken"] = token
                page = self.request(
                    "POST",
                    "/rest/api/3/changelog/bulkfetch",
                    "POST /rest/api/3/changelog/bulkfetch",
                    body=body,
                )
                if page is None:
                    complete = False
                    break
                for log in page.get("issueChangeLogs") or []:
                    issue_id = str(log.get("issueId"))
                    for h in log.get("changeHistories") or []:
                        hid = (issue_id, h.get("id"))
                        if hid in seen:
                            continue
                        seen.add(hid)
                        out.setdefault(issue_id, []).append(h)
                token = page.get("nextPageToken")
                if not token:
                    break
        return out, complete


def error_message(resp: requests.Response) -> str:
    if "html" in resp.headers.get("Content-Type", "").lower():
        return f"{resp.reason or 'error'} (HTML error page, not a Jira API response)"
    try:
        data = resp.json()
    except ValueError:
        return resp.text[:300] or resp.reason or ""
    if not isinstance(data, dict):
        return resp.text[:300]
    parts = list(data.get("errorMessages") or [])
    parts += [f"{k}: {v}" for k, v in (data.get("errors") or {}).items()]
    if data.get("errorMessage"):
        parts.append(data["errorMessage"])
    return "; ".join(parts) or resp.text[:300]


def name_of(obj, key="name"):
    return obj.get(key) if isinstance(obj, dict) else None


def parse_ts(value):
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def counts(values) -> dict:
    return dict(Counter(NONE_LABEL if v is None else v for v in values).most_common())


def number_stats(values: list) -> dict:
    if not values:
        return {"count": 0, "median": None, "mean": None, "max": None}
    return {
        "count": len(values),
        "median": round(statistics.median(values), 2),
        "mean": round(statistics.fmean(values), 2),
        "max": round(max(values), 2),
    }


def int_env(name: str, default: int):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def list_env(name: str) -> list:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


def connection_settings():
    """Read the category settings. Returns (base_url, email, token), or an error string."""
    base_url = os.environ.get("JIRA_BASE_URL", "").strip().rstrip("/")
    email = os.environ.get("JIRA_EMAIL", "").strip()
    api_token = os.environ.get("JIRA_API_TOKEN", "").strip()
    for var, value in (
        ("JIRA_BASE_URL", base_url),
        ("JIRA_EMAIL", email),
        ("JIRA_API_TOKEN", api_token),
    ):
        if not value:
            return f"{var} is not set"
    if not base_url.startswith("https://"):
        return f"JIRA_BASE_URL must be an https:// URL, got {base_url!r}"
    return base_url, email, api_token


def collector_info(client: JiraClient):
    me = client.request("GET", "/rest/api/3/myself", "GET /rest/api/3/myself")
    if not me:
        return None
    return {
        "account_id": me.get("accountId"),
        "display_name": me.get("displayName"),
        "account_type": me.get("accountType"),
        "active": me.get("active"),
    }


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def write_and_finish(logger: logging.Logger, client: JiraClient, evidence: dict, filename: str, extra_failure: str = "") -> int:
    """Write the evidence file, then report the run's outcome. Returns the exit code."""
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / filename
    try:
        output_path.write_text(json.dumps(evidence, indent=2))
    except OSError as e:
        report_failure(f"could not write evidence file: {e}", "internal_error")
        return 1

    logger.info("Evidence saved to %s", output_path)

    if client.api_failures:
        codes = client.failure_codes
        if "auth_failed" in codes:
            code = "auth_failed"
        elif len(set(codes)) == 1:
            code = codes[0]
        else:
            code = "partial_failure"
        detail = "; ".join(
            f"{f['operation']}: {f['type']} {f['message']}".strip()
            for f in client.api_failures[:3]
        )
        reason = f"{len(client.api_failures)} Jira API call(s) failed during collection - {detail}"
        if extra_failure:
            reason = f"{extra_failure}; {reason}"
        report_failure(reason, code)
        return 1
    if extra_failure:
        report_failure(extra_failure, "partial_failure")
        return 1
    return 0
