#!/usr/bin/env python3
"""
Jira Site Inventory

Inventories a Jira Cloud site — deployment info, projects, issue types,
priorities, statuses and Jira Service Management service desks — and pages the
issues updated within a lookback window (or matching an explicit JQL) into a
per-issue list plus a summary: counts by project, type, status and priority,
open vs resolved, change and incident tickets, and time to resolution.

Only endpoints an ordinary licensed account can read are called, so the API
token needs Browse Projects on the projects to be collected and nothing more.
Jira Service Management is detected from the project list: only a JSM site has
`service_desk` projects, and only then is the service-desk API called. A site
without JSM answers that API with a 403 HTML page, indistinguishable from a real
permission denial, so it must not be asked. No JSM is recorded as
`available: false`, not as a collection failure.
"""

import json
import logging
import os
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("jira_site_inventory")

OUTPUT_FILE = "jira_site_inventory.json"
PAGE_SIZE = 100
TIMEOUT = 60

ISSUE_FIELDS = [
    "summary",
    "project",
    "issuetype",
    "status",
    "priority",
    "assignee",
    "reporter",
    "created",
    "updated",
    "resolutiondate",
    "resolution",
    "labels",
]

# Issue-type names (lowercased) that mark a ticket as a change or an incident.
# These are the Jira Service Management defaults plus the common renames; a site
# that names them differently still has every issue in `issues`, just not in
# the change/incident rollups.
CHANGE_TYPES = {
    "change",
    "change request",
    "normal change",
    "standard change",
    "emergency change",
}
INCIDENT_TYPES = {"incident", "major incident", "security incident"}

# Bucket label for an issue with no value in a rolled-up field. Team-managed
# projects have no priority field at all, so this is common, not an edge case.
NONE_LABEL = "(none)"

NOT_FOUND = object()


class _Abort(Exception):
    """A failure no further call can get past (bad credential, host unreachable)."""


class JiraClient:
    def __init__(self, base_url: str, email: str, api_token: str) -> None:
        self.base_url = base_url
        self.session = requests.Session()
        self.session.auth = (email, api_token)
        self.session.headers.update({"Accept": "application/json"})
        # Contract shape ({operation, type, message}); the status code for each
        # entry is kept alongside, for choosing the run's failure code.
        self.api_failures: list[dict] = []
        self.failure_codes: list[str] = []

    def _fail(self, operation: str, type_: str, message: str, code: str) -> None:
        self.api_failures.append(
            {"operation": operation, "type": type_, "message": message[:500]}
        )
        self.failure_codes.append(code)

    def request(self, method, path, operation, *, params=None, body=None, allow_404=False):
        """Return the decoded JSON body, NOT_FOUND (when allowed), or None on failure."""
        try:
            resp = self.session.request(
                method,
                f"{self.base_url}{path}",
                params=params,
                json=body,
                timeout=TIMEOUT,
            )
        except requests.RequestException as e:
            self._fail(operation, type(e).__name__, str(e), "target_unreachable")
            raise _Abort from e

        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                self._fail(operation, "InvalidJSON", resp.text[:300], "partial_failure")
                return None
        if resp.status_code == 404 and allow_404:
            return NOT_FOUND

        message = _error_message(resp)
        if resp.status_code == 401:
            self._fail(operation, "HTTP401", message, "auth_failed")
            raise _Abort
        code = {403: "not_authorized", 429: "rate_limited", 400: "bad_config"}.get(
            resp.status_code, "partial_failure"
        )
        self._fail(operation, f"HTTP{resp.status_code}", message, code)
        return None

    def paged_values(self, path, operation, params=None):
        """Page a Jira platform `startAt`/`isLast` list endpoint."""
        values: list = []
        start_at = 0
        while True:
            page = self.request(
                "GET",
                path,
                operation,
                params={**(params or {}), "startAt": start_at, "maxResults": 50},
            )
            if page is None:
                return values
            batch = page.get("values") or []
            values.extend(batch)
            start_at += len(batch)
            if page.get("isLast", True) or not batch:
                return values

    def service_desks(self):
        """Page the JSM service-desk list; NOT_FOUND when the site has no JSM."""
        desks: list = []
        start = 0
        while True:
            page = self.request(
                "GET",
                "/rest/servicedeskapi/servicedesk",
                "GET /rest/servicedeskapi/servicedesk",
                params={"start": start, "limit": 50},
                allow_404=True,
            )
            if page is NOT_FOUND:
                return NOT_FOUND
            if page is None:
                return None
            batch = page.get("values") or []
            desks.extend(batch)
            start += len(batch)
            if page.get("isLastPage", True) or not batch:
                return desks

    def search_issues(self, jql: str, max_issues: int):
        """Page POST /rest/api/3/search/jql. Returns (issues, truncated)."""
        issues: list = []
        token = None
        while True:
            body = {
                "jql": jql,
                "fields": ISSUE_FIELDS,
                "maxResults": min(PAGE_SIZE, max_issues - len(issues)),
            }
            if token:
                body["nextPageToken"] = token
            page = self.request(
                "POST", "/rest/api/3/search/jql", "POST /rest/api/3/search/jql", body=body
            )
            if page is None:
                return issues, False
            issues.extend(page.get("issues") or [])
            token = page.get("nextPageToken")
            more = bool(token) and not page.get("isLast", False)
            if not more:
                return issues, False
            if len(issues) >= max_issues:
                return issues, True


def _error_message(resp: requests.Response) -> str:
    if "html" in resp.headers.get("Content-Type", "").lower():
        return f"{resp.reason or 'error'} (HTML error page, not a Jira API response)"
    try:
        data = resp.json()
    except ValueError:
        return resp.text[:300] or resp.reason or ""
    parts = list(data.get("errorMessages") or [])
    parts += [f"{k}: {v}" for k, v in (data.get("errors") or {}).items()]
    if data.get("errorMessage"):
        parts.append(data["errorMessage"])
    return "; ".join(parts) or resp.text[:300]


def _name(obj, key="name"):
    return obj.get(key) if isinstance(obj, dict) else None


def _parse_ts(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        return None


def _project_record(p: dict) -> dict:
    insight = p.get("insight") or {}
    return {
        "id": p.get("id"),
        "key": p.get("key"),
        "name": p.get("name"),
        "project_type": p.get("projectTypeKey"),
        "style": p.get("style"),
        "is_private": p.get("isPrivate"),
        "lead": _name(p.get("lead"), "displayName"),
        "issue_types": sorted({t.get("name") for t in p.get("issueTypes") or [] if t.get("name")}),
        "total_issue_count": insight.get("totalIssueCount"),
        "last_issue_update_time": insight.get("lastIssueUpdateTime"),
    }


def _issue_record(issue: dict) -> dict:
    f = issue.get("fields") or {}
    status = f.get("status") or {}
    created = _parse_ts(f.get("created"))
    resolved = _parse_ts(f.get("resolutiondate"))
    hours = (
        round((resolved - created).total_seconds() / 3600, 2)
        if created and resolved
        else None
    )
    return {
        "key": issue.get("key"),
        "summary": f.get("summary"),
        "project": _name(f.get("project"), "key"),
        "issue_type": _name(f.get("issuetype")),
        "status": status.get("name"),
        "status_category": _name(status.get("statusCategory"), "key"),
        "priority": _name(f.get("priority")),
        "assignee": _name(f.get("assignee"), "displayName"),
        "reporter": _name(f.get("reporter"), "displayName"),
        "created": f.get("created"),
        "updated": f.get("updated"),
        "resolved": f.get("resolutiondate"),
        "resolution": _name(f.get("resolution")),
        "hours_to_resolve": hours,
        "labels": f.get("labels") or [],
    }


def _counts(values) -> dict:
    return dict(Counter(NONE_LABEL if v is None else v for v in values).most_common())


def _hours_stats(values: list) -> dict:
    if not values:
        return {"count": 0, "median": None, "mean": None}
    return {
        "count": len(values),
        "median": round(statistics.median(values), 2),
        "mean": round(statistics.fmean(values), 2),
    }


def _ticket_rollup(issues: list) -> dict:
    return {
        "total": len(issues),
        "open": sum(1 for i in issues if i["status_category"] != "done"),
        "resolved": sum(1 for i in issues if i["resolved"]),
        "by_status": _counts(i["status"] for i in issues),
        "by_priority": _counts(i["priority"] for i in issues),
        "resolution_hours": _hours_stats(
            [i["hours_to_resolve"] for i in issues if i["hours_to_resolve"] is not None]
        ),
    }


def _summarize(projects: list, issues: list, service_desks) -> dict:
    by_priority_hours: dict = {}
    for i in issues:
        if i["hours_to_resolve"] is not None:
            by_priority_hours.setdefault(i["priority"] or NONE_LABEL, []).append(
                i["hours_to_resolve"]
            )
    changes = [i for i in issues if (i["issue_type"] or "").lower() in CHANGE_TYPES]
    incidents = [i for i in issues if (i["issue_type"] or "").lower() in INCIDENT_TYPES]
    return {
        "projects": {
            "total": len(projects),
            "by_type": _counts(p["project_type"] for p in projects),
            "without_lead": sum(1 for p in projects if not p["lead"]),
        },
        "service_desks": len(service_desks) if isinstance(service_desks, list) else None,
        "issues": {
            "total": len(issues),
            "open": sum(1 for i in issues if i["status_category"] != "done"),
            "resolved": sum(1 for i in issues if i["resolved"]),
            "open_unassigned": sum(
                1 for i in issues if i["status_category"] != "done" and not i["assignee"]
            ),
            "by_project": _counts(i["project"] for i in issues),
            "by_issue_type": _counts(i["issue_type"] for i in issues),
            "by_status_category": _counts(i["status_category"] for i in issues),
            "by_priority": _counts(i["priority"] for i in issues),
            "resolution_hours": {
                "overall": _hours_stats(
                    [i["hours_to_resolve"] for i in issues if i["hours_to_resolve"] is not None]
                ),
                "by_priority": {
                    k: _hours_stats(v) for k, v in sorted(by_priority_hours.items())
                },
            },
        },
        "change_issues": _ticket_rollup(changes),
        "incident_issues": _ticket_rollup(incidents),
    }


def _int_env(name: str, default: int):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself and reads env directly.
    load_dotenv()

    base_url = os.environ.get("JIRA_BASE_URL", "").strip().rstrip("/")
    email = os.environ.get("JIRA_EMAIL", "").strip()
    api_token = os.environ.get("JIRA_API_TOKEN", "").strip()
    for var, value in (
        ("JIRA_BASE_URL", base_url),
        ("JIRA_EMAIL", email),
        ("JIRA_API_TOKEN", api_token),
    ):
        if not value:
            report_failure(f"{var} is not set", "bad_config")
            return 1
    if not base_url.startswith("https://"):
        report_failure(
            f"JIRA_BASE_URL must be an https:// URL, got {base_url!r}", "bad_config"
        )
        return 1

    lookback_days = _int_env("JIRA_LOOKBACK_DAYS", 90)
    max_issues = _int_env("JIRA_MAX_ISSUES", 2000)
    if lookback_days is None or max_issues is None:
        report_failure(
            "JIRA_LOOKBACK_DAYS and JIRA_MAX_ISSUES must be positive integers",
            "bad_config",
        )
        return 1
    jql = os.environ.get("JIRA_ISSUE_JQL", "").strip()
    if jql:
        lookback_days = None
    else:
        jql = f"updated >= -{lookback_days}d ORDER BY updated DESC"

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    client = JiraClient(base_url, email, api_token)
    site = collector = None
    projects: list = []
    issue_types: list = []
    priorities: list = []
    statuses: list = []
    service_desks = None
    jsm_available = None
    issues: list = []
    truncated = False

    try:
        info = client.request("GET", "/rest/api/3/serverInfo", "GET /rest/api/3/serverInfo")
        if info:
            site = {
                "base_url": info.get("baseUrl"),
                "server_title": info.get("serverTitle"),
                "deployment_type": info.get("deploymentType"),
                "version": info.get("version"),
                "build_number": info.get("buildNumber"),
            }
        me = client.request("GET", "/rest/api/3/myself", "GET /rest/api/3/myself")
        if me:
            collector = {
                "account_id": me.get("accountId"),
                "display_name": me.get("displayName"),
                "account_type": me.get("accountType"),
                "active": me.get("active"),
            }

        projects = [
            _project_record(p)
            for p in client.paged_values(
                "/rest/api/3/project/search",
                "GET /rest/api/3/project/search",
                params={"expand": "lead,insight,issueTypes"},
            )
        ]

        raw_types = client.request("GET", "/rest/api/3/issuetype", "GET /rest/api/3/issuetype")
        issue_types = [
            {
                "id": t.get("id"),
                "name": t.get("name"),
                "subtask": t.get("subtask"),
                "hierarchy_level": t.get("hierarchyLevel"),
                # Team-managed projects each carry their own copy of a type
                # (Story, Epic, ...), so a name can repeat once per project.
                "project_id": _name((t.get("scope") or {}).get("project"), "id"),
            }
            for t in raw_types or []
        ]

        priorities = [
            {"id": p.get("id"), "name": p.get("name"), "is_default": p.get("isDefault")}
            for p in client.paged_values(
                "/rest/api/3/priority/search", "GET /rest/api/3/priority/search"
            )
        ]

        raw_statuses = client.request("GET", "/rest/api/3/status", "GET /rest/api/3/status")
        statuses = sorted(
            (
                {
                    "id": s.get("id"),
                    "name": s.get("name"),
                    "category": _name(s.get("statusCategory"), "key"),
                }
                for s in raw_statuses or []
            ),
            key=lambda s: (s["category"] or "", s["name"] or ""),
        )

        has_service_projects = any(p["project_type"] == "service_desk" for p in projects)
        desks = client.service_desks() if has_service_projects else NOT_FOUND
        if desks is NOT_FOUND:
            service_desks = []
            jsm_available = False
        elif desks is None:
            jsm_available = None
        else:
            service_desks = [
                {
                    "id": d.get("id"),
                    "project_key": d.get("projectKey"),
                    "project_name": d.get("projectName"),
                }
                for d in desks
            ]
            jsm_available = True

        raw_issues, truncated = client.search_issues(jql, max_issues)
        issues = [_issue_record(i) for i in raw_issues]
    except _Abort:
        pass  # already recorded in api_failures; write what was collected

    evidence = {
        "metadata": {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "base_url": base_url,
            "jql": jql,
            "lookback_days": lookback_days,
            "max_issues": max_issues,
            "issues_collected": len(issues),
            "issues_truncated": truncated,
            "partial_failure": bool(client.api_failures),
            "api_failures": client.api_failures,
        },
        "site": site,
        "collector": collector,
        "summary": _summarize(projects, issues, service_desks),
        "projects": projects,
        "issue_types": issue_types,
        "priorities": priorities,
        "statuses": statuses,
        "service_management": {
            "available": jsm_available,
            "service_desks": service_desks,
        },
        "issues": issues,
    }

    output_path = output_dir / OUTPUT_FILE
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
        report_failure(
            f"{len(client.api_failures)} Jira API call(s) failed during collection - {detail}",
            code,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
