#!/usr/bin/env python3
"""Jira site inventory: deployment info, projects, issue types, priorities, statuses, JSM desks and recent issues."""

import logging
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from jira_common import (  # noqa: E402
    NONE_LABEL,
    NOT_FOUND,
    Abort,
    Counts,
    JiraClient,
    collector_info,
    connection_settings,
    counts,
    int_env,
    list_env,
    name_of,
    null_summary,
    number_stats,
    parse_ts,
    report_failure,
    utc_now,
    write_and_finish,
)

logger = logging.getLogger("jira_site_inventory")

OUTPUT_FILE = "jira_site_inventory.json"

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

ORDER_BY = re.compile(r"\border\s+by\b", re.IGNORECASE)
# A quoted JQL string, in either quote style, with backslash escapes.
QUOTED = re.compile(r""""(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'""")


def _match_projects(raw_projects: list, wanted: list):
    """(projects named in JIRA_PROJECTS, ignoring case; names that matched none).

    A value is a project key first. Only a value that is no project's key is tried as an exact project name, so a
    value cannot select two projects, one by key and another that happens to carry the same text as its name.
    """
    keys = {str(p.get("key") or "").lower() for p in raw_projects}
    by_key = {w.lower() for w in wanted if w.lower() in keys}
    by_name = {w.lower() for w in wanted if w.lower() not in keys}
    matched = [
        p for p in raw_projects
        if str(p.get("key") or "").lower() in by_key or str(p.get("name") or "").lower() in by_name
    ]
    names = {str(p.get("name") or "").lower() for p in raw_projects}
    return matched, [w for w in wanted if w.lower() not in keys and w.lower() not in names]


def _order_by_start(jql: str):
    """Where the ORDER BY clause starts, or None. The words inside a quoted string are text, not the clause."""
    # Quoted spans are blanked to the same length, so a match position is a position in the original query.
    blanked = QUOTED.sub(lambda q: " " * len(q.group(0)), jql)
    m = ORDER_BY.search(blanked)
    return m.start() if m else None


def _scoped_jql(project_ids: list, jql: str) -> str:
    """Limit a query to the selected projects, whatever else it says.

    ORDER BY always ends a JQL query, so the condition before it is wrapped and ANDed with the project clause: a
    condition naming other projects can narrow the result, never widen it.
    """
    clause = f"project in ({', '.join(project_ids)})"
    start = _order_by_start(jql)
    condition, order = (jql.strip(), "") if start is None else (jql[:start].strip(), jql[start:].strip())
    return " ".join(x for x in (clause, f"AND ({condition})" if condition else "", order) if x)


def _project_record(p: dict) -> dict:
    insight = p.get("insight") or {}
    return {
        "id": p.get("id"),
        "key": p.get("key"),
        "name": p.get("name"),
        "project_type": p.get("projectTypeKey"),
        "style": p.get("style"),
        "is_private": p.get("isPrivate"),
        "lead": name_of(p.get("lead"), "displayName"),
        "issue_types": sorted({t.get("name") for t in p.get("issueTypes") or [] if t.get("name")}),
        "total_issue_count": insight.get("totalIssueCount"),
        "last_issue_update_time": insight.get("lastIssueUpdateTime"),
    }


def _issue_record(issue: dict) -> dict:
    f = issue.get("fields") or {}
    status = f.get("status") or {}
    created = parse_ts(f.get("created"))
    resolved = parse_ts(f.get("resolutiondate"))
    hours = (
        round((resolved - created).total_seconds() / 3600, 2)
        if created and resolved
        else None
    )
    return {
        "key": issue.get("key"),
        "summary": f.get("summary"),
        "project": name_of(f.get("project"), "key"),
        "issue_type": name_of(f.get("issuetype")),
        "status": status.get("name"),
        "status_category": name_of(status.get("statusCategory"), "key"),
        "priority": name_of(f.get("priority")),
        "assignee": name_of(f.get("assignee"), "displayName"),
        "reporter": name_of(f.get("reporter"), "displayName"),
        "created": f.get("created"),
        "updated": f.get("updated"),
        "resolved": f.get("resolutiondate"),
        "resolution": name_of(f.get("resolution")),
        "hours_to_resolve": hours,
        "labels": f.get("labels") or [],
    }


def _ticket_rollup(issues: list) -> dict:
    return {
        "total": len(issues),
        "open": sum(1 for i in issues if i["status_category"] != "done"),
        "resolved": sum(1 for i in issues if i["resolved"]),
        "by_status": counts(i["status"] for i in issues),
        "by_priority": counts(i["priority"] for i in issues),
        "resolution_hours": number_stats(
            [i["hours_to_resolve"] for i in issues if i["hours_to_resolve"] is not None]
        ),
    }


def _summarize(
    projects: list, issues: list, service_desks, projects_ok: bool = True, issues_ok: bool = True
) -> dict:
    """Null, not zero, for a section whose read failed or did not finish."""
    by_priority_hours: dict = {}
    for i in issues:
        if i["hours_to_resolve"] is not None:
            by_priority_hours.setdefault(i["priority"] or NONE_LABEL, []).append(
                i["hours_to_resolve"]
            )
    changes = [i for i in issues if (i["issue_type"] or "").lower() in CHANGE_TYPES]
    incidents = [i for i in issues if (i["issue_type"] or "").lower() in INCIDENT_TYPES]
    projects_section = {
        "total": len(projects),
        "by_type": counts(p["project_type"] for p in projects),
        "without_lead": sum(1 for p in projects if not p["lead"]),
    }
    issues_section = {
        "issues": {
            "total": len(issues),
            "open": sum(1 for i in issues if i["status_category"] != "done"),
            "resolved": sum(1 for i in issues if i["resolved"]),
            "open_unassigned": sum(
                1 for i in issues if i["status_category"] != "done" and not i["assignee"]
            ),
            "by_project": counts(i["project"] for i in issues),
            "by_issue_type": counts(i["issue_type"] for i in issues),
            "by_status_category": counts(i["status_category"] for i in issues),
            "by_priority": counts(i["priority"] for i in issues),
            "resolution_hours": {
                "overall": number_stats(
                    [i["hours_to_resolve"] for i in issues if i["hours_to_resolve"] is not None]
                ),
                # Keyed by data, so null_summary nulls it whole (see Counts).
                "by_priority": Counts(
                    (k, number_stats(v)) for k, v in sorted(by_priority_hours.items())
                ),
            },
        },
        "change_issues": _ticket_rollup(changes),
        "incident_issues": _ticket_rollup(incidents),
    }
    return {
        "projects": projects_section if projects_ok else null_summary(projects_section),
        "service_desks": len(service_desks) if isinstance(service_desks, list) else None,
        **(issues_section if issues_ok else null_summary(issues_section)),
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself and reads env directly.
    load_dotenv()

    settings = connection_settings()
    if isinstance(settings, str):
        report_failure(settings, "bad_config")
        return 1
    base_url, email, api_token = settings

    lookback_days = int_env("JIRA_LOOKBACK_DAYS", 90)
    max_issues = int_env("JIRA_MAX_ISSUES", 2000)
    if lookback_days is None or max_issues is None:
        report_failure(
            "JIRA_LOOKBACK_DAYS and JIRA_MAX_ISSUES must be positive integers",
            "bad_config",
        )
        return 1
    # Comma-separated project keys or exact names (a name may contain spaces, not commas).
    wanted_projects = list_env("JIRA_PROJECTS")
    jql = os.environ.get("JIRA_ISSUE_JQL", "").strip()
    if jql:
        lookback_days = None
    else:
        jql = f"updated >= -{lookback_days}d ORDER BY updated DESC"

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
    projects_ok = False
    issues_ok = False
    # projects_filter is the setting as given; projects_selected is the keys it matched, null until matched.
    scope = {"projects_filter": wanted_projects or None, "projects_selected": None, "projects_left_out": None,
             "issue_types_scope": "site", "statuses_scope": "site", "priorities_scope": "site"}

    try:
        # /myself first: serverInfo answers anonymously, so a bad token must be
        # seen on a call that needs the credential, where a 401 is auth_failed.
        collector = collector_info(client)
        info = client.request("GET", "/rest/api/3/serverInfo", "GET /rest/api/3/serverInfo")
        if info:
            site = {
                "base_url": info.get("baseUrl"),
                "server_title": info.get("serverTitle"),
                "deployment_type": info.get("deploymentType"),
                "version": info.get("version"),
                "build_number": info.get("buildNumber"),
            }
        raw_projects, projects_ok = client.paged_values(
            "/rest/api/3/project/search",
            "GET /rest/api/3/project/search",
            params={"expand": "lead,insight,issueTypes"},
        )
        selected = None
        if wanted_projects:
            if not projects_ok:
                # Without the whole list the names cannot be matched, and nothing site-wide may stand in for them.
                client.fail("JIRA_PROJECTS", "Unresolved", "the project list did not finish, so JIRA_PROJECTS "
                            "could not be matched; no project, type, status or issue was collected", "partial_failure")
                jql = None  # no query ran, and the unscoped one must not read as if it had
                raise Abort
            selected, unmatched = _match_projects(raw_projects, wanted_projects)
            if unmatched:
                report_failure(
                    "JIRA_PROJECTS names no project this account can see: " + ", ".join(unmatched)
                    + " (match is on the project key or its exact name)", "bad_config")
                return 1
            scope.update(projects_selected=sorted(str(p.get("key")) for p in selected),
                         projects_left_out=len(raw_projects) - len(selected), issue_types_scope="projects",
                         statuses_scope="projects")
            raw_projects = selected
            jql = _scoped_jql([str(p.get("id")) for p in selected], jql)
        projects = [_project_record(p) for p in raw_projects]

        raw_types = client.request("GET", "/rest/api/3/issuetype", "GET /rest/api/3/issuetype")
        if selected is not None:
            # A project lists the types it uses, team-managed copies included.
            type_ids = {str(t.get("id")) for p in selected for t in p.get("issueTypes") or []}
            raw_types = [t for t in raw_types or [] if str(t.get("id")) in type_ids]
        issue_types = [
            {
                "id": t.get("id"),
                "name": t.get("name"),
                "subtask": t.get("subtask"),
                "hierarchy_level": t.get("hierarchyLevel"),
                # Team-managed projects each carry their own copy of a type
                # (Story, Epic, ...), so a name can repeat once per project.
                "project_id": name_of((t.get("scope") or {}).get("project"), "id"),
            }
            for t in raw_types or []
        ]

        raw_priorities, _ = client.paged_values(
            "/rest/api/3/priority/search", "GET /rest/api/3/priority/search"
        )
        priorities = [
            {"id": p.get("id"), "name": p.get("name"), "is_default": p.get("isDefault")}
            for p in raw_priorities
        ]

        if selected is None:
            raw_statuses = client.request("GET", "/rest/api/3/status", "GET /rest/api/3/status")
        else:
            # The statuses each selected project's workflows use, once each; a project whose read fails is recorded.
            by_id: dict = {}
            for p in selected:
                per_type = client.request("GET", f"/rest/api/3/project/{p.get('id')}/statuses",
                                          "GET /rest/api/3/project/{id}/statuses")
                for t in per_type or []:
                    for st in t.get("statuses") or []:
                        by_id.setdefault(str(st.get("id")), st)
            raw_statuses = list(by_id.values())
        statuses = sorted(
            (
                {
                    "id": s.get("id"),
                    "name": s.get("name"),
                    "category": name_of(s.get("statusCategory"), "key"),
                }
                for s in raw_statuses or []
            ),
            key=lambda s: (s["category"] or "", s["name"] or ""),
        )

        # Jira Service Management is detected from the project list: only a JSM
        # site has `service_desk` projects, and only then is the service-desk API
        # called. A site without JSM answers that API with a 403 HTML page,
        # indistinguishable from a real permission denial, so it must not be
        # asked. No JSM is recorded as `available: false`, not as a failure.
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
                if selected is None
                or str(d.get("projectKey") or "") in {str(p.get("key") or "") for p in selected}
            ]
            jsm_available = True

        raw_issues, truncated, search_complete = client.search_issues(jql, ISSUE_FIELDS, max_issues)
        issues = [_issue_record(i) for i in raw_issues]
        # A capped search is also unfinished: its totals would read as the population.
        issues_ok = search_complete and not truncated
    except Abort:
        pass  # already recorded in api_failures; write what was collected
    except Exception as e:  # unexpected response shape: keep what was collected and say why
        client.fail("collection", type(e).__name__, str(e)[:200], "internal_error")
        projects_ok = issues_ok = False  # the collection did not finish, so no count is trusted

    evidence = {
        "metadata": {
            "collected_at": utc_now().isoformat(),
            "base_url": base_url,
            "jql": jql,
            "lookback_days": lookback_days,
            "max_issues": max_issues,
            "issues_collected": len(issues),
            "issues_truncated": truncated,
            # With JIRA_PROJECTS, projects, issue types, statuses, service desks and issues are limited to the named
            # projects (only a count of the others is kept); priorities are site-wide either way.
            **scope,
            "partial_failure": bool(client.api_failures),
            "api_failures": client.api_failures,
        },
        "site": site,
        "collector": collector,
        "summary": _summarize(projects, issues, service_desks, projects_ok, issues_ok),
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

    incomplete = f"issues truncated at JIRA_MAX_ISSUES={max_issues}" if truncated else ""
    return write_and_finish(logger, client, evidence, OUTPUT_FILE, incomplete)


if __name__ == "__main__":
    sys.exit(main())
