#!/usr/bin/env python3
"""
Wiz Posture Issues

Summarizes Wiz Issues of type CLOUD_CONFIGURATION and TOXIC_COMBINATION: what
is open, how severe, how old against the remediation window, whether the
serious ones are tracked in a ticketing system (ServiceNow / Jira via Wiz's
serviceTickets link), and how many were resolved recently.

This replaces the legacy wiz_issues_report.py, which pushed a CSV into a
Paramify assessment. Here the same data becomes KSI evidence instead.

Speaks to KSI-CNA-EIS (persistent automated assessment) and KSI-SVC-EIS
(evaluating and improving security). Threat-detection issues are excluded by
default: they need read:threat_issues and are incident evidence, not posture.
"""

import logging
import statistics
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from wiz_client import (  # type: ignore  # noqa: E402
    WizClient,
    age_days,
    collect_guarded,
    env_int,
    env_list,
    evidence,
    parse_ts,
    run_fetcher,
)
from vuln_summary import SEVERITIES, sla_days  # type: ignore  # noqa: E402

logger = logging.getLogger("wiz_posture_issues")

ISSUES_QUERY = """
query WizPostureIssues($first: Int, $after: String, $filterBy: IssueFilters) {
  issuesV2(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      type
      status
      severity
      createdAt
      statusChangedAt
      resolvedAt
      dueAt
      serviceTickets { externalId name url }
      sourceRules {
        __typename
        ... on Control { id name }
        ... on CloudConfigurationRule { id name }
      }
      entitySnapshot { type nativeType cloudPlatform subscriptionName }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


def slim(issue: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    rules = issue.get("sourceRules") or []
    entity = issue.get("entitySnapshot") or {}
    tickets = issue.get("serviceTickets") or []
    due = parse_ts(issue.get("dueAt"))
    return {
        "id": issue.get("id"),
        "type": issue.get("type"),
        "status": issue.get("status"),
        "severity": issue.get("severity"),
        "created_at": issue.get("createdAt"),
        "resolved_at": issue.get("resolvedAt"),
        "due_at": issue.get("dueAt"),
        "overdue": bool(due and due < now and (issue.get("status") or "") in {"OPEN", "IN_PROGRESS"}),
        "age_days": age_days(issue.get("createdAt"), now),
        "rule": (rules[0] or {}).get("name") if rules else None,
        "entity_type": entity.get("nativeType") or entity.get("type"),
        "cloud_platform": entity.get("cloudPlatform"),
        "subscription": entity.get("subscriptionName"),
        "ticketed": bool(tickets),
        "tickets": [{"id": t.get("externalId"), "url": t.get("url")} for t in tickets],
    }


def summarize(open_rows: List[Dict[str, Any]], resolved_rows: List[Dict[str, Any]],
              resolved_window_days: int) -> Dict[str, Any]:
    windows = sla_days()
    by_sev = Counter(r.get("severity") or "UNKNOWN" for r in open_rows)
    past = Counter(r["severity"] for r in open_rows
                   if r.get("severity") in windows and (r.get("age_days") or 0) > windows[r["severity"]])
    oldest: Dict[str, int] = {}
    for r in open_rows:
        if r.get("age_days") is None:
            continue
        s = r.get("severity") or "UNKNOWN"
        oldest[s] = max(oldest.get(s, 0), r["age_days"])

    serious = [r for r in open_rows if r.get("severity") in {"CRITICAL", "HIGH"}]
    ticketed = sum(1 for r in serious if r.get("ticketed"))

    ttr = []
    for r in resolved_rows:
        c, z = parse_ts(r.get("created_at")), parse_ts(r.get("resolved_at"))
        if c and z and z >= c:
            ttr.append((z - c).days)

    return {
        "open_issue_count": len(open_rows),
        "open_by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES if by_sev.get(s)},
        "open_by_type": dict(Counter(r.get("type") or "unknown" for r in open_rows)),
        "open_by_status": dict(Counter(r.get("status") or "unknown" for r in open_rows)),
        "remediation_windows_days": windows,
        "past_remediation_window_by_severity": dict(past),
        "oldest_open_age_days_by_severity": oldest,
        "overdue_by_due_date_count": sum(1 for r in open_rows if r.get("overdue")),
        "critical_high_open": len(serious),
        "critical_high_ticketed": ticketed,
        "critical_high_ticketed_pct": round(100.0 * ticketed / len(serious), 1) if serious else None,
        "top_rules": Counter(r.get("rule") or "unknown" for r in open_rows).most_common(15),
        "resolved_window_days": resolved_window_days,
        "resolved_in_window": len(resolved_rows),
        "median_days_to_resolve": statistics.median(ttr) if ttr else None,
    }


def body(client: WizClient) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    types = env_list("WIZ_ISSUE_TYPES", ["CLOUD_CONFIGURATION", "TOXIC_COMBINATION"])
    open_statuses = env_list("WIZ_ISSUE_OPEN_STATUSES", ["OPEN", "IN_PROGRESS"])
    window = env_int("WIZ_RESOLVED_WINDOW_DAYS", 90)
    cap = env_int("WIZ_MAX_RECORDS", 50000)

    open_raw = client.paginate("issuesV2 (open)", ISSUES_QUERY, "issuesV2",
                               {"filterBy": {"type": types, "status": open_statuses}}, max_records=cap)
    since = (now - timedelta(days=window)).strftime("%Y-%m-%dT%H:%M:%SZ")
    resolved_raw = client.paginate("issuesV2 (resolved)", ISSUES_QUERY, "issuesV2",
                                   {"filterBy": {"type": types, "status": ["RESOLVED"],
                                                 "statusChangedAt": {"after": since}}}, max_records=cap)

    open_rows = [slim(i, now) for i in open_raw]
    resolved_rows = [slim(i, now) for i in resolved_raw]
    return evidence(
        client=client,
        operations=["issuesV2"],
        records=open_rows,
        analysis=summarize(open_rows, resolved_rows, window),
        empty_message="Wiz returned no open posture issues for the selected types. "
                      "Check wiz_scan_coverage before reading this as a clean result.",
        filter={"types": types, "open_statuses": open_statuses, "resolved_since": since},
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_posture_issues.json", logger))
