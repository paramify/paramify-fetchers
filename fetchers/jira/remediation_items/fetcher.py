#!/usr/bin/env python3
"""Jira remediation items: findings tickets matched by JQL, with owner, due date and status history."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from jira_common import (  # noqa: E402
    Abort,
    JiraClient,
    collector_info,
    connection_settings,
    counts,
    int_env,
    name_of,
    number_stats,
    parse_ts,
    report_failure,
    utc_now,
    write_and_finish,
)

logger = logging.getLogger("jira_remediation_items")

OUTPUT_FILE = "jira_remediation_items.json"

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
    "duedate",
    "labels",
    "components",
    "parent",
    "issuelinks",
]


def _links(f: dict) -> list:
    out = []
    for link in f.get("issuelinks") or []:
        ltype = link.get("type") or {}
        if link.get("outwardIssue"):
            out.append({"relation": ltype.get("outward"), "key": link["outwardIssue"].get("key")})
        elif link.get("inwardIssue"):
            out.append({"relation": ltype.get("inward"), "key": link["inwardIssue"].get("key")})
    return out


def _status_transitions(histories: list) -> list:
    moves = []
    for h in histories:
        for item in h.get("items") or []:
            if item.get("fieldId") == "status" or item.get("field") == "status":
                moves.append(
                    {
                        "at": h.get("created"),
                        "by": name_of(h.get("author"), "displayName"),
                        "from": item.get("fromString"),
                        "to": item.get("toString"),
                    }
                )
    return sorted(moves, key=lambda m: m["at"] or "")


def _item_record(issue: dict, histories: list, now) -> dict:
    f = issue.get("fields") or {}
    status = f.get("status") or {}
    status_category = name_of(status.get("statusCategory"), "key")
    is_open = status_category != "done"
    created = parse_ts(f.get("created"))
    resolved = parse_ts(f.get("resolutiondate"))
    due = f.get("duedate")
    overdue = bool(is_open and due and due < now.date().isoformat())
    transitions = _status_transitions(histories)
    return {
        "key": issue.get("key"),
        "summary": f.get("summary"),
        "project": name_of(f.get("project"), "key"),
        "issue_type": name_of(f.get("issuetype")),
        "priority": name_of(f.get("priority")),
        "status": status.get("name"),
        "status_category": status_category,
        "is_open": is_open,
        "assignee": name_of(f.get("assignee"), "displayName"),
        "reporter": name_of(f.get("reporter"), "displayName"),
        "created": f.get("created"),
        "updated": f.get("updated"),
        "due_date": due,
        "resolved": f.get("resolutiondate"),
        "resolution": name_of(f.get("resolution")),
        "overdue": overdue,
        "days_open": round(((resolved or now) - created).total_seconds() / 86400, 2) if created else None,
        "days_to_close": round((resolved - created).total_seconds() / 86400, 2)
        if created and resolved
        else None,
        "labels": f.get("labels") or [],
        "components": [c.get("name") for c in f.get("components") or [] if c.get("name")],
        "parent": name_of(f.get("parent"), "key"),
        "linked_issues": _links(f),
        "status_transitions": transitions,
        "status_change_count": len(transitions),
    }


def _summarize(items: list) -> dict:
    open_items = [i for i in items if i["is_open"]]
    closed = [i for i in items if not i["is_open"]]
    return {
        "total": len(items),
        "open": len(open_items),
        "closed": len(closed),
        "open_overdue": sum(1 for i in open_items if i["overdue"]),
        "open_unassigned": sum(1 for i in open_items if not i["assignee"]),
        "open_without_due_date": sum(1 for i in open_items if not i["due_date"]),
        "closed_after_due_date": sum(
            1
            for i in closed
            if i["due_date"] and i["resolved"] and i["resolved"][:10] > i["due_date"]
        ),
        "days_to_close": number_stats([i["days_to_close"] for i in closed if i["days_to_close"] is not None]),
        "open_age_days": number_stats([i["days_open"] for i in open_items if i["days_open"] is not None]),
        "by_status": counts(i["status"] for i in items),
        "by_priority": counts(i["priority"] for i in items),
        "by_project": counts(i["project"] for i in items),
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    settings = connection_settings()
    if isinstance(settings, str):
        report_failure(settings, "bad_config")
        return 1
    base_url, email, api_token = settings

    jql = os.environ.get("JIRA_REMEDIATION_JQL", "").strip()
    if not jql:
        report_failure(
            "JIRA_REMEDIATION_JQL is not set; it selects the findings tickets, e.g. "
            "'project = OPS AND labels = cp-test-finding'",
            "bad_config",
        )
        return 1
    max_items = int_env("JIRA_REMEDIATION_MAX_ITEMS", 2000)
    if max_items is None:
        report_failure("JIRA_REMEDIATION_MAX_ITEMS must be a positive integer", "bad_config")
        return 1

    client = JiraClient(base_url, email, api_token)
    now = utc_now()
    collector = None
    items: list = []
    truncated = False
    history_complete = True

    try:
        collector = collector_info(client)
        raw, truncated, _ = client.search_issues(jql, ISSUE_FIELDS, max_items)
        histories, history_complete = client.bulk_changelogs(
            [str(i.get("id")) for i in raw if i.get("id")], ["status"]
        )
        items = [_item_record(i, histories.get(str(i.get("id")), []), now) for i in raw]
    except Abort:
        pass

    evidence = {
        "metadata": {
            "collected_at": now.isoformat(),
            "base_url": base_url,
            "jql": jql,
            "max_items": max_items,
            "items_collected": len(items),
            "items_truncated": truncated,
            "status_history_complete": history_complete,
            "partial_failure": bool(client.api_failures),
            "api_failures": client.api_failures,
        },
        "collector": collector,
        "summary": _summarize(items),
        "items": items,
    }
    return write_and_finish(logger, client, evidence, OUTPUT_FILE)


if __name__ == "__main__":
    sys.exit(main())
