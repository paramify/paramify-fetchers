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
    done_entries,
    in_offset_of,
    int_env,
    name_of,
    null_summary,
    number_stats,
    parse_ts,
    report_failure,
    status_catalog,
    utc_now,
    write_and_finish,
    zone_of,
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


def _status_transitions(histories: list, reference=None, zone=None) -> list:
    """Status moves oldest first, with times in the issue's own timezone (see in_offset_of)."""
    moves = []
    for h in histories:
        at = in_offset_of(h.get("created"), reference, zone)
        for item in h.get("items") or []:
            if item.get("fieldId") == "status" or item.get("field") == "status":
                moves.append(
                    {
                        "at": at,
                        "by": name_of(h.get("author"), "displayName"),
                        "from": item.get("fromString"),
                        "to": item.get("toString"),
                        "from_id": str(item.get("from")) if item.get("from") is not None else None,
                        "to_id": str(item.get("to")) if item.get("to") is not None else None,
                    }
                )
    return sorted(moves, key=lambda m: str(m["at"] or ""))


def _item_record(
    issue: dict, histories: list, now, history_known: bool = True, catalog=(set(), set(), False), zone=None
) -> dict:
    f = issue.get("fields") or {}
    status = f.get("status") or {}
    status_category = name_of(status.get("statusCategory"), "key")
    is_open = status_category != "done"
    created = parse_ts(f.get("created"))
    due = f.get("duedate")
    overdue = bool(is_open and due and due < now.date().isoformat())
    transitions = _status_transitions(histories, f.get("created"), zone)
    # A ticket can be done without a resolutiondate (a status moved to the done
    # category with no resolution set). Fall back to the LAST entry into the
    # done category (by status id and category, so Resolved-then-Closed sweeps
    # and renamed statuses are handled) so a late closure is still measured,
    # and say which was used. An earlier closure that was reopened is recorded
    # as reopened. When the history read failed the close time is unknown.
    done_moves = done_entries(transitions, status, catalog)
    closed_at, closed_at_source = f.get("resolutiondate"), "resolutiondate"
    if not is_open and not closed_at:
        done_move = next((m for m in reversed(done_moves) if m["at"]), None)
        closed_at = done_move["at"] if done_move else None
        closed_at_source = "status_history" if done_move else ("unknown" if not history_known else None)
    resolved = parse_ts(closed_at)
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
        "closed_at": closed_at if not is_open else None,
        "closed_at_source": closed_at_source if not is_open else None,
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
        "status_change_count": len(transitions) if history_known else None,
        "status_history_known": history_known,
        "reopened": len(done_moves) > 1 if history_known else None,
    }


def _summarize(items: list, complete: bool = True) -> dict:
    open_items = [i for i in items if i["is_open"]]
    closed = [i for i in items if not i["is_open"]]
    summary = {
        "total": len(items),
        "open": len(open_items),
        "closed": len(closed),
        "open_overdue": sum(1 for i in open_items if i["overdue"]),
        "open_unassigned": sum(1 for i in open_items if not i["assignee"]),
        "open_without_due_date": sum(1 for i in open_items if not i["due_date"]),
        "closed_after_due_date": sum(
            1
            for i in closed
            if i["due_date"] and i["closed_at"] and i["closed_at"][:10] > i["due_date"]
        ),
        "closed_without_close_time": sum(
            1 for i in closed if not i["closed_at"] and i["closed_at_source"] != "unknown"
        ),
        "closed_close_time_unknown": sum(1 for i in closed if i["closed_at_source"] == "unknown"),
        "days_to_close": number_stats([i["days_to_close"] for i in closed if i["days_to_close"] is not None]),
        "open_age_days": number_stats([i["days_open"] for i in open_items if i["days_open"] is not None]),
        "by_status": counts(i["status"] for i in items),
        "by_priority": counts(i["priority"] for i in items),
        "by_project": counts(i["project"] for i in items),
    }
    # When the ticket search did not finish, every count would be too low and read
    # as "none found", so the summary is reported as not measured instead.
    return summary if complete else null_summary(summary)


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
    search_complete = False
    catalog = (set(), set(), False)

    try:
        collector = collector_info(client)
        zone = zone_of((collector or {}).get("time_zone"))
        catalog = status_catalog(client)
        raw, truncated, search_complete = client.search_issues(jql, ISSUE_FIELDS, max_items)
        histories, history_complete, unknown_ids = client.bulk_changelogs(
            [str(i.get("id")) for i in raw if i.get("id")], ["status"]
        )
        items = [
            _item_record(
                i, histories.get(str(i.get("id")), []), now, str(i.get("id")) not in unknown_ids, catalog, zone
            )
            for i in raw
        ]
    except Abort:
        pass
    except Exception as e:  # unexpected response shape: keep what was collected and say why
        client.fail("collection", type(e).__name__, str(e)[:200], "internal_error")
        search_complete = False  # the collection did not finish, so no count is trusted

    evidence = {
        "metadata": {
            "collected_at": now.isoformat(),
            "base_url": base_url,
            "jql": jql,
            "max_items": max_items,
            "items_collected": len(items),
            "items_truncated": truncated,
            "search_complete": search_complete,
            "status_history_complete": history_complete,
            "done_statuses_known": catalog[2],
            "partial_failure": bool(client.api_failures),
            "api_failures": client.api_failures,
        },
        "collector": collector,
        # A capped search is also unfinished: "total: 2000" of a larger population
        # would read as the population.
        "summary": _summarize(items, search_complete and not truncated),
        "items": items,
    }
    incomplete = ""
    if truncated:
        incomplete = f"tickets truncated at JIRA_REMEDIATION_MAX_ITEMS={max_items}"
    elif not history_complete:
        incomplete = "status history incomplete for some tickets"
    return write_and_finish(logger, client, evidence, OUTPUT_FILE, incomplete)


if __name__ == "__main__":
    sys.exit(main())
