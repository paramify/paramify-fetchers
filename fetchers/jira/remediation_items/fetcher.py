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
    all_field_ids,
    collector_info,
    connection_settings,
    counts,
    done_entries,
    field_value,
    in_offset_of,
    int_env,
    is_date_only,
    list_env,
    name_of,
    null_summary,
    number_stats,
    parse_ts,
    report_failure,
    resolve_fields,
    role_state,
    status_catalog,
    ts_sort_key,
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


def _is_past(due, now, zone=None):
    """True when `due` has passed at `now`, None when it does not parse. A date
    without a time has passed only once its whole day is over in the collector's
    timezone (the zone Jira renders dates in), or in UTC without one."""
    td = parse_ts(due)
    if not td:
        return None
    if is_date_only(due):
        today = now.astimezone(zone).date() if zone is not None else now.date()
        return today.isoformat() > due
    return now > td


def _closed_after(closed_at, due):
    """True when the close time is after the due value, None when either does not
    parse. Against a date without a time only the calendar days are compared, so a
    ticket closed on its due day is not late."""
    tc, td = parse_ts(closed_at), parse_ts(due)
    if not tc or not td:
        return None
    if is_date_only(due) or is_date_only(closed_at):
        return closed_at[:10] > due[:10]
    return tc > td


def _due_value(f: dict, due_ids):
    """The ticket's due value: the built-in duedate, or the first configured field holding a value."""
    if due_ids is None:
        return f.get("duedate")
    return next((v for v in (field_value(f.get(fid)) for fid in due_ids) if v not in (None, "")), None)


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
    return sorted(moves, key=lambda m: ts_sort_key(m["at"]))


def _item_record(
    issue: dict,
    histories: list,
    now,
    history_known: bool = True,
    catalog=(set(), set(), False),
    zone=None,
    due_ids=None,
    due_known: bool = True,
    risk=None,
) -> dict:
    """One ticket. `due_ids` is None for the built-in duedate, else the configured
    field's ids; `due_known` is False when that field could not be resolved, and
    then nothing about due dates is stated. `risk` is None when no risk-accepted
    value is configured, else (status names, resolution names), lowercased."""
    f = issue.get("fields") or {}
    status = f.get("status") or {}
    status_category = name_of(status.get("statusCategory"), "key")
    is_open = status_category != "done"
    created = parse_ts(f.get("created"))
    due = _due_value(f, due_ids) if due_known else None
    # A due value that is not a date (the configured field holds free text) is
    # kept as written and judged neither overdue nor on time.
    due_parses = bool(due) and parse_ts(due) is not None
    if not due_known:
        overdue = None
    elif not is_open or not due:
        overdue = False
    else:
        overdue = _is_past(due, now, zone)
    risk_accepted = None
    if risk is not None:
        risk_accepted = (status.get("name") or "").strip().lower() in risk[0] or (
            name_of(f.get("resolution")) or ""
        ).strip().lower() in risk[1]
    transitions = _status_transitions(histories, f.get("created"), zone)
    # A ticket can be done without a resolutiondate (a status moved to the done
    # category with no resolution set). Fall back to the LAST entry into the
    # done category (by status id and category, so Resolved-then-Closed sweeps
    # and renamed statuses are handled) so a late closure is still measured,
    # and say which was used. An earlier closure that was reopened is recorded
    # as reopened. When the history read failed, or the status catalog could not
    # be read (so a Resolved-then-Closed sweep would be taken for the closure),
    # the close time is unknown, never guessed.
    done_moves = done_entries(transitions, status, catalog)
    closed_at, closed_at_source = f.get("resolutiondate"), "resolutiondate"
    if not is_open and not closed_at:
        done_move = next((m for m in reversed(done_moves) if parse_ts(m["at"])), None) if catalog[2] else None
        closed_at = done_move["at"] if done_move else None
        closed_at_source = (
            "status_history" if done_move else ("unknown" if not (history_known and catalog[2]) else None)
        )
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
        "due_date_known": due_known,
        "due_date_unparseable": bool(due) and not due_parses,
        "resolved": f.get("resolutiondate"),
        "closed_at": closed_at if not is_open else None,
        "closed_at_source": closed_at_source if not is_open else None,
        "resolution": name_of(f.get("resolution")),
        "risk_accepted": risk_accepted,
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
        # Closed and reopened: for an open ticket one earlier closure is enough.
        "reopened": len(done_moves) > (0 if is_open else 1) if history_known else None,
    }


def _unmatched(items: list, statuses: list, resolutions: list) -> list:
    seen_status = {(i["status"] or "").strip().lower() for i in items}
    seen_resolution = {(i["resolution"] or "").strip().lower() for i in items}
    return sorted(
        [v for v in statuses if v.lower() not in seen_status]
        + [v for v in resolutions if v.lower() not in seen_resolution]
    )


def _summarize(items: list, complete: bool = True, due_known: bool = True, risk_on: bool = False) -> dict:
    open_items = [i for i in items if i["is_open"]]
    closed = [i for i in items if not i["is_open"]]
    summary = {
        "total": len(items),
        "open": len(open_items),
        "closed": len(closed),
        # The due-date counts are null, not zero, when the configured due-date field
        # could not be resolved: no due date was read, so none can be counted.
        "open_overdue": sum(1 for i in open_items if i["overdue"]) if due_known else None,
        "open_unassigned": sum(1 for i in open_items if not i["assignee"]),
        "open_without_due_date": sum(1 for i in open_items if not i["due_date"]) if due_known else None,
        "open_due_date_unparseable": sum(1 for i in open_items if i["due_date_unparseable"]) if due_known else None,
        "closed_after_due_date": sum(1 for i in closed if _closed_after(i["closed_at"], i["due_date"]))
        if due_known
        else None,
        # Null unless a risk-accepted status or resolution is configured.
        "risk_accepted": sum(1 for i in items if i["risk_accepted"]) if risk_on else None,
        "closed_risk_accepted": sum(1 for i in closed if i["risk_accepted"]) if risk_on else None,
        "closed_excluding_risk_accepted": sum(1 for i in closed if not i["risk_accepted"]) if risk_on else None,
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

    due_field = os.environ.get("JIRA_REMEDIATION_DUE_DATE_FIELD", "").strip()
    if due_field and role_state(due_field) == "invalid":
        report_failure(
            "JIRA_REMEDIATION_DUE_DATE_FIELD must be a field name or customfield_ ids separated by commas",
            "bad_config",
        )
        return 1
    risk_statuses = list_env("JIRA_REMEDIATION_RISK_ACCEPTED_STATUSES")
    risk_resolutions = list_env("JIRA_REMEDIATION_RISK_ACCEPTED_RESOLUTIONS")
    risk = None
    if risk_statuses or risk_resolutions:
        risk = ({v.lower() for v in risk_statuses}, {v.lower() for v in risk_resolutions})

    client = JiraClient(base_url, email, api_token)
    now = utc_now()
    collector = None
    items: list = []
    truncated = False
    history_complete = True
    search_complete = False
    catalog = (set(), set(), False)
    due_ids = None  # None reads the built-in duedate
    due_known = not due_field  # a configured field is unknown until it resolves
    problems: dict = {}
    candidates: dict = {}

    try:
        collector = collector_info(client)
        zone = zone_of((collector or {}).get("time_zone"))
        catalog = status_catalog(client)
        if due_field:
            ids, problems, candidates = resolve_fields(client, {"due_date": due_field})
            due_ids = ids.get("due_date")
            due_known = bool(due_ids)
        search_fields = list(dict.fromkeys(ISSUE_FIELDS + all_field_ids({"due_date": due_ids or []})))
        raw, truncated, search_complete = client.search_issues(jql, search_fields, max_items)
        histories, history_complete, unknown_ids = client.bulk_changelogs(
            [str(i.get("id")) for i in raw if i.get("id")], ["status"]
        )
        items = [
            _item_record(
                i,
                histories.get(str(i.get("id")), []),
                now,
                str(i.get("id")) not in unknown_ids,
                catalog,
                zone,
                due_ids,
                due_known,
                risk,
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
            "due_date_field": due_field or "duedate",
            "due_date_field_ids": due_ids if due_field else ["duedate"],
            "due_date_known": due_known,
            "field_candidates": candidates,
            "risk_accepted_statuses": risk_statuses if risk else None,
            "risk_accepted_resolutions": risk_resolutions if risk else None,
            # Configured values seen on no collected ticket: none may exist, or the
            # value is mistyped and those tickets were counted as ordinary closures.
            "risk_accepted_values_unmatched": _unmatched(items, risk_statuses, risk_resolutions) if risk else None,
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
        "summary": _summarize(items, search_complete and not truncated, due_known, risk is not None),
        "items": items,
    }
    incomplete = ""
    if truncated:
        incomplete = f"tickets truncated at JIRA_REMEDIATION_MAX_ITEMS={max_items}"
    elif not history_complete:
        incomplete = "status history incomplete for some tickets"
    field_reason = ""
    if not due_known and problems:
        field_reason = (
            f"due-date field not resolved ({problems.get('due_date')}): no due date was read, so overdue and the "
            "other due-date counts are not stated. Set JIRA_REMEDIATION_DUE_DATE_FIELD to the field's name or a "
            "customfield_ id from metadata.field_candidates, or leave it empty to read the built-in Due date"
        )
    if field_reason:
        logger.warning("%s", field_reason)
        incomplete = f"{incomplete}; {field_reason}" if incomplete else field_reason
    return write_and_finish(logger, client, evidence, OUTPUT_FILE, incomplete)


if __name__ == "__main__":
    sys.exit(main())
