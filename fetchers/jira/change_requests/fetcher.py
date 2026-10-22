#!/usr/bin/env python3
"""Jira change requests: CCB approval, deployment, testing, notification and exception review per ticket."""

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
    disabled_roles,
    done_entries,
    field_problem_reason,
    in_offset_of,
    int_env,
    invalid_roles,
    is_date_only,
    json_env,
    list_env,
    name_of,
    null_summary,
    parse_ts,
    report_failure,
    resolve_fields,
    role_values,
    status_catalog,
    utc_now,
    write_and_finish,
    zone_of,
)

logger = logging.getLogger("jira_change_requests")

OUTPUT_FILE = "jira_change_requests.json"

# Field roles and the default Jira field names they are looked up by.
DEFAULT_FIELDS = {
    "change_type": "Change Type",
    "risk": "Change Risk",
    "approver": "CCB Approver",
    "approved_at": "CCB Approval Date",
    "security_review": "Security Impact Analysis",
    "test_results": "Test Results",
    "deployed_at": "Deployed At",
    "exception_expiry": "Exception Expiry",
    "last_reviewed": "Last Reviewed",
}
BASE_FIELDS = [
    "summary",
    "project",
    "issuetype",
    "status",
    "created",
    "updated",
    "resolutiondate",
    "labels",
    "components",
    "issuelinks",
    "watches",
    "comment",
    "resolution",
]
# Done tickets closed with these resolutions were never deployed.
DEFAULT_NOT_DEPLOYED = ["Won't Do", "Won't Fix", "Cancelled", "Canceled", "Duplicate", "Rejected", "Declined"]
PASSED_TESTS = {"passed", "pass"}
FAILED_TESTS = {"failed", "fail"}
DONE_REVIEWS = {"completed", "complete", "done", "yes"}


# Findings that cannot be produced when the field role they read is turned off
# (an empty name in JIRA_CHANGE_FIELDS). Listed in metadata.checks_disabled so an
# evidence file never looks clean about a check that did not run.
FINDINGS_BY_FIELD = {
    "last_reviewed": ["exception_review_overdue"],
    "exception_expiry": ["exception_open_past_expiry"],
    "test_results": ["deployed_with_failed_tests", "deployed_without_passing_tests"],
    "security_review": ["connection_without_security_review"],
    "risk": ["connection_without_risk"],
}


def _checks_disabled(disabled_fields) -> list:
    return sorted({f for role in disabled_fields for f in FINDINGS_BY_FIELD.get(role, [])})


def _lower_set(values) -> set:
    return {v.strip().lower() for v in values if v and v.strip()}


def _transitions(histories: list, field_ids: dict, reference=None, zone=None) -> tuple:
    """Return (status_moves, field_changes) from changelog histories, oldest first.

    Times are rendered in the issue's own UTC offset (see in_offset_of) so a move
    compares with a date-only field the same way a field timestamp does.
    """
    moves, changes = [], []
    watched = {fid: role for role, fids in field_ids.items() for fid in fids}
    for h in histories:
        at = in_offset_of(h.get("created"), reference, zone)
        for item in h.get("items") or []:
            fid = item.get("fieldId") or item.get("field")
            if fid == "status":
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
            elif fid in watched:
                changes.append(
                    {
                        "at": at,
                        "by": name_of(h.get("author"), "displayName"),
                        "field": watched[fid],
                        "to": item.get("toString"),
                    }
                )
    key = lambda m: str(m["at"] or "")  # noqa: E731
    return sorted(moves, key=key), sorted(changes, key=key)


def _links(f: dict) -> list:
    out = []
    for link in f.get("issuelinks") or []:
        ltype = link.get("type") or {}
        if link.get("outwardIssue"):
            out.append({"relation": ltype.get("outward"), "key": link["outwardIssue"].get("key")})
        elif link.get("inwardIssue"):
            out.append({"relation": ltype.get("inward"), "key": link["inwardIssue"].get("key")})
    return out


def _record(
    issue: dict,
    histories: list,
    ids: dict,
    cfg: dict,
    now,
    catalog=(set(), set(), False),
    history_known: bool = True,
    zone=None,
) -> dict:
    f = issue.get("fields") or {}
    status = f.get("status") or {}
    category = name_of(status.get("statusCategory"), "key")
    issue_type = name_of(f.get("issuetype"))
    custom = role_values(f, ids)
    moves, changes = _transitions(histories, ids, f.get("created"), zone)
    # When this ticket's history read failed, nothing derived from it is known:
    # a status-based approval, the first move into done, who recorded the approval.
    unknown = []

    approved_status_move = next(
        (m for m in moves if (m["to"] or "").strip().lower() in cfg["approved_statuses"]), None
    )
    approved_at = custom.get("approved_at")
    if custom.get("approver") and approved_at:
        approval_source = "fields"
    elif approved_status_move:
        approval_source = "status"
        approved_at = approved_status_move["at"]
    else:
        approval_source = None
    change_type = custom.get("change_type")
    preapproved = bool(change_type) and change_type.strip().lower() in cfg["preapproved_types"]

    resolution = name_of(f.get("resolution"))
    closed = category == "done"
    cancelled = closed and (resolution or "").strip().lower() in cfg["not_deployed"]
    done = (closed and not cancelled) or bool(custom.get("deployed_at"))
    # Deployment time, when there is no deployed-at field: the FIRST move into the
    # done category. A ticket deployed on day 1, approved on day 3 and reopened
    # and closed again on day 10 was still approved late; using the last move
    # would hide that. Both moves are recorded so a reviewer can see a reopen.
    done_moves = done_entries(moves, status, catalog) if closed else []
    first_done_at = done_moves[0]["at"] if done_moves else None
    last_done_at = done_moves[-1]["at"] if done_moves else None
    deployed_at = custom.get("deployed_at") or first_done_at or (
        f.get("resolutiondate") if closed and not cancelled else None
    )
    approval_change = next(
        (c for c in reversed(changes) if c["field"] in ("approver", "approved_at")), None
    )
    approved_ts, deployed_ts = parse_ts(approved_at), parse_ts(deployed_at)
    # A date-only value (an approval date field) has no time of day, so it is
    # compared with the deployment at day granularity: an earlier day is before,
    # a later day is after, and the same day is unknown rather than guessed.
    approval_granularity = "day" if is_date_only(approved_at) or is_date_only(deployed_at) else "minute"
    if not (approved_ts and deployed_ts):
        approved_before_deploy = None
    elif approval_granularity == "day":
        a_day, d_day = approved_ts.date(), deployed_ts.date()
        approved_before_deploy = None if a_day == d_day else a_day < d_day
    else:
        approved_before_deploy = approved_ts <= deployed_ts

    tests = (custom.get("test_results") or "").strip().lower()
    review = (custom.get("security_review") or "").strip().lower()
    approval_time_unparseable = bool(approval_source and approved_at and not approved_ts)
    is_exception = (issue_type or "").strip().lower() in cfg["exception_types"]
    is_connection = (issue_type or "").strip().lower() in cfg["connection_types"]
    watches = f.get("watches") if isinstance(f.get("watches"), dict) else {}
    comments = f.get("comment") if isinstance(f.get("comment"), dict) else {}

    # A status-based approval lives in the history; with the history unknown an
    # absent approval is unknown, not missing.
    approval_unknown = bool(not history_known and not approval_source and cfg["approved_statuses"])

    findings = []
    if approval_time_unparseable:
        findings.append("approval_time_unparseable")
    if done and not is_exception:
        if approval_unknown and not preapproved:
            unknown.append("approval_unknown")
        elif not approval_source and not preapproved:
            findings.append("deployed_without_approval")
        if approved_before_deploy is False:
            findings.append("approved_after_deploy")
        if tests in FAILED_TESTS:
            findings.append("deployed_with_failed_tests")
        elif "test_results" in ids and tests not in PASSED_TESTS:
            findings.append("deployed_without_passing_tests")
        if is_connection and "security_review" in ids and review not in DONE_REVIEWS:
            findings.append("connection_without_security_review")
        if is_connection and "risk" in ids and not custom.get("risk"):
            findings.append("connection_without_risk")
        # Jira makes the reporter a watcher, so one watcher alone is not a trail.
        if not comments.get("total") and (watches.get("watchCount") or 0) <= 1:
            findings.append("deployed_without_notification_trail")

    exception = None
    if is_exception:
        expiry = custom.get("exception_expiry")
        reviewed = custom.get("last_reviewed")
        reviewed_ts = parse_ts(reviewed)
        days_since_review = (now - reviewed_ts).days if reviewed_ts else None
        today = now.date().isoformat()
        exception = {
            "open": not closed,
            "approved": bool(approval_source),
            "expiry": expiry,
            "last_reviewed": reviewed,
            "days_since_review": days_since_review,
            # None when the last-reviewed field is turned off: the check cannot run.
            "review_overdue": None
            if "last_reviewed" not in ids
            else (not closed)
            and (days_since_review is None or days_since_review > cfg["review_days"]),
            "open_past_expiry": (not closed) and bool(expiry) and str(expiry)[:10] < today,
            "closed_at": f.get("resolutiondate") if closed else None,
        }
        if approval_unknown:
            unknown.append("approval_unknown")
        elif not approval_source:
            findings.append("exception_without_approval")
        if exception["review_overdue"]:
            findings.append("exception_review_overdue")
        if exception["open_past_expiry"]:
            findings.append("exception_open_past_expiry")

    return {
        "key": issue.get("key"),
        "summary": f.get("summary"),
        "project": name_of(f.get("project"), "key"),
        "issue_type": issue_type,
        "kind": "exception" if is_exception else "internal_connection" if is_connection else "change",
        "status": status.get("name"),
        "status_category": category,
        "resolution": resolution,
        "cancelled": cancelled,
        "created": f.get("created"),
        "resolved": f.get("resolutiondate"),
        "change_type": change_type,
        "preapproved": preapproved,
        "risk": custom.get("risk"),
        "approver": custom.get("approver"),
        "approved_at": approved_at,
        "approval_source": approval_source,
        "approval_recorded_by": approval_change["by"] if approval_change else None,
        "deployed": done and not is_exception,
        "deployed_at": deployed_at if not is_exception else None,
        "last_done_at": last_done_at if not is_exception else None,
        "reopened": len(done_moves) > 1 if history_known else None,
        "status_history_known": history_known,
        "approved_before_deploy": approved_before_deploy,
        "approval_order_granularity": approval_granularity if approved_ts and deployed_ts else None,
        "test_results": custom.get("test_results"),
        "security_review": custom.get("security_review"),
        "watch_count": watches.get("watchCount"),
        "comment_count": comments.get("total"),
        "labels": f.get("labels") or [],
        "components": [c.get("name") for c in f.get("components") or [] if c.get("name")],
        "linked_issues": _links(f),
        "exception": exception,
        "status_transitions": moves,
        "field_changes": changes,
        "findings": findings,
        "unknown": unknown,
    }


def _summarize(records: list, complete: bool = True) -> dict:
    changes = [r for r in records if r["kind"] != "exception"]
    deployed = [r for r in changes if r["deployed"]]
    exceptions = [r for r in records if r["kind"] == "exception"]
    open_ex = [r for r in exceptions if r["exception"]["open"]]
    all_findings = [f for r in records for f in r["findings"]]
    summary = {
        "total": len(records),
        "by_kind": counts(r["kind"] for r in records),
        "by_change_type": counts(r["change_type"] for r in changes),
        "by_risk": counts(r["risk"] for r in changes),
        "by_status": counts(r["status"] for r in records),
        "changes_deployed": len(deployed),
        "changes_deployed_with_approval": sum(1 for r in deployed if r["approval_source"]),
        "changes_approved_before_deploy": sum(1 for r in deployed if r["approved_before_deploy"]),
        "changes_approval_order_unknown": sum(
            1 for r in deployed if r["approval_source"] and r["approved_before_deploy"] is None
        ),
        # Deployed changes whose approval could not be read (history read failed):
        # they are in changes_deployed but in neither the approved nor the
        # pre-approved count, so this names the difference.
        "changes_approval_unknown": sum(1 for r in deployed if "approval_unknown" in r["unknown"]),
        "changes_deployed_preapproved": sum(
            1 for r in deployed if not r["approval_source"] and r["preapproved"]
        ),
        "changes_open": sum(1 for r in changes if not r["deployed"] and not r["cancelled"]),
        "changes_cancelled": sum(1 for r in changes if r["cancelled"]),
        "exceptions_total": len(exceptions),
        "exceptions_open": len(open_ex),
        "exceptions_closed": len(exceptions) - len(open_ex),
        "findings": counts(all_findings),
        "tickets_with_findings": sum(1 for r in records if r["findings"]),
        "unknown": counts(u for r in records for u in r["unknown"]),
        "tickets_with_unknown_checks": sum(1 for r in records if r["unknown"]),
    }
    # When the ticket search did not finish, every count would read as "none found".
    return summary if complete else null_summary(summary)


def _config():
    fields, err = json_env("JIRA_CHANGE_FIELDS", {})
    if err:
        return None, err
    unknown = sorted(set(fields) - set(DEFAULT_FIELDS))
    if unknown:
        return None, f"JIRA_CHANGE_FIELDS has unknown keys: {', '.join(unknown)}"
    review_days = int_env("JIRA_EXCEPTION_REVIEW_DAYS", 365)
    max_items = int_env("JIRA_CHANGE_MAX_ITEMS", 2000)
    if review_days is None or max_items is None:
        return None, "JIRA_EXCEPTION_REVIEW_DAYS and JIRA_CHANGE_MAX_ITEMS must be positive integers"
    merged = {**DEFAULT_FIELDS, **fields}
    invalid = invalid_roles(merged)
    if invalid:
        return None, (
            f"JIRA_CHANGE_FIELDS values must be a field name, a customfield_ id or a list of "
            f"ids; not so for: {', '.join(invalid)}"
        )
    disabled = disabled_roles(merged)
    approved_statuses = _lower_set(list_env("JIRA_CHANGE_APPROVED_STATUSES"))
    if not approved_statuses and disabled & {"approver", "approved_at"}:
        return None, (
            "no way to detect an approval: JIRA_CHANGE_APPROVED_STATUSES is empty and the "
            "approver or approved_at field is turned off in JIRA_CHANGE_FIELDS; every change "
            "and exception would be reported as unapproved"
        )
    # Unset means the Standard default; set to an empty value means nothing is pre-approved.
    preapproved_types = _lower_set(
        list_env("JIRA_CHANGE_PREAPPROVED_TYPES") if "JIRA_CHANGE_PREAPPROVED_TYPES" in os.environ else ["Standard"]
    )
    if "change_type" in disabled and preapproved_types:
        return None, (
            "JIRA_CHANGE_PREAPPROVED_TYPES is set but the change_type field is turned off in "
            "JIRA_CHANGE_FIELDS; every pre-approved change would be reported as unapproved. "
            "Set JIRA_CHANGE_PREAPPROVED_TYPES to an empty value if no change type is pre-approved"
        )
    return {
        "fields": merged,
        "disabled_fields": sorted(disabled),
        "approved_statuses": approved_statuses,
        "preapproved_types": preapproved_types,
        "exception_types": _lower_set(
            list_env("JIRA_EXCEPTION_ISSUE_TYPES") or ["Configuration Exception"]
        ),
        "connection_types": _lower_set(
            list_env("JIRA_CONNECTION_ISSUE_TYPES") or ["Internal Connection"]
        ),
        "not_deployed": _lower_set(list_env("JIRA_NOT_DEPLOYED_RESOLUTIONS") or DEFAULT_NOT_DEPLOYED),
        "review_days": review_days,
        "max_items": max_items,
    }, None


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
    jql = os.environ.get("JIRA_CHANGE_JQL", "").strip()
    if not jql:
        report_failure(
            "JIRA_CHANGE_JQL is not set; it selects the change, internal connection and "
            "exception tickets, e.g. 'project = CCB'",
            "bad_config",
        )
        return 1
    cfg, err = _config()
    if err:
        report_failure(err, "bad_config")
        return 1

    client = JiraClient(base_url, email, api_token)
    now = utc_now()
    collector = None
    ids: dict = {}
    problems: dict = {}
    candidates: dict = {}
    records: list = []
    truncated = False
    history_complete = True
    search_complete = False
    catalog = (set(), set(), False)
    try:
        collector = collector_info(client)
        ids, problems, candidates = resolve_fields(client, cfg["fields"])
        catalog = status_catalog(client)
        zone = zone_of((collector or {}).get("time_zone"))
        raw, truncated, search_complete = client.search_issues(
            jql, BASE_FIELDS + all_field_ids(ids), cfg["max_items"]
        )
        histories, history_complete, unknown_ids = client.bulk_changelogs(
            [str(i.get("id")) for i in raw if i.get("id")],
            ["status"] + all_field_ids(ids),
        )
        records = [
            _record(
                i, histories.get(str(i.get("id")), []), ids, cfg, now, catalog,
                history_known=str(i.get("id")) not in unknown_ids, zone=zone,
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
            "field_names": cfg["fields"],
            "fields_resolved": ids,
            "field_problems": problems,
            "field_candidates": candidates,
            "checks_disabled": _checks_disabled(cfg["disabled_fields"]),
            "not_deployed_resolutions": sorted(cfg["not_deployed"]),
            "approved_statuses": sorted(cfg["approved_statuses"]),
            "preapproved_change_types": sorted(cfg["preapproved_types"]),
            "exception_review_days": cfg["review_days"],
            "max_items": cfg["max_items"],
            "items_collected": len(records),
            "items_truncated": truncated,
            "search_complete": search_complete,
            "status_history_complete": history_complete,
            "done_statuses_known": catalog[2],
            "partial_failure": bool(client.api_failures),
            "api_failures": client.api_failures,
        },
        "collector": collector,
        # A capped search is also unfinished: its totals would read as the population.
        "summary": _summarize(records, search_complete and not truncated),
        "tickets": records,
    }
    incomplete = ""
    if truncated:
        incomplete = f"tickets truncated at JIRA_CHANGE_MAX_ITEMS={cfg['max_items']}"
    elif not history_complete:
        incomplete = "status history incomplete for some tickets"
    field_reason = field_problem_reason(problems, "JIRA_CHANGE_FIELDS")
    if field_reason:
        logger.warning("%s", field_reason)
        incomplete = f"{incomplete}; {field_reason}" if incomplete else field_reason
    return write_and_finish(logger, client, evidence, OUTPUT_FILE, incomplete)


if __name__ == "__main__":
    sys.exit(main())
