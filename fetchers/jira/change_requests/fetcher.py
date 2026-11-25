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
    fetch_issues,
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
    role_state,
    role_values,
    status_catalog,
    ts_sort_key,
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
# Roles with no default name: off unless JIRA_CHANGE_FIELDS names them.
# notification_due and notification_sent are read from the linked notification
# tickets, not from the change.
OPTIONAL_FIELDS = ("emergency", "notification_due", "notification_sent")
NOTIFICATION_ROLES = ("notification_due", "notification_sent")
NOTIFICATION_FIELDS = ["summary", "issuetype", "status", "created", "resolutiondate", "resolution", "labels"]
TRUE_VALUES, FALSE_VALUES = {"true", "1", "yes"}, {"false", "0", "no", ""}
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
    key = lambda m: ts_sort_key(m["at"])  # noqa: E731
    return sorted(moves, key=key), sorted(changes, key=key)


def _links(f: dict) -> list:
    out = []
    for link in f.get("issuelinks") or []:
        ltype = link.get("type") or {}
        side = "outward" if link.get("outwardIssue") else "inward" if link.get("inwardIssue") else None
        if side:
            other = link[side + "Issue"]
            fields = other.get("fields") if isinstance(other.get("fields"), dict) else {}
            out.append(
                {
                    "relation": ltype.get(side),
                    "key": other.get("key"),
                    # None when Jira did not say: the link is then not known to be a notification or not.
                    "issue_type": name_of(fields.get("issuetype")),
                }
            )
    return out


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


def _is_after(a, b):
    """True when a is after b, None when either does not parse. Against a date
    without a time only the calendar days are compared, so the due day itself is on time."""
    ta, tb = parse_ts(a), parse_ts(b)
    if not ta or not tb:
        return None
    if is_date_only(a) or is_date_only(b):
        return a[:10] > b[:10]
    return ta > tb


def _notification(issue: dict, histories: list, history_known: bool, ids: dict, cfg: dict, now, catalog, zone) -> dict:
    """One linked notification ticket. It counts as sent when it is in a done status
    and was not cancelled; the sent time is the notification_sent field when that
    holds a value, else its first move into a done status, else its resolution date."""
    f = issue.get("fields") or {}
    status = f.get("status") or {}
    closed = name_of(status.get("statusCategory"), "key") == "done"
    cancelled = closed and (name_of(f.get("resolution")) or "").strip().lower() in cfg["not_deployed"]
    sent = closed and not cancelled
    custom = role_values(f, {r: ids[r] for r in NOTIFICATION_ROLES if r in ids})
    due = custom.get("notification_due")
    sent_field = custom.get("notification_sent")
    sent_at, source = None, None
    if sent:
        moves, _ = _transitions(histories, {}, f.get("created"), zone)
        done_moves = [m for m in done_entries(moves, status, catalog) if parse_ts(m["at"])] if catalog[2] else []
        if sent_field:
            sent_at, source = sent_field, "field"
        elif done_moves:
            sent_at, source = done_moves[0]["at"], "status_history"
        elif f.get("resolutiondate"):
            sent_at, source = f.get("resolutiondate"), "resolutiondate"
    due_on = "notification_due" in ids
    return {
        "key": issue.get("key"),
        "read": True,
        "summary": f.get("summary"),
        "issue_type": name_of(f.get("issuetype")),
        "status": status.get("name"),
        "created": f.get("created"),
        "labels": f.get("labels") or [],
        "cancelled": cancelled,
        "sent": sent,
        "sent_at": sent_at,
        "sent_at_source": source,
        # The notification_sent field as written, also when the ticket is not done yet.
        "sent_field_value": sent_field if "notification_sent" in ids else None,
        "status_history_known": history_known,
        "due": due if due_on else None,
        # None when the notification_due field is off or this ticket has no due value.
        "overdue": (_is_past(due, now, zone) if not sent and not cancelled else False) if due_on and due else None,
        "sent_late": _is_after(sent_at, due) if due_on and due and sent and sent_at else None,
    }


def _record(
    issue: dict,
    histories: list,
    ids: dict,
    cfg: dict,
    now,
    catalog=(set(), set(), False),
    history_known: bool = True,
    zone=None,
    notes=None,
) -> dict:
    """`notes` maps the key of every linked notification ticket that was read to its
    record (see _notification); it is None when notification tickets are not configured."""
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
    # With JIRA_CHANGE_DEPLOYED_STATUSES set, a change is deployed when it entered
    # (or is in) one of those statuses, not when it reached the done category: a
    # ticket closed without passing through them was not deployed. When this
    # ticket's history could not be read and it is not in such a status now,
    # whether it was deployed is unknown, never "not deployed".
    deploy_statuses = cfg["deployed_statuses"]
    deploy_moves = [m for m in moves if (m["to"] or "").strip().lower() in deploy_statuses]
    deployment_unknown = False
    if deploy_statuses:
        by_status = bool(deploy_moves) or (status.get("name") or "").strip().lower() in deploy_statuses
        done = by_status or bool(custom.get("deployed_at"))
        deployment_unknown = not done and not history_known
    else:
        done = (closed and not cancelled) or bool(custom.get("deployed_at"))
    # Deployment time, when there is no deployed-at field: the FIRST move into the
    # done category. A ticket deployed on day 1, approved on day 3 and reopened
    # and closed again on day 10 was still approved late; using the last move
    # would hide that. Both moves are recorded so a reviewer can see a reopen.
    done_moves = done_entries(moves, status, catalog) if closed else []
    first_done_at = done_moves[0]["at"] if done_moves else None
    last_done_at = done_moves[-1]["at"] if done_moves else None
    if deploy_statuses:
        deployed_at = custom.get("deployed_at") or (deploy_moves[0]["at"] if deploy_moves else None)
    else:
        deployed_at = custom.get("deployed_at") or first_done_at or (
            f.get("resolutiondate") if closed and not cancelled else None
        )
    # None when the emergency field is not configured or could not be resolved.
    emergency = None
    if cfg["emergency_values"] and "emergency" in ids:
        emergency = (custom.get("emergency") or "").strip().lower() in cfg["emergency_values"]
    approval_change = next(
        (c for c in reversed(changes) if c["field"] in ("approver", "approved_at")), None
    )
    # Who approved: the approver field, or whoever moved the ticket into the approved status.
    approved_by = None
    if approval_source == "fields":
        approved_by = custom.get("approver")
    elif approval_source == "status":
        approved_by = approved_status_move["by"]
    # With JIRA_CHANGE_EMERGENCY_APPROVAL_EXEMPT on, an emergency change may be deployed
    # before it is approved: the approval findings are recorded under `exempted`, not `findings`.
    approval_exempt = (emergency is True) if cfg["emergency_exempt"] else None
    links = _links(f)
    notifications = notification_required = None
    untyped_links = False
    if cfg["notification_types"]:
        linked = [k for k in links if (k["issue_type"] or "").strip().lower() in cfg["notification_types"]]
        untyped_links = any(k["issue_type"] is None for k in links)
        notifications = [
            {**(notes or {}).get(k["key"], {"key": k["key"], "read": False}), "relation": k["relation"]} for k in linked
        ]
        if cfg["notification_required_types"]:
            notification_required = bool(change_type) and change_type.strip().lower() in cfg["notification_required_types"]
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
    exempted = []
    if approval_time_unparseable:
        findings.append("approval_time_unparseable")
    if not is_exception:
        if deployment_unknown:
            unknown.append("deployment_unknown")
        elif deploy_statuses and done and not deployed_at:
            # In a deployed status with no move into it on record: deployed, but when is not known.
            unknown.append("deployment_time_unknown")
    if done and not is_exception:
        if approval_unknown and not preapproved:
            unknown.append("approval_unknown")
        elif not approval_source and not preapproved:
            (exempted if approval_exempt else findings).append("deployed_without_approval")
        if approved_before_deploy is False:
            (exempted if approval_exempt else findings).append("approved_after_deploy")
        if tests in FAILED_TESTS:
            findings.append("deployed_with_failed_tests")
        elif "test_results" in ids and tests not in PASSED_TESTS:
            findings.append("deployed_without_passing_tests")
        if is_connection and "security_review" in ids and review not in DONE_REVIEWS:
            findings.append("connection_without_security_review")
        if is_connection and "risk" in ids and not custom.get("risk"):
            findings.append("connection_without_risk")
        if notifications is None:
            # Jira makes the reporter a watcher, so one watcher alone is not a trail.
            if not comments.get("total") and (watches.get("watchCount") or 0) <= 1:
                findings.append("deployed_without_notification_trail")
        elif notification_required and not notifications:
            # A link whose issue type Jira did not give may be the notification: unknown, not missing.
            if untyped_links:
                unknown.append("notification_link_type_unknown")
            else:
                findings.append("notification_missing")
    if notifications and not is_exception:
        if any(not n["read"] for n in notifications):
            unknown.append("notifications_not_read")
        if any(n.get("overdue") for n in notifications):
            findings.append("notification_overdue")
        if any(n.get("sent_late") for n in notifications):
            findings.append("notification_sent_late")

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
        "approved_by": approved_by,
        # None unless JIRA_CHANGE_EMERGENCY_APPROVAL_EXEMPT is on.
        "approval_exempt": approval_exempt,
        "approval_recorded_by": approval_change["by"] if approval_change else None,
        "emergency": emergency,
        "emergency_value": custom.get("emergency") if "emergency" in ids else None,
        # None when the ticket's history could not be read and its status does not say (see deployment_unknown).
        "deployed": None if deployment_unknown and not is_exception else done and not is_exception,
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
        "linked_issues": links,
        # None unless JIRA_CHANGE_NOTIFICATION_ISSUE_TYPES is set; exceptions take no notification checks.
        "notification_required": notification_required if not is_exception else None,
        "notifications": notifications if not is_exception else None,
        "exception": exception,
        "status_transitions": moves,
        "field_changes": changes,
        "findings": findings,
        # Findings not raised because the change is an exempt emergency change.
        "exempted": exempted,
        "unknown": unknown,
    }


def _emergency_summary(changes: list) -> dict:
    """The same approval counts as the main summary, for emergency changes only."""
    emergency = [r for r in changes if r["emergency"]]
    deployed = [r for r in emergency if r["deployed"]]
    return {
        "total": len(emergency),
        "deployed": len(deployed),
        "deployed_with_approval": sum(1 for r in deployed if r["approval_source"]),
        "approved_before_deploy": sum(1 for r in deployed if r["approved_before_deploy"]),
        "approved_after_deploy": sum(1 for r in deployed if r["approved_before_deploy"] is False),
        # Counted whether it was raised as a finding or exempted.
        "deployed_without_approval": sum(
            1 for r in deployed if "deployed_without_approval" in r["findings"] + r["exempted"]
        ),
        "open": sum(1 for r in emergency if r["deployed"] is False and r["status_category"] != "done"),
        "findings": counts(f for r in emergency for f in r["findings"]),
        "exempted": counts(f for r in emergency for f in r["exempted"]),
        "keys": [r["key"] for r in emergency],
    }


def _notification_summary(changes: list, required_on: bool) -> dict:
    """Counts over the linked notification tickets; a ticket linked to two changes is counted once."""
    notes = list({n["key"]: n for r in changes for n in r["notifications"] or []}.values())
    read = [n for n in notes if n["read"]]
    requiring = [r for r in changes if r["notification_required"]]
    return {
        # Null unless JIRA_CHANGE_NOTIFICATION_REQUIRED_TYPES is set.
        "changes_requiring": len(requiring) if required_on else None,
        "changes_requiring_with_notification": sum(1 for r in requiring if r["notifications"]) if required_on else None,
        "changes_deployed_without_required_notification": sum(
            1 for r in requiring if "notification_missing" in r["findings"]
        )
        if required_on
        else None,
        "tickets": len(notes),
        "tickets_not_read": len(notes) - len(read),
        "tickets_sent": sum(1 for n in read if n["sent"]),
        "tickets_open": sum(1 for n in read if not n["sent"] and not n["cancelled"]),
        "tickets_cancelled": sum(1 for n in read if n["cancelled"]),
        "tickets_overdue": sum(1 for n in read if n["overdue"]),
        "tickets_sent_late": sum(1 for n in read if n["sent_late"]),
    }


def _summarize(
    records: list,
    complete: bool = True,
    emergency_on: bool = False,
    deploy_by_status: bool = False,
    notifications_on: bool = False,
    notification_required_on: bool = False,
) -> dict:
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
        # A done ticket is never open; without deployed statuses every done ticket is
        # deployed or cancelled, so the extra condition changes nothing there.
        "changes_open": sum(
            1
            for r in changes
            if r["deployed"] is False and not r["cancelled"] and r["status_category"] != "done"
        ),
        # Closed without entering a deployed status and not cancelled. Null unless
        # JIRA_CHANGE_DEPLOYED_STATUSES is set (otherwise such a ticket counts as deployed).
        "changes_closed_without_deployment": sum(
            1
            for r in changes
            if r["deployed"] is False and not r["cancelled"] and r["status_category"] == "done"
        )
        if deploy_by_status
        else None,
        "changes_deployment_unknown": sum(1 for r in changes if r["deployed"] is None),
        # Null unless the emergency field and JIRA_CHANGE_EMERGENCY_VALUES are set and the field resolved.
        "emergency": _emergency_summary(changes) if emergency_on else None,
        # Null unless JIRA_CHANGE_NOTIFICATION_ISSUE_TYPES is set.
        "notifications": _notification_summary(changes, notification_required_on) if notifications_on else None,
        "exempted": counts(f for r in records for f in r["exempted"]),
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
    unknown = sorted(set(fields) - set(DEFAULT_FIELDS) - set(OPTIONAL_FIELDS))
    if unknown:
        return None, f"JIRA_CHANGE_FIELDS has unknown keys: {', '.join(unknown)}"
    review_days = int_env("JIRA_EXCEPTION_REVIEW_DAYS", 365)
    max_items = int_env("JIRA_CHANGE_MAX_ITEMS", 2000)
    if review_days is None or max_items is None:
        return None, "JIRA_EXCEPTION_REVIEW_DAYS and JIRA_CHANGE_MAX_ITEMS must be positive integers"
    merged = {**DEFAULT_FIELDS, **fields}
    # An optional role left empty is simply off: it is not a field problem.
    for role in OPTIONAL_FIELDS:
        if role in merged and role_state(merged[role]) == "disabled":
            del merged[role]
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
    emergency_values = _lower_set(list_env("JIRA_CHANGE_EMERGENCY_VALUES"))
    if ("emergency" in merged) != bool(emergency_values):
        return None, (
            "the emergency field in JIRA_CHANGE_FIELDS and JIRA_CHANGE_EMERGENCY_VALUES must be set "
            "together: one names the field, the other the values that mean an emergency change"
        )
    exempt_raw = os.environ.get("JIRA_CHANGE_EMERGENCY_APPROVAL_EXEMPT", "").strip().lower()
    if exempt_raw not in TRUE_VALUES | FALSE_VALUES:
        return None, "JIRA_CHANGE_EMERGENCY_APPROVAL_EXEMPT must be true or false"
    emergency_exempt = exempt_raw in TRUE_VALUES
    if emergency_exempt and not emergency_values:
        return None, (
            "JIRA_CHANGE_EMERGENCY_APPROVAL_EXEMPT is on but no emergency field is set in JIRA_CHANGE_FIELDS; "
            "there is no way to tell which changes are emergency changes"
        )
    notification_types = _lower_set(list_env("JIRA_CHANGE_NOTIFICATION_ISSUE_TYPES"))
    notification_required_types = _lower_set(list_env("JIRA_CHANGE_NOTIFICATION_REQUIRED_TYPES"))
    if not notification_types:
        needs = [r for r in NOTIFICATION_ROLES if r in merged]
        if notification_required_types:
            needs.append("JIRA_CHANGE_NOTIFICATION_REQUIRED_TYPES")
        if needs:
            return None, (
                f"{', '.join(needs)} set without JIRA_CHANGE_NOTIFICATION_ISSUE_TYPES; "
                "that setting names the issue types of the linked notification tickets"
            )
    if notification_required_types and "change_type" in disabled:
        return None, (
            "JIRA_CHANGE_NOTIFICATION_REQUIRED_TYPES is set but the change_type field is turned off in "
            "JIRA_CHANGE_FIELDS; no change could be matched to it"
        )
    return {
        "fields": merged,
        "disabled_fields": sorted(disabled),
        "emergency_exempt": emergency_exempt,
        "notification_types": notification_types,
        "notification_required_types": notification_required_types,
        "deployed_statuses": _lower_set(list_env("JIRA_CHANGE_DEPLOYED_STATUSES")),
        "emergency_values": emergency_values,
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
    # Configured deployed statuses that are not statuses on this site; None until checked.
    deploy_unmatched = None
    notes = None
    notes_complete = True
    try:
        collector = collector_info(client)
        ids, problems, candidates = resolve_fields(client, cfg["fields"])
        catalog = status_catalog(client)
        if cfg["deployed_statuses"]:
            site = client.request("GET", "/rest/api/3/status", "GET /rest/api/3/status")
            if isinstance(site, list):
                names = {st["name"].strip().lower() for st in site if isinstance(st, dict) and isinstance(st.get("name"), str)}
                deploy_unmatched = sorted(cfg["deployed_statuses"] - names)
        zone = zone_of((collector or {}).get("time_zone"))
        raw, truncated, search_complete = client.search_issues(
            jql, BASE_FIELDS + all_field_ids(ids), cfg["max_items"]
        )
        histories, history_complete, unknown_ids = client.bulk_changelogs(
            [str(i.get("id")) for i in raw if i.get("id")],
            ["status"] + all_field_ids(ids),
        )
        if cfg["notification_types"]:
            # The search gives each linked issue's type; the linked notification tickets
            # are then read once for their status, dates and status history.
            keys = {
                k["key"]
                for i in raw
                for k in _links(i.get("fields") or {})
                if (k["issue_type"] or "").strip().lower() in cfg["notification_types"]
            }
            note_fields = NOTIFICATION_FIELDS + all_field_ids({r: ids[r] for r in NOTIFICATION_ROLES if r in ids})
            note_issues, note_missing, notes_complete = fetch_issues(client, keys, note_fields)
            note_hist, note_hist_complete, note_unknown = client.bulk_changelogs(
                [str(n.get("id")) for n in note_issues if n.get("id")], ["status"]
            )
            notes_complete = notes_complete and note_hist_complete and not note_missing
            notes = {
                n.get("key"): _notification(
                    n, note_hist.get(str(n.get("id")), []), str(n.get("id")) not in note_unknown,
                    ids, cfg, now, catalog, zone,
                )
                for n in note_issues
            }
        records = [
            _record(
                i, histories.get(str(i.get("id")), []), ids, cfg, now, catalog,
                history_known=str(i.get("id")) not in unknown_ids, zone=zone, notes=notes,
            )
            for i in raw
        ]
    except Abort:
        pass
    except Exception as e:  # unexpected response shape: keep what was collected and say why
        client.fail("collection", type(e).__name__, str(e)[:200], "internal_error")
        search_complete = False  # the collection did not finish, so no count is trusted

    emergency_seen = {(r["emergency_value"] or "").strip().lower() for r in records}
    # With notification tickets configured they replace the comments-and-watchers check, and
    # the notification findings whose setting is missing are listed as off. Without them the
    # notification findings are an optional feature that was not asked for, and are not listed.
    checks_off = set(_checks_disabled(cfg["disabled_fields"]))
    if cfg["notification_types"]:
        checks_off.add("deployed_without_notification_trail")
        if not cfg["notification_required_types"]:
            checks_off.add("notification_missing")
        if "notification_due" not in ids:
            checks_off.update(["notification_overdue", "notification_sent_late"])
    change_types_seen = {(r["change_type"] or "").strip().lower() for r in records}
    evidence = {
        "metadata": {
            "collected_at": now.isoformat(),
            "base_url": base_url,
            "jql": jql,
            "field_names": cfg["fields"],
            "fields_resolved": ids,
            "field_problems": problems,
            "field_candidates": candidates,
            "checks_disabled": sorted(checks_off),
            "not_deployed_resolutions": sorted(cfg["not_deployed"]),
            "approved_statuses": sorted(cfg["approved_statuses"]),
            "deployed_statuses": sorted(cfg["deployed_statuses"]) or None,
            "deployed_statuses_not_on_site": deploy_unmatched,
            "emergency_values": sorted(cfg["emergency_values"]) or None,
            # Configured emergency values held by no collected ticket: there may be no
            # emergency change, or the value is not how the field spells it.
            "emergency_values_unmatched": sorted(cfg["emergency_values"] - {v for v in emergency_seen if v})
            if cfg["emergency_values"]
            else None,
            "emergency_approval_exempt": cfg["emergency_exempt"],
            "notification_issue_types": sorted(cfg["notification_types"]) or None,
            "notification_required_change_types": sorted(cfg["notification_required_types"]) or None,
            # Configured change types held by no collected ticket: none may exist, or the
            # value is not how the field spells it and those changes were not checked.
            "notification_required_change_types_unmatched": sorted(cfg["notification_required_types"] - change_types_seen)
            if cfg["notification_required_types"]
            else None,
            "notification_tickets_complete": notes_complete if cfg["notification_types"] else None,
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
        "summary": _summarize(
            records,
            search_complete and not truncated,
            bool(cfg["emergency_values"]) and "emergency" in ids,
            bool(cfg["deployed_statuses"]),
            bool(cfg["notification_types"]),
            bool(cfg["notification_required_types"]),
        ),
        "tickets": records,
    }
    incomplete = ""
    if truncated:
        incomplete = f"tickets truncated at JIRA_CHANGE_MAX_ITEMS={cfg['max_items']}"
    elif not history_complete:
        incomplete = "status history incomplete for some tickets"
    elif not notes_complete:
        incomplete = "some linked notification tickets could not be read"
    if deploy_unmatched:
        # A mistyped status would report every change as not deployed, with no finding.
        reason = (
            f"JIRA_CHANGE_DEPLOYED_STATUSES names no status on this site: {', '.join(deploy_unmatched)}; "
            "deployments into it cannot be seen"
        )
        logger.warning("%s", reason)
        incomplete = f"{incomplete}; {reason}" if incomplete else reason
    field_reason = field_problem_reason(problems, "JIRA_CHANGE_FIELDS")
    if field_reason:
        logger.warning("%s", field_reason)
        incomplete = f"{incomplete}; {field_reason}" if incomplete else field_reason
    return write_and_finish(logger, client, evidence, OUTPUT_FILE, incomplete)


if __name__ == "__main__":
    sys.exit(main())
