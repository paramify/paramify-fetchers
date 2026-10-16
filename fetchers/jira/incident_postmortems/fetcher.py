#!/usr/bin/env python3
"""Jira incidents: severity, category, reporting times, response phases, post-mortems and their action items."""

import logging
import math
import os
import re
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
    fetch_issues,
    field_value,
    int_env,
    json_env,
    list_env,
    name_of,
    number_stats,
    parse_ts,
    report_failure,
    resolve_fields,
    utc_now,
    write_and_finish,
)

logger = logging.getLogger("jira_incident_postmortems")

OUTPUT_FILE = "jira_incident_postmortems.json"

DEFAULT_FIELDS = {
    "severity": "Severity",
    "category": "Incident Category",
    "detected_at": "Detected At",
    "reported_at": "Reported At",
    "phase": "Incident Phase",
}
INCIDENT_FIELDS = [
    "summary",
    "project",
    "issuetype",
    "status",
    "priority",
    "assignee",
    "created",
    "resolutiondate",
    "resolution",
    "issuelinks",
]
# Resolved incidents closed with these resolutions need no post-mortem.
DEFAULT_NO_REVIEW = ["Won't Do", "Cancelled", "Canceled", "Duplicate", "False Positive", "Not an Incident"]
POSTMORTEM_FIELDS = ["summary", "issuetype", "status", "created", "resolutiondate", "subtasks", "assignee"]
ACTION_FIELDS = ["summary", "status", "assignee", "duedate", "created", "resolutiondate", "parent"]


def _minutes_between(start, end):
    a, b = parse_ts(start), parse_ts(end)
    if not a or not b:
        return None
    return round((b - a).total_seconds() / 60, 1)


def _category_target(category, targets: dict):
    """Target minutes for a category: exact name, else the longest whole-word prefix (case-insensitive)."""
    if not category:
        return None
    lowered = {k.strip().lower(): v for k, v in targets.items()}
    cat = category.strip().lower()
    if cat in lowered:
        return lowered[cat]
    matches = [k for k in lowered if re.match(re.escape(k) + r"(?![0-9a-z])", cat)]
    return lowered[max(matches, key=len)] if matches else None


def _history(histories: list, phase_id) -> tuple:
    moves, phases = [], []
    for h in histories:
        for item in h.get("items") or []:
            fid = item.get("fieldId") or item.get("field")
            entry = {
                "at": h.get("created"),
                "by": name_of(h.get("author"), "displayName"),
                "from": item.get("fromString"),
                "to": item.get("toString"),
            }
            if fid == "status":
                moves.append(entry)
            elif phase_id and fid == phase_id:
                phases.append(entry)
    key = lambda m: str(m["at"] or "")  # noqa: E731
    return sorted(moves, key=key), sorted(phases, key=key)


def _linked_keys(f: dict, types: set = None) -> list:
    """Keys of linked issues, optionally only those whose issue type is in `types` (lowercased)."""
    keys = []
    for link in f.get("issuelinks") or []:
        if not isinstance(link, dict):
            continue
        other = link.get("outwardIssue") or link.get("inwardIssue") or {}
        if not isinstance(other, dict) or not other.get("key"):
            continue
        if types is not None:
            itype = name_of((other.get("fields") or {}).get("issuetype"))
            if (itype or "").strip().lower() not in types:
                continue
        keys.append(other["key"])
    return keys


def _action_record(issue: dict, now) -> dict:
    f = issue.get("fields") or {}
    status = f.get("status") or {}
    is_open = name_of(status.get("statusCategory"), "key") != "done"
    due = f.get("duedate")
    return {
        "key": issue.get("key"),
        "summary": f.get("summary"),
        "postmortem": name_of(f.get("parent"), "key"),
        "status": status.get("name"),
        "is_open": is_open,
        "assignee": name_of(f.get("assignee"), "displayName"),
        "due_date": due,
        "overdue": bool(is_open and due and due < now.date().isoformat()),
        "resolved": f.get("resolutiondate"),
    }


def _incident_record(issue, histories, ids, cfg, postmortems: dict, actions: dict, hidden: set) -> dict:
    f = issue.get("fields") or {}
    status = f.get("status") or {}
    resolved = name_of(status.get("statusCategory"), "key") == "done"
    resolution = name_of(f.get("resolution"))
    no_review = resolved and (resolution or "").strip().lower() in cfg["no_review"]
    custom = {role: field_value(f.get(fid)) for role, fid in ids.items()}
    moves, phase_changes = _history(histories, ids.get("phase"))

    detected = custom.get("detected_at")
    reported = custom.get("reported_at") or f.get("created")
    reported_source = "field" if custom.get("reported_at") else "created"
    minutes = _minutes_between(detected, reported)
    category = custom.get("category")
    target = _category_target(category, cfg["category_targets"])

    phases_seen = []
    first = [phase_changes[0]["from"]] if phase_changes else []
    for p in first + [c["to"] for c in phase_changes] + [custom.get("phase")]:
        if p and p not in phases_seen:
            phases_seen.append(p)

    linked_pm = _linked_keys(f, cfg["postmortem_types"])
    pm_keys = [k for k in linked_pm if k in postmortems]
    pm_hidden = [k for k in linked_pm if k in hidden]
    pm_records = [postmortems[k] for k in pm_keys]
    action_items = [a for k in pm_keys for a in actions.get(k, [])]
    severity = custom.get("severity")
    required = resolved and not no_review and (
        not cfg["required_severities"] or (severity or "").strip().lower() in cfg["required_severities"]
    )

    findings = []
    if not detected:
        findings.append("missing_detected_time")
    elif minutes is None:
        findings.append("detected_or_reported_time_unparseable")
    elif minutes < 0:
        findings.append("reported_before_detected")
    elif minutes > cfg["report_minutes"]:
        findings.append("reported_late")
    if target is not None and minutes is not None and minutes > target:
        findings.append("category_notification_target_missed")
    if not severity:
        findings.append("missing_severity")
    if not category:
        findings.append("missing_category")
    elif cfg["category_targets"] and target is None:
        findings.append("category_without_target")
    missing_phases = [p for p in cfg["required_phases"] if p.lower() not in {x.lower() for x in phases_seen}]
    if resolved and not no_review and missing_phases:
        findings.append("phases_missing")
    if required and not pm_keys:
        findings.append("postmortem_not_visible" if pm_hidden else "resolved_without_postmortem")
    if pm_keys and not action_items:
        findings.append("postmortem_without_action_items")
    if any(a["is_open"] and not a["assignee"] for a in action_items):
        findings.append("unassigned_action_items")
    if any(a["overdue"] for a in action_items):
        findings.append("overdue_action_items")

    return {
        "key": issue.get("key"),
        "summary": f.get("summary"),
        "project": name_of(f.get("project"), "key"),
        "issue_type": name_of(f.get("issuetype")),
        "status": status.get("name"),
        "resolved": resolved,
        "resolution": resolution,
        "resolved_at": f.get("resolutiondate"),
        "created": f.get("created"),
        "severity": severity,
        "category": category,
        "assignee": name_of(f.get("assignee"), "displayName"),
        "detected_at": detected,
        "reported_at": reported,
        "reported_at_source": reported_source,
        "minutes_to_report": minutes,
        "report_window_minutes": cfg["report_minutes"],
        "category_target_minutes": target,
        "current_phase": custom.get("phase"),
        "phases_seen": phases_seen,
        "phases_missing": missing_phases if resolved else [],
        "postmortem_required": required,
        "postmortems": pm_records,
        "action_items": action_items,
        "status_transitions": moves,
        "phase_changes": phase_changes,
        "findings": findings,
    }


def _summarize(incidents: list) -> dict:
    actions = [a for i in incidents for a in i["action_items"]]
    timed = [i["minutes_to_report"] for i in incidents if i["minutes_to_report"] is not None]
    resolved = [i for i in incidents if i["resolved"]]
    return {
        "incidents": len(incidents),
        "open": len(incidents) - len(resolved),
        "resolved": len(resolved),
        "by_severity": counts(i["severity"] for i in incidents),
        "by_category": counts(i["category"] for i in incidents),
        "by_current_phase": counts(i["current_phase"] for i in incidents),
        "minutes_to_report": number_stats(timed),
        "reported_within_window": sum(
            1 for i in incidents
            if i["minutes_to_report"] is not None
            and 0 <= i["minutes_to_report"] <= i["report_window_minutes"]
        ),
        "reported_time_from_ticket_created": sum(
            1 for i in incidents if i["reported_at_source"] == "created"
        ),
        "reported_late": sum(1 for i in incidents if "reported_late" in i["findings"]),
        "category_target_missed": sum(
            1 for i in incidents if "category_notification_target_missed" in i["findings"]
        ),
        "missing_detected_time": sum(1 for i in incidents if "missing_detected_time" in i["findings"]),
        "postmortem_required": sum(1 for i in incidents if i["postmortem_required"]),
        "resolved_with_postmortem": sum(1 for i in resolved if i["postmortems"]),
        "resolved_without_postmortem": sum(
            1 for i in incidents if "resolved_without_postmortem" in i["findings"]
        ),
        "action_items": {
            "total": len(actions),
            "open": sum(1 for a in actions if a["is_open"]),
            "done": sum(1 for a in actions if not a["is_open"]),
            "open_unassigned": sum(1 for a in actions if a["is_open"] and not a["assignee"]),
            "overdue": sum(1 for a in actions if a["overdue"]),
        },
        "findings": counts(f for i in incidents for f in i["findings"]),
    }


def _config():
    fields, err = json_env("JIRA_INCIDENT_FIELDS", {})
    if err:
        return None, err
    unknown = sorted(set(fields) - set(DEFAULT_FIELDS))
    if unknown:
        return None, f"JIRA_INCIDENT_FIELDS has unknown keys: {', '.join(unknown)}"
    targets, err = json_env("JIRA_INCIDENT_CATEGORY_TARGETS", {})
    if err:
        return None, err
    if not all(
        isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v > 0
        for v in targets.values()
    ):
        return None, "JIRA_INCIDENT_CATEGORY_TARGETS values must be positive minutes"
    report_minutes = int_env("JIRA_INCIDENT_REPORT_MINUTES", 60)
    max_items = int_env("JIRA_INCIDENT_MAX_ITEMS", 1000)
    if report_minutes is None or max_items is None:
        return None, "JIRA_INCIDENT_REPORT_MINUTES and JIRA_INCIDENT_MAX_ITEMS must be positive integers"
    return {
        "fields": {**DEFAULT_FIELDS, **fields},
        "category_targets": targets,
        "report_minutes": report_minutes,
        "max_items": max_items,
        "postmortem_types": {
            t.lower() for t in (list_env("JIRA_POSTMORTEM_ISSUE_TYPES") or ["Post-mortem"])
        },
        "required_severities": {t.lower() for t in list_env("JIRA_POSTMORTEM_REQUIRED_SEVERITIES")},
        "required_phases": list_env("JIRA_INCIDENT_REQUIRED_PHASES"),
        "no_review": {t.lower() for t in (list_env("JIRA_NO_POSTMORTEM_RESOLUTIONS") or DEFAULT_NO_REVIEW)},
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
    jql = os.environ.get("JIRA_INCIDENT_JQL", "").strip()
    if not jql:
        report_failure(
            "JIRA_INCIDENT_JQL is not set; it selects the incident tickets, e.g. "
            "'project = IR AND issuetype = Incident'",
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
    incidents: list = []
    truncated = False
    history_complete = True
    related_complete = True
    missing_related: list = []

    try:
        collector = collector_info(client)
        ids, problems = resolve_fields(client, cfg["fields"])
        raw, truncated, _ = client.search_issues(
            jql, INCIDENT_FIELDS + sorted(set(ids.values())), cfg["max_items"]
        )
        history_fields = ["status"] + ([ids["phase"]] if "phase" in ids else [])
        histories, history_complete = client.bulk_changelogs(
            [str(i.get("id")) for i in raw if i.get("id")], history_fields
        )

        linked = {
            k for i in raw for k in _linked_keys(i.get("fields") or {}, cfg["postmortem_types"])
        }
        linked_issues, missing_pm, ok_pm = fetch_issues(client, linked, POSTMORTEM_FIELDS)
        postmortems = {}
        subtask_keys = []
        for pm in linked_issues:
            pf = pm.get("fields") or {}
            if (name_of(pf.get("issuetype")) or "").strip().lower() not in cfg["postmortem_types"]:
                continue
            subs = [s.get("key") for s in pf.get("subtasks") or [] if s.get("key")]
            subtask_keys.extend(subs)
            postmortems[pm.get("key")] = {
                "key": pm.get("key"),
                "summary": pf.get("summary"),
                "status": name_of(pf.get("status")),
                "created": pf.get("created"),
                "resolved": pf.get("resolutiondate"),
                "action_item_count": len(subs),
            }
        action_issues, missing_ai, ok_ai = fetch_issues(client, subtask_keys, ACTION_FIELDS)
        actions: dict = {}
        for a in action_issues:
            rec = _action_record(a, now)
            actions.setdefault(rec["postmortem"], []).append(rec)
        related_complete = ok_pm and ok_ai
        missing_related = sorted(set(missing_pm) | set(missing_ai))

        incidents = [
            _incident_record(
                i, histories.get(str(i.get("id")), []), ids, cfg, postmortems, actions, set(missing_pm)
            )
            for i in raw
        ]
    except Abort:
        pass
    except Exception as e:  # unexpected response shape: keep what was collected and say why
        client.fail("collection", type(e).__name__, str(e)[:200], "internal_error")

    evidence = {
        "metadata": {
            "collected_at": now.isoformat(),
            "base_url": base_url,
            "jql": jql,
            "field_names": cfg["fields"],
            "fields_resolved": ids,
            "field_problems": problems,
            "required_phases": cfg["required_phases"],
            "no_postmortem_resolutions": sorted(cfg["no_review"]),
            "report_window_minutes": cfg["report_minutes"],
            "category_targets_minutes": cfg["category_targets"],
            "postmortem_issue_types": sorted(cfg["postmortem_types"]),
            "postmortem_required_severities": sorted(cfg["required_severities"]) or "all resolved",
            "max_items": cfg["max_items"],
            "incidents_collected": len(incidents),
            "incidents_truncated": truncated,
            "status_history_complete": history_complete,
            "related_issues_complete": related_complete,
            "related_issues_not_visible": missing_related,
            "partial_failure": bool(client.api_failures),
            "api_failures": client.api_failures,
        },
        "collector": collector,
        "summary": _summarize(incidents),
        "incidents": incidents,
    }
    incomplete = ""
    if truncated:
        incomplete = f"incidents truncated at JIRA_INCIDENT_MAX_ITEMS={cfg['max_items']}"
    elif not history_complete:
        incomplete = "status or phase history incomplete for some incidents"
    elif not related_complete or missing_related:
        incomplete = "some post-mortems or action items could not be read"
    return write_and_finish(logger, client, evidence, OUTPUT_FILE, incomplete)


if __name__ == "__main__":
    sys.exit(main())
