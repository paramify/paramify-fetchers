#!/usr/bin/env python3
"""Qualys scan schedules: active recurring schedules, whether their option profiles authenticate, and recent scan runs."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "_shared"))
from qualys_client import QualysError, text  # noqa: E402
from qualys_evidence import (  # noqa: E402
    NOT_RETURNED,
    cutoff,
    int_config,
    qualys_time,
    run,
)

OUTPUT_FILE = "qualys_scan_schedules.json"
SCHEDULE_PATH = "/api/5.0/fo/schedule/scan/"
PROFILE_PATH = "/api/4.0/fo/subscription/option_profile/vm/"
SCAN_PATH = "/api/3.0/fo/scan/"
RECURRENCE = {"DAILY": ("daily", "frequency_days", 1), "WEEKLY": ("weekly", "frequency_weeks", 7),
              "MONTHLY": ("monthly", "frequency_months", 31)}
RECURRENCE_KEYS = ("daily", "weekly", "monthly", "once", NOT_RETURNED)
STATE_KEYS = ("finished", "running", "queued", "loading", "paused", "canceled", "error", "other", NOT_RETURNED)
TYPE_KEYS = ("scheduled", "on_demand", "api", "other", NOT_RETURNED)


def recurrence(scan):
    """(kind, interval in days at most) from the SCHEDULE element."""
    schedule = scan.find("SCHEDULE")
    if schedule is None:
        return NOT_RETURNED, None
    for tag, (kind, attr, unit) in RECURRENCE.items():
        elem = schedule.find(tag)
        if elem is not None:
            try:
                return kind, int(elem.get(attr, "")) * unit
            except ValueError:
                return kind, None
    return "once", None


def profiles(client):
    """{title: authentication types or None when the profile list carries no authentication setting}."""
    found, auth_seen = {}, False
    for p in client.records(PROFILE_PATH, {"action": "list"}, "OPTION_PROFILE", "list_option_profiles"):
        title = text(p, "BASIC_INFO/GROUP_NAME") or text(p, "TITLE")
        auth = p.find("SCAN/AUTHENTICATION")
        auth_seen = auth_seen or auth is not None
        found[title] = sorted(t.strip() for t in (auth.text or "").split(",") if t.strip()) if auth is not None else []
    return found if auth_seen else {title: None for title in found}


def schedule_item(scan, auth_by_profile):
    kind, interval = recurrence(scan)
    active_value = text(scan, "ACTIVE")
    profile = text(scan, "OPTION_PROFILE/TITLE")
    auth = auth_by_profile.get(profile) if auth_by_profile is not None else None
    return {
        "schedule_id": text(scan, "ID"),
        "title": text(scan, "TITLE"),
        "active": None if active_value is None else active_value != "0",
        "active_value": active_value,
        "target": text(scan, "TARGET"),
        "asset_groups": sorted(t.text.strip() for t in scan.iter("ASSET_GROUP_TITLE") if t.text and t.text.strip()),
        "targets_tags": scan.find("ASSET_TAGS") is not None,
        "option_profile": profile,
        "recurrence": kind,
        "interval_days": interval,
        "launch_type": text(scan, "SCHEDULE/LAUNCH_TYPE"),
        "next_launch_utc": text(scan, "SCHEDULE/NEXTLAUNCH_UTC"),
        "authentication_types": auth,
        "authenticated": None if auth is None else bool(auth),
    }


def scan_item(scan):
    return {
        "scan_ref": text(scan, "REF"),
        "type": text(scan, "TYPE"),
        "title": text(scan, "TITLE"),
        "launched": text(scan, "LAUNCH_DATETIME"),
        "state": text(scan, "STATUS/STATE"),
        "sub_state": text(scan, "STATUS/SUB_STATE"),
        "option_profile": text(scan, "OPTION_PROFILE/TITLE"),
    }


def bucket(value, keys):
    if not value:
        return NOT_RETURNED
    key = value.strip().lower().replace("-", "_")
    return key if key in keys else "other"


def counts(items, field, keys):
    result = {k: 0 for k in keys}
    for item in items:
        result[bucket(item[field], keys)] += 1
    return result


def collect(client, ledger, now):
    window = int_config("QUALYS_SCAN_WINDOW_DAYS", 31)
    auth_by_profile = None
    try:
        auth_by_profile = profiles(client)
    except QualysError as e:
        ledger.add(e)
    schedules = [schedule_item(s, auth_by_profile) for s in client.records(
        SCHEDULE_PATH, {"action": "list"}, "SCAN", "list_scan_schedules")]
    scans = None
    try:
        scans = [scan_item(s) for s in client.records(
            SCAN_PATH, {"action": "list", "launched_after_datetime": qualys_time(cutoff(now, window))},
            "SCAN", "list_scans")]
    except QualysError as e:
        ledger.add(e)

    active = [s for s in schedules if s["active"]]
    recurring = [s for s in active if s["recurrence"] in ("daily", "weekly", "monthly")]
    summary = {
        "total_schedules": len(schedules),
        "active_schedules": len(active),
        "inactive_schedules": sum(1 for s in schedules if s["active"] is False),
        "active_schedules_by_recurrence": {k: sum(1 for s in active if s["recurrence"] == k) for k in RECURRENCE_KEYS},
        "scan_window_days": window,
        "active_schedules_within_window": sum(
            1 for s in recurring if s["interval_days"] is not None and s["interval_days"] <= window),
        "active_schedules_over_window": sum(
            1 for s in recurring if s["interval_days"] is not None and s["interval_days"] > window),
        "active_schedules_interval_unread": sum(1 for s in recurring if s["interval_days"] is None),
        "active_schedules_with_authentication": sum(1 for s in active if s["authenticated"] is True),
        "active_schedules_without_authentication": sum(1 for s in active if s["authenticated"] is False),
        "active_schedules_authentication_unread": sum(1 for s in active if s["authenticated"] is None),
        "option_profiles": None if auth_by_profile is None else len(auth_by_profile),
        "option_profiles_with_authentication": None if auth_by_profile is None or None in auth_by_profile.values()
        else sum(1 for v in auth_by_profile.values() if v),
        "scans_in_window": None if scans is None else len(scans),
        "scans_by_state": None if scans is None else counts(scans, "state", STATE_KEYS),
        "scans_by_type": None if scans is None else counts(scans, "type", TYPE_KEYS),
        "scheduled_scans_finished_in_window": None if scans is None else sum(
            1 for s in scans if bucket(s["type"], TYPE_KEYS) == "scheduled" and bucket(s["state"], STATE_KEYS) == "finished"),
    }
    body = {"schedules": schedules, "scans": scans,
            "option_profiles": None if auth_by_profile is None else
            [{"title": t, "authentication_types": a} for t, a in sorted(auth_by_profile.items(), key=lambda x: str(x[0]))]}
    return body, summary, len(schedules)


if __name__ == "__main__":
    raise SystemExit(run("qualys_scan_schedules", OUTPUT_FILE, collect))
