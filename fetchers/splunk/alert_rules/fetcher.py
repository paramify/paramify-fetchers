#!/usr/bin/env python3
"""Every alert on a Splunk deployment: what it watches for, who it notifies, and how often it ran and fired."""

import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from splunk_client import (  # noqa: E402
    NON_NOTIFYING_ACTIONS,
    as_bool,
    as_int,
    iso,
    run,
    split_list,
    to_epoch,
)

NAME = "splunk_alert_rules"
# Without admin_all_objects Splunk hides saved searches only admin may read, and reports the smaller count as the total.
CAPABILITIES = ["search", "admin_all_objects"]
CONFIG = {"lookback_days": ("SPLUNK_ALERT_LOOKBACK_DAYS", 30)}

SAVED_SEARCHES = "servicesNS/-/-/saved/searches"  # every app and user; plain services/ sees only the caller's app
# Splunk Web's own definition of an alert. is_alert() applies it locally, and Splunk's answer must agree.
ALERT_FILTER = ('(is_scheduled=1 AND (alert_type!=always OR alert.track=1 OR (dispatch.earliest_time="rt*" '
                'AND dispatch.latest_time="rt*" AND actions="*" AND actions!="")))')
RUNS_SPL = ('search index=_internal sourcetype=scheduler savedsearch_id=* '
            '| stats count as runs count(eval(status="skipped")) as skipped latest(_time) as last_run '
            'latest(status) as last_status latest(user) as last_user by savedsearch_id')
FIRED_SPL = ("search index=_audit action=alert_fired "
             "| stats count as fired max(trigger_time) as last_fired by ss_user ss_app ss_name")


def key(entry):
    """(namespace user, app, name): the identity Splunk's logs use for a saved search."""
    parts = urlparse(entry.get("id", "")).path.strip("/").split("/")
    if len(parts) >= 3 and parts[0] == "servicesNS":
        return unquote(parts[1]), unquote(parts[2]), entry["name"]
    return None, (entry.get("acl") or {}).get("app"), entry["name"]


def is_alert(content):
    if not as_bool(content.get("is_scheduled")):
        return False
    if content.get("alert_type") != "always" or as_bool(content.get("alert.track")):
        return True
    earliest, latest = str(content.get("dispatch.earliest_time") or ""), str(content.get("dispatch.latest_time") or "")
    return earliest.startswith("rt") and latest.startswith("rt") and bool(split_list(content.get("actions")))


def search_row(entry):
    c, acl = entry["content"], entry.get("acl") or {}
    user, app, name = key(entry)
    return {
        "name": name,
        "app": app,
        "namespace_user": user,
        "owner": acl.get("owner"),
        "sharing": acl.get("sharing"),
        "enabled": not as_bool(c.get("disabled")),
        "orphan": bool(as_bool(c.get("orphan"))),  # the owner no longer exists, so the scheduler skips it
        "cron_schedule": c.get("cron_schedule"),
        "alert_type": c.get("alert_type"),
        "alert_track": bool(as_bool(c.get("alert.track"))),
        "dispatch_earliest_time": c.get("dispatch.earliest_time"),
        "dispatch_latest_time": c.get("dispatch.latest_time"),
        "actions": split_list(c.get("actions")),
    }


def alert_row(entry, run_stats, fire_stats, days):
    c, row = entry["content"], search_row(entry)
    recipients = [] if "email" not in row["actions"] else list(dict.fromkeys(
        r for field in ("action.email.to", "action.email.cc", "action.email.bcc") for r in split_list(c.get(field))))
    return {
        **row,
        "severity": as_int(c.get("alert.severity")),
        "has_notification_action": any(a not in NON_NOTIFYING_ACTIONS for a in row["actions"]),
        "email_recipients": recipients,
        "throttled": bool(as_bool(c.get("alert.suppress"))),
        "throttle_period": c.get("alert.suppress.period") or None,
        "lookback_days": days,
        "runs_in_window": as_int(run_stats.get("runs")) or 0,
        "skipped_in_window": as_int(run_stats.get("skipped")) or 0,
        "last_run": iso(to_epoch(run_stats.get("last_run"))),
        "last_run_status": run_stats.get("last_status"),
        "last_run_as": run_stats.get("last_user"),
        "fired_in_window": as_int(fire_stats.get("fired")) or 0,
        "last_fired": iso(to_epoch(fire_stats.get("last_fired"))),
        "alert_comparator": c.get("alert_comparator") or None,
        "alert_threshold": c.get("alert_threshold") or None,
        "alert_condition": c.get("alert_condition") or None,
        "description": c.get("description") or None,
        "search": c.get("search"),
    }


def resolver(keys):
    """Match a (user, app, name) from Splunk's logs to an alert, falling back to (app, name) when that is unique."""
    exact, by_app_name = set(keys), {}
    for k in keys:
        by_app_name.setdefault(k[1:], []).append(k)
    unique = {app_name: ks[0] for app_name, ks in by_app_name.items() if len(ks) == 1}
    return lambda k: k if k in exact else unique.get(tuple(k[1:]))


def collect(client, config):
    days = config["lookback_days"]
    if not client.require_searchable_indexes(["_audit", "_internal"]):
        return None
    entries = client.list(SAVED_SEARCHES, add_orphan_field=1)
    splunk_alerts = client.list(SAVED_SEARCHES, search=ALERT_FILTER)
    runs = client.search(RUNS_SPL, earliest=f"-{days}d")
    fires = client.search(FIRED_SPL, earliest=f"-{days}d")
    if None in (entries, splunk_alerts, runs, fires):
        return None

    scheduled = sorted((e for e in entries if as_bool(e["content"].get("is_scheduled"))),
                       key=lambda e: (e["name"].lower(), key(e)[1] or ""))
    alerts = [e for e in scheduled if is_alert(e["content"])]
    ours, theirs = {key(e) for e in alerts}, {key(e) for e in splunk_alerts}
    if ours != theirs:
        client.fail(f"GET {SAVED_SEARCHES}?search=<alert filter>", "ClassificationMismatch",
                    f"alerts only Splunk found: {sorted(theirs - ours)}; only we found: {sorted(ours - theirs)}",
                    "internal_error")

    resolve = resolver(list(ours))
    run_stats = {}
    for r in runs:
        parts = tuple(str(r.get("savedsearch_id", "")).split(";", 2))
        if len(parts) == 3 and resolve(parts):
            run_stats[resolve(parts)] = r
    fire_stats, unmatched = {}, []
    for r in fires:
        raw = (r.get("ss_user"), r.get("ss_app"), r.get("ss_name"))
        if resolve(raw):
            fire_stats[resolve(raw)] = r
        else:
            unmatched.append(";".join(str(p) for p in raw))

    alert_rows = [alert_row(e, run_stats.get(key(e), {}), fire_stats.get(key(e), {}), days) for e in alerts]
    enabled = [a for a in alert_rows if a["enabled"]]
    return {
        "metadata": {"alert_definition": ALERT_FILTER},
        "summary": {
            "saved_searches_total": len(entries),
            "scheduled_total": len(scheduled),
            "alerts_total": len(alert_rows),
            "alerts_enabled": len(enabled),
            "alerts_enabled_with_notification_action": sum(a["has_notification_action"] for a in enabled),
            "alerts_fired_in_window": sum(a["fired_in_window"] > 0 for a in alert_rows),
            "fired_in_window_total": sum(a["fired_in_window"] for a in alert_rows),
            "fired_unmatched": sorted(unmatched),  # fires of alerts that no longer exist, or could not be matched
        },
        "alerts": alert_rows,
        "other_scheduled_searches": [search_row(e) for e in scheduled if not is_alert(e["content"])],
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CAPABILITIES, CONFIG))
