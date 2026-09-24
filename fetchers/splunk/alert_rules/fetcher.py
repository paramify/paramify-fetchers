#!/usr/bin/env python3
"""Splunk alert rules: every scheduled search Splunk classes as an alert, its trigger and actions, and whether it ran and fired."""

import logging
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from splunk_client import (  # noqa: E402
    NON_NOTIFYING_ACTIONS,
    SplunkClient,
    env_int,
    finish,
    iso,
    now_epoch,
    report_failure,
    split_list,
    target_from_env,
    to_epoch,
    write_evidence,
)

FETCHER = "splunk_alert_rules"
logger = logging.getLogger(FETCHER)

SAVED_SEARCHES = "servicesNS/-/-/saved/searches"
# The saved/searches view coerces alert.track to a bool, so "auto" reads false; the conf view keeps it.
SAVED_SEARCH_CONF = "servicesNS/-/-/configs/conf-savedsearches"
ALERT_ACTIONS = "servicesNS/-/-/alerts/alert_actions"
FIRED_ALERTS = "servicesNS/-/-/alerts/fired_alerts/-"
REQUIRED_CAPABILITIES = ["search", "admin_all_objects"]
REQUIRED_INDEXES = ["_audit", "_internal"]
# Splunk Web's own alert filter (ALERT_SEARCH_STRING); is_alert() is the same rule, and the two are compared.
ALERT_FILTER = ('(is_scheduled=1 AND (alert_type!=always OR alert.track=1 OR (dispatch.earliest_time="rt*" '
                'AND dispatch.latest_time="rt*" AND actions="*" AND actions!="")))')
FIRED_SPL = ("search index=_audit action=alert_fired "
             "| stats count as fired max(trigger_time) as last_fired by ss_user ss_app ss_name")
RUNS_SPL = ('search index=_internal sourcetype=scheduler savedsearch_id=* '
            '| stats count as runs count(eval(status="skipped")) as skipped latest(_time) as last_run '
            'latest(status) as last_status latest(user) as last_user by savedsearch_id')


def namespace(entry):
    parts = urlparse(entry.get("id", "")).path.strip("/").split("/")
    if len(parts) >= 3 and parts[0] == "servicesNS":
        return unquote(parts[1]), unquote(parts[2])
    return None, entry.get("acl", {}).get("app")


def track_setting(raw):
    value = str(raw).strip().lower()
    if value in ("1", "true", "t", "yes", "y"):
        return "true"
    return "false" if value in ("0", "false", "f", "no", "n", "", "none") else value


def is_tracked(row, tracking_actions):
    if row["alert_track"] != "auto":
        return row["alert_track"] == "true"
    if row["alert_type"] == "always":
        return False
    return None if tracking_actions is None else any(a in tracking_actions for a in row["actions"])


def is_alert(content, actions):
    if not content.get("is_scheduled"):
        return False
    if content.get("alert_type") != "always" or content.get("alert.track"):
        return True
    earliest, latest = str(content.get("dispatch.earliest_time") or ""), str(content.get("dispatch.latest_time") or "")
    return earliest.startswith("rt") and latest.startswith("rt") and bool(actions)


def scheduled_row(entry, raw_track):
    c, acl = entry["content"], entry.get("acl", {})
    ns_user, app = namespace(entry)
    actions = split_list(c.get("actions"))
    return {
        "name": entry["name"],
        "app": app,
        "namespace_user": ns_user,
        "owner": acl.get("owner"),
        "sharing": acl.get("sharing"),
        "is_alert": is_alert(c, actions),
        "is_scheduled": bool(c.get("is_scheduled")),
        "alert_type": c.get("alert_type"),
        "alert_track": track_setting(c.get("alert.track") if raw_track is None else raw_track),
        "dispatch_earliest_time": c.get("dispatch.earliest_time"),
        "dispatch_latest_time": c.get("dispatch.latest_time"),
        "actions": actions,
        "enabled": not c.get("disabled"),
        "orphan": bool(c.get("orphan")),
        "cron_schedule": c.get("cron_schedule"),
    }


def alert_row(entry, row, lookback_days, tracking_actions, runs, fired, triggered):
    c = entry["content"]
    email = "email" in row["actions"]
    recipients = []
    for field in ("action.email.to", "action.email.cc", "action.email.bcc"):
        recipients += [r for r in split_list(c.get(field)) if r not in recipients]
    key = (row["namespace_user"], row["app"], row["name"])
    run = runs.get(key, {}) if runs is not None else None
    fire = fired.get(key, {}) if fired is not None else None
    tracked = is_tracked(row, tracking_actions)
    return {
        **row,
        "severity": c.get("alert.severity"),
        "has_notification_action": any(a not in NON_NOTIFYING_ACTIONS for a in row["actions"]),
        "email_recipients": recipients if email else [],
        "tracked": tracked,
        "alert_expires": c.get("alert.expires"),
        "throttled": bool(c.get("alert.suppress")),
        "throttle_period": c.get("alert.suppress.period") or None,
        "lookback_days": lookback_days,
        "runs_in_window": None if run is None else int(run.get("runs") or 0),
        "skipped_in_window": None if run is None else int(run.get("skipped") or 0),
        "last_run": None if run is None else iso(to_epoch(run.get("last_run"))),
        "last_run_status": None if run is None else run.get("last_status"),
        "last_run_as": None if run is None else run.get("last_user"),
        "fired_in_window": None if fire is None else int(fire.get("fired") or 0),
        "last_fired": None if fire is None else iso(to_epoch(fire.get("last_fired"))),
        "triggered_unexpired": None if triggered is None else triggered.get(key) or (0 if tracked else None),
        "alert_comparator": c.get("alert_comparator") or None,
        "alert_threshold": c.get("alert_threshold") or None,
        "alert_condition": c.get("alert_condition") or None,
        "description": c.get("description") or None,
        "search": c.get("search"),
    }


class Resolver:
    """Maps a (namespace user, app, name) key from logs or fired alerts to an alert, falling back to a unique (app, name)."""

    def __init__(self, keys):
        self.keys = set(keys)
        by_app_name = {}
        for k in keys:
            by_app_name.setdefault(k[1:], []).append(k)
        self.by_app_name = {k: v[0] for k, v in by_app_name.items() if len(v) == 1}

    def __call__(self, key):
        return key if key in self.keys else self.by_app_name.get(key[1:])


def collect_runs(client, resolve, lookback_days):
    rows = client.search(RUNS_SPL, earliest=f"-{lookback_days}d")
    if rows is None:
        return None
    runs = {}
    for r in rows:
        parts = r["savedsearch_id"].split(";", 2)
        key = resolve(tuple(parts)) if len(parts) == 3 else None
        if key:
            runs[key] = r
    return runs


def collect_fired(client, resolve, lookback_days, unmatched):
    rows = client.search(FIRED_SPL, earliest=f"-{lookback_days}d")
    if rows is None:
        return None
    fired = {}
    for r in rows:
        raw = (r.get("ss_user"), r.get("ss_app"), r.get("ss_name"))
        key = resolve(raw)
        if key:
            fired[key] = r
        else:
            unmatched.add(";".join(str(p) for p in raw))
    return fired


def collect_triggered(client, resolve, unmatched):
    entries = client.list(FIRED_ALERTS)
    if entries is None:
        return None, None
    instances = [e for e in entries if e["name"] != "-"]
    triggered = {}
    for e in instances:
        ns_user, app = namespace(e)
        raw = (ns_user, app, e["content"].get("savedsearch_name"))
        key = resolve(raw)
        if key:
            triggered[key] = triggered.get(key, 0) + 1
        else:
            unmatched.add(";".join(str(p) for p in raw))
    return triggered, len(instances)


def check_classification(client, rows):
    """Splunk's server-side evaluation of the alert filter must name exactly the alerts is_alert() found."""
    entries = client.list(SAVED_SEARCHES, search=ALERT_FILTER)
    if entries is None:
        return
    server = {(*namespace(e), e["name"]) for e in entries}
    local = {(r["namespace_user"], r["app"], r["name"]) for r in rows if r["is_alert"]}
    if server != local:
        client.fail(f"GET {SAVED_SEARCHES}?search=<alert filter>", "ClassificationMismatch",
                    f"Splunk's alert filter: {sorted(server - local)} not derived locally; "
                    f"derived locally but not Splunk's: {sorted(local - server)}", "internal_error")


def by_name(pair):
    return pair[1]["name"].lower(), pair[1]["app"] or ""


def collect(client, lookback_days):
    entries = client.list(SAVED_SEARCHES, add_orphan_field=1)
    if entries is None:
        return None
    conf = client.list(SAVED_SEARCH_CONF)
    raw_track = {(*namespace(e), e["name"]): e["content"].get("alert.track") for e in conf or []}
    action_entries = client.list(ALERT_ACTIONS)
    tracking_actions = None if action_entries is None else {
        e["name"] for e in action_entries if track_setting(e["content"].get("track_alert")) == "true"}
    scheduled = [(e, scheduled_row(e, raw_track.get((*namespace(e), e["name"]))))
                 for e in entries if e["content"].get("is_scheduled")]
    check_classification(client, [row for _, row in scheduled])
    alert_pairs = [(e, row) for e, row in scheduled if row["is_alert"]]
    resolve = Resolver([(row["namespace_user"], row["app"], row["name"]) for _, row in alert_pairs])
    unmatched = set()
    runs = fired = None
    if client.require_searchable_indexes(REQUIRED_INDEXES):
        runs = collect_runs(client, resolve, lookback_days)
        fired = collect_fired(client, resolve, lookback_days, unmatched)
    triggered, triggered_total = collect_triggered(client, resolve, unmatched)
    alerts = [alert_row(e, row, lookback_days, tracking_actions, runs, fired, triggered)
              for e, row in sorted(alert_pairs, key=by_name)]
    others = [row for _, row in sorted(scheduled, key=by_name) if not row["is_alert"]]
    return {"saved_searches_total": len(entries), "scheduled_total": len(scheduled),
            "alerts": alerts, "others": others, "unmatched": sorted(unmatched), "triggered_total": triggered_total}


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    try:
        target = target_from_env()
        lookback_days = env_int("SPLUNK_ALERT_LOOKBACK_DAYS", 30)
    except ValueError as exc:
        report_failure(str(exc), "bad_config")
        return 1

    client = SplunkClient(target["base_url"], target["token"], target["verify_ssl"])
    now = now_epoch()
    version = client.server_version()
    result = collect(client, lookback_days) if client.require_capabilities(REQUIRED_CAPABILITIES) else None
    alerts = (result or {}).get("alerts", [])
    enabled = [a for a in alerts if a["enabled"]]
    fired_known = all(a["fired_in_window"] is not None for a in alerts)
    summary = {
        "saved_searches_total": result["saved_searches_total"],
        "scheduled_total": result["scheduled_total"],
        "alerts_total": len(alerts),
        "alerts_enabled": len(enabled),
        "alerts_enabled_with_notification_action": sum(a["has_notification_action"] for a in enabled),
        "alerts_fired_in_window": sum(bool(a["fired_in_window"]) for a in alerts) if fired_known else None,
        "fired_in_window_total": sum(a["fired_in_window"] for a in alerts) if fired_known else None,
        "triggered_unexpired_total": result["triggered_total"],
        "fired_unmatched": result["unmatched"],
    } if result else {}

    evidence = {
        "metadata": {
            "collected_at": iso(now),
            "target": target["name"],
            "base_url": target["base_url"],
            "splunk_version": version,
            "lookback_days": lookback_days,
            "alert_definition": ALERT_FILTER,
            **client.failure_metadata(),
        },
        "summary": summary,
        "alerts": alerts,
        "other_scheduled_searches": (result or {}).get("others", []),
    }
    return finish(logger, write_evidence(FETCHER, target["name"], evidence), client)


if __name__ == "__main__":
    sys.exit(main())
