#!/usr/bin/env python3
"""
Splunk Saved Searches and Alerts

Collects every saved search on a Splunk deployment with its schedule, alerting
configuration and notification actions, from the management REST API.

Why this evidence set
---------------------
CR26's KSI-MLA-RVL reads, in full: *"Logs are persistently reviewed and
audited."* The index fetcher deliberately does not claim anyone reads the logs —
it evidences the store, not the reading. This is the one that evidences the
reading.

A **scheduled** saved search is automated review, and its `cron_schedule` is the
"persistently" the indicator asks for. An **alert** — a saved search whose
`alert_type` is not `always` — is the monitoring half, and its actions are what
turns a match into something a human sees.

Also speaks to KSI-MLA-OSM (the SIEM being *used*, not merely present) and
KSI-CMT-LMC where a search watches the audit trail for changes.

The three ways this goes wrong, all of which are reported by name
----------------------------------------------------------------
1. **Scheduled but disabled.** Review that was configured and then switched off.
   A stock Splunk ships nine of these — the DMC alerts are all scheduled and all
   disabled out of the box — so this is not a hypothetical.
2. **Enabled but unrouted.** An alert that fires, tracks nothing and notifies
   nobody: `alert.track` false and no actions. It runs, it matches, and no
   record of the match survives. Indistinguishable from working, from the
   outside.
3. **Ad hoc.** A saved search with no schedule is someone's bookmark. It is
   evidence of a query existing, not of review happening, and it is counted
   separately rather than folded into the total.

No pass/fail verdict. A deployment may have every reason for the shape it is in;
judgment is Paramify-side.
"""

import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from splunk_client import (  # type: ignore  # noqa: E402
    SplunkAuthError,
    as_bool,
    as_int,
    build_client,
    evidence,
    evidence_error,
    flatten,
    read_server_info,
    run_fetcher,
)

logger = logging.getLogger("splunk_saved_searches")

# The namespace matters here and does not elsewhere.
#
# `/services/saved/searches` is scoped to the calling user's app context and
# returned **8 of 174** saved searches on the instance this was built against —
# a 95% undercount, reported as a complete collection. `/servicesNS/-/-/`
# wildcards user and app and returns all of them.
#
# Measured, not assumed: for `data/indexes`, `authentication/users`,
# `authorization/roles` and `data/inputs/monitor` the two paths return
# identical counts. Knowledge objects are namespaced; system configuration is
# not. That is why the index fetcher does not need this and this one does.
SEARCHES_PATH = "/servicesNS/-/-/saved/searches"

# `alert_type` is the literal string "always" for a scheduled *report* — it
# means "alert every time it runs", i.e. not really an alert. Anything else is
# a real alerting condition.
NOT_AN_ALERT = "always"


def action_list(record: Dict[str, Any]) -> List[str]:
    """
    The enabled alert actions.

    `actions` is a **comma-separated string**, not a list — `""`,
    `"outputtelemetry"`, `"summary_index"` are the real values on a stock
    install. Treating it as a list iterates its characters, and testing it for
    membership matches substrings.
    """
    raw = record.get("actions")
    if not isinstance(raw, str):
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def is_alert(record: Dict[str, Any]) -> bool:
    """True when this is an alerting search rather than a scheduled report."""
    alert_type = record.get("alert_type")
    if not isinstance(alert_type, str) or not alert_type.strip():
        return False
    return alert_type.strip().lower() != NOT_AN_ALERT


def notifies_someone(record: Dict[str, Any]) -> bool:
    """
    Whether a triggered alert leaves any trace.

    Two independent ways it can: `alert.track` puts it in Splunk's own triggered
    -alerts list, and an action (email, webhook, script, summary index) sends it
    somewhere. Neither, and the alert fires into the void — it runs, it matches,
    and nothing survives to be reviewed.
    """
    return bool(as_bool(record.get("alert.track")) or action_list(record))


def describe(record: Dict[str, Any]) -> Dict[str, Any]:
    """One saved search, reduced to the fields an assessor reads."""
    scheduled = as_bool(record.get("is_scheduled"))
    disabled = as_bool(record.get("disabled"))
    return {
        "name": record.get("name"),
        "app": record.get("acl_app"),
        "owner": record.get("acl_owner"),
        "sharing": record.get("acl_sharing"),
        "description": record.get("description") or None,
        "scheduled": scheduled,
        "disabled": disabled,
        # Live review is both: configured to run, and not switched off.
        "running": bool(scheduled) and disabled is False,
        "cron_schedule": record.get("cron_schedule") or None,
        # Splunk's own answer to "when does this next run". The strongest
        # evidence that a schedule is real rather than merely written down.
        "next_scheduled_time": record.get("next_scheduled_time") or None,
        "is_alert": is_alert(record),
        "alert_type": record.get("alert_type"),
        "alert_condition": " ".join(
            str(record.get(k))
            for k in ("alert_comparator", "alert_threshold")
            if record.get(k)
        )
        or None,
        "alert_severity": as_int(record.get("alert.severity")),
        "alert_tracked": as_bool(record.get("alert.track")),
        "actions": action_list(record),
        "notifies": notifies_someone(record),
    }


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Reduce the saved-search list to the posture a reviewer reads first.

    The headline is `running_scheduled_searches`: configured to run, and not
    disabled. Every way that can fail is also listed by name, because a
    deployment can have a full library of well-written detection searches and
    be performing no review at all.
    """
    described = [describe(r) for r in records if isinstance(r, dict)]

    running = [d for d in described if d["running"]]
    scheduled_off = [d for d in described if d["scheduled"] and d["disabled"] is True]
    ad_hoc = [d for d in described if d["scheduled"] is False]
    unreadable = [d["name"] for d in described if d["scheduled"] is None or d["disabled"] is None]

    alerts = [d for d in described if d["is_alert"]]
    running_alerts = [d for d in alerts if d["running"]]
    unrouted = [d["name"] for d in running_alerts if not d["notifies"]]

    # A search that is running but whose next run Splunk cannot name. Reported,
    # not counted against the deployment: a real-time schedule or a search that
    # has not been dispatched since a restart both look like this, and neither
    # is a finding on its own.
    no_next_run = [d["name"] for d in running if not d["next_scheduled_time"]]

    action_counts: Counter = Counter()
    for d in described:
        for action in d["actions"]:
            action_counts[action] += 1

    return {
        "total_saved_searches": len(described),
        # The KSI-MLA-RVL claim rests on this number, not on the total.
        "running_scheduled_searches": len(running),
        "running_scheduled_search_names": [d["name"] for d in running],
        "scheduled_but_disabled": [d["name"] for d in scheduled_off],
        "ad_hoc_searches": len(ad_hoc),
        "searches_with_unreadable_state": unreadable,
        "total_alerts": len(alerts),
        "running_alerts": len(running_alerts),
        # An alert that fires and notifies nobody. Runs, matches, leaves no
        # trace — indistinguishable from working unless you look here.
        "running_alerts_that_notify_nobody": unrouted,
        "running_searches_with_no_next_run_time": no_next_run,
        "schedules": {
            d["name"]: d["cron_schedule"] for d in running if d["cron_schedule"]
        },
        "by_app": dict(Counter(d["app"] or "unknown" for d in described).most_common()),
        "by_owner": dict(Counter(d["owner"] or "unknown" for d in described).most_common()),
        "by_action": dict(action_counts.most_common()),
        "searches": described,
    }


def collect() -> Dict[str, Any]:
    try:
        client = build_client()
    except (SplunkAuthError, RuntimeError) as e:
        return evidence_error(str(e))

    read_server_info(client)

    records = [flatten(entry) for entry in client.collect(SEARCHES_PATH)]

    return evidence(
        client=client,
        endpoint=SEARCHES_PATH,
        records=records,
        data=[describe(r) for r in records if isinstance(r, dict)],
        analysis=summarize(records),
        empty_message="No saved searches returned",
    )


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "splunk_saved_searches.json", logger))
