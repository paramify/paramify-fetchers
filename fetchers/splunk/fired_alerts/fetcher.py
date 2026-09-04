#!/usr/bin/env python3
"""
Splunk Fired Alerts

Collects the alerts that have actually triggered, per saved search, with their
trigger times and severities.

Why this evidence set is separate from `splunk_saved_searches`
--------------------------------------------------------------
`splunk_saved_searches` proves review is *configured*: which searches run, on
what cadence, and whether anyone is notified. It cannot show that any of it ever
produced anything. This one does — it is the difference between a scheduled
review and a review that happened.

The same split exists in the closest category already in this repo:
`datadog_siem_detection_rules` and `datadog_siem_signals` are two evidence sets
for exactly this reason.

Speaks to KSI-MLA-02, "regularly review and audit logs", alongside the saved
search fetcher.

**The caveat that must travel with this evidence**
--------------------------------------------------
**Fired alerts expire.** Splunk keeps a triggered alert for `alert.expires` —
24 hours by default — and then deletes it. So this is a **rolling window**, not
a complete history, and "3 alerts fired" means "3 in the retention window", not
"3 ever".

That is stated in the evidence body itself (`retention_note`), not just here,
because an assessor reading a small number without it would draw exactly the
wrong conclusion. A deployment with a quiet window and one with no alerting at
all look identical in this data, which is why `splunk_saved_searches` is the
fetcher that establishes whether alerting is configured.

**And the list is eventually consistent.** Observed on the instance this was
built against: the same deployment reported 10 firings, then 0, then 17 within
a few hours — the zero was immediately after a Splunk restart, before the
scheduler had repopulated. So a run timed badly reads as "nothing is alerting"
for a second reason that has nothing to do with expiry. Neither is a fault this
fetcher can detect from a single collection; both are why the count travels
with its caveat rather than alone.

The other thing that is easy to get wrong
-----------------------------------------
The collection contains a **rollup entry named `-`** carrying the total count
across all alerts, alongside the per-search entries. Counting it as a saved
search double-counts every firing and invents an alert named `-`. It is
excluded, and used as a cross-check instead.
"""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from splunk_client import (  # type: ignore  # noqa: E402
    SplunkAuthError,
    as_int,
    build_client,
    evidence,
    evidence_error,
    flatten,
    read_server_info,
    run_fetcher,
)

logger = logging.getLogger("splunk_fired_alerts")

# Knowledge objects need the wildcard namespace — fired alerts belong to the
# saved search that produced them, and those span apps.
FIRED_PATH = "/servicesNS/-/-/alerts/fired_alerts"

# Splunk returns a rollup entry under this name carrying the total across every
# alert. It is not a saved search, and counting it as one double-counts.
ROLLUP_NAME = "-"

# Splunk's alert severity scale, from the `alert.severity` setting.
SEVERITY_LABELS = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "fatal"}

# Per-search firing detail is a call each. A deployment with many alerting
# searches would otherwise make hundreds of requests, so it is bounded and the
# cap is recorded when hit rather than silently truncating.
DEFAULT_MAX_SEARCHES = 200


def severity_label(value: Any) -> str:
    """
    Splunk sends `severity` as an integer on the fired-alert record.

    An unrecognized number is reported as `unknown-<n>` rather than folded into
    a known band: inventing a severity is worse than admitting the scale moved.
    """
    number = as_int(value)
    if number is None:
        return "unspecified"
    return SEVERITY_LABELS.get(number, f"unknown-{number}")


def trigger_age_hours(epoch: Any) -> Optional[float]:
    """Hours since a firing. None when the timestamp cannot be read."""
    value = as_int(epoch)
    if value is None or value <= 0:
        return None
    delta = datetime.now(timezone.utc) - datetime.fromtimestamp(value, tz=timezone.utc)
    return round(max(delta.total_seconds(), 0) / 3600, 2)


def describe_firing(record: Dict[str, Any]) -> Dict[str, Any]:
    """One triggered alert instance."""
    return {
        "saved_search": record.get("savedsearch_name"),
        "severity": severity_label(record.get("severity")),
        "severity_value": as_int(record.get("severity")),
        "trigger_time": record.get("trigger_time_rendered") or None,
        "trigger_time_epoch": as_int(record.get("trigger_time")),
        "hours_ago": trigger_age_hours(record.get("trigger_time")),
        # When this firing will be deleted. The reason the whole evidence set is
        # a window rather than a history.
        "expires": record.get("expiration_time_rendered") or None,
        "alert_type": record.get("alert_type"),
        "digest_mode": record.get("digest_mode"),
        "sid": record.get("sid"),
    }


def summarize(
    per_search: List[Dict[str, Any]],
    firings: List[Dict[str, Any]],
    reported_total: Optional[int],
    truncated: bool,
) -> Dict[str, Any]:
    """
    Reduce the firings to what a reviewer reads first.

    Deliberately reports both what was counted and what Splunk said the total
    was. They should agree; if they do not, the collection missed something and
    a reviewer needs to see that rather than a confident single number.
    """
    described = [describe_firing(f) for f in firings if isinstance(f, dict)]

    by_search: Counter = Counter()
    for entry in per_search:
        name = entry.get("name")
        count = as_int(entry.get("triggered_alert_count")) or 0
        if isinstance(name, str) and name != ROLLUP_NAME:
            by_search[name] = count

    ages = [d["hours_ago"] for d in described if d["hours_ago"] is not None]

    return {
        "searches_that_fired": len(by_search),
        "firings_collected": len(described),
        # Splunk's own rollup, kept as a cross-check rather than as the answer.
        "total_reported_by_splunk": reported_total,
        "counts_agree": reported_total is None or reported_total == sum(by_search.values()),
        "firings_by_search": dict(by_search.most_common()),
        "firings_by_severity": dict(
            Counter(d["severity"] for d in described).most_common()
        ),
        "most_recent_firing_hours_ago": min(ages) if ages else None,
        "oldest_retained_firing_hours_ago": max(ages) if ages else None,
        "per_search_detail_truncated": truncated,
        # Repeated in the evidence body because a number without it reads wrong.
        "retention_note": (
            "Splunk deletes a triggered alert after `alert.expires` (24 hours by "
            "default), so these are the firings still inside the retention "
            "window, not a complete history. The list is also eventually "
            "consistent: immediately after a restart it can be empty and "
            "repopulate minutes later. A quiet window, a recent restart and a "
            "deployment with no alerting configured all look identical here — "
            "splunk_saved_searches is what distinguishes them."
        ),
        "firings": described,
    }


def collect() -> Dict[str, Any]:
    try:
        client = build_client()
    except (SplunkAuthError, RuntimeError) as e:
        return evidence_error(str(e))

    read_server_info(client)

    try:
        max_searches = int(os.environ.get("SPLUNK_MAX_ALERT_SEARCHES", DEFAULT_MAX_SEARCHES))
    except ValueError:
        logger.warning(
            "SPLUNK_MAX_ALERT_SEARCHES is not an integer; using %s", DEFAULT_MAX_SEARCHES
        )
        max_searches = DEFAULT_MAX_SEARCHES

    entries = [flatten(e) for e in client.collect(FIRED_PATH)]

    # The rollup is Splunk's total across everything. Pulled out before the
    # per-search list so it is never mistaken for an alert of its own.
    rollup = next((e for e in entries if e.get("name") == ROLLUP_NAME), None)
    reported_total = as_int((rollup or {}).get("triggered_alert_count"))
    per_search = [e for e in entries if e.get("name") != ROLLUP_NAME]

    # Each search's firings are a separate call, so this is bounded.
    truncated = len(per_search) > max_searches
    if truncated:
        logger.warning(
            "%d searches have fired; collecting detail for the first %d",
            len(per_search),
            max_searches,
        )

    firings: List[Dict[str, Any]] = []
    for entry in per_search[:max_searches]:
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        firings.extend(
            flatten(e) for e in client.collect(f"{FIRED_PATH}/{quote(name, safe='')}")
        )

    return evidence(
        client=client,
        endpoint=FIRED_PATH,
        records=firings,
        data=[describe_firing(f) for f in firings if isinstance(f, dict)],
        analysis=summarize(per_search, firings, reported_total, truncated),
        empty_message=(
            "No alerts have fired within Splunk's retention window. This is not "
            "evidence that alerting is unconfigured — see splunk_saved_searches."
        ),
        searches_that_fired=len(per_search),
    )


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "splunk_fired_alerts.json", logger))
