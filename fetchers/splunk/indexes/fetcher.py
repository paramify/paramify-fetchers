#!/usr/bin/env python3
"""
Splunk Index Configuration

Collects every index on a Splunk deployment with its retention, archival,
volume and per-index data integrity setting, from the management REST API.

Why this evidence set
---------------------
CR26's KSI-MLA-OSM reads: *"A Security Information and Event Management (SIEM)
or similar system(s) is used and persistently reviewed for centralized,
tamper-resistant logging of events, activities, and changes."* An index list is
close to a restatement of it — the indexes ARE the centralized store, their
retention settings say for how long, and Splunk's per-index data integrity
control is the tamper-resistance the indicator names.

`enableDataIntegrityControl` is the load-bearing field. With it on, Splunk
computes SHA-256 hashes over each bucket's slices at roll time and writes an
`l_Hashes_<bucketID>.dat` alongside the data, which `splunk check-integrity`
verifies later. That is a cryptographic integrity claim about stored log data,
which is also the one thing the CrowdStrike set could not evidence at all
(KSI-SVC-VRI — see the FileVantage fetcher docstring for why its change records
carry no reachable digest).

Also speaks to KSI-MLA-RVL (*"logs are persistently reviewed and audited"*) and
KSI-CMT-LMC (*"modifications to the cloud service offering are logged and
monitored"*) by way of `_audit`, Splunk's own audit trail index.

Deliberately NOT claimed
------------------------
Nothing about whether anyone actually reads the logs. This is the store's
configuration, not evidence of review — a saved-search or alerting fetcher
would be the one to speak to that, and it is a separate evidence set.

Nor is there any pass/fail verdict here. An index with no retention policy may
be entirely correct for that deployment. Judgment is Paramify-side; this reports
what is configured and names what a reviewer would want to look at.
"""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

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

logger = logging.getLogger("splunk_indexes")

INDEXES_PATH = "/services/data/indexes"

# Splunk's internal indexes are created by the product, not the customer, and
# several are themselves evidence: `_audit` is the audit trail and `_internal`
# holds the platform's own logs. They are reported separately rather than
# filtered out — an `_audit` index that has been disabled or given a short
# retention is exactly the kind of thing this fetcher exists to surface.
INTERNAL_INDEX_PREFIX = "_"

# Splunk's own audit trail. KSI-CMT-LMC is about modifications being logged and
# monitored, and on a Splunk deployment this index is where that lands.
AUDIT_INDEX = "_audit"

# `frozenTimePeriodInSecs` is how long data lives before freezing. Splunk's
# stock default is 188697600 (~6 years); 0 has a special meaning, below.
SECONDS_PER_DAY = 86400


def retention_days(record: Dict[str, Any]) -> Optional[int]:
    """
    Retention in days, or None when it cannot be read.

    `frozenTimePeriodInSecs` is a string like `"188697600"`. Zero is not "no
    retention" — Splunk treats it as freeze-immediately, which is a real and
    very aggressive setting, so it is kept as 0 rather than folded into None.
    """
    seconds = as_int(record.get("frozenTimePeriodInSecs"))
    if seconds is None or seconds < 0:
        return None
    return seconds // SECONDS_PER_DAY


def archives_on_freeze(record: Dict[str, Any]) -> bool:
    """
    Whether frozen data is archived rather than deleted.

    Splunk deletes frozen buckets unless `coldToFrozenDir` or
    `coldToFrozenScript` says otherwise. For a log store under a retention
    obligation the difference between the two is the whole point, and it is not
    visible from the retention period alone.
    """
    return bool(
        (record.get("coldToFrozenDir") or "").strip()
        or (record.get("coldToFrozenScript") or "").strip()
    )


def describe(record: Dict[str, Any]) -> Dict[str, Any]:
    """One index, reduced to the fields an assessor reads."""
    name = record.get("name")
    return {
        "name": name,
        "internal": isinstance(name, str) and name.startswith(INTERNAL_INDEX_PREFIX),
        "datatype": record.get("datatype"),
        "disabled": as_bool(record.get("disabled")),
        "data_integrity_control": as_bool(record.get("enableDataIntegrityControl")),
        "retention_days": retention_days(record),
        "archives_on_freeze": archives_on_freeze(record),
        "cold_to_frozen_dir": record.get("coldToFrozenDir") or None,
        "total_event_count": as_int(record.get("totalEventCount")),
        "current_size_mb": as_int(record.get("currentDBSizeMB")),
        "max_total_size_mb": as_int(record.get("maxTotalDataSizeMB")),
        "min_time": record.get("minTime"),
        "max_time": record.get("maxTime"),
        "home_path": record.get("homePath_expanded") or record.get("homePath"),
    }


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Reduce the index list to the posture a reviewer reads first.

    Every count here excludes the indexes whose value could not be read, and
    those are reported on their own. A deployment where a setting is spelled in
    a way this does not recognize must not come back looking like a deployment
    where the setting is off — an unreadable value and a disabled control are
    different findings, and only one of them is the customer's.
    """
    described = [describe(r) for r in records if isinstance(r, dict)]

    enabled = [d for d in described if d["disabled"] is False]
    disabled = [d for d in described if d["disabled"] is True]
    unreadable_state = [d["name"] for d in described if d["disabled"] is None]

    integrity_on = [d for d in described if d["data_integrity_control"] is True]
    integrity_off = [d for d in described if d["data_integrity_control"] is False]
    integrity_unknown = [d["name"] for d in described if d["data_integrity_control"] is None]

    with_retention = [d for d in described if d["retention_days"] is not None]
    unreadable_retention = [d["name"] for d in described if d["retention_days"] is None]

    populated = [d for d in described if (d["total_event_count"] or 0) > 0]
    audit = next((d for d in described if d["name"] == AUDIT_INDEX), None)

    total_events = sum(d["total_event_count"] or 0 for d in described)
    total_size_mb = sum(d["current_size_mb"] or 0 for d in described)

    return {
        "total_indexes": len(described),
        "enabled_indexes": len(enabled),
        "disabled_indexes": [d["name"] for d in disabled],
        "indexes_with_unreadable_enabled_state": unreadable_state,
        "internal_indexes": len([d for d in described if d["internal"]]),
        "customer_indexes": len([d for d in described if not d["internal"]]),
        # The tamper-resistance half of KSI-MLA-OSM, and the whole of the
        # KSI-SVC-VRI claim. Named individually rather than counted, because
        # which indexes are covered is the question, not how many.
        "data_integrity_control_enabled": [d["name"] for d in integrity_on],
        "data_integrity_control_disabled": [d["name"] for d in integrity_off],
        "data_integrity_control_unreadable": integrity_unknown,
        "retention_days_by_index": {
            d["name"]: d["retention_days"] for d in with_retention
        },
        "shortest_retention_days": min(
            (d["retention_days"] for d in with_retention), default=None
        ),
        "indexes_with_unreadable_retention": unreadable_retention,
        "indexes_archiving_on_freeze": [d["name"] for d in described if d["archives_on_freeze"]],
        # An index that exists but has never received an event is either newly
        # created or a data feed that silently stopped. The fetcher does not
        # know which; a reviewer does.
        "indexes_with_no_events": [d["name"] for d in described if not (d["total_event_count"] or 0)],
        "populated_indexes": len(populated),
        "total_events": total_events,
        "total_size_mb": total_size_mb,
        "audit_index": audit,
        "indexes": described,
    }


def collect() -> Dict[str, Any]:
    try:
        client = build_client()
    except (SplunkAuthError, RuntimeError) as e:
        return evidence_error(str(e))

    # Read first so the version and role travel with the evidence even if the
    # index call is the one that fails.
    read_server_info(client)

    records = [flatten(entry) for entry in client.collect(INDEXES_PATH)]

    return evidence(
        client=client,
        endpoint=INDEXES_PATH,
        records=records,
        data=[describe(r) for r in records if isinstance(r, dict)],
        analysis=summarize(records),
        empty_message="No indexes returned",
    )


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "splunk_indexes.json", logger))
