#!/usr/bin/env python3
"""Every Splunk index with its event count, size, time span, when it last received data and whether it has gone stale."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from splunk_client import (  # noqa: E402
    SplunkClient,
    env_int,
    finish,
    iso,
    minutes_since,
    now_epoch,
    report_failure,
    target_from_env,
    to_epoch,
    write_evidence,
)

FETCHER = "splunk_index_activity"
logger = logging.getLogger(FETCHER)

REQUIRED_CAPABILITIES = ["search", "rest_properties_get"]
COUNTS_SPL = "| eventcount summarize=false report_size=true index=* index=_*"
EVENT_TIMES_SPL = ("| tstats min(_time) as first_event max(_time) as last_event max(_indextime) as last_indexed "
                   "where index=* OR index=_* by index")
# Metric data points carry no _indextime (mstats rejects it, mpreview has none), so the newest point's own time is used.
METRIC_TIMES_SPL = ("| mstats earliest_time(_value) as first_event latest_time(_value) as last_event "
                    "where (index=* OR index=_*) AND metric_name=* by index")
LAST_RECEIVED_RULE = ("event indexes: max(_indextime) from tstats, when an indexer last wrote an event to the index "
                      "(last_received_basis index_time); metric indexes: the newest data point's timestamp from mstats, "
                      "because Splunk stores no index time for metrics (last_received_basis event_time). Both searches "
                      "span every search peer; stale is true when no data exists or its last_received is more than "
                      "max_silence_minutes before or after collection.")


def counts_by_index(rows):
    out = {}
    for r in rows:
        agg = out.setdefault(r["index"], {"count": 0, "size_bytes": 0, "servers": set()})
        agg["count"] += int(r.get("count") or 0)
        agg["size_bytes"] += int(r.get("size_bytes") or 0)
        agg["servers"].add(r.get("server"))
    return out


def times_by_index(client):
    event, metric = client.search(EVENT_TIMES_SPL), client.search(METRIC_TIMES_SPL)
    return ({r["index"]: r for r in event} if event is not None else None,
            {r["index"]: r for r in metric} if metric is not None else None)


def index_row(entry, counts, event_times, metric_times, now, window):
    c, name = entry["content"], entry["name"]
    enabled, metric = not c.get("disabled"), c.get("datatype") == "metric"
    times = metric_times if metric else event_times
    known = enabled and times is not None and counts is not None and name in counts
    t = times.get(name, {}) if known else {}
    count = (counts or {}).get(name) if enabled else None
    last_received = to_epoch(t.get("last_event" if metric else "last_indexed"))
    since = minutes_since(last_received, now)
    holds_data = bool(t) or bool(count and count["count"])
    return {
        "name": name,
        "datatype": c.get("datatype"),
        "enabled": enabled,
        "internal": name.startswith("_"),
        "holds_data": holds_data if known else None,
        "minutes_since_last_received": since,
        "max_silence_minutes": window,
        "stale": (since is None or abs(since) > window) if known or not enabled else None,
        "last_received": iso(last_received),
        "last_received_basis": "event_time" if metric else "index_time",
        "event_count": count["count"] if count else None,
        "size_bytes": count["size_bytes"] if count else None,
        "first_event": iso(to_epoch(t.get("first_event"))),
        "last_event": iso(to_epoch(t.get("last_event"))),
        "servers": sorted(count["servers"]) if count else [],
        "local_event_count": c.get("totalEventCount"),
        "local_size_mb": c.get("currentDBSizeMB"),
        "local_earliest_event": iso(to_epoch(c.get("minTime"))),
        "local_latest_event": iso(to_epoch(c.get("maxTime"))),
        "app": (entry.get("acl") or {}).get("app"),
    }


def collect(client, window):
    count_rows = client.search(COUNTS_SPL)
    counts = counts_by_index(count_rows) if count_rows is not None else None
    searchable = set(counts) if counts is not None else None
    entries = client.list_indexes(searchable)
    if entries is None:
        return None, None
    enabled = [e["name"] for e in entries if not e["content"].get("disabled")]
    if searchable is not None:
        client.require_searchable_indexes(enabled, searchable)
    event_times, metric_times = times_by_index(client)
    now = now_epoch()
    rows = [index_row(e, counts, event_times, metric_times, now, window) for e in sorted(entries, key=lambda e: e["name"])]
    return rows, now


def summary_of(rows):
    enabled = [r for r in rows if r["enabled"]]
    judged = all(r["holds_data"] is not None for r in enabled)
    holding = [r for r in enabled if r["holds_data"]]
    return {
        "indexes_total": len(rows),
        "indexes_enabled": len(enabled),
        "indexes_holding_data": len(holding) if judged else None,
        "indexes_stale": sum(r["stale"] for r in enabled) if judged else None,
        "quiet_indexes": [r["name"] for r in holding if r["stale"]] if judged else None,
        "empty_indexes": [r["name"] for r in enabled if r["holds_data"] is False] if judged else None,
        "disabled_indexes": [r["name"] for r in rows if not r["enabled"]],
        "metric_indexes": [r["name"] for r in rows if r["datatype"] == "metric"],
    }


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    try:
        target = target_from_env()
        window = env_int("SPLUNK_MAX_SILENCE_MINUTES", 60)
    except ValueError as exc:
        report_failure(str(exc), "bad_config")
        return 1

    client = SplunkClient(target["base_url"], target["token"], target["verify_ssl"])
    version = client.server_version()
    rows, judged_at = collect(client, window) if client.require_capabilities(REQUIRED_CAPABILITIES) else (None, None)

    evidence = {
        "metadata": {
            "collected_at": iso(judged_at or now_epoch()),
            "target": target["name"],
            "base_url": target["base_url"],
            "splunk_version": version,
            "max_silence_minutes": window,
            "last_received_rule": LAST_RECEIVED_RULE,
            **client.failure_metadata(),
        },
        "summary": summary_of(rows) if rows is not None else {},
        "indexes": rows or [],
    }
    return finish(logger, write_evidence(FETCHER, target["name"], evidence), client)


if __name__ == "__main__":
    sys.exit(main())
