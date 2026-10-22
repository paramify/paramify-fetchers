#!/usr/bin/env python3
"""Whether each Splunk index is still receiving data: when it last received any, and whether it has gone stale."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from splunk_client import (  # noqa: E402
    as_bool,
    as_int,
    iso,
    now_epoch,
    run,
    silence,
    to_epoch,
)

NAME = "splunk_index_activity"
CAPABILITIES = ["search", "rest_properties_get"]
CONFIG = {"max_silence_minutes": ("SPLUNK_MAX_SILENCE_MINUTES", 60)}

# Event count and size per index and search peer, from bucket metadata.
COUNTS_SPL = "| eventcount summarize=false report_size=true index=* index=_*"
# When an indexer last wrote to each event index, whatever the events' own timestamps say.
EVENT_TIMES_SPL = ("| tstats min(_time) as first_event max(_time) as last_event max(_indextime) as last_indexed "
                   "where index=* OR index=_* by index")
# Metric data points have no index time, so a metric index is judged by its newest data point.
METRIC_TIMES_SPL = ("| mstats earliest_time(_value) as first_event latest_time(_value) as last_event "
                    "where (index=* OR index=_*) AND metric_name=* by index")


def counts_by_index(rows):
    out = {}
    for r in rows:
        agg = out.setdefault(r["index"], {"count": 0, "size_bytes": 0, "servers": set()})
        agg["count"] += as_int(r.get("count")) or 0
        agg["size_bytes"] += as_int(r.get("size_bytes")) or 0
        agg["servers"].add(r.get("server"))
    return out


def index_row(entry, counts, times, now, window):
    c, name = entry["content"], entry["name"]
    enabled = not as_bool(c.get("disabled"))
    metric = c.get("datatype") == "metric"
    t = times.get(name, {}) if enabled else {}
    count = counts.get(name) if enabled else None
    last_received = to_epoch(t.get("last_event" if metric else "last_indexed"))
    minutes, stale = silence(last_received, now, window)
    return {
        "name": name,
        "datatype": c.get("datatype"),
        "enabled": enabled,
        "internal": name.startswith("_"),
        "holds_data": bool(t or (count and count["count"])) if enabled else None,
        "stale": stale,
        "last_received": iso(last_received),
        "last_received_basis": "event_time" if metric else "index_time",
        "minutes_since_last_received": minutes,
        "max_silence_minutes": window,
        "event_count": count["count"] if count else None,
        "size_bytes": count["size_bytes"] if count else None,
        "first_event": iso(to_epoch(t.get("first_event"))),
        "last_event": iso(to_epoch(t.get("last_event"))),
        "servers": sorted(s for s in count["servers"] if s) if count else [],
        "app": (entry.get("acl") or {}).get("app"),
    }


def summarize(rows):
    enabled = [r for r in rows if r["enabled"]]
    return {
        "indexes_total": len(rows),
        "indexes_enabled": len(enabled),
        "indexes_holding_data": sum(bool(r["holds_data"]) for r in enabled),
        "indexes_stale": sum(r["stale"] for r in enabled),
        "quiet_indexes": [r["name"] for r in enabled if r["holds_data"] and r["stale"]],
        "empty_indexes": [r["name"] for r in enabled if r["holds_data"] is False],
        "disabled_indexes": [r["name"] for r in rows if not r["enabled"]],
        "metric_indexes": [r["name"] for r in rows if r["datatype"] == "metric"],
    }


def collect(client, config):
    entries = client.list_indexes(require_searchable=True)
    counts = client.search(COUNTS_SPL)
    event_times = client.search(EVENT_TIMES_SPL)
    metric_times = client.search(METRIC_TIMES_SPL)
    if None in (entries, counts, event_times, metric_times):
        return None
    now = now_epoch()
    by_index = counts_by_index(counts)
    times = {r["index"]: r for r in event_times + metric_times}
    rows = [index_row(e, by_index, times, now, config["max_silence_minutes"])
            for e in sorted(entries, key=lambda e: e["name"])]
    return {"summary": summarize(rows), "indexes": rows}


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CAPABILITIES, CONFIG))
