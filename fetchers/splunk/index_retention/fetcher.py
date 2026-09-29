#!/usr/bin/env python3
"""How long each Splunk index keeps data, whether frozen data is archived, and whether data integrity control is on."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from splunk_client import as_bool, as_int, run  # noqa: E402

NAME = "splunk_index_retention"
CAPABILITIES = ["search", "rest_properties_get"]  # list_indexes() reads indexes.conf and searches the peers
AUDIT_INDEX = "_audit"


def retention_days(content):
    """frozenTimePeriodInSecs in whole days. 0 means freeze immediately; None means unreadable."""
    seconds = as_int(content.get("frozenTimePeriodInSecs"))
    return None if seconds is None or seconds < 0 else seconds // 86400


def archives_on_freeze(content):
    """Splunk deletes frozen data unless coldToFrozenDir or coldToFrozenScript archives it."""
    return any(str(content.get(key) or "").strip() for key in ("coldToFrozenDir", "coldToFrozenScript"))


def index_row(entry):
    c = entry["content"]
    return {
        "name": entry["name"],
        "datatype": c.get("datatype"),
        "enabled": not as_bool(c.get("disabled")),
        "internal": entry["name"].startswith("_"),
        "data_integrity_control": as_bool(c.get("enableDataIntegrityControl")),
        "retention_days": retention_days(c),
        "archives_on_freeze": archives_on_freeze(c),
        "cold_to_frozen_dir": c.get("coldToFrozenDir") or None,
        "max_total_size_mb": as_int(c.get("maxTotalDataSizeMB")),
        "app": (entry.get("acl") or {}).get("app"),
    }


def summarize(rows):
    retention = [r["retention_days"] for r in rows if r["retention_days"] is not None]
    return {
        "indexes_total": len(rows),
        "data_integrity_control_enabled": [r["name"] for r in rows if r["data_integrity_control"] is True],
        "data_integrity_control_disabled": [r["name"] for r in rows if r["data_integrity_control"] is False],
        "shortest_retention_days": min(retention) if retention else None,
        "indexes_archiving_on_freeze": [r["name"] for r in rows if r["archives_on_freeze"]],
        "audit_index": next((r for r in rows if r["name"] == AUDIT_INDEX), None),
    }


def collect(client, config):
    entries = client.list_indexes()
    if entries is None:
        return None
    rows = [index_row(e) for e in sorted(entries, key=lambda e: e["name"])]
    return {"summary": summarize(rows), "indexes": rows}


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CAPABILITIES))
