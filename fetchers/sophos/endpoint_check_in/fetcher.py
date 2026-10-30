#!/usr/bin/env python3
"""Sophos Central check-in status per endpoint: hours since last seen, and online now."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "_shared"))
from sophos_evidence import (  # noqa: E402
    ABSENT,
    age,
    count_by,
    endpoint_identity,
    largest,
    run,
    tally,
)

OUTPUT_FILE = "sophos_endpoint_check_in.json"


def item(ep: dict, now) -> dict:
    unread: dict = {}
    hours = age(ep.get("lastSeenAt"), now, 3600)
    if hours is None:
        unread["hours_since_last_seen"] = ABSENT
    online = ep.get("online")
    if not isinstance(online, bool):
        # A community report says Sophos sometimes leaves `online` out.
        online = None
        unread["online"] = ABSENT
    result = {
        **endpoint_identity(ep),
        "last_seen_at": ep.get("lastSeenAt"),
        "hours_since_last_seen": hours,
        "online": online,
        "isolation_status": (ep.get("isolation") or {}).get("status"),
        "lockdown_status": (ep.get("lockdown") or {}).get("status"),
    }
    if unread:
        result["unread_facts"] = unread
    return result


def collect(client, ledger, now):
    endpoints, reported_total = client.list_endpoints()
    items = [item(ep, now) for ep in endpoints]
    online, offline, online_unread = tally(items, "online")
    summary = {
        "total_endpoints": len(items),
        "endpoints_by_type": count_by(items, "type"),
        "endpoints_online": online,
        "endpoints_offline": offline,
        "endpoints_online_unread": online_unread,
        "max_hours_since_last_seen": largest(items, "hours_since_last_seen"),
        "endpoints_last_seen_unread": sum(1 for i in items if i["hours_since_last_seen"] is None),
    }
    return items, summary, {"collected": len(items), "reported_total": reported_total}


if __name__ == "__main__":
    raise SystemExit(run("sophos_endpoint_check_in", OUTPUT_FILE, collect))
