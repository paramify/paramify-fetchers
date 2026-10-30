#!/usr/bin/env python3
"""Sophos Central agent update status per endpoint: days since update, protection package status."""

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

OUTPUT_FILE = "sophos_agent_updates.json"


def item(ep: dict, now) -> dict:
    unread: dict = {}
    days = age(ep.get("lastAgentUpdateAt"), now, 86400)
    if days is None:
        unread["days_since_agent_update"] = ABSENT
    package = ((ep.get("packages") or {}).get("protection")) or {}
    status = package.get("status")
    if status:
        not_upgradable = status != "upgradable"
    else:
        not_upgradable = None
        unread["protection_package_not_upgradable"] = ABSENT
    products = ep.get("assignedProducts") if isinstance(ep.get("assignedProducts"), list) else []
    result = {
        **endpoint_identity(ep),
        "last_agent_update_at": ep.get("lastAgentUpdateAt"),
        "days_since_agent_update": days,
        "protection_package_name": package.get("name"),
        "protection_package_status": status,
        "protection_package_not_upgradable": not_upgradable,
        "assigned_product_versions": {p.get("code"): p.get("version") for p in products if p.get("code")},
    }
    if unread:
        result["unread_facts"] = unread
    return result


def collect(client, ledger, now):
    endpoints, reported_total = client.list_endpoints()
    items = [item(ep, now) for ep in endpoints]
    current, upgradable, package_unread = tally(items, "protection_package_not_upgradable")
    summary = {
        "total_endpoints": len(items),
        "endpoints_by_protection_package_status": count_by(items, "protection_package_status"),
        "endpoints_package_not_upgradable": current,
        "endpoints_package_upgradable": upgradable,
        "endpoints_package_unread": package_unread,
        "max_days_since_agent_update": largest(items, "days_since_agent_update"),
        "endpoints_agent_update_unread": sum(1 for i in items if i["days_since_agent_update"] is None),
    }
    return items, summary, {"collected": len(items), "reported_total": reported_total}


if __name__ == "__main__":
    raise SystemExit(run("sophos_agent_updates", OUTPUT_FILE, collect))
