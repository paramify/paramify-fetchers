#!/usr/bin/env python3
"""
Wiz Scan Coverage

Lists every cloud account (AWS account, Azure subscription, GCP project) Wiz
knows about, with its connection status and last scan time, plus the Wiz
connectors that feed them.

Why this fetcher exists: every other Wiz fetcher reports what Wiz *found*. A
clean vulnerability or configuration summary is only meaningful if Wiz is
actually connected to, and recently scanning, every account in the boundary.
This is the evidence for that "ongoing basis" claim.

Speaks to KSI-PIY-GIV (inventory) and KSI-CNA-EIS (persistent automated
assessment). It reports coverage; it does not decide whether coverage is
complete, because only the customer knows which accounts are in the boundary.
"""

import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from wiz_client import (  # type: ignore  # noqa: E402
    WizClient,
    age_days,
    collect_guarded,
    env_int,
    evidence,
    run_fetcher,
)

logger = logging.getLogger("wiz_scan_coverage")

ACCOUNTS_QUERY = """
query WizCloudAccounts($first: Int, $after: String) {
  cloudAccounts(first: $first, after: $after) {
    nodes { id name cloudProvider status lastScannedAt resourceCount virtualMachineCount containerCount }
    pageInfo { hasNextPage endCursor }
  }
}
"""

CONNECTORS_QUERY = """
query WizConnectors($first: Int, $after: String) {
  connectors(first: $first, after: $after) {
    nodes { id name enabled status }
    pageInfo { hasNextPage endCursor }
  }
}
"""


HEALTH_QUERY = """
query WizSystemHealthIssues {
  systemHealthIssues(first: 1) { totalCount }
}
"""


def summarize(accounts: List[Dict[str, Any]], connectors: Optional[List[Dict[str, Any]]],
              stale_days: int, now: Optional[datetime] = None) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    rows = []
    for a in accounts:
        age = age_days(a.get("lastScannedAt"), now)
        rows.append({
            "id": a.get("id"),
            "name": a.get("name"),
            "cloud_provider": a.get("cloudProvider"),
            "status": a.get("status"),
            "last_scanned_at": a.get("lastScannedAt"),
            "days_since_last_scan": age,
            "resource_count": a.get("resourceCount"),
            "virtual_machine_count": a.get("virtualMachineCount"),
            "container_count": a.get("containerCount"),
        })

    not_connected = [r for r in rows if (r["status"] or "").upper() != "CONNECTED"]
    never_scanned = [r for r in rows if r["days_since_last_scan"] is None]
    stale = [r for r in rows if r["days_since_last_scan"] is not None and r["days_since_last_scan"] > stale_days]
    ages = [r["days_since_last_scan"] for r in rows if r["days_since_last_scan"] is not None]

    analysis: Dict[str, Any] = {
        "cloud_account_count": len(rows),
        "by_cloud_provider": dict(Counter(r["cloud_provider"] or "unknown" for r in rows)),
        "by_status": dict(Counter(r["status"] or "unknown" for r in rows)),
        "not_connected_count": len(not_connected),
        "not_connected_accounts": [{"name": r["name"], "status": r["status"]} for r in not_connected],
        "stale_scan_threshold_days": stale_days,
        "stale_scan_count": len(stale),
        "stale_scan_accounts": [{"name": r["name"], "last_scanned_at": r["last_scanned_at"]} for r in stale],
        "never_scanned_count": len(never_scanned),
        "max_days_since_last_scan": max(ages) if ages else None,
        "total_resources": sum(r["resource_count"] or 0 for r in rows),
        "total_virtual_machines": sum(r["virtual_machine_count"] or 0 for r in rows),
        "total_containers": sum(r["container_count"] or 0 for r in rows),
        "boundary_note": "Compare cloud_account_count and names against the authorization boundary; "
                         "an account missing here is not being scanned by Wiz.",
    }
    if connectors is not None:
        analysis["connector_count"] = len(connectors)
        analysis["connectors_by_status"] = dict(Counter(c.get("status") or "unknown" for c in connectors))
        disabled = [c.get("name") for c in connectors if c.get("enabled") is False]
        analysis["connectors_disabled_count"] = len(disabled)
        analysis["connectors_disabled"] = disabled
    return {"accounts": rows, "analysis": analysis}


def body(client: WizClient) -> Dict[str, Any]:
    stale_days = env_int("WIZ_STALE_SCAN_DAYS", 7)
    accounts = client.paginate("cloudAccounts", ACCOUNTS_QUERY, "cloudAccounts")
    raw_connectors = client.paginate("connectors", CONNECTORS_QUERY, "connectors")
    connectors = [{"id": c.get("id"), "name": c.get("name"), "enabled": c.get("enabled"),
                   "status": c.get("status")} for c in raw_connectors]
    result = summarize(accounts, connectors, stale_days)
    # System health issues are Wiz's own "your scanning is degraded" signals
    # (missing permissions, failed scans). Only the count is taken here.
    health = client.graphql("systemHealthIssues", HEALTH_QUERY)
    if health is not None:
        result["analysis"]["system_health_issue_count"] = (health.get("systemHealthIssues") or {}).get("totalCount")
    return evidence(
        client=client,
        operations=["cloudAccounts", "connectors", "systemHealthIssues"],
        records=result["accounts"],
        analysis=result["analysis"],
        empty_message="Wiz returned no cloud accounts. Either no cloud is connected to this tenant, "
                      "or the service account cannot see them (check read:cloud_accounts and project scope).",
        connectors=connectors,
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_scan_coverage.json", logger))
