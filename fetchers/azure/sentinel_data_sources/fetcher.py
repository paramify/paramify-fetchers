#!/usr/bin/env python3
"""Microsoft Sentinel data sources per workspace: data connectors, and which tables received data in the window."""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import (  # noqa: E402
    SI_API,
    int_config,
    iso_duration_days,
    run_workspaces,
)

NAME = "azure_sentinel_data_sources"
WINDOW_ENV = "SENTINEL_INGESTION_WINDOW_DAYS"
# Sentinel's own connector status calls a source connected if it ingested within 14 days.
DEFAULT_WINDOW_DAYS = 14

# Written by the workspace or by Sentinel itself (UEBA included), or agent liveness (Heartbeat): not monitored sources.
NON_SOURCE_TABLES = frozenset({
    "Usage", "Operation", "LAQueryLogs", "SentinelHealth", "SentinelAudit",
    "SecurityIncident", "Watchlist", "ConfidentialWatchlist",
    "Anomalies", "BehaviorAnalytics", "UserPeerAnalytics", "UserAccessAnalytics", "IdentityInfo",
    "Heartbeat",
})
# SecurityAlert holds both other products' alerts (each a source) and Sentinel's own analytics alerts (not one).
ALERTS_TABLE = "SecurityAlert"
SENTINEL_PRODUCTS = frozenset({"azure sentinel", "microsoft sentinel"})

INGESTION_QUERY = (
    "union withsource=ParamifySourceTable * "
    "| where TimeGenerated > ago({days}d) "
    "| summarize LastIngested = max(TimeGenerated), Records = count() by ParamifySourceTable"
)
ALERT_PRODUCTS_QUERY = (
    "SecurityAlert "
    "| where TimeGenerated > ago({days}d) "
    "| summarize LastIngested = max(TimeGenerated), Records = count() by ProductName"
)

logger = logging.getLogger(NAME)


def project_connector(connector: Dict[str, Any]) -> Dict[str, Any]:
    props = connector.get("properties") or {}
    data_types = {
        name: (value or {}).get("state")
        for name, value in sorted((props.get("dataTypes") or {}).items())
        if isinstance(value, dict)
    }
    return {
        "name": connector.get("name"),
        "kind": connector.get("kind"),
        "data_types": data_types,
        "enabled_data_types": [n for n, s in data_types.items() if (s or "").lower() == "enabled"],
        "is_active": props.get("isActive"),
        "tenant_id": props.get("tenantId"),
        "subscription_id": props.get("subscriptionId"),
    }


def project_tables(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    tables = [
        {
            "table": row.get("ParamifySourceTable"),
            "last_ingested": row.get("LastIngested"),
            "records": row.get("Records"),
            "counts_as_source": row.get("ParamifySourceTable") not in NON_SOURCE_TABLES | {ALERTS_TABLE},
        }
        for row in rows
        if row.get("ParamifySourceTable")
    ]
    return sorted(tables, key=lambda t: t["table"].lower())


def project_alert_products(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    products = [
        {
            "product": row.get("ProductName") or "unknown",
            "last_ingested": row.get("LastIngested"),
            "records": row.get("Records"),
            "counts_as_source": (row.get("ProductName") or "").lower() not in SENTINEL_PRODUCTS,
        }
        for row in rows
    ]
    return sorted(products, key=lambda p: p["product"].lower())


def collect(client, ws: Dict[str, Any], collector) -> Dict[str, Any]:
    days = int_config(WINDOW_ENV, DEFAULT_WINDOW_DAYS)
    connectors = collector.guard(
        f"securityinsights.dataConnectors.list({ws['name']})",
        lambda: client.list(f"{ws['id']}/providers/Microsoft.SecurityInsights/dataConnectors", SI_API),
    )
    rows = None
    if ws.get("customer_id"):
        rows = collector.guard(
            f"loganalytics.query(table ingestion, {ws['name']})",
            lambda: client.query(ws["customer_id"], INGESTION_QUERY.format(days=days), iso_duration_days(days)),
        )
    else:
        collector.record(f"workspace customerId ({ws['name']})", LookupError("workspace has no customerId to query"))

    tables = project_tables(rows) if rows is not None else None
    alert_rows = None
    if any(t["table"] == ALERTS_TABLE for t in tables or []):
        alert_rows = collector.guard(
            f"loganalytics.query(SecurityAlert products, {ws['name']})",
            lambda: client.query(ws["customer_id"], ALERT_PRODUCTS_QUERY.format(days=days), iso_duration_days(days)),
        )
    products = project_alert_products(alert_rows or [])
    sources = [t["table"] for t in tables or [] if t["counts_as_source"]]
    sources += [f"{ALERTS_TABLE} ({p['product']})" for p in products if p["counts_as_source"]]
    projected = [project_connector(c) for c in connectors or []]
    return {
        "ingestion_window_days": days,
        "data_connectors": sorted(projected, key=lambda c: ((c["kind"] or ""), (c["name"] or ""))),
        "data_connectors_total": len(projected) if connectors is not None else None,
        "tables": tables,
        "source_tables": sources if tables is not None else None,
        "sources_ingesting": len(sources) if tables is not None else None,
        "alert_products": products if tables is not None else None,
        "non_source_tables": [t["table"] for t in tables or [] if not t["counts_as_source"] and t["table"] != ALERTS_TABLE],
    }


def summarize(workspaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = [w.get("sources_ingesting") for w in workspaces if w.get("sources_ingesting") is not None]
    return {
        "min_sources_ingesting": min(counts) if counts else None,
        "workspaces_with_2plus_sources": sum(1 for c in counts if c >= 2),
        "workspaces_with_no_sources": sum(1 for c in counts if c == 0),
        "data_connectors_total": sum(w.get("data_connectors_total") or 0 for w in workspaces),
    }


def main() -> int:
    return run_workspaces(fetcher=NAME, logger=logger, collect=collect, summarize=summarize)


if __name__ == "__main__":
    sys.exit(main())
