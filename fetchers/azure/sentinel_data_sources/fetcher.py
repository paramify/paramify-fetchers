#!/usr/bin/env python3
"""Microsoft Sentinel data sources per workspace: data connectors with their last data received, and which tables received data in the window."""

import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import (  # noqa: E402
    LAW_API,
    SI_API,
    SI_PREVIEW_API,
    QueryError,
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
# Cloud Discovery logs are an opt-in extra on the Defender for Cloud Apps connector, which otherwise sends only alerts.
ALERT_ONLY_EXTRAS = frozenset({"McasShadowItReporting"})
SENTINEL_PRODUCTS = frozenset({"azure sentinel", "microsoft sentinel"})
HEALTH_TABLE = "SentinelHealth"
# Worst first for a connector fed by several connections; any other status, null included, sits between Warning and Success.
HEALTH_RANK = {"failure": 3, "warning": 2, "success": 0}

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
HEALTH_QUERY = (
    "SentinelHealth "
    "| where TimeGenerated > ago({days}d) and SentinelResourceType == 'Data connector' "
    "| summarize arg_max(TimeGenerated, Status, Reason, Description, SentinelResourceKind, SentinelResourceName) "
    "by SentinelResourceId"
)

# Connector definitions installed from Content Hub come back from the preview listing as these kinds.
UI_KINDS = frozenset({"StaticUI", "GenericUI"})
LAST_DATA_SUFFIX = "\n| summarize Time = max(TimeGenerated)\n| where isnotempty(Time)"
_BARE_TABLE = re.compile(
    r"^\s*([A-Za-z_]\w*)\s*\|\s*summarize\s+Time\s*=\s*max\(\s*TimeGenerated\s*\)\s*\|\s*where\s+isnotempty\(\s*Time\s*\)\s*$"
)
_FIRST_NAME = re.compile(r"[A-Za-z_]\w*")
# Words that open a query without naming its table.
_KQL_OPENERS = frozenset({
    "union", "let", "search", "find", "print", "range", "datatable", "table", "materialize", "evaluate",
    "externaldata", "external_table",
})
QUERY_BATCH = 100
# Basic and Auxiliary tables answer only /search: union * on /query skips them, and naming one fails to resolve.
QUERYABLE_PLAN = "Analytics"

# Connection kinds whose Content Hub definition has another id: this kind is Entra ID Protection, not the Entra ID logs connector.
KIND_DEFINITION = {"AzureActiveDirectory": "AzureActiveDirectoryIdentityProtection"}
DEFENDER_XDR_ALERT_PRODUCTS = (
    '"Microsoft Defender Advanced Threat Protection", "Office 365 Advanced Threat Protection", '
    '"Azure Advanced Threat Protection", "Microsoft Cloud App Security", "Microsoft 365 Defender", "Microsoft Defender XDR"'
)

# Built-in connection kinds and what they fill, for a connection whose connector definition isn't installed.
BUILT_IN_DATA_TYPES: Dict[str, List[Tuple[str, str]]] = {
    "AzureActiveDirectory": [("SecurityAlert (IPC)", 'SecurityAlert | where ProductName == "Azure Active Directory Identity Protection"')],
    "AzureAdvancedThreatProtection": [("SecurityAlert (AATP)", 'SecurityAlert | where ProductName == "Azure Advanced Threat Protection"')],
    "AzureSecurityCenter": [("SecurityAlert (ASC)", 'SecurityAlert | where ProductName == "Azure Security Center"')],
    "IOT": [("SecurityAlert (ASC for IoT)", 'SecurityAlert | where ProductName == "Azure Security Center for IoT"')],
    "MicrosoftCloudAppSecurity": [
        ("SecurityAlert (MCAS)", 'SecurityAlert | where ProductName == "Microsoft Cloud App Security"'),
        ("McasShadowItReporting", "McasShadowItReporting"),
    ],
    "MicrosoftDefenderAdvancedThreatProtection": [("SecurityAlert (MDATP)", 'SecurityAlert | where ProviderName == "MDATP"')],
    "OfficeATP": [("SecurityAlert (OATP)", 'SecurityAlert | where ProviderName == "OATP"')],
    "OfficeIRM": [("SecurityAlert (OfficeIRM)", 'SecurityAlert | where ProductName == "Microsoft 365 Insider Risk Management"')],
    "Office365": [
        ("OfficeActivity (Exchange)", 'OfficeActivity | where OfficeWorkload == "Exchange"'),
        ("OfficeActivity (SharePoint)", 'OfficeActivity | where OfficeWorkload in ("SharePoint", "OneDrive")'),
        ("OfficeActivity (Teams)", 'OfficeActivity | where OfficeWorkload == "MicrosoftTeams"'),
    ],
    "MicrosoftThreatProtection": [
        ("SecurityIncident", 'SecurityIncident | where ProviderName in ("Microsoft 365 Defender", "Microsoft XDR")'),
        ("SecurityAlert", f"SecurityAlert | where ProductName in ({DEFENDER_XDR_ALERT_PRODUCTS})"),
    ],
    "ThreatIntelligence": [("ThreatIntelligenceIndicator", "ThreatIntelligenceIndicator")],
    "ThreatIntelligenceTaxii": [("ThreatIntelligenceIndicator", "ThreatIntelligenceIndicator")],
    "MicrosoftThreatIntelligence": [("ThreatIntelligenceIndicator", "ThreatIntelligenceIndicator")],
    "AmazonWebServicesCloudTrail": [("AWSCloudTrail", "AWSCloudTrail")],
    "Dynamics365": [("Dynamics365Activity", "Dynamics365Activity")],
    "OfficePowerBI": [("PowerBIActivity", "PowerBIActivity")],
    "Office365Project": [("ProjectActivity", "ProjectActivity")],
    "MicrosoftPurviewInformationProtection": [("MicrosoftPurviewInformationProtection", "MicrosoftPurviewInformationProtection")],
}

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


def connections(stable: List[Dict[str, Any]], preview: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Configured connections from both listings, merged by name; the stable listing omits kinds such as MicrosoftThreatProtection."""
    merged: Dict[str, Dict[str, Any]] = {}
    for listing, raw in (("stable", stable), ("preview", preview or [])):
        for c in raw:
            if c.get("kind") in UI_KINDS:
                continue
            key = (c.get("name") or "").lower()
            if key in merged:
                merged[key]["seen_in"].append(listing)
            else:
                merged[key] = {**project_connector(c), "seen_in": [listing], "_raw": c}
    return sorted(merged.values(), key=lambda c: ((c["kind"] or ""), (c["name"] or "")))


def query_table(query: str) -> Optional[str]:
    first = _FIRST_NAME.search(query)
    return first.group(0) if first and first.group(0).lower() not in _KQL_OPENERS else None


def definition_of(kind: Optional[str]) -> Optional[str]:
    return KIND_DEFINITION.get(kind or "", kind)


def definition_data_types(ui: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(name, last-data query) per data type; a codeless definition's {{graphQueriesTableName}} is filled in."""
    out = []
    for dt in ui.get("dataTypes") or []:
        query = (dt.get("lastDataReceivedQuery") or "").replace("\u200b", "")
        query = query.replace("{{graphQueriesTableName}}", ui.get("graphQueriesTableName") or "{{graphQueriesTableName}}")
        if dt.get("name") and query and "{{" not in query:
            out.append((dt["name"], query))
    return out


def link(definition: Dict[str, Any], conns: List[Dict[str, Any]]) -> List[str]:
    """Connections that feed a definition: one of its kind, one built from it, or Defender XDR carrying its alerts."""
    name = (definition.get("name") or "").lower()
    criteria = (definition.get("properties") or {}).get("connectorUiConfig") or {}
    criteria = criteria.get("connectivityCriterias") or criteria.get("connectivityCriteria") or []
    mtp_alerts = any(c.get("type") == "MtpAlerts" for c in criteria if isinstance(c, dict))
    linked = []
    for c in conns:
        props = (c["_raw"].get("properties") or {})
        if (
            (definition_of(c["kind"]) or "").lower() == name
            or (props.get("connectorDefinitionName") or "").lower() == name
            or (mtp_alerts and c["kind"] == "MicrosoftThreatProtection" and "alerts" in c["enabled_data_types"])
        ):
            linked.append(c["name"])
    return sorted(linked)


def connector_catalog(
    preview: Optional[List[Dict[str, Any]]], definitions: List[Dict[str, Any]], conns: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Every installed connector definition, plus each built-in connection whose definition isn't installed."""
    catalog = []
    for source, raw in (("content_hub", [c for c in preview or [] if c.get("kind") in UI_KINDS]), ("codeless", definitions)):
        for d in raw:
            ui = (d.get("properties") or {}).get("connectorUiConfig") or {}
            catalog.append({
                "id": d.get("name"),
                "title": ui.get("title"),
                "definition": source,
                "connections": link(d, conns),
                "_data_types": definition_data_types(ui),
            })
    defined = {(c["id"] or "").lower() for c in catalog if c["id"]}
    built_in: Dict[str, Dict[str, Any]] = {}
    for c in conns:
        definition = ((c["_raw"].get("properties") or {}).get("connectorDefinitionName") or "").lower()
        kind_id = definition_of(c["kind"])
        if (kind_id or "").lower() in defined or (definition and definition in defined):
            continue
        entry = built_in.setdefault((kind_id or "").lower(), {
            "id": kind_id,
            "title": None,
            "definition": "built_in" if c["kind"] in BUILT_IN_DATA_TYPES else "unknown",
            "connections": [],
            "_data_types": [(n, q + LAST_DATA_SUFFIX) for n, q in BUILT_IN_DATA_TYPES.get(c["kind"] or "", [])],
        })
        entry["connections"].append(c["name"])
    return sorted(catalog + list(built_in.values()), key=lambda c: (c["id"] or "").lower())


Pending = List[Tuple[Tuple[int, int], str, str]]


def last_data_queries(
    catalog: List[Dict[str, Any]], ingested: Dict[str, Any], plans: Optional[Dict[str, str]]
) -> Tuple[Dict[Tuple[int, int], Any], Pending]:
    """Answers taken straight from table ingestion, and the queries still to run; a table on a plan /query can't read is left unmeasured."""
    known: Dict[Tuple[int, int], Any] = {}
    pending = []
    for ci, c in enumerate(catalog):
        for di, (name, query) in enumerate(c["_data_types"]):
            table = query_table(query)
            plan = (plans or {}).get(table or "")
            if table in ingested and _BARE_TABLE.match(query):
                known[(ci, di)] = ingested[table]
            elif plan == QUERYABLE_PLAN and table not in ingested:
                known[(ci, di)] = None
            elif plan in (None, QUERYABLE_PLAN):  # parser functions, union and let queries run as written
                pending.append(((ci, di), query, f"{c['id']}: {name}"))
    return known, pending


def run_last_data(client, customer_id: str, pending: Pending, days: int, notes: List[str]) -> Dict[Tuple[int, int], Any]:
    """One union per batch; a 400 means a definition's query is malformed, so that batch is retried one query at a time."""
    found: Dict[Tuple[int, int], Any] = {key: None for key, _, _ in pending}

    def union(batch):
        parts = [f"({q}\n| extend ParamifyIndex = {i})" for i, (_, q, _) in enumerate(batch)]
        rows = client.query(customer_id, "union isfuzzy=true " + ",\n".join(parts), iso_duration_days(days))
        for row in rows:
            found[batch[int(row["ParamifyIndex"])][0]] = row.get("Time")

    for start in range(0, len(pending), QUERY_BATCH):
        batch = pending[start:start + QUERY_BATCH]
        try:
            union(batch)
        except QueryError as exc:
            if not exc.code.startswith("(400)"):
                raise
            for item in batch:
                try:
                    union([item])
                except QueryError as one:
                    if not one.code.startswith("(400)"):
                        raise
                    found.pop(item[0])
                    notes.append(f"last-data query for {item[2]} failed, so it reads as unmeasured: {one}")
    return found


def finish_catalog(catalog: List[Dict[str, Any]], answers: Optional[Dict[Tuple[int, int], Any]], health: Dict[str, Dict[str, Any]], conns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ids = {c["name"]: (c["_raw"].get("id") or "").lower() for c in conns}
    out = []
    for ci, c in enumerate(catalog):
        data_types = [
            {
                "name": name,
                "table": query_table(query),
                "last_data_received": answers.get((ci, di)) if answers is not None else None,
            }
            for di, (name, query) in enumerate(c["_data_types"])
        ]
        times = [d["last_data_received"] for d in data_types if d["last_data_received"]]
        tables = {d["table"] for d in data_types}
        unmeasured = answers is None or any((ci, di) not in answers for di in range(len(data_types)))
        rows = [health[ids[n]] for n in c["connections"] if ids.get(n) and ids[n] in health]
        worst = max(rows, key=lambda r: HEALTH_RANK.get((r["status"] or "").lower(), 1), default=None)
        out.append({
            **{k: v for k, v in c.items() if not k.startswith("_")},
            "data_types": data_types,
            # No alert in the window is normal for these, so they read as quiet rather than not connected.
            "alert_only": ALERTS_TABLE in tables and tables <= {ALERTS_TABLE} | ALERT_ONLY_EXTRAS,
            "last_data_received": max(times) if times else None,
            "connected": True if times else (None if unmeasured or not data_types else False),
            "health_status": worst["status"] if worst else None,
        })
    return out


def project_health(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        (
            {
                "resource_name": r.get("SentinelResourceName"),
                "resource_id": r.get("SentinelResourceId"),
                "kind": r.get("SentinelResourceKind"),
                "status": r.get("Status"),
                "reason": r.get("Reason"),
                "description": r.get("Description"),
                "status_time": r.get("TimeGenerated"),
            }
            for r in rows
        ),
        key=lambda h: (h["resource_name"] or "").lower(),
    )


def collect(client, ws: Dict[str, Any], collector) -> Dict[str, Any]:
    days = int_config(WINDOW_ENV, DEFAULT_WINDOW_DAYS)
    path = f"{ws['id']}/providers/Microsoft.SecurityInsights"
    notes: List[str] = []
    connectors = collector.guard(
        f"securityinsights.dataConnectors.list({ws['name']})", lambda: client.list(f"{path}/dataConnectors", SI_API)
    )
    preview = None
    try:
        preview = client.list(f"{path}/dataConnectors", SI_PREVIEW_API)
    except Exception as exc:  # noqa: BLE001 — adds Content Hub definitions and kinds the stable listing omits
        notes.append(f"preview listing at {SI_PREVIEW_API} failed, so Content Hub connectors and preview-only kinds may be missing: {exc}")
    definitions = collector.guard(
        f"securityinsights.dataConnectorDefinitions.list({ws['name']})",
        lambda: client.list(f"{path}/dataConnectorDefinitions", SI_API),
    )
    listed = collector.guard(
        f"operationalinsights.tables.list({ws['name']})", lambda: client.list(f"{ws['id']}/tables", LAW_API)
    )
    plans = (
        {t["name"]: (t.get("properties") or {}).get("plan") or QUERYABLE_PLAN for t in listed if t.get("name")}
        if listed is not None else None
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

    conns = connections(connectors, preview) if connectors is not None else []
    catalog = connector_catalog(preview, definitions or [], conns)
    for c in catalog:
        if c["definition"] in ("content_hub", "codeless") and not c["_data_types"]:
            notes.append(f"connector {c['id']} has no data type with a usable last-data query, so it reads as unmeasured")
    complete = connectors is not None and preview is not None and definitions is not None
    answers = None
    found: Optional[Dict[Tuple[int, int], Any]] = {}
    if tables is not None:
        ingested = {t["table"]: t["last_ingested"] for t in tables}
        known, pending = last_data_queries(catalog, ingested, plans)
        found = collector.guard(
            f"loganalytics.query(connector last data, {ws['name']})",
            lambda: run_last_data(client, ws["customer_id"], pending, days, notes),
        ) if pending else {}
        # Without the table plans, an empty answer may be a Basic table /query can't read.
        answers = {k: v for k, v in {**known, **(found or {})}.items() if v or plans is not None}
    # A failed last-data query leaves the counts unknown, not partial.
    measured = answers is not None and found is not None and plans is not None and complete
    health_on = any(t["table"] == HEALTH_TABLE for t in tables or []) if tables is not None else None
    health_rows = None
    if health_on:
        health_rows = collector.guard(
            f"loganalytics.query(SentinelHealth connectors, {ws['name']})",
            lambda: client.query(ws["customer_id"], HEALTH_QUERY.format(days=days), iso_duration_days(days)),
        )
    health = project_health(health_rows) if health_rows is not None else None
    by_id = {(h["resource_id"] or "").lower(): h for h in health or []}
    finished = finish_catalog(catalog, answers, by_id, conns)
    projected = [{k: v for k, v in c.items() if k != "_raw"} for c in conns]
    return {
        "ingestion_window_days": days,
        "data_connectors": projected,
        "data_connectors_total": len(projected) if connectors is not None and preview is not None else None,
        "connectors": finished,
        "connectors_total": len(finished) if complete else None,
        "connectors_connected": sum(1 for c in finished if c["connected"] is True) if measured else None,
        "connectors_not_connected": (
            [c["id"] for c in finished if c["connected"] is False and not c["alert_only"]] if measured else None
        ),
        "connectors_quiet": [c["id"] for c in finished if c["connected"] is False and c["alert_only"]] if measured else None,
        "health_monitoring": health_on,
        "connector_health": health,
        "connectors_unhealthy": (
            sum(1 for h in health if (h["status"] or "").lower() != "success") if health is not None else None
        ),
        "tables": tables,
        "tables_not_measured": sorted(n for n, p in plans.items() if p != QUERYABLE_PLAN) if plans is not None else None,
        "source_tables": sources if tables is not None else None,
        "sources_ingesting": len(sources) if tables is not None else None,
        "alert_products": products if tables is not None else None,
        "non_source_tables": [t["table"] for t in tables or [] if not t["counts_as_source"] and t["table"] != ALERTS_TABLE],
        "notes": notes,
    }


def _total(workspaces: List[Dict[str, Any]], field: str) -> Optional[int]:
    """Sum over the workspaces that have the field; None when none does, so an unknown never reads as zero."""
    values = [w[field] for w in workspaces if w.get(field) is not None]
    return sum(len(v) if isinstance(v, list) else v for v in values) if values else None


def summarize(workspaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = [w.get("sources_ingesting") for w in workspaces if w.get("sources_ingesting") is not None]
    return {
        "min_sources_ingesting": min(counts) if counts else None,
        "workspaces_with_2plus_sources": sum(1 for c in counts if c >= 2),
        "workspaces_with_no_sources": sum(1 for c in counts if c == 0),
        "data_connectors_total": _total(workspaces, "data_connectors_total"),
        "connectors_connected": _total(workspaces, "connectors_connected"),
        "connectors_not_connected": _total(workspaces, "connectors_not_connected"),
        "connectors_quiet": _total(workspaces, "connectors_quiet"),
        "workspaces_with_health_monitoring": sum(1 for w in workspaces if w.get("health_monitoring") is True),
        "connectors_unhealthy": _total(workspaces, "connectors_unhealthy"),
    }


def main() -> int:
    return run_workspaces(fetcher=NAME, logger=logger, collect=collect, summarize=summarize)


if __name__ == "__main__":
    sys.exit(main())
