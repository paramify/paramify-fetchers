"""Workspace ingestion queries and table classes shared by the Sentinel data-source and analytics-rule fetchers."""

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
