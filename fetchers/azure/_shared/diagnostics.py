"""Per-resource Azure Monitor diagnostic settings: categories, projection and whether audit logs reach a sink."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from azure_common import basename, model_attr

DESTINATION_STORAGE_ACCOUNT = "storage_account"
DESTINATION_LOG_ANALYTICS = "log_analytics_workspace"
DESTINATION_EVENT_HUB = "event_hub"
DESTINATION_PARTNER_SOLUTION = "partner_solution"

CATEGORY_TYPE_LOGS = "Logs"
CATEGORY_TYPE_METRICS = "Metrics"

# Category groups that include every audit category, whatever the resource type.
AUDIT_CATEGORY_GROUPS = ("audit", "allLogs")


def resource_uri(resource_id: str) -> str:
    """The SDK substitutes this unquoted after a "/", so a leading slash doubles it."""
    return (resource_id or "").lstrip("/")


def project_category(category: Any) -> Dict[str, Any]:
    """One `DiagnosticSettingsCategoryResource` (6.x flattens `properties`)."""
    return {
        "name": model_attr(category, "name"),
        "category_type": model_attr(category, "category_type"),
        "category_groups": list(model_attr(category, "category_groups") or []),
    }


def project_diagnostic_setting(setting: Any) -> Dict[str, Any]:
    """azure-mgmt-monitor 6.x flattens `properties.*` onto DiagnosticSettingsResource."""
    return {
        "id": model_attr(setting, "id"),
        "name": model_attr(setting, "name") or basename(model_attr(setting, "id")),
        "storage_account_id": model_attr(setting, "storage_account_id"),
        "workspace_id": model_attr(setting, "workspace_id"),
        "event_hub_name": model_attr(setting, "event_hub_name"),
        "event_hub_authorization_rule_id": model_attr(setting, "event_hub_authorization_rule_id"),
        "marketplace_partner_id": model_attr(setting, "marketplace_partner_id"),
        "log_analytics_destination_type": model_attr(setting, "log_analytics_destination_type"),
        "logs": [
            {
                "category": model_attr(log, "category"),
                "category_group": model_attr(log, "category_group"),
                # ARM omits `enabled` on a category never selected; absent means off.
                "enabled": bool(model_attr(log, "enabled") or False),
            }
            for log in (model_attr(setting, "logs") or [])
        ],
    }


def diagnostic_destinations(setting: Dict[str, Any]) -> List[str]:
    found = []
    if setting.get("storage_account_id"):
        found.append(DESTINATION_STORAGE_ACCOUNT)
    if setting.get("workspace_id"):
        found.append(DESTINATION_LOG_ANALYTICS)
    if setting.get("event_hub_authorization_rule_id") or setting.get("event_hub_name"):
        found.append(DESTINATION_EVENT_HUB)
    if setting.get("marketplace_partner_id"):
        found.append(DESTINATION_PARTNER_SOLUTION)
    return found


def enabled_categories(logs: List[Dict[str, Any]]) -> List[str]:
    return sorted({log["category"] for log in logs if log["enabled"] and log["category"]})


def enabled_category_groups(logs: List[Dict[str, Any]]) -> List[str]:
    return sorted({log["category_group"] for log in logs if log["enabled"] and log["category_group"]})


def diagnostic_setting_record(setting: Dict[str, Any], audit_categories: Iterable[str]) -> Dict[str, Any]:
    """A setting with no destination captures nothing, whatever its categories say."""
    audit_categories = set(audit_categories)
    logs = [
        {
            "category": log.get("category"),
            "category_group": log.get("category_group"),
            "enabled": bool(log.get("enabled") or False),
        }
        for log in (setting.get("logs") or [])
    ]
    destinations = diagnostic_destinations(setting)
    captured = sorted(
        {
            category
            for log in logs
            if log["enabled"]
            for category in (
                audit_categories if log["category_group"] in AUDIT_CATEGORY_GROUPS
                else ({log["category"]} & audit_categories)
            )
        }
    ) if destinations else []
    return {**{k: setting.get(k) for k in (
        "id", "name", "storage_account_id", "workspace_id", "event_hub_name",
        "event_hub_authorization_rule_id", "marketplace_partner_id")},
        "destinations": destinations,
        "logs": logs,
        "audit_categories_captured": captured,
    }


def audit_logging_summary(settings: Optional[List[Dict[str, Any]]], audit_categories: Iterable[str]) -> Dict[str, Any]:
    """`settings` None (read failed) gives audit_logging_enabled None — unknown, never "not logged"."""
    if settings is None:
        return {
            "diagnostic_settings": None,
            "audit_logging_enabled": None,
            "audit_categories_captured": [],
            "audit_log_destinations": [],
        }
    records = sorted(
        (diagnostic_setting_record(s, audit_categories) for s in settings), key=lambda r: r.get("id") or ""
    )
    auditing = [r for r in records if r["audit_categories_captured"]]
    return {
        "diagnostic_settings": records,
        "audit_logging_enabled": bool(auditing),
        "audit_categories_captured": sorted({c for r in auditing for c in r["audit_categories_captured"]}),
        "audit_log_destinations": [
            {"type": kind, "resource_id": resource_id}
            for kind, resource_id in sorted({
                (kind, resource_id)
                for r in auditing
                for kind, resource_id in (
                    (DESTINATION_STORAGE_ACCOUNT, r["storage_account_id"]),
                    (DESTINATION_LOG_ANALYTICS, r["workspace_id"]),
                    (DESTINATION_EVENT_HUB, r["event_hub_authorization_rule_id"] or r["event_hub_name"]),
                    (DESTINATION_PARTNER_SOLUTION, r["marketplace_partner_id"]),
                )
                if resource_id
            })
        ],
    }


def list_diagnostic_settings(monitor_client: Any, resource_id: str) -> List[Dict[str, Any]]:
    """Raises for the caller's guard."""
    return [project_diagnostic_setting(s) for s in monitor_client.diagnostic_settings.list(resource_id)]
