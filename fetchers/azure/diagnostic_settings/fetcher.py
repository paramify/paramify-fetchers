#!/usr/bin/env python3
"""Azure Activity Log export: the SUBSCRIPTION-scope diagnostic settings, the log
categories each has on, and where it sends them.

Ported from prowler/providers/azure/services/monitor/monitor_service.py (Apache-2.0).
Without a setting the Activity Log is retained 90 days and then gone. Requires
azure-mgmt-monitor<7: 7.0.0 ships no diagnostic-settings operations and no Diagnostic*
models at all (verified against both releases), so this would collect nothing. Scope is
the subscription only — `diagnostic_settings.list()` takes one resource URI, and
per-resource settings belong to that service's own evidence set.
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_diagnostic_settings")

# Reported in full: an absent category means "not selected", not "unavailable".
ACTIVITY_LOG_CATEGORIES = (
    "Administrative",
    "Security",
    "ServiceHealth",
    "Alert",
    "Recommendation",
    "Policy",
    "Autoscale",
    "ResourceHealth",
)

# The four monitor_diagnostic_setting_with_appropriate_categories wants on ONE
# setting — CIS Azure 5.1.2's "appropriate categories".
REQUIRED_LOG_CATEGORIES = ("Administrative", "Security", "Alert", "Policy")

# A setting must have at least one; ARM omits the id of every destination not in use.
DESTINATION_STORAGE_ACCOUNT = "storage_account"
DESTINATION_LOG_ANALYTICS = "log_analytics_workspace"
DESTINATION_EVENT_HUB = "event_hub"
DESTINATION_PARTNER_SOLUTION = "partner_solution"

# Prowler's exact resource URI for subscription scope: no leading slash (the SDK
# builds "/{resourceUri}/providers/Microsoft.Insights/diagnosticSettings").
SUBSCRIPTION_SCOPE_URI = "subscriptions/{subscription_id}/"


# --- projection: the only code that touches an azure-mgmt model ---

def project_log_settings(log) -> dict:
    """Read one `LogSettings` model into a flat dict.

    Exactly one of `category` / `category_group` is populated per entry.
    `retention_policy` is ARM's legacy per-setting retention — retired in favour of the
    destination's own, still returned, emitted so a reader sees the 0.
    """
    retention = model_attr(log, "retention_policy")
    return {
        "category": model_attr(log, "category"),
        "category_group": model_attr(log, "category_group"),
        "enabled": model_attr(log, "enabled"),
        "retention_policy": {
            "enabled": model_attr(retention, "enabled"),
            "days": model_attr(retention, "days"),
        },
    }


def project_diagnostic_setting(setting) -> dict:
    """Read a `DiagnosticSettingsResource` model's attributes into a flat dict.

    azure-mgmt-monitor 6.x is msrest-generated and FLATTENS `properties.*` onto the
    model (`storage_account_id` maps to `properties.storageAccountId`), verified
    against the installed SDK's `_attribute_map`.
    """
    setting_id = model_attr(setting, "id")
    return {
        "id": setting_id,
        # Prowler derives this from the id's last segment; the SDK's own `name` wins.
        "name": model_attr(setting, "name") or basename(setting_id),
        "storage_account_id": model_attr(setting, "storage_account_id"),
        "workspace_id": model_attr(setting, "workspace_id"),
        "event_hub_name": model_attr(setting, "event_hub_name"),
        "event_hub_authorization_rule_id": model_attr(
            setting, "event_hub_authorization_rule_id"
        ),
        "service_bus_rule_id": model_attr(setting, "service_bus_rule_id"),
        "marketplace_partner_id": model_attr(setting, "marketplace_partner_id"),
        "log_analytics_destination_type": model_attr(setting, "log_analytics_destination_type"),
        "logs": [project_log_settings(log) for log in (model_attr(setting, "logs") or [])],
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def log_record(log: dict) -> dict:
    """Normalize one projected log selection.

    `enabled` is coerced: ARM omits it on a category never selected, and absent means
    off — a validator asserting `false` would not match `null`.
    """
    retention = log.get("retention_policy") or {}
    return {
        "category": log.get("category"),
        "category_group": log.get("category_group"),
        "enabled": bool(log.get("enabled") or False),
        "retention_policy": {
            "enabled": bool(retention.get("enabled") or False),
            "days": int(retention.get("days") or 0),
        },
    }


def destinations(setting: dict) -> list[str]:
    """Which sinks this setting exports to, in a stable order.

    Ids, not resolved: a destination in another subscription still returns its id.
    """
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


def enabled_categories(logs: list[dict]) -> list[str]:
    """The category names this setting actually captures, sorted.

    A group selection captures categories without naming them, so groups are reported
    separately rather than expanded by guesswork.
    """
    return sorted({log["category"] for log in logs if log["enabled"] and log["category"]})


def enabled_category_groups(logs: list[dict]) -> list[str]:
    return sorted({log["category_group"] for log in logs if log["enabled"] and log["category_group"]})


def diagnostic_setting_record(setting: dict) -> dict:
    """Normalize one projected diagnostic setting into an evidence record."""
    logs = [log_record(log) for log in (setting.get("logs") or [])]
    categories = enabled_categories(logs)
    groups = enabled_category_groups(logs)
    # "allLogs" selects every category including the required four (how most
    # portal-created settings look); ignoring it reports a logged subscription as not.
    captures_all = "allLogs" in groups

    return {
        "id": setting.get("id"),
        "name": setting.get("name"),
        "storage_account_id": setting.get("storage_account_id"),
        "storage_account_name": basename(setting.get("storage_account_id")),
        "workspace_id": setting.get("workspace_id"),
        "workspace_name": basename(setting.get("workspace_id")),
        "event_hub_name": setting.get("event_hub_name"),
        "event_hub_authorization_rule_id": setting.get("event_hub_authorization_rule_id"),
        "service_bus_rule_id": setting.get("service_bus_rule_id"),
        "marketplace_partner_id": setting.get("marketplace_partner_id"),
        "log_analytics_destination_type": setting.get("log_analytics_destination_type"),
        "destinations": destinations(setting),
        "logs": logs,
        "enabled_log_categories": categories,
        "enabled_log_category_groups": groups,
        "captures_all_log_categories": captures_all,
        "missing_required_log_categories": (
            []
            if captures_all
            else [c for c in REQUIRED_LOG_CATEGORIES if c not in categories]
        ),
        "captures_required_log_categories": captures_all
        or all(c in categories for c in REQUIRED_LOG_CATEGORIES),
    }


def category_coverage(settings: list[dict]) -> dict:
    """Which Activity Log categories are captured by ANY setting.

    The union across settings, not per setting: Administrative to a storage account and
    Security to a workspace still captures both. Prowler's stricter one-setting reading
    is `settings_capturing_required_categories`.
    """
    captures_all = any(s["captures_all_log_categories"] for s in settings)
    covered = {c for s in settings for c in s["enabled_log_categories"]}
    return {
        category: captures_all or category in covered for category in ACTIVITY_LOG_CATEGORIES
    }


def summarize(settings: list[dict]) -> dict:
    """Whether the Activity Log is exported at all, and whether it is complete."""
    coverage = category_coverage(settings)
    required_covered = [c for c in REQUIRED_LOG_CATEGORIES if coverage.get(c)]
    return {
        "total_diagnostic_settings": len(settings),
        "activity_log_exported": bool(settings),
        "settings_with_storage_account": sum(
            1 for s in settings if DESTINATION_STORAGE_ACCOUNT in s["destinations"]
        ),
        "settings_with_log_analytics_workspace": sum(
            1 for s in settings if DESTINATION_LOG_ANALYTICS in s["destinations"]
        ),
        "settings_with_event_hub": sum(
            1 for s in settings if DESTINATION_EVENT_HUB in s["destinations"]
        ),
        "settings_with_partner_solution": sum(
            1 for s in settings if DESTINATION_PARTNER_SOLUTION in s["destinations"]
        ),
        "log_category_coverage": coverage,
        "required_log_categories": list(REQUIRED_LOG_CATEGORIES),
        "covered_required_log_categories": len(required_covered),
        "required_log_category_percentage": coverage_percentage(
            len(required_covered), len(REQUIRED_LOG_CATEGORIES)
        ),
        "all_required_log_categories_covered": len(required_covered)
        == len(REQUIRED_LOG_CATEGORIES),
        # Prowler's stricter reading: ONE setting carrying all four categories.
        "settings_capturing_required_categories": sum(
            1 for s in settings if s["captures_required_log_categories"]
        ),
        "settings_with_legacy_retention": sum(
            1
            for s in settings
            if any(log["retention_policy"]["enabled"] for log in s["logs"])
        ),
    }


# --- collection (lazy azure imports) ---

def collect_diagnostic_settings(subscription_id, cred, collector: Collector) -> list[dict]:
    """One diagnostic_settings.list() at subscription scope."""
    from azure.mgmt.monitor import MonitorManagementClient

    def _client():
        return MonitorManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("monitor.MonitorManagementClient (init)", _client)
    if client is None:
        return []

    # azure-mgmt-monitor 7.0.0 dropped this operation group; without the check the
    # failure would read as an opaque AttributeError instead of naming the fix.
    if getattr(client, "diagnostic_settings", None) is None:
        collector.record(
            "monitor.diagnostic_settings.list",
            RuntimeError(
                "the installed azure-mgmt-monitor has no diagnostic_settings "
                "operation group (removed in 7.0.0) — pin azure-mgmt-monitor<7"
            ),
        )
        return []

    def _list():
        # Subscription scope returns one page; the SDK follows nextLink regardless.
        return [
            diagnostic_setting_record(project_diagnostic_setting(s))
            for s in client.diagnostic_settings.list(
                resource_uri=SUBSCRIPTION_SCOPE_URI.format(subscription_id=subscription_id)
            )
        ]

    settings = collector.guard("monitor.diagnostic_settings.list", _list, default=[])
    return sorted(settings, key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request header at INFO; warnings still get through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    settings: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # ARM returns an empty list, not an error, for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Insights"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Insights is not registered on subscription %s — no "
                "diagnostic settings can exist; reporting status not_registered",
                subscription_id,
            )
        settings = collect_diagnostic_settings(subscription_id, cred, collector)
        if not settings and collector.ok:
            logger.warning(
                "No subscription-scope diagnostic setting on %s — the Activity Log "
                "is not exported and is retained for 90 days only",
                subscription_id,
            )
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "diagnostic_settings": settings,
            "scope": "subscription",
            "provider_registration_status": registration,
        },
        summary={**summarize(settings), "provider_registration_status": registration},
    )

    filename = (
        f"azure_diagnostic_settings_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
