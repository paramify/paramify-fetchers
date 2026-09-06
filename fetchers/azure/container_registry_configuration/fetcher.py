#!/usr/bin/env python3
"""
Azure Container Registry configuration — admin account, network exposure, audit logging

Ported from Prowler's
prowler/providers/azure/services/containerregistry/containerregistry_service.py
(Apache-2.0), with TWO DELIBERATE DEPARTURES:

1. `public_network_access` is read off the attribute the SDK actually has. Prowler reads
   `getattr(registry, "public_network_access_enabled", "Enabled")`, but the model's field
   is `public_network_access` ("Enabled"/"Disabled") — verified against
   azure-mgmt-containerregistry 15.0.0, whose flattened attribute set has no
   `public_network_access_enabled` — so Prowler's getattr always misses and its default
   makes every registry read as publicly accessible.
2. Diagnostic settings are listed here per registry, because Prowler's registry service
   imports a `monitor_client` singleton, which a fetcher cannot do. That OVERLAPS the
   dedicated Azure diagnostic settings fetcher but is no substitute: its
   subscription-scoped listing excludes a registry's own settings.

MONITOR SDK PIN: azure-mgmt-monitor 7.0.0 REMOVED the `diagnostic_settings` operation
group (6.0.2 has it under `v2021_05_01_preview`), so this needs
`azure-mgmt-monitor>=6.0.2,<7`; a newer install is reported as a collection failure
naming the pin, not a bare AttributeError.
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
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_container_registry_configuration")

# "Enabled"/"Disabled" string enums, compared case-insensitively against the wire value.
DISABLED = "disabled"
ENABLED = "enabled"

# network_rule_set.default_action: "Allow" is the permissive default, under which the
# IP rules grant nothing extra because everything is already allowed.
NETWORK_DEFAULT_ACTION_DENY = "deny"


# --- projection: the only code that touches an azure-mgmt model ---

def project_private_endpoint_connection(connection) -> dict:
    """Read a `PrivateEndpointConnection` model — Prowler's three fields plus state.

    A connection in any state other than Approved is not carrying traffic.
    """
    return {
        "id": model_attr(connection, "id"),
        "name": model_attr(connection, "name"),
        "type": model_attr(connection, "type"),
        "status": model_attr(
            model_attr(connection, "private_link_service_connection_state"), "status"
        ),
        "provisioning_state": model_attr(connection, "provisioning_state"),
    }


def project_policies(policies) -> dict:
    """Read a `Policies` model — content trust, quarantine, retention, export, ARM audience.

    Not part of Prowler's projection; free in the same list response.
    """
    quarantine = model_attr(policies, "quarantine_policy")
    trust = model_attr(policies, "trust_policy")
    retention = model_attr(policies, "retention_policy")
    export = model_attr(policies, "export_policy")
    arm_audience = model_attr(policies, "azure_ad_authentication_as_arm_policy")
    return {
        "quarantine_policy_status": model_attr(quarantine, "status"),
        "trust_policy_status": model_attr(trust, "status"),
        "trust_policy_type": model_attr(trust, "type"),
        "retention_policy_status": model_attr(retention, "status"),
        "retention_policy_days": model_attr(retention, "days"),
        "export_policy_status": model_attr(export, "status"),
        "azure_ad_authentication_as_arm_policy_status": model_attr(arm_audience, "status"),
    }


def project_registry(registry) -> dict:
    """Read a `Registry` model's attributes into a flat snake_case dict.

    `model_attr`'s enum unwrapping matters at nearly every line: `sku.name`,
    `public_network_access`, the policy statuses and `network_rule_set.default_action`
    are enum members, and `str()` on one renders "SkuName.PREMIUM", not "Premium".
    """
    network_rule_set = model_attr(registry, "network_rule_set")
    return {
        "id": model_attr(registry, "id"),
        "name": model_attr(registry, "name"),
        "location": model_attr(registry, "location"),
        "sku": model_attr(model_attr(registry, "sku"), "name"),
        "login_server": model_attr(registry, "login_server"),
        # --- who can authenticate ---
        "admin_user_enabled": model_attr(registry, "admin_user_enabled"),
        "anonymous_pull_enabled": model_attr(registry, "anonymous_pull_enabled"),
        # --- network exposure ---
        # The SDK field is `public_network_access` ("Enabled"/"Disabled"), NOT
        # `public_network_access_enabled` (see the module docstring).
        "public_network_access": model_attr(registry, "public_network_access"),
        "network_rule_bypass_options": model_attr(registry, "network_rule_bypass_options"),
        "network_rule_set": {
            "default_action": model_attr(network_rule_set, "default_action"),
            "ip_rules": [
                {
                    "action": model_attr(rule, "action"),
                    "ip_address_or_range": model_attr(rule, "ip_address_or_range"),
                }
                for rule in (model_attr(network_rule_set, "ip_rules") or [])
            ],
        },
        "data_endpoint_enabled": model_attr(registry, "data_endpoint_enabled"),
        "private_endpoint_connections": [
            project_private_endpoint_connection(connection)
            for connection in (model_attr(registry, "private_endpoint_connections") or [])
        ],
        # --- at rest ---
        "encryption_status": model_attr(model_attr(registry, "encryption"), "status"),
        "zone_redundancy": model_attr(registry, "zone_redundancy"),
        # --- supply chain / retention ---
        "policies": project_policies(model_attr(registry, "policies")),
        # Filled in by the diagnostic-settings enrichment.
        "monitor_diagnostic_settings": [],
    }


def project_diagnostic_setting(setting) -> dict:
    """Read a `DiagnosticSettingsResource` model — one log/metric export target.

    Ported from Prowler's monitor_service.diagnostic_settings_with_uri(), plus the metric
    categories and the event hub destination.
    """
    return {
        "id": model_attr(setting, "id"),
        # Prowler derives the display name from the id's last segment.
        "name": model_attr(setting, "name") or basename(model_attr(setting, "id")),
        "storage_account_id": model_attr(setting, "storage_account_id"),
        "workspace_id": model_attr(setting, "workspace_id"),
        "event_hub_name": model_attr(setting, "event_hub_name"),
        "logs": [
            {
                "category": model_attr(log, "category"),
                "category_group": model_attr(log, "category_group"),
                "enabled": model_attr(log, "enabled"),
            }
            for log in (model_attr(setting, "logs") or [])
        ],
        "metrics": [
            {
                "category": model_attr(metric, "category"),
                "enabled": model_attr(metric, "enabled"),
            }
            for metric in (model_attr(setting, "metrics") or [])
        ],
    }


# --- pure transforms (dicts in, evidence records out) ---

def _is_enabled_status(value) -> bool:
    """Is an "Enabled"/"Disabled" string enum enabled? Absent reads as not enabled."""
    return str(value or "").lower() == ENABLED


def diagnostic_setting_record(setting: dict) -> dict:
    """Normalize one projected diagnostic setting, coercing the per-category enables."""
    return {
        "id": setting.get("id"),
        "name": setting.get("name"),
        "storage_account_id": setting.get("storage_account_id"),
        "storage_account_name": basename(setting.get("storage_account_id")),
        "workspace_id": setting.get("workspace_id"),
        "event_hub_name": setting.get("event_hub_name"),
        "logs": [
            {
                "category": log.get("category"),
                "category_group": log.get("category_group"),
                "enabled": bool(log.get("enabled") or False),
            }
            for log in (setting.get("logs") or [])
        ],
        "metrics": [
            {
                "category": metric.get("category"),
                "enabled": bool(metric.get("enabled") or False),
            }
            for metric in (setting.get("metrics") or [])
        ],
    }


def registry_record(registry: dict) -> dict:
    """Normalize one projected registry into an evidence record.

    Optional booleans are coerced with `bool(x or False)`: Azure omits
    `admin_user_enabled` / `anonymous_pull_enabled` / `data_endpoint_enabled` when off,
    and a regex asserting `false` would not match `null`. `public_network_access` is kept
    raw AND reduced to a boolean with ABSENT READ AS PUBLIC: "Enabled" is the service
    default, so an omitted field means a publicly-reachable registry ("Disabled" is the
    only value that passes, as in Prowler's check).
    """
    resource_id = registry.get("id")
    network_rule_set = registry.get("network_rule_set") or {}
    default_action = network_rule_set.get("default_action")
    connections = list(registry.get("private_endpoint_connections") or [])
    public_network_access = registry.get("public_network_access")

    return {
        "id": resource_id,
        "name": registry.get("name"),
        "location": registry.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "sku": registry.get("sku"),
        "login_server": registry.get("login_server"),
        # --- who can authenticate (a true here is a standing finding) ---
        "admin_user_enabled": bool(registry.get("admin_user_enabled") or False),
        "anonymous_pull_enabled": bool(registry.get("anonymous_pull_enabled") or False),
        # --- network exposure ---
        "public_network_access": public_network_access,
        "public_network_access_enabled": str(public_network_access or "").lower() != DISABLED,
        "network_rule_bypass_options": registry.get("network_rule_bypass_options"),
        "network_rule_set": {
            "default_action": default_action,
            "ip_rules": [
                {
                    "action": rule.get("action"),
                    "ip_address_or_range": rule.get("ip_address_or_range"),
                }
                for rule in (network_rule_set.get("ip_rules") or [])
            ],
        },
        "network_rules_default_deny": str(default_action or "").lower()
        == NETWORK_DEFAULT_ACTION_DENY,
        "data_endpoint_enabled": bool(registry.get("data_endpoint_enabled") or False),
        "private_endpoint_connections": connections,
        "private_link_in_use": bool(connections),
        # --- at rest ---
        "encryption_status": registry.get("encryption_status"),
        "customer_managed_key": _is_enabled_status(registry.get("encryption_status")),
        "zone_redundancy": registry.get("zone_redundancy"),
        # --- supply chain / retention ---
        "policies": registry.get("policies") or {},
        # --- audit logging ---
        "monitor_diagnostic_settings": [
            diagnostic_setting_record(setting)
            for setting in (registry.get("monitor_diagnostic_settings") or [])
        ],
    }


def has_enabled_log(registry: dict) -> bool:
    """Does the registry ship at least one ENABLED log category anywhere?

    A setting can exist with every category switched off, hence counting enabled
    categories rather than settings.
    """
    return any(
        log["enabled"]
        for setting in (registry.get("monitor_diagnostic_settings") or [])
        for log in (setting.get("logs") or [])
    )


def summarize(registries: list[dict]) -> dict:
    """The counts a reviewer reads first, one per Prowler container-registry check."""
    total = len(registries)
    admin_disabled = sum(1 for r in registries if not r["admin_user_enabled"])
    private = sum(1 for r in registries if not r["public_network_access_enabled"])
    return {
        "total_registries": total,
        # Counted as registries WITH the shared admin account — that is the finding.
        "admin_user_enabled_registries": total - admin_disabled,
        "admin_user_disabled_percentage": coverage_percentage(admin_disabled, total),
        "anonymous_pull_enabled_registries": sum(
            1 for r in registries if r["anonymous_pull_enabled"]
        ),
        "public_network_access_registries": total - private,
        "private_network_access_registries": private,
        "private_network_access_percentage": coverage_percentage(private, total),
        "network_rules_default_deny_registries": sum(
            1 for r in registries if r["network_rules_default_deny"]
        ),
        "private_link_registries": sum(1 for r in registries if r["private_link_in_use"]),
        "customer_managed_key_registries": sum(1 for r in registries if r["customer_managed_key"]),
        "content_trust_registries": sum(
            1 for r in registries if _is_enabled_status(r["policies"].get("trust_policy_status"))
        ),
        "quarantine_policy_registries": sum(
            1
            for r in registries
            if _is_enabled_status(r["policies"].get("quarantine_policy_status"))
        ),
        "retention_policy_registries": sum(
            1
            for r in registries
            if _is_enabled_status(r["policies"].get("retention_policy_status"))
        ),
        "premium_sku_registries": sum(1 for r in registries if r["sku"] == "Premium"),
        "registries_with_diagnostic_settings": sum(
            1 for r in registries if r["monitor_diagnostic_settings"]
        ),
        "registries_with_enabled_logs": sum(1 for r in registries if has_enabled_log(r)),
    }


# --- collection (lazy azure imports) ---

def diagnostic_settings_resource_uri(resource_id: str) -> str:
    """The `resource_uri` form diagnostic_settings.list() wants.

    The SDK substitutes it unquoted into
    "/{resourceUri}/providers/Microsoft.Insights/diagnosticSettings", so a leading slash
    would produce a double-slashed path. Prowler rebuilds the string from subscription +
    resource group + name; the registry's own ARM id cannot drift from the resource.
    """
    return (resource_id or "").lstrip("/")


def collect_registries(subscription_id, cred, collector: Collector) -> list[dict]:
    """One subscription-wide registries.list(), then one diagnostic-settings list per registry.

    `registries.list()` returns an ItemPaged, so the SDK follows nextLink itself. The
    diagnostic settings need a second SDK (azure-mgmt-monitor) because they live under
    Microsoft.Insights, not the registry's own provider. Each SDK import lives inside its
    guarded factory so a missing (or too new) azure-mgmt-* package becomes a recorded
    failure with evidence plus a status file, not a traceback.
    """

    def _client():
        # Lazy: the transforms above must import with no azure-* package present.
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient

        return ContainerRegistryManagementClient(
            credential=cred, subscription_id=subscription_id
        )

    client = collector.guard(
        "containerregistry.ContainerRegistryManagementClient (init)", _client
    )
    if client is None:
        return []

    registries = collector.guard(
        "containerregistry.registries.list",
        lambda: [registry_record(project_registry(r)) for r in client.registries.list()],
        default=[],
    )
    if registries:
        _attach_diagnostic_settings(subscription_id, cred, collector, registries)

    return sorted(registries, key=lambda r: r.get("id") or "")


def _attach_diagnostic_settings(
    subscription_id, cred, collector: Collector, registries: list[dict]
) -> None:
    """Fill each registry's `monitor_diagnostic_settings` in place."""

    def _monitor_client():
        from azure.mgmt.monitor import MonitorManagementClient  # lazy

        client = MonitorManagementClient(credential=cred, subscription_id=subscription_id)
        # azure-mgmt-monitor 7.0.0 dropped the operation group entirely; say so
        # instead of letting an AttributeError name a missing attribute.
        if getattr(client, "diagnostic_settings", None) is None:
            raise RuntimeError(
                "installed azure-mgmt-monitor has no diagnostic_settings operation "
                "group (removed in 7.0.0) — pin azure-mgmt-monitor>=6.0.2,<7"
            )
        return client

    monitor = collector.guard("monitor.MonitorManagementClient (init)", _monitor_client)
    if monitor is None:
        return

    for registry in registries:
        resource_id, name = registry.get("id"), registry.get("name")
        if not resource_id:
            collector.record(
                "monitor.diagnostic_settings.list",
                RuntimeError(f"container registry {name!r} has no resource id"),
            )
            continue
        registry["monitor_diagnostic_settings"] = collector.guard(
            f"monitor.diagnostic_settings.list ({name})",
            lambda resource_id=resource_id: sorted(
                (
                    diagnostic_setting_record(project_diagnostic_setting(setting))
                    for setting in monitor.diagnostic_settings.list(
                        resource_uri=diagnostic_settings_resource_uri(resource_id)
                    )
                ),
                key=lambda r: r.get("id") or "",
            ),
            default=[],
        )


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request and response header at INFO, which would bury
    # this fetcher's lines in the runner's stderr tail. Warnings still come through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    registries: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call, so a zero-registry result is legible: Azure
        # returns an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.ContainerRegistry"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.ContainerRegistry is not registered on subscription %s — no "
                "registries in use; reporting status not_registered",
                subscription_id,
            )
        registries = collect_registries(subscription_id, cred, collector)
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
            "registries": registries,
            "provider_registration_status": registration,
        },
        summary={**summarize(registries), "provider_registration_status": registration},
    )

    filename = (
        f"azure_container_registry_configuration_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
