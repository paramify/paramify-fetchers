#!/usr/bin/env python3
"""
Azure Databricks workspace network isolation and managed-disk encryption.

Ported from Prowler
prowler/providers/azure/services/databricks/databricks_service.py (Apache-2.0), plus
the workspace SKU and the managed-disk key source / rotation flag, which Prowler does
not keep and which say WHY a key counts as customer-managed.
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

logger = logging.getLogger("azure_databricks_workspace_configuration")

# encryption.entities.managed_disk.key_source. "Microsoft.Keyvault" means the disks
# are encrypted with a customer-managed key; "Default" is the platform key.
KEY_SOURCE_KEYVAULT = "microsoft.keyvault"

# The SKU tier that carries the network-isolation features (VNet injection, private
# connectivity, customer-managed keys).
PREMIUM_SKU = "premium"


# --- projection: the only azure-mgmt model access ---

def _custom_parameter(parameters, name):
    """Read one `WorkspaceCustom*Parameter`'s `.value` off the parameters block.

    Databricks wraps each creation parameter in a small model instead of returning the
    value, so every read is two hops — and both are routinely absent (`parameters` itself
    is None on a workspace created with all defaults).
    """
    return model_attr(model_attr(parameters, name), "value")


def project_workspace(workspace) -> dict:
    """Read a `Workspace` model into a flat snake_case dict. Every hop of
    `encryption.entities.managed_disk.key_vault_properties` is absent on a workspace using
    platform-managed keys, hence the None-tolerant reads.
    """
    sku = model_attr(workspace, "sku")
    parameters = model_attr(workspace, "parameters")
    managed_disk = model_attr(
        model_attr(model_attr(workspace, "encryption"), "entities"), "managed_disk"
    )
    key_vault_properties = model_attr(managed_disk, "key_vault_properties")

    return {
        "id": model_attr(workspace, "id"),
        "name": model_attr(workspace, "name"),
        "location": model_attr(workspace, "location"),
        "provisioning_state": model_attr(workspace, "provisioning_state"),
        "managed_resource_group_id": model_attr(workspace, "managed_resource_group_id"),
        "sku": {
            "name": model_attr(sku, "name"),
            "tier": model_attr(sku, "tier"),
        },
        "public_network_access": model_attr(workspace, "public_network_access"),
        "required_nsg_rules": model_attr(workspace, "required_nsg_rules"),
        "no_public_ip_enabled": _custom_parameter(parameters, "enable_no_public_ip"),
        "custom_managed_vnet_id": _custom_parameter(parameters, "custom_virtual_network_id"),
        "managed_disk_encryption": {
            "key_source": model_attr(managed_disk, "key_source"),
            "key_name": model_attr(key_vault_properties, "key_name"),
            "key_version": model_attr(key_vault_properties, "key_version"),
            "key_vault_uri": model_attr(key_vault_properties, "key_vault_uri"),
            "rotation_to_latest_key_version_enabled": model_attr(
                managed_disk, "rotation_to_latest_key_version_enabled"
            ),
        },
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def managed_disk_encryption_record(encryption: dict | None) -> dict:
    """Normalize the managed-disk encryption block, deciding CMK vs platform key.

    A Key Vault URI (or key_source "Microsoft.Keyvault") is what makes the key
    customer-managed; Prowler treats the presence of key_vault_properties as the same
    signal. Databricks disks are always encrypted, so "encrypted: true" would be a
    constant — what varies is who holds the key.
    """
    encryption = encryption if isinstance(encryption, dict) else {}
    key_source = encryption.get("key_source")
    key_vault_uri = encryption.get("key_vault_uri")
    return {
        "key_source": key_source,
        "key_name": encryption.get("key_name"),
        "key_version": encryption.get("key_version"),
        "key_vault_uri": key_vault_uri,
        "rotation_to_latest_key_version_enabled": bool(
            encryption.get("rotation_to_latest_key_version_enabled") or False
        ),
        "customer_managed_key": bool(key_vault_uri) or (
            str(key_source or "").lower() == KEY_SOURCE_KEYVAULT
        ),
    }


def workspace_record(workspace: dict) -> dict:
    """Normalize one projected Databricks workspace into an evidence record.

    Booleans are coerced with `bool(x or False)` because Azure omits a false-y field
    rather than returning `false`, and a validator asserting `false` would not match
    `null`. `enable_no_public_ip` is the exception Prowler keeps as None — a workspace
    that does not expose the setting at all — so `no_public_ip_setting_present` sits
    beside the coerced boolean and keeps absent from reading as "nodes have public IPs".
    """
    resource_id = workspace.get("id")
    sku = workspace.get("sku") or {}
    no_public_ip = workspace.get("no_public_ip_enabled")
    custom_vnet = workspace.get("custom_managed_vnet_id")
    public_network_access = workspace.get("public_network_access")
    return {
        "id": resource_id,
        "name": workspace.get("name"),
        "location": workspace.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "provisioning_state": workspace.get("provisioning_state"),
        "managed_resource_group_id": workspace.get("managed_resource_group_id"),
        "sku_name": sku.get("name"),
        "sku_tier": sku.get("tier"),
        "premium_sku": str(sku.get("name") or sku.get("tier") or "").lower() == PREMIUM_SKU,
        "public_network_access": public_network_access,
        "public_network_access_disabled": (
            str(public_network_access or "").lower() == "disabled"
        ),
        "required_nsg_rules": workspace.get("required_nsg_rules"),
        # --- secure cluster connectivity ---
        "no_public_ip_enabled": bool(no_public_ip or False),
        "no_public_ip_setting_present": no_public_ip is not None,
        # --- VNet injection ---
        "custom_managed_vnet_id": custom_vnet,
        "vnet_injected": bool(custom_vnet),
        "managed_disk_encryption": managed_disk_encryption_record(
            workspace.get("managed_disk_encryption")
        ),
    }


def summarize(workspaces: list[dict]) -> dict:
    """Isolation and CMK coverage — the two things that vary between workspaces."""
    total = len(workspaces)
    cmk = sum(1 for w in workspaces if w["managed_disk_encryption"]["customer_managed_key"])
    isolated = sum(
        1 for w in workspaces if w["public_network_access_disabled"] and w["no_public_ip_enabled"]
    )
    return {
        "total_workspaces": total,
        "public_network_access_disabled_workspaces": sum(
            1 for w in workspaces if w["public_network_access_disabled"]
        ),
        "publicly_accessible_workspaces": sum(
            1 for w in workspaces if not w["public_network_access_disabled"]
        ),
        "no_public_ip_workspaces": sum(1 for w in workspaces if w["no_public_ip_enabled"]),
        "vnet_injected_workspaces": sum(1 for w in workspaces if w["vnet_injected"]),
        "network_isolated_workspaces": isolated,
        "network_isolated_percentage": coverage_percentage(isolated, total),
        "customer_managed_key_workspaces": cmk,
        "platform_managed_key_workspaces": total - cmk,
        "cmk_percentage": coverage_percentage(cmk, total),
        "key_rotation_enabled_workspaces": sum(
            1
            for w in workspaces
            if w["managed_disk_encryption"]["rotation_to_latest_key_version_enabled"]
        ),
        "premium_sku_workspaces": sum(1 for w in workspaces if w["premium_sku"]),
    }


# --- collection (lazy azure imports) ---

def collect_workspaces(subscription_id, cred, collector: Collector) -> list[dict]:
    """One workspaces.list_by_subscription() call: no per-resource GET is needed, the list
    already carries the SKU, network settings, wrapped parameters and encryption block.
    """
    from azure.mgmt.databricks import AzureDatabricksManagementClient

    def _client():
        return AzureDatabricksManagementClient(
            credential=cred, subscription_id=subscription_id
        )

    client = collector.guard("databricks.AzureDatabricksManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [
            workspace_record(project_workspace(workspace))
            for workspace in client.workspaces.list_by_subscription()
        ]

    workspaces = collector.guard(
        "databricks.workspaces.list_by_subscription", _list, default=[]
    )
    return sorted(workspaces, key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which would
    # dominate the runner's stderr tail. Their warnings and errors still come through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    workspaces: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call, so a zero-workspace result is legible: Azure returns
        # an empty list for an unregistered provider, and Microsoft.Databricks is
        # unregistered on most subscriptions.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Databricks"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Databricks is not registered on subscription %s — no "
                "Databricks in use; reporting status not_registered",
                subscription_id,
            )
        workspaces = collect_workspaces(subscription_id, cred, collector)
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
            "databricks_workspaces": workspaces,
            "provider_registration_status": registration,
        },
        summary={**summarize(workspaces), "provider_registration_status": registration},
    )

    filename = (
        f"azure_databricks_workspace_configuration_"
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
