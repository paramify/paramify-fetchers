#!/usr/bin/env python3
"""Azure Key Vault configuration for one subscription: the authorization model, the
recoverability, network exposure and SKU of every vault.

Ported from prowler/providers/azure/services/keyvault/keyvault_service.py
(Apache-2.0), plus the SKU, network ACLs and access policies Prowler reads off the raw
model. `enable_rbac_authorization` decides how the rest reads — Azure returns an empty
`access_policies` list for an RBAC vault. Management plane only: no key material,
secret value or certificate is read.
"""

import logging
import os
import sys
from enum import Enum
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
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

logger = logging.getLogger("azure_key_vault_configuration")

# Selected by `enable_rbac_authorization`. Under RBAC the grants live in Azure role
# assignments, outside this evidence set; otherwise they are `access_policies`.
ACCESS_MODEL_RBAC = "rbac"
ACCESS_MODEL_ACCESS_POLICY = "access_policy"

# publicNetworkAccess is OMITTED by ARM when it was never restricted, and absent
# means Enabled — Prowler encodes the same default inline.
PUBLIC_NETWORK_ACCESS_DEFAULT = "Enabled"

# ARM omits networkAcls entirely on a vault that was never firewalled, and the
# service default for defaultAction is Allow.
NETWORK_ACL_DEFAULT_ACTION = "Allow"


# --- projection: the only code that touches an azure-mgmt model ---

def properties_bag(model):
    """Return the model's `properties` sub-model, or the model itself.

    azure-mgmt-keyvault 14.x does NOT flatten `properties` onto the resource, so
    `vault.tenant_id` is absent (verified against the installed SDK); older
    msrest-generated releases DO flatten it, leaving no `properties` at all.
    """
    bag = model_attr(model, "properties")
    return model if bag is None else bag


def _str_list(value) -> list:
    """Normalize a list-valued SDK field, unwrapping any `str` enum members.

    `model_attr` unwraps an enum handed to it directly, but permission verbs and IP
    rules arrive as LISTS; an unwrapped member reads "KeyPermissions.GET".
    """
    if not isinstance(value, list):
        return []
    return [item.value if isinstance(item, Enum) else item for item in value]


def _permission_verbs(permissions, *names) -> list:
    """Read one permission-verb list off an `AccessPolicyEntry.permissions` model.

    The `keys` verb list is spelled `keys_property` on azure-mgmt-keyvault 14.x (the
    model is Mapping-like, so the generator renamed it to keep `.keys()` working):
    reading `keys` there returns the BOUND METHOD — truthy, not a list.
    """
    for name in names:
        value = model_attr(permissions, name)
        if isinstance(value, list):
            return _str_list(value)
    return []


def project_access_policy(entry) -> dict:
    """Read one `AccessPolicyEntry` into a flat dict — principals and verbs only."""
    permissions = model_attr(entry, "permissions")
    return {
        "tenant_id": model_attr(entry, "tenant_id"),
        "object_id": model_attr(entry, "object_id"),
        "application_id": model_attr(entry, "application_id"),
        "permissions": {
            "keys": _permission_verbs(permissions, "keys_property", "keys"),
            "secrets": _permission_verbs(permissions, "secrets"),
            "certificates": _permission_verbs(permissions, "certificates"),
            "storage": _permission_verbs(permissions, "storage"),
        },
    }


def project_private_endpoint_connection(connection) -> dict:
    """Read one `PrivateEndpointConnectionItem` into a flat dict."""
    properties = properties_bag(connection)
    state = model_attr(properties, "private_link_service_connection_state")
    return {
        "id": model_attr(connection, "id"),
        "provisioning_state": model_attr(properties, "provisioning_state"),
        "connection_status": model_attr(state, "status"),
    }


def project_vault(vault) -> dict:
    """Read a `Vault` model's attributes into a flat snake_case dict.

    Un-defaulted: `None` means "the API did not return this field", and `vault_record()`
    decides how an absence reads.
    """
    properties = properties_bag(vault)
    sku = model_attr(properties, "sku")
    network_acls = model_attr(properties, "network_acls")

    return {
        "id": model_attr(vault, "id"),
        "name": model_attr(vault, "name"),
        "location": model_attr(vault, "location"),
        "type": model_attr(vault, "type"),
        # --- authorization model ---
        "tenant_id": model_attr(properties, "tenant_id"),
        "enable_rbac_authorization": model_attr(properties, "enable_rbac_authorization"),
        "access_policies": [
            project_access_policy(entry)
            for entry in (model_attr(properties, "access_policies") or [])
        ],
        # --- recoverability ---
        "enable_soft_delete": model_attr(properties, "enable_soft_delete"),
        "enable_purge_protection": model_attr(properties, "enable_purge_protection"),
        "soft_delete_retention_in_days": model_attr(properties, "soft_delete_retention_in_days"),
        # --- network exposure ---
        "public_network_access": model_attr(properties, "public_network_access"),
        "network_acls": {
            "bypass": model_attr(network_acls, "bypass"),
            "default_action": model_attr(network_acls, "default_action"),
            "ip_rules": [
                model_attr(rule, "value") for rule in (model_attr(network_acls, "ip_rules") or [])
            ],
            "virtual_network_rules": [
                model_attr(rule, "id")
                for rule in (model_attr(network_acls, "virtual_network_rules") or [])
            ],
        },
        "private_endpoint_connections": [
            project_private_endpoint_connection(connection)
            for connection in (model_attr(properties, "private_endpoint_connections") or [])
        ],
        # --- platform integration + SKU ---
        "sku": {
            "family": model_attr(sku, "family"),
            "name": model_attr(sku, "name"),
        },
        "vault_uri": model_attr(properties, "vault_uri"),
        "enabled_for_deployment": model_attr(properties, "enabled_for_deployment"),
        "enabled_for_disk_encryption": model_attr(properties, "enabled_for_disk_encryption"),
        "enabled_for_template_deployment": model_attr(
            properties, "enabled_for_template_deployment"
        ),
        "provisioning_state": model_attr(properties, "provisioning_state"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def vault_record(vault: dict) -> dict:
    """Normalize one projected vault into an evidence record.

    Optional booleans are COERCED: ARM omits `enablePurgeProtection` /
    `enableRbacAuthorization` when never turned on, so the raw value is None and a
    validator asserting `false` would not match `null`. Absent means disabled — no
    third state — which is how Prowler reads the same absences.
    """
    resource_id = vault.get("id")
    network_acls = vault.get("network_acls") or {}

    rbac = bool(vault.get("enable_rbac_authorization") or False)
    soft_delete = bool(vault.get("enable_soft_delete") or False)
    purge_protection = bool(vault.get("enable_purge_protection") or False)
    public_access = vault.get("public_network_access") or PUBLIC_NETWORK_ACCESS_DEFAULT
    default_action = network_acls.get("default_action") or NETWORK_ACL_DEFAULT_ACTION
    policies = vault.get("access_policies") or []

    return {
        "id": resource_id,
        "name": vault.get("name"),
        "location": vault.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "tenant_id": vault.get("tenant_id"),
        # --- authorization model ---
        "rbac_authorization_enabled": rbac,
        # Derived: under RBAC the access_policies list is inapplicable, not empty.
        "access_model": ACCESS_MODEL_RBAC if rbac else ACCESS_MODEL_ACCESS_POLICY,
        "access_policies": policies,
        "access_policy_count": len(policies),
        # --- recoverability (Prowler's keyvault_recoverable is the AND of the two) ---
        "soft_delete_enabled": soft_delete,
        "purge_protection_enabled": purge_protection,
        "recoverable": soft_delete and purge_protection,
        "soft_delete_retention_in_days": vault.get("soft_delete_retention_in_days"),
        # --- network exposure ---
        "public_network_access": public_access,
        "public_network_access_disabled": str(public_access).lower() == "disabled",
        "network_acls": {
            "bypass": network_acls.get("bypass") or "AzureServices",
            "default_action": default_action,
            "ip_rules": network_acls.get("ip_rules") or [],
            "virtual_network_rules": network_acls.get("virtual_network_rules") or [],
        },
        "network_acl_default_deny": str(default_action).lower() == "deny",
        "private_endpoint_connections": vault.get("private_endpoint_connections") or [],
        # --- platform integration + SKU ---
        "sku": vault.get("sku") or {"family": None, "name": None},
        "vault_uri": vault.get("vault_uri"),
        "enabled_for_deployment": bool(vault.get("enabled_for_deployment") or False),
        "enabled_for_disk_encryption": bool(vault.get("enabled_for_disk_encryption") or False),
        "enabled_for_template_deployment": bool(
            vault.get("enabled_for_template_deployment") or False
        ),
        "provisioning_state": vault.get("provisioning_state"),
    }


def summarize(vaults: list[dict]) -> dict:
    """RBAC adoption and recoverability are the headlines."""
    total = len(vaults)
    rbac = sum(1 for v in vaults if v["rbac_authorization_enabled"])
    recoverable = sum(1 for v in vaults if v["recoverable"])
    return {
        "total_key_vaults": total,
        "rbac_authorization_vaults": rbac,
        "access_policy_vaults": total - rbac,
        "rbac_authorization_percentage": coverage_percentage(rbac, total),
        "soft_delete_vaults": sum(1 for v in vaults if v["soft_delete_enabled"]),
        "purge_protection_vaults": sum(1 for v in vaults if v["purge_protection_enabled"]),
        "recoverable_vaults": recoverable,
        "recoverable_percentage": coverage_percentage(recoverable, total),
        "public_network_access_disabled_vaults": sum(
            1 for v in vaults if v["public_network_access_disabled"]
        ),
        "network_acl_default_deny_vaults": sum(1 for v in vaults if v["network_acl_default_deny"]),
        "private_endpoint_vaults": sum(1 for v in vaults if v["private_endpoint_connections"]),
        "premium_sku_vaults": sum(
            1 for v in vaults if str((v["sku"] or {}).get("name") or "").lower() == "premium"
        ),
        "total_access_policies": sum(v["access_policy_count"] for v in vaults),
    }


# --- collection (lazy azure imports) ---

def collect_key_vaults(subscription_id, cred, collector: Collector) -> list[dict]:
    """One vaults.list_by_subscription() call."""
    from azure.mgmt.keyvault import KeyVaultManagementClient

    def _client():
        return KeyVaultManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("keyvault.KeyVaultManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself.
        return [vault_record(project_vault(v)) for v in client.vaults.list_by_subscription()]

    vaults = collector.guard("keyvault.vaults.list_by_subscription", _list, default=[])
    return sorted(vaults, key=lambda r: r.get("id") or "")


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

    vaults: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # ARM returns an empty list, not an error, for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.KeyVault"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.KeyVault is not registered on subscription %s — no key "
                "vaults in use; reporting status not_registered",
                subscription_id,
            )
        vaults = collect_key_vaults(subscription_id, cred, collector)
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
            "key_vaults": vaults,
            "provider_registration_status": registration,
        },
        summary={**summarize(vaults), "provider_registration_status": registration},
    )

    filename = (
        f"azure_key_vault_configuration_"
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
