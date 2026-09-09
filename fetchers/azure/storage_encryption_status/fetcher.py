#!/usr/bin/env python3
"""Azure Storage encryption at rest, per storage account in one subscription.

Azure Storage is ALWAYS encrypted at rest, so "encrypted: true" can never fail; what
varies is `encryption.key_source` (customer-managed Key Vault key vs
Microsoft.Storage) and whether infrastructure (double) encryption is on.
Ported from prowler/providers/azure/services/storage/storage_service.py (Apache-2.0).
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
    dig,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_storage_encryption_status")

# encryption.key_source: "Microsoft.Keyvault" is a customer-managed key held in Key
# Vault; "Microsoft.Storage" is the platform-managed default.
KEY_SOURCE_KEYVAULT = "microsoft.keyvault"

# Expected per-account: the account kind has no Blob (or File) endpoint (e.g. a
# FileStorage or BlockBlobStorage account). Prowler string-matches these and
# continues; they are NOT collection failures and must not push the fetcher to exit 1.
BENIGN_UNSUPPORTED_SERVICE = (
    "Blob is not supported for the account.",
    "File is not supported for the account.",
)


# --- projection: the only code here that touches an azure-mgmt model ---

def project_storage_account(account) -> dict:
    """Read a `StorageAccount` model's attributes into a flat snake_case dict.

    Values are un-defaulted: `None` means the API did not return the field, and
    `account_record()` decides how to read an absence.
    """
    encryption = model_attr(account, "encryption")
    network_rule_set = model_attr(account, "network_rule_set")
    key_policy = model_attr(account, "key_policy")
    sku = model_attr(account, "sku")

    return {
        "id": model_attr(account, "id"),
        "name": model_attr(account, "name"),
        "location": model_attr(account, "location"),
        # --- encryption at rest ---
        "encryption_type": model_attr(encryption, "key_source"),
        "infrastructure_encryption": model_attr(encryption, "require_infrastructure_encryption"),
        # --- encryption in transit ---
        "enable_https_traffic_only": model_attr(account, "enable_https_traffic_only"),
        "minimum_tls_version": model_attr(account, "minimum_tls_version"),
        # --- network exposure ---
        "allow_blob_public_access": model_attr(account, "allow_blob_public_access"),
        "public_network_access": model_attr(account, "public_network_access"),
        "network_rule_set": {
            "bypass": model_attr(network_rule_set, "bypass"),
            "default_action": model_attr(network_rule_set, "default_action"),
        },
        "private_endpoint_connections": [
            {
                "id": model_attr(pec, "id"),
                "name": model_attr(pec, "name"),
                "type": model_attr(pec, "type"),
            }
            for pec in (model_attr(account, "private_endpoint_connections") or [])
        ],
        # --- key + identity management ---
        "key_expiration_period_in_days": model_attr(key_policy, "key_expiration_period_in_days"),
        "allow_shared_key_access": model_attr(account, "allow_shared_key_access"),
        # The SDK spells Entra ID's former name: defaultToOAuthAuthentication.
        "default_to_entra_authorization": model_attr(account, "default_to_o_auth_authentication"),
        # --- durability / replication ---
        "replication_settings": model_attr(sku, "name"),
        "allow_cross_tenant_replication": model_attr(account, "allow_cross_tenant_replication"),
    }


def project_blob_service_properties(properties) -> dict:
    """Read a `BlobServiceProperties` model's attributes into a flat dict."""
    container_policy = model_attr(properties, "container_delete_retention_policy")
    return {
        "id": model_attr(properties, "id"),
        "name": model_attr(properties, "name"),
        "type": model_attr(properties, "type"),
        "default_service_version": model_attr(properties, "default_service_version"),
        "container_delete_retention_policy": {
            "enabled": model_attr(container_policy, "enabled"),
            "days": model_attr(container_policy, "days"),
        },
        "is_versioning_enabled": model_attr(properties, "is_versioning_enabled"),
    }


def project_file_service_properties(properties) -> dict:
    """Read a `FileServiceProperties` model's attributes into a flat dict."""
    share_policy = model_attr(properties, "share_delete_retention_policy")
    smb = model_attr(model_attr(properties, "protocol_settings"), "smb")
    return {
        "id": model_attr(properties, "id"),
        "name": model_attr(properties, "name"),
        "type": model_attr(properties, "type"),
        "share_delete_retention_policy": {
            "enabled": model_attr(share_policy, "enabled"),
            "days": model_attr(share_policy, "days"),
        },
        "smb_protocol_settings": {
            "channel_encryption": model_attr(smb, "channel_encryption"),
            "supported_versions": model_attr(smb, "versions"),
        },
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def _retention_policy(policy: dict | None) -> dict:
    """Normalize a {enabled, days} soft-delete policy, defaulting to off/0.

    Mirrors Prowler: the API omits the block when the feature was never turned on,
    so absent reads as disabled rather than unknown.
    """
    policy = policy if isinstance(policy, dict) else {}
    return {
        "enabled": bool(policy.get("enabled") or False),
        "days": int(policy.get("days") or 0),
    }


def _semicolon_list(value) -> list:
    """Split a ";"-delimited SMB settings string ("AES-128-GCM;AES-256-GCM")."""
    if not value:
        return []
    if isinstance(value, list):
        return value
    return str(value).rstrip(";").split(";")


def account_record(account: dict) -> dict:
    """Normalize one projected storage account into an evidence record.

    Prowler's defaults are preserved: the API omits allow_cross_tenant_replication,
    allow_shared_key_access and the network_rule_set fields when they sit at their
    (permissive) service defaults, so absent must read as that default, not as None.
    """
    resource_id = account.get("id")
    network_rule_set = account.get("network_rule_set") or {}

    key_source = account.get("encryption_type")
    key_expiration = account.get("key_expiration_period_in_days")

    cross_tenant = account.get("allow_cross_tenant_replication")
    shared_key = account.get("allow_shared_key_access")
    entra_auth = account.get("default_to_entra_authorization")

    return {
        "id": resource_id,
        "name": account.get("name"),
        "location": account.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        # --- encryption at rest (the evidence that actually varies) ---
        "encryption_type": key_source,
        "customer_managed_key": str(key_source or "").lower() == KEY_SOURCE_KEYVAULT,
        # Coerced, not passed through: Azure OMITS requireInfrastructureEncryption
        # when it was never enabled (confirmed live), and a validator regex asserting
        # `false` would not match `null`. Absent means disabled; there is no third state.
        "infrastructure_encryption": bool(account.get("infrastructure_encryption") or False),
        # --- encryption in transit ---
        "enable_https_traffic_only": bool(account.get("enable_https_traffic_only") or False),
        "minimum_tls_version": account.get("minimum_tls_version"),
        # --- network exposure ---
        "allow_blob_public_access": bool(account.get("allow_blob_public_access") or False),
        "public_network_access": account.get("public_network_access"),
        "network_rule_set": {
            "bypass": network_rule_set.get("bypass") or "AzureServices",
            "default_action": network_rule_set.get("default_action") or "Allow",
        },
        "private_endpoint_connections": [
            {
                "id": pec.get("id"),
                "name": pec.get("name"),
                "type": pec.get("type"),
            }
            for pec in (account.get("private_endpoint_connections") or [])
        ],
        # --- key + identity management ---
        "key_expiration_period_in_days": int(key_expiration) if key_expiration is not None else None,
        "allow_shared_key_access": True if shared_key is None else bool(shared_key),
        "default_to_entra_authorization": False if entra_auth is None else bool(entra_auth),
        # --- durability / replication ---
        "replication_settings": account.get("replication_settings"),
        "allow_cross_tenant_replication": True if cross_tenant is None else bool(cross_tenant),
        # Filled in by the blob/file enrichment; None = not collected (no endpoint).
        "blob_properties": None,
        "file_service_properties": None,
    }


def blob_properties_record(properties: dict) -> dict:
    """Normalize projected blob service properties — versioning + soft delete."""
    return {
        "id": properties.get("id"),
        "name": properties.get("name"),
        "type": properties.get("type"),
        "default_service_version": properties.get("default_service_version"),
        "container_delete_retention_policy": _retention_policy(
            properties.get("container_delete_retention_policy")
        ),
        "versioning_enabled": bool(properties.get("is_versioning_enabled") or False),
    }


def file_service_properties_record(properties: dict) -> dict:
    """Normalize projected file service properties — share soft delete + SMB."""
    smb = properties.get("smb_protocol_settings") or {}
    return {
        "id": properties.get("id"),
        "name": properties.get("name"),
        "type": properties.get("type"),
        "share_delete_retention_policy": _retention_policy(
            properties.get("share_delete_retention_policy")
        ),
        "smb_protocol_settings": {
            "channel_encryption": _semicolon_list(smb.get("channel_encryption")),
            "supported_versions": _semicolon_list(smb.get("supported_versions")),
        },
    }


def summarize(accounts: list[dict]) -> dict:
    """CMK coverage is the headline, not an encrypted/total percentage.

    Azure Storage encrypts at rest unconditionally, so a generic "encrypted"
    percentage would be a constant 100 and prove nothing.
    """
    cmk = sum(1 for a in accounts if a["customer_managed_key"])
    total = len(accounts)
    return {
        "total_storage_accounts": total,
        "customer_managed_key_storage": cmk,
        "platform_managed_key_storage": total - cmk,
        "cmk_percentage": coverage_percentage(cmk, total),
        "infrastructure_encryption_accounts": sum(
            1 for a in accounts if a["infrastructure_encryption"]
        ),
        "https_only_accounts": sum(1 for a in accounts if a["enable_https_traffic_only"]),
        "minimum_tls_1_2_accounts": sum(
            1 for a in accounts if (a["minimum_tls_version"] or "") in ("TLS1_2", "TLS1_3")
        ),
        "public_blob_access_accounts": sum(1 for a in accounts if a["allow_blob_public_access"]),
        "shared_key_access_accounts": sum(1 for a in accounts if a["allow_shared_key_access"]),
        "private_endpoint_accounts": sum(
            1 for a in accounts if a["private_endpoint_connections"]
        ),
        "key_expiration_policy_accounts": sum(
            1 for a in accounts if a["key_expiration_period_in_days"] is not None
        ),
        "blob_versioning_accounts": sum(
            1 for a in accounts if dig(a, "blob_properties", "versioning_enabled")
        ),
        "container_soft_delete_accounts": sum(
            1
            for a in accounts
            if dig(a, "blob_properties", "container_delete_retention_policy", "enabled")
        ),
        "share_soft_delete_accounts": sum(
            1
            for a in accounts
            if dig(a, "file_service_properties", "share_delete_retention_policy", "enabled")
        ),
    }


# --- collection (lazy azure imports) ---

def _is_benign_unsupported(exc: BaseException) -> bool:
    message = str(exc).strip()
    return any(marker in message for marker in BENIGN_UNSUPPORTED_SERVICE)


def collect_storage_accounts(subscription_id, cred, collector: Collector) -> list[dict]:
    """One storage_accounts.list() plus a blob/file service GET per account.

    The list response already carries the encryption / network / key-policy fields;
    only versioning and the soft-delete policies need the per-account GETs.
    """
    from azure.mgmt.storage import StorageManagementClient

    def _client():
        return StorageManagementClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("storage.StorageManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [
            account_record(project_storage_account(a)) for a in client.storage_accounts.list()
        ]

    accounts = collector.guard("storage.storage_accounts.list", _list, default=[])

    for account in accounts:
        group, name = account.get("resource_group"), account.get("name")
        if not group or not name:
            collector.record(
                "storage.blob_services.get_service_properties",
                RuntimeError(f"storage account {name!r} has no resource group in its id"),
            )
            continue
        account["blob_properties"] = _service_properties(
            collector,
            "storage.blob_services.get_service_properties",
            name,
            lambda: blob_properties_record(
                project_blob_service_properties(
                    client.blob_services.get_service_properties(group, name)
                )
            ),
        )
        account["file_service_properties"] = _service_properties(
            collector,
            "storage.file_services.get_service_properties",
            name,
            lambda: file_service_properties_record(
                project_file_service_properties(
                    client.file_services.get_service_properties(group, name)
                )
            ),
        )

    return sorted(accounts, key=lambda r: r.get("id") or "")


def _service_properties(collector: Collector, operation: str, account_name: str, fn):
    """Run one service-properties GET, tolerating the benign "not supported" error.

    Not routed through Collector.guard because "Blob is not supported for the
    account." is expected for an account kind with no such endpoint and would
    otherwise fail the whole run. Prowler skips it the same way.
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if _is_benign_unsupported(exc):
            logger.warning(
                "%s: skipping %s — %s", operation, account_name, str(exc).strip().splitlines()[0]
            )
            return None
        collector.record(f"{operation} ({account_name})", exc)
        return None


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which would
    # bury this fetcher's own lines and dominate the runner's stderr tail.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    accounts: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call, so a zero-account result is legible: Azure
        # returns an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Storage"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Storage is not registered on subscription %s — no storage "
                "in use; reporting status not_registered",
                subscription_id,
            )
        accounts = collect_storage_accounts(subscription_id, cred, collector)
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
            "storage_accounts": accounts,
            "provider_registration_status": registration,
        },
        summary={**summarize(accounts), "provider_registration_status": registration},
    )

    filename = (
        f"azure_storage_encryption_status_"
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
