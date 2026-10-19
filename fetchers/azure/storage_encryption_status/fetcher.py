#!/usr/bin/env python3
"""Azure Storage encryption at rest, per storage account in one subscription.

Azure Storage is ALWAYS encrypted at rest, so "encrypted: true" can never fail; what
varies is `encryption.key_source` (customer-managed Key Vault key vs
Microsoft.Storage) and whether infrastructure (double) encryption is on.
Ported from prowler/providers/azure/services/storage/storage_service.py (Apache-2.0).
Also geo-replication health, access-key age (from keyCreationTime; keys are never
listed), blob containers and owner / classification tags.
"""

import logging
import os
import re
import sys
from datetime import datetime, timezone
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

# Standard_GRS / RAGRS / GZRS / RAGZRS replicate to a secondary region; RA* can read from it.
GEO_REDUNDANT_SKU = re.compile(r"G(Z)?RS$", re.IGNORECASE)
READ_ACCESS_SKU = re.compile(r"RAG(Z)?RS$", re.IGNORECASE)

STATS_COLLECTED = "collected"
STATS_UNAVAILABLE = "unavailable"
STATS_FAILED = "failed"
STATS_NOT_APPLICABLE = "not_applicable"
# The service's answer while the secondary cannot report a sync time; a posture, not a failed run.
LAST_SYNC_UNAVAILABLE = ("lastsynctimeunavailable", "last sync time is unavailable")

CONTAINERS_COLLECTED = "collected"
CONTAINERS_NOT_SUPPORTED = "not_supported"
CONTAINERS_FAILED = "failed"
CONTAINERS_NOT_ATTEMPTED = "not_attempted"

ACCESS_KEY_NAMES = ("key1", "key2")
ACCESS_KEY_AGE_BENCHMARK_DAYS = 90

# Matched case-insensitively with punctuation ignored, so "Data-Classification" is "DataClassification".
OWNER_TAG_KEYS_ENV = "AZURE_STORAGE_OWNER_TAG_KEYS"
CLASSIFICATION_TAG_KEYS_ENV = "AZURE_STORAGE_CLASSIFICATION_TAG_KEYS"
DEFAULT_OWNER_TAG_KEYS = ("Owner", "OwnerEmail", "TechnicalOwner", "BusinessOwner", "DataOwner")
DEFAULT_CLASSIFICATION_TAG_KEYS = (
    "Classification",
    "DataClassification",
    "DataSensitivity",
    "Sensitivity",
    "Confidentiality",
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
        "primary_location": model_attr(account, "primary_location"),
        "secondary_location": model_attr(account, "secondary_location"),
        "status_of_primary": model_attr(account, "status_of_primary"),
        "status_of_secondary": model_attr(account, "status_of_secondary"),
        "last_geo_failover_time": model_attr(account, "last_geo_failover_time"),
        # When each key was last generated; the keys themselves are never listed.
        "key_creation_time": {
            name: model_attr(model_attr(account, "key_creation_time"), name) for name in ACCESS_KEY_NAMES
        },
        "tags": model_attr(account, "tags"),
    }


def project_geo_replication_stats(stats) -> dict:
    """Read a `GeoReplicationStats` model (from get_properties expand=geoReplicationStats)."""
    return {
        "status": model_attr(stats, "status"),
        "last_sync_time": model_attr(stats, "last_sync_time"),
        "can_failover": model_attr(stats, "can_failover"),
        "can_planned_failover": model_attr(stats, "can_planned_failover"),
        "post_failover_redundancy": model_attr(stats, "post_failover_redundancy"),
        "post_planned_failover_redundancy": model_attr(stats, "post_planned_failover_redundancy"),
    }


def project_container(container) -> dict:
    """Read a `ListContainerItem`; metadata values are dropped, only their keys are kept."""
    versioning = model_attr(container, "immutable_storage_with_versioning")
    metadata = model_attr(container, "metadata")
    return {
        "id": model_attr(container, "id"),
        "name": model_attr(container, "name"),
        "public_access": model_attr(container, "public_access"),
        # None when the list response carried no metadata field at all.
        "metadata_keys": sorted(metadata.keys()) if metadata is not None else None,
        "has_immutability_policy": model_attr(container, "has_immutability_policy"),
        "has_legal_hold": model_attr(container, "has_legal_hold"),
        "version_level_immutability": model_attr(versioning, "enabled"),
        "last_modified_time": model_attr(container, "last_modified_time"),
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


def _as_datetime(value) -> datetime | None:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso_utc(value) -> str | None:
    moment = _as_datetime(value)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if moment else None


def _normalize_tag_key(key) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key or "").lower())


def tag_keys_from_env(env_name: str, default: tuple) -> tuple:
    """Comma-separated tag keys from the environment, else the defaults."""
    raw = os.environ.get(env_name) or ""
    keys = tuple(k.strip() for k in raw.split(",") if k.strip())
    return keys or default


def tag_value(tags: dict | None, keys) -> str | None:
    """The first of `keys` present on the resource, compared without case or punctuation."""
    by_key = {_normalize_tag_key(k): v for k, v in (tags or {}).items()}
    for key in keys:
        value = by_key.get(_normalize_tag_key(key))
        if value not in (None, ""):
            return value
    return None


def access_key_records(created: dict | None, expiration_days: int | None, now: datetime) -> list[dict]:
    """Age of key1 and key2 from keyCreationTime, against keyPolicy.keyExpirationPeriodInDays."""
    records = []
    for name in ACCESS_KEY_NAMES:
        moment = _as_datetime((created or {}).get(name))
        age = (now - moment).days if moment else None
        records.append({
            "name": name,
            "created": _iso_utc(moment),
            "age_days": age,
            "exceeds_expiration_period": (
                age > expiration_days if age is not None and expiration_days is not None else None
            ),
        })
    return records


def geo_replication_stats_record(
    stats: dict | None, stats_status: str, now: datetime, message: str | None = None
) -> dict:
    """Secondary-region health; `sync_lag_minutes` is how far the secondary trails the primary."""
    stats = stats or {}
    last_sync = _as_datetime(stats.get("last_sync_time"))
    return {
        "stats_status": stats_status,
        "status": stats.get("status"),
        "last_sync_time": _iso_utc(last_sync),
        "sync_lag_minutes": int((now - last_sync).total_seconds() // 60) if last_sync else None,
        "can_failover": stats.get("can_failover"),
        "can_planned_failover": stats.get("can_planned_failover"),
        "post_failover_redundancy": stats.get("post_failover_redundancy"),
        "post_planned_failover_redundancy": stats.get("post_planned_failover_redundancy"),
        "message": message,
    }


def container_record(container: dict, account_allows_public_access: bool) -> dict:
    """One blob container; anonymous access needs both the container level and the account switch."""
    public_access = container.get("public_access") or "None"
    has_level = str(public_access).lower() != "none"
    return {
        "id": container.get("id"),
        "name": container.get("name"),
        "public_access": public_access,
        "anonymous_access_effective": has_level and bool(account_allows_public_access),
        "metadata_keys": container.get("metadata_keys"),
        "has_immutability_policy": bool(container.get("has_immutability_policy") or False),
        "has_legal_hold": bool(container.get("has_legal_hold") or False),
        "version_level_immutability": bool(container.get("version_level_immutability") or False),
        "last_modified_time": _iso_utc(container.get("last_modified_time")),
    }


def account_record(
    account: dict,
    now: datetime | None = None,
    owner_tag_keys: tuple = DEFAULT_OWNER_TAG_KEYS,
    classification_tag_keys: tuple = DEFAULT_CLASSIFICATION_TAG_KEYS,
) -> dict:
    """Normalize one projected storage account into an evidence record.

    Prowler's defaults are preserved: the API omits allow_cross_tenant_replication,
    allow_shared_key_access and the network_rule_set fields when they sit at their
    (permissive) service defaults, so absent must read as that default, not as None.
    """
    now = now or datetime.now(timezone.utc)
    resource_id = account.get("id")
    network_rule_set = account.get("network_rule_set") or {}

    key_source = account.get("encryption_type")
    key_expiration = account.get("key_expiration_period_in_days")

    cross_tenant = account.get("allow_cross_tenant_replication")
    shared_key = account.get("allow_shared_key_access")
    entra_auth = account.get("default_to_entra_authorization")

    sku = str(account.get("replication_settings") or "")
    expiration_days = int(key_expiration) if key_expiration is not None else None
    keys = access_key_records(account.get("key_creation_time"), expiration_days, now)
    ages = [k["age_days"] for k in keys if k["age_days"] is not None]
    exceeds = [k["exceeds_expiration_period"] for k in keys]
    tags = account.get("tags") or {}

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
        # --- geo-replication (stats filled in by the get_properties enrichment) ---
        "geo_redundant": bool(GEO_REDUNDANT_SKU.search(sku)),
        "read_access_secondary": bool(READ_ACCESS_SKU.search(sku)),
        "primary_location": account.get("primary_location"),
        "secondary_location": account.get("secondary_location"),
        "status_of_primary": account.get("status_of_primary"),
        "status_of_secondary": account.get("status_of_secondary"),
        "last_geo_failover_time": _iso_utc(account.get("last_geo_failover_time")),
        "geo_replication_stats": None,
        # --- access-key age ---
        "access_keys": keys,
        "access_key_max_age_days": max(ages) if ages else None,
        # None when there is no expiry policy or a key's creation time is unknown.
        "access_keys_within_expiration_period": (
            False if True in exceeds else None if None in exceeds else True
        ),
        # --- containers (filled in by the blob_containers enrichment) ---
        "containers_status": CONTAINERS_NOT_ATTEMPTED,
        "containers": None,
        # --- ownership ---
        "tags": dict(sorted(tags.items())),
        "owner_tag": tag_value(tags, owner_tag_keys),
        "classification_tag": tag_value(tags, classification_tag_keys),
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
        **summarize_replication_keys_containers(accounts),
    }


def summarize_replication_keys_containers(accounts: list[dict]) -> dict:
    geo = [a for a in accounts if a.get("geo_redundant")]
    stats = [a["geo_replication_stats"] for a in geo if a.get("geo_replication_stats")]
    collected = [s for s in stats if s["stats_status"] == STATS_COLLECTED]
    lags = [s["sync_lag_minutes"] for s in collected if s["sync_lag_minutes"] is not None]
    ages = [a["access_key_max_age_days"] for a in accounts if a.get("access_key_max_age_days") is not None]
    containers = [c for a in accounts for c in (a.get("containers") or [])]
    return {
        # --- geo-replication ---
        "geo_redundant_accounts": len(geo),
        "read_access_geo_redundant_accounts": sum(1 for a in geo if a["read_access_secondary"]),
        "geo_replication_stats_collected_accounts": len(collected),
        "geo_replication_live_accounts": sum(
            1 for s in collected if str(s["status"] or "").lower() == "live"
        ),
        "geo_replication_max_sync_lag_minutes": max(lags) if lags else None,
        "geo_failover_ready_accounts": sum(1 for s in collected if s["can_failover"]),
        "secondary_unavailable_accounts": sum(
            1 for a in geo if str(a.get("status_of_secondary") or "").lower() == "unavailable"
        ),
        "geo_failed_over_accounts": sum(1 for a in accounts if a.get("last_geo_failover_time")),
        # --- access-key age ---
        "access_key_age_known_accounts": sum(
            1
            for a in accounts
            if a.get("access_keys") and all(k["age_days"] is not None for k in a["access_keys"])
        ),
        "access_key_max_age_days": max(ages) if ages else None,
        "accounts_with_access_key_older_than_90_days": sum(
            1 for age in ages if age > ACCESS_KEY_AGE_BENCHMARK_DAYS
        ),
        "accounts_with_access_key_beyond_expiration_period": sum(
            1 for a in accounts if a.get("access_keys_within_expiration_period") is False
        ),
        # --- containers ---
        "total_containers": len(containers),
        "containers_with_public_access_level": sum(
            1 for c in containers if str(c["public_access"]).lower() != "none"
        ),
        "anonymously_accessible_containers": sum(1 for c in containers if c["anonymous_access_effective"]),
        "containers_with_immutability_policy": sum(1 for c in containers if c["has_immutability_policy"]),
        "containers_with_legal_hold": sum(1 for c in containers if c["has_legal_hold"]),
        "accounts_with_containers_not_collected": sum(
            1 for a in accounts if a.get("containers_status") == CONTAINERS_FAILED
        ),
        # --- ownership ---
        "accounts_with_owner_tag": sum(1 for a in accounts if a.get("owner_tag") is not None),
        "accounts_with_classification_tag": sum(
            1 for a in accounts if a.get("classification_tag") is not None
        ),
    }


# --- collection (lazy azure imports) ---

def _is_benign_unsupported(exc: BaseException) -> bool:
    message = str(exc).strip()
    return any(marker in message for marker in BENIGN_UNSUPPORTED_SERVICE)


def collect_storage_accounts(
    subscription_id, cred, collector: Collector, now: datetime | None = None
) -> list[dict]:
    """One storage_accounts.list() plus a blob/file service GET and a container list per account,
    and a get_properties(expand=geoReplicationStats) per geo-redundant account.

    The list response already carries the encryption / network / key-policy fields and
    keyCreationTime, so key age needs no key read; listKeys is never called.
    """
    from azure.mgmt.storage import StorageManagementClient

    now = now or datetime.now(timezone.utc)
    owner_keys = tag_keys_from_env(OWNER_TAG_KEYS_ENV, DEFAULT_OWNER_TAG_KEYS)
    classification_keys = tag_keys_from_env(CLASSIFICATION_TAG_KEYS_ENV, DEFAULT_CLASSIFICATION_TAG_KEYS)

    def _client():
        return StorageManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("storage.StorageManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [
            account_record(project_storage_account(a), now, owner_keys, classification_keys)
            for a in client.storage_accounts.list()
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
        if account["geo_redundant"]:
            account["geo_replication_stats"] = _geo_replication_stats(client, collector, group, name, now)
        _collect_containers(client, collector, account, group, name)

    return sorted(accounts, key=lambda r: r.get("id") or "")


def _geo_replication_stats(client, collector: Collector, group: str, name: str, now: datetime) -> dict:
    """get_properties(expand=geoReplicationStats); LastSyncTimeUnavailable is a posture, not a failure."""
    try:
        account = client.storage_accounts.get_properties(group, name, expand="geoReplicationStats")
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        message = " ".join(str(exc).split())[:300]
        if any(marker in message.lower() for marker in LAST_SYNC_UNAVAILABLE):
            logger.warning("storage account %s: last sync time unavailable — %s", name, message)
            return geo_replication_stats_record(None, STATS_UNAVAILABLE, now, message)
        collector.record(f"storage.storage_accounts.get_properties geoReplicationStats ({name})", exc)
        return geo_replication_stats_record(None, STATS_FAILED, now, message)
    stats = model_attr(account, "geo_replication_stats")
    if stats is None:
        return geo_replication_stats_record(None, STATS_NOT_APPLICABLE, now)
    return geo_replication_stats_record(project_geo_replication_stats(stats), STATS_COLLECTED, now)


def _collect_containers(client, collector: Collector, account: dict, group: str, name: str) -> None:
    """blob_containers.list(): every container's access level and immutability flags."""
    try:
        listed = [project_container(c) for c in client.blob_containers.list(group, name)]
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        if _is_benign_unsupported(exc):
            account["containers_status"] = CONTAINERS_NOT_SUPPORTED
            return
        collector.record(f"storage.blob_containers.list ({name})", exc)
        account["containers_status"] = CONTAINERS_FAILED
        return
    allows_public = account["allow_blob_public_access"]
    account["containers_status"] = CONTAINERS_COLLECTED
    account["containers"] = sorted(
        (container_record(c, allows_public) for c in listed), key=lambda r: r.get("name") or ""
    )


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
        accounts = collect_storage_accounts(subscription_id, cred, collector, datetime.now(timezone.utc))
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
