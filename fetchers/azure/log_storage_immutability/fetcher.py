#!/usr/bin/env python3
"""Immutability of the blob containers Azure Monitor writes logs to: retention policies, legal holds, and soft delete."""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import ArmError, dig, run_subscription  # noqa: E402

NAME = "azure_log_storage_immutability"
STORAGE_API = "2023-05-01"

# Container names Azure Monitor itself creates: diagnostic settings, the Activity Log, metrics, and workspace data export.
LOG_CONTAINER_PREFIXES = (
    ("insights-activity-logs", "activity_log"),
    ("insights-logs-", "resource_logs"),
    ("insights-metrics-", "metrics"),
    ("am-", "workspace_export"),
)

logger = logging.getLogger(NAME)


def list_containers(client, account: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Containers of one account; an account with no blob service (FileStorage) has none, which is not a failure."""
    if (account.get("kind") or "").lower() == "filestorage":
        return []
    try:
        return client.list(f"{account['id']}/blobServices/default/containers", STORAGE_API)
    except ArmError as exc:
        if exc.code == "FeatureNotSupportedForAccount":
            return []
        raise


def log_type(container_name: str) -> Optional[str]:
    name = (container_name or "").lower()
    return next((kind for prefix, kind in LOG_CONTAINER_PREFIXES if name.startswith(prefix)), None)


def project_container(container: Dict[str, Any], account_version_level: bool) -> Dict[str, Any]:
    props = container.get("properties") or {}
    policy = dig(props, "immutabilityPolicy", "properties") or {}
    state = policy.get("state")
    days = policy.get("immutabilityPeriodSinceCreationInDays")
    legal_hold = props.get("hasLegalHold") is True
    version_level = dig(props, "immutableStorageWithVersioning", "enabled") is True or account_version_level
    return {
        "container": container.get("name"),
        "log_type": log_type(container.get("name")),
        "time_based_policy_state": state if props.get("hasImmutabilityPolicy") else None,
        "retention_days": days if props.get("hasImmutabilityPolicy") else None,
        "allow_protected_append_writes": policy.get("allowProtectedAppendWrites"),
        "legal_hold": legal_hold,
        "version_level_immutability": version_level,
        "locked": state == "Locked" and props.get("hasImmutabilityPolicy") is True,
        "protected": legal_hold or (props.get("hasImmutabilityPolicy") is True and state in ("Locked", "Unlocked")),
    }


def collect(client, subscription_id: str, collector) -> tuple:
    accounts = collector.guard(
        "storage.storageAccounts.list",
        lambda: client.list(f"/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts", STORAGE_API),
    )
    if accounts is None:
        return {"accounts": None}, {}
    out: List[Dict[str, Any]] = []
    for account in sorted(accounts, key=lambda a: (a.get("id") or "").lower()):
        containers = collector.guard(
            f"storage.blobContainers.list({account.get('name')})",
            lambda a=account: list_containers(client, a),
        )
        logs = [c for c in containers or [] if log_type(c.get("name"))]
        if not logs:
            continue
        service = collector.guard(
            f"storage.blobServices.get({account.get('name')})",
            lambda a=account: client.get(f"{a['id']}/blobServices/default", STORAGE_API),
        ) or {}
        account_level = dig(account, "properties", "immutableStorageWithVersioning") or {}
        projected = sorted(
            (project_container(c, account_level.get("enabled") is True) for c in logs), key=lambda c: c["container"]
        )
        out.append({
            "account": account.get("name"),
            "id": account.get("id"),
            "account_version_level_immutability": account_level.get("enabled") is True,
            "account_default_policy": account_level.get("immutabilityPolicy"),
            "blob_soft_delete_days": dig(service, "properties", "deleteRetentionPolicy", "days")
            if dig(service, "properties", "deleteRetentionPolicy", "enabled") else 0,
            "versioning_enabled": dig(service, "properties", "isVersioningEnabled") is True,
            "log_containers": projected,
        })

    containers = [c for a in out for c in a["log_containers"]]
    retention = [c["retention_days"] for c in containers if c["retention_days"] is not None]
    summary = {
        "storage_accounts_scanned": len(accounts),
        "accounts_with_log_containers": len(out),
        "log_containers": len(containers),
        "locked_policy": sum(1 for c in containers if c["locked"]),
        "unlocked_policy_only": sum(1 for c in containers if c["time_based_policy_state"] == "Unlocked" and not c["legal_hold"]),
        "legal_hold": sum(1 for c in containers if c["legal_hold"]),
        "unprotected": sum(1 for c in containers if not c["protected"]),
        "min_retention_days": min(retention) if retention else None,
    }
    return {"accounts": out}, summary


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
