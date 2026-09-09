#!/usr/bin/env python3
"""
Azure Cosmos DB account security configuration

Per database account: the API kind, customer-managed-key encryption, local-auth,
network exposure (virtual-network firewall, IP rules, private endpoints, TLS floor),
automatic failover and the backup policy mode.

Ported from prowler/providers/azure/services/cosmosdb/cosmosdb_service.py
(Apache-2.0), adding `key_vault_key_uri`, the virtual-network / IP rule lists and
`network_acl_bypass`: without the allow-lists, "firewall enabled" is a bare boolean a
reviewer cannot check.
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

logger = logging.getLogger("azure_cosmosdb_configuration")

# BackupPolicy.type. "Continuous" gives point-in-time restore; "Periodic" is the older
# snapshot mode and the default when no explicit choice was made.
BACKUP_POLICY_CONTINUOUS = "continuous"

# "SecuredByPerimeter" is Microsoft's Network Security Perimeter, which Prowler accepts
# alongside "Disabled" as not reachable from the public internet.
PRIVATE_NETWORK_ACCESS = ("disabled", "securedbyperimeter")

# MinimalTlsVersion is spelled "Tls" / "Tls11" / "Tls12" / "Tls13". Absent is NOT
# compliant: an account that never set the property accepts TLS 1.0.
RECOMMENDED_TLS_VERSIONS = ("tls12", "tls13")


# --- projection: azure-mgmt models in, flat dicts out ---

def project_database_account(account) -> dict:
    """`backup_policy` comes back as the TYPED subclass the discriminator selected
    (`ContinuousModeBackupPolicy` / `PeriodicModeBackupPolicy`), so `.type` reads one
    level down. Values stay un-defaulted — None means the API did not return the
    field, and `account_record()` decides how to read an absence.
    """
    backup_policy = model_attr(account, "backup_policy")
    return {
        "id": model_attr(account, "id"),
        "name": model_attr(account, "name"),
        "type": model_attr(account, "type"),
        "location": model_attr(account, "location"),
        "kind": model_attr(account, "kind"),
        "tags": model_attr(account, "tags"),
        "database_account_offer_type": model_attr(account, "database_account_offer_type"),
        "document_endpoint": model_attr(account, "document_endpoint"),
        "disable_local_auth": model_attr(account, "disable_local_auth"),
        "default_identity": model_attr(account, "default_identity"),
        "is_virtual_network_filter_enabled": model_attr(
            account, "is_virtual_network_filter_enabled"
        ),
        "public_network_access": model_attr(account, "public_network_access"),
        "minimal_tls_version": model_attr(account, "minimal_tls_version"),
        "network_acl_bypass": model_attr(account, "network_acl_bypass"),
        "virtual_network_rules": [
            {
                "id": model_attr(rule, "id"),
                "ignore_missing_v_net_service_endpoint": model_attr(
                    rule, "ignore_missing_v_net_service_endpoint"
                ),
            }
            for rule in (model_attr(account, "virtual_network_rules") or [])
        ],
        "ip_rules": [
            model_attr(rule, "ip_address_or_range")
            for rule in (model_attr(account, "ip_rules") or [])
        ],
        "private_endpoint_connections": [
            {
                "id": model_attr(pec, "id"),
                "name": model_attr(pec, "name"),
                "type": model_attr(pec, "type"),
                "provisioning_state": model_attr(pec, "provisioning_state"),
            }
            for pec in (model_attr(account, "private_endpoint_connections") or [])
        ],
        "key_vault_key_uri": model_attr(account, "key_vault_key_uri"),
        "enable_automatic_failover": model_attr(account, "enable_automatic_failover"),
        "enable_multiple_write_locations": model_attr(
            account, "enable_multiple_write_locations"
        ),
        "backup_policy_type": model_attr(backup_policy, "type"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def account_record(account: dict) -> dict:
    """Optional booleans are coerced with `bool(x or False)`: Azure OMITS
    `disableLocalAuth`, `enableAutomaticFailover` and `isVirtualNetworkFilterEnabled`
    at their false-y defaults rather than returning `false`, and a validator regex
    asserting `false` would not match `null`. Absent means disabled for all three.
    """
    resource_id = account.get("id")
    key_vault_key_uri = account.get("key_vault_key_uri")
    backup_policy_type = account.get("backup_policy_type")
    public_network_access = account.get("public_network_access")
    minimal_tls_version = account.get("minimal_tls_version")
    private_endpoints = account.get("private_endpoint_connections") or []

    return {
        "id": resource_id,
        "name": account.get("name"),
        "type": account.get("type"),
        "location": account.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "kind": account.get("kind"),
        "tags": account.get("tags") or {},
        "database_account_offer_type": account.get("database_account_offer_type"),
        "document_endpoint": account.get("document_endpoint"),
        # --- encryption at rest ---
        "key_vault_key_uri": key_vault_key_uri,
        "customer_managed_key": bool(key_vault_key_uri),
        # --- authentication ---
        "disable_local_auth": bool(account.get("disable_local_auth") or False),
        "default_identity": account.get("default_identity"),
        # --- network exposure ---
        "is_virtual_network_filter_enabled": bool(
            account.get("is_virtual_network_filter_enabled") or False
        ),
        "public_network_access": public_network_access,
        "public_network_access_disabled": (
            str(public_network_access or "").lower() in PRIVATE_NETWORK_ACCESS
        ),
        "minimal_tls_version": minimal_tls_version,
        # Absent accepts TLS 1.0, so it is not compliant.
        "minimal_tls_version_recommended": (
            str(minimal_tls_version or "").lower() in RECOMMENDED_TLS_VERSIONS
        ),
        "network_acl_bypass": account.get("network_acl_bypass"),
        "virtual_network_rules": [
            {
                "id": rule.get("id"),
                "ignore_missing_v_net_service_endpoint": bool(
                    rule.get("ignore_missing_v_net_service_endpoint") or False
                ),
            }
            for rule in (account.get("virtual_network_rules") or [])
        ],
        "ip_rules": [rule for rule in (account.get("ip_rules") or []) if rule],
        "private_endpoint_connections": [
            {
                "id": pec.get("id"),
                "name": pec.get("name"),
                "type": pec.get("type"),
                "provisioning_state": pec.get("provisioning_state"),
            }
            for pec in private_endpoints
        ],
        "uses_private_endpoints": bool(private_endpoints),
        # --- durability ---
        "enable_automatic_failover": bool(account.get("enable_automatic_failover") or False),
        "enable_multiple_write_locations": bool(
            account.get("enable_multiple_write_locations") or False
        ),
        "backup_policy_type": backup_policy_type,
        "continuous_backup": str(backup_policy_type or "").lower() == BACKUP_POLICY_CONTINUOUS,
    }


def summarize(accounts: list[dict]) -> dict:
    """CMK coverage, not encrypted/total: Cosmos DB encrypts at rest unconditionally, so
    an "encrypted" percentage would be a constant 100.
    """
    total = len(accounts)
    cmk = sum(1 for a in accounts if a["customer_managed_key"])
    return {
        "total_cosmosdb_accounts": total,
        "customer_managed_key_accounts": cmk,
        "platform_managed_key_accounts": total - cmk,
        "cmk_percentage": coverage_percentage(cmk, total),
        "local_auth_disabled_accounts": sum(1 for a in accounts if a["disable_local_auth"]),
        "virtual_network_filter_accounts": sum(
            1 for a in accounts if a["is_virtual_network_filter_enabled"]
        ),
        "public_network_access_disabled_accounts": sum(
            1 for a in accounts if a["public_network_access_disabled"]
        ),
        "recommended_minimal_tls_accounts": sum(
            1 for a in accounts if a["minimal_tls_version_recommended"]
        ),
        "private_endpoint_accounts": sum(1 for a in accounts if a["uses_private_endpoints"]),
        "automatic_failover_accounts": sum(
            1 for a in accounts if a["enable_automatic_failover"]
        ),
        "multiple_write_location_accounts": sum(
            1 for a in accounts if a["enable_multiple_write_locations"]
        ),
        "continuous_backup_accounts": sum(1 for a in accounts if a["continuous_backup"]),
        "accounts_by_kind": _count_by_kind(accounts),
    }


def _count_by_kind(accounts: list[dict]) -> dict:
    """Accounts per API kind, sorted so the summary block is byte-stable between runs
    (a regex validator must not fire on key reordering alone).
    """
    counts: dict[str, int] = {}
    for account in accounts:
        kind = account.get("kind") or "unknown"
        counts[kind] = counts.get(kind, 0) + 1
    return dict(sorted(counts.items()))


# --- collection (lazy azure imports) ---

def collect_database_accounts(subscription_id, cred, collector: Collector) -> list[dict]:
    """One database_accounts.list() — the whole projection is in that response."""

    def _client():
        from azure.mgmt.cosmosdb import CosmosDBManagementClient  # lazy

        return CosmosDBManagementClient(credential=cred, subscription_id=subscription_id)

    # Guarded: a missing azure-mgmt-cosmosdb becomes internal_error, evidence still written.
    client = collector.guard("cosmosdb.CosmosDBManagementClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself, so pagination is handled.
        return [
            account_record(project_database_account(a))
            for a in client.database_accounts.list()
        ]

    accounts = collector.guard("cosmosdb.database_accounts.list", _list, default=[])
    return sorted(accounts, key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request/response header at INFO — far too noisy here.
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
        # Asked first: an unregistered provider returns an empty list, not an error.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.DocumentDB"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.DocumentDB is not registered on subscription %s — no Cosmos "
                "DB in use; reporting status not_registered",
                subscription_id,
            )
        accounts = collect_database_accounts(subscription_id, cred, collector)
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
            "cosmosdb_accounts": accounts,
            "provider_registration_status": registration,
        },
        summary={**summarize(accounts), "provider_registration_status": registration},
    )

    filename = (
        f"azure_cosmosdb_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
