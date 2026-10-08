#!/usr/bin/env python3
"""Azure Cache for Redis (classic) transport, authentication and network configuration."""

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
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)

logger = logging.getLogger("azure_redis_cache_configuration")

RECOMMENDED_TLS_VERSIONS = ("1.2", "1.3")


def project_cache(cache) -> dict:
    """Allow-list projection: access_keys and the storage connection strings are never read."""
    sku = model_attr(cache, "sku")
    config = model_attr(cache, "redis_configuration")
    return {
        "id": model_attr(cache, "id"),
        "name": model_attr(cache, "name"),
        "location": model_attr(cache, "location"),
        "tags": model_attr(cache, "tags"),
        "sku_name": model_attr(sku, "name"),
        "sku_family": model_attr(sku, "family"),
        "sku_capacity": model_attr(sku, "capacity"),
        "redis_version": model_attr(cache, "redis_version"),
        "host_name": model_attr(cache, "host_name"),
        "port": model_attr(cache, "port"),
        "ssl_port": model_attr(cache, "ssl_port"),
        "enable_non_ssl_port": model_attr(cache, "enable_non_ssl_port"),
        "minimum_tls_version": model_attr(cache, "minimum_tls_version"),
        "public_network_access": model_attr(cache, "public_network_access"),
        "disable_access_key_authentication": model_attr(cache, "disable_access_key_authentication"),
        "aad_enabled": model_attr(config, "aad_enabled"),
        "authnotrequired": model_attr(config, "authnotrequired"),
        "rdb_backup_enabled": model_attr(config, "rdb_backup_enabled"),
        "aof_backup_enabled": model_attr(config, "aof_backup_enabled"),
        "subnet_id": model_attr(cache, "subnet_id"),
        "zones": model_attr(cache, "zones"),
        "replicas_per_primary": model_attr(cache, "replicas_per_primary"),
        "shard_count": model_attr(cache, "shard_count"),
        "update_channel": model_attr(cache, "update_channel"),
        "provisioning_state": model_attr(cache, "provisioning_state"),
        "private_endpoint_connections": [
            {
                "id": model_attr(pec, "id"),
                "name": model_attr(pec, "name"),
                "provisioning_state": model_attr(pec, "provisioning_state"),
                "status": model_attr(
                    model_attr(pec, "private_link_service_connection_state"), "status"
                ),
            }
            for pec in (model_attr(cache, "private_endpoint_connections") or [])
        ],
    }


def project_firewall_rule(rule) -> dict:
    return {
        "name": model_attr(rule, "name"),
        "start_ip": model_attr(rule, "start_ip"),
        "end_ip": model_attr(rule, "end_ip"),
    }


def cache_record(cache: dict, firewall_rules) -> dict:
    """`firewall_rules` is None when the rule list could not be read."""
    tls = cache.get("minimum_tls_version")
    pna = cache.get("public_network_access")
    pecs = cache.get("private_endpoint_connections") or []
    approved = [p for p in pecs if str(p.get("status") or "").lower() == "approved"]
    tls_ok = str(tls or "") in RECOMMENDED_TLS_VERSIONS
    non_ssl = bool(cache.get("enable_non_ssl_port") or False)
    public_disabled = str(pna or "").lower() == "disabled"
    vnet_injected = bool(cache.get("subnet_id"))
    return {
        **cache,
        "resource_group": resource_group_from_id(cache.get("id")),
        "tags": cache.get("tags") or {},
        "zones": cache.get("zones") or [],
        "enable_non_ssl_port": non_ssl,
        "minimum_tls_version_recommended": tls_ok,
        "tls_only": tls_ok and not non_ssl,
        "auth_required": str(cache.get("authnotrequired") or "").lower() != "true",
        "entra_only": bool(cache.get("disable_access_key_authentication") or False),
        "entra_auth_enabled": str(cache.get("aad_enabled") or "").lower() == "true",
        "public_network_access_disabled": public_disabled,
        "approved_private_endpoints": len(approved),
        "vnet_injected": vnet_injected,
        "private_only": public_disabled and (bool(approved) or vnet_injected),
        "firewall_rules_read": firewall_rules is not None,
        "firewall_rules": firewall_rules,
    }


def summarize(caches: list[dict]) -> dict:
    total = len(caches)
    tls_only = sum(1 for c in caches if c["tls_only"])
    by_sku: dict[str, int] = {}
    for c in caches:
        sku = c.get("sku_name") or "unknown"
        by_sku[sku] = by_sku.get(sku, 0) + 1
    return {
        "total_caches": total,
        "tls_only_caches": tls_only,
        "tls_only_percentage": coverage_percentage(tls_only, total),
        "recommended_minimum_tls_caches": sum(1 for c in caches if c["minimum_tls_version_recommended"]),
        "non_ssl_port_enabled_caches": sum(1 for c in caches if c["enable_non_ssl_port"]),
        "auth_not_required_caches": sum(1 for c in caches if not c["auth_required"]),
        "access_keys_disabled_caches": sum(1 for c in caches if c["entra_only"]),
        "entra_auth_enabled_caches": sum(1 for c in caches if c["entra_auth_enabled"]),
        "public_network_access_disabled_caches": sum(
            1 for c in caches if c["public_network_access_disabled"]
        ),
        "public_network_access_unset_caches": sum(
            1 for c in caches if c.get("public_network_access") is None
        ),
        "private_only_caches": sum(1 for c in caches if c["private_only"]),
        "vnet_injected_caches": sum(1 for c in caches if c["vnet_injected"]),
        "firewall_rules_unread_caches": sum(1 for c in caches if not c["firewall_rules_read"]),
        "caches_by_sku": dict(sorted(by_sku.items())),
    }


def collect_caches(subscription_id, cred, collector: Collector) -> list[dict]:
    """redis.list_by_subscription(), then firewall_rules.list per cache."""

    def _client():
        from azure.mgmt.redis import RedisManagementClient  # lazy

        return RedisManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    client = collector.guard("redis.RedisManagementClient (init)", _client)
    if client is None:
        return []

    caches = collector.guard(
        "redis.redis.list_by_subscription",
        lambda: [project_cache(c) for c in client.redis.list_by_subscription()],
        default=[],
    )
    records = []
    for cache in caches:
        rg = resource_group_from_id(cache.get("id"))
        name = cache.get("name")
        rules = collector.guard(
            f"redis.firewall_rules.list({rg}/{name})",
            lambda: sorted(
                (project_firewall_rule(r) for r in client.firewall_rules.list(rg, name)),
                key=lambda r: r.get("name") or "",
            ),
        )
        records.append(cache_record(cache, rules))
    return sorted(records, key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    caches: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Cache"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Cache is not registered on subscription %s — reporting "
                "status not_registered",
                subscription_id,
            )
        caches = collect_caches(subscription_id, cred, collector)
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
        results={"redis_caches": caches, "provider_registration_status": registration},
        summary={**summarize(caches), "provider_registration_status": registration},
    )
    filename = (
        "azure_redis_cache_configuration_"
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
