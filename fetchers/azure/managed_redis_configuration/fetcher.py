#!/usr/bin/env python3
"""Azure Managed Redis (redisEnterprise) cluster and database security configuration."""

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

logger = logging.getLogger("azure_managed_redis_configuration")

RECOMMENDED_TLS_VERSIONS = ("1.2", "1.3")


def project_cluster(cluster) -> dict:
    """Flat snake_case view of a redisEnterprise Cluster model."""
    sku = model_attr(cluster, "sku")
    encryption = model_attr(cluster, "encryption")
    cmk = model_attr(encryption, "customer_managed_key_encryption")
    return {
        "id": model_attr(cluster, "id"),
        "name": model_attr(cluster, "name"),
        "location": model_attr(cluster, "location"),
        "kind": model_attr(cluster, "kind"),
        "tags": model_attr(cluster, "tags"),
        "sku_name": model_attr(sku, "name"),
        "sku_capacity": model_attr(sku, "capacity"),
        "zones": model_attr(cluster, "zones"),
        "high_availability": model_attr(cluster, "high_availability"),
        "redundancy_mode": model_attr(cluster, "redundancy_mode"),
        "redis_version": model_attr(cluster, "redis_version"),
        "host_name": model_attr(cluster, "host_name"),
        "provisioning_state": model_attr(cluster, "provisioning_state"),
        "resource_state": model_attr(cluster, "resource_state"),
        "minimum_tls_version": model_attr(cluster, "minimum_tls_version"),
        "public_network_access": model_attr(cluster, "public_network_access"),
        "cmk_key_url": model_attr(cmk, "key_encryption_key_url"),
        "private_endpoint_connections": [
            {
                "id": model_attr(pec, "id"),
                "name": model_attr(pec, "name"),
                "provisioning_state": model_attr(pec, "provisioning_state"),
                "status": model_attr(
                    model_attr(pec, "private_link_service_connection_state"), "status"
                ),
            }
            for pec in (model_attr(cluster, "private_endpoint_connections") or [])
        ],
    }


def project_database(db) -> dict:
    """Flat snake_case view of a redisEnterprise Database model."""
    persistence = model_attr(db, "persistence")
    geo = model_attr(db, "geo_replication")
    return {
        "id": model_attr(db, "id"),
        "name": model_attr(db, "name"),
        "port": model_attr(db, "port"),
        "client_protocol": model_attr(db, "client_protocol"),
        "access_keys_authentication": model_attr(db, "access_keys_authentication"),
        "clustering_policy": model_attr(db, "clustering_policy"),
        "eviction_policy": model_attr(db, "eviction_policy"),
        "redis_version": model_attr(db, "redis_version"),
        "provisioning_state": model_attr(db, "provisioning_state"),
        "aof_enabled": model_attr(persistence, "aof_enabled"),
        "rdb_enabled": model_attr(persistence, "rdb_enabled"),
        "geo_replication_group": model_attr(geo, "group_nickname"),
        "geo_replication_linked_databases": [
            model_attr(link, "id") for link in (model_attr(geo, "linked_databases") or [])
        ],
        "modules": [model_attr(m, "name") for m in (model_attr(db, "modules") or [])],
    }


def database_record(db: dict) -> dict:
    """Absent access_keys_authentication is treated as Enabled, the pre-2024 service default."""
    protocol = db.get("client_protocol")
    keys = db.get("access_keys_authentication")
    return {
        **db,
        "client_protocol_encrypted": str(protocol or "").lower() == "encrypted",
        "access_keys_authentication_disabled": str(keys or "").lower() == "disabled",
        "aof_enabled": bool(db.get("aof_enabled") or False),
        "rdb_enabled": bool(db.get("rdb_enabled") or False),
    }


def cluster_record(cluster: dict, databases: list[dict]) -> dict:
    """Evidence record for one cluster, its databases nested beneath it."""
    resource_id = cluster.get("id")
    tls = cluster.get("minimum_tls_version")
    pna = cluster.get("public_network_access")
    pecs = cluster.get("private_endpoint_connections") or []
    approved = [p for p in pecs if str(p.get("status") or "").lower() == "approved"]
    tls_ok = str(tls or "") in RECOMMENDED_TLS_VERSIONS
    public_disabled = str(pna or "").lower() == "disabled"
    return {
        **cluster,
        "resource_group": resource_group_from_id(resource_id),
        "tags": cluster.get("tags") or {},
        "zones": cluster.get("zones") or [],
        "customer_managed_key": bool(cluster.get("cmk_key_url")),
        "minimum_tls_version_recommended": tls_ok,
        "public_network_access_disabled": public_disabled,
        "approved_private_endpoints": len(approved),
        "private_only": public_disabled and bool(approved),
        "databases": databases,
        "tls_only": tls_ok and all(d["client_protocol_encrypted"] for d in databases),
        "entra_only": bool(databases)
        and all(d["access_keys_authentication_disabled"] for d in databases),
    }


def summarize(clusters: list[dict]) -> dict:
    """Counts per posture property; databases are counted across every cluster."""
    total = len(clusters)
    dbs = [d for c in clusters for d in c["databases"]]
    tls_only = sum(1 for c in clusters if c["tls_only"])
    return {
        "total_clusters": total,
        "total_databases": len(dbs),
        "tls_only_clusters": tls_only,
        "tls_only_percentage": coverage_percentage(tls_only, total),
        "recommended_minimum_tls_clusters": sum(
            1 for c in clusters if c["minimum_tls_version_recommended"]
        ),
        "public_network_access_disabled_clusters": sum(
            1 for c in clusters if c["public_network_access_disabled"]
        ),
        "private_only_clusters": sum(1 for c in clusters if c["private_only"]),
        "customer_managed_key_clusters": sum(1 for c in clusters if c["customer_managed_key"]),
        "encrypted_protocol_databases": sum(1 for d in dbs if d["client_protocol_encrypted"]),
        "plaintext_protocol_databases": sum(1 for d in dbs if not d["client_protocol_encrypted"]),
        "access_keys_disabled_databases": sum(
            1 for d in dbs if d["access_keys_authentication_disabled"]
        ),
        "access_keys_enabled_databases": sum(
            1 for d in dbs if not d["access_keys_authentication_disabled"]
        ),
    }


def collect_clusters(subscription_id, cred, collector: Collector) -> list[dict]:
    """redis_enterprise.list() then databases.list_by_cluster per cluster."""

    def _client():
        from azure.mgmt.redisenterprise import RedisEnterpriseManagementClient  # lazy

        return RedisEnterpriseManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    client = collector.guard("redisenterprise.RedisEnterpriseManagementClient (init)", _client)
    if client is None:
        return []

    raw = collector.guard(
        "redisenterprise.redis_enterprise.list",
        lambda: [project_cluster(c) for c in client.redis_enterprise.list()],
        default=[],
    )
    records = []
    for cluster in raw:
        rg = resource_group_from_id(cluster.get("id"))
        name = cluster.get("name")
        dbs = collector.guard(
            f"redisenterprise.databases.list_by_cluster({rg}/{name})",
            lambda: [
                database_record(project_database(d))
                for d in client.databases.list_by_cluster(rg, name)
            ],
            default=[],
        )
        records.append(cluster_record(cluster, sorted(dbs, key=lambda d: d.get("id") or "")))
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

    clusters: list[dict] = []
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
        clusters = collect_clusters(subscription_id, cred, collector)
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
        results={"redis_clusters": clusters, "provider_registration_status": registration},
        summary={**summarize(clusters), "provider_registration_status": registration},
    )
    filename = (
        "azure_managed_redis_configuration_"
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
