#!/usr/bin/env python3
"""Azure Cache for Redis (classic): transport, authentication, data access, network, logging, patching and resilience."""

import ipaddress
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
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)
from diagnostics import audit_logging_summary, list_diagnostic_settings  # noqa: E402

logger = logging.getLogger("azure_redis_cache_configuration")

RECOMMENDED_TLS_VERSIONS = ("1.2", "1.3")
# Connection and Entra sign-in audit logs, the data-plane audit trail a cache can export.
REDIS_AUDIT_CATEGORIES = ("ConnectedClientList", "MSEntraAuthenticationAuditLog")
# Basic is a single node with no replica and no SLA.
UNREPLICATED_SKUS = ("basic",)


# --- projection: allow-listed, so access_keys and storage connection strings are never read ---

def project_cache(cache) -> dict:
    sku = model_attr(cache, "sku")
    config = model_attr(cache, "redis_configuration")
    identity = model_attr(cache, "identity")
    return {
        "id": model_attr(cache, "id"),
        "name": model_attr(cache, "name"),
        "location": model_attr(cache, "location"),
        "tags": model_attr(cache, "tags"),
        "sku_name": model_attr(sku, "name"),
        "sku_family": model_attr(sku, "family"),
        "sku_capacity": model_attr(sku, "capacity"),
        "redis_version": model_attr(cache, "redis_version"),
        "update_channel": model_attr(cache, "update_channel"),
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
        "rdb_backup_frequency": model_attr(config, "rdb_backup_frequency"),
        "aof_backup_enabled": model_attr(config, "aof_backup_enabled"),
        "preferred_data_persistence_auth_method": model_attr(config, "preferred_data_persistence_auth_method"),
        "identity_type": model_attr(identity, "type"),
        "subnet_id": model_attr(cache, "subnet_id"),
        "zones": model_attr(cache, "zones"),
        "replicas_per_primary": model_attr(cache, "replicas_per_primary"),
        "shard_count": model_attr(cache, "shard_count"),
        "provisioning_state": model_attr(cache, "provisioning_state"),
        "private_endpoint_connections": [
            {
                "id": model_attr(pec, "id"),
                "name": model_attr(pec, "name"),
                "provisioning_state": model_attr(pec, "provisioning_state"),
                "status": model_attr(model_attr(pec, "private_link_service_connection_state"), "status"),
            }
            for pec in (model_attr(cache, "private_endpoint_connections") or [])
        ],
    }


def firewall_rule_record(rule) -> dict:
    start, end = model_attr(rule, "start_ip"), model_attr(rule, "end_ip")
    try:
        first, last = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
        count = last - first + 1 if last >= first else 0
    except (ipaddress.AddressValueError, TypeError, ValueError):
        first = last = count = None
    return {
        "name": model_attr(rule, "name"),
        "start_ip": start,
        "end_ip": end,
        "address_count": count,
        "allows_all_ips": first == 0 and last == 2**32 - 1,
    }


def project_access_policy(policy) -> dict:
    return {
        "name": model_attr(policy, "name"),
        "type": model_attr(policy, "type_properties_type"),
        "permissions": model_attr(policy, "permissions"),
    }


def project_access_assignment(assignment) -> dict:
    return {
        "name": model_attr(assignment, "name"),
        "access_policy_name": model_attr(assignment, "access_policy_name"),
        "object_id": model_attr(assignment, "object_id"),
        "object_id_alias": model_attr(assignment, "object_id_alias"),
    }


def project_schedule_entry(entry) -> dict:
    return {
        "day_of_week": model_attr(entry, "day_of_week"),
        "start_hour_utc": model_attr(entry, "start_hour_utc"),
        "maintenance_window": str(model_attr(entry, "maintenance_window") or "") or None,
    }


def project_linked_server(link) -> dict:
    return {
        "name": model_attr(link, "name"),
        "linked_redis_cache": basename(model_attr(link, "linked_redis_cache_id")),
        "linked_redis_cache_location": model_attr(link, "linked_redis_cache_location"),
        "server_role": model_attr(link, "server_role"),
    }


# --- pure transforms ---

def _sorted(records, key):
    return None if records is None else sorted(records, key=lambda r: r.get(key) or "")


def cache_record(cache: dict, extras: dict) -> dict:
    """`extras` holds the per-cache reads; a value of None means that read failed (unknown)."""
    tls = cache.get("minimum_tls_version")
    pna = cache.get("public_network_access")
    pecs = cache.get("private_endpoint_connections") or []
    approved = [p for p in pecs if str(p.get("status") or "").lower() == "approved"]
    tls_ok = str(tls or "") in RECOMMENDED_TLS_VERSIONS
    non_ssl = bool(cache.get("enable_non_ssl_port") or False)
    public_disabled = str(pna or "").lower() == "disabled"
    vnet_injected = bool(cache.get("subnet_id"))
    auth_required = str(cache.get("authnotrequired") or "").lower() != "true"
    keys_disabled = bool(cache.get("disable_access_key_authentication") or False)
    entra = str(cache.get("aad_enabled") or "").lower() == "true"
    rules = _sorted(extras.get("firewall_rules"), "name")
    schedule = extras.get("patch_schedule")
    linked = _sorted(extras.get("linked_servers"), "name")
    sku = str(cache.get("sku_name") or "").lower()
    zones = cache.get("zones") or []
    return {
        **cache,
        "resource_group": resource_group_from_id(cache.get("id")),
        "tags": cache.get("tags") or {},
        "zones": zones,
        # --- transport ---
        "enable_non_ssl_port": non_ssl,
        "minimum_tls_version_recommended": tls_ok,
        "tls_only": tls_ok and not non_ssl,
        # --- authentication and data access ---
        "auth_required": auth_required,
        "entra_only": keys_disabled,
        "entra_auth_enabled": entra,
        "auth_methods": sorted(
            ([] if keys_disabled else ["access_key_auth"]) + (["entra_id"] if entra else [])
        ) if auth_required else ["none"],
        "access_policies": _sorted(extras.get("access_policies"), "name"),
        "access_policy_assignments": _sorted(extras.get("access_policy_assignments"), "object_id"),
        # --- network exposure ---
        "public_network_access_disabled": public_disabled,
        "approved_private_endpoints": len(approved),
        "vnet_injected": vnet_injected,
        "private_only": public_disabled and (bool(approved) or vnet_injected),
        "firewall_rules": rules,
        "firewall_allows_all_ips": None if rules is None else any(r["allows_all_ips"] for r in rules),
        # --- logging ---
        **audit_logging_summary(extras.get("diagnostic_settings"), REDIS_AUDIT_CATEGORIES),
        # --- patching ---
        "patch_schedule": schedule,
        "maintenance_window_configured": None if schedule is None else bool(schedule),
        # --- resilience ---
        "replicated": sku not in UNREPLICATED_SKUS,
        "zone_redundant": len(zones) > 1,
        "linked_servers": linked,
        "geo_replicated": None if linked is None else bool(linked),
        "persistence_enabled": str(cache.get("rdb_backup_enabled") or "").lower() == "true"
        or str(cache.get("aof_backup_enabled") or "").lower() == "true",
    }


# Exception lists name the caches behind each failed expectation, so a reviewer can sample them.
EXCEPTIONS = {
    "not_tls_only": lambda c: not c["tls_only"],
    "non_ssl_port_enabled": lambda c: c["enable_non_ssl_port"],
    "auth_not_required": lambda c: not c["auth_required"],
    "access_keys_enabled": lambda c: not c["entra_only"],
    "public_network_access_not_disabled": lambda c: not c["public_network_access_disabled"],
    "firewall_allows_all_ips": lambda c: c["firewall_allows_all_ips"] is True,
    "no_audit_logging": lambda c: c["audit_logging_enabled"] is False,
    "no_maintenance_window": lambda c: c["maintenance_window_configured"] is False,
    "not_replicated": lambda c: not c["replicated"],
    "unknown_state": lambda c: any(
        c[k] is None for k in ("firewall_rules", "audit_logging_enabled", "maintenance_window_configured",
                               "access_policy_assignments", "geo_replicated")
    ),
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
        "access_policy_assignments": sum(len(c["access_policy_assignments"] or []) for c in caches),
        "public_network_access_disabled_caches": sum(1 for c in caches if c["public_network_access_disabled"]),
        "public_network_access_unset_caches": sum(1 for c in caches if c.get("public_network_access") is None),
        "private_only_caches": sum(1 for c in caches if c["private_only"]),
        "vnet_injected_caches": sum(1 for c in caches if c["vnet_injected"]),
        "firewall_allows_all_ips_caches": sum(1 for c in caches if c["firewall_allows_all_ips"] is True),
        "audit_logging_enabled_caches": sum(1 for c in caches if c["audit_logging_enabled"] is True),
        "maintenance_window_caches": sum(1 for c in caches if c["maintenance_window_configured"] is True),
        "replicated_caches": sum(1 for c in caches if c["replicated"]),
        "zone_redundant_caches": sum(1 for c in caches if c["zone_redundant"]),
        "geo_replicated_caches": sum(1 for c in caches if c["geo_replicated"] is True),
        "persistence_enabled_caches": sum(1 for c in caches if c["persistence_enabled"]),
        "caches_by_sku": dict(sorted(by_sku.items())),
        "caches_by_redis_version": dict(sorted(
            {v: sum(1 for c in caches if (c.get("redis_version") or "unknown") == v)
             for v in {c.get("redis_version") or "unknown" for c in caches}}.items()
        )),
        "exceptions": {
            name: sorted(c["name"] for c in caches if test(c)) for name, test in EXCEPTIONS.items()
        },
    }


# --- collection (lazy azure imports) ---

def _patch_schedule(client, rg, name):
    """No schedule is a 404 ("There are no patch schedules"), which means Azure picks the time."""
    from azure.core.exceptions import ResourceNotFoundError  # lazy

    try:
        return [
            project_schedule_entry(e)
            for s in client.patch_schedules.list_by_redis_resource(rg, name)
            for e in (model_attr(s, "schedule_entries") or [])
        ]
    except ResourceNotFoundError:
        return []


def collect_caches(subscription_id, cred, collector: Collector) -> list[dict]:
    def _clients():
        from azure.mgmt.monitor import MonitorManagementClient  # lazy
        from azure.mgmt.redis import RedisManagementClient  # lazy

        return (
            RedisManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
            MonitorManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
        )

    clients = collector.guard("redis.RedisManagementClient (init)", _clients)
    if clients is None:
        return []
    client, monitor = clients

    caches = collector.guard(
        "redis.redis.list_by_subscription",
        lambda: [project_cache(c) for c in client.redis.list_by_subscription()],
        default=[],
    )
    records = []
    for cache in caches:
        rg, name, cid = resource_group_from_id(cache.get("id")), cache.get("name"), cache.get("id")
        reads = {
            "firewall_rules": lambda: [firewall_rule_record(r) for r in client.firewall_rules.list(rg, name)],
            "access_policies": lambda: [project_access_policy(p) for p in client.access_policy.list(rg, name)],
            "access_policy_assignments": lambda: [
                project_access_assignment(a) for a in client.access_policy_assignment.list(rg, name)
            ],
            "patch_schedule": lambda: _patch_schedule(client, rg, name),
            "linked_servers": lambda: [project_linked_server(s) for s in client.linked_server.list(rg, name)],
            "diagnostic_settings": lambda: list_diagnostic_settings(monitor, cid),
        }
        extras = {key: collector.guard(f"redis.{key}({rg}/{name})", read) for key, read in reads.items()}
        records.append(cache_record(cache, extras))
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
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Cache")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Cache is not registered on subscription %s — reporting status not_registered",
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
    filename = f"azure_redis_cache_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
