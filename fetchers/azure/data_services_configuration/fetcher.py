#!/usr/bin/env python3
"""Azure DocumentDB (MongoDB vCore), Data Explorer and Event Hubs: public access, TLS, authentication, encryption, access and logging."""

import logging
import os
import sys
from datetime import timedelta
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
    credential,
    failure_reason,
    list_diagnostic_settings,
    logs_exported,
    model_attr,
    monitor_client,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)

logger = logging.getLogger("azure_data_services_configuration")

PROVIDERS = {
    "mongo_clusters": "Microsoft.DocumentDB",
    "data_explorer": "Microsoft.Kusto",
    "event_hubs": "Microsoft.EventHub",
}
ALLOW_ALL_RANGE = ("0.0.0.0", "255.255.255.255")
AZURE_SERVICES_RANGE = ("0.0.0.0", "0.0.0.0")
# Data Explorer roles that can change data or grant access.
KUSTO_ADMIN_ROLES = {"alldatabasesadmin", "admin"}


def compact(name) -> str:
    return "".join(ch for ch in str(name or "").lower() if ch.isalnum())


def plain(value):
    """An enum's wire value, else the value itself; applied to list members model_attr does not reach."""
    return getattr(value, "value", value)


def days(period) -> object:
    if isinstance(period, timedelta):
        return period.days
    return period


def identity_type(resource):
    return model_attr(model_attr(resource, "identity"), "type")


def private_endpoints(connections) -> list:
    return [
        {
            "id": model_attr(c, "id"),
            "status": model_attr(model_attr(c, "private_link_service_connection_state"), "status"),
        }
        for c in connections or []
    ]


def diagnostics_record(monitor, collector: Collector, resource: dict, categories: tuple) -> dict:
    diagnostics = None
    if monitor is not None:
        diagnostics = collector.guard(
            f"monitor.diagnostic_settings.list({resource['resource_group']}/{resource['name']})",
            lambda: list_diagnostic_settings(monitor, resource["id"]),
        )
    return {
        "diagnostic_settings": diagnostics,
        "audit_logs_exported": logs_exported(diagnostics, categories=categories),
    }


# --------------------------------------------------------------------------- #
# Azure DocumentDB (MongoDB vCore)
# --------------------------------------------------------------------------- #

def project_firewall_rule(rule) -> dict:
    props = model_attr(rule, "properties")
    start, end = model_attr(props, "start_ip_address"), model_attr(props, "end_ip_address")
    return {
        "name": model_attr(rule, "name"),
        "start_ip_address": start,
        "end_ip_address": end,
        "allow_all": (start, end) == ALLOW_ALL_RANGE,
        # Azure's "Allow Azure services" convention is the 0.0.0.0 - 0.0.0.0 rule.
        "allow_azure_services": (start, end) == AZURE_SERVICES_RANGE,
    }


def mongo_public_access(public_network_access, rules: list) -> str:
    """disabled / allow_all / restricted / no_rules: with public access on, only firewall rules admit traffic."""
    if str(public_network_access or "").lower() == "disabled":
        return "disabled"
    if any(r["allow_all"] for r in rules):
        return "allow_all"
    return "restricted" if rules else "no_rules"


def project_mongo_cluster(cluster) -> dict:
    props = model_attr(cluster, "properties")
    modes = [plain(m) for m in model_attr(model_attr(props, "auth_config"), "allowed_modes") or []]
    ha = model_attr(model_attr(props, "high_availability"), "target_mode")
    encryption = model_attr(model_attr(props, "encryption"), "customer_managed_key_encryption")
    return {
        "id": model_attr(cluster, "id"),
        "name": model_attr(cluster, "name"),
        "location": model_attr(cluster, "location"),
        "resource_group": resource_group_from_id(model_attr(cluster, "id")),
        "tags": model_attr(cluster, "tags") or {},
        "identity_type": identity_type(cluster),
        "server_version": model_attr(props, "server_version"),
        "cluster_status": model_attr(props, "cluster_status"),
        "compute_tier": model_attr(model_attr(props, "compute"), "tier"),
        "storage_size_gb": model_attr(model_attr(props, "storage"), "size_gb"),
        "shard_count": model_attr(model_attr(props, "sharding"), "shard_count"),
        "public_network_access": model_attr(props, "public_network_access"),
        "private_endpoint_connections": private_endpoints(model_attr(props, "private_endpoint_connections")),
        # MongoDB vCore accepts TLS 1.2+ only and has no setting to weaken it.
        "tls_enforced_by_platform": True,
        "auth_modes": modes,
        "entra_auth_enabled": any(compact(m) == "microsoftentraid" for m in modes),
        "native_auth_enabled": any(compact(m) == "nativeauth" for m in modes),
        "high_availability_mode": ha,
        "high_availability_enabled": compact(ha) not in ("", "disabled"),
        "customer_managed_key": encryption is not None,
        "data_api_enabled": compact(model_attr(model_attr(props, "data_api"), "mode")) == "enabled",
        "earliest_restore_time": model_attr(model_attr(props, "backup"), "earliest_restore_time"),
    }


# --------------------------------------------------------------------------- #
# Azure Data Explorer (Kusto)
# --------------------------------------------------------------------------- #

def project_principal(assignment) -> dict:
    role = model_attr(assignment, "role")
    return {
        "role": role,
        "admin": compact(role) in KUSTO_ADMIN_ROLES,
        "principal_type": model_attr(assignment, "principal_type"),
        "principal_name": model_attr(assignment, "principal_name"),
        "principal_id": model_attr(assignment, "principal_id"),
        "tenant_id": model_attr(assignment, "tenant_id"),
    }


def project_callout_policy(policy) -> dict:
    return {
        "callout_type": model_attr(policy, "callout_type"),
        "uri_regex": model_attr(policy, "callout_uri_regex"),
        "outbound_access": model_attr(policy, "outbound_access"),
        "allowed": compact(model_attr(policy, "outbound_access")) == "allow",
    }


def project_database(database) -> dict:
    return {
        "id": model_attr(database, "id"),
        "name": basename(model_attr(database, "name")),
        "kind": model_attr(database, "kind"),
        "soft_delete_days": days(model_attr(database, "soft_delete_period")),
        "hot_cache_days": days(model_attr(database, "hot_cache_period")),
    }


def project_kusto_cluster(cluster) -> dict:
    tenants = [model_attr(t, "value") for t in model_attr(cluster, "trusted_external_tenants") or []]
    pna = model_attr(cluster, "public_network_access")
    ip_ranges = model_attr(cluster, "allowed_ip_range_list") or []
    if str(pna or "").lower() == "disabled":
        exposure = "private"
    elif ip_ranges:
        exposure = "restricted"
    else:
        exposure = "open"
    return {
        "id": model_attr(cluster, "id"),
        "name": model_attr(cluster, "name"),
        "location": model_attr(cluster, "location"),
        "resource_group": resource_group_from_id(model_attr(cluster, "id")),
        "tags": model_attr(cluster, "tags") or {},
        "sku": model_attr(model_attr(cluster, "sku"), "name"),
        "zones": model_attr(cluster, "zones") or [],
        "identity_type": identity_type(cluster),
        "state": model_attr(cluster, "state"),
        "public_network_access": pna,
        "allowed_ip_ranges": ip_ranges,
        "network_exposure": exposure,
        "vnet_injected": model_attr(cluster, "virtual_network_configuration") is not None,
        "private_endpoint_connections": private_endpoints(model_attr(cluster, "private_endpoint_connections")),
        "restrict_outbound_network_access": model_attr(cluster, "restrict_outbound_network_access"),
        "outbound_restricted": compact(model_attr(cluster, "restrict_outbound_network_access")) == "enabled",
        "allowed_fqdns": model_attr(cluster, "allowed_fqdn_list") or [],
        "disk_encryption_enabled": bool(model_attr(cluster, "enable_disk_encryption") or False),
        "double_encryption_enabled": bool(model_attr(cluster, "enable_double_encryption") or False),
        "customer_managed_key": model_attr(cluster, "key_vault_properties") is not None,
        "trusted_external_tenants": tenants,
        "trusts_any_tenant": any(str(t) == "*" for t in tenants),
        "accepted_audiences": [model_attr(a, "value") for a in model_attr(cluster, "accepted_audiences") or []],
        "purge_enabled": bool(model_attr(cluster, "enable_purge") or False),
        "streaming_ingest_enabled": bool(model_attr(cluster, "enable_streaming_ingest") or False),
    }


# --------------------------------------------------------------------------- #
# Event Hubs
# --------------------------------------------------------------------------- #

def tls_below_1_2(version) -> bool:
    try:
        return float(str(version)) < 1.2
    except (TypeError, ValueError):
        return False


def project_authorization_rule(rule) -> dict:
    rights = [plain(r) for r in model_attr(rule, "rights") or []]
    return {
        "name": model_attr(rule, "name"),
        "rights": rights,
        "manage": any(compact(r) == "manage" for r in rights),
    }


def project_event_hub(hub) -> dict:
    retention = model_attr(hub, "retention_description")
    hours = model_attr(retention, "retention_time_in_hours")
    return {
        "name": model_attr(hub, "name"),
        "status": model_attr(hub, "status"),
        "partition_count": model_attr(hub, "partition_count"),
        "retention_hours": hours,
        "retention_days": model_attr(hub, "message_retention_in_days"),
        "cleanup_policy": model_attr(retention, "cleanup_policy"),
        "capture_enabled": bool(model_attr(model_attr(hub, "capture_description"), "enabled") or False),
    }


def project_namespace(namespace) -> dict:
    encryption = model_attr(namespace, "encryption")
    tls = model_attr(namespace, "minimum_tls_version")
    disable_local_auth = model_attr(namespace, "disable_local_auth")
    locations = model_attr(model_attr(namespace, "geo_data_replication"), "locations") or []
    return {
        "id": model_attr(namespace, "id"),
        "name": model_attr(namespace, "name"),
        "location": model_attr(namespace, "location"),
        "resource_group": resource_group_from_id(model_attr(namespace, "id")),
        "tags": model_attr(namespace, "tags") or {},
        "sku": model_attr(model_attr(namespace, "sku"), "name"),
        "identity_type": identity_type(namespace),
        "status": model_attr(namespace, "status"),
        "minimum_tls_version": tls,
        "tls_below_1_2": tls_below_1_2(tls),
        "public_network_access": model_attr(namespace, "public_network_access"),
        "private_endpoint_connections": private_endpoints(model_attr(namespace, "private_endpoint_connections")),
        "disable_local_auth": disable_local_auth,
        # disableLocalAuth defaults to false: unset means shared access keys work.
        "local_auth_enabled": disable_local_auth is not True,
        "zone_redundant": bool(model_attr(namespace, "zone_redundant") or False),
        "geo_replication_locations": [model_attr(loc, "location_name") for loc in locations],
        "geo_replica_regions": sum(
            1 for loc in locations if compact(model_attr(loc, "role_type")) != "primary"
        ),
        "kafka_enabled": bool(model_attr(namespace, "kafka_enabled") or False),
        "customer_managed_key": compact(model_attr(encryption, "key_source")) == "microsoftkeyvault",
        "infrastructure_encryption_required": bool(model_attr(encryption, "require_infrastructure_encryption") or False),
    }


def namespace_record(namespace: dict, rules, auth_rules, hubs) -> dict:
    """`rules` is the network rule set, each argument None when it could not be read."""
    default_action = model_attr(rules, "default_action")
    ruleset_pna = model_attr(rules, "public_network_access")
    pna_disabled = any(
        str(v or "").lower() == "disabled" for v in (namespace["public_network_access"], ruleset_pna)
    )
    if rules is None:
        exposure = "private" if str(namespace["public_network_access"] or "").lower() == "disabled" else None
    elif pna_disabled:
        exposure = "private"
    elif str(default_action or "allow").lower() == "deny":
        exposure = "restricted"
    else:
        exposure = "open"
    manage_rules = [r for r in auth_rules or [] if r["manage"]]
    return {
        **namespace,
        "network_rules_default_action": default_action,
        "trusted_service_access_enabled": model_attr(rules, "trusted_service_access_enabled"),
        "ip_rules": [model_attr(r, "ip_mask") for r in model_attr(rules, "ip_rules") or []],
        "virtual_network_rule_subnet_ids": [
            model_attr(model_attr(r, "subnet"), "id") for r in model_attr(rules, "virtual_network_rules") or []
        ],
        "network_exposure": exposure,
        "authorization_rules": auth_rules,
        "manage_rights_rules": None if auth_rules is None else [r["name"] for r in manage_rules],
        # A shared key with Manage rights is full control of the namespace while local auth is on.
        "shared_key_full_control": None
        if auth_rules is None
        else namespace["local_auth_enabled"] and bool(manage_rules),
        "event_hubs": hubs,
    }


# --------------------------------------------------------------------------- #

def summarize(mongo: list, kusto: list, eventhub: list) -> dict:
    hubs = [h for n in eventhub for h in n["event_hubs"] or []]
    kusto_principals = [p for c in kusto for p in c["cluster_principals"] or []]
    kusto_principals += [p for c in kusto for d in c["databases"] or [] for p in d["principals"] or []]
    retention = [h["retention_days"] for h in hubs if h["retention_days"] is not None]

    def count(items, pred):
        return sum(1 for i in items if pred(i))

    return {
        "total_mongo_clusters": len(mongo),
        "mongo_clusters_public_access_disabled": count(mongo, lambda m: m["public_access"] == "disabled"),
        "mongo_clusters_firewall_allow_all": count(mongo, lambda m: m["public_access"] == "allow_all"),
        "mongo_clusters_firewall_restricted": count(mongo, lambda m: m["public_access"] == "restricted"),
        "mongo_clusters_public_access_unknown": count(mongo, lambda m: m["public_access"] is None),
        "mongo_clusters_with_private_endpoints": count(mongo, lambda m: m["private_endpoint_connections"]),
        "mongo_clusters_native_auth_enabled": count(mongo, lambda m: m["native_auth_enabled"]),
        "mongo_clusters_entra_auth_enabled": count(mongo, lambda m: m["entra_auth_enabled"]),
        "mongo_clusters_high_availability_enabled": count(mongo, lambda m: m["high_availability_enabled"]),
        "mongo_clusters_customer_managed_key": count(mongo, lambda m: m["customer_managed_key"]),
        "mongo_clusters_data_api_enabled": count(mongo, lambda m: m["data_api_enabled"]),
        "mongo_clusters_audit_logs_exported": count(mongo, lambda m: m["audit_logs_exported"] is True),
        "mongo_clusters_audit_logs_unknown": count(mongo, lambda m: m["audit_logs_exported"] is None),
        "total_data_explorer_clusters": len(kusto),
        "data_explorer_clusters_open_to_all_networks": count(kusto, lambda c: c["network_exposure"] == "open"),
        "data_explorer_clusters_network_restricted": count(kusto, lambda c: c["network_exposure"] == "restricted"),
        "data_explorer_clusters_private_only": count(kusto, lambda c: c["network_exposure"] == "private"),
        "data_explorer_clusters_vnet_injected": count(kusto, lambda c: c["vnet_injected"]),
        "data_explorer_clusters_outbound_restricted": count(kusto, lambda c: c["outbound_restricted"]),
        "data_explorer_clusters_disk_encryption_enabled": count(kusto, lambda c: c["disk_encryption_enabled"]),
        "data_explorer_clusters_double_encryption_enabled": count(kusto, lambda c: c["double_encryption_enabled"]),
        "data_explorer_clusters_customer_managed_key": count(kusto, lambda c: c["customer_managed_key"]),
        "data_explorer_clusters_trusting_any_tenant": count(kusto, lambda c: c["trusts_any_tenant"]),
        "data_explorer_clusters_purge_enabled": count(kusto, lambda c: c["purge_enabled"]),
        "data_explorer_callout_policies_allowed": sum(
            1 for c in kusto for p in c["callout_policies"] or [] if p["allowed"]
        ),
        "data_explorer_clusters_callout_policies_unknown": count(kusto, lambda c: c["callout_policies"] is None),
        "data_explorer_clusters_audit_logs_exported": count(kusto, lambda c: c["audit_logs_exported"] is True),
        "data_explorer_clusters_audit_logs_unknown": count(kusto, lambda c: c["audit_logs_exported"] is None),
        "data_explorer_principal_assignments": len(kusto_principals),
        "data_explorer_admin_assignments": count(kusto_principals, lambda p: p["admin"]),
        "data_explorer_admin_user_assignments": count(
            kusto_principals, lambda p: p["admin"] and compact(p["principal_type"]) == "user"
        ),
        "data_explorer_clusters_principals_unknown": count(
            kusto, lambda c: c["cluster_principals"] is None or any(d["principals"] is None for d in c["databases"] or [])
        ),
        "total_event_hub_namespaces": len(eventhub),
        "event_hub_namespaces_tls_below_1_2": count(eventhub, lambda n: n["tls_below_1_2"]),
        "event_hub_namespaces_open_to_all_networks": count(eventhub, lambda n: n["network_exposure"] == "open"),
        "event_hub_namespaces_network_restricted": count(eventhub, lambda n: n["network_exposure"] == "restricted"),
        "event_hub_namespaces_private_only": count(eventhub, lambda n: n["network_exposure"] == "private"),
        "event_hub_namespaces_network_exposure_unknown": count(eventhub, lambda n: n["network_exposure"] is None),
        "event_hub_namespaces_local_auth_enabled": count(eventhub, lambda n: n["local_auth_enabled"]),
        "event_hub_namespaces_shared_key_full_control": count(eventhub, lambda n: n["shared_key_full_control"] is True),
        "event_hub_namespaces_customer_managed_key": count(eventhub, lambda n: n["customer_managed_key"]),
        "event_hub_namespaces_zone_redundant": count(eventhub, lambda n: n["zone_redundant"]),
        "event_hub_namespaces_geo_replicated": count(eventhub, lambda n: n["geo_replica_regions"]),
        "event_hub_namespaces_audit_logs_exported": count(eventhub, lambda n: n["audit_logs_exported"] is True),
        "event_hub_namespaces_audit_logs_unknown": count(eventhub, lambda n: n["audit_logs_exported"] is None),
        "total_event_hubs": len(hubs),
        "event_hubs_with_capture": count(hubs, lambda h: h["capture_enabled"]),
        "event_hubs_with_manage_rights_rules": count(hubs, lambda h: h["manage_rights_rules"]),
        "event_hubs_authorization_rules_unknown": count(hubs, lambda h: h["authorization_rules"] is None),
        "event_hubs_minimum_retention_days": min(retention) if retention else None,
    }


def collect(subscription_id, cred, collector: Collector) -> tuple:
    def _clients():
        from azure.mgmt.eventhub import EventHubManagementClient  # lazy
        from azure.mgmt.kusto import KustoManagementClient  # lazy
        from azure.mgmt.mongocluster import MongoClusterMgmtClient  # lazy

        kwargs = {"credential": cred, "subscription_id": subscription_id, **arm_client_kwargs()}
        return MongoClusterMgmtClient(**kwargs), KustoManagementClient(**kwargs), EventHubManagementClient(**kwargs)

    clients = collector.guard("data services clients (init)", _clients)
    if clients is None:
        return [], [], []
    mongo_client, kusto_client, eh_client = clients

    mongo = collector.guard(
        "mongocluster.mongo_clusters.list",
        lambda: [project_mongo_cluster(m) for m in mongo_client.mongo_clusters.list()],
        default=[],
    )
    kusto = collector.guard(
        "kusto.clusters.list", lambda: [project_kusto_cluster(c) for c in kusto_client.clusters.list()], default=[]
    )
    eventhub = collector.guard(
        "eventhub.namespaces.list", lambda: [project_namespace(n) for n in eh_client.namespaces.list()], default=[]
    )
    monitor = (
        collector.guard("monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred))
        if mongo or kusto or eventhub
        else None
    )

    mongo_records = []
    for cluster in mongo:
        rg, name = cluster["resource_group"], cluster["name"]
        rules = collector.guard(
            f"mongocluster.firewall_rules.list_by_mongo_cluster({rg}/{name})",
            lambda rg=rg, name=name: [
                project_firewall_rule(r) for r in mongo_client.firewall_rules.list_by_mongo_cluster(rg, name)
            ],
        )
        mongo_records.append(
            {
                **cluster,
                "firewall_rules": None if rules is None else sorted(rules, key=lambda r: r["name"] or ""),
                "public_access": None if rules is None else mongo_public_access(cluster["public_network_access"], rules),
                **diagnostics_record(monitor, collector, cluster, ("vcoremongorequests",)),
            }
        )

    kusto_records = []
    for cluster in kusto:
        rg, name = cluster["resource_group"], cluster["name"]
        principals = collector.guard(
            f"kusto.cluster_principal_assignments.list({rg}/{name})",
            lambda rg=rg, name=name: [
                project_principal(p) for p in kusto_client.cluster_principal_assignments.list(rg, name)
            ],
        )
        databases = collector.guard(
            f"kusto.databases.list_by_cluster({rg}/{name})",
            lambda rg=rg, name=name: [project_database(d) for d in kusto_client.databases.list_by_cluster(rg, name)],
        )
        for db in databases or []:
            db["principals"] = collector.guard(
                f"kusto.database_principal_assignments.list({rg}/{name}/{db['name']})",
                lambda rg=rg, name=name, db=db: [
                    project_principal(p)
                    for p in kusto_client.database_principal_assignments.list(rg, name, db["name"])
                ],
            )
        callouts = collector.guard(
            f"kusto.clusters.list_callout_policies({rg}/{name})",
            lambda rg=rg, name=name: [project_callout_policy(p) for p in kusto_client.clusters.list_callout_policies(rg, name)],
        )
        kusto_records.append(
            {
                **cluster,
                "callout_policies": None if callouts is None else sorted(callouts, key=lambda p: p["uri_regex"] or ""),
                "cluster_principals": None
                if principals is None
                else sorted(principals, key=lambda p: (p["role"] or "", p["principal_name"] or "")),
                "databases": None if databases is None else sorted(databases, key=lambda d: d["name"] or ""),
                **diagnostics_record(monitor, collector, cluster, ("command", "query", "journal")),
            }
        )

    eh_records = []
    for namespace in eventhub:
        rg, name = namespace["resource_group"], namespace["name"]
        rules = collector.guard(
            f"eventhub.namespaces.get_network_rule_set({rg}/{name})",
            lambda rg=rg, name=name: eh_client.namespaces.get_network_rule_set(rg, name),
        )
        auth_rules = collector.guard(
            f"eventhub.namespaces.list_authorization_rules({rg}/{name})",
            lambda rg=rg, name=name: [
                project_authorization_rule(r) for r in eh_client.namespaces.list_authorization_rules(rg, name)
            ],
        )
        hubs = collector.guard(
            f"eventhub.event_hubs.list_by_namespace({rg}/{name})",
            lambda rg=rg, name=name: [project_event_hub(h) for h in eh_client.event_hubs.list_by_namespace(rg, name)],
        )
        for hub in hubs or []:
            hub["authorization_rules"] = collector.guard(
                f"eventhub.event_hubs.list_authorization_rules({rg}/{name}/{hub['name']})",
                lambda rg=rg, name=name, hub=hub: [
                    project_authorization_rule(r)
                    for r in eh_client.event_hubs.list_authorization_rules(rg, name, hub["name"])
                ],
            )
            hub["manage_rights_rules"] = (
                None if hub["authorization_rules"] is None else [r["name"] for r in hub["authorization_rules"] if r["manage"]]
            )
        eh_records.append(
            {
                **namespace_record(
                    namespace,
                    rules,
                    None if auth_rules is None else sorted(auth_rules, key=lambda r: r["name"] or ""),
                    None if hubs is None else sorted(hubs, key=lambda h: h["name"] or ""),
                ),
                **diagnostics_record(monitor, collector, namespace, ("runtimeauditlogs",)),
            }
        )
    key = lambda r: r["id"] or ""  # noqa: E731
    return sorted(mongo_records, key=key), sorted(kusto_records, key=key), sorted(eh_records, key=key)


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

    mongo: list = []
    kusto: list = []
    eventhub: list = []
    registration = {f"provider_registration_status_{key}": REGISTRATION_UNKNOWN for key in PROVIDERS}
    if subscription_id and cred is not None:
        for key, namespace in PROVIDERS.items():
            registration[f"provider_registration_status_{key}"] = provider_registration_status(
                collector, subscription_id, cred, namespace
            )
            if registration[f"provider_registration_status_{key}"] == NOT_REGISTERED:
                logger.warning(
                    "%s is not registered on subscription %s — reporting status not_registered",
                    namespace,
                    subscription_id,
                )
        mongo, kusto, eventhub = collect(subscription_id, cred, collector)
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
            "mongo_clusters": mongo,
            "data_explorer_clusters": kusto,
            "event_hub_namespaces": eventhub,
            **registration,
        },
        summary={**summarize(mongo, kusto, eventhub), **registration},
    )
    filename = f"azure_data_services_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
