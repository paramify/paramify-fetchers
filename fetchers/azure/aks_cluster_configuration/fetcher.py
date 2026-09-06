#!/usr/bin/env python3
"""
Azure Kubernetes Service cluster configuration — API server exposure, RBAC, monitoring

Ported from Prowler's prowler/providers/azure/services/aks/aks_service.py
(Apache-2.0), with ONE DELIBERATE DEPARTURE: Prowler drops any cluster whose
`kubernetes_version` is falsy. Every cluster the API returns is reported here — a
cluster mid-provision or in a failed state is exactly the one a reviewer needs to see.
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

logger = logging.getLogger("azure_aks_cluster_configuration")

# auto_upgrade_profile.upgrade_channel: "none" is the literal for "no automatic
# upgrades"; an absent field means the same thing.
UPGRADE_CHANNEL_NONE = "none"


# --- projection: the only code that touches an azure-mgmt model ---

def project_agent_pool_profile(profile) -> dict:
    """Read a `ManagedClusterAgentPoolProfile`; Prowler keeps only name + public IP."""
    return {
        "name": model_attr(profile, "name"),
        "enable_node_public_ip": model_attr(profile, "enable_node_public_ip"),
        "mode": model_attr(profile, "mode"),
        "count": model_attr(profile, "count"),
        "vm_size": model_attr(profile, "vm_size"),
        "os_type": model_attr(profile, "os_type"),
        "os_sku": model_attr(profile, "os_sku"),
        "os_disk_type": model_attr(profile, "os_disk_type"),
        "enable_encryption_at_host": model_attr(profile, "enable_encryption_at_host"),
        "enable_auto_scaling": model_attr(profile, "enable_auto_scaling"),
        "orchestrator_version": model_attr(profile, "orchestrator_version"),
        "vnet_subnet_id": model_attr(profile, "vnet_subnet_id"),
    }


def project_managed_cluster(cluster) -> dict:
    """Read a `ManagedCluster` model's attributes into a flat snake_case dict.

    The Defender and Azure Monitor readings are three and two optional hops deep: a
    cluster that never enabled either omits the whole subtree. `network_policy` and
    `upgrade_channel` are enums, which `model_attr` unwraps to their wire strings.
    """
    network_profile = model_attr(cluster, "network_profile")
    api_server_access = model_attr(cluster, "api_server_access_profile")
    auto_upgrade = model_attr(cluster, "auto_upgrade_profile")
    security_profile = model_attr(cluster, "security_profile")
    defender = model_attr(security_profile, "defender")
    aad_profile = model_attr(cluster, "aad_profile")

    return {
        "id": model_attr(cluster, "id"),
        "name": model_attr(cluster, "name"),
        "location": model_attr(cluster, "location"),
        "provisioning_state": model_attr(cluster, "provisioning_state"),
        "sku_tier": model_attr(model_attr(cluster, "sku"), "tier"),
        # --- API server exposure ---
        "public_fqdn": model_attr(cluster, "fqdn"),
        "private_fqdn": model_attr(cluster, "private_fqdn"),
        "public_network_access": model_attr(cluster, "public_network_access"),
        "enable_private_cluster": model_attr(api_server_access, "enable_private_cluster"),
        "authorized_ip_ranges": model_attr(api_server_access, "authorized_ip_ranges"),
        "disable_run_command": model_attr(api_server_access, "disable_run_command"),
        # --- authorization ---
        "rbac_enabled": model_attr(cluster, "enable_rbac"),
        "azure_rbac_enabled": model_attr(aad_profile, "enable_azure_rbac"),
        "entra_managed_identity": model_attr(aad_profile, "managed"),
        "local_accounts_disabled": model_attr(cluster, "disable_local_accounts"),
        "workload_identity_enabled": model_attr(
            model_attr(security_profile, "workload_identity"), "enabled"
        ),
        "oidc_issuer_enabled": model_attr(
            model_attr(cluster, "oidc_issuer_profile"), "enabled"
        ),
        # --- network ---
        "network_policy": model_attr(network_profile, "network_policy"),
        "network_plugin": model_attr(network_profile, "network_plugin"),
        "outbound_type": model_attr(network_profile, "outbound_type"),
        # --- patching ---
        "kubernetes_version": model_attr(cluster, "kubernetes_version"),
        "current_kubernetes_version": model_attr(cluster, "current_kubernetes_version"),
        "auto_upgrade_channel": model_attr(auto_upgrade, "upgrade_channel"),
        "node_os_upgrade_channel": model_attr(auto_upgrade, "node_os_upgrade_channel"),
        # --- monitoring ---
        "defender_enabled": model_attr(
            model_attr(defender, "security_monitoring"), "enabled"
        ),
        "defender_log_analytics_workspace_id": model_attr(
            defender, "log_analytics_workspace_resource_id"
        ),
        "azure_monitor_enabled": model_attr(
            model_attr(model_attr(cluster, "azure_monitor_profile"), "metrics"), "enabled"
        ),
        # --- node estate + at-rest key ---
        "disk_encryption_set_id": model_attr(cluster, "disk_encryption_set_id"),
        "node_resource_group": model_attr(cluster, "node_resource_group"),
        "agent_pool_profiles": [
            project_agent_pool_profile(profile)
            for profile in (model_attr(cluster, "agent_pool_profiles") or [])
        ],
    }


# --- pure transforms (dicts in, evidence records out) ---

def agent_pool_record(profile: dict) -> dict:
    """Normalize one projected agent pool, coercing the optional `enable_*` flags."""
    return {
        "name": profile.get("name"),
        "enable_node_public_ip": bool(profile.get("enable_node_public_ip") or False),
        "mode": profile.get("mode"),
        "count": profile.get("count"),
        "vm_size": profile.get("vm_size"),
        "os_type": profile.get("os_type"),
        "os_sku": profile.get("os_sku"),
        "os_disk_type": profile.get("os_disk_type"),
        "enable_encryption_at_host": bool(profile.get("enable_encryption_at_host") or False),
        "enable_auto_scaling": bool(profile.get("enable_auto_scaling") or False),
        "orchestrator_version": profile.get("orchestrator_version"),
        "vnet_subnet_id": profile.get("vnet_subnet_id"),
    }


def cluster_record(cluster: dict) -> dict:
    """Normalize one projected managed cluster into an evidence record.

    Optional booleans are coerced with `bool(x or False)`: Azure omits a false-y field
    rather than returning `false`, and a regex asserting `false` would not match `null`.
    """
    resource_id = cluster.get("id")
    agent_pools = [agent_pool_record(p) for p in (cluster.get("agent_pool_profiles") or [])]
    authorized_ip_ranges = cluster.get("authorized_ip_ranges") or []
    private_fqdn = cluster.get("private_fqdn")
    upgrade_channel = cluster.get("auto_upgrade_channel")

    return {
        "id": resource_id,
        "name": cluster.get("name"),
        "location": cluster.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "provisioning_state": cluster.get("provisioning_state"),
        "sku_tier": cluster.get("sku_tier"),
        # --- API server exposure ---
        "public_fqdn": cluster.get("public_fqdn"),
        "private_fqdn": private_fqdn,
        "public_network_access": cluster.get("public_network_access"),
        "private_cluster": bool(cluster.get("enable_private_cluster") or False),
        "authorized_ip_ranges": authorized_ip_ranges,
        # A private cluster has no public API endpoint, so it needs no IP allow-list;
        # either one restricts who can reach the API server.
        "api_server_access_restricted": bool(
            authorized_ip_ranges or cluster.get("enable_private_cluster")
        ),
        "run_command_disabled": bool(cluster.get("disable_run_command") or False),
        # --- authorization ---
        "rbac_enabled": bool(cluster.get("rbac_enabled") or False),
        "azure_rbac_enabled": bool(cluster.get("azure_rbac_enabled") or False),
        "entra_managed_identity": bool(cluster.get("entra_managed_identity") or False),
        "local_accounts_disabled": bool(cluster.get("local_accounts_disabled") or False),
        "workload_identity_enabled": bool(cluster.get("workload_identity_enabled") or False),
        "oidc_issuer_enabled": bool(cluster.get("oidc_issuer_enabled") or False),
        # --- network ---
        "network_policy": cluster.get("network_policy"),
        "network_policy_enabled": bool(cluster.get("network_policy")),
        "network_plugin": cluster.get("network_plugin"),
        "outbound_type": cluster.get("outbound_type"),
        # --- patching ---
        "kubernetes_version": cluster.get("kubernetes_version"),
        "current_kubernetes_version": cluster.get("current_kubernetes_version"),
        "auto_upgrade_channel": upgrade_channel,
        # Absent and the literal "none" both mean no automatic upgrades.
        "auto_upgrade_enabled": bool(upgrade_channel)
        and str(upgrade_channel).lower() != UPGRADE_CHANNEL_NONE,
        "node_os_upgrade_channel": cluster.get("node_os_upgrade_channel"),
        # --- monitoring ---
        "defender_enabled": bool(cluster.get("defender_enabled") or False),
        "defender_log_analytics_workspace_id": cluster.get(
            "defender_log_analytics_workspace_id"
        ),
        "azure_monitor_enabled": bool(cluster.get("azure_monitor_enabled") or False),
        # --- node estate ---
        "disk_encryption_set_id": cluster.get("disk_encryption_set_id"),
        "node_resource_group": cluster.get("node_resource_group"),
        "agent_pool_profiles": agent_pools,
        # Prowler's aks_clusters_created_with_private_nodes reading: any pool handing
        # its nodes a public IP puts them on the Internet.
        "node_public_ip_pools": [p["name"] for p in agent_pools if p["enable_node_public_ip"]],
    }


def summarize(clusters: list[dict]) -> dict:
    """Coverage counts across the cluster estate, one per Prowler AKS check."""
    total = len(clusters)
    private = sum(1 for c in clusters if c["private_cluster"])
    restricted = sum(1 for c in clusters if c["api_server_access_restricted"])
    return {
        "total_clusters": total,
        "private_clusters": private,
        "private_cluster_percentage": coverage_percentage(private, total),
        "api_server_access_restricted_clusters": restricted,
        "api_server_access_restricted_percentage": coverage_percentage(restricted, total),
        "clusters_with_authorized_ip_ranges": sum(
            1 for c in clusters if c["authorized_ip_ranges"]
        ),
        "rbac_enabled_clusters": sum(1 for c in clusters if c["rbac_enabled"]),
        "azure_rbac_enabled_clusters": sum(1 for c in clusters if c["azure_rbac_enabled"]),
        "local_accounts_disabled_clusters": sum(
            1 for c in clusters if c["local_accounts_disabled"]
        ),
        "workload_identity_clusters": sum(
            1 for c in clusters if c["workload_identity_enabled"]
        ),
        "network_policy_clusters": sum(1 for c in clusters if c["network_policy_enabled"]),
        "auto_upgrade_clusters": sum(1 for c in clusters if c["auto_upgrade_enabled"]),
        "defender_enabled_clusters": sum(1 for c in clusters if c["defender_enabled"]),
        "azure_monitor_enabled_clusters": sum(
            1 for c in clusters if c["azure_monitor_enabled"]
        ),
        "clusters_with_public_node_ips": sum(1 for c in clusters if c["node_public_ip_pools"]),
        "total_agent_pools": sum(len(c["agent_pool_profiles"]) for c in clusters),
        # Sorted unique: the version spread at a glance, and a byte-stable payload.
        "kubernetes_versions": sorted(
            {c["kubernetes_version"] for c in clusters if c["kubernetes_version"]}
        ),
    }


# --- collection (lazy azure imports) ---

def collect_clusters(subscription_id, cred, collector: Collector) -> list[dict]:
    """One subscription-wide managed_clusters.list().

    The list response carries the whole projection (no per-cluster GET needed) and is an
    ItemPaged, so the SDK follows nextLink. The SDK import lives inside the guarded
    factory so a missing azure-mgmt-containerservice becomes a recorded failure
    (classified `internal_error`) with evidence plus a status file, not a traceback.
    """

    def _client():
        from azure.mgmt.containerservice import ContainerServiceClient  # lazy

        return ContainerServiceClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("containerservice.ContainerServiceClient (init)", _client)
    if client is None:
        return []

    clusters = collector.guard(
        "containerservice.managed_clusters.list",
        lambda: [
            cluster_record(project_managed_cluster(c)) for c in client.managed_clusters.list()
        ],
        default=[],
    )
    return sorted(clusters, key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request and response header at INFO, which would bury
    # this fetcher's lines in the runner's stderr tail. Warnings still come through.
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
        # Asked BEFORE the list call, so a zero-cluster result is legible: Azure
        # returns an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.ContainerService"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.ContainerService is not registered on subscription %s — no "
                "AKS in use; reporting status not_registered",
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
        results={
            "clusters": clusters,
            "provider_registration_status": registration,
        },
        summary={**summarize(clusters), "provider_registration_status": registration},
    )

    filename = (
        f"azure_aks_cluster_configuration_"
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
