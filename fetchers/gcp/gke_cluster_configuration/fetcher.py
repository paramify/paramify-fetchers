#!/usr/bin/env python3
"""
KSI-CNA-IBP / KSI-CNA-MAT / KSI-CNA-ULN / KSI-IAM-ELP / KSI-IAM-SNU / KSI-SVC-EIS / KSI-SVC-VRI: GKE Cluster Configuration

Every GKE cluster in one project with the posture that separates a hardened
cluster from a default one: private nodes and control-plane endpoint,
master-authorized networks, network policy, legacy ABAC, Workload Identity,
shielded nodes, Binary Authorization, control-plane logging and monitoring, etcd
secrets encryption, release channel, and per node pool auto-upgrade, auto-repair,
boot-disk CMEK and service account. `master_auth` is read field by field on
purpose: that block also carries the control plane's client certificate and
private key, which must never land in evidence.

Ported from Prowler's GCP GKE service (Apache-2.0).
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from gcp_common import (  # noqa: E402
    Collector,
    build_payload,
    coverage_percentage,
    credentials,
    dig_any,
    resolve_project,
    sanitize_for_filename,
    service_disabled,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("gcp_gke_cluster_configuration")


# --- pure transforms ---

def node_pool_record(pool: dict) -> dict:
    """Normalize one node pool into an evidence record.

    `service_account: "default"` is the literal the API returns when the pool runs
    as the over-privileged Compute Engine default service account.
    """
    cfg = dig_any(pool, "config") or {}
    mgmt = dig_any(pool, "management") or {}
    shielded = dig_any(cfg, "shielded_instance_config") or {}
    node_metadata = dig_any(cfg, "metadata") or {}
    service_account = dig_any(cfg, "service_account") or None
    boot_disk_kms = dig_any(cfg, "boot_disk_kms_key") or None

    return {
        "name": dig_any(pool, "name"),
        "version": dig_any(pool, "version") or None,
        "status": dig_any(pool, "status") or None,
        "initial_node_count": dig_any(pool, "initial_node_count"),
        "locations": sorted(dig_any(pool, "locations") or []),
        "autoscaling_enabled": bool(dig_any(pool, "autoscaling", "enabled")),
        "auto_upgrade": bool(dig_any(mgmt, "auto_upgrade")),
        "auto_repair": bool(dig_any(mgmt, "auto_repair")),
        "upgrade_strategy": dig_any(pool, "upgrade_settings", "strategy") or None,
        "machine_type": dig_any(cfg, "machine_type") or None,
        "image_type": dig_any(cfg, "image_type") or None,
        "service_account": service_account,
        "uses_default_service_account": service_account == "default",
        # Absent/empty ⇒ the Google-managed default, as for a standalone disk.
        "boot_disk_cmek": boot_disk_kms is not None,
        "boot_disk_kms_key": boot_disk_kms,
        "secure_boot": bool(dig_any(shielded, "enable_secure_boot")),
        "integrity_monitoring": bool(dig_any(shielded, "enable_integrity_monitoring")),
        "workload_metadata_mode": dig_any(cfg, "workload_metadata_config", "mode") or None,
        # Node metadata values come back as strings, not booleans.
        "legacy_endpoints_disabled": str(
            node_metadata.get("disable-legacy-endpoints", "")
        ).lower() == "true",
    }


def cluster_record(cluster: dict) -> dict:
    """Normalize one cluster resource into an evidence record."""
    private = dig_any(cluster, "private_cluster_config") or {}
    authorized_networks = dig_any(cluster, "master_authorized_networks_config") or {}
    network_policy = dig_any(cluster, "network_policy") or {}
    network_config = dig_any(cluster, "network_config") or {}
    database_encryption = dig_any(cluster, "database_encryption") or {}
    workload_pool = dig_any(cluster, "workload_identity_config", "workload_pool") or None
    legacy_abac = bool(dig_any(cluster, "legacy_abac", "enabled"))
    # Sorted by name so unchanged infra re-runs byte-stable.
    node_pools = sorted(
        (node_pool_record(p) for p in (dig_any(cluster, "node_pools") or [])),
        key=lambda p: p.get("name") or "",
    )

    return {
        "name": dig_any(cluster, "name"),
        "id": dig_any(cluster, "id") or None,
        "location": dig_any(cluster, "location") or None,
        "locations": sorted(dig_any(cluster, "locations") or []),
        "status": dig_any(cluster, "status") or None,
        "initial_cluster_version": dig_any(cluster, "initial_cluster_version") or None,
        "current_master_version": dig_any(cluster, "current_master_version") or None,
        "current_node_count": dig_any(cluster, "current_node_count"),
        "release_channel": dig_any(cluster, "release_channel", "channel") or None,
        "autopilot": bool(dig_any(cluster, "autopilot", "enabled")),
        # --- network exposure ---
        "private_nodes": bool(dig_any(private, "enable_private_nodes")),
        "private_control_plane_endpoint": bool(dig_any(private, "enable_private_endpoint")),
        # The endpoint IPs are deliberately not copied; reachability is the fact.
        "control_plane_endpoint_access": (
            "private" if dig_any(private, "enable_private_endpoint") else "public"
        ),
        "master_ipv4_cidr_block": dig_any(private, "master_ipv4_cidr_block") or None,
        "master_authorized_networks_enabled": bool(dig_any(authorized_networks, "enabled")),
        "master_authorized_network_count": len(dig_any(authorized_networks, "cidr_blocks") or []),
        "network_policy_enabled": bool(dig_any(network_policy, "enabled")),
        "network_policy_provider": dig_any(network_policy, "provider") or None,
        "dataplane_v2": dig_any(network_config, "datapath_provider") == "ADVANCED_DATAPATH",
        "intranode_visibility": bool(dig_any(network_config, "enable_intra_node_visibility")),
        # --- authorization ---
        # RBAC is always on in a supported cluster; legacy ABAC is what bypasses it.
        "legacy_abac_enabled": legacy_abac,
        "rbac_only_authorization": not legacy_abac,
        "client_certificate_issued": bool(
            dig_any(cluster, "master_auth", "client_certificate_config",
                    "issue_client_certificate")
        ),
        "workload_identity_enabled": workload_pool is not None,
        "workload_identity_pool": workload_pool,
        "node_service_account": dig_any(cluster, "node_config", "service_account") or None,
        # --- host / workload hardening ---
        "shielded_nodes_enabled": bool(dig_any(cluster, "shielded_nodes", "enabled")),
        "confidential_nodes_enabled": bool(dig_any(cluster, "confidential_nodes", "enabled")),
        "binary_authorization_enabled": bool(dig_any(cluster, "binary_authorization", "enabled")),
        "binary_authorization_mode": (
            dig_any(cluster, "binary_authorization", "evaluation_mode") or None
        ),
        # --- control-plane logging / monitoring ---
        "logging_service": dig_any(cluster, "logging_service") or None,
        "monitoring_service": dig_any(cluster, "monitoring_service") or None,
        "control_plane_logging_components": sorted(
            dig_any(cluster, "logging_config", "component_config", "enable_components") or []
        ),
        "control_plane_monitoring_components": sorted(
            dig_any(cluster, "monitoring_config", "component_config", "enable_components") or []
        ),
        "managed_prometheus_enabled": bool(
            dig_any(cluster, "monitoring_config", "managed_prometheus_config", "enabled")
        ),
        # --- encryption at rest of Kubernetes Secrets in etcd ---
        "etcd_cmek": dig_any(database_encryption, "state") == "ENCRYPTED",
        "etcd_encryption_state": dig_any(database_encryption, "state") or None,
        "etcd_kms_key_name": dig_any(database_encryption, "key_name") or None,
        "node_pool_count": len(node_pools),
        "node_pools": node_pools,
    }


def summarize(clusters: list[dict], *, api_readable: bool = True) -> dict:
    pools = [p for c in clusters for p in c["node_pools"]]
    private = sum(1 for c in clusters if c["private_nodes"])
    workload_identity = sum(1 for c in clusters if c["workload_identity_enabled"])
    auto_upgrade = sum(1 for p in pools if p["auto_upgrade"])
    return {
        # False when the Container API is disabled or the list failed — "could not
        # look" rather than "no clusters".
        "gke_api_readable": api_readable,
        "total_clusters": len(clusters),
        "private_node_clusters": private,
        "private_node_percentage": coverage_percentage(private, len(clusters)),
        "private_control_plane_clusters": sum(
            1 for c in clusters if c["private_control_plane_endpoint"]
        ),
        "master_authorized_networks_clusters": sum(
            1 for c in clusters if c["master_authorized_networks_enabled"]
        ),
        "network_policy_clusters": sum(1 for c in clusters if c["network_policy_enabled"]),
        "workload_identity_clusters": workload_identity,
        "workload_identity_percentage": coverage_percentage(workload_identity, len(clusters)),
        "shielded_nodes_clusters": sum(1 for c in clusters if c["shielded_nodes_enabled"]),
        "legacy_abac_clusters": sum(1 for c in clusters if c["legacy_abac_enabled"]),
        "binary_authorization_clusters": sum(
            1 for c in clusters if c["binary_authorization_enabled"]
        ),
        "etcd_cmek_clusters": sum(1 for c in clusters if c["etcd_cmek"]),
        "release_channel_clusters": sum(
            1 for c in clusters if c["release_channel"] not in (None, "UNSPECIFIED")
        ),
        "total_node_pools": len(pools),
        "auto_upgrade_node_pools": auto_upgrade,
        "auto_upgrade_percentage": coverage_percentage(auto_upgrade, len(pools)),
        "auto_repair_node_pools": sum(1 for p in pools if p["auto_repair"]),
        "cmek_boot_disk_node_pools": sum(1 for p in pools if p["boot_disk_cmek"]),
        "default_service_account_node_pools": sum(
            1 for p in pools if p["uses_default_service_account"]
        ),
    }


# --- collection ---

def collect_clusters(project, creds, collector: Collector) -> list[dict] | None:
    """Every cluster in the project, or None when GKE could not be listed."""
    from google.cloud import container_v1

    def _list():
        client = container_v1.ClusterManagerClient(credentials=creds)
        # locations/- = every zone and region; ListClustersResponse is not paged.
        response = client.list_clusters(parent=f"projects/{project}/locations/-")
        return [
            cluster_record(container_v1.Cluster.to_dict(c, use_integers_for_enums=False))
            for c in response.clusters
        ]

    # A project that has never run GKE has container.googleapis.com disabled and
    # the call 403s rather than returning an empty list — evidence, not a failure.
    records = collector.guard("container.clusters.list", _list, tolerate=service_disabled)
    if records is None:
        return None
    return sorted(records, key=lambda r: (r.get("location") or "", r.get("name") or ""))


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    proj = resolve_project(collector)
    project = proj["project"]
    creds = collector.guard("google.auth.default (credentials)", credentials)

    clusters: list[dict] | None = None
    if project and creds is not None:
        clusters = collect_clusters(project, creds, collector)
    elif not project:
        collector.record("resolve_project", RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"clusters": clusters or []},
        summary=summarize(clusters or [], api_readable=clusters is not None),
    )

    filename = f"gcp_gke_cluster_configuration_{sanitize_for_filename(project or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
