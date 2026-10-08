#!/usr/bin/env python3
"""Azure VPN gateways, their connections' IKE/IPsec settings, and local network gateways."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    arm_client_kwargs,
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)
from vpn_crypto import project_ipsec_policy, weak_algorithms  # noqa: E402

logger = logging.getLogger("azure_vpn_gateway_configuration")

IPSEC_CONNECTION_TYPES = ("ipsec", "vnet2vnet")


def project_gateway(gw) -> dict:
    sku = model_attr(gw, "sku")
    bgp = model_attr(gw, "bgp_settings")
    p2s = model_attr(gw, "vpn_client_configuration")
    return {
        "id": model_attr(gw, "id"),
        "name": model_attr(gw, "name"),
        "location": model_attr(gw, "location"),
        "tags": model_attr(gw, "tags"),
        "gateway_type": model_attr(gw, "gateway_type"),
        "vpn_type": model_attr(gw, "vpn_type"),
        "vpn_gateway_generation": model_attr(gw, "vpn_gateway_generation"),
        "sku_name": model_attr(sku, "name"),
        "sku_tier": model_attr(sku, "tier"),
        "active_active": model_attr(gw, "active_active"),
        "enable_bgp": model_attr(gw, "enable_bgp"),
        "bgp_asn": model_attr(bgp, "asn"),
        "disable_ip_sec_replay_protection": model_attr(gw, "disable_ip_sec_replay_protection"),
        "provisioning_state": model_attr(gw, "provisioning_state"),
        "p2s": None if p2s is None else {
            "vpn_client_protocols": model_attr(p2s, "vpn_client_protocols") or [],
            "vpn_authentication_types": model_attr(p2s, "vpn_authentication_types") or [],
            "aad_tenant": model_attr(p2s, "aad_tenant"),
            "root_certificates": len(model_attr(p2s, "vpn_client_root_certificates") or []),
            "revoked_certificates": len(model_attr(p2s, "vpn_client_revoked_certificates") or []),
            "radius_servers": len(model_attr(p2s, "radius_servers") or [])
            + (1 if model_attr(p2s, "radius_server_address") else 0),
            "ipsec_policies": [
                project_ipsec_policy(p) for p in (model_attr(p2s, "vpn_client_ipsec_policies") or [])
            ],
        },
    }


def project_connection(conn) -> dict:
    gw1 = model_attr(model_attr(conn, "virtual_network_gateway1"), "id")
    gw2 = model_attr(model_attr(conn, "virtual_network_gateway2"), "id")
    lng = model_attr(model_attr(conn, "local_network_gateway2"), "id")
    return {
        "id": model_attr(conn, "id"),
        "name": model_attr(conn, "name"),
        "location": model_attr(conn, "location"),
        "tags": model_attr(conn, "tags"),
        "connection_type": model_attr(conn, "connection_type"),
        "connection_protocol": model_attr(conn, "connection_protocol"),
        "connection_mode": model_attr(conn, "connection_mode"),
        "connection_status": model_attr(conn, "connection_status"),
        "authentication_type": model_attr(conn, "authentication_type"),
        "enable_bgp": model_attr(conn, "enable_bgp"),
        "use_policy_based_traffic_selectors": model_attr(conn, "use_policy_based_traffic_selectors"),
        "dpd_timeout_seconds": model_attr(conn, "dpd_timeout_seconds"),
        "virtual_network_gateway1": basename(gw1),
        "virtual_network_gateway2": basename(gw2),
        "local_network_gateway2": basename(lng),
        "ipsec_policies": [project_ipsec_policy(p) for p in (model_attr(conn, "ipsec_policies") or [])],
        "provisioning_state": model_attr(conn, "provisioning_state"),
    }


def project_local_gateway(lng) -> dict:
    space = model_attr(lng, "local_network_address_space")
    return {
        "id": model_attr(lng, "id"),
        "name": model_attr(lng, "name"),
        "location": model_attr(lng, "location"),
        "gateway_ip_address": model_attr(lng, "gateway_ip_address"),
        "fqdn": model_attr(lng, "fqdn"),
        "address_prefixes": model_attr(space, "address_prefixes") or [],
        "bgp_asn": model_attr(model_attr(lng, "bgp_settings"), "asn"),
        "provisioning_state": model_attr(lng, "provisioning_state"),
    }


def gateway_record(gw: dict) -> dict:
    return {
        **gw,
        "resource_group": resource_group_from_id(gw.get("id")),
        "tags": gw.get("tags") or {},
        "active_active": bool(gw.get("active_active") or False),
        "enable_bgp": bool(gw.get("enable_bgp") or False),
        "p2s_enabled": bool(gw.get("p2s") and gw["p2s"]["vpn_client_protocols"]),
    }


def connection_record(conn: dict) -> dict:
    """ikev2 is None for connection types that are not IPsec tunnels (ExpressRoute)."""
    is_ipsec = str(conn.get("connection_type") or "").lower() in IPSEC_CONNECTION_TYPES
    policies = conn.get("ipsec_policies") or []
    return {
        **conn,
        "resource_group": resource_group_from_id(conn.get("id")),
        "tags": conn.get("tags") or {},
        "enable_bgp": bool(conn.get("enable_bgp") or False),
        "use_policy_based_traffic_selectors": bool(
            conn.get("use_policy_based_traffic_selectors") or False
        ),
        "is_ipsec_tunnel": is_ipsec,
        "ikev2": (str(conn.get("connection_protocol") or "").lower() == "ikev2") if is_ipsec else None,
        "explicit_ipsec_policy": bool(policies),
        "weak_ipsec_algorithms": weak_algorithms(policies),
    }


def summarize(gateways: list[dict], connections: list[dict], local_gateways: list[dict]) -> dict:
    tunnels = [c for c in connections if c["is_ipsec_tunnel"]]
    ikev2 = sum(1 for c in tunnels if c["ikev2"])
    return {
        "total_gateways": len(gateways),
        "vpn_gateways": sum(1 for g in gateways if str(g.get("gateway_type") or "").lower() == "vpn"),
        "active_active_gateways": sum(1 for g in gateways if g["active_active"]),
        "p2s_enabled_gateways": sum(1 for g in gateways if g["p2s_enabled"]),
        "total_connections": len(connections),
        "ipsec_connections": len(tunnels),
        "ikev2_connections": ikev2,
        "ikev1_connections": len(tunnels) - ikev2,
        "ikev2_percentage": coverage_percentage(ikev2, len(tunnels)),
        "explicit_ipsec_policy_connections": sum(1 for c in tunnels if c["explicit_ipsec_policy"]),
        "weak_ipsec_policy_connections": sum(1 for c in tunnels if c["weak_ipsec_algorithms"]),
        "total_local_network_gateways": len(local_gateways),
    }


def collect(subscription_id, cred, collector: Collector):
    def _clients():
        from azure.mgmt.network import NetworkManagementClient  # lazy

        try:
            from azure.mgmt.resource.resources import ResourceManagementClient  # lazy
        except ImportError:  # pragma: no cover - depends on installed SDK version
            from azure.mgmt.resource import ResourceManagementClient  # lazy
        return (
            ResourceManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
            NetworkManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
        )

    clients = collector.guard("network.NetworkManagementClient (init)", _clients)
    if clients is None:
        return [], [], []
    rm, net = clients
    groups = collector.guard(
        "resource.resource_groups.list",
        lambda: sorted(model_attr(g, "name") for g in rm.resource_groups.list()),
        default=[],
    )
    gateways, connections, local_gateways = [], [], []
    for rg in groups:
        gateways += collector.guard(
            f"network.virtual_network_gateways.list({rg})",
            lambda: [gateway_record(project_gateway(g)) for g in net.virtual_network_gateways.list(rg)],
            default=[],
        )
        connections += collector.guard(
            f"network.virtual_network_gateway_connections.list({rg})",
            lambda: [
                connection_record(project_connection(c))
                for c in net.virtual_network_gateway_connections.list(rg)
            ],
            default=[],
        )
        local_gateways += collector.guard(
            f"network.local_network_gateways.list({rg})",
            lambda: [project_local_gateway(g) for g in net.local_network_gateways.list(rg)],
            default=[],
        )

    def by_id(records):
        return sorted(records, key=lambda r: r.get("id") or "")

    return by_id(gateways), by_id(connections), by_id(local_gateways)


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

    gateways, connections, local_gateways = [], [], []
    if subscription_id and cred is not None:
        gateways, connections, local_gateways = collect(subscription_id, cred, collector)
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
            "virtual_network_gateways": gateways,
            "connections": connections,
            "local_network_gateways": local_gateways,
        },
        summary=summarize(gateways, connections, local_gateways),
    )
    filename = (
        f"azure_vpn_gateway_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
