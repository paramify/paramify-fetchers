#!/usr/bin/env python3
"""Azure Virtual WANs, hubs, hub VPN/P2S gateways, VPN sites and server configurations."""

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

logger = logging.getLogger("azure_virtual_wan_configuration")


def _ref(model, name):
    return basename(model_attr(model_attr(model, name), "id"))


def project_wan(wan) -> dict:
    return {
        "id": model_attr(wan, "id"),
        "name": model_attr(wan, "name"),
        "location": model_attr(wan, "location"),
        "tags": model_attr(wan, "tags"),
        # properties.type (Basic/Standard) is shadowed by the resource type on the flattened model.
        "type": model_attr(model_attr(wan, "properties"), "type"),
        "disable_vpn_encryption": bool(model_attr(wan, "disable_vpn_encryption") or False),
        "allow_branch_to_branch_traffic": model_attr(wan, "allow_branch_to_branch_traffic"),
        "allow_vnet_to_vnet_traffic": model_attr(wan, "allow_vnet_to_vnet_traffic"),
        "virtual_hubs": [basename(model_attr(h, "id")) for h in (model_attr(wan, "virtual_hubs") or [])],
        "provisioning_state": model_attr(wan, "provisioning_state"),
    }


def project_hub(hub) -> dict:
    firewall = _ref(hub, "azure_firewall")
    partner = _ref(hub, "security_partner_provider")
    return {
        "id": model_attr(hub, "id"),
        "name": model_attr(hub, "name"),
        "location": model_attr(hub, "location"),
        "tags": model_attr(hub, "tags"),
        "virtual_wan": _ref(hub, "virtual_wan"),
        "sku": model_attr(hub, "sku"),
        "address_prefix": model_attr(hub, "address_prefix"),
        "azure_firewall": firewall,
        "security_partner_provider": partner,
        "security_provider_name": model_attr(hub, "security_provider_name"),
        "secured_hub": bool(firewall or partner),
        "vpn_gateway": _ref(hub, "vpn_gateway"),
        "p2s_vpn_gateway": _ref(hub, "p2_s_vpn_gateway"),
        "express_route_gateway": _ref(hub, "express_route_gateway"),
        "allow_branch_to_branch_traffic": model_attr(hub, "allow_branch_to_branch_traffic"),
        "hub_routing_preference": model_attr(hub, "hub_routing_preference"),
        "routing_state": model_attr(hub, "routing_state"),
        "provisioning_state": model_attr(hub, "provisioning_state"),
    }


def link_connection_record(link) -> dict:
    policies = [project_ipsec_policy(p) for p in (model_attr(link, "ipsec_policies") or [])]
    protocol = model_attr(link, "vpn_connection_protocol_type")
    return {
        "id": model_attr(link, "id"),
        "name": model_attr(link, "name"),
        "vpn_site_link": _ref(link, "vpn_site_link"),
        "connection_status": model_attr(link, "connection_status"),
        "vpn_connection_protocol_type": protocol,
        "vpn_link_connection_mode": model_attr(link, "vpn_link_connection_mode"),
        "enable_bgp": bool(model_attr(link, "enable_bgp") or False),
        "use_policy_based_traffic_selectors": bool(
            model_attr(link, "use_policy_based_traffic_selectors") or False
        ),
        "ikev2": str(protocol or "").lower() == "ikev2",
        "ipsec_policies": policies,
        "explicit_ipsec_policy": bool(policies),
        "weak_ipsec_algorithms": weak_algorithms(policies),
        "provisioning_state": model_attr(link, "provisioning_state"),
    }


def project_vpn_gateway(gw) -> dict:
    return {
        "id": model_attr(gw, "id"),
        "name": model_attr(gw, "name"),
        "location": model_attr(gw, "location"),
        "virtual_hub": _ref(gw, "virtual_hub"),
        "vpn_gateway_scale_unit": model_attr(gw, "vpn_gateway_scale_unit"),
        "bgp_asn": model_attr(model_attr(gw, "bgp_settings"), "asn"),
        "provisioning_state": model_attr(gw, "provisioning_state"),
        "connections": sorted(
            (
                {
                    "id": model_attr(c, "id"),
                    "name": model_attr(c, "name"),
                    "remote_vpn_site": _ref(c, "remote_vpn_site"),
                    "connection_status": model_attr(c, "connection_status"),
                    "enable_internet_security": bool(model_attr(c, "enable_internet_security") or False),
                    "link_connections": sorted(
                        (link_connection_record(link) for link in (model_attr(c, "vpn_link_connections") or [])),
                        key=lambda r: r.get("id") or "",
                    ),
                }
                for c in (model_attr(gw, "connections") or [])
            ),
            key=lambda r: r.get("id") or "",
        ),
    }


def project_vpn_site(site) -> dict:
    device = model_attr(site, "device_properties")
    return {
        "id": model_attr(site, "id"),
        "name": model_attr(site, "name"),
        "location": model_attr(site, "location"),
        "virtual_wan": _ref(site, "virtual_wan"),
        "device_vendor": model_attr(device, "device_vendor"),
        "device_model": model_attr(device, "device_model"),
        "address_prefixes": model_attr(model_attr(site, "address_space"), "address_prefixes") or [],
        "is_security_site": bool(model_attr(site, "is_security_site") or False),
        "links": [
            {
                "name": model_attr(link, "name"),
                "ip_address": model_attr(link, "ip_address"),
                "fqdn": model_attr(link, "fqdn"),
            }
            for link in (model_attr(site, "vpn_site_links") or [])
        ],
        "provisioning_state": model_attr(site, "provisioning_state"),
    }


def project_p2s_gateway(gw) -> dict:
    return {
        "id": model_attr(gw, "id"),
        "name": model_attr(gw, "name"),
        "location": model_attr(gw, "location"),
        "virtual_hub": _ref(gw, "virtual_hub"),
        "vpn_server_configuration": _ref(gw, "vpn_server_configuration"),
        "custom_dns_servers": model_attr(gw, "custom_dns_servers") or [],
        "provisioning_state": model_attr(gw, "provisioning_state"),
    }


def project_server_configuration(cfg) -> dict:
    policies = [project_ipsec_policy(p) for p in (model_attr(cfg, "vpn_client_ipsec_policies") or [])]
    aad = model_attr(cfg, "aad_authentication_parameters")
    return {
        "id": model_attr(cfg, "id"),
        "name": model_attr(cfg, "name"),
        "location": model_attr(cfg, "location"),
        "vpn_protocols": model_attr(cfg, "vpn_protocols") or [],
        "vpn_authentication_types": model_attr(cfg, "vpn_authentication_types") or [],
        "aad_tenant": model_attr(aad, "aad_tenant"),
        "root_certificates": len(model_attr(cfg, "vpn_client_root_certificates") or []),
        "revoked_certificates": len(model_attr(cfg, "vpn_client_revoked_certificates") or []),
        "radius_servers": len(model_attr(cfg, "radius_servers") or [])
        + (1 if model_attr(cfg, "radius_server_address") else 0),
        "ipsec_policies": policies,
        "weak_ipsec_algorithms": weak_algorithms(policies),
        "provisioning_state": model_attr(cfg, "provisioning_state"),
    }


def with_common(record: dict) -> dict:
    return {**record, "resource_group": resource_group_from_id(record.get("id")),
            "tags": record.get("tags") or {}}


def summarize(results: dict) -> dict:
    wans, hubs = results["virtual_wans"], results["virtual_hubs"]
    connections = [c for g in results["vpn_gateways"] for c in g["connections"]]
    links = [link for c in connections for link in c["link_connections"]]
    ikev2 = sum(1 for link in links if link["ikev2"])
    secured = sum(1 for h in hubs if h["secured_hub"])
    return {
        "total_virtual_wans": len(wans),
        "vpn_encryption_disabled_wans": sum(1 for w in wans if w["disable_vpn_encryption"]),
        "total_virtual_hubs": len(hubs),
        "secured_hubs": secured,
        "secured_hub_percentage": coverage_percentage(secured, len(hubs)),
        "total_vpn_gateways": len(results["vpn_gateways"]),
        "total_vpn_connections": len(connections),
        "total_vpn_link_connections": len(links),
        "ikev2_link_connections": ikev2,
        "ikev1_link_connections": len(links) - ikev2,
        "explicit_ipsec_policy_link_connections": sum(1 for link in links if link["explicit_ipsec_policy"]),
        "weak_ipsec_policy_link_connections": sum(1 for link in links if link["weak_ipsec_algorithms"]),
        "total_vpn_sites": len(results["vpn_sites"]),
        "total_p2s_vpn_gateways": len(results["p2s_vpn_gateways"]),
        "total_vpn_server_configurations": len(results["vpn_server_configurations"]),
    }


COLLECTIONS = (
    ("virtual_wans", "virtual_wans", project_wan),
    ("virtual_hubs", "virtual_hubs", project_hub),
    ("vpn_gateways", "vpn_gateways", project_vpn_gateway),
    ("vpn_sites", "vpn_sites", project_vpn_site),
    ("p2s_vpn_gateways", "p2_svpn_gateways", project_p2s_gateway),
    ("vpn_server_configurations", "vpn_server_configurations", project_server_configuration),
)


def collect(subscription_id, cred, collector: Collector) -> dict:
    def _client():
        from azure.mgmt.network import NetworkManagementClient  # lazy

        return NetworkManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    client = collector.guard("network.NetworkManagementClient (init)", _client)
    results = {key: [] for key, _, _ in COLLECTIONS}
    if client is None:
        return results
    for key, operation, project in COLLECTIONS:
        records = collector.guard(
            f"network.{operation}.list",
            lambda: [with_common(project(r)) for r in getattr(client, operation).list()],
            default=[],
        )
        results[key] = sorted(records, key=lambda r: r.get("id") or "")
    return results


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

    results = {key: [] for key, _, _ in COLLECTIONS}
    if subscription_id and cred is not None:
        results = collect(subscription_id, cred, collector)
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
        results=results,
        summary=summarize(results),
    )
    filename = (
        f"azure_virtual_wan_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
