#!/usr/bin/env python3
"""Azure VNet egress routing: where each subnet's Internet-bound traffic goes, for one subscription."""

import ipaddress
import logging
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    PLATFORM_SUBNET_NAMES,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    arm_id_key,
    basename,
    build_payload,
    classify_failure_code,
    credential,
    enabled_subscription_ids,
    failure_reason,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    vnet_id_of,
    write_evidence,
)
from azure_rest import int_config  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402
from scope_exclusions import excluded_item  # noqa: E402

logger = logging.getLogger("azure_vnet_egress_routing")

DEFAULT_ROUTE = ipaddress.ip_network("0.0.0.0/0")
APPLIANCE_HOPS = ("VirtualAppliance", "VirtualApplianceEcmp")
SUBNET_EGRESS_PATHS = (
    "appliance", "blackhole", "gateway", "nat_gateway", "default_outbound", "none", "other",
    "virtual_hub_unresolved", "platform_managed",
)
# Measured: a Virtual WAN hub connection peers the spoke to a Microsoft-managed HV_<hub>_<guid> VNet.
HUB_PEER_VNET = re.compile(
    r"/virtualNetworks/HV_(.+)_[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$", re.IGNORECASE
)
NIC_EGRESS_PATHS = SUBNET_EGRESS_PATHS + ("public_ip", "mixed")
# A route to Internet on a subnet whose default goes elsewhere sends that range around the default's path.
BYPASSABLE_PATHS = ("appliance", "blackhole", "gateway", "other")
THREAT_INTEL_STRICTNESS = {"Off": 0, "Alert": 1, "Deny": 2}
SEARCH_LIMIT_ENV = "VIRTUAL_HUB_SEARCH_MAX_SUBSCRIPTIONS"
DEFAULT_SEARCH_LIMIT = 50
EXCLUSION_KINDS = ("virtual_network", "subnet", "route_table", "network_interface", "azure_firewall", "virtual_hub")


# --- projection: the only code here that touches an azure-mgmt model ---

def _ids(models) -> list:
    return [model_attr(m, "id") for m in (models or []) if model_attr(m, "id")]


def _prefixes(model) -> list:
    single = model_attr(model, "address_prefix")
    return [p for p in [single, *(model_attr(model, "address_prefixes") or [])] if p]


def project_route(route) -> dict:
    ecmp = model_attr(model_attr(route, "next_hop"), "next_hop_ip_addresses") or []
    single = model_attr(route, "next_hop_ip_address")
    return {
        "name": model_attr(route, "name"),
        "address_prefix": model_attr(route, "address_prefix"),
        "next_hop_type": model_attr(route, "next_hop_type"),
        "next_hop_ip_addresses": [ip for ip in [single, *ecmp] if ip],
    }


def project_route_table(table) -> dict:
    return {
        "id": model_attr(table, "id"),
        "name": model_attr(table, "name"),
        "location": model_attr(table, "location"),
        "disable_bgp_route_propagation": model_attr(table, "disable_bgp_route_propagation"),
        "routes": [project_route(r) for r in (model_attr(table, "routes") or [])],
        "subnet_ids": _ids(model_attr(table, "subnets")),
    }


def project_subnet(subnet) -> dict:
    return {
        "id": model_attr(subnet, "id"),
        "name": model_attr(subnet, "name"),
        "address_prefixes": _prefixes(subnet),
        "route_table_id": model_attr(model_attr(subnet, "route_table"), "id"),
        "nat_gateway_id": model_attr(model_attr(subnet, "nat_gateway"), "id"),
        "default_outbound_access": model_attr(subnet, "default_outbound_access"),
        "service_endpoints": [
            model_attr(e, "service") for e in (model_attr(subnet, "service_endpoints") or [])
        ],
        "delegations": [
            model_attr(d, "service_name") for d in (model_attr(subnet, "delegations") or [])
        ],
    }


def project_virtual_network(vnet) -> dict:
    return {
        "id": model_attr(vnet, "id"),
        "name": model_attr(vnet, "name"),
        "location": model_attr(vnet, "location"),
        "address_prefixes": model_attr(model_attr(vnet, "address_space"), "address_prefixes") or [],
        "default_public_nat_gateway_id": model_attr(
            model_attr(vnet, "default_public_nat_gateway"), "id"
        ),
        "subnets": [project_subnet(s) for s in (model_attr(vnet, "subnets") or [])],
    }


def project_peering(peering) -> dict:
    remote = model_attr(peering, "remote_address_space") or model_attr(
        peering, "remote_virtual_network_address_space"
    )
    return {
        "name": model_attr(peering, "name"),
        "peering_state": model_attr(peering, "peering_state"),
        "remote_virtual_network_id": model_attr(model_attr(peering, "remote_virtual_network"), "id"),
        "remote_address_prefixes": model_attr(remote, "address_prefixes") or [],
    }


def project_network_interface(nic) -> dict:
    return {
        "id": model_attr(nic, "id"),
        "name": model_attr(nic, "name"),
        "location": model_attr(nic, "location"),
        "virtual_machine_id": model_attr(model_attr(nic, "virtual_machine"), "id"),
        "enable_ip_forwarding": model_attr(nic, "enable_ip_forwarding"),
        "default_outbound_connectivity_enabled": model_attr(nic, "default_outbound_connectivity_enabled"),
        "ip_configurations": [
            {
                "subnet_id": model_attr(model_attr(ipc, "subnet"), "id"),
                "private_ip_address": model_attr(ipc, "private_ip_address"),
                "public_ip_address_id": model_attr(model_attr(ipc, "public_ip_address"), "id"),
            }
            for ipc in (model_attr(nic, "ip_configurations") or [])
        ],
    }


def project_firewall(firewall) -> dict:
    sku = model_attr(firewall, "sku")
    return {
        "id": model_attr(firewall, "id"),
        "name": model_attr(firewall, "name"),
        "location": model_attr(firewall, "location"),
        "sku_name": model_attr(sku, "name"),
        "sku_tier": model_attr(sku, "tier"),
        "threat_intel_mode": model_attr(firewall, "threat_intel_mode"),
        "firewall_policy_id": model_attr(model_attr(firewall, "firewall_policy"), "id"),
        "virtual_hub_id": model_attr(model_attr(firewall, "virtual_hub"), "id"),
        "hub_private_ip_address": model_attr(model_attr(firewall, "hub_ip_addresses"), "private_ip_address"),
        "ip_configurations": [
            {
                "subnet_id": model_attr(model_attr(ipc, "subnet"), "id"),
                "private_ip_address": model_attr(ipc, "private_ip_address"),
            }
            for ipc in (model_attr(firewall, "ip_configurations") or [])
        ],
    }


def project_virtual_hub(hub, intents, connections, tables) -> dict:
    return {
        "id": model_attr(hub, "id"),
        "name": model_attr(hub, "name"),
        "location": model_attr(hub, "location"),
        "firewall_id": model_attr(model_attr(hub, "azure_firewall"), "id"),
        "routing_policies": [
            {"destinations": list(model_attr(p, "destinations") or []), "next_hop": model_attr(p, "next_hop")}
            for intent in intents
            for p in (model_attr(intent, "routing_policies") or [])
        ],
        "connections": [
            {
                "remote_virtual_network_id": model_attr(model_attr(c, "remote_virtual_network"), "id"),
                "enable_internet_security": model_attr(c, "enable_internet_security"),
                "associated_route_table_id": model_attr(
                    model_attr(model_attr(c, "routing_configuration"), "associated_route_table"), "id"
                ),
            }
            for c in connections
        ],
        "route_tables": [
            {
                "id": model_attr(t, "id"),
                "routes": [
                    {
                        "destinations": list(model_attr(r, "destinations") or []),
                        "next_hop_type": model_attr(r, "next_hop_type"),
                        "next_hop": model_attr(r, "next_hop"),
                    }
                    for r in (model_attr(t, "routes") or [])
                ],
            }
            for t in tables
        ],
    }


def project_firewall_policy(policy) -> dict:
    return {
        "id": model_attr(policy, "id"),
        "name": model_attr(policy, "name"),
        "sku_tier": model_attr(model_attr(policy, "sku"), "tier"),
        "threat_intel_mode": model_attr(policy, "threat_intel_mode"),
        "intrusion_detection_mode": model_attr(model_attr(policy, "intrusion_detection"), "mode"),
        "base_policy_id": model_attr(model_attr(policy, "base_policy"), "id"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def _network(prefix):
    # Service-tag prefixes ("AzureCloud") are valid route destinations but not CIDRs.
    try:
        return ipaddress.ip_network(str(prefix), strict=False)
    except ValueError:
        return None


def default_route(routes: list[dict]):
    """The route that carries 0.0.0.0/0, with the prefixes it is made of.

    Routes of one next-hop kind that together cover 0.0.0.0/0 (0.0.0.0/1 + 128.0.0.0/1) are more specific than an
    exact 0.0.0.0/0 route, so they win over it.
    """
    by_hop = {}
    for route in routes:
        net = _network(route.get("address_prefix"))
        if net is not None and net.version == 4 and net.prefixlen:
            hop = route.get("next_hop_type")
            by_hop.setdefault("appliance" if hop in APPLIANCE_HOPS else hop, []).append((net, route))
    for parts in by_hop.values():
        nets = [net for net, _ in parts]
        if list(ipaddress.collapse_addresses(nets)) != [DEFAULT_ROUTE]:
            continue
        top = sorted(
            ((net, r) for net, r in parts if not any(net != other and net.subnet_of(other) for other in nets)),
            key=lambda p: p[0],
        )
        return {
            "name": "+".join(r.get("name") or "" for _, r in top),
            "address_prefix": str(DEFAULT_ROUTE),
            "next_hop_type": top[0][1].get("next_hop_type"),
            "next_hop_ip_addresses": list(dict.fromkeys(ip for _, r in top for ip in r["next_hop_ip_addresses"])),
            "address_prefixes": [r.get("address_prefix") for _, r in top],
        }
    exact = next((r for r in routes if _network(r.get("address_prefix")) == DEFAULT_ROUTE), None)
    return {**exact, "address_prefixes": [exact.get("address_prefix")]} if exact else None


def internet_bypass_routes(routes: list[dict], path: str) -> list:
    if path not in BYPASSABLE_PATHS:
        return []
    return [
        {"name": r.get("name"), "address_prefix": r.get("address_prefix")}
        for r in routes
        if r.get("next_hop_type") == "Internet"
    ]


def forced_through_appliance(prefix: str, routes: list[dict]) -> bool:
    """Do the routes send all of `prefix` to an appliance, beating its system route?"""
    target = _network(prefix)
    if target is None:
        return False
    inside = [
        (net, r)
        for r in routes
        if (net := _network(r.get("address_prefix"))) is not None
        and net.version == target.version
        and net.subnet_of(target)
    ]
    if any(r.get("next_hop_type") not in APPLIANCE_HOPS for _, r in inside):
        return False
    return list(ipaddress.collapse_addresses(net for net, _ in inside)) == [target]


def appliance_owner(ips: list, owners_by_ip: dict) -> str:
    if not ips:
        return "unknown"
    owners = [owners_by_ip.get(ip) for ip in ips]
    if any(o is None for o in owners):
        return "not_in_subscription"
    kinds = {
        "azure_firewall" if o["kind"] == "azure_firewall"
        else "nic_ip_forwarding" if o.get("enable_ip_forwarding") else "nic_no_ip_forwarding"
        for o in owners
    }
    if "nic_no_ip_forwarding" in kinds:
        return "nic_no_ip_forwarding"
    return kinds.pop() if len(kinds) == 1 else "mixed"


def subnet_egress_path(subnet: dict, vnet: dict, route) -> str:
    if (subnet.get("name") or "").lower() in PLATFORM_SUBNET_NAMES:
        return "platform_managed"
    hop = route.get("next_hop_type") if route else "Internet"
    if hop in APPLIANCE_HOPS:
        return "appliance"
    if hop == "None":
        return "blackhole"
    if hop == "VirtualNetworkGateway":
        return "gateway"
    if hop != "Internet":
        return "other"
    if subnet.get("nat_gateway_id") or vnet.get("default_public_nat_gateway_id"):
        return "nat_gateway"
    return "default_outbound" if subnet.get("default_outbound_access") is not False else "none"


HUB = "virtual_hub"


def appliances_by_vnet_ip(nics: list[dict], firewalls: list[dict]) -> dict:
    """(lower-cased VNet id, private IP) -> what holds that IP; Virtual WAN hub firewalls key on HUB."""
    index = {}
    holders = [(n, "nic") for n in nics] + [(f, "azure_firewall") for f in firewalls]
    for holder, kind in holders:
        owner = {"kind": kind, "id": holder.get("id"), "enable_ip_forwarding": holder.get("enable_ip_forwarding")}
        for ipc in holder.get("ip_configurations") or []:
            if ipc.get("private_ip_address"):
                index[(vnet_id_of(ipc.get("subnet_id")), ipc["private_ip_address"])] = owner
        if holder.get("hub_private_ip_address"):
            index[(HUB, holder["hub_private_ip_address"])] = owner
    return index


def hub_routes_by_vnet(hubs: list[dict]) -> dict:
    """Lower-cased spoke VNet id -> the Virtual WAN hub it connects to and where that hub sends its traffic."""
    index = {}
    for hub in hubs:
        policies = hub.get("routing_policies") or []
        internet = next((p["next_hop"] for p in policies if "Internet" in p["destinations"]), None)
        private = next((p["next_hop"] for p in policies if "PrivateTraffic" in p["destinations"]), None)
        tables = {arm_id_key(t["id"]): t for t in hub.get("route_tables") or []}
        default_table = next((t for k, t in tables.items() if k.endswith("/defaultroutetable")), None)
        for conn in hub.get("connections") or []:
            hop = internet
            if hop is None:
                table = tables.get(arm_id_key(conn.get("associated_route_table_id"))) or default_table
                hop = next(
                    (r["next_hop"] for r in (table or {}).get("routes", []) if "0.0.0.0/0" in r["destinations"]), None
                )
            index[arm_id_key(conn.get("remote_virtual_network_id"))] = {
                "virtual_hub_id": hub["id"],
                "internet_next_hop": hop if conn.get("enable_internet_security") else None,
                "private_next_hop": private,
            }
    return index


def hub_spoke_name(peers: list[dict]):
    """The Virtual WAN hub a VNet's own peerings say it connects to: its name, "" if unreadable, None if not a spoke."""
    names = [m.group(1) for p in peers if (m := HUB_PEER_VNET.search(p.get("remote_virtual_network_id") or ""))]
    if names:
        return names[0]
    return "" if any((p.get("name") or "").lower().startswith("remotevnettohubpeering") for p in peers) else None


def subnet_record(
    subnet: dict, vnet: dict, tables_by_id: dict, peers: list[dict], appliances: dict, hub_routes: dict
) -> dict:
    table = tables_by_id.get(arm_id_key(subnet.get("route_table_id")))
    routes = table["routes"] if table else []
    route = default_route(routes)
    path = subnet_egress_path(subnet, vnet, route)
    bgp = not (table and table.get("disable_bgp_route_propagation"))
    hub = hub_routes.get(arm_id_key(vnet["id"])) or {}
    # A hub's propagated 0.0.0.0/0 beats the system route and NAT gateway, but not a user-defined default route.
    hub_may_route = route is None and bgp and path in ("default_outbound", "none", "nat_gateway")
    hub_hop = hub.get("internet_next_hop") if hub_may_route else None
    unresolved = hub_may_route and not hub and hub_spoke_name(peers) is not None
    if hub_hop:
        path = "appliance"
    elif unresolved:
        path = "virtual_hub_unresolved"
    if route:
        source, hop_type = "user_defined", route.get("next_hop_type")
    elif hub_hop:
        source, hop_type = "virtual_hub", "VirtualHub"
    elif unresolved:
        source, hop_type = "virtual_hub_unresolved", None
    else:
        source, hop_type = "system", "Internet"
    connected = [p for p in peers if p.get("peering_state") == "Connected"]
    reachable = [arm_id_key(vnet["id"]), *(arm_id_key(p.get("remote_virtual_network_id")) for p in connected), HUB]
    owner, firewall_ids = None, []
    if hub_hop:
        is_firewall = "/azurefirewalls/" in arm_id_key(hub_hop)
        owner, firewall_ids = ("azure_firewall", [hub_hop]) if is_firewall else ("hub_appliance", [])
    elif path == "appliance":
        owners_by_ip = {
            ip: next((appliances[(v, ip)] for v in reachable if (v, ip) in appliances), None)
            for ip in route["next_hop_ip_addresses"]
        }
        owner = appliance_owner(route["next_hop_ip_addresses"], owners_by_ip)
        firewall_ids = sorted({o["id"] for o in owners_by_ip.values() if o and o["kind"] == "azure_firewall"})
    peer_prefixes = sorted({p for peer in connected for p in peer.get("remote_address_prefixes") or []})
    return {
        "id": subnet.get("id"),
        "name": subnet.get("name"),
        "virtual_network_id": vnet.get("id"),
        "virtual_network_name": vnet.get("name"),
        "location": vnet.get("location"),
        "resource_group": resource_group_from_id(subnet.get("id")),
        "address_prefixes": subnet.get("address_prefixes") or [],
        "platform_subnet": path == "platform_managed",
        "egress_path": path,
        "default_outbound_access": subnet.get("default_outbound_access"),
        "default_outbound_access_effective": subnet.get("default_outbound_access") is not False,
        "route_table_id": subnet.get("route_table_id"),
        "bgp_route_propagation": bgp,
        "default_route": {
            "source": source,
            "next_hop_type": hop_type,
            "next_hop_ip_addresses": route.get("next_hop_ip_addresses", []) if route else [],
            "next_hop_resource_id": hub_hop,
            "user_defined_prefixes": route["address_prefixes"] if route else [],
        },
        "internet_bypass_routes": internet_bypass_routes(routes, path),
        "virtual_hub_id": hub.get("virtual_hub_id"),
        "virtual_hub_private_traffic_next_hop": hub.get("private_next_hop"),
        "appliance_owner": owner,
        "appliance_firewall_ids": firewall_ids,
        "nat_gateway_id": subnet.get("nat_gateway_id") or vnet.get("default_public_nat_gateway_id"),
        "nat_gateway_source": (
            "subnet" if subnet.get("nat_gateway_id")
            else "vnet_default" if vnet.get("default_public_nat_gateway_id") else None
        ),
        "service_endpoints": sorted(s for s in subnet.get("service_endpoints") or [] if s),
        "delegations": sorted(d for d in subnet.get("delegations") or [] if d),
        "unrouted_internal_prefixes": [
            p for p in vnet.get("address_prefixes") or [] if not forced_through_appliance(p, routes)
        ],
        "unrouted_peered_prefixes": [p for p in peer_prefixes if not forced_through_appliance(p, routes)],
    }


def virtual_network_record(vnet: dict, peers: list[dict], hub_routes: dict) -> dict:
    hub = hub_routes.get(arm_id_key(vnet["id"]))
    spoke_name = hub_spoke_name(peers)
    spoke = hub is not None or spoke_name is not None
    return {
        "id": vnet["id"],
        "name": vnet["name"],
        "location": vnet["location"],
        "resource_group": resource_group_from_id(vnet["id"]),
        "address_prefixes": vnet["address_prefixes"],
        "default_public_nat_gateway_id": vnet["default_public_nat_gateway_id"],
        "subnet_count": len(vnet["subnets"]),
        "virtual_hub_spoke": spoke,
        "virtual_hub_resolved": (hub is not None) if spoke else None,
        "virtual_hub_name": basename(hub["virtual_hub_id"]) if hub else spoke_name or None,
        "virtual_hub_id": (hub or {}).get("virtual_hub_id"),
        "virtual_hub_internet_next_hop": (hub or {}).get("internet_next_hop"),
        "virtual_hub_private_traffic_next_hop": (hub or {}).get("private_next_hop"),
        "connected_peer_prefixes": sorted(
            {
                p
                for peer in peers
                if peer.get("peering_state") == "Connected"
                for p in peer.get("remote_address_prefixes") or []
            }
        ),
    }


def route_table_record(table: dict) -> dict:
    route = default_route(table["routes"])
    return {
        "id": table.get("id"),
        "name": table.get("name"),
        "location": table.get("location"),
        "resource_group": resource_group_from_id(table.get("id")),
        "disable_bgp_route_propagation": bool(table.get("disable_bgp_route_propagation")),
        "routes": table["routes"],
        "default_route_next_hop_type": route.get("next_hop_type") if route else None,
        "subnet_ids": sorted(table["subnet_ids"]),
        "associated": bool(table["subnet_ids"]),
    }


def network_interface_record(nic: dict, path_by_subnet: dict) -> dict:
    subnet_ids = sorted({c["subnet_id"] for c in nic.get("ip_configurations") or [] if c.get("subnet_id")})
    has_public_ip = any(c.get("public_ip_address_id") for c in nic.get("ip_configurations") or [])
    paths = {path_by_subnet.get(arm_id_key(s)) for s in subnet_ids} - {None}
    path = paths.pop() if len(paths) == 1 else ("mixed" if paths else None)
    if has_public_ip and path in ("default_outbound", "none"):
        path = "public_ip"
    return {
        "id": nic.get("id"),
        "name": nic.get("name"),
        "location": nic.get("location"),
        "resource_group": resource_group_from_id(nic.get("id")),
        "virtual_machine_id": nic.get("virtual_machine_id"),
        "subnet_ids": subnet_ids,
        "has_public_ip": has_public_ip,
        "enable_ip_forwarding": bool(nic.get("enable_ip_forwarding")),
        "default_outbound_connectivity_enabled": nic.get("default_outbound_connectivity_enabled"),
        "egress_path": path,
    }


def policy_threat_intel_mode(policy_id: str, policies_by_id: dict):
    """(mode, chain resolved): the strictest threat-intel mode along a policy's base_policy chain.

    A child policy inherits its parent's mode and may only tighten it. With a parent out of reach, only Deny is certain.
    """
    modes, seen, resolved = [], set(), True
    while policy_id and arm_id_key(policy_id) not in seen:
        seen.add(arm_id_key(policy_id))
        policy = policies_by_id.get(arm_id_key(policy_id))
        if policy is None:
            resolved = False
            break
        modes.append(policy.get("threat_intel_mode"))
        policy_id = policy.get("base_policy_id")
    known = [m for m in modes if m in THREAT_INTEL_STRICTNESS]
    mode = max(known, key=THREAT_INTEL_STRICTNESS.get) if known else None
    return (mode if resolved or mode == "Deny" else None), resolved


def firewall_record(firewall: dict, policies_by_id: dict, subnets: list[dict]) -> dict:
    policy_id = firewall.get("firewall_policy_id")
    policy = policies_by_id.get(arm_id_key(policy_id)) if policy_id else None
    chain_mode, chain_resolved = policy_threat_intel_mode(policy_id, policies_by_id) if policy_id else (None, None)
    configs = firewall.get("ip_configurations") or []
    ips = {c["private_ip_address"] for c in configs if c.get("private_ip_address")}
    if firewall.get("hub_private_ip_address"):
        ips.add(firewall["hub_private_ip_address"])
    key = arm_id_key(firewall.get("id"))
    return {
        "id": firewall.get("id"),
        "name": firewall.get("name"),
        "location": firewall.get("location"),
        "resource_group": resource_group_from_id(firewall.get("id")),
        "sku_name": firewall.get("sku_name"),
        "sku_tier": firewall.get("sku_tier"),
        "virtual_network_id": next(
            (c["subnet_id"][: len(vnet_id_of(c["subnet_id"]))] for c in configs if vnet_id_of(c.get("subnet_id"))), None
        ),
        "virtual_hub_id": firewall.get("virtual_hub_id"),
        "private_ip_addresses": sorted(ips),
        "threat_intel_mode": firewall.get("threat_intel_mode"),
        "firewall_policy_id": policy_id,
        "firewall_policy_resolved": chain_resolved,
        "policy_base_policy_id": policy.get("base_policy_id") if policy else None,
        "policy_threat_intel_mode": policy.get("threat_intel_mode") if policy else None,
        "policy_intrusion_detection_mode": policy.get("intrusion_detection_mode") if policy else None,
        "policy_sku_tier": policy.get("sku_tier") if policy else None,
        "effective_threat_intel_mode": chain_mode if policy_id else firewall.get("threat_intel_mode"),
        "routed_workload_subnets": sum(
            1 for s in subnets
            if not s["platform_subnet"] and key in {arm_id_key(i) for i in s["appliance_firewall_ids"]}
        ),
    }


def _count_by(records: list[dict], key: str, values: tuple) -> dict:
    return {v: sum(1 for r in records if r.get(key) == v) for v in values}


def summarize(
    vnets: list[dict], subnets: list[dict], tables: list[dict], nics: list[dict], firewalls: list[dict],
    hubs: list[dict] = (),
) -> dict:
    workload = [s for s in subnets if not s["platform_subnet"]]
    return {
        "total_virtual_networks": len(vnets),
        "total_subnets": len(subnets),
        "workload_subnets": len(workload),
        "platform_subnets": len(subnets) - len(workload),
        "workload_subnets_by_egress_path": _count_by(workload, "egress_path", SUBNET_EGRESS_PATHS[:-1]),
        "workload_subnets_default_outbound_effective": sum(
            1 for s in workload if s["default_outbound_access_effective"]
        ),
        "workload_subnets_appliance_with_default_outbound_fallback": sum(
            1 for s in workload if s["egress_path"] == "appliance" and s["default_outbound_access_effective"]
        ),
        "workload_subnets_appliance_not_in_subscription": sum(
            1 for s in workload if s["appliance_owner"] == "not_in_subscription"
        ),
        "workload_subnets_appliance_azure_firewall": sum(
            1 for s in workload if s["appliance_owner"] == "azure_firewall"
        ),
        "workload_subnets_via_virtual_hub": sum(1 for s in workload if s["default_route"]["source"] == "virtual_hub"),
        "workload_subnets_with_internet_bypass_routes": sum(1 for s in workload if s["internet_bypass_routes"]),
        "workload_subnets_with_service_endpoints": sum(1 for s in workload if s["service_endpoints"]),
        "workload_subnets_with_unrouted_internal_prefixes": sum(
            1 for s in workload if s["unrouted_internal_prefixes"]
        ),
        "workload_subnets_with_unrouted_peered_prefixes": sum(
            1 for s in workload if s["unrouted_peered_prefixes"]
        ),
        "total_route_tables": len(tables),
        "unassociated_route_tables": sum(1 for t in tables if not t["associated"]),
        "total_network_interfaces": len(nics),
        "network_interfaces_by_egress_path": _count_by(nics, "egress_path", NIC_EGRESS_PATHS),
        "network_interfaces_default_outbound_connectivity_enabled": sum(
            1 for n in nics if n["default_outbound_connectivity_enabled"]
        ),
        "total_virtual_hubs": len(hubs),
        "virtual_hub_spokes": sum(1 for v in vnets if v["virtual_hub_spoke"]),
        "virtual_hub_spokes_unresolved": sum(1 for v in vnets if v["virtual_hub_resolved"] is False),
        "total_azure_firewalls": len(firewalls),
        "azure_firewalls_by_effective_threat_intel_mode": {
            mode: sum(1 for f in firewalls if f["effective_threat_intel_mode"] == mode)
            for mode in ("Deny", "Alert", "Off")
        },
        "azure_firewalls_with_no_routed_subnet": sum(1 for f in firewalls if not f["routed_workload_subnets"]),
    }


def build_records(
    raw_vnets: list[dict], peers_by_vnet: dict, raw_tables: list[dict], raw_nics: list[dict],
    raw_firewalls: list[dict], raw_policies: list[dict], raw_hubs: list[dict] = (),
):
    tables_by_id = {arm_id_key(t["id"]): t for t in raw_tables}
    appliances = appliances_by_vnet_ip(raw_nics, raw_firewalls)
    hub_routes = hub_routes_by_vnet(raw_hubs)
    subnets = [
        subnet_record(s, v, tables_by_id, peers_by_vnet.get(arm_id_key(v["id"]), []), appliances, hub_routes)
        for v in raw_vnets
        for s in v["subnets"]
    ]
    vnets = [virtual_network_record(v, peers_by_vnet.get(arm_id_key(v["id"]), []), hub_routes) for v in raw_vnets]
    path_by_subnet = {arm_id_key(s["id"]): s["egress_path"] for s in subnets}
    nics = [network_interface_record(n, path_by_subnet) for n in raw_nics]
    tables = [route_table_record(t) for t in raw_tables]
    policies_by_id = {arm_id_key(p["id"]): p for p in raw_policies}
    firewalls = [firewall_record(f, policies_by_id, subnets) for f in raw_firewalls]
    hubs = [
        {
            "id": h["id"],
            "name": h["name"],
            "location": h["location"],
            "subscription_id": h["id"].split("/")[2],
            "resource_group": resource_group_from_id(h["id"]),
            "firewall_id": h["firewall_id"],
            "routing_policies": h["routing_policies"],
            "connections": sorted(h["connections"], key=lambda c: arm_id_key(c["remote_virtual_network_id"])),
        }
        for h in raw_hubs
    ]

    def by_id(records):
        return sorted(records, key=lambda r: arm_id_key(r.get("id")))

    return by_id(vnets), by_id(subnets), by_id(tables), by_id(nics), by_id(firewalls), by_id(hubs)


def unresolved_spokes(vnets: list[dict], peers_by_vnet: dict, hubs: list[dict]) -> dict:
    """Lower-cased VNet id -> hub name, for spoke VNets that none of `hubs` connects."""
    connected = hub_routes_by_vnet(hubs)
    spokes = {}
    for vnet in vnets:
        key = arm_id_key(vnet["id"])
        name = hub_spoke_name(peers_by_vnet.get(key, []))
        if name is not None and key not in connected:
            spokes[key] = name
    return spokes


def split_network_interfaces(nics: list[dict], exclusions: ResourceExclusions) -> tuple[list[dict], list[dict]]:
    """A NIC leaves scope when a pattern matches it or one of its subnets (and so that subnet's virtual network)."""
    kept, excluded = exclusions.split(nics, "network_interface")
    in_scope = []
    for nic in kept:
        matches = [(pattern, s) for s in nic["subnet_ids"] if exclusions and (pattern := exclusions.match(s))]
        if not matches:
            in_scope.append(nic)
            continue
        pattern, subnet_id = matches[0]
        excluded.append(excluded_item(
            "network_interface", nic["name"], pattern, "subnet_matched", id=nic["id"],
            resource_group=nic["resource_group"], location=nic["location"], matched_id=subnet_id))
    return in_scope, excluded


def split_records(exclusions: ResourceExclusions, vnets, subnets, tables, nics, firewalls, hubs) -> tuple:
    """Each collection's in-scope records, then every excluded entry; a subnet follows its virtual network's id."""
    kept, excluded = [], []
    for kind, records in zip(EXCLUSION_KINDS, (vnets, subnets, tables, nics, firewalls, hubs)):
        if kind == "network_interface":
            records, out = split_network_interfaces(records, exclusions)
        else:
            records, out = exclusions.split(records, kind)
        kept.append(records)
        excluded += out
    return (*kept, excluded)


# --- collection (lazy azure imports) ---

def new_hub_search() -> dict:
    return {
        "spokes_needing_search": 0, "max_subscriptions": None, "subscriptions_searched": [],
        "subscriptions_over_limit": 0, "spokes_found": 0, "failures": [],
    }


def _attempt(search: dict, operation: str, fn, default):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — a spoke left unfound reads virtual_hub_unresolved; this subscription's evidence is whole
        search["failures"].append({"operation": operation, "type": type(exc).__name__, "message": str(exc)})
        logger.warning("Virtual hub search: %s failed (%s: %s)", operation, type(exc).__name__, exc)
        return default


def remote_virtual_hubs(
    subscription_ids: list, network_client, unresolved: dict, search: dict, limit: int = DEFAULT_SEARCH_LIMIT
) -> list:
    """Hubs in other subscriptions that connect an unresolved spoke; each spoke found leaves `unresolved`.

    A hub found here keeps only its connections to those spokes: the rest are another subscription's network.
    """
    names = {n.lower() for n in unresolved.values()}
    search["max_subscriptions"] = limit
    search["subscriptions_over_limit"] = max(len(subscription_ids) - limit, 0)
    hubs = []
    for sub in subscription_ids[:limit]:
        if not unresolved:
            break
        search["subscriptions_searched"].append(sub)
        client = _attempt(search, f"network.NetworkManagementClient ({sub})", lambda: network_client(sub), None)
        listed = _attempt(search, f"network.virtual_hubs.list({sub})", lambda: list(client.virtual_hubs.list()), []) if client else []
        for hub in listed:
            rg, name = resource_group_from_id(model_attr(hub, "id")), model_attr(hub, "name")
            if "" not in names and (name or "").lower() not in names:
                continue
            connections = _attempt(
                search, f"network.hub_virtual_network_connections.list({name})",
                lambda: list(client.hub_virtual_network_connections.list(rg, name)), [],
            )
            connections = [
                c for c in connections
                if arm_id_key(model_attr(model_attr(c, "remote_virtual_network"), "id")) in unresolved
            ]
            if not connections:
                continue
            record = project_virtual_hub(
                hub,
                _attempt(search, f"network.routing_intent.list({name})", lambda: list(client.routing_intent.list(rg, name)), []),
                connections,
                _attempt(search, f"network.hub_route_tables.list({name})", lambda: list(client.hub_route_tables.list(rg, name)), []),
            )
            hubs.append(record)
            for key in hub_routes_by_vnet([record]):
                if unresolved.pop(key, None) is not None:
                    search["spokes_found"] += 1
    return hubs


def collect(subscription_id, cred, collector: Collector):
    """VNets, peerings, route tables, NICs, Azure Firewalls and policies, and Virtual WAN hub routing."""
    from azure.mgmt.network import NetworkManagementClient

    search = new_hub_search()
    client = collector.guard(
        "network.NetworkManagementClient (init)",
        lambda: NetworkManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        ),
    )
    if client is None:
        return ([], {}, [], [], [], [], []), search

    vnets = collector.guard(
        "network.virtual_networks.list_all",
        lambda: [project_virtual_network(v) for v in client.virtual_networks.list_all()],
        default=[],
    )
    peers_by_vnet = {}
    for vnet in vnets:
        peers_by_vnet[arm_id_key(vnet["id"])] = collector.guard(
            f"network.virtual_network_peerings.list({vnet['name']})",
            lambda vnet=vnet: [
                project_peering(p)
                for p in client.virtual_network_peerings.list(
                    resource_group_from_id(vnet["id"]), vnet["name"]
                )
            ],
            default=[],
        )
    tables = collector.guard(
        "network.route_tables.list_all",
        lambda: [project_route_table(t) for t in client.route_tables.list_all()],
        default=[],
    )
    nics = collector.guard(
        "network.network_interfaces.list_all",
        lambda: [project_network_interface(n) for n in client.network_interfaces.list_all()],
        default=[],
    )
    firewalls = collector.guard(
        "network.azure_firewalls.list_all",
        lambda: [project_firewall(f) for f in client.azure_firewalls.list_all()],
        default=[],
    )
    policies = collector.guard(
        "network.firewall_policies.list_all",
        lambda: [project_firewall_policy(p) for p in client.firewall_policies.list_all()],
        default=[],
    )
    hubs = []
    for hub in collector.guard("network.virtual_hubs.list", lambda: list(client.virtual_hubs.list()), default=[]):
        rg, name = resource_group_from_id(model_attr(hub, "id")), model_attr(hub, "name")
        hubs.append(project_virtual_hub(
            hub,
            collector.guard(f"network.routing_intent.list({name})", lambda: list(client.routing_intent.list(rg, name)), default=[]),
            collector.guard(
                f"network.hub_virtual_network_connections.list({name})",
                lambda: list(client.hub_virtual_network_connections.list(rg, name)),
                default=[],
            ),
            collector.guard(f"network.hub_route_tables.list({name})", lambda: list(client.hub_route_tables.list(rg, name)), default=[]),
        ))
    # A spoke's hub often lives in a separate connectivity subscription; look in every other one this credential sees.
    unresolved = unresolved_spokes(vnets, peers_by_vnet, hubs)
    search["spokes_needing_search"] = len(unresolved)
    if unresolved:
        others = _attempt(
            search, "subscription.subscriptions.list",
            lambda: [s for s in enabled_subscription_ids(cred) if s.lower() != subscription_id.lower()], [],
        )
        hubs += remote_virtual_hubs(
            others,
            lambda sub: NetworkManagementClient(credential=cred, subscription_id=sub, **arm_client_kwargs()),
            unresolved,
            search,
            int_config(SEARCH_LIMIT_ENV, DEFAULT_SEARCH_LIMIT),
        )
    return (vnets, peers_by_vnet, tables, nics, firewalls, policies, hubs), search


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

    raw, search = ([], {}, [], [], [], [], []), new_hub_search()
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Network")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Network is not registered on subscription %s — reporting status not_registered",
                subscription_id,
            )
        raw, search = collect(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    vnets, subnets, tables, nics, firewalls, hubs = build_records(*raw)
    # Egress paths, appliance owners and firewall routing were resolved against every record, so in-scope verdicts hold.
    exclusions = ResourceExclusions.from_env()
    exclusions.record_invalid(collector)
    vnets, subnets, tables, nics, firewalls, hubs, excluded = split_records(
        exclusions, vnets, subnets, tables, nics, firewalls, hubs
    )
    exclusions.warn_unmatched(logger)
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "virtual_networks": vnets,
            "subnets": subnets,
            "route_tables": tables,
            "network_interfaces": nics,
            "azure_firewalls": firewalls,
            "virtual_hubs": hubs,
            "virtual_hub_search": search,
            "provider_registration_status": registration,
            "excluded": excluded,
        },
        summary={
            **summarize(vnets, subnets, tables, nics, firewalls, hubs),
            "provider_registration_status": registration,
            **exclusions.summary(excluded, EXCLUSION_KINDS, {
                "virtual_networks": len(vnets), "subnets": len(subnets), "route_tables": len(tables),
                "network_interfaces": len(nics), "azure_firewalls": len(firewalls), "virtual_hubs": len(hubs)}),
        },
    )

    filename = f"azure_vnet_egress_routing_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
