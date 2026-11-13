"""Azure VNet verdict logic (egress routing, DDoS protection, east-west segmentation): pure functions, no SDK or network."""

from __future__ import annotations

import importlib.util
import ipaddress
import random
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


egress = _load("vnet_egress_routing")
ddos = _load("ddos_protection")
nsg = _load("network_security_groups")

SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
OTHER_SUB = "/subscriptions/00000000-0000-0000-0000-000000000002"
NET = f"{SUB}/resourceGroups/rg/providers/Microsoft.Network"
VNET = f"{NET}/virtualNetworks/spoke"
HUB = f"{OTHER_SUB}/resourceGroups/hub/providers/Microsoft.Network/virtualHubs/hub1"
HUB_FW = f"{OTHER_SUB}/resourceGroups/hub/providers/Microsoft.Network/azureFirewalls/fw-hub"
HV_PEER = "/subscriptions/ffffffff-0000-0000-0000-000000000000/resourceGroups/RG_hub1/providers/Microsoft.Network" \
          "/virtualNetworks/HV_hub1_1b2c3d4e-0000-1111-2222-333344445555"


# --- egress routing ---

def route(prefix, hop, *ips, name=None):
    return {"name": name or prefix, "address_prefix": prefix, "next_hop_type": hop, "next_hop_ip_addresses": list(ips)}


def table(*routes, bgp_off=False):
    return {"id": f"{NET}/routeTables/rt", "name": "rt", "location": "eastus", "disable_bgp_route_propagation": bgp_off,
            "routes": list(routes), "subnet_ids": [f"{VNET}/subnets/app"]}


def subnet(name="app", routed=True, nat=None, default_outbound=None):
    return {"id": f"{VNET}/subnets/{name}", "name": name, "address_prefixes": ["10.1.1.0/24"],
            "route_table_id": f"{NET}/routeTables/rt" if routed else None, "nat_gateway_id": nat,
            "default_outbound_access": default_outbound, "service_endpoints": [], "delegations": []}


def vnet(*subnets, nat=None):
    return {"id": VNET, "name": "spoke", "location": "eastus", "address_prefixes": ["10.1.0.0/16"],
            "default_public_nat_gateway_id": nat, "subnets": list(subnets) or [subnet()]}


def firewall(ip="10.0.0.4", policy=None, mode=None, name="fw"):
    return {"id": f"{NET}/azureFirewalls/{name}", "name": name, "location": "eastus", "sku_name": "AZFW_VNet",
            "sku_tier": "Standard", "threat_intel_mode": mode, "firewall_policy_id": policy, "virtual_hub_id": None,
            "hub_private_ip_address": None,
            "ip_configurations": [{"subnet_id": f"{VNET}/subnets/AzureFirewallSubnet", "private_ip_address": ip}]}


def nic(name, ip=None, forwarding=False, public=False, subnets=("app",)):
    return {"id": f"{NET}/networkInterfaces/{name}", "name": name, "location": "eastus", "virtual_machine_id": None,
            "enable_ip_forwarding": forwarding, "default_outbound_connectivity_enabled": None,
            "ip_configurations": [
                {"subnet_id": f"{VNET}/subnets/{s}", "private_ip_address": ip,
                 "public_ip_address_id": f"{NET}/publicIPAddresses/{name}" if public else None}
                for s in subnets
            ]}


def hub(*connections, policies=(), tables=()):
    return {"id": HUB, "name": "hub1", "location": "eastus", "firewall_id": HUB_FW,
            "routing_policies": list(policies), "connections": list(connections), "route_tables": list(tables)}


def connection(vnet_id=VNET, internet_security=True, table_id=None):
    return {"remote_virtual_network_id": vnet_id, "enable_internet_security": internet_security,
            "associated_route_table_id": table_id}


def egress_run(network=None, tables=(), peers=(), nics=(), firewalls=(), policies=(), hubs=()):
    network = network or vnet()
    vnets, subnets, route_tables, nic_records, fws, hub_records = egress.build_records(
        [network], {VNET.lower(): list(peers)}, list(tables), list(nics), list(firewalls), list(policies), list(hubs)
    )
    return {
        "vnet": vnets[0],
        "subnets": {s["name"]: s for s in subnets},
        "tables": route_tables,
        "nics": {n["name"]: n for n in nic_records},
        "firewalls": fws,
        "summary": egress.summarize(vnets, subnets, route_tables, nic_records, fws, hub_records),
    }


@pytest.mark.parametrize("sub, network, default, path", [
    ({"name": "GatewaySubnet"}, {}, route("0.0.0.0/0", "VirtualAppliance"), "platform_managed"),
    ({"name": "app"}, {}, route("0.0.0.0/0", "VirtualAppliance", "10.0.0.4"), "appliance"),
    ({"name": "app"}, {}, route("0.0.0.0/0", "VirtualApplianceEcmp", "10.0.0.4"), "appliance"),
    ({"name": "app"}, {}, route("0.0.0.0/0", "None"), "blackhole"),
    ({"name": "app"}, {}, route("0.0.0.0/0", "VirtualNetworkGateway"), "gateway"),
    ({"name": "app"}, {}, route("0.0.0.0/0", "VnetLocal"), "other"),
    ({"name": "app", "nat_gateway_id": "nat"}, {}, None, "nat_gateway"),
    ({"name": "app"}, {"default_public_nat_gateway_id": "nat"}, None, "nat_gateway"),
    ({"name": "app", "default_outbound_access": None}, {}, None, "default_outbound"),
    ({"name": "app", "default_outbound_access": True}, {}, route("0.0.0.0/0", "Internet"), "default_outbound"),
    ({"name": "app", "default_outbound_access": False}, {}, None, "none"),
])
def test_subnet_egress_path(sub, network, default, path):
    assert egress.subnet_egress_path(sub, network, default) == path


@pytest.mark.parametrize("routes, hop, ips, prefixes", [
    ([route("0.0.0.0/0", "VirtualAppliance", "10.0.0.4")], "VirtualAppliance", ["10.0.0.4"], ["0.0.0.0/0"]),
    ([route("0.0.0.0/1", "VirtualAppliance", "10.0.0.4"), route("128.0.0.0/1", "VirtualAppliance", "10.0.0.4")],
     "VirtualAppliance", ["10.0.0.4"], ["0.0.0.0/1", "128.0.0.0/1"]),
    # The halves are more specific than an exact 0.0.0.0/0, so they win over it.
    ([route("0.0.0.0/0", "Internet"), route("128.0.0.0/1", "VirtualAppliance", "10.0.0.5"),
      route("0.0.0.0/1", "VirtualAppliance", "10.0.0.4"), route("10.0.0.0/8", "VirtualAppliance", "10.0.0.9")],
     "VirtualAppliance", ["10.0.0.4", "10.0.0.5"], ["0.0.0.0/1", "128.0.0.0/1"]),
    ([route("0.0.0.0/1", "VirtualAppliance", "10.0.0.4"), route("128.0.0.0/1", "VirtualApplianceEcmp", "10.0.0.5")],
     "VirtualAppliance", ["10.0.0.4", "10.0.0.5"], ["0.0.0.0/1", "128.0.0.0/1"]),
    ([route("0.0.0.0/1", "None"), route("128.0.0.0/2", "None"), route("192.0.0.0/2", "None")],
     "None", [], ["0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"]),
])
def test_default_route_exact_or_split(routes, hop, ips, prefixes):
    found = egress.default_route(routes)
    assert (found["next_hop_type"], found["next_hop_ip_addresses"], found["address_prefixes"]) == (hop, ips, prefixes)


@pytest.mark.parametrize("routes", [
    [],
    [route("0.0.0.0/1", "VirtualAppliance", "10.0.0.4")],
    [route("0.0.0.0/1", "VirtualAppliance", "10.0.0.4"), route("128.0.0.0/1", "None")],
    [route("::/1", "VirtualAppliance", "fd00::4"), route("8000::/1", "VirtualAppliance", "fd00::4")],
    [route("AzureCloud", "VirtualAppliance", "10.0.0.4")],
])
def test_no_default_route(routes):
    assert egress.default_route(routes) is None


def test_split_default_route_reaches_the_firewall():
    rt = table(route("0.0.0.0/1", "VirtualAppliance", "10.0.0.4"), route("128.0.0.0/1", "VirtualAppliance", "10.0.0.4"))
    run = egress_run(tables=[rt], firewalls=[firewall()])
    app = run["subnets"]["app"]
    assert app["egress_path"] == "appliance" and app["appliance_owner"] == "azure_firewall"
    assert app["default_route"]["source"] == "user_defined"
    assert app["default_route"]["user_defined_prefixes"] == ["0.0.0.0/1", "128.0.0.0/1"]
    assert run["tables"][0]["default_route_next_hop_type"] == "VirtualAppliance"
    assert run["firewalls"][0]["routed_workload_subnets"] == 1


def test_internet_routes_on_an_appliance_subnet_are_bypasses():
    rt = table(route("0.0.0.0/0", "VirtualAppliance", "10.0.0.4"), route("20.0.0.0/8", "Internet"),
               route("AzureCloud", "Internet"), route("10.2.0.0/16", "VnetLocal"))
    run = egress_run(tables=[rt], firewalls=[firewall()])
    assert run["subnets"]["app"]["internet_bypass_routes"] == [
        {"name": "20.0.0.0/8", "address_prefix": "20.0.0.0/8"}, {"name": "AzureCloud", "address_prefix": "AzureCloud"}]
    assert run["summary"]["workload_subnets_with_internet_bypass_routes"] == 1


@pytest.mark.parametrize("routes, bypasses", [
    ([route("0.0.0.0/0", "VirtualNetworkGateway"), route("AzureCloud", "Internet")], 1),
    ([route("0.0.0.0/1", "VirtualAppliance", "10.0.0.4"), route("128.0.0.0/1", "VirtualAppliance", "10.0.0.4"),
      route("128.0.0.0/2", "Internet")], 1),
    ([route("0.0.0.0/0", "Internet"), route("20.0.0.0/8", "Internet")], 0),
    ([route("20.0.0.0/8", "Internet")], 0),
])
def test_internet_bypass_only_counts_against_a_non_internet_default(routes, bypasses):
    assert len(egress_run(tables=[table(*routes)])["subnets"]["app"]["internet_bypass_routes"]) == bypasses


def test_internet_route_bypasses_a_virtual_hub_default():
    run = egress_run(tables=[table(route("AzureCloud", "Internet"))],
                     hubs=[hub(connection(), policies=[{"destinations": ["Internet"], "next_hop": HUB_FW}])])
    app = run["subnets"]["app"]
    assert app["default_route"]["source"] == "virtual_hub"
    assert app["internet_bypass_routes"] == [{"name": "AzureCloud", "address_prefix": "AzureCloud"}]


@pytest.mark.parametrize("prefix, routes, forced", [
    ("10.1.0.0/16", [route("10.1.0.0/16", "VirtualAppliance")], True),
    ("10.1.0.0/16", [route("10.1.0.0/17", "VirtualAppliance"), route("10.1.128.0/17", "VirtualApplianceEcmp")], True),
    ("10.1.0.0/16", [route("10.1.0.0/17", "VirtualAppliance")], False),
    ("10.1.0.0/16", [route("10.0.0.0/8", "VirtualAppliance")], False),
    ("10.1.0.0/16", [route("10.1.0.0/16", "VirtualAppliance"), route("10.1.5.0/24", "Internet")], False),
    ("AzureCloud", [route("0.0.0.0/0", "VirtualAppliance")], False),
])
def test_forced_through_appliance(prefix, routes, forced):
    assert egress.forced_through_appliance(prefix, routes) is forced


FW_OWNER = {"kind": "azure_firewall", "id": "fw"}
FWD_NIC = {"kind": "nic", "id": "n1", "enable_ip_forwarding": True}
PLAIN_NIC = {"kind": "nic", "id": "n2", "enable_ip_forwarding": False}


@pytest.mark.parametrize("ips, owners, verdict", [
    ([], {}, "unknown"),
    (["10.0.0.4"], {"10.0.0.4": None}, "not_in_subscription"),
    (["10.0.0.4"], {"10.0.0.4": FW_OWNER}, "azure_firewall"),
    (["10.0.0.4"], {"10.0.0.4": FWD_NIC}, "nic_ip_forwarding"),
    (["10.0.0.4"], {"10.0.0.4": PLAIN_NIC}, "nic_no_ip_forwarding"),
    (["a", "b"], {"a": FW_OWNER, "b": FWD_NIC}, "mixed"),
    (["a", "b"], {"a": FW_OWNER, "b": PLAIN_NIC}, "nic_no_ip_forwarding"),
])
def test_appliance_owner(ips, owners, verdict):
    assert egress.appliance_owner(ips, owners) == verdict


def test_appliance_owner_is_found_in_a_connected_peer():
    peer_nic = nic("nva", ip="10.9.0.4", forwarding=True, subnets=())
    peer_nic["ip_configurations"] = [{"subnet_id": f"{NET}/virtualNetworks/hubnet/subnets/nva",
                                      "private_ip_address": "10.9.0.4", "public_ip_address_id": None}]
    peers = [{"name": "to-hub", "peering_state": "Connected", "remote_virtual_network_id": f"{NET}/virtualNetworks/hubnet",
              "remote_address_prefixes": ["10.9.0.0/16"]}]
    run = egress_run(tables=[table(route("0.0.0.0/0", "VirtualAppliance", "10.9.0.4"))], peers=peers, nics=[peer_nic])
    app = run["subnets"]["app"]
    assert app["appliance_owner"] == "nic_ip_forwarding"
    assert app["unrouted_peered_prefixes"] == ["10.9.0.0/16"]


INTERNET_TO_FW = {"destinations": ["Internet"], "next_hop": HUB_FW}
PRIVATE_TO_FW = {"destinations": ["PrivateTraffic"], "next_hop": HUB_FW}
NVA = f"{OTHER_SUB}/resourceGroups/hub/providers/Microsoft.Network/virtualHubs/hub1/hubVirtualNetworkConnections/nva"


def hub_table(name, *routes):
    return {"id": f"{HUB}/hubRouteTables/{name}", "routes": [
        {"destinations": [d], "next_hop_type": "ResourceId", "next_hop": hop} for d, hop in routes]}


@pytest.mark.parametrize("h, internet, private", [
    (hub(connection(), policies=[INTERNET_TO_FW, PRIVATE_TO_FW]), HUB_FW, HUB_FW),
    (hub(connection(), policies=[PRIVATE_TO_FW]), None, HUB_FW),
    (hub(connection(table_id=f"{HUB}/hubRouteTables/custom"),
         tables=[hub_table("custom", ("0.0.0.0/0", NVA)), hub_table("defaultRouteTable")]), NVA, None),
    (hub(connection(), tables=[hub_table("defaultRouteTable", ("0.0.0.0/0", HUB_FW))]), HUB_FW, None),
    (hub(connection(internet_security=False), policies=[INTERNET_TO_FW]), None, None),
])
def test_hub_routes_by_vnet(h, internet, private):
    routes = egress.hub_routes_by_vnet([h])[VNET.lower()]
    assert (routes["virtual_hub_id"], routes["internet_next_hop"], routes["private_next_hop"]) == (HUB, internet, private)


def test_virtual_hub_default_reaches_the_spoke():
    run = egress_run(network=vnet(subnet(routed=False), subnet("nat", routed=False, nat="nat")),
                     hubs=[hub(connection(), policies=[INTERNET_TO_FW])])
    for name in ("app", "nat"):
        s = run["subnets"][name]
        assert s["egress_path"] == "appliance" and s["appliance_owner"] == "azure_firewall"
        assert s["default_route"]["next_hop_resource_id"] == HUB_FW
        assert s["appliance_firewall_ids"] == [HUB_FW]
    assert run["vnet"]["virtual_hub_resolved"] is True
    assert run["summary"]["workload_subnets_via_virtual_hub"] == 2


@pytest.mark.parametrize("rt, path, source", [
    (table(bgp_off=True), "default_outbound", "system"),
    (table(route("0.0.0.0/0", "Internet")), "default_outbound", "user_defined"),
    (table(route("0.0.0.0/0", "VirtualAppliance", "10.0.0.4")), "appliance", "user_defined"),
])
def test_virtual_hub_default_loses_to_the_subnet_route_table(rt, path, source):
    run = egress_run(tables=[rt], firewalls=[firewall()], hubs=[hub(connection(), policies=[INTERNET_TO_FW])])
    app = run["subnets"]["app"]
    assert (app["egress_path"], app["default_route"]["source"]) == (path, source)


def test_hub_appliance_that_is_not_a_firewall():
    run = egress_run(hubs=[hub(connection(), policies=[{"destinations": ["Internet"], "next_hop": NVA}])])
    assert run["subnets"]["app"]["appliance_owner"] == "hub_appliance"


def test_spoke_without_its_hub_is_unresolved_not_default_outbound():
    peers = [{"name": "RemoteVnetToHubPeering_1b2c", "peering_state": "Connected", "remote_virtual_network_id": HV_PEER,
              "remote_address_prefixes": ["10.100.0.0/23"]}]
    run = egress_run(network=vnet(subnet(routed=False)), peers=peers)
    app = run["subnets"]["app"]
    assert app["egress_path"] == "virtual_hub_unresolved"
    assert app["default_route"]["source"] == "virtual_hub_unresolved"
    assert (run["vnet"]["virtual_hub_spoke"], run["vnet"]["virtual_hub_resolved"]) == (True, False)
    assert run["vnet"]["virtual_hub_name"] == "hub1"
    assert run["summary"]["virtual_hub_spokes_unresolved"] == 1


@pytest.mark.parametrize("peers, name", [
    ([{"name": "RemoteVnetToHubPeering_1b2c", "remote_virtual_network_id": HV_PEER}], "hub1"),
    ([{"name": "RemoteVnetToHubPeering_1b2c", "remote_virtual_network_id": None}], ""),
    ([{"name": "to-hub", "remote_virtual_network_id": f"{NET}/virtualNetworks/hubnet"}], None),
    ([], None),
])
def test_hub_spoke_name(peers, name):
    assert egress.hub_spoke_name(peers) == name


def test_nic_public_ip_overrides_default_outbound_only():
    rt = table(route("0.0.0.0/0", "VirtualAppliance", "10.0.0.4"))
    run = egress_run(network=vnet(subnet(), subnet("web", routed=False)), tables=[rt], firewalls=[firewall()],
                     nics=[nic("vm-web", public=True, subnets=("web",)), nic("vm-app", public=True),
                           nic("vm-both", subnets=("app", "web"))])
    assert run["nics"]["vm-web"]["egress_path"] == "public_ip"
    assert run["nics"]["vm-app"]["egress_path"] == "appliance"
    assert run["nics"]["vm-both"]["egress_path"] == "mixed"


def policy(name, mode, base=None):
    return {"id": f"{NET}/firewallPolicies/{name}", "name": name, "sku_tier": "Standard", "threat_intel_mode": mode,
            "intrusion_detection_mode": None, "base_policy_id": f"{NET}/firewallPolicies/{base}" if base else None}


@pytest.mark.parametrize("policies, mode, resolved", [
    ([policy("child", "Alert", "base"), policy("base", "Deny")], "Deny", True),
    ([policy("child", "Deny", "base"), policy("base", "Alert")], "Deny", True),
    ([policy("child", "Off", "base"), policy("base", "Alert")], "Alert", True),
    ([policy("child", "Deny", "base")], "Deny", False),
    ([policy("child", "Alert", "base")], None, False),
    ([policy("child", "Alert", "base"), policy("base", "Alert", "child")], "Alert", True),
    ([], None, False),
])
def test_threat_intel_mode_follows_the_base_policy(policies, mode, resolved):
    fw = firewall(policy=f"{NET}/firewallPolicies/child", mode="Off")
    record = egress_run(firewalls=[fw], policies=policies)["firewalls"][0]
    assert (record["effective_threat_intel_mode"], record["firewall_policy_resolved"]) == (mode, resolved)


def test_firewall_without_policy_uses_its_own_mode():
    record = egress_run(firewalls=[firewall(mode="Alert")])["firewalls"][0]
    assert (record["effective_threat_intel_mode"], record["firewall_policy_resolved"]) == ("Alert", None)


class FakeNetwork:
    def __init__(self, hubs):
        self.virtual_hubs = NS(list=lambda: [h for h, _ in hubs])
        conns = {h.name: c for h, c in hubs}
        self.hub_virtual_network_connections = NS(list=lambda rg, name: conns[name])
        self.routing_intent = NS(list=lambda rg, name: [NS(routing_policies=[NS(destinations=["Internet"], next_hop=HUB_FW)])])
        self.hub_route_tables = NS(list=lambda rg, name: [])


def fake_hub(name, *vnet_ids):
    h = NS(id=f"{OTHER_SUB}/resourceGroups/hub/providers/Microsoft.Network/virtualHubs/{name}", name=name,
           location="eastus", azure_firewall=NS(id=HUB_FW))
    return h, [NS(remote_virtual_network=NS(id=v), enable_internet_security=True, routing_configuration=None)
               for v in vnet_ids]


def test_remote_hub_search_keeps_only_this_subscriptions_spokes():
    elsewhere = "/subscriptions/00000000-0000-0000-0000-000000000003/resourceGroups/x/providers/Microsoft.Network" \
                "/virtualNetworks/theirs"
    clients = {
        "a": FakeNetwork([fake_hub("other", elsewhere)]),
        "b": FakeNetwork([fake_hub("hub1", VNET.upper(), elsewhere)]),
        "c": FakeNetwork([]),
    }

    def client(sub):
        if sub == "broken":
            raise PermissionError("no access")
        return clients[sub]

    unresolved, search = {VNET.lower(): "hub1"}, egress.new_hub_search()
    hubs = egress.remote_virtual_hubs(["broken", "a", "b", "c"], client, unresolved, search)
    assert [c["remote_virtual_network_id"] for c in hubs[0]["connections"]] == [VNET.upper()]
    assert hubs[0]["routing_policies"] == [{"destinations": ["Internet"], "next_hop": HUB_FW}]
    assert unresolved == {}
    assert search["subscriptions_searched"] == ["broken", "a", "b"]
    assert search["spokes_found"] == 1
    assert [f["type"] for f in search["failures"]] == ["PermissionError"]


def test_remote_hub_search_stops_at_the_limit():
    unresolved, search = {VNET.lower(): "hub1"}, egress.new_hub_search()
    clients = {s: FakeNetwork([]) for s in "abc"}
    clients["c"] = FakeNetwork([fake_hub("hub1", VNET)])
    assert egress.remote_virtual_hubs(["a", "b", "c"], clients.get, unresolved, search, limit=2) == []
    assert search["subscriptions_searched"] == ["a", "b"]
    assert (search["max_subscriptions"], search["subscriptions_over_limit"]) == (2, 1)
    assert unresolved == {VNET.lower(): "hub1"}


# --- DDoS protection ---

PLAN = f"{NET}/ddosProtectionPlans/plan"
PROTECTED = f"{NET}/virtualNetworks/protected"
BARE = f"{NET}/virtualNetworks/bare"


def ddos_vnet(vid, plan=True, configs=()):
    return {"id": vid, "name": vid.rsplit("/", 1)[1], "location": "eastus", "enable_ddos_protection": plan,
            "ddos_protection_plan_id": PLAN if plan else None, "subnet_ip_configuration_ids": list(configs)}


def public_ip(name, config=None, nat=None, mode=None):
    return {"id": f"{NET}/publicIPAddresses/{name}", "name": name, "location": "eastus", "ip_address": "20.0.0.1",
            "sku_name": "Standard", "sku_tier": "Regional", "ip_configuration_id": config, "nat_gateway_id": nat,
            "protection_mode": mode, "ddos_protection_plan_id": None}


GATEWAY_CONFIG = f"{NET}/virtualNetworkGateways/vpn/ipConfigurations/default"
APPGW_CONFIG = f"{NET}/applicationGateways/agw/gatewayIPConfigurations/gw"
NIC_CONFIG = f"{NET}/networkInterfaces/vm1/ipConfigurations/ipconfig1"
VMSS_CONFIG = f"{SUB}/resourceGroups/mc/providers/Microsoft.Compute/virtualMachineScaleSets/aks/virtualMachines/0" \
              "/networkInterfaces/aks-nic/ipConfigurations/ipconfig1"
LB = f"{NET}/loadBalancers/kubernetes"


def lb(name="kubernetes", configs=(), vnets=()):
    return {"id": f"{NET}/loadBalancers/{name}", "backend_ip_configuration_ids": list(configs),
            "backend_virtual_network_ids": list(vnets)}


@pytest.mark.parametrize("ip, attached, network, protection", [
    ({"protection_mode": "Enabled"}, "network_interface", None, "ip_protection"),
    ({"protection_mode": "Disabled"}, "network_interface", ddos_vnet(PROTECTED), "disabled"),
    ({}, "unattached", None, "none"),
    ({"protection_mode": "Enabled"}, "nat_gateway", None, "not_supported"),
    ({}, "load_balancer", None, "unknown"),
    ({"protection_mode": "VirtualNetworkInherited"}, "network_interface", ddos_vnet(PROTECTED), "network_protection"),
    ({}, "network_interface", ddos_vnet(BARE, plan=False), "none"),
    ({}, "network_interface", {**ddos_vnet(PROTECTED), "enable_ddos_protection": False}, "none"),
])
def test_effective_protection(ip, attached, network, protection):
    assert ddos.effective_protection(ip, attached, network) == protection


@pytest.mark.parametrize("resource, configs, nics, lbs, found", [
    (f"{NET}/virtualNetworkGateways/vpn", [GATEWAY_CONFIG], [], [], PROTECTED),
    (f"{NET}/applicationGateways/agw", [APPGW_CONFIG], [], [], PROTECTED),
    (f"{NET}/networkInterfaces/vm1", [], [{"id": f"{NET}/networkInterfaces/vm1", "subnet_ids": [f"{PROTECTED}/subnets/a"]}],
     [], PROTECTED),
    (LB, [VMSS_CONFIG], [], [lb(configs=[VMSS_CONFIG.upper()])], PROTECTED),
    (LB, [], [{"id": f"{NET}/networkInterfaces/vm1", "subnet_ids": [f"{PROTECTED}/subnets/a"]}],
     [lb(configs=[NIC_CONFIG])], PROTECTED),
    (LB, [], [], [lb(vnets=[PROTECTED, PROTECTED.upper()])], PROTECTED),
    (LB, [VMSS_CONFIG], [], [lb(configs=[VMSS_CONFIG], vnets=[BARE])], None),
    (LB, [], [], [lb(configs=[NIC_CONFIG])], None),
    (LB, [], [], [lb()], None),
])
def test_vnet_by_resource(resource, configs, nics, lbs, found):
    index = ddos.vnet_by_resource([ddos_vnet(PROTECTED, configs=configs), ddos_vnet(BARE, plan=False)], nics, lbs)
    assert index.get(resource.lower()) == (found.lower() if found else None)


def test_load_balancer_and_nat_gateway_ips_end_to_end():
    vnets = [ddos_vnet(PROTECTED, configs=[VMSS_CONFIG]), ddos_vnet(BARE, plan=False, configs=[NIC_CONFIG])]
    ips = [public_ip("lb", config=f"{LB}/frontendIPConfigurations/fe"), public_ip("nat", nat=f"{NET}/natGateways/nat"),
           public_ip("vm", config=NIC_CONFIG), public_ip("spare")]
    plans = [{"id": PLAN, "name": "plan", "location": "eastus", "virtual_network_ids": [PROTECTED], "public_ip_address_ids": []}]
    _, vnet_records, ip_records = ddos.build_records(plans, vnets, ips, [], [lb(configs=[VMSS_CONFIG])])
    by_name = {i["name"]: i for i in ip_records}
    assert by_name["lb"]["effective_protection"] == "network_protection"
    assert by_name["lb"]["virtual_network_id"] == PROTECTED
    assert by_name["nat"]["effective_protection"] == "not_supported"
    assert by_name["vm"]["effective_protection"] == "none"
    summary = ddos.summarize(plans, vnet_records, ip_records)
    assert summary["attached_public_ips_by_effective_protection"] == {
        "network_protection": 1, "ip_protection": 0, "none": 1, "disabled": 0, "not_supported": 1, "unknown": 0}
    assert summary["attached_public_ips_unprotected"] == 1
    assert summary["virtual_networks_with_attached_public_ips_without_plan"] == 1


# --- east-west segmentation ---

WEB, APP, DATA = "10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"
SUBNETS = {"web": WEB, "app": APP, "data": DATA}


def rule(priority, direction, access, src="*", dst="*", ports="*", protocol="*", src_asg=None):
    many_src, many_dst, many_ports = (isinstance(v, list) for v in (src, dst, ports))
    return {
        "name": f"r{priority}{direction[0]}", "priority": priority, "direction": direction, "access": access,
        "protocol": protocol,
        "source_address_prefix": None if many_src or src_asg else src, "source_address_prefixes": src if many_src else [],
        "destination_address_prefix": None if many_dst else dst, "destination_address_prefixes": dst if many_dst else [],
        "destination_port_range": None if many_ports else ports, "destination_port_ranges": ports if many_ports else [],
        "source_application_security_group_ids": [f"{NET}/applicationSecurityGroups/{src_asg}"] if src_asg else [],
    }


DEFAULTS = [
    rule(65000, "Inbound", "Allow", "VirtualNetwork", "VirtualNetwork"),
    rule(65001, "Inbound", "Allow", "AzureLoadBalancer", "*"),
    rule(65500, "Inbound", "Deny"),
    rule(65000, "Outbound", "Allow", "VirtualNetwork", "VirtualNetwork"),
    rule(65001, "Outbound", "Allow", "*", "Internet"),
    rule(65500, "Outbound", "Deny"),
]


def security_group(name, *rules):
    return nsg.security_group_record({"id": f"{NET}/networkSecurityGroups/{name}", "name": name, "location": "eastus",
                                      "security_rules": list(rules), "default_security_rules": DEFAULTS})


def ew_subnet(name, prefix, group=None, nsg_id=None):
    return {"id": f"{VNET}/subnets/{name}", "name": name, "address_prefixes": [prefix],
            "nsg_id": nsg_id or (f"{NET}/networkSecurityGroups/{group}" if group else None)}


def east_west(subnets, groups):
    vnets = [nsg.virtual_network_record({"id": VNET, "name": "spoke", "location": "eastus", "subnets": subnets})]
    out = nsg.with_east_west(vnets, groups)
    return {s["name"]: s for s in out[0]["subnets"]}, nsg.summarize(groups, out, [])


def test_default_rules_leave_every_tier_open():
    subnets, summary = east_west([ew_subnet(n, p, "shared") for n, p in SUBNETS.items()], [security_group("shared")])
    assert {n: s["east_west_segmentation"] for n, s in subnets.items()} == dict.fromkeys(SUBNETS, "unsegmented")
    assert summary["east_west_subnet_pairs"] == summary["open_east_west_subnet_pairs"] == 6


def test_tiered_rules_segment_app_and_data():
    groups = [
        security_group("web"),
        security_group("app", rule(100, "Inbound", "Allow", WEB, APP, "8080", "Tcp"),
                       rule(4000, "Inbound", "Deny", "VirtualNetwork", "*")),
        security_group("data", rule(100, "Inbound", "Allow", APP, DATA, "1433", "Tcp"), rule(4096, "Inbound", "Deny")),
    ]
    subnets, summary = east_west([ew_subnet(n, p, n) for n, p in SUBNETS.items()], groups)
    assert subnets["app"]["segmented_from_subnets"] == ["data", "web"]
    assert subnets["data"]["east_west_segmentation"] == "segmented"
    assert subnets["web"]["east_west_segmentation"] == "unsegmented"
    assert summary["workload_subnets_by_east_west_segmentation"] == {
        "segmented": 2, "partial": 0, "unsegmented": 1, "undetermined": 0, "no_peer_subnets": 0}


def test_all_port_allow_from_one_tier_is_partial():
    data = security_group("data", rule(100, "Inbound", "Allow", APP, "*"), rule(4096, "Inbound", "Deny"))
    subnets, _ = east_west([ew_subnet("web", WEB), ew_subnet("app", APP), ew_subnet("data", DATA, "data")], [data])
    assert subnets["data"]["east_west_segmentation"] == "partial"
    assert (subnets["data"]["open_from_subnets"], subnets["data"]["segmented_from_subnets"]) == (["app"], ["web"])


def test_outbound_deny_on_the_source_segments_the_pair():
    web = security_group("web", rule(100, "Outbound", "Deny", "*", DATA))
    subnets, _ = east_west([ew_subnet("web", WEB, "web"), ew_subnet("data", DATA)], [web])
    assert subnets["data"]["segmented_from_subnets"] == ["web"]
    assert subnets["web"]["open_from_subnets"] == ["data"]


@pytest.mark.parametrize("deny, segmented", [
    (rule(100, "Inbound", "Deny", ports=["0-1023", "1024-65535"]), True),
    (rule(100, "Inbound", "Deny", ports="1-65535"), True),
    (rule(100, "Inbound", "Deny", ports=["0-1023", "1025-65535"]), False),
    (rule(100, "Inbound", "Deny", ports="22"), False),
    (rule(100, "Inbound", "Deny", "10.1.1.0/25"), False),
    (rule(100, "Inbound", "Deny", ["10.1.1.0/25", "10.1.1.128/25"]), True),
    (rule(100, "Inbound", "Deny", protocol="Tcp"), False),
])
def test_what_counts_as_a_full_deny(deny, segmented):
    subnets, _ = east_west([ew_subnet("web", WEB), ew_subnet("data", DATA, "data")], [security_group("data", deny)])
    assert subnets["data"]["segmented_from_subnets" if segmented else "open_from_subnets"] == ["web"]


@pytest.mark.parametrize("ports, covered", [
    (["*"], True), (["0-65535"], True), (["1-65535"], True), (["0-1023", "1024-65535"], True),
    (["1024-65535", "0-1023"], True), (["0-100", "50-65535"], True), (["0-1023", "1025-65535"], False),
    (["2-65535"], False), (["22"], False), ([None], False), (["junk"], False), ([], False),
])
def test_covers_all_ports(ports, covered):
    assert nsg.covers_all_ports(ports) is covered


@pytest.mark.parametrize("rule_prefixes, coverage", [
    (["VirtualNetwork"], "full"), (["10.1.0.0/16"], "full"), (["10.1.1.0/25"], "partial"),
    (["10.2.0.0/16", "Internet", "AzureLoadBalancer"], "none"), (["10.1.1.0/25", "10.1.1.128/25"], "full"),
    (["fd00::/8"], "none"), (["10.1.1.4"], "partial"),
])
def test_prefix_coverage(rule_prefixes, coverage):
    assert nsg.prefix_coverage(rule_prefixes, [WEB]) == coverage


def test_asg_allow_and_unreadable_nsg_are_undetermined():
    data = security_group("data", rule(100, "Inbound", "Allow", src_asg="asg-app"), rule(4096, "Inbound", "Deny"))
    far = f"{OTHER_SUB}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/far"
    subnets, summary = east_west(
        [ew_subnet("app", APP), ew_subnet("data", DATA, "data"), ew_subnet("far", "10.1.9.0/24", nsg_id=far)], [data])
    assert subnets["data"]["undetermined_from_subnets"] == ["app", "far"]
    assert subnets["far"]["east_west_segmentation"] == "undetermined"
    assert summary["workload_subnets_by_east_west_segmentation"]["undetermined"] == 2


def test_platform_subnets_are_left_out_and_a_lone_subnet_has_no_peers():
    subnets, _ = east_west([ew_subnet("app", APP), ew_subnet("AzureBastionSubnet", "10.1.4.0/26")], [])
    assert subnets["app"]["east_west_segmentation"] == "no_peer_subnets"
    assert subnets["AzureBastionSubnet"]["east_west_segmentation"] is None


# An independent packet-level check: first-match evaluation of each NSG for sampled addresses on one TCP port that no
# narrower generated rule names, so it sees exactly what the fetcher's all-port reasoning should.
PROBE_PORT = 47123


def _holds(values, ip):
    for value in values:
        if value in ("*", "VirtualNetwork"):
            return True
        try:
            if ip in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            pass
    return False


def _port_matches(r, port):
    for value in [r["destination_port_range"], *r["destination_port_ranges"]]:
        if value == "*":
            return True
        if value:
            low, _, high = value.partition("-")
            if int(low) <= port <= int(high or low):
                return True
    return False


def packet_allowed(group, direction, src, dst):
    if group is None:
        return True
    rules = sorted((r for r in group["security_rules"] + group["default_security_rules"] if r["direction"] == direction),
                   key=lambda r: r["priority"])
    for r in rules:
        if (r["protocol"] in ("*", "Tcp") and _port_matches(r, PROBE_PORT)
                and _holds([r["source_address_prefix"], *r["source_address_prefixes"]], src)
                and _holds([r["destination_address_prefix"], *r["destination_address_prefixes"]], dst)):
            return r["access"] == "Allow"
    return False


def samples(prefix):
    net = ipaddress.ip_network(prefix)
    return [net.network_address + i for i in (4, 7, 132, 250)]


WHOLE_PREFIXES = ["*", "VirtualNetwork", "10.1.0.0/16", "Internet", "AzureLoadBalancer", WEB, APP, DATA, [WEB, APP],
                  [APP, DATA]]
PART_PREFIXES = ["10.1.1.0/25", "10.1.2.128/25", "10.1.3.7", ["10.1.1.0/25", "10.1.3.0/25"]]
PORTS = ["*", "0-65535", "1-65535", "22", "1433", "8080-8090", "0-1023", ["0-1023", "1024-65535"],
         ["1-1023", "1024-65535"]]


def random_group(rng, name, partial):
    rules = []
    for priority in rng.sample(range(100, 4097), rng.randint(0, 5)):
        access = rng.choice(["Allow", "Deny"])
        prefixes = WHOLE_PREFIXES + (PART_PREFIXES if partial else [])
        protocols = (["*", "Tcp", "Udp"] if access == "Allow" or partial else ["*", "Udp"])
        rules.append(rule(priority, rng.choice(["Inbound", "Outbound"]), access, rng.choice(prefixes),
                          rng.choice(prefixes), rng.choice(PORTS), rng.choice(protocols)))
    return security_group(name, *rules)


def simulate(rng, partial):
    groups = {n: random_group(rng, n, partial) for n in SUBNETS if rng.random() < 0.8}
    subnets, _ = east_west([ew_subnet(n, p, n if n in groups else None) for n, p in SUBNETS.items()], list(groups.values()))
    for dst_name, dst in subnets.items():
        for src_name in SUBNETS:
            if src_name == dst_name:
                continue
            flows = [
                packet_allowed(groups.get(src_name), "Outbound", a, b) and packet_allowed(groups.get(dst_name), "Inbound", a, b)
                for a in samples(SUBNETS[src_name]) for b in samples(SUBNETS[dst_name])
            ]
            yield dst, src_name, flows


@pytest.mark.parametrize("seed", range(40))
def test_east_west_matches_a_packet_simulator_on_whole_subnet_rules(seed):
    rng = random.Random(seed)
    for _ in range(10):
        for dst, src_name, flows in simulate(rng, partial=False):
            expected = "open" if all(flows) else "segmented" if not any(flows) else "mixed"
            assert expected != "mixed"
            assert src_name in dst[f"{expected}_from_subnets"], (seed, dst["name"], src_name, expected)


@pytest.mark.parametrize("seed", range(40))
def test_segmented_is_never_claimed_when_a_packet_gets_through(seed):
    rng = random.Random(1000 + seed)
    for _ in range(10):
        for dst, src_name, flows in simulate(rng, partial=True):
            if src_name in dst["segmented_from_subnets"]:
                assert not any(flows), (seed, dst["name"], src_name)
