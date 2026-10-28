"""resource_exclusions in the Azure network fetchers: excluded resources leave every count and stay listed under excluded."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
IN_RG = f"{SUB}/resourceGroups/rg-in"
OUT_RG = f"{SUB}/resourceGroups/rg-out"
NET_IN = f"{IN_RG}/providers/Microsoft.Network"
NET_OUT = f"{OUT_RG}/providers/Microsoft.Network"
EXCLUSION_FIELDS = ("resource_exclusion_patterns", "resource_exclusion_patterns_unmatched")


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_exclusions_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nsg = _load("network_security_groups")
pe = _load("private_endpoint_configuration")
dns = _load("private_dns_zone_configuration")
egress = _load("vnet_egress_routing")


def _run(m, monkeypatch, tmp_path, patterns, filename):
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)
    code = m.main()
    return code, json.loads((tmp_path / f"{filename}_s1.json").read_text())


def _added_fields(kinds: dict) -> dict:
    """The fields a run without patterns adds to the summary: kind -> in-scope total."""
    return {
        "resource_exclusion_patterns": [],
        "resource_exclusion_patterns_unmatched": [],
        **{f"excluded_{kind}s": 0 for kind in kinds},
        **{f"in_scope_{kind}s": total for kind, total in kinds.items()},
    }


def _excluded(evidence) -> list:
    return sorted((e["kind"], e["name"], e["pattern"], e["reason"]) for e in evidence["results"]["excluded"])


# --- network_security_groups ---

def _nsg_records():
    groups = [
        nsg.security_group_record({"id": f"{NET_IN}/networkSecurityGroups/nsg-in", "name": "nsg-in",
                                   "location": "regionwest", "security_rules": [], "default_security_rules": []}),
        nsg.security_group_record({"id": f"{NET_OUT}/networkSecurityGroups/nsg-out", "name": "nsg-out",
                                   "location": "regionwest", "security_rules": [], "default_security_rules": []}),
        nsg.security_group_record({"id": f"{NET_IN}/networkSecurityGroups/nsg-east", "name": "nsg-east",
                                   "location": "regioneast", "security_rules": [], "default_security_rules": []}),
    ]
    vnets = [
        nsg.virtual_network_record({"id": f"{NET_IN}/virtualNetworks/vnet-in", "name": "vnet-in", "location": "regionwest",
                                    "subnets": [
                                        # An in-scope subnet filtered by an excluded NSG.
                                        {"id": f"{NET_IN}/virtualNetworks/vnet-in/subnets/app", "name": "app",
                                         "nsg_id": groups[1]["id"], "address_prefixes": ["10.0.1.0/24"]},
                                        {"id": f"{NET_IN}/virtualNetworks/vnet-in/subnets/data", "name": "data",
                                         "nsg_id": None, "address_prefixes": ["10.0.2.0/24"]},
                                    ]}),
        nsg.virtual_network_record({"id": f"{NET_OUT}/virtualNetworks/vnet-out", "name": "vnet-out",
                                    "location": "regionwest", "subnets": [
                                        {"id": f"{NET_OUT}/virtualNetworks/vnet-out/subnets/x", "name": "x",
                                         "nsg_id": None, "address_prefixes": ["10.9.0.0/24"]}]}),
    ]

    def nic(rg_net, name, subnet_id):
        return {"id": f"{rg_net}/networkInterfaces/{name}", "name": name, "location": "regionwest", "nsg_id": None,
                "virtual_machine_id": None, "ip_configurations": [{"subnet_id": subnet_id}]}

    index = nsg.subnet_nsg_index(vnets)
    nics = [nsg.network_interface_record(n, index) for n in (
        nic(NET_IN, "nic-in", vnets[0]["subnets"][0]["id"]),
        nic(NET_IN, "nic-follow", vnets[1]["subnets"][0]["id"]),
        nic(NET_OUT, "nic-out", vnets[0]["subnets"][1]["id"]),
    )]
    return groups, nsg.with_east_west(vnets, groups), nics


def run_nsg(monkeypatch, tmp_path, patterns):
    monkeypatch.setattr(nsg, "collect_network", lambda sub, cred, collector: _nsg_records())
    return _run(nsg, monkeypatch, tmp_path, patterns, "azure_network_security_groups")


def test_nsg_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_nsg(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"] == {
        **nsg.summarize(*_nsg_records()), "provider_registration_status": "registered",
        **_added_fields({"network_security_group": 3, "virtual_network": 2, "network_interface": 3}),
    }


def test_nsg_exclude_by_group_and_region_and_nics_follow_their_virtual_network(monkeypatch, tmp_path):
    code, evidence = run_nsg(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("network_interface", "nic-follow", "rg:rg-out", "virtual_network_matched"),
        ("network_interface", "nic-out", "rg:rg-out", "resource_matched"),
        ("network_security_group", "nsg-east", "location:regioneast", "resource_matched"),
        ("network_security_group", "nsg-out", "rg:rg-out", "resource_matched"),
        ("virtual_network", "vnet-out", "rg:rg-out", "resource_matched"),
    ]
    follow = next(e for e in results["excluded"] if e["name"] == "nic-follow")
    assert follow["matched_id"] == f"{NET_OUT}/virtualNetworks/vnet-out" and follow["id"].endswith("/nic-follow")
    assert [g["name"] for g in results["network_security_groups"]] == ["nsg-in"]
    assert [v["name"] for v in results["virtual_networks"]] == ["vnet-in"]
    assert [n["name"] for n in results["network_interfaces"]] == ["nic-in"]
    # The excluded NSG still filters the in-scope subnet and NIC, and decides the subnet's east-west verdict.
    app = results["virtual_networks"][0]["subnets"][0]
    assert app["east_west_segmentation"] == "unsegmented"
    assert results["network_interfaces"][0]["nsg_protection_source"] == "subnet"
    assert (summary["total_network_security_groups"], summary["in_scope_network_security_groups"],
            summary["excluded_network_security_groups"]) == (1, 1, 2)
    assert (summary["total_virtual_networks"], summary["total_subnets"], summary["subnets_with_nsg"]) == (1, 2, 1)
    assert (summary["total_network_interfaces"], summary["excluded_network_interfaces"]) == (1, 2)
    assert summary["nic_nsg_coverage_percentage"] == 100
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_nsg_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_nsg(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_network_security_groups"] == 3


# --- private_endpoint_configuration ---

STORAGE_IN = f"{IN_RG}/providers/Microsoft.Storage/storageAccounts/stin"
STORAGE_OUT = f"{OUT_RG}/providers/Microsoft.Storage/storageAccounts/stout"


def _endpoint(rg_net, name, location, target):
    conn = {"name": name, "manual": False, "target_resource_id": target, "target_resource_name": target.rsplit("/", 1)[1],
            "target_resource_type": "Microsoft.Storage/storageAccounts", "group_ids": ["blob"],
            "checked_resource_id": target, "target_slot": None, "status": "Approved", "status_description": None,
            "actions_required": None, "provisioning_state": "Succeeded"}
    subnet = f"{rg_net}/virtualNetworks/vnet/subnets/pe"
    record = {"id": f"{rg_net}/privateEndpoints/{name}", "name": name, "location": location, "tags": {},
              "provisioning_state": "Succeeded", "subnet_id": subnet, "virtual_network_id": pe.virtual_network_id(subnet),
              "virtual_network_name": "vnet", "network_interface_ids": [], "custom_dns_configs": [], "connections": [conn]}
    lookups = {STORAGE_IN.lower(): {"public_network_access": "Enabled"},
               STORAGE_OUT.lower(): {"public_network_access": "Disabled"}}
    return pe.endpoint_record(record, [], lookups, set(), {}, set(), None)


def _pe_records():
    return [
        # An in-scope endpoint to a resource in the excluded group.
        _endpoint(NET_IN, "pe-in", "regionwest", STORAGE_OUT),
        _endpoint(NET_OUT, "pe-out", "regionwest", STORAGE_IN),
        _endpoint(NET_IN, "pe-east", "regioneast", STORAGE_IN),
    ]


def run_pe(monkeypatch, tmp_path, patterns):
    monkeypatch.setattr(pe, "collect_endpoints", lambda sub, cred, collector: _pe_records())
    return _run(pe, monkeypatch, tmp_path, patterns, "azure_private_endpoint_configuration")


def test_private_endpoints_without_patterns_add_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_pe(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"] == {
        **pe.summarize(_pe_records()), "provider_registration_status": "registered",
        **_added_fields({"private_endpoint": 3}),
    }


def test_private_endpoints_exclude_by_group_and_region_but_keep_a_target_in_an_excluded_group(monkeypatch, tmp_path):
    code, evidence = run_pe(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, location:nowhere")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("private_endpoint", "pe-east", "location:regioneast", "resource_matched"),
        ("private_endpoint", "pe-out", "rg:rg-out", "resource_matched"),
    ]
    [kept] = results["private_endpoints"]
    assert kept["name"] == "pe-in" and kept["connections"][0]["target_public_network_access_state"] == "disabled"
    assert (summary["total_private_endpoints"], summary["in_scope_private_endpoints"],
            summary["excluded_private_endpoints"]) == (1, 1, 2)
    # Only the in-scope endpoint's target counts, though it sits in the excluded group.
    assert (summary["total_target_resources"], summary["target_resources_public_access_disabled"],
            summary["target_resources_public_access_enabled"]) == (1, 1, 0)
    assert summary["resource_exclusion_patterns_unmatched"] == ["location:nowhere"]


def test_private_endpoints_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_pe(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_private_endpoints"] == 3


# --- private_dns_zone_configuration ---

BLOB_ZONE = "privatelink.blob.core.windows.net"


def _zone(rg_net, name, links=()):
    zone = {"id": f"{rg_net}/privateDnsZones/{name}", "name": name, "tags": {}, "provisioning_state": "Succeeded",
            "number_of_record_sets": 1, "max_number_of_record_sets": 25000, "number_of_virtual_network_links": len(links)}
    link_records = [{"id": f"{zone['id']}/virtualNetworkLinks/{v}", "name": v, "virtual_network_id": f"{rg_net}/virtualNetworks/{v}",
                     "virtual_network_name": v, "registration_enabled": False, "resolution_policy": None,
                     "virtual_network_link_state": "Completed", "provisioning_state": "Succeeded"} for v in links]
    return dns.zone_record(zone, link_records, [], {}, {}, None)


def _dns_records():
    # The same zone name in the in-scope and the excluded group: a duplicate either way.
    zones = [_zone(NET_IN, BLOB_ZONE), _zone(NET_OUT, BLOB_ZONE, ["vnet-out"]), _zone(NET_IN, "corp.example", ["vnet-in"])]
    return zones, dns.duplicate_zone_names(zones, None, None), "target_subscription"


def run_dns(monkeypatch, tmp_path, patterns):
    monkeypatch.setattr(dns, "collect_zones", lambda sub, cred, collector: _dns_records())
    return _run(dns, monkeypatch, tmp_path, patterns, "azure_private_dns_zone_configuration")


def test_private_dns_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_dns(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"] == {
        **dns.summarize(*_dns_records()), "provider_registration_status": "registered",
        **_added_fields({"private_dns_zone": 3}),
    }


def test_private_dns_zones_leave_by_group_or_id_never_by_region(monkeypatch, tmp_path):
    code, evidence = run_dns(monkeypatch, tmp_path, "rg:rg-out, location:regionwest, id:*/privateDnsZones/corp.example")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("private_dns_zone", "corp.example", "id:*/privateDnsZones/corp.example", "resource_matched"),
        ("private_dns_zone", BLOB_ZONE, "rg:rg-out", "resource_matched"),
    ]
    assert all(e["location"] is None for e in results["excluded"])
    assert [z["id"] for z in results["private_zones"]] == [f"{NET_IN}/privateDnsZones/{BLOB_ZONE}"]
    assert (summary["total_zones"], summary["in_scope_private_dns_zones"], summary["excluded_private_dns_zones"]) == (1, 1, 2)
    # The excluded zones' links leave with them.
    assert (summary["total_virtual_network_links"], summary["zones_without_virtual_network_links"]) == (0, 1)
    # The in-scope zone's name is still a duplicate of the excluded copy.
    assert [(d["name"], len(d["zone_ids"])) for d in summary["duplicate_zone_names"]] == [(BLOB_ZONE, 2)]
    assert summary["resource_exclusion_patterns_unmatched"] == ["location:regionwest"]


def test_private_dns_duplicates_of_excluded_zones_only_are_not_listed(monkeypatch, tmp_path):
    code, evidence = run_dns(monkeypatch, tmp_path, f"rg:rg-out, id:{NET_IN}/privateDnsZones/{BLOB_ZONE}")
    assert code == 0
    assert evidence["summary"]["duplicate_zone_names"] == []
    assert [z["name"] for z in evidence["results"]["private_zones"]] == ["corp.example"]


def test_private_dns_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_dns(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_zones"] == 3


# --- vnet_egress_routing ---

VNET_IN = f"{NET_IN}/virtualNetworks/vnet-in"
VNET_OUT = f"{NET_OUT}/virtualNetworks/vnet-out"
VNET_EAST = f"{NET_IN}/virtualNetworks/vnet-east"
ROUTE_TABLE_OUT = f"{NET_OUT}/routeTables/rt-out"
FIREWALL = f"{NET_IN}/azureFirewalls/fw-in"


def _subnet(vnet_id, name, routed=False):
    return {"id": f"{vnet_id}/subnets/{name}", "name": name, "address_prefixes": [], "route_table_id": ROUTE_TABLE_OUT if routed else None,
            "nat_gateway_id": None, "default_outbound_access": None, "service_endpoints": [], "delegations": []}


def _vnet(vnet_id, location, prefix, *subnets):
    return {"id": vnet_id, "name": vnet_id.rsplit("/", 1)[1], "location": location, "address_prefixes": [prefix],
            "default_public_nat_gateway_id": None, "subnets": list(subnets)}


def _egress_raw():
    vnets = [
        _vnet(VNET_IN, "regionwest", "10.0.0.0/16", _subnet(VNET_IN, "app", routed=True), _subnet(VNET_IN, "AzureFirewallSubnet")),
        _vnet(VNET_OUT, "regionwest", "10.1.0.0/16", _subnet(VNET_OUT, "x", routed=True)),
        _vnet(VNET_EAST, "regioneast", "10.2.0.0/16", _subnet(VNET_EAST, "y")),
    ]
    peers = {VNET_OUT.lower(): [{"name": "to-in", "peering_state": "Connected", "remote_virtual_network_id": VNET_IN,
                                 "remote_address_prefixes": ["10.0.0.0/16"]}]}
    # The in-scope subnet's route table is in the excluded group, and sends it to the in-scope firewall.
    tables = [{"id": ROUTE_TABLE_OUT, "name": "rt-out", "location": "regionwest", "disable_bgp_route_propagation": False,
               "routes": [{"name": "default", "address_prefix": "0.0.0.0/0", "next_hop_type": "VirtualAppliance",
                           "next_hop_ip_addresses": ["10.0.0.4"]}],
               "subnet_ids": [f"{VNET_IN}/subnets/app", f"{VNET_OUT}/subnets/x"]}]
    nics = [{"id": f"{NET_IN}/networkInterfaces/{name}", "name": name, "location": "regionwest", "virtual_machine_id": None,
             "enable_ip_forwarding": False, "default_outbound_connectivity_enabled": None,
             "ip_configurations": [{"subnet_id": subnet, "private_ip_address": "10.0.1.4", "public_ip_address_id": None}]}
            for name, subnet in (("nic-in", f"{VNET_IN}/subnets/app"), ("nic-follow", f"{VNET_OUT}/subnets/x"))]
    firewalls = [{"id": FIREWALL, "name": "fw-in", "location": "regionwest", "sku_name": "AZFW_VNet", "sku_tier": "Standard",
                  "threat_intel_mode": "Deny", "firewall_policy_id": None, "virtual_hub_id": None, "hub_private_ip_address": None,
                  "ip_configurations": [{"subnet_id": f"{VNET_IN}/subnets/AzureFirewallSubnet", "private_ip_address": "10.0.0.4"}]}]
    return vnets, peers, tables, nics, firewalls, [], []


def run_egress(monkeypatch, tmp_path, patterns):
    monkeypatch.setattr(egress, "collect", lambda sub, cred, collector: (_egress_raw(), egress.new_hub_search()))
    return _run(egress, monkeypatch, tmp_path, patterns, "azure_vnet_egress_routing")


def test_egress_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_egress(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"] == {
        **egress.summarize(*egress.build_records(*_egress_raw())), "provider_registration_status": "registered",
        **_added_fields({"virtual_network": 3, "subnet": 4, "route_table": 1, "network_interface": 2,
                         "azure_firewall": 1, "virtual_hub": 0}),
    }


def test_egress_exclude_by_group_and_region_but_keep_routing_through_excluded_records(monkeypatch, tmp_path):
    code, evidence = run_egress(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("network_interface", "nic-follow", "rg:rg-out", "subnet_matched"),
        ("route_table", "rt-out", "rg:rg-out", "resource_matched"),
        ("subnet", "x", "rg:rg-out", "resource_matched"),
        ("subnet", "y", "location:regioneast", "resource_matched"),
        ("virtual_network", "vnet-east", "location:regioneast", "resource_matched"),
        ("virtual_network", "vnet-out", "rg:rg-out", "resource_matched"),
    ]
    follow = next(e for e in results["excluded"] if e["name"] == "nic-follow")
    assert follow["matched_id"] == f"{VNET_OUT}/subnets/x"
    # The in-scope subnet keeps the path its excluded route table gives it, and the firewall still counts both subnets.
    app = next(s for s in results["subnets"] if s["name"] == "app")
    assert (app["egress_path"], app["appliance_owner"], app["appliance_firewall_ids"]) == ("appliance", "azure_firewall", [FIREWALL])
    assert results["azure_firewalls"][0]["routed_workload_subnets"] == 2
    assert [n["name"] for n in results["network_interfaces"]] == ["nic-in"]
    assert (summary["total_virtual_networks"], summary["in_scope_virtual_networks"], summary["excluded_virtual_networks"]) == (1, 1, 2)
    assert (summary["total_subnets"], summary["workload_subnets"], summary["excluded_subnets"]) == (2, 1, 2)
    assert summary["workload_subnets_by_egress_path"]["appliance"] == 1
    assert (summary["total_route_tables"], summary["excluded_route_tables"]) == (0, 1)
    assert (summary["total_network_interfaces"], summary["excluded_network_interfaces"]) == (1, 1)
    assert (summary["total_azure_firewalls"], summary["azure_firewalls_with_no_routed_subnet"]) == (1, 0)
    assert (summary["in_scope_virtual_hubs"], summary["excluded_virtual_hubs"]) == (0, 0)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_egress_bare_pattern_fails_the_run(monkeypatch, tmp_path):
    code, evidence = run_egress(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["summary"]["total_virtual_networks"] == 3
