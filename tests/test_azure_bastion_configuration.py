"""azure_bastion_configuration: host features, subnet NSG, audit log export, VM reachability through peering, failure semantics. Synthetic payloads, no SDK or network."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_bastion_configuration_under_test",
                                               AZURE / "bastion_configuration" / "fetcher.py")
bs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bs)
azure_rest = sys.modules["azure_rest"]
Collector = sys.modules["azure_common"].Collector
ResourceExclusions = sys.modules["resource_exclusions"].ResourceExclusions

SUB = "/subscriptions/s1"
HUB_SUB = "s2"
NET = f"{SUB}/resourceGroups/rg-net/providers/Microsoft.Network"
VNET_A = f"{NET}/virtualNetworks/vnet-a"
VNET_B = f"{NET}/virtualNetworks/vnet-b"
VNET_C = f"{NET}/virtualNetworks/vnet-c"
HUB_VNET = f"/subscriptions/{HUB_SUB}/resourceGroups/rg-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub"
HOST = f"{NET}/bastionHosts/bas-a"
WORKSPACE = f"{SUB}/resourceGroups/rg-logs/providers/Microsoft.OperationalInsights/workspaces/law"
COMPUTE = f"{SUB}/resourceGroups/rg-app/providers/Microsoft.Compute"


def raw_host(hid=HOST, vnet=VNET_A, *, sku="Standard", developer=False, **features):
    props = {"scaleUnits": 2, "provisioningState": "Succeeded", "dnsName": "bst.bastion.azure.us",
             "enableShareableLink": False, "enableIpConnect": False, "enableTunneling": True, "enableFileCopy": False,
             "enableKerberos": False, "enableSessionRecording": False, "enablePrivateOnlyBastion": False,
             "disableCopyPaste": False, "networkAcls": {"ipRules": []}}
    props.update(features)
    if developer:
        props["virtualNetwork"] = {"id": vnet}
    else:
        props["ipConfigurations"] = [{"name": "ipc", "properties": {
            "subnet": {"id": f"{vnet}/subnets/AzureBastionSubnet"},
            "publicIPAddress": {"id": f"{NET}/publicIPAddresses/pip-bas"}}}]
    # As ARM returns it: sku beside properties, not inside.
    return {"id": hid, "name": hid.rsplit("/", 1)[-1], "location": "usgovvirginia", "zones": ["1", "2", "3"],
            "sku": {"name": sku}, "properties": props}


def raw_vm(name, nic_ids):
    return {"id": f"{COMPUTE}/virtualMachines/{name}", "name": name, "location": "usgovvirginia",
            "properties": {"networkProfile": {"networkInterfaces": [{"id": n} for n in nic_ids]}}}


def raw_nic(name, vnet, public_ip=None):
    config = {"name": "ipc", "properties": {"subnet": {"id": f"{vnet}/subnets/default"}}}
    if public_ip:
        config["properties"]["publicIPAddress"] = {"id": public_ip}
    return {"id": f"{NET}/networkInterfaces/{name}", "name": name, "properties": {"ipConfigurations": [config]}}


def raw_vnet(vid, peerings=(), nsg=True, access=True):
    subnet = {"id": f"{vid}/subnets/AzureBastionSubnet", "name": "AzureBastionSubnet", "properties": {}}
    if nsg:
        subnet["properties"]["networkSecurityGroup"] = {"id": f"{NET}/networkSecurityGroups/nsg-bastion"}
    return {"id": vid, "name": vid.rsplit("/", 1)[-1], "properties": {"subnets": [subnet], "virtualNetworkPeerings": [
        {"name": f"to-{r.rsplit('/', 1)[-1]}", "properties": {"remoteVirtualNetwork": {"id": r}, "peeringState": state,
                                                               "allowVirtualNetworkAccess": access}}
        for r, state in peerings]}}


def _setting(name, logs, **dest):
    return {"name": name, "properties": {"logs": logs, **dest}}


SUBNET_WITH_NSG = {"id": f"{VNET_A}/subnets/AzureBastionSubnet",
                   "properties": {"networkSecurityGroup": {"id": f"{NET}/networkSecurityGroups/nsg-bastion"}}}


# --- hosts ---

def test_host_record_reads_features_subnet_and_logs() -> None:
    settings = [_setting("s", [{"category": "BastionAuditLogs", "enabled": True}], workspaceId=WORKSPACE)]
    host = bs.host_record(raw_host(enableShareableLink=True, enableIpConnect=True, disableCopyPaste=True,
                                   networkAcls={"ipRules": [{"addressPrefix": "203.0.113.0/24"}]}),
                          SUBNET_WITH_NSG, True, settings)
    assert host["sku"] == "standard" and host["virtual_network_id"] == VNET_A.lower()
    assert host["subnet_has_nsg"] is True and host["subnet_nsg_id"].endswith("/nsg-bastion")
    assert host["shareable_links_enabled"] and host["ip_connect_enabled"] and host["copy_paste_disabled"]
    assert host["native_client_tunneling_enabled"] is True and host["file_copy_enabled"] is False
    assert host["ip_allowlist_rules"] == 1 and host["public_ip_ids"] == [f"{NET}/publicIPAddresses/pip-bas"]
    assert host["logs"]["audit_logs_exported"] is True and host["logs"]["destinations"][0]["kind"] == "log_analytics"


def test_host_without_nsg_and_without_audit_export() -> None:
    settings = [_setting("s", [{"category": "BastionAuditLogs", "enabled": False}], storageAccountId=f"{SUB}/sa")]
    host = bs.host_record(raw_host(), {"id": "x", "properties": {}}, True, settings)
    assert host["subnet_has_nsg"] is False
    assert host["logs"]["audit_logs_exported"] is False and host["logs"]["destinations"][0]["audit_logs"] is False


def test_unread_subnet_and_settings_read_null() -> None:
    host = bs.host_record(raw_host(), None, False, None)
    assert host["subnet_read"] is False and host["subnet_has_nsg"] is None
    assert host["logs"]["diagnostic_settings_read"] is False and host["logs"]["audit_logs_exported"] is None


def test_developer_host_has_a_vnet_but_no_subnet() -> None:
    host = bs.host_record(raw_host(sku="Developer", developer=True), None, False, [])
    assert host["sku"] == "developer" and host["virtual_network_id"] == VNET_A.lower() and host["subnet_id"] is None
    assert host["subnet_read"] is None and host["subnet_has_nsg"] is None and host["public_ip_ids"] == []


def test_optional_features_read_null_when_the_api_omits_them() -> None:
    raw = raw_host()
    del raw["properties"]["enablePrivateOnlyBastion"], raw["properties"]["enableSessionRecording"]
    host = bs.host_record(raw, SUBNET_WITH_NSG, True, [])
    assert host["private_only"] is None and host["session_recording_enabled"] is None
    assert bs.summarize([host], [], True, True, True)["bastion_hosts_private_only"] == 0


def test_category_group_counts_as_audit_export() -> None:
    logs = bs.audit_export([_setting("s", [{"categoryGroup": "allLogs", "enabled": True}], workspaceId=WORKSPACE)])
    assert logs["audit_logs_exported"] is True


# --- virtual machines ---

def _nics(*specs):
    return {bs.arm_id_key(n["id"]): n for n in (raw_nic(*s) for s in specs)}


def _bastions(**by_vnet):
    return {bs.arm_id_key(v): [{"name": n, "sku": sku} for n, sku in hosts] for v, hosts in by_vnet.items()}


def test_vm_in_bastion_vnet() -> None:
    vm = bs.vm_record(raw_vm("vm1", [f"{NET}/networkInterfaces/n1"]), _nics(("n1", VNET_A)),
                      {bs.arm_id_key(VNET_A): [{"name": "bas-a", "sku": "standard"}]}, {}, {})
    assert vm["bastion_path"] == bs.IN_VNET and vm["reached_by_bastions"] == ["bas-a"]
    assert vm["virtual_network_ids"] == [VNET_A.lower()] and vm["public_ip_ids"] == []


def test_vm_reached_through_a_connected_peering_only() -> None:
    peerings = bs.peering_map([raw_vnet(VNET_B, [(VNET_A, "Connected")]), raw_vnet(VNET_C, [(VNET_A, "Disconnected")])])
    bastions = {bs.arm_id_key(VNET_A): [{"name": "bas-a", "sku": "standard"}]}
    via = bs.vm_record(raw_vm("vm2", [f"{NET}/networkInterfaces/n2"]), _nics(("n2", VNET_B)), bastions, peerings, {})
    assert via["bastion_path"] == bs.VIA_PEERING and via["reached_by_bastions"] == ["bas-a"]
    cut = bs.vm_record(raw_vm("vm3", [f"{NET}/networkInterfaces/n3"]), _nics(("n3", VNET_C)), bastions, peerings, {})
    assert cut["bastion_path"] == bs.NONE
    # the link that matters is the one on the Bastion's side: it must also allow virtual network access
    closed = bs.peering_map([raw_vnet(VNET_B, [(VNET_A, "Connected")]), raw_vnet(VNET_A, [(VNET_B, "Connected")], access=False)])
    blocked = bs.vm_record(raw_vm("vm2", [f"{NET}/networkInterfaces/n2"]), _nics(("n2", VNET_B)), bastions, closed, {})
    assert blocked["bastion_path"] == bs.NONE
    open_both = bs.peering_map([raw_vnet(VNET_B, [(VNET_A, "Connected")]), raw_vnet(VNET_A, [(VNET_B, "Connected")])])
    assert bs.vm_record(raw_vm("vm2", [f"{NET}/networkInterfaces/n2"]), _nics(("n2", VNET_B)), bastions, open_both,
                        {})["bastion_path"] == bs.VIA_PEERING
    developer = {bs.arm_id_key(VNET_A): [{"name": "bas-dev", "sku": "developer"}]}
    dev = bs.vm_record(raw_vm("vm2", [f"{NET}/networkInterfaces/n2"]), _nics(("n2", VNET_B)), developer, peerings, {})
    assert dev["bastion_path"] == bs.NONE
    same = bs.vm_record(raw_vm("vm1", [f"{NET}/networkInterfaces/n1"]), _nics(("n1", VNET_A)), developer, peerings, {})
    assert same["bastion_path"] == bs.IN_VNET


def test_vm_peered_into_another_subscription() -> None:
    peerings = bs.peering_map([raw_vnet(VNET_B, [(HUB_VNET, "Connected")])])
    nics = _nics(("n2", VNET_B, f"{NET}/publicIPAddresses/pip-vm"))
    readable = bs.vm_record(raw_vm("vm2", [f"{NET}/networkInterfaces/n2"]), nics, {}, peerings,
                            {HUB_SUB: {bs.arm_id_key(HUB_VNET): [{"name": "bas-hub (subscription s2)", "sku": "basic"}]}})
    assert readable["bastion_path"] == bs.VIA_PEERING and readable["reached_by_bastions"] == ["bas-hub (subscription s2)"]
    assert readable["public_ip_ids"] == [f"{NET}/publicIPAddresses/pip-vm"]
    unreadable = bs.vm_record(raw_vm("vm2", [f"{NET}/networkInterfaces/n2"]), nics, {}, peerings, {HUB_SUB: None})
    assert unreadable["bastion_path"] == bs.UNKNOWN
    empty = bs.vm_record(raw_vm("vm2", [f"{NET}/networkInterfaces/n2"]), nics, {}, peerings, {HUB_SUB: {}})
    assert empty["bastion_path"] == bs.NONE


def test_vm_with_unread_nic_is_unknown() -> None:
    vm = bs.vm_record(raw_vm("vm4", [f"{NET}/networkInterfaces/missing"]), {}, _bastions(**{VNET_A: [("bas-a", "standard")]}), {}, {})
    assert vm["bastion_path"] == bs.UNKNOWN and vm["network_interfaces_read"] is False


# --- summary ---

def test_summary_counts_features_and_paths() -> None:
    settings = [_setting("s", [{"category": "BastionAuditLogs", "enabled": True}], workspaceId=WORKSPACE)]
    hosts = [bs.host_record(raw_host(enableShareableLink=True), SUBNET_WITH_NSG, True, settings),
             bs.host_record(raw_host(f"{NET}/bastionHosts/bas-b", VNET_B, sku="Premium", enableSessionRecording=True,
                                     enablePrivateOnlyBastion=True), {"properties": {}}, True, [])]
    bastions = _bastions(**{VNET_A: [("bas-a", "standard")], VNET_B: [("bas-b", "premium")]})
    peerings = bs.peering_map([raw_vnet(VNET_C, [(VNET_A, "Connected")])])
    nics = _nics(("n1", VNET_A), ("n2", VNET_C), ("n3", f"{NET}/virtualNetworks/vnet-d", f"{NET}/publicIPAddresses/p"))
    vms = [bs.vm_record(raw_vm(f"vm{i}", [f"{NET}/networkInterfaces/n{i}"]), nics, bastions, peerings, {}) for i in (1, 2, 3)]
    summary = bs.summarize(hosts, vms, True, True, True)
    assert summary["bastion_hosts"] == 2 and summary["bastion_hosts_by_sku"] == {"premium": 1, "standard": 1}
    assert summary["virtual_networks_with_bastion"] == 2 and summary["bastion_hosts_with_public_ip"] == 2
    assert summary["bastion_hosts_with_shareable_links"] == 1 and summary["bastion_hosts_private_only"] == 1
    assert summary["bastion_hosts_with_session_recording"] == 1 and summary["bastion_hosts_with_native_client_tunneling"] == 2
    assert summary["bastion_hosts_with_subnet_nsg"] == 1 and summary["bastion_hosts_without_subnet_nsg"] == 1
    assert summary["bastion_hosts_exporting_audit_logs"] == 1 and summary["bastion_hosts_without_audit_log_export"] == 1
    assert summary["virtual_machines"] == 3 and summary["virtual_machines_with_public_ip"] == 1
    assert summary["virtual_machines_with_bastion_in_vnet"] == 1 and summary["virtual_machines_with_bastion_via_peering"] == 1
    assert summary["virtual_machines_without_bastion_path"] == 1 and summary["virtual_machines_with_unknown_bastion_path"] == 0
    assert summary["bastion_path_percentage"] == 66


def test_summary_nulls_when_something_was_unread() -> None:
    hosts = [bs.host_record(raw_host(), None, False, None)]
    vms = [bs.vm_record(raw_vm("vm1", [f"{NET}/networkInterfaces/none"]), {}, {}, {}, {})]
    summary = bs.summarize(hosts, vms, True, True, True)
    assert summary["bastion_hosts_with_subnet_nsg"] is None and summary["bastion_hosts_exporting_audit_logs"] is None
    assert summary["virtual_machines_with_unknown_bastion_path"] == 1
    assert summary["virtual_machines_without_bastion_path"] is None and summary["bastion_path_percentage"] is None
    assert bs.summarize([], [], True, True, False)["bastion_path_percentage"] is None
    assert bs.summarize([], [], False, True, True)["bastion_path_percentage"] is None
    assert bs.summarize([], [], True, True, True)["bastion_path_percentage"] == 0


# --- collection through a fake ARM ---

class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text = status, body, "", json.dumps(body)
        self.headers: dict = {}

    def json(self):
        return self._body


class _Arm:
    def __init__(self, *, hub_readable=True, nics_fail=False, hosts_fail=False, vnets_fail=False):
        self.hub_readable, self.nics_fail, self.hosts_fail, self.vnets_fail = hub_readable, nics_fail, hosts_fail, vnets_fail
        self.urls: list[str] = []

    def get(self, url, params=None, headers=None, timeout=None):
        path = urlparse(url).path
        self.urls.append(path)
        if path.endswith(f"/subscriptions/{HUB_SUB}/providers/Microsoft.Network/bastionHosts"):
            if not self.hub_readable:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            return _Resp(200, {"value": [raw_host(f"/subscriptions/{HUB_SUB}/resourceGroups/rg-hub/providers/Microsoft.Network/bastionHosts/bas-hub", HUB_VNET)]})
        if path.endswith("/providers/Microsoft.Network/bastionHosts"):
            if self.hosts_fail:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            return _Resp(200, {"value": [raw_host()]})
        if path.endswith("/providers/Microsoft.Insights/diagnosticSettings"):
            return _Resp(200, {"value": [_setting("s", [{"category": "BastionAuditLogs", "enabled": True}], workspaceId=WORKSPACE)]})
        if path.endswith("/providers/Microsoft.Compute/virtualMachines"):
            return _Resp(200, {"value": [raw_vm("vm-a", [f"{NET}/networkInterfaces/n1"]),
                                         raw_vm("vm-spoke", [f"{NET}/networkInterfaces/n2"]),
                                         raw_vm("vm-island", [f"{NET}/networkInterfaces/n3"])]})
        if path.endswith("/providers/Microsoft.Network/networkInterfaces"):
            if self.nics_fail:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            return _Resp(200, {"value": [raw_nic("n1", VNET_A), raw_nic("n2", VNET_B), raw_nic("n3", VNET_C)]})
        if path.endswith("/providers/Microsoft.Network/virtualNetworks"):
            if self.vnets_fail:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            return _Resp(200, {"value": [raw_vnet(VNET_A), raw_vnet(VNET_B, [(HUB_VNET, "Connected")]), raw_vnet(VNET_C)]})
        return _Resp(404, {"error": {"code": "NotFound", "message": path}})


class _Cred:
    def get_token(self, scope):
        return namedtuple("T", "token expires_on")("tok", 9_999_999_999)


def _collect(arm, exclusions=None):
    client = azure_rest.AzureRestClient(_Cred(), session=arm)
    collector = Collector(logging.getLogger("test"))
    results, summary = bs.collect(client, "s1", collector, exclusions)
    return results, summary, collector


def test_collect_resolves_hosts_vms_and_a_peered_subscription(assert_summary_documented) -> None:
    arm = _Arm()
    results, summary, collector = _collect(arm)
    assert collector.ok, collector.failures
    assert_summary_documented("azure/bastion_configuration", summary)
    assert [h["name"] for h in results["bastion_hosts"]] == ["bas-a"]
    assert results["bastion_hosts"][0]["subnet_has_nsg"] is True and results["bastion_hosts"][0]["logs"]["audit_logs_exported"] is True
    paths = {v["name"]: v["bastion_path"] for v in results["virtual_machines"]}
    assert paths == {"vm-a": bs.IN_VNET, "vm-spoke": bs.VIA_PEERING, "vm-island": bs.NONE}
    assert results["peered_subscriptions"] == {HUB_SUB: {bs.arm_id_key(HUB_VNET): ["bas-hub (subscription s2)"]}}
    assert summary["virtual_machines_with_bastion_via_peering"] == 1 and summary["bastion_path_percentage"] == 66
    assert summary["in_scope_bastion_hosts"] == 1 and summary["in_scope_virtual_machines"] == 3
    assert sum(1 for u in arm.urls if u.endswith(f"/{HUB_SUB}/providers/Microsoft.Network/bastionHosts")) == 1
    assert not any("/subnets/" in u for u in arm.urls)  # the subnet's NSG comes from the virtual network list


def test_unreadable_peered_subscription_reads_unknown_not_failed() -> None:
    results, summary, collector = _collect(_Arm(hub_readable=False))
    assert collector.ok
    paths = {v["name"]: v["bastion_path"] for v in results["virtual_machines"]}
    assert paths["vm-spoke"] == bs.UNKNOWN and paths["vm-a"] == bs.IN_VNET
    assert results["peered_subscriptions"] == {HUB_SUB: None}
    assert summary["virtual_machines_with_unknown_bastion_path"] == 1 and summary["bastion_path_percentage"] is None


def test_failed_nic_list_leaves_every_path_unknown_and_fails() -> None:
    results, summary, collector = _collect(_Arm(nics_fail=True))
    assert not collector.ok
    assert {v["bastion_path"] for v in results["virtual_machines"]} == {bs.UNKNOWN}
    assert summary["virtual_machines_read"] is False and summary["virtual_machines_without_bastion_path"] is None


def test_failed_host_list_leaves_every_unreached_vm_unknown_and_fails() -> None:
    results, summary, collector = _collect(_Arm(hosts_fail=True))
    assert not collector.ok and summary["bastion_hosts_read"] is False
    # An unread host list is not an empty one: no host count reads as a known 0.
    for key in ("bastion_hosts", "bastion_hosts_by_sku", "bastion_hosts_with_subnet_nsg",
                "bastion_hosts_without_subnet_nsg", "bastion_hosts_without_audit_log_export",
                "bastion_hosts_with_public_ip", "virtual_networks_with_bastion"):
        assert summary[key] is None, key
    assert summary["in_scope_bastion_hosts"] is None and summary["excluded_bastion_hosts"] is None
    paths = {v["name"]: v["bastion_path"] for v in results["virtual_machines"]}
    assert paths == {"vm-a": bs.UNKNOWN, "vm-spoke": bs.VIA_PEERING, "vm-island": bs.UNKNOWN}
    assert summary["virtual_machines_without_bastion_path"] is None and summary["bastion_path_percentage"] is None


def test_failed_vnet_list_nulls_the_nsg_field_and_unreached_paths() -> None:
    results, summary, collector = _collect(_Arm(vnets_fail=True))
    assert not collector.ok and results["bastion_hosts"][0]["subnet_has_nsg"] is None
    assert summary["bastion_hosts_with_subnet_nsg"] is None
    paths = {v["name"]: v["bastion_path"] for v in results["virtual_machines"]}
    assert paths == {"vm-a": bs.IN_VNET, "vm-spoke": bs.UNKNOWN, "vm-island": bs.UNKNOWN}
    assert summary["virtual_machines_with_unknown_bastion_path"] == 2 and summary["bastion_path_percentage"] is None


def test_exclusions_remove_a_vm_and_a_host() -> None:
    results, summary, collector = _collect(_Arm(), ResourceExclusions(["id:*/vm-island", "id:*/bas-a"]))
    assert collector.ok
    assert results["bastion_hosts"] == [] and [v["name"] for v in results["virtual_machines"]] == ["vm-a", "vm-spoke"]
    assert summary["excluded_bastion_hosts"] == 1 and summary["excluded_virtual_machines"] == 1
    assert {v["bastion_path"] for v in results["virtual_machines"]} == {bs.NONE, bs.VIA_PEERING}


def _vm(name, nic, vnet, bastions, peerings=None, foreign=None):
    return bs.vm_record(raw_vm(name, [f"{NET}/networkInterfaces/{nic}"]), _nics((nic, vnet)), bastions, peerings or {}, foreign or {})


def test_a_host_that_is_not_ready_or_has_no_sku_is_not_counted_as_a_path() -> None:
    failed = {bs.arm_id_key(VNET_A): [{"name": "bas-a", "sku": "standard", "state": "failed"}]}
    assert _vm("vm1", "n1", VNET_A, failed)["bastion_path"] == bs.UNKNOWN
    ready = {bs.arm_id_key(VNET_A): [{"name": "bas-a", "sku": "standard", "state": "succeeded"}]}
    assert _vm("vm1", "n1", VNET_A, ready)["bastion_path"] == bs.IN_VNET
    peerings = bs.peering_map([raw_vnet(VNET_B, [(VNET_A, "Connected")])])
    nosku = {bs.arm_id_key(VNET_A): [{"name": "bas-a", "sku": "unknown", "state": "succeeded"}]}
    assert _vm("vm2", "n2", VNET_B, nosku, peerings)["bastion_path"] == bs.UNKNOWN
    updating = {bs.arm_id_key(VNET_A): [{"name": "bas-a", "sku": "basic", "state": "updating"}]}
    assert _vm("vm2", "n2", VNET_B, updating, peerings)["bastion_path"] == bs.UNKNOWN
    foreign = {HUB_SUB: {bs.arm_id_key(HUB_VNET): [{"name": "bas-hub", "sku": "premium", "state": "deleting"}]}}
    hub_peerings = bs.peering_map([raw_vnet(VNET_B, [(HUB_VNET, "Connected")])])
    assert _vm("vm2", "n2", VNET_B, {}, hub_peerings, foreign)["bastion_path"] == bs.UNKNOWN
    dev_foreign = {HUB_SUB: {bs.arm_id_key(HUB_VNET): [{"name": "bas-dev", "sku": "developer", "state": "succeeded"}]}}
    assert _vm("vm2", "n2", VNET_B, {}, hub_peerings, dev_foreign)["bastion_path"] == bs.NONE


def test_a_host_subnet_id_with_unusual_casing_still_registers_its_vnet() -> None:
    raw = raw_host()
    raw["properties"]["ipConfigurations"][0]["properties"]["subnet"]["id"] = f"{VNET_A}/Subnets/AzureBastionSubnet"
    host = bs.host_record(raw, None, False, [])
    assert host["virtual_network_id"] == VNET_A.lower()
    mixed = bs.host_record(raw_host(f"{NET}/bastionHosts/bas-dev", VNET_A.upper().replace("/SUBSCRIPTIONS", "/subscriptions"),
                                    sku="Developer", developer=True), None, False, [])
    summary = bs.summarize([host, mixed], [], True, True, True)
    assert summary["virtual_networks_with_bastion"] == 1


def test_public_ip_count_and_path_counts_read_null_when_interfaces_were_not_read() -> None:
    hosts = [bs.host_record(raw_host(), SUBNET_WITH_NSG, True, [])]
    vms = [bs.vm_record(raw_vm("vm4", [f"{NET}/networkInterfaces/missing"]), {}, {}, {}, {})]
    summary = bs.summarize(hosts, vms, True, True, True)
    assert summary["virtual_machines_with_public_ip"] is None and summary["virtual_machines_with_unknown_bastion_path"] == 1
    unread = bs.summarize(hosts, [], True, False, True)
    assert unread["virtual_machines_with_bastion_in_vnet"] is None and unread["virtual_machines_with_bastion_via_peering"] is None
    assert unread["virtual_machines_with_public_ip"] is None
    clean = bs.summarize(hosts, [_vm("vm1", "n1", VNET_A, {})], True, True, True)
    assert clean["virtual_machines_with_public_ip"] == 0


def test_a_peering_that_omits_allow_virtual_network_access_is_treated_as_allowing_it() -> None:
    vnet = raw_vnet(VNET_B, [(VNET_A, "Connected")])
    del vnet["properties"]["virtualNetworkPeerings"][0]["properties"]["allowVirtualNetworkAccess"]
    back = raw_vnet(VNET_A, [(VNET_B, "Connected")])
    del back["properties"]["virtualNetworkPeerings"][0]["properties"]["allowVirtualNetworkAccess"]
    bastions = {bs.arm_id_key(VNET_A): [{"name": "bas-a", "sku": "standard", "state": "succeeded"}]}
    assert _vm("vm2", "n2", VNET_B, bastions, bs.peering_map([vnet, back]))["bastion_path"] == bs.VIA_PEERING


def test_audit_export_to_an_event_hub_and_a_partner_counts() -> None:
    logs = [{"category": "BastionAuditLogs", "enabled": True}]
    hub = bs.audit_export([_setting("eh", logs, eventHubAuthorizationRuleId=f"{SUB}/eh")])
    partner = bs.audit_export([_setting("p", logs, marketplacePartnerId=f"{SUB}/partner")])
    assert hub["audit_logs_exported"] is True and hub["destinations"][0]["kind"] == "event_hub"
    assert partner["audit_logs_exported"] is True and partner["destinations"][0]["kind"] == "partner"


def test_foreign_developer_host_does_not_reach_across_a_peering() -> None:
    hub_peerings = bs.peering_map([raw_vnet(VNET_B, [(HUB_VNET, "Connected")])])
    dev = {HUB_SUB: {bs.arm_id_key(HUB_VNET): [{"name": "d", "sku": "developer", "state": "succeeded"}]}}
    assert _vm("vm2", "n2", VNET_B, {}, hub_peerings, dev)["bastion_path"] == bs.NONE


def test_the_sku_is_read_from_the_top_of_the_resource() -> None:
    raw = raw_host(sku="Basic")
    assert "sku" not in raw["properties"] and bs.host_record(raw, None, False, [])["sku"] == "basic"
    del raw["sku"]
    assert bs.host_record(raw, None, False, [])["sku"] == "unknown"


class _VmListFails(_Arm):
    def get(self, url, params=None, headers=None, timeout=None):
        if urlparse(url).path.endswith("/providers/Microsoft.Compute/virtualMachines"):
            return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
        return super().get(url, params, headers, timeout)


def test_failed_vm_list_leaves_the_machine_counts_null() -> None:
    results, summary, collector = _collect(_VmListFails())
    assert not collector.ok and summary["virtual_machines_read"] is False
    for key in ("virtual_machines", "virtual_machines_with_unknown_bastion_path", "virtual_machines_without_bastion_path",
                "bastion_path_percentage", "in_scope_virtual_machines"):
        assert summary[key] is None, key
    # The host list was read, so its counts stand.
    assert summary["bastion_hosts"] == 1
