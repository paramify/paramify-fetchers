#!/usr/bin/env python3
"""Azure Bastion hosts: SKU and features, subnet NSG, audit log export, and which virtual machines a Bastion can reach."""

import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    arm_id_key,
    coverage_percentage,
    dig,
    resource_group_from_id,
    sorted_counts,
    vnet_id_of,
)
from azure_rest import DIAG_API, ArmError, run_subscription  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402

NAME = "azure_bastion_configuration"
logger = logging.getLogger(NAME)

NETWORK_API = "2024-05-01"
COMPUTE_API = "2024-07-01"
AUDIT_LOG_CATEGORY = "BastionAuditLogs"
LOG_GROUPS = {"alllogs", "audit"}
IN_VNET, VIA_PEERING, NONE, UNKNOWN = "in_vnet", "via_peering", "none", "unknown"
# A host that is not (or not yet) in this state cannot be counted on to carry a session.
READY_STATES = ("succeeded", "")


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _subscription_of(resource_id: Optional[str]) -> str:
    parts = arm_id_key(resource_id).split("/")
    return parts[2] if len(parts) > 2 and parts[1] == "subscriptions" else ""


# --- hosts ---

def audit_export(settings: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Where BastionAuditLogs goes; a category group (allLogs, audit) covers it."""
    if settings is None:
        return {"diagnostic_settings_read": False, "destinations": None, "audit_logs_exported": None}
    destinations: List[Dict[str, Any]] = []
    for setting in settings:
        props = setting.get("properties") or {}
        enabled = [log for log in props.get("logs") or [] if log.get("enabled") is True]
        audit = any(_lower(log.get("category")) == AUDIT_LOG_CATEGORY.lower() or _lower(log.get("categoryGroup")) in LOG_GROUPS
                    for log in enabled)
        for kind, key in (("log_analytics", "workspaceId"), ("storage", "storageAccountId"),
                          ("event_hub", "eventHubAuthorizationRuleId"), ("partner", "marketplacePartnerId")):
            if props.get(key):
                destinations.append({"setting": setting.get("name"), "kind": kind, "target_id": props.get(key),
                                     "audit_logs": audit})
    return {"diagnostic_settings_read": True, "destinations": destinations,
            "audit_logs_exported": any(d["audit_logs"] for d in destinations)}


def host_subnet_id(raw: Dict[str, Any]) -> Optional[str]:
    configs = dig(raw, "properties", "ipConfigurations") or []
    return dig(configs[0], "properties", "subnet", "id") if configs else None


def host_record(raw: Dict[str, Any], subnet: Optional[Dict[str, Any]], subnet_read: bool, settings) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    configs = props.get("ipConfigurations") or []
    subnet_id = host_subnet_id(raw)
    # The Developer SKU attaches to a virtual network without a subnet of its own.
    vnet_id = arm_id_key(dig(props, "virtualNetwork", "id")) or vnet_id_of(subnet_id) or None
    nsg_id = dig(subnet or {}, "properties", "networkSecurityGroup", "id") if subnet_read else None
    # sku sits at the top of a bastionHosts resource, beside properties, not inside it.
    sku = _lower(dig(raw, "sku", "name") or dig(props, "sku", "name")) or "unknown"

    def flag(key: str) -> Optional[bool]:
        """None when the API version in use does not report the feature at all."""
        return None if key not in props else props.get(key) is True

    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "resource_group": resource_group_from_id(raw.get("id")),
        "location": raw.get("location"),
        "zones": sorted(str(z) for z in raw.get("zones") or []),
        "sku": sku,
        "scale_units": props.get("scaleUnits"),
        "provisioning_state": props.get("provisioningState"),
        "dns_name": props.get("dnsName"),
        "virtual_network_id": vnet_id,
        "subnet_id": subnet_id,
        "subnet_read": subnet_read if subnet_id else None,
        "subnet_nsg_id": nsg_id,
        "subnet_has_nsg": bool(nsg_id) if (subnet_id and subnet_read) else None,
        "public_ip_ids": sorted({p for p in (dig(c, "properties", "publicIPAddress", "id") for c in configs) if p}),
        "shareable_links_enabled": props.get("enableShareableLink") is True,
        "ip_connect_enabled": props.get("enableIpConnect") is True,
        "native_client_tunneling_enabled": props.get("enableTunneling") is True,
        "file_copy_enabled": props.get("enableFileCopy") is True,
        "kerberos_enabled": props.get("enableKerberos") is True,
        "session_recording_enabled": flag("enableSessionRecording"),
        "private_only": flag("enablePrivateOnlyBastion"),
        "copy_paste_disabled": props.get("disableCopyPaste") is True,
        "ip_allowlist_rules": len(dig(props, "networkAcls", "ipRules") or []),
        "logs": audit_export(settings),
    }


# --- virtual machines ---

def vm_record(raw: Dict[str, Any], nics: Dict[str, Dict[str, Any]], bastion_vnets: Dict[str, List[Dict[str, str]]],
              peerings: Dict[str, List[Dict[str, Any]]],
              foreign_bastion_vnets: Dict[str, Optional[Dict[str, List[Dict[str, str]]]]]) -> Dict[str, Any]:
    """Where the VM sits and whether a Bastion in its VNet, or in a connected peered VNet, can reach it."""
    nic_ids = [dig(n, "id") for n in dig(raw, "properties", "networkProfile", "networkInterfaces") or []]
    vnets: Set[str] = set()
    public_ips: List[str] = []
    nics_read = True
    for nic_id in nic_ids:
        nic = nics.get(arm_id_key(nic_id))
        if nic is None:
            nics_read = False
            continue
        for config in dig(nic, "properties", "ipConfigurations") or []:
            vnet = vnet_id_of(dig(config, "properties", "subnet", "id"))
            if vnet:
                vnets.add(vnet)
            pip = dig(config, "properties", "publicIPAddress", "id")
            if pip:
                public_ips.append(pip)
    path, reached_by, unknown = NONE, [], False
    for vnet in sorted(vnets):
        local = bastion_vnets.get(vnet) or []
        ready = [h for h in local if h.get("state", "") in READY_STATES]
        if ready:
            path, reached_by = IN_VNET, [h["name"] for h in ready]
            break
        unknown = unknown or bool(local)  # a host is there but not in a ready state
        for peering in peerings.get(vnet) or []:
            remote = peering["remote_vnet_id"]
            if not peering["connected"]:
                continue
            # allowVirtualNetworkAccess on a link governs traffic leaving the VNet that link belongs to, so what lets a
            # session run from the Bastion's VNet to the VM is the link on the Bastion's side, when it can be read.
            back = [p for p in peerings.get(remote) or [] if p["remote_vnet_id"] == vnet]
            if remote in peerings and not any(p["connected"] and p["allows_vnet_access"] for p in back):
                continue
            hosts = list(bastion_vnets.get(remote) or [])
            foreign = foreign_bastion_vnets.get(_subscription_of(remote))
            if foreign is None and _subscription_of(remote) in foreign_bastion_vnets:
                unknown = True
            hosts += (foreign or {}).get(remote) or []
            # The Developer SKU does not reach peered virtual networks.
            candidates = [h for h in hosts if h["sku"] != "developer"]
            reaching = [h for h in candidates if h["sku"] != "unknown" and h.get("state", "") in READY_STATES]
            if reaching:
                path, reached_by = VIA_PEERING, [h["name"] for h in reaching]
                break
            unknown = unknown or bool(candidates)  # a host whose SKU or state is not known may or may not reach
        if path != NONE:
            break
    if path == NONE and (unknown or not nics_read or not vnets):
        path = UNKNOWN
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "resource_group": resource_group_from_id(raw.get("id")),
        "location": raw.get("location"),
        "virtual_network_ids": sorted(vnets),
        "network_interfaces_read": nics_read,
        "public_ip_ids": sorted(set(public_ips)),
        "bastion_path": path,
        "reached_by_bastions": sorted(reached_by),
    }


def peering_map(vnets: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for vnet in vnets:
        key = arm_id_key(vnet.get("id"))
        for peering in dig(vnet, "properties", "virtualNetworkPeerings") or []:
            props = peering.get("properties") or {}
            remote = arm_id_key(dig(props, "remoteVirtualNetwork", "id"))
            if remote:
                out.setdefault(key, []).append({"name": peering.get("name"), "remote_vnet_id": remote,
                                                "connected": _lower(props.get("peeringState")) == "connected",
                                                "allows_vnet_access": props.get("allowVirtualNetworkAccess") is not False})
    return out


# --- summary ---

def _known(items, key) -> Optional[int]:
    if any(i.get(key) is None for i in items):
        return None
    return sum(1 for i in items if i.get(key))


def summarize(hosts: List[Dict[str, Any]], vms: List[Dict[str, Any]], hosts_read: bool, vms_read: bool,
              vnets_read: bool, vm_list_read: Optional[bool] = None) -> Dict[str, Any]:
    """vms_read is the machine and interface lists together; vm_list_read the machine list alone (defaults to vms_read).
    A failed list is not an empty one, so every count that depends on it reads null, never a clean-looking 0."""
    vm_list_read = vms_read if vm_list_read is None else vm_list_read
    paths = Counter(v["bastion_path"] for v in vms)
    known = hosts_read and vms_read and vnets_read and paths[UNKNOWN] == 0
    with_path = paths[IN_VNET] + paths[VIA_PEERING]
    logs_known = all(h["logs"]["diagnostic_settings_read"] for h in hosts)
    with_subnet = [h for h in hosts if h["subnet_id"]]
    summary = {
        "bastion_hosts_read": hosts_read,
        "bastion_hosts": len(hosts),
        "bastion_hosts_by_sku": sorted_counts(Counter(h["sku"] for h in hosts)),
        "virtual_networks_with_bastion": len({arm_id_key(h["virtual_network_id"]) for h in hosts if h["virtual_network_id"]}),
        "bastion_hosts_with_public_ip": sum(1 for h in hosts if h["public_ip_ids"]),
        "bastion_hosts_private_only": sum(1 for h in hosts if h["private_only"] is True),
        "bastion_hosts_with_shareable_links": sum(1 for h in hosts if h["shareable_links_enabled"]),
        "bastion_hosts_with_ip_connect": sum(1 for h in hosts if h["ip_connect_enabled"]),
        "bastion_hosts_with_native_client_tunneling": sum(1 for h in hosts if h["native_client_tunneling_enabled"]),
        "bastion_hosts_with_file_copy": sum(1 for h in hosts if h["file_copy_enabled"]),
        "bastion_hosts_with_copy_paste_disabled": sum(1 for h in hosts if h["copy_paste_disabled"]),
        "bastion_hosts_with_kerberos": sum(1 for h in hosts if h["kerberos_enabled"]),
        "bastion_hosts_with_session_recording": sum(1 for h in hosts if h["session_recording_enabled"] is True),
        "bastion_hosts_with_ip_allowlist": sum(1 for h in hosts if h["ip_allowlist_rules"]),
        "bastion_hosts_with_subnet_nsg": _known(with_subnet, "subnet_has_nsg"),
        "bastion_hosts_without_subnet_nsg": None if any(h["subnet_has_nsg"] is None for h in with_subnet)
        else sum(1 for h in with_subnet if h["subnet_has_nsg"] is False),
        "bastion_hosts_exporting_audit_logs": None if not logs_known else sum(1 for h in hosts if h["logs"]["audit_logs_exported"]),
        "bastion_hosts_without_audit_log_export": None if not logs_known
        else sum(1 for h in hosts if not h["logs"]["audit_logs_exported"]),
        "virtual_machines_read": vms_read,
        "virtual_machines": len(vms),
        "virtual_machines_with_public_ip": None if (not vms_read or any(not v["network_interfaces_read"] for v in vms))
        else sum(1 for v in vms if v["public_ip_ids"]),
        # An in-VNet path needs the host list; a peering path needs the host and virtual network lists too.
        "virtual_machines_with_bastion_in_vnet": paths[IN_VNET] if vms_read and hosts_read else None,
        "virtual_machines_with_bastion_via_peering": paths[VIA_PEERING] if vms_read and hosts_read and vnets_read else None,
        "virtual_machines_without_bastion_path": paths[NONE] if known else None,
        "virtual_machines_with_unknown_bastion_path": paths[UNKNOWN],
        "bastion_path_percentage": coverage_percentage(with_path, len(vms)) if known else None,
    }
    if not hosts_read:
        summary.update({k: None for k in summary
                        if k.startswith("bastion_hosts") and k != "bastion_hosts_read"
                        or k == "virtual_networks_with_bastion"})
    if not vm_list_read:
        summary.update({"virtual_machines": None, "virtual_machines_with_unknown_bastion_path": None})
    return summary


# --- collection ---

def _list(client, path: str, api: str, operation: str, collector: Collector) -> Optional[List[Dict[str, Any]]]:
    """None when the list failed; a provider the subscription never registered has none of its resources."""
    def _read():
        try:
            return client.list(path, api)
        except ArmError as exc:
            if exc.code.lower() == "missingsubscriptionregistration":
                return []
            raise
    return collector.guard(operation, _read)


def _foreign_bastion_vnets(client, subscription: str) -> Optional[Dict[str, List[Dict[str, str]]]]:
    """{vnet id: [hosts]} for another subscription's Bastion hosts, when the credential may list them; None when it may not."""
    try:
        hosts = client.list(f"/subscriptions/{subscription}/providers/Microsoft.Network/bastionHosts", NETWORK_API)
    except ArmError as exc:
        if exc.status in (401, 403, 404) or exc.code.lower() == "missingsubscriptionregistration":
            logger.warning("bastion hosts in peered subscription %s could not be listed: %s", subscription, exc)
            return None if exc.status in (401, 403, 404) else {}
        raise
    out: Dict[str, List[Dict[str, str]]] = {}
    for host in hosts:
        subnet_id = host_subnet_id(host)
        vnet = dig(host, "properties", "virtualNetwork", "id") or (vnet_id_of(subnet_id) if subnet_id else "")
        if vnet:
            out.setdefault(arm_id_key(vnet), []).append({"name": f"{host.get('name')} (subscription {subscription})",
                                                        "sku": _lower(dig(host, "sku", "name") or dig(host, "properties", "sku", "name")) or "unknown",
                                                        "state": _lower(dig(host, "properties", "provisioningState"))})
    return out


def collect(client, subscription_id: str, collector: Collector, exclusions: Optional[ResourceExclusions] = None) -> tuple:
    exclusions = exclusions if exclusions is not None else ResourceExclusions()
    net = f"/subscriptions/{subscription_id}/providers/Microsoft.Network"
    raw_hosts = _list(client, f"{net}/bastionHosts", NETWORK_API, "network.bastionHosts.list", collector)
    raw_vms = _list(client, f"/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines", COMPUTE_API,
                    "compute.virtualMachines.list", collector)
    raw_nics = _list(client, f"{net}/networkInterfaces", NETWORK_API, "network.networkInterfaces.list", collector)
    raw_vnets = _list(client, f"{net}/virtualNetworks", NETWORK_API, "network.virtualNetworks.list", collector)
    hosts_read, vms_read = raw_hosts is not None, raw_vms is not None
    kept_hosts, excluded_hosts = exclusions.split(raw_hosts or [], "bastion_host")
    raw_vms, excluded_vms = exclusions.split(raw_vms or [], "virtual_machine")
    exclusions.record_invalid(collector)
    if not (hosts_read and vms_read):
        exclusions.mark_unread()
    exclusions.warn_unmatched(logger)

    subnets = {arm_id_key(sn.get("id")): sn for vnet in raw_vnets or [] for sn in dig(vnet, "properties", "subnets") or []}
    hosts: List[Dict[str, Any]] = []
    for raw in sorted(kept_hosts, key=lambda h: arm_id_key(h.get("id"))):
        subnet = subnets.get(arm_id_key(host_subnet_id(raw)))
        settings = collector.guard(
            f"insights.diagnosticSettings.list({raw.get('name')})",
            lambda rid=raw.get("id"): client.list(f"{rid}/providers/Microsoft.Insights/diagnosticSettings", DIAG_API),
        )
        hosts.append(host_record(raw, subnet, subnet is not None, settings))

    bastion_vnets: Dict[str, List[Dict[str, str]]] = {}
    for host in hosts:
        if host["virtual_network_id"]:
            bastion_vnets.setdefault(arm_id_key(host["virtual_network_id"]), []).append(
                {"name": host["name"], "sku": host["sku"], "state": _lower(host["provisioning_state"])})
    nics = {arm_id_key(n.get("id")): n for n in raw_nics or []}
    peerings = peering_map(raw_vnets or [])
    # A VNet peered from another subscription may hold the Bastion; its hosts are listed when the credential allows.
    foreign: Dict[str, Optional[Dict[str, List[Dict[str, str]]]]] = {}
    for links in peerings.values():
        for peering in links:
            other = _subscription_of(peering["remote_vnet_id"])
            if other and other != subscription_id.lower() and other not in foreign:
                foreign[other] = collector.guard(f"network.bastionHosts.list({other})",
                                                 lambda o=other: _foreign_bastion_vnets(client, o))
    vms = [vm_record(raw, nics, bastion_vnets, peerings, foreign)
           for raw in sorted(raw_vms, key=lambda v: arm_id_key(v.get("id")))]
    # Without the host, interface or virtual network list no "none" verdict can be trusted.
    for vm in vms:
        if raw_nics is None:
            vm["network_interfaces_read"] = False
        if vm["bastion_path"] == NONE and (raw_hosts is None or raw_nics is None or raw_vnets is None):
            vm["bastion_path"] = UNKNOWN

    results = {
        "bastion_hosts": hosts,
        "virtual_machines": vms,
        "peered_subscriptions": {k: ({vn: sorted(h["name"] for h in hs) for vn, hs in sorted(v.items())} if v is not None else None)
                                 for k, v in sorted(foreign.items())},
        "excluded": sorted(excluded_hosts + excluded_vms, key=lambda e: arm_id_key(e.get("id"))),
    }
    summary = {**summarize(hosts, vms, hosts_read, vms_read and raw_nics is not None, raw_vnets is not None, vms_read),
               **exclusions.summary(excluded_hosts + excluded_vms, ("bastion_host", "virtual_machine"),
                                    {"bastion_hosts": len(hosts) if hosts_read else None,
                                     "virtual_machines": len(vms) if vms_read else None})}
    return results, summary


def collect_subscription(client, subscription_id: str, collector: Collector) -> tuple:
    return collect(client, subscription_id, collector, ResourceExclusions.from_env())


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect_subscription)


if __name__ == "__main__":
    sys.exit(main())
