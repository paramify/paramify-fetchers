#!/usr/bin/env python3
"""Azure private DNS zones: VNet links, record sets, and whether privatelink records point at live private endpoints."""

import ipaddress
import json
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
    arm_client_kwargs,
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    lookup_status,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    resource_group_scope_of,
    sanitize_for_filename,
    subscription_of,
    write_evidence,
)
from private_dns import project_vnet_link, project_zone_group  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402
from resource_graph import (  # noqa: E402
    lookup_by_ids,
    query_all,
    quoted_ids,
    readable_scopes,
    resource_graph_client,
)

logger = logging.getLogger("azure_private_dns_zone_configuration")

RECORD_STATUSES = (
    "backed",
    "partially_backed",
    "ip_mismatch",
    "endpoint_not_approved",
    "stale",
    "platform_managed",
    "no_addresses",
    "unverified",
    "unknown",
)
# When a record's IPs disagree and none is backed, the record carries the most serious.
IP_STATUS_SEVERITY = ("ip_mismatch", "endpoint_not_approved", "stale", "unknown", "unverified", "platform_managed")
# Something other than an Approved endpoint serving the record holds the IP in a VNet the zone resolves for.
NETWORK_FINDINGS = frozenset({"ip_mismatch", "endpoint_not_approved", "platform_managed"})
# Zones whose public name differs from the private-link zone with "privatelink" removed.
PUBLIC_SUFFIX_ALIASES = {
    "vaultcore.azure.net": "vault.azure.net",
    "vaultcore.usgovcloudapi.net": "vault.usgovcloudapi.net",
    "vaultcore.azure.cn": "vault.azure.cn",
}
# mv-expand defaults to 128 rows per input row. A NIC holds at most 256 IP configurations, so
# 2000 can never cut one short.
MV_EXPAND_LIMIT = 2000

# Every private endpoint NIC IP the credential can see, with the FQDNs it serves and the subnet it sits in.
ENDPOINT_IPS_QUERY = (
    "Resources | where type =~ 'microsoft.network/networkinterfaces' "
    "and isnotnull(properties.privateEndpoint) "
    f"| mv-expand ipc = properties.ipConfigurations limit {MV_EXPAND_LIMIT} "
    "| project id, ip = tostring(ipc.properties.privateIPAddress), "
    "private_endpoint_id = tostring(properties.privateEndpoint.id), "
    "fqdns = ipc.properties.privateLinkConnectionProperties.fqdns, "
    "subnet_id = tostring(ipc.properties.subnet.id) "
    "| order by id asc, ip asc"
)

# Private IPs held by something other than a private endpoint: ordinary NICs and internal load balancer
# frontends (an AKS private cluster's API server sits behind one).
OTHER_NIC_IPS_QUERY = (
    "Resources | where type =~ 'microsoft.network/networkinterfaces' "
    "and isnull(properties.privateEndpoint) "
    f"| mv-expand ipc = properties.ipConfigurations limit {MV_EXPAND_LIMIT} "
    "| project id, ip = tostring(ipc.properties.privateIPAddress), subnet_id = tostring(ipc.properties.subnet.id) "
    "| where isnotempty(ip) | order by id asc, ip asc"
)
LOAD_BALANCER_IPS_QUERY = (
    "Resources | where type =~ 'microsoft.network/loadbalancers' "
    f"| mv-expand fe = properties.frontendIPConfigurations limit {MV_EXPAND_LIMIT} "
    "| project id, ip = tostring(fe.properties.privateIPAddress), subnet_id = tostring(fe.properties.subnet.id) "
    "| where isnotempty(ip) | order by id asc, ip asc"
)

# Each private endpoint's connection states, so a record is backed only by an Approved endpoint.
ENDPOINT_STATUS_QUERY = (
    "Resources | where type =~ 'microsoft.network/privateendpoints' "
    "| project id, auto = properties.privateLinkServiceConnections, "
    "manual = properties.manualPrivateLinkServiceConnections "
    "| order by id asc"
)

# Every private DNS zone and VNet link the credential can see, for duplicates across subscriptions.
ZONES_QUERY = (
    "Resources | where type =~ 'microsoft.network/privatednszones' "
    "| project id, name = tolower(name) | order by id asc"
)
LINKS_QUERY = (
    "Resources | where type =~ 'microsoft.network/privatednszones/virtualnetworklinks' "
    "| project id, zone_id = tolower(tostring(split(tolower(id), '/virtualnetworklinks/')[0])), "
    "virtual_network_id = tostring(properties.virtualNetwork.id) "
    "| order by id asc"
)


def _networks(prefixes) -> list:
    nets = []
    for prefix in prefixes or []:
        try:
            nets.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError:
            pass
    return nets


def vnets_query(ids: list[str]) -> str:
    """The given VNets with address space, peerings, and each subnet's prefixes and IP configuration ids.

    A VNet read lists every IP configuration in its subnets, including NICs in resource groups the
    credential cannot read.
    """
    return (
        f"Resources | where type =~ 'microsoft.network/virtualnetworks' and id in~ ({quoted_ids(ids)}) "
        "| project id, address_prefixes = properties.addressSpace.addressPrefixes, "
        "peerings = properties.virtualNetworkPeerings, subnets = properties.subnets "
        "| order by id asc"
    )


def reverse_peers_query(ids: list[str]) -> str:
    """VNets with a Connected peering to one of the given VNets, each with the hubs it peers with: the spokes
    of a linked hub the credential can't read."""
    return (
        "Resources | where type =~ 'microsoft.network/virtualnetworks' "
        f"| mv-expand p = properties.virtualNetworkPeerings limit {MV_EXPAND_LIMIT} "
        f"| where tostring(p.properties.remoteVirtualNetwork.id) in~ ({quoted_ids(ids)}) "
        "and tostring(p.properties.peeringState) =~ 'Connected' "
        "| summarize hubs = make_set(tolower(tostring(p.properties.remoteVirtualNetwork.id))) by id "
        "| order by id asc"
    )


def spokes_by_hub(rows: dict, hubs, failed) -> dict:
    """Hub id → ids of the VNets peered with it, from reverse_peers_query rows; None for a hub whose query failed."""
    out: dict = {hub: set() for hub in hubs}
    for row in rows.values():
        found = row.get("hubs") or []
        for hub in json.loads(found) if isinstance(found, str) else found:
            out.setdefault(hub.lower(), set()).add((row.get("id") or "").lower())
    return {**out, **{hub: None for hub in failed}}


def vnet_of(subnet_id):
    """Lowercased VNet id from a subnet id; None when the id names no subnet.

    Split at the last /subnets/: a resource group or VNet may itself be named "subnets".
    """
    head, sep, _ = (subnet_id or "").lower().rpartition("/subnets/")
    return head if sep else None


def vnet_index(rows):
    """Lowercased VNet id → {"nets", "peers", "subnets"}; None when the query failed.

    peers are the VNets reached over a Connected peering. Each subnet carries its prefixes and the
    resource groups of every NIC holding an IP in it.
    """
    if rows is None:
        return None
    index = {}
    for row in rows:
        subnets = []
        for subnet in row.get("subnets") or []:
            props = (subnet or {}).get("properties") or {}
            prefixes = props.get("addressPrefixes") or ([props["addressPrefix"]] if props.get("addressPrefix") else [])
            holders = {
                resource_group_scope_of(cfg.get("id"))
                for cfg in props.get("ipConfigurations") or []
                if cfg.get("id")
            }
            subnets.append({"nets": _networks(prefixes), "holder_resource_groups": holders})
        peers = set()
        for peering in row.get("peerings") or []:
            props = (peering or {}).get("properties") or {}
            remote = ((props.get("remoteVirtualNetwork") or {}).get("id") or "").lower()
            if remote and str(props.get("peeringState") or "").lower() == "connected":
                peers.add(remote)
        index[(row.get("id") or "").lower()] = {
            "nets": _networks(row.get("address_prefixes")),
            "peers": peers,
            "subnets": subnets,
        }
    return index


def zone_networks(links, vnets, failed_vnets=frozenset(), spokes=None):
    """Lowercased ids of the VNets a zone resolves for: its linked VNets and the VNets peered with them.

    A peering is seen from either side: in a linked VNet's own list, or in a VNet whose Connected peering
    points at a linked VNet (`spokes`, hub → spokes, for linked hubs the credential can't read). None when
    the links could not be read, when the spokes of a linked hub could not be listed, or when the lookup of
    a VNet in the set failed.
    """
    if links is None or vnets is None:
        return None
    spokes = spokes or {}
    linked = {(link.get("virtual_network_id") or "").lower() for link in links if link.get("virtual_network_id")}
    if any(spokes.get(v, ()) is None for v in linked):
        return None
    networks = linked | {peer for v in linked for peer in (vnets.get(v) or {}).get("peers", ())}
    networks |= {spoke for v in linked for spoke in spokes.get(v, ())}
    networks |= {v for v, vnet in vnets.items() if vnet["peers"] & linked}
    return None if networks & set(failed_vnets) else networks


def link_status(vnet_id, vnets, scopes, failed_vnets=frozenset()) -> str:
    """found / not_found (deleted) / not_visible (scope unreadable) / unknown (lookup failed)."""
    key = (vnet_id or "").lower()
    found = vnets is not None and key in vnets
    return lookup_status(vnet_id, found, vnets is not None and key not in failed_vnets, scopes)


def _is_privatelink_label(label: str) -> bool:
    return label == "privatelink" or label.startswith("privatelink-")


def is_privatelink_zone(name) -> bool:
    """A Private Link zone: one of its labels is privatelink or privatelink-*, wherever it sits.

    Covers privatelink.blob.core.windows.net, AKS's <guid>.privatelink.<region>.azmk8s.io and
    Azure Virtual Desktop's privatelink-global.wvd.microsoft.com.
    """
    return any(_is_privatelink_label(label) for label in (name or "").lower().rstrip(".").split("."))


def public_suffix(zone_name) -> str:
    """The public DNS suffix a private-link zone shadows: the zone without its privatelink label."""
    labels = [label for label in (zone_name or "").lower().rstrip(".").split(".") if not _is_privatelink_label(label)]
    suffix = ".".join(labels)
    return PUBLIC_SUFFIX_ALIASES.get(suffix, suffix)


def endpoint_serves(record_name: str, record_fqdn: str, endpoint_fqdns: list, zone_name: str = "") -> bool:
    """Whether an endpoint's FQDNs name this record, service suffix included.

    The endpoint must publish either the record's full name (AKS keeps the privatelink label) or the
    record's name under the zone's public suffix: a blob record never matches the IP of acct.file… or
    acct.vault.azure.net. Key Vault's zone privatelink.vaultcore.azure.net maps to vault.azure.net (and
    likewise in Azure Government and Azure China).
    """
    name = (record_name or "").lower()
    full = (record_fqdn or "").lower().rstrip(".")
    public = f"{name}.{public_suffix(zone_name)}" if zone_name else None
    return any(f == full or (public and f == public) for f in endpoint_fqdns)


def project_zone(zone) -> dict:
    return {
        "id": model_attr(zone, "id"),
        "name": model_attr(zone, "name"),
        "tags": model_attr(zone, "tags") or {},
        "provisioning_state": model_attr(zone, "provisioning_state"),
        "number_of_record_sets": model_attr(zone, "number_of_record_sets"),
        "max_number_of_record_sets": model_attr(zone, "max_number_of_record_sets"),
        "number_of_virtual_network_links": model_attr(zone, "number_of_virtual_network_links"),
    }


def project_record_set(record) -> dict:
    cname = model_attr(record, "cname_record")
    return {
        "name": model_attr(record, "name"),
        "record_type": (model_attr(record, "type") or "").rsplit("/", 1)[-1],
        "fqdn": model_attr(record, "fqdn"),
        "ttl": model_attr(record, "ttl"),
        "is_auto_registered": bool(model_attr(record, "is_auto_registered") or False),
        "ip_addresses": [model_attr(a, "ipv4_address") for a in model_attr(record, "a_records") or []]
        + [model_attr(a, "ipv6_address") for a in model_attr(record, "aaaa_records") or []],
        "cname": model_attr(cname, "cname"),
    }


def endpoint_index(rows):
    """ip → [{private_endpoint_id, fqdns, virtual_network_id}] from the NIC query; None when the query failed."""
    if rows is None:
        return None
    index: dict = {}
    for row in rows:
        ip = row.get("ip")
        if ip:
            index.setdefault(ip, []).append(
                {
                    "private_endpoint_id": row.get("private_endpoint_id"),
                    "fqdns": [f.lower().rstrip(".") for f in row.get("fqdns") or []],
                    "virtual_network_id": vnet_of(row.get("subnet_id")),
                }
            )
    return index


def endpoint_approvals(rows):
    """Lowercased private endpoint id → True when every connection is Approved; None when the query failed."""
    if rows is None:
        return None
    out = {}
    for row in rows:
        conns = (row.get("auto") or []) + (row.get("manual") or [])
        states = [
            str((((c or {}).get("properties") or {}).get("privateLinkServiceConnectionState") or {}).get("status") or "")
            for c in conns
        ]
        out[(row.get("id") or "").lower()] = bool(states) and all(s.lower() == "approved" for s in states)
    return out


def holder_index(*row_sets):
    """IP → [{id, virtual_network_id}] of the non-endpoint resources holding it; None when any query failed."""
    if any(rows is None for rows in row_sets):
        return None
    index: dict = {}
    for rows in row_sets:
        for row in rows:
            if row.get("ip"):
                index.setdefault(row["ip"], []).append(
                    {"id": row.get("id"), "virtual_network_id": vnet_of(row.get("subnet_id"))}
                )
    return index


def status_in_network(addr, network, record, zone_name, held, others_here, vnets, approvals, others, scopes) -> tuple:
    """(status, private endpoint ids) for an IP within one VNet the zone resolves for.

    `held` / `others_here` are the private endpoints and other resources holding the IP in that VNet.
    """
    serving = [
        ep["private_endpoint_id"]
        for ep in held
        # An endpoint that publishes no FQDNs (a custom Private Link service) can only be matched by IP.
        if not ep["fqdns"] or endpoint_serves(record["name"], record["fqdn"], ep["fqdns"], zone_name)
    ]
    if serving:
        if approvals is None:
            return "unknown", serving
        if any(approvals.get((pid or "").lower()) for pid in serving):
            return "backed", serving
        return "endpoint_not_approved", serving
    if held:
        return "ip_mismatch", [ep["private_endpoint_id"] for ep in held]
    if others is None:
        return "unknown", []
    if others_here:
        return "platform_managed", []
    vnet = vnets.get(network)
    if vnet is None or addr is None:
        return "unverified", []
    if scopes is None:
        return "unknown", []
    # Subnets of one VNet never overlap, so at most one holds the IP.
    subnet = next((s for s in vnet["subnets"] if any(addr in net for net in s["nets"])), None)
    if subnet is None or any(rg not in scopes["resource_groups"] for rg in subnet["holder_resource_groups"]):
        return "unverified", []
    return "stale", []


def classify_ip(
    ip, record: dict, endpoints, vnets, zone_name="", approvals=None, others=None, scopes=None, networks=None
) -> tuple:
    """(status, private endpoint ids, VNets matched or None when a lookup it needs failed) for one IP of a privatelink A record.

    The IP is matched only in `networks`, the VNets the zone resolves for (zone_networks): those that
    hold it or whose address space contains it. An IP is not unique across a tenant, so a resource
    holding the same address in an unrelated VNet says nothing about this record.

    backed                — an Approved private endpoint holds the IP and serves this record's name
    endpoint_not_approved — the endpoint serving the name is Pending, Rejected or Disconnected
    ip_mismatch           — a private endpoint holds the IP but serves a different name
    platform_managed      — no private endpoint holds it, but a live NIC or internal load balancer does
                            (an AKS private cluster's API server, for one)
    stale                 — nothing holds the IP, it sits in a readable VNet, and every resource group with a
                            NIC in its subnet is readable, so an endpoint there could not have been missed
    unverified            — no readable VNet the zone resolves for holds or contains the IP (the zone has no
                            links, or its linked VNets are unreadable), a NIC in its subnet is in a resource
                            group the credential cannot read, or it falls in more than one of those VNets
                            and they disagree
    unknown               — a lookup this depends on failed; never reported as stale

    The fourth value is whether any of those VNets found a NETWORK_FINDINGS status for the IP.
    """
    if endpoints is None or vnets is None or networks is None:
        return "unknown", [], None, False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        addr = None
    held = [ep for ep in endpoints.get(ip, []) if ep["virtual_network_id"] in networks]
    others_held = [h for h in (others or {}).get(ip, []) if h["virtual_network_id"] in networks]
    matched = {h["virtual_network_id"] for h in held + others_held}
    if addr is not None:
        matched |= {v for v in networks if any(addr in net for net in (vnets.get(v) or {}).get("nets", ()))}
    if not matched:
        return ("unknown", [], None, False) if others is None else ("unverified", [], [], False)
    verdicts = [
        status_in_network(
            addr,
            v,
            record,
            zone_name,
            [ep for ep in held if ep["virtual_network_id"] == v],
            [h for h in others_held if h["virtual_network_id"] == v],
            vnets,
            approvals,
            others,
            scopes,
        )
        for v in sorted(matched)
    ]
    statuses = {status for status, _ in verdicts}
    ids = sorted({pid for _, pids in verdicts for pid in pids if pid})
    if len(statuses) == 1:
        [status] = statuses
    else:
        # Overlapping VNets the zone resolves for disagree: say so rather than pick one.
        status = "unknown" if "unknown" in statuses else "unverified"
    return status, ids, sorted(matched), bool(statuses & NETWORK_FINDINGS)


def record_status(ip_statuses: list) -> str:
    """backed only when every IP is; partially_backed when some are; no_addresses for a record with
    no IP at all; else the most serious."""
    if not ip_statuses:
        return "no_addresses"
    if all(s == "backed" for s in ip_statuses):
        return "backed"
    if "backed" in ip_statuses:
        return "partially_backed"
    for status in IP_STATUS_SEVERITY:
        if status in ip_statuses:
            return status
    return "unknown"


# zone_group_proof's input when no endpoint zone groups were read and none failed.
NO_ZONE_GROUPS: tuple = ({}, frozenset())


def fqdn_key(fqdn) -> str:
    return (fqdn or "").lower().rstrip(".")


def zone_group_index(groups_by_endpoint: dict) -> dict:
    """(zone id, FQDN) → [(endpoint id, IPs)] from each endpoint's projected private DNS zone groups."""
    index: dict = {}
    for endpoint_id, groups in groups_by_endpoint.items():
        for group in groups:
            for cfg in group["private_dns_zone_configs"]:
                for record_set in cfg["record_sets"]:
                    key = ((cfg["private_dns_zone_id"] or "").lower(), fqdn_key(record_set["fqdn"]))
                    index.setdefault(key, []).append((endpoint_id.lower(), frozenset(record_set["ip_addresses"])))
    return index


def zone_group_proof(record: dict, zone_id, endpoints, approvals, zone_groups) -> tuple:
    """(True, endpoint id) when an Approved private endpoint whose NIC holds every IP of the record registers it,
    through its own private DNS zone group, in this zone with this FQDN and exactly these IPs; (None, None) when a
    lookup that could have proved it failed; else (False, None).

    `zone_groups` is (zone_group_index, ids of endpoints whose zone groups could not be read), or None.
    """
    ips = frozenset(record["ip_addresses"])
    if not ips:
        return False, None
    if endpoints is None or zone_groups is None:
        return None, None
    registered, failed = zone_groups
    original = {(ep["private_endpoint_id"] or "").lower(): ep["private_endpoint_id"] for ip in ips for ep in endpoints.get(ip, [])}
    holders = [{(ep["private_endpoint_id"] or "").lower() for ep in endpoints.get(ip, [])} for ip in ips]
    candidates = set.intersection(*holders) - {""}
    if not candidates:
        return False, None
    unknown = bool(candidates & failed)
    for endpoint_id, registered_ips in registered.get(((zone_id or "").lower(), fqdn_key(record["fqdn"])), []):
        if endpoint_id in candidates and registered_ips == ips:
            if approvals is None:
                unknown = True
            elif approvals.get(endpoint_id):
                return True, original[endpoint_id]
    return (None, None) if unknown else (False, None)


def classify_record(
    record: dict,
    zone_name: str,
    endpoints,
    vnets,
    approvals=None,
    others=None,
    scopes=None,
    networks=None,
    zone_id=None,
    zone_groups=NO_ZONE_GROUPS,
) -> dict:
    """A privatelink A record with each IP's status, the VNets it was matched in, the record's overall status,
    and which proof backs it: its endpoint's own zone group, or the network match."""
    if not is_privatelink_zone(zone_name) or record["record_type"] != "A" or record["name"] == "@":
        return {**record, "private_endpoint_status": None, "private_endpoint_ids": []}
    per_ip, per_ip_networks, endpoint_ids, found = {}, {}, set(), set()
    for ip in record["ip_addresses"]:
        status, ids, matched, finding = classify_ip(
            ip, record, endpoints, vnets, zone_name, approvals, others, scopes, networks
        )
        per_ip[ip] = status
        per_ip_networks[ip] = matched
        endpoint_ids.update(ids)
        if finding:
            found.add(ip)
    network_backed = "backed" in per_ip.values()
    proof, proving_endpoint = zone_group_proof(record, zone_id, endpoints, approvals, zone_groups)
    # The proof never overrules what the zone's own VNets found holding an IP.
    provable = [ip for ip in per_ip if ip not in found]
    zone_group_backed = proof and bool(provable)
    if zone_group_backed:
        per_ip.update(dict.fromkeys(provable, "backed"))
        endpoint_ids.add(proving_endpoint)
    elif proof is None:
        # The zone groups that could have backed the record were not read: unknown, never stale.
        per_ip = {ip: "unknown" if status == "stale" else status for ip, status in per_ip.items()}
    return {
        **record,
        "ip_address_statuses": per_ip,
        "ip_address_networks": per_ip_networks,
        "private_endpoint_status": record_status(list(per_ip.values())),
        "private_endpoint_ids": sorted(endpoint_ids),
        "zone_group_backed": zone_group_backed,
        "backed_by": [p for p, ok in (("network", network_backed), ("zone_group", zone_group_backed)) if ok] or None,
    }


def zone_record(
    zone: dict,
    links,
    records,
    endpoints,
    vnets,
    scopes,
    approvals=None,
    others=None,
    failed_vnets=frozenset(),
    spokes=None,
    zone_groups=NO_ZONE_GROUPS,
) -> dict:
    """`links` / `records` are None when they could not be listed: unknown, never "none".

    `failed_vnets` are the VNets whose lookup failed: links to them and records of zones that resolve for them
    are unknown, while other zones are classified as usual. `spokes` is spokes_by_hub for unreadable linked hubs.
    `zone_groups` is collect_zone_groups' result, None when the endpoint lookup it needs failed.
    """
    networks = zone_networks(links, vnets, failed_vnets, spokes)
    if links is not None:
        links = sorted(
            (
                {**link, "virtual_network_status": link_status(link["virtual_network_id"], vnets, scopes, failed_vnets)}
                for link in links
            ),
            key=lambda r: r.get("id") or "",
        )
    if records is not None:
        records = sorted(
            (
                classify_record(
                    r, zone["name"], endpoints, vnets, approvals, others, scopes, networks, zone["id"], zone_groups
                )
                for r in records
                if r["record_type"] != "SOA"
            ),
            key=lambda r: (r["name"] or "", r["record_type"]),
        )
    return {
        **zone,
        "resource_group": resource_group_from_id(zone.get("id")),
        "is_privatelink_zone": is_privatelink_zone(zone["name"]),
        "virtual_network_links": links,
        "record_sets": records,
    }


def duplicate_zone_names(zones: list[dict], all_zones, all_links) -> list[dict]:
    """Zone names in this subscription that also exist elsewhere, with every copy's VNets.

    `all_zones` / `all_links` are every zone and link the credential can read across
    subscriptions; when that query failed they are None and only this subscription is
    compared.
    """
    if all_zones is None or all_links is None:
        all_zones = [{"id": z["id"], "name": z["name"].lower()} for z in zones]
        all_links = [
            {"zone_id": z["id"].lower(), "virtual_network_id": link["virtual_network_id"]}
            for z in zones
            for link in z["virtual_network_links"] or []
        ]
    vnets_by_zone: dict = {}
    for link in all_links:
        vnets_by_zone.setdefault((link.get("zone_id") or "").lower(), set()).add(
            link.get("virtual_network_id")
        )
    by_name: dict = {}
    for z in all_zones:
        by_name.setdefault(z.get("name") or "", []).append(z.get("id"))
    local = {z["name"].lower() for z in zones}
    return [
        {
            "name": name,
            "zone_ids": sorted(ids),
            "virtual_network_ids": sorted(
                {v for i in ids for v in vnets_by_zone.get((i or "").lower(), set()) if v}
            ),
        }
        for name, ids in sorted(by_name.items())
        if name in local and len(ids) > 1
    ]


def summarize(zones: list[dict], duplicates: list[dict], duplicates_scope: str) -> dict:
    links = [link for z in zones for link in z["virtual_network_links"] or []]
    pl_records = [
        r for z in zones for r in z["record_sets"] or [] if r.get("private_endpoint_status") is not None
    ]
    by_status = {s: 0 for s in RECORD_STATUSES}
    for r in pl_records:
        by_status[r["private_endpoint_status"]] += 1

    def links_with(status):
        return sum(1 for link in links if link["virtual_network_status"] == status)

    return {
        "total_zones": len(zones),
        "privatelink_zones": sum(1 for z in zones if z["is_privatelink_zone"]),
        "custom_zones": sum(1 for z in zones if not z["is_privatelink_zone"]),
        "zones_without_virtual_network_links": sum(1 for z in zones if z["virtual_network_links"] == []),
        # Zones whose links or record sets could not be listed: unknown, never "unlinked" or "no records".
        "zones_links_unknown": sum(1 for z in zones if z["virtual_network_links"] is None),
        "zones_records_unknown": sum(1 for z in zones if z["record_sets"] is None),
        "duplicate_zone_names": duplicates,
        "duplicate_zone_names_scope": duplicates_scope,
        "total_virtual_network_links": len(links),
        "links_with_auto_registration": sum(1 for link in links if link["registration_enabled"]),
        "links_with_nxdomain_redirect": sum(
            1 for link in links if str(link["resolution_policy"] or "").lower() == "nxdomainredirect"
        ),
        "links_to_deleted_virtual_networks": links_with("not_found"),
        "links_to_unreadable_virtual_networks": links_with("not_visible"),
        "links_virtual_network_unknown": links_with("unknown"),
        "links_not_completed": sum(
            1 for link in links if str(link["virtual_network_link_state"] or "").lower() != "completed"
        ),
        "privatelink_a_records": len(pl_records),
        **{f"privatelink_records_{s}": by_status[s] for s in RECORD_STATUSES},
        "privatelink_records_backed_percentage": coverage_percentage(by_status["backed"], len(pl_records)),
    }


def collect_zone_groups(cred, endpoint_ids, collector: Collector) -> tuple:
    """(zone_group_index, lowercased ids of the endpoints whose zone groups could not be read).

    Read per endpoint with private_dns_zone_groups.list, each in its own subscription; a failed read is recorded
    and leaves only that endpoint's zone groups unknown.
    """
    by_id: dict = {}
    for endpoint_id in endpoint_ids:
        if endpoint_id:
            by_id.setdefault(endpoint_id.lower(), endpoint_id)
    clients: dict = {}
    groups, failed = {}, set()
    for key, endpoint_id in sorted(by_id.items()):
        sub, rg, name = subscription_of(endpoint_id), resource_group_from_id(endpoint_id), basename(endpoint_id)
        if sub not in clients:

            def _client(sub=sub):
                from azure.mgmt.network import NetworkManagementClient  # lazy

                return NetworkManagementClient(credential=cred, subscription_id=sub, **arm_client_kwargs())

            clients[sub] = collector.guard(f"network.NetworkManagementClient (init, {sub})", _client)
        client = clients[sub]
        read = None
        if client is not None:
            read = collector.guard(
                f"network.private_dns_zone_groups.list({rg}/{name})",
                lambda: [project_zone_group(g) for g in client.private_dns_zone_groups.list(name, rg)],
            )
        if read is None:
            failed.add(key)
        else:
            groups[key] = read
    return zone_group_index(groups), failed


def collect_zones(subscription_id, cred, collector: Collector) -> tuple:
    """(zone records, duplicate zone names, the scope duplicates were compared across)."""

    def _client():
        from azure.mgmt.privatedns import PrivateDnsManagementClient  # lazy

        return PrivateDnsManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("privatedns.PrivateDnsManagementClient (init)", _client)
    if client is None:
        return [], [], None
    zones = collector.guard(
        "privatedns.private_zones.list",
        lambda: [project_zone(z) for z in client.private_zones.list()],
        default=[],
    )
    if not zones:
        return [], [], None
    links, records = {}, {}
    for zone in zones:
        rg = resource_group_from_id(zone.get("id"))
        # No default: a failed list is None (unknown), never an unlinked zone or a zone with no records.
        links[zone["id"]] = collector.guard(
            f"privatedns.virtual_network_links.list({rg}/{zone['name']})",
            lambda: [project_vnet_link(link) for link in client.virtual_network_links.list(rg, zone["name"])],
        )
        records[zone["id"]] = collector.guard(
            f"privatedns.record_sets.list({rg}/{zone['name']})",
            lambda: [project_record_set(r) for r in client.record_sets.list(rg, zone["name"])],
        )

    graph = collector.guard("resourcegraph.ResourceGraphClient (init)", lambda: resource_graph_client(cred))

    def _graph(label, query):
        # Unscoped: endpoints, NICs and VNets in other readable subscriptions resolve too.
        if graph is None:
            return None
        return collector.guard(f"resourcegraph.resources ({label})", lambda: query_all(graph, None, query)["rows"])

    def _linked(privatelink_only: bool) -> set:
        return {
            link["virtual_network_id"].lower()
            for z in zones
            if not privatelink_only or is_privatelink_zone(z["name"])
            for link in links[z["id"]] or []
            if link["virtual_network_id"]
        }

    endpoints, approvals, others = {}, {}, {}
    if any(is_privatelink_zone(z["name"]) for z in zones):
        endpoints = endpoint_index(_graph("private endpoint NICs", ENDPOINT_IPS_QUERY))
        approvals = endpoint_approvals(_graph("private endpoint connection states", ENDPOINT_STATUS_QUERY))
        others = holder_index(
            _graph("other NIC IPs", OTHER_NIC_IPS_QUERY), _graph("load balancer frontend IPs", LOAD_BALANCER_IPS_QUERY)
        )
    # Only the VNets the zones resolve for: every linked VNet, then the VNets peered with a private-link zone's.
    # A failed chunk leaves only its own VNets unknown, and with them the zones that resolve for them.
    vnets, failed_vnets, spokes = None, set(), {}
    if graph is not None:
        linked = _linked(False)
        rows, failed_vnets = lookup_by_ids(graph, linked, vnets_query, "linked virtual networks", collector)
        read = vnet_index(list(rows.values()))
        privatelink_linked = _linked(True)
        peers = {p for v in privatelink_linked for p in (read.get(v) or {}).get("peers", ())}
        # A linked VNet the credential can't read lists no peers: find the readable VNets peered with it instead.
        unread = privatelink_linked - set(read) - failed_vnets
        # A failed query leaves those hubs' zones unknown (None in spokes) but their links as already read.
        spoke_rows, failed_unread = lookup_by_ids(
            graph, unread, reverse_peers_query, "VNets peered with unreadable linked VNets", collector
        )
        spokes = spokes_by_hub(spoke_rows, unread, failed_unread)
        peer_rows, failed_peers = lookup_by_ids(
            graph, (peers | set(spoke_rows)) - linked, vnets_query, "peered virtual networks", collector
        )
        vnets = vnet_index(list(rows.values()) + list(peer_rows.values()))
        failed_vnets |= failed_peers
    scopes = readable_scopes(cred, collector)
    # Zone groups of the endpoints whose NIC holds a privatelink A record's IP: proof that does not depend on topology.
    zone_groups = None
    if endpoints is not None:
        record_ips = {
            ip
            for z in zones
            if is_privatelink_zone(z["name"])
            for r in records[z["id"]] or []
            if r["record_type"] == "A"
            for ip in r["ip_addresses"]
        }
        holders = {ep["private_endpoint_id"] for ip in record_ips for ep in endpoints.get(ip, [])}
        zone_groups = collect_zone_groups(cred, holders, collector)
    out = sorted(
        (
            zone_record(
                z,
                links[z["id"]],
                records[z["id"]],
                endpoints,
                vnets,
                scopes,
                approvals,
                others,
                failed_vnets,
                spokes,
                zone_groups,
            )
            for z in zones
        ),
        key=lambda r: r.get("id") or "",
    )
    all_zones = _graph("private DNS zones", ZONES_QUERY)
    all_links = _graph("private DNS zone links", LINKS_QUERY)
    scope = "target_subscription" if all_zones is None or all_links is None else "readable_subscriptions"
    return out, duplicate_zone_names(out, all_zones, all_links), scope


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

    zones: list[dict] = []
    duplicates: list[dict] = []
    duplicates_scope = None
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Network")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Network is not registered on subscription %s — reporting status not_registered",
                subscription_id,
            )
        zones, duplicates, duplicates_scope = collect_zones(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    # Records were classified and duplicates found against every zone first, so in-scope verdicts don't change.
    exclusions = ResourceExclusions.from_env()
    exclusions.record_invalid(collector)
    # A private DNS zone is global, so only rg: and id: patterns can take one out.
    zones, excluded = exclusions.split(zones, "private_dns_zone", location=lambda z: None)
    in_scope_names = {z["name"].lower() for z in zones}
    duplicates = [d for d in duplicates if d["name"] in in_scope_names]
    exclusions.warn_unmatched(logger)

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={"private_zones": zones, "provider_registration_status": registration, "excluded": excluded},
        summary={
            **summarize(zones, duplicates, duplicates_scope),
            "provider_registration_status": registration,
            **exclusions.summary(excluded, ("private_dns_zone",), {"private_dns_zones": len(zones)}),
        },
    )
    filename = f"azure_private_dns_zone_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
