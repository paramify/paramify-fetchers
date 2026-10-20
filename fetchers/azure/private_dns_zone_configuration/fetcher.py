#!/usr/bin/env python3
"""Azure private DNS zones: VNet links, record sets, and whether privatelink records point at live private endpoints."""

import ipaddress
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
    write_evidence,
)
from private_dns import project_vnet_link  # noqa: E402
from resource_graph import (  # noqa: E402
    query_all,
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
# Zones whose public name differs from the private-link zone with "privatelink" removed.
PUBLIC_SUFFIX_ALIASES = {"vaultcore.azure.net": "vault.azure.net"}
# mv-expand defaults to 128 rows per input row. A NIC holds at most 256 IP configurations, so
# 2000 can never cut one short.
MV_EXPAND_LIMIT = 2000

# Every VNet with its address space and each subnet's prefixes and IP configuration ids. A VNet read
# lists every IP configuration in its subnets, including NICs in resource groups the credential cannot read.
VNETS_QUERY = (
    "Resources | where type =~ 'microsoft.network/virtualnetworks' "
    "| project id, address_prefixes = properties.addressSpace.addressPrefixes, subnets = properties.subnets "
    "| order by id asc"
)

# Every private endpoint NIC IP the credential can see, with the FQDNs it serves.
ENDPOINT_IPS_QUERY = (
    "Resources | where type =~ 'microsoft.network/networkinterfaces' "
    "and isnotnull(properties.privateEndpoint) "
    f"| mv-expand limit {MV_EXPAND_LIMIT} ipc = properties.ipConfigurations "
    "| project id, ip = tostring(ipc.properties.privateIPAddress), "
    "private_endpoint_id = tostring(properties.privateEndpoint.id), "
    "fqdns = ipc.properties.privateLinkConnectionProperties.fqdns "
    "| order by id asc, ip asc"
)

# Private IPs held by something other than a private endpoint: ordinary NICs and internal load balancer
# frontends (an AKS private cluster's API server sits behind one).
OTHER_NIC_IPS_QUERY = (
    "Resources | where type =~ 'microsoft.network/networkinterfaces' "
    "and isnull(properties.privateEndpoint) "
    f"| mv-expand limit {MV_EXPAND_LIMIT} ipc = properties.ipConfigurations "
    "| project id, ip = tostring(ipc.properties.privateIPAddress) "
    "| where isnotempty(ip) | order by id asc, ip asc"
)
LOAD_BALANCER_IPS_QUERY = (
    "Resources | where type =~ 'microsoft.network/loadbalancers' "
    f"| mv-expand limit {MV_EXPAND_LIMIT} fe = properties.frontendIPConfigurations "
    "| project id, ip = tostring(fe.properties.privateIPAddress) "
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


def vnet_index(rows):
    """Lowercased VNet id → {"nets", "subnets"}; None when the query failed.

    Each subnet carries its prefixes and the resource groups of every NIC holding an IP in it.
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
        index[(row.get("id") or "").lower()] = {"nets": _networks(row.get("address_prefixes")), "subnets": subnets}
    return index


def containing_network(ip, vnets: dict):
    """(in a readable VNet, the subnet holding the IP or None)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, None
    for vnet in vnets.values():
        if any(addr in net for net in vnet["nets"]):
            for subnet in vnet["subnets"]:
                if any(addr in net for net in subnet["nets"]):
                    return True, subnet
            return True, None
    return False, None


def link_status(vnet_id, vnets, scopes) -> str:
    """found / not_found (deleted) / not_visible (scope unreadable) / unknown (lookup failed)."""
    found = vnets is not None and (vnet_id or "").lower() in vnets
    return lookup_status(vnet_id, found, vnets is not None, scopes)


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
    acct.vault.azure.net. Key Vault's zone privatelink.vaultcore.azure.net maps to vault.azure.net.
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
    """ip → [{private_endpoint_id, fqdns}] from the NIC query; None when the query failed."""
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
    """IP → ids of the non-endpoint resources holding it; None when any query failed."""
    if any(rows is None for rows in row_sets):
        return None
    index: dict = {}
    for rows in row_sets:
        for row in rows:
            if row.get("ip"):
                index.setdefault(row["ip"], []).append(row.get("id"))
    return index


def classify_ip(ip, record: dict, endpoints, vnets, zone_name="", approvals=None, others=None, scopes=None) -> tuple:
    """(status, private endpoint ids) for one IP of a privatelink A record.

    backed                — an Approved private endpoint holds the IP and serves this record's name
    endpoint_not_approved — the endpoint serving the name is Pending, Rejected or Disconnected
    ip_mismatch           — a private endpoint holds the IP but serves a different name
    platform_managed      — no private endpoint holds it, but a live NIC or internal load balancer does
                            (an AKS private cluster's API server, for one)
    stale                 — nothing holds the IP, it sits in a readable VNet, and every resource group with a
                            NIC in its subnet is readable, so an endpoint there could not have been missed
    unverified            — nothing visible holds it and it is outside every readable VNet, or a NIC in its
                            subnet is in a resource group the credential cannot read
    unknown               — a lookup this depends on failed; never reported as stale
    """
    held = (endpoints or {}).get(ip, [])
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
    if endpoints is None or vnets is None or others is None:
        return "unknown", []
    if others.get(ip):
        return "platform_managed", []
    in_vnet, subnet = containing_network(ip, vnets)
    if not in_vnet:
        return "unverified", []
    if scopes is None:
        return "unknown", []
    holders = subnet["holder_resource_groups"] if subnet else set()
    if subnet is None or any(rg not in scopes["resource_groups"] for rg in holders):
        return "unverified", []
    return "stale", []


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


def classify_record(record: dict, zone_name: str, endpoints, vnets, approvals=None, others=None, scopes=None) -> dict:
    """A privatelink A record with each IP's status and the record's overall status."""
    if not is_privatelink_zone(zone_name) or record["record_type"] != "A" or record["name"] == "@":
        return {**record, "private_endpoint_status": None, "private_endpoint_ids": []}
    per_ip, endpoint_ids = {}, set()
    for ip in record["ip_addresses"]:
        status, ids = classify_ip(ip, record, endpoints, vnets, zone_name, approvals, others, scopes)
        per_ip[ip] = status
        endpoint_ids.update(ids)
    return {
        **record,
        "ip_address_statuses": per_ip,
        "private_endpoint_status": record_status(list(per_ip.values())),
        "private_endpoint_ids": sorted(endpoint_ids),
    }


def zone_record(zone: dict, links, records, endpoints, vnets, scopes, approvals=None, others=None) -> dict:
    """`links` / `records` are None when they could not be listed: unknown, never "none"."""
    if links is not None:
        links = sorted(
            ({**link, "virtual_network_status": link_status(link["virtual_network_id"], vnets, scopes)} for link in links),
            key=lambda r: r.get("id") or "",
        )
    if records is not None:
        records = sorted(
            (
                classify_record(r, zone["name"], endpoints, vnets, approvals, others, scopes)
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

    endpoints, approvals, others = {}, {}, {}
    if any(is_privatelink_zone(z["name"]) for z in zones):
        endpoints = endpoint_index(_graph("private endpoint NICs", ENDPOINT_IPS_QUERY))
        approvals = endpoint_approvals(_graph("private endpoint connection states", ENDPOINT_STATUS_QUERY))
        others = holder_index(
            _graph("other NIC IPs", OTHER_NIC_IPS_QUERY), _graph("load balancer frontend IPs", LOAD_BALANCER_IPS_QUERY)
        )
    vnets = vnet_index(_graph("virtual networks", VNETS_QUERY))
    scopes = readable_scopes(cred, collector)
    out = sorted(
        (
            zone_record(z, links[z["id"]], records[z["id"]], endpoints, vnets, scopes, approvals, others)
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

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={"private_zones": zones, "provider_registration_status": registration},
        summary={
            **summarize(zones, duplicates, duplicates_scope),
            "provider_registration_status": registration,
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
