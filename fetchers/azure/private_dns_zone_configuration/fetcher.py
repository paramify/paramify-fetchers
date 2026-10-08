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
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    lookup_status,
    model_attr,
    provider_registration_status,
    readable_scopes,
    report_failure,
    resolve_subscription,
    resource_graph_rows,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)

logger = logging.getLogger("azure_private_dns_zone_configuration")

PRIVATELINK_PREFIX = "privatelink."
RECORD_STATUSES = ("backed", "partially_backed", "ip_mismatch", "stale", "unverified", "unknown")
# When a record's IPs disagree and none is backed, the record carries the most serious.
IP_STATUS_SEVERITY = ("ip_mismatch", "stale", "unknown", "unverified")

VNETS_QUERY = (
    "Resources | where type =~ 'microsoft.network/virtualnetworks' "
    "| project id, address_prefixes = properties.addressSpace.addressPrefixes"
)

# Every private endpoint NIC IP the credential can see, with the FQDNs it serves.
ENDPOINT_IPS_QUERY = (
    "Resources | where type =~ 'microsoft.network/networkinterfaces' "
    "and isnotnull(properties.privateEndpoint) "
    "| mv-expand ipc = properties.ipConfigurations "
    "| project ip = tostring(ipc.properties.privateIPAddress), "
    "private_endpoint_id = tostring(properties.privateEndpoint.id), "
    "fqdns = ipc.properties.privateLinkConnectionProperties.fqdns"
)

# Every private DNS zone and VNet link the credential can see, for duplicates across subscriptions.
ZONES_QUERY = (
    "Resources | where type =~ 'microsoft.network/privatednszones' "
    "| project id, name = tolower(name)"
)
LINKS_QUERY = (
    "Resources | where type =~ 'microsoft.network/privatednszones/virtualnetworklinks' "
    "| project zone_id = tolower(tostring(split(tolower(id), '/virtualnetworklinks/')[0])), "
    "virtual_network_id = tostring(properties.virtualNetwork.id)"
)


def vnet_index(rows):
    """Lowercased VNet id → its address prefixes as ip_network objects; None when the query failed."""
    if rows is None:
        return None
    index = {}
    for row in rows:
        nets = []
        for prefix in row.get("address_prefixes") or []:
            try:
                nets.append(ipaddress.ip_network(prefix, strict=False))
            except ValueError:
                pass
        index[(row.get("id") or "").lower()] = nets
    return index


def in_visible_vnet(ip, vnets: dict) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for nets in vnets.values() for net in nets)


def link_status(vnet_id, vnets, scopes) -> str:
    """found / not_found (deleted) / not_visible (scope unreadable) / unknown (lookup failed)."""
    found = vnets is not None and (vnet_id or "").lower() in vnets
    return lookup_status(vnet_id, found, vnets is not None, scopes)


def is_privatelink_zone(name) -> bool:
    return (name or "").lower().startswith(PRIVATELINK_PREFIX)


def endpoint_serves(record_name: str, record_fqdn: str, endpoint_fqdns: list) -> bool:
    """Whether an endpoint's FQDNs name this record.

    Matched on the record's own name, not on a public name derived from the zone:
    Key Vault's zone is privatelink.vaultcore.azure.net while its FQDN is
    <vault>.vault.azure.net, and AKS FQDNs keep the privatelink label. Every
    service's endpoint FQDN starts with the record's relative name, and for AKS
    it is the record's full name.
    """
    name = (record_name or "").lower()
    full = (record_fqdn or "").lower().rstrip(".")
    return any(f == full or f.startswith(name + ".") for f in endpoint_fqdns)


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


def project_link(link) -> dict:
    vnet_id = model_attr(model_attr(link, "virtual_network"), "id")
    return {
        "id": model_attr(link, "id"),
        "name": model_attr(link, "name"),
        "virtual_network_id": vnet_id,
        "virtual_network_name": basename(vnet_id),
        "registration_enabled": bool(model_attr(link, "registration_enabled") or False),
        "resolution_policy": model_attr(link, "resolution_policy"),
        "virtual_network_link_state": model_attr(link, "virtual_network_link_state"),
        "provisioning_state": model_attr(link, "provisioning_state"),
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


def classify_ip(ip, record: dict, endpoints, vnets) -> tuple:
    """(status, private endpoint ids) for one IP of a privatelink A record.

    backed      — a private endpoint holds the IP and serves this record's name
    ip_mismatch — a private endpoint holds the IP but serves a different name
    stale       — no private endpoint holds the IP, and it sits in a VNet this credential can read
    unverified  — no visible private endpoint holds the IP, and it is outside every readable VNet
    unknown     — a lookup this depends on failed; never reported as stale
    """
    held = (endpoints or {}).get(ip, [])
    serving = [
        ep["private_endpoint_id"]
        for ep in held
        # An endpoint that publishes no FQDNs (a custom Private Link service) can only be matched by IP.
        if not ep["fqdns"] or endpoint_serves(record["name"], record["fqdn"], ep["fqdns"])
    ]
    if serving:
        return "backed", serving
    if held:
        return "ip_mismatch", [ep["private_endpoint_id"] for ep in held]
    if endpoints is None or vnets is None:
        return "unknown", []
    return ("stale" if in_visible_vnet(ip, vnets) else "unverified"), []


def record_status(ip_statuses: list) -> str:
    """backed only when every IP is; partially_backed when some are; else the most serious."""
    if ip_statuses and all(s == "backed" for s in ip_statuses):
        return "backed"
    if "backed" in ip_statuses:
        return "partially_backed"
    for status in IP_STATUS_SEVERITY:
        if status in ip_statuses:
            return status
    return "unknown"


def classify_record(record: dict, zone_name: str, endpoints, vnets) -> dict:
    """A privatelink A record with each IP's status and the record's overall status."""
    if not is_privatelink_zone(zone_name) or record["record_type"] != "A" or record["name"] == "@":
        return {**record, "private_endpoint_status": None, "private_endpoint_ids": []}
    per_ip, endpoint_ids = {}, set()
    for ip in record["ip_addresses"]:
        status, ids = classify_ip(ip, record, endpoints, vnets)
        per_ip[ip] = status
        endpoint_ids.update(ids)
    return {
        **record,
        "ip_address_statuses": per_ip,
        "private_endpoint_status": record_status(list(per_ip.values())),
        "private_endpoint_ids": sorted(endpoint_ids),
    }


def zone_record(zone: dict, links: list, records: list, endpoints, vnets, scopes) -> dict:
    links = [
        {**link, "virtual_network_status": link_status(link["virtual_network_id"], vnets, scopes)}
        for link in links
    ]
    records = [
        classify_record(r, zone["name"], endpoints, vnets) for r in records if r["record_type"] != "SOA"
    ]
    return {
        **zone,
        "resource_group": resource_group_from_id(zone.get("id")),
        "is_privatelink_zone": is_privatelink_zone(zone["name"]),
        "virtual_network_links": sorted(links, key=lambda r: r.get("id") or ""),
        "record_sets": sorted(records, key=lambda r: (r["name"] or "", r["record_type"])),
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
            for link in z["virtual_network_links"]
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
    links = [link for z in zones for link in z["virtual_network_links"]]
    pl_records = [
        r for z in zones for r in z["record_sets"] if r.get("private_endpoint_status") is not None
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
        "zones_without_virtual_network_links": sum(1 for z in zones if not z["virtual_network_links"]),
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
        links[zone["id"]] = collector.guard(
            f"privatedns.virtual_network_links.list({rg}/{zone['name']})",
            lambda: [project_link(link) for link in client.virtual_network_links.list(rg, zone["name"])],
            default=[],
        )
        records[zone["id"]] = collector.guard(
            f"privatedns.record_sets.list({rg}/{zone['name']})",
            lambda: [project_record_set(r) for r in client.record_sets.list(rg, zone["name"])],
            default=[],
        )

    def _graph(label, query):
        return collector.guard(f"resourcegraph.resources ({label})", lambda: resource_graph_rows(cred, query))

    endpoints = {}
    if any(is_privatelink_zone(z["name"]) for z in zones):
        endpoints = endpoint_index(_graph("private endpoint NICs", ENDPOINT_IPS_QUERY))
    vnets = vnet_index(_graph("virtual networks", VNETS_QUERY))
    scopes = readable_scopes(cred, collector)
    out = sorted(
        (zone_record(z, links[z["id"]], records[z["id"]], endpoints, vnets, scopes) for z in zones),
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
