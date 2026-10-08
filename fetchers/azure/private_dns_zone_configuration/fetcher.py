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
    report_failure,
    resolve_subscription,
    resource_graph_rows,
    resource_group_from_id,
    sanitize_for_filename,
    visible_subscription_ids,
    write_evidence,
)

logger = logging.getLogger("azure_private_dns_zone_configuration")

PRIVATELINK_PREFIX = "privatelink."
VNETS_QUERY = (
    "Resources | where type =~ 'microsoft.network/virtualnetworks' "
    "| project id, address_prefixes = properties.addressSpace.addressPrefixes"
)

# Every private endpoint NIC IP the credential can see, with the public FQDNs it serves.
ENDPOINT_IPS_QUERY = (
    "Resources | where type =~ 'microsoft.network/networkinterfaces' and isnotnull(properties.privateEndpoint) "
    "| mv-expand ipc = properties.ipConfigurations "
    "| project ip = tostring(ipc.properties.privateIPAddress), "
    "private_endpoint_id = tostring(properties.privateEndpoint.id), "
    "fqdns = ipc.properties.privateLinkConnectionProperties.fqdns"
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


def link_status(vnet_id, vnets, visible_subscriptions) -> str:
    """found / not_found (deleted) / not_visible (subscription unreadable) / unknown (lookup failed)."""
    found = vnets is not None and (vnet_id or "").lower() in vnets
    return lookup_status(vnet_id, found, vnets is not None, visible_subscriptions)


def is_privatelink_zone(name) -> bool:
    return (name or "").lower().startswith(PRIVATELINK_PREFIX)


def public_fqdn(record_name, zone_name):
    """`acct` in `privatelink.blob.core.windows.net` → `acct.blob.core.windows.net`."""
    suffix = zone_name[len(PRIVATELINK_PREFIX):]
    return f"{record_name}.{suffix}".lower()


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


def classify_record(record: dict, zone_name: str, endpoints, vnets) -> dict:
    """Whether a privatelink A record resolves to a private endpoint that serves its name.

    backed      — some IP belongs to a private endpoint that serves this name
    ip_mismatch — the IP belongs to a private endpoint serving a different name
    stale       — no private endpoint holds the IP, and it sits in a VNet this credential can read
    unverified  — no visible private endpoint holds the IP, and it is outside every readable VNet
    unknown     — a lookup this depends on failed; never reported as stale
    """
    if not is_privatelink_zone(zone_name) or record["record_type"] != "A" or record["name"] == "@":
        return {**record, "private_endpoint_status": None, "private_endpoint_ids": []}
    fqdn = public_fqdn(record["name"], zone_name)
    backed, mismatched = [], []
    for ip in record["ip_addresses"]:
        for ep in (endpoints or {}).get(ip, []):
            (backed if fqdn in ep["fqdns"] else mismatched).append(ep["private_endpoint_id"])
    if backed:
        status = "backed"
    elif mismatched:
        status = "ip_mismatch"
    elif endpoints is None or vnets is None:
        status = "unknown"
    elif any(in_visible_vnet(ip, vnets) for ip in record["ip_addresses"]):
        status = "stale"
    else:
        status = "unverified"
    return {
        **record,
        "public_fqdn": fqdn,
        "private_endpoint_status": status,
        "private_endpoint_ids": sorted(set(backed or mismatched)),
    }


def zone_record(
    zone: dict, links: list, records: list, endpoints, vnets, visible_subscriptions
) -> dict:
    links = [
        {**link, "virtual_network_status": link_status(link["virtual_network_id"], vnets, visible_subscriptions)}
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


def summarize(zones: list[dict]) -> dict:
    links = [link for z in zones for link in z["virtual_network_links"]]
    pl_records = [
        r for z in zones for r in z["record_sets"] if r.get("private_endpoint_status") is not None
    ]
    by_status = {s: 0 for s in ("backed", "ip_mismatch", "stale", "unverified", "unknown")}
    for r in pl_records:
        by_status[r["private_endpoint_status"]] += 1

    by_name: dict = {}
    for z in zones:
        by_name.setdefault(z["name"].lower(), []).append(z)
    duplicates = [
        {
            "name": name,
            "zone_ids": sorted(z["id"] for z in group),
            "virtual_network_ids": sorted(
                {link["virtual_network_id"] for z in group for link in z["virtual_network_links"]}
            ),
        }
        for name, group in sorted(by_name.items())
        if len(group) > 1
    ]
    return {
        "total_zones": len(zones),
        "privatelink_zones": sum(1 for z in zones if z["is_privatelink_zone"]),
        "custom_zones": sum(1 for z in zones if not z["is_privatelink_zone"]),
        "zones_without_virtual_network_links": sum(1 for z in zones if not z["virtual_network_links"]),
        "duplicate_zone_names": duplicates,
        "total_virtual_network_links": len(links),
        "links_with_auto_registration": sum(1 for link in links if link["registration_enabled"]),
        "links_with_nxdomain_redirect": sum(
            1 for link in links if str(link["resolution_policy"] or "").lower() == "nxdomainredirect"
        ),
        "links_to_deleted_virtual_networks": sum(
            1 for link in links if link["virtual_network_status"] == "not_found"
        ),
        "links_to_unreadable_virtual_networks": sum(
            1 for link in links if link["virtual_network_status"] == "not_visible"
        ),
        "links_virtual_network_unknown": sum(
            1 for link in links if link["virtual_network_status"] == "unknown"
        ),
        "links_not_completed": sum(
            1 for link in links if str(link["virtual_network_link_state"] or "").lower() != "completed"
        ),
        "privatelink_a_records": len(pl_records),
        "privatelink_records_backed": by_status["backed"],
        "privatelink_records_ip_mismatch": by_status["ip_mismatch"],
        "privatelink_records_stale": by_status["stale"],
        "privatelink_records_unverified": by_status["unverified"],
        "privatelink_records_unknown": by_status["unknown"],
        "privatelink_records_backed_percentage": coverage_percentage(by_status["backed"], len(pl_records)),
    }


def collect_zones(subscription_id, cred, collector: Collector) -> list[dict]:
    def _client():
        from azure.mgmt.privatedns import PrivateDnsManagementClient  # lazy

        return PrivateDnsManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("privatedns.PrivateDnsManagementClient (init)", _client)
    if client is None:
        return []
    zones = collector.guard(
        "privatedns.private_zones.list",
        lambda: [project_zone(z) for z in client.private_zones.list()],
        default=[],
    )
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

    if not zones:
        return []
    endpoints = {}
    if any(is_privatelink_zone(z["name"]) for z in zones):
        endpoints = endpoint_index(
            collector.guard(
                "resourcegraph.resources (private endpoint NICs)",
                lambda: resource_graph_rows(cred, ENDPOINT_IPS_QUERY),
            )
        )
    vnets = vnet_index(
        collector.guard(
            "resourcegraph.resources (virtual networks)",
            lambda: resource_graph_rows(cred, VNETS_QUERY),
        )
    )
    visible = visible_subscription_ids(cred, collector)
    out = [
        zone_record(z, links[z["id"]], records[z["id"]], endpoints, vnets, visible) for z in zones
    ]
    return sorted(out, key=lambda r: r.get("id") or "")


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
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Network")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Network is not registered on subscription %s — reporting status not_registered",
                subscription_id,
            )
        zones = collect_zones(subscription_id, cred, collector)
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
        summary={**summarize(zones), "provider_registration_status": registration},
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
