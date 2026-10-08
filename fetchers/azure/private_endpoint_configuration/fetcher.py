#!/usr/bin/env python3
"""Azure private endpoints: connection state, DNS zone groups, subnet policy, and the target's public network access."""

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
    dig,
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

logger = logging.getLogger("azure_private_endpoint_configuration")

STATUSES = ("Approved", "Pending", "Rejected", "Disconnected")
LOOKUP_CHUNK = 200
# privateEndpointNetworkPolicies values under which the subnet's NSG / route table apply to endpoint traffic.
NSG_POLICIES = ("enabled", "networksecuritygroupenabled")
ROUTE_TABLE_POLICIES = ("enabled", "routetableenabled")


def virtual_network_id(subnet_id):
    """VNet id from a subnet id: everything before `/subnets/`."""
    if not subnet_id:
        return None
    head, sep, _ = subnet_id.partition("/subnets/")
    return head if sep else None


def resource_type_from_id(resource_id):
    """`Microsoft.Web/sites` from an ARM id; None when the id has no provider segment."""
    parts = (resource_id or "").split("/")
    lowered = [p.lower() for p in parts]
    if "providers" not in lowered:
        return None
    i = len(lowered) - 1 - lowered[::-1].index("providers")
    if i + 2 >= len(parts):
        return None
    return f"{parts[i + 1]}/{parts[i + 2]}"


def checked_resource_id(target_id, group_ids):
    """The resource whose public access governs this connection.

    An App Service slot is private-linked through its parent site with group id
    "sites-<slot>", and the slot carries its own publicNetworkAccess.
    """
    if (resource_type_from_id(target_id) or "").lower() == "microsoft.web/sites":
        for group in group_ids or []:
            if group.lower().startswith("sites-") and len(group) > len("sites-"):
                return f"{target_id}/slots/{group[len('sites-'):]}"
    return target_id


def project_connection(conn, manual: bool) -> dict:
    state = model_attr(conn, "private_link_service_connection_state")
    target_id = model_attr(conn, "private_link_service_id")
    group_ids = model_attr(conn, "group_ids") or []
    checked_id = checked_resource_id(target_id, group_ids)
    return {
        "name": model_attr(conn, "name"),
        "manual": manual,
        "target_resource_id": target_id,
        "target_resource_name": basename(target_id),
        "target_resource_type": resource_type_from_id(target_id),
        "group_ids": group_ids,
        "checked_resource_id": checked_id,
        "target_slot": basename(checked_id) if checked_id != target_id else None,
        "status": model_attr(state, "status"),
        "status_description": model_attr(state, "description"),
        "actions_required": model_attr(state, "actions_required"),
        "provisioning_state": model_attr(conn, "provisioning_state"),
    }


def project_endpoint(pe) -> dict:
    subnet_id = model_attr(model_attr(pe, "subnet"), "id")
    connections = [project_connection(c, False) for c in model_attr(pe, "private_link_service_connections") or []]
    connections += [
        project_connection(c, True) for c in model_attr(pe, "manual_private_link_service_connections") or []
    ]
    return {
        "id": model_attr(pe, "id"),
        "name": model_attr(pe, "name"),
        "location": model_attr(pe, "location"),
        "tags": model_attr(pe, "tags") or {},
        "provisioning_state": model_attr(pe, "provisioning_state"),
        "subnet_id": subnet_id,
        "virtual_network_id": virtual_network_id(subnet_id),
        "virtual_network_name": basename(virtual_network_id(subnet_id)),
        "network_interface_ids": [
            model_attr(n, "id") for n in model_attr(pe, "network_interfaces") or []
        ],
        "custom_dns_configs": [
            {"fqdn": model_attr(c, "fqdn"), "ip_addresses": model_attr(c, "ip_addresses") or []}
            for c in model_attr(pe, "custom_dns_configs") or []
        ],
        "connections": connections,
    }


def project_zone_group(group) -> dict:
    configs = []
    for cfg in model_attr(group, "private_dns_zone_configs") or []:
        zone_id = model_attr(cfg, "private_dns_zone_id")
        configs.append(
            {
                "private_dns_zone_id": zone_id,
                "private_dns_zone_name": basename(zone_id),
                "record_sets": [
                    {
                        "fqdn": model_attr(r, "fqdn"),
                        "record_type": model_attr(r, "record_type"),
                        "ip_addresses": model_attr(r, "ip_addresses") or [],
                        "provisioning_state": model_attr(r, "provisioning_state"),
                    }
                    for r in model_attr(cfg, "record_sets") or []
                ],
            }
        )
    return {
        "name": model_attr(group, "name"),
        "provisioning_state": model_attr(group, "provisioning_state"),
        "private_dns_zone_configs": configs,
    }


def nic_private_ips(nic_row) -> list:
    """Private IPs off a Resource Graph NIC row's raw ipConfigurations."""
    ips = []
    for cfg in (nic_row or {}).get("ip_configurations") or []:
        ip = dig(cfg, "properties", "privateIPAddress")
        if ip:
            ips.append(ip)
    return ips


def public_access_state(row, status: str) -> str:
    """disabled / enabled / unset when the resource was read, else its lookup status.

    unset is kept apart rather than read as either.
    """
    if row is None:
        return status
    pna = str(row.get("public_network_access") or "").lower()
    if pna == "disabled":
        return "disabled"
    if pna:
        return "enabled"
    return "unset"


def target_record(conn: dict, lookups: dict, failed: set, visible) -> dict:
    """The connection plus what Resource Graph says about the resource it governs."""
    key = (conn.get("checked_resource_id") or "").lower()
    row = lookups.get(key)
    status = lookup_status(conn.get("checked_resource_id"), row is not None, key not in failed, visible)
    pna = (row or {}).get("public_network_access")
    return {
        **conn,
        "target_found": row is not None,
        "target_lookup_status": status,
        "target_public_network_access": pna,
        "target_public_network_access_state": public_access_state(row, status),
        "target_public_network_access_disabled": str(pna or "").lower() == "disabled",
        "target_network_acls_default_action": (row or {}).get("network_acls_default_action"),
    }


def subnet_record(subnet_id, subnets: dict, failed_vnets: set, visible) -> dict:
    """The endpoint subnet's policy setting and attached NSG / route table."""
    row = subnets.get((subnet_id or "").lower())
    vnet_ok = (virtual_network_id(subnet_id) or "").lower() not in failed_vnets
    policies = (row or {}).get("policies")
    nsg_id = (row or {}).get("nsg_id")
    nsg_applies = str(policies or "").lower() in NSG_POLICIES
    return {
        "subnet_lookup_status": lookup_status(subnet_id, row is not None, vnet_ok, visible),
        "subnet_private_endpoint_network_policies": policies,
        "subnet_network_security_group_id": nsg_id,
        "subnet_route_table_id": (row or {}).get("route_table_id"),
        "subnet_nsg_applies_to_endpoint": nsg_applies,
        "subnet_route_table_applies_to_endpoint": str(policies or "").lower() in ROUTE_TABLE_POLICIES,
        "endpoint_nsg_enforced": nsg_applies and bool(nsg_id),
    }


def endpoint_record(
    pe: dict, zone_groups: list, lookups: dict, failed: set, subnets: dict, failed_vnets: set, visible
) -> dict:
    connections = [target_record(c, lookups, failed, visible) for c in pe["connections"]]
    statuses = [c["status"] for c in connections]
    ips = []
    for nic_id in pe["network_interface_ids"]:
        ips.extend(nic_private_ips(lookups.get((nic_id or "").lower())))
    zones = sorted(
        {cfg["private_dns_zone_name"] for g in zone_groups for cfg in g["private_dns_zone_configs"] if cfg["private_dns_zone_name"]}
    )
    return {
        **pe,
        **subnet_record(pe.get("subnet_id"), subnets, failed_vnets, visible),
        "resource_group": resource_group_from_id(pe.get("id")),
        "connections": connections,
        "connection_status": statuses[0] if len(set(statuses)) == 1 else ("Mixed" if statuses else None),
        "approved": bool(statuses) and all(s == "Approved" for s in statuses),
        "private_ip_addresses": sorted(set(ips)),
        "private_dns_zone_groups": zone_groups,
        "private_dns_zone_names": zones,
        "has_private_dns_zone_group": bool(zones),
    }


def summarize(endpoints: list[dict]) -> dict:
    total = len(endpoints)
    by_status = {s: 0 for s in STATUSES}
    by_target_type: dict = {}
    for e in endpoints:
        status = e["connection_status"] or "None"
        by_status[status] = by_status.get(status, 0) + 1
        for c in e["connections"]:
            # ARM ids carry whatever casing the creator used ("Microsoft.Web/Sites" and "/sites").
            key = (c["target_resource_type"] or "unknown").lower()
            by_target_type[key] = by_target_type.get(key, 0) + 1
    approved = sum(1 for e in endpoints if e["approved"])
    with_dns = sum(1 for e in endpoints if e["has_private_dns_zone_group"])

    targets = {}
    for e in endpoints:
        for c in e["connections"]:
            if c["checked_resource_id"]:
                targets[c["checked_resource_id"].lower()] = c
    found = [c for c in targets.values() if c["target_found"]]
    lookup_counts = {s: 0 for s in ("not_found", "not_visible", "unknown")}
    for c in targets.values():
        if c["target_lookup_status"] in lookup_counts:
            lookup_counts[c["target_lookup_status"]] += 1
    subnets = {}
    for e in endpoints:
        if e.get("subnet_id"):
            subnets[e["subnet_id"].lower()] = e
    read_subnets = [e for e in subnets.values() if e["subnet_lookup_status"] == "found"]
    disabled = sum(1 for c in found if c["target_public_network_access_disabled"])
    enabled = sum(1 for c in found if c["target_public_network_access_state"] == "enabled")
    unset = sum(1 for c in found if c["target_public_network_access_state"] == "unset")
    firewalled = sum(
        1
        for c in found
        if not c["target_public_network_access_disabled"]
        and str(c["target_network_acls_default_action"] or "").lower() == "deny"
    )
    return {
        "total_private_endpoints": total,
        "approved_endpoints": approved,
        "not_approved_endpoints": total - approved,
        "approved_percentage": coverage_percentage(approved, total),
        "endpoints_by_connection_status": by_status,
        "endpoints_with_private_dns_zone_group": with_dns,
        "endpoints_without_private_dns_zone_group": total - with_dns,
        "connections_by_target_type": dict(sorted(by_target_type.items())),
        "total_target_resources": len(targets),
        "target_resources_found": len(found),
        "target_resources_not_found": lookup_counts["not_found"],
        "target_resources_not_visible": lookup_counts["not_visible"],
        "target_resources_lookup_unknown": lookup_counts["unknown"],
        "target_resources_public_access_disabled": disabled,
        "target_resources_public_access_not_disabled": len(found) - disabled,
        "target_resources_public_access_enabled": enabled,
        "target_resources_public_access_unset": unset,
        "target_resources_public_access_firewall_deny_default": firewalled,
        "target_public_access_disabled_percentage": coverage_percentage(disabled, len(found)),
        "endpoints_nsg_enforced": sum(1 for e in endpoints if e["endpoint_nsg_enforced"]),
        "endpoints_subnet_policies_disabled": sum(
            1
            for e in endpoints
            if e["subnet_lookup_status"] == "found"
            and str(e["subnet_private_endpoint_network_policies"] or "").lower() == "disabled"
        ),
        "endpoints_subnet_lookup_not_read": sum(1 for e in endpoints if e["subnet_lookup_status"] != "found"),
        "total_endpoint_subnets": len(subnets),
        "endpoint_subnets_nsg_applies": sum(1 for e in read_subnets if e["subnet_nsg_applies_to_endpoint"]),
        "endpoint_subnets_with_nsg": sum(1 for e in read_subnets if e["subnet_network_security_group_id"]),
        "endpoint_subnets_with_nsg_not_applied": sum(
            1
            for e in read_subnets
            if e["subnet_network_security_group_id"] and not e["subnet_nsg_applies_to_endpoint"]
        ),
    }


def quoted_ids(ids: list[str]) -> str:
    return ", ".join("'" + i.replace("'", "''") + "'" for i in ids)


def lookup_query(ids: list[str]) -> str:
    return (
        f"Resources | where id in~ ({quoted_ids(ids)}) "
        "| project id, type, "
        "public_network_access = tostring(properties.publicNetworkAccess), "
        "network_acls_default_action = tostring(properties.networkAcls.defaultAction), "
        "ip_configurations = properties.ipConfigurations"
    )


def subnet_query(vnet_ids: list[str]) -> str:
    return (
        f"Resources | where id in~ ({quoted_ids(vnet_ids)}) "
        "| mv-expand s = properties.subnets "
        "| project id = tostring(s.id), "
        "policies = tostring(s.properties.privateEndpointNetworkPolicies), "
        "nsg_id = tostring(s.properties.networkSecurityGroup.id), "
        "route_table_id = tostring(s.properties.routeTable.id)"
    )


def lookup_by_ids(cred, ids: list[str], build_query, label: str, collector: Collector):
    """Resource Graph rows keyed by lowercased id, plus the ids whose chunk failed.

    Unscoped so resources in other readable subscriptions resolve.
    """
    unique = sorted({i.lower() for i in ids if i})
    out, failed = {}, set()
    for start in range(0, len(unique), LOOKUP_CHUNK):
        chunk = unique[start : start + LOOKUP_CHUNK]
        rows = collector.guard(
            f"resourcegraph.resources ({label} {start + 1}-{start + len(chunk)})",
            lambda: resource_graph_rows(cred, build_query(chunk)),
        )
        if rows is None:
            failed.update(chunk)
            continue
        for row in rows:
            row = {k: (None if v == "" else v) for k, v in row.items()}
            out[(row.get("id") or "").lower()] = row
    return out, failed


def collect_endpoints(subscription_id, cred, collector: Collector) -> list[dict]:
    def _client():
        from azure.mgmt.network import NetworkManagementClient  # lazy

        return NetworkManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("network.NetworkManagementClient (init)", _client)
    if client is None:
        return []
    endpoints = collector.guard(
        "network.private_endpoints.list_by_subscription",
        lambda: [project_endpoint(pe) for pe in client.private_endpoints.list_by_subscription()],
        default=[],
    )
    zone_groups = {}
    for pe in endpoints:
        rg = resource_group_from_id(pe.get("id"))
        zone_groups[pe["id"]] = collector.guard(
            f"network.private_dns_zone_groups.list({rg}/{pe.get('name')})",
            lambda: [project_zone_group(g) for g in client.private_dns_zone_groups.list(pe["name"], rg)],
            default=[],
        )

    ids = [c["checked_resource_id"] for pe in endpoints for c in pe["connections"]]
    ids += [n for pe in endpoints for n in pe["network_interface_ids"]]
    lookups, failed = lookup_by_ids(cred, ids, lookup_query, "lookup", collector)
    vnet_ids = [virtual_network_id(pe["subnet_id"]) for pe in endpoints]
    subnets, failed_vnets = lookup_by_ids(cred, vnet_ids, subnet_query, "subnet lookup", collector)
    visible = visible_subscription_ids(cred, collector) if endpoints else set()

    records = [
        endpoint_record(pe, zone_groups[pe["id"]], lookups, failed, subnets, failed_vnets, visible)
        for pe in endpoints
    ]
    return sorted(records, key=lambda r: r.get("id") or "")


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

    endpoints: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Network")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Network is not registered on subscription %s — reporting status not_registered",
                subscription_id,
            )
        endpoints = collect_endpoints(subscription_id, cred, collector)
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
        results={"private_endpoints": endpoints, "provider_registration_status": registration},
        summary={**summarize(endpoints), "provider_registration_status": registration},
    )
    filename = f"azure_private_endpoint_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
