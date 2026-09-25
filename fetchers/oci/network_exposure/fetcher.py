#!/usr/bin/env python3
"""
OCI networking — what the rules allow, and whether anything can actually reach it

Every VCN, subnet, security list and network security group in scope, with each
ingress and egress rule parsed into peer, protocol and port range; the subnet
controls that override rules entirely (`prohibit_internet_ingress`,
`prohibit_public_ip_on_vnic`); the route tables and gateways that decide whether
a subnet is reachable from the internet at all; and the flow logs configured
over each subnet or VCN.

Evidence for KSI-CNA-RNT, "resources are persistently reviewed to ensure they
are appropriately configured to limit inbound and outbound network traffic",
KSI-CNA-MAT (minimal attack surface) and KSI-MLA-LET for the flow logs.

Ported from Prowler's OCI network service (Apache-2.0,
prowler/providers/oraclecloud/services/network, commit 5fe1a67) — the SSH and
RDP ingress checks for security lists and NSGs, the default-security-list check,
and the subnet flow-logs check. Five departures, every one of them a rule
Prowler would call clean:

  * IPv6 IS INVISIBLE TO PROWLER. Every check compares `source == "0.0.0.0/0"`,
    so `::/0` — the IPv6 internet, and a legal source on the same rule list —
    passes every one of them.

  * ONLY SSH AND RDP ARE CHECKED. A rule opening 5432, 3306, 1521, 445 or
    "all ports" to the internet is not SSH, so nothing fires. Here every port
    range open to the internet is recorded, and a named set of sensitive ports
    is called out.

  * EGRESS IS NOT CHECKED AT ALL. The indicator says "inbound and outbound".
    The live tenancy's security lists both allow egress to 0.0.0.0/0 on every
    protocol, which no Prowler check reports.

  * UDP IS NOT PARSED. Prowler reads `tcp_options` only, so a UDP rule to the
    internet is read as "no ports specified" or skipped by protocol.

  * A RULE THAT NOTHING CAN REACH IS NOT AN EXPOSURE. Three facts decide that,
    all verified live: a security list attached to no subnet applies to nothing;
    `prohibit_internet_ingress` on a subnet blocks inbound regardless of rules;
    and a subnet whose route table has no 0.0.0.0/0 route to an *enabled*
    internet gateway is not reachable. The staged tenancy has an SSH-from-
    anywhere rule on a list attached to no subnet, in a VCN with no gateway, so
    `internet_ingress_rules` and `reachable_internet_ingress_rules` deliberately
    disagree — the first is the configuration finding, the second the exposure.

NSGs ARE NOT SCOPED TO SUBNETS. An NSG attaches to VNICs, not subnets, so its
rules cannot be resolved to a route table here; NSG exposure is reported on the
rules alone and never folded into the reachable counts.
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from oci_common import (  # noqa: E402
    Collector,
    as_bool,
    build_payload,
    coverage_percentage,
    finish,
    iso,
    list_all,
    load_config,
    make_client,
    resolve_scope,
    sanitize_for_filename,
    short_ocid,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_network_exposure")

# Both spellings of "the whole internet". Prowler only knows the first.
INTERNET_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

# OCI writes the IANA protocol number as a string, or "all".
PROTOCOL_NAMES = {"1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6", "all": "all"}
ALL_PROTOCOLS = "all"
TCP, UDP = "6", "17"

# Ports worth naming when they are open to the internet. Not exhaustive by
# design — every internet-open range is recorded either way.
SENSITIVE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 135: "RPC", 139: "NetBIOS",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle DB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
    11211: "memcached", 27017: "MongoDB",
}

ALL_PORTS = (1, 65535)
GONE_STATES = frozenset({"TERMINATED", "TERMINATING"})
FLOW_LOG_SERVICE = "flowlogs"


# --- pure transforms ---

def _port_range(options) -> tuple:
    """The destination port range of a tcp/udp options block.

    An options block with no destination range means every port, which is the
    case Prowler treats as "no ports specified" and skips for RDP.
    """
    if not options:
        return ALL_PORTS
    destination = options.get("destination_port_range")
    if not destination:
        return ALL_PORTS
    low, high = destination.get("min"), destination.get("max")
    if low is None and high is None:
        return ALL_PORTS
    return (low if low is not None else 1, high if high is not None else 65535)


def rule_record(rule: dict, *, direction: str) -> dict:
    """One security rule, from a security list or an NSG, parsed.

    `direction` is INGRESS or EGRESS; security-list rules carry it implicitly by
    which list they came from, NSG rules carry it in the record itself.
    """
    direction = (rule.get("direction") or direction).upper()
    inbound = direction == "INGRESS"
    peer = rule.get("source") if inbound else rule.get("destination")
    peer_type = rule.get("source_type") if inbound else rule.get("destination_type")
    protocol = rule.get("protocol")
    is_internet = peer in INTERNET_CIDRS

    ranges = []
    if protocol == ALL_PROTOCOLS or protocol is None:
        ranges = [ALL_PORTS]
    elif protocol == TCP:
        ranges = [_port_range(rule.get("tcp_options"))]
    elif protocol == UDP:
        ranges = [_port_range(rule.get("udp_options"))]

    # Named only for INGRESS from the internet: that is a port reachable from
    # outside. On egress the meaningful fact is that everything is allowed out,
    # which `opens_all_ports` already says — listing 17 service names there is
    # noise, not a finding.
    protocol_name = PROTOCOL_NAMES.get(protocol, protocol) if protocol is not None else None
    exposed = sorted(
        {name for low, high in ranges for port, name in SENSITIVE_PORTS.items() if low <= port <= high}
    ) if is_internet and inbound else []

    return {
        "direction": direction,
        "peer": peer,
        "peer_type": peer_type,
        "is_internet": is_internet,
        "protocol": protocol,
        "protocol_name": protocol_name,
        "port_ranges": [list(r) for r in ranges],
        "opens_all_ports": ALL_PORTS in ranges,
        "sensitive_ports_exposed": exposed,
        # A stateless rule has no connection tracking, so the return path needs
        # its own rule — and it applies to traffic a stateful rule would not.
        "is_stateless": rule.get("is_stateless") is True,
        "icmp_type": (rule.get("icmp_options") or {}).get("type"),
        "description": rule.get("description"),
    }


def security_list_record(security_list: dict, *, is_default=False, attached_subnets=()) -> dict:
    ingress = [rule_record(r, direction="INGRESS") for r in security_list.get("ingress_security_rules") or []]
    egress = [rule_record(r, direction="EGRESS") for r in security_list.get("egress_security_rules") or []]
    return {
        "id": security_list.get("id"),
        "display_name": security_list.get("display_name"),
        "vcn_id": security_list.get("vcn_id"),
        "compartment_id": security_list.get("compartment_id"),
        "lifecycle_state": security_list.get("lifecycle_state"),
        "is_default": is_default,
        "time_created": iso(security_list.get("time_created")),
        "ingress_rules": ingress,
        "egress_rules": egress,
        # A list attached to no subnet governs no traffic.
        "attached_subnet_ids": sorted(attached_subnets),
        "is_attached": bool(attached_subnets),
    }


def nsg_record(nsg: dict, *, rules=None) -> dict:
    """`rules` is None when the per-NSG rule listing failed — not "no rules"."""
    records = [rule_record(r, direction=r.get("direction") or "INGRESS") for r in rules] if rules is not None else None
    return {
        "id": nsg.get("id"),
        "display_name": nsg.get("display_name"),
        "vcn_id": nsg.get("vcn_id"),
        "compartment_id": nsg.get("compartment_id"),
        "lifecycle_state": nsg.get("lifecycle_state"),
        "time_created": iso(nsg.get("time_created")),
        "rules": records,
        "rules_read": records is not None,
        "rule_count": len(records) if records is not None else None,
    }


def subnet_record(subnet: dict, *, internet_routable=None, flow_logs=()) -> dict:
    return {
        "id": subnet.get("id"),
        "display_name": subnet.get("display_name"),
        "vcn_id": subnet.get("vcn_id"),
        "compartment_id": subnet.get("compartment_id"),
        "lifecycle_state": subnet.get("lifecycle_state"),
        "cidr_block": subnet.get("cidr_block"),
        "ipv6_cidr_block": subnet.get("ipv6_cidr_block"),
        "route_table_id": subnet.get("route_table_id"),
        "security_list_ids": sorted(subnet.get("security_list_ids") or []),
        # These two override every rule on the subnet.
        "prohibit_internet_ingress": subnet.get("prohibit_internet_ingress") is True,
        "prohibit_public_ip_on_vnic": subnet.get("prohibit_public_ip_on_vnic") is True,
        "is_private": subnet.get("prohibit_public_ip_on_vnic") is True,
        # None when the route table could not be read.
        "internet_routable": internet_routable,
        "flow_logs": list(flow_logs),
        "flow_logging_enabled": any(log["is_enabled"] for log in flow_logs),
    }


def flow_log_record(log: dict) -> dict:
    source = (log.get("configuration") or {}).get("source") or {}
    return {
        "id": log.get("id"),
        "display_name": log.get("display_name"),
        "is_enabled": log.get("is_enabled") is True,
        "resource": source.get("resource"),
        "category": source.get("category"),
        "retention_duration": log.get("retention_duration"),
    }


def internet_gateway_record(gateway: dict, *, routed=None) -> dict:
    """One internet gateway: the only way inbound internet traffic enters a VCN.

    `is_routed` says whether any route table in scope sends a default route to
    it. An enabled gateway nothing routes to exposes nothing; None when no
    route table could be read.
    """
    return {
        "id": gateway.get("id"),
        "display_name": gateway.get("display_name"),
        "compartment_id": gateway.get("compartment_id"),
        "vcn_id": gateway.get("vcn_id"),
        "lifecycle_state": gateway.get("lifecycle_state"),
        # Absent reads as enabled, the state a gateway is created in: read as
        # disabled, a missing flag made every route through it unreachable.
        "is_enabled": gateway.get("is_enabled") is not False,
        "is_routed": routed,
    }


def route_table_routes_to_internet(route_table: dict, *, enabled_gateway_ids=()) -> bool:
    """True when a default route points at an ENABLED internet gateway.

    A gateway that exists but is disabled routes nothing, and a route to a NAT
    gateway is egress-only — neither makes a subnet reachable inbound.
    """
    for rule in route_table.get("route_rules") or []:
        destination = rule.get("destination") or rule.get("cidr_block")
        if destination in INTERNET_CIDRS and rule.get("network_entity_id") in enabled_gateway_ids:
            return True
    return False


def summarize(vcns, subnets, security_lists, nsgs, *, gateways=(), api_readable: bool = True) -> dict:
    live_gateways = [g for g in gateways if g["lifecycle_state"] not in GONE_STATES]
    live_subnets = [s for s in subnets if s["lifecycle_state"] not in GONE_STATES]
    live_lists = [s for s in security_lists if s["lifecycle_state"] not in GONE_STATES]
    live_nsgs = [n for n in nsgs if n["lifecycle_state"] not in GONE_STATES]

    subnets_by_id = {s["id"]: s for s in live_subnets}

    def reachable(security_list):
        """Attached to at least one subnet that is actually internet-facing."""
        return any(
            subnets_by_id[sid]["internet_routable"] and not subnets_by_id[sid]["prohibit_internet_ingress"]
            for sid in security_list["attached_subnet_ids"] if sid in subnets_by_id
        )

    list_ingress = [(sl, r) for sl in live_lists for r in sl["ingress_rules"]]
    list_egress = [(sl, r) for sl in live_lists for r in sl["egress_rules"]]
    nsg_rules = [(n, r) for n in live_nsgs for r in n["rules"] or []]

    internet_ingress = [(sl, r) for sl, r in list_ingress if r["is_internet"]]
    reachable_ingress = [(sl, r) for sl, r in internet_ingress if reachable(sl)]
    internet_egress = [(sl, r) for sl, r in list_egress if r["is_internet"]]
    nsg_internet_ingress = [(n, r) for n, r in nsg_rules if r["direction"] == "INGRESS" and r["is_internet"]]

    def ports(pairs):
        return sorted({name for _, r in pairs for name in r["sensitive_ports_exposed"]})

    return {
        # False when the network API could not be listed — not "no VCNs".
        "network_readable": api_readable,
        "total_vcns": len(vcns),
        "total_subnets": len(live_subnets),
        "total_security_lists": len(live_lists),
        "total_network_security_groups": len(live_nsgs),
        "nsgs_with_unreadable_rules": sum(1 for n in live_nsgs if not n["rules_read"]),
        # INGRESS — configuration, then actual exposure.
        "internet_ingress_rules": len(internet_ingress),
        "reachable_internet_ingress_rules": len(reachable_ingress),
        "internet_ingress_rules_on_unattached_lists": sum(
            1 for sl, _ in internet_ingress if not sl["is_attached"]
        ),
        "sensitive_ports_open_to_internet": ports(internet_ingress),
        "sensitive_ports_reachable_from_internet": ports(reachable_ingress),
        "internet_ingress_rules_opening_all_ports": sum(1 for _, r in internet_ingress if r["opens_all_ports"]),
        "ipv6_internet_ingress_rules": sum(1 for _, r in internet_ingress if r["peer"] == "::/0"),
        # EGRESS — the half Prowler does not check at all.
        "internet_egress_rules": len(internet_egress),
        "unrestricted_internet_egress_rules": sum(1 for _, r in internet_egress if r["opens_all_ports"]),
        "security_lists_with_unrestricted_egress": sorted(
            f"{sl['display_name']} ({short_ocid(sl['id'])})" for sl, r in internet_egress
            if r["opens_all_ports"] and sl["display_name"]
        ),
        # NSGs, reported apart because they attach to VNICs, not subnets.
        "nsg_internet_ingress_rules": len(nsg_internet_ingress),
        "nsg_sensitive_ports_open_to_internet": ports(nsg_internet_ingress),
        # Default security lists carry traffic for any subnet that names no other.
        "default_security_lists_with_internet_ingress": len(
            {sl["id"] for sl, _ in internet_ingress if sl["is_default"]}
        ),
        "stateless_rules": sum(1 for _, r in list_ingress + list_egress + nsg_rules if r["is_stateless"]),
        # Gateways: an enabled one with a default route to it is the way in.
        "internet_gateways": len(live_gateways),
        "enabled_internet_gateways": sorted(
            f"{g['display_name']} ({short_ocid(g['id'])})" for g in live_gateways if g["is_enabled"]
        ),
        "enabled_internet_gateways_routed_to": sum(
            1 for g in live_gateways if g["is_enabled"] and g["is_routed"]
        ),
        # Subnet-level controls, which override rules.
        "private_subnets": sum(1 for s in live_subnets if s["is_private"]),
        "subnets_prohibiting_internet_ingress": sum(1 for s in live_subnets if s["prohibit_internet_ingress"]),
        "internet_routable_subnets": sum(1 for s in live_subnets if s["internet_routable"]),
        "subnets_with_unreadable_route_table": sum(1 for s in live_subnets if s["internet_routable"] is None),
        "unattached_security_lists": sum(1 for sl in live_lists if not sl["is_attached"]),
        # Flow logs.
        "subnets_with_flow_logging": sum(1 for s in live_subnets if s["flow_logging_enabled"]),
        "flow_logging_percentage": coverage_percentage(
            sum(1 for s in live_subnets if s["flow_logging_enabled"]), len(live_subnets)
        ),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool):
    import oci  # lazy

    identity = make_client(oci.identity.IdentityClient, auth)
    network = make_client(oci.core.VirtualNetworkClient, auth)
    logging_client = make_client(oci.logging.LoggingManagementClient, auth)

    compartments = walk_compartments(
        identity, scope["compartment_id"], collector,
        include_subcompartments=include_sub, tenancy=auth.get("tenancy"),
    )

    vcns: list[dict] = []
    subnets: list[dict] = []
    security_lists: list[dict] = []
    nsgs: list[dict] = []
    unreadable = 0

    # Everything is gathered first and joined after the walk. OCI lets a subnet,
    # its route table, the gateway that route targets, its security lists and
    # the log group holding its flow log each sit in a different compartment,
    # and landing zones split them exactly that way. A per-compartment join
    # read a live internet-reachable subnet as unreachable, its security list
    # as unattached and its flow log as missing.
    default_list_ids: set = set()
    raw_gateways: list[dict] = []
    raw_route_tables: list[dict] = []
    raw_subnets: list[dict] = []
    raw_security_lists: list[dict] = []
    flow_logs_by_resource: dict[str, list] = {}

    for comp in compartments:
        cid, cname = comp["id"], comp["name"]

        found = collector.guard(
            f"virtual_network.list_vcns ({cname})",
            lambda c=cid: list_all(network.list_vcns, c),
        )
        if found is None:
            unreadable += 1
            continue

        for vcn in found:
            plain = to_plain(vcn)
            if plain.get("default_security_list_id"):
                default_list_ids.add(plain["default_security_list_id"])
            vcns.append({
                "id": plain.get("id"),
                "display_name": plain.get("display_name"),
                "compartment_id": plain.get("compartment_id"),
                "lifecycle_state": plain.get("lifecycle_state"),
                "cidr_blocks": plain.get("cidr_blocks") or [],
                "ipv6_cidr_blocks": plain.get("ipv6_cidr_blocks") or [],
                "is_zpr_only": plain.get("is_zpr_only") is True,
                "default_security_list_id": plain.get("default_security_list_id"),
            })

        # Gateways decide whether a default route reaches the internet at all.
        raw_gateways += [to_plain(g) for g in collector.guard(
            f"virtual_network.list_internet_gateways ({cname})",
            lambda c=cid: list_all(network.list_internet_gateways, c),
            default=[],
        ) or []]
        raw_route_tables += [to_plain(t) for t in collector.guard(
            f"virtual_network.list_route_tables ({cname})",
            lambda c=cid: list_all(network.list_route_tables, c),
            default=[],
        ) or []]

        for group in collector.guard(
            f"logging.list_log_groups ({cname})",
            lambda c=cid: list_all(logging_client.list_log_groups, c),
            default=[],
        ) or []:
            for entry in collector.guard(
                f"logging.list_logs ({group.display_name})",
                lambda g=group.id: list_all(logging_client.list_logs, g),
                default=[],
            ) or []:
                plain = to_plain(entry)
                source = (plain.get("configuration") or {}).get("source") or {}
                if source.get("service") == FLOW_LOG_SERVICE and source.get("resource"):
                    flow_logs_by_resource.setdefault(source["resource"], []).append(plain)

        raw_subnets += [to_plain(s) for s in collector.guard(
            f"virtual_network.list_subnets ({cname})",
            lambda c=cid: list_all(network.list_subnets, c),
            default=[],
        ) or []]
        raw_security_lists += [to_plain(sl) for sl in collector.guard(
            f"virtual_network.list_security_lists ({cname})",
            lambda c=cid: list_all(network.list_security_lists, c),
            default=[],
        ) or []]

        for nsg in collector.guard(
            f"virtual_network.list_network_security_groups ({cname})",
            lambda c=cid: list_all(network.list_network_security_groups, compartment_id=c),
            default=[],
        ) or []:
            plain = to_plain(nsg)
            rules = collector.guard(
                f"virtual_network.list_network_security_group_security_rules ({plain.get('display_name')})",
                lambda n=plain["id"]: list_all(network.list_network_security_group_security_rules, n),
            )
            nsgs.append(nsg_record(plain, rules=[to_plain(r) for r in rules] if rules is not None else None))

    enabled_gateways = {g["id"] for g in raw_gateways if g.get("is_enabled") is not False}
    routed_to = {
        rule.get("network_entity_id")
        for t in raw_route_tables for rule in t.get("route_rules") or []
        if (rule.get("destination") or rule.get("cidr_block")) in INTERNET_CIDRS
    }
    gateways = sorted(
        (internet_gateway_record(g, routed=(g["id"] in routed_to) if raw_route_tables else None)
         for g in raw_gateways),
        key=lambda r: (r.get("display_name") or "", r.get("id") or ""),
    )

    # A route table outside the scope stays unknown (None), never "not routable".
    route_tables = {
        t["id"]: route_table_routes_to_internet(t, enabled_gateway_ids=enabled_gateways)
        for t in raw_route_tables
    }
    attached_by_list: dict[str, set] = {}
    for subnet in raw_subnets:
        for list_id in subnet.get("security_list_ids") or []:
            attached_by_list.setdefault(list_id, set()).add(subnet["id"])
        # A flow log set on the VCN covers every subnet under it.
        logs = flow_logs_by_resource.get(subnet["id"], []) + flow_logs_by_resource.get(subnet.get("vcn_id") or "", [])
        subnets.append(subnet_record(
            subnet,
            internet_routable=route_tables.get(subnet.get("route_table_id")),
            flow_logs=[flow_log_record(log) for log in logs],
        ))
    for plain in raw_security_lists:
        security_lists.append(security_list_record(
            plain,
            is_default=plain.get("id") in default_list_ids,
            attached_subnets=attached_by_list.get(plain["id"], set()),
        ))

    if compartments and unreadable == len(compartments):
        return None, None, None, None, None, len(compartments)

    vcns.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    subnets.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    security_lists.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    nsgs.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    return vcns, subnets, security_lists, nsgs, gateways, len(compartments)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    include_sub = as_bool(os.environ.get("OCI_INCLUDE_SUBCOMPARTMENTS"), default=True)

    auth: dict = {}
    scope: dict = {"compartment_id": None, "compartment_source": "unresolved"}
    vcns = subnets = security_lists = nsgs = gateways = None
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            try:
                vcns, subnets, security_lists, nsgs, gateways, scanned = collect(
                    auth, scope, collector, include_sub=include_sub)
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("virtual_network.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={
            "vcns": vcns or [],
            "subnets": subnets or [],
            "security_lists": security_lists or [],
            "network_security_groups": nsgs or [],
            "internet_gateways": gateways or [],
        },
        summary=summarize(vcns or [], subnets or [], security_lists or [], nsgs or [],
                          gateways=gateways or [], api_readable=vcns is not None),
        compartments_scanned=scanned,
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_network_exposure_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)
    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
