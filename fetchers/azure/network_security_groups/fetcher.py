#!/usr/bin/env python3
"""Azure network security groups, virtual networks and NICs for one subscription.

Ported from prowler/providers/azure/services/network/network_service.py
(Apache-2.0); the "open to the Internet" match replicates Prowler's
network_ssh_internet_access_restricted check. Beyond Prowler: each NSG's default
rules (where the platform's AllowInternetOutBound lives, so outbound posture is
readable at all) and each network interface's effective NSG coverage, NIC-level or
inherited from its subnet.
"""

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
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_network_security_groups")

# Prowler's match set for "the whole Internet" as a rule source and for "any
# protocol", kept as literals so the summary math matches what Prowler would flag.
INTERNET_SOURCE_PREFIXES = ("Internet", "*", "0.0.0.0/0")
ANY_TCP_PROTOCOLS = ("TCP", "Tcp", "*")

# The admin ports the summary counts Internet exposure for.
ADMIN_PORTS = {"ssh": 22, "rdp": 3389}

# A rule destination that covers the public Internet. "*" is every address,
# Internet the service tag the platform's own AllowInternetOutBound uses.
INTERNET_DESTINATION_PREFIXES = ("Internet", "*", "0.0.0.0/0")


# --- projection: the only code here that touches an azure-mgmt model ---

def project_security_rule(rule) -> dict:
    """Read a `SecurityRule` model's attributes into a flat snake_case dict."""
    return {
        "id": model_attr(rule, "id"),
        "name": model_attr(rule, "name"),
        "destination_port_range": model_attr(rule, "destination_port_range"),
        "destination_port_ranges": model_attr(rule, "destination_port_ranges"),
        "protocol": model_attr(rule, "protocol"),
        "source_address_prefix": model_attr(rule, "source_address_prefix"),
        "source_address_prefixes": model_attr(rule, "source_address_prefixes"),
        "access": model_attr(rule, "access"),
        "direction": model_attr(rule, "direction"),
        "priority": model_attr(rule, "priority"),
        "destination_address_prefix": model_attr(rule, "destination_address_prefix"),
        "destination_address_prefixes": model_attr(rule, "destination_address_prefixes"),
    }


def project_security_group(group) -> dict:
    """Read a `NetworkSecurityGroup` model, including its inline security rules.

    `default_security_rules` are the six platform rules every NSG carries (priority
    65000+). They cannot be deleted, only overridden by a lower-numbered custom rule,
    so an NSG with no outbound rules of its own still allows all Internet egress.
    """
    return {
        "id": model_attr(group, "id"),
        "name": model_attr(group, "name"),
        "location": model_attr(group, "location"),
        "security_rules": [
            project_security_rule(rule) for rule in (model_attr(group, "security_rules") or [])
        ],
        "default_security_rules": [
            project_security_rule(rule)
            for rule in (model_attr(group, "default_security_rules") or [])
        ],
    }


def project_network_interface(nic) -> dict:
    """Read a `NetworkInterface` model: its own NSG, its VM, and each IP config's subnet."""
    return {
        "id": model_attr(nic, "id"),
        "name": model_attr(nic, "name"),
        "location": model_attr(nic, "location"),
        "nsg_id": model_attr(model_attr(nic, "network_security_group"), "id"),
        "virtual_machine_id": model_attr(model_attr(nic, "virtual_machine"), "id"),
        "ip_configurations": [
            {
                "name": model_attr(ipc, "name"),
                "subnet_id": model_attr(model_attr(ipc, "subnet"), "id"),
                "private_ip_address": model_attr(ipc, "private_ip_address"),
                "public_ip_address_id": model_attr(
                    model_attr(ipc, "public_ip_address"), "id"
                ),
            }
            for ipc in (model_attr(nic, "ip_configurations") or [])
        ],
    }


def project_subnet(subnet) -> dict:
    """Read a `Subnet` model, flattening the attached NSG down to its id."""
    return {
        "id": model_attr(subnet, "id"),
        "name": model_attr(subnet, "name"),
        "nsg_id": model_attr(model_attr(subnet, "network_security_group"), "id"),
    }


def project_virtual_network(vnet) -> dict:
    """Read a `VirtualNetwork` model, including its subnets."""
    return {
        "id": model_attr(vnet, "id"),
        "name": model_attr(vnet, "name"),
        "location": model_attr(vnet, "location"),
        "enable_ddos_protection": model_attr(vnet, "enable_ddos_protection"),
        "subnets": [project_subnet(s) for s in (model_attr(vnet, "subnets") or [])],
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def security_rule_record(rule: dict) -> dict:
    """Normalize one projected NSG security rule — Prowler's six-field projection.

    Prowler's defaults: `access` "Allow" and `direction` "Inbound" when absent, the
    conservative reading. The plural, list-valued `destination_port_ranges` /
    `source_address_prefixes` are carried too, which Prowler's checks do not read: a
    rule using the plural form has the singular set to null, so without them the
    evidence would silently show an empty port for a real open rule.
    """
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "destination_port_range": rule.get("destination_port_range"),
        "destination_port_ranges": rule.get("destination_port_ranges") or [],
        "protocol": rule.get("protocol"),
        "source_address_prefix": rule.get("source_address_prefix"),
        "source_address_prefixes": rule.get("source_address_prefixes") or [],
        "access": rule.get("access") or "Allow",
        "direction": rule.get("direction") or "Inbound",
        "priority": rule.get("priority"),
        "destination_address_prefix": rule.get("destination_address_prefix"),
        "destination_address_prefixes": rule.get("destination_address_prefixes") or [],
    }


def security_group_record(group: dict) -> dict:
    """Normalize one projected NSG with its inline rules."""
    resource_id = group.get("id")
    return {
        "id": resource_id,
        "name": group.get("name"),
        "location": group.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "security_rules": [
            security_rule_record(rule) for rule in (group.get("security_rules") or [])
        ],
        # Kept apart from security_rules so the existing rule counts keep meaning
        # "rules someone wrote".
        "default_security_rules": [
            security_rule_record(rule)
            for rule in (group.get("default_security_rules") or [])
        ],
    }


def subnet_record(subnet: dict) -> dict:
    """Normalize one VNet subnet with the id of the NSG attached to it (or None)."""
    return {
        "id": subnet.get("id"),
        "name": subnet.get("name"),
        "nsg_id": subnet.get("nsg_id"),
    }


def virtual_network_record(vnet: dict) -> dict:
    """Normalize one projected virtual network with its subnets and DDoS state."""
    resource_id = vnet.get("id")
    return {
        "id": resource_id,
        "name": vnet.get("name"),
        "location": vnet.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "enable_ddos_protection": bool(vnet.get("enable_ddos_protection") or False),
        "subnets": [subnet_record(s) for s in (vnet.get("subnets") or [])],
    }


def _arm_id_key(resource_id) -> str:
    """ARM ids are case-insensitive, and Azure does not keep one spelling: an NSG's
    back-reference to a subnet and the VNet's own subnet id differ in case (seen
    live). Compare on this, never on the raw string.
    """
    return str(resource_id or "").lower()


def network_interface_record(nic: dict, subnet_nsg_by_id: dict) -> dict:
    """Normalize one NIC and resolve its effective NSG coverage.

    Traffic to a NIC is filtered by the NSG on the NIC AND the NSG on its subnet, so
    either one counts as protected. `subnet_nsg_by_id` maps lower-cased subnet ids
    from this subscription's VNets to their NSG id (or None). A subnet absent from it
    (a VNet in another subscription) is listed in `unresolved_subnet_ids` and does not
    count as protection: the evidence cannot show an NSG it did not read.
    """
    resource_id = nic.get("id")
    subnet_ids = sorted(
        {c["subnet_id"] for c in (nic.get("ip_configurations") or []) if c.get("subnet_id")}
    )
    subnet_nsg_ids = sorted(
        {
            subnet_nsg_by_id[_arm_id_key(s)]
            for s in subnet_ids
            if subnet_nsg_by_id.get(_arm_id_key(s))
        }
    )
    unresolved = [s for s in subnet_ids if _arm_id_key(s) not in subnet_nsg_by_id]
    nic_nsg = nic.get("nsg_id")
    if nic_nsg and subnet_nsg_ids:
        source = "nic_and_subnet"
    elif nic_nsg:
        source = "nic"
    elif subnet_nsg_ids:
        source = "subnet"
    else:
        source = "none"
    return {
        "id": resource_id,
        "name": nic.get("name"),
        "location": nic.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "virtual_machine_id": nic.get("virtual_machine_id"),
        "attached": bool(nic.get("virtual_machine_id")),
        "nsg_id": nic_nsg,
        "subnet_ids": subnet_ids,
        "subnet_nsg_ids": subnet_nsg_ids,
        "unresolved_subnet_ids": unresolved,
        "has_public_ip": any(
            c.get("public_ip_address_id") for c in (nic.get("ip_configurations") or [])
        ),
        "nsg_protection_source": source,
        "protected_by_nsg": source != "none",
    }


def subnet_nsg_index(virtual_networks: list[dict]) -> dict:
    """Lower-cased subnet id -> attached NSG id (or None), across the listed VNets."""
    return {
        _arm_id_key(s["id"]): s.get("nsg_id")
        for v in virtual_networks
        for s in v["subnets"]
        if s.get("id")
    }


def _destinations(rule: dict) -> list:
    return [rule.get("destination_address_prefix"), *(rule.get("destination_address_prefixes") or [])]


def rule_allows_internet_outbound(rule: dict) -> bool:
    """An outbound Allow rule whose destination includes the public Internet."""
    return (
        rule.get("direction") == "Outbound"
        and rule.get("access") == "Allow"
        and any(d in INTERNET_DESTINATION_PREFIXES for d in _destinations(rule))
    )


def _is_catch_all_internet_outbound(rule: dict) -> bool:
    """An outbound rule covering every port and protocol to an Internet destination —
    the shape of the platform's AllowInternetOutBound and of a rule overriding it.
    """
    ports = [rule.get("destination_port_range"), *(rule.get("destination_port_ranges") or [])]
    return (
        rule.get("direction") == "Outbound"
        and rule.get("protocol") == "*"
        and "*" in ports
        and any(d in INTERNET_DESTINATION_PREFIXES for d in _destinations(rule))
    )


def unrestricted_internet_outbound(group: dict) -> bool:
    """Is all-port Internet egress allowed through this NSG?

    Walks custom and default rules in priority order (lowest number wins) and takes
    the first catch-all rule toward the Internet. With no custom override that is the
    default AllowInternetOutBound (65001), so an NSG nobody touched reads True. A
    narrower Deny (one port) does not count as an override: other egress still flows.
    The source prefix is not considered. A rule with no priority sorts last.
    """
    rules = sorted(
        (*group["security_rules"], *group.get("default_security_rules", [])),
        key=lambda r: r["priority"] if isinstance(r.get("priority"), int) else 1 << 30,
    )
    for rule in rules:
        if _is_catch_all_internet_outbound(rule):
            return rule["access"] == "Allow"
    return False


def _port_in_range(port_range, port: int) -> bool:
    """Does a rule's destination port range cover `port`?

    Prowler's condition (exact match, or a "low-high" range spanning it), extended
    with "*" — which the SDK also returns and which covers every port.
    """
    if not port_range:
        return False
    text = str(port_range).strip()
    if text == "*":
        return True
    if text == str(port):
        return True
    if "-" in text:
        low, _, high = text.partition("-")
        try:
            return int(low) <= port <= int(high)
        except ValueError:
            return False
    return False


def rule_opens_port_to_internet(rule: dict, port: int) -> bool:
    """Prowler's fail condition for "port <n> reachable from the Internet"."""
    ranges = [rule.get("destination_port_range"), *(rule.get("destination_port_ranges") or [])]
    sources = [rule.get("source_address_prefix"), *(rule.get("source_address_prefixes") or [])]
    return (
        any(_port_in_range(r, port) for r in ranges)
        and rule.get("protocol") in ANY_TCP_PROTOCOLS
        and any(s in INTERNET_SOURCE_PREFIXES for s in sources)
        and rule.get("access") == "Allow"
        and rule.get("direction") == "Inbound"
    )


def summarize(
    security_groups: list[dict],
    virtual_networks: list[dict],
    network_interfaces: list[dict] | None = None,
) -> dict:
    """Counts a reviewer reads first: admin ports exposed, subnets and NICs left
    unprotected, and how much Internet egress the NSGs allow.
    """
    nics = network_interfaces or []
    rules = [rule for g in security_groups for rule in g["security_rules"]]
    subnets = [s for v in virtual_networks for s in v["subnets"]]
    associated = sum(1 for s in subnets if s["nsg_id"])

    exposure = {
        f"{label}_open_to_internet_groups": sum(
            1
            for g in security_groups
            if any(rule_opens_port_to_internet(r, port) for r in g["security_rules"])
        )
        for label, port in ADMIN_PORTS.items()
    }

    return {
        "total_network_security_groups": len(security_groups),
        "total_security_rules": len(rules),
        "inbound_allow_rules": sum(
            1 for r in rules if r["direction"] == "Inbound" and r["access"] == "Allow"
        ),
        "internet_sourced_allow_rules": sum(
            1
            for r in rules
            if r["access"] == "Allow"
            and r["direction"] == "Inbound"
            and (
                r["source_address_prefix"] in INTERNET_SOURCE_PREFIXES
                or any(s in INTERNET_SOURCE_PREFIXES for s in r["source_address_prefixes"])
            )
        ),
        **exposure,
        "total_virtual_networks": len(virtual_networks),
        "ddos_protected_virtual_networks": sum(
            1 for v in virtual_networks if v["enable_ddos_protection"]
        ),
        "total_subnets": len(subnets),
        "subnets_with_nsg": associated,
        "subnets_without_nsg": len(subnets) - associated,
        "subnet_nsg_coverage_percentage": coverage_percentage(associated, len(subnets)),
        # --- outbound (custom rules only, like the inbound counts above) ---
        "outbound_allow_rules": sum(
            1 for r in rules if r["direction"] == "Outbound" and r["access"] == "Allow"
        ),
        "outbound_deny_rules": sum(
            1 for r in rules if r["direction"] == "Outbound" and r["access"] == "Deny"
        ),
        "internet_destined_allow_rules": sum(1 for r in rules if rule_allows_internet_outbound(r)),
        # --- outbound, effective (custom + default rules in priority order) ---
        "unrestricted_internet_outbound_groups": sum(
            1 for g in security_groups if unrestricted_internet_outbound(g)
        ),
        "restricted_internet_outbound_groups": sum(
            1 for g in security_groups if not unrestricted_internet_outbound(g)
        ),
        # --- network interfaces: NSG on the NIC, or inherited from its subnet ---
        "total_network_interfaces": len(nics),
        "nics_with_nic_nsg": sum(1 for n in nics if n["nsg_id"]),
        "nics_protected_by_subnet_nsg_only": sum(
            1 for n in nics if n["nsg_protection_source"] == "subnet"
        ),
        "nics_without_any_nsg": sum(1 for n in nics if not n["protected_by_nsg"]),
        "nic_nsg_coverage_percentage": coverage_percentage(
            sum(1 for n in nics if n["protected_by_nsg"]), len(nics)
        ),
    }


# --- collection (lazy azure imports) ---

def collect_network(
    subscription_id, cred, collector: Collector
) -> tuple[list[dict], list[dict], list[dict]]:
    """Three subscription-wide list calls: NSGs (with inline and default rules), VNets
    and network interfaces.

    `list_all()` is the subscription-scoped variant (vs `list(resource_group)`) and
    returns an ItemPaged, so the SDK follows nextLink itself. NICs are resolved against
    the VNets' subnets after both lists return, so subnet-inherited NSGs count.
    """
    from azure.mgmt.network import NetworkManagementClient

    def _client():
        return NetworkManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("network.NetworkManagementClient (init)", _client)
    if client is None:
        return [], [], []

    groups = collector.guard(
        "network.network_security_groups.list_all",
        lambda: [
            security_group_record(project_security_group(g))
            for g in client.network_security_groups.list_all()
        ],
        default=[],
    )
    vnets = collector.guard(
        "network.virtual_networks.list_all",
        lambda: [
            virtual_network_record(project_virtual_network(v))
            for v in client.virtual_networks.list_all()
        ],
        default=[],
    )

    raw_nics = collector.guard(
        "network.network_interfaces.list_all",
        lambda: [project_network_interface(n) for n in client.network_interfaces.list_all()],
        default=[],
    )
    subnet_index = subnet_nsg_index(vnets)
    nics = [network_interface_record(n, subnet_index) for n in raw_nics]

    return (
        sorted(groups, key=lambda r: r.get("id") or ""),
        sorted(vnets, key=lambda r: r.get("id") or ""),
        sorted(nics, key=lambda r: r.get("id") or ""),
    )


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which would
    # bury this fetcher's own lines and dominate the runner's stderr tail.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    security_groups: list[dict] = []
    virtual_networks: list[dict] = []
    network_interfaces: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list calls, so a zero-NSG result is legible: Azure
        # returns an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Network"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Network is not registered on subscription %s — no "
                "networking in use; reporting status not_registered",
                subscription_id,
            )
        security_groups, virtual_networks, network_interfaces = collect_network(
            subscription_id, cred, collector
        )
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
        results={
            "network_security_groups": security_groups,
            "virtual_networks": virtual_networks,
            "network_interfaces": network_interfaces,
            "provider_registration_status": registration,
        },
        summary={
            **summarize(security_groups, virtual_networks, network_interfaces),
            "provider_registration_status": registration,
        },
    )

    filename = (
        f"azure_network_security_groups_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
