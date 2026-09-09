#!/usr/bin/env python3
"""
GCP VPC Network Configuration

Network-segmentation evidence for one project: every VPC network with its subnet
mode (legacy / auto / custom), routing mode, peerings and subnet count; and every
subnet with its CIDR, Private Google Access, and VPC flow logs — enabled or not,
and when enabled the aggregation interval, sampling rate, metadata setting and
any capture filter. Whether the auto-created `default` network still exists is
reported explicitly.

Ported from Prowler's GCP compute service (Apache-2.0).
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from gcp_common import (  # noqa: E402
    Collector,
    basename,
    build_payload,
    coverage_percentage,
    credentials,
    first,
    resolve_project,
    sanitize_for_filename,
    service_disabled,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("gcp_vpc_network_configuration")

# The auto-created network every new project gets: auto mode, one subnet per
# region, permissive default-allow rules — Prowler's compute_network_default_in_use.
DEFAULT_NETWORK_NAME = "default"

_SUBNET_MODE_LEGACY = "legacy"
_SUBNET_MODE_AUTO = "auto"
_SUBNET_MODE_CUSTOM = "custom"


# --- pure transforms ---

def subnet_mode(network: dict) -> str:
    """Prowler's legacy / auto / custom classification.

    A presence test, not a boolean read: a legacy network has no
    `autoCreateSubnetworks` field at all, so absent and `False` differ.
    GAPIC `to_dict()` omits unset optional fields, so that distinction survives.
    """
    for key in ("autoCreateSubnetworks", "auto_create_subnetworks"):
        if key in network:
            return _SUBNET_MODE_AUTO if network[key] else _SUBNET_MODE_CUSTOM
    return _SUBNET_MODE_LEGACY


def network_record(network: dict) -> dict:
    """Normalize one VPC network into an evidence record."""
    mode = subnet_mode(network)
    subnetworks = first(network, "subnetworks") or []
    peerings = first(network, "peerings") or []
    name = first(network, "name")
    return {
        "name": name,
        "id": first(network, "id"),
        "description": first(network, "description"),
        "subnet_mode": mode,
        "auto_mode": mode == _SUBNET_MODE_AUTO,
        "custom_mode": mode == _SUBNET_MODE_CUSTOM,
        "legacy": mode == _SUBNET_MODE_LEGACY,
        "is_default_network": name == DEFAULT_NETWORK_NAME,
        # Only a legacy network has a network-wide IPv4 range.
        "legacy_ipv4_range": first(network, "IPv4Range", "I_pv4_range", "ipv4_range"),
        "routing_mode": first(
            first(network, "routingConfig", "routing_config") or {},
            "routingMode",
            "routing_mode",
        ),
        "mtu": first(network, "mtu"),
        "subnet_count": len(subnetworks),
        "subnet_names": sorted(basename(s) for s in subnetworks),
        "peering_count": len(peerings),
        "peerings": sorted(
            {
                str(first(p, "name"))
                for p in peerings
                if first(p, "name")
            }
        ),
        "firewall_policy_enforcement_order": first(
            network,
            "networkFirewallPolicyEnforcementOrder",
            "network_firewall_policy_enforcement_order",
        ),
        "creation_timestamp": first(network, "creationTimestamp", "creation_timestamp"),
    }


def subnet_record(subnet: dict) -> dict:
    """Normalize one subnet into an evidence record.

    `logConfig.enable` is the field the API maintains; `enableFlowLogs` is the
    deprecated top-level flag Prowler reads, kept here as a fallback.
    """
    log_config = first(subnet, "logConfig", "log_config") or {}
    log_config_enable = first(log_config, "enable")
    legacy_flag = first(subnet, "enableFlowLogs", "enable_flow_logs")
    flow_logs = bool(log_config_enable if log_config_enable is not None else legacy_flag)
    filter_expr = first(log_config, "filterExpr", "filter_expr")

    return {
        "name": first(subnet, "name"),
        "id": first(subnet, "id"),
        "region": basename(first(subnet, "region")),
        "network": basename(first(subnet, "network")),
        "ip_cidr_range": first(subnet, "ipCidrRange", "ip_cidr_range"),
        "secondary_range_count": len(
            first(subnet, "secondaryIpRanges", "secondary_ip_ranges") or []
        ),
        "purpose": first(subnet, "purpose"),
        "role": first(subnet, "role"),
        "stack_type": first(subnet, "stackType", "stack_type"),
        "state": first(subnet, "state"),
        # Lets a VM with no external IP reach Google APIs.
        "private_google_access": bool(
            first(subnet, "privateIpGoogleAccess", "private_ip_google_access")
        ),
        # --- VPC flow logs ---
        "flow_logs_enabled": flow_logs,
        "flow_log_aggregation_interval": first(
            log_config, "aggregationInterval", "aggregation_interval"
        ),
        "flow_log_sampling": first(log_config, "flowSampling", "flow_sampling"),
        "flow_log_metadata": first(log_config, "metadata"),
        "flow_log_metadata_field_count": len(
            first(log_config, "metadataFields", "metadata_fields") or []
        ),
        # A filter narrows what is captured, so full-coverage claims need it read.
        "flow_log_filtered": bool(filter_expr),
        "flow_log_filter": filter_expr,
        "creation_timestamp": first(subnet, "creationTimestamp", "creation_timestamp"),
    }


def summarize(
    networks: list[dict], subnets: list[dict], *, api_readable: bool = True
) -> dict:
    with_subnets = {s["network"] for s in subnets if s["network"]}
    flow_logs = sum(1 for s in subnets if s["flow_logs_enabled"])
    private_access = sum(1 for s in subnets if s["private_google_access"])
    return {
        # False when compute.googleapis.com is disabled or a list call failed —
        # "could not look", not "no networks".
        "compute_api_readable": api_readable,
        "total_networks": len(networks),
        "default_network_present": any(n["is_default_network"] for n in networks),
        "legacy_networks": sum(1 for n in networks if n["legacy"]),
        "auto_mode_networks": sum(1 for n in networks if n["auto_mode"]),
        "custom_mode_networks": sum(1 for n in networks if n["custom_mode"]),
        "custom_mode_percentage": coverage_percentage(
            sum(1 for n in networks if n["custom_mode"]), len(networks)
        ),
        "peered_networks": sum(1 for n in networks if n["peering_count"] > 0),
        "networks_without_subnets": sorted(
            n["name"] for n in networks if n["name"] and n["name"] not in with_subnets
        ),
        "total_subnets": len(subnets),
        "regions_with_subnets": sorted({s["region"] for s in subnets if s["region"]}),
        "subnets_with_flow_logs": flow_logs,
        "flow_log_percentage": coverage_percentage(flow_logs, len(subnets)),
        "subnets_with_filtered_flow_logs": sum(1 for s in subnets if s["flow_log_filtered"]),
        "flow_log_aggregation_intervals": sorted(
            {
                str(s["flow_log_aggregation_interval"])
                for s in subnets
                if s["flow_logs_enabled"] and s["flow_log_aggregation_interval"]
            }
        ),
        # One subnet at 0.1% is the weak link in an otherwise fully-logged VPC.
        "lowest_flow_log_sampling": min(
            (
                s["flow_log_sampling"]
                for s in subnets
                if s["flow_logs_enabled"] and s["flow_log_sampling"] is not None
            ),
            default=None,
        ),
        "subnets_with_private_google_access": private_access,
        "private_google_access_percentage": coverage_percentage(private_access, len(subnets)),
    }


# --- collection ---

def collect_networks(project, creds, collector: Collector) -> list[dict] | None:
    """Every VPC network in the project, or None when Compute could not be listed."""
    from google.cloud import compute_v1

    def _list():
        client = compute_v1.NetworksClient(credentials=creds)
        # Networks are a global resource; the GAPIC pager walks every page.
        return [
            network_record(compute_v1.Network.to_dict(n))
            for n in client.list(project=project)
        ]

    records = collector.guard("compute.networks.list", _list, tolerate=service_disabled)
    if records is None:
        return None
    return sorted(records, key=lambda r: r.get("name") or "")


def collect_subnets(project, creds, collector: Collector) -> list[dict] | None:
    """Every subnet in the project, or None when Compute could not be listed."""
    from google.cloud import compute_v1

    def _list():
        client = compute_v1.SubnetworksClient(credentials=creds)
        out = []
        for _region, scoped in client.aggregated_list(project=project):
            for subnet in getattr(scoped, "subnetworks", []) or []:
                out.append(subnet_record(compute_v1.Subnetwork.to_dict(subnet)))
        return out

    records = collector.guard(
        "compute.subnetworks.aggregatedList", _list, tolerate=service_disabled
    )
    if records is None:
        return None
    return sorted(
        records,
        key=lambda r: (r.get("network") or "", r.get("region") or "", r.get("name") or ""),
    )


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    proj = resolve_project(collector)
    project = proj["project"]
    creds = collector.guard("google.auth.default (credentials)", credentials)

    networks: list[dict] | None = None
    subnets: list[dict] | None = None
    if project and creds is not None:
        networks = collect_networks(project, creds, collector)
        subnets = collect_subnets(project, creds, collector)
    elif not project:
        collector.record(
            "resolve_project",
            RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"),
        )

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"networks": networks or [], "subnets": subnets or []},
        summary=summarize(
            networks or [],
            subnets or [],
            api_readable=networks is not None and subnets is not None,
        ),
    )

    filename = f"gcp_vpc_network_configuration_{sanitize_for_filename(project or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
