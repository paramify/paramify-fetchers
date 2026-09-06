#!/usr/bin/env python3
"""
GCP VPC Firewall Rules

Every VPC firewall rule in one project with the fields that decide network
exposure: direction, allowed and denied protocol/port ranges, source and
destination ranges, target tags and service accounts, priority, disabled state
and rule logging — the evidence for "is SSH, RDP or anything else open to
0.0.0.0/0". Only `allowed` rules can expose a port, so the exposure fields
derive from those alone; `denied` entries are reported as segmentation context.

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

logger = logging.getLogger("gcp_firewall_rules")

# "The whole internet". Prowler matches only the IPv4 any-address; a dual-stack
# VPC with ::/0 is equally exposed.
INTERNET_RANGES = frozenset({"0.0.0.0/0", "::/0"})

# Ports whose exposure to the internet is the finding, and the service name
# reported for each. 22 (SSH) and 3389 (RDP) are Prowler's two firewall checks;
# the rest are the remote-administration and datastore ports that should never
# answer from 0.0.0.0/0. Deliberately a fixed, documented table rather than a
# config knob: the evidence has to mean the same thing across every project.
SENSITIVE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    135: "msrpc",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    2375: "docker_api",
    2379: "etcd",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# Protocols a port number is meaningful for; `all` is handled separately. Every
# SENSITIVE_PORTS entry is TCP, matching Prowler's tcp-only port matching.
_PORT_PROTOCOLS = ("tcp",)


# --- pure transforms ---

def port_spec_covers(spec, port: int) -> bool:
    """True when a Compute `ports` entry covers `port`.

    Entries are a single port ("22") or an inclusive range ("3000-3100"), per
    Prowler's expansion. An unparseable entry counts as no match rather than
    raising: a malformed rule must not take down the collection.
    """
    text = str(spec).strip()
    if "-" in text:
        low, _, high = text.partition("-")
        try:
            return int(low) <= port <= int(high)
        except ValueError:
            return False
    try:
        return int(text) == port
    except ValueError:
        return False


def protocol_rule(entry: dict) -> dict:
    """Normalize one `allowed` / `denied` entry.

    The protocol key is `I_p_protocol` from a GAPIC `to_dict()` (verified against
    google-cloud-compute) and `IPProtocol` over REST, hence the spelling list. No
    `ports` means every port of that protocol — the exposure Prowler flags — so
    `all_ports` states it rather than leaving an empty list to interpret.
    """
    ports = [str(p) for p in (first(entry, "ports") or [])]
    protocol = first(entry, "I_p_protocol", "IPProtocol", "ip_protocol", "i_p_protocol")
    return {
        "protocol": protocol,
        "ports": ports,
        "all_ports": not ports,
    }


def rules_cover_port(rules: list[dict], port: int) -> bool:
    """True when any normalized rule opens `port`."""
    for rule in rules:
        protocol = str(rule.get("protocol") or "").lower()
        if protocol == "all":
            return True
        if protocol not in _PORT_PROTOCOLS:
            continue
        specs = rule.get("ports") or []
        if not specs:
            return True
        if any(port_spec_covers(spec, port) for spec in specs):
            return True
    return False


def rules_cover_every_port(rules: list[dict]) -> bool:
    """True when any rule opens every port of its protocol (or every protocol)."""
    return any(
        str(rule.get("protocol") or "").lower() == "all" or not (rule.get("ports") or [])
        for rule in rules
    )


def firewall_record(firewall: dict) -> dict:
    """Normalize one firewall rule into an evidence record."""
    allowed = [protocol_rule(r) for r in (first(firewall, "allowed") or [])]
    denied = [protocol_rule(r) for r in (first(firewall, "denied") or [])]
    source_ranges = sorted(first(firewall, "sourceRanges", "source_ranges") or [])
    destination_ranges = sorted(
        first(firewall, "destinationRanges", "destination_ranges") or []
    )
    source_tags = sorted(first(firewall, "sourceTags", "source_tags") or [])
    source_service_accounts = sorted(
        first(firewall, "sourceServiceAccounts", "source_service_accounts") or []
    )
    target_tags = sorted(first(firewall, "targetTags", "target_tags") or [])
    target_service_accounts = sorted(
        first(firewall, "targetServiceAccounts", "target_service_accounts") or []
    )
    log_config = first(firewall, "logConfig", "log_config") or {}
    direction = first(firewall, "direction")
    disabled = bool(first(firewall, "disabled"))

    ingress = str(direction or "").upper() == "INGRESS"
    from_internet = bool(INTERNET_RANGES & set(source_ranges))
    # Egress, deny and disabled rules expose nothing; all three are still reported.
    exposing = ingress and from_internet and not disabled and bool(allowed)

    return {
        "name": first(firewall, "name"),
        "id": first(firewall, "id"),
        "description": first(firewall, "description"),
        "network": basename(first(firewall, "network")),
        "direction": direction,
        "priority": first(firewall, "priority"),
        "disabled": disabled,
        "enforced": not disabled,
        # A rule carries either `allowed` or `denied`, never both.
        "action": "allow" if allowed else ("deny" if denied else None),
        "allowed": allowed,
        "denied": denied,
        "source_ranges": source_ranges,
        "destination_ranges": destination_ranges,
        "source_tags": source_tags,
        "source_service_accounts": source_service_accounts,
        "target_tags": target_tags,
        "target_service_accounts": target_service_accounts,
        # No target selector means the rule hits every instance in the network.
        "applies_to_all_instances": not target_tags and not target_service_accounts,
        "source_includes_internet": from_internet,
        "open_to_internet": exposing,
        "exposes_all_ports": exposing and rules_cover_every_port(allowed),
        "internet_exposed_sensitive_services": sorted(
            {
                service
                for port, service in SENSITIVE_PORTS.items()
                if rules_cover_port(allowed, port)
            }
        )
        if exposing
        else [],
        "logging_enabled": bool(first(log_config, "enable")),
        "log_metadata": first(log_config, "metadata"),
        "creation_timestamp": first(firewall, "creationTimestamp", "creation_timestamp"),
    }


def summarize(rules: list[dict], *, api_readable: bool = True) -> dict:
    exposing = [r for r in rules if r["internet_exposed_sensitive_services"]]
    services = sorted({s for r in exposing for s in r["internet_exposed_sensitive_services"]})
    logging_enabled = sum(1 for r in rules if r["logging_enabled"])
    return {
        # False when compute.googleapis.com is not enabled (recorded in
        # metadata.skipped_calls) or the list call failed — not "no rules".
        "compute_api_readable": api_readable,
        "total_rules": len(rules),
        "ingress_rules": sum(1 for r in rules if str(r["direction"] or "").upper() == "INGRESS"),
        "egress_rules": sum(1 for r in rules if str(r["direction"] or "").upper() == "EGRESS"),
        "allow_rules": sum(1 for r in rules if r["action"] == "allow"),
        "deny_rules": sum(1 for r in rules if r["action"] == "deny"),
        "disabled_rules": sum(1 for r in rules if r["disabled"]),
        "rules_open_to_internet": sum(1 for r in rules if r["open_to_internet"]),
        # Enforced ingress allow rules reaching a SENSITIVE_PORTS service.
        "rules_exposing_sensitive_ports_to_internet": len(exposing),
        "internet_exposed_sensitive_services": services,
        "ssh_open_to_internet": "ssh" in services,
        "rdp_open_to_internet": "rdp" in services,
        "rules_exposing_all_ports_to_internet": sum(1 for r in rules if r["exposes_all_ports"]),
        "internet_open_rules_applying_to_all_instances": sum(
            1 for r in rules if r["open_to_internet"] and r["applies_to_all_instances"]
        ),
        "rules_with_logging_enabled": logging_enabled,
        "logging_enabled_percentage": coverage_percentage(logging_enabled, len(rules)),
        "networks_with_rules": sorted({r["network"] for r in rules if r["network"]}),
    }


# --- collection ---

def collect_firewall_rules(project, creds, collector: Collector) -> list[dict] | None:
    """Every firewall rule in the project, or None when Compute could not be listed."""
    from google.cloud import compute_v1

    def _list():
        client = compute_v1.FirewallsClient(credentials=creds)
        # Firewall rules are a global resource — no per-region walk.
        return [
            firewall_record(compute_v1.Firewall.to_dict(f))
            for f in client.list(project=project)
        ]

    records = collector.guard("compute.firewalls.list", _list, tolerate=service_disabled)
    if records is None:
        return None
    return sorted(records, key=lambda r: (r.get("network") or "", r.get("name") or ""))


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

    rules: list[dict] | None = None
    if project and creds is not None:
        rules = collect_firewall_rules(project, creds, collector)
    elif not project:
        collector.record(
            "resolve_project",
            RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"),
        )

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"firewall_rules": rules or []},
        summary=summarize(rules or [], api_readable=rules is not None),
    )

    filename = f"gcp_firewall_rules_{sanitize_for_filename(project or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
