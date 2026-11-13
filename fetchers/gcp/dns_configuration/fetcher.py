#!/usr/bin/env python3
"""
GCP Cloud DNS Configuration

Every Cloud DNS managed zone in one project: DNSSEC state and signing algorithms
(RSASHA1 in either position being the finding), public or private visibility and
query logging, plus the project's DNS policies. Visibility is collected because
DNSSEC does not apply to a private zone at all, so the summary reports DNSSEC
coverage over public zones only.

Ported from Prowler's GCP DNS service (Apache-2.0).
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
    dig_any,
    resolve_project,
    sanitize_for_filename,
    service_disabled,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("gcp_dns_configuration")

# SHA-1 is collision-broken, so a signature chain rooted in it proves nothing.
_WEAK_ALGORITHMS = frozenset({"rsasha1"})

# Key-signing and zone-signing keys are configured independently; either can be
# the weak one, so the two are tracked apart.
_KEY_SIGNING = "keySigning"
_ZONE_SIGNING = "zoneSigning"

# DNSSEC only protects public resolution; a private zone has no public path.
_PUBLIC_VISIBILITY = "public"


# --- pure transforms ---

def key_spec_record(spec: dict) -> dict:
    """One DNSSEC key spec: which key it signs, with what, at what length."""
    algorithm = (dig_any(spec, "algorithm") or "").lower() or None
    return {
        "key_type": dig_any(spec, "key_type") or None,
        "algorithm": algorithm,
        "key_length": dig_any(spec, "key_length"),
        "weak_algorithm": algorithm in _WEAK_ALGORITHMS,
    }


def algorithms_for(specs: list[dict], key_type: str) -> list[str]:
    """The algorithms configured for one key type, deduplicated and sorted."""
    return sorted(
        {s["algorithm"] for s in specs if s["key_type"] == key_type and s["algorithm"]}
    )


def zone_record(zone: dict) -> dict:
    """Normalize one managed zone into an evidence record.

    `visibility` defaults to public: the API omits the field on a public zone, and
    guessing "private" for an absent value would understate the exposure.
    """
    specs = [key_spec_record(s) for s in (dig_any(zone, "dnssec_config", "default_key_specs") or [])]
    # "on" | "off" | "transfer" — kept as a state, not flattened: "transfer" is real.
    state = (dig_any(zone, "dnssec_config", "state") or "").lower() or None
    visibility = (dig_any(zone, "visibility") or _PUBLIC_VISIBILITY).lower()

    key_signing = algorithms_for(specs, _KEY_SIGNING)
    zone_signing = algorithms_for(specs, _ZONE_SIGNING)
    rsasha1_key = any(a in _WEAK_ALGORITHMS for a in key_signing)
    rsasha1_zone = any(a in _WEAK_ALGORITHMS for a in zone_signing)

    private = dig_any(zone, "private_visibility_config") or {}

    return {
        "name": dig_any(zone, "name") or None,
        "id": dig_any(zone, "id") or None,
        "dns_name": dig_any(zone, "dns_name") or None,
        "description": dig_any(zone, "description") or None,
        "creation_time": dig_any(zone, "creation_time") or None,
        "visibility": visibility,
        "public": visibility == _PUBLIC_VISIBILITY,
        "dnssec_applicable": visibility == _PUBLIC_VISIBILITY,
        "dnssec_state": state,
        "dnssec_enabled": state == "on",
        "dnssec_non_existence": dig_any(zone, "dnssec_config", "non_existence") or None,
        "key_specs": specs,
        "key_signing_algorithms": key_signing,
        "zone_signing_algorithms": zone_signing,
        "rsasha1_key_signing": rsasha1_key,
        "rsasha1_zone_signing": rsasha1_zone,
        "uses_weak_signing_algorithm": rsasha1_key or rsasha1_zone,
        "logging_enabled": bool(dig_any(zone, "cloud_logging_config", "enable_logging")),
        "name_servers": sorted(dig_any(zone, "name_servers") or []),
        "name_server_set": dig_any(zone, "name_server_set") or None,
        "private_networks": sorted(
            basename(dig_any(net, "network_url")) or ""
            for net in (dig_any(private, "networks") or [])
        ),
        "private_gke_clusters": sorted(
            dig_any(cluster, "gke_cluster_name") or ""
            for cluster in (dig_any(private, "gke_clusters") or [])
        ),
        # A forwarding or peering zone is where the answers actually come from.
        "forwarding_targets": sorted(
            dig_any(target, "ipv4_address") or dig_any(target, "domain_name") or ""
            for target in (dig_any(zone, "forwarding_config", "target_name_servers") or [])
        ),
        "peering_target_network": basename(
            dig_any(zone, "peering_config", "target_network", "network_url")
        ),
        "reverse_lookup": dig_any(zone, "reverse_lookup_config") is not None,
    }


def policy_record(policy: dict) -> dict:
    """Normalize one DNS policy: logging and inbound forwarding, per network."""
    return {
        "name": dig_any(policy, "name") or None,
        "id": dig_any(policy, "id") or None,
        "description": dig_any(policy, "description") or None,
        "logging_enabled": bool(dig_any(policy, "enable_logging")),
        "inbound_forwarding_enabled": bool(dig_any(policy, "enable_inbound_forwarding")),
        "networks": sorted(
            basename(dig_any(net, "network_url")) or ""
            for net in (dig_any(policy, "networks") or [])
        ),
        "alternative_name_servers": sorted(
            dig_any(target, "ipv4_address") or dig_any(target, "domain_name") or ""
            for target in (
                dig_any(policy, "alternative_name_server_config", "target_name_servers") or []
            )
        ),
    }


def summarize(zones: list[dict], policies: list[dict], api_readable: bool = True) -> dict:
    public = [z for z in zones if z["public"]]
    signed_public = [z for z in public if z["dnssec_enabled"]]
    logged = [z for z in zones if z["logging_enabled"]]

    key_algorithms: dict[str, int] = {}
    zone_algorithms: dict[str, int] = {}
    for zone in zones:
        for algorithm in zone["key_signing_algorithms"]:
            key_algorithms[algorithm] = key_algorithms.get(algorithm, 0) + 1
        for algorithm in zone["zone_signing_algorithms"]:
            zone_algorithms[algorithm] = zone_algorithms.get(algorithm, 0) + 1

    return {
        # False means the API is disabled or unreadable, not that there are no zones.
        "dns_api_readable": api_readable,
        "total_managed_zones": len(zones),
        "public_zones": len(public),
        "private_zones": len(zones) - len(public),
        "dnssec_enabled_zones": sum(1 for z in zones if z["dnssec_enabled"]),
        "dnssec_transferring_zones": sum(1 for z in zones if z["dnssec_state"] == "transfer"),
        # Public zones only: counting private ones as failures would misreport it.
        "dnssec_public_zone_percentage": coverage_percentage(len(signed_public), len(public)),
        "unsigned_public_zones": len(public) - len(signed_public),
        "zones_using_weak_signing_algorithm": sum(
            1 for z in zones if z["uses_weak_signing_algorithm"]
        ),
        "rsasha1_key_signing_zones": sum(1 for z in zones if z["rsasha1_key_signing"]),
        "rsasha1_zone_signing_zones": sum(1 for z in zones if z["rsasha1_zone_signing"]),
        "key_signing_algorithms": dict(sorted(key_algorithms.items())),
        "zone_signing_algorithms": dict(sorted(zone_algorithms.items())),
        "logging_enabled_zones": len(logged),
        "logging_enabled_zone_percentage": coverage_percentage(len(logged), len(zones)),
        "forwarding_zones": sum(1 for z in zones if z["forwarding_targets"]),
        "peering_zones": sum(1 for z in zones if z["peering_target_network"]),
        "total_dns_policies": len(policies),
        "logging_enabled_policies": sum(1 for p in policies if p["logging_enabled"]),
        "inbound_forwarding_policies": sum(
            1 for p in policies if p["inbound_forwarding_enabled"]
        ),
    }


# --- collection ---

def _service(creds):
    # Discovery, not GAPIC: no GAPIC client exposes dnssecConfig. Do not "modernise".
    from googleapiclient.discovery import build

    return build("dns", "v1", credentials=creds, cache_discovery=False)


def _paginate(request_factory, key: str) -> list[dict]:
    """Walk a discovery list endpoint's pageToken chain to the end."""
    items: list[dict] = []
    page_token = None
    while True:
        response = request_factory(page_token).execute()
        items.extend(response.get(key) or [])
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return items


def collect_zones(project, creds, collector: Collector) -> tuple[list[dict], bool]:
    """Managed zones in the project.

    A project that never enabled dns.googleapis.com 403s with SERVICE_DISABLED —
    evidence that it serves no DNS, so it is tolerated and reported as an
    unreadable API rather than a failure.
    """
    def _list():
        service = _service(creds)
        zones = _paginate(
            lambda token: service.managedZones().list(project=project, pageToken=token),
            "managedZones",
        )
        return [zone_record(z) for z in zones]

    zones = collector.guard(
        "dns.managedZones.list", _list, default=None, tolerate=service_disabled
    )
    records = sorted(zones or [], key=lambda z: z.get("name") or "")
    return records, zones is not None


def collect_policies(project, creds, collector: Collector) -> list[dict]:
    def _list():
        service = _service(creds)
        policies = _paginate(
            lambda token: service.policies().list(project=project, pageToken=token),
            "policies",
        )
        return [policy_record(p) for p in policies]

    records = collector.guard(
        "dns.policies.list", _list, default=[], tolerate=service_disabled
    )
    return sorted(records, key=lambda p: p.get("name") or "")


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

    zones: list[dict] = []
    policies: list[dict] = []
    api_readable = False
    if project and creds is not None:
        zones, api_readable = collect_zones(project, creds, collector)
        policies = collect_policies(project, creds, collector)
    elif not project:
        collector.record(
            "resolve_project",
            RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"),
        )

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"managed_zones": zones, "dns_policies": policies},
        summary=summarize(zones, policies, api_readable=api_readable),
    )

    filename = f"gcp_dns_configuration_{sanitize_for_filename(project or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
