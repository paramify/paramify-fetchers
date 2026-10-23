#!/usr/bin/env python3
"""Azure DNS public zones with DNSSEC state and record sets, and private zones with their VNet links."""

import logging
import os
import sys
from collections import Counter
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
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    sorted_counts,
    write_evidence,
)
from private_dns import project_vnet_link  # noqa: E402
from scope_exclusions import ScopeExclusions, excluded_item  # noqa: E402

logger = logging.getLogger("azure_dns_configuration")

SCOPE_EXCLUSIONS_ENV = "AZURE_DNS_SCOPE_EXCLUSIONS"

DNSSEC_API_VERSION = "2023-07-01-preview"

ENDPOINT_TYPES = ("A", "AAAA", "CNAME")
FAILOVER_METHODS = ("front_door", "traffic_manager", "cdn", "record_update")
ALIAS_TARGET_TYPES = {
    "microsoft.cdn/profiles/afdendpoints": "front_door",
    "microsoft.network/frontdoors": "front_door",
    "microsoft.network/trafficmanagerprofiles": "traffic_manager",
    "microsoft.cdn/profiles/endpoints": "cdn_endpoint",
    "microsoft.network/publicipaddresses": "public_ip",
}
RECORD_SET_TYPE_PREFIX = "microsoft.network/dnszones/"
CNAME_SUFFIXES = (
    (".azurefd.net", "front_door"),
    (".trafficmanager.net", "traffic_manager"),
    (".usgovtrafficmanager.net", "traffic_manager"),
    (".azureedge.net", "cdn"),
)


def project_public_zone(zone) -> dict:
    return {
        "id": model_attr(zone, "id"),
        "name": model_attr(zone, "name"),
        "zone_type": model_attr(zone, "zone_type"),
        "tags": model_attr(zone, "tags"),
        "name_servers": model_attr(zone, "name_servers"),
        "number_of_record_sets": model_attr(zone, "number_of_record_sets"),
    }


def project_dnssec_config(body: dict) -> dict:
    """Wire-shape JSON from the REST call; DS digest values are omitted, counts kept."""
    props = (body or {}).get("properties") or {}
    keys = props.get("signingKeys") or []
    return {
        "provisioning_state": props.get("provisioningState"),
        "signing_keys": [
            {
                "flags": k.get("flags"),
                "key_tag": k.get("keyTag"),
                "protocol": k.get("protocol"),
                "security_algorithm_type": k.get("securityAlgorithmType"),
                "delegation_signer_records": len(k.get("delegationSignerInfo") or []),
            }
            for k in keys
        ],
    }


def arm_resource_type(resource_id: str | None) -> str | None:
    """Lower-cased ARM type of a resource id, e.g. microsoft.cdn/profiles/afdendpoints."""
    parts = (resource_id or "").strip("/").split("/")
    lowered = [p.lower() for p in parts]
    if "providers" not in lowered:
        return None
    rest = parts[lowered.index("providers") + 1:]
    if len(rest) < 3:
        return None
    return "/".join([rest[0], *rest[1::2]]).lower()


def joined(*parts) -> str:
    return " ".join(str(p) for p in parts if p is not None and p != "")


def record_targets(rs, record_type: str) -> list[str]:
    """Each value the record set answers with, as one string per record."""
    if record_type == "A":
        return [model_attr(r, "ipv4_address") for r in model_attr(rs, "a_records") or []]
    if record_type == "AAAA":
        return [model_attr(r, "ipv6_address") for r in model_attr(rs, "aaaa_records") or []]
    if record_type == "CNAME":
        cname = model_attr(model_attr(rs, "cname_record"), "cname")
        return [cname] if cname else []
    if record_type == "MX":
        return [joined(model_attr(r, "preference"), model_attr(r, "exchange")) for r in model_attr(rs, "mx_records") or []]
    if record_type == "NS":
        return [model_attr(r, "nsdname") for r in model_attr(rs, "ns_records") or []]
    if record_type == "PTR":
        return [model_attr(r, "ptrdname") for r in model_attr(rs, "ptr_records") or []]
    if record_type == "TXT":
        # A TXT record over 255 characters arrives as several strings.
        return ["".join(model_attr(r, "value") or []) for r in model_attr(rs, "txt_records") or []]
    if record_type == "SRV":
        return [joined(*(model_attr(r, k) for k in ("priority", "weight", "port", "target")))
                for r in model_attr(rs, "srv_records") or []]
    if record_type == "CAA":
        return [joined(model_attr(r, "flags"), model_attr(r, "tag"),
                       None if model_attr(r, "value") is None else f'"{model_attr(r, "value")}"')
                for r in model_attr(rs, "caa_records") or []]
    if record_type == "SOA":
        soa = model_attr(rs, "soa_record")
        return [joined(model_attr(soa, "host"), model_attr(soa, "email"))] if soa else []
    return []


def failover_method(record_type: str, alias_type: str | None, targets: list[str]) -> str | None:
    """How an A, AAAA or CNAME record moves traffic to another region; None for other types and empty records."""
    if record_type not in ENDPOINT_TYPES or not (alias_type or targets):
        return None
    if alias_type in ("front_door", "traffic_manager"):
        return alias_type
    if alias_type == "cdn_endpoint":
        return "cdn"
    if record_type == "CNAME" and not alias_type:
        host = (targets[0] if targets else "").rstrip(".").lower()
        for suffix, method in CNAME_SUFFIXES:
            if host.endswith(suffix):
                return method
    return "record_update"


def alias_target_type(alias_id: str | None) -> str | None:
    if not alias_id:
        return None
    arm_type = arm_resource_type(alias_id) or ""
    return "record_set" if arm_type.startswith(RECORD_SET_TYPE_PREFIX) else ALIAS_TARGET_TYPES.get(arm_type, "other")


def project_record_set(rs) -> dict:
    record_type = str(model_attr(rs, "type") or "").rsplit("/", 1)[-1].upper()
    alias_id = model_attr(model_attr(rs, "target_resource"), "id")
    alias_type = alias_target_type(alias_id)
    targets = [t for t in record_targets(rs, record_type) if t]
    return {
        "name": model_attr(rs, "name"),
        "fqdn": model_attr(rs, "fqdn"),
        "type": record_type,
        "ttl": model_attr(rs, "ttl"),
        "targets": targets,
        "alias_target_resource_id": alias_id,
        "alias_target_type": alias_type,
        "failover_method": failover_method(record_type, alias_type, targets),
        "same_zone_target": None,
        "provisioning_state": model_attr(rs, "provisioning_state"),
    }


def same_zone_link(record: dict, zone_name: str) -> tuple[str, tuple[str, ...]] | None:
    """(name, types) of the record set in this zone an alias or CNAME points at."""
    zone = (zone_name or "").rstrip(".").lower()
    if record["alias_target_type"] == "record_set":
        # .../dnszones/<zone>/<TYPE>/<name>
        parts = record["alias_target_resource_id"].rstrip("/").split("/")
        return (parts[-1], (parts[-2].upper(),)) if len(parts) >= 3 and parts[-3].lower() == zone else None
    if record["type"] == "CNAME" and record["targets"] and not record["alias_target_resource_id"]:
        host = record["targets"][0].rstrip(".").lower()
        if host == zone:
            return "@", ENDPOINT_TYPES
        if zone and host.endswith("." + zone):
            return host[:-len(zone) - 1], ENDPOINT_TYPES
    return None


def resolve_zone_links(record_sets: list[dict], zone_name: str) -> list[dict]:
    """One hop: a record pointing at another record set in the zone takes that record set's own failover method."""
    direct = {(str(r["name"]).lower(), r["type"]): r["failover_method"] for r in record_sets}
    for record in record_sets:
        link = same_zone_link(record, zone_name) if record["type"] in ENDPOINT_TYPES else None
        if not link:
            continue
        name, types = link
        # A name with no record set here, such as one in a delegated child zone, is not a link.
        if not any((name.lower(), t) in direct for t in types):
            continue
        record["same_zone_target"] = name
        methods = {direct.get((name.lower(), t)) for t in types} - {None}
        if record["failover_method"] == "record_update" and len(methods) == 1:
            record["failover_method"] = methods.pop()
    return record_sets


DNSSEC_READ_FAILED = object()


def public_zone_record(zone: dict, dnssec, record_sets: list[dict] | None = None) -> dict:
    """`dnssec` is the projected config, None when unsigned, or DNSSEC_READ_FAILED; `record_sets` is None when unread."""
    read_failed = dnssec is DNSSEC_READ_FAILED
    dnssec = None if read_failed else dnssec
    keys = (dnssec or {}).get("signing_keys") or []
    state = (dnssec or {}).get("provisioning_state")
    return {
        **zone,
        "resource_group": resource_group_from_id(zone.get("id")),
        "tags": zone.get("tags") or {},
        "name_servers": zone.get("name_servers") or [],
        "dnssec_provisioning_state": state,
        "dnssec_signing_keys": keys,
        "dnssec_enabled": None if read_failed else (str(state or "").lower() == "succeeded" and bool(keys)),
        "delegation_signer_records": sum(k["delegation_signer_records"] for k in keys),
        "record_sets": record_sets,
    }


def project_private_zone(zone) -> dict:
    return {
        "id": model_attr(zone, "id"),
        "name": model_attr(zone, "name"),
        "tags": model_attr(zone, "tags"),
        "number_of_record_sets": model_attr(zone, "number_of_record_sets"),
        "number_of_virtual_network_links": model_attr(zone, "number_of_virtual_network_links"),
        "number_of_virtual_network_links_with_registration": model_attr(
            zone, "number_of_virtual_network_links_with_registration"
        ),
        "provisioning_state": model_attr(zone, "provisioning_state"),
    }


def private_zone_record(zone: dict, links: list[dict]) -> dict:
    return {
        **zone,
        "resource_group": resource_group_from_id(zone.get("id")),
        "tags": zone.get("tags") or {},
        "virtual_network_links": links,
    }


def exclude_record_sets(public: list[dict], exclusions: ScopeExclusions) -> tuple[list[dict], list[dict]]:
    """Each zone without the record sets whose relative name or FQDN matches a pattern, and those record sets."""
    zones, excluded = [], []
    for zone in public:
        if zone["record_sets"] is None:
            zones.append(zone)
            continue
        kept = []
        for record in zone["record_sets"]:
            pattern = exclusions.match(record["name"], record["fqdn"])
            if pattern is None:
                kept.append(record)
                continue
            excluded.append(excluded_item("record_set", record["name"], pattern, zone=zone["name"], zone_id=zone["id"],
                                          type=record["type"], fqdn=record["fqdn"]))
        zones.append({**zone, "record_sets": kept})
    return zones, excluded


def summarize(public: list[dict], private: list[dict]) -> dict:
    total = len(public)
    signed = sum(1 for z in public if z["dnssec_enabled"] is True)
    unknown = sum(1 for z in public if z["dnssec_enabled"] is None)
    record_sets = [r for z in public for r in z.get("record_sets") or []]
    endpoints = [r for r in record_sets if r["type"] in ENDPOINT_TYPES]
    by_method = Counter(r["failover_method"] for r in endpoints)
    return {
        "total_public_zones": total,
        "dnssec_enabled_public_zones": signed,
        "dnssec_disabled_public_zones": total - signed - unknown,
        "dnssec_unknown_public_zones": unknown,
        "dnssec_percentage": coverage_percentage(signed, total),
        "total_private_zones": len(private),
        "total_private_zone_virtual_network_links": sum(
            len(z["virtual_network_links"]) for z in private
        ),
        "private_zones_without_links": sum(1 for z in private if not z["virtual_network_links"]),
        "auto_registration_links": sum(
            1 for z in private for link in z["virtual_network_links"] if link["registration_enabled"]
        ),
        "total_public_record_sets": len(record_sets),
        "public_zones_record_sets_unread": sum(1 for z in public if z.get("record_sets") is None),
        "public_record_sets_by_type": sorted_counts(Counter(r["type"] for r in record_sets)),
        "public_alias_record_sets": sum(1 for r in record_sets if r["alias_target_resource_id"]),
        "public_endpoint_record_sets": len(endpoints),
        "public_endpoint_record_sets_empty": sum(
            1 for r in endpoints if not r["targets"] and not r["alias_target_resource_id"]),
        "public_endpoint_record_sets_by_failover_method": {m: by_method.get(m, 0) for m in FAILOVER_METHODS},
    }


def fetch_dnssec(arm, zone_id: str):
    """GET dnssecConfigs/default through an ARM pipeline client; None when unsigned."""
    from azure.core.rest import HttpRequest  # lazy

    url = f"{zone_id}/dnssecConfigs/default?api-version={DNSSEC_API_VERSION}"
    response = arm.send_request(HttpRequest("GET", url))
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return project_dnssec_config(response.json())


def collect_public_zones(subscription_id, cred, collector: Collector) -> list[dict]:
    def _clients():
        from azure.mgmt.dns import DnsManagementClient  # lazy
        from azure.mgmt.privatedns import PrivateDnsManagementClient  # lazy

        # PrivateDnsManagementClient is only the authenticated ARM pipeline for the DNSSEC GET.
        return (
            DnsManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
            PrivateDnsManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
        )

    clients = collector.guard("dns.DnsManagementClient (init)", _clients)
    if clients is None:
        return []
    dns, arm = clients
    zones = collector.guard(
        "dns.zones.list", lambda: [project_public_zone(z) for z in dns.zones.list()], default=[]
    )
    records = []
    for zone in zones:
        dnssec = collector.guard(
            f"dns.dnssecConfigs.get({zone.get('name')})",
            lambda: fetch_dnssec(arm, zone["id"]),
            default=DNSSEC_READ_FAILED,
        )
        rg = resource_group_from_id(zone.get("id"))
        record_sets = collector.guard(
            f"dns.record_sets.list_all_by_dns_zone({rg}/{zone.get('name')})",
            lambda: resolve_zone_links(sorted(
                (project_record_set(r) for r in dns.record_sets.list_all_by_dns_zone(rg, zone["name"])),
                key=lambda r: (r["name"] or "", r["type"]),
            ), zone["name"]),
        )
        records.append(public_zone_record(zone, dnssec, record_sets))
    return sorted(records, key=lambda r: r.get("id") or "")


def collect_private_zones(subscription_id, cred, collector: Collector) -> list[dict]:
    def _client():
        from azure.mgmt.privatedns import PrivateDnsManagementClient  # lazy

        return PrivateDnsManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    client = collector.guard("privatedns.PrivateDnsManagementClient (init)", _client)
    if client is None:
        return []
    zones = collector.guard(
        "privatedns.private_zones.list",
        lambda: [project_private_zone(z) for z in client.private_zones.list()],
        default=[],
    )
    records = []
    for zone in zones:
        rg = resource_group_from_id(zone.get("id"))
        links = collector.guard(
            f"privatedns.virtual_network_links.list({rg}/{zone.get('name')})",
            lambda: [
                project_vnet_link(link)
                for link in client.virtual_network_links.list(rg, zone["name"])
            ],
            default=[],
        )
        records.append(private_zone_record(zone, sorted(links, key=lambda r: r.get("id") or "")))
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

    public: list[dict] = []
    private: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Network"
        )
        if registration == NOT_REGISTERED:
            logger.warning("Microsoft.Network is not registered on subscription %s", subscription_id)
        public = collect_public_zones(subscription_id, cred, collector)
        private = collect_private_zones(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    exclusions = ScopeExclusions.from_env(SCOPE_EXCLUSIONS_ENV)
    public, excluded = exclude_record_sets(public, exclusions)
    exclusions.warn_unmatched(logger)

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "public_zones": public,
            "private_zones": private,
            "provider_registration_status": registration,
            "excluded": excluded,
        },
        summary={**summarize(public, private), "provider_registration_status": registration,
                 **exclusions.summary(excluded, ("record_set",))},
    )
    filename = f"azure_dns_configuration_{sanitize_for_filename(subscription_id or 'unknown')}.json"
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
