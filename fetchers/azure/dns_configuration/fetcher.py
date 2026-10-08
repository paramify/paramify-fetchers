#!/usr/bin/env python3
"""Azure DNS public zones with DNSSEC state, and private zones with their VNet links."""

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
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)

logger = logging.getLogger("azure_dns_configuration")

DNSSEC_API_VERSION = "2023-07-01-preview"



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


DNSSEC_READ_FAILED = object()


def public_zone_record(zone: dict, dnssec) -> dict:
    """`dnssec` is the projected config, None when unsigned, or DNSSEC_READ_FAILED (state unknown)."""
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


def project_vnet_link(link) -> dict:
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


def private_zone_record(zone: dict, links: list[dict]) -> dict:
    return {
        **zone,
        "resource_group": resource_group_from_id(zone.get("id")),
        "tags": zone.get("tags") or {},
        "virtual_network_links": links,
    }


def summarize(public: list[dict], private: list[dict]) -> dict:
    total = len(public)
    signed = sum(1 for z in public if z["dnssec_enabled"] is True)
    unknown = sum(1 for z in public if z["dnssec_enabled"] is None)
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
        records.append(public_zone_record(zone, dnssec))
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

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "public_zones": public,
            "private_zones": private,
            "provider_registration_status": registration,
        },
        summary={**summarize(public, private), "provider_registration_status": registration},
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
