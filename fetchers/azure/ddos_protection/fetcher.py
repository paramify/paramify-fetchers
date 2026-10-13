#!/usr/bin/env python3
"""Azure DDoS Protection coverage of every public IP, and the DDoS plans behind it, for one subscription."""

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
    arm_id_key,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    vnet_id_of,
    write_evidence,
)

logger = logging.getLogger("azure_ddos_protection")

ATTACHMENT_TYPES = {
    "networkinterfaces": "network_interface",
    "loadbalancers": "load_balancer",
    "bastionhosts": "bastion_host",
    "azurefirewalls": "azure_firewall",
    "virtualnetworkgateways": "virtual_network_gateway",
    "applicationgateways": "application_gateway",
}
EFFECTIVE_PROTECTION = ("network_protection", "ip_protection", "none", "disabled", "not_supported", "unknown")


# --- projection: the only code here that touches an azure-mgmt model ---

def _ids(models) -> list:
    return [model_attr(m, "id") for m in (models or []) if model_attr(m, "id")]


def project_plan(plan) -> dict:
    return {
        "id": model_attr(plan, "id"),
        "name": model_attr(plan, "name"),
        "location": model_attr(plan, "location"),
        "virtual_network_ids": _ids(model_attr(plan, "virtual_networks")),
        "public_ip_address_ids": _ids(model_attr(plan, "public_ip_addresses")),
    }


def project_virtual_network(vnet) -> dict:
    return {
        "id": model_attr(vnet, "id"),
        "name": model_attr(vnet, "name"),
        "location": model_attr(vnet, "location"),
        "enable_ddos_protection": model_attr(vnet, "enable_ddos_protection"),
        "ddos_protection_plan_id": model_attr(model_attr(vnet, "ddos_protection_plan"), "id"),
        "subnet_ip_configuration_ids": [
            i
            for s in (model_attr(vnet, "subnets") or [])
            for i in _ids(model_attr(s, "ip_configurations")) + _ids(model_attr(s, "application_gateway_ip_configurations"))
        ],
    }


def project_public_ip(ip) -> dict:
    sku = model_attr(ip, "sku")
    ddos = model_attr(ip, "ddos_settings")
    return {
        "id": model_attr(ip, "id"),
        "name": model_attr(ip, "name"),
        "location": model_attr(ip, "location"),
        "ip_address": model_attr(ip, "ip_address"),
        "sku_name": model_attr(sku, "name"),
        "sku_tier": model_attr(sku, "tier"),
        "ip_configuration_id": model_attr(model_attr(ip, "ip_configuration"), "id"),
        "nat_gateway_id": model_attr(model_attr(ip, "nat_gateway"), "id"),
        "protection_mode": model_attr(ddos, "protection_mode"),
        "ddos_protection_plan_id": model_attr(model_attr(ddos, "ddos_protection_plan"), "id"),
    }


def project_network_interface(nic) -> dict:
    return {
        "id": model_attr(nic, "id"),
        "subnet_ids": [
            model_attr(model_attr(ipc, "subnet"), "id") for ipc in (model_attr(nic, "ip_configurations") or [])
        ],
    }


def project_load_balancer(lb) -> dict:
    pools = model_attr(lb, "backend_address_pools") or []
    addresses = [a for p in pools for a in (model_attr(p, "load_balancer_backend_addresses") or [])]
    return {
        "id": model_attr(lb, "id"),
        "backend_ip_configuration_ids": [i for p in pools for i in _ids(model_attr(p, "backend_ip_configurations"))]
        + [i for a in addresses if (i := model_attr(model_attr(a, "network_interface_ip_configuration"), "id"))],
        "backend_virtual_network_ids": [
            i for i in [
                *(model_attr(model_attr(p, "virtual_network"), "id") for p in pools),
                *(model_attr(model_attr(a, "virtual_network"), "id") for a in addresses),
                *(vnet_id_of(model_attr(model_attr(a, "subnet"), "id")) for a in addresses),
            ] if i
        ],
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def resource_of(child_id):
    """(attachment type, owning resource id) for an ARM child id such as an IP configuration."""
    parts = str(child_id or "").split("/")
    lowered = [p.lower() for p in parts]
    if "providers" not in lowered:
        return None, None
    i = lowered.index("providers")
    if len(parts) < i + 4:
        return None, None
    return ATTACHMENT_TYPES.get(lowered[i + 2], "other"), "/".join(parts[: i + 4])


def attachment(ip: dict):
    if ip.get("ip_configuration_id"):
        return resource_of(ip["ip_configuration_id"])
    if ip.get("nat_gateway_id"):
        return "nat_gateway", ip["nat_gateway_id"]
    return "unattached", None


def _nic_of(config_id) -> str:
    """The NIC id of a NIC IP configuration id (VM or scale-set instance)."""
    key = arm_id_key(config_id)
    return key.rsplit("/ipconfigurations/", 1)[0] if "/networkinterfaces/" in key else ""


def vnet_by_resource(vnets: list[dict], nics: list[dict], load_balancers: list[dict] = ()) -> dict:
    """Lower-cased resource id -> lower-cased VNet id, from subnet back-references, NIC subnets, then a load
    balancer's backend pools (whose IP configurations or addresses must all sit in one VNet)."""
    index, by_config = {}, {}
    for vnet in vnets:
        for config_id in vnet.get("subnet_ip_configuration_ids") or []:
            by_config[arm_id_key(config_id)] = arm_id_key(vnet["id"])
            _, resource_id = resource_of(config_id)
            if resource_id:
                index.setdefault(arm_id_key(resource_id), arm_id_key(vnet["id"]))
    for nic in nics:
        vnet_ids = {vnet_id_of(s) for s in nic.get("subnet_ids") or [] if vnet_id_of(s)}
        if len(vnet_ids) == 1:
            index.setdefault(arm_id_key(nic["id"]), vnet_ids.pop())
    for lb in load_balancers:
        backends = {arm_id_key(v) for v in lb.get("backend_virtual_network_ids") or []}
        for config_id in lb.get("backend_ip_configuration_ids") or []:
            backends.add(by_config.get(arm_id_key(config_id)) or index.get(_nic_of(config_id)))
        if len(backends) == 1 and None not in backends:
            index.setdefault(arm_id_key(lb["id"]), backends.pop())
    return index


def vnet_has_plan(vnet) -> bool:
    return bool(vnet and vnet.get("enable_ddos_protection") and vnet.get("ddos_protection_plan_id"))


def effective_protection(ip: dict, attached_to: str, vnet) -> str:
    if attached_to == "nat_gateway":
        return "not_supported"
    mode = ip.get("protection_mode") or "VirtualNetworkInherited"
    if mode == "Enabled":
        return "ip_protection"
    if mode == "Disabled":
        return "disabled"
    if attached_to == "unattached":
        return "none"
    if vnet is None:
        return "unknown"
    return "network_protection" if vnet_has_plan(vnet) else "none"


def public_ip_record(ip: dict, resource_vnets: dict, vnets_by_id: dict) -> dict:
    attached_to, resource_id = attachment(ip)
    vnet = vnets_by_id.get(resource_vnets.get(arm_id_key(resource_id))) if resource_id else None
    return {
        "id": ip.get("id"),
        "name": ip.get("name"),
        "location": ip.get("location"),
        "resource_group": resource_group_from_id(ip.get("id")),
        "ip_address": ip.get("ip_address"),
        "sku_name": ip.get("sku_name"),
        "sku_tier": ip.get("sku_tier"),
        "attached_to_type": attached_to,
        "attached_resource_id": resource_id,
        "internet_facing": attached_to != "unattached",
        "virtual_network_id": vnet.get("id") if vnet else None,
        "protection_mode": ip.get("protection_mode"),
        "ip_ddos_protection_plan_id": ip.get("ddos_protection_plan_id"),
        "virtual_network_ddos_protection_plan_id": vnet.get("ddos_protection_plan_id") if vnet else None,
        "effective_protection": effective_protection(ip, attached_to, vnet),
    }


def virtual_network_record(vnet: dict, plan_ids: set, ips: list[dict]) -> dict:
    key = arm_id_key(vnet.get("id"))
    attached = [i for i in ips if i["internet_facing"] and arm_id_key(i["virtual_network_id"]) == key]
    plan_id = vnet.get("ddos_protection_plan_id")
    return {
        "id": vnet.get("id"),
        "name": vnet.get("name"),
        "location": vnet.get("location"),
        "resource_group": resource_group_from_id(vnet.get("id")),
        "enable_ddos_protection": bool(vnet.get("enable_ddos_protection")),
        "ddos_protection_plan_id": plan_id,
        "ddos_protection_plan_in_subscription": (arm_id_key(plan_id) in plan_ids) if plan_id else None,
        "has_ddos_plan": vnet_has_plan(vnet),
        "attached_public_ips": len(attached),
        "unprotected_attached_public_ips": sum(1 for i in attached if i["effective_protection"] in ("none", "disabled")),
    }


def plan_record(plan: dict) -> dict:
    return {
        "id": plan.get("id"),
        "name": plan.get("name"),
        "location": plan.get("location"),
        "resource_group": resource_group_from_id(plan.get("id")),
        "virtual_network_ids": sorted(plan.get("virtual_network_ids") or []),
        "public_ip_address_ids": sorted(plan.get("public_ip_address_ids") or []),
    }


def summarize(plans: list[dict], vnets: list[dict], ips: list[dict]) -> dict:
    facing = [i for i in ips if i["internet_facing"]]
    with_ips = [v for v in vnets if v["attached_public_ips"]]
    return {
        "total_ddos_protection_plans": len(plans),
        "total_virtual_networks": len(vnets),
        "virtual_networks_with_ddos_plan": sum(1 for v in vnets if v["has_ddos_plan"]),
        "virtual_networks_with_attached_public_ips": len(with_ips),
        "virtual_networks_with_attached_public_ips_without_plan": sum(1 for v in with_ips if not v["has_ddos_plan"]),
        "total_public_ips": len(ips),
        "attached_public_ips": len(facing),
        "attached_public_ips_by_effective_protection": {
            p: sum(1 for i in facing if i["effective_protection"] == p) for p in EFFECTIVE_PROTECTION
        },
        "attached_public_ips_unprotected": sum(1 for i in facing if i["effective_protection"] in ("none", "disabled")),
    }


def build_records(
    raw_plans: list[dict], raw_vnets: list[dict], raw_ips: list[dict], raw_nics: list[dict], raw_lbs: list[dict] = (),
):
    resource_vnets = vnet_by_resource(raw_vnets, raw_nics, raw_lbs)
    vnets_by_id = {arm_id_key(v["id"]): v for v in raw_vnets}
    ips = [public_ip_record(i, resource_vnets, vnets_by_id) for i in raw_ips]
    plan_ids = {arm_id_key(p["id"]) for p in raw_plans}
    vnets = [virtual_network_record(v, plan_ids, ips) for v in raw_vnets]
    plans = [plan_record(p) for p in raw_plans]

    def by_id(records):
        return sorted(records, key=lambda r: arm_id_key(r.get("id")))

    return by_id(plans), by_id(vnets), by_id(ips)


# --- collection (lazy azure imports) ---

def collect(subscription_id, cred, collector: Collector):
    """DDoS protection plans, VNets with their subnets' back-references, public IPs, NICs and load balancers."""
    from azure.mgmt.network import NetworkManagementClient

    client = collector.guard(
        "network.NetworkManagementClient (init)",
        lambda: NetworkManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        ),
    )
    if client is None:
        return [], [], [], [], []

    plans = collector.guard(
        "network.ddos_protection_plans.list",
        lambda: [project_plan(p) for p in client.ddos_protection_plans.list()],
        default=[],
    )
    vnets = collector.guard(
        "network.virtual_networks.list_all",
        lambda: [project_virtual_network(v) for v in client.virtual_networks.list_all()],
        default=[],
    )
    ips = collector.guard(
        "network.public_ip_addresses.list_all",
        lambda: [project_public_ip(i) for i in client.public_ip_addresses.list_all()],
        default=[],
    )
    nics = collector.guard(
        "network.network_interfaces.list_all",
        lambda: [project_network_interface(n) for n in client.network_interfaces.list_all()],
        default=[],
    )
    lbs = collector.guard(
        "network.load_balancers.list_all",
        lambda: [project_load_balancer(lb) for lb in client.load_balancers.list_all()],
        default=[],
    )
    return plans, vnets, ips, nics, lbs


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

    raw = ([], [], [], [], [])
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Network")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Network is not registered on subscription %s — reporting status not_registered",
                subscription_id,
            )
        raw = collect(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    plans, vnets, ips = build_records(*raw)
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "ddos_protection_plans": plans,
            "virtual_networks": vnets,
            "public_ip_addresses": ips,
            "provider_registration_status": registration,
        },
        summary={**summarize(plans, vnets, ips), "provider_registration_status": registration},
    )

    filename = f"azure_ddos_protection_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
