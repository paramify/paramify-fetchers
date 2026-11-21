#!/usr/bin/env python3
"""Azure DNS security policies (DNS resolver policies) for one subscription: their security rules, the virtual
networks each one is linked to, whether their DNS query logs are exported, and which virtual networks no policy
with an enabled block rule covers.

Azure's threat-intelligence domain list (AzureDnsThreatIntel) is visible only through the preview API, which is
tried first. Where the preview isn't served, the GA API is used and the threat-intelligence fields read null.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from arm_rest import arm_rest_client, get_json, list_all  # noqa: E402
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_id_key,
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)
from resource_exclusions import ResourceExclusions  # noqa: E402

logger = logging.getLogger("azure_dns_resolver_policy")

PREVIEW_API = "2025-10-01-preview"
GA_API = "2025-05-01"
VNET_API = "2024-05-01"
DIAGNOSTICS_API = "2021-05-01-preview"
THREAT_INTEL = "AzureDnsThreatIntel"
PROVIDER = "Microsoft.Network"


def _api_unsupported(exc: BaseException) -> bool:
    """ARM's answer to an api-version the cloud doesn't serve, such as a preview missing from a sovereign cloud."""
    text = f"{getattr(exc, 'message', '') or ''} {exc}".lower()
    return getattr(exc, "status_code", None) == 400 and ("api-version" in text or "apiversion" in text)


# --- pure transforms ---

def rule_record(rule: Dict[str, Any], threat_intel_visible: bool) -> Dict[str, Any]:
    props = rule.get("properties") or {}
    managed = props.get("managedDomainLists")
    return {
        "name": rule.get("name"),
        "priority": props.get("priority"),
        "action": (props.get("action") or {}).get("actionType"),
        "enabled": (props.get("dnsSecurityRuleState") or "Enabled") == "Enabled",
        "domain_list_ids": sorted(d.get("id") for d in props.get("dnsResolverDomainLists") or [] if d.get("id")),
        "managed_domain_lists": sorted(managed or []) if threat_intel_visible else None,
    }


def logs_record(settings: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Whether any diagnostic setting sends an enabled log category somewhere; null when the settings were unread."""
    if settings is None:
        return {"query_logs_exported": None, "log_destinations": None}
    exporting = []
    for s in settings:
        p = s.get("properties") or {}
        logs_on = any(entry.get("enabled") for entry in p.get("logs") or [])
        dest = next((p[k] for k in ("workspaceId", "storageAccountId", "eventHubAuthorizationRuleId", "marketplacePartnerId")
                     if p.get(k)), None)
        if logs_on and dest:
            exporting.append(dest)
    return {"query_logs_exported": bool(exporting), "log_destinations": sorted(exporting)}


def policy_record(policy: Dict[str, Any], rules: Optional[List[Dict[str, Any]]], links: Optional[List[Dict[str, Any]]],
                  settings: Optional[List[Dict[str, Any]]], threat_intel_visible: bool) -> Dict[str, Any]:
    rs = [rule_record(r, threat_intel_visible) for r in rules] if rules is not None else None
    blocking = [r for r in rs or [] if r["enabled"] and r["action"] == "Block"]
    return {
        "id": policy.get("id"),
        "name": policy.get("name"),
        "location": policy.get("location"),
        "resource_group": resource_group_from_id(policy.get("id")),
        "security_rules": sorted(rs, key=lambda r: (r["priority"] is None, r["priority"])) if rs is not None else None,
        "blocks": bool(blocking) if rs is not None else None,
        "blocks_threat_intel": (any(THREAT_INTEL in (r["managed_domain_lists"] or []) for r in blocking)
                                if rs is not None and threat_intel_visible else None),
        "linked_virtual_network_ids": sorted(
            ((link.get("properties") or {}).get("virtualNetwork") or {}).get("id") for link in links
            if ((link.get("properties") or {}).get("virtualNetwork") or {}).get("id")) if links is not None else None,
        **logs_record(settings),
    }


def _covered(linked: List[Dict[str, Any]], links_unknown: bool, field: str) -> Optional[bool]:
    """True if a linked policy has `field`; null while a policy's links or that field are unread, since an unread
    policy might cover the VNet; otherwise false."""
    if any(p[field] for p in linked):
        return True
    if links_unknown or any(p[field] is None for p in linked):
        return None
    return False


def vnet_record(vnet: Dict[str, Any], policies: List[Dict[str, Any]]) -> Dict[str, Any]:
    key = arm_id_key(vnet.get("id"))
    linked = [p for p in policies if key in {arm_id_key(i) for i in p["linked_virtual_network_ids"] or []}]
    unknown = any(p["linked_virtual_network_ids"] is None for p in policies)
    return {
        "id": vnet.get("id"),
        "name": vnet.get("name"),
        "location": vnet.get("location"),
        "resource_group": resource_group_from_id(vnet.get("id")),
        "policy_ids": sorted(p["id"] for p in linked),
        "covered_by_blocking_policy": _covered(linked, unknown, "blocks"),
        "covered_by_threat_intel_block": _covered(linked, unknown, "blocks_threat_intel"),
    }


def _count(records: List[Dict[str, Any]], field: str, value: Any) -> Optional[int]:
    if any(r[field] is None for r in records):
        return None
    return sum(1 for r in records if r[field] == value)


def summarize(policies: Optional[List[Dict[str, Any]]], vnets: Optional[List[Dict[str, Any]]],
              domain_lists: Optional[List[Dict[str, Any]]], threat_intel_visible: Optional[bool], api_version: Optional[str]) -> Dict[str, Any]:
    p_read, v_read = policies is not None, vnets is not None
    ps, vs = policies or [], vnets or []
    rules = [r for p in ps for r in p["security_rules"] or []]
    rules_known = p_read and all(p["security_rules"] is not None for p in ps)
    return {
        "api_version": api_version,
        "threat_intel_visible": threat_intel_visible,
        # The policies
        "security_rules": len(rules) if rules_known else None,
        "security_rules_enabled": sum(1 for r in rules if r["enabled"]) if rules_known else None,
        "enabled_rules_by_action": ({a: sum(1 for r in rules if r["enabled"] and r["action"] == a) for a in ("Allow", "Alert", "Block")}
                                    if rules_known else None),
        "policies_blocking": _count(ps, "blocks", True) if p_read else None,
        "policies_blocking_threat_intel": _count(ps, "blocks_threat_intel", True) if p_read and threat_intel_visible else None,
        "domain_lists": len(domain_lists) if domain_lists is not None else None,
        # Which networks they cover
        "virtual_networks_linked_to_policy": (sum(1 for v in vs if v["policy_ids"]) if p_read and all(
            p["linked_virtual_network_ids"] is not None for p in ps) else None) if v_read else None,
        "virtual_networks_without_blocking_policy": _count(vs, "covered_by_blocking_policy", False) if v_read and p_read else None,
        "virtual_networks_without_threat_intel_block": (_count(vs, "covered_by_threat_intel_block", False)
                                                        if v_read and p_read and threat_intel_visible else None),
        # Are queries logged?
        "policies_with_query_logs_exported": _count(ps, "query_logs_exported", True) if p_read else None,
        "policies_without_query_logs_exported": _count(ps, "query_logs_exported", False) if p_read else None,
    }


# --- collection ---

def read_policies(client, subscription_id: str, collector: Collector) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    """The subscription's DNS resolver policies and the api-version that answered: the preview first, else GA."""
    path = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/dnsResolverPolicies"
    try:
        return list_all(client, path, PREVIEW_API)["items"], PREVIEW_API
    except Exception as exc:  # noqa: BLE001 — boundary
        if not _api_unsupported(exc):
            collector.record(f"dnsResolverPolicies.list ({PREVIEW_API})", exc)
            return None, None
        logger.info("%s not served here; reading DNS resolver policies with %s", PREVIEW_API, GA_API)
    items = collector.guard(f"dnsResolverPolicies.list ({GA_API})", lambda: list_all(client, path, GA_API)["items"])
    return items, GA_API if items is not None else None


def collect(client, subscription_id: str, collector: Collector):
    policies, api = read_policies(client, subscription_id, collector)
    threat_intel_visible = (api == PREVIEW_API) if api else None
    records: Optional[List[Dict[str, Any]]] = None
    if policies is not None:
        records = []
        for p in policies:
            pid = p.get("id")
            rules = collector.guard(f"dnsSecurityRules.list ({p.get('name')})",
                                    lambda: list_all(client, f"{pid}/dnsSecurityRules", api)["items"])
            links = collector.guard(f"virtualNetworkLinks.list ({p.get('name')})",
                                    lambda: list_all(client, f"{pid}/virtualNetworkLinks", api)["items"])
            settings = collector.guard(f"diagnosticSettings.list ({p.get('name')})",
                                       lambda: get_json(client, f"{pid}/providers/Microsoft.Insights/diagnosticSettings"
                                                                f"?api-version={DIAGNOSTICS_API}").get("value") or [])
            records.append(policy_record(p, rules, links, settings, bool(threat_intel_visible)))
    domain_lists = collector.guard(
        "dnsResolverDomainLists.list",
        lambda: list_all(client, f"/subscriptions/{subscription_id}/providers/Microsoft.Network/dnsResolverDomainLists",
                         api or GA_API)["items"])
    vnets = collector.guard(
        "virtualNetworks.list_all",
        lambda: list_all(client, f"/subscriptions/{subscription_id}/providers/Microsoft.Network/virtualNetworks", VNET_API)["items"])
    return records, vnets, domain_lists, threat_intel_visible, api


def domain_list_record(d: Dict[str, Any]) -> Dict[str, Any]:
    domains = (d.get("properties") or {}).get("domains")
    return {"id": d.get("id"), "name": d.get("name"), "location": d.get("location"),
            "resource_group": resource_group_from_id(d.get("id")),
            # Azure leaves domains null for a large domain list uploaded from a file.
            "domain_count": len(domains) if isinstance(domains, list) else None}


def build_scoped(policies, vnets, exclusions: ResourceExclusions):
    """Coverage is worked out against every policy; excluded policies and VNets then leave the lists and counts."""
    excluded: List[Dict[str, Any]] = []
    vnet_records = [vnet_record(v, policies or []) for v in vnets] if vnets is not None else None
    if policies is not None:
        policies, out = exclusions.split(policies, "dns_resolver_policy")
        excluded += out
    if vnet_records is not None:
        vnet_records, out = exclusions.split(vnet_records, "virtual_network")
        excluded += out
    return policies, vnet_records, excluded


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    raw: tuple = (None, None, None, None, None)
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, PROVIDER)
        if registration == NOT_REGISTERED:
            logger.warning("%s is not registered on subscription %s", PROVIDER, subscription_id)
        client = collector.guard("arm_rest_client (init)", lambda: arm_rest_client(cred))
        if client is not None:
            raw = collect(client, subscription_id, collector)
    elif not subscription_id:
        collector.record("resolve_subscription", RuntimeError(
            "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an ambient Azure credential that can list subscriptions)"))

    policies, vnets, domain_lists, threat_intel_visible, api = raw
    exclusions = ResourceExclusions.from_env()
    exclusions.record_invalid(collector)
    policies, vnet_records, excluded = build_scoped(policies, vnets, exclusions)
    lists = [domain_list_record(d) for d in domain_lists] if domain_lists is not None else None
    exclusions.warn_unmatched(logger)
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={"dns_resolver_policies": policies, "virtual_networks": vnet_records, "domain_lists": lists,
                 "provider_registration_status": registration, "excluded": excluded},
        summary={
            **summarize(policies, vnet_records, lists, threat_intel_visible, api),
            "provider_registration_status": registration,
            **exclusions.summary(excluded, ("dns_resolver_policy", "virtual_network"), {
                "dns_resolver_policies": len(policies) if policies is not None else None,
                "virtual_networks": len(vnet_records) if vnet_records is not None else None}),
        },
    )
    path = write_evidence(output_dir, f"azure_dns_resolver_policy_{sanitize_for_filename(subscription_id or 'unknown')}.json", evidence)
    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
