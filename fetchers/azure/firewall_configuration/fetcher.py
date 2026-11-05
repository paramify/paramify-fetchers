#!/usr/bin/env python3
"""Azure Firewalls and Firewall Policies: every rule, threat intelligence, IDPS, TLS inspection, DNS proxy, forced tunneling and log export."""

import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    arm_id_key,
    basename,
    coverage_percentage,
    dig,
    resource_group_from_id,
    sorted_counts,
)
from azure_rest import DIAG_API, ArmError, run_subscription  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402

NAME = "azure_firewall_configuration"
logger = logging.getLogger(NAME)

NETWORK_API = "2024-05-01"

ALLOW, DENY, DNAT = "allow", "deny", "dnat"
NETWORK_RULE, APPLICATION_RULE, NAT_RULE = "network", "application", "nat"
ADMIN_PORTS = (22, 3389)
# Anything that stands for "every address" in a rule, as Azure accepts it.
ANY_ADDRESS = {"*", "0.0.0.0/0", "any"}
# Log categories that record rule decisions, in the legacy (AzureDiagnostics) and resource-specific tables.
RULE_LOG_CATEGORIES = ("AzureFirewallNetworkRule", "AzureFirewallApplicationRule", "AZFWNetworkRule",
                       "AZFWApplicationRule", "AZFWNatRule")
THREAT_LOG_CATEGORIES = ("AZFWThreatIntel", "AZFWIdpsSignature")
ALL_LOGS_GROUP = "alllogs"


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _list(value: Any) -> List[str]:
    return [str(v) for v in (value or []) if v is not None]


def _any_address(values: List[str]) -> bool:
    return any(v.strip().lower() in ANY_ADDRESS for v in values)


def _port_ranges(values: List[str]) -> List[tuple]:
    """Every (low, high) in the values; an entry may be *, a port, a range or a comma list. Unparseable parts are skipped."""
    ranges: List[tuple] = []
    for value in values:
        for text in str(value).split(","):
            text = text.strip()
            if text == "*":
                ranges.append((1, 65535))
                continue
            low, _, high = text.partition("-")
            try:
                ranges.append((int(low), int(high or low)))
            except ValueError:
                continue
    return ranges


def _any_port(values: List[str]) -> bool:
    """True when the ports together cover 1-65535, however they are split."""
    reach = 0
    for low, high in sorted(_port_ranges(values)):
        if low > reach + 1:
            return False
        reach = max(reach, high)
    return reach >= 65535


def _covers_port(values: List[str], port: int) -> bool:
    return any(low <= port <= high for low, high in _port_ranges(values))


# --- rules ---

def rule_record(raw: Dict[str, Any], *, group: Optional[str], group_priority: Optional[int], collection: Dict[str, Any],
                rule_type: str, action: str) -> Dict[str, Any]:
    """One rule in the shape shared by Firewall Policy rules and the classic rule collections on a firewall."""
    protocols = raw.get("protocols") or raw.get("ipProtocols") or []
    if protocols and isinstance(protocols[0], dict):
        protocols = [f"{p.get('protocolType')}:{p.get('port')}" if p.get("port") is not None
                     else str(p.get("protocolType")) for p in protocols]
    sources = _list(raw.get("sourceAddresses"))
    source_groups = _list(raw.get("sourceIpGroups"))
    destinations = _list(raw.get("destinationAddresses")) + _list(raw.get("destinationFqdns"))
    destination_groups = _list(raw.get("destinationIpGroups"))
    ports = _list(raw.get("destinationPorts"))
    target_fqdns = _list(raw.get("targetFqdns"))
    target_urls = _list(raw.get("targetUrls"))
    fqdn_tags = _list(raw.get("fqdnTags"))
    web_categories = _list(raw.get("webCategories"))
    record = {
        "name": raw.get("name"),
        "rule_type": rule_type,
        "action": action,
        "collection_group": group,
        "collection_group_priority": group_priority,
        "collection": collection.get("name"),
        "collection_priority": collection.get("priority"),
        "source_addresses": sources,
        "source_ip_groups": [basename(g) for g in source_groups],
        "destination_addresses": destinations,
        "destination_ip_groups": [basename(g) for g in destination_groups],
        "destination_ports": ports,
        "protocols": _list(protocols),
        "target_fqdns": target_fqdns,
        "target_urls": target_urls,
        "fqdn_tags": fqdn_tags,
        "web_categories": web_categories,
        "translated_address": raw.get("translatedAddress") or raw.get("translatedFqdn"),
        "translated_port": raw.get("translatedPort"),
        "terminate_tls": raw.get("terminateTLS"),
    }
    # An IP group adds addresses to the rule, so a "*" beside one is still every address.
    any_source = _any_address(sources)
    record["from_any_source"] = any_source
    if rule_type == NETWORK_RULE:
        any_destination = _any_address(destinations)
        # An ICMP-only rule carries port * but opens no TCP or UDP flow.
        carries_data = not protocols or any(str(p).upper() != "ICMP" for p in protocols)
        record["to_any_destination"] = action == ALLOW and any_destination
        record["allow_all"] = action == ALLOW and any_source and any_destination and _any_port(ports) and carries_data
    elif rule_type == APPLICATION_RULE:
        # A "*" target with no tag or category scoping it lets any web destination through.
        record["to_any_fqdn"] = action == ALLOW and ("*" in target_fqdns or "*" in target_urls) \
            and not fqdn_tags and not web_categories
    else:
        translated = [str(raw["translatedPort"])] if raw.get("translatedPort") is not None else []
        record["to_admin_port"] = any(_covers_port(ports + translated, port) for port in ADMIN_PORTS)
    return record


def policy_rules(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for group in groups:
        props = group.get("properties") or {}
        for collection in props.get("ruleCollections") or []:
            kind = _lower(collection.get("ruleCollectionType"))
            action = _lower(dig(collection, "action", "type"))
            action = DNAT if "nat" in kind else action
            for raw in collection.get("rules") or []:
                rule_type = {"applicationrule": APPLICATION_RULE, "networkrule": NETWORK_RULE,
                             "natrule": NAT_RULE}.get(_lower(raw.get("ruleType")), _lower(raw.get("ruleType")))
                rules.append(rule_record(raw, group=group.get("name"), group_priority=props.get("priority"),
                                         collection=collection, rule_type=rule_type, action=action))
    return rules


def classic_rules(firewall_props: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Rules configured on the firewall itself, used when no Firewall Policy is attached."""
    rules: List[Dict[str, Any]] = []
    for key, rule_type in (("networkRuleCollections", NETWORK_RULE), ("applicationRuleCollections", APPLICATION_RULE),
                           ("natRuleCollections", NAT_RULE)):
        for collection in firewall_props.get(key) or []:
            props = collection.get("properties") or {}
            action = _lower(dig(props, "action", "type"))
            action = DNAT if rule_type == NAT_RULE else action
            shaped = {"name": collection.get("name"), "priority": props.get("priority")}
            for raw in props.get("rules") or []:
                rules.append(rule_record(raw, group=None, group_priority=None, collection=shaped,
                                         rule_type=rule_type, action=action))
    return rules


def rule_findings(rules: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    if rules is None:
        return {"rules": None, "rules_by_type": None, "rules_by_action": None, "allow_all_network_rules": None,
                "network_rules_to_any_destination": None, "application_rules_to_any_fqdn": None,
                "dnat_rules": None, "dnat_rules_to_admin_ports": None, "dnat_rules_from_any_source": None}
    dnat = [r for r in rules if r["rule_type"] == NAT_RULE]
    return {
        "rules": len(rules),
        "rules_by_type": sorted_counts(Counter(r["rule_type"] for r in rules)),
        "rules_by_action": sorted_counts(Counter(r["action"] for r in rules)),
        "allow_all_network_rules": sum(1 for r in rules if r.get("allow_all")),
        "network_rules_to_any_destination": sum(1 for r in rules if r.get("to_any_destination")),
        "application_rules_to_any_fqdn": sum(1 for r in rules if r.get("to_any_fqdn")),
        "dnat_rules": len(dnat),
        "dnat_rules_to_admin_ports": sum(1 for r in dnat if r.get("to_admin_port")),
        "dnat_rules_from_any_source": sum(1 for r in dnat if r.get("from_any_source")),
    }


# --- policies ---

def policy_record(raw: Dict[str, Any], groups: Optional[List[Dict[str, Any]]], subscription_id: str) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    idps = props.get("intrusionDetection") or {}
    idps_config = idps.get("configuration") or {}
    dns = props.get("dnsSettings") or {}
    insights = props.get("insights") or {}
    base = dig(props, "basePolicy", "id")
    rules = policy_rules(groups) if groups is not None else None
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "resource_group": resource_group_from_id(raw.get("id")),
        "location": raw.get("location"),
        "sku_tier": dig(props, "sku", "tier"),
        "provisioning_state": props.get("provisioningState"),
        "threat_intel_mode": props.get("threatIntelMode"),
        "threat_intel_allowlist_fqdns": len(dig(props, "threatIntelWhitelist", "fqdns") or []),
        "threat_intel_allowlist_ip_addresses": len(dig(props, "threatIntelWhitelist", "ipAddresses") or []),
        "idps_mode": idps.get("mode"),
        "idps_profile": idps.get("profile"),
        "idps_signature_overrides": len(idps_config.get("signatureOverrides") or []),
        "idps_bypass_rules": len(idps_config.get("bypassTrafficSettings") or []),
        "tls_inspection_enabled": bool(dig(props, "transportSecurity", "certificateAuthority", "keyVaultSecretId")),
        "dns_proxy_enabled": dns.get("enableProxy") is True,
        "dns_servers": len(dns.get("servers") or []),
        "insights_enabled": insights.get("isEnabled") is True,
        "insights_workspace_id": dig(insights, "logAnalyticsResources", "defaultWorkspaceId", "id"),
        "explicit_proxy_enabled": dig(props, "explicitProxy", "enableExplicitProxy") is True,
        "sql_redirect_allowed": dig(props, "sql", "allowSqlRedirect") is True,
        "base_policy_id": base,
        "base_policy_in_subscription": (arm_id_key(base).startswith(f"/subscriptions/{subscription_id.lower()}/")
                                        if base else None),
        "child_policies": len(props.get("childPolicies") or []),
        "firewalls": [f.get("id") for f in props.get("firewalls") or []],
        "rule_collection_groups": len(groups) if groups is not None else None,
        "rules_read": groups is not None,
        "rule_summary": rule_findings(rules),
        "rules": rules,
    }


def chain(policy_id: Optional[str], policies: Dict[str, Dict[str, Any]], seen=None) -> Optional[List[Dict[str, Any]]]:
    """The policy and its base policies, nearest first; None if any link is unread (another subscription, or a failed read)."""
    seen = seen or set()
    key = arm_id_key(policy_id)
    if not key or key in seen:
        return [] if key in seen else None
    policy = policies.get(key)
    if policy is None or not policy["rules_read"]:
        return None
    seen.add(key)
    rest = chain(policy.get("base_policy_id"), policies, seen) if policy.get("base_policy_id") else []
    return None if rest is None else [policy, *rest]


# --- firewalls ---

def exported_destinations(settings: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Which categories each diagnostic setting sends where; a category group (allLogs, audit) counts for every category."""
    if settings is None:
        return {"diagnostic_settings_read": False, "destinations": None, "categories": None}
    destinations: List[Dict[str, Any]] = []
    categories: set = set()
    for setting in settings:
        props = setting.get("properties") or {}
        enabled = [log for log in props.get("logs") or [] if log.get("enabled") is True]
        if not enabled:
            continue
        groups = {_lower(log.get("categoryGroup")) for log in enabled if log.get("categoryGroup")}
        grouped = ALL_LOGS_GROUP in groups
        names = {log.get("category") for log in enabled if log.get("category")}
        if grouped:
            names.update(RULE_LOG_CATEGORIES + THREAT_LOG_CATEGORIES)
        # Another group (audit) is recorded by name; which categories it holds is Azure's to define.
        names.update(f"group:{g}" for g in groups - {ALL_LOGS_GROUP})
        categories.update(names)
        for kind, key in (("log_analytics", "workspaceId"), ("storage", "storageAccountId"),
                          ("event_hub", "eventHubAuthorizationRuleId"), ("partner", "marketplacePartnerId")):
            if props.get(key):
                destinations.append({"setting": setting.get("name"), "kind": kind, "target_id": props.get(key),
                                     "categories": sorted(names) if not grouped else ["group:allLogs"]})
    return {"diagnostic_settings_read": True, "destinations": destinations, "categories": sorted(categories)}


def firewall_record(raw: Dict[str, Any], policies: Dict[str, Dict[str, Any]], settings) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    policy_id = dig(props, "firewallPolicy", "id")
    classic = classic_rules(props) if not policy_id else []
    policy_chain = chain(policy_id, policies) if policy_id else []
    rules_read = policy_chain is not None
    rules = None if not rules_read else (classic if not policy_id else
                                         [r for p in policy_chain for r in p["rules"]])
    effective = policy_chain[0] if policy_chain else None
    logs = exported_destinations(settings)
    categories = set(logs["categories"] or [])
    additional = props.get("additionalProperties") or {}
    hub_ips = dig(props, "hubIPAddresses", "publicIPs", "addresses") or []
    public_ips = [dig(c, "properties", "publicIPAddress", "id") for c in props.get("ipConfigurations") or []]
    public_ips = [p for p in public_ips if p] + [h.get("address") for h in hub_ips if h.get("address")]
    private_ips = {ip for ip in (dig(c, "properties", "privateIPAddress") for c in props.get("ipConfigurations") or []) if ip}
    if dig(props, "hubIPAddresses", "privateIPAddress"):
        private_ips.add(props["hubIPAddresses"]["privateIPAddress"])
    findings = rule_findings(rules)
    # Azure Firewall denies whatever no rule allows, so a firewall with no allow-all network rule and no any-FQDN
    # application rule filters egress, including one with no rules or only DNAT rules (it denies every flow).
    enforcing = None if rules is None else findings["allow_all_network_rules"] == 0 \
        and findings["application_rules_to_any_fqdn"] == 0
    # Once a policy is attached Azure ignores the firewall's own settings, so an unread policy leaves them unknown.
    settings_known = effective is not None or not policy_id
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "resource_group": resource_group_from_id(raw.get("id")),
        "location": raw.get("location"),
        "zones": sorted(_list(raw.get("zones"))),
        "sku_name": dig(props, "sku", "name"),
        "sku_tier": dig(props, "sku", "tier"),
        "deployment": "virtual_hub" if dig(props, "virtualHub", "id") else "virtual_network",
        "provisioning_state": props.get("provisioningState"),
        "firewall_policy_id": policy_id,
        "firewall_policy_name": basename(policy_id),
        "policy_chain": [p["name"] for p in policy_chain] if policy_chain else ([] if not policy_id else None),
        "classic_rule_collections": sum(len(props.get(k) or []) for k in
                                        ("networkRuleCollections", "applicationRuleCollections", "natRuleCollections")),
        "rules_read": rules_read,
        "rule_source": "policy" if policy_id else ("classic" if classic else "none"),
        "public_ip_addresses": sorted(set(public_ips)),
        "private_ip_addresses": sorted(private_ips),
        "management_ip_configured": bool(props.get("managementIpConfiguration")),
        "settings_read": settings_known,
        "threat_intel_mode": (effective["threat_intel_mode"] if effective else
                              (props.get("threatIntelMode") if settings_known else None)),
        "idps_mode": effective["idps_mode"] if effective else None,
        "tls_inspection_enabled": effective["tls_inspection_enabled"] if effective else (False if settings_known else None),
        "dns_proxy_enabled": (effective["dns_proxy_enabled"] if effective else
                              (_lower(additional.get("Network.DNS.EnableProxy")) == "true" if settings_known else None)),
        "egress_filtering_enforced": enforcing,
        "rule_summary": findings,
        "classic_rules": classic,
        "logs": logs,
        "rule_logs_exported": None if not logs["diagnostic_settings_read"] else bool(categories & set(RULE_LOG_CATEGORIES)),
        "threat_logs_exported": None if not logs["diagnostic_settings_read"] else bool(categories & set(THREAT_LOG_CATEGORIES)),
    }


# --- summary ---

def _count(items, key, value=True) -> int:
    return sum(1 for i in items if i.get(key) == value)


def _known(items, key) -> Optional[int]:
    """A count that reads null while any item's value is unknown, so an unread firewall never reads as safe."""
    if any(i.get(key) is None for i in items):
        return None
    return sum(1 for i in items if i.get(key))


def summarize(firewalls: List[Dict[str, Any]], policies: List[Dict[str, Any]], firewalls_read: bool,
              policies_read: bool, foreign_policies: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Rule counts cover this subscription's policies and every policy from another subscription that one of its firewalls reaches."""
    foreign_policies = foreign_policies or []
    in_use = {arm_id_key(f["firewall_policy_id"]) for f in firewalls if f.get("firewall_policy_id")}
    rules_known = all(f["rules_read"] for f in firewalls)
    all_rules = [r for p in policies + foreign_policies if p["rules_read"] for r in p["rules"]] + \
                [r for f in firewalls if f["rule_source"] == "classic" for r in f["classic_rules"]]
    # The rule counts cover every firewall's classic rules and every policy's rules, so either list failing leaves them partial.
    findings = rule_findings(all_rules if (firewalls_read and policies_read and rules_known
                                           and all(p["rules_read"] for p in policies + foreign_policies)) else None)
    enforcing = _known(firewalls, "egress_filtering_enforced")
    settings_known = all(f["settings_read"] for f in firewalls)
    # Every documented mode is listed, at 0 when no firewall has it, so a missing key never has to be read as 0.
    ti = Counter({mode: 0 for mode in ("alert", "deny", "off", "unknown")})
    ti.update(_lower(f.get("threat_intel_mode")) or "unknown" for f in firewalls)
    deployments = Counter({"virtual_hub": 0, "virtual_network": 0})
    deployments.update(f["deployment"] for f in firewalls)

    def setting(predicate) -> Optional[int]:
        return sum(1 for f in firewalls if predicate(f)) if settings_known else None

    summary = {
        "firewalls_read": firewalls_read,
        "firewalls": len(firewalls),
        "firewalls_by_sku_tier": sorted_counts(Counter(_lower(f.get("sku_tier")) or "unknown" for f in firewalls)),
        "firewalls_by_deployment": sorted_counts(deployments),
        "firewalls_with_policy": _count(firewalls, "rule_source", "policy"),
        "firewalls_with_classic_rules": _count(firewalls, "rule_source", "classic"),
        "firewalls_without_rules": _count(firewalls, "rule_source", "none"),
        "firewalls_with_rules_unread": sum(1 for f in firewalls if not f["rules_read"]),
        "firewall_policies_read": policies_read,
        "firewall_policies": len(policies),
        "firewall_policies_in_use": sum(1 for p in policies if arm_id_key(p["id"]) in in_use or p["firewalls"]),
        "firewall_policies_unused": sum(1 for p in policies if arm_id_key(p["id"]) not in in_use and not p["firewalls"]),
        "firewall_policies_with_base_policy": sum(1 for p in policies if p.get("base_policy_id")),
        "firewall_policies_with_rules_unread": sum(1 for p in policies if not p["rules_read"]),
        **findings,
        "firewalls_enforcing_egress_filtering": enforcing,
        "firewalls_with_allow_all_rule": None if not rules_known else sum(
            1 for f in firewalls if f["rule_summary"]["allow_all_network_rules"]
            or f["rule_summary"]["application_rules_to_any_fqdn"]),
        "egress_filtering_percentage": None if enforcing is None else coverage_percentage(enforcing, len(firewalls)),
        "firewalls_with_settings_unread": sum(1 for f in firewalls if not f["settings_read"]),
        "firewalls_by_threat_intel_mode": sorted_counts(ti),
        "firewalls_with_threat_intel_deny": setting(lambda f: _lower(f.get("threat_intel_mode")) == "deny"),
        "firewalls_with_idps_deny": setting(lambda f: _lower(f.get("idps_mode")) == "deny"),
        "firewalls_with_idps_alert_only": setting(lambda f: _lower(f.get("idps_mode")) == "alert"),
        "firewalls_without_idps": setting(lambda f: _lower(f.get("idps_mode")) not in ("deny", "alert")),
        "firewalls_with_tls_inspection": setting(lambda f: f.get("tls_inspection_enabled") is True),
        "firewalls_with_dns_proxy": setting(lambda f: f.get("dns_proxy_enabled") is True),
        "firewalls_with_management_ip": _count(firewalls, "management_ip_configured"),
        "firewalls_with_public_ip": sum(1 for f in firewalls if f["public_ip_addresses"]),
        "firewalls_exporting_rule_logs": _known(firewalls, "rule_logs_exported"),
        "firewalls_exporting_threat_logs": _known(firewalls, "threat_logs_exported"),
        "firewalls_without_log_export": None if any(f["rule_logs_exported"] is None for f in firewalls)
        else sum(1 for f in firewalls if not f["logs"]["destinations"]),
        "log_categories_exported": sorted({c for f in firewalls for c in (f["logs"]["categories"] or [])}),
    }
    # A failed list is not an empty one: every count that depends on it reads null, never a clean-looking 0.
    if not firewalls_read:
        summary.update({k: None for k in summary
                        if (k == "firewalls" or k.startswith("firewalls_") or k == "log_categories_exported"
                            or k == "egress_filtering_percentage") and k != "firewalls_read"})
    if not policies_read:
        summary.update({k: None for k in summary if k.startswith("firewall_policies") and k != "firewall_policies_read"})
    return summary


# --- collection ---

def _provider_list(client, path: str, operation: str, collector: Collector) -> Optional[List[Dict[str, Any]]]:
    """None when the list failed; a subscription without the provider registered has none of its resources."""
    def _list_():
        try:
            return client.list(path, NETWORK_API)
        except ArmError as exc:
            if exc.code.lower() == "missingsubscriptionregistration":
                return []
            raise
    return collector.guard(operation, _list_)


def read_groups(client, policy_id: str, collector: Collector) -> Optional[List[Dict[str, Any]]]:
    def _read():
        groups = client.list(f"{policy_id}/ruleCollectionGroups", NETWORK_API)
        # A listing that leaves the collections out is completed with one read per group.
        return [g if (g.get("properties") or {}).get("ruleCollections") is not None or not g.get("id")
                else client.get(g["id"], NETWORK_API) for g in groups]
    return collector.guard(f"network.firewallPolicyRuleCollectionGroups.list({basename(policy_id)})", _read)


def read_foreign_policy(client, policy_id: str, collector: Collector) -> Optional[Dict[str, Any]]:
    """A policy in another subscription, read if the credential may; a refusal leaves it unread, not failed."""
    try:
        return client.get(policy_id, NETWORK_API)
    except ArmError as exc:
        if exc.status in (401, 403, 404):
            logger.warning("firewall policy %s could not be read with this credential: %s", policy_id, exc)
            return None
        collector.record(f"network.firewallPolicies.get({basename(policy_id)})", exc)
        return None
    except Exception as exc:  # noqa: BLE001 -- a timeout or a malformed reply is a failure to record, never a crash
        collector.record(f"network.firewallPolicies.get({basename(policy_id)})", exc)
        return None


def collect(client, subscription_id: str, collector: Collector, exclusions: Optional[ResourceExclusions] = None) -> tuple:
    exclusions = exclusions if exclusions is not None else ResourceExclusions()
    base = f"/subscriptions/{subscription_id}/providers/Microsoft.Network"
    raw_firewalls = _provider_list(client, f"{base}/azureFirewalls", "network.azureFirewalls.list", collector)
    raw_policies = _provider_list(client, f"{base}/firewallPolicies", "network.firewallPolicies.list", collector)
    firewalls_read, policies_read = raw_firewalls is not None, raw_policies is not None
    raw_firewalls, excluded_fw = exclusions.split(raw_firewalls or [], "firewall")
    raw_policies, excluded_pol = exclusions.split(raw_policies or [], "firewall_policy")
    exclusions.record_invalid(collector)

    # Policies another subscription holds, or a base policy outside this one, are read when the credential allows.
    known = {arm_id_key(p.get("id")) for p in raw_policies}
    wanted = [dig(f, "properties", "firewallPolicy", "id") for f in raw_firewalls]
    wanted += [dig(p, "properties", "basePolicy", "id") for p in raw_policies]
    foreign: List[Dict[str, Any]] = []
    while wanted:
        pid = wanted.pop()
        if pid and arm_id_key(pid) not in known and not exclusions.match(pid, record=False):
            known.add(arm_id_key(pid))
            extra = read_foreign_policy(client, pid, collector)
            if extra:
                foreign.append(extra)
                wanted.append(dig(extra, "properties", "basePolicy", "id"))
    exclusions.warn_unmatched(logger)

    policies: Dict[str, Dict[str, Any]] = {}
    for raw in sorted(raw_policies + foreign, key=lambda p: arm_id_key(p.get("id"))):
        groups = read_groups(client, raw["id"], collector) if raw.get("id") else None
        policies[arm_id_key(raw.get("id"))] = policy_record(raw, groups, subscription_id)

    firewalls = []
    for raw in sorted(raw_firewalls, key=lambda f: arm_id_key(f.get("id"))):
        settings = collector.guard(
            f"insights.diagnosticSettings.list({raw.get('name')})",
            lambda rid=raw.get("id"): client.list(f"{rid}/providers/Microsoft.Insights/diagnosticSettings", DIAG_API),
        )
        firewalls.append(firewall_record(raw, policies, settings))

    own = [p for k, p in policies.items() if k.startswith(f"/subscriptions/{subscription_id.lower()}/")]
    outside = [p for k, p in policies.items() if not k.startswith(f"/subscriptions/{subscription_id.lower()}/")]
    results = {
        "firewalls": firewalls,
        "firewall_policies": own,
        "foreign_firewall_policies": outside,
        "excluded": sorted(excluded_fw + excluded_pol, key=lambda e: arm_id_key(e.get("id"))),
    }
    summary = {**summarize(firewalls, own, firewalls_read, policies_read, outside),
               **exclusions.summary(excluded_fw + excluded_pol, ("firewall", "firewall_policy"),
                                    {"firewalls": len(firewalls) if firewalls_read else None,
                                     "firewall_policies": len(own) if policies_read else None})}
    return results, summary


def collect_subscription(client, subscription_id: str, collector: Collector) -> tuple:
    return collect(client, subscription_id, collector, ResourceExclusions.from_env())


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect_subscription)


if __name__ == "__main__":
    sys.exit(main())
