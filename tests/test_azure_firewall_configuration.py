"""azure_firewall_configuration: rule normalization and findings, policy chains, effective settings, log export, failure semantics. Synthetic payloads, no SDK or network."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_firewall_configuration_under_test",
                                               AZURE / "firewall_configuration" / "fetcher.py")
fw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fw)
azure_rest = sys.modules["azure_rest"]
Collector = sys.modules["azure_common"].Collector
ResourceExclusions = sys.modules["resource_exclusions"].ResourceExclusions

SUB = "/subscriptions/s1"
OTHER = "/subscriptions/s2"
RG = f"{SUB}/resourceGroups/rg-hub/providers/Microsoft.Network"
POLICY = f"{RG}/firewallPolicies/pol-child"
BASE = f"{RG}/firewallPolicies/pol-base"
FOREIGN = f"{OTHER}/resourceGroups/rg-sec/providers/Microsoft.Network/firewallPolicies/pol-corp"
FIREWALL = f"{RG}/azureFirewalls/fw-hub"
CLASSIC = f"{RG}/azureFirewalls/fw-classic"
WORKSPACE = f"{SUB}/resourceGroups/rg-logs/providers/Microsoft.OperationalInsights/workspaces/law"


def net_rule(name, sources, destinations, ports, protocols=("TCP",)):
    return {"ruleType": "NetworkRule", "name": name, "sourceAddresses": list(sources),
            "destinationAddresses": list(destinations), "destinationPorts": list(ports), "ipProtocols": list(protocols)}


def app_rule(name, sources, fqdns=(), tags=(), categories=(), urls=()):
    return {"ruleType": "ApplicationRule", "name": name, "sourceAddresses": list(sources),
            "protocols": [{"protocolType": "Https", "port": 443}], "targetFqdns": list(fqdns),
            "fqdnTags": list(tags), "webCategories": list(categories), "targetUrls": list(urls)}


def nat_rule(name, sources, ports, translated="10.0.1.4"):
    return {"ruleType": "NatRule", "name": name, "sourceAddresses": list(sources), "destinationAddresses": ["20.1.1.1"],
            "destinationPorts": list(ports), "ipProtocols": ["TCP"], "translatedAddress": translated,
            "translatedPort": ports[0]}


def group(policy, name, priority, collections):
    return {"id": f"{policy}/ruleCollectionGroups/{name}", "name": name,
            "properties": {"priority": priority, "ruleCollections": collections}}


def filter_collection(name, action, rules, priority=100):
    return {"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": name, "priority": priority,
            "action": {"type": action}, "rules": rules}


def nat_collection(name, rules, priority=100):
    return {"ruleCollectionType": "FirewallPolicyNatRuleCollection", "name": name, "priority": priority,
            "action": {"type": "DNAT"}, "rules": rules}


def raw_policy(pid, *, tier="Premium", threat="Deny", idps="Deny", tls=True, proxy=True, base=None, firewalls=()):
    props = {
        "sku": {"tier": tier}, "threatIntelMode": threat, "provisioningState": "Succeeded",
        "threatIntelWhitelist": {"fqdns": ["ok.example.com"], "ipAddresses": []},
        "intrusionDetection": {"mode": idps, "profile": "Standard",
                               "configuration": {"signatureOverrides": [{"id": "1"}], "bypassTrafficSettings": []}},
        "dnsSettings": {"servers": [], "enableProxy": proxy},
        "insights": {"isEnabled": True, "logAnalyticsResources": {"defaultWorkspaceId": {"id": WORKSPACE}}},
        "firewalls": [{"id": f} for f in firewalls],
    }
    if tls:
        props["transportSecurity"] = {"certificateAuthority": {"name": "ca", "keyVaultSecretId": "https://kv/secret"}}
    if base:
        props["basePolicy"] = {"id": base}
    return {"id": pid, "name": pid.rsplit("/", 1)[-1], "location": "usgovvirginia", "properties": props}


def raw_firewall(fid, *, policy=POLICY, tier="Premium", classic=None, management=False, hub=False):
    props = {"sku": {"name": "AZFW_Hub" if hub else "AZFW_VNet", "tier": tier}, "provisioningState": "Succeeded",
             "threatIntelMode": "Alert", "additionalProperties": {"Network.DNS.EnableProxy": "true"}}
    if policy:
        props["firewallPolicy"] = {"id": policy}
    if hub:
        props["virtualHub"] = {"id": f"{RG}/virtualHubs/hub"}
        props["hubIPAddresses"] = {"publicIPs": {"addresses": [{"address": "20.2.2.2"}]}}
    else:
        props["ipConfigurations"] = [{"name": "ipc", "properties": {
            "privateIPAddress": "10.0.0.4", "subnet": {"id": f"{RG}/virtualNetworks/vnet/subnets/AzureFirewallSubnet"},
            "publicIPAddress": {"id": f"{RG}/publicIPAddresses/pip-fw"}}}]
    if management:
        props["managementIpConfiguration"] = {"name": "mgmt", "properties": {}}
    props.update(classic or {})
    return {"id": fid, "name": fid.rsplit("/", 1)[-1], "location": "usgovvirginia", "zones": ["1", "2", "3"],
            "properties": props}


CLASSIC_RULES = {
    "networkRuleCollections": [{"name": "allow-dns", "properties": {"priority": 100, "action": {"type": "Allow"}, "rules": [
        {"name": "dns", "protocols": ["UDP"], "sourceAddresses": ["10.0.0.0/8"], "destinationAddresses": ["*"],
         "destinationPorts": ["53"]}]}}],
    "applicationRuleCollections": [{"name": "allow-web", "properties": {"priority": 200, "action": {"type": "Allow"}, "rules": [
        {"name": "updates", "sourceAddresses": ["10.0.0.0/8"], "protocols": [{"protocolType": "Https", "port": 443}],
         "fqdnTags": ["WindowsUpdate"]}]}}],
    "natRuleCollections": [{"name": "publish", "properties": {"priority": 300, "action": {"type": "Dnat"}, "rules": [
        {"name": "rdp", "protocols": ["TCP"], "sourceAddresses": ["*"], "destinationAddresses": ["20.1.1.1"],
         "destinationPorts": ["3389"], "translatedAddress": "10.0.1.5", "translatedPort": "3389"}]}}],
}


# --- rules ---

def test_allow_all_needs_any_source_any_destination_and_any_port() -> None:
    col = filter_collection("c", "Allow", [])
    full = fw.rule_record(net_rule("r", ["*"], ["0.0.0.0/0"], ["*"]), group="g", group_priority=1, collection=col,
                          rule_type=fw.NETWORK_RULE, action=fw.ALLOW)
    assert full["allow_all"] is True and full["to_any_destination"] is True and full["from_any_source"] is True
    ports = fw.rule_record(net_rule("r", ["*"], ["*"], ["443"]), group="g", group_priority=1, collection=col,
                           rule_type=fw.NETWORK_RULE, action=fw.ALLOW)
    assert ports["allow_all"] is False and ports["to_any_destination"] is True
    scoped = fw.rule_record({**net_rule("r", ["*"], ["*"], ["*"]), "destinationIpGroups": [f"{RG}/ipGroups/g1"]},
                            group="g", group_priority=1, collection=col, rule_type=fw.NETWORK_RULE, action=fw.ALLOW)
    assert scoped["allow_all"] is True and scoped["destination_ip_groups"] == ["g1"]  # a group adds addresses, never narrows
    denied = fw.rule_record(net_rule("r", ["*"], ["*"], ["*"]), group="g", group_priority=1, collection=col,
                            rule_type=fw.NETWORK_RULE, action=fw.DENY)
    assert denied["allow_all"] is False and denied["to_any_destination"] is False


def test_application_rule_to_any_fqdn_only_when_nothing_scopes_it() -> None:
    col = filter_collection("c", "Allow", [])
    wide = fw.rule_record(app_rule("r", ["10.0.0.0/8"], fqdns=["*"]), group="g", group_priority=1, collection=col,
                          rule_type=fw.APPLICATION_RULE, action=fw.ALLOW)
    assert wide["to_any_fqdn"] is True and wide["protocols"] == ["Https:443"]
    tagged = fw.rule_record(app_rule("r", ["*"], fqdns=["*"], tags=["WindowsUpdate"]), group="g", group_priority=1,
                            collection=col, rule_type=fw.APPLICATION_RULE, action=fw.ALLOW)
    assert tagged["to_any_fqdn"] is False
    named = fw.rule_record(app_rule("r", ["*"], fqdns=["*.ubuntu.com"]), group="g", group_priority=1, collection=col,
                           rule_type=fw.APPLICATION_RULE, action=fw.ALLOW)
    assert named["to_any_fqdn"] is False


def test_dnat_rule_flags_admin_ports_and_any_source() -> None:
    col = nat_collection("c", [])
    rdp = fw.rule_record(nat_rule("r", ["*"], ["3389"]), group="g", group_priority=1, collection=col,
                         rule_type=fw.NAT_RULE, action=fw.DNAT)
    assert rdp["to_admin_port"] is True and rdp["from_any_source"] is True and rdp["translated_address"] == "10.0.1.4"
    https = fw.rule_record(nat_rule("r", ["203.0.113.0/24"], ["443"]), group="g", group_priority=1, collection=col,
                           rule_type=fw.NAT_RULE, action=fw.DNAT)
    assert https["to_admin_port"] is False and https["from_any_source"] is False


def test_policy_rules_carry_group_and_collection_and_nat_action() -> None:
    groups = [group(POLICY, "g1", 100, [
        filter_collection("net", "Allow", [net_rule("a", ["10.0.0.0/8"], ["10.1.0.0/16"], ["443"])], 100),
        nat_collection("nat", [nat_rule("p", ["*"], ["22"])], 200),
    ])]
    rules = fw.policy_rules(groups)
    assert [(r["rule_type"], r["action"], r["collection_group"], r["collection_priority"]) for r in rules] == [
        (fw.NETWORK_RULE, fw.ALLOW, "g1", 100), (fw.NAT_RULE, fw.DNAT, "g1", 200)]
    assert fw.rule_findings(rules) == {
        "rules": 2, "rules_by_type": {"nat": 1, "network": 1}, "rules_by_action": {"allow": 1, "dnat": 1},
        "allow_all_network_rules": 0, "network_rules_to_any_destination": 0, "application_rules_to_any_fqdn": 0,
        "dnat_rules": 1, "dnat_rules_to_admin_ports": 1, "dnat_rules_from_any_source": 1}


def test_classic_rules_are_read_from_the_firewall_in_the_same_shape() -> None:
    rules = fw.classic_rules(CLASSIC_RULES)
    kinds = {(r["rule_type"], r["action"]) for r in rules}
    assert kinds == {(fw.NETWORK_RULE, fw.ALLOW), (fw.APPLICATION_RULE, fw.ALLOW), (fw.NAT_RULE, fw.DNAT)}
    net = next(r for r in rules if r["rule_type"] == fw.NETWORK_RULE)
    assert net["to_any_destination"] is True and net["allow_all"] is False and net["protocols"] == ["UDP"]
    assert next(r for r in rules if r["rule_type"] == fw.NAT_RULE)["to_admin_port"] is True


def test_unread_rules_give_null_findings() -> None:
    assert all(v is None for v in fw.rule_findings(None).values())


# --- policy chain and effective settings ---

def _policies(**kwargs):
    child = fw.policy_record(raw_policy(POLICY, base=BASE, firewalls=[FIREWALL]), [group(POLICY, "g", 100, [
        filter_collection("c", "Allow", [app_rule("web", ["10.0.0.0/8"], fqdns=["*.example.gov"])])])], "s1")
    base = fw.policy_record(raw_policy(BASE, threat="Alert", idps="Alert", tls=False), [group(BASE, "g", 100, [
        filter_collection("c", "Deny", [net_rule("block", ["*"], ["*"], ["*"])])])], "s1")
    base.update(kwargs)
    return {fw.arm_id_key(POLICY): child, fw.arm_id_key(BASE): base}


def test_chain_walks_base_policies_nearest_first() -> None:
    policies = _policies()
    names = [p["name"] for p in fw.chain(POLICY, policies)]
    assert names == ["pol-child", "pol-base"]
    assert policies[fw.arm_id_key(POLICY)]["base_policy_in_subscription"] is True


def test_chain_is_unread_when_a_base_policy_is_unread_or_missing() -> None:
    assert fw.chain(POLICY, _policies(rules_read=False)) is None
    only_child = {k: v for k, v in _policies().items() if k == fw.arm_id_key(POLICY)}
    assert fw.chain(POLICY, only_child) is None
    assert fw.chain(FOREIGN, {}) is None


def test_chain_stops_on_a_cycle() -> None:
    policies = _policies(base_policy_id=POLICY)
    assert [p["name"] for p in fw.chain(POLICY, policies)] == ["pol-child", "pol-base"]


def test_firewall_takes_settings_from_the_nearest_policy_and_rules_from_the_chain() -> None:
    record = fw.firewall_record(raw_firewall(FIREWALL), _policies(), [])
    assert record["policy_chain"] == ["pol-child", "pol-base"] and record["rules_read"] is True
    assert record["threat_intel_mode"] == "Deny" and record["idps_mode"] == "Deny"
    assert record["tls_inspection_enabled"] is True and record["dns_proxy_enabled"] is True
    assert record["rule_summary"]["rules"] == 2 and record["rule_summary"]["rules_by_action"] == {"allow": 1, "deny": 1}
    assert record["egress_filtering_enforced"] is True
    assert record["public_ip_addresses"] == [f"{RG}/publicIPAddresses/pip-fw"] and record["private_ip_addresses"] == ["10.0.0.4"]
    assert record["management_ip_configured"] is False and record["deployment"] == "virtual_network"
    assert record["settings_read"] is True
    assert record["rule_logs_exported"] is False and record["logs"]["destinations"] == []


def test_firewall_with_unread_policy_reads_null_not_false() -> None:
    record = fw.firewall_record(raw_firewall(FIREWALL, policy=FOREIGN), {}, [])
    assert record["rules_read"] is False and record["policy_chain"] is None
    assert record["egress_filtering_enforced"] is None and record["rule_summary"]["rules"] is None
    # Azure ignores the firewall's own settings once a policy is attached, so nothing is known.
    assert record["settings_read"] is False and record["threat_intel_mode"] is None
    assert record["idps_mode"] is None and record["tls_inspection_enabled"] is None and record["dns_proxy_enabled"] is None


def test_classic_firewall_uses_its_own_rules_and_dns_proxy_property() -> None:
    record = fw.firewall_record(raw_firewall(CLASSIC, policy=None, classic=CLASSIC_RULES, management=True), {}, None)
    assert record["rule_source"] == "classic" and record["classic_rule_collections"] == 3
    assert record["rules_read"] is True and record["rule_summary"]["dnat_rules_to_admin_ports"] == 1
    assert record["egress_filtering_enforced"] is True  # any-destination on one port is broad, not allow-all
    assert record["dns_proxy_enabled"] is True and record["management_ip_configured"] is True and record["threat_intel_mode"] == "Alert"
    assert record["settings_read"] is True and record["idps_mode"] is None and record["tls_inspection_enabled"] is False
    assert record["rule_logs_exported"] is None and record["logs"]["diagnostic_settings_read"] is False


def test_firewall_without_rules_enforces_filtering_by_default_deny() -> None:
    # Azure Firewall denies whatever no rule allows, so a firewall with no rules blocks every flow.
    record = fw.firewall_record(raw_firewall(CLASSIC, policy=None), {}, [])
    assert record["rule_source"] == "none" and record["egress_filtering_enforced"] is True
    summary = fw.summarize([record], [], True, True)
    assert (summary["firewalls_without_rules"], summary["firewalls_enforcing_egress_filtering"]) == (1, 1)


def test_hub_firewall_lists_hub_public_and_private_ips() -> None:
    raw = raw_firewall(FIREWALL, hub=True)
    raw["properties"]["hubIPAddresses"]["privateIPAddress"] = "10.9.0.4"
    record = fw.firewall_record(raw, _policies(), [])
    assert record["deployment"] == "virtual_hub" and record["public_ip_addresses"] == ["20.2.2.2"]
    assert record["private_ip_addresses"] == ["10.9.0.4"]


def test_dnat_only_firewall_enforces_egress_filtering_by_default_deny() -> None:
    # DNAT rules only translate inbound traffic; outbound traffic still meets the default deny.
    classic = {"natRuleCollections": CLASSIC_RULES["natRuleCollections"]}
    record = fw.firewall_record(raw_firewall(CLASSIC, policy=None, classic=classic), {}, [])
    assert record["rule_source"] == "classic" and record["egress_filtering_enforced"] is True


@pytest.mark.parametrize("ports, allow_all, admin", [
    (["*"], True, True), (["1-65535"], True, True), (["0-65535"], True, True), (["3000-4000"], False, True),
    (["22"], False, True), (["443"], False, False), (["80-443"], False, False), (["abc"], False, False),
])
def test_port_ranges(ports, allow_all, admin) -> None:
    assert fw._any_port(ports) is allow_all
    assert any(fw._covers_port(ports, p) for p in fw.ADMIN_PORTS) is admin


@pytest.mark.parametrize("ports, allow_all", [
    (["1-1000", "1001-65535"], True), (["1-1000", "1002-65535"], False), (["1-65535"], True),
    (["22,3389"], False), (["1-30000,30001-65535"], True), (["*", "abc"], True),
])
def test_split_ports_are_unioned_and_comma_lists_are_read(ports, allow_all) -> None:
    assert fw._any_port(ports) is allow_all
    if ports == ["22,3389"]:
        assert fw._covers_port(ports, 22) and fw._covers_port(ports, 3389) and not fw._covers_port(ports, 80)


def test_icmp_only_rules_and_ip_groups_in_allow_all() -> None:
    def record(rule):
        return fw.rule_record(rule, group=None, group_priority=None, collection={}, rule_type=fw.NETWORK_RULE, action=fw.ALLOW)
    assert record(net_rule("ping", ["*"], ["*"], ["*"], protocols=["ICMP"]))["allow_all"] is False
    assert record(net_rule("any", ["*"], ["*"], ["*"], protocols=["Any"]))["allow_all"] is True
    assert record(net_rule("mix", ["*"], ["*"], ["*"], protocols=["ICMP", "TCP"]))["allow_all"] is True
    grouped = net_rule("grp", ["*"], ["*"], ["*"])
    grouped["sourceIpGroups"], grouped["destinationIpGroups"] = ["/g/one"], ["/g/two"]
    assert record(grouped)["allow_all"] is True and record(grouped)["from_any_source"] is True


def test_dnat_to_an_admin_port_is_found_by_its_translated_port() -> None:
    rule = nat_rule("ssh", ["10.0.0.0/8"], ["8022"])
    rule["translatedPort"] = 22
    record = fw.rule_record(rule, group="g", group_priority=1, collection={}, rule_type=fw.NAT_RULE, action=fw.DNAT)
    assert record["to_admin_port"] is True
    rule["translatedPort"] = "8080"
    assert fw.rule_record(rule, group="g", group_priority=1, collection={}, rule_type=fw.NAT_RULE,
                          action=fw.DNAT)["to_admin_port"] is False


# --- log export ---

def _setting(name, logs, **dest):
    return {"name": name, "properties": {"logs": logs, **dest}}


def test_exported_destinations_resolve_categories_and_groups() -> None:
    settings = [
        _setting("to-law", [{"category": "AZFWNetworkRule", "enabled": True}, {"category": "AZFWThreatIntel", "enabled": False}],
                 workspaceId=WORKSPACE),
        _setting("to-storage", [{"categoryGroup": "allLogs", "enabled": True}], storageAccountId=f"{SUB}/sa"),
        _setting("off", [{"category": "AZFWIdpsSignature", "enabled": False}], workspaceId=WORKSPACE),
    ]
    logs = fw.exported_destinations(settings)
    assert logs["diagnostic_settings_read"] is True
    assert [(d["setting"], d["kind"], d["categories"]) for d in logs["destinations"]] == [
        ("to-law", "log_analytics", ["AZFWNetworkRule"]), ("to-storage", "storage", ["group:allLogs"])]
    assert "AZFWIdpsSignature" in logs["categories"] and "AZFWNetworkRule" in logs["categories"]
    assert logs["destinations"][1]["categories"] == ["group:allLogs"]
    record = fw.firewall_record(raw_firewall(FIREWALL), _policies(), settings)
    assert record["rule_logs_exported"] is True and record["threat_logs_exported"] is True


def test_only_a_named_rule_category_or_all_logs_counts_as_rule_logs() -> None:
    settings = [_setting("s", [{"category": "AZFWDnsQuery", "enabled": True}], workspaceId=WORKSPACE)]
    record = fw.firewall_record(raw_firewall(FIREWALL), _policies(), settings)
    assert record["rule_logs_exported"] is False and record["threat_logs_exported"] is False
    assert record["logs"]["destinations"][0]["kind"] == "log_analytics"
    audit = [_setting("s", [{"categoryGroup": "audit", "enabled": True}], workspaceId=WORKSPACE)]
    record = fw.firewall_record(raw_firewall(FIREWALL), _policies(), audit)
    assert record["rule_logs_exported"] is False and record["logs"]["categories"] == ["group:audit"]


# --- summary ---

def test_summary_counts_and_nulls() -> None:
    policies = _policies()
    settings = [_setting("s", [{"category": "AZFWApplicationRule", "enabled": True}], workspaceId=WORKSPACE)]
    good = fw.firewall_record(raw_firewall(FIREWALL), policies, settings)
    unread = fw.firewall_record(raw_firewall(CLASSIC, policy=FOREIGN), policies, settings)
    own = list(policies.values())
    summary = fw.summarize([good], own, True, True)
    assert summary["firewalls"] == 1 and summary["firewalls_with_policy"] == 1
    assert summary["firewall_policies"] == 2 and summary["firewall_policies_in_use"] == 1
    assert summary["firewall_policies_unused"] == 1 and summary["firewall_policies_with_base_policy"] == 1
    assert summary["rules"] == 2 and summary["firewalls_enforcing_egress_filtering"] == 1
    assert summary["egress_filtering_percentage"] == 100 and summary["firewalls_with_allow_all_rule"] == 0
    assert summary["firewalls_by_threat_intel_mode"] == {"alert": 0, "deny": 1, "off": 0, "unknown": 0} and summary["firewalls_with_idps_deny"] == 1
    assert summary["firewalls_with_settings_unread"] == 0 and summary["firewalls_with_management_ip"] == 0
    assert summary["firewalls_with_tls_inspection"] == 1 and summary["firewalls_with_public_ip"] == 1
    assert summary["firewalls_exporting_rule_logs"] == 1 and summary["firewalls_exporting_threat_logs"] == 0
    assert summary["firewalls_without_log_export"] == 0 and summary["log_categories_exported"] == ["AZFWApplicationRule"]

    mixed = fw.summarize([good, unread], own, True, True)
    assert mixed["firewalls_with_rules_unread"] == 1
    for key in ("rules", "allow_all_network_rules", "firewalls_enforcing_egress_filtering", "egress_filtering_percentage",
                "firewalls_with_allow_all_rule", "dnat_rules"):
        assert mixed[key] is None, key
    assert mixed["firewalls_with_settings_unread"] == 1 and mixed["firewalls_by_threat_intel_mode"] == {"alert": 0, "deny": 1, "off": 0, "unknown": 1}
    for key in ("firewalls_without_idps", "firewalls_with_idps_deny", "firewalls_with_tls_inspection", "firewalls_with_dns_proxy",
                "firewalls_with_threat_intel_deny"):
        assert mixed[key] is None, key


def test_summary_with_no_firewalls() -> None:
    summary = fw.summarize([], [], True, True)
    assert summary["firewalls"] == 0 and summary["rules"] == 0 and summary["egress_filtering_percentage"] == 0
    assert summary["firewalls_enforcing_egress_filtering"] == 0 and summary["log_categories_exported"] == []


# --- collection through a fake ARM ---

class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text = status, body, "", json.dumps(body)
        self.headers: dict = {}

    def json(self):
        return self._body


class _Arm:
    def __init__(self, *, registered=True, foreign_readable=True, groups_fail=False, list_fail=False,
                 bare_groups=False, firewalls=None, policies=None, foreign_base=None):
        self.registered, self.foreign_readable, self.foreign_base = registered, foreign_readable, foreign_base
        self.groups_fail, self.list_fail, self.bare_groups = groups_fail, list_fail, bare_groups
        self.firewalls = firewalls if firewalls is not None else [raw_firewall(FIREWALL), raw_firewall(CLASSIC, policy=FOREIGN)]
        self.policies = policies if policies is not None else [raw_policy(POLICY, base=BASE, firewalls=[FIREWALL]),
                                                               raw_policy(BASE, threat="Alert", idps="Off", tls=False)]
        self.urls: list[str] = []

    def get(self, url, params=None, headers=None, timeout=None):
        path = urlparse(url).path
        self.urls.append(path + "?api-version=" + (params or {}).get("api-version", ""))
        if not self.registered and "/Microsoft.Network/" in path:
            return _Resp(409, {"error": {"code": "MissingSubscriptionRegistration", "message": "not registered"}})
        if path.endswith("/providers/Microsoft.Network/azureFirewalls"):
            if self.list_fail:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            return _Resp(200, {"value": self.firewalls})
        if path.endswith("/providers/Microsoft.Network/firewallPolicies"):
            return _Resp(200, {"value": self.policies})
        if path.endswith("/ruleCollectionGroups"):
            if self.groups_fail and "/pol-base/" in path:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no groups"}})
            policy = path.rsplit("/ruleCollectionGroups", 1)[0]
            g = group(policy, "g", 100, [filter_collection("c", "Allow", [net_rule("a", ["*"], ["*"], ["*"])])]
                      if "/pol-base" in policy else [filter_collection("c", "Allow", [app_rule("w", ["*"], fqdns=["*.gov"])])])
            if self.bare_groups:
                g = {"id": g["id"], "name": g["name"], "properties": {"priority": 100}}
            return _Resp(200, {"value": [g]})
        if "/ruleCollectionGroups/" in path:
            policy = path.rsplit("/ruleCollectionGroups/", 1)[0]
            return _Resp(200, group(policy, "g", 100, [filter_collection("c", "Allow", [net_rule("a", ["10.0.0.0/8"], ["*"], ["443"])])]))
        if path == FOREIGN.lower() or path == FOREIGN:
            if not self.foreign_readable:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            return _Resp(200, raw_policy(FOREIGN, threat="Deny", idps="Deny", base=self.foreign_base))
        if self.foreign_base and path == self.foreign_base:
            return _Resp(200, raw_policy(self.foreign_base, threat="Alert", idps="Off", tls=False))
        if path.endswith("/providers/Microsoft.Insights/diagnosticSettings"):
            return _Resp(200, {"value": [_setting("s", [{"category": "AZFWNetworkRule", "enabled": True}], workspaceId=WORKSPACE)]})
        return _Resp(404, {"error": {"code": "NotFound", "message": path}})


class _Cred:
    def get_token(self, scope):
        return namedtuple("T", "token expires_on")("tok", 9_999_999_999)


def _collect(arm, exclusions=None):
    client = azure_rest.AzureRestClient(_Cred(), session=arm)
    collector = Collector(logging.getLogger("test"))
    results, summary = fw.collect(client, "s1", collector, exclusions)
    return results, summary, collector


def test_collect_reads_policies_chains_and_foreign_policies(assert_summary_documented) -> None:
    arm = _Arm()
    results, summary, collector = _collect(arm)
    assert collector.ok, collector.failures
    assert_summary_documented("azure/firewall_configuration", summary)
    assert [f["name"] for f in results["firewalls"]] == ["fw-classic", "fw-hub"]
    hub = next(f for f in results["firewalls"] if f["name"] == "fw-hub")
    classic = next(f for f in results["firewalls"] if f["name"] == "fw-classic")
    assert hub["policy_chain"] == ["pol-child", "pol-base"] and hub["egress_filtering_enforced"] is False
    assert hub["rule_summary"]["allow_all_network_rules"] == 1  # inherited from the base policy
    assert classic["policy_chain"] == ["pol-corp"] and classic["egress_filtering_enforced"] is True
    assert [p["name"] for p in results["firewall_policies"]] == ["pol-base", "pol-child"]
    assert [p["name"] for p in results["foreign_firewall_policies"]] == ["pol-corp"]
    assert summary["firewalls_with_allow_all_rule"] == 1 and summary["firewalls_enforcing_egress_filtering"] == 1
    assert summary["rules"] == 3  # both own policies and the foreign policy a firewall here uses, each counted once
    assert summary["firewalls_exporting_rule_logs"] == 2 and summary["firewall_policies"] == 2
    assert summary["excluded_firewalls"] == 0 and summary["in_scope_firewall_policies"] == 2
    assert any(p.endswith("/pol-corp?api-version=" + fw.NETWORK_API) for p in arm.urls)


def test_foreign_policy_base_policy_is_followed() -> None:
    base = f"{OTHER}/resourceGroups/rg-sec/providers/Microsoft.Network/firewallPolicies/pol-corp-base"
    arm = _Arm(foreign_base=base)
    results, summary, collector = _collect(arm)
    assert collector.ok
    classic = next(f for f in results["firewalls"] if f["name"] == "fw-classic")
    assert classic["policy_chain"] == ["pol-corp", "pol-corp-base"] and classic["rules_read"] is True
    assert classic["rule_summary"]["rules"] == 2 and classic["threat_intel_mode"] == "Deny"
    assert [p["name"] for p in results["foreign_firewall_policies"]] == ["pol-corp", "pol-corp-base"]


def test_unreadable_foreign_policy_is_unread_not_a_failure() -> None:
    results, summary, collector = _collect(_Arm(foreign_readable=False))
    assert collector.ok
    classic = next(f for f in results["firewalls"] if f["name"] == "fw-classic")
    assert classic["rules_read"] is False and classic["egress_filtering_enforced"] is None
    assert summary["firewalls_with_rules_unread"] == 1 and summary["firewalls_enforcing_egress_filtering"] is None
    assert results["foreign_firewall_policies"] == []


def test_failed_rule_group_read_fails_the_run_and_nulls_the_chain() -> None:
    results, summary, collector = _collect(_Arm(groups_fail=True))
    assert not collector.ok and "pol-base" in collector.failures[0]["operation"]
    hub = next(f for f in results["firewalls"] if f["name"] == "fw-hub")
    assert hub["rules_read"] is False and hub["rule_summary"]["rules"] is None
    base = next(p for p in results["firewall_policies"] if p["name"] == "pol-base")
    assert base["rules_read"] is False and base["rules"] is None and base["rule_summary"]["rules"] is None
    assert summary["firewall_policies_with_rules_unread"] == 1 and summary["rules"] is None


def test_bare_group_listing_is_completed_with_a_get_per_group() -> None:
    arm = _Arm(bare_groups=True)
    results, summary, collector = _collect(arm)
    assert collector.ok
    child = next(p for p in results["firewall_policies"] if p["name"] == "pol-child")
    assert child["rules"][0]["name"] == "a" and child["rules"][0]["to_any_destination"] is True
    assert any("/ruleCollectionGroups/g?" in u for u in arm.urls)


def test_failed_firewall_list_fails_the_run_with_nothing_assessed() -> None:
    results, summary, collector = _collect(_Arm(list_fail=True))
    assert not collector.ok and summary["firewalls_read"] is False
    assert summary["in_scope_firewalls"] is None and summary["excluded_firewalls"] is None
    assert summary["firewall_policies_read"] is True
    # An unread firewall list is not an empty one: no firewall or rule count reads as a known 0.
    for key in ("firewalls", "firewalls_by_sku_tier", "firewalls_with_policy", "firewalls_enforcing_egress_filtering",
                "egress_filtering_percentage", "firewalls_with_threat_intel_deny", "firewalls_with_allow_all_rule",
                "firewalls_without_log_export", "log_categories_exported", "rules", "allow_all_network_rules",
                "application_rules_to_any_fqdn", "rules_by_type"):
        assert summary[key] is None, key
    # The policy list was read, so its counts stand.
    assert summary["firewall_policies"] == 2


def test_unregistered_provider_reads_as_no_firewalls() -> None:
    results, summary, collector = _collect(_Arm(registered=False))
    assert collector.ok and summary["firewalls"] == 0 and summary["firewall_policies"] == 0
    assert summary["firewalls_read"] is True


def test_exclusions_remove_a_firewall_and_a_policy_and_skip_their_reads() -> None:
    arm = _Arm()
    results, summary, collector = _collect(arm, ResourceExclusions(["id:*/fw-classic", "id:*/pol-base", "rg:nope"]))
    assert collector.ok
    assert [f["name"] for f in results["firewalls"]] == ["fw-hub"]
    assert [p["name"] for p in results["firewall_policies"]] == ["pol-child"]
    assert summary["excluded_firewalls"] == 1 and summary["excluded_firewall_policies"] == 1
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:nope"]
    assert not any("/pol-corp" in u for u in arm.urls)  # only the excluded firewall referenced it
    hub = results["firewalls"][0]
    assert hub["rules_read"] is False  # its base policy was excluded, so the chain is incomplete


def test_invalid_exclusion_pattern_fails_the_run() -> None:
    results, summary, collector = _collect(_Arm(), ResourceExclusions(["fw-hub"]))
    assert not collector.ok and "resource exclusion pattern" in collector.failures[0]["message"]


class _Timeout(Exception):
    pass


def test_a_timeout_reading_a_foreign_policy_is_recorded_not_a_crash() -> None:
    import requests

    class Boom(_Arm):
        def get(self, url, params=None, headers=None, timeout=None):
            if urlparse(url).path.lower() == FOREIGN.lower():
                raise requests.Timeout("read timed out")
            return super().get(url, params, headers, timeout)

    results, summary, collector = _collect(Boom())
    assert not collector.ok and any("pol-corp" in f["operation"] for f in collector.failures)
    classic = next(f for f in results["firewalls"] if f["name"] == "fw-classic")
    assert classic["rules_read"] is False and summary["rules"] is None and summary["firewalls_with_rules_unread"] == 1


def test_a_foreign_allow_all_rule_reaches_the_summary_counts() -> None:
    class Wide(_Arm):
        def get(self, url, params=None, headers=None, timeout=None):
            path = urlparse(url).path
            if path.lower().endswith("/pol-corp/rulecollectiongroups"):
                g = group(FOREIGN, "g", 100, [filter_collection("c", "Allow", [net_rule("a", ["*"], ["*"], ["*"])])])
                return _Resp(200, {"value": [g]})
            return super().get(url, params, headers, timeout)

    _, summary, collector = _collect(Wide())
    assert collector.ok and summary["firewalls_with_allow_all_rule"] == 2
    assert summary["allow_all_network_rules"] == 2  # the base policy's rule and the foreign policy's rule


class _ListsFail(_Arm):
    """Refuses the firewall list, the policy list, or both."""

    def __init__(self, firewalls_fail=True, policies_fail=True, **kwargs):
        super().__init__(list_fail=firewalls_fail, **kwargs)
        self.policies_fail = policies_fail

    def get(self, url, params=None, headers=None, timeout=None):
        if self.policies_fail and urlparse(url).path.endswith("/providers/Microsoft.Network/firewallPolicies"):
            return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
        return super().get(url, params, headers, timeout)


def test_failed_policy_list_leaves_the_policy_and_rule_counts_null() -> None:
    results, summary, collector = _collect(_ListsFail(firewalls_fail=False))
    assert not collector.ok and summary["firewall_policies_read"] is False and summary["firewalls"] == 2
    for key in ("firewall_policies", "firewall_policies_in_use", "firewall_policies_unused",
                "firewall_policies_with_base_policy", "firewall_policies_with_rules_unread", "rules",
                "allow_all_network_rules"):
        assert summary[key] is None, key


def test_failed_policy_list_with_no_firewalls_leaves_rule_counts_null() -> None:
    results, summary, collector = _collect(_ListsFail(firewalls_fail=False, firewalls=[]))
    assert summary["firewalls"] == 0 and summary["rules"] is None and summary["allow_all_network_rules"] is None


def test_both_lists_failed_reads_nothing_as_zero() -> None:
    results, summary, collector = _collect(_ListsFail())
    assert not collector.ok
    assert (summary["firewalls_read"], summary["firewall_policies_read"]) == (False, False)
    zeros = {k: v for k, v in summary.items() if not isinstance(v, bool) and v in (0, {}, [])
             and not k.startswith(("excluded_", "resource_exclusion"))}
    assert zeros == {}, zeros
