"""resource_exclusions in the Azure Front Door and DNS fetchers: excluded resources leave every count and stay listed under excluded."""

from __future__ import annotations

import copy
import importlib.util
import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

from azure_common import Collector  # noqa: E402
from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
IN_RG = f"{SUB}/resourceGroups/rg-in"
OUT_RG = f"{SUB}/resourceGroups/rg-out"
NET_IN = f"{IN_RG}/providers/Microsoft.Network"
NET_OUT = f"{OUT_RG}/providers/Microsoft.Network"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_resource_exclusions_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dns = _load("dns_configuration")
waf = _load("front_door_waf_policies")
tls = _load("front_door_tls")
coverage = _load("front_door_waf_coverage")
origins = _load("front_door_origins")
fd = sys.modules["frontdoor"]


def _run(m, monkeypatch, tmp_path, patterns, filename, scope=None):
    monkeypatch.setattr(m, "load_dotenv", lambda: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    for env, value in ((ENV, patterns), (getattr(m, "SCOPE_EXCLUSIONS_ENV", None), scope)):
        if env is None:
            continue
        if value is None:
            monkeypatch.delenv(env, raising=False)
        else:
            monkeypatch.setenv(env, value)
    code = m.main()
    return code, json.loads((tmp_path / f"{filename}_s1.json").read_text())


def _added_fields(kinds: dict) -> dict:
    """The fields a run without patterns adds to the summary: kind -> in-scope total (None: no in_scope field)."""
    return {
        "resource_exclusion_patterns": [],
        "resource_exclusion_patterns_unmatched": [],
        **{f"excluded_{kind}s": 0 for kind in kinds},
        **{f"in_scope_{kind}s": total for kind, total in kinds.items() if total is not None},
    }


def _excluded(evidence, kinds=None) -> list:
    return sorted((e["kind"], e["name"], e["pattern"], e["reason"]) for e in evidence["results"]["excluded"]
                  if kinds is None or e["kind"] in kinds)


# --- dns_configuration ---

AFD_OUT = f"{OUT_RG}/providers/Microsoft.Cdn/profiles/fd-out/afdEndpoints/web"
VNET_OUT = f"{NET_OUT}/virtualNetworks/vnet-out"


def _record(zone, name, record_type, **kw):
    fqdn = f"{zone}." if name == "@" else f"{name}.{zone}."
    return NS(name=name, type=f"Microsoft.Network/dnszones/{record_type}", fqdn=fqdn, ttl=300,
              provisioning_state="Succeeded", **kw)


# zone name -> (network prefix, DNSSEC signed, record sets)
PUBLIC_ZONES = {
    "in.example": (NET_IN, True, [
        # An alias to a Front Door endpoint in the excluded group.
        _record("in.example", "@", "A", target_resource=NS(id=AFD_OUT)),
        _record("in.example", "www", "CNAME", cname_record=NS(cname="web.z01.azurefd.net")),
    ]),
    "out.example": (NET_OUT, False, [
        _record("out.example", "www", "CNAME", cname_record=NS(cname="www.example.net")),
        _record("out.example", "legacy", "A", a_records=[NS(ipv4_address="203.0.113.7")]),
    ]),
    "named.example": (NET_IN, False, [_record("named.example", "@", "MX", mx_records=[NS(preference=10, exchange="mx.example.net")])]),
}
# zone name -> (network prefix, linked virtual networks)
PRIVATE_ZONES = {
    # Linked to a virtual network in the excluded group.
    "privatelink.blob.core.windows.net": (NET_IN, [VNET_OUT]),
    "corp.internal": (NET_OUT, [f"{NET_OUT}/virtualNetworks/vnet-corp"]),
}


def _fake_dns_sdk(monkeypatch, reads: list):
    """The DNS and private DNS clients over PUBLIC_ZONES and PRIVATE_ZONES; each per-zone read is appended to `reads`."""
    signed = {"properties": {"provisioningState": "Succeeded", "signingKeys": [
        {"flags": 257, "keyTag": 1, "protocol": 3, "securityAlgorithmType": 13, "delegationSignerInfo": [{}]}]}}

    def send_request(request):
        zone = request[1].split("/dnszones/")[1].split("/")[0]
        reads.append(("dnssec", zone))
        if PUBLIC_ZONES[zone][1]:
            return NS(status_code=200, raise_for_status=lambda: None, json=lambda: signed)
        return NS(status_code=404)

    def record_sets(rg, name):
        reads.append(("record_sets", name))
        return iter(PUBLIC_ZONES[name][2])

    def links(rg, name):
        reads.append(("links", name))
        net, vnets = PRIVATE_ZONES[name]
        return iter(NS(id=f"{net}/privateDnsZones/{name}/virtualNetworkLinks/{v.rsplit('/', 1)[1]}", name=v.rsplit("/", 1)[1],
                       virtual_network=NS(id=v), registration_enabled=True, resolution_policy=None,
                       virtual_network_link_state="Completed", provisioning_state="Succeeded") for v in vnets)

    public = [NS(id=f"{net}/dnszones/{name}", name=name, zone_type="Public", tags={}, name_servers=["ns1.example.net."],
                 number_of_record_sets=len(rs) + 2, location="global") for name, (net, _, rs) in PUBLIC_ZONES.items()]
    private = [NS(id=f"{net}/privateDnsZones/{name}", name=name, tags={}, number_of_record_sets=1,
                  number_of_virtual_network_links=len(v), number_of_virtual_network_links_with_registration=len(v),
                  provisioning_state="Succeeded", location="global") for name, (net, v) in PRIVATE_ZONES.items()]
    dns_client = NS(zones=NS(list=lambda: iter(public)), record_sets=NS(list_all_by_dns_zone=record_sets))
    private_client = NS(send_request=send_request, private_zones=NS(list=lambda: iter(private)),
                        virtual_network_links=NS(list=links))
    monkeypatch.setitem(sys.modules, "azure.mgmt.dns", NS(DnsManagementClient=lambda **kw: dns_client))
    monkeypatch.setitem(sys.modules, "azure.mgmt.privatedns", NS(PrivateDnsManagementClient=lambda **kw: private_client))
    monkeypatch.setitem(sys.modules, "azure.core.rest", NS(HttpRequest=lambda method, url: (method, url)))


def run_dns(monkeypatch, tmp_path, patterns, reads=None, scope=None):
    _fake_dns_sdk(monkeypatch, [] if reads is None else reads)
    return _run(dns, monkeypatch, tmp_path, patterns, "azure_dns_configuration", scope)


def test_dns_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    reads: list = []
    code, evidence = run_dns(monkeypatch, tmp_path, None, reads)
    assert code == 0 and evidence["results"]["excluded"] == []
    collector = Collector(logging.getLogger("test"))
    public = dns.collect_public_zones("s1", object(), collector)
    private = dns.collect_private_zones("s1", object(), collector)
    assert evidence["results"]["public_zones"] == public and evidence["results"]["private_zones"] == private
    assert evidence["summary"] == {
        **dns.summarize(public, private), "provider_registration_status": "registered",
        "scope_exclusion_patterns": [], "scope_exclusion_patterns_unmatched": [], "excluded_record_sets": 0,
        "in_scope_record_sets": 5,
        **_added_fields({"public_dns_zone": 3, "private_dns_zone": 2}),
    }
    assert {z for kind, z in reads if kind == "record_sets"} == set(PUBLIC_ZONES)


def test_dns_zones_leave_by_group_or_id_and_keep_cross_references(monkeypatch, tmp_path):
    reads: list = []
    code, evidence = run_dns(monkeypatch, tmp_path, "rg:rg-out, id:*/dnszones/named.example, location:regionwest, rg:typo",
                             reads)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("private_dns_zone", "corp.internal", "rg:rg-out", "resource_matched"),
        ("public_dns_zone", "named.example", "id:*/dnszones/named.example", "resource_matched"),
        ("public_dns_zone", "out.example", "rg:rg-out", "resource_matched"),
    ]
    assert all(e["location"] == "global" for e in results["excluded"])
    assert {e["resource_group"] for e in results["excluded"]} == {"rg-in", "rg-out"}
    # Excluded zones get no DNSSEC, record-set or link reads.
    assert sorted(reads) == [("dnssec", "in.example"), ("links", "privatelink.blob.core.windows.net"),
                             ("record_sets", "in.example")]
    assert [z["name"] for z in results["public_zones"]] == ["in.example"]
    assert [z["name"] for z in results["private_zones"]] == ["privatelink.blob.core.windows.net"]
    # The alias to an excluded Front Door endpoint and the link to an excluded virtual network stay.
    alias = next(r for r in results["public_zones"][0]["record_sets"] if r["type"] == "A")
    assert (alias["alias_target_resource_id"], alias["failover_method"]) == (AFD_OUT, "front_door")
    assert results["private_zones"][0]["virtual_network_links"][0]["virtual_network_id"] == VNET_OUT
    assert (summary["total_public_zones"], summary["dnssec_enabled_public_zones"], summary["dnssec_percentage"]) == (1, 1, 100)
    assert (summary["total_public_record_sets"], summary["public_alias_record_sets"]) == (2, 1)
    assert summary["public_endpoint_record_sets_by_failover_method"]["front_door"] == 2
    assert (summary["total_private_zones"], summary["total_private_zone_virtual_network_links"],
            summary["auto_registration_links"]) == (1, 1, 1)
    assert (summary["excluded_public_dns_zones"], summary["in_scope_public_dns_zones"],
            summary["excluded_private_dns_zones"], summary["in_scope_private_dns_zones"]) == (2, 1, 1, 1)
    assert summary["in_scope_record_sets"] == 2
    assert summary["resource_exclusion_patterns_unmatched"] == ["location:regionwest", "rg:typo"]


def test_dns_zones_are_global(monkeypatch, tmp_path):
    code, evidence = run_dns(monkeypatch, tmp_path, "location:global")
    summary = evidence["summary"]
    assert code == 0 and len(evidence["results"]["excluded"]) == 5
    assert (summary["in_scope_public_dns_zones"], summary["in_scope_private_dns_zones"], summary["total_public_zones"]) == (0, 0, 0)
    assert summary["dnssec_percentage"] == 0 and summary["resource_exclusion_patterns_unmatched"] == []


def test_dns_record_set_scope_exclusions_apply_to_the_zones_left_in_scope(monkeypatch, tmp_path):
    code, evidence = run_dns(monkeypatch, tmp_path, "rg:rg-out", scope="www, legacy")
    summary = evidence["summary"]
    assert code == 0
    assert _excluded(evidence) == [
        ("private_dns_zone", "corp.internal", "rg:rg-out", "resource_matched"),
        ("public_dns_zone", "out.example", "rg:rg-out", "resource_matched"),
        ("record_set", "www", "www", "name_matched"),
    ]
    # legacy exists only in the excluded zone, so the scope pattern matched nothing.
    assert summary["scope_exclusion_patterns_unmatched"] == ["legacy"]
    assert (summary["excluded_record_sets"], summary["in_scope_record_sets"], summary["excluded_public_dns_zones"]) == (1, 2, 1)


# --- front_door_waf_policies ---

WAF_TYPE = "Microsoft.Network/frontdoorWebApplicationFirewallPolicies"
SECURITY_POLICY_OUT = f"{OUT_RG}/providers/Microsoft.Cdn/profiles/fd-out/securityPolicies/sp"


def _waf_policy(rg_id, name, sku="Premium_AzureFrontDoor", mode="Prevention", links=()):
    return {"id": f"{rg_id}/providers/{WAF_TYPE}/{name}", "name": name, "location": "Global", "sku": sku,
            "enabled_state": "Enabled", "mode": mode, "request_body_check": "Enabled", "provisioning_state": "Succeeded",
            "resource_state": "Enabled", "managed_rule_sets": [], "exceptions": [], "custom_rules": [],
            "security_policy_links": list(links)}


WAF_POLICIES = [
    # Attached through a security policy of a profile in the excluded group.
    _waf_policy(IN_RG, "waf-in", links=[SECURITY_POLICY_OUT]),
    _waf_policy(OUT_RG, "waf-out", mode="Detection"),
    _waf_policy(IN_RG, "waf-named", sku="Standard_AzureFrontDoor", mode="Detection"),
    _waf_policy(OUT_RG, "waf-classic", sku="Classic_AzureFrontDoor"),
]


def run_waf(monkeypatch, tmp_path, patterns):
    monkeypatch.setattr(waf, "collect_waf_policies", lambda *a: (copy.deepcopy(WAF_POLICIES), fd.definition_index([])))
    return _run(waf, monkeypatch, tmp_path, patterns, "azure_front_door_waf_policies")


def test_waf_policies_without_patterns_add_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_waf(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    records = sorted((fd.waf_policy_record(p) for p in WAF_POLICIES[:3]), key=lambda r: r["id"].lower())
    assert evidence["results"]["waf_policies"] == records
    assert evidence["summary"] == {
        **waf.summarize(records, {"Classic_AzureFrontDoor": 1}), "provider_registration_status": "registered",
        "resource_exclusion_patterns": [], "resource_exclusion_patterns_unmatched": [],
        "excluded_waf_policies": 0, "in_scope_waf_policies": 3,
    }


def test_waf_policies_leave_by_group_or_id_and_keep_their_association(monkeypatch, tmp_path):
    code, evidence = run_waf(monkeypatch, tmp_path, f"rg:rg-out, id:*/{WAF_TYPE}/waf-named, location:regionwest")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("waf_policy", "waf-named", f"id:*/{WAF_TYPE}/waf-named", "resource_matched"),
        ("waf_policy", "waf-out", "rg:rg-out", "resource_matched"),
    ]
    [kept] = results["waf_policies"]
    assert kept["name"] == "waf-in" and kept["associated"] is True
    assert (summary["total_waf_policies"], summary["premium_waf_policies"], summary["standard_waf_policies"]) == (1, 1, 0)
    assert (summary["associated_waf_policies"], summary["policies_in_detection_mode"]) == (1, 0)
    # Classic policies are counted whatever the patterns: they are not evaluated.
    assert summary["skipped_policies_by_sku"] == {"Classic_AzureFrontDoor": 1}
    assert (summary["excluded_waf_policies"], summary["in_scope_waf_policies"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["location:regionwest"]


def test_waf_policies_are_global(monkeypatch, tmp_path):
    code, evidence = run_waf(monkeypatch, tmp_path, "location:GLOBAL")
    assert code == 0 and evidence["summary"]["in_scope_waf_policies"] == 0
    assert {e["location"] for e in evidence["results"]["excluded"]} == {"Global"}


# --- Front Door profiles: front_door_tls, front_door_waf_coverage, front_door_origins ---

FD_GROUPS = {"fd-in": "rg-in", "fd-out": "rg-out", "fd-named": "rg-in"}
FDIDS = {"fd-in": "00000000-0000-0000-0000-0000000000aa", "fd-out": "00000000-0000-0000-0000-0000000000bb",
         "fd-named": "00000000-0000-0000-0000-0000000000cc"}
# app -> (resource group, region, public network access)
APPS = {
    "app-east": ("rg-in", "regioneast", "Enabled"),
    "app-out": ("rg-out", "regionwest", "Disabled"),
    "app-shared": ("rg-in", "regioneast", "Disabled"),
    "app-shared-west": ("rg-in", "regionwest", "Disabled"),
    "app-lonely": ("rg-in", "regioncentral", "Disabled"),
}
# profile -> the apps its one origin group reaches: fd-in reaches an app in the excluded group, and only the excluded
# fd-out reaches app-shared and its twin.
FRONTS = {"fd-in": ("app-east", "app-out"), "fd-out": ("app-shared", "app-shared-west"), "fd-named": ("app-east",)}
WAF_OUT_ID = f"{OUT_RG}/providers/{WAF_TYPE}/waf-out"


def _profile_id(name):
    return f"{SUB}/resourceGroups/{FD_GROUPS[name]}/providers/Microsoft.Cdn/profiles/{name}"


def _site_id(app):
    return f"{SUB}/resourceGroups/{APPS[app][0]}/providers/Microsoft.Web/sites/{app}"


def _plan_id(app):
    return f"{IN_RG}/providers/Microsoft.Web/serverfarms/plan-{app}"


def _fd_topology(name):
    pid = _profile_id(name)
    domain = {"id": f"{pid}/customDomains/www", "name": "www", "host_name": f"www.{name}.example",
              "domain_validation_state": "Approved", "certificate_type": "ManagedCertificate", "minimum_tls_version": "TLS12",
              "cipher_suite_set_type": "TLS12_2022", "customized_cipher_suites_tls12": [], "customized_cipher_suites_tls13": [],
              "secret_id": None}
    route = {"id": f"{pid}/afdEndpoints/e/routes/r", "name": "r", "enabled_state": "Enabled", "supported_protocols": ["Https"],
             "https_redirect": None, "forwarding_protocol": "HttpsOnly", "patterns_to_match": ["/*"],
             "link_to_default_domain": "Disabled", "custom_domains": [{"id": domain["id"], "is_active": True}],
             "origin_group_id": f"{pid}/originGroups/g", "origin_path": None, "rule_set_ids": []}
    group_id = f"{pid}/originGroups/g"
    group = {"id": group_id, "name": "g", "session_affinity_state": None, "load_balancing": None,
             "health_probe": {"probe_path": "/", "probe_request_type": "HEAD", "probe_protocol": "Https",
                              "probe_interval_in_seconds": 100},
             "authentication": {"type": "SystemAssignedIdentity"}, "provisioning_state": "Succeeded", "deployment_status": None,
             "origins_projected": [{
                 "id": f"{group_id}/origins/{app}", "name": app, "host_name": f"{app}.azurewebsites.net",
                 "origin_host_header": None, "http_port": 80, "https_port": 443, "priority": 1, "weight": 1000,
                 "enabled_state": "Enabled", "enforce_certificate_name_check": True,
                 "certificate_name_check_validation_mode": None, "custom_certificate_subjects": [], "azure_origin_id": None,
                 "private_link": None, "provisioning_state": "Succeeded", "deployment_status": None,
             } for app in FRONTS[name]]}
    # fd-in's WAF policy sits in the excluded group.
    waf_id = WAF_OUT_ID if name == "fd-in" else f"{IN_RG}/providers/{WAF_TYPE}/waf-in"
    return {
        "profile": {"id": pid, "name": name, "sku": "Premium_AzureFrontDoor", "resource_state": "Active",
                    "front_door_id": FDIDS[name]},
        "endpoints": [{"id": f"{pid}/afdEndpoints/e", "name": "e", "host_name": f"e-{name}.z01.azurefd.net",
                       "enabled_state": "Enabled", "deployment_status": None, "routes": [route]}],
        "custom_domains": [domain],
        "rule_sets": {},
        "secrets": [],
        "security_policies": [{"id": f"{pid}/securityPolicies/sp", "name": "sp", "type": "WebApplicationFirewall",
                               "waf_policy_id": waf_id, "is_profile_level": False,
                               "associations": [{"domains": [{"id": domain["id"], "is_active": True}], "routes": [],
                                                 "patterns_to_match": ["/*"]}],
                               "deployment_status": None, "provisioning_state": "Succeeded"}],
        "log_categories": [{"name": "FrontDoorWebApplicationFirewallLog", "category_type": "Logs",
                            "category_groups": ["allLogs"]}],
        "log_settings": [{"id": f"{pid}/diagnosticSettings/d", "name": "d", "workspace_id": f"{IN_RG}/ws",
                          "storage_account_id": None, "event_hub_name": None, "event_hub_authorization_rule_id": None,
                          "marketplace_partner_id": None, "logs": [{"category": None, "category_group": "allLogs", "enabled": True}]}],
        "origin_groups": [group],
    }


def _topologies():
    return [_fd_topology(name) for name in sorted(FD_GROUPS, key=lambda n: _profile_id(n).lower())]


def _blocking_waf_policies():
    rule_set = {"rule_set_type": "Microsoft_DefaultRuleSet", "rule_set_version": "2.1", "rule_set_action": "Block",
                "exclusions": [], "rule_group_overrides": []}
    policies = [{**_waf_policy(rg, name), "managed_rule_sets": [rule_set]} for rg, name in ((IN_RG, "waf-in"), (OUT_RG, "waf-out"))]
    definitions = fd.definition_index([{"rule_set_type": "Microsoft_DefaultRuleSet", "rule_set_version": "2.1", "rule_groups": [
        {"rule_group_name": "SQLI", "rules": [{"rule_id": "1", "default_state": "Enabled", "default_action": "AnomalyScoring"}]}]}])
    return policies, definitions


def _fake_cdn(monkeypatch, module, reads: list):
    """The CDN, Monitor and WAF reads behind collect_profiles over _topologies(); each per-profile read is appended to
    `reads` as (what, profile name)."""
    by_name = {c["profile"]["name"]: c for c in _topologies()}
    by_rg_name = {(FD_GROUPS[n], n): c for n, c in by_name.items()}

    def per_profile(key):
        def read(cdn, collector, profile):
            reads.append((key, profile["name"]))
            return copy.deepcopy(by_name[profile["name"]][key])
        return read

    def listed(key):
        def read(rg, name):
            reads.append((key, name))
            return copy.deepcopy(by_rg_name[(rg, name)][key])
        return read

    def by_uri(key):
        def read(resource_uri):
            name = resource_uri.rsplit("/", 1)[1]
            reads.append((key, name))
            return copy.deepcopy(by_name[name][key])
        return read

    cdn = NS(secrets=NS(list_by_profile=listed("secrets")), security_policies=NS(list_by_profile=listed("security_policies")))
    monitor = NS(diagnostic_settings_category=NS(list=by_uri("log_categories")), diagnostic_settings=NS(list=by_uri("log_settings")))
    monkeypatch.setitem(sys.modules, "azure.mgmt.monitor", NS(MonitorManagementClient=lambda **kw: monitor))
    for attr, fake in {
        "cdn_client": lambda *a, **k: cdn,
        "front_door_profiles": lambda client, collector: ([copy.deepcopy(c["profile"]) for c in _topologies()],
                                                          {"Standard_Microsoft": 1}),
        "endpoints_with_routes": per_profile("endpoints"),
        "custom_domains": per_profile("custom_domains"),
        "rule_sets_with_rules": per_profile("rule_sets"),
        "project_secret": lambda s: s,
        "project_security_policy": lambda s: s,
        "project_log_category": lambda c: c,
        "project_log_setting": lambda s: s,
        "collect_waf_policies": lambda *a: _blocking_waf_policies(),
    }.items():
        if hasattr(module, attr):
            monkeypatch.setattr(module, attr, fake)


def run_tls(monkeypatch, tmp_path, patterns, reads=None, scope=None):
    _fake_cdn(monkeypatch, tls, [] if reads is None else reads)
    return _run(tls, monkeypatch, tmp_path, patterns, "azure_front_door_tls", scope)


def run_coverage(monkeypatch, tmp_path, patterns, reads=None, scope=None):
    _fake_cdn(monkeypatch, coverage, [] if reads is None else reads)
    return _run(coverage, monkeypatch, tmp_path, patterns, "azure_front_door_waf_coverage", scope)


PROFILE_PATTERNS = "rg:rg-out, id:*/profiles/fd-named, location:regionwest, rg:typo"
PROFILES_OUT = [
    ("profile", "fd-named", "id:*/profiles/fd-named", "resource_matched"),
    ("profile", "fd-out", "rg:rg-out", "resource_matched"),
]


def test_tls_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_tls(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    parts = [tls.tls_for_profile(c, tls.datetime.now(tls.timezone.utc)) for c in _topologies()]
    routes, domains = [r for p in parts for r in p["routes"]], [d for p in parts for d in p["custom_domains"]]
    assert evidence["results"]["routes"] == routes and evidence["results"]["custom_domains"] == domains
    assert evidence["summary"] == {
        **tls.summarize([c["profile"] for c in _topologies()], {"Standard_Microsoft": 1}, routes, domains, []),
        "provider_registration_status": "registered",
        **tls.ScopeExclusions().summary([], tls.EXCLUDED_KINDS, {**fd.in_scope_totals([p["in_scope"] for p in parts]),
                                                                 "secrets": 0}),
        **_added_fields({"profile": 3}),
    }


def test_tls_profiles_leave_by_group_or_id_with_their_routes_and_domains(monkeypatch, tmp_path):
    reads: list = []
    code, evidence = run_tls(monkeypatch, tmp_path, PROFILE_PATTERNS, reads)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == PROFILES_OUT
    assert all(e["location"] == "global" for e in results["excluded"])
    assert {name for _, name in reads} == {"fd-in"}
    assert [p["name"] for p in results["profiles"]] == ["fd-in"]
    assert [d["host_name"] for d in results["custom_domains"]] == ["www.fd-in.example"]
    assert (summary["total_front_door_profiles"], summary["total_routes"], summary["total_custom_domains"]) == (1, 1, 1)
    assert (summary["serving_routes_https_only"], summary["served_domains_below_tls12"]) == (1, 0)
    assert summary["skipped_profiles_by_sku"] == {"Standard_Microsoft": 1}
    assert (summary["excluded_profiles"], summary["in_scope_profiles"]) == (2, 1)
    assert (summary["in_scope_hosts"], summary["in_scope_routes"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["location:regionwest", "rg:typo"]


def test_coverage_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = run_coverage(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    policies, definitions = _blocking_waf_policies()
    waf_by_key = {fd.arm_key(p["id"]): fd.waf_policy_record(p, definitions) for p in policies}
    profiles, host_routes, security_policies, scopes = [], [], [], []
    for c in _topologies():
        cov = coverage.coverage_for_profile(c, waf_by_key)
        scopes.append(cov["in_scope"])
        host_routes += cov["host_routes"]
        security_policies += [{**sp, "profile": c["profile"]["name"]} for sp in c["security_policies"]]
        profiles.append({**c["profile"], **coverage.profile_log_export(c["log_categories"], c["log_settings"]),
                         "waf_in_use": any(h["serving"] and h["effective_scope"] != "none" for h in cov["host_routes"]),
                         "endpoint_count": cov["endpoint_count"], "route_count": cov["route_count"],
                         "custom_domain_count": cov["custom_domain_count"], "security_policy_count": 1})
    assert evidence["results"]["profiles"] == profiles and evidence["results"]["host_routes"] == host_routes
    assert evidence["summary"] == {
        **coverage.summarize(profiles, {"Standard_Microsoft": 1}, host_routes, [], [], security_policies),
        "provider_registration_status": "registered",
        **coverage.ScopeExclusions().summary([], coverage.EXCLUDED_KINDS, {**fd.in_scope_totals(scopes), "host_routes": 3}),
        **_added_fields({"profile": 3}),
    }


def test_coverage_profiles_leave_and_an_excluded_waf_policy_still_protects(monkeypatch, tmp_path):
    reads: list = []
    code, evidence = run_coverage(monkeypatch, tmp_path, PROFILE_PATTERNS, reads)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == PROFILES_OUT
    assert {name for _, name in reads} == {"fd-in"}
    [host_route] = results["host_routes"]
    # fd-in's WAF policy sits in the excluded group; it still applies and blocks.
    assert (host_route["host_name"], host_route["waf_policy_id"], host_route["protected"]) == (
        "www.fd-in.example", WAF_OUT_ID, True)
    assert [sp["profile"] for sp in results["security_policies"]] == ["fd-in"]
    assert (summary["total_front_door_profiles"], summary["total_security_policies"], summary["total_host_routes"]) == (1, 1, 1)
    assert (summary["protected_host_route_percentage"], summary["host_routes_waf_unresolved"]) == (100, 0)
    assert (summary["profiles_with_waf_in_use"], summary["profiles_waf_log_exported"]) == (1, 1)
    assert (summary["excluded_profiles"], summary["in_scope_profiles"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["location:regionwest", "rg:typo"]


@pytest.mark.parametrize("run", [run_tls, run_coverage])
def test_profiles_are_global(monkeypatch, tmp_path, run):
    code, evidence = run(monkeypatch, tmp_path, "location:global")
    assert code == 0 and evidence["summary"]["in_scope_profiles"] == 0
    assert evidence["summary"]["total_front_door_profiles"] == 0 and len(evidence["results"]["excluded"]) == 3


# --- front_door_origins ---

SITES = {fd.arm_key(_site_id(app)): {
    "id": _site_id(app), "name": app, "type": "Microsoft.Web/sites", "kind": "app", "location": region,
    "subscriptionId": "s1", "tags": {}, "state": "Running", "server_farm_id": _plan_id(app), "public_network_access": public,
} for app, (_, region, public) in APPS.items()}
SITES_BY_HOST = {f"{app}.azurewebsites.net": fd.arm_key(_site_id(app)) for app in APPS}
REGIONS = {f"{app}.azurewebsites.net": region for app, (_, region, _) in APPS.items()}
PLANS = {fd.arm_key(_plan_id(app)): {"id": _plan_id(app), "name": f"plan-{app}", "location": "regioneast",
                                     "sku": {"name": "P1v3", "tier": "PremiumV3", "capacity": 2}, "zone_redundant": False}
         for app in APPS}
# app-east admits the Front Door ids of fd-in and fd-named, both of which serve it.
APP_EAST_CONFIG = {
    "public_network_access": None,
    "ip_security_restrictions": [{"name": "front-door", "priority": 100, "action": "Allow", "tag": "ServiceTag",
                                  "ip_address": "AzureFrontDoor.Backend", "vnet_subnet_resource_id": None,
                                  "headers": {"x-azure-fdid": [FDIDS["fd-in"], FDIDS["fd-named"]]}}],
    "ip_security_restrictions_default_action": None, "scm_ip_security_restrictions": [],
    "scm_ip_security_restrictions_default_action": None, "scm_ip_security_restrictions_use_main": True,
}


def run_origins(monkeypatch, tmp_path, patterns, reads=None, scope=None):
    reads = [] if reads is None else reads
    for attr, fake in {
        "collect_profiles": lambda subscription_id, cred, collector: (_topologies(), {}),
        "graph_client": lambda *a: object(),
        "lookup_regions": lambda *a: ({}, REGIONS),
        "lookup_sites": lambda *a: (copy.deepcopy(SITES), SITES_BY_HOST),
        "lookup_plans": lambda *a: PLANS,
        "read_site_configs": lambda cred, collector, sites: reads.extend(("config", s["name"]) for s in sites) or {
            fd.arm_key(_site_id("app-east")): APP_EAST_CONFIG},
        "collect_origin_metrics": lambda sub, cred, collector, profiles, window: reads.extend(
            ("metrics", p["name"]) for p in profiles) or {},
    }.items():
        monkeypatch.setattr(origins, attr, fake)
    for env in (origins.PRODUCTION_TAG_ENV, origins.LOOKBACK_ENV):
        monkeypatch.delenv(env, raising=False)
    return _run(origins, monkeypatch, tmp_path, patterns, "azure_front_door_origins", scope)


def _app_east_record(evidence, profile="fd-in"):
    return next(r for r in evidence["results"]["app_service_origins"] if r["profile"] == profile and r["origin"] == "app-east")


def test_origins_without_patterns_add_only_empty_exclusion_fields(monkeypatch, tmp_path):
    reads: list = []
    code, evidence = run_origins(monkeypatch, tmp_path, None, reads)
    summary = evidence["summary"]
    assert code == 0 and evidence["results"]["excluded"] == []
    added = _added_fields({"profile": 3, "production_app": None})
    old_keys = {*origins.summarize([], {}, []), *origins.summarize_app_services([], [], None),
                *origins.summarize_health([], [], 7, ("", "")), "provider_registration_status",
                *origins.ScopeExclusions().summary([], origins.EXCLUDED_KINDS, {
                    **fd.in_scope_totals([]), "origin_groups": 0, "apps": 0})}
    assert set(summary) == old_keys | set(added) and {k: summary[k] for k in added} == added
    assert sorted(n for kind, n in reads if kind == "metrics") == ["fd-in", "fd-named", "fd-out"]
    assert sorted(n for kind, n in reads if kind == "config") == ["app-east", "app-out", "app-shared", "app-shared-west"]
    assert (summary["total_front_door_profiles"], summary["total_origin_groups"], summary["total_origins"]) == (3, 3, 5)
    assert (summary["production_web_apps"], summary["production_web_apps_behind_front_door"],
            summary["production_web_apps_regional_twin_ready"]) == (5, 4, 4)
    assert (summary["serving_app_service_origins"], summary["serving_app_service_origins_locked_to_front_door"]) == (5, 5)
    east = _app_east_record(evidence)
    assert (east["locked_to_front_door"], east["fronting_front_door_ids"]) == (True, [FDIDS["fd-named"]])


def test_origins_profiles_and_apps_leave_by_group_id_or_region_and_keep_cross_references(monkeypatch, tmp_path):
    reads: list = []
    code, evidence = run_origins(monkeypatch, tmp_path, "rg:rg-out, id:*/profiles/fd-named, location:regioncentral, rg:typo",
                                 reads)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("production_app", "app-lonely", "location:regioncentral", "resource_matched"),
        ("production_app", "app-out", "rg:rg-out", "resource_matched"),
        *PROFILES_OUT,
    ]
    # Excluded profiles get no metric reads, and apps only they reach no access-restriction reads.
    assert [n for kind, n in reads if kind == "metrics"] == ["fd-in"]
    assert sorted(n for kind, n in reads if kind == "config") == ["app-east", "app-out"]
    assert [p["name"] for p in results["profiles"]] == ["fd-in"]
    assert [h["origin_group_id"] for h in results["origin_health"]] == [f"{_profile_id('fd-in')}/originGroups/g"]
    # fd-in's origin to the excluded app-out stays and keeps the group's second region.
    [group] = results["origin_groups"]
    assert ([o["name"] for o in group["origins"]], group["enabled_regions"]) == (["app-east", "app-out"], ["regioneast", "regionwest"])
    assert (summary["total_origins"], summary["serving_groups_multi_region_active_active"]) == (2, 1)
    assert sorted(r["origin"] for r in results["app_service_origins"]) == ["app-east", "app-out"]
    apps = {a["name"]: a for a in results["production_apps"]}
    assert sorted(apps) == ["app-east", "app-shared", "app-shared-west"]
    # app-east keeps its twin in the excluded group; the apps only the excluded fd-out reaches stay behind Front Door.
    assert [t["origin"] for t in apps["app-east"]["regional_twins"]] == ["app-out"]
    assert all(a["regional_twin_ready"] for a in apps.values())
    assert {g["profile"] for g in apps["app-shared"]["origin_groups"]} == {"fd-out"}
    assert (summary["production_web_apps"], summary["production_web_apps_behind_front_door"],
            summary["production_web_apps_regional_twin_ready"]) == (3, 3, 3)
    # An excluded profile doesn't vouch for an app that admits its Front Door id, as an out-of-scope route doesn't.
    east = _app_east_record(evidence)
    assert (east["locked_to_front_door"], east["lockdown_gaps"], east["other_front_door_ids_allowed"]) == (
        False, ["other_front_door_id_allowed"], [FDIDS["fd-named"]])
    assert (summary["excluded_profiles"], summary["in_scope_profiles"], summary["excluded_production_apps"]) == (2, 1, 2)
    assert "in_scope_production_apps" not in summary and summary["in_scope_apps"] == 3
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_origins_profiles_are_global(monkeypatch, tmp_path):
    code, evidence = run_origins(monkeypatch, tmp_path, "location:global")
    summary = evidence["summary"]
    assert code == 0 and (summary["in_scope_profiles"], summary["total_origin_groups"]) == (0, 0)
    # Every app stays behind Front Door: the excluded profiles still reach them.
    assert (summary["production_web_apps"], summary["production_web_apps_behind_front_door"]) == (5, 4)


# --- both kinds of exclusion, and bad patterns ---

@pytest.mark.parametrize("run", [run_tls, run_coverage, run_origins])
def test_scope_exclusions_apply_to_the_profiles_left_in_scope(monkeypatch, tmp_path, run):
    code, evidence = run(monkeypatch, tmp_path, "rg:rg-out", scope="www.fd-out.example, www.fd-in.example")
    summary = evidence["summary"]
    assert code == 0
    assert _excluded(evidence, {"profile", "custom_domain"}) == [
        ("custom_domain", "www.fd-in.example", "www.fd-in.example", "name_matched"),
        ("profile", "fd-out", "rg:rg-out", "resource_matched")]
    assert summary["scope_exclusion_patterns_unmatched"] == ["www.fd-out.example"]
    assert (summary["excluded_custom_domains"], summary["in_scope_custom_domains"], summary["excluded_profiles"]) == (1, 1, 1)


@pytest.mark.parametrize("run", [run_dns, run_waf, run_tls, run_coverage, run_origins])
def test_a_bare_pattern_fails_the_run(monkeypatch, tmp_path, run):
    code, evidence = run(monkeypatch, tmp_path, "rg-out")
    assert code == 1
    assert evidence["results"]["excluded"] == [] and evidence["summary"]["resource_exclusion_patterns_unmatched"] == ["rg-out"]
    assert "rg:, location: or id:" in json.dumps(evidence["metadata"]["api_failures"])
