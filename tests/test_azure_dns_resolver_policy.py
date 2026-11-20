"""azure_dns_resolver_policy over ARM REST responses shaped like the documented Microsoft.Network dnsResolverPolicies,
dnsSecurityRules, virtualNetworkLinks and dnsResolverDomainLists resources: no SDK, no credentials, no network.

The subscription holds two policies. policy-core blocks Azure's threat-intelligence list, allows an internal domain
list, is linked to the hub and app networks and sends its query logs to a workspace. policy-dev only alerts, is linked
to the dev network and sends no logs. A fourth network has no policy at all.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))
spec = importlib.util.spec_from_file_location("azure_dns_resolver_policy_under_test", AZURE / "dns_resolver_policy" / "fetcher.py")
fx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fx)

SUB = "/subscriptions/s1"
NET = f"{SUB}/resourceGroups/rg-net/providers/Microsoft.Network"
CORE, DEV = f"{NET}/dnsResolverPolicies/policy-core", f"{NET}/dnsResolverPolicies/policy-dev"
VNETS = {n: f"{SUB}/resourceGroups/rg-{n}/providers/Microsoft.Network/virtualNetworks/vnet-{n}" for n in ("hub", "app", "dev", "isolated")}
LIST_BLOCK, LIST_ALLOW = f"{NET}/dnsResolverDomainLists/blocked-domains", f"{NET}/dnsResolverDomainLists/internal-domains"


def rule(name, priority, action, lists=(), managed=None, state="Enabled"):
    props = {"priority": priority, "action": {"actionType": action}, "dnsSecurityRuleState": state,
             "dnsResolverDomainLists": [{"id": i} for i in lists], "provisioningState": "Succeeded"}
    if managed is not None:
        props["managedDomainLists"] = managed
    return {"id": f"{CORE}/dnsSecurityRules/{name}", "name": name, "type": "Microsoft.Network/dnsResolverPolicies/dnsSecurityRules",
            "properties": props}


def link(policy, vnet):
    return {"id": f"{policy}/virtualNetworkLinks/{vnet.rsplit('/', 1)[1]}", "properties": {"virtualNetwork": {"id": vnet}}}


def policy(pid, location="eastus2"):
    return {"id": pid, "name": pid.rsplit("/", 1)[1], "location": location, "properties": {"provisioningState": "Succeeded"}}


PREVIEW = {
    f"{SUB}/providers/Microsoft.Network/dnsResolverPolicies": [policy(CORE), policy(DEV)],
    f"{CORE}/dnsSecurityRules": [rule("block-threat-intel", 100, "Block", [LIST_BLOCK], ["AzureDnsThreatIntel"]),
                                 rule("allow-internal", 200, "Allow", [LIST_ALLOW], [])],
    f"{DEV}/dnsSecurityRules": [rule("alert-only", 100, "Alert", [LIST_BLOCK], [])],
    f"{CORE}/virtualNetworkLinks": [link(CORE, VNETS["hub"]), link(CORE, VNETS["app"])],
    f"{DEV}/virtualNetworkLinks": [link(DEV, VNETS["dev"])],
    f"{SUB}/providers/Microsoft.Network/dnsResolverDomainLists": [
        {"id": LIST_BLOCK, "name": "blocked-domains", "location": "eastus2",
         "properties": {"domains": ["bad.example.", "worse.example.", "malware.example."]}},
        {"id": LIST_ALLOW, "name": "internal-domains", "location": "eastus2", "properties": {"domains": None}}],
    f"{SUB}/providers/Microsoft.Network/virtualNetworks": [{"id": v, "name": v.rsplit("/", 1)[1], "location": "eastus2"}
                                                           for v in VNETS.values()],
}
DIAGNOSTICS = {
    CORE: [{"id": f"{CORE}/providers/microsoft.insights/diagnosticSettings/to-workspace", "properties": {
        "workspaceId": f"{SUB}/resourceGroups/rg-logs/providers/Microsoft.OperationalInsights/workspaces/law",
        "logs": [{"category": "DnsResponse", "enabled": True}]}}],
    DEV: [],
}


class HttpError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status_code, self.message = status, message


class Arm:
    def __init__(self, preview_served=True, refused=()):
        self.preview_served, self.refused, self.calls = preview_served, set(refused), []

    def list_all(self, client, path, api_version):
        self.calls.append((path, api_version))
        if api_version == fx.PREVIEW_API and not self.preview_served:
            raise HttpError(400, "(InvalidApiVersionParameter) The api-version '2025-10-01-preview' is invalid.")
        if path in self.refused:
            raise HttpError(403, "(AuthorizationFailed) does not have authorization")
        items = json.loads(json.dumps(PREVIEW[path]))
        if api_version != fx.PREVIEW_API:
            for i in items:
                (i.get("properties") or {}).pop("managedDomainLists", None)
        return {"items": items, "pages": 1}

    def get_json(self, client, url):
        pid = url.split("/providers/Microsoft.Insights")[0]
        if pid in self.refused:
            raise HttpError(403, "(AuthorizationFailed) does not have authorization")
        return {"value": DIAGNOSTICS[pid]}


@pytest.fixture
def run(monkeypatch, tmp_path):
    def go(**kwargs):
        arm = Arm(**kwargs)
        for name, value in (("load_dotenv", lambda *a, **k: None),
                            ("resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "target"}),
                            ("credential", lambda: object()), ("provider_registration_status", lambda *a: "registered"),
                            ("arm_rest_client", lambda cred: object()), ("list_all", arm.list_all), ("get_json", arm.get_json)):
            monkeypatch.setattr(fx, name, value)
        monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
        monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
        code = fx.main()
        return code, json.loads((tmp_path / "azure_dns_resolver_policy_s1.json").read_text()), arm
    monkeypatch.delenv("AZURE_RESOURCE_EXCLUSIONS", raising=False)
    return go


def test_policies_rules_links_and_logs_give_coverage(run, assert_summary_documented):
    code, ev, _ = run()
    s = ev["summary"]
    assert code == 0 and (s["api_version"], s["threat_intel_visible"]) == (fx.PREVIEW_API, True)
    assert (s["security_rules"], s["security_rules_enabled"]) == (3, 3)
    assert s["enabled_rules_by_action"] == {"Allow": 1, "Alert": 1, "Block": 1}
    assert (s["policies_blocking"], s["policies_blocking_threat_intel"], s["domain_lists"]) == (1, 1, 2)
    # dev is linked only to an alerting policy; isolated to none.
    assert (s["virtual_networks_linked_to_policy"], s["virtual_networks_without_blocking_policy"],
            s["virtual_networks_without_threat_intel_block"]) == (3, 2, 2)
    assert (s["policies_with_query_logs_exported"], s["policies_without_query_logs_exported"]) == (1, 1)
    assert (s["in_scope_dns_resolver_policies"], s["in_scope_virtual_networks"]) == (2, 4)
    assert_summary_documented("azure/dns_resolver_policy", s)


def test_records_count_domains_without_copying_them(run):
    _, ev, _ = run()
    text = json.dumps(ev)
    assert "bad.example." not in text
    lists = {d["name"]: d["domain_count"] for d in ev["results"]["domain_lists"]}
    assert lists == {"blocked-domains": 3, "internal-domains": None}
    vnets = {v["name"]: v for v in ev["results"]["virtual_networks"]}
    assert vnets["vnet-hub"]["covered_by_threat_intel_block"] is True and vnets["vnet-dev"]["covered_by_blocking_policy"] is False


def test_without_the_preview_api_threat_intel_is_unknown_not_absent(run, assert_summary_documented):
    code, ev, arm = run(preview_served=False)
    s = ev["summary"]
    assert code == 0 and (s["api_version"], s["threat_intel_visible"]) == (fx.GA_API, False)
    assert (s["policies_blocking_threat_intel"], s["virtual_networks_without_threat_intel_block"]) == (None, None)
    # Blocking itself is still judged from the GA rules.
    assert (s["policies_blocking"], s["virtual_networks_without_blocking_policy"]) == (1, 2)
    assert any(v == fx.GA_API for _, v in arm.calls)
    assert_summary_documented("azure/dns_resolver_policy", s)


def test_an_unread_policy_link_leaves_coverage_unjudged(run):
    code, ev, _ = run(refused={f"{DEV}/virtualNetworkLinks"})
    s = ev["summary"]
    assert code == 1
    assert (s["virtual_networks_linked_to_policy"], s["virtual_networks_without_blocking_policy"]) == (None, None)
    vnets = {v["name"]: v for v in ev["results"]["virtual_networks"]}
    # A network the readable policy covers still shows as covered.
    assert vnets["vnet-hub"]["covered_by_blocking_policy"] is True and vnets["vnet-isolated"]["covered_by_blocking_policy"] is None


def test_unread_diagnostic_settings_leave_log_counts_null(run):
    code, ev, _ = run(refused={DEV})
    assert code == 1
    assert (ev["summary"]["policies_with_query_logs_exported"], ev["summary"]["policies_without_query_logs_exported"]) == (None, None)


def test_a_refused_policy_list_nulls_everything_it_feeds(run, assert_summary_documented):
    code, ev, _ = run(refused={f"{SUB}/providers/Microsoft.Network/dnsResolverPolicies"})
    s = ev["summary"]
    assert code == 1 and (s["api_version"], s["threat_intel_visible"]) == (None, None)
    for k in ("security_rules", "policies_blocking", "virtual_networks_without_blocking_policy",
              "policies_with_query_logs_exported", "in_scope_dns_resolver_policies"):
        assert s[k] is None, k
    assert s["in_scope_virtual_networks"] == 4
    assert_summary_documented("azure/dns_resolver_policy", s)


def test_an_excluded_network_leaves_the_counts(run, monkeypatch):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "rg:rg-isolated")
    code, ev, _ = run()
    s = ev["summary"]
    assert code == 0 and (s["excluded_virtual_networks"], s["in_scope_virtual_networks"]) == (1, 3)
    assert s["virtual_networks_without_blocking_policy"] == 1
    assert [e["name"] for e in ev["results"]["excluded"]] == ["vnet-isolated"]
