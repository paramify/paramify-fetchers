"""resource_exclusions in the Azure gateway fetchers: excluded resources leave every count and stay listed under excluded."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
NET_IN = f"{SUB}/resourceGroups/rg-in/providers/Microsoft.Network"
NET_OUT = f"{SUB}/resourceGroups/rg-out/providers/Microsoft.Network"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_gateway_exclusions_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backend = _load("app_gateway_backend_tls")
listeners = _load("app_gateway_tls_listeners")
waf = _load("app_gateway_waf")
ddos = _load("ddos_protection")
flow = _load("network_flow_logs")
vwan = _load("virtual_wan_configuration")
vpn = _load("vpn_gateway_configuration")
ag = sys.modules["app_gateway"]


def _added(kinds: dict, excluded_keys=None) -> dict:
    """The fields a run without patterns adds to the summary: plural -> in-scope total."""
    return {
        "resource_exclusion_patterns": [],
        "resource_exclusion_patterns_unmatched": [],
        **{f"excluded_{k}": 0 for k in (excluded_keys or kinds)},
        **{f"in_scope_{k}": v for k, v in kinds.items()},
    }


def _excluded(evidence) -> list:
    return sorted((e["kind"], e["name"], e["pattern"], e["reason"]) for e in evidence["results"]["excluded"])


def _environment(m, monkeypatch, tmp_path, patterns):
    monkeypatch.setattr(m, "load_dotenv", lambda *a: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)


def _read(tmp_path, filename):
    return json.loads((tmp_path / f"{filename}_s1.json").read_text())


def _fake_azure(monkeypatch, client):
    for name in ("azure.mgmt.network", "azure.mgmt.resource.resources", "azure.mgmt.resource"):
        module = types.ModuleType(name)
        module.NetworkManagementClient = lambda **k: client
        module.ResourceManagementClient = lambda **k: client
        monkeypatch.setitem(sys.modules, name, module)


# --- application gateway fetchers ---

def _gateway(name, rg_net, location, listener_protocol="Http", policy_id=None, listener_names=("l1",)):
    gid = f"{rg_net}/applicationGateways/{name}"

    def child(kind, n):
        return NS(id=f"{gid}/{kind}/{n}")

    http_listeners = [
        NS(id=f"{gid}/httpListeners/{n}", name=n, protocol=listener_protocol,
           frontend_port=child("frontendPorts", "p"), frontend_ip_configuration=child("frontendIPConfigurations", "pub"),
           firewall_policy=NS(id=policy_id) if policy_id else None)
        for n in listener_names
    ]
    return NS(
        id=gid, name=name, location=location, sku=NS(name="WAF_v2", tier="WAF_v2"), operational_state="Running",
        frontend_ip_configurations=[NS(id=f"{gid}/frontendIPConfigurations/pub", public_ip_address=NS(id="/pip"))],
        frontend_ports=[NS(id=f"{gid}/frontendPorts/p", port=80)],
        http_listeners=http_listeners,
        backend_http_settings_collection=[NS(id=f"{gid}/backendHttpSettingsCollection/bs", name="bs", protocol=listener_protocol,
                                            port=80)],
        request_routing_rules=[NS(name="r", http_listener=child("httpListeners", listener_names[0]),
                                  backend_http_settings=child("backendHttpSettingsCollection", "bs"))],
    )


def _gateways():
    return [
        _gateway("agw-in", NET_IN, "regionwest"),
        _gateway("agw-out", NET_OUT, "regionwest"),
        _gateway("agw-east", NET_IN, "regioneast", "Https"),
    ]


def _run_gateway_fetcher(m, monkeypatch, tmp_path, patterns, name, gateways=None):
    _environment(ag, monkeypatch, tmp_path, patterns)
    gateways = _gateways() if gateways is None else gateways
    monkeypatch.setattr(ag, "list_gateways", lambda *a: gateways)
    monkeypatch.setattr(ag, "resource_graph_gateway_count", lambda *a: len(gateways))
    code = m.run_fetcher(name, m.logger, m.build)
    return code, _read(tmp_path, name)


def test_backend_tls_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = _run_gateway_fetcher(backend, monkeypatch, tmp_path, None, "azure_app_gateway_backend_tls")
    results = evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert evidence["summary"] == {
        **backend.summarize(results["application_gateways"], results["backend_settings"]),
        "completeness_match": True, "provider_registration_status": "registered",
        **_added({"application_gateways": 3, "backend_settings": 3}, ("application_gateways",)),
    }


def test_backend_tls_excludes_gateways_by_group_and_region_and_their_settings_follow(monkeypatch, tmp_path):
    code, evidence = _run_gateway_fetcher(
        backend, monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo", "azure_app_gateway_backend_tls")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("application_gateway", "agw-east", "location:regioneast", "resource_matched"),
        ("application_gateway", "agw-out", "rg:rg-out", "resource_matched"),
    ]
    assert [g["name"] for g in results["application_gateways"]] == ["agw-in"]
    assert [s["gateway_name"] for s in results["backend_settings"]] == ["agw-in"]
    # Only agw-in's plaintext setting counts; the excluded gateways' settings (one encrypted) do not.
    assert (summary["total_application_gateways"], summary["total_backend_settings"], summary["plaintext_in_use"],
            summary["encrypted_in_use"]) == (1, 1, 1, 0)
    assert (summary["excluded_application_gateways"], summary["in_scope_application_gateways"],
            summary["in_scope_backend_settings"]) == (2, 1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    # The completeness check compares the full listing, not the in-scope one.
    assert results["completeness"]["listed"] == 3 and summary["completeness_match"] is True


def test_backend_tls_excludes_a_gateway_by_id(monkeypatch, tmp_path):
    pattern = f"id:{NET_IN}/applicationGateways/agw-in"
    _, evidence = _run_gateway_fetcher(backend, monkeypatch, tmp_path, pattern, "azure_app_gateway_backend_tls")
    assert _excluded(evidence) == [("application_gateway", "agw-in", pattern, "resource_matched")]
    assert evidence["summary"]["total_application_gateways"] == 2


def test_tls_listeners_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = _run_gateway_fetcher(listeners, monkeypatch, tmp_path, None, "azure_app_gateway_tls_listeners")
    results = evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert evidence["summary"] == {
        **listeners.summarize(results["application_gateways"], results["listeners"]),
        "completeness_match": True, "provider_registration_status": "registered",
        **_added({"application_gateways": 3, "listeners": 3}, ("application_gateways",)),
    }


def test_tls_listeners_exclude_gateways_and_listeners_follow(monkeypatch, tmp_path):
    code, evidence = _run_gateway_fetcher(
        listeners, monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo", "azure_app_gateway_tls_listeners")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("application_gateway", "agw-east", "location:regioneast", "resource_matched"),
        ("application_gateway", "agw-out", "rg:rg-out", "resource_matched"),
    ]
    assert [li["gateway_name"] for li in results["listeners"]] == ["agw-in"]
    # The excluded gateway agw-east held the only encrypted listener.
    assert (summary["total_listeners"], summary["plaintext_listeners"], summary["encrypted_listeners"]) == (1, 1, 0)
    assert (summary["total_application_gateways"], summary["excluded_application_gateways"],
            summary["in_scope_listeners"]) == (1, 2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def _policy(name, rg_net, state, mode, location="regionwest"):
    return NS(id=f"{rg_net}/ApplicationGatewayWebApplicationFirewallPolicies/{name}", name=name, location=location,
              policy_settings=NS(state=state, mode=mode), managed_rules=None, custom_rules=[])


def _waf_scenario(monkeypatch):
    pol_out = f"{NET_OUT}/ApplicationGatewayWebApplicationFirewallPolicies/pol-out"
    gone = f"{NET_IN}/ApplicationGatewayWebApplicationFirewallPolicies/pol-gone"
    gateways = [
        # An in-scope listener whose policy sits in the excluded group, and one with no policy.
        _gateway("agw-in", NET_IN, "regionwest", policy_id=pol_out, listener_names=("l1", "l3")),
        _gateway("agw-out", NET_OUT, "regionwest", policy_id=gone),
    ]
    gateways[0].http_listeners[1].firewall_policy = None
    fetched = []
    monkeypatch.setattr(waf, "collect_policies", lambda *a: [_policy("pol-out", NET_OUT, "Enabled", "Prevention"),
                                                             _policy("pol-in", NET_IN, "Enabled", "Detection")])
    monkeypatch.setattr(waf, "fetch_policy", lambda pid, cred, collector: (fetched.append(pid), (None, waf.unresolved_policy(pid)))[1])
    return gateways, fetched


def test_waf_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    gateways, _ = _waf_scenario(monkeypatch)
    code, evidence = _run_gateway_fetcher(waf, monkeypatch, tmp_path, None, "azure_app_gateway_waf", gateways)
    results = evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert evidence["summary"] == {
        **waf.summarize(results["application_gateways"], results["listeners"], results["waf_policies"]),
        "completeness_match": True, "provider_registration_status": "registered",
        **_added({"application_gateways": 2, "listeners": 3, "waf_policies": 3}, ("application_gateways",)),
        "excluded_waf_policies": 0,
    }


def test_waf_excluded_policy_leaves_the_list_but_an_in_scope_listener_keeps_its_verdict(monkeypatch, tmp_path):
    gateways, fetched = _waf_scenario(monkeypatch)
    code, evidence = _run_gateway_fetcher(waf, monkeypatch, tmp_path, "rg:rg-out, location:nowhere", "azure_app_gateway_waf", gateways)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("application_gateway", "agw-out", "rg:rg-out", "resource_matched"),
        ("waf_policy", "pol-out", "rg:rg-out", "resource_matched"),
    ]
    assert [p["name"] for p in results["waf_policies"]] == ["pol-in"]
    listener = {li["name"]: li for li in results["listeners"]}
    assert set(listener) == {"l1", "l3"}
    # l1 is still enforced by the excluded policy; l3 has none.
    assert (listener["l1"]["waf_enforcing"], listener["l1"]["waf_policy"]) == (True, "pol-out")
    assert listener["l3"]["waf_enforcing"] is False
    assert (summary["total_http_listeners"], summary["listeners_waf_enforcing"], summary["listeners_without_waf"]) == (2, 1, 1)
    assert (summary["total_waf_policies"], summary["policies_prevention"], summary["policies_detection"]) == (1, 0, 1)
    assert (summary["excluded_waf_policies"], summary["excluded_application_gateways"],
            summary["in_scope_waf_policies"]) == (1, 1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["location:nowhere"]
    # The excluded gateway's referenced policy is never read.
    assert fetched == []


# --- ddos_protection ---

def _ddos_raw():
    def cfg(rg_net, vnet, nic):
        return f"{rg_net}/networkInterfaces/{nic}/ipConfigurations/ipc"

    plans = [
        {"id": f"{NET_IN}/ddosProtectionPlans/plan-in", "name": "plan-in", "location": "regionwest",
         "virtual_network_ids": [], "public_ip_address_ids": []},
        {"id": f"{NET_IN}/ddosProtectionPlans/plan-east", "name": "plan-east", "location": "regioneast",
         "virtual_network_ids": [], "public_ip_address_ids": []},
    ]
    vnets = [
        {"id": f"{NET_IN}/virtualNetworks/vnet-in", "name": "vnet-in", "location": "regionwest",
         "enable_ddos_protection": False, "ddos_protection_plan_id": None,
         "subnet_ip_configuration_ids": [cfg(NET_IN, "vnet-in", "nic-b"), cfg(NET_IN, "vnet-in", "nic-c")]},
        {"id": f"{NET_OUT}/virtualNetworks/vnet-out", "name": "vnet-out", "location": "regionwest",
         "enable_ddos_protection": True, "ddos_protection_plan_id": plans[0]["id"],
         "subnet_ip_configuration_ids": [cfg(NET_OUT, "vnet-out", "nic-a")]},
    ]

    def ip(name, rg_net, nic):
        return {"id": f"{rg_net}/publicIPAddresses/{name}", "name": name, "location": "regionwest",
                "ip_configuration_id": cfg(rg_net, "", nic), "protection_mode": "VirtualNetworkInherited",
                "sku_name": "Standard", "sku_tier": "Regional"}

    ips = [ip("ip-a", NET_IN, "nic-a"), ip("ip-b", NET_IN, "nic-b"), ip("ip-c", NET_OUT, "nic-c")]
    # ip-a's NIC sits in the excluded VNet, which has a plan; ip-c is in the excluded group but on the in-scope VNet.
    ips[0]["ip_configuration_id"] = cfg(NET_OUT, "vnet-out", "nic-a")
    ips[2]["ip_configuration_id"] = cfg(NET_IN, "vnet-in", "nic-c")
    return plans, vnets, ips, [], []


def _run_ddos(monkeypatch, tmp_path, patterns):
    monkeypatch.setattr(ddos, "collect", lambda *a: _ddos_raw())
    _environment(ddos, monkeypatch, tmp_path, patterns)
    return ddos.main(), _read(tmp_path, "azure_ddos_protection")


def test_ddos_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = _run_ddos(monkeypatch, tmp_path, None)
    assert code == 0 and evidence["results"]["excluded"] == []
    assert evidence["summary"] == {
        **ddos.summarize(*ddos.build_records(*_ddos_raw())), "provider_registration_status": "registered",
        **_added({"ddos_protection_plans": 2, "virtual_networks": 2, "public_ips": 3},
                 ("ddos_protection_plans", "virtual_networks", "public_ips")),
    }


def test_ddos_exclusions_keep_an_in_scope_ip_protected_through_an_excluded_vnet(monkeypatch, tmp_path):
    code, evidence = _run_ddos(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("ddos_protection_plan", "plan-east", "location:regioneast", "resource_matched"),
        ("public_ip", "ip-c", "rg:rg-out", "resource_matched"),
        ("virtual_network", "vnet-out", "rg:rg-out", "resource_matched"),
    ]
    ips = {i["name"]: i for i in results["public_ip_addresses"]}
    assert set(ips) == {"ip-a", "ip-b"}
    # ip-a is protected by the excluded VNet's plan and keeps that verdict.
    assert ips["ip-a"]["effective_protection"] == "network_protection"
    assert ips["ip-b"]["effective_protection"] == "none"
    # vnet-in's attached IPs exclude the excluded ip-c, which also sits on it.
    vnet = results["virtual_networks"][0]
    assert (vnet["name"], vnet["attached_public_ips"], vnet["unprotected_attached_public_ips"]) == ("vnet-in", 1, 1)
    assert (summary["total_public_ips"], summary["attached_public_ips_unprotected"],
            summary["total_virtual_networks"], summary["total_ddos_protection_plans"]) == (2, 1, 1, 1)
    assert (summary["excluded_public_ips"], summary["excluded_virtual_networks"], summary["excluded_ddos_protection_plans"],
            summary["in_scope_public_ips"]) == (1, 1, 1, 2)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_ddos_excluded_plan_does_not_change_a_virtual_networks_plan_verdict(monkeypatch, tmp_path):
    pattern = f"id:{NET_IN}/ddosProtectionPlans/plan-in"
    monkeypatch.setattr(ddos, "collect", lambda *a: _ddos_raw())
    _environment(ddos, monkeypatch, tmp_path, pattern)
    ddos.main()
    evidence = _read(tmp_path, "azure_ddos_protection")
    vnets = {v["name"]: v for v in evidence["results"]["virtual_networks"]}
    assert _excluded(evidence)[0] == ("ddos_protection_plan", "plan-in", pattern, "resource_matched")
    # vnet-out references the excluded plan and still has one.
    assert vnets["vnet-out"]["has_ddos_plan"] is True and vnets["vnet-out"]["ddos_protection_plan_in_subscription"] is True


# --- network_flow_logs ---

def _flow_client():
    w_in, w_out = f"{NET_IN}/networkWatchers/w-in", f"{NET_OUT}/networkWatchers/w-out"
    vnet_in, vnet_out, vnet_two = (f"{NET_IN}/virtualNetworks/vnet-in", f"{NET_OUT}/virtualNetworks/vnet-out",
                                   f"{NET_IN}/virtualNetworks/vnet-two")

    def subnet(vnet, name):
        return NS(id=f"{vnet}/subnets/{name}", name=name, address_prefix="10.0.0.0/24", network_security_group=None,
                  ip_configurations=[NS(id="x")])

    def log(watcher, name, target, enabled=True):
        return NS(id=f"{watcher}/flowLogs/{name}", name=name, location="regionwest", enabled=enabled,
                  target_resource_id=target, retention_policy=NS(enabled=True, days=90), format=None,
                  flow_analytics_configuration=None, storage_id=None, enabled_filtering_criteria=None)

    watchers = [NS(id=w_in, name="w-in", location="regionwest"), NS(id=w_out, name="w-out", location="regionwest")]
    logs = {
        "w-in": [log(w_in, "fl-s1", f"{vnet_two}/subnets/s1"), log(w_in, "fl-own", f"{NET_IN}/networkInterfaces/nic1"),
                 log(w_in, "fl-to-out", vnet_out)],
        "w-out": [log(w_out, "fl-vnet-in", vnet_in)],
    }
    vnets = [
        NS(id=vnet_in, name="vnet-in", location="regionwest", subnets=[subnet(vnet_in, "app"), subnet(vnet_in, "data")]),
        NS(id=vnet_out, name="vnet-out", location="regionwest", subnets=[subnet(vnet_out, "x")]),
        NS(id=vnet_two, name="vnet-two", location="regionwest", subnets=[subnet(vnet_two, "s1"), subnet(vnet_two, "s2")]),
    ]
    return NS(
        network_watchers=NS(list_all=lambda: watchers),
        flow_logs=NS(list=lambda rg, name: logs[name]),
        virtual_networks=NS(list_all=lambda: vnets),
        network_security_groups=NS(list_all=lambda: []),
    ), vnet_two


def _run_flow(monkeypatch, tmp_path, patterns):
    client, vnet_two = _flow_client()
    _fake_azure(monkeypatch, client)
    _environment(flow, monkeypatch, tmp_path, patterns(vnet_two) if callable(patterns) else patterns)
    return flow.main(), _read(tmp_path, "azure_network_flow_logs")


def test_flow_logs_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = _run_flow(monkeypatch, tmp_path, None)
    results = evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert evidence["summary"] == {
        **flow.summarize(results["network_watchers"], results["flow_logs"], results["virtual_networks"]),
        "provider_registration_status": "registered",
        **_added({"network_watchers": 2, "flow_logs": 4, "virtual_networks": 3, "subnets": 5},
                 ("network_watchers", "flow_logs", "virtual_networks", "subnets")),
    }


def test_flow_logs_exclusions_follow_targets_and_keep_coverage_verdicts(monkeypatch, tmp_path):
    def patterns(vnet_two):
        return (f"rg:rg-out, id:{NET_IN}/virtualNetworks/vnet-in/subnets/data, id:{vnet_two}/subnets/s2, "
                f"id:{NET_IN}/networkWatchers/w-in/flowLogs/fl-own, location:nowhere")

    code, evidence = _run_flow(monkeypatch, tmp_path, patterns)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("flow_log", "fl-own", f"id:{NET_IN}/networkWatchers/w-in/flowLogs/fl-own", "resource_matched"),
        ("flow_log", "fl-to-out", "rg:rg-out", "target_matched"),
        ("network_watcher", "w-out", "rg:rg-out", "resource_matched"),
        ("subnet", "data", f"id:{NET_IN}/virtualNetworks/vnet-in/subnets/data", "resource_matched"),
        ("subnet", "s2", f"id:{NET_IN}/virtualNetworks/vnet-two/subnets/s2", "resource_matched"),
        ("virtual_network", "vnet-out", "rg:rg-out", "resource_matched"),
    ]
    by_reason = {e["name"]: e for e in results["excluded"]}
    assert by_reason["fl-to-out"]["matched_id"] == f"{NET_OUT}/virtualNetworks/vnet-out"
    assert [w["name"] for w in results["network_watchers"]] == ["w-in"]
    # fl-vnet-in sits under the excluded watcher but logs an in-scope network, so it stays.
    assert [f["name"] for f in results["flow_logs"]] == ["fl-s1", "fl-vnet-in"]
    vnets = {v["name"]: v for v in results["virtual_networks"]}
    assert set(vnets) == {"vnet-in", "vnet-two"}
    assert vnets["vnet-in"]["coverage"] == "full" and [s["name"] for s in vnets["vnet-in"]["subnets"]] == ["app"]
    assert vnets["vnet-two"]["coverage"] == "full" and [s["name"] for s in vnets["vnet-two"]["subnets"]] == ["s1"]
    assert (summary["total_network_watchers"], summary["total_flow_logs"], summary["total_virtual_networks"],
            summary["total_subnets"]) == (1, 2, 2, 2)
    assert (summary["virtual_networks_fully_covered"], summary["virtual_networks_partially_covered"],
            summary["subnets_covered"]) == (2, 0, 2)
    assert (summary["excluded_network_watchers"], summary["excluded_flow_logs"], summary["excluded_virtual_networks"],
            summary["excluded_subnets"]) == (1, 2, 1, 2)
    assert (summary["in_scope_flow_logs"], summary["in_scope_subnets"]) == (2, 2)
    assert summary["resource_exclusion_patterns_unmatched"] == ["location:nowhere"]


def test_flow_logs_stay_when_their_watcher_or_its_resource_group_is_excluded(monkeypatch, tmp_path):
    patterns = f"rg:rg-out, id:{NET_IN}/networkWatchers/w-in"
    code, evidence = _run_flow(monkeypatch, tmp_path, patterns)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and results["network_watchers"] == []
    # Only fl-to-out leaves, and with its target (vnet-out in rg-out), not with its watcher.
    assert [e for e in _excluded(evidence) if e[0] == "flow_log"] == [
        ("flow_log", "fl-to-out", "rg:rg-out", "target_matched")]
    assert [f["name"] for f in results["flow_logs"]] == ["fl-own", "fl-s1", "fl-vnet-in"]
    assert (summary["total_network_watchers"], summary["total_flow_logs"], summary["enabled_flow_logs"]) == (0, 3, 3)
    assert (summary["excluded_network_watchers"], summary["excluded_flow_logs"]) == (2, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == []


def test_flow_logs_a_vnet_whose_every_subnet_is_excluded_leaves_every_count(monkeypatch, tmp_path):
    s1, s2 = f"id:{NET_IN}/virtualNetworks/vnet-two/subnets/s1", f"id:{NET_IN}/virtualNetworks/vnet-two/subnets/s2"
    _, evidence = _run_flow(monkeypatch, tmp_path, f"{s1}, {s2}")
    summary, results = evidence["summary"], evidence["results"]
    out = {(e["kind"], e["name"]): e for e in results["excluded"]}
    vnet_two = out[("virtual_network", "vnet-two")]
    assert (vnet_two["reason"], vnet_two["pattern"]) == ("subnets_matched", s2)
    assert vnet_two["id"] == f"{NET_IN}/virtualNetworks/vnet-two"
    assert out[("flow_log", "fl-s1")]["reason"] == "target_matched"
    assert sorted(v["name"] for v in results["virtual_networks"]) == ["vnet-in", "vnet-out"]
    buckets = ("virtual_networks_fully_covered", "virtual_networks_partially_covered", "virtual_networks_not_covered",
               "virtual_networks_coverage_unknown")
    assert summary["total_virtual_networks"] == sum(summary[k] for k in buckets) == 2
    assert (summary["excluded_virtual_networks"], summary["in_scope_virtual_networks"]) == (1, 2)
    assert (summary["excluded_subnets"], summary["in_scope_subnets"]) == (2, 3)


def test_flow_logs_a_trailing_star_watcher_pattern_keeps_its_logs_and_a_log_pattern_still_takes_one():
    watcher = f"{NET_IN}/networkWatchers/NetworkWatcher_xeast"
    logs = [{"id": f"{watcher}/flowLogs/{name}", "name": name, "location": "regionwest",
             "target_resource_id": f"{NET_IN}/virtualNetworks/vnet-in"} for name in ("fl1", "fl2")]
    rules = flow.ResourceExclusions(["id:*/networkWatchers/NetworkWatcher_x*", f"id:{watcher}/flowLogs/fl2"])
    kept, out = flow.split_flow_logs(logs, [], rules)
    assert [log["name"] for log in kept] == ["fl1"]
    assert [(e["name"], e["pattern"], e["reason"]) for e in out] == [
        ("fl2", f"id:{watcher}/flowLogs/fl2", "resource_matched")]
    assert rules.unmatched() == ["id:*/networkWatchers/NetworkWatcher_x*"]


def test_flow_logs_a_log_on_a_vnet_that_left_with_its_subnets_leaves_too():
    vnet = f"{NET_IN}/virtualNetworks/vnet-two"
    log = {"id": f"{NET_IN}/networkWatchers/w-in/flowLogs/fl-vnet", "name": "fl-vnet", "location": "regionwest",
           "target_resource_id": vnet}
    gone = [{"id": vnet, "pattern": f"id:{vnet}/subnets/s2"}]
    kept, out = flow.split_flow_logs([log], gone, flow.ResourceExclusions([f"id:{vnet}/subnets/s2"]))
    assert kept == [] and [(e["reason"], e["pattern"], e["matched_id"]) for e in out] == [
        ("target_matched", f"id:{vnet}/subnets/s2", vnet)]


# --- virtual_wan_configuration ---

def _wan_client():
    def rid(rg_net, kind, name):
        return f"{rg_net}/{kind}/{name}"

    def ref(rg_net, kind, name):
        return NS(id=rid(rg_net, kind, name))

    wans = [NS(id=rid(NET_IN, "virtualWans", "wan-in"), name="wan-in", location="regionwest"),
            NS(id=rid(NET_OUT, "virtualWans", "wan-out"), name="wan-out", location="regionwest")]

    def hub(name, rg_net, wan_rg, wan, location="regionwest"):
        return NS(id=rid(rg_net, "virtualHubs", name), name=name, location=location,
                  virtual_wan=ref(wan_rg, "virtualWans", wan))

    hubs = [hub("hub-in", NET_IN, NET_IN, "wan-in"), hub("hub-via", NET_IN, NET_OUT, "wan-out"),
            hub("hub-east", NET_IN, NET_IN, "wan-in", "regioneast")]

    def gateway(name, hub_name, with_connection=False):
        connections = [NS(id=rid(NET_IN, "vpnGateways", f"{name}/vpnConnections/c"), name="c", remote_vpn_site=None,
                          vpn_link_connections=[NS(id="l", name="l", vpn_connection_protocol_type="IKEv2")])]
        return NS(id=rid(NET_IN, "vpnGateways", name), name=name, location="regionwest",
                  virtual_hub=ref(NET_IN, "virtualHubs", hub_name), connections=connections if with_connection else [])

    vpn_gateways = [gateway("gw-in", "hub-in", True), gateway("gw-via", "hub-via", True), gateway("gw-follow", "hub-east")]
    p2s = [NS(id=rid(NET_IN, "p2sVpnGateways", "p2s-in"), name="p2s-in", location="regionwest",
              virtual_hub=ref(NET_IN, "virtualHubs", "hub-in")),
           NS(id=rid(NET_IN, "p2sVpnGateways", "p2s-via"), name="p2s-via", location="regionwest",
              virtual_hub=ref(NET_IN, "virtualHubs", "hub-via"))]
    sites = [NS(id=rid(NET_IN, "vpnSites", "site-in"), name="site-in", location="regionwest",
                virtual_wan=ref(NET_IN, "virtualWans", "wan-in")),
             NS(id=rid(NET_IN, "vpnSites", "site-via"), name="site-via", location="regionwest",
                virtual_wan=ref(NET_OUT, "virtualWans", "wan-out"))]
    configs = [NS(id=rid(NET_IN, "vpnServerConfigurations", "cfg-in"), name="cfg-in", location="regionwest"),
               NS(id=rid(NET_OUT, "vpnServerConfigurations", "cfg-out"), name="cfg-out", location="regionwest")]
    return NS(
        virtual_wans=NS(list=lambda: wans), virtual_hubs=NS(list=lambda: hubs), vpn_gateways=NS(list=lambda: vpn_gateways),
        vpn_sites=NS(list=lambda: sites), p2_svpn_gateways=NS(list=lambda: p2s),
        vpn_server_configurations=NS(list=lambda: configs),
    )


def _run_wan(monkeypatch, tmp_path, patterns):
    _fake_azure(monkeypatch, _wan_client())
    _environment(vwan, monkeypatch, tmp_path, patterns)
    return vwan.main(), _read(tmp_path, "azure_virtual_wan_configuration")


def test_virtual_wan_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence = _run_wan(monkeypatch, tmp_path, None)
    results = evidence["results"]
    assert code == 0 and results["excluded"] == []
    assert evidence["summary"] == {
        **vwan.summarize(results), "provider_registration_status": "registered",
        **_added({"virtual_wans": 2, "virtual_hubs": 3, "vpn_gateways": 3, "vpn_sites": 2, "p2s_vpn_gateways": 2,
                  "vpn_server_configurations": 2},
                 ("virtual_wans", "virtual_hubs", "vpn_gateways", "vpn_sites", "p2s_vpn_gateways",
                  "vpn_server_configurations")),
    }


def test_virtual_wan_hubs_leave_with_their_wan_and_gateways_and_sites_follow(monkeypatch, tmp_path):
    code, evidence = _run_wan(monkeypatch, tmp_path, "rg:rg-out, location:regioneast, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("p2s_vpn_gateway", "p2s-via", "rg:rg-out", "virtual_hub_matched"),
        ("virtual_hub", "hub-east", "location:regioneast", "resource_matched"),
        ("virtual_hub", "hub-via", "rg:rg-out", "virtual_wan_matched"),
        ("virtual_wan", "wan-out", "rg:rg-out", "resource_matched"),
        ("vpn_gateway", "gw-follow", "location:regioneast", "virtual_hub_matched"),
        ("vpn_gateway", "gw-via", "rg:rg-out", "virtual_hub_matched"),
        ("vpn_server_configuration", "cfg-out", "rg:rg-out", "resource_matched"),
        ("vpn_site", "site-via", "rg:rg-out", "virtual_wan_matched"),
    ]
    out = {e["name"]: e for e in results["excluded"]}
    assert out["hub-via"]["matched_id"].endswith("/virtualWans/wan-out")
    assert out["gw-via"]["matched_id"].endswith("/virtualHubs/hub-via")
    assert [h["name"] for h in results["virtual_hubs"]] == ["hub-in"]
    assert [g["name"] for g in results["vpn_gateways"]] == ["gw-in"]
    assert (summary["total_virtual_wans"], summary["total_virtual_hubs"], summary["total_vpn_gateways"],
            summary["total_vpn_connections"], summary["total_vpn_sites"], summary["total_p2s_vpn_gateways"],
            summary["total_vpn_server_configurations"]) == (1, 1, 1, 1, 1, 1, 1)
    assert (summary["excluded_virtual_wans"], summary["excluded_virtual_hubs"], summary["excluded_vpn_gateways"],
            summary["excluded_p2s_vpn_gateways"], summary["excluded_vpn_sites"],
            summary["excluded_vpn_server_configurations"]) == (1, 2, 2, 1, 1, 1)
    assert summary["in_scope_vpn_gateways"] == 1
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]


def test_virtual_wan_id_on_a_wan_takes_its_hub(monkeypatch, tmp_path):
    pattern = f"id:{NET_IN}/virtualWans/wan-in"
    _, evidence = _run_wan(monkeypatch, tmp_path, pattern)
    out = {e["name"]: e for e in evidence["results"]["excluded"]}
    assert out["hub-in"]["reason"] == "virtual_wan_matched" and out["gw-in"]["reason"] == "virtual_hub_matched"
    assert out["site-in"]["reason"] == "virtual_wan_matched" and out["p2s-in"]["reason"] == "virtual_hub_matched"


# --- vpn_gateway_configuration ---

def _vpn_client(reads):
    def gw(name, rg_net):
        return NS(id=f"{rg_net}/virtualNetworkGateways/{name}", name=name, location="regionwest", gateway_type="Vpn")

    def lng(name, rg_net):
        return NS(id=f"{rg_net}/localNetworkGateways/{name}", name=name, location="regionwest")

    def conn(name, rg_net, owner, protocol, local):
        return NS(id=f"{rg_net}/connections/{name}", name=name, location="regionwest", connection_type="IPsec",
                  connection_protocol=protocol, ipsec_policies=[],
                  virtual_network_gateway1=NS(id=f"{owner}"), local_network_gateway2=NS(id=local))

    gateways = [gw("gw-in", NET_IN), gw("gw-out", NET_OUT)]
    locals_ = [lng("lng-in", NET_IN), lng("lng-out", NET_OUT)]
    conns = [
        conn("conn-in", NET_IN, gateways[0].id, "IKEv2", locals_[1].id),
        conn("conn-follow", NET_IN, gateways[1].id, "IKEv1", locals_[0].id),
        conn("conn-own", NET_OUT, gateways[0].id, "IKEv1", locals_[0].id),
    ]

    def in_group(items, rg):
        return [i for i in items if f"/resourceGroups/{rg}/" in i.id]

    def get(rg, name):
        reads.append(name)
        return NS(connection_status="Connected")

    return NS(
        resource_groups=NS(list=lambda: [NS(name="rg-in"), NS(name="rg-out")]),
        virtual_network_gateways=NS(list=lambda rg: in_group(gateways, rg)),
        virtual_network_gateway_connections=NS(list=lambda rg: in_group(conns, rg), get=get),
        local_network_gateways=NS(list=lambda rg: in_group(locals_, rg)),
    )


def _run_vpn(monkeypatch, tmp_path, patterns):
    reads: list = []
    _fake_azure(monkeypatch, _vpn_client(reads))
    _environment(vpn, monkeypatch, tmp_path, patterns)
    return vpn.main(), _read(tmp_path, "azure_vpn_gateway_configuration"), reads


def test_vpn_without_patterns_adds_only_empty_exclusion_fields(monkeypatch, tmp_path):
    code, evidence, reads = _run_vpn(monkeypatch, tmp_path, None)
    results = evidence["results"]
    assert code == 0 and results["excluded"] == [] and len(reads) == 3
    assert evidence["summary"] == {
        **vpn.summarize(results["virtual_network_gateways"], results["connections"], results["local_network_gateways"]),
        "provider_registration_status": "registered",
        **_added({"virtual_network_gateways": 2, "connections": 3, "local_network_gateways": 2},
                 ("virtual_network_gateways", "connections", "local_network_gateways")),
    }


def test_vpn_connections_leave_with_their_gateway_and_keep_a_verdict_toward_an_excluded_local_gateway(monkeypatch, tmp_path):
    code, evidence, reads = _run_vpn(monkeypatch, tmp_path, "rg:rg-out, rg:typo")
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert _excluded(evidence) == [
        ("connection", "conn-follow", "rg:rg-out", "gateway_matched"),
        ("connection", "conn-own", "rg:rg-out", "resource_matched"),
        ("local_network_gateway", "lng-out", "rg:rg-out", "resource_matched"),
        ("virtual_network_gateway", "gw-out", "rg:rg-out", "resource_matched"),
    ]
    out = {e["name"]: e for e in results["excluded"]}
    assert out["conn-follow"]["matched_id"] == f"{NET_OUT}/virtualNetworkGateways/gw-out"
    assert [c["name"] for c in results["connections"]] == ["conn-in"]
    # conn-in points at the excluded lng-out and still counts, IKEv2 and connected.
    assert results["connections"][0]["local_network_gateway2"] == "lng-out"
    assert (summary["total_connections"], summary["ikev2_connections"], summary["ikev1_connections"],
            summary["connected_connections"]) == (1, 1, 0, 1)
    assert (summary["total_gateways"], summary["total_local_network_gateways"]) == (1, 1)
    assert (summary["excluded_connections"], summary["excluded_virtual_network_gateways"],
            summary["excluded_local_network_gateways"], summary["in_scope_connections"]) == (2, 1, 1, 1)
    assert summary["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    # Excluded connections get no per-connection read.
    assert reads == ["conn-in"]


# --- a list that wasn't read leaves its counts null ---

REFUSED = PermissionError("(AuthorizationFailed) 403")


def _refuse(monkeypatch, module, operation):
    """The collector records a 403 for one operation and returns its default, as a refused list does."""
    class Refusing(module.Collector):
        def guard(self, op, fn, default=None):
            if op == operation:
                self.record(op, REFUSED)
                return default
            return super().guard(op, fn, default)

    monkeypatch.setattr(module, "Collector", Refusing)


def _refused_gateways(m, name):
    def run(monkeypatch, tmp_path):
        _environment(ag, monkeypatch, tmp_path, "rg:rg-out")
        monkeypatch.setattr(ag, "list_gateways", lambda s, c, collector: collector.record(
            "network.application_gateways.list_all", REFUSED))
        monkeypatch.setattr(ag, "resource_graph_gateway_count", lambda *a: 3)
        if m is waf:
            monkeypatch.setattr(waf, "collect_policies", lambda *a: [_policy("pol-in", NET_IN, "Enabled", "Prevention")])
        return m.run_fetcher(name, m.logger, m.build), _read(tmp_path, name)
    return run


def _refused_waf_policies(monkeypatch, tmp_path):
    _fake_azure(monkeypatch, NS(web_application_firewall_policies=NS(list_all=lambda: [])))
    _refuse(monkeypatch, ag, "network.web_application_firewall_policies.list_all")
    _environment(ag, monkeypatch, tmp_path, "rg:rg-out")
    monkeypatch.setattr(ag, "list_gateways", lambda *a: _gateways())
    monkeypatch.setattr(ag, "resource_graph_gateway_count", lambda *a: 3)
    monkeypatch.setattr(waf, "fetch_policy", lambda pid, cred, collector: (None, waf.unresolved_policy(pid)))
    return waf.run_fetcher("azure_app_gateway_waf", waf.logger, waf.build), _read(tmp_path, "azure_app_gateway_waf")


def _refused_ddos(operation):
    def run(monkeypatch, tmp_path):
        _fake_azure(monkeypatch, NS(**{name: NS(list=lambda: [], list_all=lambda: []) for name in (
            "ddos_protection_plans", "virtual_networks", "public_ip_addresses", "network_interfaces", "load_balancers")}))
        _refuse(monkeypatch, ddos, operation)
        _environment(ddos, monkeypatch, tmp_path, "rg:rg-out")
        return ddos.main(), _read(tmp_path, "azure_ddos_protection")
    return run


def _refused(m, run, operation):
    def go(monkeypatch, tmp_path):
        _refuse(monkeypatch, m, operation)
        result = run(monkeypatch, tmp_path, "rg:rg-out")
        return result[0], result[1]
    return go


@pytest.mark.parametrize("run, unread, read", [
    (_refused_gateways(backend, "azure_app_gateway_backend_tls"), ("application_gateways", "backend_settings"), ()),
    (_refused_gateways(listeners, "azure_app_gateway_tls_listeners"), ("application_gateways", "listeners"), ()),
    (_refused_gateways(waf, "azure_app_gateway_waf"), ("application_gateways", "listeners"), ("waf_policies",)),
    (_refused_waf_policies, ("waf_policies",), ("application_gateways",)),
    (_refused_ddos("network.ddos_protection_plans.list"), ("ddos_protection_plans",), ("virtual_networks", "public_ips")),
    (_refused_ddos("network.virtual_networks.list_all"), ("virtual_networks",), ("ddos_protection_plans", "public_ips")),
    (_refused_ddos("network.public_ip_addresses.list_all"), ("public_ips",), ("ddos_protection_plans", "virtual_networks")),
    (_refused(flow, _run_flow, "network.virtual_networks.list_all"), ("virtual_networks", "subnets"),
     ("network_watchers", "flow_logs")),
    (_refused(flow, _run_flow, "network.network_watchers.list_all"), ("network_watchers", "flow_logs"),
     ("virtual_networks", "subnets")),
    # A hub's gateways leave with an excluded hub, so with the hub list unread their in-scope counts are unknown too.
    (_refused(vwan, _run_wan, "network.virtual_hubs.list"), ("virtual_hubs", "vpn_gateways", "p2s_vpn_gateways"),
     ("virtual_wans", "vpn_sites", "vpn_server_configurations")),
    (_refused(vpn, _run_vpn, "resource.resource_groups.list"),
     ("virtual_network_gateways", "connections", "local_network_gateways"), ()),
], ids=["backend", "listeners", "waf-gateways", "waf-policies", "ddos-plans", "ddos-vnets", "ddos-ips", "flow-vnets",
        "flow-watchers", "wan-hubs", "vpn-groups"])
def test_a_list_that_wasnt_read_leaves_its_exclusion_counts_null(run, unread, read, monkeypatch, tmp_path):
    code, evidence = run(monkeypatch, tmp_path)
    summary = evidence["summary"]
    assert code == 1
    # Listeners and backend settings have no excluded count of their own: they leave with their gateway.
    assert {k: (summary[f"in_scope_{k}"], summary.get(f"excluded_{k}")) for k in unread} == dict.fromkeys(
        unread, (None, None))
    assert all(isinstance(summary[f"in_scope_{k}"], int) and isinstance(summary[f"excluded_{k}"], int) for k in read)


# --- a bare pattern fails every fetcher ---

def _runners():
    def gateway_runner(m, name):
        return lambda mp, tp, p: _run_gateway_fetcher(m, mp, tp, p, name)[0]

    return {
        "backend": gateway_runner(backend, "azure_app_gateway_backend_tls"),
        "listeners": gateway_runner(listeners, "azure_app_gateway_tls_listeners"),
        "waf": lambda mp, tp, p: (_waf_scenario(mp), _run_gateway_fetcher(waf, mp, tp, p, "azure_app_gateway_waf", []))[1][0],
        "ddos": lambda mp, tp, p: _run_ddos(mp, tp, p)[0],
        "flow": lambda mp, tp, p: _run_flow(mp, tp, p)[0],
        "wan": lambda mp, tp, p: _run_wan(mp, tp, p)[0],
        "vpn": lambda mp, tp, p: _run_vpn(mp, tp, p)[0],
    }


@pytest.mark.parametrize("family", ["backend", "listeners", "waf", "ddos", "flow", "wan", "vpn"])
def test_a_bare_pattern_fails_the_run(family, monkeypatch, tmp_path, capsys):
    assert _runners()[family](monkeypatch, tmp_path, "rg-out") == 1
