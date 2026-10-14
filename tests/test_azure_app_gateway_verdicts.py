"""Azure Application Gateway verdict logic over modelled gateways: no SDK, no credentials, no network."""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tls = _load("app_gateway_tls_listeners")
backend = _load("app_gateway_backend_tls")
waf = _load("app_gateway_waf")
ag = sys.modules["app_gateway"]
from azure_common import Collector  # noqa: E402

GW = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/agw"
POLICIES = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/"
OTHER_SUB_POLICY = (
    "/subscriptions/other/resourceGroups/sec/providers/Microsoft.Network/"
    "ApplicationGatewayWebApplicationFirewallPolicies/central"
)


def child(kind, name):
    return f"{GW}/{kind}/{name}"


def ref(kind, name):
    return ns(id=child(kind, name))


def policy_ref(name):
    return ns(id=POLICIES + name)


def http_listener(name, protocol="Http", frontend="public", **extra):
    return ns(
        id=child("httpListeners", name), name=name, protocol=protocol,
        frontend_port=ref("frontendPorts", "p"), frontend_ip_configuration=ref("frontendIPConfigurations", frontend),
        **extra,
    )


def gateway(**extra):
    base = {
        "id": GW, "name": "agw", "sku": ns(name="WAF_v2", tier="WAF_v2"),
        "frontend_ip_configurations": [
            ns(id=child("frontendIPConfigurations", "public"), public_ip_address=ns(id="/pip")),
            ns(id=child("frontendIPConfigurations", "private"), public_ip_address=None),
        ],
        "frontend_ports": [ns(id=child("frontendPorts", "p"), port=443)],
    }
    return ns(**{**base, **extra})


def basic_rule(name, listener, redirect=None, backend_settings=None):
    return ns(
        name=name, rule_type="Basic", http_listener=ref("httpListeners", listener),
        redirect_configuration=ref("redirectConfigurations", redirect) if redirect else None,
        backend_http_settings=ref("backendHttpSettingsCollection", backend_settings) if backend_settings else None,
    )


def path_rule_routing(name, listener, path_map):
    return ns(name=name, rule_type="PathBasedRouting", http_listener=ref("httpListeners", listener),
              url_path_map=ref("urlPathMaps", path_map))


def redirect(name, target_listener=None, target_url=None):
    return ns(id=child("redirectConfigurations", name),
              target_listener=ref("httpListeners", target_listener) if target_listener else None, target_url=target_url)


def record(records, name):
    return next(r for r in records if r["name"] == name)


# --- redirect_behaviour and secure_transport -----------------------------------------------------------------


def redirect_gateway(rules, redirects, path_maps=()):
    return gateway(
        http_listeners=[http_listener("http80"), http_listener("https443", "Https"), http_listener("http8080")],
        request_routing_rules=rules, redirect_configurations=list(redirects), url_path_maps=list(path_maps),
    )


def test_basic_redirect_to_https_listener_is_secure():
    gw = redirect_gateway([basic_rule("r", "http80", redirect="toHttps")], [redirect("toHttps", "https443")])
    r = record(tls.listener_records(gw), "http80")
    assert (r["redirect_only"], r["redirect_target_https"], r["secure_transport"]) == (True, True, True)


def test_path_based_rule_where_every_path_redirects_is_secure():
    path_map = ns(
        id=child("urlPathMaps", "m"), default_redirect_configuration=ref("redirectConfigurations", "toHttps"),
        path_rules=[ns(name="a", redirect_configuration=ref("redirectConfigurations", "toUrl"))],
    )
    gw = redirect_gateway(
        [path_rule_routing("r", "http80", "m")],
        [redirect("toHttps", "https443"), redirect("toUrl", target_url="HTTPS://example.com")],
        [path_map],
    )
    r = record(tls.listener_records(gw), "http80")
    assert (r["redirect_only"], r["redirect_target_https"], r["secure_transport"]) == (True, True, True)


def test_path_map_mixing_redirect_and_backend_routing_is_not_redirect_only():
    path_map = ns(
        id=child("urlPathMaps", "m"), default_redirect_configuration=ref("redirectConfigurations", "toHttps"),
        path_rules=[ns(name="api", redirect_configuration=None, backend_http_settings=ref("backendHttpSettingsCollection", "b"))],
    )
    gw = redirect_gateway([path_rule_routing("r", "http80", "m")], [redirect("toHttps", "https443")], [path_map])
    r = record(tls.listener_records(gw), "http80")
    assert (r["redirect_only"], r["secure_transport"]) == (False, False)


def test_one_redirecting_rule_and_one_routing_rule_is_not_redirect_only():
    gw = redirect_gateway(
        [basic_rule("r1", "http80", redirect="toHttps"), basic_rule("r2", "http80", backend_settings="b")],
        [redirect("toHttps", "https443")],
    )
    assert record(tls.listener_records(gw), "http80")["redirect_only"] is False


@pytest.mark.parametrize("redirects, path_maps, rule, expected", [
    pytest.param([], [], basic_rule("r", "http80", redirect="missing"), (True, None), id="redirect config not found"),
    pytest.param([redirect("toGone", "gone")], [], basic_rule("r", "http80", redirect="toGone"), (True, None),
                 id="target listener not found"),
    pytest.param([], [], path_rule_routing("r", "http80", "missing"), (None, None), id="path map not found"),
])
def test_unresolvable_redirect_is_unknown_and_not_secure(redirects, path_maps, rule, expected):
    r = record(tls.listener_records(redirect_gateway([rule], redirects, path_maps)), "http80")
    assert (r["redirect_only"], r["redirect_target_https"]) == expected
    assert r["secure_transport"] is False


@pytest.mark.parametrize("target", [
    pytest.param(redirect("toHttp", "http8080"), id="http listener"),
    pytest.param(redirect("toHttp", target_url="http://example.com"), id="http url"),
])
def test_redirect_to_plain_http_is_not_secure(target):
    gw = redirect_gateway([basic_rule("r", "http80", redirect="toHttp")], [target])
    r = record(tls.listener_records(gw), "http80")
    assert (r["redirect_only"], r["redirect_target_https"], r["secure_transport"]) == (True, False, False)


def test_http_listener_without_rules_is_plaintext():
    r = record(tls.listener_records(redirect_gateway([], [])), "http8080")
    assert (r["redirect_only"], r["secure_transport"]) == (False, False)


def test_l4_tcp_listener_counts_as_plaintext_and_tls_as_encrypted():
    gw = gateway(listeners=[
        ns(id=child("listeners", "tcp"), name="tcp", protocol="Tcp", frontend_ip_configuration=ref("frontendIPConfigurations", "public")),
        ns(id=child("listeners", "tls"), name="tls", protocol="Tls", frontend_ip_configuration=ref("frontendIPConfigurations", "public")),
    ], default_predefined_ssl_policy="AppGwSslPolicy20220101")
    records = tls.listener_records(gw)
    assert record(records, "tcp")["secure_transport"] is False
    assert record(records, "tls")["secure_transport"] is True
    summary = tls.summarize([], records)
    assert (summary["plaintext_listeners"], summary["public_plaintext_listeners"]) == (1, 1)


# --- effective TLS policy -------------------------------------------------------------------------------------


def tls_gateway(ssl_policy=None, default=None):
    return gateway(
        http_listeners=[
            http_listener("withProfile", "Https", ssl_profile=ref("sslProfiles", "strict")),
            http_listener("noProfile", "Https"),
            http_listener("plain", "Http"),
        ],
        ssl_profiles=[ns(id=child("sslProfiles", "strict"), ssl_policy=ns(policy_type="CustomV2", min_protocol_version="TLSv1_3"))],
        ssl_policy=ssl_policy, default_predefined_ssl_policy=default,
    )


@pytest.mark.parametrize("ssl_policy, default, no_profile", [
    pytest.param(ns(policy_type="Predefined", policy_name="AppGwSslPolicy20150501"), "AppGwSslPolicy20220101",
                 ("gateway", "TLSv1_0"), id="gateway beats platform default"),
    pytest.param(None, "AppGwSslPolicy20220101", ("platform_default", "TLSv1_2"), id="platform default"),
    pytest.param(None, None, ("default_not_reported", None), id="nothing reported"),
])
def test_tls_policy_precedence(ssl_policy, default, no_profile):
    records = tls.listener_records(tls_gateway(ssl_policy, default))
    profile = record(records, "withProfile")
    assert (profile["tls_policy_source"], profile["effective_min_tls_version"]) == ("ssl_profile", "TLSv1_3")
    other = record(records, "noProfile")
    assert (other["tls_policy_source"], other["effective_min_tls_version"]) == no_profile
    assert record(records, "plain")["tls_policy_source"] == "not_applicable"


def projected(**fields):
    return {"policy_type": None, "policy_name": None, "min_protocol_version": None, "cipher_suites": [],
            "disabled_ssl_protocols": [], **fields}


@pytest.mark.parametrize("policy, expected", [
    pytest.param(projected(policy_type="Custom", min_protocol_version="TLSv1_1"), "TLSv1_1", id="Custom"),
    pytest.param(projected(policy_type="CustomV2", min_protocol_version="TLSv1_3"), "TLSv1_3", id="CustomV2"),
    pytest.param(projected(policy_type="Custom", policy_name="AppGwSslPolicy20220101", min_protocol_version="TLSv1_0"),
                 "TLSv1_0", id="Custom ignores a stray policy name"),
    pytest.param(projected(policy_type="CustomV2", policy_name="AppGwSslPolicy20150501", min_protocol_version="TLSv1_2"),
                 "TLSv1_2", id="CustomV2 ignores a stray policy name"),
    pytest.param(projected(policy_type="Predefined", policy_name="AppGwSslPolicy20170401S"), "TLSv1_2", id="Predefined"),
    pytest.param(projected(policy_type="Predefined", policy_name="AppGwSslPolicy2099"), None, id="unknown predefined"),
    pytest.param(projected(disabled_ssl_protocols=["TLSv1_0", "TLSv1_1"]), "TLSv1_2", id="legacy 1.0 and 1.1 off"),
    pytest.param(projected(disabled_ssl_protocols=["TLSv1_0"]), "TLSv1_1", id="legacy 1.0 off"),
    pytest.param(None, None, id="no policy"),
])
def test_policy_min_tls(policy, expected):
    assert tls.policy_min_tls(policy) == expected


def test_ssl_policy_with_only_disabled_protocols_is_projected():
    policy = tls.project_ssl_policy(ns(disabled_ssl_protocols=["TLSv1_0", "TLSv1_1"]))
    assert tls.policy_min_tls(policy) == "TLSv1_2"
    assert tls.project_ssl_policy(ns()) is None


# --- WAF precedence and waf_enforcing -------------------------------------------------------------------------


def waf_policy(name, state="Enabled", mode="Prevention"):
    return {"id": POLICIES + name, "name": name, "resolved": True, "state": state, "mode": mode}


def policies(*items):
    return {ag.arm_id_key(p["id"]): p for p in items}


def only_listener(gw, known):
    (r,) = waf.listener_waf_records(gw, known)
    return r


def test_path_rule_policy_overrides_the_listener_policy():
    gw = gateway(
        http_listeners=[http_listener("l", "Https", firewall_policy=policy_ref("prevent"))],
        url_path_maps=[ns(id=child("urlPathMaps", "m"), path_rules=[ns(name="api", firewall_policy=policy_ref("detect"))])],
        request_routing_rules=[path_rule_routing("r", "l", "m")],
    )
    r = only_listener(gw, policies(waf_policy("prevent"), waf_policy("detect", mode="Detection")))
    assert (r["waf_source"], r["waf_mode"]) == ("listener", "Prevention")
    assert [(p["path_rule"], p["mode"]) for p in r["path_rule_policies"]] == [("api", "Detection")]
    assert r["waf_enforcing"] is False


def test_listener_policy_overrides_the_gateway_policy():
    gw = gateway(firewall_policy=policy_ref("prevent"),
                 http_listeners=[http_listener("l", "Https", firewall_policy=policy_ref("detect"))])
    r = only_listener(gw, policies(waf_policy("prevent"), waf_policy("detect", mode="Detection")))
    assert (r["waf_source"], r["waf_policy"], r["waf_enforcing"]) == ("listener", "detect", False)


def test_gateway_policy_overrides_legacy_configuration():
    gw = gateway(firewall_policy=policy_ref("detect"), http_listeners=[http_listener("l", "Https")],
                 web_application_firewall_configuration=ns(enabled=True, firewall_mode="Prevention"))
    r = only_listener(gw, policies(waf_policy("detect", mode="Detection")))
    assert (r["waf_source"], r["waf_mode"], r["waf_enforcing"]) == ("gateway", "Detection", False)


@pytest.mark.parametrize("state, mode, expected", [
    ("Enabled", "Prevention", True),
    ("Enabled", "Detection", False),
    ("Disabled", "Prevention", False),
])
def test_enforcing_needs_enabled_prevention(state, mode, expected):
    gw = gateway(firewall_policy=policy_ref("p"), http_listeners=[http_listener("l", "Https")])
    assert only_listener(gw, policies(waf_policy("p", state, mode)))["waf_enforcing"] is expected


def test_unresolved_policy_is_unknown_not_enforcing():
    gw = gateway(firewall_policy=policy_ref("gone"), http_listeners=[http_listener("l", "Https")])
    r = only_listener(gw, {})
    assert (r["waf_policy_resolved"], r["waf_enforcing"]) == (False, None)


def test_unresolved_path_rule_policy_makes_an_enforcing_listener_unknown():
    gw = gateway(
        firewall_policy=policy_ref("prevent"), http_listeners=[http_listener("l", "Https")],
        url_path_maps=[ns(id=child("urlPathMaps", "m"), path_rules=[ns(name="api", firewall_policy=policy_ref("gone"))])],
        request_routing_rules=[path_rule_routing("r", "l", "m")],
    )
    assert only_listener(gw, policies(waf_policy("prevent")))["waf_enforcing"] is None


def test_standard_tier_gateway_has_no_waf():
    gw = gateway(sku=ns(name="Standard_v2", tier="Standard_v2"), http_listeners=[http_listener("l", "Http")])
    r = only_listener(gw, {})
    assert (r["waf_source"], r["waf_enforcing"]) == ("none", False)


@pytest.mark.parametrize("enabled, state, expected", [
    (True, "Enabled", True),
    (False, "Disabled", False),
    (None, None, None),
])
def test_legacy_configuration_reads_missing_enabled_as_unknown(enabled, state, expected):
    gw = gateway(http_listeners=[http_listener("l", "Https")],
                 web_application_firewall_configuration=ns(enabled=enabled, firewall_mode="Prevention"))
    r = only_listener(gw, {})
    assert (r["waf_source"], r["waf_state"], r["waf_enforcing"]) == ("legacy_config", state, expected)


class HttpError(Exception):
    def __init__(self, status_code):
        super().__init__(f"({status_code}) refused")
        self.status_code = status_code


def fake_network(monkeypatch, get_error):
    def get(resource_group, name):
        raise get_error

    def client(**_):
        return ns(web_application_firewall_policies=ns(list_all=lambda: [], get=get))

    monkeypatch.setitem(sys.modules, "azure.mgmt.network", ns(NetworkManagementClient=client))


def cross_subscription_gateway():
    return gateway(firewall_policy=ns(id=OTHER_SUB_POLICY), http_listeners=[http_listener("l", "Https")])


@pytest.mark.parametrize("status_code, read_status", [(401, "not_authorized"), (403, "not_authorized"), (404, "not_found")])
def test_unreadable_cross_subscription_policy_does_not_fail_the_run(monkeypatch, status_code, read_status):
    fake_network(monkeypatch, HttpError(status_code))
    collector = Collector(logging.getLogger("test"))
    results, summary = waf.build([cross_subscription_gateway()], collector, "s", object())
    assert collector.ok
    (policy,) = results["waf_policies"]
    assert (policy["resolved"], policy["read_status"]) == (False, read_status)
    assert results["listeners"][0]["waf_enforcing"] is None
    assert summary["unreadable_waf_policies"] == 1


def test_other_errors_reading_a_policy_still_fail_the_run(monkeypatch):
    fake_network(monkeypatch, HttpError(500))
    collector = Collector(logging.getLogger("test"))
    results, _ = waf.build([cross_subscription_gateway()], collector, "s", object())
    assert not collector.ok
    assert results["listeners"][0]["waf_enforcing"] is None


# --- backend certificate validation ---------------------------------------------------------------------------


def backend_gateway(*l7, l4=()):
    return gateway(
        backend_http_settings_collection=list(l7), backend_settings_collection=list(l4),
        request_routing_rules=[basic_rule(f"r-{s.name}", "l", backend_settings=s.name) for s in l7],
        routing_rules=[ns(name=f"r-{s.name}", backend_settings=ns(id=s.id)) for s in l4],
    )


def l7_setting(name, protocol="Https", **fields):
    return ns(id=child("backendHttpSettingsCollection", name), name=name, protocol=protocol, port=443, **fields)


def l4_setting(name, protocol):
    return ns(id=child("backendSettingsCollection", name), name=name, protocol=protocol, port=443)


@pytest.mark.parametrize("setting, validation, secure", [
    pytest.param(l7_setting("off", validate_cert_chain_and_expiry=False), "disabled", False, id="validation false"),
    pytest.param(l7_setting("omitted"), "default_enabled", True, id="validation omitted"),
    pytest.param(l7_setting("on", validate_cert_chain_and_expiry=True), "enabled", True, id="validation true"),
    pytest.param(l7_setting("nosni", validate_cert_chain_and_expiry=True, validate_sni=False), "enabled", False,
                 id="sni validation false"),
    pytest.param(l7_setting("plain", "Http"), "not_applicable", False, id="plain http"),
])
def test_l7_backend_validation(setting, validation, secure):
    (r,) = backend.backend_setting_records(backend_gateway(setting))
    assert (r["in_use"], r["certificate_validation"], r["secure_backend"]) == (True, validation, secure)


@pytest.mark.parametrize("protocol, validation, secure", [
    ("Tls", "not_configurable", True),
    ("Tcp", "not_applicable", False),
])
def test_l4_backend_validation(protocol, validation, secure):
    (r,) = backend.backend_setting_records(backend_gateway(l4=[l4_setting("s", protocol)]))
    assert (r["layer"], r["certificate_validation"], r["secure_backend"]) == ("L4", validation, secure)


def test_unused_insecure_setting_is_not_counted():
    gw = backend_gateway(l7_setting("on", validate_cert_chain_and_expiry=True))
    gw.backend_http_settings_collection.append(l7_setting("unused", validate_cert_chain_and_expiry=False))
    records = backend.backend_setting_records(gw)
    assert record(records, "unused")["in_use"] is False
    assert backend.summarize([], records)["certificate_validation_disabled_in_use"] == 0


# --- completeness -----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("listed, true_count, match, failed", [
    (2, 3, False, True),
    (3, 3, True, False),
    (None, 3, None, False),
    (3, None, None, False),
])
def test_completeness(listed, true_count, match, failed):
    collector = Collector(logging.getLogger("test"))
    result = ag.completeness(listed, true_count, collector)
    assert result["match"] is match
    assert collector.ok is not failed


def counts(monkeypatch, listed, true_counts):
    lists, graph = iter(listed), iter(true_counts)
    monkeypatch.setattr(ag, "list_gateways", lambda *_: [object()] * next(lists))
    monkeypatch.setattr(ag, "resource_graph_gateway_count", lambda *_: next(graph))
    sleeps = []
    return sleeps, sleeps.append


def test_mismatch_that_clears_on_recount_passes(monkeypatch):
    sleeps, sleep = counts(monkeypatch, [1, 2], [2, 2])
    collector = Collector(logging.getLogger("test"))
    raw, coverage = ag.collect_gateways("s", object(), collector, logging.getLogger("test"), sleep)
    assert sleeps == [ag.RECOUNT_DELAY_SECONDS]
    assert (len(raw), coverage["match"], coverage["recounted"], collector.ok) == (2, True, True, True)


def test_mismatch_that_persists_fails(monkeypatch):
    sleeps, sleep = counts(monkeypatch, [1, 1], [2, 2])
    collector = Collector(logging.getLogger("test"))
    _, coverage = ag.collect_gateways("s", object(), collector, logging.getLogger("test"), sleep)
    assert (len(sleeps), coverage["match"], coverage["recounted"], collector.ok) == (1, False, True, False)


def test_match_does_not_recount(monkeypatch):
    sleeps, sleep = counts(monkeypatch, [2], [2])
    _, coverage = ag.collect_gateways("s", object(), Collector(logging.getLogger("test")), logging.getLogger("test"), sleep)
    assert (sleeps, coverage["recounted"]) == ([], False)
