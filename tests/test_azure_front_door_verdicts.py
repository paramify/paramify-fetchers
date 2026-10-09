"""Azure Front Door verdict logic: pure functions over projected dicts, no SDK or network."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

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


coverage = _load("front_door_waf_coverage")
tls = _load("front_door_tls")
origins = _load("front_door_origins")
fd = sys.modules["frontdoor"]

GROUPS = ("SQLI", "XSS", "PHP")
NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)


def definitions(rule_set_type="Microsoft_DefaultRuleSet", off_by_default=()):
    def group(name, state):
        return {"rule_group_name": name, "rules": [
            {"rule_id": f"{name}-{i}", "default_state": state, "default_action": "AnomalyScoring"} for i in (1, 2)
        ]}

    return fd.definition_index([{
        "rule_set_type": rule_set_type,
        "rule_set_version": "2.1",
        "rule_groups": [group(g, "Enabled") for g in GROUPS] + [group(g, "Disabled") for g in off_by_default],
    }])


def override(rule_id, enabled_state="Enabled", action=None):
    return {"rule_id": rule_id, "enabled_state": enabled_state, "action": action, "exclusions": []}


def custom_rule(action="Allow", operator="Any", negate=False, rule_type="MatchRule", values=("10.0.0.0/8",),
                variable="RemoteAddr"):
    return {
        "name": "rule1", "priority": 1, "enabled_state": "Enabled", "rule_type": rule_type, "action": action,
        "rate_limit_threshold": None, "rate_limit_duration_in_minutes": None, "match_condition_count": 1,
        "match_conditions": [{"match_variable": variable, "selector": None, "operator": operator,
                              "negate_condition": negate, "match_value": list(values)}],
        "group_by": [],
    }


def policy(group_overrides=(), rule_set_type="Microsoft_DefaultRuleSet", custom_rules=(), **settings):
    return {
        "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/waf",
        "name": "waf", "location": "Global", "sku": "Premium_AzureFrontDoor",
        "enabled_state": "Enabled", "mode": "Prevention", "request_body_check": "Enabled",
        "provisioning_state": "Succeeded", "resource_state": "Enabled",
        "managed_rule_sets": [{
            "rule_set_type": rule_set_type, "rule_set_version": "2.1", "rule_set_action": "Block",
            "exclusions": [], "rule_group_overrides": list(group_overrides),
        }],
        "exceptions": [], "custom_rules": list(custom_rules), "security_policy_links": [{"id": "sp"}],
        **settings,
    }


def group_override(name, rules):
    return {"rule_group_name": name, "rules": rules, "exclusions": []}


def test_every_group_blocking_is_blocking():
    record = fd.waf_policy_record(policy(), definitions())
    assert record["blocking"] is True
    assert record["not_blocking_reasons"] == []
    assert record["default_rule_set_blocking_rules"] == 6


@pytest.mark.parametrize("overrides", [
    pytest.param([group_override("SQLI", None)], id="group-overridden-off"),
    pytest.param([group_override("SQLI", [override("SQLI-1", "Disabled"), override("SQLI-2", "Disabled")])],
                 id="every-rule-disabled"),
    pytest.param([group_override("SQLI", [override("SQLI-1", action="Log"), override("SQLI-2", action="Log")])],
                 id="every-rule-log"),
    pytest.param([group_override("SQLI", [override("SQLI-1", action="Allow"), override("SQLI-2", action="Allow")])],
                 id="every-rule-allow"),
])
def test_group_without_blocking_rule_makes_policy_not_blocking(overrides):
    record = fd.waf_policy_record(policy(overrides), definitions())
    assert record["blocking"] is False
    assert record["not_blocking_reasons"] == ["rule_groups_not_blocking"]
    assert record["default_rule_set_groups_without_blocking_rules"] == ["SQLI"]


THREAT_INTEL = ("MS-ThreatIntel-AppSec", "MS-ThreatIntel-SQLI", "MS-ThreatIntel-WebShells")


def test_stock_policy_with_groups_off_by_default_is_blocking():
    record = fd.waf_policy_record(policy(), definitions(off_by_default=THREAT_INTEL))
    assert record["blocking"] is True
    assert record["default_rule_set_groups_off_by_default"] == list(THREAT_INTEL)
    assert record["default_rule_set_groups_without_blocking_rules"] == []
    assert record["default_rule_set_fully_disabled_groups"] == []


@pytest.mark.parametrize("action, off_by_default", [
    pytest.param("Block", [], id="enabled-to-block"),
    pytest.param("Log", ["MS-ThreatIntel-SQLI"], id="enabled-to-log"),
])
def test_group_off_by_default_leaves_the_list_only_when_a_rule_blocks(action, off_by_default):
    overrides = [group_override("MS-ThreatIntel-SQLI", [override("MS-ThreatIntel-SQLI-1", action=action)])]
    record = fd.waf_policy_record(policy(overrides), definitions(off_by_default=["MS-ThreatIntel-SQLI"]))
    assert record["blocking"] is True
    assert record["default_rule_set_groups_off_by_default"] == off_by_default


def test_allow_override_is_listed_and_not_counted_as_blocking():
    record = fd.waf_policy_record(policy([group_override("XSS", [override("XSS-1", action="Allow")])]), definitions())
    rule_set = record["managed_rule_sets"][0]
    assert rule_set["allow_rules"] == [{"rule_group": "XSS", "rule_id": "XSS-1"}]
    assert record["default_rule_set_blocking_rules"] == 5
    assert record["blocking"] is True


def test_missing_rule_definition_is_not_blocking():
    record = fd.waf_policy_record(policy(), fd.definition_index([]))
    assert record["not_blocking_reasons"] == ["rule_definition_not_found"]


def test_default_rule_set_type_matches_case_insensitively():
    record = fd.waf_policy_record(policy(rule_set_type="microsoft_defaultruleset"), definitions("microsoft_defaultruleset"))
    assert record["managed_rule_sets"][0]["is_default_rule_set"] is True
    assert record["blocking"] is True


@pytest.mark.parametrize("rule, blocking", [
    pytest.param(custom_rule(), False, id="allow-any"),
    pytest.param(custom_rule(operator="IPMatch", values=["0.0.0.0/0"]), False, id="allow-all-ipv4"),
    pytest.param(custom_rule(operator="IPMatch", values=["::/0"], variable="SocketAddr"), False, id="allow-all-ipv6"),
    pytest.param(custom_rule(operator="IPMatch", values=["0.0.0.0/0"], negate=True), True, id="allow-negated-all-ipv4"),
    pytest.param(custom_rule(operator="IPMatch"), True, id="allow-scoped"),
    pytest.param(custom_rule(negate=True), True, id="allow-negated-any"),
    pytest.param(custom_rule(action="Block"), True, id="block-any"),
    pytest.param(custom_rule(rule_type="RateLimitRule"), True, id="rate-limit"),
])
def test_allow_all_custom_rule(rule, blocking):
    record = fd.waf_policy_record(policy(custom_rules=[rule]), definitions())
    assert record["blocking"] is blocking
    assert ("allow_all_custom_rule" in record["not_blocking_reasons"]) is not blocking


@pytest.mark.parametrize("overrides, protected", [
    pytest.param([], True, id="blocking-waf"),
    pytest.param([group_override("SQLI", None)], False, id="group-off"),
])
def test_host_behind_waf_with_group_off_is_unprotected(overrides, protected):
    waf = fd.waf_policy_record(policy(overrides), definitions())
    host = {"id": "/domains/d1", "host_name": "app.example.com", "kind": "custom_domain", "is_active": True}
    sp = {"id": "sp", "name": "sp", "type": "WebApplicationFirewall", "is_profile_level": False,
          "waf_policy_id": waf["id"],
          "associations": [{"domains": [{"id": "/domains/D1", "is_active": True}], "routes": [], "patterns_to_match": ["/*"]}]}
    record = coverage.host_route_record(
        {"name": "p", "sku": "Premium_AzureFrontDoor"},
        {"id": "/endpoints/e", "name": "e", "host_name": "e.azurefd.net", "enabled_state": "Enabled"},
        {"id": "/routes/r", "name": "r", "enabled_state": "Enabled", "supported_protocols": ["Https"], "https_redirect": None},
        host, [sp], {fd.arm_key(waf["id"]): waf},
    )
    assert record["effective_scope"] == "domain"
    assert record["protected"] is protected
    assert record["unprotected_reasons"] == ([] if protected else ["waf_not_blocking"])


@pytest.mark.parametrize("expiration, expected", [
    pytest.param(None, (None, None, None), id="absent"),
    pytest.param("not-a-date", (None, None, None), id="unparsable"),
    pytest.param("2026-10-01T00:00:00Z", (-7, True, False), id="expired"),
    pytest.param("2026-10-20T00:00:00.1234567Z", (12, False, True), id="expiring-soon"),
    pytest.param("2027-01-01T00:00:00+00:00", (85, False, False), id="valid"),
])
def test_certificate_expiry(expiration, expected):
    result = tls.certificate_expiry(expiration, NOW)
    assert (result["days_until_expiry"], result["certificate_expired"], result["certificate_expiring_soon"]) == expected


def test_unknown_expiry_is_counted_not_read_as_valid():
    def domain(status, expiration):
        return {"served": True, "routed": True, "below_tls12": False, "effective_minimum_tls": "TLS12",
                "domain_validation_state": "Approved", "certificate_status": status,
                "cipher_suite_set_type": "TLS12_2023", "certificate_type": "ManagedCertificate",
                **tls.certificate_expiry(expiration, NOW)}

    domains = [domain("managed_without_secret", None), domain("missing", None),
               domain("found", "2026-10-01T00:00:00Z"), domain("found", "2027-01-01T00:00:00Z")]
    summary = tls.summarize([], {}, [], domains, [])
    assert summary["served_domains_certificate_expiry_unknown"] == 2
    assert summary["served_domains_certificate_expired"] == 1
    assert summary["served_domains_certificate_expiring_soon"] == 0


def origin(enabled_state="Enabled"):
    return {"name": "o1", "host_name": "app.azurewebsites.net", "enabled_state": enabled_state, "priority": 1,
            "weight": 1000, "enforce_certificate_name_check": True, "azure_origin_id": None,
            "private_link": {"target_id": "/sites/app", "group_id": "sites", "private_endpoint_location": "eastus",
                             "status": None}}


@pytest.mark.parametrize("states, protected, reasons", [
    pytest.param(["Enabled"], True, [], id="enabled-private-link"),
    pytest.param(["Disabled", "Disabled"], False, ["no_enabled_origin"], id="every-origin-disabled"),
])
def test_origin_group_needs_an_enabled_origin_to_be_protected(states, protected, reasons):
    group = {"id": "/originGroups/g", "name": "g", "authentication": {"type": "SystemAssignedIdentity"},
             "health_probe": None}
    path = {"origin_group_id": "/origingroups/G", "serving": True, "protocols_to_origin": ["Https"],
            "endpoint": "e", "route": "r", "via": "route", "forwarding_protocol": "HttpsOnly"}
    record = origins.group_record({"name": "p", "sku": "Premium_AzureFrontDoor"}, group,
                                  [origin(s) for s in states], [path], {}, {})
    assert record["connection_protected"] is protected
    assert record["unprotected_reasons"] == reasons
