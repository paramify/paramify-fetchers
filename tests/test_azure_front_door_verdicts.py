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


# --- App Service origin lockdown and regional twins ---

OWN_FDID = "00000000-0000-0000-0000-0000000000aa"
OTHER_FDID = "00000000-0000-0000-0000-0000000000bb"
UNKNOWN_FDID = "00000000-0000-0000-0000-0000000000cc"
SITE = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/{}"


def rule(name, priority=100, action="Allow", tag="Default", ip="10.0.0.0/8", headers=None, subnet=None):
    return {"name": name, "priority": priority, "action": action, "tag": tag, "ip_address": ip,
            "vnet_subnet_resource_id": subnet, "headers": headers or {}}


def fd_rule(*fdids, priority=100, header="x-azure-fdid"):
    return rule("front-door", priority, tag="ServiceTag", ip="AzureFrontDoor.Backend",
                headers={header: list(fdids)} if fdids else None)


def config(*rules, default=None, public_network_access=None):
    return {"public_network_access": public_network_access, "ip_security_restrictions": list(rules),
            "ip_security_restrictions_default_action": default}


@pytest.mark.parametrize("public, cfg, private_link, locked, basis, gaps", [
    pytest.param("Disabled", config(rule("Allow all", 2147483647, ip="Any")), False, True,
                 "public_network_access_disabled", [], id="public-access-disabled"),
    pytest.param("Enabled", config(fd_rule(OWN_FDID)), False, True, "front_door_id_restricted", [], id="own-fdid-only"),
    pytest.param("Enabled", config(fd_rule(OWN_FDID.upper(), header="X-Azure-FDID")), False, True,
                 "front_door_id_restricted", [], id="header-and-id-case-insensitive"),
    pytest.param("Enabled", config(fd_rule(OWN_FDID, OTHER_FDID)), False, False, None,
                 ["other_front_door_id_allowed"], id="own-and-another-profile"),
    pytest.param(None, config(rule("Allow all", 2147483647, ip="Any")), False, False, None,
                 ["public_access_unrestricted"], id="allow-all-and-unset-public-access"),
    pytest.param("Enabled", config(), False, False, None, ["public_access_unrestricted"], id="no-rules"),
    pytest.param("Enabled", config(fd_rule(OWN_FDID), default="Allow"), False, False, None,
                 ["public_access_unrestricted"], id="default-allow"),
    pytest.param("Enabled", config(fd_rule()), False, False, None, ["front_door_rule_without_fdid"],
                 id="service-tag-without-fdid"),
    pytest.param("Enabled", config(fd_rule(OWN_FDID, UNKNOWN_FDID)), False, False, None,
                 ["unknown_front_door_id_allowed"], id="unknown-fdid"),
    pytest.param("Enabled", config(fd_rule(OTHER_FDID)), False, False, None,
                 ["other_front_door_id_allowed", "profile_front_door_id_not_allowed"], id="other-profile-only"),
    pytest.param("Enabled", config(fd_rule(OWN_FDID), rule("office", 200)), False, False, None,
                 ["non_front_door_allow_rule"], id="ip-allow-bypasses-front-door"),
    pytest.param("Enabled", config(fd_rule(OWN_FDID, priority=50), rule("Deny all", 100, "Deny", ip="Any"),
                                   rule("office", 200)), False, True, "front_door_id_restricted", [],
                 id="allow-after-catch-all-deny-is-unreachable"),
    pytest.param("Enabled", config(rule("Deny all", 100, "Deny", ip="Any")), True, True, "no_public_allow_rule", [],
                 id="private-link-public-denied"),
    pytest.param("Enabled", config(rule("Deny all", 100, "Deny", ip="Any")), False, False, None,
                 ["profile_front_door_id_not_allowed"], id="public-origin-front-door-shut-out"),
    pytest.param("Enabled", None, False, False, None, ["access_restrictions_unread"], id="config-unread"),
])
def test_app_service_lockdown(public, cfg, private_link, locked, basis, gaps):
    record = origins.lockdown(public, cfg, OWN_FDID, {OWN_FDID, OTHER_FDID}, private_link)
    assert record["locked_to_front_door"] is locked
    assert record["lockdown_basis"] == basis
    assert record["lockdown_gaps"] == gaps


def test_lockdown_reports_the_ids_it_compared():
    record = origins.lockdown("Enabled", config(fd_rule(OWN_FDID, UNKNOWN_FDID), rule("office", 200)), OWN_FDID,
                              {OWN_FDID}, False)
    assert record["allowed_front_door_ids"] == [OWN_FDID, UNKNOWN_FDID]
    assert record["profile_front_door_id_allowed"] is True
    assert record["other_front_door_ids_allowed"] == [UNKNOWN_FDID]
    assert record["non_front_door_allow_rules"] == ["office"]


def test_other_profile_front_door_id_is_counted():
    group = {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Cdn/profiles/p/originGroups/g", "name": "g",
             "profile": "p", "serving": True, "best_priority": 1, "origins": [origin_rec("east", "eastus", "app-east")]}
    sites = {origins.arm_key(SITE.format("app-east")): site_row("app-east", "eastus", "plan", public="Enabled")}
    configs = {origins.arm_key(SITE.format("app-east")): config(fd_rule(OWN_FDID, OTHER_FDID))}
    profile_fdids = {origins.profile_key(group["id"]): OWN_FDID, "/other-profile": OTHER_FDID}
    app_origins = origins.app_service_origin_records([group], profile_fdids, sites, {}, {}, configs, "s")
    summary = origins.summarize_app_services(app_origins, [], None)
    assert summary["serving_app_service_origins_other_front_door_id_allowed"] == 1
    assert summary["serving_app_service_origins_not_locked"] == 1


def test_app_fronted_by_two_profiles_is_locked_on_both():
    groups = [{"id": f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Cdn/profiles/{p}/originGroups/g",
               "name": "g", "profile": p, "serving": True, "best_priority": 1,
               "origins": [origin_rec("east", "eastus", "app-east")]} for p in ("p1", "p2")]
    sites = {origins.arm_key(SITE.format("app-east")): site_row("app-east", "eastus", "plan", public="Enabled")}
    configs = {origins.arm_key(SITE.format("app-east")): config(fd_rule(OWN_FDID, OTHER_FDID))}
    profile_fdids = {origins.profile_key(groups[0]["id"]): OWN_FDID, origins.profile_key(groups[1]["id"]): OTHER_FDID}
    records = origins.app_service_origin_records(groups, profile_fdids, sites, {}, {}, configs, "s")
    assert [(r["profile"], r["locked_to_front_door"], r["lockdown_gaps"]) for r in records] == [
        ("p1", True, []), ("p2", True, [])]
    assert [r["other_front_door_ids_allowed"] for r in records] == [[OTHER_FDID], [OWN_FDID]]


def test_unknown_profile_front_door_id_is_a_gap():
    record = origins.lockdown("Enabled", config(fd_rule(OWN_FDID)), None, set(), False)
    assert record["lockdown_gaps"] == ["unknown_front_door_id_allowed"]
    record = origins.lockdown("Enabled", config(rule("Deny all", 100, "Deny", ip="Any")), None, set(), False)
    assert record["lockdown_gaps"] == ["profile_front_door_id_unknown"]


def projected_origin(name, host="app.azurewebsites.net", azure_origin=None, target=None, group_id="sites"):
    return {"id": f"/originGroups/g/origins/{name}", "name": name, "host_name": host, "azure_origin_id": azure_origin,
            "private_link": None if target is None else {"target_id": target, "group_id": group_id,
                                                         "private_endpoint_location": "eastus", "status": None}}


@pytest.mark.parametrize("origin, expected", [
    pytest.param(projected_origin("o", azure_origin=SITE.format("App")), (SITE.format("app").lower(), "azure_origin"),
                 id="azure-origin"),
    pytest.param(projected_origin("o", target=SITE.format("app")), (SITE.format("app").lower(), "private_link_target"),
                 id="private-link"),
    pytest.param(projected_origin("o", target=SITE.format("app"), group_id="sites-Staging"),
                 (SITE.format("app").lower() + "/slots/staging", "private_link_target"), id="private-link-slot"),
    pytest.param(projected_origin("o", host="app.contoso.example"), (SITE.format("app").lower(), "host_name"),
                 id="host-name"),
    pytest.param(projected_origin("o", host="acct.blob.core.windows.net",
                                  target="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct",
                                  group_id="blob"), (None, None), id="storage-origin"),
])
def test_origin_site_id(origin, expected):
    assert origins.origin_site_id(origin, {"app.contoso.example": SITE.format("app").lower()}) == expected


def origin_rec(name, region, site=None, enabled="Enabled", priority=1):
    return {"id": f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Cdn/profiles/p/originGroups/g/origins/{name}",
            "name": name, "host_name": f"{name}.azurewebsites.net", "azure_origin_id": None,
            "private_link": {"target_id": SITE.format(site), "group_id": "sites", "private_endpoint_location": region,
                             "status": None} if site else None,
            "effective_enabled_state": enabled, "priority": priority, "region": region}


def site_row(name, location, plan, kind="app", public="Disabled"):
    return {"id": SITE.format(name), "name": name, "type": "Microsoft.Web/sites", "kind": kind, "location": location,
            "subscriptionId": "s", "tags": {"Environment": "Prod"}, "state": "Running",
            "server_farm_id": f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/serverfarms/{plan}",
            "public_network_access": public}


def plan_row(name, capacity, tier="PremiumV3"):
    return {"id": f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/serverfarms/{name}", "name": name,
            "location": "East US", "sku": {"name": "P1v3", "tier": tier, "capacity": capacity}, "zone_redundant": True}


def twin_fixture(east_capacity=2, west_capacity=2, west_tier="PremiumV3", west_region="westus", west_enabled="Enabled",
                 serving=True):
    group = {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Cdn/profiles/p/originGroups/g", "name": "g",
             "profile": "p", "serving": serving, "best_priority": 1,
             "origins": [origin_rec("east", "eastus", "app-east"),
                         origin_rec("west", west_region, "app-west", enabled=west_enabled)]}
    sites = {origins.arm_key(SITE.format(n)): site_row(n, loc, f"plan-{n}")
             for n, loc in (("app-east", "eastus"), ("app-west", "westus"), ("app-lonely", "eastus"))}
    plans = {origins.arm_key(plan_row(f"plan-{n}", c)["id"]): plan_row(f"plan-{n}", c, t)
             for n, c, t in (("app-east", east_capacity, "PremiumV3"), ("app-west", west_capacity, west_tier),
                             ("app-lonely", 1, "PremiumV3"))}
    app_origins = origins.app_service_origin_records([group], {}, sites, {}, plans, {}, "s")
    apps = origins.production_apps(sites, "s", None, [group], app_origins, plans)
    return app_origins, {a["name"]: a for a in apps}


@pytest.mark.parametrize("kwargs, ready, gaps, sufficient", [
    pytest.param({}, True, [], True, id="equal-capacity-twin"),
    pytest.param({"east_capacity": 3, "west_capacity": 1}, False, ["twin_capacity_short"], False, id="smaller-twin"),
    pytest.param({"east_capacity": 3, "west_capacity": 0, "west_tier": "ElasticPremium"}, True, [], True,
                 id="platform-scaled-twin"),
    pytest.param({"west_region": "eastus"}, False, ["no_regional_twin"], None, id="twin-in-same-region"),
    pytest.param({"west_region": None}, False, ["twin_region_unresolved"], None, id="twin-region-unresolved"),
    pytest.param({"west_enabled": "Disabled"}, False, ["no_regional_twin"], None, id="twin-disabled"),
    pytest.param({"serving": False}, False, ["not_behind_front_door"], None, id="group-not-serving"),
])
def test_regional_twin(kwargs, ready, gaps, sufficient):
    _, apps = twin_fixture(**kwargs)
    east = apps["app-east"]
    assert east["regional_twin_ready"] is ready
    assert east["twin_gaps"] == gaps
    assert east["twin_capacity_sufficient"] is sufficient


def test_app_outside_every_origin_group_is_flagged():
    _, apps = twin_fixture()
    lonely = apps["app-lonely"]
    assert (lonely["in_origin_group"], lonely["behind_front_door"], lonely["twin_gaps"]) == (
        False, False, ["not_behind_front_door"])


@pytest.mark.parametrize("subscription, gap", [
    pytest.param("s", "site_not_found", id="deleted-in-target-subscription"),
    pytest.param("other", "site_not_visible", id="outside-target-subscription"),
])
def test_origin_to_missing_site_is_not_locked(subscription, gap):
    group = {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Cdn/profiles/p/originGroups/g", "name": "g",
             "profile": "p", "serving": True, "best_priority": 1, "origins": [origin_rec("gone", None, "app-gone")]}
    [record] = origins.app_service_origin_records([group], {}, {}, {}, {}, {}, subscription)
    assert (record["site_found"], record["locked_to_front_door"], record["lockdown_gaps"]) == (False, False, [gap])


def test_app_service_summary_counts_serving_origins_and_app_types():
    app_origins, apps = twin_fixture(east_capacity=3, west_capacity=1)
    func = {**apps["app-lonely"], "app_type": "function_app"}
    summary = origins.summarize_app_services(app_origins, [apps["app-east"], apps["app-west"], func], None)
    assert summary["serving_app_service_origins"] == 2
    assert summary["serving_app_service_origins_locked_to_front_door"] == 2
    assert summary["production_web_apps"] == 2
    assert summary["production_web_apps_twin_capacity_short"] == 1
    assert summary["production_web_apps_regional_twin_ready"] == 1
    assert summary["production_function_apps_not_behind_front_door"] == 1


@pytest.mark.parametrize("tag, matched", [
    pytest.param(None, True, id="unset"),
    pytest.param("environment=prod", True, id="key-and-value-case-insensitive"),
    pytest.param("environment", True, id="key-only"),
    pytest.param("environment=dev", False, id="other-value"),
    pytest.param("tier=web", False, id="missing-key"),
])
def test_production_tag(tag, matched):
    assert origins.matches_tag({"Environment": "Prod"}, tag) is matched


def test_site_queries_cover_the_subscription_slots_and_hosts():
    queries = origins.site_queries("sub-1", [SITE.format("a").lower()], ["a.azurewebsites.net", "bad'host"])
    assert "subscriptionId =~ 'sub-1'" in queries[0] and "'microsoft.web/sites/slots'" not in queries[0]
    assert "'microsoft.web/sites/slots'" in queries[1] and SITE.format("a").lower() in queries[1]
    assert "mv-expand h = properties.enabledHostNames" in queries[2] and "bad'host" not in queries[2]


class FakeGraph:
    """Serves `rows` two per page by skip token; `repeat` keeps handing back the first token."""

    def __init__(self, rows, truncated=False, repeat=False):
        self.rows, self.truncated, self.repeat, self.requests = rows, truncated, repeat, []

    def resources(self, request):
        from types import SimpleNamespace as NS

        self.requests.append(request)
        start = int(request.options.skip_token or 0)
        end = 2 if self.repeat else start + 2
        return NS(total_records=len(self.rows), result_truncated="true" if self.truncated else "false",
                  data=self.rows[start:end], skip_token=str(end) if end < len(self.rows) else None)


@pytest.fixture
def graph_models(monkeypatch):
    from types import ModuleType
    from types import SimpleNamespace as NS

    models = ModuleType("azure.mgmt.resourcegraph.models")
    models.QueryRequest = lambda **kw: NS(**kw)
    models.QueryRequestOptions = lambda **kw: NS(**kw)
    monkeypatch.setitem(sys.modules, "azure.mgmt.resourcegraph.models", models)


def test_graph_rows_pages_across_subscriptions(graph_models):
    graph = FakeGraph([{"key": str(n)} for n in range(5)])
    assert [r["key"] for r in origins.graph_rows(graph, "resources | order by key asc")] == ["0", "1", "2", "3", "4"]
    assert len(graph.requests) == 3
    assert all(r.subscriptions is None for r in graph.requests)


@pytest.mark.parametrize("graph", [
    pytest.param(FakeGraph([{"key": "a"}], truncated=True), id="truncated"),
    pytest.param(FakeGraph([{"key": str(n)} for n in range(5)], repeat=True), id="repeated-skip-token"),
])
def test_graph_paging_failure_is_reported(graph_models, graph):
    collector = origins.Collector(origins.logger)
    assert origins.lookup_plans(graph, collector, ["/subscriptions/s/serverfarms/p"]) == {}
    assert not collector.ok


def test_lookup_queries_project_id_and_order_by_it():
    queries = (origins.region_queries(["/a"], ["a.example"]) + origins.site_queries("sub-1", ["/a"], ["a.example"])
               + origins.plan_queries(["/p"]))
    assert len(queries) == 6
    assert all(" | order by id asc" in q and " id, " in q for q in queries)
    union = origins.region_queries([], ["a.example"])[0]
    assert union.count("project key = ") == 2 and union.count(", id, location") == 2


# --- live origin health and traffic ---

HOURS = [f"2026-10-08T{h:02d}:00:00Z" for h in range(6)]


def series(origin, values, key="total", group=None):
    return {"origin": origin, "origin_group": group,
            "points": [{"time": t, "average": None, "minimum": None, "total": None,
                        **({key: v} if key != "health" else {"average": v, "minimum": v})} for t, v in zip(HOURS, values)]}


def health_group(load_balancing=None, west_header=None, regions=("eastus", "westus")):
    east, west = origin_rec("east", regions[0]), origin_rec("west", regions[1])
    west["origin_host_header"] = west_header
    return {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Cdn/profiles/p/originGroups/g", "name": "g",
            "profile": "p", "serving": True, "load_balancing": load_balancing,
            "enabled_regions": sorted({r for r in regions if r}), "origins": [east, west]}


def failover_metrics(west_host="west.azurewebsites.net"):
    return {
        "health": [series("east.azurewebsites.net:443", [100, 100, 100, 50, 0, 0], "health", group="G"),
                   series("west.azurewebsites.net:443", [100] * 6, "health", group="g")],
        "requests": [series("east.azurewebsites.net", [10, 10, 10, 0, 0, 0]),
                     series(west_host, [0, 0, 0, 5, 20, 20])],
    }


@pytest.mark.parametrize("value, host", [
    pytest.param("App.AzureWebsites.net:443", "app.azurewebsites.net", id="port-stripped"),
    pytest.param("app.azurewebsites.net", "app.azurewebsites.net", id="no-port"),
    pytest.param(None, "", id="absent"),
])
def test_metric_host(value, host):
    assert origins.metric_host(value) == host


@pytest.mark.parametrize("load_balancing, threshold", [
    pytest.param(None, 75.0, id="documented-defaults"),
    pytest.param({"sample_size": 2, "successful_samples_required": 2}, 100.0, id="all-samples"),
    pytest.param({"sample_size": 4, "successful_samples_required": 9}, 100.0, id="required-capped-at-size"),
])
def test_health_threshold(load_balancing, threshold):
    assert origins.health_threshold({"load_balancing": load_balancing}) == threshold


def test_failover_between_regions():
    [record], unmatched = origins.origin_health_records([health_group()], {fd.arm_key(health_group()["id"]).split(
        "/origingroups/")[0]: failover_metrics()})
    assert unmatched == []
    regions = {r["region"]: r for r in record["regions"]}
    assert (regions["eastus"]["requests"], regions["westus"]["requests"]) == (30, 45)
    assert regions["eastus"]["request_share_percentage"] == 40.0
    assert (regions["eastus"]["hours_healthy"], regions["eastus"]["healthy_last_hour"]) == (3, False)
    assert record["all_regions_healthy_last_hour"] is False
    assert record["regions_serving_last_hour"] == ["westus"]
    assert record["all_enabled_regions_serving_last_hour"] is False
    assert record["traffic_shifts"] == [
        {"time": HOURS[3], "serving_regions_before": ["eastus"], "serving_regions_after": ["westus"]}]
    assert len(record["hourly_by_region"]) == 6
    east = next(o for o in record["origins"] if o["origin"] == "east")
    assert (east["health_min"], east["first_hour_serving"], east["last_hour_serving"]) == (0, HOURS[0], HOURS[2])


def test_requests_match_the_origin_host_header():
    group = health_group(west_header="www.contoso.example")
    key = origins.profile_key(group["id"])
    [record], unmatched = origins.origin_health_records([group], {key: failover_metrics("www.contoso.example")})
    assert unmatched == []
    assert next(o for o in record["origins"] if o["origin"] == "west")["requests"] == 45


def test_series_for_no_known_origin_is_reported():
    group = health_group()
    key = origins.profile_key(group["id"])
    metrics = failover_metrics("gone.azurewebsites.net")
    [record], unmatched = origins.origin_health_records([group], {key: metrics})
    assert [(u["metric"], u["origin"], u["total"]) for u in unmatched] == [
        ("OriginRequestCount", "gone.azurewebsites.net", 45)]
    assert next(o for o in record["origins"] if o["origin"] == "west")["requests"] is None


def test_single_region_group_has_no_hourly_breakdown_or_shifts():
    group = health_group(regions=("eastus", "eastus"))
    key = origins.profile_key(group["id"])
    [record], _ = origins.origin_health_records([group], {key: failover_metrics()})
    assert (record["multi_region"], record["hourly_by_region"], record["traffic_shift_count"]) == (False, [], 0)
    assert record["regions_serving_last_hour"] == ["eastus"]


def with_empty_final_hour(metrics):
    for s in metrics["health"] + metrics["requests"]:
        s["points"].append({"time": "2026-10-08T06:00:00Z", "average": None, "minimum": None, "total": None})
    return metrics


def test_last_hour_is_the_newest_hour_with_data():
    group = health_group()
    key = origins.profile_key(group["id"])
    [record], _ = origins.origin_health_records([group], {key: with_empty_final_hour(failover_metrics())})
    assert record["last_hour"] == HOURS[-1]
    assert record["regions_serving_last_hour"] == ["westus"]
    assert record["all_regions_healthy_last_hour"] is False
    assert len(record["hourly_by_region"]) == 7
    west = next(o for o in record["origins"] if o["origin"] == "west")
    assert west["last_hour_health_avg"] == 100


def test_last_hour_is_the_profiles_newest_hour_with_data():
    group = health_group()
    stale = {**health_group(), "id": group["id"].replace("/originGroups/g", "/originGroups/stale"), "name": "stale",
             "origins": [origin_rec("old-east", "eastus"), origin_rec("old-west", "westus")]}
    metrics = failover_metrics()
    metrics["health"].append(series("old-east.azurewebsites.net", [100], "health", group="stale"))
    metrics["requests"].append(series("old-east.azurewebsites.net", [10]))
    records, _ = origins.origin_health_records([group, stale], {origins.profile_key(group["id"]): metrics})
    old = next(r for r in records if r["origin_group"] == "stale")
    assert old["last_hour"] == HOURS[-1] and old["has_traffic"] is True
    assert (old["regions_serving_last_hour"], old["all_regions_healthy_last_hour"]) == ([], None)
    assert all(r["healthy_last_hour"] is None and r["serving_last_hour"] is False for r in old["regions"])
    summary = origins.summarize_health([old], [], 7, ("start", "end"))
    assert summary["serving_groups_all_regions_healthy_last_hour"] == 0
    assert summary["serving_multi_region_groups_all_regions_serving_last_hour"] == 0


def test_health_data_counts_an_unresolved_region():
    group = health_group(regions=(None, None))
    key = origins.profile_key(group["id"])
    [record], _ = origins.origin_health_records([group], {key: with_empty_final_hour(failover_metrics())})
    assert [r["region"] for r in record["regions"]] == ["unresolved"]
    assert (record["has_health_data"], record["all_regions_healthy_last_hour"]) == (True, None)


def test_group_without_metrics_has_no_data():
    [record], _ = origins.origin_health_records([health_group()], {})
    assert (record["has_health_data"], record["has_traffic"], record["all_regions_healthy_last_hour"]) == (
        False, False, None)


def test_health_summary():
    group = health_group()
    key = origins.profile_key(group["id"])
    records, unmatched = origins.origin_health_records([group], {key: failover_metrics()})
    summary = origins.summarize_health(records, unmatched, 7, ("start", "end"))
    assert summary["serving_multi_region_groups"] == 1
    assert summary["serving_multi_region_groups_with_traffic_shift"] == 1
    assert summary["serving_groups_region_unhealthy_last_hour"] == 1
    assert summary["regions_serving_traffic"] == ["eastus", "westus"]
    assert summary["metrics_lookback_days"] == 7


def test_project_metric_series_reads_dimensions_and_hours():
    from types import SimpleNamespace as NS

    point = NS(time_stamp=datetime(2026, 10, 8, 3, tzinfo=timezone.utc), average=None, minimum=None, total=7.0)
    ts = NS(metadatavalues=[NS(name=NS(value="Origin"), value="app.azurewebsites.net")], data=[point])
    [s] = origins.project_metric_series(NS(value=[NS(timeseries=[ts])]))
    assert s == {"origin": "app.azurewebsites.net", "origin_group": None,
                 "points": [{"time": "2026-10-08T03:00:00Z", "average": None, "minimum": None, "total": 7.0}]}


def test_metrics_window_uses_whole_hours():
    assert origins.metrics_window(7, datetime(2026, 10, 8, 3, 41, tzinfo=timezone.utc)) == (
        "2026-10-01T03:00:00Z", "2026-10-08T03:00:00Z")


@pytest.mark.parametrize("raw, days, failed", [
    pytest.param(None, 7, False, id="default"),
    pytest.param("90", 30, False, id="clamped"),
    pytest.param("week", 7, True, id="invalid"),
])
def test_lookback_days(monkeypatch, raw, days, failed):
    if raw is None:
        monkeypatch.delenv(origins.LOOKBACK_ENV, raising=False)
    else:
        monkeypatch.setenv(origins.LOOKBACK_ENV, raw)
    collector = origins.Collector(origins.logger)
    assert origins.lookback_days(collector) == days
    assert (not collector.ok) is failed
