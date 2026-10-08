"""Shared Azure Front Door helpers: the profile/endpoint/route/domain walk, WAF policy verdicts, wire-key reads."""

from __future__ import annotations

from collections import Counter
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from azure_common import (
    Collector,
    arm_client_kwargs,
    model_attr,
    resource_group_from_id,
)

FRONT_DOOR_SKUS = ("Standard_AzureFrontDoor", "Premium_AzureFrontDoor")
DEFAULT_RULE_SET_TYPES = ("DefaultRuleSet", "Microsoft_DefaultRuleSet")
ENFORCING_ACTIONS = ("Block", "Redirect")
# Managed-rule actions that stop or score a request; Allow and Log let it through.
BLOCKING_RULE_ACTIONS = ("Block", "Redirect", "AnomalyScoring")
# First GA api-version whose security policies carry isProfileLevel and associations[].routes.
SECURITY_POLICY_API_VERSION = "2026-07-01"
# Documented API defaults when a route omits them.
DEFAULT_SUPPORTED_PROTOCOLS = ["Http", "Https"]
DEFAULT_HTTPS_REDIRECT = "Disabled"
DEFAULT_FORWARDING_PROTOCOL = "MatchRequest"


def wire(model: Any, *keys: str) -> Any:
    """Read a field the SDK does not model, by its wire key; the hybrid models keep them."""
    cur = model
    for key in keys:
        if cur is None or not hasattr(cur, "get"):
            return None
        cur = cur.get(key)
    return cur


def arm_key(resource_id: Optional[str]) -> str:
    """ARM ids are case-insensitive and Azure mixes spellings; compare on this."""
    return str(resource_id or "").lower().rstrip("/")


def enum_list(values: Any) -> List[str]:
    return [v.value if isinstance(v, Enum) else v for v in (values or [])]


# --- WAF policy projection ---

def project_exclusion(exclusion) -> dict:
    return {
        "match_variable": model_attr(exclusion, "match_variable"),
        "selector_match_operator": model_attr(exclusion, "selector_match_operator"),
        "selector": model_attr(exclusion, "selector"),
    }


def project_rule_override(rule) -> dict:
    return {
        "rule_id": model_attr(rule, "rule_id"),
        "enabled_state": model_attr(rule, "enabled_state"),
        "action": model_attr(rule, "action"),
        "exclusions": [project_exclusion(e) for e in (model_attr(rule, "exclusions") or [])],
    }


def project_rule_set(rule_set) -> dict:
    return {
        "rule_set_type": model_attr(rule_set, "rule_set_type"),
        "rule_set_version": model_attr(rule_set, "rule_set_version"),
        "rule_set_action": model_attr(rule_set, "rule_set_action"),
        "exclusions": [project_exclusion(e) for e in (model_attr(rule_set, "exclusions") or [])],
        "rule_group_overrides": [
            {
                "rule_group_name": model_attr(group, "rule_group_name"),
                "rules": (
                    None
                    if model_attr(group, "rules") is None
                    else [project_rule_override(r) for r in model_attr(group, "rules")]
                ),
                "exclusions": [project_exclusion(e) for e in (model_attr(group, "exclusions") or [])],
            }
            for group in (model_attr(rule_set, "rule_group_overrides") or [])
        ],
    }


def project_custom_rule(rule) -> dict:
    return {
        "name": model_attr(rule, "name"),
        "priority": model_attr(rule, "priority"),
        "enabled_state": model_attr(rule, "enabled_state"),
        "rule_type": model_attr(rule, "rule_type"),
        "action": model_attr(rule, "action"),
        "rate_limit_threshold": model_attr(rule, "rate_limit_threshold"),
        "rate_limit_duration_in_minutes": model_attr(rule, "rate_limit_duration_in_minutes"),
        "match_condition_count": len(model_attr(rule, "match_conditions") or []),
        "match_conditions": [
            {
                "match_variable": model_attr(c, "match_variable"),
                "selector": model_attr(c, "selector"),
                "operator": model_attr(c, "operator"),
                "negate_condition": model_attr(c, "negate_condition"),
                "match_value": list(model_attr(c, "match_value") or []),
            }
            for c in (model_attr(rule, "match_conditions") or [])
        ],
        "group_by": [model_attr(g, "variable_name") for g in (model_attr(rule, "group_by") or [])],
    }


def project_waf_policy(policy) -> dict:
    props = model_attr(policy, "properties")
    settings = model_attr(props, "policy_settings")
    managed = model_attr(props, "managed_rules")
    return {
        "id": model_attr(policy, "id"),
        "name": model_attr(policy, "name"),
        "location": model_attr(policy, "location"),
        "sku": model_attr(model_attr(policy, "sku"), "name"),
        "enabled_state": model_attr(settings, "enabled_state"),
        "mode": model_attr(settings, "mode"),
        "request_body_check": model_attr(settings, "request_body_check"),
        "provisioning_state": model_attr(props, "provisioning_state"),
        "resource_state": model_attr(props, "resource_state"),
        "managed_rule_sets": [project_rule_set(rs) for rs in (model_attr(managed, "managed_rule_sets") or [])],
        "exceptions": list(wire(managed, "exceptionsList", "exceptions") or []),
        "custom_rules": [
            project_custom_rule(r) for r in (model_attr(model_attr(props, "custom_rules"), "rules") or [])
        ],
        "security_policy_links": [
            model_attr(link, "id") for link in (model_attr(props, "security_policy_links") or [])
        ],
    }


def project_rule_set_definition(definition) -> dict:
    props = model_attr(definition, "properties")
    return {
        "rule_set_type": model_attr(props, "rule_set_type"),
        "rule_set_version": model_attr(props, "rule_set_version"),
        "rule_groups": [
            {
                "rule_group_name": model_attr(group, "rule_group_name"),
                "rules": [
                    {
                        "rule_id": model_attr(rule, "rule_id"),
                        "default_state": model_attr(rule, "default_state"),
                        "default_action": model_attr(rule, "default_action"),
                    }
                    for rule in (model_attr(group, "rules") or [])
                ],
            }
            for group in (model_attr(props, "rule_groups") or [])
        ],
    }


# --- WAF policy verdict (flat dicts in, records out) ---

def _version_key(version: str):
    try:
        return tuple(int(part) for part in str(version).split("."))
    except ValueError:
        return None


def definition_index(definitions: List[dict]) -> dict:
    """Rule-set definitions keyed by (type, version), plus the newest numeric version per type."""
    by_key, latest = {}, {}
    for d in definitions:
        rs_type = str(d["rule_set_type"] or "").lower()
        by_key[(rs_type, d["rule_set_version"])] = d
        key = _version_key(d["rule_set_version"])
        if key is not None and (rs_type not in latest or key > _version_key(latest[rs_type])):
            latest[rs_type] = d["rule_set_version"]
    return {"by_key": by_key, "latest": latest}


def effective_rule_counts(rule_set: dict, definition: Optional[dict], disabled_groups: List[str]) -> dict:
    """Each defined rule's state after overrides: group override with no rules, else the rule's override, else its default."""
    if definition is None:
        return {"rule_definition_found": False, "total_rules": None, "enabled_rules": None,
                "blocking_rules": None, "fully_disabled_rule_groups": None, "groups_without_blocking_rules": None}
    groups_off = {str(g).lower() for g in disabled_groups}
    overrides = {
        (str(group["rule_group_name"]).lower(), str(rule["rule_id"])): rule
        for group in rule_set["rule_group_overrides"]
        for rule in (group["rules"] or [])
    }
    total = enabled = blocking = 0
    fully_off, not_blocking = [], []
    for group in definition["rule_groups"]:
        name = group["rule_group_name"]
        group_enabled = group_blocking = 0
        for rule in group["rules"]:
            override = overrides.get((str(name).lower(), str(rule["rule_id"])))
            if str(name).lower() in groups_off:
                state, action = "Disabled", None
            elif override is not None:
                state, action = override["enabled_state"] or "Disabled", override["action"] or rule["default_action"]
            else:
                state, action = rule["default_state"] or "Enabled", rule["default_action"]
            total += 1
            if state == "Enabled":
                enabled += 1
                group_enabled += 1
                blocking += action in BLOCKING_RULE_ACTIONS
                group_blocking += action in BLOCKING_RULE_ACTIONS
        if group["rules"] and not group_enabled:
            fully_off.append(name)
        if group["rules"] and not group_blocking:
            not_blocking.append(name)
    return {"rule_definition_found": True, "total_rules": total, "enabled_rules": enabled,
            "blocking_rules": blocking, "fully_disabled_rule_groups": sorted(fully_off),
            "groups_without_blocking_rules": sorted(not_blocking)}


def rule_set_record(rule_set: dict, definitions: Optional[dict] = None) -> dict:
    disabled_groups, disabled_rules, log_only_rules, allow_rules = [], [], [], []
    exclusion_count = len(rule_set["exclusions"])
    for group in rule_set["rule_group_overrides"]:
        name = group["rule_group_name"]
        exclusion_count += len(group["exclusions"])
        if not group["rules"]:
            disabled_groups.append(name)
            continue
        for rule in group["rules"]:
            exclusion_count += len(rule["exclusions"])
            ref = {"rule_group": name, "rule_id": rule["rule_id"]}
            if (rule["enabled_state"] or "Disabled") == "Disabled":
                disabled_rules.append(ref)
            elif rule["action"] == "Log":
                log_only_rules.append(ref)
            elif rule["action"] == "Allow":
                allow_rules.append(ref)
    is_default = str(rule_set["rule_set_type"] or "").lower() in {t.lower() for t in DEFAULT_RULE_SET_TYPES}
    index = definitions or {"by_key": {}, "latest": {}}
    rs_type = str(rule_set["rule_set_type"] or "").lower()
    definition = index["by_key"].get((rs_type, rule_set["rule_set_version"]))
    return {
        **rule_set,
        "effective_action": rule_set["rule_set_action"] or ("Block" if is_default else None),
        "is_default_rule_set": is_default,
        "disabled_rule_groups": sorted(g for g in disabled_groups if g),
        "disabled_rules": disabled_rules,
        "log_only_rules": log_only_rules,
        "allow_rules": allow_rules,
        "total_exclusions": exclusion_count,
        **effective_rule_counts(rule_set, definition, disabled_groups),
        "latest_version_available": index["latest"].get(rs_type),
    }


def custom_rule_record(rule: dict) -> dict:
    conditions = rule["match_conditions"]
    return {
        **rule,
        "enabled_state": rule["enabled_state"] or "Enabled",
        "matches_all_requests": bool(conditions)
        and all(c["operator"] == "Any" and not c["negate_condition"] for c in conditions),
    }


def allows_all_requests(rule: dict) -> bool:
    """An enabled match rule that allows every request; custom rules run before managed rules."""
    return (rule["enabled_state"] == "Enabled" and rule["rule_type"] == "MatchRule"
            and rule["action"] == "Allow" and rule["matches_all_requests"])


def not_blocking_reasons(enabled_state: str, mode, rule_sets: List[dict], custom_rules: List[dict]) -> List[str]:
    reasons = []
    if enabled_state != "Enabled":
        reasons.append("policy_disabled")
    if mode is None:
        reasons.append("mode_unset")
    elif mode != "Prevention":
        reasons.append("mode_detection")
    default_sets = [rs for rs in rule_sets if rs["is_default_rule_set"]]
    if not default_sets:
        reasons.append("no_default_rule_set")
    else:
        if not any(rs["effective_action"] in ENFORCING_ACTIONS for rs in default_sets):
            reasons.append("default_rule_set_log_only")
        if not all(rs["rule_definition_found"] for rs in default_sets):
            reasons.append("rule_definition_not_found")
        elif any(rs["groups_without_blocking_rules"] for rs in default_sets):
            reasons.append("rule_groups_not_blocking")
    if any(allows_all_requests(r) for r in custom_rules):
        reasons.append("allow_all_custom_rule")
    return reasons


def waf_policy_record(policy: dict, definitions: Optional[dict] = None) -> dict:
    rule_sets = [rule_set_record(rs, definitions) for rs in policy["managed_rule_sets"]]
    core = next((rs for rs in rule_sets if rs["is_default_rule_set"]), None)
    custom_rules = [custom_rule_record(r) for r in policy["custom_rules"]]
    enabled_state = policy["enabled_state"] or "Enabled"
    reasons = not_blocking_reasons(enabled_state, policy["mode"], rule_sets, custom_rules)
    return {
        **policy,
        "resource_group": resource_group_from_id(policy["id"]),
        "enabled_state": enabled_state,
        "managed_rule_sets": rule_sets,
        "custom_rules": custom_rules,
        "allow_all_custom_rules": [r["name"] for r in custom_rules if allows_all_requests(r)],
        "rate_limit_rules": sum(
            1 for r in custom_rules if r["rule_type"] == "RateLimitRule" and r["enabled_state"] == "Enabled"
        ),
        "disabled_managed_rules": sum(len(rs["disabled_rules"]) for rs in rule_sets),
        "disabled_managed_rule_groups": sum(len(rs["disabled_rule_groups"]) for rs in rule_sets),
        "default_rule_set_version": core["rule_set_version"] if core else None,
        "default_rule_set_latest_version": core["latest_version_available"] if core else None,
        "default_rule_set_total_rules": core["total_rules"] if core else None,
        "default_rule_set_enabled_rules": core["enabled_rules"] if core else None,
        "default_rule_set_blocking_rules": core["blocking_rules"] if core else None,
        "default_rule_set_fully_disabled_groups": core["fully_disabled_rule_groups"] if core else None,
        "default_rule_set_groups_without_blocking_rules": core["groups_without_blocking_rules"] if core else None,
        "associated": bool(policy["security_policy_links"]),
        "blocking": not reasons,
        "not_blocking_reasons": reasons,
    }


def select_front_door(projected: List[dict]) -> Tuple[List[dict], Dict[str, int]]:
    kept = [p for p in projected if p["sku"] in FRONT_DOOR_SKUS]
    skipped = Counter(str(p["sku"]) for p in projected if p["sku"] not in FRONT_DOOR_SKUS)
    return kept, dict(sorted(skipped.items()))


# --- Front Door topology projection (profiles, endpoints, routes, custom domains) ---

def project_profile(profile) -> dict:
    return {
        "id": model_attr(profile, "id"),
        "name": model_attr(profile, "name"),
        "sku": model_attr(model_attr(profile, "sku"), "name"),
        "resource_state": model_attr(model_attr(profile, "properties"), "resource_state"),
    }


def project_endpoint(endpoint) -> dict:
    props = model_attr(endpoint, "properties")
    return {
        "id": model_attr(endpoint, "id"),
        "name": model_attr(endpoint, "name"),
        "host_name": model_attr(props, "host_name"),
        "enabled_state": model_attr(props, "enabled_state"),
        "deployment_status": model_attr(props, "deployment_status"),
    }


def project_reference(ref) -> dict:
    return {"id": model_attr(ref, "id"), "is_active": model_attr(ref, "is_active")}


def project_route(route) -> dict:
    props = model_attr(route, "properties")
    return {
        "id": model_attr(route, "id"),
        "name": model_attr(route, "name"),
        "enabled_state": model_attr(props, "enabled_state"),
        "supported_protocols": enum_list(model_attr(props, "supported_protocols")),
        "https_redirect": model_attr(props, "https_redirect"),
        "forwarding_protocol": model_attr(props, "forwarding_protocol"),
        "patterns_to_match": list(model_attr(props, "patterns_to_match") or []),
        "link_to_default_domain": model_attr(props, "link_to_default_domain"),
        "custom_domains": [project_reference(d) for d in (model_attr(props, "custom_domains") or [])],
        "origin_group_id": model_attr(model_attr(props, "origin_group"), "id"),
        "origin_path": model_attr(props, "origin_path"),
        "rule_set_ids": [model_attr(r, "id") for r in (model_attr(props, "rule_sets") or [])],
    }


def project_custom_domain(domain) -> dict:
    props = model_attr(domain, "properties")
    tls = model_attr(props, "tls_settings")
    suites = model_attr(tls, "customized_cipher_suite_set")
    return {
        "id": model_attr(domain, "id"),
        "name": model_attr(domain, "name"),
        "host_name": model_attr(props, "host_name"),
        "domain_validation_state": model_attr(props, "domain_validation_state"),
        "certificate_type": model_attr(tls, "certificate_type"),
        "minimum_tls_version": model_attr(tls, "minimum_tls_version"),
        "cipher_suite_set_type": model_attr(tls, "cipher_suite_set_type"),
        "customized_cipher_suites_tls12": enum_list(model_attr(suites, "cipher_suite_set_for_tls12")),
        "customized_cipher_suites_tls13": enum_list(model_attr(suites, "cipher_suite_set_for_tls13")),
        "secret_id": model_attr(model_attr(tls, "secret"), "id"),
    }


def route_hosts(endpoint: dict, route: dict, domains_by_key: dict) -> List[dict]:
    """Hosts a route serves: its custom domains, plus the endpoint's own domain when linked."""
    hosts = []
    for ref in route["custom_domains"]:
        domain = domains_by_key.get(arm_key(ref["id"]), {})
        hosts.append({
            "id": ref["id"],
            "host_name": domain.get("host_name"),
            "kind": "custom_domain",
            "is_active": ref["is_active"],
        })
    if route["link_to_default_domain"] == "Enabled":
        hosts.append({"id": endpoint["id"], "host_name": endpoint["host_name"], "kind": "endpoint_default", "is_active": None})
    return hosts


def route_serving(endpoint: dict, route: dict) -> bool:
    return endpoint["enabled_state"] == "Enabled" and route["enabled_state"] == "Enabled"


# --- rule sets: HTTP→HTTPS redirects and origin overrides ---

def project_rule_condition(condition) -> dict:
    params = model_attr(condition, "parameters")
    return {
        "name": model_attr(condition, "name"),
        "operator": model_attr(params, "operator"),
        "negate_condition": model_attr(params, "negate_condition"),
        "match_values": enum_list(model_attr(params, "match_values")),
    }


def project_rule_action(action) -> dict:
    params = model_attr(action, "parameters")
    override = model_attr(params, "origin_group_override")
    return {
        "name": model_attr(action, "name"),
        "redirect_type": model_attr(params, "redirect_type"),
        "destination_protocol": model_attr(params, "destination_protocol"),
        "origin_group_override_id": model_attr(model_attr(override, "origin_group"), "id"),
        "forwarding_protocol_override": model_attr(override, "forwarding_protocol"),
        "overrides_origin_group": override is not None,
    }


def project_rule(rule) -> dict:
    props = model_attr(rule, "properties")
    return {
        "id": model_attr(rule, "id"),
        "name": model_attr(rule, "name"),
        "order": model_attr(props, "order"),
        "match_processing_behavior": model_attr(props, "match_processing_behavior"),
        "conditions": [project_rule_condition(c) for c in (model_attr(props, "conditions") or [])],
        "actions": [project_rule_action(a) for a in (model_attr(props, "actions") or [])],
    }


def redirects_all_http(rule: dict) -> bool:
    """A redirect to Https with no condition, or only a request-scheme condition that matches exactly HTTP."""
    conditions = rule["conditions"]
    if len(conditions) > 1:
        return False
    if conditions:
        cond = conditions[0]
        values = {str(v).upper() for v in cond["match_values"]}
        if cond["name"] != "RequestScheme" or (cond["operator"] or "Equal") != "Equal":
            return False
        if not ((values == {"HTTP"} and not cond["negate_condition"]) or (values == {"HTTPS"} and cond["negate_condition"])):
            return False
    return any(a["name"] == "UrlRedirect" and a["destination_protocol"] == "Https" for a in rule["actions"])


def attached_rules(rule_set_ids: List[str], rule_sets_by_key: dict) -> List[Tuple[dict, dict]]:
    """(rule set, rule) in evaluation order: the route's rule-set order, then each set's rule order."""
    ordered = []
    for rs_id in rule_set_ids:
        rule_set = rule_sets_by_key.get(arm_key(rs_id))
        if rule_set:
            ordered += [(rule_set, rule) for rule in rule_set["rules"]]
    return ordered


def rule_set_https_redirect(rule_set_ids: List[str], rule_sets_by_key: dict) -> Optional[dict]:
    for rule_set, rule in attached_rules(rule_set_ids, rule_sets_by_key):
        if redirects_all_http(rule):
            return {"rule_set": rule_set["name"], "rule": rule["name"]}
        # An earlier rule that stops evaluation may catch HTTP first.
        if rule["match_processing_behavior"] == "Stop":
            return None
    return None


def https_only_basis(protocols: List[str], https_redirect: str, rule_set_redirect: bool) -> Optional[str]:
    if "Http" not in protocols:
        return "https_only_protocols" if "Https" in protocols else None
    if https_redirect == "Enabled":
        return "https_redirect"
    if rule_set_redirect:
        return "rule_set_redirect"
    return None


def route_https(route: dict, rule_sets_by_key: dict) -> dict:
    """Whether a route only ever handles HTTPS requests, applying the API defaults for absent fields."""
    protocols = route["supported_protocols"] or DEFAULT_SUPPORTED_PROTOCOLS
    redirect = route["https_redirect"] or DEFAULT_HTTPS_REDIRECT
    rule = rule_set_https_redirect(route["rule_set_ids"], rule_sets_by_key)
    basis = https_only_basis(protocols, redirect, rule is not None)
    return {
        "effective_supported_protocols": protocols,
        "effective_https_redirect": redirect,
        "https_redirect_rule": rule if basis == "rule_set_redirect" else None,
        "accepts_http": "Http" in protocols,
        "https_only": basis is not None,
        "https_only_basis": basis,
    }


# --- Front Door topology collection (lazy azure imports) ---

def cdn_client(subscription_id: str, cred, collector: Collector, api_version: Optional[str] = None):
    from azure.mgmt.cdn import CdnManagementClient

    kwargs = {"credential": cred, "subscription_id": subscription_id, **arm_client_kwargs()}
    if api_version:
        # Pinned per client: a per-call api_version kwarg is silently ignored by azure-mgmt-cdn 14.
        kwargs["api_version"] = api_version
    label = f"cdn.CdnManagementClient (init{', ' + api_version if api_version else ''})"
    return collector.guard(label, lambda: CdnManagementClient(**kwargs))


def front_door_profiles(cdn, collector: Collector) -> Tuple[List[dict], Dict[str, int]]:
    """Standard/Premium profiles sorted by id, and a count of the other CDN SKUs skipped."""
    projected = collector.guard("cdn.profiles.list", lambda: [project_profile(p) for p in cdn.profiles.list()], default=[])
    kept, skipped = select_front_door(projected)
    return sorted(kept, key=lambda p: arm_key(p["id"])), skipped


def endpoints_with_routes(cdn, collector: Collector, profile: dict) -> List[dict]:
    rg, name = resource_group_from_id(profile["id"]), profile["name"]
    endpoints = collector.guard(
        f"cdn.afd_endpoints.list_by_profile({name})",
        lambda: [project_endpoint(e) for e in cdn.afd_endpoints.list_by_profile(rg, name)],
        default=[],
    )
    for endpoint in endpoints:
        endpoint["routes"] = collector.guard(
            f"cdn.routes.list_by_endpoint({name}/{endpoint['name']})",
            lambda: [project_route(r) for r in cdn.routes.list_by_endpoint(rg, name, endpoint["name"])],
            default=[],
        )
    return endpoints


def rule_sets_with_rules(cdn, collector: Collector, profile: dict) -> Dict[str, dict]:
    """Every rule set in the profile with its rules in order, keyed by lower-cased id."""
    rg, name = resource_group_from_id(profile["id"]), profile["name"]
    rule_sets = collector.guard(
        f"cdn.rule_sets.list_by_profile({name})",
        lambda: [{"id": model_attr(rs, "id"), "name": model_attr(rs, "name")} for rs in cdn.rule_sets.list_by_profile(rg, name)],
        default=[],
    )
    for rule_set in rule_sets:
        rules = collector.guard(
            f"cdn.rules.list_by_rule_set({name}/{rule_set['name']})",
            lambda: [project_rule(r) for r in cdn.rules.list_by_rule_set(rg, name, rule_set["name"])],
            default=[],
        )
        rule_set["rules"] = sorted(rules, key=lambda r: (r["order"] is None, r["order"] or 0))
    return {arm_key(rs["id"]): rs for rs in rule_sets}


def custom_domains(cdn, collector: Collector, profile: dict) -> List[dict]:
    rg, name = resource_group_from_id(profile["id"]), profile["name"]
    return collector.guard(
        f"cdn.afd_custom_domains.list_by_profile({name})",
        lambda: [project_custom_domain(d) for d in cdn.afd_custom_domains.list_by_profile(rg, name)],
        default=[],
    )


def collect_waf_policies(subscription_id: str, cred, collector: Collector) -> Tuple[List[dict], dict]:
    """Every Front Door WAF policy in the subscription (all SKUs; callers filter), and the managed rule-set definitions index."""
    from azure.mgmt.frontdoor import FrontDoorManagementClient

    client = collector.guard(
        "frontdoor.FrontDoorManagementClient (init)",
        lambda: FrontDoorManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        ),
    )
    if client is None:
        return [], definition_index([])
    policies = collector.guard(
        "frontdoor.policies.list_by_subscription",
        lambda: [project_waf_policy(p) for p in client.policies.list_by_subscription()],
        default=[],
    )
    definitions = collector.guard(
        "frontdoor.managed_rule_sets.list",
        lambda: [project_rule_set_definition(d) for d in client.managed_rule_sets.list()],
        default=[],
    )
    return policies, definition_index(definitions)
