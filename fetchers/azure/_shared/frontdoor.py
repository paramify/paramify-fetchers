"""Shared Azure Front Door helpers: WAF policy projection, its blocking verdict, and wire-key reads."""

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
# First GA api-version whose security policies carry isProfileLevel and associations[].routes.
SECURITY_POLICY_API_VERSION = "2026-07-01"


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
                blocking += action != "Log"
                group_blocking += action != "Log"
        if group["rules"] and not group_enabled:
            fully_off.append(name)
        if group["rules"] and not group_blocking:
            not_blocking.append(name)
    return {"rule_definition_found": True, "total_rules": total, "enabled_rules": enabled,
            "blocking_rules": blocking, "fully_disabled_rule_groups": sorted(fully_off),
            "groups_without_blocking_rules": sorted(not_blocking)}


def rule_set_record(rule_set: dict, definitions: Optional[dict] = None) -> dict:
    disabled_groups, disabled_rules, log_only_rules = [], [], []
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
    is_default = rule_set["rule_set_type"] in DEFAULT_RULE_SET_TYPES
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
        "total_exclusions": exclusion_count,
        **effective_rule_counts(rule_set, definition, disabled_groups),
        "latest_version_available": index["latest"].get(rs_type),
    }


def custom_rule_record(rule: dict) -> dict:
    return {**rule, "enabled_state": rule["enabled_state"] or "Enabled"}


def not_blocking_reasons(enabled_state: str, mode, rule_sets: List[dict]) -> List[str]:
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
    elif not any(rs["effective_action"] in ENFORCING_ACTIONS for rs in default_sets):
        reasons.append("default_rule_set_log_only")
    return reasons


def waf_policy_record(policy: dict, definitions: Optional[dict] = None) -> dict:
    rule_sets = [rule_set_record(rs, definitions) for rs in policy["managed_rule_sets"]]
    core = next((rs for rs in rule_sets if rs["is_default_rule_set"]), None)
    custom_rules = [custom_rule_record(r) for r in policy["custom_rules"]]
    enabled_state = policy["enabled_state"] or "Enabled"
    reasons = not_blocking_reasons(enabled_state, policy["mode"], rule_sets)
    return {
        **policy,
        "resource_group": resource_group_from_id(policy["id"]),
        "enabled_state": enabled_state,
        "managed_rule_sets": rule_sets,
        "custom_rules": custom_rules,
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
