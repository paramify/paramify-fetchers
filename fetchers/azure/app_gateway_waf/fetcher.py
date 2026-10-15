#!/usr/bin/env python3
"""Azure Application Gateway WAF enforcement per listener and the WAF policies behind it."""

import logging
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from app_gateway import (  # noqa: E402
    arm_id_key,
    frontend_ip_types,
    frontend_ports,
    gateway_identity,
    index_by_id,
    ref_id,
    rules_by_listener,
    run_fetcher,
)
from azure_common import (  # noqa: E402
    Collector,
    arm_client_kwargs,
    basename,
    model_attr,
    resource_group_from_id,
)

logger = logging.getLogger("azure_app_gateway_waf")

# Reading a referenced policy can be refused or 404 without the collection being broken.
UNREADABLE_STATUS = {401: "not_authorized", 403: "not_authorized", 404: "not_found"}


def subscription_from_id(resource_id: str | None) -> str | None:
    parts = str(resource_id or "").split("/")
    lowered = [p.lower() for p in parts]
    return parts[lowered.index("subscriptions") + 1] if "subscriptions" in lowered else None


def policy_record(policy) -> dict:
    settings = model_attr(policy, "policy_settings")
    managed = model_attr(policy, "managed_rules")
    rule_sets = []
    for rule_set in model_attr(managed, "managed_rule_sets") or []:
        overrides = [
            {
                "rule_group": model_attr(group, "rule_group_name"),
                "rule_id": model_attr(rule, "rule_id"),
                "state": model_attr(rule, "state"),
                "action": model_attr(rule, "action"),
            }
            for group in (model_attr(rule_set, "rule_group_overrides") or [])
            for rule in (model_attr(group, "rules") or [])
        ]
        rule_sets.append({
            "rule_set_type": model_attr(rule_set, "rule_set_type"),
            "rule_set_version": model_attr(rule_set, "rule_set_version"),
            "rule_overrides": overrides,
            "disabled_rules": [o for o in overrides if o["state"] == "Disabled"],
            "computed_disabled_rules": [
                {"rule_group": model_attr(g, "rule_group_name"), "rules": list(model_attr(g, "rules") or [])}
                for g in (model_attr(rule_set, "computed_disabled_rules") or [])
            ],
        })
    custom_rules = [
        {
            "name": model_attr(rule, "name"),
            "priority": model_attr(rule, "priority"),
            "rule_type": model_attr(rule, "rule_type"),
            "action": model_attr(rule, "action"),
            "state": model_attr(rule, "state"),
            "rate_limit_threshold": model_attr(rule, "rate_limit_threshold"),
            "rate_limit_duration": model_attr(rule, "rate_limit_duration"),
        }
        for rule in (model_attr(policy, "custom_rules") or [])
    ]
    resource_id = model_attr(policy, "id")
    return {
        "id": resource_id,
        "name": model_attr(policy, "name"),
        "resource_group": resource_group_from_id(resource_id),
        "location": model_attr(policy, "location"),
        "resolved": True,
        "read_status": "read",
        "read_error": None,
        "state": model_attr(settings, "state"),
        "mode": model_attr(settings, "mode"),
        "request_body_check": model_attr(settings, "request_body_check"),
        "managed_rule_sets": rule_sets,
        "disabled_rule_count": sum(len(rs["disabled_rules"]) for rs in rule_sets),
        "rule_overrides_without_state": sum(1 for rs in rule_sets for o in rs["rule_overrides"] if o["state"] is None),
        "exclusion_count": len(model_attr(managed, "exclusions") or []),
        "custom_rules": custom_rules,
        "rate_limit_rules": sum(
            1 for r in custom_rules if r["rule_type"] == "RateLimitRule" and r["state"] != "Disabled"
        ),
        "attached_application_gateways": len(model_attr(policy, "application_gateways") or []),
        "attached_http_listeners": len(model_attr(policy, "http_listeners") or []),
        "attached_path_rules": len(model_attr(policy, "path_based_rules") or []),
    }


def unresolved_policy(policy_id: str, read_status: str | None = None, read_error: str | None = None) -> dict:
    return {"id": policy_id, "name": basename(policy_id), "resource_group": resource_group_from_id(policy_id),
            "resolved": False, "read_status": read_status, "read_error": read_error, "state": None, "mode": None}


def legacy_waf(gateway) -> dict | None:
    config = model_attr(gateway, "web_application_firewall_configuration")
    if config is None:
        return None
    enabled = model_attr(config, "enabled")
    return {
        "enabled": enabled,
        "state": None if enabled is None else ("Enabled" if enabled else "Disabled"),
        "mode": model_attr(config, "firewall_mode"),
        "rule_set_type": model_attr(config, "rule_set_type"),
        "rule_set_version": model_attr(config, "rule_set_version"),
        "disabled_rule_groups": len(model_attr(config, "disabled_rule_groups") or []),
        "exclusion_count": len(model_attr(config, "exclusions") or []),
    }


def enforcing(state, mode) -> bool | None:
    if state is None or mode is None:
        return None
    return state == "Enabled" and mode == "Prevention"


def listener_waf_records(gateway, policies: dict) -> list[dict]:
    """One record per L7 listener with the WAF that applies to it; WAF never applies to L4 listeners."""
    ports = frontend_ports(gateway)
    ip_types = frontend_ip_types(gateway)
    path_maps = index_by_id(model_attr(gateway, "url_path_maps"))
    listener_rules = rules_by_listener(gateway)
    gateway_policy_id = ref_id(gateway, "firewall_policy")
    legacy = legacy_waf(gateway)

    def policy_summary(policy_id):
        policy = policies.get(arm_id_key(policy_id)) or unresolved_policy(policy_id)
        return {"policy": policy["name"], "policy_id": policy_id, "resolved": policy["resolved"],
                "state": policy["state"], "mode": policy["mode"]}

    records = []
    for listener in model_attr(gateway, "http_listeners") or []:
        listener_policy_id = ref_id(listener, "firewall_policy")
        if listener_policy_id or gateway_policy_id:
            source = "listener" if listener_policy_id else "gateway"
            effective = policy_summary(listener_policy_id or gateway_policy_id)
        elif legacy is not None:
            source = "legacy_config"
            effective = {"policy": None, "policy_id": None, "resolved": True,
                         "state": legacy["state"], "mode": legacy["mode"]}
        else:
            source = "none"
            effective = {"policy": None, "policy_id": None, "resolved": True, "state": None, "mode": None}

        path_policies = []
        for rule in listener_rules.get(arm_id_key(model_attr(listener, "id")), []):
            path_map = path_maps.get(arm_id_key(ref_id(rule, "url_path_map")))
            for path_rule in (model_attr(path_map, "path_rules") or []) if path_map is not None else []:
                if ref_id(path_rule, "firewall_policy"):
                    path_policies.append({"path_rule": model_attr(path_rule, "name"),
                                          **policy_summary(ref_id(path_rule, "firewall_policy"))})

        if source == "none":
            waf_enforcing = False
        else:
            states = [enforcing(effective["state"], effective["mode"])]
            states += [enforcing(p["state"], p["mode"]) for p in path_policies]
            waf_enforcing = False if False in states else (None if None in states else True)
        records.append({
            "gateway_id": model_attr(gateway, "id"),
            "gateway_name": model_attr(gateway, "name"),
            "gateway_sku_tier": model_attr(model_attr(gateway, "sku"), "tier"),
            "id": model_attr(listener, "id"),
            "name": model_attr(listener, "name"),
            "protocol": model_attr(listener, "protocol"),
            "port": ports.get(arm_id_key(ref_id(listener, "frontend_port"))),
            "frontend_type": ip_types.get(arm_id_key(ref_id(listener, "frontend_ip_configuration"))),
            "waf_source": source,
            "waf_policy": effective["policy"],
            "waf_policy_id": effective["policy_id"],
            "waf_policy_resolved": effective["resolved"],
            "waf_state": effective["state"],
            "waf_mode": effective["mode"],
            "path_rule_policies": path_policies,
            "waf_enforcing": waf_enforcing,
        })
    return records


def gateway_record(gateway, listeners: list[dict]) -> dict:
    return {
        **gateway_identity(gateway),
        "firewall_policy": basename(ref_id(gateway, "firewall_policy")),
        "firewall_policy_id": ref_id(gateway, "firewall_policy"),
        "force_firewall_policy_association": model_attr(gateway, "force_firewall_policy_association"),
        "legacy_waf_configuration": legacy_waf(gateway),
        "listener_count": len(listeners),
        "listeners_not_enforcing": sum(1 for li in listeners if li["waf_enforcing"] is not True),
    }


def collect_policies(subscription_id, cred, collector: Collector) -> list:
    """Every WAF policy in the subscription."""
    if cred is None:
        return []

    def _client():
        from azure.mgmt.network import NetworkManagementClient  # lazy

        return NetworkManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("network.NetworkManagementClient (init)", _client)
    if client is None:
        return []
    return collector.guard(
        "network.web_application_firewall_policies.list_all",
        lambda: list(client.web_application_firewall_policies.list_all()),
        default=[],
    )


def fetch_policy(policy_id: str, cred, collector: Collector) -> tuple:
    """GET a referenced WAF policy that list_all did not return: (model, None), or (None, unresolved record)."""
    operation = f"network.web_application_firewall_policies.get ({basename(policy_id)})"
    try:
        from azure.mgmt.network import NetworkManagementClient  # lazy

        client = NetworkManagementClient(
            credential=cred, subscription_id=subscription_from_id(policy_id), **arm_client_kwargs()
        )
        return client.web_application_firewall_policies.get(resource_group_from_id(policy_id), basename(policy_id)), None
    except Exception as exc:  # noqa: BLE001 — boundary: classify, don't crash the run
        status = UNREADABLE_STATUS.get(getattr(exc, "status_code", None))
        if status is None:
            collector.record(operation, exc)
            return None, unresolved_policy(policy_id)
        logger.warning("%s: %s, recorded as unresolved", operation, status)
        return None, unresolved_policy(policy_id, status, " ".join(str(exc).split())[:200])


def referenced_policy_ids(gateway) -> set:
    ids = {ref_id(gateway, "firewall_policy")}
    ids |= {ref_id(li, "firewall_policy") for li in (model_attr(gateway, "http_listeners") or [])}
    for path_map in model_attr(gateway, "url_path_maps") or []:
        ids |= {ref_id(p, "firewall_policy") for p in (model_attr(path_map, "path_rules") or [])}
    return {i for i in ids if i}


def summarize(gateways: list[dict], listeners: list[dict], policies: list[dict]) -> dict:
    return {
        "total_application_gateways": len(gateways),
        "waf_tier_gateways": sum(1 for g in gateways if "WAF" in str(g["sku_tier"] or "")),
        "total_http_listeners": len(listeners),
        "listeners_waf_enforcing": sum(1 for li in listeners if li["waf_enforcing"] is True),
        "listeners_waf_detection_only": sum(
            1 for li in listeners if li["waf_state"] == "Enabled" and li["waf_mode"] == "Detection"
        ),
        "listeners_waf_disabled": sum(1 for li in listeners if li["waf_state"] == "Disabled"),
        "listeners_without_waf": sum(1 for li in listeners if li["waf_source"] == "none"),
        "public_listeners_not_enforcing": sum(
            1 for li in listeners if li["frontend_type"] == "public" and li["waf_enforcing"] is not True
        ),
        "total_waf_policies": len(policies),
        "unresolved_waf_policies": sum(1 for p in policies if not p["resolved"]),
        "unreadable_waf_policies": sum(1 for p in policies if p.get("read_status") in ("not_authorized", "not_found")),
        "policies_prevention": sum(1 for p in policies if p["state"] == "Enabled" and p["mode"] == "Prevention"),
        "policies_detection": sum(1 for p in policies if p["state"] == "Enabled" and p["mode"] == "Detection"),
        "policies_disabled": sum(1 for p in policies if p["state"] == "Disabled"),
        "disabled_managed_rules": sum(p.get("disabled_rule_count") or 0 for p in policies),
        "rate_limit_rules": sum(p.get("rate_limit_rules") or 0 for p in policies),
    }


def build(raw_gateways: list, collector: Collector, subscription_id, cred) -> tuple[dict, dict]:
    policy_models = index_by_id(collect_policies(subscription_id, cred, collector))
    unresolved_by_id = {}
    if cred is not None:
        for policy_id in sorted(set().union(*(referenced_policy_ids(g) for g in raw_gateways)) if raw_gateways else []):
            if arm_id_key(policy_id) not in policy_models:
                fetched, unresolved = fetch_policy(policy_id, cred, collector)
                if fetched is not None:
                    policy_models[arm_id_key(policy_id)] = fetched
                else:
                    unresolved_by_id[arm_id_key(policy_id)] = unresolved
    policies = {k: policy_record(p) for k, p in policy_models.items()} | unresolved_by_id
    for g in raw_gateways:
        for policy_id in referenced_policy_ids(g):
            policies.setdefault(arm_id_key(policy_id), unresolved_policy(policy_id))

    gateways, listeners = [], []
    for gateway in raw_gateways:
        records = collector.guard(
            f"project listener WAF ({model_attr(gateway, 'name')})",
            lambda g=gateway: listener_waf_records(g, policies),
            default=[],
        )
        listeners.extend(records)
        gateways.append(gateway_record(gateway, records))
    gateways.sort(key=lambda r: arm_id_key(r["id"]))
    listeners.sort(key=lambda r: arm_id_key(r["id"]))
    policy_list = sorted(policies.values(), key=lambda p: arm_id_key(p["id"]))
    return (
        {"application_gateways": gateways, "listeners": listeners, "waf_policies": policy_list},
        summarize(gateways, listeners, policy_list),
    )


if __name__ == "__main__":
    sys.exit(run_fetcher("azure_app_gateway_waf", logger, build))
