#!/usr/bin/env python3
"""Which Azure Front Door hosts and routes are protected by a blocking WAF, for one subscription."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)
from frontdoor import (  # noqa: E402
    SECURITY_POLICY_API_VERSION,
    arm_key,
    cdn_client,
    collect_waf_policies,
    custom_domains,
    endpoints_with_routes,
    front_door_profiles,
    project_reference,
    route_hosts,
    route_serving,
    waf_policy_record,
    wire,
)

logger = logging.getLogger("azure_front_door_waf_coverage")

SCOPES = ("route", "domain", "profile")
WAF_LOG_CATEGORY = "FrontDoorWebApplicationFirewallLog"
ACCESS_LOG_CATEGORY = "FrontDoorAccessLog"


# --- projection: the only code here that touches an azure-mgmt model ---

def project_security_policy(policy) -> dict:
    props = model_attr(policy, "properties")
    params = model_attr(props, "parameters")
    return {
        "id": model_attr(policy, "id"),
        "name": model_attr(policy, "name"),
        "type": model_attr(params, "type"),
        "waf_policy_id": model_attr(model_attr(params, "waf_policy"), "id"),
        # Recorded responses return isProfileLevel false when it was never set, and routes null.
        "is_profile_level": wire(params, "isProfileLevel") is True,
        "associations": [
            {
                "domains": [project_reference(d) for d in (model_attr(a, "domains") or [])],
                "routes": [r.get("id") for r in (wire(a, "routes") or []) if hasattr(r, "get")],
                "patterns_to_match": list(model_attr(a, "patterns_to_match") or []),
            }
            for a in (model_attr(params, "associations") or [])
        ],
        "deployment_status": model_attr(props, "deployment_status"),
        "provisioning_state": model_attr(props, "provisioning_state"),
    }


def project_log_category(category) -> dict:
    return {
        "name": model_attr(category, "name"),
        "category_type": model_attr(category, "category_type"),
        "category_groups": list(model_attr(category, "category_groups") or []),
    }


def project_log_setting(setting) -> dict:
    return {
        "id": model_attr(setting, "id"),
        "name": model_attr(setting, "name"),
        "workspace_id": model_attr(setting, "workspace_id"),
        "storage_account_id": model_attr(setting, "storage_account_id"),
        "event_hub_name": model_attr(setting, "event_hub_name"),
        "event_hub_authorization_rule_id": model_attr(setting, "event_hub_authorization_rule_id"),
        "marketplace_partner_id": model_attr(setting, "marketplace_partner_id"),
        "logs": [
            {
                "category": model_attr(log, "category"),
                "category_group": model_attr(log, "category_group"),
                # ARM omits `enabled` on a category never selected; absent means off.
                "enabled": bool(model_attr(log, "enabled") or False),
            }
            for log in (model_attr(setting, "logs") or [])
        ],
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def setting_destinations(setting: dict) -> list[str]:
    # ARM returns "" as well as null for an unused destination.
    found = []
    if setting["workspace_id"]:
        found.append("log_analytics_workspace")
    if setting["storage_account_id"]:
        found.append("storage_account")
    if setting["event_hub_authorization_rule_id"] or setting["event_hub_name"]:
        found.append("event_hub")
    if setting["marketplace_partner_id"]:
        found.append("partner_solution")
    return found


def profile_log_export(categories: list[dict], settings: list[dict]) -> dict:
    """Which Front Door log categories some diagnostic setting exports, and where."""
    groups_of = {c["name"]: {g.lower() for g in c["category_groups"]} for c in categories if c["category_type"] == "Logs"}
    records, captured = [], {}
    for setting in settings:
        sinks = setting_destinations(setting)
        names = {log["category"] for log in setting["logs"] if log["enabled"] and log["category"]}
        groups = {log["category_group"].lower() for log in setting["logs"] if log["enabled"] and log["category_group"]}
        exports = bool(sinks) and bool(names or groups)
        records.append({**setting, "destinations": sinks, "exports_logs": exports,
                        "enabled_log_categories": sorted(names), "enabled_log_category_groups": sorted(groups)})
        if not exports:
            continue
        for name, member_of in groups_of.items():
            if name in names or "alllogs" in groups or member_of & groups:
                captured.setdefault(name, set()).update(sinks)
    return {
        "log_categories": sorted(groups_of),
        "log_settings": records,
        "captured_log_categories": sorted(captured),
        "waf_log_exported": WAF_LOG_CATEGORY in captured,
        "waf_log_destinations": sorted(captured.get(WAF_LOG_CATEGORY, ())),
        "access_log_exported": ACCESS_LOG_CATEGORY in captured,
    }


def resolve_scope(host_key: str, route_key: str, security_policies: list[dict]):
    """Most specific WAF association for one host on one route: (scope, policy, association, other matches)."""
    found = {scope: [] for scope in SCOPES}
    for sp in security_policies:
        if sp["type"] != "WebApplicationFirewall":
            continue
        for assoc in sp["associations"]:
            domains = {arm_key(d["id"]) for d in assoc["domains"]}
            routes = {arm_key(r) for r in assoc["routes"]}
            if route_key in routes and (not domains or host_key in domains):
                found["route"].append((sp, assoc))
            elif not routes and host_key in domains:
                found["domain"].append((sp, assoc))
        if sp["is_profile_level"]:
            found["profile"].append((sp, None))
    for scope in SCOPES:
        if found[scope]:
            sp, assoc = found[scope][0]
            return scope, sp, assoc, len(found[scope]) - 1
    return "none", None, None, 0


def host_route_record(profile, endpoint, route, host, security_policies, waf_by_key) -> dict:
    scope, sp, assoc, competing = resolve_scope(arm_key(host["id"]), arm_key(route["id"]), security_policies)
    waf = waf_by_key.get(arm_key(sp["waf_policy_id"])) if sp else None
    patterns = assoc["patterns_to_match"] if assoc else None
    assoc_ref = next(
        (d for d in (assoc["domains"] if assoc else []) if arm_key(d["id"]) == arm_key(host["id"])), None
    )
    assoc_active = assoc_ref["is_active"] if assoc_ref else None
    serving = route_serving(endpoint, route)

    reasons = []
    if scope == "none":
        reasons.append("no_waf")
    else:
        if waf is None:
            reasons.append("waf_unresolved")
        elif not waf["blocking"]:
            reasons.append("waf_not_blocking")
        if patterns is not None and "/*" not in patterns:
            reasons.append("partial_path_coverage")
        if host["is_active"] is False or assoc_active is False:
            reasons.append("host_reference_inactive")
    return {
        "profile": profile["name"],
        "profile_sku": profile["sku"],
        "endpoint": endpoint["name"],
        "endpoint_host_name": endpoint["host_name"],
        "route": route["name"],
        "route_id": route["id"],
        "host_name": host["host_name"],
        "host_kind": host["kind"],
        "host_id": host["id"],
        "serving": serving,
        "supported_protocols": route["supported_protocols"],
        "https_redirect": route["https_redirect"],
        "effective_scope": scope,
        "security_policy": sp["name"] if sp else None,
        "security_policy_id": sp["id"] if sp else None,
        "other_matches_at_scope": competing,
        "patterns_to_match": patterns,
        "route_domain_is_active": host["is_active"],
        "association_domain_is_active": assoc_active,
        "waf_policy_id": sp["waf_policy_id"] if sp else None,
        "waf_policy": waf["name"] if waf else None,
        "waf_mode": waf["mode"] if waf else None,
        "waf_enabled_state": waf["enabled_state"] if waf else None,
        "waf_blocking": waf["blocking"] if waf else False,
        "waf_not_blocking_reasons": waf["not_blocking_reasons"] if waf else [],
        "waf_disabled_managed_rules": waf["disabled_managed_rules"] if waf else None,
        "waf_default_rule_set_enabled_rules": waf["default_rule_set_enabled_rules"] if waf else None,
        "waf_default_rule_set_total_rules": waf["default_rule_set_total_rules"] if waf else None,
        "waf_default_rule_set_fully_disabled_groups": waf["default_rule_set_fully_disabled_groups"] if waf else None,
        "protected": serving and not reasons,
        "unprotected_reasons": reasons,
    }


def coverage_for_profile(collected: dict, waf_by_key: dict) -> dict:
    profile, sps = collected["profile"], collected["security_policies"]
    domains_by_key = {arm_key(d["id"]): d for d in collected["custom_domains"]}
    host_routes, endpoints_without_routes, routed = [], [], set()
    for endpoint in collected["endpoints"]:
        if not endpoint["routes"]:
            endpoints_without_routes.append(
                {"profile": profile["name"], "endpoint": endpoint["name"], "host_name": endpoint["host_name"]}
            )
        for route in endpoint["routes"]:
            routed |= {arm_key(d["id"]) for d in route["custom_domains"]}
            for host in route_hosts(endpoint, route, domains_by_key):
                host_routes.append(host_route_record(profile, endpoint, route, host, sps, waf_by_key))
    unrouted = [
        {"profile": profile["name"], "custom_domain": d["name"], "host_name": d["host_name"]}
        for d in collected["custom_domains"]
        if arm_key(d["id"]) not in routed
    ]
    return {"host_routes": host_routes, "endpoints_without_routes": endpoints_without_routes, "unrouted_custom_domains": unrouted}


def summarize(profiles, skipped_by_sku, host_routes, endpoints_without_routes, unrouted, security_policies) -> dict:
    serving = [h for h in host_routes if h["serving"]]
    waf_profiles = [p for p in profiles if p["waf_in_use"]]
    unprotected = [h for h in serving if not h["protected"]]

    def reason(name: str) -> int:
        return sum(1 for h in serving if name in h["unprotected_reasons"])

    protected = len(serving) - len(unprotected)
    return {
        "total_front_door_profiles": len(profiles),
        "premium_profiles": sum(1 for p in profiles if p["sku"] == "Premium_AzureFrontDoor"),
        "standard_profiles": sum(1 for p in profiles if p["sku"] == "Standard_AzureFrontDoor"),
        "skipped_profiles_by_sku": skipped_by_sku,
        "total_endpoints": sum(p["endpoint_count"] for p in profiles),
        "endpoints_without_routes": len(endpoints_without_routes),
        "total_routes": sum(p["route_count"] for p in profiles),
        "total_custom_domains": sum(p["custom_domain_count"] for p in profiles),
        "unrouted_custom_domains": len(unrouted),
        "total_security_policies": len(security_policies),
        "total_host_routes": len(host_routes),
        "serving_host_routes": len(serving),
        "protected_host_routes": protected,
        "unprotected_host_routes": len(unprotected),
        "protected_host_route_percentage": coverage_percentage(protected, len(serving)),
        "host_routes_without_waf": reason("no_waf"),
        "host_routes_waf_not_blocking": reason("waf_not_blocking"),
        "host_routes_waf_unresolved": reason("waf_unresolved"),
        "host_routes_partial_path_coverage": reason("partial_path_coverage"),
        "host_routes_reference_inactive": reason("host_reference_inactive"),
        **{f"host_routes_{s}_scope": sum(1 for h in serving if h["effective_scope"] == s) for s in (*SCOPES, "none")},
        "profiles_with_waf_in_use": len(waf_profiles),
        "profiles_waf_log_exported": sum(1 for p in profiles if p["waf_log_exported"]),
        "profiles_with_waf_in_use_without_waf_log_export": sum(1 for p in waf_profiles if not p["waf_log_exported"]),
        "security_policies_api_version": SECURITY_POLICY_API_VERSION,
    }


# --- collection (lazy azure imports) ---

def collect_profiles(subscription_id, cred, collector: Collector) -> tuple[list[dict], dict]:
    from azure.mgmt.monitor import MonitorManagementClient

    cdn = cdn_client(subscription_id, cred, collector)
    cdn_sp = cdn_client(subscription_id, cred, collector, api_version=SECURITY_POLICY_API_VERSION)
    monitor = collector.guard(
        "monitor.MonitorManagementClient (init)",
        lambda: MonitorManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
    )
    if cdn is None or cdn_sp is None or monitor is None:
        return [], {}

    profiles, skipped = front_door_profiles(cdn, collector)
    collected = []
    for profile in profiles:
        rg, name = resource_group_from_id(profile["id"]), profile["name"]
        # The SDK substitutes resource_uri after a "/", so a leading slash would double it.
        uri = (profile["id"] or "").lstrip("/")
        collected.append({
            "profile": profile,
            "endpoints": endpoints_with_routes(cdn, collector, profile),
            "custom_domains": custom_domains(cdn, collector, profile),
            "security_policies": collector.guard(
                f"cdn.security_policies.list_by_profile({name})",
                lambda: [project_security_policy(s) for s in cdn_sp.security_policies.list_by_profile(rg, name)],
                default=[],
            ),
            "log_categories": collector.guard(
                f"monitor.diagnostic_settings_category.list({name})",
                lambda: [project_log_category(c) for c in monitor.diagnostic_settings_category.list(resource_uri=uri)],
                default=[],
            ),
            "log_settings": collector.guard(
                f"monitor.diagnostic_settings.list({name})",
                lambda: [project_log_setting(s) for s in monitor.diagnostic_settings.list(resource_uri=uri)],
                default=[],
            ),
        })
    return collected, skipped


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure SDKs log every HTTP request at INFO, which would bury the runner's stderr tail.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    collected: list[dict] = []
    skipped_by_sku: dict = {}
    waf_by_key: dict = {}
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Cdn")
        if registration == NOT_REGISTERED:
            logger.warning("Microsoft.Cdn is not registered on subscription %s", subscription_id)
        collected, skipped_by_sku = collect_profiles(subscription_id, cred, collector)
        waf_policies, definitions = collect_waf_policies(subscription_id, cred, collector)
        waf_by_key = {arm_key(p["id"]): waf_policy_record(p, definitions) for p in waf_policies}
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    profiles, host_routes, no_routes, unrouted, security_policies = [], [], [], [], []
    for c in collected:
        cov = coverage_for_profile(c, waf_by_key)
        host_routes += cov["host_routes"]
        no_routes += cov["endpoints_without_routes"]
        unrouted += cov["unrouted_custom_domains"]
        security_policies += [{**sp, "profile": c["profile"]["name"]} for sp in c["security_policies"]]
        profiles.append({
            **c["profile"],
            **profile_log_export(c["log_categories"], c["log_settings"]),
            "waf_in_use": any(h["serving"] and h["effective_scope"] != "none" for h in cov["host_routes"]),
            "endpoint_count": len(c["endpoints"]),
            "route_count": sum(len(e["routes"]) for e in c["endpoints"]),
            "custom_domain_count": len(c["custom_domains"]),
            "security_policy_count": len(c["security_policies"]),
        })

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "host_routes": host_routes,
            "endpoints_without_routes": no_routes,
            "unrouted_custom_domains": unrouted,
            "security_policies": security_policies,
            "profiles": profiles,
            "provider_registration_status": registration,
        },
        summary={
            **summarize(profiles, skipped_by_sku, host_routes, no_routes, unrouted, security_policies),
            "provider_registration_status": registration,
        },
    )
    filename = f"azure_front_door_waf_coverage_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
