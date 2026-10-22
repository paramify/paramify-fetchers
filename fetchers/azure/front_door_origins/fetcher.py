#!/usr/bin/env python3
"""Azure Front Door origin groups and origins: regions serving traffic, how Front Door connects to each origin, whether each App Service origin only accepts its own profile, and which apps lack a regional twin, for one subscription."""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
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
    credential,
    failure_reason,
    model_attr,
    monitor_client,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)
from frontdoor import (  # noqa: E402
    DEFAULT_FORWARDING_PROTOCOL,
    arm_key,
    attached_rules,
    cdn_client,
    endpoints_with_routes,
    front_door_profiles,
    route_https,
    route_serving,
    rule_sets_with_rules,
    wire,
)
from resource_graph import (  # noqa: E402
    ALL_SUBSCRIPTIONS,
    query_all,
    resource_graph_client,
)

logger = logging.getLogger("azure_front_door_origins")

# First GA api-version with certificateNameCheckValidationMode and tokenDestinationHeader.
ORIGIN_API_VERSION = "2026-07-01"
LOOKUP_CHUNK = 50
FRONT_DOOR_SERVICE_TAG = "azurefrontdoor.backend"
FDID_HEADER = "x-azure-fdid"
# An access-restriction address matching every caller; "Any" is ARM's synthetic "Allow all" rule.
ALL_ADDRESSES = ("any", "*", "0.0.0.0/0", "::/0", "internet")
# Tiers where the platform scales instances itself, so sku.capacity is not an instance count.
PLATFORM_SCALED_TIERS = ("dynamic", "flexconsumption", "elasticpremium")
PRODUCTION_TAG_ENV = "AZURE_PRODUCTION_APP_TAG"
LOOKBACK_ENV = "AZURE_FRONT_DOOR_METRICS_LOOKBACK_DAYS"
DEFAULT_LOOKBACK_DAYS = 7
# "Last hour" must fall in the window's last this-many hours; older data leaves it unknown.
LAST_HOUR_BUCKETS = 3
MAX_LOOKBACK_DAYS = 30
# The metrics API returns only 10 dimension series unless asked for more.
METRICS_TOP = 1000
MAX_TRAFFIC_SHIFTS = 100
# Front Door's documented loadBalancingSettings defaults.
DEFAULT_SAMPLE_SIZE = 4
DEFAULT_SUCCESSFUL_SAMPLES = 3


# --- projection: the only code here that touches an azure-mgmt model ---

def project_origin_group(group) -> dict:
    props = model_attr(group, "properties")
    lb = model_attr(props, "load_balancing_settings")
    probe = model_attr(props, "health_probe_settings")
    auth = model_attr(props, "authentication")
    return {
        "id": model_attr(group, "id"),
        "name": model_attr(group, "name"),
        "session_affinity_state": model_attr(props, "session_affinity_state"),
        "load_balancing": None if lb is None else {
            "sample_size": model_attr(lb, "sample_size"),
            "successful_samples_required": model_attr(lb, "successful_samples_required"),
            "additional_latency_in_milliseconds": model_attr(lb, "additional_latency_in_milliseconds"),
        },
        "health_probe": None if probe is None else {
            "probe_path": model_attr(probe, "probe_path"),
            "probe_request_type": model_attr(probe, "probe_request_type"),
            "probe_protocol": model_attr(probe, "probe_protocol"),
            "probe_interval_in_seconds": model_attr(probe, "probe_interval_in_seconds"),
        },
        "authentication": None if auth is None else {
            "type": model_attr(auth, "type"),
            "scope": model_attr(auth, "scope"),
            "user_assigned_identity_id": model_attr(model_attr(auth, "user_assigned_identity"), "id"),
            "token_destination_header": wire(auth, "tokenDestinationHeader"),
        },
        "provisioning_state": model_attr(props, "provisioning_state"),
        "deployment_status": model_attr(props, "deployment_status"),
    }


def project_origin(origin) -> dict:
    props = model_attr(origin, "properties")
    link = model_attr(props, "shared_private_link_resource")
    return {
        "id": model_attr(origin, "id"),
        "name": model_attr(origin, "name"),
        "host_name": model_attr(props, "host_name"),
        "origin_host_header": model_attr(props, "origin_host_header"),
        "http_port": model_attr(props, "http_port"),
        "https_port": model_attr(props, "https_port"),
        "priority": model_attr(props, "priority"),
        "weight": model_attr(props, "weight"),
        "enabled_state": model_attr(props, "enabled_state"),
        "enforce_certificate_name_check": model_attr(props, "enforce_certificate_name_check"),
        "certificate_name_check_validation_mode": wire(props, "certificateNameCheckValidationMode"),
        "custom_certificate_subjects": list(wire(props, "customCertificateSubjects") or []),
        "azure_origin_id": model_attr(model_attr(props, "azure_origin"), "id"),
        "private_link": None if link is None else {
            "target_id": model_attr(model_attr(link, "private_link"), "id"),
            "group_id": model_attr(link, "group_id"),
            "private_endpoint_location": model_attr(link, "private_link_location"),
            "status": model_attr(link, "status"),
        },
        "provisioning_state": model_attr(props, "provisioning_state"),
        "deployment_status": model_attr(props, "deployment_status"),
    }


def project_access_restriction(rule) -> dict:
    return {
        "name": model_attr(rule, "name"),
        "priority": model_attr(rule, "priority"),
        "action": model_attr(rule, "action"),
        "tag": model_attr(rule, "tag"),
        "ip_address": model_attr(rule, "ip_address"),
        "vnet_subnet_resource_id": model_attr(rule, "vnet_subnet_resource_id"),
        "headers": {str(k): [str(v) for v in (vals or [])] for k, vals in (model_attr(rule, "headers") or {}).items()},
    }


def project_metric_series(response) -> list[dict]:
    series = []
    for metric in model_attr(response, "value") or []:
        for ts in model_attr(metric, "timeseries") or []:
            dims = {str(model_attr(model_attr(m, "name"), "value") or "").lower(): model_attr(m, "value")
                    for m in (model_attr(ts, "metadatavalues") or [])}
            series.append({
                "origin": dims.get("origin"),
                "origin_group": dims.get("origingroup"),
                "points": [{
                    "time": hour_key(model_attr(p, "time_stamp")),
                    "average": model_attr(p, "average"),
                    "minimum": model_attr(p, "minimum"),
                    "total": model_attr(p, "total"),
                } for p in (model_attr(ts, "data") or [])],
            })
    return series


def hour_key(value) -> str | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value) if value else None


def project_site_config(config) -> dict:
    return {
        "public_network_access": model_attr(config, "public_network_access"),
        "ip_security_restrictions": [project_access_restriction(r) for r in (model_attr(config, "ip_security_restrictions") or [])],
        "ip_security_restrictions_default_action": model_attr(config, "ip_security_restrictions_default_action"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def protocols_to_origin(forwarding_protocol: str, route_https_only: bool) -> list[str]:
    if forwarding_protocol == "HttpsOnly":
        return ["Https"]
    if forwarding_protocol == "HttpOnly":
        return ["Http"]
    if forwarding_protocol == "MatchRequest" and route_https_only:
        return ["Https"]
    return ["Http", "Https"]


def origin_paths(profile: dict, endpoints: list[dict], rule_sets_by_key: dict) -> list[dict]:
    """Every way a route reaches an origin group: its own originGroup, and each rule-set override attached to it."""
    paths = []
    for endpoint in endpoints:
        for route in endpoint["routes"]:
            https = route_https(route, rule_sets_by_key)
            base = {
                "profile": profile["name"],
                "endpoint": endpoint["name"],
                "route": route["name"],
                "route_id": route["id"],
                "serving": route_serving(endpoint, route),
                "route_https_only": https["https_only"],
            }
            forwarding = route["forwarding_protocol"] or DEFAULT_FORWARDING_PROTOCOL
            paths.append({**base, "origin_group_id": route["origin_group_id"], "via": "route",
                          "forwarding_protocol": forwarding,
                          "protocols_to_origin": protocols_to_origin(forwarding, https["https_only"])})
            for rule_set, rule in attached_rules(route["rule_set_ids"], rule_sets_by_key):
                for action in rule["actions"]:
                    if not action["overrides_origin_group"]:
                        continue
                    forwarding = action["forwarding_protocol_override"] or DEFAULT_FORWARDING_PROTOCOL
                    paths.append({**base, "origin_group_id": action["origin_group_override_id"] or route["origin_group_id"],
                                  "via": f"rule:{rule_set['name']}/{rule['name']}", "forwarding_protocol": forwarding,
                                  "protocols_to_origin": protocols_to_origin(forwarding, https["https_only"])})
    return paths


def origin_region(origin: dict, regions_by_id: dict, regions_by_host: dict) -> tuple[str | None, str | None]:
    candidates = (("azure_origin", origin["azure_origin_id"]), ("private_link_target", (origin["private_link"] or {}).get("target_id")))
    for source, resource_id in candidates:
        if resource_id and arm_key(resource_id) in regions_by_id:
            return regions_by_id[arm_key(resource_id)], source
    host = str(origin["host_name"] or "").lower()
    if host in regions_by_host:
        return regions_by_host[host], "host_name"
    return None, None


def origin_record(origin: dict, regions_by_id: dict, regions_by_host: dict) -> dict:
    region, source = origin_region(origin, regions_by_id, regions_by_host)
    name_check = origin["enforce_certificate_name_check"]
    return {
        **origin,
        "effective_enabled_state": origin["enabled_state"] or "Enabled",
        "effective_enforce_certificate_name_check": True if name_check is None else name_check,
        "region": region,
        "region_source": source,
    }


def group_record(profile: dict, group: dict, origins: list[dict], paths: list[dict], regions_by_id: dict, regions_by_host: dict) -> dict:
    records = [origin_record(o, regions_by_id, regions_by_host) for o in origins]
    enabled = [o for o in records if o["effective_enabled_state"] == "Enabled"]
    priorities = [o["priority"] for o in enabled if o["priority"] is not None]
    best = min(priorities) if priorities else None
    # An origin with no priority can't be ruled out of the active set.
    active = [o for o in enabled if o["priority"] is None or o["priority"] == best]
    active_regions = sorted({o["region"] for o in active if o["region"]})
    enabled_regions = sorted({o["region"] for o in enabled if o["region"]})
    group_paths = [p for p in paths if arm_key(p["origin_group_id"]) == arm_key(group["id"])]
    serving_paths = [p for p in group_paths if p["serving"]]
    protocols = sorted({proto for p in serving_paths for proto in p["protocols_to_origin"]})
    name_check_off = sorted(o["name"] for o in enabled if not o["effective_enforce_certificate_name_check"])
    all_private_link = bool(enabled) and all(o["private_link"] for o in enabled)
    serving = bool(serving_paths)

    reasons = []
    if not enabled:
        reasons.append("no_enabled_origin")
    if "Http" in protocols:
        reasons.append("http_to_origin")
    if name_check_off:
        reasons.append("certificate_name_check_disabled")
    if not all_private_link and group["authentication"] is None:
        reasons.append("no_private_link_or_origin_auth")
    return {
        "profile": profile["name"],
        "profile_sku": profile["sku"],
        **group,
        "origins": records,
        "routes": [{k: p[k] for k in ("endpoint", "route", "serving", "via", "forwarding_protocol", "protocols_to_origin")}
                   for p in group_paths],
        "serving": serving,
        "total_origins": len(records),
        "enabled_origins": len(enabled),
        "best_priority": best,
        "active_origins": len(active),
        "active_regions": active_regions,
        "enabled_regions": enabled_regions,
        "enabled_origins_region_unresolved": sum(1 for o in enabled if not o["region"]),
        "multi_region_active_active": len(active_regions) >= 2,
        "multi_region_failover": len(enabled_regions) >= 2,
        "health_probe_enabled": group["health_probe"] is not None,
        "protocols_to_origin": protocols,
        "certificate_name_check_disabled_origins": name_check_off,
        "private_link_origins": sum(1 for o in enabled if o["private_link"]),
        "all_enabled_origins_private_link": all_private_link,
        "origin_authentication": group["authentication"] is not None,
        "connection_protected": serving and not reasons,
        "unprotected_reasons": reasons,
    }


def summarize(profiles: list[dict], skipped_by_sku: dict, groups: list[dict]) -> dict:
    serving = [g for g in groups if g["serving"]]
    origins = [o for g in groups for o in g["origins"]]

    def count(items, pred) -> int:
        return sum(1 for i in items if pred(i))

    def reason(name: str) -> int:
        return count(serving, lambda g: name in g["unprotected_reasons"])

    return {
        "total_front_door_profiles": len(profiles),
        "premium_profiles": count(profiles, lambda p: p["sku"] == "Premium_AzureFrontDoor"),
        "standard_profiles": count(profiles, lambda p: p["sku"] == "Standard_AzureFrontDoor"),
        "skipped_profiles_by_sku": skipped_by_sku,
        "total_origin_groups": len(groups),
        "serving_origin_groups": len(serving),
        "unused_origin_groups": len(groups) - len(serving),
        "total_origins": len(origins),
        "enabled_origins": count(origins, lambda o: o["effective_enabled_state"] == "Enabled"),
        "private_link_origins": count(origins, lambda o: o["private_link"] is not None),
        "origins_by_region_source": dict(sorted(Counter(str(o["region_source"]) for o in origins).items())),
        "serving_regions": sorted({r for g in serving for r in g["active_regions"]}),
        "serving_groups_multi_region_active_active": count(serving, lambda g: g["multi_region_active_active"]),
        "serving_groups_multi_region_failover": count(serving, lambda g: g["multi_region_failover"]),
        "serving_groups_single_enabled_origin": count(serving, lambda g: g["enabled_origins"] == 1),
        "serving_groups_without_enabled_origin": count(serving, lambda g: g["enabled_origins"] == 0),
        "serving_groups_region_unresolved": count(serving, lambda g: g["enabled_origins_region_unresolved"] > 0),
        "serving_groups_multi_origin_without_health_probe": count(
            serving, lambda g: g["enabled_origins"] > 1 and not g["health_probe_enabled"]
        ),
        "serving_groups_http_health_probe": count(serving, lambda g: (g["health_probe"] or {}).get("probe_protocol") == "Http"),
        "serving_groups_connection_protected": count(serving, lambda g: g["connection_protected"]),
        "serving_groups_connection_unprotected": count(serving, lambda g: not g["connection_protected"]),
        "serving_groups_http_to_origin": reason("http_to_origin"),
        "serving_groups_certificate_name_check_disabled": reason("certificate_name_check_disabled"),
        "serving_groups_without_private_link_or_origin_auth": reason("no_private_link_or_origin_auth"),
        "serving_groups_all_private_link": count(serving, lambda g: g["all_enabled_origins_private_link"]),
        "serving_groups_origin_authentication": count(serving, lambda g: g["origin_authentication"]),
        "origin_api_version": ORIGIN_API_VERSION,
    }


# --- App Service origins: lockdown to Front Door, and regional twins ---

def is_web_site_id(resource_id: str | None) -> bool:
    parts = arm_key(resource_id).split("/")
    return (len(parts) in (9, 11) and parts[1] == "subscriptions" and parts[6:8] == ["microsoft.web", "sites"]
            and (len(parts) == 9 or parts[9] == "slots"))


def origin_site_id(origin: dict, sites_by_host: dict) -> tuple[str | None, str | None]:
    """The App Service app (or slot) behind an origin: its azureOrigin, its private-link target, else the app owning its host name."""
    if is_web_site_id(origin["azure_origin_id"]):
        return arm_key(origin["azure_origin_id"]), "azure_origin"
    link = origin["private_link"] or {}
    if is_web_site_id(link.get("target_id")):
        # A slot's private link targets the parent app with group id "sites-<slot>".
        group_id = str(link.get("group_id") or "").lower()
        slot = group_id[len("sites-"):] if group_id.startswith("sites-") and "/slots/" not in arm_key(link["target_id"]) else ""
        return arm_key(link["target_id"]) + (f"/slots/{slot}" if slot else ""), "private_link_target"
    host = str(origin["host_name"] or "").lower()
    if host in sites_by_host:
        return sites_by_host[host], "host_name"
    return None, None


def plan_record(row: dict | None) -> dict | None:
    if not row:
        return None
    sku = row.get("sku") or {}
    tier = str(sku.get("tier") or "")
    capacity = sku.get("capacity")
    platform_scaled = tier.lower() in PLATFORM_SCALED_TIERS
    return {
        "id": row.get("id"),
        "name": row.get("name"),
        "location": normalize_region(row.get("location")),
        "sku_name": sku.get("name"),
        "sku_tier": tier or None,
        "sku_capacity": capacity,
        "instance_count": capacity if isinstance(capacity, int) and not platform_scaled else None,
        "platform_scaled": platform_scaled,
        "zone_redundant": bool(row.get("zone_redundant") or False),
    }


def profile_key(child_id: str | None) -> str:
    return arm_key(child_id).split("/origingroups/")[0]


def normalize_region(location) -> str | None:
    return str(location).lower().replace(" ", "") if location else None


def header_values(rule: dict, name: str) -> list[str]:
    values = next((v for k, v in (rule["headers"] or {}).items() if str(k).lower() == name), None) or []
    return sorted({part.strip().lower() for v in values for part in str(v).split(",") if part.strip()})


def is_front_door_rule(rule: dict) -> bool:
    return (str(rule["tag"] or "").lower() == "servicetag"
            and str(rule["ip_address"] or "").strip().lower() == FRONT_DOOR_SERVICE_TAG)


def matches_all_callers(rule: dict) -> bool:
    return (str(rule["ip_address"] or "").strip().lower() in ALL_ADDRESSES
            and not rule["vnet_subnet_resource_id"] and not rule["headers"])


def public_allow_rules(rules: list[dict], default_action) -> tuple[list[dict], bool]:
    """Allow rules a public caller can match before any catch-all rule, and whether unmatched callers are let in."""
    ordered = sorted(rules, key=lambda r: r["priority"] if isinstance(r["priority"], int) else 1 << 31)
    allows = []
    for rule in ordered:
        if matches_all_callers(rule):
            return allows, str(rule["action"] or "Allow").lower() == "allow"
        if str(rule["action"] or "Allow").lower() == "allow":
            allows.append(rule)
    # Unset default: no rules allows everyone; any rule denies the rest.
    return allows, str(default_action or ("Deny" if rules else "Allow")).lower() == "allow"


def lockdown(public_network_access, config: dict | None, profile_fdid: str | None, known_fdids: set,
             private_link: bool, fronting_fdids: frozenset = frozenset()) -> dict:
    """Whether only Front Door can reach the app: public access off, or access restrictions admitting only the X-Azure-FDID
    of its own profile or of another profile that also serves the app (fronting_fdids), whose WAF is judged on its own record."""
    rules = (config or {}).get("ip_security_restrictions") or []
    allows, unmatched_allowed = public_allow_rules(rules, (config or {}).get("ip_security_restrictions_default_action"))
    fd_rules = [r for r in allows if is_front_door_rule(r)]
    allowed_fdids = sorted({v for r in fd_rules for v in header_values(r, FDID_HEADER)})
    own = str(profile_fdid or "").lower() or None
    fronting = {str(f).lower() for f in fronting_fdids}
    record = {
        "public_network_access_disabled": str(public_network_access or "").lower() == "disabled",
        "access_restrictions_read": config is not None,
        "access_restrictions": rules,
        "access_restrictions_default_action": (config or {}).get("ip_security_restrictions_default_action"),
        "unmatched_public_callers_allowed": unmatched_allowed if config is not None else None,
        "front_door_allow_rules": [r["name"] for r in fd_rules],
        "non_front_door_allow_rules": [r["name"] for r in allows if not is_front_door_rule(r)],
        "allowed_front_door_ids": allowed_fdids,
        "profile_front_door_id": profile_fdid,
        "profile_front_door_id_allowed": None if own is None or config is None else own in allowed_fdids,
        # Ids of other profiles that also serve the app are judged on those profiles' own records.
        "fronting_front_door_ids": [f for f in allowed_fdids if f != own and f in fronting],
        "other_front_door_ids_allowed": [f for f in allowed_fdids if f != own and f not in fronting],
    }
    if record["public_network_access_disabled"]:
        return {**record, "locked_to_front_door": True, "lockdown_basis": "public_network_access_disabled", "lockdown_gaps": []}
    gaps = []
    if config is None:
        gaps.append("access_restrictions_unread")
    else:
        if unmatched_allowed:
            gaps.append("public_access_unrestricted")
        if record["non_front_door_allow_rules"]:
            gaps.append("non_front_door_allow_rule")
        if any(not header_values(r, FDID_HEADER) for r in fd_rules):
            gaps.append("front_door_rule_without_fdid")
        if set(allowed_fdids) - known_fdids - {own}:
            gaps.append("unknown_front_door_id_allowed")
        # Another profile in the subscription may lack the serving profile's WAF, so it is a way around it.
        if (set(allowed_fdids) & known_fdids) - {own} - fronting:
            gaps.append("other_front_door_id_allowed")
        # Over private link Front Door skips access restrictions, so only a public origin needs its own id admitted.
        if not private_link and not set(gaps) - {"other_front_door_id_allowed"}:
            if own is None:
                gaps.append("profile_front_door_id_unknown")
            elif own not in allowed_fdids:
                gaps.append("profile_front_door_id_not_allowed")
    basis = None
    if not gaps:
        basis = "front_door_id_restricted" if fd_rules else "no_public_allow_rule"
    return {**record, "locked_to_front_door": not gaps, "lockdown_basis": basis, "lockdown_gaps": gaps}


def fronting_profiles(groups: list[dict], profile_fdids: dict, sites_by_host: dict) -> dict:
    """Per app, the Front Door ids of the profiles whose serving groups reach it through an enabled origin."""
    fronting: dict = {}
    for group in groups:
        for origin in group["origins"]:
            site_id, _ = origin_site_id(origin, sites_by_host)
            fdid = profile_fdids.get(profile_key(group["id"]))
            if site_id and fdid and group["serving"] and origin["effective_enabled_state"] == "Enabled":
                fronting.setdefault(site_id, set()).add(fdid)
    return fronting


def app_service_origin_records(groups: list[dict], profile_fdids: dict, sites_by_key: dict, sites_by_host: dict,
                               plans_by_key: dict, configs_by_key: dict, subscription_id,
                               fronting: dict | None = None) -> list[dict]:
    """Each App Service origin with its lockdown; `fronting` (default: from `groups`) exempts profiles that also serve the app."""
    known = {str(f).lower() for f in profile_fdids.values() if f}
    own_sub = f"/subscriptions/{str(subscription_id or '').lower()}/"
    if fronting is None:
        fronting = fronting_profiles(groups, profile_fdids, sites_by_host)
    records = []
    for group in groups:
        for origin in group["origins"]:
            site_id, source = origin_site_id(origin, sites_by_host)
            if site_id is None:
                continue
            site = sites_by_key.get(site_id)
            base = {
                "profile": group["profile"],
                "origin_group": group["name"],
                "origin_group_id": group["id"],
                "origin": origin["name"],
                "origin_id": origin["id"],
                "host_name": origin["host_name"],
                "serving": group["serving"] and origin["effective_enabled_state"] == "Enabled",
                "private_link": origin["private_link"] is not None,
                "site_id": site_id,
                "site_id_source": source,
                "site_found": site is not None,
            }
            if site is None:
                # The whole target subscription was listed, so a miss there is a deleted app; elsewhere it may be out of reach.
                gap = "site_not_found" if site_id.startswith(own_sub) else "site_not_visible"
                records.append({**base, "site_name": None, "site_kind": None, "site_state": None, "site_location": None,
                                "public_network_access": None, "plan": None, "locked_to_front_door": False,
                                "lockdown_basis": None, "lockdown_gaps": [gap]})
                continue
            config = configs_by_key.get(site_id)
            public_access = (config or {}).get("public_network_access") or site.get("public_network_access") or None
            records.append({
                **base,
                "site_name": site.get("name"),
                "site_kind": site.get("kind"),
                "site_state": site.get("state") or None,
                "site_location": normalize_region(site.get("location")),
                "public_network_access": public_access,
                "plan": plan_record(plans_by_key.get(arm_key(site.get("server_farm_id")))),
                **lockdown(public_access, config, profile_fdids.get(profile_key(group["id"])), known,
                           origin["private_link"] is not None, frozenset(fronting.get(site_id, ()))),
            })
    return records


def is_function_app(kind) -> bool:
    return "functionapp" in str(kind or "").lower()


def matches_tag(tags: dict | None, production_tag: str | None) -> bool:
    if not production_tag:
        return True
    key, _, value = production_tag.partition("=")
    found = next((v for k, v in (tags or {}).items() if str(k).lower() == key.strip().lower()), None)
    if found is None:
        return False
    return not value or str(found).strip().lower() == value.strip().lower()


def capacity_covers(twin_plan: dict | None, own_plan: dict | None) -> bool | None:
    """Can the twin's plan take this app's load: platform-scaled, or at least as many instances."""
    if not twin_plan or not own_plan:
        return None
    if twin_plan["platform_scaled"]:
        return True
    if own_plan["instance_count"] is None or twin_plan["instance_count"] is None:
        return None
    return twin_plan["instance_count"] >= own_plan["instance_count"]


def web_app_record(site: dict, groups_by_key: dict, app_origins: list[dict], origins_by_key: dict, plan: dict | None) -> dict:
    key = arm_key(site["id"])
    own_region = normalize_region(site.get("location"))
    mine = [r for r in app_origins if r["site_id"] == key]
    serving = [r for r in mine if r["serving"]]
    twins, unresolved = [], False
    for row in serving:
        group = groups_by_key[arm_key(row["origin_group_id"])]
        for other in group["origins"]:
            if arm_key(other["id"]) == arm_key(row["origin_id"]) or other["effective_enabled_state"] != "Enabled":
                continue
            twin_app = origins_by_key.get(arm_key(other["id"]))
            if twin_app and twin_app["site_id"] == key:
                continue
            if not other["region"]:
                unresolved = True
                continue
            if other["region"] == own_region:
                continue
            twin_plan = (twin_app or {}).get("plan")
            twins.append({
                "profile": row["profile"],
                "origin_group": row["origin_group"],
                "origin": other["name"],
                "region": other["region"],
                "site_id": (twin_app or {}).get("site_id"),
                "active": other["priority"] is None or other["priority"] == group["best_priority"],
                "plan": twin_plan,
                "capacity_covers": capacity_covers(twin_plan, plan),
            })
    covers = [t["capacity_covers"] for t in twins]
    sufficient = True if True in covers else (False if covers and all(c is False for c in covers) else None)
    gaps = []
    if not serving:
        gaps.append("not_behind_front_door")
    elif not twins:
        gaps.append("twin_region_unresolved" if unresolved or not own_region else "no_regional_twin")
    elif sufficient is False:
        gaps.append("twin_capacity_short")
    elif sufficient is None:
        gaps.append("twin_capacity_unknown")
    return {
        "id": site["id"],
        "name": site.get("name"),
        "kind": site.get("kind"),
        "app_type": "function_app" if is_function_app(site.get("kind")) else "web_app",
        "state": site.get("state") or None,
        "location": own_region,
        "public_network_access": site.get("public_network_access") or None,
        "plan": plan,
        "origin_groups": [{"profile": r["profile"], "origin_group": r["origin_group"], "origin": r["origin"],
                           "serving": r["serving"]} for r in mine],
        "in_origin_group": bool(mine),
        "behind_front_door": bool(serving),
        "regional_twins": twins,
        "has_regional_twin": bool(twins),
        "twin_capacity_sufficient": sufficient if twins else None,
        "regional_twin_ready": not gaps,
        "twin_gaps": gaps,
    }


def production_apps(sites_by_key: dict, subscription_id, production_tag, groups: list[dict], app_origins: list[dict],
                    plans_by_key: dict) -> list[dict]:
    """Every app (not slot) in the subscription, narrowed by the production tag when set, with its regional-twin verdict."""
    groups_by_key = {arm_key(g["id"]): g for g in groups}
    origins_by_key = {arm_key(r["origin_id"]): r for r in app_origins}
    return [
        web_app_record(site, groups_by_key, app_origins, origins_by_key,
                       plan_record(plans_by_key.get(arm_key(site.get("server_farm_id")))))
        for _, site in sorted(sites_by_key.items())
        if str(site.get("type") or "").lower() == "microsoft.web/sites"
        and str(site.get("subscriptionId") or "").lower() == str(subscription_id or "").lower()
        and matches_tag(site.get("tags"), production_tag)
    ]


def summarize_app_services(app_origins: list[dict], apps: list[dict], production_tag: str | None) -> dict:
    serving = [r for r in app_origins if r["serving"]]

    def gap(name: str) -> int:
        return sum(1 for r in serving if name in r["lockdown_gaps"])

    summary = {
        "app_service_origins": len(app_origins),
        "serving_app_service_origins": len(serving),
        "serving_app_service_origins_locked_to_front_door": sum(1 for r in serving if r["locked_to_front_door"]),
        "serving_app_service_origins_not_locked": sum(1 for r in serving if not r["locked_to_front_door"]),
        "serving_app_service_origins_public_network_access_disabled": sum(
            1 for r in serving if r.get("public_network_access_disabled")),
        "serving_app_service_origins_site_not_found": gap("site_not_found"),
        "serving_app_service_origins_site_not_visible": gap("site_not_visible"),
        "serving_app_service_origins_access_restrictions_unread": gap("access_restrictions_unread"),
        "serving_app_service_origins_public_access_unrestricted": gap("public_access_unrestricted"),
        "serving_app_service_origins_non_front_door_allow_rule": gap("non_front_door_allow_rule"),
        "serving_app_service_origins_front_door_rule_without_fdid": gap("front_door_rule_without_fdid"),
        "serving_app_service_origins_unknown_front_door_id_allowed": gap("unknown_front_door_id_allowed"),
        "serving_app_service_origins_other_front_door_id_allowed": gap("other_front_door_id_allowed"),
        "serving_app_service_origins_profile_front_door_id_not_allowed": gap("profile_front_door_id_not_allowed"),
        "serving_app_service_origins_profile_front_door_id_unknown": gap("profile_front_door_id_unknown"),
        "production_tag": production_tag,
    }
    for app_type in ("web_app", "function_app"):
        typed = [a for a in apps if a["app_type"] == app_type]
        summary.update({
            f"production_{app_type}s": len(typed),
            f"production_{app_type}s_behind_front_door": sum(1 for a in typed if a["behind_front_door"]),
            f"production_{app_type}s_not_behind_front_door": sum(1 for a in typed if not a["behind_front_door"]),
            f"production_{app_type}s_regional_twin_ready": sum(1 for a in typed if a["regional_twin_ready"]),
            f"production_{app_type}s_without_regional_twin": sum(
                1 for a in typed if {"no_regional_twin", "twin_region_unresolved"} & set(a["twin_gaps"])),
            f"production_{app_type}s_twin_capacity_short": sum(1 for a in typed if "twin_capacity_short" in a["twin_gaps"]),
            f"production_{app_type}s_twin_capacity_unknown": sum(1 for a in typed if "twin_capacity_unknown" in a["twin_gaps"]),
        })
    return summary


# --- live origin health and traffic, from Azure Monitor metrics ---

def metric_host(value) -> str:
    """The Origin dimension is the origin's host name, sometimes with ":port"."""
    host = str(value or "").strip().lower()
    head, _, port = host.rpartition(":")
    return head if head and port.isdigit() else host


def request_keys(origin: dict) -> set:
    # OriginRequestCount names the origin by the Host header sent to it (origin_host_header), health by host_name.
    return {k for k in (str(origin["host_name"] or "").lower(), str(origin.get("origin_host_header") or "").lower()) if k}


def health_threshold(group: dict) -> float:
    """The share of probes the group's load-balancing settings require before Front Door calls an origin healthy."""
    lb = group["load_balancing"] or {}
    size = lb.get("sample_size") or DEFAULT_SAMPLE_SIZE
    needed = min(lb.get("successful_samples_required") or DEFAULT_SUCCESSFUL_SAMPLES, size)
    return round(100 * needed / size, 2)


def hourly(series: list[dict]) -> dict:
    """Per hour: mean of the averages, lowest minimum, and summed totals across the given series."""
    hours: dict = {}
    for s in series:
        for p in s["points"]:
            h = hours.setdefault(p["time"], {"averages": [], "minimums": [], "total": None})
            if p["average"] is not None:
                h["averages"].append(p["average"])
            if p["minimum"] is not None:
                h["minimums"].append(p["minimum"])
            if p["total"] is not None:
                h["total"] = (h["total"] or 0) + p["total"]
    return {
        t: {"health_avg": round(sum(h["averages"]) / len(h["averages"]), 2) if h["averages"] else None,
            "health_min": min(h["minimums"]) if h["minimums"] else None,
            "requests": h["total"]}
        for t, h in hours.items()
    }


def mean(values) -> float | None:
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 2) if values else None


def traffic_shifts(hours: list[str], region_hours: dict) -> list[dict]:
    """Hours where the set of regions receiving requests changed from the previous hour that had traffic."""
    shifts, previous = [], None
    for t in hours:
        serving = sorted(r for r, by_hour in region_hours.items() if (by_hour.get(t, {}).get("requests") or 0) > 0)
        if not serving:
            continue
        if previous is not None and serving != previous:
            shifts.append({"time": t, "serving_regions_before": previous, "serving_regions_after": serving})
        previous = serving
    return shifts


def last_hours(metrics: dict, window_end: str) -> tuple[str | None, str | None]:
    """The profile's newest hour with requests and newest hour with a health value, each taken separately (ingestion lags
    per profile and per metric), or None when it falls before the window's last LAST_HOUR_BUCKETS hours."""
    end = datetime.strptime(window_end, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    floor = (end - timedelta(hours=LAST_HOUR_BUCKETS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    requests = max((p["time"] for s in metrics["requests"] for p in s["points"] if (p["total"] or 0) > 0), default=None)
    health = max((p["time"] for s in metrics["health"] for p in s["points"] if p["average"] is not None), default=None)
    return tuple(h if h is not None and h >= floor else None for h in (requests, health))


def group_health_record(profile_key_: str, group: dict, health: list[dict], requests: list[dict], shared_hosts: dict,
                        last_request_hour: str | None, last_health_hour: str | None) -> dict:
    """A group's health and traffic. "Last hour" is the profile's newest recent hour with requests (for serving) or with
    health data (for health); a group silent then isn't serving, and with no recent hour both are unknown."""
    threshold = health_threshold(group)
    group_name = str(group["name"] or "").lower()
    origin_rows, origin_hours, region_hours = [], [], {}
    for o in group["origins"]:
        host = str(o["host_name"] or "").lower()
        keys = request_keys(o)
        o_health = hourly([s for s in health if str(s["origin_group"] or "").lower() == group_name
                           and metric_host(s["origin"]) == host])
        o_requests = hourly([s for s in requests if metric_host(s["origin"]) in keys])
        by_hour = {t: {**o_health.get(t, {"health_avg": None, "health_min": None}),
                       "requests": o_requests.get(t, {}).get("requests")} for t in set(o_health) | set(o_requests)}
        times = sorted(by_hour)
        served = [t for t in times if (by_hour[t]["requests"] or 0) > 0]
        origin_hours.append(by_hour)
        origin_rows.append({
            "origin": o["name"],
            "host_name": o["host_name"],
            "region": o["region"],
            "effective_enabled_state": o["effective_enabled_state"],
            "health_avg": mean(h["health_avg"] for h in by_hour.values()),
            "health_min": min((h["health_min"] for h in by_hour.values() if h["health_min"] is not None), default=None),
            "hours_with_health_data": sum(1 for h in by_hour.values() if h["health_avg"] is not None),
            "hours_healthy": sum(1 for h in by_hour.values() if h["health_avg"] is not None and h["health_avg"] >= threshold),
            "requests": sum(h["requests"] or 0 for h in by_hour.values()) if o_requests else None,
            "hours_serving": len(served),
            "first_hour_serving": served[0] if served else None,
            "last_hour_serving": served[-1] if served else None,
            "requests_shared_with_groups": sorted({g for k in keys for g in shared_hosts.get((profile_key_, k), [])
                                                   if g != group["name"]}),
        })
        region = region_hours.setdefault(o["region"] or "unresolved", {})
        for t, h in by_hour.items():
            slot = region.setdefault(t, {"health": [], "healthy": False, "requests": 0})
            if h["health_avg"] is not None:
                slot["health"].append(h["health_avg"])
                slot["healthy"] = slot["healthy"] or h["health_avg"] >= threshold
            slot["requests"] += h["requests"] or 0
    hours = sorted({t for by_hour in region_hours.values() for t in by_hour})
    for row, by_hour in zip(origin_rows, origin_hours):
        row["last_hour_health_avg"] = by_hour.get(last_health_hour, {}).get("health_avg") if last_health_hour else None
    group_requests = sum(s["requests"] for by_hour in region_hours.values() for s in by_hour.values())
    regions = []
    for name, by_hour in sorted(region_hours.items()):
        with_health = [s for s in by_hour.values() if s["health"]]
        total = sum(s["requests"] for s in by_hour.values())
        health_slot = by_hour.get(last_health_hour, {}) if last_health_hour else {}
        request_slot = by_hour.get(last_request_hour, {}) if last_request_hour else {}
        regions.append({
            "region": name,
            "origins": sorted(r["origin"] for r in origin_rows if (r["region"] or "unresolved") == name),
            "health_avg": mean(v for s in with_health for v in s["health"]),
            "hours_with_health_data": len(with_health),
            "hours_healthy": sum(1 for s in with_health if s["healthy"]),
            "healthy_last_hour": bool(health_slot.get("healthy")) if health_slot.get("health") else None,
            "requests": total,
            "request_share_percentage": round(100 * total / group_requests, 2) if group_requests else None,
            "hours_serving": sum(1 for s in by_hour.values() if s["requests"] > 0),
            "serving_last_hour": (request_slot.get("requests") or 0) > 0 if last_request_hour else None,
        })
    resolved = [r for r in regions if r["region"] != "unresolved"]
    with_health = [r for r in resolved if r["healthy_last_hour"] is not None]
    shifts = traffic_shifts(hours, {r: region_hours[r] for r in region_hours if r != "unresolved"})
    multi_region = len(group["enabled_regions"]) >= 2
    return {
        "profile": group["profile"],
        "origin_group": group["name"],
        "origin_group_id": group["id"],
        "serving": group["serving"],
        "enabled_regions": group["enabled_regions"],
        "multi_region": multi_region,
        "health_threshold_percentage": threshold,
        "has_health_data": any(r["hours_with_health_data"] for r in regions),
        "has_traffic": group_requests > 0,
        "requests": group_requests,
        "last_request_hour": last_request_hour,
        "last_health_hour": last_health_hour,
        "origins": origin_rows,
        "regions": regions,
        "all_regions_healthy_last_hour": all(r["healthy_last_hour"] for r in with_health) if with_health else None,
        "regions_serving_last_hour": [r["region"] for r in resolved if r["serving_last_hour"]],
        "all_enabled_regions_serving_last_hour": None if last_request_hour is None else bool(group["enabled_regions"]) and all(
            any(r["region"] == e and r["serving_last_hour"] for r in resolved) for e in group["enabled_regions"]),
        "traffic_shift_count": len(shifts),
        "traffic_shifts": shifts[-MAX_TRAFFIC_SHIFTS:],
        "hourly_by_region": [
            {"time": t, "regions": {r: {"requests": region_hours[r].get(t, {}).get("requests", 0),
                                        "health_avg": mean(region_hours[r].get(t, {}).get("health", []))}
                                    for r in sorted(region_hours)}}
            for t in hours
        ] if multi_region else [],
    }


def origin_health_records(groups: list[dict], metrics_by_profile: dict, window_end: str) -> tuple[list[dict], list[dict]]:
    """Each group's health and traffic per origin and region, and the metric series matching no origin."""
    hosts_by_profile: dict = {}
    for g in groups:
        for o in g["origins"]:
            for k in request_keys(o):
                hosts_by_profile.setdefault((profile_key(g["id"]), k), set()).add(g["name"])
    records = []
    for g in groups:
        key = profile_key(g["id"])
        metrics = metrics_by_profile.get(key) or {"health": [], "requests": []}
        records.append(group_health_record(key, g, metrics["health"], metrics["requests"], hosts_by_profile,
                                           *last_hours(metrics, window_end)))
    unmatched = [
        {"profile_id": key, "metric": metric, "origin": s["origin"], "origin_group": s["origin_group"],
         "total": sum(p["total"] or 0 for p in s["points"]) if metric == "OriginRequestCount" else None}
        for key, metrics in sorted(metrics_by_profile.items())
        for metric, series in (("OriginHealthPercentage", metrics["health"]), ("OriginRequestCount", metrics["requests"]))
        for s in series
        if (key, metric_host(s["origin"])) not in hosts_by_profile
    ]
    return records, unmatched


def summarize_health(records: list[dict], unmatched: list[dict], days: int, window: tuple[str, str]) -> dict:
    serving = [r for r in records if r["serving"]]
    multi = [r for r in serving if r["multi_region"]]
    return {
        "metrics_lookback_days": days,
        "metrics_window_start": window[0],
        "metrics_window_end": window[1],
        "serving_groups_with_health_data": sum(1 for r in serving if r["has_health_data"]),
        "serving_groups_with_traffic": sum(1 for r in serving if r["has_traffic"]),
        "serving_groups_without_traffic": sum(1 for r in serving if not r["has_traffic"]),
        "serving_groups_all_regions_healthy_last_hour": sum(1 for r in serving if r["all_regions_healthy_last_hour"]),
        "serving_groups_region_unhealthy_last_hour": sum(1 for r in serving if r["all_regions_healthy_last_hour"] is False),
        "serving_multi_region_groups": len(multi),
        "serving_multi_region_groups_all_regions_healthy_last_hour": sum(1 for r in multi if r["all_regions_healthy_last_hour"]),
        "serving_multi_region_groups_all_regions_serving_last_hour": sum(
            1 for r in multi if r["all_enabled_regions_serving_last_hour"]),
        "serving_multi_region_groups_with_traffic_shift": sum(1 for r in multi if r["traffic_shift_count"]),
        "regions_serving_traffic": sorted({reg["region"] for r in serving for reg in r["regions"]
                                           if reg["requests"] and reg["region"] != "unresolved"}),
        "origin_metric_series_unmatched": len(unmatched),
    }


# --- collection (lazy azure imports) ---

def kql_list(values) -> str:
    # ARM ids and host names never contain quotes; drop any value that would break the literal.
    return ", ".join(f"'{v}'" for v in values if "'" not in v and "\\" not in v)


def region_queries(resource_ids: list[str], host_names: list[str]) -> list[str]:
    queries = []
    for i in range(0, len(resource_ids), LOOKUP_CHUNK):
        ids = kql_list(resource_ids[i:i + LOOKUP_CHUNK])
        if ids:
            queries.append(f"resources | where id in~ ({ids}) | project key = tolower(id), id, location | order by id asc")
    for i in range(0, len(host_names), LOOKUP_CHUNK):
        hosts = kql_list(host_names[i:i + LOOKUP_CHUNK])
        if not hosts:
            continue
        queries.append(
            "resources | where type =~ 'microsoft.web/sites'"
            " | mv-expand h = properties.enabledHostNames to typeof(string)"
            f" | where h in~ ({hosts}) | project key = tolower(h), id, location"
            " | union (resources | where type =~ 'microsoft.storage/storageaccounts'"
            " | mv-expand e = pack_array(properties.primaryEndpoints.blob, properties.primaryEndpoints.web,"
            " properties.primaryEndpoints.dfs, properties.primaryEndpoints.file, properties.primaryEndpoints.queue,"
            " properties.primaryEndpoints.table) to typeof(string)"
            f" | extend h = tolower(tostring(parse_url(e).Host)) | where h in~ ({hosts}) | project key = h, id, location)"
            " | order by id asc, key asc"
        )
    return queries


def graph_client(cred, collector: Collector):
    return collector.guard("resourcegraph.ResourceGraphClient (init)", lambda: resource_graph_client(cred))


def graph_rows(client, query: str) -> list[dict]:
    # An origin can live in any subscription the credential reads.
    return query_all(client, ALL_SUBSCRIPTIONS, query)["rows"]


def lookup_regions(client, collector: Collector, resource_ids: list[str], host_names: list[str]) -> tuple[dict, dict]:
    """Location of each origin's target resource, by ARM id and by host name, from Resource Graph."""
    if client is None or (not resource_ids and not host_names):
        return {}, {}
    found: dict = {}
    for n, query in enumerate(region_queries(resource_ids, host_names)):
        for row in collector.guard(f"resourcegraph.resources (origin regions {n + 1})", lambda: graph_rows(client, query), default=[]):
            if row.get("key") and row.get("location"):
                found[row["key"].rstrip("/")] = str(row["location"]).lower().replace(" ", "")
    hosts = {h.lower() for h in host_names}
    return ({k: v for k, v in found.items() if k not in hosts}, {k: v for k, v in found.items() if k in hosts})


SITE_TYPES = "type in~ ('microsoft.web/sites', 'microsoft.web/sites/slots')"
SITE_COLUMNS = (
    "key = tolower(id), id, name, type, kind, location, subscriptionId, tags, state = tostring(properties.state),"
    " server_farm_id = tostring(properties.serverFarmId), public_network_access = tostring(properties.publicNetworkAccess)"
)


def site_queries(subscription_id: str, site_ids: list[str], host_names: list[str]) -> list[str]:
    """Every app in the subscription, plus each origin's app or slot by id or host name in any subscription."""
    queries = []
    if subscription_id and "'" not in subscription_id:
        queries.append(f"resources | where type =~ 'microsoft.web/sites' and subscriptionId =~ '{subscription_id}'"
                       f" | project {SITE_COLUMNS}, host = '' | order by id asc")
    for i in range(0, len(site_ids), LOOKUP_CHUNK):
        ids = kql_list(site_ids[i:i + LOOKUP_CHUNK])
        if ids:
            queries.append(f"resources | where {SITE_TYPES} and id in~ ({ids}) | project {SITE_COLUMNS}, host = ''"
                           " | order by id asc")
    for i in range(0, len(host_names), LOOKUP_CHUNK):
        hosts = kql_list(host_names[i:i + LOOKUP_CHUNK])
        if hosts:
            queries.append(f"resources | where {SITE_TYPES} | mv-expand h = properties.enabledHostNames to typeof(string)"
                           f" | where h in~ ({hosts}) | project {SITE_COLUMNS}, host = tolower(h) | order by id asc, host asc")
    return queries


def plan_queries(plan_ids: list[str]) -> list[str]:
    queries = []
    for i in range(0, len(plan_ids), LOOKUP_CHUNK):
        ids = kql_list(plan_ids[i:i + LOOKUP_CHUNK])
        if ids:
            queries.append(f"resources | where type =~ 'microsoft.web/serverfarms' and id in~ ({ids})"
                           " | project key = tolower(id), id, name, location, sku, zone_redundant = tobool(properties.zoneRedundant)"
                           " | order by id asc")
    return queries


def lookup_sites(client, collector: Collector, subscription_id: str, site_ids: list[str], host_names: list[str]) -> tuple[dict, dict]:
    """App Service apps from Resource Graph keyed by lower-cased id, and the app owning each looked-up host name."""
    if client is None:
        return {}, {}
    sites, by_host = {}, {}
    for n, query in enumerate(site_queries(subscription_id, site_ids, host_names)):
        for row in collector.guard(f"resourcegraph.resources (sites {n + 1})", lambda: graph_rows(client, query), default=[]):
            if not row.get("key"):
                continue
            key = row["key"].rstrip("/")
            sites[key] = {k: v for k, v in row.items() if k not in ("key", "host")}
            if row.get("host"):
                by_host[row["host"]] = key
    return sites, by_host


def lookup_plans(client, collector: Collector, plan_ids: list[str]) -> dict:
    plans: dict = {}
    if client is None:
        return plans
    for n, query in enumerate(plan_queries(plan_ids)):
        for row in collector.guard(f"resourcegraph.resources (plans {n + 1})", lambda: graph_rows(client, query), default=[]):
            if row.get("key"):
                plans[row["key"].rstrip("/")] = {k: v for k, v in row.items() if k != "key"}
    return plans


def read_site_configs(cred, collector: Collector, sites: list[dict]) -> dict:
    """config/web (access restrictions) for each app or slot, on a client per subscription."""
    from azure.mgmt.web import WebSiteManagementClient

    clients: dict = {}
    configs = {}
    for site in sites:
        parts = str(site["id"]).split("/")
        sub, rg, name = parts[2], parts[4], parts[8]
        slot = parts[10] if len(parts) == 11 else None
        if sub.lower() not in clients:
            clients[sub.lower()] = collector.guard(
                f"web.WebSiteManagementClient (init {sub})",
                lambda: WebSiteManagementClient(credential=cred, subscription_id=sub, **arm_client_kwargs()),
            )
        client = clients[sub.lower()]
        if client is None:
            continue
        if slot:
            config = collector.guard(f"web.web_apps.get_configuration_slot({name}/{slot})",
                                     lambda: project_site_config(client.web_apps.get_configuration_slot(rg, name, slot)))
        else:
            config = collector.guard(f"web.web_apps.get_configuration({name})",
                                     lambda: project_site_config(client.web_apps.get_configuration(rg, name)))
        if config is not None:
            configs[arm_key(site["id"])] = config
    return configs


def lookback_days(collector: Collector) -> int:
    raw = os.environ.get(LOOKBACK_ENV) or str(DEFAULT_LOOKBACK_DAYS)
    try:
        days = int(raw)
    except ValueError:
        collector.record(f"config {LOOKBACK_ENV}",
                         ValueError(f"invalid lookback {raw!r}: expected an integer from 1 to {MAX_LOOKBACK_DAYS}"))
        return DEFAULT_LOOKBACK_DAYS
    clamped = min(max(days, 1), MAX_LOOKBACK_DAYS)
    if clamped != days:
        logger.warning("%s=%d is outside 1-%d; using %d", LOOKBACK_ENV, days, MAX_LOOKBACK_DAYS, clamped)
    return clamped


def metrics_window(days: int, now: datetime) -> tuple[str, str]:
    # Whole hours only: the current hour's bucket is still filling.
    end = now.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=days)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_origin_metrics(subscription_id, cred, collector: Collector, profiles: list[dict], window: tuple[str, str]) -> dict:
    """Hourly OriginHealthPercentage (by origin and group) and OriginRequestCount (by origin) for each profile."""
    if not profiles:
        return {}
    monitor = collector.guard("monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred))
    if monitor is None:
        return {}
    timespan = f"{window[0]}/{window[1]}"
    metrics = {}
    for profile in profiles:
        uri = str(profile["id"]).lstrip("/")
        metrics[arm_key(profile["id"])] = {
            "health": collector.guard(
                f"monitor.metrics.list(OriginHealthPercentage, {profile['name']})",
                lambda: project_metric_series(monitor.metrics.list(
                    uri, timespan=timespan, interval=timedelta(hours=1), metricnames="OriginHealthPercentage",
                    aggregation="Average,Minimum", filter="Origin eq '*' and OriginGroup eq '*'", top=METRICS_TOP)),
                default=[],
            ),
            "requests": collector.guard(
                f"monitor.metrics.list(OriginRequestCount, {profile['name']})",
                lambda: project_metric_series(monitor.metrics.list(
                    uri, timespan=timespan, interval=timedelta(hours=1), metricnames="OriginRequestCount",
                    aggregation="Total", filter="Origin eq '*'", top=METRICS_TOP)),
                default=[],
            ),
        }
    return metrics


def collect_profiles(subscription_id, cred, collector: Collector) -> tuple[list[dict], dict]:
    cdn = cdn_client(subscription_id, cred, collector)
    cdn_origins = cdn_client(subscription_id, cred, collector, api_version=ORIGIN_API_VERSION)
    if cdn is None or cdn_origins is None:
        return [], {}
    profiles, skipped = front_door_profiles(cdn, collector)
    collected = []
    for profile in profiles:
        rg, name = resource_group_from_id(profile["id"]), profile["name"]
        # The X-Azure-FDID value Front Door stamps on every request it forwards.
        profile["front_door_id"] = collector.guard(
            f"cdn.profiles.get({name})",
            lambda: model_attr(model_attr(cdn.profiles.get(rg, name), "properties"), "front_door_id"),
        )
        groups = collector.guard(
            f"cdn.afd_origin_groups.list_by_profile({name})",
            lambda: [project_origin_group(g) for g in cdn_origins.afd_origin_groups.list_by_profile(rg, name)],
            default=[],
        )
        for group in groups:
            group["origins_projected"] = collector.guard(
                f"cdn.afd_origins.list_by_origin_group({name}/{group['name']})",
                lambda: [project_origin(o) for o in cdn_origins.afd_origins.list_by_origin_group(rg, name, group["name"])],
                default=[],
            )
        collected.append({
            "profile": profile,
            "endpoints": endpoints_with_routes(cdn, collector, profile),
            "rule_sets": rule_sets_with_rules(cdn, collector, profile),
            "origin_groups": sorted(groups, key=lambda g: arm_key(g["id"])),
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
    regions_by_id: dict = {}
    regions_by_host: dict = {}
    sites_by_key: dict = {}
    sites_by_host: dict = {}
    plans_by_key: dict = {}
    configs_by_key: dict = {}
    metrics_by_profile: dict = {}
    days = lookback_days(collector)
    window = metrics_window(days, datetime.now(timezone.utc))
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Cdn")
        if registration == NOT_REGISTERED:
            logger.warning("Microsoft.Cdn is not registered on subscription %s", subscription_id)
        collected, skipped_by_sku = collect_profiles(subscription_id, cred, collector)
        origins = [o for c in collected for g in c["origin_groups"] for o in g["origins_projected"]]
        ids = sorted({arm_key(i) for o in origins for i in (o["azure_origin_id"], (o["private_link"] or {}).get("target_id")) if i})
        hosts = sorted({str(o["host_name"]).lower() for o in origins if o["host_name"]})
        graph = graph_client(cred, collector)
        regions_by_id, regions_by_host = lookup_regions(graph, collector, ids, hosts)
        known_sites = [(o, origin_site_id(o, {})[0]) for o in origins]
        sites_by_key, sites_by_host = lookup_sites(
            graph, collector, subscription_id, sorted({k for _, k in known_sites if k}),
            sorted({str(o["host_name"]).lower() for o, k in known_sites if o["host_name"] and not k}),
        )
        origin_sites = {origin_site_id(o, sites_by_host)[0] for o in origins} & set(sites_by_key)
        plans_by_key = lookup_plans(graph, collector, sorted({
            arm_key(s["server_farm_id"]) for s in sites_by_key.values() if s.get("server_farm_id")}))
        configs_by_key = read_site_configs(cred, collector, [sites_by_key[k] for k in sorted(origin_sites)])
        metrics_by_profile = collect_origin_metrics(subscription_id, cred, collector, [c["profile"] for c in collected], window)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    profiles, groups = [], []
    for c in collected:
        paths = origin_paths(c["profile"], c["endpoints"], c["rule_sets"])
        profile_groups = [
            group_record(c["profile"], {k: v for k, v in g.items() if k != "origins_projected"}, g["origins_projected"],
                         paths, regions_by_id, regions_by_host)
            for g in c["origin_groups"]
        ]
        groups += profile_groups
        profiles.append({
            **c["profile"],
            "origin_group_count": len(profile_groups),
            "origin_count": sum(g["total_origins"] for g in profile_groups),
        })

    profile_fdids = {arm_key(p["id"]): p.get("front_door_id") for p in profiles}
    app_origins = app_service_origin_records(groups, profile_fdids, sites_by_key, sites_by_host, plans_by_key, configs_by_key,
                                             subscription_id)
    production_tag = (os.environ.get(PRODUCTION_TAG_ENV) or "").strip() or None
    apps = production_apps(sites_by_key, subscription_id, production_tag, groups, app_origins, plans_by_key)
    health, unmatched = origin_health_records(groups, metrics_by_profile, window[1])

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={"origin_groups": groups, "profiles": profiles, "provider_registration_status": registration,
                 "app_service_origins": app_origins, "production_apps": apps, "origin_health": health,
                 "unmatched_origin_metrics": unmatched},
        summary={**summarize(profiles, skipped_by_sku, groups), "provider_registration_status": registration,
                 **summarize_app_services(app_origins, apps, production_tag),
                 **summarize_health(health, unmatched, days, window)},
    )
    filename = f"azure_front_door_origins_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
