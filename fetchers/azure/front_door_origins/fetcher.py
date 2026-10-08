#!/usr/bin/env python3
"""Azure Front Door origin groups and origins: regions serving traffic, and how Front Door connects to each origin, for one subscription."""

import logging
import os
import sys
from collections import Counter
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

logger = logging.getLogger("azure_front_door_origins")

# First GA api-version with certificateNameCheckValidationMode and tokenDestinationHeader.
ORIGIN_API_VERSION = "2026-07-01"
LOOKUP_CHUNK = 50
PAGE_SIZE = 1000
MAX_PAGES = 100


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


# --- collection (lazy azure imports) ---

def kql_list(values) -> str:
    # ARM ids and host names never contain quotes; drop any value that would break the literal.
    return ", ".join(f"'{v}'" for v in values if "'" not in v and "\\" not in v)


def region_queries(resource_ids: list[str], host_names: list[str]) -> list[str]:
    queries = []
    for i in range(0, len(resource_ids), LOOKUP_CHUNK):
        ids = kql_list(resource_ids[i:i + LOOKUP_CHUNK])
        if ids:
            queries.append(f"resources | where id in~ ({ids}) | project key = tolower(id), location")
    for i in range(0, len(host_names), LOOKUP_CHUNK):
        hosts = kql_list(host_names[i:i + LOOKUP_CHUNK])
        if not hosts:
            continue
        queries.append(
            "resources | where type =~ 'microsoft.web/sites'"
            " | mv-expand h = properties.enabledHostNames to typeof(string)"
            f" | where h in~ ({hosts}) | project key = tolower(h), location"
            " | union (resources | where type =~ 'microsoft.storage/storageaccounts'"
            " | mv-expand e = pack_array(properties.primaryEndpoints.blob, properties.primaryEndpoints.web,"
            " properties.primaryEndpoints.dfs, properties.primaryEndpoints.file, properties.primaryEndpoints.queue,"
            " properties.primaryEndpoints.table) to typeof(string)"
            f" | extend h = tolower(tostring(parse_url(e).Host)) | where h in~ ({hosts}) | project key = h, location)"
        )
    return queries


def lookup_regions(cred, collector: Collector, resource_ids: list[str], host_names: list[str]) -> tuple[dict, dict]:
    """Location of each origin's target resource, by ARM id and by host name, from Resource Graph."""
    if not resource_ids and not host_names:
        return {}, {}
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    client = collector.guard(
        "resourcegraph.ResourceGraphClient (init)", lambda: ResourceGraphClient(credential=cred, **arm_client_kwargs())
    )
    if client is None:
        return {}, {}

    def run(query: str) -> list[dict]:
        rows, skip_token, pages = [], None, 0
        while True:
            # No subscription filter: an origin can live in any subscription the credential reads.
            response = client.resources(QueryRequest(
                query=query, options=QueryRequestOptions(top=PAGE_SIZE, skip_token=skip_token, result_format="objectArray")
            ))
            rows += model_attr(response, "data") or []
            skip_token, pages = model_attr(response, "skip_token"), pages + 1
            if not skip_token:
                return rows
            if pages >= MAX_PAGES:
                raise RuntimeError(f"Resource Graph paging did not terminate after {pages} page(s)")

    found: dict = {}
    for n, query in enumerate(region_queries(resource_ids, host_names)):
        for row in collector.guard(f"resourcegraph.resources (origin regions {n + 1})", lambda: run(query), default=[]):
            if row.get("key") and row.get("location"):
                found[row["key"].rstrip("/")] = str(row["location"]).lower().replace(" ", "")
    hosts = {h.lower() for h in host_names}
    return ({k: v for k, v in found.items() if k not in hosts}, {k: v for k, v in found.items() if k in hosts})


def collect_profiles(subscription_id, cred, collector: Collector) -> tuple[list[dict], dict]:
    cdn = cdn_client(subscription_id, cred, collector)
    cdn_origins = cdn_client(subscription_id, cred, collector, api_version=ORIGIN_API_VERSION)
    if cdn is None or cdn_origins is None:
        return [], {}
    profiles, skipped = front_door_profiles(cdn, collector)
    collected = []
    for profile in profiles:
        rg, name = resource_group_from_id(profile["id"]), profile["name"]
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
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Cdn")
        if registration == NOT_REGISTERED:
            logger.warning("Microsoft.Cdn is not registered on subscription %s", subscription_id)
        collected, skipped_by_sku = collect_profiles(subscription_id, cred, collector)
        origins = [o for c in collected for g in c["origin_groups"] for o in g["origins_projected"]]
        ids = sorted({arm_key(i) for o in origins for i in (o["azure_origin_id"], (o["private_link"] or {}).get("target_id")) if i})
        hosts = sorted({str(o["host_name"]).lower() for o in origins if o["host_name"]})
        regions_by_id, regions_by_host = lookup_regions(cred, collector, ids, hosts)
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

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={"origin_groups": groups, "profiles": profiles, "provider_registration_status": registration},
        summary={**summarize(profiles, skipped_by_sku, groups), "provider_registration_status": registration},
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
