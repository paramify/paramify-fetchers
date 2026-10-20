#!/usr/bin/env python3
"""Azure Application Gateway listeners with their protocol, redirect behaviour and effective TLS policy."""

import logging
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from app_gateway import (  # noqa: E402
    ENCRYPTED_PROTOCOLS,
    arm_id_key,
    enum_value,
    frontend_ip_types,
    frontend_ports,
    gateway_identity,
    index_by_id,
    ref_id,
    rules_by_listener,
    run_fetcher,
)
from azure_common import Collector, basename, model_attr  # noqa: E402

logger = logging.getLogger("azure_app_gateway_tls_listeners")

PREDEFINED_MIN_TLS = {
    "AppGwSslPolicy20150501": "TLSv1_0",
    "AppGwSslPolicy20170401": "TLSv1_1",
    "AppGwSslPolicy20170401S": "TLSv1_2",
    "AppGwSslPolicy20220101": "TLSv1_2",
    "AppGwSslPolicy20220101S": "TLSv1_2",
}
TLS_ORDER = ("TLSv1_0", "TLSv1_1", "TLSv1_2", "TLSv1_3")
BELOW_TLS12 = ("TLSv1_0", "TLSv1_1")


def project_ssl_policy(policy) -> dict | None:
    record = {
        "policy_type": model_attr(policy, "policy_type"),
        "policy_name": model_attr(policy, "policy_name"),
        "min_protocol_version": model_attr(policy, "min_protocol_version"),
        "cipher_suites": [str(enum_value(c)) for c in (model_attr(policy, "cipher_suites") or [])],
        "disabled_ssl_protocols": [
            str(enum_value(p)) for p in (model_attr(policy, "disabled_ssl_protocols") or [])
        ],
    }
    return record if any(record.values()) else None


def policy_min_tls(policy: dict | None) -> str | None:
    if not policy:
        return None
    if policy["policy_type"] in ("Custom", "CustomV2"):
        return policy["min_protocol_version"]
    if policy["policy_name"]:
        return PREDEFINED_MIN_TLS.get(policy["policy_name"])
    if policy["disabled_ssl_protocols"]:
        return next((v for v in TLS_ORDER if v not in policy["disabled_ssl_protocols"]), None)
    return policy["min_protocol_version"]


def effective_tls(protocol, profile_policy, gateway_policy, default_policy_name) -> dict:
    """The policy a listener actually gets: SSL profile, else gateway, else the platform default."""
    if protocol not in ENCRYPTED_PROTOCOLS:
        source, policy = "not_applicable", None
    elif profile_policy:
        source, policy = "ssl_profile", profile_policy
    elif gateway_policy:
        source, policy = "gateway", gateway_policy
    elif default_policy_name:
        source, policy = "platform_default", {
            "policy_type": "Predefined", "policy_name": default_policy_name,
            "min_protocol_version": None, "cipher_suites": [], "disabled_ssl_protocols": [],
        }
    else:
        source, policy = "default_not_reported", None
    return {
        "tls_policy_source": source,
        "tls_policy_type": (policy or {}).get("policy_type"),
        "tls_policy_name": (policy or {}).get("policy_name"),
        "effective_min_tls_version": policy_min_tls(policy),
        "cipher_suites": (policy or {}).get("cipher_suites") or [],
    }


def rule_redirect_ids(rule, path_maps: dict) -> list | None:
    """Redirect config ids if every path of the rule redirects, [] if any path routes, None if unknown."""
    rule_type = model_attr(rule, "rule_type")
    if rule_type == "Basic":
        redirect = ref_id(rule, "redirect_configuration")
        return [redirect] if redirect else []
    if rule_type == "PathBasedRouting":
        path_map = path_maps.get(arm_id_key(ref_id(rule, "url_path_map")))
        if path_map is None:
            return None
        ids = [ref_id(path_map, "default_redirect_configuration")]
        ids += [ref_id(p, "redirect_configuration") for p in (model_attr(path_map, "path_rules") or [])]
        return ids if all(ids) else []
    return None


def redirect_target_https(redirect, listener_protocols: dict) -> bool | None:
    target_listener = ref_id(redirect, "target_listener")
    if target_listener:
        protocol = listener_protocols.get(arm_id_key(target_listener))
        return None if protocol is None else protocol == "Https"
    target_url = model_attr(redirect, "target_url")
    return str(target_url).lower().startswith("https://") if target_url else None


def all_true(values: list) -> bool | None:
    if any(v is False for v in values):
        return False
    return True if values and all(v is True for v in values) else None


def redirect_behaviour(rules: list, path_maps: dict, redirects: dict, listener_protocols: dict) -> dict:
    if not rules:
        return {"redirect_only": False, "redirect_target_https": None}
    per_rule = [rule_redirect_ids(r, path_maps) for r in rules]
    if any(ids == [] for ids in per_rule):
        return {"redirect_only": False, "redirect_target_https": None}
    if any(ids is None for ids in per_rule):
        return {"redirect_only": None, "redirect_target_https": None}
    targets = [
        redirect_target_https(redirects.get(arm_id_key(i)), listener_protocols)
        if arm_id_key(i) in redirects else None
        for ids in per_rule for i in ids
    ]
    return {"redirect_only": True, "redirect_target_https": all_true(targets)}


def secure_transport(record: dict) -> bool:
    if record["protocol"] in ENCRYPTED_PROTOCOLS:
        return True
    return record["protocol"] == "Http" and record["redirect_only"] is True and record["redirect_target_https"] is True


def listener_records(gateway) -> list[dict]:
    """One record per L7 (http_listeners) and L4 (listeners) listener on the gateway."""
    ports = frontend_ports(gateway)
    ip_types = frontend_ip_types(gateway)
    profiles = index_by_id(model_attr(gateway, "ssl_profiles"))
    path_maps = index_by_id(model_attr(gateway, "url_path_maps"))
    redirects = index_by_id(model_attr(gateway, "redirect_configurations"))
    gateway_policy = project_ssl_policy(model_attr(gateway, "ssl_policy"))
    default_policy = model_attr(gateway, "default_predefined_ssl_policy")
    http_listeners = model_attr(gateway, "http_listeners") or []
    l4_listeners = model_attr(gateway, "listeners") or []
    listener_protocols = {
        arm_id_key(model_attr(li, "id")): model_attr(li, "protocol") for li in (*http_listeners, *l4_listeners)
    }
    listener_rules = rules_by_listener(gateway)

    records = []
    for layer, listeners in (("L7", http_listeners), ("L4", l4_listeners)):
        for listener in listeners:
            key = arm_id_key(model_attr(listener, "id"))
            protocol = model_attr(listener, "protocol")
            profile_id = ref_id(listener, "ssl_profile")
            profile = profiles.get(arm_id_key(profile_id))
            rules = listener_rules.get(key, [])
            host_names = [h for h in [model_attr(listener, "host_name"), *(model_attr(listener, "host_names") or [])] if h]
            record = {
                "gateway_id": model_attr(gateway, "id"),
                "gateway_name": model_attr(gateway, "name"),
                "gateway_operational_state": model_attr(gateway, "operational_state"),
                "id": model_attr(listener, "id"),
                "name": model_attr(listener, "name"),
                "layer": layer,
                "protocol": protocol,
                "port": ports.get(arm_id_key(ref_id(listener, "frontend_port"))),
                "frontend_ip_configuration": basename(ref_id(listener, "frontend_ip_configuration")),
                "frontend_type": ip_types.get(arm_id_key(ref_id(listener, "frontend_ip_configuration"))),
                "host_names": host_names,
                "ssl_certificate": basename(ref_id(listener, "ssl_certificate")),
                "ssl_profile": basename(profile_id),
                "routing_rules": sorted(model_attr(r, "name") or "" for r in rules),
                **(
                    redirect_behaviour(rules, path_maps, redirects, listener_protocols)
                    if layer == "L7" else {"redirect_only": None, "redirect_target_https": None}
                ),
                **effective_tls(
                    protocol,
                    project_ssl_policy(model_attr(profile, "ssl_policy")) if profile is not None else None,
                    gateway_policy,
                    default_policy,
                ),
            }
            record["secure_transport"] = secure_transport(record)
            records.append(record)
    return records


def gateway_record(gateway, listeners: list[dict]) -> dict:
    return {
        **gateway_identity(gateway),
        "enable_fips": model_attr(gateway, "enable_fips"),
        "ssl_policy": project_ssl_policy(model_attr(gateway, "ssl_policy")),
        "default_predefined_ssl_policy": model_attr(gateway, "default_predefined_ssl_policy"),
        "ssl_profiles": sorted(
            basename(model_attr(p, "id")) or "" for p in (model_attr(gateway, "ssl_profiles") or [])
        ),
        "listener_count": len(listeners),
        "plaintext_listener_count": sum(1 for li in listeners if not li["secure_transport"]),
    }


def summarize(gateways: list[dict], listeners: list[dict]) -> dict:
    plaintext = [li for li in listeners if not li["secure_transport"]]
    encrypted = [li for li in listeners if li["protocol"] in ENCRYPTED_PROTOCOLS]
    return {
        "total_application_gateways": len(gateways),
        "running_application_gateways": sum(1 for g in gateways if g["operational_state"] == "Running"),
        "total_listeners": len(listeners),
        "l7_listeners": sum(1 for li in listeners if li["layer"] == "L7"),
        "l4_listeners": sum(1 for li in listeners if li["layer"] == "L4"),
        "encrypted_listeners": len(encrypted),
        "http_redirect_only_listeners": sum(
            1 for li in listeners if li["protocol"] == "Http" and li["secure_transport"]
        ),
        "plaintext_listeners": len(plaintext),
        "public_plaintext_listeners": sum(1 for li in plaintext if li["frontend_type"] == "public"),
        "listeners_below_tls12": sum(1 for li in encrypted if li["effective_min_tls_version"] in BELOW_TLS12),
        "listeners_tls_version_unknown": sum(1 for li in encrypted if not li["effective_min_tls_version"]),
        "gateways_fips_enabled": sum(1 for g in gateways if g["enable_fips"] is True),
        "gateways_fips_disabled": sum(1 for g in gateways if g["enable_fips"] is False),
        "gateways_fips_not_reported": sum(1 for g in gateways if g["enable_fips"] is None),
    }


def build(raw_gateways: list, collector: Collector, subscription_id, cred) -> tuple[dict, dict]:
    gateways, listeners = [], []
    for gateway in raw_gateways:
        records = collector.guard(
            f"project listeners ({model_attr(gateway, 'name')})", lambda g=gateway: listener_records(g), default=[]
        )
        listeners.extend(records)
        gateways.append(gateway_record(gateway, records))
    gateways.sort(key=lambda r: arm_id_key(r["id"]))
    listeners.sort(key=lambda r: arm_id_key(r["id"]))
    return {"application_gateways": gateways, "listeners": listeners}, summarize(gateways, listeners)


if __name__ == "__main__":
    sys.exit(run_fetcher("azure_app_gateway_tls_listeners", logger, build))
