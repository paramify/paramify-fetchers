#!/usr/bin/env python3
"""Azure Application Gateway backend settings: whether traffic to each backend is encrypted and its certificate validated."""

import logging
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from app_gateway import (  # noqa: E402
    ENCRYPTED_PROTOCOLS,
    arm_id_key,
    gateway_identity,
    index_by_id,
    ref_id,
    run_fetcher,
)
from azure_common import Collector, basename, model_attr  # noqa: E402

logger = logging.getLogger("azure_app_gateway_backend_tls")


def certificate_validation(layer: str, protocol, validate_chain) -> str:
    if protocol not in ENCRYPTED_PROTOCOLS:
        return "not_applicable"
    if layer == "L4":
        return "not_configurable"
    if validate_chain is False:
        return "disabled"
    return "enabled" if validate_chain is True else "default_enabled"


def setting_usage(gateway) -> dict:
    """Backend setting id -> names of the rules and path rules that send traffic through it."""
    usage: dict = {}

    def add(setting_id, name):
        if setting_id:
            usage.setdefault(arm_id_key(setting_id), set()).add(name or "")

    path_maps = index_by_id(model_attr(gateway, "url_path_maps"))
    for rule in model_attr(gateway, "request_routing_rules") or []:
        name = model_attr(rule, "name")
        add(ref_id(rule, "backend_http_settings"), name)
        path_map = path_maps.get(arm_id_key(ref_id(rule, "url_path_map")))
        if path_map is not None:
            add(ref_id(path_map, "default_backend_http_settings"), name)
            for path_rule in model_attr(path_map, "path_rules") or []:
                add(ref_id(path_rule, "backend_http_settings"), f"{name}/{model_attr(path_rule, 'name')}")
    for rule in model_attr(gateway, "routing_rules") or []:
        add(ref_id(rule, "backend_settings"), model_attr(rule, "name"))
    return usage


def ref_names(refs) -> list:
    return sorted(basename(model_attr(r, "id")) or "" for r in (refs or []))


def backend_setting_records(gateway) -> list[dict]:
    """One record per L7 (backendHttpSettingsCollection) and L4 (backendSettingsCollection) setting."""
    probes = index_by_id(model_attr(gateway, "probes"))
    usage = setting_usage(gateway)
    records = []
    layers = (
        ("L7", model_attr(gateway, "backend_http_settings_collection") or []),
        ("L4", model_attr(gateway, "backend_settings_collection") or []),
    )
    for layer, settings in layers:
        for setting in settings:
            protocol = model_attr(setting, "protocol")
            l7 = layer == "L7"
            validate_chain = model_attr(setting, "validate_cert_chain_and_expiry") if l7 else None
            validate_sni = model_attr(setting, "validate_sni") if l7 else None
            used_by = sorted(usage.get(arm_id_key(model_attr(setting, "id")), set()))
            validation = certificate_validation(layer, protocol, validate_chain)
            encrypted = protocol in ENCRYPTED_PROTOCOLS
            records.append({
                "gateway_id": model_attr(gateway, "id"),
                "gateway_name": model_attr(gateway, "name"),
                "gateway_operational_state": model_attr(gateway, "operational_state"),
                "id": model_attr(setting, "id"),
                "name": model_attr(setting, "name"),
                "layer": layer,
                "protocol": protocol,
                "port": model_attr(setting, "port"),
                "used_by_rules": used_by,
                "in_use": bool(used_by),
                "encrypted": encrypted,
                "validate_cert_chain_and_expiry": validate_chain,
                "validate_sni": validate_sni,
                "sni_name": model_attr(setting, "sni_name") if l7 else None,
                "certificate_validation": validation,
                "host_name": model_attr(setting, "host_name"),
                "pick_host_name_from_backend_address": model_attr(setting, "pick_host_name_from_backend_address"),
                "trusted_root_certificates": ref_names(model_attr(setting, "trusted_root_certificates")),
                "authentication_certificates": ref_names(model_attr(setting, "authentication_certificates")) if l7 else [],
                "probe": basename(ref_id(setting, "probe")),
                "probe_protocol": model_attr(probes.get(arm_id_key(ref_id(setting, "probe"))), "protocol"),
                "secure_backend": encrypted and validation != "disabled" and validate_sni is not False,
            })
    return records


def gateway_record(gateway, settings: list[dict]) -> dict:
    in_use = [s for s in settings if s["in_use"]]
    return {
        **gateway_identity(gateway),
        "trusted_root_certificates": sorted(
            (
                {
                    "name": model_attr(c, "name"),
                    "source": "key_vault" if model_attr(c, "key_vault_secret_id") else "uploaded",
                }
                for c in (model_attr(gateway, "trusted_root_certificates") or [])
            ),
            key=lambda c: c["name"] or "",
        ),
        "backend_setting_count": len(settings),
        "insecure_backend_settings_in_use": sum(1 for s in in_use if not s["secure_backend"]),
    }


def summarize(gateways: list[dict], settings: list[dict]) -> dict:
    in_use = [s for s in settings if s["in_use"]]
    return {
        "total_application_gateways": len(gateways),
        "total_backend_settings": len(settings),
        "in_use_backend_settings": len(in_use),
        "encrypted_in_use": sum(1 for s in in_use if s["encrypted"]),
        "plaintext_in_use": sum(1 for s in in_use if not s["encrypted"]),
        "certificate_validation_disabled_in_use": sum(1 for s in in_use if s["certificate_validation"] == "disabled"),
        "sni_validation_disabled_in_use": sum(1 for s in in_use if s["validate_sni"] is False),
        "insecure_backend_settings_in_use": sum(1 for s in in_use if not s["secure_backend"]),
        "plaintext_probes_in_use": sum(1 for s in in_use if s["probe_protocol"] in ("Http", "Tcp")),
    }


def build(raw_gateways: list, collector: Collector, subscription_id, cred) -> tuple[dict, dict]:
    gateways, settings = [], []
    for gateway in raw_gateways:
        records = collector.guard(
            f"project backend settings ({model_attr(gateway, 'name')})",
            lambda g=gateway: backend_setting_records(g),
            default=[],
        )
        settings.extend(records)
        gateways.append(gateway_record(gateway, records))
    gateways.sort(key=lambda r: arm_id_key(r["id"]))
    settings.sort(key=lambda r: arm_id_key(r["id"]))
    return {"application_gateways": gateways, "backend_settings": settings}, summarize(gateways, settings)


if __name__ == "__main__":
    sys.exit(run_fetcher("azure_app_gateway_backend_tls", logger, build))
