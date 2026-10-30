#!/usr/bin/env python3
"""Sophos Central protection state per endpoint: services, tamper protection, product, threats."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "_shared"))
from sophos_client import SophosError  # noqa: E402
from sophos_evidence import (  # noqa: E402
    ABSENT,
    PROTECTION_PRODUCTS,
    count_by,
    endpoint_identity,
    run,
    tally,
)

OUTPUT_FILE = "sophos_endpoint_protection.json"


def item(ep: dict) -> dict:
    unread: dict = {}
    health = ep.get("health") if isinstance(ep.get("health"), dict) else {}
    services = (health.get("services") or {}).get("serviceDetails")
    if isinstance(services, list) and services:
        not_running = sorted(f"{s.get('name')}: {s.get('status')}" for s in services if s.get("status") != "running")
        all_running = not not_running
    else:
        not_running, all_running = None, None
        unread["services_all_running"] = ABSENT

    tamper = ep.get("tamperProtectionEnabled")
    if not isinstance(tamper, bool):
        tamper = None
        unread["tamper_protection_enabled"] = ABSENT

    products = ep.get("assignedProducts")
    if isinstance(products, list):
        installed = any(p.get("code") in PROTECTION_PRODUCTS and p.get("status") == "installed" for p in products)
        product_list = [{"code": p.get("code"), "status": p.get("status"), "version": p.get("version")}
                        for p in products]
    else:
        installed, product_list = None, None
        unread["protection_product_installed"] = ABSENT

    threats = (health.get("threats") or {}).get("status")
    if threats:
        threats_good = threats == "good"
    else:
        threats_good = None
        unread["threats_status_good"] = ABSENT

    os_info = ep.get("os") or {}
    result = {
        **endpoint_identity(ep),
        "os_platform": os_info.get("platform"),
        "os_name": os_info.get("name"),
        "health_overall": health.get("overall"),
        "health_services_status": (health.get("services") or {}).get("status"),
        "health_threats_status": threats,
        "services_all_running": all_running,
        "stopped_or_missing_services": not_running,
        "tamper_protection_enabled": tamper,
        "tamper_protection_supported": ep.get("tamperProtectionSupported"),
        "protection_product_installed": installed,
        "assigned_products": product_list,
        "threats_status_good": threats_good,
    }
    if unread:
        result["unread_facts"] = unread
    return result


def collect(client, ledger, now):
    endpoints, reported_total = client.list_endpoints()
    items = [item(ep) for ep in endpoints]
    try:
        tenant_tamper = client.get("/endpoint/v1/settings/tamper-protection", "tenant_tamper_protection").get("enabled")
    except SophosError as e:
        ledger.add(e)
        tenant_tamper = None
    for i in items:
        i["tenant_tamper_protection_enabled"] = tenant_tamper

    running, not_running, services_unread = tally(items, "services_all_running")
    tp_on, tp_off, tp_unread = tally(items, "tamper_protection_enabled")
    prod_yes, prod_no, prod_unread = tally(items, "protection_product_installed")
    thr_good, thr_not, thr_unread = tally(items, "threats_status_good")
    summary = {
        "total_endpoints": len(items),
        "endpoints_by_type": count_by(items, "type"),
        "endpoints_by_health_overall": count_by(items, "health_overall"),
        "endpoints_all_services_running": running,
        "endpoints_service_not_running": not_running,
        "endpoints_services_unread": services_unread,
        "endpoints_tamper_protection_enabled": tp_on,
        "endpoints_tamper_protection_disabled": tp_off,
        "endpoints_tamper_protection_unread": tp_unread,
        "endpoints_protection_product_installed": prod_yes,
        "endpoints_protection_product_not_installed": prod_no,
        "endpoints_protection_product_unread": prod_unread,
        "endpoints_threats_status_good": thr_good,
        "endpoints_threats_status_not_good": thr_not,
        "endpoints_threats_status_unread": thr_unread,
        "tenant_tamper_protection_enabled": tenant_tamper,
    }
    return items, summary, {"collected": len(items), "reported_total": reported_total}


if __name__ == "__main__":
    raise SystemExit(run("sophos_endpoint_protection", OUTPUT_FILE, collect))
