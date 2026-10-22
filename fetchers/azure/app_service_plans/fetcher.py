#!/usr/bin/env python3
"""
Azure App Service plans: the compute an app runs on, and how available it is.

Availability for App Service is a property of the plan, not the app: the plan's SKU
sets the tier (Free and Shared carry no SLA), `sku.capacity` is the instance count,
and `zone_redundant` spreads those instances across availability zones. So each plan
is reported with the sites running on it (joined by `server_farm_id`), and each site
carries the few availability fields `web_apps.list()` already returns. Two
subscription-wide list calls, no per-resource GETs; Reader is sufficient.
"""

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
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_app_service_plans")

# SKU tiers with no instance SLA (shared infrastructure, one instance at most).
NO_SLA_TIERS = ("free", "shared")

# Tiers where the platform scales instances itself, so `sku.capacity` is not a
# provisioned instance count (it reads 0 on a consumption plan, seen live).
PLATFORM_SCALED_TIERS = ("dynamic", "flexconsumption", "elasticpremium")


# --- projection: the only azure-mgmt model access ---

def project_plan(plan) -> dict:
    """Read an `AppServicePlan` model into a flat snake_case dict, un-defaulted."""
    sku = model_attr(plan, "sku")
    return {
        "id": model_attr(plan, "id"),
        "name": model_attr(plan, "name"),
        "location": model_attr(plan, "location"),
        "kind": model_attr(plan, "kind"),
        "status": model_attr(plan, "status"),
        "sku_name": model_attr(sku, "name"),
        "sku_tier": model_attr(sku, "tier"),
        "sku_size": model_attr(sku, "size"),
        "sku_family": model_attr(sku, "family"),
        "sku_capacity": model_attr(sku, "capacity"),
        "zone_redundant": model_attr(plan, "zone_redundant"),
        "number_of_workers": model_attr(plan, "number_of_workers"),
        "maximum_number_of_workers": model_attr(plan, "maximum_number_of_workers"),
        "maximum_elastic_worker_count": model_attr(plan, "maximum_elastic_worker_count"),
        "elastic_scale_enabled": model_attr(plan, "elastic_scale_enabled"),
        "per_site_scaling": model_attr(plan, "per_site_scaling"),
        "number_of_sites": model_attr(plan, "number_of_sites"),
        "reserved": model_attr(plan, "reserved"),
    }


def project_site(site) -> dict:
    """Read the availability-relevant fields of a `Site` model from `web_apps.list()`.

    `site_config` on a list result is partial, but carries `number_of_workers`, the
    site's own instance count when the plan has per-site scaling on.
    """
    return {
        "id": model_attr(site, "id"),
        "name": model_attr(site, "name"),
        "kind": model_attr(site, "kind"),
        "state": model_attr(site, "state"),
        "server_farm_id": model_attr(site, "server_farm_id"),
        "redundancy_mode": model_attr(site, "redundancy_mode"),
        "client_affinity_enabled": model_attr(site, "client_affinity_enabled"),
        "number_of_workers": model_attr(model_attr(site, "site_config"), "number_of_workers"),
    }


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def _arm_id_key(resource_id) -> str:
    """ARM ids are case-insensitive, and Azure does not keep one spelling of them
    across resources; join on this, never on the raw string.
    """
    return str(resource_id or "").lower()


def site_record(site: dict) -> dict:
    """Normalize one site; booleans coerced because Azure omits a false field."""
    return {
        "id": site.get("id"),
        "name": site.get("name"),
        "kind": site.get("kind"),
        "state": site.get("state"),
        "redundancy_mode": site.get("redundancy_mode"),
        "client_affinity_enabled": bool(site.get("client_affinity_enabled") or False),
        "number_of_workers": site.get("number_of_workers"),
    }


def plan_record(plan: dict, sites: list[dict]) -> dict:
    """Normalize one plan, attaching the sites whose `server_farm_id` names it.

    `instance_count` is `sku.capacity`, the provisioned instances. On a
    platform-scaled tier (consumption, elastic premium) that is not a fixed count,
    which `platform_scaled` says so a reviewer does not read 0 as "no instances".
    """
    resource_id = plan.get("id")
    tier = str(plan.get("sku_tier") or "")
    capacity = plan.get("sku_capacity")
    instance_count = capacity if isinstance(capacity, int) else None
    key = _arm_id_key(resource_id)
    attached = sorted(
        (site_record(s) for s in sites if _arm_id_key(s.get("server_farm_id")) == key),
        key=lambda r: r.get("id") or "",
    )
    return {
        "id": resource_id,
        "name": plan.get("name"),
        "location": plan.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "kind": plan.get("kind"),
        "status": plan.get("status"),
        "sku": {
            "name": plan.get("sku_name"),
            "tier": plan.get("sku_tier"),
            "size": plan.get("sku_size"),
            "family": plan.get("sku_family"),
            "capacity": capacity,
        },
        "instance_count": instance_count,
        "zone_redundant": bool(plan.get("zone_redundant") or False),
        "multi_instance": bool(instance_count and instance_count > 1),
        "no_sla_tier": tier.lower() in NO_SLA_TIERS,
        "platform_scaled": tier.lower() in PLATFORM_SCALED_TIERS,
        "number_of_workers": plan.get("number_of_workers"),
        "maximum_number_of_workers": plan.get("maximum_number_of_workers"),
        "maximum_elastic_worker_count": plan.get("maximum_elastic_worker_count"),
        "elastic_scale_enabled": bool(plan.get("elastic_scale_enabled") or False),
        "per_site_scaling": bool(plan.get("per_site_scaling") or False),
        "linux": bool(plan.get("reserved") or False),
        "number_of_sites": plan.get("number_of_sites"),
        "sites": attached,
    }


def summarize(plans: list[dict]) -> dict:
    """How many plans (and the sites on them) survive a zone or an instance failure."""
    total = len(plans)
    zone_redundant = sum(1 for p in plans if p["zone_redundant"])
    sites = [s for p in plans for s in p["sites"]]
    return {
        "total_app_service_plans": total,
        "zone_redundant_plans": zone_redundant,
        "zone_redundant_percentage": coverage_percentage(zone_redundant, total),
        "multi_instance_plans": sum(1 for p in plans if p["multi_instance"]),
        # Fixed-capacity plans running one instance: an instance failure is an outage.
        "single_instance_plans": sum(
            1 for p in plans if not p["platform_scaled"] and (p["instance_count"] or 0) <= 1
        ),
        "platform_scaled_plans": sum(1 for p in plans if p["platform_scaled"]),
        "no_sla_tier_plans": sum(1 for p in plans if p["no_sla_tier"]),
        "empty_plans": sum(1 for p in plans if not p["sites"]),
        "total_sites": len(sites),
        "sites_on_zone_redundant_plans": sum(
            len(p["sites"]) for p in plans if p["zone_redundant"]
        ),
        "sites_on_multi_instance_plans": sum(
            len(p["sites"]) for p in plans if p["multi_instance"]
        ),
    }


# --- collection (lazy azure imports) ---

def collect_plans(subscription_id, cred, collector: Collector) -> list[dict]:
    """app_service_plans.list(detailed=True), then web_apps.list() for the join.

    Both are ItemPaged, so the SDK follows nextLink itself. `web_apps.list()` returns
    web apps AND function apps; both run on a plan, so neither is filtered out. If the
    site list fails the plans are still reported, with no sites attached.
    """
    from azure.mgmt.web import WebSiteManagementClient

    def _client():
        return WebSiteManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    client = collector.guard("web.WebSiteManagementClient (init)", _client)
    if client is None:
        return []

    raw_plans = collector.guard(
        "web.app_service_plans.list",
        lambda: [project_plan(p) for p in client.app_service_plans.list(detailed=True)],
        default=[],
    )
    raw_sites = collector.guard(
        "web.web_apps.list",
        lambda: [project_site(s) for s in client.web_apps.list()],
        default=[],
    )
    plans = [plan_record(p, raw_sites) for p in raw_plans]
    return sorted(plans, key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which would
    # dominate the runner's stderr tail. Their warnings and errors still come through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    plans: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list call, so a zero-plan result is legible: Azure returns
        # an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Web"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Web is not registered on subscription %s — no App Service "
                "in use; reporting status not_registered",
                subscription_id,
            )
        plans = collect_plans(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "app_service_plans": plans,
            "provider_registration_status": registration,
        },
        summary={**summarize(plans), "provider_registration_status": registration},
    )

    filename = (
        f"azure_app_service_plans_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
