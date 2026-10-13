#!/usr/bin/env python3
"""Azure App Service web-app backups: automatic backups, the custom backup schedule and custom backup history."""

import logging
import os
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from app_service import is_web_app, web_client  # noqa: E402
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_id_key,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    failure_reason,
    get_optional,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    sorted_counts,
    write_evidence,
)
from azure_rest import parse_time, pinned_credential  # noqa: E402
from resource_graph import query_all, resource_graph_client  # noqa: E402

logger = logging.getLogger("azure_app_service_backups")

# Backup and restore needs Basic or above; Free and Shared plans have neither kind.
BACKUP_TIERS = ("basic", "standard", "premium", "isolated")
NO_BACKUP_TIERS = ("free", "shared")
AUTOMATIC_BACKUP_INTERVAL_HOURS = 1
AUTOMATIC_BACKUP_RETENTION_DAYS = 30
HOURS_PER_UNIT = {"hour": 1, "day": 24}
SUCCEEDED = "succeeded"
FAILED_STATUSES = ("failed", "timedout", "partiallysucceeded", "skipped")
RECENT_BACKUPS = 20
WORKERS = 4

WEB_SITES_QUERY = (
    "Resources | where type =~ 'microsoft.web/sites'"
    " | project id = tostring(id), name, kind = tostring(kind) | order by id asc"
)

# A backup's storage URL carries its SAS token in the query string.
_URL_QUERY = re.compile(r"(https?://[^\s?\"'<>]+)\?[^\s\"'<>]*", re.IGNORECASE)


def lower(value) -> str:
    return str(value or "").lower()


def iso(value):
    if isinstance(value, datetime):
        parsed = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    else:
        parsed = parse_time(value)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if parsed else None


def strip_sas(text):
    return _URL_QUERY.sub(r"\1", text) if isinstance(text, str) else text


def storage_destination(url) -> dict:
    parts = urlsplit(url or "")
    segments = [s for s in parts.path.split("/") if s]
    return {
        "storage_account": parts.hostname.split(".")[0] if parts.hostname else None,
        "storage_container": segments[0] if segments else None,
        "storage_url": f"{parts.scheme}://{parts.hostname}{parts.path}" if parts.hostname else None,
    }


# --- projection: azure-mgmt models in, flat dicts out ---

def project_site(site) -> dict:
    resource_id = model_attr(site, "id")
    return {
        "id": resource_id,
        "name": model_attr(site, "name"),
        "resource_group": resource_group_from_id(resource_id),
        "location": model_attr(site, "location"),
        "kind": model_attr(site, "kind"),
        "state": model_attr(site, "state"),
        "plan_tier": model_attr(site, "sku"),
        "app_service_plan_id": model_attr(site, "server_farm_id"),
    }


def project_databases(databases) -> list[dict]:
    # connection_string is a secret and is never read.
    return [
        {
            "database_type": model_attr(db, "database_type"),
            "name": model_attr(db, "name"),
            "connection_string_name": model_attr(db, "connection_string_name"),
        }
        for db in (databases or [])
    ]


def project_backup_configuration(request) -> dict:
    schedule = model_attr(request, "backup_schedule")
    return {
        "backup_name": model_attr(request, "backup_name"),
        "enabled": model_attr(request, "enabled"),
        **storage_destination(model_attr(request, "storage_account_url")),
        "schedule": None if schedule is None else {
            "frequency_interval": model_attr(schedule, "frequency_interval"),
            "frequency_unit": model_attr(schedule, "frequency_unit"),
            "keep_at_least_one_backup": model_attr(schedule, "keep_at_least_one_backup"),
            "retention_period_in_days": model_attr(schedule, "retention_period_in_days"),
            "start_time": iso(model_attr(schedule, "start_time")),
            "last_execution_time": iso(model_attr(schedule, "last_execution_time")),
        },
        "databases": project_databases(model_attr(request, "databases")),
    }


def project_backup_item(item) -> dict:
    # BackupItem's flattened `name` is the resource's ("site/1"); the backup's own name is under properties.
    return {
        "id": model_attr(item, "id"),
        "backup_id": model_attr(item, "backup_id"),
        "name": model_attr(model_attr(item, "properties"), "name"),
        "status": model_attr(item, "status"),
        "scheduled": model_attr(item, "scheduled"),
        "created": iso(model_attr(item, "created")),
        "finished": iso(model_attr(item, "finished_time_stamp")),
        "last_restored": iso(model_attr(item, "last_restore_time_stamp")),
        "size_in_bytes": model_attr(item, "size_in_bytes"),
        "website_size_in_bytes": model_attr(item, "website_size_in_bytes"),
        **storage_destination(model_attr(item, "storage_account_url")),
        "blob_name": model_attr(item, "blob_name"),
        "log": strip_sas(model_attr(item, "log")),
        "databases": project_databases(model_attr(item, "databases")),
    }


# --- pure transforms (flat dicts in, evidence records out) ---

def plan_supports_backups(tier):
    text = lower(tier)
    if text.startswith(NO_BACKUP_TIERS):
        return False
    if text.startswith(BACKUP_TIERS):
        return True
    return None


def any_true(values):
    if any(v is True for v in values):
        return True
    return None if any(v is None for v in values) else False


def all_true(values):
    if any(v is False for v in values):
        return False
    return None if not values or any(v is None for v in values) else True


def interval_hours(schedule):
    hours = HOURS_PER_UNIT.get(lower((schedule or {}).get("frequency_unit")))
    interval = (schedule or {}).get("frequency_interval")
    return interval * hours if hours and isinstance(interval, int) else None


def automatic_summary(times):
    if times is None:
        return None
    kept = sorted(t for t in times if t)
    return {
        "count": len(times),
        "latest": kept[-1] if kept else None,
        "oldest": kept[0] if kept else None,
        "interval_hours": AUTOMATIC_BACKUP_INTERVAL_HOURS,
        "retention_days": AUTOMATIC_BACKUP_RETENTION_DAYS,
    }


def history_summary(items):
    if items is None:
        return None
    ordered = sorted(items, key=lambda b: (b.get("created") or "", b.get("backup_id") or 0), reverse=True)
    succeeded = [b for b in ordered if lower(b.get("status")) == SUCCEEDED]
    return {
        "count": len(items),
        "by_status": sorted_counts(Counter(b.get("status") or "unknown" for b in items)),
        "latest_status": ordered[0].get("status") if ordered else None,
        "latest_succeeded": succeeded[0].get("created") if succeeded else None,
        "recent": ordered[:RECENT_BACKUPS],
    }


def app_record(site: dict, times, history, config, config_found) -> dict:
    """`config_found` is False on a 404 (none configured) and None when the read failed; None never reads as off."""
    supported = plan_supports_backups(site.get("plan_tier"))
    automatic = automatic_summary(times)
    custom = history_summary(history)
    schedule = (config or {}).get("schedule")
    if supported is False:
        has_automatic = configured = scheduled = False
    else:
        has_automatic = None if automatic is None else automatic["count"] > 0
        configured = None if config_found is None else bool(config_found and (config or {}).get("storage_url"))
        scheduled = None if configured is None else bool(configured and config.get("enabled") and schedule)
    retention = schedule.get("retention_period_in_days") if scheduled else None
    custom_interval = interval_hours(schedule) if scheduled else None
    intervals = ([AUTOMATIC_BACKUP_INTERVAL_HOURS] if has_automatic else []) + (
        [custom_interval] if custom_interval else []
    )
    restore_points = [p for p in ((automatic or {}).get("latest"), (custom or {}).get("latest_succeeded")) if p]
    return {
        **site,
        "backups_supported": supported,
        "automatic_backups": automatic,
        "has_automatic_backups": has_automatic,
        "custom_backup_configuration_found": False if supported is False else config_found,
        "custom_backup_configuration": config,
        "custom_backup_configured": configured,
        "scheduled_custom_backup_enabled": scheduled,
        "custom_backup_interval_hours": custom_interval,
        "custom_backup_retention_days": retention,
        # 0 keeps scheduled backups forever (az webapp config backup update --retention).
        "custom_backup_retention_indefinite": None if retention is None else retention == 0,
        "custom_backup_history": custom,
        "backed_up": any_true([has_automatic, scheduled]),
        "effective_backup_interval_hours": min(intervals) if intervals else None,
        "latest_restore_point": max(restore_points) if restore_points else None,
    }


def summarize(apps: list[dict], inventory) -> dict:
    total = len(apps)
    backed = sum(1 for a in apps if a["backed_up"] is True)
    intervals = [a["effective_backup_interval_hours"] for a in apps if a["effective_backup_interval_hours"]]
    return {
        "total_web_apps": total,
        "apps_by_plan_tier": sorted_counts(Counter(a["plan_tier"] or "unknown" for a in apps)),
        "apps_on_tier_without_backups": sum(1 for a in apps if a["backups_supported"] is False),
        "apps_with_automatic_backups": sum(1 for a in apps if a["has_automatic_backups"] is True),
        "apps_automatic_backups_unknown": sum(1 for a in apps if a["has_automatic_backups"] is None),
        "apps_with_custom_backup_configured": sum(1 for a in apps if a["custom_backup_configured"] is True),
        "apps_custom_backup_configuration_unknown": sum(
            1 for a in apps if a["custom_backup_configured"] is None
        ),
        "apps_with_scheduled_custom_backup": sum(
            1 for a in apps if a["scheduled_custom_backup_enabled"] is True
        ),
        "apps_with_custom_backup_history": sum(
            1 for a in apps if ((a["custom_backup_history"] or {}).get("count") or 0) > 0
        ),
        "apps_latest_custom_backup_failed": sum(
            1 for a in apps if lower((a["custom_backup_history"] or {}).get("latest_status")) in FAILED_STATUSES
        ),
        "apps_backed_up": backed,
        "apps_not_backed_up": sum(1 for a in apps if a["backed_up"] is False),
        "apps_backed_up_unknown": sum(1 for a in apps if a["backed_up"] is None),
        "backup_coverage_percentage": coverage_percentage(backed, total),
        "all_web_apps_backed_up": all_true([a["backed_up"] for a in apps]),
        "longest_effective_backup_interval_hours": max(intervals) if intervals else None,
        "resource_graph_web_apps": (inventory or {}).get("resource_graph_web_apps"),
        "web_apps_added_from_resource_graph": len((inventory or {}).get("added_from_resource_graph") or []),
    }


# --- collection (lazy azure imports) ---

def list_web_apps(client, collector: Collector) -> list[dict]:
    return collector.guard(
        "web.web_apps.list",
        lambda: [project_site(s) for s in client.web_apps.list() if is_web_app(model_attr(s, "kind"))],
        default=[],
    )


def reconcile(client, collector: Collector, apps: list[dict], rows: list[dict]):
    """Add web apps Resource Graph lists that web_apps.list() did not, once a GET shows they still exist."""
    listed = {arm_id_key(a["id"]) for a in apps}
    graph = {arm_id_key(r.get("id")): r for r in rows if r.get("id") and is_web_app(r.get("kind"))}
    added, stale = [], []
    for key in sorted(set(graph) - listed):
        row = graph[key]
        group, name = resource_group_from_id(row["id"]), row.get("name")
        site, found = get_optional(
            collector, f"web.web_apps.get ({name})", lambda: client.web_apps.get(group, name)
        )
        if found and site is not None:
            added.append(project_site(site))
        elif found is not None:
            stale.append(row["id"])
    return apps + added, {
        "resource_graph_web_apps": len(graph),
        "listed_web_apps": len(apps),
        "added_from_resource_graph": sorted(a["id"] for a in added),
        "resource_graph_stale": sorted(stale),
        "not_in_resource_graph": sorted(a["id"] for a in apps if arm_id_key(a["id"]) not in graph),
    }


def collect_app(client, collector: Collector, site: dict) -> dict:
    group, name = site.get("resource_group"), site.get("name")
    if plan_supports_backups(site.get("plan_tier")) is False:
        return app_record(site, None, None, None, None)
    if not group or not name:
        collector.record("web.web_apps", RuntimeError(f"web app {name!r} has no resource group in its id"))
        return app_record(site, None, None, None, None)
    times = collector.guard(
        f"web.web_apps.list_snapshots ({name})",
        lambda: [iso(model_attr(s, "time")) for s in client.web_apps.list_snapshots(group, name)],
    )
    history = collector.guard(
        f"web.web_apps.list_backups ({name})",
        lambda: [project_backup_item(b) for b in client.web_apps.list_backups(group, name)],
    )
    # A POST needing Microsoft.Web/sites/config/list/action, which Reader lacks.
    config, found = get_optional(
        collector,
        f"web.web_apps.get_backup_configuration ({name})",
        lambda: project_backup_configuration(client.web_apps.get_backup_configuration(group, name)),
    )
    return app_record(site, times, history, config, found)


def collect(subscription_id, cred, collector: Collector):
    client = web_client(subscription_id, cred, collector)
    if client is None:
        return [], None
    apps = list_web_apps(client, collector)

    graph = collector.guard("resourcegraph.ResourceGraphClient (init)", lambda: resource_graph_client(cred))
    result = graph and collector.guard(
        "resourcegraph.resources (web sites)", lambda: query_all(graph, subscription_id, WEB_SITES_QUERY)
    )
    inventory = None
    if result is not None:
        apps, inventory = reconcile(client, collector, apps, result["rows"])

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        records = list(pool.map(lambda site: collect_app(client, collector, site), apps))
    return sorted(records, key=lambda r: arm_id_key(r["id"])), inventory


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", lambda: pinned_credential(subscription_id))

    apps: list[dict] = []
    inventory = None
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Web")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Web is not registered on subscription %s — no App Service in use",
                subscription_id,
            )
        apps, inventory = collect(subscription_id, cred, collector)
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
            "web_apps": apps,
            "inventory_check": inventory,
            "provider_registration_status": registration,
        },
        summary={**summarize(apps, inventory), "provider_registration_status": registration},
    )

    filename = f"azure_app_service_backups_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)
    logger.info("Evidence saved to %s (%d web apps)", path, len(apps))

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
