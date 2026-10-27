#!/usr/bin/env python3
"""Azure App Service web-app backups: observed restore points, the custom backup schedule and custom backup history."""

import logging
import os
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from app_service import is_not_authorized, is_web_app, web_client  # noqa: E402
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
    is_not_found,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    sorted_counts,
    write_evidence,
)
from azure_rest import int_config, parse_time, pinned_credential  # noqa: E402
from resource_graph import query_all, resource_graph_client  # noqa: E402

logger = logging.getLogger("azure_app_service_backups")

# Backup and restore needs Basic or above; Free and Shared plans have neither kind.
BACKUP_TIERS = ("basic", "standard", "premium", "isolated")
NO_BACKUP_TIERS = ("free", "shared")
AUTOMATIC_BACKUP_INTERVAL_HOURS = 1
AUTOMATIC_BACKUP_RETENTION_DAYS = 30
# The platform keeps every hourly automatic backup for 3 days, then every 3rd, then every 6th.
AUTOMATIC_BACKUP_FULL_RETENTION_HOURS = 72
HOURS_PER_UNIT = {"hour": 1, "day": 24}
SUCCEEDED = "succeeded"
FAILED_STATUSES = ("failed", "timedout", "partiallysucceeded", "skipped")
RECENT_BACKUPS = 20
WORKERS = 4

WINDOW_ENV = "AZURE_APP_SERVICE_BACKUP_WINDOW_HOURS"
RPO_ENV = "AZURE_APP_SERVICE_RPO_HOURS"
RESTORE_WINDOW_ENV = "AZURE_APP_SERVICE_RESTORE_WINDOW_DAYS"
DEFAULT_WINDOW_HOURS = 48
DEFAULT_RESTORE_WINDOW_DAYS = 365

CONFIGURATION_PERMISSION = "Microsoft.Web/sites/config/list/action"
CONFIG_FOUND = "found"
CONFIG_NOT_CONFIGURED = "not_configured"
CONFIG_NOT_AUTHORIZED = "not_authorized"
CONFIG_ERROR = "error"
CONFIG_NOT_READ = "not_read"

FUNCTION_APP_REASON = (
    "function app: not assessed. Most use Azure Files content storage, which App Service backups do not cover; "
    "their configuration is evidenced by azure_function_app_configuration."
)
SLOT_REASON = (
    "deployment slot: only production sites are assessed. Slots are backed up separately, "
    "and Basic plans back up the production slot only."
)
LIMITATIONS = [
    "Automatic backups are taken hourly and kept 30 days, are held by the platform in the app's own datacenter, "
    "cannot be downloaded, and do not include linked databases; database backups are evidenced by the database "
    "services' own fetchers.",
    "Function apps and deployment slots are not assessed; they are listed under exclusions.",
    f"The custom backup configuration needs {CONFIGURATION_PERMISSION}, which is opt-in. Without it the "
    "configuration fields are null and custom_backup_configuration_status is not_authorized; custom backups that "
    "ran are still read from the backup history.",
    "For custom backup storage accounts, region, replication and account-level version immutability come from "
    "Resource Graph. Container immutability policies and legal holds are not read, and accounts outside this "
    "subscription are unresolved.",
    "Restores are visible only through last_restored on custom backups; restores from automatic backups leave "
    "no record here.",
    f"Intervals are measured over the restore points within the window; automatic backups older than "
    f"{AUTOMATIC_BACKUP_FULL_RETENTION_HOURS} hours are thinned by the platform, so a wider window reads "
    "thinning as gaps.",
]

# `kind` is a KQL keyword: projecting `kind = tostring(kind)` fails with ParserFailure (measured).
SITES_QUERY = (
    "Resources | where type in~ ('microsoft.web/sites', 'microsoft.web/sites/slots')"
    " | project id = tostring(id), name, kind, type = tolower(type) | order by id asc"
)
SITE_TYPE = "microsoft.web/sites"
SLOT_TYPE = "microsoft.web/sites/slots"
STORAGE_NAME = re.compile(r"^[a-z0-9]{3,24}$")

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


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hours(delta: timedelta) -> float:
    return round(delta.total_seconds() / 3600, 2)


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


def read_settings() -> dict:
    window = int_config(WINDOW_ENV, DEFAULT_WINDOW_HOURS)
    if window > AUTOMATIC_BACKUP_FULL_RETENTION_HOURS:
        logger.warning(
            "%s=%d is wider than the %d hours the platform keeps every automatic backup; "
            "thinned backups will read as gaps",
            WINDOW_ENV, window, AUTOMATIC_BACKUP_FULL_RETENTION_HOURS,
        )
    return {
        "restore_point_window_hours": window,
        "recovery_point_objective_hours": int_config(RPO_ENV, 0) or None,
        "restore_test_window_days": int_config(RESTORE_WINDOW_ENV, DEFAULT_RESTORE_WINDOW_DAYS),
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


def all_true(values):
    if any(v is False for v in values):
        return False
    return None if not values or any(v is None for v in values) else True


def interval_hours(schedule):
    unit = HOURS_PER_UNIT.get(lower((schedule or {}).get("frequency_unit")))
    interval = (schedule or {}).get("frequency_interval")
    return interval * unit if unit and isinstance(interval, int) else None


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
        "held_by_platform_in_same_datacenter": True,
        "includes_linked_databases": False,
    }


def history_summary(items):
    if items is None:
        return None
    ordered = sorted(items, key=lambda b: (b.get("created") or "", b.get("backup_id") or 0), reverse=True)
    succeeded = [b for b in ordered if lower(b.get("status")) == SUCCEEDED]
    restores = sorted(b["last_restored"] for b in items if b.get("last_restored"))
    return {
        "count": len(items),
        "by_status": sorted_counts(Counter(b.get("status") or "unknown" for b in items)),
        "latest_status": ordered[0].get("status") if ordered else None,
        "latest_succeeded": succeeded[0].get("created") if succeeded else None,
        "latest_restore": restores[-1] if restores else None,
        "recent": ordered[:RECENT_BACKUPS],
    }


def observed_restore_points(points: list, now: datetime, window_hours: int) -> dict:
    """Age of the newest restore point, and the largest gap between consecutive points inside the window."""
    parsed = sorted({t for t in (parse_time(p) for p in points) if t})
    recent = [t for t in parsed if now - t <= timedelta(hours=window_hours)]
    gaps = [b - a for a, b in zip(recent, recent[1:])]
    return {
        "latest": iso(parsed[-1]) if parsed else None,
        "age_hours": max(hours(now - parsed[-1]), 0.0) if parsed else None,
        "in_window": len(recent),
        "largest_gap_hours": hours(max(gaps)) if gaps else None,
    }


def meets_objective(supported, age, effective, rpo):
    if rpo is None:
        return None
    if supported is False or (age is not None and age > rpo):
        return False
    return None if effective is None else effective <= rpo


def app_record(site: dict, times, history, config, config_status, settings: dict, now: datetime) -> dict:
    """`times`/`history` None means the read failed; a backup verdict is then null unless a fresh point proves it."""
    supported = plan_supports_backups(site.get("plan_tier"))
    window = settings["restore_point_window_hours"]
    automatic = automatic_summary(times)
    custom = history_summary(history)
    schedule = (config or {}).get("schedule")
    if supported is False:
        has_automatic = configured = scheduled = False
        config_status = CONFIG_NOT_READ
    else:
        has_automatic = None if automatic is None else automatic["count"] > 0
        configured = {CONFIG_FOUND: bool((config or {}).get("storage_url")), CONFIG_NOT_CONFIGURED: False}.get(
            config_status
        )
        scheduled = None if configured is None else bool(configured and config.get("enabled") and schedule)
    retention = schedule.get("retention_period_in_days") if scheduled else None
    custom_interval = interval_hours(schedule) if scheduled else None
    configured_intervals = ([AUTOMATIC_BACKUP_INTERVAL_HOURS] if has_automatic else []) + (
        [custom_interval] if custom_interval else []
    )

    succeeded = [b["created"] for b in (history or []) if lower(b.get("status")) == SUCCEEDED]
    observed = observed_restore_points((times or []) + succeeded, now, window)
    age, gap = observed["age_hours"], observed["largest_gap_hours"]
    if supported is False:
        backed_up = False
    elif age is not None and age <= window:
        backed_up = True
    else:
        backed_up = False if times is not None and history is not None else None
    effective = max(gap, age) if gap is not None else None
    latest_restore = (custom or {}).get("latest_restore")
    restore_cutoff = now - timedelta(days=settings["restore_test_window_days"])
    storage_accounts = sorted(
        {a for a in [(config or {}).get("storage_account")] + [b.get("storage_account") for b in history or []] if a}
    )
    return {
        **site,
        "backups_supported": supported,
        "automatic_backups": automatic,
        "has_automatic_backups": has_automatic,
        "custom_backup_configuration_status": config_status,
        "custom_backup_configuration_found": {CONFIG_FOUND: True, CONFIG_NOT_CONFIGURED: False}.get(
            config_status, False if supported is False else None
        ),
        "custom_backup_configuration": config,
        "custom_backup_configured": configured,
        "scheduled_custom_backup_enabled": scheduled,
        "custom_backup_interval_hours": custom_interval,
        "custom_backup_retention_days": retention,
        # 0 keeps scheduled backups forever (az webapp config backup update --retention).
        "custom_backup_retention_indefinite": None if retention is None else retention == 0,
        "custom_backup_history": custom,
        "custom_backup_storage_accounts": storage_accounts,
        "custom_backup_restored_in_window": (
            None if custom is None else bool(latest_restore and parse_time(latest_restore) >= restore_cutoff)
        ),
        "latest_restore_point": observed["latest"],
        "latest_restore_point_age_hours": age,
        "restore_points_in_window": observed["in_window"],
        "largest_restore_point_gap_hours": gap,
        "backed_up": backed_up,
        "effective_backup_interval_hours": effective,
        "configured_backup_interval_hours": min(configured_intervals) if configured_intervals else None,
        "meets_recovery_point_objective": meets_objective(
            supported, age, effective, settings["recovery_point_objective_hours"]
        ),
    }


def storage_account_record(name: str, apps: list[str], row, looked_up: bool) -> dict:
    replication = (row or {}).get("replication") or None
    return {
        "name": name,
        "apps": apps,
        "resolved": (row is not None) if looked_up else None,
        "id": (row or {}).get("id"),
        "location": (row or {}).get("location"),
        "replication": replication,
        "geo_redundant": None if replication is None else any(s in lower(replication) for s in ("grs", "gzrs")),
        # Resource Graph omits the property when version immutability was never enabled.
        "immutable_storage_with_versioning": None if row is None else bool(row.get("versionImmutability") or False),
    }


def storage_accounts_query(names: list[str]) -> str:
    quoted = ", ".join(f"'{n}'" for n in names)
    return (
        f"Resources | where type =~ 'microsoft.storage/storageaccounts' and name in~ ({quoted})"
        " | project id = tostring(id), name, location, replication = tostring(sku.name),"
        " versionImmutability = tobool(properties.immutableStorageWithVersioning.enabled) | order by id asc"
    )


def summarize(apps: list[dict], inventory, exclusions: dict, storage: list[dict], settings: dict) -> dict:
    total = len(apps)
    backed = sum(1 for a in apps if a["backed_up"] is True)

    def biggest(key):
        values = [a[key] for a in apps if a[key] is not None]
        return max(values) if values else None

    rpo = settings["recovery_point_objective_hours"]
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
        "apps_custom_backup_configuration_not_authorized": sum(
            1 for a in apps if a["custom_backup_configuration_status"] == CONFIG_NOT_AUTHORIZED
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
        "apps_with_custom_backup_restore_in_window": sum(
            1 for a in apps if a["custom_backup_restored_in_window"] is True
        ),
        "apps_backed_up": backed,
        "apps_not_backed_up": sum(1 for a in apps if a["backed_up"] is False),
        "apps_backed_up_unknown": sum(1 for a in apps if a["backed_up"] is None),
        "backup_coverage_percentage": coverage_percentage(backed, total),
        "all_web_apps_backed_up": all_true([a["backed_up"] for a in apps]),
        "restore_point_window_hours": settings["restore_point_window_hours"],
        "max_latest_restore_point_age_hours": biggest("latest_restore_point_age_hours"),
        "largest_restore_point_gap_hours": biggest("largest_restore_point_gap_hours"),
        "longest_effective_backup_interval_hours": biggest("effective_backup_interval_hours"),
        "longest_configured_backup_interval_hours": biggest("configured_backup_interval_hours"),
        "apps_backup_interval_unknown": sum(
            1 for a in apps if a["backups_supported"] is not False and a["effective_backup_interval_hours"] is None
        ),
        "recovery_point_objective_hours": rpo,
        "apps_meeting_recovery_point_objective": sum(1 for a in apps if a["meets_recovery_point_objective"] is True),
        "apps_missing_recovery_point_objective": sum(
            1 for a in apps if a["meets_recovery_point_objective"] is False
        ),
        "apps_recovery_point_objective_unknown": (
            None if rpo is None else sum(1 for a in apps if a["meets_recovery_point_objective"] is None)
        ),
        "all_web_apps_meet_recovery_point_objective": (
            None if rpo is None else all_true([a["meets_recovery_point_objective"] for a in apps])
        ),
        "excluded_function_apps": exclusions["function_apps"]["count"],
        "excluded_deployment_slots": exclusions["deployment_slots"]["count"],
        "custom_backup_storage_accounts": len(storage),
        "custom_backup_storage_accounts_geo_redundant": sum(1 for s in storage if s["geo_redundant"] is True),
        "custom_backup_storage_accounts_unresolved": sum(1 for s in storage if s["resolved"] is not True),
        "resource_graph_web_apps": (inventory or {}).get("resource_graph_web_apps"),
        "web_apps_added_from_resource_graph": len((inventory or {}).get("added_from_resource_graph") or []),
    }


def exclusion(resources, reason: str) -> dict:
    listed = None if resources is None else sorted(
        ({"id": r.get("id"), "name": r.get("name"), "kind": r.get("kind")} for r in resources),
        key=lambda r: arm_id_key(r["id"]),
    )
    return {"count": None if listed is None else len(listed), "reason": reason, "resources": listed}


# --- collection (lazy azure imports) ---

def list_sites(client, collector: Collector):
    """Every site web_apps.list() returns, projected; None when the list failed."""
    return collector.guard("web.web_apps.list", lambda: [project_site(s) for s in client.web_apps.list()])


def reconcile(client, collector: Collector, apps: list[dict], rows: list[dict]):
    """Add web apps Resource Graph lists that web_apps.list() did not, once a GET shows they still exist."""
    listed = {arm_id_key(a["id"]) for a in apps}
    graph = {
        arm_id_key(r.get("id")): r
        for r in rows
        if r.get("id") and lower(r.get("type")) == SITE_TYPE and is_web_app(r.get("kind"))
    }
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


def read_configuration(client, collector: Collector, group: str, name: str):
    """(configuration, status). A 403 is the opt-in permission not granted: unknown, not a collection failure."""
    try:
        return project_backup_configuration(client.web_apps.get_backup_configuration(group, name)), CONFIG_FOUND
    except Exception as exc:  # noqa: BLE001 — classify, then record only real failures
        if is_not_found(exc):
            return None, CONFIG_NOT_CONFIGURED
        if is_not_authorized(exc):
            return None, CONFIG_NOT_AUTHORIZED
        collector.record(f"web.web_apps.get_backup_configuration ({name})", exc)
        return None, CONFIG_ERROR


def collect_app(client, collector: Collector, site: dict, settings: dict, now: datetime) -> dict:
    group, name = site.get("resource_group"), site.get("name")
    if plan_supports_backups(site.get("plan_tier")) is False:
        return app_record(site, None, None, None, CONFIG_NOT_READ, settings, now)
    if not group or not name:
        collector.record("web.web_apps", RuntimeError(f"web app {name!r} has no resource group in its id"))
        return app_record(site, None, None, None, CONFIG_ERROR, settings, now)
    times = collector.guard(
        f"web.web_apps.list_snapshots ({name})",
        lambda: [iso(model_attr(s, "time")) for s in client.web_apps.list_snapshots(group, name)],
    )
    history = collector.guard(
        f"web.web_apps.list_backups ({name})",
        lambda: [project_backup_item(b) for b in client.web_apps.list_backups(group, name)],
    )
    config, status = read_configuration(client, collector, group, name)
    return app_record(site, times, history, config, status, settings, now)


def resolve_storage(graph, subscription_id, collector: Collector, apps: list[dict]) -> list[dict]:
    users: dict = {}
    for app in apps:
        for account in app["custom_backup_storage_accounts"]:
            users.setdefault(account.lower(), []).append(app["name"])
    names = sorted(n for n in users if STORAGE_NAME.match(n))
    rows = None
    if names and graph is not None:
        result = collector.guard(
            "resourcegraph.resources (backup storage accounts)",
            lambda: query_all(graph, subscription_id, storage_accounts_query(names)),
        )
        rows = None if result is None else {lower(r.get("name")): r for r in result["rows"]}
    return [
        storage_account_record(name, sorted(users[name]), (rows or {}).get(name), rows is not None)
        for name in sorted(users)
    ]


def collect(subscription_id, cred, collector: Collector, settings: dict, now: datetime):
    exclusions = {
        "function_apps": exclusion(None, FUNCTION_APP_REASON),
        "deployment_slots": exclusion(None, SLOT_REASON),
    }
    client = web_client(subscription_id, cred, collector)
    if client is None:
        return [], None, exclusions, []
    sites = list_sites(client, collector)
    apps = [s for s in sites or [] if is_web_app(s.get("kind"))]

    graph = collector.guard("resourcegraph.ResourceGraphClient (init)", lambda: resource_graph_client(cred))
    result = graph and collector.guard(
        "resourcegraph.resources (web sites and slots)", lambda: query_all(graph, subscription_id, SITES_QUERY)
    )
    rows = None if result is None else result["rows"]
    inventory = None
    if rows is not None:
        apps, inventory = reconcile(client, collector, apps, rows)

    functions = None
    if sites is not None or rows is not None:
        found = {arm_id_key(s["id"]): s for s in sites or [] if not is_web_app(s.get("kind"))}
        for row in rows or []:
            if row.get("type") == SITE_TYPE and not is_web_app(row.get("kind")):
                found.setdefault(arm_id_key(row.get("id")), row)
        functions = list(found.values())
    exclusions = {
        "function_apps": exclusion(functions, FUNCTION_APP_REASON),
        "deployment_slots": exclusion(
            None if rows is None else [r for r in rows if r.get("type") == SLOT_TYPE], SLOT_REASON
        ),
    }

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        records = list(pool.map(lambda site: collect_app(client, collector, site, settings, now), apps))
    records.sort(key=lambda r: arm_id_key(r["id"]))
    storage = resolve_storage(graph, subscription_id, collector, records)
    return records, inventory, exclusions, storage


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    settings = read_settings()
    now = utc_now()

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", lambda: pinned_credential(subscription_id))

    apps: list[dict] = []
    inventory, storage = None, []
    exclusions = {
        "function_apps": exclusion(None, FUNCTION_APP_REASON),
        "deployment_slots": exclusion(None, SLOT_REASON),
    }
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(collector, subscription_id, cred, "Microsoft.Web")
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Web is not registered on subscription %s — no App Service in use",
                subscription_id,
            )
        apps, inventory, exclusions, storage = collect(subscription_id, cred, collector, settings, now)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    not_authorized = sum(1 for a in apps if a["custom_backup_configuration_status"] == CONFIG_NOT_AUTHORIZED)
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "evaluated_at": iso(now),
            "settings": settings,
            "web_apps": apps,
            "exclusions": exclusions,
            "custom_backup_storage_accounts": storage,
            "custom_backup_configuration_access": {
                "permission": CONFIGURATION_PERMISSION,
                "opt_in": True,
                "apps_not_authorized": not_authorized,
                "note": (
                    f"{CONFIGURATION_PERMISSION} was not granted, so the custom backup configuration is unknown "
                    "for these apps; backup history and automatic backups were still read."
                ) if not_authorized else None,
            },
            "inventory_check": inventory,
            "limitations": LIMITATIONS,
            "provider_registration_status": registration,
        },
        summary={
            **summarize(apps, inventory, exclusions, storage, settings),
            "provider_registration_status": registration,
        },
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
