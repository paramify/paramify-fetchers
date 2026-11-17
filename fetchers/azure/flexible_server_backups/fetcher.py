#!/usr/bin/env python3
"""Azure Database for PostgreSQL and MySQL flexible servers: whether each server's automated backups run, how long they are kept, whether they are geo-redundant, and point-in-time restores."""

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import NOT_REGISTERED, REGISTERED, REGISTRATION_UNKNOWN, Collector, arm_id_key, resource_group_from_id  # noqa: E402
from azure_rest import int_config, parse_time, run_subscription  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402

NAME = "azure_flexible_server_backups"
logger = logging.getLogger(NAME)

PROVIDERS_API = "2021-04-01"
# Newest stable versions this projection was written against; a cloud that does not list one (Azure Government
# lags) gets the newest stable version it does list below it.
ENGINES = {
    "postgresql": {"namespace": "Microsoft.DBforPostgreSQL", "preferred": "2024-08-01"},
    "mysql": {"namespace": "Microsoft.DBforMySQL", "preferred": "2023-12-30"},
}
REPLICA_ROLES = frozenset({"replica", "asyncreplica", "geoasyncreplica", "secondary"})

WINDOW_ENV = "AZURE_FLEXIBLE_SERVER_BACKUP_WINDOW_HOURS"
RETENTION_ENV = "AZURE_FLEXIBLE_SERVER_BACKUP_RETENTION_DAYS"
LOOKBACK_ENV = "AZURE_FLEXIBLE_SERVER_RESTORE_LOOKBACK_DAYS"
DEFAULT_WINDOW_HOURS = 26
MAX_LOOKBACK_DAYS = 3650


# --- pure transforms ---

def choose_api_version(listed: List[str], preferred: str) -> str:
    stable = sorted(v for v in listed if "preview" not in v.lower() and v <= preferred)
    return stable[-1] if stable else preferred


def shared_versions(resource_types: List[Dict[str, Any]]) -> List[str]:
    """API versions listed for both flexibleServers and flexibleServers/backups, since one version serves both calls.
    Falls back to the flexibleServers list when the provider does not list the backups type."""
    def listed(name):
        return next((list(rt.get("apiVersions") or []) for rt in resource_types
                     if (rt.get("resourceType") or "").lower() == name), None)
    servers, backups = listed("flexibleservers") or [], listed("flexibleservers/backups")
    return [v for v in servers if v in set(backups)] if backups is not None else servers


def server_record(engine: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    backup = props.get("backup") or {}
    role = (props.get("replicationRole") or "").lower()
    source = props.get("sourceServerResourceId")
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "engine": engine,
        "resource_group": resource_group_from_id(raw.get("id")),
        "location": raw.get("location"),
        "state": props.get("state"),
        # A stopped server takes no backups, so it shows without a recent one; stopped_servers names the reason.
        "stopped": (props.get("state") or "").lower() == "stopped",
        "replica": role in REPLICA_ROLES,
        "restored_from": source if source and role not in REPLICA_ROLES else None,
        "created": (raw.get("systemData") or {}).get("createdAt"),
        "backup_retention_days": backup.get("backupRetentionDays"),
        "geo_redundant_backup": (backup.get("geoRedundantBackup") or "").lower() == "enabled" if backup.get("geoRedundantBackup") else None,
        "earliest_restore_date": backup.get("earliestRestoreDate"),
    }


# How each engine labels a backup in GET flexibleServers/{server}/backups (properties.backupType, properties.source),
# compared exactly and without regard to case. PostgreSQL's backupType is a defined enum: Full is a scheduled
# automatic backup and "Customer On-Demand" (source "Customer Initiated") one a person took. MySQL's backupType and
# source are free text: only FULL from Automatic is confirmed as automatic, and no on-demand value is confirmed yet.
# Anything else is unknown, never automatic, so an unrecognized backup can never stand in for broken automation.
AUTOMATIC, MANUAL, UNKNOWN = "automatic", "manual", "unknown"
BACKUP_KINDS = {
    "postgresql": {("full", None): AUTOMATIC, ("full", "automatic"): AUTOMATIC,
                   ("customer on-demand", None): MANUAL, ("customer on-demand", "customer initiated"): MANUAL},
    "mysql": {("full", "automatic"): AUTOMATIC},
}


# MySQL labels an on-demand backup FULL / Automatic, the same as a scheduled one (Microsoft's BackupPut.json example,
# 2023-12-30); only the name, customer_<time>_<id>_<user name>, sets it apart. Scheduled backups are named daily_... in
# that example but daily-<time>-<id> in a live Azure Government response (2024-12-30), so both separators are accepted.
MYSQL_ON_DEMAND_PREFIXES = ("customer_", "customer-")


def backup_kind(engine: str, backup: Dict[str, Any]) -> str:
    """automatic, manual or unknown, from the exact backupType and source the engine reports. A MySQL backup named
    customer_... or customer-... is manual whatever its labels, so a recent on-demand backup never stands in for automatic ones."""
    props = backup.get("properties") or {}
    if engine == "mysql" and str(backup.get("name") or "").lower().startswith(MYSQL_ON_DEMAND_PREFIXES):
        return MANUAL

    def norm(value):
        return str(value).strip().lower() if value not in (None, "") else None
    return BACKUP_KINDS.get(engine, {}).get((norm(props.get("backupType")), norm(props.get("source"))), UNKNOWN)


def _newest(backups: List[Dict[str, Any]]) -> Optional[datetime]:
    times = [t for t in (parse_time((b.get("properties") or {}).get("completedTime")) for b in backups) if t]
    return max(times) if times else None


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def with_backups(server: Dict[str, Any], backups: Optional[List[Dict[str, Any]]], settings: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    """Automatic and manual backups apart; only the newest automatic backup is judged against the window. Null when unread."""
    if backups is None:
        return {**server, "backups_read": False, "automatic_backups": None, "manual_backups": None, "unknown_type_backups": None,
                "unknown_backup_labels": None, "latest_automatic_backup": None,
                "latest_manual_backup": None, "hours_since_latest_automatic_backup": None, "backup_within_window": None,
                "manual_backup_within_window": None}
    kinds = [(b, backup_kind(server["engine"], b)) for b in backups]
    automatic = [b for b, k in kinds if k == AUTOMATIC]
    manual = [b for b, k in kinds if k == MANUAL]
    unknown = [b for b, k in kinds if k == UNKNOWN]
    labels = sorted({f"{(b.get('properties') or {}).get('backupType')} / {(b.get('properties') or {}).get('source')}" for b in unknown})
    auto, man = _newest(automatic), _newest(manual)
    hours = round((now - auto).total_seconds() / 3600, 1) if auto else None
    return {**server, "backups_read": True, "automatic_backups": len(automatic), "manual_backups": len(manual),
            "unknown_type_backups": len(unknown), "unknown_backup_labels": labels,
            "latest_automatic_backup": _iso(auto), "latest_manual_backup": _iso(man), "hours_since_latest_automatic_backup": hours,
            "backup_within_window": hours is not None and hours <= settings["window_hours"],
            "manual_backup_within_window": bool(man) and (now - man).total_seconds() / 3600 <= settings["window_hours"]}


def summarize(servers: List[Dict[str, Any]], settings: Dict[str, Any], now: datetime, listed: bool = True) -> Dict[str, Any]:
    primaries = [s for s in servers if not s["replica"]]
    read = [s for s in primaries if s["backups_read"]]
    complete = listed and len(read) == len(primaries)
    lookback = settings["restore_lookback_days"]
    required = settings["required_retention_days"]

    def known(value):
        return value if complete else None

    retention = [s["backup_retention_days"] for s in primaries if s["backup_retention_days"] is not None]
    unknown_retention = sum(1 for s in primaries if s["backup_retention_days"] is None)
    return {
        "database_servers_postgresql": sum(1 for s in servers if s["engine"] == "postgresql") if listed else None,
        "database_servers_mysql": sum(1 for s in servers if s["engine"] == "mysql") if listed else None,
        "replica_servers": sum(1 for s in servers if s["replica"]) if listed else None,
        "backup_servers": len(primaries) if listed else None,
        "backup_servers_read": len(read) if listed else None,
        "servers_with_automatic_backup_within_window": known(sum(1 for s in primaries if s["backup_within_window"])),
        "servers_without_automatic_backup_within_window": known(sorted(s["name"] for s in primaries if not s["backup_within_window"])),
        "servers_relying_on_manual_backup": known(sum(1 for s in primaries if not s["backup_within_window"] and s["manual_backup_within_window"])),
        "servers_with_manual_backups": known(sum(1 for s in primaries if s["manual_backups"])),
        "servers_with_unknown_backup_types": known(sum(1 for s in primaries if s["unknown_type_backups"])),
        "max_hours_since_automatic_backup": known(max((s["hours_since_latest_automatic_backup"] for s in primaries), default=None)
                                                  if all(s["hours_since_latest_automatic_backup"] is not None for s in primaries) else None),
        "servers_geo_redundant_backup": sum(1 for s in primaries if s["geo_redundant_backup"]) if listed else None,
        "min_backup_retention_days": min(retention) if listed and retention else None,
        "max_backup_retention_days": max(retention) if listed and retention else None,
        "servers_retention_below_required": (sum(1 for s in primaries if s["backup_retention_days"] is not None
                                                 and s["backup_retention_days"] < required)
                                             if listed and required is not None else None),
        "servers_retention_unknown": unknown_retention if listed else None,
        "stopped_servers": sum(1 for s in primaries if s["stopped"]) if listed else None,
        "required_retention_days": required,
        "restored_servers_within_lookback": sum(1 for s in servers if s["restored_from"] and parse_time(s["created"])
                                                and parse_time(s["created"]) >= now - timedelta(days=lookback)) if listed and lookback else None,
        "restored_servers_date_unknown": sum(1 for s in servers if s["restored_from"] and not parse_time(s["created"])) if listed else None,
        "backup_window_hours": settings["window_hours"],
        "restore_lookback_days": settings["restore_lookback_days"],
    }


def settings_from_env(collector: Collector) -> Dict[str, Any]:
    raw = (os.environ.get(RETENTION_ENV) or "").strip()
    required = int(raw) if raw.isdigit() and int(raw) > 0 else None
    if raw and required is None:
        collector.record(f"config {RETENTION_ENV}", ValueError(f"{RETENTION_ENV}={raw!r} is not a whole number above 0"))
    raw_lookback = (os.environ.get(LOOKBACK_ENV) or "").strip()
    lookback = min(int(raw_lookback), MAX_LOOKBACK_DAYS) if raw_lookback.isdigit() and int(raw_lookback) > 0 else None  # unset until adopted
    if raw_lookback and lookback is None:
        collector.record(f"config {LOOKBACK_ENV}", ValueError(f"{LOOKBACK_ENV}={raw_lookback!r} is not a whole number above 0; left unset"))
    return {"window_hours": int_config(WINDOW_ENV, DEFAULT_WINDOW_HOURS), "required_retention_days": required, "restore_lookback_days": lookback}


# --- collection ---

def read_provider(client, subscription_id: str, engine: str, collector: Collector) -> Dict[str, Any]:
    spec = ENGINES[engine]
    body = collector.guard(f"providers.get({spec['namespace']})", lambda: client.get(
        f"/subscriptions/{subscription_id}/providers/{spec['namespace']}", PROVIDERS_API), default=None)
    if body is None:
        return {"registration": REGISTRATION_UNKNOWN, "api_version": spec["preferred"]}
    versions = shared_versions(body.get("resourceTypes") or [])
    state = (body.get("registrationState") or "").lower()
    return {"registration": REGISTERED if state == "registered" else NOT_REGISTERED,
            "api_version": choose_api_version(versions, spec["preferred"])}


def collect(client, subscription_id: str, collector: Collector, exclusions: Optional[ResourceExclusions] = None,
            now: Optional[datetime] = None) -> tuple:
    exclusions = exclusions if exclusions is not None else ResourceExclusions()
    now = now or datetime.now(timezone.utc)
    settings = settings_from_env(collector)
    servers: List[Dict[str, Any]] = []
    excluded: List[dict] = []
    listed = True
    providers = {}
    for engine, spec in ENGINES.items():
        provider = read_provider(client, subscription_id, engine, collector)
        providers[engine] = provider
        if provider["registration"] == NOT_REGISTERED:
            continue  # an unregistered provider has no servers, which is known
        api = provider["api_version"]
        raw = collector.guard(f"{engine}.flexibleServers.list", lambda: client.list(
            f"/subscriptions/{subscription_id}/providers/{spec['namespace']}/flexibleServers", api), default=None)
        if raw is None:
            listed = False
            continue
        found = sorted((server_record(engine, s) for s in raw), key=lambda s: arm_id_key(s["id"]))
        found, out = exclusions.split(found, "database_server")
        excluded += out
        for s in found:
            if s["replica"]:
                # Read replicas take no backups of their own; they are counted, not judged.
                servers.append({**s, "backups_read": False, "automatic_backups": None, "manual_backups": None,
                                "unknown_type_backups": None, "unknown_backup_labels": None,
                                "latest_automatic_backup": None, "latest_manual_backup": None,
                                "hours_since_latest_automatic_backup": None, "backup_within_window": None,
                                "manual_backup_within_window": None})
                continue
            backups = collector.guard(f"{engine}.backups.list ({s['name']})",
                                      lambda s=s: client.list(f"{s['id']}/backups", api), default=None)
            servers.append(with_backups(s, backups, settings, now))
    exclusions.record_invalid(collector)
    if not listed:
        exclusions.mark_unread()
    exclusions.warn_unmatched(logger)
    results = {"database_servers": servers, "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "api_versions": {e: p["api_version"] for e, p in providers.items()},
               "excluded": sorted(excluded, key=lambda e: arm_id_key(e.get("id")))}
    summary = {**summarize(servers, settings, now, listed),
               **{f"{e}_provider_registration_status": p["registration"] for e, p in providers.items()},
               **exclusions.summary(excluded, ("database_server",), {"database_servers": len(servers) if listed else None})}
    return results, summary


def collect_subscription(client, subscription_id: str, collector: Collector) -> tuple:
    return collect(client, subscription_id, collector, ResourceExclusions.from_env())


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect_subscription)


if __name__ == "__main__":
    sys.exit(main())
