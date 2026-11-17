#!/usr/bin/env python3
"""Velero backup storage locations in Azure Blob Storage: each location's storage settings, every backup's outcome and expiry, and every restore's result."""

import gzip
import json
import logging
import os
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import Collector, arm_id_key, resource_group_from_id  # noqa: E402
from azure_rest import MAX_RETRIES, RETRY_STATUSES, ArmError, int_config, parse_time, retry_wait, run_subscription  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402

NAME = "azure_velero_backups"
logger = logging.getLogger(NAME)

STORAGE_API = "2023-01-01"
# Blob REST version that accepts Entra (OAuth) tokens; the audience is the same in every cloud.
BLOB_VERSION = "2021-12-02"
STORAGE_RESOURCE = "https://storage.azure.com"
WORKERS = 8
PAGE_SIZE = 5000

CONTAINERS_ENV = "AZURE_VELERO_CONTAINER_NAMES"
LOCATIONS_ENV = "AZURE_VELERO_BACKUP_LOCATIONS"
WINDOW_ENV = "AZURE_VELERO_SUCCESS_WINDOW_HOURS"
GRACE_ENV = "AZURE_VELERO_EXPIRY_GRACE_HOURS"
INTERVAL_ENV = "AZURE_VELERO_RESTORE_TEST_INTERVAL_DAYS"
EXPECTED_ENV = "AZURE_VELERO_EXPECTED_SCHEDULES"
RPO_ENV = "AZURE_VELERO_RPO_HOURS"
MISSED_LOOKBACK_ENV = "AZURE_VELERO_MISSED_RUN_LOOKBACK_DAYS"
DEFAULT_MISSED_LOOKBACK_DAYS = 7
MAX_MISSED_LOOKBACK_DAYS = 90
DEFAULT_CONTAINERS = ("velero",)
DEFAULT_WINDOW_HOURS = 26
DEFAULT_GRACE_HOURS = 24

GEO_REPLICATED_SKUS = frozenset({"standard_grs", "standard_ragrs", "standard_gzrs", "standard_ragzrs"})
SCHEDULE_LABEL = "velero.io/schedule-name"
COMPLETED, PARTIALLY_FAILED, FAILED = "Completed", "PartiallyFailed", "Failed"


# --- pure transforms ---

def _csv(value: Optional[str]) -> List[str]:
    return [part.strip() for part in (value or "").split(",") if part.strip()]


def parse_locations(value: Optional[str]) -> Tuple[List[Dict[str, str]], List[str]]:
    """`account/container[/prefix]` entries, and the entries that are not in that form."""
    locations, invalid = [], []
    for entry in _csv(value):
        parts = entry.strip("/").split("/", 2)
        if len(parts) < 2 or not all(parts[:2]):
            invalid.append(entry)
            continue
        locations.append({"account": parts[0].lower(), "container": parts[1], "prefix": parts[2].strip("/") if len(parts) > 2 else ""})
    return locations, invalid


def parse_expected(value: Optional[str]) -> Tuple[Optional[List[Dict[str, Any]]], List[str]]:
    """`name:hours` entries (the schedule and how often it should produce a backup); None when unset."""
    if not (value or "").strip():
        return None, []
    expected, invalid = [], []
    for entry in _csv(value):
        name, _, hours = entry.rpartition(":")
        if name and hours.isdigit() and int(hours) > 0:
            expected.append({"name": name, "interval_hours": int(hours)})
        else:
            invalid.append(entry)
    return expected, invalid


def schedule_check(name: str, interval_hours: Optional[int], backups: List[Dict[str, Any]], settings: Dict[str, Any],
                   now: datetime) -> Dict[str, Any]:
    """One schedule: its backups, newest success, missed periods over the lookback, and the recovery point objective."""
    mine = [b for b in backups if b["schedule"] == name]
    done = sorted(t for t in (parse_time(b["completed"]) for b in mine if b["phase"] == COMPLETED) if t)
    hours = round((now - done[-1]).total_seconds() / 3600, 1) if done else None
    missed = periods = None
    if interval_hours:
        periods = int(settings["missed_run_lookback_days"] * 24 // interval_hours)
        step = timedelta(hours=interval_hours)
        missed = sum(1 for i in range(periods)
                     if not any(now - (i + 1) * step < t <= now - i * step for t in done))
    rpo = settings["rpo_hours"]
    return {"name": name, "expected_interval_hours": interval_hours, "backups": len(mine), "backups_completed": len(done),
            "newest_success": done[-1].strftime("%Y-%m-%dT%H:%M:%SZ") if done else None, "hours_since_success": hours,
            "periods_checked": periods, "missed_runs": missed,
            "exceeds_rpo": (hours is None or hours > rpo) if rpo else None}


def schedule_checks(backups: List[Dict[str, Any]], settings: Dict[str, Any], now: datetime) -> List[Dict[str, Any]]:
    """Expected schedules when listed (so one with no backups still appears); otherwise every schedule a backup names."""
    if settings["expected_schedules"] is not None:
        return [schedule_check(e["name"], e["interval_hours"], backups, settings, now) for e in settings["expected_schedules"]]
    return [schedule_check(n, None, backups, settings, now) for n in sorted({b["schedule"] for b in backups if b["schedule"]})]


def account_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    sku = ((raw.get("sku") or {}).get("name") or "")
    key_source = (props.get("encryption") or {}).get("keySource")
    return {
        "id": raw.get("id"),
        "name": (raw.get("name") or "").lower(),
        "resource_group": resource_group_from_id(raw.get("id")),
        "location": raw.get("location"),
        "sku": sku or None,
        "geo_replicated": sku.lower() in GEO_REPLICATED_SKUS if sku else None,
        "encryption_key_source": key_source,
        "customer_managed_key": (key_source or "").lower() == "microsoft.keyvault" if key_source else None,
        "blob_endpoint": (props.get("primaryEndpoints") or {}).get("blob"),
    }


def backup_record(name: str, raw: Dict[str, Any], now: datetime, grace_hours: int) -> Dict[str, Any]:
    status = raw.get("status") or {}
    labels = (raw.get("metadata") or {}).get("labels") or {}
    expiration = parse_time(status.get("expiration"))
    attempted = sum(int(status.get(k) or 0) for k in ("volumeSnapshotsAttempted", "csiVolumeSnapshotsAttempted"))
    completed = sum(int(status.get(k) or 0) for k in ("volumeSnapshotsCompleted", "csiVolumeSnapshotsCompleted"))
    return {
        "name": name,
        "schedule": labels.get(SCHEDULE_LABEL) or None,
        "phase": status.get("phase"),
        "started": status.get("startTimestamp"),
        "completed": status.get("completionTimestamp"),
        "expiration": status.get("expiration"),
        "errors": status.get("errors") or 0,
        "warnings": status.get("warnings") or 0,
        "volume_snapshots_attempted": attempted,
        "volume_snapshots_completed": completed,
        "volume_snapshots_incomplete": completed < attempted,
        "expired_not_deleted": bool(expiration and (now - expiration).total_seconds() > grace_hours * 3600),
    }


def count_messages(section: Any) -> int:
    """Messages in a Velero results section: lists under 'velero' and 'cluster', and per namespace."""
    if not isinstance(section, dict):
        return 0
    total = sum(len(section.get(k) or []) for k in ("velero", "cluster"))
    return total + sum(len(v or []) for v in (section.get("namespaces") or {}).values())


def restore_record(name: str, results: Optional[Dict[str, Any]], written: Optional[str]) -> Dict[str, Any]:
    if results is None:
        return {"name": name, "results_read": False, "errors": None, "warnings": None, "clean": None, "results_written": written}
    errors, warnings = count_messages(results.get("errors")), count_messages(results.get("warnings"))
    return {"name": name, "results_read": True, "errors": errors, "warnings": warnings, "clean": errors == 0, "results_written": written}


def summarize(locations: List[Dict[str, Any]], settings: Dict[str, Any], now: datetime, discovered: bool = True) -> Dict[str, Any]:
    """Counts are null, not 0, unless discovery finished and every location's backups were read."""
    read = [loc for loc in locations if loc["backups_read"]]
    complete = discovered and len(read) == len(locations)
    backups = [b for loc in read for b in loc["backups"]]
    restores = [r for loc in locations if loc["restores_read"] for r in loc["restores"]]
    restores_complete = discovered and all(loc["restores_read"] for loc in locations)
    latest: Dict[str, datetime] = {}
    for b in backups:
        when = parse_time(b["completed"])
        if b["schedule"] and b["phase"] == COMPLETED and when and (b["schedule"] not in latest or when > latest[b["schedule"]]):
            latest[b["schedule"]] = when
    schedules = sorted({b["schedule"] for b in backups if b["schedule"]})
    hours = {s: (now - latest[s]).total_seconds() / 3600 for s in latest}
    recent = [s for s in schedules if s in hours and hours[s] <= settings["success_window_hours"]]
    clean_times = [parse_time(r["results_written"]) for r in restores if r["clean"]]
    clean_times = [t for t in clean_times if t]
    checks = schedule_checks(backups, settings, now)
    expected = settings["expected_schedules"]

    def known(value):
        return value if complete else None

    return {
        "backup_locations": len(locations) if discovered else None,
        "backup_locations_read": len(read),
        "backup_locations_geo_replicated": sum(1 for loc in locations if loc["geo_replicated"]),
        "backup_locations_customer_managed_key": sum(1 for loc in locations if loc["customer_managed_key"]),
        "backups_total": known(len(backups)),
        "backups_completed": known(sum(1 for b in backups if b["phase"] == COMPLETED)),
        "backups_partially_failed": known(sum(1 for b in backups if b["phase"] == PARTIALLY_FAILED)),
        "backups_failed": known(sum(1 for b in backups if b["phase"] == FAILED)),
        "backups_other_phase": known(sum(1 for b in backups if b["phase"] not in (COMPLETED, PARTIALLY_FAILED, FAILED))),
        "backups_metadata_unreadable": known(sum(loc["backups_unreadable"] for loc in read)),
        "backups_volume_snapshots_incomplete": known(sum(1 for b in backups if b["volume_snapshots_incomplete"])),
        "expired_backups_not_deleted": known(sum(1 for b in backups if b["expired_not_deleted"])),
        "schedules_observed": known(len(schedules)),
        "schedules_with_success_within_window": known(len(recent)),
        "schedules_without_success_within_window": known(sorted(set(schedules) - set(recent))),
        "max_hours_since_scheduled_success": known(round(max(hours.values()), 1) if hours and set(hours) == set(schedules) else None),
        "success_window_hours": settings["success_window_hours"],
        "expected_schedules": len(expected) if expected is not None else None,
        "expected_schedules_without_backups": known(sum(1 for c in checks if c["backups"] == 0)) if expected is not None else None,
        "expected_schedules_without_backups_names": known(sorted(c["name"] for c in checks if c["backups"] == 0)) if expected is not None else None,
        "missed_scheduled_runs": known(sum(c["missed_runs"] for c in checks)) if expected is not None else None,
        "schedules_with_missed_runs": known(sum(1 for c in checks if c["missed_runs"])) if expected is not None else None,
        "missed_run_lookback_days": settings["missed_run_lookback_days"],
        "rpo_hours": settings["rpo_hours"],
        "schedules_exceeding_rpo": known(sum(1 for c in checks if c["exceeds_rpo"])) if settings["rpo_hours"] else None,
        "expiry_grace_hours": settings["expiry_grace_hours"],
        "restores_total": len(restores) if restores_complete else None,
        "restores_without_errors": sum(1 for r in restores if r["clean"]) if restores_complete else None,
        "restores_with_errors": sum(1 for r in restores if r["clean"] is False) if restores_complete else None,
        "restores_results_missing": sum(1 for r in restores if not r["results_read"]) if restores_complete else None,
        "days_since_last_clean_restore": int((now - max(clean_times)).total_seconds() // 86400) if restores_complete and clean_times else None,
        "restores_date_unknown": sum(1 for r in restores if r["results_read"] and not parse_time(r["results_written"])) if restores_complete else None,
        "restore_test_interval_days": settings.get("restore_test_interval_days"),
        "clean_restore_within_interval": (bool(clean_times) and (now - max(clean_times)).days <= settings["restore_test_interval_days"])
        if restores_complete and settings.get("restore_test_interval_days") else None,
    }


def settings_from_env(collector: Optional[Collector] = None) -> Dict[str, Any]:
    locations, invalid = parse_locations(os.environ.get(LOCATIONS_ENV))
    if collector is not None and invalid:
        collector.record(f"config {LOCATIONS_ENV}", ValueError(f"{LOCATIONS_ENV} entries must be account/container[/prefix]: {invalid!r}"))
    raw = (os.environ.get(INTERVAL_ENV) or "").strip()
    interval = int(raw) if raw.isdigit() and int(raw) > 0 else None  # unset until the offering adopts a restore-test interval
    if collector is not None and raw and interval is None:
        collector.record(f"config {INTERVAL_ENV}", ValueError(f"{INTERVAL_ENV}={raw!r} is not a whole number above 0; left unset"))
    expected, bad = parse_expected(os.environ.get(EXPECTED_ENV))
    if collector is not None and bad:
        collector.record(f"config {EXPECTED_ENV}", ValueError(f"{EXPECTED_ENV} entries must be schedule:hours: {bad!r}"))
        expected = None  # a malformed list is unknown, never an empty one that reads as nothing expected
    raw_rpo = (os.environ.get(RPO_ENV) or "").strip()
    rpo = int(raw_rpo) if raw_rpo.isdigit() and int(raw_rpo) > 0 else None  # unset until the offering's objective is configured
    if collector is not None and raw_rpo and rpo is None:
        collector.record(f"config {RPO_ENV}", ValueError(f"{RPO_ENV}={raw_rpo!r} is not a whole number above 0; left unset"))
    raw_lb = (os.environ.get(MISSED_LOOKBACK_ENV) or "").strip()
    lookback = min(int(raw_lb), MAX_MISSED_LOOKBACK_DAYS) if raw_lb.isdigit() and int(raw_lb) > 0 else DEFAULT_MISSED_LOOKBACK_DAYS
    if collector is not None and raw_lb and not (raw_lb.isdigit() and int(raw_lb) > 0):
        collector.record(f"config {MISSED_LOOKBACK_ENV}", ValueError(f"{MISSED_LOOKBACK_ENV}={raw_lb!r} is not a whole number above 0"))
    return {
        "expected_schedules": expected,
        "rpo_hours": rpo,
        "missed_run_lookback_days": lookback,
        "restore_test_interval_days": interval,
        "container_names": _csv(os.environ.get(CONTAINERS_ENV)) or list(DEFAULT_CONTAINERS),
        "explicit_locations": locations,
        "success_window_hours": int_config(WINDOW_ENV, DEFAULT_WINDOW_HOURS),
        "expiry_grace_hours": int_config(GRACE_ENV, DEFAULT_GRACE_HOURS),
    }


# --- blob data plane ---

class BlobReader:
    """Read-only Blob REST calls, only to blob endpoints ARM returned for this subscription's accounts."""

    def __init__(self, client, allowed_endpoints: List[str]):
        self.session, self.cred = client.session, client.cred
        self.allowed = {urlsplit(e).netloc.lower() for e in allowed_endpoints if e}
        self._token: Any = None

    def token(self) -> str:
        if self._token is None or self._token.expires_on - 120 < __import__("time").time():
            self._token = self.cred.get_token(f"{STORAGE_RESOURCE}/.default")
        return self._token.token

    def _get(self, endpoint: str, container: str, path: str = "", params: Optional[Dict[str, str]] = None):
        url = endpoint.rstrip("/") + "/" + quote(container) + (("/" + quote(path)) if path else "")
        target = urlsplit(url)
        if (target.scheme != "https" or target.netloc.lower() not in self.allowed or target.username or target.password
                or target.fragment or not target.path.startswith("/" + quote(container))):
            raise ValueError("Blob read origin is untrusted")
        import time
        for attempt in range(MAX_RETRIES + 1):
            response = self.session.get(url, params=params, timeout=60, allow_redirects=False, headers={
                "Authorization": f"Bearer {self.token()}", "x-ms-version": BLOB_VERSION})
            if response.status_code not in RETRY_STATUSES or attempt == MAX_RETRIES:
                break
            time.sleep(retry_wait(response, attempt))
        if response.status_code >= 300:
            raise ArmError(response.status_code, response.headers.get("x-ms-error-code") or "BlobError", (response.text or "")[:300])
        return response

    def list(self, endpoint: str, container: str, prefix: str) -> List[Dict[str, Optional[str]]]:
        """Every blob under `prefix`: name and last-modified time, across every page."""
        blobs, marker = [], None
        while True:
            params = {"restype": "container", "comp": "list", "prefix": prefix, "maxresults": str(PAGE_SIZE)}
            if marker:
                params["marker"] = marker
            root = ET.fromstring(self._get(endpoint, container, params=params).content)
            for blob in root.iter("Blob"):
                blobs.append({"name": blob.findtext("Name"), "last_modified": blob.findtext("Properties/Last-Modified")})
            marker = root.findtext("NextMarker")
            if not marker:
                return blobs

    def read_json(self, endpoint: str, container: str, name: str) -> Any:
        body = self._get(endpoint, container, name).content
        return json.loads(gzip.decompress(body) if name.endswith(".gz") else body)


def _http_time(value: Optional[str]) -> Optional[str]:
    """RFC 1123 Last-Modified to ISO 8601 UTC."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


# --- collection ---

def read_location(reader: BlobReader, account: Dict[str, Any], container: str, prefix: str, settings: Dict[str, Any],
                  now: datetime, collector: Collector) -> Dict[str, Any]:
    base = (prefix + "/") if prefix else ""
    label = f"{account['name']}/{container}{'/' + prefix if prefix else ''}"
    loc = {"storage_account_id": account["id"], "storage_account": account["name"], "container": container, "prefix": prefix or None,
           "sku": account["sku"], "geo_replicated": account["geo_replicated"], "encryption_key_source": account["encryption_key_source"],
           "customer_managed_key": account["customer_managed_key"], "backups_read": False, "backups_unreadable": 0, "backups": [],
           "restores_read": False, "restores": []}
    listed = collector.guard(f"blob.list backups ({label})", lambda: reader.list(account["blob_endpoint"], container, base + "backups/"), default=None)
    if listed is not None:
        names = sorted({b["name"][len(base + "backups/"):].split("/", 1)[0] for b in listed
                        if b["name"].endswith("/velero-backup.json")})

        def one(n):
            try:
                return backup_record(n, reader.read_json(account["blob_endpoint"], container, f"{base}backups/{n}/velero-backup.json"),
                                     now, settings["expiry_grace_hours"])
            except Exception as exc:  # noqa: BLE001 - recorded; the backup counts as unreadable
                collector.record(f"blob.get velero-backup.json ({label}/{n})", exc)
                return None
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            records = list(pool.map(one, names))
        loc["backups"] = [r for r in records if r is not None]
        loc["backups_unreadable"] = sum(1 for r in records if r is None)
        loc["backups_read"] = True
    restored = collector.guard(f"blob.list restores ({label})", lambda: reader.list(account["blob_endpoint"], container, base + "restores/"), default=None)
    if restored is not None:
        by_name: Dict[str, Optional[Dict[str, Optional[str]]]] = {}
        for b in restored:
            n = b["name"][len(base + "restores/"):].split("/", 1)[0]
            by_name.setdefault(n, None)
            if b["name"].endswith(f"/restore-{n}-results.gz"):
                by_name[n] = b

        def restore(item):
            n, blob = item
            if blob is None:
                return restore_record(n, None, None)
            try:
                return restore_record(n, reader.read_json(account["blob_endpoint"], container, blob["name"]), _http_time(blob["last_modified"]))
            except Exception as exc:  # noqa: BLE001 - recorded; the restore result stays unknown
                collector.record(f"blob.get restore results ({label}/{n})", exc)
                return restore_record(n, None, _http_time(blob["last_modified"]))
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            loc["restores"] = list(pool.map(restore, sorted(by_name.items())))
        loc["restores_read"] = True
    return loc


def collect(client, subscription_id: str, collector: Collector, exclusions: Optional[ResourceExclusions] = None,
            now: Optional[datetime] = None) -> tuple:
    exclusions = exclusions if exclusions is not None else ResourceExclusions()
    now = now or datetime.now(timezone.utc)
    settings = settings_from_env(collector)
    raw = collector.guard("storage.storageAccounts.list", lambda: client.list(
        f"/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts", STORAGE_API), default=None)
    accounts_listed = raw is not None
    discovered = accounts_listed
    accounts = sorted((account_record(a) for a in raw or []), key=lambda a: arm_id_key(a["id"]))
    accounts, excluded = exclusions.split(accounts, "storage_account")
    by_name = {a["name"]: a for a in accounts}
    targets: List[Tuple[Dict[str, Any], str, str]] = []
    if settings["explicit_locations"]:
        for want in settings["explicit_locations"]:
            account = by_name.get(want["account"])
            if account is None:
                discovered = False
                collector.record(f"config {LOCATIONS_ENV}", ValueError(
                    f"storage account {want['account']!r} is not an in-scope account in this subscription"))
                continue
            targets.append((account, want["container"], want["prefix"]))
    else:
        wanted = {c.lower() for c in settings["container_names"]}
        for account in accounts:
            containers = collector.guard(f"storage.blobContainers.list ({account['name']})", lambda a=account: client.list(
                f"{a['id']}/blobServices/default/containers", STORAGE_API), default=None)
            discovered = discovered and containers is not None
            for c in containers or []:
                if (c.get("name") or "").lower() in wanted:
                    targets.append((account, c["name"], ""))
    reader = BlobReader(client, [a["blob_endpoint"] for a in accounts])
    locations = []
    for account, container, prefix in targets:
        if not account["blob_endpoint"]:
            discovered = False
            collector.record(f"storage.blobEndpoint ({account['name']})", ValueError("the account reports no blob endpoint"))
            continue
        locations.append(read_location(reader, account, container, prefix, settings, now, collector))
    exclusions.record_invalid(collector)
    if not accounts_listed:
        exclusions.mark_unread()
    exclusions.warn_unmatched(logger)
    all_backups = [b for loc in locations if loc["backups_read"] for b in loc["backups"]]
    results = {"backup_locations": locations, "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "schedules": schedule_checks(all_backups, settings, now),
               "container_names": settings["container_names"], "explicit_locations": settings["explicit_locations"],
               "excluded": sorted(excluded, key=lambda e: arm_id_key(e.get("id")))}
    summary = {**summarize(locations, settings, now, discovered),
               **exclusions.summary(excluded, ("storage_account",), {"storage_accounts": len(accounts) if accounts_listed else None})}
    return results, summary


def collect_subscription(client, subscription_id: str, collector: Collector) -> tuple:
    return collect(client, subscription_id, collector, ResourceExclusions.from_env())


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect_subscription)


if __name__ == "__main__":
    sys.exit(main())
