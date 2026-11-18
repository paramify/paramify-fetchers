#!/usr/bin/env python3
"""Velero backup storage locations in Azure Blob Storage: each location's storage settings, every backup's outcome and expiry, and every restore's result."""

import gzip
import json
import logging
import math
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit

import requests

# Blob list responses are XML: parse them with entities and external references refused.
from defusedxml import ElementTree as ET

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import Collector, arm_id_key, resource_group_from_id  # noqa: E402
from azure_rest import (  # noqa: E402
    MAX_RETRIES,
    MAX_RETRY_WAIT,
    MAX_TIMEOUT_RETRIES,
    RETRY_STATUSES,
    ArmError,
    int_config,
    parse_time,
    retry_wait,
    run_subscription,
)
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
RETRY_SUFFIX_ENV = "AZURE_VELERO_RETRY_SUFFIX"
VALIDATION_LABEL_ENV = "AZURE_VELERO_VALIDATION_LABEL"
DEFAULT_MISSED_LOOKBACK_DAYS = 7
MAX_MISSED_LOOKBACK_DAYS = 90
DEFAULT_CONTAINERS = ("velero",)
DEFAULT_WINDOW_HOURS = 26
DEFAULT_GRACE_HOURS = 24
# A gap between Completed backups counts a missed run only when it is longer than the interval plus this share of it,
# so a backup that finishes a few minutes later than the day before is not a missed run.
RUN_GRACE_FRACTION = 0.1
# An expected schedule's success window is its interval plus this slack, at least MIN_WINDOW_SLACK_HOURS.
MIN_WINDOW_SLACK_HOURS = 2

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


def retention_hours(backups: List[Dict[str, Any]]) -> Optional[float]:
    """The shortest retention among a schedule's backups (expiration minus completion), in hours; None when unknown."""
    spans = [(parse_time(b["expiration"]) - parse_time(b["completed"])).total_seconds() / 3600
             for b in backups if parse_time(b["expiration"]) and parse_time(b["completed"])]
    spans = [s for s in spans if s > 0]
    return min(spans) if spans else None


def count_missed(done: List[datetime], interval_hours: int, window_start: datetime, now: datetime) -> int:
    """Missed runs from the gaps between Completed backups, and from the newest one to now.

    Each gap longer than the interval plus RUN_GRACE_FRACTION of it adds floor((gap - grace) / interval) missed runs.
    The first gap starts at the newest Completed backup at or before window_start, or at window_start when there is
    none, so a run due just inside the window is not lost; runs that fell due before window_start in that gap are
    subtracted, so an outage that ended before the lookback does not count. A schedule with no Completed backup at
    all misses every interval in the window.
    """
    step = interval_hours * 3600
    window = (now - window_start).total_seconds()
    if not done:
        return int(window // step)
    grace = step * RUN_GRACE_FRACTION
    before = [t for t in done if t <= window_start]
    points = [before[-1] if before else window_start] + [t for t in done if t > window_start] + [now]
    missed = 0
    for i, (a, b) in enumerate(zip(points, points[1:])):
        runs = math.floor(((b - a).total_seconds() - grace) / step)
        if i == 0 and before:
            runs -= math.floor((window_start - a).total_seconds() / step)  # due before the window started
        missed += max(0, runs)
    return missed


def success_window_hours(interval_hours: Optional[int], settings: Dict[str, Any]) -> float:
    """An expected schedule is judged against its own interval plus slack; any other schedule against success_window_hours."""
    if interval_hours:
        return interval_hours + max(MIN_WINDOW_SLACK_HOURS, interval_hours // 10)
    return settings["success_window_hours"]


def schedule_check(name: str, interval_hours: Optional[int], backups: List[Dict[str, Any]], settings: Dict[str, Any],
                   now: datetime) -> Dict[str, Any]:
    """One schedule: its backups, newest success, missed runs over the lookback, and the recovery point objective.

    Missed runs are judged only over the part of the lookback the schedule's backups are still kept for, because Velero
    deletes each backup when its retention ends and a deleted backup is not a missed run.
    """
    mine = [b for b in backups if b["schedule"] == name]
    done = sorted(t for t in (parse_time(b["completed"]) for b in mine if b["phase"] == COMPLETED) if t)
    hours = round((now - done[-1]).total_seconds() / 3600, 1) if done else None
    missed = periods = None
    retention = retention_hours(mine)
    lookback = settings["missed_run_lookback_days"] * 24
    checked = min(lookback, retention) if retention else lookback
    if interval_hours:
        periods = int(checked // interval_hours)
        missed = count_missed(done, interval_hours, now - timedelta(hours=checked), now)
    rpo = settings["rpo_hours"]
    window = success_window_hours(interval_hours, settings)
    return {"name": name, "expected_interval_hours": interval_hours, "backups": len(mine), "backups_completed": len(done),
            "newest_success": done[-1].strftime("%Y-%m-%dT%H:%M:%SZ") if done else None, "hours_since_success": hours,
            "success_window_hours": window, "success_within_window": hours is not None and hours <= window,
            "retention_hours": round(retention, 1) if retention else None, "hours_checked_for_missed_runs": round(checked, 1),
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
        "labels": dict(labels),
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


def parse_label(value: Optional[str]) -> Optional[Tuple[str, str]]:
    """`key=value`; None when unset or not in that form."""
    key, sep, val = (value or "").strip().partition("=")
    return (key.strip(), val.strip()) if sep and key.strip() and val.strip() else None


def classify_history(backups: List[Dict[str, Any]], restores: List[Dict[str, Any]], retry_suffix: Optional[str]) -> None:
    """Classify one location's failures as resolved or current; records are updated in place.

    No failure is excluded by its name or labels. When retry_suffix is set, a failure is also resolved by its own retry:
    a backup named <name><retry_suffix> that completed later (every attempted snapshot, for a snapshot shortfall), or a
    restore named <name><retry_suffix> that finished later without errors. A failed retry, or none, leaves it current.

    A Failed or PartiallyFailed backup is resolved once its schedule has a Completed backup that finished after it; a
    backup with no schedule is never resolved, since a later manual backup may cover other namespaces. A scheduled
    backup with incomplete volume snapshots is
    resolved once a later Completed backup of the same schedule completed every snapshot it attempted. A restore with
    errors is resolved only by its own retry, since storage doesn't record which backup a restore used. A failure without a readable time is never
    resolved. History is kept: the totals still count every record in storage.
    """
    def when(b):
        return parse_time(b["completed"]) or parse_time(b["started"])

    newest_done: Dict[Optional[str], datetime] = {}
    newest_full: Dict[Optional[str], datetime] = {}
    for x in backups:
        done = parse_time(x["completed"]) if x["phase"] == COMPLETED else None
        if done:
            newest_done[x["schedule"]] = max(done, newest_done.get(x["schedule"], done))
            if not x["volume_snapshots_incomplete"]:
                newest_full[x["schedule"]] = max(done, newest_full.get(x["schedule"], done))
    retried_done: Dict[str, datetime] = {}
    retried_full: Dict[str, datetime] = {}
    if retry_suffix:
        for x in backups:
            done = parse_time(x["completed"]) if x["phase"] == COMPLETED else None
            if done and x["name"].endswith(retry_suffix):
                retried_done[x["name"][:-len(retry_suffix)]] = done
                if not x["volume_snapshots_incomplete"]:
                    retried_full[x["name"][:-len(retry_suffix)]] = done
    for b in backups:
        t = when(b)
        later_done, later_full = newest_done.get(b["schedule"]), newest_full.get(b["schedule"])
        # A backup with no schedule label is never resolved: a later manual backup may cover other namespaces entirely.
        scheduled = b["schedule"] is not None
        by_retry = bool(t and retried_done.get(b["name"]) and retried_done[b["name"]] > t)
        by_full_retry = bool(t and retried_full.get(b["name"]) and retried_full[b["name"]] > t)
        failed = b["phase"] in (FAILED, PARTIALLY_FAILED)
        b["failure_resolved"] = bool(scheduled and t and later_done and later_done > t) or by_retry if failed else None
        b["snapshots_resolved"] = (bool(scheduled and t and later_full and later_full > t) or by_full_retry
                                   if b["volume_snapshots_incomplete"] else None)
        b["resolved_by_retry"] = (failed and by_retry) or (bool(b["volume_snapshots_incomplete"]) and by_full_retry)
    clean_retry = {r["name"][:-len(retry_suffix)]: parse_time(r["results_written"]) for r in restores
                   if retry_suffix and r["clean"] and r["name"].endswith(retry_suffix) and parse_time(r["results_written"])}
    for r in restores:
        t = parse_time(r["results_written"])
        by_retry = bool(t and clean_retry.get(r["name"]) and clean_retry[r["name"]] > t)
        # Backup storage doesn't record which backup a restore used, so only the restore's own retry can resolve it.
        r["error_resolved"] = by_retry if r["clean"] is False else None
        r["resolved_by_retry"] = r["clean"] is False and by_retry


def summarize(locations: List[Dict[str, Any]], settings: Dict[str, Any], now: datetime, discovered: bool = True) -> Dict[str, Any]:
    """Counts are null, not 0, unless discovery finished and every location's backups were read."""
    read = [loc for loc in locations if loc["backups_read"]]
    complete = discovered and len(read) == len(locations)
    backups = [b for loc in read for b in loc["backups"]]
    restores = [r for loc in locations if loc["restores_read"] for r in loc["restores"]]
    restores_complete = discovered and all(loc["restores_read"] for loc in locations)
    # Names and schedules are local to an account/container/prefix, not globally unique.
    for loc in locations:
        classify_history(loc["backups"] if loc["backups_read"] else [],
                         loc["restores"] if loc["restores_read"] else [], settings.get("retry_suffix"))
    label = settings.get("validation_label")
    validation = [b for b in backups if label and b.get("labels", {}).get(label[0]) == label[1]]
    latest: Dict[str, datetime] = {}
    for b in backups:
        when = parse_time(b["completed"])
        if b["schedule"] and b["phase"] == COMPLETED and when and (b["schedule"] not in latest or when > latest[b["schedule"]]):
            latest[b["schedule"]] = when
    schedules = sorted({b["schedule"] for b in backups if b["schedule"]})
    hours = {s: (now - latest[s]).total_seconds() / 3600 for s in latest}
    expected = settings["expected_schedules"]
    windows = {e["name"]: success_window_hours(e["interval_hours"], settings) for e in expected or []}
    recent = [s for s in schedules if s in hours and hours[s] <= windows.get(s, settings["success_window_hours"])]
    clean_times = [parse_time(r["results_written"]) for r in restores if r["clean"]]
    clean_times = [t for t in clean_times if t]
    checks = schedule_checks(backups, settings, now)

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
        "backups_failed_unresolved": known(sum(1 for b in backups if b["failure_resolved"] is False)),
        "backups_volume_snapshots_incomplete_unresolved": known(sum(1 for b in backups
                                                                    if b["snapshots_resolved"] is False)),
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
        "restores_with_errors_unresolved": sum(1 for r in restores if r["error_resolved"] is False)
        if restores_complete else None,
        "restores_results_missing": sum(1 for r in restores if not r["results_read"]) if restores_complete else None,
        "failures_resolved_by_retry": (sum(1 for b in backups if b["resolved_by_retry"]) + sum(1 for r in restores if r["resolved_by_retry"])
                                       if complete and restores_complete and settings.get("retry_suffix") else None),
        "retry_suffix": settings.get("retry_suffix"),
        "validation_backups": known(len(validation)) if label else None,
        "validation_backups_failed": known(sum(1 for b in validation if b["phase"] in (FAILED, PARTIALLY_FAILED))) if label else None,
        "validation_label": f"{label[0]}={label[1]}" if label else None,
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
    raw_label = (os.environ.get(VALIDATION_LABEL_ENV) or "").strip()
    if collector is not None and raw_label and parse_label(raw_label) is None:
        collector.record(f"config {VALIDATION_LABEL_ENV}", ValueError(f"{VALIDATION_LABEL_ENV}={raw_label!r} must be key=value; left unset"))
    return {
        "retry_suffix": (os.environ.get(RETRY_SUFFIX_ENV) or "").strip() or None,
        "validation_label": parse_label(os.environ.get(VALIDATION_LABEL_ENV)),
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
        if self._token is None or self._token.expires_on - 120 < time.time():
            self._token = self.cred.get_token(f"{STORAGE_RESOURCE}/.default")
        return self._token.token

    def _get(self, endpoint: str, container: str, path: str = "", params: Optional[Dict[str, str]] = None):
        url = endpoint.rstrip("/") + "/" + quote(container) + (("/" + quote(path)) if path else "")
        target = urlsplit(url)
        if (target.scheme != "https" or target.netloc.lower() not in self.allowed or target.username or target.password
                or target.fragment or not target.path.startswith("/" + quote(container))):
            raise ValueError("Blob read origin is untrusted")
        timeouts = 0
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.get(url, params=params, timeout=60, allow_redirects=False, headers={
                    "Authorization": f"Bearer {self.token()}", "x-ms-version": BLOB_VERSION})
            except requests.ConnectionError:
                if attempt == MAX_RETRIES:
                    raise
                time.sleep(float(min(2 ** attempt, MAX_RETRY_WAIT)))
                continue
            except requests.Timeout:  # reads only, so a resend is safe; bounded as in azure_rest
                if timeouts == MAX_TIMEOUT_RETRIES or attempt == MAX_RETRIES:
                    raise
                timeouts += 1
                time.sleep(float(min(2 ** attempt, MAX_RETRY_WAIT)))
                continue
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
