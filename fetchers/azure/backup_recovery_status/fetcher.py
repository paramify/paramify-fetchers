#!/usr/bin/env python3
"""Azure backup and recovery: every Recovery Services vault, the backup policies it
defines, its own soft-delete / immutability / restore posture, and what it protects.

Ported from prowler/providers/azure/services/recovery/recovery_service.py (Apache-2.0),
whose MINIMUM_RETENTION_DAYS = 30 is the threshold reported here. Retention goes beyond
Prowler, which reads only `retention_policy.daily_schedule.retention_duration.count` —
so a policy keeping weekly recovery points for twelve weeks reads as having NO
retention. Every schedule shape is projected instead, and `max_retention_days` derived
from all of them.

Each vault's restore jobs over a window are read too, with the recovery point each one
used, so restore duration and recovery point age can be compared with the objectives.
"""

import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    sorted_counts,
    write_evidence,
)
from azure_rest import bounded_int_config, parse_time  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402
from scope_exclusions import excluded_item  # noqa: E402

logger = logging.getLogger("azure_backup_recovery_status")

# Prowler's recovery_vault_backup_policy_retention_adequate constant. Emitted in the
# summary so the threshold the percentage is measured against is never implicit.
MINIMUM_RETENTION_DAYS = 30

RESTORE_WINDOW_ENV = "AZURE_BACKUP_RESTORE_WINDOW_DAYS"
DEFAULT_RESTORE_WINDOW_DAYS = 365
# A cap, so a mistyped window can't page years of 30-day slices per vault for history Azure has likely dropped.
MAX_RESTORE_WINDOW_DAYS = 365
# Azure PowerShell refuses job queries spanning more than 30 days, so the window is read in slices.
JOB_QUERY_SLICE_DAYS = 30
# The $filter date format az backup job list sends.
JOB_FILTER_TIME_FORMAT = "%Y-%m-%d %I:%M:%S %p"
SUCCEEDED_JOB_STATUS = "completed"
FAILED_JOB_STATUS = "failed"
# Property-bag keys, compared lowercased with everything but letters dropped.
RECOVERY_POINT_TIME_KEYS = ("recoverypointtime", "recoverypointtimeinutc")
RESTORE_TYPE_KEYS = ("jobtype", "restoretype")
RESTORE_TARGET_KEYS = ("restoredestination",)
# By workload type, else backup management type: SQL writes day first 24-hour, VM and Azure Files month first AM/PM.
RECOVERY_POINT_TIME_FORMATS = {
    "sqldatabase": ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"),
    "azureiaasvm": ("%m/%d/%Y %I:%M:%S %p",),
    "azurestorage": ("%m/%d/%Y %I:%M:%S %p",),
}
_ISO_DURATION = re.compile(r"^P(?:(\d+(?:\.\d+)?)D)?(?:T(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?)?$")
_URL_QUERY = re.compile(r"(https?://[^\s?\"'<>]+)\?[^\s\"'<>]*", re.IGNORECASE)

# RetentionDurationType -> days, to make the four granularities comparable.
# Approximate BY DESIGN (a month is not 30 days), which is why the raw
# {count, duration_type} pairs are emitted too: this number exists to be
# thresholded, not quoted as a fact.
RETENTION_DURATION_DAYS = {
    "days": 1,
    "weeks": 7,
    "months": 30,
    "years": 365,
}

# Compared case-folded, because ARM's enums are mixed case.
PROTECTED_STATES = ("protected",)
HEALTHY_BACKUP_STATUSES = ("completed", "success", "succeeded", "healthy")


# --- projection: the only code that touches an azure-mgmt model ---

def properties_bag(model):
    """Return the model's `properties` sub-model, or the model itself.

    Neither recoveryservices nor recoveryservicesbackup flattens `properties` onto the
    resource — the backup package cannot, because `properties` is polymorphic
    (AzureIaaSVMProtectionPolicy vs AzureSqlProtectionPolicy vs ...).
    """
    bag = model_attr(model, "properties")
    return model if bag is None else bag


def _timestamp(value) -> str | None:
    """Render a backup timestamp as one UTC ISO-8601 string.

    msrest deserializes ARM's iso-8601 fields into `datetime`, and
    `json.dump(default=str)` would write "2026-08-13 02:00:00+00:00", not the
    "%Y-%m-%dT%H:%M:%SZ" the rest of the category uses.
    """
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def project_retention_duration(duration) -> dict:
    """Read a `RetentionDuration` ({count, duration_type}) into a flat dict."""
    return {
        "count": model_attr(duration, "count"),
        "duration_type": model_attr(duration, "duration_type"),
    }


def project_retention_schedule(schedule) -> dict | None:
    """Read one retention schedule (daily / weekly / monthly / yearly)."""
    if schedule is None:
        return None
    return {
        "retention_duration": project_retention_duration(
            model_attr(schedule, "retention_duration")
        ),
        "retention_times": [
            _timestamp(t) for t in (model_attr(schedule, "retention_times") or [])
        ],
        "days_of_the_week": model_attr(schedule, "days_of_the_week"),
        "months_of_year": model_attr(schedule, "months_of_year"),
        "retention_schedule_format_type": model_attr(schedule, "retention_schedule_format_type"),
    }


def project_retention_policy(policy) -> dict | None:
    """Read a retention policy in either of ARM's two shapes.

    `LongTermRetentionPolicy` carries up to four named schedules; `SimpleRetentionPolicy`
    (Azure SQL) carries a bare `retention_duration` and no schedule at all.
    """
    if policy is None:
        return None
    return {
        "retention_policy_type": model_attr(policy, "retention_policy_type"),
        # SimpleRetentionPolicy's flat form.
        "retention_duration": project_retention_duration(
            model_attr(policy, "retention_duration")
        ),
        "daily_schedule": project_retention_schedule(model_attr(policy, "daily_schedule")),
        "weekly_schedule": project_retention_schedule(model_attr(policy, "weekly_schedule")),
        "monthly_schedule": project_retention_schedule(model_attr(policy, "monthly_schedule")),
        "yearly_schedule": project_retention_schedule(model_attr(policy, "yearly_schedule")),
    }


def project_schedule_policy(schedule) -> dict | None:
    """Read a `SimpleSchedulePolicy` — how often a backup is taken."""
    if schedule is None:
        return None
    return {
        "schedule_policy_type": model_attr(schedule, "schedule_policy_type"),
        "schedule_run_frequency": model_attr(schedule, "schedule_run_frequency"),
        "schedule_run_days": model_attr(schedule, "schedule_run_days"),
        "schedule_run_times": [
            _timestamp(t) for t in (model_attr(schedule, "schedule_run_times") or [])
        ],
        "schedule_weekly_frequency": model_attr(schedule, "schedule_weekly_frequency"),
    }


def project_backup_policy(policy) -> dict:
    """Read a `ProtectionPolicyResource` into a flat snake_case dict.

    `sub_protection_policy` is the SAP HANA / SQL-in-VM shape: the policy itself has no
    retention, each sub-policy carries its own, and ignoring it would report those
    policies as having no retention at all.
    """
    properties = properties_bag(policy)
    return {
        "id": model_attr(policy, "id"),
        "name": model_attr(policy, "name"),
        "type": model_attr(policy, "type"),
        "location": model_attr(policy, "location"),
        "backup_management_type": model_attr(properties, "backup_management_type"),
        "policy_type": model_attr(properties, "policy_type"),
        "workload_type": model_attr(properties, "work_load_type"),
        "protected_items_count": model_attr(properties, "protected_items_count"),
        "time_zone": model_attr(properties, "time_zone"),
        "instant_rp_retention_range_in_days": model_attr(
            properties, "instant_rp_retention_range_in_days"
        ),
        "schedule_policy": project_schedule_policy(model_attr(properties, "schedule_policy")),
        "retention_policy": project_retention_policy(model_attr(properties, "retention_policy")),
        "sub_protection_policies": [
            {
                "policy_type": model_attr(sub, "policy_type"),
                "schedule_policy": project_schedule_policy(model_attr(sub, "schedule_policy")),
                "retention_policy": project_retention_policy(
                    model_attr(sub, "retention_policy")
                ),
            }
            for sub in (model_attr(properties, "sub_protection_policy") or [])
        ],
    }


def project_protected_item(item) -> dict:
    """Read a `ProtectedItemResource` into a flat snake_case dict.

    The health fields live on the workload SUBCLASSES of `ProtectedItem`, not the base,
    so `model_attr`'s None-tolerance is what lets one projection read every workload
    type without branching on the subclass.
    """
    properties = properties_bag(item)
    return {
        "id": model_attr(item, "id"),
        "name": model_attr(item, "name"),
        "protected_item_type": model_attr(properties, "protected_item_type"),
        "backup_management_type": model_attr(properties, "backup_management_type"),
        "workload_type": model_attr(properties, "workload_type"),
        "container_name": model_attr(properties, "container_name"),
        "friendly_name": model_attr(properties, "friendly_name"),
        "source_resource_id": model_attr(properties, "source_resource_id"),
        "backup_policy_id": model_attr(properties, "policy_id"),
        "backup_policy_name": model_attr(properties, "policy_name"),
        "protection_state": model_attr(properties, "protection_state"),
        "protection_status": model_attr(properties, "protection_status"),
        "health_status": model_attr(properties, "health_status"),
        "last_backup_status": model_attr(properties, "last_backup_status"),
        "last_backup_time": _timestamp(model_attr(properties, "last_backup_time")),
        "last_recovery_point": _timestamp(model_attr(properties, "last_recovery_point")),
        "is_scheduled_for_deferred_delete": model_attr(
            properties, "is_scheduled_for_deferred_delete"
        ),
        "is_archive_enabled": model_attr(properties, "is_archive_enabled"),
        "soft_delete_retention_period_in_days": model_attr(
            properties, "soft_delete_retention_period_in_days"
        ),
    }


def project_vault(vault) -> dict:
    """Read a Recovery Services `Vault` into a flat snake_case dict."""
    properties = properties_bag(vault)
    sku = model_attr(vault, "sku")
    security = model_attr(properties, "security_settings")
    soft_delete = model_attr(security, "soft_delete_settings")
    immutability = model_attr(security, "immutability_settings")
    redundancy = model_attr(properties, "redundancy_settings")
    encryption = model_attr(properties, "encryption")

    return {
        "id": model_attr(vault, "id"),
        "name": model_attr(vault, "name"),
        "location": model_attr(vault, "location"),
        "type": model_attr(vault, "type"),
        "sku_name": model_attr(sku, "name"),
        "sku_tier": model_attr(sku, "tier"),
        "provisioning_state": model_attr(properties, "provisioning_state"),
        "public_network_access": model_attr(properties, "public_network_access"),
        "backup_storage_version": model_attr(properties, "backup_storage_version"),
        "private_endpoint_state_for_backup": model_attr(
            properties, "private_endpoint_state_for_backup"
        ),
        # --- recoverability of the backups themselves ---
        "soft_delete_state": model_attr(soft_delete, "soft_delete_state"),
        "soft_delete_retention_period_in_days": model_attr(
            soft_delete, "soft_delete_retention_period_in_days"
        ),
        "immutability_state": model_attr(immutability, "state"),
        "multi_user_authorization": model_attr(security, "multi_user_authorization"),
        # --- durability ---
        "cross_region_restore": model_attr(redundancy, "cross_region_restore"),
        "standard_tier_storage_redundancy": model_attr(
            redundancy, "standard_tier_storage_redundancy"
        ),
        "infrastructure_encryption": model_attr(encryption, "infrastructure_encryption"),
        "encryption_key_uri": model_attr(
            model_attr(encryption, "key_vault_properties"), "key_uri"
        ),
    }


def _job_time(value) -> str | None:
    # A raw string still gets the one format, so times sort and compare as text.
    return _timestamp(parse_time(value) or value if isinstance(value, str) else value)


def project_job(job) -> dict:
    """Read a backup `JobResource` (any workload subclass) into a flat dict; the list call leaves extended info out."""
    properties = properties_bag(job)
    errors = model_attr(properties, "error_details") or []
    return {
        "id": model_attr(job, "id"),
        "name": model_attr(job, "name"),
        "job_type": model_attr(properties, "job_type"),
        "operation": model_attr(properties, "operation"),
        "status": model_attr(properties, "status"),
        "entity_friendly_name": model_attr(properties, "entity_friendly_name"),
        "backup_management_type": model_attr(properties, "backup_management_type"),
        "workload_type": model_attr(properties, "workload_type"),
        "container_name": model_attr(properties, "container_name"),
        "start_time": _job_time(model_attr(properties, "start_time")),
        "end_time": _job_time(model_attr(properties, "end_time")),
        "duration_seconds": duration_seconds(model_attr(properties, "duration")),
        "is_user_triggered": model_attr(properties, "is_user_triggered"),
        "errors": [
            {
                "error_code": model_attr(e, "error_code"),
                "error_title": model_attr(e, "error_title"),
                "error_string": model_attr(e, "error_string"),
            }
            for e in errors
        ],
    }


def project_job_property_bag(job) -> dict:
    """The job details' extended_info.property_bag, with any URL's query string (a SAS token) dropped."""
    bag = model_attr(model_attr(properties_bag(job), "extended_info"), "property_bag") or {}
    return {str(k): _URL_QUERY.sub(r"\1", v) if isinstance(v, str) else v for k, v in dict(bag).items()}


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def retention_duration_days(duration: dict | None) -> int | None:
    """Convert one {count, duration_type} pair to a day count.

    None for an absent duration or an unrecognized/`Invalid` type, which keeps "no
    retention configured" distinguishable from "0 days".
    """
    if not isinstance(duration, dict):
        return None
    count = duration.get("count")
    if count is None:
        return None
    multiplier = RETENTION_DURATION_DAYS.get(str(duration.get("duration_type") or "").lower())
    if multiplier is None:
        return None
    try:
        return int(count) * multiplier
    except (TypeError, ValueError):
        return None


def _retention_policy_day_counts(policy: dict | None) -> list[int]:
    """Every retention figure in one projected retention policy, in days."""
    if not isinstance(policy, dict):
        return []
    candidates = [policy.get("retention_duration")]
    for key in ("daily_schedule", "weekly_schedule", "monthly_schedule", "yearly_schedule"):
        schedule = policy.get(key)
        if isinstance(schedule, dict):
            candidates.append(schedule.get("retention_duration"))
    return [days for days in (retention_duration_days(c) for c in candidates) if days is not None]


def daily_retention_days(policy: dict) -> int | None:
    """Prowler's exact figure: `retention_policy.daily_schedule.retention_duration.count`.

    Kept alongside the derived maximum so a reviewer comparing against a Prowler run
    sees the same number. A raw `count`, NOT converted — daily durations are always Days.
    """
    schedule = (policy.get("retention_policy") or {}).get("daily_schedule")
    if not isinstance(schedule, dict):
        return None
    count = (schedule.get("retention_duration") or {}).get("count")
    return int(count) if count is not None else None


def max_retention_days(policy: dict) -> int | None:
    """The longest retention this policy keeps anything for, in days.

    Spans the top-level policy AND every sub-protection policy, because a SAP HANA or
    SQL-in-VM policy carries all its retention down there. None means none could be
    read at all — itself the finding.
    """
    counts = _retention_policy_day_counts(policy.get("retention_policy"))
    for sub in policy.get("sub_protection_policies") or []:
        counts.extend(_retention_policy_day_counts((sub or {}).get("retention_policy")))
    return max(counts) if counts else None


def backup_policy_record(policy: dict) -> dict:
    """Normalize one projected backup policy into an evidence record."""
    retention = max_retention_days(policy)
    return {
        "id": policy.get("id"),
        "name": policy.get("name"),
        "type": policy.get("type"),
        "location": policy.get("location"),
        "backup_management_type": policy.get("backup_management_type"),
        "policy_type": policy.get("policy_type"),
        "workload_type": policy.get("workload_type"),
        "protected_items_count": int(policy.get("protected_items_count") or 0),
        "time_zone": policy.get("time_zone"),
        "instant_rp_retention_range_in_days": policy.get("instant_rp_retention_range_in_days"),
        "schedule_policy": policy.get("schedule_policy"),
        "retention_policy": policy.get("retention_policy"),
        "sub_protection_policies": policy.get("sub_protection_policies") or [],
        "daily_retention_days": daily_retention_days(policy),
        "max_retention_days": retention,
        "retention_threshold_days": MINIMUM_RETENTION_DAYS,
        "meets_retention_threshold": retention is not None
        and retention >= MINIMUM_RETENTION_DAYS,
    }


def protected_item_record(item: dict, policies_by_id: dict) -> dict:
    """Normalize one projected protected item, joined to the policy governing it.

    ARM gives the item a `policy_id` and nothing else, so without the join a reader
    cannot tell whether a protected VM is kept for 7 days or 7 years.
    """
    policy_id = item.get("backup_policy_id")
    policy = policies_by_id.get(policy_id) or {}
    state = str(item.get("protection_state") or "").strip().lower()
    last_status = str(item.get("last_backup_status") or "").strip().lower()
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "friendly_name": item.get("friendly_name"),
        "protected_item_type": item.get("protected_item_type"),
        "backup_management_type": item.get("backup_management_type"),
        "workload_type": item.get("workload_type"),
        "container_name": item.get("container_name"),
        "source_resource_id": item.get("source_resource_id"),
        "backup_policy_id": policy_id,
        "backup_policy_name": item.get("backup_policy_name") or policy.get("name")
        or basename(policy_id),
        "protection_state": item.get("protection_state"),
        "protection_status": item.get("protection_status"),
        "health_status": item.get("health_status"),
        "last_backup_status": item.get("last_backup_status"),
        "last_backup_time": item.get("last_backup_time"),
        "last_recovery_point": item.get("last_recovery_point"),
        "is_scheduled_for_deferred_delete": bool(
            item.get("is_scheduled_for_deferred_delete") or False
        ),
        "is_archive_enabled": bool(item.get("is_archive_enabled") or False),
        "soft_delete_retention_period_in_days": item.get("soft_delete_retention_period_in_days"),
        # --- derived, from the joined policy ---
        "policy_max_retention_days": policy.get("max_retention_days"),
        "meets_retention_threshold": bool(policy.get("meets_retention_threshold")),
        "protected": state in PROTECTED_STATES,
        "last_backup_healthy": last_status in HEALTHY_BACKUP_STATUSES,
    }


def vault_record(vault: dict) -> dict:
    """Normalize one projected vault plus the policies and items collected for it."""
    resource_id = vault.get("id")
    soft_delete = str(vault.get("soft_delete_state") or "").strip().lower()
    immutability = str(vault.get("immutability_state") or "").strip().lower()
    policies = vault.get("backup_policies") or []
    items = vault.get("backup_protected_items") or []
    return {
        "id": resource_id,
        "name": vault.get("name"),
        "location": vault.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "sku_name": vault.get("sku_name"),
        "sku_tier": vault.get("sku_tier"),
        "provisioning_state": vault.get("provisioning_state"),
        "public_network_access": vault.get("public_network_access"),
        "backup_storage_version": vault.get("backup_storage_version"),
        "private_endpoint_state_for_backup": vault.get("private_endpoint_state_for_backup"),
        # --- recoverability of the backups themselves ---
        "soft_delete_state": vault.get("soft_delete_state"),
        # "AlwaysON" is soft delete that cannot be turned off, so it counts as
        # enabled; only "Disabled"/"Invalid" do not.
        "soft_delete_enabled": soft_delete in ("enabled", "alwayson"),
        "soft_delete_retention_period_in_days": vault.get(
            "soft_delete_retention_period_in_days"
        ),
        "immutability_state": vault.get("immutability_state"),
        "immutability_enabled": immutability in ("unlocked", "locked"),
        "multi_user_authorization": vault.get("multi_user_authorization"),
        # --- durability ---
        "cross_region_restore": vault.get("cross_region_restore"),
        "cross_region_restore_enabled": str(vault.get("cross_region_restore") or "")
        .strip()
        .lower()
        == "enabled",
        "standard_tier_storage_redundancy": vault.get("standard_tier_storage_redundancy"),
        "infrastructure_encryption": vault.get("infrastructure_encryption"),
        "encryption_key_uri": vault.get("encryption_key_uri"),
        # --- what it protects ---
        "backup_policies": policies,
        "backup_protected_items": items,
        "total_backup_policies": len(policies),
        "total_protected_items": len(items),
        # Listed jobs, or None when unread; read_restore_job_details joins their details and counts them.
        "restore_jobs": vault.get("restore_jobs"),
    }


def summarize(vaults: list[dict], listed: bool = True) -> dict:
    """The headline is retention adequacy across PROTECTED ITEMS, not policies.

    A vault can define a dozen policies and protect nothing. The threshold is emitted
    next to the percentage so the number is never bare. When the vault list wasn't
    read (`listed` false), every count is null rather than 0.
    """
    if not listed:
        return {k: (MINIMUM_RETENTION_DAYS if k == "retention_threshold_days" else None)
                for k in summarize([])}
    policies = [p for v in vaults for p in v["backup_policies"]]
    items = [i for v in vaults for i in v["backup_protected_items"]]
    adequate_items = sum(1 for i in items if i["meets_retention_threshold"])

    workloads: dict[str, int] = {}
    for item in items:
        workloads[str(item["workload_type"] or "unknown")] = (
            workloads.get(str(item["workload_type"] or "unknown"), 0) + 1
        )

    return {
        "total_recovery_services_vaults": len(vaults),
        "vaults_with_protected_items": sum(1 for v in vaults if v["total_protected_items"]),
        "vaults_without_protected_items": sum(
            1 for v in vaults if not v["total_protected_items"]
        ),
        "soft_delete_enabled_vaults": sum(1 for v in vaults if v["soft_delete_enabled"]),
        "immutability_enabled_vaults": sum(1 for v in vaults if v["immutability_enabled"]),
        "cross_region_restore_vaults": sum(
            1 for v in vaults if v["cross_region_restore_enabled"]
        ),
        "total_backup_policies": len(policies),
        "policies_meeting_retention_threshold": sum(
            1 for p in policies if p["meets_retention_threshold"]
        ),
        "policies_without_readable_retention": sum(
            1 for p in policies if p["max_retention_days"] is None
        ),
        "total_protected_items": len(items),
        "protected_items_with_policy": sum(1 for i in items if i["backup_policy_id"]),
        "protected_items_in_protected_state": sum(1 for i in items if i["protected"]),
        "protected_items_with_healthy_last_backup": sum(
            1 for i in items if i["last_backup_healthy"]
        ),
        "retention_threshold_days": MINIMUM_RETENTION_DAYS,
        "protected_items_meeting_retention_threshold": adequate_items,
        "retention_threshold_percentage": coverage_percentage(adequate_items, len(items)),
        "protected_items_by_workload_type": workloads,
    }


def duration_seconds(value) -> float | None:
    """A job duration in seconds, from a timedelta or ARM's ISO-8601 form ("PT3M1.8153383S")."""
    if isinstance(value, timedelta):
        return round(value.total_seconds(), 1)
    match = _ISO_DURATION.match(str(value or "").strip())
    if not value or not match or not any(match.groups()):
        return None
    days, hours, minutes, seconds = (float(g or 0) for g in match.groups())
    return round(((days * 24 + hours) * 60 + minutes) * 60 + seconds, 1)


def _bag_value(bag: dict, keys: tuple) -> str | None:
    for key, value in bag.items():
        if re.sub(r"[^a-z]", "", key.lower()) in keys and value not in (None, ""):
            return str(value)
    return None


def parse_recovery_point_time(text: str | None, job_kind: str | None) -> datetime | None:
    """The property bag's recovery point time in UTC: ISO-8601 or job_kind's RECOVERY_POINT_TIME_FORMATS form, else None."""
    if not text:
        return None
    parsed = parse_time(text)
    if parsed is not None:
        return parsed
    for fmt in RECOVERY_POINT_TIME_FORMATS.get(str(job_kind or "").strip().lower(), ()):
        try:
            return datetime.strptime(text.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hours(delta: timedelta) -> float:
    return round(delta.total_seconds() / 3600, 2)


def restore_job_record(job: dict, bag: dict | None) -> dict:
    """One restore job joined to its details (`bag` None: the read failed); a recovery point after the start is null."""
    start = parse_time(job.get("start_time"))
    point_text = _bag_value(bag, RECOVERY_POINT_TIME_KEYS) if bag is not None else None
    # Only workload jobs (SQL, SAP HANA) have a workload type; VM and Azure Files jobs have a backup management type.
    point = parse_recovery_point_time(point_text, job.get("workload_type") or job.get("backup_management_type"))
    if point is not None and start is not None and point > start:
        point = None
    status = str(job.get("status") or "").strip().lower()
    duration = job.get("duration_seconds")
    return {
        **job,
        "succeeded": status == SUCCEEDED_JOB_STATUS,
        "duration_minutes": round(duration / 60, 2) if isinstance(duration, (int, float)) else None,
        "details_read": bag is not None,
        "restore_type": _bag_value(bag, RESTORE_TYPE_KEYS) if bag is not None else None,
        "restore_target": None if bag is None else {
            k: v for k, v in bag.items()
            if re.sub(r"[^a-z]", "", k.lower()).startswith("target")
            or re.sub(r"[^a-z]", "", k.lower()) in RESTORE_TARGET_KEYS
        },
        "recovery_point_time_text": point_text,
        "recovery_point_time": _timestamp(point),
        "recovery_point_age_hours": _hours(start - point) if point is not None and start is not None else None,
        "job_properties": bag,
    }


def vault_restore_fields(jobs: list[dict] | None) -> dict:
    """A vault's restore jobs and their counts; `jobs` is None when the job list wasn't read, so every count is null."""
    read = jobs is not None
    jobs = sorted(jobs or [], key=lambda j: j.get("start_time") or "", reverse=True)
    succeeded = [j for j in jobs if j.get("succeeded")]
    return {
        "restore_jobs": jobs,
        "restore_jobs_read": read,
        "total_restore_jobs": len(jobs) if read else None,
        "succeeded_restore_jobs": len(succeeded) if read else None,
        "latest_succeeded_restore_time": max((j["end_time"] for j in succeeded if j.get("end_time")), default=None)
        if read else None,
    }


def summarize_restores(vaults: list[dict], window_days: int, now: datetime, listed: bool = True) -> dict:
    """Restore counts across vaults; all but the window and `restore_jobs_read` are null if the vault list or any
    vault's jobs are unread."""
    read = listed and all(v.get("restore_jobs_read") for v in vaults)
    jobs = [j for v in vaults for j in v.get("restore_jobs") or []]
    succeeded = [j for j in jobs if j.get("succeeded")]
    latest = max((j["end_time"] for j in succeeded if j.get("end_time")), default=None)
    durations = [j["duration_minutes"] for j in succeeded if j.get("duration_minutes") is not None]
    ages = [j["recovery_point_age_hours"] for j in succeeded if j.get("recovery_point_age_hours") is not None]
    details_read = all(j.get("details_read") for j in succeeded)
    latest_time = parse_time(latest)
    fields = {
        "total_restore_jobs": len(jobs),
        "succeeded_restore_jobs": len(succeeded),
        "failed_restore_jobs": sum(
            1 for j in jobs if str(j.get("status") or "").strip().lower() == FAILED_JOB_STATUS
        ),
        "restore_jobs_by_status": sorted_counts(Counter(str(j.get("status") or "unknown") for j in jobs)),
        "vaults_with_succeeded_restore": sum(1 for v in vaults if v.get("succeeded_restore_jobs")),
        "latest_succeeded_restore_time": latest,
        "days_since_latest_succeeded_restore": round((now - latest_time).total_seconds() / 86400, 1)
        if latest_time else None,
        "longest_succeeded_restore_minutes": max(durations) if durations else None,
        "max_recovery_point_age_hours": max(ages) if ages and details_read else None,
        "succeeded_restores_without_recovery_point_time": sum(
            1 for j in succeeded if j.get("recovery_point_time") is None
        ),
    }
    return {
        "restore_job_window_days": window_days,
        "restore_jobs_read": read,
        **{k: (v if read else None) for k, v in fields.items()},
    }


def _job_key(name) -> str:
    return re.sub(r"\s+", " ", str(name or "")).strip().lower()


def exclude_protected_items(exclusions: ResourceExclusions, vaults: list[dict]) -> tuple[list[dict], list[dict]]:
    """(in-scope vaults holding only their in-scope protected items, excluded entries). An item leaves when a pattern
    matches its id or the resource it protects, whose id its entry then carries; a vault whose items all leave stays
    in scope. An excluded vault's items are never listed. A restore job leaves with the item it restored, matched by
    friendly name in the same vault, because a job names its item only that way; a name an in-scope item of the vault
    shares keeps the job in scope."""
    all_items = [(vault, item) for vault in vaults for item in vault["backup_protected_items"]]
    by_item = {"resource_id": lambda p: p[1].get("id") or p[0].get("id"), "location": lambda p: p[0].get("location"),
               "resource_group": lambda p: p[0].get("resource_group")}
    by_resource = {"resource_id": lambda p: p[1].get("source_resource_id"), "location": lambda p: None,
                   "resource_group": lambda p: None}
    items, by_vault = exclusions.split(all_items, "protected_item", name=lambda p: p[1].get("name"), **by_item)
    first = list(items)
    items, by_source = exclusions.split(items, "protected_item", name=lambda p: p[1].get("name"), **by_resource)
    first_ids, kept_ids = {id(i) for _, i in first}, {id(i) for _, i in items}
    removed = ([(p, by_item) for p in all_items if id(p[1]) not in first_ids]
               + [(p, by_resource) for p in first if id(p[1]) not in kept_ids])
    patterns: dict = {}
    for pair, keys in removed:
        vault, item = pair
        if _job_key(item.get("friendly_name")):
            # The same keys the split matched on, so the pattern doesn't depend on the order of its entries.
            pattern = exclusions.match(*(keys[k](pair) for k in ("resource_id", "location", "resource_group")))
            patterns.setdefault((id(vault), _job_key(item.get("friendly_name"))), pattern)
    in_scope: dict = {id(vault): [] for vault in vaults}
    for vault, item in items:
        in_scope[id(vault)].append(item)
        patterns.pop((id(vault), _job_key(item.get("friendly_name"))), None)
    by_job: list[dict] = []
    copies = []
    for v in vaults:
        copy = {**v, "backup_protected_items": in_scope[id(v)], "total_protected_items": len(in_scope[id(v)])}
        if v.get("restore_jobs"):
            jobs = []
            for job in v["restore_jobs"]:
                pattern = patterns.get((id(v), _job_key(job.get("entity_friendly_name"))))
                if pattern is None:
                    jobs.append(job)
                else:
                    by_job.append(excluded_item(
                        "restore_job", job.get("entity_friendly_name"), pattern, "protected_item_excluded",
                        id=job.get("id"), resource_group=v.get("resource_group"), location=v.get("location")))
            copy["restore_jobs"] = jobs
        copies.append(copy)
    return copies, by_vault + by_source + by_job


# --- collection (lazy azure imports) ---

def _backup_client(cred, subscription_id):
    """RecoveryServicesBackupClient, whichever module the installed SDK keeps it in.

    azure-mgmt-recoveryservicesbackup 10.0.0 collapsed the multiapi layout: the client
    moved to the package root and the `activestamp` / `passivestamp` sub-packages Prowler
    imports its MODELS from are gone. Older releases keep it under `.activestamp` and
    re-export it at the root, so the root import goes first.
    """
    # Lazy, so the pure transforms above import with no azure-* package present.
    try:
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
    except ImportError:  # pragma: no cover - depends on installed SDK version
        from azure.mgmt.recoveryservicesbackup.activestamp import (
            RecoveryServicesBackupClient,
        )
    return RecoveryServicesBackupClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())


def job_windows(now: datetime, days: int):
    """(start, end) slices of at most JOB_QUERY_SLICE_DAYS covering the `days` before `now`, newest first."""
    start, end = now - timedelta(days=days), now
    while end > start:
        begin = max(start, end - timedelta(days=JOB_QUERY_SLICE_DAYS))
        yield begin, end
        end = begin


def restore_job_filter(start: datetime, end: datetime) -> str:
    return (f"operation eq 'Restore' and startTime eq '{start.strftime(JOB_FILTER_TIME_FORMAT)}'"
            f" and endTime eq '{end.strftime(JOB_FILTER_TIME_FORMAT)}'")


def list_restore_jobs(backup, group: str, name: str, window_days: int, now: datetime,
                      collector: Collector) -> list[dict] | None:
    """backup_jobs.list per window slice, deduplicated by id; None once a slice fails, since the list is then partial."""
    jobs: dict = {}
    for start, end in job_windows(now, window_days):
        page = collector.guard(
            f"recoveryservicesbackup.backup_jobs.list ({name})",
            lambda start=start, end=end: [
                project_job(j) for j in backup.backup_jobs.list(
                    vault_name=name, resource_group_name=group, filter=restore_job_filter(start, end))
            ],
        )
        if page is None:
            return None
        for job in page:
            if "restore" in str(job.get("operation") or "").lower():
                jobs.setdefault(job.get("id") or job.get("name"), job)
    return list(jobs.values())


def read_restore_job_details(subscription_id, cred, collector: Collector, vaults: list[dict]) -> list[dict]:
    """job_details.get per in-scope restore job (the list leaves the property bag out), then each vault's counts."""
    backup = None
    if any(v.get("restore_jobs") for v in vaults):
        backup = collector.guard(
            "recoveryservicesbackup.RecoveryServicesBackupClient (init)",
            lambda: _backup_client(cred, subscription_id),
        )

    def bag(vault, job):
        if backup is None or not job.get("name"):
            return None
        return collector.guard(
            f"recoveryservicesbackup.job_details.get ({vault.get('name')})",
            lambda: project_job_property_bag(backup.job_details.get(
                vault_name=vault.get("name"), resource_group_name=vault.get("resource_group"), job_name=job["name"])),
        )

    finished = []
    for vault in vaults:
        jobs = vault.get("restore_jobs")
        if jobs is not None:
            jobs = [restore_job_record(job, bag(vault, job)) for job in jobs]
        finished.append({**vault, **vault_restore_fields(jobs)})
    return finished


def collect_vaults(subscription_id, cred, collector: Collector, exclusions: ResourceExclusions | None = None,
                   excluded: list | None = None, restore_window_days: int = DEFAULT_RESTORE_WINDOW_DAYS,
                   now: datetime | None = None) -> list[dict] | None:
    """vaults.list_by_subscription_id(), then policies, protected items and restore jobs per vault; vaults the
    exclusions take out go to `excluded` unread. None when the vault list couldn't be read."""
    now = now or utc_now()
    from azure.mgmt.recoveryservices import RecoveryServicesClient

    def _client():
        return RecoveryServicesClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("recoveryservices.RecoveryServicesClient (init)", _client)
    if client is None:
        return None

    def _list():
        # ItemPaged: the SDK follows nextLink itself.
        return [project_vault(v) for v in client.vaults.list_by_subscription_id()]

    vaults = collector.guard("recoveryservices.vaults.list_by_subscription_id", _list)
    if vaults is None:
        return None
    if exclusions:
        vaults, out = exclusions.split(vaults, "recovery_services_vault")
        if excluded is not None:
            excluded += sorted(out, key=lambda e: e["id"] or "")
    if not vaults:
        return []

    backup = collector.guard(
        "recoveryservicesbackup.RecoveryServicesBackupClient (init)",
        lambda: _backup_client(cred, subscription_id),
    )

    for vault in vaults:
        vault["backup_policies"] = []
        vault["backup_protected_items"] = []
        vault["restore_jobs"] = None
        group, name = resource_group_from_id(vault.get("id")), vault.get("name")
        if backup is None:
            continue
        if not group or not name:
            collector.record(
                "recoveryservicesbackup.backup_policies.list",
                RuntimeError(f"recovery vault {name!r} has no resource group in its id"),
            )
            continue

        policies = collector.guard(
            f"recoveryservicesbackup.backup_policies.list ({name})",
            lambda group=group, name=name: [
                backup_policy_record(project_backup_policy(p))
                for p in backup.backup_policies.list(
                    vault_name=name, resource_group_name=group
                )
            ],
            default=[],
        )
        vault["backup_policies"] = sorted(policies, key=lambda r: r.get("id") or "")
        policies_by_id = {p["id"]: p for p in vault["backup_policies"] if p.get("id")}

        items = collector.guard(
            f"recoveryservicesbackup.backup_protected_items.list ({name})",
            lambda group=group, name=name: [
                protected_item_record(project_protected_item(i), policies_by_id)
                for i in backup.backup_protected_items.list(
                    vault_name=name, resource_group_name=group
                )
            ],
            default=[],
        )
        vault["backup_protected_items"] = sorted(items, key=lambda r: r.get("id") or "")
        vault["restore_jobs"] = list_restore_jobs(backup, group, name, restore_window_days, now, collector)

    return sorted((vault_record(v) for v in vaults), key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request header at INFO; warnings still get through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    vaults: list[dict] = []
    # False until the vault list is read, so a missing subscription or credential, or a refused list, reads null.
    listed = False
    excluded: list[dict] = []
    exclusions = ResourceExclusions.from_env()
    restore_window_days, restore_window_requested = bounded_int_config(
        collector, RESTORE_WINDOW_ENV, DEFAULT_RESTORE_WINDOW_DAYS, MAX_RESTORE_WINDOW_DAYS)
    now = utc_now()
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # ARM returns an empty list, not an error, for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.RecoveryServices"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.RecoveryServices is not registered on subscription %s — "
                "no Recovery Services vaults in use; reporting status not_registered",
                subscription_id,
            )
        collected = collect_vaults(subscription_id, cred, collector, exclusions, excluded, restore_window_days, now)
        listed, vaults = collected is not None, collected or []
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    exclusions.record_invalid(collector)
    vaults, out = exclude_protected_items(exclusions, vaults)
    excluded += out
    vaults = read_restore_job_details(subscription_id, cred, collector, vaults)
    items_read = not any(f["operation"].startswith("recoveryservicesbackup.backup_protected_items.list")
                         for f in collector.failures)
    restores_read = listed and all(v["restore_jobs_read"] for v in vaults)
    if not (restores_read and items_read):
        exclusions.mark_unread()
    exclusions.warn_unmatched(logger)

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "recovery_services_vaults": vaults,
            "provider_registration_status": registration,
            "restore_job_window_days_requested": restore_window_requested,
            "excluded": excluded,
        },
        summary={
            **summarize(vaults, listed),
            **summarize_restores(vaults, restore_window_days, now, listed),
            "provider_registration_status": registration,
            **exclusions.summary(excluded, ("recovery_services_vault", "protected_item", "restore_job"), {
                "recovery_services_vaults": len(vaults) if listed else None,
                "protected_items": sum(v["total_protected_items"] for v in vaults) if listed else None,
                "restore_jobs": sum(v["total_restore_jobs"] for v in vaults) if restores_read else None,
            }),
        },
    )

    filename = (
        f"azure_backup_recovery_status_"
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
