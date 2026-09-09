#!/usr/bin/env python3
"""Azure backup and recovery: every Recovery Services vault, the backup policies it
defines, its own soft-delete / immutability / restore posture, and what it protects.

Ported from prowler/providers/azure/services/recovery/recovery_service.py (Apache-2.0),
whose MINIMUM_RETENTION_DAYS = 30 is the threshold reported here. Retention goes beyond
Prowler, which reads only `retention_policy.daily_schedule.retention_duration.count` —
so a policy keeping weekly recovery points for twelve weeks reads as having NO
retention. Every schedule shape is projected instead, and `max_retention_days` derived
from all of them.
"""

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    basename,
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

logger = logging.getLogger("azure_backup_recovery_status")

# Prowler's recovery_vault_backup_policy_retention_adequate constant. Emitted in the
# summary so the threshold the percentage is measured against is never implicit.
MINIMUM_RETENTION_DAYS = 30

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
    }


def summarize(vaults: list[dict]) -> dict:
    """The headline is retention adequacy across PROTECTED ITEMS, not policies.

    A vault can define a dozen policies and protect nothing. The threshold is emitted
    next to the percentage so the number is never bare.
    """
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
    return RecoveryServicesBackupClient(credential=cred, subscription_id=subscription_id)


def collect_vaults(subscription_id, cred, collector: Collector) -> list[dict]:
    """vaults.list_by_subscription_id(), then policies + protected items per vault."""
    from azure.mgmt.recoveryservices import RecoveryServicesClient

    def _client():
        return RecoveryServicesClient(credential=cred, subscription_id=subscription_id)

    client = collector.guard("recoveryservices.RecoveryServicesClient (init)", _client)
    if client is None:
        return []

    def _list():
        # ItemPaged: the SDK follows nextLink itself.
        return [project_vault(v) for v in client.vaults.list_by_subscription_id()]

    vaults = collector.guard(
        "recoveryservices.vaults.list_by_subscription_id", _list, default=[]
    )
    if not vaults:
        return []

    backup = collector.guard(
        "recoveryservicesbackup.RecoveryServicesBackupClient (init)",
        lambda: _backup_client(cred, subscription_id),
    )

    for vault in vaults:
        vault["backup_policies"] = []
        vault["backup_protected_items"] = []
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
        vaults = collect_vaults(subscription_id, cred, collector)
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
            "recovery_services_vaults": vaults,
            "provider_registration_status": registration,
        },
        summary={**summarize(vaults), "provider_registration_status": registration},
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
