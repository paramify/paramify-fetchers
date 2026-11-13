#!/usr/bin/env python3
"""
GCP Cloud SQL Backup & High Availability Configuration

Recovery-planning evidence for each Cloud SQL instance in one project: whether
automated backups run and in which window, whether point-in-time recovery is on,
how many backups and days of transaction log are retained, and whether the
instance is regional (standby in a second zone, automatic failover) or zonal.
Siblings gcp_cloud_sql_network_configuration and gcp_cloud_sql_encryption_status
project different slices of the same `instances.list` response.

Ported from Prowler's GCP Cloud SQL service (Apache-2.0).
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from gcp_common import (  # noqa: E402
    Collector,
    build_payload,
    coverage_percentage,
    credentials,
    dig_any,
    resolve_project,
    sanitize_for_filename,
    service_disabled,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("gcp_cloud_sql_backup_configuration")

# The instanceType of a primary; READ_REPLICA_INSTANCE and the legacy first-generation
# type inherit availability from their primary.
_PRIMARY_INSTANCE_TYPE = "CLOUD_SQL_INSTANCE"

# availabilityType that provisions a standby in a second zone with automatic
# failover. ZONAL (the default) has neither.
_REGIONAL_AVAILABILITY = "REGIONAL"


# --- pure transforms ---

def is_mysql(database_version) -> bool:
    """MySQL is the engine whose PITR signal is binaryLogEnabled, not the toggle."""
    return "MYSQL" in str(database_version or "").upper()


def point_in_time_recovery(backup: dict, database_version) -> bool:
    """Whether the instance can be restored to an arbitrary moment.

    Per engine, not OR-ed: a MySQL instance must not look protected by an unused field.
    """
    if is_mysql(database_version):
        return bool(dig_any(backup, "binary_log_enabled"))
    return bool(dig_any(backup, "point_in_time_recovery_enabled"))


def instance_record(inst: dict) -> dict:
    settings = dig_any(inst, "settings") or {}
    backup = dig_any(settings, "backup_configuration") or {}
    retention = dig_any(backup, "backup_retention_settings") or {}
    failover_replica = dig_any(inst, "failover_replica") or {}

    database_version = dig_any(inst, "database_version")
    instance_type = dig_any(inst, "instance_type") or None
    availability_type = dig_any(settings, "availability_type") or None
    replica_names = sorted(dig_any(inst, "replica_names") or [])

    return {
        "name": dig_any(inst, "name"),
        "region": dig_any(inst, "region"),
        "database_version": database_version,
        "state": dig_any(inst, "state"),
        "instance_type": instance_type,
        "is_primary": instance_type == _PRIMARY_INSTANCE_TYPE,
        "master_instance_name": dig_any(inst, "master_instance_name") or None,
        "create_time": dig_any(inst, "create_time") or None,
        # --- automated backups ---
        "backup_enabled": bool(dig_any(backup, "enabled")),
        # HH:MM UTC — the start of the daily backup window.
        "backup_start_time": dig_any(backup, "start_time") or None,
        "backup_location": dig_any(backup, "location") or None,
        "retained_backup_count": dig_any(retention, "retained_backups"),
        "retention_unit": dig_any(retention, "retention_unit") or None,
        # --- point-in-time recovery ---
        "point_in_time_recovery_enabled": point_in_time_recovery(backup, database_version),
        # Both raw fields kept so the engine-specific derivation above is auditable.
        "pitr_toggle_enabled": bool(dig_any(backup, "point_in_time_recovery_enabled")),
        "binary_log_enabled": bool(dig_any(backup, "binary_log_enabled")),
        "transaction_log_retention_days": dig_any(backup, "transaction_log_retention_days"),
        "transactional_log_storage_state": dig_any(
            backup, "transactional_log_storage_state"
        ) or None,
        # --- high availability / topology ---
        "availability_type": availability_type,
        "high_availability": availability_type == _REGIONAL_AVAILABILITY,
        "zone": dig_any(inst, "gce_zone") or None,
        "secondary_zone": dig_any(inst, "secondary_gce_zone") or None,
        "failover_replica_name": dig_any(failover_replica, "name") or None,
        "failover_replica_available": bool(dig_any(failover_replica, "available")),
        "read_replica_names": replica_names,
        "read_replica_count": len(replica_names),
        # Not a backup, but what stops a recovery plan being defeated by a delete.
        "deletion_protection_enabled": bool(dig_any(settings, "deletion_protection_enabled")),
    }


def summarize(instances: list[dict], *, api_readable: bool = True) -> dict:
    # HA is a primary's property — replicas inherit it, so they would dilute the rate.
    primaries = [i for i in instances if i["is_primary"]]
    backed_up = sum(1 for i in instances if i["backup_enabled"])
    pitr = sum(1 for i in instances if i["point_in_time_recovery_enabled"])
    regional = sum(1 for i in primaries if i["high_availability"])

    retained = [
        i["retained_backup_count"] for i in instances if i["retained_backup_count"] is not None
    ]
    log_days = [
        i["transaction_log_retention_days"]
        for i in instances
        if i["transaction_log_retention_days"] is not None
    ]
    return {
        # False when sqladmin.googleapis.com is not enabled (recorded in
        # metadata.skipped_calls) — "no instances" and "could not look" are different.
        "cloud_sql_api_readable": api_readable,
        "total_instances": len(instances),
        "primary_instances": len(primaries),
        "read_replica_instances": len(instances) - len(primaries),
        "backup_enabled_instances": backed_up,
        "backup_enabled_percentage": coverage_percentage(backed_up, len(instances)),
        "point_in_time_recovery_instances": pitr,
        "point_in_time_recovery_percentage": coverage_percentage(pitr, len(instances)),
        "high_availability_instances": regional,
        "high_availability_percentage": coverage_percentage(regional, len(primaries)),
        "zonal_primary_instances": len(primaries) - regional,
        "instances_with_failover_replica": sum(
            1 for i in instances if i["failover_replica_name"]
        ),
        "instances_with_read_replicas": sum(1 for i in instances if i["read_replica_count"]),
        "deletion_protection_instances": sum(
            1 for i in instances if i["deletion_protection_enabled"]
        ),
        # The weakest link, not the average: recovery is bounded by the shortest one.
        "minimum_retained_backup_count": min(retained) if retained else None,
        "maximum_retained_backup_count": max(retained) if retained else None,
        "minimum_transaction_log_retention_days": min(log_days) if log_days else None,
        "maximum_transaction_log_retention_days": max(log_days) if log_days else None,
    }


# --- collection ---

def collect_instances(project, creds, collector: Collector) -> list[dict] | None:
    """Every Cloud SQL instance in the project, or None when it could not list."""
    from googleapiclient.discovery import build

    def _list():
        service = build("sqladmin", "v1beta4", credentials=creds, cache_discovery=False)
        items, page_token = [], None
        while True:
            resp = service.instances().list(project=project, pageToken=page_token).execute()
            items.extend(resp.get("items", []) or [])
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
        return [instance_record(i) for i in items]

    # A project that has never run Cloud SQL has the API disabled and 403s here rather
    # than returning an empty list — evidence, not a failure.
    records = collector.guard("sqladmin.instances.list", _list, tolerate=service_disabled)
    if records is None:
        return None
    return sorted(records, key=lambda r: r.get("name") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    proj = resolve_project(collector)
    project = proj["project"]
    creds = collector.guard("google.auth.default (credentials)", credentials)

    instances: list[dict] | None = None
    if project and creds is not None:
        instances = collect_instances(project, creds, collector)
    elif not project:
        collector.record("resolve_project", RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"instances": instances or []},
        summary=summarize(instances or [], api_readable=instances is not None),
    )

    filename = (
        f"gcp_cloud_sql_backup_configuration_{sanitize_for_filename(project or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
