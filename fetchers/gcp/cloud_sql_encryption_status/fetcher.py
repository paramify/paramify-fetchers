#!/usr/bin/env python3
"""
KSI-SVC-SIN / KSI-RPL-ABO: GCP Cloud SQL Encryption at Rest

For each Cloud SQL instance in one project, reports whether disk encryption at
rest uses a customer-managed key (CMEK) or the Google-managed key, plus backup
configuration. Cloud SQL is always encrypted at rest by default, so
"encrypted: true" can never fail — the fact that varies is CMEK vs Google-managed
and which KMS key.
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
    dig,
    first,
    resolve_project,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("gcp_cloud_sql_encryption_status")


# --- pure transforms ---

def instance_record(inst: dict) -> dict:
    """Normalize one Cloud SQL instance resource dict into an evidence record.

    CMEK is the PRESENCE of diskEncryptionConfiguration.kmsKeyName. On a
    Google-managed instance both diskEncryptionConfiguration and
    diskEncryptionStatus are absent entirely (verified against the sample), so we
    test for presence, not for an empty value.
    """
    kms = dig(inst, "diskEncryptionConfiguration", "kmsKeyName") or dig(
        inst, "disk_encryption_configuration", "kmsKeyName"
    )
    kms_version = dig(inst, "diskEncryptionStatus", "kmsKeyVersionName")
    backup = dig(inst, "settings", "backupConfiguration") or {}

    return {
        "name": first(inst, "name"),
        "region": first(inst, "region"),
        "database_version": first(inst, "databaseVersion", "database_version"),
        "state": first(inst, "state"),
        "cmek": kms is not None,
        "kms_key_name": kms,
        # Full version resource path; basename is the version number.
        "kms_key_version": kms_version,
        "backup_enabled": bool(first(backup, "enabled")),
        "backup_start_time": first(backup, "startTime", "start_time"),
        "backup_retained_count": dig(backup, "backupRetentionSettings", "retainedBackups"),
        "point_in_time_recovery_enabled": bool(
            first(backup, "pointInTimeRecoveryEnabled", "binaryLogEnabled")
        ),
    }


def summarize(instances: list[dict]) -> dict:
    cmek = sum(1 for i in instances if i["cmek"])
    return {
        "total_instances": len(instances),
        "cmek_instances": cmek,
        "google_managed_instances": len(instances) - cmek,
        "cmek_percentage": coverage_percentage(cmek, len(instances)),
        "backup_enabled_instances": sum(1 for i in instances if i["backup_enabled"]),
    }


# --- collection ---

def collect_instances(project, creds, collector: Collector) -> list[dict]:
    # Discovery client: Cloud SQL Admin has no stable dedicated GAPIC client.
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

    records = collector.guard("sqladmin.instances.list", _list, default=[])
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

    instances: list[dict] = []
    if project and creds is not None:
        instances = collect_instances(project, creds, collector)
    elif not project:
        collector.record("resolve_project", RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"instances": instances},
        summary=summarize(instances),
    )

    filename = f"gcp_cloud_sql_encryption_status_{sanitize_for_filename(project or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
