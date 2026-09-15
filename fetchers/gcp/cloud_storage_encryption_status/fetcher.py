#!/usr/bin/env python3
"""
KSI-SVC-SIN / KSI-RPL-ABO: GCP Cloud Storage Encryption at Rest

For each Cloud Storage bucket in one project, reports whether the default
encryption uses a customer-managed key (CMEK) or the Google-managed key, and the
data-protection posture (uniform bucket-level access, versioning, retention).
Cloud Storage is always encrypted at rest by default, so "encrypted: true" can
never fail — the fact that varies is CMEK vs Google-managed and which KMS key.
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

logger = logging.getLogger("gcp_cloud_storage_encryption_status")


# --- pure transforms ---

def bucket_record(bucket: dict) -> dict:
    """Normalize one bucket resource dict into an evidence record.

    CMEK is the PRESENCE of encryption.defaultKmsKeyName. Handles both the real
    GCS JSON API shape (nested encryption / iamConfiguration / versioning /
    retentionPolicy, camelCase) and the flattened `gcloud storage buckets
    describe` shape (default_kms_key, uniform_bucket_level_access, snake_case),
    so the transform is robust to whichever the collector hands in.
    """
    kms = dig(bucket, "encryption", "defaultKmsKeyName") or first(bucket, "default_kms_key")

    ubla = dig(bucket, "iamConfiguration", "uniformBucketLevelAccess", "enabled")
    if ubla is None:
        ubla = first(bucket, "uniform_bucket_level_access", "uniformBucketLevelAccess")

    versioning = dig(bucket, "versioning", "enabled")
    if versioning is None:
        versioning = first(bucket, "versioning_enabled")

    retention_period = dig(bucket, "retentionPolicy", "retentionPeriod") or dig(
        bucket, "retention_policy", "retentionPeriod"
    )

    pap = dig(bucket, "iamConfiguration", "publicAccessPrevention") or first(
        bucket, "public_access_prevention"
    )

    return {
        "name": first(bucket, "name"),
        "location": first(bucket, "location"),
        "location_type": first(bucket, "locationType", "location_type"),
        "cmek": kms is not None,
        "kms_key_name": kms,
        "uniform_bucket_level_access": bool(ubla),
        "versioning_enabled": bool(versioning),
        "has_retention_policy": retention_period is not None,
        "retention_period_seconds": retention_period,
        "public_access_prevention": pap,
    }


def summarize(buckets: list[dict]) -> dict:
    cmek = sum(1 for b in buckets if b["cmek"])
    return {
        "total_buckets": len(buckets),
        "cmek_buckets": cmek,
        "google_managed_buckets": len(buckets) - cmek,
        "cmek_percentage": coverage_percentage(cmek, len(buckets)),
        "uniform_access_buckets": sum(1 for b in buckets if b["uniform_bucket_level_access"]),
        "versioned_buckets": sum(1 for b in buckets if b["versioning_enabled"]),
    }


# --- collection ---

def collect_buckets(project, creds, collector: Collector) -> list[dict]:
    from google.cloud import storage

    def _list():
        client = storage.Client(project=project, credentials=creds)
        # list_buckets() returns full bucket resources (encryption block included),
        # so no per-bucket GET is required. _properties is the raw REST dict.
        return [bucket_record(b._properties) for b in client.list_buckets()]

    records = collector.guard("storage.buckets.list", _list, default=[])
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

    buckets: list[dict] = []
    if project and creds is not None:
        buckets = collect_buckets(project, creds, collector)
    elif not project:
        collector.record("resolve_project", RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"buckets": buckets},
        summary=summarize(buckets),
    )

    filename = f"gcp_cloud_storage_encryption_status_{sanitize_for_filename(project or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
