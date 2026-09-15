#!/usr/bin/env python3
"""
KSI-SVC-SIN: GCP Persistent Disk & Snapshot Encryption at Rest

For each Compute Engine persistent disk and snapshot in one project, reports
whether encryption at rest uses a customer-managed key (CMEK) or the default
Google-managed key. GCP encrypts every disk and snapshot at rest by default, so
"encrypted: true" can never be false and would be worthless evidence — the fact
that actually varies is CMEK vs Google-managed, and which KMS key is attached.
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
    basename,
    build_payload,
    coverage_percentage,
    credentials,
    first,
    resolve_project,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("gcp_persistent_disk_encryption_status")


# --- pure transforms ---

def _kms_key_name(encryption_block) -> str | None:
    """kmsKeyName out of a *EncryptionKey block, tolerant of key spellings."""
    return first(encryption_block, "kmsKeyName", "kms_key_name")


def disk_record(disk: dict) -> dict:
    """Normalize one compute disk dict into an evidence record.

    CMEK is determined by the PRESENCE of diskEncryptionKey.kmsKeyName. On a
    Google-managed disk the diskEncryptionKey block is absent entirely (verified
    against the sample: default-disk has no diskEncryptionKey key at all), so we
    test for presence, not for an empty value.
    """
    enc = first(disk, "diskEncryptionKey", "disk_encryption_key")
    kms = _kms_key_name(enc)
    users = first(disk, "users") or []
    return {
        "name": first(disk, "name"),
        "zone": basename(first(disk, "zone")),
        "type": basename(first(disk, "type")),
        "status": first(disk, "status"),
        "size_gb": first(disk, "sizeGb", "size_gb"),
        "attached_to": sorted(basename(u) for u in users),
        "cmek": kms is not None,
        "kms_key_name": kms,
    }


def snapshot_record(snap: dict) -> dict:
    """Normalize one compute snapshot dict into an evidence record."""
    enc = first(snap, "snapshotEncryptionKey", "snapshot_encryption_key")
    kms = _kms_key_name(enc)
    return {
        "name": first(snap, "name"),
        "source_disk": basename(first(snap, "sourceDisk", "source_disk")),
        "status": first(snap, "status"),
        "disk_size_gb": first(snap, "diskSizeGb", "disk_size_gb"),
        "storage_locations": sorted(first(snap, "storageLocations", "storage_locations") or []),
        "cmek": kms is not None,
        "kms_key_name": kms,
    }


def summarize(disks: list[dict], snapshots: list[dict]) -> dict:
    cmek_disks = sum(1 for d in disks if d["cmek"])
    cmek_snaps = sum(1 for s in snapshots if s["cmek"])
    return {
        "total_disks": len(disks),
        "cmek_disks": cmek_disks,
        "google_managed_disks": len(disks) - cmek_disks,
        "cmek_disk_percentage": coverage_percentage(cmek_disks, len(disks)),
        "total_snapshots": len(snapshots),
        "cmek_snapshots": cmek_snaps,
        "google_managed_snapshots": len(snapshots) - cmek_snaps,
        "cmek_snapshot_percentage": coverage_percentage(cmek_snaps, len(snapshots)),
    }


# --- collection ---

def collect_disks(project, creds, collector: Collector) -> list[dict]:
    from google.cloud import compute_v1

    def _list():
        client = compute_v1.DisksClient(credentials=creds)
        out = []
        for _zone, scoped in client.aggregated_list(project=project):
            for disk in getattr(scoped, "disks", []) or []:
                out.append(disk_record(compute_v1.Disk.to_dict(disk)))
        return out

    records = collector.guard("compute.disks.aggregatedList", _list, default=[])
    return sorted(records, key=lambda r: (r.get("zone") or "", r.get("name") or ""))


def collect_snapshots(project, creds, collector: Collector) -> list[dict]:
    from google.cloud import compute_v1

    def _list():
        client = compute_v1.SnapshotsClient(credentials=creds)
        return [snapshot_record(compute_v1.Snapshot.to_dict(s)) for s in client.list(project=project)]

    records = collector.guard("compute.snapshots.list", _list, default=[])
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

    disks: list[dict] = []
    snapshots: list[dict] = []
    if project and creds is not None:
        disks = collect_disks(project, creds, collector)
        snapshots = collect_snapshots(project, creds, collector)
    elif not project:
        collector.record("resolve_project", RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"disks": disks, "snapshots": snapshots},
        summary=summarize(disks, snapshots),
    )

    filename = f"gcp_persistent_disk_encryption_status_{sanitize_for_filename(project or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        reason, code = collector.failure_report()
        report_failure(reason, code)
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
