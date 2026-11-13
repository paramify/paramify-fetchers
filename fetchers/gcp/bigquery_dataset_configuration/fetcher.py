#!/usr/bin/env python3
"""
GCP BigQuery Dataset Configuration

For each BigQuery dataset in one project: the dataset-level CMEK key, the access
control list with any public grant called out, the default table expiration and
the location. BigQuery is always encrypted at rest, so "encrypted: true" can
never fail — what varies is CMEK vs Google-managed, who is on the ACL, and where
the data lives.

Ported from Prowler's GCP BigQuery service (Apache-2.0).
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

logger = logging.getLogger("gcp_bigquery_dataset_configuration")

# allUsers is anyone on the internet; allAuthenticatedUsers is any Google account.
_PUBLIC_PRINCIPALS = frozenset({"allusers", "allauthenticatedusers"})

# The ACL entry fields that identify a principal, in API order. Exactly one is set.
_PRINCIPAL_KEYS = (
    "userByEmail",
    "groupByEmail",
    "domain",
    "specialGroup",
    "iamMember",
    "view",
    "routine",
    "dataset",
)

# Entry fields whose value is a person or a mailing list.
_PERSONAL_KEYS = frozenset({"userByEmail", "groupByEmail"})

# iamMember carries a full IAM principal string, so a person can arrive through it too.
_PERSONAL_IAM_PREFIXES = ("user:", "group:", "principal:", "principalset:")

# Entry fields whose value is a BigQuery resource reference rather than a string.
_RESOURCE_KEYS = frozenset({"view", "routine", "dataset"})


# --- pure transforms ---

def is_public_principal(principal) -> bool:
    """Exact match against allUsers / allAuthenticatedUsers.

    Exact, per entry: a substring grep of the ACL also fires on `allusers-admin@corp.com`.
    Tolerates the `iamMember` spelling, where the principal arrives bare or prefixed.
    """
    value = str(principal or "").strip().lower()
    return value in _PUBLIC_PRINCIPALS or value.split(":")[-1] in _PUBLIC_PRINCIPALS


def resource_path(ref) -> str | None:
    """A view / routine / authorized-dataset reference as project.dataset.object."""
    if not isinstance(ref, dict):
        return None
    # An authorized-dataset entry wraps the reference one level deeper.
    inner = dig_any(ref, "dataset")
    if isinstance(inner, dict):
        ref = inner
    parts = [
        dig_any(ref, "project_id"),
        dig_any(ref, "dataset_id"),
        dig_any(ref, "table_id") or dig_any(ref, "routine_id"),
    ]
    path = ".".join(str(p) for p in parts if p)
    return path or None


def access_entry_record(entry: dict) -> dict:
    """One dataset ACL entry: its role, principal type, and principal when nameable.

    `principal` is None for a person or group entry: identities are counted, not named.
    """
    principal_type = next((k for k in _PRINCIPAL_KEYS if dig_any(entry, k) is not None), None)
    raw = dig_any(entry, principal_type) if principal_type else None

    if principal_type in _RESOURCE_KEYS:
        principal = resource_path(raw)
    elif principal_type in _PERSONAL_KEYS:
        principal = None
    elif principal_type == "iamMember" and str(raw or "").lower().startswith(
        _PERSONAL_IAM_PREFIXES
    ):
        principal = None
    else:
        principal = str(raw) if raw is not None else None

    return {
        # Authorized views / routines / datasets carry no role.
        "role": dig_any(entry, "role") or None,
        "principal_type": principal_type,
        "principal": principal,
        "public": is_public_principal(raw) if not isinstance(raw, dict) else False,
    }


def dataset_record(dataset: dict) -> dict:
    """Normalize one dataset resource dict into an evidence record.

    CMEK is the PRESENCE of defaultEncryptionConfiguration.kmsKeyName — the block is
    absent entirely on a Google-managed dataset — the same rule the Cloud SQL, Cloud
    Storage and Persistent Disk encryption fetchers use.
    """
    reference = dig_any(dataset, "dataset_reference") or {}
    kms = dig_any(dataset, "default_encryption_configuration", "kms_key_name")
    entries = [access_entry_record(e) for e in (dig_any(dataset, "access") or [])]

    public_entries = sorted(
        (e for e in entries if e["public"]),
        key=lambda e: (e["principal"] or "", e["role"] or ""),
    )
    # Non-personal entries are safe to name and are the ones a reviewer acts on.
    named_entries = sorted(
        (e for e in entries if e["principal"] is not None and not e["public"]),
        key=lambda e: (e["principal_type"] or "", e["principal"] or "", e["role"] or ""),
    )
    type_counts: dict[str, int] = {}
    for entry in entries:
        key = entry["principal_type"] or "unknown"
        type_counts[key] = type_counts.get(key, 0) + 1

    default_expiration_ms = dig_any(dataset, "default_table_expiration_ms")
    expiration_days = (
        int(int(default_expiration_ms) // 86_400_000)
        if str(default_expiration_ms or "").isdigit()
        else None
    )

    return {
        "name": dig_any(reference, "dataset_id") or None,
        "id": dig_any(dataset, "id") or None,
        "project": dig_any(reference, "project_id") or None,
        "location": dig_any(dataset, "location") or None,
        "friendly_name": dig_any(dataset, "friendly_name") or None,
        "labels": dig_any(dataset, "labels") or {},
        "creation_time": dig_any(dataset, "creation_time") or None,
        "last_modified_time": dig_any(dataset, "last_modified_time") or None,
        # --- encryption at rest ---
        "cmek": kms is not None,
        "kms_key_name": kms,
        # --- access control ---
        "publicly_accessible": bool(public_entries),
        "public_access_entries": public_entries,
        "access_entries": named_entries,
        "access_entry_count": len(entries),
        "access_entry_counts_by_principal_type": type_counts,
        "access_roles": sorted({e["role"] for e in entries if e["role"]}),
        "domain_access": sorted(
            e["principal"] for e in entries if e["principal_type"] == "domain" and e["principal"]
        ),
        # --- retention ---
        "default_table_expiration_ms": default_expiration_ms,
        "default_table_expiration_days": expiration_days,
        "has_default_table_expiration": default_expiration_ms is not None,
        "default_partition_expiration_ms": dig_any(dataset, "default_partition_expiration_ms"),
        "max_time_travel_hours": dig_any(dataset, "max_time_travel_hours"),
    }


def _grants_to(dataset: dict, principal: str) -> bool:
    """Whether this dataset's ACL names one specific public principal."""
    return any(
        str(entry["principal"] or "").split(":")[-1].lower() == principal
        for entry in dataset["public_access_entries"]
    )


def summarize(datasets: list[dict], *, api_readable: bool = True) -> dict:
    cmek = sum(1 for d in datasets if d["cmek"])
    public = sum(1 for d in datasets if d["publicly_accessible"])
    # Counted independently: a dataset can grant both, so one is not the other's inverse.
    all_users = sum(1 for d in datasets if _grants_to(d, "allusers"))
    all_authenticated = sum(1 for d in datasets if _grants_to(d, "allauthenticatedusers"))
    return {
        # False when bigquery.googleapis.com is not enabled on this project (recorded
        # in metadata.skipped_calls) — "no datasets" vs "could not look".
        "bigquery_api_readable": api_readable,
        "total_datasets": len(datasets),
        "cmek_datasets": cmek,
        "google_managed_datasets": len(datasets) - cmek,
        "cmek_percentage": coverage_percentage(cmek, len(datasets)),
        "distinct_kms_keys": sorted({d["kms_key_name"] for d in datasets if d["kms_key_name"]}),
        "publicly_accessible_datasets": public,
        "datasets_with_all_users": all_users,
        "datasets_with_all_authenticated_users": all_authenticated,
        "non_public_dataset_percentage": coverage_percentage(
            len(datasets) - public, len(datasets)
        ),
        "datasets_with_domain_access": sum(1 for d in datasets if d["domain_access"]),
        "datasets_with_default_table_expiration": sum(
            1 for d in datasets if d["has_default_table_expiration"]
        ),
        "locations": sorted({d["location"] for d in datasets if d["location"]}),
    }


# --- collection ---

def collect_datasets(project, creds, collector: Collector) -> list[dict] | None:
    """Every dataset in the project, or None when BigQuery could not be listed.

    datasets.list returns only a reference and the location, so each dataset is fetched
    once for its ACL and encryption config — Prowler's same two-step. One call per
    dataset, not per table.
    """
    from google.cloud import bigquery

    client = collector.guard(
        "bigquery.client",
        lambda: bigquery.Client(project=project, credentials=creds),
        tolerate=service_disabled,
    )
    if client is None:
        return None

    # The client's iterator walks every page; no manual page-token loop.
    listed = collector.guard(
        "bigquery.datasets.list",
        lambda: list(client.list_datasets(project=project)),
        tolerate=service_disabled,
    )
    if listed is None:
        return None

    records = []
    for item in listed:
        dataset_id = getattr(item, "dataset_id", None)

        def _get(reference=item.reference):
            return client.get_dataset(reference).to_api_repr()

        resource = collector.guard(f"bigquery.datasets.get ({dataset_id})", _get)
        if resource is not None:
            records.append(dataset_record(resource))
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

    datasets: list[dict] | None = None
    if project and creds is not None:
        datasets = collect_datasets(project, creds, collector)
    elif not project:
        collector.record("resolve_project", RuntimeError("no project id (set GOOGLE_CLOUD_PROJECT or configure ADC)"))

    evidence = build_payload(
        project=project,
        project_source=proj["project_source"],
        collector=collector,
        results={"datasets": datasets or []},
        summary=summarize(datasets or [], api_readable=datasets is not None),
    )

    filename = (
        f"gcp_bigquery_dataset_configuration_{sanitize_for_filename(project or 'unknown')}.json"
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
