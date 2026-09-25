#!/usr/bin/env python3
"""
OCI Object Storage — who can reach each bucket, whose key encrypts it, and what is logged

Every bucket in scope with its public access type, the key encrypting it,
versioning, retention rules, replication policies, object-event emission, the
read and write logs configured against it, and — the part a public-access check
misses — every pre-authenticated request that hands out access by URL.

Evidence for KSI-SVC-SIN (encrypted and secured from unwanted access),
KSI-IAM-ELP (a PAR is an access grant to whoever holds the link) and
KSI-MLA-LET (the list of resources and event types that are logged).

Ported from Prowler's OCI objectstorage service (Apache-2.0,
prowler/providers/oraclecloud/services/objectstorage, commit 5fe1a67) — the
`objectstorage_bucket_not_publicly_accessible`, `_encrypted_with_cmk`,
`_versioning_enabled` and `_logging_enabled` checks. Three additions:

  * PRE-AUTHENTICATED REQUESTS ARE THE HOLE IN THE PUBLIC-ACCESS CHECK. A bucket
    with `public_access_type: NoPublicAccess` is readable by anyone holding a PAR
    URL, and a PAR with `access_type: AnyObjectRead` plus
    `bucket_listing_action: ListObjects` exposes the whole bucket. Prowler reads
    the access type and stops, so this is invisible to it. Staged on the live
    tenancy — a private bucket carrying exactly such a PAR — and reported as
    `buckets_private_but_reachable_by_par`.

  * READ LOGGING IS REPORTED BESIDE WRITE LOGGING. Prowler's check computes
    `has_read_logging` and then never uses it. Both are recorded: a bucket with
    write logging alone cannot answer "who read this object".

  * REPLICATION AND RETENTION ARE COLLECTED. A replication policy copies objects
    to another bucket, possibly in another region, which the encryption and
    access answers must travel with; a retention rule with `time_rule_locked` in
    the past is immutability that cannot be undone.

A PAR's secret is its URL, which OCI returns only at creation and never again.
Nothing here can read it, and nothing here logs one.
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from oci_common import (  # noqa: E402
    Collector,
    age_in_days,
    as_bool,
    build_payload,
    coverage_percentage,
    finish,
    iso,
    list_all,
    load_config,
    make_client,
    resolve_scope,
    sanitize_for_filename,
    short_ocid,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_object_storage_buckets")

NO_PUBLIC_ACCESS = "NoPublicAccess"

# PAR access types that let the holder read or write objects. "AnyObject*" covers
# the whole bucket; the others are scoped to one object named at creation.
PAR_WHOLE_BUCKET_ACCESS = frozenset({"AnyObjectRead", "AnyObjectWrite", "AnyObjectReadWrite"})
PAR_WRITE_ACCESS = frozenset({"ObjectWrite", "ObjectReadWrite", "AnyObjectWrite", "AnyObjectReadWrite"})

OBJECT_STORAGE_SERVICE = "objectstorage"


# --- pure transforms ---

def par_record(par: dict, *, now=None) -> dict:
    """One pre-authenticated request. The URL is not readable after creation."""
    access = par.get("access_type")
    expires = par.get("time_expires")
    days_left = age_in_days(expires, now=now)
    return {
        # The PAR OCID is deliberately not recorded. It is not the secret — that
        # is the access URI, which OCI returns only at creation — but it is an
        # opaque high-entropy blob, and `name` identifies the PAR for a reader.
        "name": par.get("name"),
        "access_type": access,
        "object_name": par.get("object_name"),
        "bucket_listing_action": par.get("bucket_listing_action"),
        "grants_whole_bucket": access in PAR_WHOLE_BUCKET_ACCESS,
        "grants_write": access in PAR_WRITE_ACCESS,
        "lists_bucket_contents": (par.get("bucket_listing_action") or "Deny") != "Deny",
        "time_created": iso(par.get("time_created")),
        "time_expires": iso(expires),
        # age_in_days on a future date is negative; flip it to days remaining.
        "days_until_expiry": -days_left if days_left is not None else None,
        "expired": days_left is not None and days_left > 0,
    }


def log_record(log: dict) -> dict:
    """One OCI log, reduced to what it logs and whether it is on."""
    source = (log.get("configuration") or {}).get("source") or {}
    return {
        "id": log.get("id"),
        "display_name": log.get("display_name"),
        "is_enabled": log.get("is_enabled") is True,
        "service": source.get("service"),
        "category": source.get("category"),
        "resource": source.get("resource"),
        "retention_duration": log.get("retention_duration"),
    }


def retention_rule_record(rule: dict, *, now=None) -> dict:
    duration = rule.get("duration") or {}
    locked = rule.get("time_rule_locked")
    lock_age = age_in_days(locked, now=now)
    return {
        "id": rule.get("id"),
        "display_name": rule.get("display_name"),
        "duration_amount": duration.get("time_amount"),
        "duration_unit": duration.get("time_unit"),
        "time_rule_locked": iso(locked),
        # A lock time in the past means the rule can no longer be shortened.
        "is_locked": lock_age is not None and lock_age > 0,
    }


def replication_record(policy: dict) -> dict:
    return {
        "id": policy.get("id"),
        "name": policy.get("name"),
        "destination_region_name": policy.get("destination_region_name"),
        "destination_bucket_name": policy.get("destination_bucket_name"),
        "status": policy.get("status"),
        "time_last_sync": iso(policy.get("time_last_sync")),
    }


def bucket_record(bucket: dict, *, pars=None, logs=(), retention=None, replication=None) -> dict:
    """One bucket. `pars`, `retention` and `replication` are None when unread."""
    access = bucket.get("public_access_type")
    public = access is not None and access != NO_PUBLIC_ACCESS
    par_records = list(pars) if pars is not None else None
    live_pars = [p for p in par_records or [] if not p["expired"]]
    bucket_logs = [log_record(entry) for entry in logs]

    def enabled_category(category):
        return any(
            entry["is_enabled"] and entry["service"] == OBJECT_STORAGE_SERVICE
            and entry["category"] == category
            for entry in bucket_logs
        )

    write_logging, read_logging = enabled_category("write"), enabled_category("read")
    return {
        "name": bucket.get("name"),
        "namespace": bucket.get("namespace"),
        "compartment_id": bucket.get("compartment_id"),
        "id": bucket.get("id"),
        "time_created": iso(bucket.get("time_created")),
        "storage_tier": bucket.get("storage_tier"),
        "approximate_count": bucket.get("approximate_count"),
        # Access.
        "public_access_type": access,
        "is_public": public,
        "is_read_only": bucket.get("is_read_only"),
        # Encryption: OCI always encrypts, so the question is whose key.
        "kms_key_id": bucket.get("kms_key_id"),
        "customer_managed_key": bucket.get("kms_key_id") is not None,
        # Durability / immutability.
        "versioning": bucket.get("versioning"),
        "versioning_enabled": bucket.get("versioning") == "Enabled",
        "retention_rules": retention,
        "locked_retention_rules": (
            sum(1 for r in retention if r["is_locked"]) if retention is not None else None
        ),
        "replication_enabled": bucket.get("replication_enabled"),
        "replication_policies": replication,
        # Logging.
        "object_events_enabled": bucket.get("object_events_enabled") is True,
        "logs": bucket_logs,
        "write_logging_enabled": write_logging,
        "read_logging_enabled": read_logging,
        # Pre-authenticated requests — access by URL, invisible to public_access_type.
        "preauthenticated_requests": par_records,
        "active_par_count": len(live_pars) if par_records is not None else None,
        "pars_granting_whole_bucket": (
            sum(1 for p in live_pars if p["grants_whole_bucket"]) if par_records is not None else None
        ),
        "pars_granting_write": (
            sum(1 for p in live_pars if p["grants_write"]) if par_records is not None else None
        ),
        "reachable_by_par": bool(live_pars) if par_records is not None else None,
        "pars_read": par_records is not None,
    }


def summarize(buckets: list[dict], *, api_readable: bool = True) -> dict:
    public = [b for b in buckets if b["is_public"]]
    with_pars = [b for b in buckets if b["pars_read"]]
    reachable = [b for b in with_pars if b["reachable_by_par"]]

    return {
        # False when Object Storage could not be listed — not "no buckets".
        "object_storage_readable": api_readable,
        "total_buckets": len(buckets),
        # Access.
        "public_buckets": len(public),
        "public_bucket_names": sorted(b["name"] for b in public if b["name"]),
        "public_access_types_in_use": sorted({b["public_access_type"] for b in public if b["public_access_type"]}),
        # Private buckets answer NoPublicAccess; no answer is not the same thing.
        "buckets_with_unknown_public_access": sum(1 for b in buckets if b["public_access_type"] is None),
        # PARs — the access a public-access check cannot see.
        "buckets_with_unreadable_pars": len(buckets) - len(with_pars),
        "buckets_reachable_by_par": len(reachable),
        "buckets_private_but_reachable_by_par": sum(1 for b in reachable if not b["is_public"]),
        "total_active_pars": sum(b["active_par_count"] or 0 for b in with_pars),
        "pars_granting_whole_bucket": sum(b["pars_granting_whole_bucket"] or 0 for b in with_pars),
        "pars_granting_write": sum(b["pars_granting_write"] or 0 for b in with_pars),
        # Encryption.
        "buckets_with_customer_managed_key": sum(1 for b in buckets if b["customer_managed_key"]),
        "customer_managed_key_percentage": coverage_percentage(
            sum(1 for b in buckets if b["customer_managed_key"]), len(buckets)
        ),
        # Durability.
        "buckets_with_versioning": sum(1 for b in buckets if b["versioning_enabled"]),
        "versioning_percentage": coverage_percentage(
            sum(1 for b in buckets if b["versioning_enabled"]), len(buckets)
        ),
        "buckets_with_retention_rules": sum(1 for b in buckets if b["retention_rules"]),
        "buckets_with_locked_retention_rules": sum(1 for b in buckets if b["locked_retention_rules"]),
        "buckets_with_replication": sum(1 for b in buckets if b["replication_policies"]),
        "replication_destination_regions": sorted({
            p["destination_region_name"] for b in buckets for p in b["replication_policies"] or []
            if p["destination_region_name"]
        }),
        # Logging — read and write kept apart.
        "buckets_with_write_logging": sum(1 for b in buckets if b["write_logging_enabled"]),
        "buckets_with_read_logging": sum(1 for b in buckets if b["read_logging_enabled"]),
        "buckets_with_no_data_logging": sum(
            1 for b in buckets if not b["write_logging_enabled"] and not b["read_logging_enabled"]
        ),
        "write_logging_percentage": coverage_percentage(
            sum(1 for b in buckets if b["write_logging_enabled"]), len(buckets)
        ),
        "buckets_emitting_object_events": sum(1 for b in buckets if b["object_events_enabled"]),
        "bucket_names_public_or_par_reachable": sorted(
            f"{b['name']} ({short_ocid(b['id'])})" for b in buckets
            if b["name"] and (b["is_public"] or b["reachable_by_par"])
        ),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool):
    import oci  # lazy

    identity = make_client(oci.identity.IdentityClient, auth)
    storage = make_client(oci.object_storage.ObjectStorageClient, auth)
    logging_client = make_client(oci.logging.LoggingManagementClient, auth)

    namespace = collector.guard("object_storage.get_namespace", lambda: storage.get_namespace().data)
    if namespace is None:
        return None, 0

    compartments = walk_compartments(
        identity, scope["compartment_id"], collector,
        include_subcompartments=include_sub, tenancy=auth.get("tenancy"),
    )

    buckets: list[dict] = []
    unreadable = 0

    # Logs are configured against a bucket by name, in a log group that need not
    # sit in the bucket's own compartment, so every log group in scope is read
    # before any bucket is matched. (Built per compartment, a bucket logged into
    # a central logging compartment read as unlogged.)
    logs_by_resource: dict[str, list] = {}
    for comp in compartments:
        for group in collector.guard(
            f"logging.list_log_groups ({comp['name']})",
            lambda c=comp["id"]: list_all(logging_client.list_log_groups, c),
            default=[],
        ) or []:
            for entry in collector.guard(
                f"logging.list_logs ({group.display_name})",
                lambda g=group.id: list_all(logging_client.list_logs, g),
                default=[],
            ) or []:
                plain = to_plain(entry)
                source = (plain.get("configuration") or {}).get("source") or {}
                if source.get("service") == OBJECT_STORAGE_SERVICE and source.get("resource"):
                    logs_by_resource.setdefault(source["resource"], []).append(plain)

    for comp in compartments:
        cid, cname = comp["id"], comp["name"]

        found = collector.guard(
            f"object_storage.list_buckets ({cname})",
            lambda c=cid: list_all(storage.list_buckets, namespace_name=namespace, compartment_id=c),
        )
        if found is None:
            unreadable += 1
            continue

        for summary in found:
            name = summary.name
            # Mandatory second call: the list summary carries no access type,
            # key, versioning or replication flag.
            detail = collector.guard(
                f"object_storage.get_bucket ({name})",
                lambda n=name: storage.get_bucket(namespace_name=namespace, bucket_name=n).data,
            )
            plain = to_plain(detail if detail is not None else summary)

            pars = collector.guard(
                f"object_storage.list_preauthenticated_requests ({name})",
                lambda n=name: list_all(storage.list_preauthenticated_requests,
                                        namespace_name=namespace, bucket_name=n),
            )
            retention = collector.guard(
                f"object_storage.list_retention_rules ({name})",
                lambda n=name: list_all(storage.list_retention_rules,
                                        namespace_name=namespace, bucket_name=n),
            )
            replication = collector.guard(
                f"object_storage.list_replication_policies ({name})",
                lambda n=name: list_all(storage.list_replication_policies,
                                        namespace_name=namespace, bucket_name=n),
            )
            buckets.append(bucket_record(
                plain,
                pars=[par_record(to_plain(p)) for p in pars] if pars is not None else None,
                logs=logs_by_resource.get(name, []),
                retention=[retention_rule_record(to_plain(r)) for r in retention]
                if retention is not None else None,
                replication=[replication_record(to_plain(r)) for r in replication]
                if replication is not None else None,
            ))

    if compartments and unreadable == len(compartments):
        return None, len(compartments)

    buckets.sort(key=lambda r: r.get("name") or "")
    return buckets, len(compartments)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    include_sub = as_bool(os.environ.get("OCI_INCLUDE_SUBCOMPARTMENTS"), default=True)

    auth: dict = {}
    scope: dict = {"compartment_id": None, "compartment_source": "unresolved"}
    buckets = None
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            try:
                buckets, scanned = collect(auth, scope, collector, include_sub=include_sub)
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("object_storage.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={"buckets": buckets or []},
        summary=summarize(buckets or [], api_readable=buckets is not None),
        compartments_scanned=scanned,
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_object_storage_buckets_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)
    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
