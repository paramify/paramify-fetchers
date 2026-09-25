#!/usr/bin/env python3
"""
OCI Block Storage — which key encrypts each volume, and whether the wire is encrypted too

Every block volume and boot volume in scope with the key that encrypts it, every
backup of those volumes with the key that encrypts the backup, and every
attachment with whether data moving between the instance and the volume is
encrypted in transit.

Evidence for KSI-SVC-SIN, "information is encrypted or otherwise secured from
unwanted access or modification". OCI encrypts every volume at rest with no way
to turn it off, so the at-rest question is not *whether* but *whose key*: an
Oracle-managed key is encryption the provider controls, a customer-managed key
in Vault is encryption the customer controls and can revoke.

Ported from Prowler's OCI blockstorage service (Apache-2.0,
prowler/providers/oraclecloud/services/blockstorage, commit 5fe1a67) — the
`blockstorage_block_volume_encrypted_with_cmk` and
`blockstorage_boot_volume_encrypted_with_cmk` checks, which test `kms_key_id is
not None` and stop there. Three additions:

  * BACKUPS CARRY THEIR OWN KEY. `VolumeBackup.kms_key_id` is independent of the
    volume's, so a customer-managed volume can have Oracle-managed backups
    holding the same bytes. Prowler does not look at backups at all.

  * IN-TRANSIT ENCRYPTION IS PART OF THE SAME INDICATOR. A volume attachment
    carries `is_pv_encryption_in_transit_enabled`; boot attachments also carry
    `encryption_in_transit_type`. Verified live: the staged instance reports
    False / NONE, so this is a real, separately reportable state.

  * UNATTACHED VOLUMES ARE COUNTED. A detached volume still holds every byte
    written to it. Cloud Guard raises BLOCK_VOLUME_NOT_ATTACHED for exactly this
    reason, and the count appears here beside the key it is encrypted with.

DELIBERATELY NOT COLLECTED: backup-policy assignments. They answer a recovery
question (KSI-RPL-ABO), not an encryption one, and cost one call per volume.

A NOTE ON THE KEY OCID. This fetcher records which key each volume uses; whether
that key is rotated, HSM-backed or pending deletion is `oci_vault_keys`. Joining
them is the assessor's job, not this fetcher's — the two evidence files carry the
same key OCIDs.
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

logger = logging.getLogger("oci_block_volume_encryption")

# States where the volume still exists and still holds data.
LIVE_VOLUME_STATES = frozenset({"AVAILABLE", "PROVISIONING", "RESTORING", "FAULTY"})
GONE_STATES = frozenset({"TERMINATED", "TERMINATING"})
ATTACHED_STATES = frozenset({"ATTACHED", "ATTACHING"})


# --- pure transforms ---

def volume_record(volume: dict, *, kind: str, attachments=(), backups=None) -> dict:
    """One block or boot volume with its key, attachments and backups.

    `backups` is None when the backup listing failed — distinct from a volume
    that genuinely has none, because "no backups" and "we could not tell" have
    opposite meanings for the key question.
    """
    key_id = volume.get("kms_key_id")
    live_attachments = [a for a in attachments if a["is_attached"]]
    backup_records = list(backups) if backups is not None else None
    return {
        "id": volume.get("id"),
        "display_name": volume.get("display_name"),
        "kind": kind,
        "compartment_id": volume.get("compartment_id"),
        "availability_domain": volume.get("availability_domain"),
        "lifecycle_state": volume.get("lifecycle_state"),
        "size_in_gbs": volume.get("size_in_gbs"),
        "volume_group_id": volume.get("volume_group_id"),
        "image_id": volume.get("image_id"),
        "time_created": iso(volume.get("time_created")),
        # At rest: OCI always encrypts; the question is whose key.
        "kms_key_id": key_id,
        "customer_managed_key": key_id is not None,
        # In transit, from the attachment rather than the volume.
        "attachments": list(attachments),
        "is_attached": bool(live_attachments),
        "in_transit_encryption_enabled": (
            any(a["in_transit_encryption_enabled"] for a in live_attachments)
            if live_attachments else None
        ),
        # Backups hold the same bytes under a key of their own.
        "backups": backup_records,
        "backup_count": len(backup_records) if backup_records is not None else None,
        "backups_with_customer_managed_key": (
            sum(1 for b in backup_records if b["customer_managed_key"]) if backup_records is not None else None
        ),
        "backups_read": backup_records is not None,
    }


def attachment_record(attachment: dict, *, kind: str) -> dict:
    state = attachment.get("lifecycle_state")
    return {
        "id": attachment.get("id"),
        "kind": kind,
        "instance_id": attachment.get("instance_id"),
        "lifecycle_state": state,
        "is_attached": state in ATTACHED_STATES,
        "in_transit_encryption_enabled": attachment.get("is_pv_encryption_in_transit_enabled") is True,
        # Boot attachments only; NONE is the live reading for an instance
        # launched without in-transit encryption.
        "encryption_in_transit_type": attachment.get("encryption_in_transit_type"),
        "is_read_only": attachment.get("is_read_only"),
        "time_created": iso(attachment.get("time_created")),
    }


def backup_record(backup: dict, *, kind: str) -> dict:
    key_id = backup.get("kms_key_id")
    return {
        "id": backup.get("id"),
        "kind": kind,
        "display_name": backup.get("display_name"),
        "lifecycle_state": backup.get("lifecycle_state"),
        "type": backup.get("type"),
        "source_type": backup.get("source_type"),
        "size_in_gbs": backup.get("size_in_gbs"),
        "kms_key_id": key_id,
        "customer_managed_key": key_id is not None,
        "time_created": iso(backup.get("time_created")),
        "expiration_time": iso(backup.get("expiration_time")),
        "is_retention_lock_enabled": backup.get("is_retention_lock_enabled"),
    }


def summarize(volumes: list[dict], *, api_readable: bool = True) -> dict:
    live = [v for v in volumes if v["lifecycle_state"] not in GONE_STATES]
    block = [v for v in live if v["kind"] == "block"]
    boot = [v for v in live if v["kind"] == "boot"]
    cmk = [v for v in live if v["customer_managed_key"]]
    attached = [v for v in live if v["is_attached"]]
    read_backups = [v for v in live if v["backups_read"]]
    all_backups = [b for v in read_backups for b in v["backups"]]

    return {
        # False when the volume listing failed — not "no volumes".
        "block_storage_readable": api_readable,
        "total_volumes": len(live),
        "block_volumes": len(block),
        "boot_volumes": len(boot),
        # At rest.
        "volumes_with_customer_managed_key": len(cmk),
        "volumes_with_oracle_managed_key": len(live) - len(cmk),
        "customer_managed_key_percentage": coverage_percentage(len(cmk), len(live)),
        "block_volumes_with_customer_managed_key": sum(1 for v in block if v["customer_managed_key"]),
        "boot_volumes_with_customer_managed_key": sum(1 for v in boot if v["customer_managed_key"]),
        "distinct_keys_in_use": len({v["kms_key_id"] for v in cmk if v["kms_key_id"]}),
        # In transit, over attached volumes only — an unattached volume has no wire.
        "attached_volumes": len(attached),
        "unattached_volumes": len(live) - len(attached),
        "attached_volumes_with_in_transit_encryption": sum(
            1 for v in attached if v["in_transit_encryption_enabled"]
        ),
        "in_transit_encryption_percentage": coverage_percentage(
            sum(1 for v in attached if v["in_transit_encryption_enabled"]), len(attached)
        ),
        # Backups.
        "volumes_with_unreadable_backups": len(live) - len(read_backups),
        "total_backups": len(all_backups),
        "backups_with_customer_managed_key": sum(1 for b in all_backups if b["customer_managed_key"]),
        "backups_with_oracle_managed_key": sum(1 for b in all_backups if not b["customer_managed_key"]),
        # The mismatch a volume-only check cannot see.
        "volumes_with_customer_key_but_oracle_managed_backups": sum(
            1 for v in read_backups
            if v["customer_managed_key"] and any(not b["customer_managed_key"] for b in v["backups"])
        ),
        "volume_names_with_oracle_managed_key": sorted(
            f"{v['display_name']} ({short_ocid(v['id'])})" for v in live
            if not v["customer_managed_key"] and v["display_name"]
        ),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool):
    import oci  # lazy

    identity = make_client(oci.identity.IdentityClient, auth)
    blockstorage = make_client(oci.core.BlockstorageClient, auth)
    compute = make_client(oci.core.ComputeClient, auth)

    compartments = walk_compartments(
        identity, scope["compartment_id"], collector,
        include_subcompartments=include_sub, tenancy=auth.get("tenancy"),
    )

    volumes: list[dict] = []
    unreadable = 0

    # Gathered across the whole scope before anything is joined. An attachment
    # lives in the INSTANCE's compartment and a backup wherever it was put, so
    # matching them only within the volume's own compartment reported a volume
    # attached from elsewhere as unattached, and missed its backups.
    attachments_by_volume: dict[str, list] = {}
    backups_by_volume: dict[str, list] = {}
    backups_complete = True
    raw_volumes: list[tuple] = []

    # Availability domains are the region's, not a compartment's: listed once
    # rather than once per compartment. Resources that are listed per AD
    # (boot volumes, File Storage) are walked over this list.
    domains = collector.guard(
        "identity.list_availability_domains",
        lambda: identity.list_availability_domains(compartment_id=auth.get("tenancy")).data,
        default=[],
    ) or []

    for comp in compartments:
        cid, cname = comp["id"], comp["name"]


        for attachment in collector.guard(
            f"compute.list_volume_attachments ({cname})",
            lambda c=cid: list_all(compute.list_volume_attachments, c),
            default=[],
        ) or []:
            plain = to_plain(attachment)
            attachments_by_volume.setdefault(plain.get("volume_id"), []).append(
                attachment_record(plain, kind="block"))
        for domain in domains:
            for attachment in collector.guard(
                f"compute.list_boot_volume_attachments ({cname}, {domain.name})",
                lambda c=cid, d=domain.name: list_all(compute.list_boot_volume_attachments, d, c),
                default=[],
            ) or []:
                plain = to_plain(attachment)
                attachments_by_volume.setdefault(plain.get("boot_volume_id"), []).append(
                    attachment_record(plain, kind="boot"))

        # One backup listing per compartment rather than one per volume.
        for backup_call, id_field, kind in (
            (blockstorage.list_volume_backups, "volume_id", "block"),
            (blockstorage.list_boot_volume_backups, "boot_volume_id", "boot"),
        ):
            backups = collector.guard(
                f"blockstorage.{backup_call.__name__} ({cname})",
                lambda call=backup_call, c=cid: list_all(call, compartment_id=c),
            )
            if backups is None:
                backups_complete = False
                continue
            for backup in backups:
                plain = to_plain(backup)
                backups_by_volume.setdefault(plain.get(id_field), []).append(backup_record(plain, kind=kind))

        found = collector.guard(
            f"blockstorage.list_volumes ({cname})",
            lambda c=cid: list_all(blockstorage.list_volumes, compartment_id=c),
        )
        if found is None:
            unreadable += 1
            found = []
        raw_volumes += [(v, "block") for v in found]

        for domain in domains:
            raw_volumes += [(v, "boot") for v in collector.guard(
                f"blockstorage.list_boot_volumes ({cname}, {domain.name})",
                lambda c=cid, d=domain.name: list_all(
                    blockstorage.list_boot_volumes, availability_domain=d, compartment_id=c),
                default=[],
            ) or []]

    for raw, kind in raw_volumes:
        plain = to_plain(raw)
        if plain.get("lifecycle_state") in GONE_STATES:
            continue
        found_backups = backups_by_volume.get(plain.get("id"), [])
        volumes.append(volume_record(
            plain, kind=kind,
            attachments=attachments_by_volume.get(plain.get("id"), []),
            # A failed listing anywhere means "none found" cannot be told apart
            # from "could not look".
            backups=found_backups if found_backups or backups_complete else None,
        ))

    if compartments and unreadable == len(compartments):
        return None, len(compartments)

    volumes.sort(key=lambda r: (r.get("kind") or "", r.get("display_name") or "", r.get("id") or ""))
    return volumes, len(compartments)


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
    volumes = None
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            try:
                volumes, scanned = collect(auth, scope, collector, include_sub=include_sub)
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("blockstorage.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={"volumes": volumes or []},
        summary=summarize(volumes or [], api_readable=volumes is not None),
        compartments_scanned=scanned,
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_block_volume_encryption_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)
    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
