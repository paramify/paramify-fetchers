#!/usr/bin/env python3
"""
OCI Vault — every key, how it is protected, and whether it is actually rotated

Every Vault in scope and every key inside it: protection mode, algorithm and
length, auto-rotation settings, the age of the key version currently in use,
whether that version arrived by automatic rotation or by hand, and whether
either the key or its vault is scheduled for deletion.

Evidence for KSI-SVC-ASM, "management, protection, and regular rotation of
digital keys, certificates, and other secrets is automated and persistently
reviewed", and KSI-SVC-SIN for the protection mode — a key held in software is
secured differently from one that never leaves an HSM.

Ported from Prowler's OCI kms service (Apache-2.0,
prowler/providers/oraclecloud/services/kms, commit 5fe1a67) — the
`kms_key_rotation_enabled` check — with four departures, three of them verified
against a live tenancy:

  * A ROTATION INTERVAL IS NOT ROTATION. Prowler passes a key when
    `rotation_interval_in_days <= 365` *or* auto-rotation is enabled, so a key
    that carries an interval from when auto-rotation was switched on, and has
    since had it switched off, reads as compliant forever. Here automatic
    rotation counts only when `is_auto_rotation_enabled` is true AND the
    interval is within the window.

  * AUTOMATIC AND MANUAL ROTATION ARE REPORTED APART. The indicator asks for
    rotation that is *automated*. A key rotated by hand inside the window
    satisfies "regular rotation" but not "is automated", so
    `rotation_is_manual` is recorded rather than folded into one pass.

  * THE VAULT TYPE DECIDES WHETHER AUTO-ROTATION IS EVEN POSSIBLE. Creating a
    key with auto-rotation in a DEFAULT (virtual) vault is refused —
    "Automatic key rotation is not supported with VIRTUAL vaults" — so every
    key in one would otherwise read as a finding no operator can clear.
    `auto_rotation_supported` carries the vault type, and the summary counts
    those keys separately.

  * DISABLED AND PENDING-DELETION KEYS ARE COLLECTED. Prowler keeps only
    ENABLED keys, so a key scheduled for deletion — which still protects
    everything encrypted under it until the day it goes — is invisible.

On the live tenancy both keys came back `protection_mode: HSM`,
`is_auto_rotation_enabled: false` and `auto_key_rotation_details: null`, and the
hand-rotated one is distinguishable only by having two key versions. That is why
version count and current-version age are on every record.
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
    service_not_subscribed,
    short_ocid,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_vault_keys")

# CIS OCI Foundations 3.x / Prowler's own window.
ROTATION_WINDOW_DAYS = 365

# Vault types that can hold auto-rotating keys. A DEFAULT vault is the shared
# virtual one; auto-rotation is refused there (verified on a live tenancy).
AUTO_ROTATION_VAULT_TYPES = frozenset({"VIRTUAL_PRIVATE"})

HSM_PROTECTION = "HSM"
LIVE_KEY_STATES = frozenset({"ENABLED", "UPDATING"})


# --- pure transforms ---

def key_record(key: dict, *, vault=None, current_version=None, version_count=None, now=None) -> dict:
    """One key, judged on whether it is actually rotated and how it is held.

    `current_version` is the KeyVersion the key points at, or None when that
    read failed; `version_count` is None for the same reason. A failed read is
    never reported as "never rotated".
    """
    rotation = key.get("auto_key_rotation_details") or {}
    interval = rotation.get("rotation_interval_in_days")
    auto_enabled = key.get("is_auto_rotation_enabled") is True
    vault_type = (vault or {}).get("vault_type")
    current_version = current_version or {}

    version_created = current_version.get("time_created")
    version_age = age_in_days(version_created, now=now)
    in_window = version_age is not None and version_age <= ROTATION_WINDOW_DAYS
    # Prowler passes on the interval alone; an interval left behind by
    # auto-rotation that was later switched off rotates nothing.
    auto_within_window = auto_enabled and interval is not None and interval <= ROTATION_WINDOW_DAYS

    return {
        "id": key.get("id"),
        "display_name": key.get("display_name"),
        "compartment_id": key.get("compartment_id"),
        "vault_id": key.get("vault_id"),
        "vault_type": vault_type,
        "lifecycle_state": key.get("lifecycle_state"),
        "protection_mode": key.get("protection_mode"),
        "is_hsm_protected": key.get("protection_mode") == HSM_PROTECTION,
        "algorithm": (key.get("key_shape") or {}).get("algorithm"),
        "length_bytes": (key.get("key_shape") or {}).get("length"),
        "curve_id": (key.get("key_shape") or {}).get("curve_id"),
        "is_primary": key.get("is_primary"),
        "restored_from_key_id": key.get("restored_from_key_id"),
        "time_created": iso(key.get("time_created")),
        # Non-null means the key is scheduled for deletion but still in force.
        "time_of_deletion": iso(key.get("time_of_deletion")),
        "pending_deletion": key.get("time_of_deletion") is not None,
        # Rotation.
        "is_auto_rotation_enabled": auto_enabled,
        "rotation_interval_in_days": interval,
        "auto_rotation_supported": vault_type in AUTO_ROTATION_VAULT_TYPES if vault_type else None,
        "auto_rotation_within_window": auto_within_window,
        "time_of_last_rotation": iso(rotation.get("time_of_last_rotation")),
        "time_of_next_rotation": iso(rotation.get("time_of_next_rotation")),
        "last_rotation_status": rotation.get("last_rotation_status"),
        # The version actually in use.
        "current_key_version_id": key.get("current_key_version"),
        "current_key_version_created": iso(version_created),
        "current_key_version_age_days": version_age,
        "current_key_version_auto_rotated": current_version.get("is_auto_rotated"),
        "current_key_version_origin": current_version.get("origin"),
        "key_version_count": version_count,
        # None when the version read failed — not "never rotated".
        "rotated_within_window": in_window if version_created is not None else None,
        "rotation_is_manual": bool(in_window and not auto_enabled) if version_created is not None else None,
        "version_read": version_created is not None,
    }


def vault_record(vault: dict) -> dict:
    return {
        "id": vault.get("id"),
        "display_name": vault.get("display_name"),
        "compartment_id": vault.get("compartment_id"),
        "vault_type": vault.get("vault_type"),
        "lifecycle_state": vault.get("lifecycle_state"),
        "is_primary": vault.get("is_primary"),
        "restored_from_vault_id": vault.get("restored_from_vault_id"),
        "time_created": iso(vault.get("time_created")),
        "time_of_deletion": iso(vault.get("time_of_deletion")),
        "pending_deletion": vault.get("time_of_deletion") is not None,
        "uses_external_key_manager": vault.get("external_key_manager_metadata_summary") is not None,
        "supports_auto_rotation": vault.get("vault_type") in AUTO_ROTATION_VAULT_TYPES,
    }


def summarize(vaults: list[dict], keys: list[dict], *, api_readable: bool = True) -> dict:
    live = [k for k in keys if k["lifecycle_state"] in LIVE_KEY_STATES]
    read = [k for k in live if k["version_read"]]
    auto = [k for k in read if k["auto_rotation_within_window"]]
    manual = [k for k in read if k["rotation_is_manual"]]
    stale = [k for k in read if not k["rotated_within_window"] and not k["auto_rotation_within_window"]]
    capable = [k for k in read if k["auto_rotation_supported"]]

    return {
        # False when Vault is not subscribed or the list call failed — not "no vaults".
        "vault_service_readable": api_readable,
        "total_vaults": len(vaults),
        "active_vaults": sum(1 for v in vaults if v["lifecycle_state"] == "ACTIVE"),
        "vaults_pending_deletion": sum(1 for v in vaults if v["pending_deletion"]),
        "vaults_supporting_auto_rotation": sum(1 for v in vaults if v["supports_auto_rotation"]),
        "vaults_using_external_key_manager": sum(1 for v in vaults if v["uses_external_key_manager"]),
        "total_keys": len(keys),
        "live_keys": len(live),
        "keys_with_unreadable_version": len(live) - len(read),
        "keys_pending_deletion": sum(1 for k in live if k["pending_deletion"]),
        # The indicator's two halves, never summed.
        "keys_with_automatic_rotation": len(auto),
        "keys_rotated_manually_within_window": len(manual),
        "keys_not_rotated_within_window": len(stale),
        "automatic_rotation_percentage": coverage_percentage(len(auto), len(read)),
        # Keys whose vault cannot do automatic rotation at all — a DEFAULT vault
        # refuses it, so this is a vault-type decision, not an operator lapse.
        "keys_in_vaults_without_auto_rotation_support": len(read) - len(capable),
        "hsm_protected_keys": sum(1 for k in live if k["is_hsm_protected"]),
        "software_protected_keys": sum(1 for k in live if k["protection_mode"] == "SOFTWARE"),
        "hsm_protection_percentage": coverage_percentage(
            sum(1 for k in live if k["is_hsm_protected"]), len(live)
        ),
        "oldest_key_version_age_days": max(
            (k["current_key_version_age_days"] for k in read
             if k["current_key_version_age_days"] is not None), default=None
        ),
        # One version means the key has never been rotated. On a young key that
        # is expected, so it is a count, not a finding — the finding is
        # keys_not_rotated_within_window.
        "keys_with_a_single_key_version": sum(1 for k in read if k["key_version_count"] == 1),
        "key_names_not_rotated_within_window": sorted(
            f"{k['display_name']} ({short_ocid(k['id'])})" for k in stale if k["display_name"]
        ),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool):
    import oci  # lazy

    identity = make_client(oci.identity.IdentityClient, auth)
    vault_client = make_client(oci.key_management.KmsVaultClient, auth)

    compartments = walk_compartments(
        identity, scope["compartment_id"], collector,
        include_subcompartments=include_sub, tenancy=auth.get("tenancy"),
    )

    vaults: list[dict] = []
    keys: list[dict] = []
    unreadable = 0

    for comp in compartments:
        cid, cname = comp["id"], comp["name"]
        found = collector.guard(
            f"kms_vault.list_vaults ({cname})",
            lambda c=cid: list_all(vault_client.list_vaults, c),
            tolerate=service_not_subscribed,
        )
        if found is None:
            unreadable += 1
            continue

        for summary in found:
            # The detail call carries time_of_deletion and is_primary, which the
            # list summary does not — a vault scheduled for deletion still holds
            # every key under it.
            detail = collector.guard(
                f"kms_vault.get_vault ({short_ocid(summary.id)})",
                lambda v=summary.id: vault_client.get_vault(v).data,
            )
            plain = to_plain(detail if detail is not None else summary)
            vaults.append(vault_record(plain))

            if plain.get("lifecycle_state") != "ACTIVE" or not plain.get("management_endpoint"):
                continue
            management = make_client(
                oci.key_management.KmsManagementClient, auth,
                service_endpoint=plain["management_endpoint"],
            )
            for key_summary in collector.guard(
                f"kms_management.list_keys ({plain.get('display_name')})",
                lambda c=cid: list_all(management.list_keys, c),
                default=[],
            ) or []:
                label = short_ocid(key_summary.id)
                # Mandatory second call: auto_key_rotation_details and
                # current_key_version are absent from KeySummary.
                key_detail = collector.guard(
                    f"kms_management.get_key ({label})",
                    lambda k=key_summary.id: management.get_key(k).data,
                )
                key = to_plain(key_detail if key_detail is not None else key_summary)

                version = None
                if key.get("current_key_version"):
                    version = collector.guard(
                        f"kms_management.get_key_version ({label})",
                        lambda k=key["id"], v=key["current_key_version"]:
                            management.get_key_version(key_id=k, key_version_id=v).data,
                    )
                versions = collector.guard(
                    f"kms_management.list_key_versions ({label})",
                    lambda k=key["id"]: list_all(management.list_key_versions, k),
                )
                keys.append(key_record(
                    key, vault=plain,
                    current_version=to_plain(version) if version is not None else None,
                    version_count=len(versions) if versions is not None else None,
                ))

    if compartments and unreadable == len(compartments):
        return None, None, len(compartments)

    vaults.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    keys.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    return vaults, keys, len(compartments)


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
    vaults = keys = None
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            try:
                vaults, keys, scanned = collect(auth, scope, collector, include_sub=include_sub)
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("kms.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={"vaults": vaults or [], "keys": keys or []},
        summary=summarize(vaults or [], keys or [], api_readable=vaults is not None),
        compartments_scanned=scanned,
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_vault_keys_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)
    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
