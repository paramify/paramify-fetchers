"""Encryption judgements in `oci_block_volume_encryption`, beyond Prowler's kms_key_id test."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "block_volume_encryption" / "fetcher.py"
KEY = "ocid1.key.oc1..cmk"


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_block_volume_encryption", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bv = _load()


def _volume(name, *, key=None, state="AVAILABLE"):
    return {"id": f"ocid1.volume.oc1..{name}", "display_name": name, "lifecycle_state": state,
            "kms_key_id": key, "size_in_gbs": 50}


def _attachment(state="ATTACHED", in_transit=False, kind="block", type_=None):
    return bv.attachment_record({"id": "a", "lifecycle_state": state, "instance_id": "i",
                                 "is_pv_encryption_in_transit_enabled": in_transit,
                                 "encryption_in_transit_type": type_}, kind=kind)


def _backup(name, *, key=None, kind="block"):
    return bv.backup_record({"id": f"b-{name}", "display_name": name, "kms_key_id": key,
                             "lifecycle_state": "AVAILABLE", "type": "FULL"}, kind=kind)


def test_a_customer_managed_volume_can_have_oracle_managed_backups():
    """Prowler looks at the volume only, so this mismatch is invisible to it."""
    volume = bv.volume_record(_volume("cmk", key=KEY), kind="block",
                              backups=[_backup("nightly"), _backup("weekly", key=KEY)])
    out = bv.summarize([volume])
    assert out["volumes_with_customer_managed_key"] == 1
    assert out["volumes_with_customer_key_but_oracle_managed_backups"] == 1
    assert out["backups_with_oracle_managed_key"] == 1
    assert out["backups_with_customer_managed_key"] == 1


def test_in_transit_encryption_is_judged_over_attached_volumes_only():
    """The live boot attachment reports False / NONE — the staged finding."""
    attached = bv.volume_record(_volume("boot"), kind="boot",
                                attachments=[_attachment(in_transit=False, kind="boot", type_="NONE")],
                                backups=[])
    detached = bv.volume_record(_volume("spare"), kind="block", attachments=[], backups=[])
    assert attached["in_transit_encryption_enabled"] is False
    assert detached["in_transit_encryption_enabled"] is None

    out = bv.summarize([attached, detached])
    assert out["attached_volumes"] == 1 and out["unattached_volumes"] == 1
    assert out["in_transit_encryption_percentage"] == 0

    encrypted = bv.volume_record(_volume("enc"), kind="block",
                                 attachments=[_attachment(in_transit=True)], backups=[])
    assert bv.summarize([encrypted])["in_transit_encryption_percentage"] == 100


def test_a_detached_attachment_does_not_make_a_volume_attached():
    volume = bv.volume_record(_volume("v"), kind="block",
                              attachments=[_attachment(state="DETACHED", in_transit=True)], backups=[])
    assert volume["is_attached"] is False
    assert volume["in_transit_encryption_enabled"] is None
    assert bv.summarize([volume])["attached_volumes"] == 0


def test_unreadable_backups_are_not_no_backups():
    volume = bv.volume_record(_volume("v", key=KEY), kind="block", backups=None)
    assert volume["backups_read"] is False and volume["backup_count"] is None
    out = bv.summarize([volume])
    assert out["volumes_with_unreadable_backups"] == 1
    assert out["total_backups"] == 0
    assert out["volumes_with_customer_key_but_oracle_managed_backups"] == 0


def test_terminated_volumes_are_excluded_from_every_count():
    out = bv.summarize([bv.volume_record(_volume("gone", state="TERMINATED"), kind="block", backups=[])])
    assert out["total_volumes"] == 0
    assert out["customer_managed_key_percentage"] == 0


def test_key_counts_split_block_from_boot_and_count_distinct_keys():
    volumes = [
        bv.volume_record(_volume("b1", key=KEY), kind="block", backups=[]),
        bv.volume_record(_volume("b2", key="ocid1.key.oc1..other"), kind="block", backups=[]),
        bv.volume_record(_volume("boot1"), kind="boot", backups=[]),
    ]
    out = bv.summarize(volumes)
    assert out["block_volumes_with_customer_managed_key"] == 2
    assert out["boot_volumes_with_customer_managed_key"] == 0
    assert out["distinct_keys_in_use"] == 2
    assert out["customer_managed_key_percentage"] == 66


def test_an_unreadable_service_is_not_no_volumes():
    assert bv.summarize([], api_readable=False)["block_storage_readable"] is False
