"""Rotation judgements in `oci_vault_keys`, including where Prowler passes a key it should not."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "vault_keys" / "fetcher.py"
NOW = datetime(2026, 9, 17, tzinfo=timezone.utc)
PRIVATE_VAULT = {"vault_type": "VIRTUAL_PRIVATE"}
DEFAULT_VAULT = {"vault_type": "DEFAULT"}


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_vault_keys", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kms = _load()


def _key(name="k", *, auto=False, interval=None, state="ENABLED", protection="HSM", deletion=None):
    rotation = {"rotation_interval_in_days": interval} if interval is not None else None
    return {"id": f"ocid1.key.oc1..{name}", "display_name": name, "lifecycle_state": state,
            "protection_mode": protection, "is_auto_rotation_enabled": auto,
            "auto_key_rotation_details": rotation, "time_of_deletion": deletion,
            "key_shape": {"algorithm": "AES", "length": 32}, "current_key_version": "v1"}


def _version(age_days, auto_rotated=False):
    return {"time_created": NOW - timedelta(days=age_days), "is_auto_rotated": auto_rotated}


def test_an_interval_without_auto_rotation_is_not_rotation():
    """Prowler passes this key forever: interval <= 365 with the flag off."""
    record = kms.key_record(_key(auto=False, interval=60), vault=PRIVATE_VAULT,
                            current_version=_version(900), version_count=1, now=NOW)
    assert record["auto_rotation_within_window"] is False
    assert record["rotated_within_window"] is False
    out = kms.summarize([], [record])
    assert out["keys_not_rotated_within_window"] == 1
    assert out["keys_with_automatic_rotation"] == 0


def test_automatic_and_manual_rotation_are_never_summed():
    auto = kms.key_record(_key("auto", auto=True, interval=90), vault=PRIVATE_VAULT,
                          current_version=_version(30, auto_rotated=True), version_count=4, now=NOW)
    manual = kms.key_record(_key("manual"), vault=PRIVATE_VAULT,
                            current_version=_version(30), version_count=2, now=NOW)
    out = kms.summarize([], [auto, manual])
    assert out["keys_with_automatic_rotation"] == 1
    assert out["keys_rotated_manually_within_window"] == 1
    assert out["automatic_rotation_percentage"] == 50


def test_a_default_vault_cannot_auto_rotate_and_is_counted_apart():
    record = kms.key_record(_key(), vault=DEFAULT_VAULT, current_version=_version(2), version_count=2, now=NOW)
    assert record["auto_rotation_supported"] is False
    out = kms.summarize([kms.vault_record({"vault_type": "DEFAULT", "lifecycle_state": "ACTIVE"})], [record])
    assert out["keys_in_vaults_without_auto_rotation_support"] == 1
    assert out["vaults_supporting_auto_rotation"] == 0


def test_a_failed_version_read_is_not_never_rotated():
    record = kms.key_record(_key(), vault=PRIVATE_VAULT, current_version=None, version_count=None, now=NOW)
    assert record["rotated_within_window"] is None and record["version_read"] is False
    out = kms.summarize([], [record])
    assert out["keys_with_unreadable_version"] == 1
    assert out["keys_not_rotated_within_window"] == 0


def test_pending_deletion_keys_are_collected_not_dropped():
    """Prowler keeps only ENABLED keys, so this one is invisible to it."""
    record = kms.key_record(_key("doomed", deletion=NOW + timedelta(days=20)), vault=PRIVATE_VAULT,
                            current_version=_version(10), version_count=1, now=NOW)
    assert record["pending_deletion"] is True
    assert kms.summarize([], [record])["keys_pending_deletion"] == 1


def test_protection_mode_is_reported_and_percentaged():
    hsm = kms.key_record(_key("h"), vault=PRIVATE_VAULT, current_version=_version(1), version_count=1, now=NOW)
    soft = kms.key_record(_key("s", protection="SOFTWARE"), vault=PRIVATE_VAULT,
                          current_version=_version(1), version_count=1, now=NOW)
    out = kms.summarize([], [hsm, soft])
    assert out["hsm_protected_keys"] == 1 and out["software_protected_keys"] == 1
    assert out["hsm_protection_percentage"] == 50


def test_an_unreadable_vault_service_is_not_no_vaults():
    assert kms.summarize([], [], api_readable=False)["vault_service_readable"] is False


def test_a_key_outside_its_vaults_compartment_is_still_collected(monkeypatch):
    """OCI lets a key live in a different compartment from its vault, and
    list_keys answers for one compartment at a time. Asked about the vault's
    own compartment only, such a key — rotated or not — was absent from the
    evidence and keys_not_rotated_within_window read clean."""
    import logging
    from types import SimpleNamespace

    pytest = __import__("pytest")
    pytest.importorskip("oci")

    class M(dict):
        __getattr__ = dict.__getitem__

    def resp(data):
        return SimpleNamespace(data=data)

    vault = M(id="v", display_name="vault", lifecycle_state="ACTIVE", vault_type="VIRTUAL_PRIVATE",
              management_endpoint="https://v-management.kms.example", compartment_id="A", time_of_deletion=None)
    stale = M(id="k-stale", display_name="stale", lifecycle_state="ENABLED", protection_mode="HSM",
              is_auto_rotation_enabled=False, auto_key_rotation_details=None, time_of_deletion=None,
              key_shape={"algorithm": "AES", "length": 32}, current_key_version="kv", compartment_id="B")
    listed = []

    class VaultClient:
        def list_vaults(self, c):
            return resp([vault] if c == "A" else [])

        def get_vault(self, v):
            return resp(vault)

    class Management:
        def list_keys(self, c):
            listed.append(c)
            # The key sits in compartment B, against the vault in A. Listed
            # twice on purpose: once per compartment that can see it.
            return resp([stale] if c in ("B", "C") else [])

        def get_key(self, k):
            return resp(stale)

        def get_key_version(self, key_id, key_version_id):
            return resp(M(time_created=NOW - timedelta(days=800), is_auto_rotated=False, origin="INTERNAL"))

        def list_key_versions(self, k):
            return resp([M(id="kv")])

    def fake_client(client_class, auth, **kwargs):
        return {"KmsVaultClient": VaultClient(), "KmsManagementClient": Management()}.get(
            client_class.__name__, SimpleNamespace())

    monkeypatch.setattr(kms, "make_client", fake_client)
    monkeypatch.setattr(kms, "walk_compartments",
                        lambda *a, **k: [{"id": "A", "name": "a"}, {"id": "B", "name": "b"}, {"id": "C", "name": "c"}])
    monkeypatch.setattr(kms, "list_all", lambda fn, *a, **k: fn(*a, **k).data)
    monkeypatch.setattr(kms, "to_plain", dict)

    collector = kms.Collector(logging.getLogger("test"))
    vaults, keys, scanned = kms.collect({"tenancy": "T"}, {"compartment_id": "T"}, collector, include_sub=True)
    assert collector.ok and scanned == 3
    assert sorted(listed) == ["A", "B", "C"], "every compartment in scope is asked about every vault"
    assert [k["id"] for k in keys] == ["k-stale"], "listed from two compartments, recorded once"
    assert kms.summarize(vaults, keys)["keys_not_rotated_within_window"] == 1
