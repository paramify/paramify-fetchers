"""Exposure and key judgements in `oci_data_service_exposure`."""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "data_service_exposure" / "fetcher.py"
KEY = "ocid1.key.oc1..cmk"


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_data_service_exposure", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ds = _load()


def _adb(name, **kwargs):
    base = {"id": f"ocid1.autonomousdatabase.oc1..{name}", "display_name": name,
            "lifecycle_state": "AVAILABLE", "is_mtls_connection_required": True,
            "kms_key_id": "ORACLE_MANAGED_KEY"}
    return ds.autonomous_database_record({**base, **kwargs})


def _export(source, access="READ_WRITE", squash="NONE"):
    return ds.export_record({"id": "e", "path": "/data", "lifecycle_state": "ACTIVE",
                             "export_options": [{"source": source, "access": access,
                                                 "identity_squash": squash}]})


def test_oracle_managed_key_literal_is_not_a_customer_key():
    """A live ADB returns the string "ORACLE_MANAGED_KEY"; `is not None` reads it as a CMK."""
    assert ds.customer_managed_key("ORACLE_MANAGED_KEY") is False
    assert ds.customer_managed_key(None) is False
    assert ds.customer_managed_key("") is False
    assert ds.customer_managed_key(KEY) is True

    oracle_key, customer_key = _adb("a"), _adb("b", kms_key_id=KEY)
    out = ds.summarize([oracle_key, customer_key], [], [], [])
    assert out["resources_with_customer_managed_key"] == 1
    assert out["resources_with_oracle_managed_key"] == 1
    assert out["customer_managed_key_percentage"] == 50


def test_no_allowlist_and_no_subnet_is_reachable_from_the_internet():
    """The staged database: whitelisted_ips None, subnet None."""
    exposed = _adb("open")
    assert exposed["publicly_reachable_without_restriction"] is True
    assert exposed["has_access_control_list"] is False

    restricted = _adb("acl", whitelisted_ips=["203.0.113.0/24"])
    private = _adb("vcn", subnet_id="ocid1.subnet.oc1..s")
    assert restricted["publicly_reachable_without_restriction"] is False
    assert private["publicly_reachable_without_restriction"] is False

    out = ds.summarize([exposed, restricted, private], [], [], [])
    assert out["autonomous_databases_publicly_reachable"] == 1
    assert out["autonomous_databases_in_vcn"] == 1
    assert [n.split(" (")[0] for n in out["autonomous_database_names_publicly_reachable"]] == ["open"]


def test_an_allowlist_containing_the_internet_is_not_a_restriction():
    record = _adb("wide", whitelisted_ips=["0.0.0.0/0"])
    assert record["access_control_allows_internet"] is True
    assert record["publicly_reachable_without_restriction"] is True


def test_mtls_disabled_is_reported():
    assert _adb("a", is_mtls_connection_required=False)["mtls_disabled"] is True
    assert _adb("b")["mtls_disabled"] is False
    out = ds.summarize([_adb("a", is_mtls_connection_required=False)], [], [], [])
    assert out["autonomous_databases_with_mtls_disabled"] == 1


def test_nfs_export_options_decide_file_storage_exposure():
    """Prowler checks the file system's key and never looks at exports."""
    worst = _export("0.0.0.0/0")
    read_only = _export("0.0.0.0/0", access="READ_ONLY")
    squashed = _export("0.0.0.0/0", squash="ALL")
    internal = _export("10.0.0.0/16")
    assert worst["internet_writable_unsquashed"] is True
    assert read_only["internet_writable"] is False and read_only["exports_to_internet"] is True
    assert squashed["internet_writable_unsquashed"] is False
    assert internal["exports_to_internet"] is False

    file_system = ds.file_system_record({"id": "f", "display_name": "share", "lifecycle_state": "ACTIVE",
                                         "kms_key_id": None}, exports=[worst, internal], mount_targets=[])
    out = ds.summarize([], [], [file_system], [])
    assert out["file_systems_exporting_to_internet"] == 1
    assert out["internet_writable_unsquashed_exports"] == 1


def test_unreadable_exports_are_not_no_exports():
    file_system = ds.file_system_record({"id": "f", "display_name": "share", "lifecycle_state": "ACTIVE"},
                                        exports=None, mount_targets=[])
    assert file_system["exports_read"] is False and file_system["export_count"] is None
    out = ds.summarize([], [], [file_system], [])
    assert out["file_systems_with_unreadable_exports"] == 1
    assert out["file_systems_exporting_to_internet"] == 0


def test_integration_instance_without_endpoint_details_is_unrestricted():
    bare = ds.integration_instance_record({"id": "i", "display_name": "i", "lifecycle_state": "ACTIVE"})
    public_open = ds.integration_instance_record({
        "id": "j", "display_name": "j", "lifecycle_state": "ACTIVE",
        "network_endpoint_details": {"network_endpoint_type": "PUBLIC"}})
    allowlisted = ds.integration_instance_record({
        "id": "k", "display_name": "k", "lifecycle_state": "ACTIVE",
        "network_endpoint_details": {"network_endpoint_type": "PUBLIC",
                                     "allowlisted_http_ips": ["203.0.113.5"]}})
    assert bare["publicly_reachable_without_restriction"] is True
    assert public_open["publicly_reachable_without_restriction"] is True
    assert allowlisted["publicly_reachable_without_restriction"] is False
    out = ds.summarize([], [], [], [bare, public_open, allowlisted])
    assert out["integration_instances_publicly_reachable"] == 2


def test_db_systems_are_collected_and_terminated_resources_are_not():
    system = ds.db_system_record({"id": "d", "display_name": "d", "lifecycle_state": "AVAILABLE",
                                  "kms_key_id": KEY})
    gone = ds.db_system_record({"id": "g", "display_name": "g", "lifecycle_state": "TERMINATED"})
    out = ds.summarize([], [system, gone], [], [])
    assert out["total_db_systems"] == 1
    assert out["db_systems_without_nsg"] == 1
    assert out["resources_with_customer_managed_key"] == 1


def test_publicly_reachable_resources_counts_every_service():
    out = ds.summarize(
        [_adb("db")], [],
        [ds.file_system_record({"id": "f", "display_name": "f", "lifecycle_state": "ACTIVE"},
                               exports=[_export("0.0.0.0/0")], mount_targets=[])],
        [ds.integration_instance_record({"id": "i", "display_name": "i", "lifecycle_state": "ACTIVE"})])
    assert out["publicly_reachable_resources"] == 3
    assert ds.summarize([], [], [], [], api_readable=False)["data_services_readable"] is False


def _mount_target(name, *, export_set, nsgs=()):
    return ds.mount_target_record({"id": f"ocid1.mounttarget.oc1..{name}", "display_name": name,
                                   "export_set_id": export_set, "nsg_ids": list(nsgs), "lifecycle_state": "ACTIVE"})


def test_a_mount_target_shared_by_two_file_systems_is_counted_once():
    unguarded = _mount_target("mt", export_set="es1")

    def fs(name):
        return ds.file_system_record({"id": name, "display_name": name, "lifecycle_state": "ACTIVE"},
                                     exports=[], mount_targets=[unguarded])

    assert ds.summarize([], [], [fs("a"), fs("b")], [])["mount_targets_without_nsg"] == 1


def test_mount_targets_are_joined_by_export_set_across_compartments(monkeypatch):
    """Every mount target in a compartment was attached to every file system in it,
    and a target in another compartment was never seen at all."""
    pytest.importorskip("oci")

    class M(dict):
        __getattr__ = dict.__getitem__

    def resp(data):
        return SimpleNamespace(data=data)

    comp_a, comp_b = {"id": "A", "name": "a"}, {"id": "B", "name": "b"}
    mt_a = M(id="mt-a", display_name="mt-a", export_set_id="es-a", nsg_ids=[], lifecycle_state="ACTIVE")
    mt_b = M(id="mt-b", display_name="mt-b", export_set_id="es-b", nsg_ids=["nsg"], lifecycle_state="ACTIVE")
    fs_a = M(id="fs-a", display_name="fs-a", lifecycle_state="ACTIVE", kms_key_id=None)
    fs_b = M(id="fs-b", display_name="fs-b", lifecycle_state="ACTIVE", kms_key_id=None)

    class FileStorage:
        def list_mount_targets(self, c, d):
            return resp({"A": [mt_a], "B": [mt_b]}[c])

        def list_file_systems(self, c, d):
            # Both file systems live in A; fs-b's export set is served from B.
            return resp([fs_a, fs_b] if c == "A" else [])

        def list_exports(self, file_system_id):
            return resp([M(id=f"exp-{file_system_id}", file_system_id=file_system_id,
                           export_set_id="es-a" if file_system_id == "fs-a" else "es-b",
                           path="/data", lifecycle_state="ACTIVE")])

        def get_export(self, e):
            return resp(M(id=e, file_system_id=e[4:], export_set_id="es-a" if e.endswith("fs-a") else "es-b",
                          path="/data", lifecycle_state="ACTIVE",
                          export_options=[{"source": "10.0.0.0/8", "access": "READ_ONLY", "identity_squash": "ROOT"}]))

    class Empty:
        def __getattr__(self, name):
            return lambda *a, **k: resp([])

    class Identity:
        def list_availability_domains(self, compartment_id):
            return resp([M(name="AD-1")])

    def fake_client(client_class, auth, **kwargs):
        return {"FileStorageClient": FileStorage(), "IdentityClient": Identity()}.get(client_class.__name__, Empty())

    monkeypatch.setattr(ds, "make_client", fake_client)
    monkeypatch.setattr(ds, "walk_compartments", lambda *a, **k: [comp_a, comp_b])
    monkeypatch.setattr(ds, "list_all", lambda fn, *a, **k: fn(*a, **k).data)
    monkeypatch.setattr(ds, "to_plain", dict)

    collector = ds.Collector(logging.getLogger("test"))
    _, _, file_systems, _, scanned = ds.collect({"tenancy": "T"}, {"compartment_id": "T"}, collector,
                                                include_sub=True)
    assert collector.ok and scanned == 2
    by_name = {f["display_name"]: f for f in file_systems}
    assert [t["id"] for t in by_name["fs-a"]["mount_targets"]] == ["mt-a"]
    assert [t["id"] for t in by_name["fs-b"]["mount_targets"]] == ["mt-b"], "joined across compartments"
    assert by_name["fs-a"]["mount_targets_without_nsg"] == 1
    assert by_name["fs-b"]["mount_targets_without_nsg"] == 0
