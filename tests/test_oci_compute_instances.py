"""Hardening judgements in `oci_compute_instances`, including Prowler's unfair secure-boot FAIL."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "compute_instances" / "fetcher.py"


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_compute_instances", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cp = _load()

SHIELDED = {"type": "AMD_MILAN_BM", "is_secure_boot_enabled": True, "is_measured_boot_enabled": True,
            "is_trusted_platform_module_enabled": True, "is_memory_encryption_enabled": True}


def _instance(name, *, platform=None, legacy=False, in_transit=False, agent=None, shape="VM.Standard.E2.1.Micro"):
    return {"id": f"ocid1.instance.oc1..{name}", "display_name": name, "shape": shape,
            "lifecycle_state": "RUNNING", "platform_config": platform,
            "instance_options": {"are_legacy_imds_endpoints_disabled": not legacy},
            "launch_options": {"is_pv_encryption_in_transit_enabled": in_transit},
            "agent_config": agent if agent is not None else {"is_monitoring_disabled": False}}


def _vnic(public=None, *, nsgs=(), skip=False):
    return cp.vnic_record({"id": "v", "display_name": "v", "public_ip": public, "private_ip": "10.0.0.5",
                           "nsg_ids": list(nsgs), "skip_source_dest_check": skip,
                           "lifecycle_state": "AVAILABLE", "is_primary": True})


def test_a_shape_without_shielded_support_is_not_a_secure_boot_failure():
    """Prowler defaults is_secure_boot_enabled to False when platform_config is None,
    so every non-shielded shape FAILs a control the hardware cannot offer."""
    micro = cp.instance_record(_instance("micro"), vnics=[])
    assert micro["shielded_instance_supported"] is False
    assert micro["is_secure_boot_enabled"] is None

    out = cp.summarize([micro])
    assert out["instances_on_shapes_without_shielded_support"] == 1
    assert out["shielded_instance_capable_instances"] == 0
    assert out["secure_boot_enabled"] == 0
    assert out["secure_boot_percentage_of_capable"] == 0


def test_boot_integrity_is_percentaged_over_capable_shapes_only():
    capable_on = cp.instance_record(_instance("bm", platform=SHIELDED, shape="BM.Standard.E4.128"), vnics=[])
    capable_off = cp.instance_record(
        _instance("bm2", platform={**SHIELDED, "is_secure_boot_enabled": False}, shape="BM.Standard.E4.128"),
        vnics=[])
    micro = cp.instance_record(_instance("micro"), vnics=[])
    out = cp.summarize([capable_on, capable_off, micro])
    assert out["shielded_instance_capable_instances"] == 2
    assert out["secure_boot_enabled"] == 1
    assert out["secure_boot_percentage_of_capable"] == 50
    assert out["measured_boot_enabled"] == 2 and out["tpm_enabled"] == 2
    assert out["memory_encryption_enabled"] == 2


def test_legacy_metadata_and_in_transit_come_from_the_right_objects():
    instance = cp.instance_record(_instance("i", legacy=True, in_transit=False), vnics=[])
    assert instance["legacy_metadata_endpoint_enabled"] is True
    assert instance["is_pv_encryption_in_transit_enabled"] is False
    out = cp.summarize([instance])
    assert out["instances_with_legacy_metadata_endpoint"] == 1
    assert out["in_transit_encryption_disabled"] == 1
    assert out["legacy_metadata_disabled_percentage"] == 0


def test_an_absent_metadata_setting_is_unknown_not_enabled():
    raw = _instance("i")
    raw["instance_options"] = {}
    instance = cp.instance_record(raw, vnics=[])
    assert instance["are_legacy_imds_endpoints_disabled"] is None
    assert instance["legacy_metadata_endpoint_enabled"] is False
    out = cp.summarize([instance])
    assert out["instances_with_unknown_metadata_endpoint_setting"] == 1
    assert out["instances_with_legacy_metadata_endpoint"] == 0


def test_public_ip_exposure_and_nsg_protection_come_from_vnics():
    """Prowler never reads VNICs, so an instance's public address is invisible to it."""
    exposed = cp.instance_record(_instance("web"), vnics=[_vnic("203.0.113.10")])
    guarded = cp.instance_record(_instance("api"), vnics=[_vnic("203.0.113.11", nsgs=["ocid1.nsg.oc1..n"])])
    private = cp.instance_record(_instance("db"), vnics=[_vnic()])
    out = cp.summarize([exposed, guarded, private])
    assert out["instances_with_public_ip"] == 2
    assert out["public_instances_without_nsg"] == 1
    assert out["public_instance_percentage"] == 66
    assert [n.split(" (")[0] for n in out["instance_names_with_public_ip"]] == ["api", "web"]


def test_unreadable_vnics_are_not_no_public_ip():
    instance = cp.instance_record(_instance("i"), vnics=None)
    assert instance["vnics_read"] is False and instance["has_public_ip"] is None
    out = cp.summarize([instance])
    assert out["instances_with_unreadable_vnics"] == 1
    assert out["instances_with_public_ip"] == 0
    assert out["public_instance_percentage"] == 0


def test_agent_and_plugin_state_is_reported():
    agent_off = cp.instance_record(_instance("off", agent={
        "is_monitoring_disabled": True, "is_management_disabled": True, "are_all_plugins_disabled": True,
        "plugins_config": [{"name": "Vulnerability Scanning", "desired_state": "ENABLED"}]}), vnics=[])
    scanning = cp.instance_record(_instance("on", agent={
        "is_monitoring_disabled": False, "are_all_plugins_disabled": False,
        "plugins_config": [{"name": "Vulnerability Scanning", "desired_state": "ENABLED"},
                           {"name": "Bastion", "desired_state": "DISABLED"}]}), vnics=[])
    # All plugins disabled beats an individual plugin's desired state.
    assert agent_off["enabled_security_plugins"] == []
    assert scanning["enabled_security_plugins"] == ["Vulnerability Scanning"]
    out = cp.summarize([agent_off, scanning])
    assert out["instances_with_all_plugins_disabled"] == 1
    assert out["instances_with_monitoring_disabled"] == 1
    assert out["instances_running_vulnerability_scanning"] == 1


def test_metadata_values_are_never_copied():
    raw = _instance("i")
    raw["metadata"] = {"ssh_authorized_keys": "ssh-rsa AAAA...", "user_data": "c2VjcmV0"}
    raw["extended_metadata"] = {"config": {"token": "s3cr3t"}}
    record = cp.instance_record(raw, vnics=[])
    assert record["metadata_keys"] == ["ssh_authorized_keys", "user_data"]
    assert "c2VjcmV0" not in str(record) and "s3cr3t" not in str(record)


def test_terminated_instances_and_unreadable_service():
    gone = cp.instance_record({**_instance("gone"), "lifecycle_state": "TERMINATED"}, vnics=[])
    assert cp.summarize([gone])["total_instances"] == 0
    assert cp.summarize([], api_readable=False)["compute_readable"] is False
