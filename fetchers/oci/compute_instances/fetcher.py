#!/usr/bin/env python3
"""
OCI Compute — instance hardening, boot integrity, and what is reachable from outside

Every compute instance in scope with its metadata-service configuration, boot
integrity settings (secure boot, measured boot, TPM, memory encryption),
in-transit encryption, Oracle Cloud Agent and plugin state, and every VNIC with
its public IP and attached network security groups.

Evidence for KSI-CNA-MAT (minimal attack surface, lateral movement minimized),
KSI-SVC-VRI (cryptographic methods validate the integrity of resources — secure
and measured boot, and the TPM that attests them) and KSI-SVC-SIN for in-transit
and memory encryption.

Ported from Prowler's OCI compute service (Apache-2.0,
prowler/providers/oraclecloud/services/compute, commit 5fe1a67) — the legacy
metadata endpoint, secure boot and in-transit encryption checks — with four
departures, the first two verified against a live instance:

  * SECURE BOOT IS NOT AVAILABLE ON EVERY SHAPE.
    `platform_config` is None on a shape that does not support shielded
    instances — confirmed on a live VM.Standard.E2.1.Micro — and Prowler's
    `hasattr(None, ...)` guard then defaults `is_secure_boot_enabled` to False,
    reporting a FAIL on hardware that cannot offer the control. Here
    `shielded_instance_supported` carries that distinction and the summary
    counts those instances separately.

  * MEASURED BOOT, TPM AND MEMORY ENCRYPTION ARE ON THE SAME OBJECT AND UNREAD.
    Secure boot alone says the firmware refused unsigned code; the TPM and
    measured boot are what let that be *attested*, which is the "cryptographic
    methods to validate integrity" half of SVC-VRI. Memory encryption (AMD SEV)
    protects data in use.

  * PUBLIC ADDRESSES ARE THE ATTACK SURFACE AND ARE NOT COLLECTED AT ALL. An
    instance's exposure lives on its VNICs (`public_ip`, `nsg_ids`,
    `skip_source_dest_check`), which Prowler never reads.

  * THE ORACLE CLOUD AGENT DECIDES WHETHER ANYTHING IS WATCHING. `agent_config`
    carries `is_monitoring_disabled`, `is_management_disabled`,
    `are_all_plugins_disabled` and the per-plugin desired state — including the
    Vulnerability Scanning and OS Management plugins that other indicators rely
    on. An instance with the agent off reports clean to every agent-based check.

INSTANCE METADATA VALUES ARE DELIBERATELY NOT COLLECTED. `metadata` and
`extended_metadata` hold cloud-init `user_data` and `ssh_authorized_keys`;
user_data routinely carries bootstrap secrets. Only the key names are recorded,
so the evidence can say a key is present without copying what is in it.
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

logger = logging.getLogger("oci_compute_instances")

GONE_STATES = frozenset({"TERMINATED", "TERMINATING"})
RUNNING_STATES = frozenset({"RUNNING", "STARTING", "PROVISIONING"})

# Agent plugins other indicators depend on, by Oracle's own plugin names.
SECURITY_PLUGINS = ("Vulnerability Scanning", "OS Management Service Agent",
                    "Management Agent", "Bastion")
PLUGIN_ENABLED = "ENABLED"


# --- pure transforms ---

def vnic_record(vnic: dict) -> dict:
    """One VNIC — where the instance is reachable and what guards it."""
    public_ip = vnic.get("public_ip")
    return {
        "id": vnic.get("id"),
        "display_name": vnic.get("display_name"),
        "is_primary": vnic.get("is_primary"),
        "subnet_id": vnic.get("subnet_id"),
        "private_ip": vnic.get("private_ip"),
        "public_ip": public_ip,
        "has_public_ip": bool(public_ip),
        "nsg_ids": sorted(vnic.get("nsg_ids") or []),
        "is_protected_by_nsg": bool(vnic.get("nsg_ids")),
        # Off means the VNIC may forward traffic it did not originate, which is
        # how a routing appliance works and how lateral movement hides.
        "skip_source_dest_check": vnic.get("skip_source_dest_check") is True,
        "ipv6_addresses": sorted(vnic.get("ipv6_addresses") or []),
        "lifecycle_state": vnic.get("lifecycle_state"),
    }


def instance_record(instance: dict, *, vnics=None) -> dict:
    """One instance. `vnics` is None when the VNIC listing failed."""
    options = instance.get("instance_options") or {}
    launch = instance.get("launch_options") or {}
    platform = instance.get("platform_config")
    agent = instance.get("agent_config") or {}
    plugins = agent.get("plugins_config")
    vnic_records = list(vnics) if vnics is not None else None

    plugin_states = {p.get("name"): p.get("desired_state") for p in plugins or []}
    agent_off = agent.get("are_all_plugins_disabled") is True

    return {
        "id": instance.get("id"),
        "display_name": instance.get("display_name"),
        "compartment_id": instance.get("compartment_id"),
        "region": instance.get("region"),
        "availability_domain": instance.get("availability_domain"),
        "fault_domain": instance.get("fault_domain"),
        "shape": instance.get("shape"),
        "image_id": instance.get("image_id"),
        "lifecycle_state": instance.get("lifecycle_state"),
        "is_running": instance.get("lifecycle_state") in RUNNING_STATES,
        "time_created": iso(instance.get("time_created")),
        "dedicated_vm_host_id": instance.get("dedicated_vm_host_id"),
        # Metadata service. None means the field was absent, not "enabled".
        "are_legacy_imds_endpoints_disabled": options.get("are_legacy_imds_endpoints_disabled"),
        "legacy_metadata_endpoint_enabled": options.get("are_legacy_imds_endpoints_disabled") is False,
        # Only the KEY NAMES — see the module docstring.
        "metadata_keys": sorted((instance.get("metadata") or {}).keys()),
        "extended_metadata_keys": sorted((instance.get("extended_metadata") or {}).keys()),
        # Encryption in transit, which lives on launch_options.
        "is_pv_encryption_in_transit_enabled": launch.get("is_pv_encryption_in_transit_enabled"),
        "boot_volume_type": launch.get("boot_volume_type"),
        "firmware": launch.get("firmware"),
        "network_type": launch.get("network_type"),
        # Boot integrity. platform_config is absent on shapes that cannot do it,
        # which is a hardware fact, not a misconfiguration.
        "shielded_instance_supported": platform is not None,
        "is_secure_boot_enabled": (platform or {}).get("is_secure_boot_enabled"),
        "is_measured_boot_enabled": (platform or {}).get("is_measured_boot_enabled"),
        "is_trusted_platform_module_enabled": (platform or {}).get("is_trusted_platform_module_enabled"),
        "is_memory_encryption_enabled": (platform or {}).get("is_memory_encryption_enabled"),
        "platform_config_type": (platform or {}).get("type"),
        # Oracle Cloud Agent — whether anything on the host reports at all.
        "is_monitoring_disabled": agent.get("is_monitoring_disabled") is True,
        "is_management_disabled": agent.get("is_management_disabled") is True,
        "are_all_plugins_disabled": agent_off,
        "plugin_states": dict(sorted(plugin_states.items())),
        "enabled_security_plugins": sorted(
            name for name in SECURITY_PLUGINS
            if not agent_off and plugin_states.get(name) == PLUGIN_ENABLED
        ),
        # Exposure.
        "vnics": vnic_records,
        "vnics_read": vnic_records is not None,
        "has_public_ip": any(v["has_public_ip"] for v in vnic_records) if vnic_records is not None else None,
        "public_ips": sorted(v["public_ip"] for v in vnic_records or [] if v["public_ip"]),
        "nsg_protected": (
            all(v["is_protected_by_nsg"] for v in vnic_records) if vnic_records else None
        ),
        "security_attributes": sorted((instance.get("security_attributes") or {}).keys()),
    }


def summarize(instances: list[dict], *, api_readable: bool = True) -> dict:
    live = [i for i in instances if i["lifecycle_state"] not in GONE_STATES]
    shielded = [i for i in live if i["shielded_instance_supported"]]
    with_vnics = [i for i in live if i["vnics_read"]]
    public = [i for i in with_vnics if i["has_public_ip"]]
    imds_known = [i for i in live if i["are_legacy_imds_endpoints_disabled"] is not None]

    def count(flag, source=None):
        return sum(1 for i in (source if source is not None else live) if i[flag])

    return {
        # False when the instance listing failed — not "no instances".
        "compute_readable": api_readable,
        "total_instances": len(live),
        "running_instances": count("is_running"),
        # Metadata service.
        "instances_with_legacy_metadata_endpoint": count("legacy_metadata_endpoint_enabled"),
        "instances_with_unknown_metadata_endpoint_setting": len(live) - len(imds_known),
        "legacy_metadata_disabled_percentage": coverage_percentage(
            sum(1 for i in imds_known if i["are_legacy_imds_endpoints_disabled"]), len(imds_known)
        ),
        # Boot integrity, over shapes that can actually do it.
        "shielded_instance_capable_instances": len(shielded),
        "instances_on_shapes_without_shielded_support": len(live) - len(shielded),
        "secure_boot_enabled": count("is_secure_boot_enabled", shielded),
        "measured_boot_enabled": count("is_measured_boot_enabled", shielded),
        "tpm_enabled": count("is_trusted_platform_module_enabled", shielded),
        "memory_encryption_enabled": count("is_memory_encryption_enabled", shielded),
        "secure_boot_percentage_of_capable": coverage_percentage(
            count("is_secure_boot_enabled", shielded), len(shielded)
        ),
        # Encryption in transit.
        "in_transit_encryption_enabled": sum(
            1 for i in live if i["is_pv_encryption_in_transit_enabled"] is True
        ),
        "in_transit_encryption_disabled": sum(
            1 for i in live if i["is_pv_encryption_in_transit_enabled"] is False
        ),
        "in_transit_encryption_unknown": sum(
            1 for i in live if i["is_pv_encryption_in_transit_enabled"] is None
        ),
        # Agent — an instance with it off answers no agent-based check.
        "instances_with_all_plugins_disabled": count("are_all_plugins_disabled"),
        "instances_with_monitoring_disabled": count("is_monitoring_disabled"),
        "instances_with_management_disabled": count("is_management_disabled"),
        "instances_running_vulnerability_scanning": sum(
            1 for i in live if "Vulnerability Scanning" in i["enabled_security_plugins"]
        ),
        # Attack surface.
        "instances_with_unreadable_vnics": len(live) - len(with_vnics),
        "instances_with_public_ip": len(public),
        "public_instance_percentage": coverage_percentage(len(public), len(with_vnics)),
        "public_instances_without_nsg": sum(1 for i in public if i["nsg_protected"] is False),
        "instances_with_source_dest_check_disabled": sum(
            1 for i in with_vnics for v in i["vnics"] if v["skip_source_dest_check"]
        ),
        "instance_names_with_public_ip": sorted(
            f"{i['display_name']} ({short_ocid(i['id'])})" for i in public if i["display_name"]
        ),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool):
    import oci  # lazy

    identity = make_client(oci.identity.IdentityClient, auth)
    compute = make_client(oci.core.ComputeClient, auth)
    network = make_client(oci.core.VirtualNetworkClient, auth)

    compartments = walk_compartments(
        identity, scope["compartment_id"], collector,
        include_subcompartments=include_sub, tenancy=auth.get("tenancy"),
    )

    instances: list[dict] = []
    unreadable = 0

    for comp in compartments:
        cid, cname = comp["id"], comp["name"]

        found = collector.guard(
            f"compute.list_instances ({cname})",
            lambda c=cid: list_all(compute.list_instances, c),
        )
        if found is None:
            unreadable += 1
            continue

        # One listing per compartment rather than one per instance; the
        # attachment carries no addresses, so each VNIC still needs its own get.
        attachments_by_instance: dict[str, list] = {}
        for attachment in collector.guard(
            f"compute.list_vnic_attachments ({cname})",
            lambda c=cid: list_all(compute.list_vnic_attachments, c),
            default=[],
        ) or []:
            plain = to_plain(attachment)
            if plain.get("lifecycle_state") == "ATTACHED" and plain.get("vnic_id"):
                attachments_by_instance.setdefault(plain.get("instance_id"), []).append(plain["vnic_id"])

        for instance in found:
            plain = to_plain(instance)
            if plain.get("lifecycle_state") in GONE_STATES:
                continue

            collected: list = []
            vnics: list | None = collected
            for vnic_id in attachments_by_instance.get(plain["id"], []):
                vnic = collector.guard(
                    f"virtual_network.get_vnic ({short_ocid(vnic_id)})",
                    lambda v=vnic_id: network.get_vnic(v).data,
                )
                if vnic is None:
                    # One unreadable VNIC makes the instance's exposure unknown;
                    # reporting the rest would read as "no public IP".
                    vnics = None
                    break
                collected.append(vnic_record(to_plain(vnic)))

            instances.append(instance_record(plain, vnics=vnics))

    if compartments and unreadable == len(compartments):
        return None, len(compartments)

    instances.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    return instances, len(compartments)


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
    instances = None
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            try:
                instances, scanned = collect(auth, scope, collector, include_sub=include_sub)
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("compute.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={"instances": instances or []},
        summary=summarize(instances or [], api_readable=instances is not None),
        compartments_scanned=scanned,
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_compute_instances_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)
    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
