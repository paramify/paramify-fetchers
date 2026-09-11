#!/usr/bin/env python3
"""
Azure virtual machine hardening — Trusted Launch, managed disks, SSH keys, extensions

Ported from `_get_virtual_machines()`, `_get_vm_scale_sets()` and
`_get_vmss_instance_ids()` in Prowler's
prowler/providers/azure/services/vm/vm_service.py (Apache-2.0).

ONE DEPARTURE FROM PROWLER, deliberate: Prowler reads a VM's extensions from
`vm.resources` on the list response, which ARM populates only on a single-VM GET — so on
a real subscription that list is empty and the evidence would read "no agents installed"
when agents are. Extensions come from a per-VM virtual_machine_extensions.list() instead.
"""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    credential,
    failure_reason,
    model_attr,
    provider_registration_status,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
    report_failure,
)

logger = logging.getLogger("azure_vm_hardening_status")

# security_profile.security_type (the SecurityTypes enum). Trusted Launch is the
# generation-2 boot-integrity mode; ConfidentialVM implies it plus memory encryption.
SECURITY_TYPE_TRUSTED_LAUNCH = "TrustedLaunch"
SECURITY_TYPE_CONFIDENTIAL_VM = "ConfidentialVM"


# --- projection: the only code that touches an azure-mgmt model ---

def project_image_reference(image) -> dict:
    """Read an `ImageReference` model — marketplace coordinates or an image id.

    Prowler keeps only `image_reference.id`, which is None for every marketplace image
    (publisher/offer/sku/version carry it), so both forms are projected. `exact_version`
    is what "latest" resolved to at deploy time.
    """
    return {
        "id": model_attr(image, "id"),
        "publisher": model_attr(image, "publisher"),
        "offer": model_attr(image, "offer"),
        "sku": model_attr(image, "sku"),
        "version": model_attr(image, "version"),
        "exact_version": model_attr(image, "exact_version"),
        "community_gallery_image_id": model_attr(image, "community_gallery_image_id"),
        "shared_gallery_image_id": model_attr(image, "shared_gallery_image_id"),
    }


def project_security_profile(profile) -> dict:
    """Read a `SecurityProfile` model, including the nested UEFI settings.

    `model_attr` unwraps the `SecurityTypes` enum to its wire string; without that the
    TrustedLaunch comparison below would never match.
    """
    uefi = model_attr(profile, "uefi_settings")
    return {
        "security_type": model_attr(profile, "security_type"),
        "encryption_at_host": model_attr(profile, "encryption_at_host"),
        "uefi_settings": {
            "secure_boot_enabled": model_attr(uefi, "secure_boot_enabled"),
            "v_tpm_enabled": model_attr(uefi, "v_tpm_enabled"),
        },
    }


def project_managed_disk(disk) -> dict:
    """Read the `managed_disk` reference off an OS or data disk (id + storage type)."""
    managed = model_attr(disk, "managed_disk")
    return {
        "id": model_attr(managed, "id"),
        "storage_account_type": model_attr(managed, "storage_account_type"),
    }


def project_storage_profile(profile) -> dict:
    """Read a `StorageProfile` model: OS disk, data disks and the source image.

    A disk whose `managed_disk` is absent but whose `vhd` is set is an UNMANAGED disk (a
    page blob in a storage account), so `vhd_uri` is projected to identify it positively.
    """
    os_disk = model_attr(profile, "os_disk")
    return {
        "os_disk": {
            "name": model_attr(os_disk, "name"),
            "operating_system_type": model_attr(os_disk, "os_type"),
            "disk_size_gb": model_attr(os_disk, "disk_size_gb"),
            "managed_disk": project_managed_disk(os_disk),
            "vhd_uri": model_attr(model_attr(os_disk, "vhd"), "uri"),
        },
        "data_disks": [
            {
                "lun": model_attr(data_disk, "lun"),
                "name": model_attr(data_disk, "name"),
                "disk_size_gb": model_attr(data_disk, "disk_size_gb"),
                "managed_disk": project_managed_disk(data_disk),
                "vhd_uri": model_attr(model_attr(data_disk, "vhd"), "uri"),
            }
            for data_disk in (model_attr(profile, "data_disks") or [])
        ],
        "image_reference": project_image_reference(model_attr(profile, "image_reference")),
    }


def project_virtual_machine(vm) -> dict:
    """Read a `VirtualMachine` model's attributes into a flat snake_case dict.

    Every nested profile is optional on a real response — `security_profile` is absent on
    a generation-1 VM, `os_profile.linux_configuration` on a Windows VM,
    `storage_profile.image_reference` on a VM built from an attached disk — hence the
    None-tolerant read at each hop.
    """
    storage_profile = model_attr(vm, "storage_profile")
    os_profile = model_attr(vm, "os_profile")
    linux_configuration = model_attr(os_profile, "linux_configuration")
    security_profile = model_attr(vm, "security_profile")

    return {
        "id": model_attr(vm, "id"),
        "name": model_attr(vm, "name"),
        "location": model_attr(vm, "location"),
        "vm_size": model_attr(model_attr(vm, "hardware_profile"), "vm_size"),
        "provisioning_state": model_attr(vm, "provisioning_state"),
        # Set when the VM is a scale-set member — the join to a scale set record.
        "virtual_machine_scale_set_id": model_attr(
            model_attr(vm, "virtual_machine_scale_set"), "id"
        ),
        "storage_profile": (
            project_storage_profile(storage_profile) if storage_profile is not None else None
        ),
        "security_profile": (
            project_security_profile(security_profile) if security_profile is not None else None
        ),
        # None (not False) when the VM is not Linux: "no such setting" and "passwords
        # allowed" are different facts.
        "linux_configuration": (
            {
                "disable_password_authentication": model_attr(
                    linux_configuration, "disable_password_authentication"
                ),
                "provision_vm_agent": model_attr(linux_configuration, "provision_vm_agent"),
            }
            if linux_configuration is not None
            else None
        ),
        # Extensions come from the per-VM enrichment call: ARM omits `resources` on the
        # list response (see the module docstring).
        "extensions": [],
    }


def project_vm_extension(extension) -> dict:
    """Read a `VirtualMachineExtension` model — one installed guest agent.

    `type` resolves to the ARM resource type, NOT the extension type: the model declares
    both a top-level `type` and a `properties.type`, and the top-level one wins on
    attribute access (azure-mgmt-compute 38.2.0), so the agent is identified from `name`
    and `publisher`.
    """
    return {
        "id": model_attr(extension, "id"),
        "name": model_attr(extension, "name"),
        "publisher": model_attr(extension, "publisher"),
        "type_handler_version": model_attr(extension, "type_handler_version"),
        "provisioning_state": model_attr(extension, "provisioning_state"),
        "auto_upgrade_minor_version": model_attr(extension, "auto_upgrade_minor_version"),
        "enable_automatic_upgrade": model_attr(extension, "enable_automatic_upgrade"),
    }


def project_scale_set(scale_set) -> dict:
    """Read a `VirtualMachineScaleSet` model, flattening its VM profile.

    The load balancer association is four optional hops deep (network_profile ->
    network_interface_configurations[] -> ip_configurations[] ->
    load_balancer_backend_address_pools[]) and any hop can be None on a real response.
    """
    sku = model_attr(scale_set, "sku")
    vm_profile = model_attr(scale_set, "virtual_machine_profile")
    security_profile = model_attr(vm_profile, "security_profile")
    linux_configuration = model_attr(
        model_attr(vm_profile, "os_profile"), "linux_configuration"
    )
    network_profile = model_attr(vm_profile, "network_profile")

    backend_pools: list = []
    for nic in model_attr(network_profile, "network_interface_configurations") or []:
        for ip_configuration in model_attr(nic, "ip_configurations") or []:
            for pool in (
                model_attr(ip_configuration, "load_balancer_backend_address_pools") or []
            ):
                pool_id = model_attr(pool, "id")
                if pool_id:
                    backend_pools.append(pool_id)

    return {
        "id": model_attr(scale_set, "id"),
        "name": model_attr(scale_set, "name"),
        "location": model_attr(scale_set, "location"),
        "sku_name": model_attr(sku, "name"),
        "sku_capacity": model_attr(sku, "capacity"),
        "orchestration_mode": model_attr(scale_set, "orchestration_mode"),
        "upgrade_policy_mode": model_attr(model_attr(scale_set, "upgrade_policy"), "mode"),
        "security_profile": (
            project_security_profile(security_profile) if security_profile is not None else None
        ),
        "linux_configuration": (
            {
                "disable_password_authentication": model_attr(
                    linux_configuration, "disable_password_authentication"
                ),
            }
            if linux_configuration is not None
            else None
        ),
        "image_reference": project_image_reference(
            model_attr(model_attr(vm_profile, "storage_profile"), "image_reference")
        ),
        "load_balancer_backend_pools": backend_pools,
        "instance_ids": [],
    }


def project_scale_set_instance(instance) -> str | None:
    """Read the `instance_id` off one `VirtualMachineScaleSetVM`."""
    return model_attr(instance, "instance_id")


# --- pure transforms (dicts in, evidence records out) ---

def _security_profile_record(profile: dict | None) -> dict:
    """Normalize a projected security profile, coercing the optional bools.

    Azure omits `secure_boot_enabled` / `v_tpm_enabled` / `encryption_at_host` rather than
    returning false, and Prowler reads each with a `False` default. An absent profile
    normalizes to the same shape with everything off, so a validator never meets a null
    parent.
    """
    profile = profile if isinstance(profile, dict) else {}
    uefi = profile.get("uefi_settings") or {}
    return {
        "security_type": profile.get("security_type"),
        "encryption_at_host": bool(profile.get("encryption_at_host") or False),
        "uefi_settings": {
            "secure_boot_enabled": bool(uefi.get("secure_boot_enabled") or False),
            "v_tpm_enabled": bool(uefi.get("v_tpm_enabled") or False),
        },
    }


def trusted_launch_enabled(security_profile: dict | None) -> bool:
    """Prowler's vm_trusted_launch_enabled condition, verbatim — all four clauses.

    ConfidentialVM is NOT accepted here even though it implies the same boot integrity,
    because Prowler's check does not and the summary is meant to line up with a Prowler
    run; `security_type` is in the record for a reviewer who reads it differently.
    """
    profile = _security_profile_record(security_profile)
    return (
        profile["security_type"] == SECURITY_TYPE_TRUSTED_LAUNCH
        and profile["uefi_settings"]["secure_boot_enabled"]
        and profile["uefi_settings"]["v_tpm_enabled"]
    )


def _disk_record(disk: dict | None) -> dict:
    """The fields an OS disk and a data disk share: identity, size, managed vs VHD."""
    disk = disk if isinstance(disk, dict) else {}
    managed = disk.get("managed_disk") or {}
    return {
        "name": disk.get("name"),
        "disk_size_gb": disk.get("disk_size_gb"),
        "managed_disk": {
            "id": managed.get("id"),
            "storage_account_type": managed.get("storage_account_type"),
        },
        "vhd_uri": disk.get("vhd_uri"),
        "managed": bool(managed.get("id")),
    }


def storage_profile_record(profile: dict | None) -> dict | None:
    """Normalize a projected storage profile; None when the API returned none."""
    if not isinstance(profile, dict):
        return None
    os_disk_projection = profile.get("os_disk") or {}
    return {
        "os_disk": {
            **_disk_record(os_disk_projection),
            "operating_system_type": os_disk_projection.get("operating_system_type"),
        },
        "data_disks": [
            {**_disk_record(d), "lun": d.get("lun")}
            for d in (profile.get("data_disks") or [])
        ],
        "image_reference": profile.get("image_reference") or {},
    }


def uses_managed_disks_only(storage_profile: dict | None) -> bool:
    """Prowler's vm_ensure_using_managed_disks condition, verbatim.

    The OS disk and every data disk must have a managed_disk. A VM with no storage profile
    reads as False (Prowler's `using_managed_disks` starts from the OS disk lookup).
    """
    if not isinstance(storage_profile, dict):
        return False
    os_disk = storage_profile.get("os_disk") or {}
    if not (os_disk.get("managed_disk") or {}).get("id"):
        return False
    return all(
        (d.get("managed_disk") or {}).get("id")
        for d in (storage_profile.get("data_disks") or [])
    )


def extension_record(extension: dict) -> dict:
    """Normalize one projected VM extension (`name` falls back to the ARM id's last segment)."""
    resource_id = extension.get("id")
    return {
        "id": resource_id,
        "name": extension.get("name") or basename(resource_id),
        "publisher": extension.get("publisher"),
        "type_handler_version": extension.get("type_handler_version"),
        "provisioning_state": extension.get("provisioning_state"),
        "auto_upgrade_minor_version": bool(
            extension.get("auto_upgrade_minor_version") or False
        ),
        "enable_automatic_upgrade": bool(extension.get("enable_automatic_upgrade") or False),
    }


def virtual_machine_record(vm: dict) -> dict:
    """Normalize one projected VM into an evidence record with its derived readings."""
    resource_id = vm.get("id")
    storage_profile = storage_profile_record(vm.get("storage_profile"))
    linux_configuration = vm.get("linux_configuration")
    password_authentication_disabled = None
    if isinstance(linux_configuration, dict):
        password_authentication_disabled = bool(
            linux_configuration.get("disable_password_authentication") or False
        )

    return {
        "id": resource_id,
        "name": vm.get("name"),
        "location": vm.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "vm_size": vm.get("vm_size"),
        "provisioning_state": vm.get("provisioning_state"),
        "virtual_machine_scale_set_id": vm.get("virtual_machine_scale_set_id"),
        # --- boot integrity ---
        "security_profile": _security_profile_record(vm.get("security_profile")),
        "trusted_launch_enabled": trusted_launch_enabled(vm.get("security_profile")),
        # --- disks ---
        "storage_profile": storage_profile,
        "managed_disks_only": uses_managed_disks_only(storage_profile),
        # --- credentials (null on a non-Linux VM: the setting does not exist) ---
        "linux_configuration": (
            {
                "disable_password_authentication": password_authentication_disabled,
                "provision_vm_agent": bool(
                    (linux_configuration or {}).get("provision_vm_agent") or False
                ),
            }
            if isinstance(linux_configuration, dict)
            else None
        ),
        "password_authentication_disabled": password_authentication_disabled,
        # --- guest agents (filled in by the per-VM enrichment call) ---
        "extensions": [extension_record(e) for e in (vm.get("extensions") or [])],
    }


def scale_set_record(scale_set: dict) -> dict:
    """Normalize one projected scale set, with Prowler's load-balancer reading."""
    resource_id = scale_set.get("id")
    pools = scale_set.get("load_balancer_backend_pools") or []
    instance_ids = scale_set.get("instance_ids") or []
    linux_configuration = scale_set.get("linux_configuration")

    return {
        "id": resource_id,
        "name": scale_set.get("name"),
        "location": scale_set.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "sku_name": scale_set.get("sku_name"),
        "sku_capacity": scale_set.get("sku_capacity"),
        "orchestration_mode": scale_set.get("orchestration_mode"),
        "upgrade_policy_mode": scale_set.get("upgrade_policy_mode"),
        "security_profile": _security_profile_record(scale_set.get("security_profile")),
        "trusted_launch_enabled": trusted_launch_enabled(scale_set.get("security_profile")),
        "linux_configuration": (
            {
                "disable_password_authentication": bool(
                    linux_configuration.get("disable_password_authentication") or False
                )
            }
            if isinstance(linux_configuration, dict)
            else None
        ),
        "image_reference": scale_set.get("image_reference") or {},
        "load_balancer_backend_pools": pools,
        "associated_with_load_balancer": bool(pools),
        "instance_ids": instance_ids,
        "instance_count": len(instance_ids),
    }


def summarize(virtual_machines: list[dict], scale_sets: list[dict]) -> dict:
    """The counts a reviewer reads first, in the same shape as the other Azure summaries.

    SSH-key enforcement is a percentage of LINUX VMs only — a Windows VM has no such
    setting, and folding it into the denominator would fail a hardened estate.
    """
    total = len(virtual_machines)
    trusted_launch = sum(1 for v in virtual_machines if v["trusted_launch_enabled"])
    managed_disks = sum(1 for v in virtual_machines if v["managed_disks_only"])
    linux = [v for v in virtual_machines if v["linux_configuration"] is not None]
    ssh_only = sum(1 for v in linux if v["password_authentication_disabled"])
    extensions = [e for v in virtual_machines for e in v["extensions"]]

    return {
        "total_virtual_machines": total,
        "trusted_launch_vms": trusted_launch,
        "trusted_launch_percentage": coverage_percentage(trusted_launch, total),
        "secure_boot_vms": sum(
            1 for v in virtual_machines if v["security_profile"]["uefi_settings"]["secure_boot_enabled"]
        ),
        "vtpm_vms": sum(
            1 for v in virtual_machines if v["security_profile"]["uefi_settings"]["v_tpm_enabled"]
        ),
        "confidential_vms": sum(
            1
            for v in virtual_machines
            if v["security_profile"]["security_type"] == SECURITY_TYPE_CONFIDENTIAL_VM
        ),
        "encryption_at_host_vms": sum(
            1 for v in virtual_machines if v["security_profile"]["encryption_at_host"]
        ),
        "managed_disk_vms": managed_disks,
        "managed_disk_percentage": coverage_percentage(managed_disks, total),
        "unmanaged_disk_vms": total - managed_disks,
        "linux_vms": len(linux),
        "linux_ssh_key_only_vms": ssh_only,
        "linux_ssh_key_only_percentage": coverage_percentage(ssh_only, len(linux)),
        "vms_with_extensions": sum(1 for v in virtual_machines if v["extensions"]),
        "total_extensions": len(extensions),
        "vms_in_scale_sets": sum(
            1 for v in virtual_machines if v["virtual_machine_scale_set_id"]
        ),
        "total_scale_sets": len(scale_sets),
        "scale_sets_with_load_balancer": sum(
            1 for s in scale_sets if s["associated_with_load_balancer"]
        ),
        "empty_scale_sets": sum(1 for s in scale_sets if not s["instance_ids"]),
        "trusted_launch_scale_sets": sum(1 for s in scale_sets if s["trusted_launch_enabled"]),
        "total_scale_set_instances": sum(s["instance_count"] for s in scale_sets),
    }


# --- collection (lazy azure imports) ---

def scale_set_name_from_id(resource_id: str | None) -> str | None:
    """Pull the scale set's name out of its ARM id.

    Prowler parses the id rather than trusting `name` because
    virtual_machine_scale_set_vms.list() takes (resource_group, scale_set_name) and the id
    is the one field guaranteed present. Matched case-insensitively: ARM is inconsistent
    about `virtualMachineScaleSets` casing across API versions.
    """
    if not resource_id:
        return None
    parts = resource_id.split("/")
    for index, part in enumerate(parts):
        if part.lower() == "virtualmachinescalesets" and index + 1 < len(parts):
            return parts[index + 1] or None
    return None


def collect_compute(
    subscription_id, cred, collector: Collector
) -> tuple[list[dict], list[dict]]:
    """Two subscription-wide list calls plus two per-resource enrichments.

    Both `list_all()` calls return ItemPaged (the SDK follows nextLink itself).
    `virtual_machine_extensions.list()` returns a `VirtualMachineExtensionsListResult`,
    NOT an ItemPaged, so the list is read off `.value`; it is not paginated. The SDK
    import lives inside the guarded factory so a missing azure-mgmt-compute becomes a
    recorded failure (classified `internal_error`) with evidence plus a status file, not
    a traceback.
    """

    def _client():
        from azure.mgmt.compute import ComputeManagementClient  # lazy

        return ComputeManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs())

    client = collector.guard("compute.ComputeManagementClient (init)", _client)
    if client is None:
        return [], []

    virtual_machines = collector.guard(
        "compute.virtual_machines.list_all",
        lambda: [
            virtual_machine_record(project_virtual_machine(vm))
            for vm in client.virtual_machines.list_all()
        ],
        default=[],
    )
    for vm in virtual_machines:
        group, name = vm.get("resource_group"), vm.get("name")
        if not group or not name:
            collector.record(
                "compute.virtual_machine_extensions.list",
                RuntimeError(f"virtual machine {name!r} has no resource group in its id"),
            )
            continue
        vm["extensions"] = collector.guard(
            f"compute.virtual_machine_extensions.list ({name})",
            lambda group=group, name=name: sorted(
                (
                    extension_record(project_vm_extension(e))
                    for e in (
                        model_attr(
                            client.virtual_machine_extensions.list(group, name), "value"
                        )
                        or []
                    )
                ),
                key=lambda r: r.get("id") or "",
            ),
            default=[],
        )

    scale_sets = collector.guard(
        "compute.virtual_machine_scale_sets.list_all",
        lambda: [
            scale_set_record(project_scale_set(s))
            for s in client.virtual_machine_scale_sets.list_all()
        ],
        default=[],
    )
    for scale_set in scale_sets:
        group = scale_set.get("resource_group")
        name = scale_set_name_from_id(scale_set.get("id")) or scale_set.get("name")
        if not group or not name:
            collector.record(
                "compute.virtual_machine_scale_set_vms.list",
                RuntimeError(f"scale set {name!r} has no resource group in its id"),
            )
            continue
        instance_ids = collector.guard(
            f"compute.virtual_machine_scale_set_vms.list ({name})",
            lambda group=group, name=name: [
                instance_id
                for instance_id in (
                    project_scale_set_instance(i)
                    for i in client.virtual_machine_scale_set_vms.list(group, name)
                )
                if instance_id
            ],
            default=[],
        )
        scale_set["instance_ids"] = sorted(instance_ids)
        scale_set["instance_count"] = len(scale_set["instance_ids"])

    return (
        sorted(virtual_machines, key=lambda r: r.get("id") or ""),
        sorted(scale_sets, key=lambda r: r.get("id") or ""),
    )


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request and response header at INFO, which would bury
    # this fetcher's lines in the runner's stderr tail. Warnings still come through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    virtual_machines: list[dict] = []
    scale_sets: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # Asked BEFORE the list calls, so a zero-VM result is legible: Azure returns
        # an empty list rather than an error for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Compute"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Compute is not registered on subscription %s — no virtual "
                "machines in use; reporting status not_registered",
                subscription_id,
            )
        virtual_machines, scale_sets = collect_compute(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "virtual_machines": virtual_machines,
            "virtual_machine_scale_sets": scale_sets,
            "provider_registration_status": registration,
        },
        summary={
            **summarize(virtual_machines, scale_sets),
            "provider_registration_status": registration,
        },
    )

    filename = (
        f"azure_vm_hardening_status_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
