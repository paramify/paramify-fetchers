#!/usr/bin/env python3
"""
OCI managed data services — who can reach the data, and whose key encrypts it

Every Autonomous Database, DB system, File Storage file system with its NFS
exports, and Integration instance in scope: the network path that reaches it
(public endpoint, access control list, private subnet, NSG), whether transport
is authenticated, and whether it is encrypted with a customer-managed key.

Evidence for KSI-SVC-SIN (information encrypted and secured from unwanted
access), KSI-CNA-MAT (minimal attack surface) and KSI-CNA-RNT (inbound traffic
limited) — the three managed services where the data sits directly behind a
network endpoint rather than behind an instance.

Ported from Prowler's OCI database, filestorage and integration services
(Apache-2.0, commit 5fe1a67) — `database_autonomous_database_access_restricted`,
`filestorage_file_system_encrypted_with_cmk` and
`integration_instance_access_restricted`, one check each. Four departures:

  * "ORACLE_MANAGED_KEY" IS A STRING, NOT NULL. A live Autonomous Database
    reports `kms_key_id: "ORACLE_MANAGED_KEY"` when Oracle holds the key.
    Prowler's key test elsewhere is `kms_key_id is not None`, which reads that
    literal as a customer-managed key — the exact inversion of the finding.
    Here a key counts only when it is a real OCID.

  * mTLS IS NOT CHECKED. `is_mtls_connection_required: false` means a wallet
    alone opens a connection, so an allow-list is the only thing left between
    the internet and the database. It belongs beside the access-control answer,
    not in a separate universe.

  * NFS EXPORT OPTIONS ARE WHERE FILE STORAGE IS ACTUALLY EXPOSED. Prowler
    checks the file system's key and nothing else. An export with
    `source: 0.0.0.0/0`, `access: READ_WRITE` and `identity_squash: NONE` hands
    root-equivalent access to anyone who can reach the mount target — which the
    mount target's own subnet and NSGs then decide.

  * DB SYSTEMS ARE NOT COVERED BY PROWLER AT ALL. Only Autonomous Databases
    are. A DB system carries the same questions (subnet, NSGs, customer key)
    and is collected here. Verified against SDK models only — the trial tenancy
    has none, and that is stated rather than implied.

An Autonomous Database with no allow-list and no subnet is reachable from the
whole internet; an empty `whitelisted_ips` is not a restrictive allow-list, it
is the absence of one. That is the live tenancy's staged case.
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
    service_not_subscribed,
    short_ocid,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_data_service_exposure")

# Oracle writes this literal into kms_key_id when it holds the key itself.
ORACLE_MANAGED_KEY = "ORACLE_MANAGED_KEY"
INTERNET_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
GONE_STATES = frozenset({"TERMINATED", "TERMINATING", "DELETED", "DELETING", "FAILED"})

PUBLIC_ENDPOINT = "PUBLIC"
READ_WRITE = "READ_WRITE"
NO_SQUASH = "NONE"


# --- pure transforms ---

def customer_managed_key(key_id) -> bool:
    """True only for a real key OCID.

    `None` means Oracle's key; so does the literal "ORACLE_MANAGED_KEY", which a
    live Autonomous Database returns. A `kms_key_id is not None` test reads that
    string as customer-managed.
    """
    return bool(key_id) and key_id != ORACLE_MANAGED_KEY and str(key_id).startswith("ocid1.")


def autonomous_database_record(database: dict) -> dict:
    allow_list = database.get("whitelisted_ips") or []
    in_vcn = bool(database.get("subnet_id"))
    # An empty allow-list is the absence of a restriction, not a restriction.
    open_to_internet = not in_vcn and not allow_list
    allows_any = any(str(entry).strip() in INTERNET_CIDRS for entry in allow_list)

    return {
        "id": database.get("id"),
        "display_name": database.get("display_name"),
        "db_name": database.get("db_name"),
        "compartment_id": database.get("compartment_id"),
        "lifecycle_state": database.get("lifecycle_state"),
        "db_workload": database.get("db_workload"),
        "db_version": database.get("db_version"),
        "is_free_tier": database.get("is_free_tier"),
        "is_dedicated": database.get("is_dedicated"),
        "time_created": iso(database.get("time_created")),
        # Network path.
        "subnet_id": database.get("subnet_id"),
        "is_in_vcn": in_vcn,
        "nsg_ids": sorted(database.get("nsg_ids") or []),
        "private_endpoint": database.get("private_endpoint"),
        "whitelisted_ips": sorted(str(entry) for entry in allow_list),
        "has_access_control_list": bool(allow_list),
        "access_control_allows_internet": allows_any,
        "publicly_reachable_without_restriction": open_to_internet or allows_any,
        # Transport.
        "is_mtls_connection_required": database.get("is_mtls_connection_required"),
        "mtls_disabled": database.get("is_mtls_connection_required") is False,
        # Encryption at rest.
        "kms_key_id": database.get("kms_key_id"),
        "customer_managed_key": customer_managed_key(database.get("kms_key_id")),
        "vault_id": database.get("vault_id"),
        # Related posture services, recorded for context rather than judged.
        "data_safe_status": database.get("data_safe_status"),
        "database_management_status": database.get("database_management_status"),
    }


def db_system_record(system: dict) -> dict:
    """A non-autonomous DB system. Prowler covers none of these."""
    return {
        "id": system.get("id"),
        "display_name": system.get("display_name"),
        "compartment_id": system.get("compartment_id"),
        "lifecycle_state": system.get("lifecycle_state"),
        "shape": system.get("shape"),
        "database_edition": system.get("database_edition"),
        "version": system.get("version"),
        "subnet_id": system.get("subnet_id"),
        "is_in_vcn": bool(system.get("subnet_id")),
        "nsg_ids": sorted(system.get("nsg_ids") or []),
        "is_protected_by_nsg": bool(system.get("nsg_ids")),
        "kms_key_id": system.get("kms_key_id"),
        "customer_managed_key": customer_managed_key(system.get("kms_key_id")),
        "license_model": system.get("license_model"),
        "node_count": system.get("node_count"),
        "time_created": iso(system.get("time_created")),
    }


def export_record(export: dict) -> dict:
    """One NFS export, with the client options that decide who may mount it."""
    options = export.get("export_options") or []
    clients = [{
        "source": option.get("source"),
        "access": option.get("access"),
        "identity_squash": option.get("identity_squash"),
        "require_privileged_source_port": option.get("require_privileged_source_port"),
        "is_anonymous_access_allowed": option.get("is_anonymous_access_allowed") is True,
        "allowed_auth": sorted(option.get("allowed_auth") or []),
        "source_is_internet": str(option.get("source") or "").strip() in INTERNET_CIDRS,
        # Root on the client stays root on the share.
        "root_not_squashed": option.get("identity_squash") == NO_SQUASH,
    } for option in options]

    return {
        "id": export.get("id"),
        "path": export.get("path"),
        "file_system_id": export.get("file_system_id"),
        "export_set_id": export.get("export_set_id"),
        "lifecycle_state": export.get("lifecycle_state"),
        "client_options": clients,
        # None means the export options could not be read.
        "options_read": bool(options) or export.get("export_options") is not None,
        "exports_to_internet": any(c["source_is_internet"] for c in clients),
        "internet_writable": any(
            c["source_is_internet"] and c["access"] == READ_WRITE for c in clients
        ),
        "internet_writable_unsquashed": any(
            c["source_is_internet"] and c["access"] == READ_WRITE and c["root_not_squashed"]
            for c in clients
        ),
    }


def file_system_record(file_system: dict, *, exports=None, mount_targets=()) -> dict:
    export_records = list(exports) if exports is not None else None
    targets = list(mount_targets)
    return {
        "id": file_system.get("id"),
        "display_name": file_system.get("display_name"),
        "compartment_id": file_system.get("compartment_id"),
        "availability_domain": file_system.get("availability_domain"),
        "lifecycle_state": file_system.get("lifecycle_state"),
        "metered_bytes": file_system.get("metered_bytes"),
        "kms_key_id": file_system.get("kms_key_id"),
        "customer_managed_key": customer_managed_key(file_system.get("kms_key_id")),
        "time_created": iso(file_system.get("time_created")),
        "exports": export_records,
        "exports_read": export_records is not None,
        "export_count": len(export_records) if export_records is not None else None,
        "exports_to_internet": any(e["exports_to_internet"] for e in export_records or []),
        "internet_writable_unsquashed_exports": sum(
            1 for e in export_records or [] if e["internet_writable_unsquashed"]
        ),
        # The mount targets that carry those exports, and what guards them.
        "mount_targets": targets,
        "mount_targets_without_nsg": sum(1 for t in targets if not t["nsg_ids"]),
    }


def mount_target_record(target: dict) -> dict:
    return {
        "id": target.get("id"),
        "display_name": target.get("display_name"),
        "subnet_id": target.get("subnet_id"),
        "export_set_id": target.get("export_set_id"),
        "nsg_ids": sorted(target.get("nsg_ids") or []),
        "lifecycle_state": target.get("lifecycle_state"),
    }


def integration_instance_record(instance: dict) -> dict:
    endpoint = instance.get("network_endpoint_details") or {}
    kind = endpoint.get("network_endpoint_type")
    allowed_ips = endpoint.get("allowlisted_http_ips") or []
    allowed_vcns = endpoint.get("allowlisted_http_vcns") or []
    # No endpoint details at all means the public endpoint is unrestricted.
    unrestricted = not endpoint or (
        kind == PUBLIC_ENDPOINT and not allowed_ips and not allowed_vcns
    )
    return {
        "id": instance.get("id"),
        "display_name": instance.get("display_name"),
        "compartment_id": instance.get("compartment_id"),
        "lifecycle_state": instance.get("lifecycle_state"),
        "integration_instance_type": instance.get("integration_instance_type"),
        "network_endpoint_type": kind,
        "allowlisted_ips": sorted(str(ip) for ip in allowed_ips),
        "allowlisted_vcn_count": len(allowed_vcns),
        "allowlist_allows_internet": any(str(ip).strip() in INTERNET_CIDRS for ip in allowed_ips),
        "publicly_reachable_without_restriction": unrestricted,
        "is_file_server_enabled": instance.get("is_file_server_enabled") is True,
        "time_created": iso(instance.get("time_created")),
    }


def summarize(databases, db_systems, file_systems, integrations, *, api_readable: bool = True) -> dict:
    live_dbs = [d for d in databases if d["lifecycle_state"] not in GONE_STATES]
    live_systems = [s for s in db_systems if s["lifecycle_state"] not in GONE_STATES]
    live_fs = [f for f in file_systems if f["lifecycle_state"] not in GONE_STATES]
    live_integrations = [i for i in integrations if i["lifecycle_state"] not in GONE_STATES]
    read_exports = [f for f in live_fs if f["exports_read"]]
    everything_with_keys = live_dbs + live_systems + live_fs

    return {
        # False when the listings failed outright — not "no data services".
        "data_services_readable": api_readable,
        # Autonomous Databases.
        "total_autonomous_databases": len(live_dbs),
        "autonomous_databases_in_vcn": sum(1 for d in live_dbs if d["is_in_vcn"]),
        "autonomous_databases_publicly_reachable": sum(
            1 for d in live_dbs if d["publicly_reachable_without_restriction"]
        ),
        "autonomous_databases_with_access_control_list": sum(
            1 for d in live_dbs if d["has_access_control_list"]
        ),
        "autonomous_databases_with_mtls_disabled": sum(1 for d in live_dbs if d["mtls_disabled"]),
        "autonomous_database_names_publicly_reachable": sorted(
            f"{d['display_name']} ({short_ocid(d['id'])})" for d in live_dbs
            if d["publicly_reachable_without_restriction"] and d["display_name"]
        ),
        # DB systems — Prowler covers none of these.
        "total_db_systems": len(live_systems),
        "db_systems_without_nsg": sum(1 for s in live_systems if not s["is_protected_by_nsg"]),
        # File Storage.
        "total_file_systems": len(live_fs),
        "file_systems_with_unreadable_exports": len(live_fs) - len(read_exports),
        "file_systems_exporting_to_internet": sum(1 for f in read_exports if f["exports_to_internet"]),
        "internet_writable_unsquashed_exports": sum(
            f["internet_writable_unsquashed_exports"] for f in read_exports
        ),
        "mount_targets_without_nsg": sum(f["mount_targets_without_nsg"] for f in live_fs),
        # Integration.
        "total_integration_instances": len(live_integrations),
        "integration_instances_publicly_reachable": sum(
            1 for i in live_integrations if i["publicly_reachable_without_restriction"]
        ),
        # Encryption, across every service that carries a key.
        "resources_with_customer_managed_key": sum(
            1 for r in everything_with_keys if r["customer_managed_key"]
        ),
        "resources_with_oracle_managed_key": sum(
            1 for r in everything_with_keys if not r["customer_managed_key"]
        ),
        "customer_managed_key_percentage": coverage_percentage(
            sum(1 for r in everything_with_keys if r["customer_managed_key"]), len(everything_with_keys)
        ),
        # Everything reachable from the internet, in one list for a reader.
        "publicly_reachable_resources": (
            sum(1 for d in live_dbs if d["publicly_reachable_without_restriction"])
            + sum(1 for f in read_exports if f["exports_to_internet"])
            + sum(1 for i in live_integrations if i["publicly_reachable_without_restriction"])
        ),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool):
    import oci  # lazy

    identity = make_client(oci.identity.IdentityClient, auth)
    database = make_client(oci.database.DatabaseClient, auth)
    file_storage = make_client(oci.file_storage.FileStorageClient, auth)
    integration = make_client(oci.integration.IntegrationInstanceClient, auth)

    compartments = walk_compartments(
        identity, scope["compartment_id"], collector,
        include_subcompartments=include_sub, tenancy=auth.get("tenancy"),
    )

    databases: list[dict] = []
    db_systems: list[dict] = []
    file_systems: list[dict] = []
    integrations: list[dict] = []
    unreadable = 0

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

        found = collector.guard(
            f"database.list_autonomous_databases ({cname})",
            lambda c=cid: list_all(database.list_autonomous_databases, c),
            tolerate=service_not_subscribed,
        )
        if found is None:
            unreadable += 1
        for db in found or []:
            databases.append(autonomous_database_record(to_plain(db)))

        for system in collector.guard(
            f"database.list_db_systems ({cname})",
            lambda c=cid: list_all(database.list_db_systems, c),
            default=[], tolerate=service_not_subscribed,
        ) or []:
            db_systems.append(db_system_record(to_plain(system)))

        for instance in collector.guard(
            f"integration.list_integration_instances ({cname})",
            lambda c=cid: list_all(integration.list_integration_instances, c),
            default=[], tolerate=service_not_subscribed,
        ) or []:
            integrations.append(integration_instance_record(to_plain(instance)))


        targets_by_export_set: dict[str, list] = {}
        for domain in domains:
            for target in collector.guard(
                f"file_storage.list_mount_targets ({cname}, {domain.name})",
                lambda c=cid, d=domain.name: list_all(file_storage.list_mount_targets, c, d),
                default=[], tolerate=service_not_subscribed,
            ) or []:
                plain = to_plain(target)
                targets_by_export_set.setdefault(plain.get("export_set_id"), []).append(
                    mount_target_record(plain))

        for domain in domains:
            for raw in collector.guard(
                f"file_storage.list_file_systems ({cname}, {domain.name})",
                lambda c=cid, d=domain.name: list_all(file_storage.list_file_systems, c, d),
                default=[], tolerate=service_not_subscribed,
            ) or []:
                plain = to_plain(raw)
                summaries = collector.guard(
                    f"file_storage.list_exports ({plain.get('display_name')})",
                    lambda f=plain["id"]: list_all(file_storage.list_exports, file_system_id=f),
                )
                exports = None
                if summaries is not None:
                    exports = []
                    for summary in summaries:
                        # Mandatory second call: ExportSummary carries no
                        # export_options, which is where the exposure lives.
                        detail = collector.guard(
                            f"file_storage.get_export ({short_ocid(summary.id)})",
                            lambda e=summary.id: file_storage.get_export(e).data,
                        )
                        exports.append(export_record(to_plain(detail if detail is not None else summary)))

                targets = [t for export_set, group in targets_by_export_set.items()
                           for t in group if export_set]
                file_systems.append(file_system_record(plain, exports=exports, mount_targets=targets))

    if compartments and unreadable == len(compartments):
        return None, None, None, None, len(compartments)

    databases.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    db_systems.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    file_systems.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    integrations.sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    return databases, db_systems, file_systems, integrations, len(compartments)


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
    databases = db_systems = file_systems = integrations = None
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            try:
                databases, db_systems, file_systems, integrations, scanned = collect(
                    auth, scope, collector, include_sub=include_sub)
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("data_services.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={
            "autonomous_databases": databases or [],
            "db_systems": db_systems or [],
            "file_systems": file_systems or [],
            "integration_instances": integrations or [],
        },
        summary=summarize(databases or [], db_systems or [], file_systems or [], integrations or [],
                          api_readable=databases is not None),
        compartments_scanned=scanned,
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_data_service_exposure_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)
    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
