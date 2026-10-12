#!/usr/bin/env python3
"""Azure Log Analytics workspaces for one subscription: retention, ingestion cap,
network exposure and access control mode, per-table retention, data exports, and
whether Microsoft Sentinel is onboarded.

azure-mgmt-loganalytics 14.x does NOT flatten `properties` onto its models (the same
change azure-mgmt-keyvault 14 made), so every read goes through `properties_bag()`.
Management plane only: no log data is queried.

Per-table retention is summarized, not dumped: a workspace ships several hundred
built-in tables (686 on a fresh one), almost all at the workspace default. The
counts cover every table; only the ones that differ from the default, and custom
tables, are listed by name.
"""

import logging
import os
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_client_kwargs,
    build_payload,
    classify_failure_code,
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

logger = logging.getLogger("azure_log_analytics_workspaces")

# ARM omits publicNetworkAccessFor* on a workspace never restricted; absent is Enabled.
PUBLIC_NETWORK_ACCESS_DEFAULT = "Enabled"

# `dailyQuotaGb` is -1 when no daily cap is set.
NO_DAILY_CAP = -1

# enableLogAccessUsingOnlyResourcePermissions, despite its name: true means a reader
# may use EITHER resource-scoped RBAC or workspace permissions ("resource-context");
# false or absent means workspace permissions are required.
ACCESS_MODE_RESOURCE_OR_WORKSPACE = "resource_or_workspace_permissions"
ACCESS_MODE_WORKSPACE_ONLY = "workspace_permissions"

# The solution Microsoft Sentinel installs on a workspace it is onboarded to.
SENTINEL_INTELLIGENCE_PACK = "SecurityInsights"

# Built-in tables report tableType "Microsoft"; anything else (CustomLog,
# RestoredLogs, SearchResults) is customer-created and listed by name.
MICROSOFT_TABLE_TYPE = "microsoft"


# --- projection: the only code that touches an azure-mgmt model ---

def properties_bag(model):
    """Return the model's `properties` sub-model, or the model itself.

    14.x keeps `properties` nested; an older msrest release flattens it and has none.
    """
    bag = model_attr(model, "properties")
    return model if bag is None else bag


def project_workspace(workspace) -> dict:
    """Read a `Workspace` model into a flat snake_case dict, un-defaulted."""
    properties = properties_bag(workspace)
    sku = model_attr(properties, "sku")
    capping = model_attr(properties, "workspace_capping")
    features = model_attr(properties, "features")
    return {
        "id": model_attr(workspace, "id"),
        "name": model_attr(workspace, "name"),
        "location": model_attr(workspace, "location"),
        "customer_id": model_attr(properties, "customer_id"),
        "provisioning_state": model_attr(properties, "provisioning_state"),
        "sku_name": model_attr(sku, "name"),
        "sku_capacity_reservation_level": model_attr(sku, "capacity_reservation_level"),
        "retention_in_days": model_attr(properties, "retention_in_days"),
        "daily_quota_gb": model_attr(capping, "daily_quota_gb"),
        "data_ingestion_status": model_attr(capping, "data_ingestion_status"),
        "public_network_access_for_ingestion": model_attr(
            properties, "public_network_access_for_ingestion"
        ),
        "public_network_access_for_query": model_attr(
            properties, "public_network_access_for_query"
        ),
        "force_cmk_for_query": model_attr(properties, "force_cmk_for_query"),
        "enable_log_access_using_only_resource_permissions": model_attr(
            features, "enable_log_access_using_only_resource_permissions"
        ),
        "disable_local_auth": model_attr(features, "disable_local_auth"),
        "enable_data_export": model_attr(features, "enable_data_export"),
        "immediate_purge_data_on_30_days": model_attr(features, "immediate_purge_data_on30_days"),
        "cluster_resource_id": model_attr(features, "cluster_resource_id"),
    }


def project_table(table) -> dict:
    """Read a `Table` model's retention fields — the schema's columns are dropped."""
    properties = properties_bag(table)
    schema = model_attr(properties, "schema")
    return {
        "name": model_attr(table, "name"),
        "plan": model_attr(properties, "plan"),
        "table_type": model_attr(schema, "table_type"),
        "retention_in_days": model_attr(properties, "retention_in_days"),
        "total_retention_in_days": model_attr(properties, "total_retention_in_days"),
        "archive_retention_in_days": model_attr(properties, "archive_retention_in_days"),
        "retention_in_days_as_default": model_attr(properties, "retention_in_days_as_default"),
        "total_retention_in_days_as_default": model_attr(
            properties, "total_retention_in_days_as_default"
        ),
    }


def project_data_export(export) -> dict:
    """Read a `DataExport` model: which tables go where, and whether it is on."""
    properties = properties_bag(export)
    destination = model_attr(properties, "destination")
    meta_data = model_attr(destination, "meta_data")
    return {
        "id": model_attr(export, "id"),
        "name": model_attr(export, "name"),
        "enable": model_attr(properties, "enable"),
        "table_names": list(model_attr(properties, "table_names") or []),
        "destination_type": model_attr(destination, "type"),
        "destination_resource_id": model_attr(destination, "resource_id"),
        "event_hub_name": model_attr(meta_data, "event_hub_name"),
    }


def project_intelligence_pack(pack) -> dict:
    return {"name": model_attr(pack, "name"), "enabled": model_attr(pack, "enabled")}


# --- pure transforms (flat snake_case dicts in, evidence records out) ---

def _sorted_counts(values) -> dict:
    counter = Counter(values)
    return {str(key): counter[key] for key in sorted(counter, key=lambda k: (k is None, k))}


def table_retention_summary(tables: list[dict]) -> dict:
    """Counts across EVERY table; only non-default and custom tables by name.

    `*_as_default` is true when the table inherits the workspace retention; a table
    whose value was set explicitly is the exception worth naming.
    """
    retention = [t["retention_in_days"] for t in tables if t["retention_in_days"] is not None]
    total = [t["total_retention_in_days"] for t in tables if t["total_retention_in_days"] is not None]
    listed = []
    for t in tables:
        non_default = (t["retention_in_days_as_default"] is False) or (
            t["total_retention_in_days_as_default"] is False
        )
        custom = str(t["table_type"] or "").lower() not in ("", MICROSOFT_TABLE_TYPE)
        if non_default or custom:
            listed.append(
                {
                    "name": t["name"],
                    "plan": t["plan"],
                    "table_type": t["table_type"],
                    "retention_in_days": t["retention_in_days"],
                    "total_retention_in_days": t["total_retention_in_days"],
                    "archive_retention_in_days": t["archive_retention_in_days"],
                    "retention_is_default": not non_default,
                    "custom_table": custom,
                }
            )
    return {
        "table_count": len(tables),
        "tables_by_plan": _sorted_counts(t["plan"] or "unknown" for t in tables),
        "tables_by_retention_in_days": _sorted_counts(retention),
        "tables_by_total_retention_in_days": _sorted_counts(total),
        "min_retention_in_days": min(retention) if retention else None,
        "min_total_retention_in_days": min(total) if total else None,
        "max_total_retention_in_days": max(total) if total else None,
        "non_default_retention_table_count": sum(
            1 for t in listed if not t["retention_is_default"]
        ),
        "custom_table_count": sum(1 for t in listed if t["custom_table"]),
        "non_default_or_custom_tables": sorted(listed, key=lambda t: t["name"] or ""),
    }


def data_export_record(export: dict) -> dict:
    return {
        **export,
        # `enable` is omitted when never set; the service default is enabled.
        "enabled": export.get("enable") is not False,
        "table_names": sorted(export.get("table_names") or []),
    }


def workspace_record(
    workspace: dict,
    tables,
    exports,
    packs,
) -> dict:
    """Normalize one projected workspace plus its per-workspace reads.

    `tables` / `exports` / `packs` are None when that read failed (recorded as an API
    failure); they are then reported as unknown rather than as empty.
    """
    resource_id = workspace.get("id")
    quota = workspace.get("daily_quota_gb")
    resource_permissions = bool(
        workspace.get("enable_log_access_using_only_resource_permissions") or False
    )
    ingestion = workspace.get("public_network_access_for_ingestion") or PUBLIC_NETWORK_ACCESS_DEFAULT
    query = workspace.get("public_network_access_for_query") or PUBLIC_NETWORK_ACCESS_DEFAULT
    enabled_packs = (
        None if packs is None else sorted(p["name"] for p in packs if p.get("enabled") and p.get("name"))
    )
    export_records = (
        None
        if exports is None
        else sorted((data_export_record(e) for e in exports), key=lambda e: e.get("name") or "")
    )

    return {
        "id": resource_id,
        "name": workspace.get("name"),
        "location": workspace.get("location"),
        "resource_group": resource_group_from_id(resource_id),
        "customer_id": workspace.get("customer_id"),
        "provisioning_state": workspace.get("provisioning_state"),
        # --- cost / retention ---
        "sku": {
            "name": workspace.get("sku_name"),
            "capacity_reservation_level": workspace.get("sku_capacity_reservation_level"),
        },
        "retention_in_days": workspace.get("retention_in_days"),
        "daily_quota_gb": quota,
        "daily_cap_enabled": quota is not None and quota != NO_DAILY_CAP,
        "data_ingestion_status": workspace.get("data_ingestion_status"),
        "immediate_purge_data_on_30_days": bool(
            workspace.get("immediate_purge_data_on_30_days") or False
        ),
        # --- network exposure ---
        "public_network_access_for_ingestion": ingestion,
        "public_network_access_for_query": query,
        "public_ingestion_enabled": str(ingestion).lower() == "enabled",
        "public_query_enabled": str(query).lower() == "enabled",
        # --- who can read the logs ---
        "enable_log_access_using_only_resource_permissions": resource_permissions,
        "access_mode": (
            ACCESS_MODE_RESOURCE_OR_WORKSPACE if resource_permissions else ACCESS_MODE_WORKSPACE_ONLY
        ),
        # Absent means shared-key auth is still allowed.
        "local_auth_disabled": bool(workspace.get("disable_local_auth") or False),
        "force_cmk_for_query": bool(workspace.get("force_cmk_for_query") or False),
        "cluster_resource_id": workspace.get("cluster_resource_id"),
        # --- per-table retention ---
        "tables_status": "collected" if tables is not None else "unavailable",
        "table_retention": table_retention_summary(tables) if tables is not None else None,
        # --- exports + SIEM ---
        "data_export_feature_enabled": bool(workspace.get("enable_data_export") or False),
        "data_exports_status": "collected" if exports is not None else "unavailable",
        "data_exports": export_records,
        "enabled_solutions": enabled_packs,
        # None (unknown) when the solutions read failed, never a guessed false.
        "sentinel_onboarded": (
            None if enabled_packs is None else SENTINEL_INTELLIGENCE_PACK in enabled_packs
        ),
    }


def summarize(workspaces: list[dict]) -> dict:
    """Retention floor, exposure, access mode and SIEM onboarding across workspaces."""
    retention = [w["retention_in_days"] for w in workspaces if w["retention_in_days"] is not None]
    table_totals = [
        w["table_retention"]["min_total_retention_in_days"]
        for w in workspaces
        if w["table_retention"] and w["table_retention"]["min_total_retention_in_days"] is not None
    ]
    return {
        "total_workspaces": len(workspaces),
        "min_workspace_retention_in_days": min(retention) if retention else None,
        "max_workspace_retention_in_days": max(retention) if retention else None,
        "min_table_total_retention_in_days": min(table_totals) if table_totals else None,
        "total_tables": sum(
            w["table_retention"]["table_count"] for w in workspaces if w["table_retention"]
        ),
        "workspaces_with_daily_cap": sum(1 for w in workspaces if w["daily_cap_enabled"]),
        "workspaces_public_ingestion_enabled": sum(
            1 for w in workspaces if w["public_ingestion_enabled"]
        ),
        "workspaces_public_query_enabled": sum(1 for w in workspaces if w["public_query_enabled"]),
        "workspaces_resource_or_workspace_access_mode": sum(
            1 for w in workspaces if w["access_mode"] == ACCESS_MODE_RESOURCE_OR_WORKSPACE
        ),
        "workspaces_workspace_only_access_mode": sum(
            1 for w in workspaces if w["access_mode"] == ACCESS_MODE_WORKSPACE_ONLY
        ),
        "workspaces_local_auth_disabled": sum(1 for w in workspaces if w["local_auth_disabled"]),
        "workspaces_with_data_exports": sum(1 for w in workspaces if w["data_exports"]),
        "total_data_exports": sum(len(w["data_exports"] or []) for w in workspaces),
        "sentinel_onboarded_workspaces": sum(1 for w in workspaces if w["sentinel_onboarded"]),
        "sentinel_onboarded": any(w["sentinel_onboarded"] for w in workspaces),
    }


# --- collection (lazy azure imports) ---

def collect_workspaces(subscription_id, cred, collector: Collector) -> list[dict]:
    """One workspaces.list(), then three GETs per workspace."""

    def _client():
        from azure.mgmt.loganalytics import LogAnalyticsManagementClient  # lazy

        return LogAnalyticsManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    client = collector.guard("loganalytics.LogAnalyticsManagementClient (init)", _client)
    if client is None:
        return []

    # ItemPaged: the SDK follows nextLink itself, here and below.
    workspaces = collector.guard(
        "loganalytics.workspaces.list",
        lambda: [project_workspace(w) for w in client.workspaces.list()],
        default=[],
    )

    records = []
    for workspace in workspaces:
        name = workspace.get("name")
        rg = resource_group_from_id(workspace.get("id"))
        if not (name and rg):
            collector.record(
                "loganalytics.workspaces.list",
                RuntimeError(f"workspace {name!r} has no parseable resource id"),
            )
            records.append(workspace_record(workspace, None, None, None))
            continue
        tables = collector.guard(
            f"loganalytics.tables.list_by_workspace ({name})",
            lambda: [project_table(t) for t in client.tables.list_by_workspace(rg, name)],
        )
        exports = collector.guard(
            f"loganalytics.data_exports.list_by_workspace ({name})",
            lambda: [project_data_export(e) for e in client.data_exports.list_by_workspace(rg, name)],
        )
        packs = collector.guard(
            f"loganalytics.intelligence_packs.list ({name})",
            lambda: [project_intelligence_pack(p) for p in client.intelligence_packs.list(rg, name)],
        )
        records.append(workspace_record(workspace, tables, exports, packs))

    return sorted(records, key=lambda r: r.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every request header at INFO; warnings still get through.
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    workspaces: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        # ARM returns an empty list, not an error, for an unregistered provider.
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.OperationalInsights"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.OperationalInsights is not registered on subscription %s — "
                "no Log Analytics workspaces in use; reporting status not_registered",
                subscription_id,
            )
        workspaces = collect_workspaces(subscription_id, cred, collector)
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
            "workspaces": workspaces,
            "provider_registration_status": registration,
        },
        summary={**summarize(workspaces), "provider_registration_status": registration},
    )

    filename = (
        f"azure_log_analytics_workspaces_"
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
