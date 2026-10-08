#!/usr/bin/env python3
"""Azure SQL Managed Instance network exposure, TLS, Entra authentication and audit-log export."""

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
    build_payload,
    classify_failure_code,
    credential,
    failure_reason,
    list_diagnostic_settings,
    model_attr,
    monitor_client,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
)
from sql_managed_instance import list_instances, lower, sql_client  # noqa: E402

logger = logging.getLogger("azure_sql_managed_instance_configuration")

RECOMMENDED_TLS_VERSIONS = ("1.2", "1.3")
AUDIT_CATEGORY = "sqlsecurityauditevents"
AUDIT_CATEGORY_GROUPS = ("audit", "alllogs")
ADMINISTRATOR_TYPE_ENTRA = "activedirectory"


# --- projection: azure-mgmt models in, flat dicts out ---

def project_instance(instance) -> dict:
    return {
        "id": model_attr(instance, "id"),
        "name": model_attr(instance, "name"),
        "location": model_attr(instance, "location"),
        "state": model_attr(instance, "state"),
        "fully_qualified_domain_name": model_attr(instance, "fully_qualified_domain_name"),
        "public_data_endpoint_enabled": model_attr(instance, "public_data_endpoint_enabled"),
        "proxy_override": model_attr(instance, "proxy_override"),
        "minimal_tls_version": model_attr(instance, "minimal_tls_version"),
        "private_endpoint_connections": [
            {
                "id": model_attr(pec, "id"),
                "private_endpoint_id": model_attr(
                    model_attr(model_attr(pec, "properties"), "private_endpoint"), "id"
                ),
                "status": model_attr(
                    model_attr(
                        model_attr(pec, "properties"), "private_link_service_connection_state"
                    ),
                    "status",
                ),
                "provisioning_state": model_attr(model_attr(pec, "properties"), "provisioning_state"),
            }
            for pec in (model_attr(instance, "private_endpoint_connections") or [])
        ],
    }


def project_administrator(admin) -> dict:
    return {
        "administrator_type": model_attr(admin, "administrator_type"),
        "login": model_attr(admin, "login"),
        "sid": model_attr(admin, "sid"),
        "tenant_id": model_attr(admin, "tenant_id"),
    }


# --- pure transforms (flat dicts in, evidence records out) ---

# Proves a route, not that auditing is on; possible fix: query the destination workspace for recent SQLSecurityAuditEvents.
def exports_audit_logs(settings: list[dict] | None) -> bool:
    return any(
        log["enabled"]
        and (
            lower(log.get("category")) == AUDIT_CATEGORY
            or lower(log.get("category_group")) in AUDIT_CATEGORY_GROUPS
        )
        for setting in settings or []
        for log in setting.get("logs") or []
    )


def instance_record(
    instance: dict,
    administrators: list[dict] | None,
    entra_only: bool | None,
    diagnostic_settings: list[dict] | None,
) -> dict:
    public = instance.get("public_data_endpoint_enabled")
    tls = instance.get("minimal_tls_version")
    connections = instance.get("private_endpoint_connections") or []
    return {
        **instance,
        "private_access_only": None if public is None else public is False,
        "minimal_tls_version_recommended": tls in RECOMMENDED_TLS_VERSIONS,
        "approved_private_endpoints": sum(1 for c in connections if lower(c.get("status")) == "approved"),
        "administrators": administrators,
        "entra_administrator_configured": any(
            lower(a.get("administrator_type")) == ADMINISTRATOR_TYPE_ENTRA for a in administrators or []
        ),
        "azure_ad_only_authentication": entra_only,
        "diagnostic_settings": diagnostic_settings,
        "audit_logs_exported": exports_audit_logs(diagnostic_settings),
        "audit_log_destinations": sorted(
            {
                dest
                for s in diagnostic_settings or []
                if exports_audit_logs([s])
                for dest in (s.get("workspace_id"), s.get("storage_account_id"), s.get("event_hub_name"))
                if dest
            }
        ),
    }


def summarize(instances: list[dict]) -> dict:
    return {
        "total_managed_instances": len(instances),
        "instances_public_data_endpoint_enabled": sum(
            1 for i in instances if i.get("public_data_endpoint_enabled") is True
        ),
        "instances_private_access_only": sum(1 for i in instances if i["private_access_only"]),
        "instances_with_approved_private_endpoint": sum(
            1 for i in instances if i["approved_private_endpoints"]
        ),
        "instances_minimal_tls_recommended": sum(
            1 for i in instances if i["minimal_tls_version_recommended"]
        ),
        "instances_entra_administrator": sum(1 for i in instances if i["entra_administrator_configured"]),
        "instances_entra_only_authentication": sum(
            1 for i in instances if i["azure_ad_only_authentication"] is True
        ),
        "instances_audit_logs_exported": sum(1 for i in instances if i["audit_logs_exported"]),
    }


# --- collection (lazy azure imports) ---

def collect(subscription_id, cred, collector: Collector) -> list[dict]:
    client = sql_client(subscription_id, cred, collector)
    if client is None:
        return []
    instances = list_instances(client, collector, project_instance)
    monitor = (
        collector.guard(
            "monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred)
        )
        if instances
        else None
    )

    records = []
    for instance in instances:
        group, name = instance["resource_group"], instance["name"]
        administrators = collector.guard(
            f"sql.managed_instance_administrators.list_by_instance ({name})",
            lambda: [
                project_administrator(a)
                for a in client.managed_instance_administrators.list_by_instance(group, name)
            ],
        )
        entra_only = collector.guard(
            f"sql.managed_instance_azure_ad_only_authentications.list_by_instance ({name})",
            lambda: any(
                model_attr(a, "azure_ad_only_authentication") is True
                for a in client.managed_instance_azure_ad_only_authentications.list_by_instance(
                    group, name
                )
            ),
        )
        settings = (
            collector.guard(
                f"monitor.diagnostic_settings.list ({name})",
                lambda: list_diagnostic_settings(monitor, instance["id"]),
            )
            if monitor is not None
            else None
        )
        records.append(instance_record(instance, administrators, entra_only, settings))

    return sorted(records, key=lambda i: i.get("id") or "")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)

    instances: list[dict] = []
    registration = REGISTRATION_UNKNOWN
    if subscription_id and cred is not None:
        registration = provider_registration_status(
            collector, subscription_id, cred, "Microsoft.Sql"
        )
        if registration == NOT_REGISTERED:
            logger.warning(
                "Microsoft.Sql is not registered on subscription %s — no SQL Managed "
                "Instance in use; reporting status not_registered",
                subscription_id,
            )
        instances = collect(subscription_id, cred, collector)
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
            "managed_instances": instances,
            "provider_registration_status": registration,
        },
        summary={**summarize(instances), "provider_registration_status": registration},
    )

    filename = (
        f"azure_sql_managed_instance_configuration_"
        f"{sanitize_for_filename(subscription_id or 'unknown')}.json"
    )
    path = write_evidence(output_dir, filename, evidence)
    logger.info("Evidence saved to %s", path)

    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
