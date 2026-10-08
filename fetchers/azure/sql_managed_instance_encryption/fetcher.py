#!/usr/bin/env python3
"""Azure SQL Managed Instance TDE protector and per-database Transparent Data Encryption."""

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
    model_attr,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    sanitize_for_filename,
    write_evidence,
)
from sql_managed_instance import (  # noqa: E402
    list_databases,
    list_instances,
    lower,
    sql_client,
)

logger = logging.getLogger("azure_sql_managed_instance_encryption")

SERVER_KEY_TYPE_CMK = "azurekeyvault"
TDE_ENABLED = "enabled"
CURRENT = "current"


# --- projection: azure-mgmt models in, flat dicts out ---

def project_instance(instance) -> dict:
    return {
        "id": model_attr(instance, "id"),
        "name": model_attr(instance, "name"),
        "location": model_attr(instance, "location"),
        "state": model_attr(instance, "state"),
    }


def project_protector(protector) -> dict:
    return {
        "server_key_type": model_attr(protector, "server_key_type"),
        "server_key_name": model_attr(protector, "server_key_name"),
        "key_vault_key_uri": model_attr(protector, "uri"),
        "thumbprint": model_attr(protector, "thumbprint"),
        "auto_rotation_enabled": bool(model_attr(protector, "auto_rotation_enabled") or False),
    }


# --- pure transforms (flat dicts in, evidence records out) ---

def database_record(database: dict, tde_state) -> dict:
    return {
        **database,
        "tde_state": tde_state,
        "tde_enabled": None if tde_state is None else lower(tde_state) == TDE_ENABLED,
    }


def instance_record(instance: dict, protector: dict | None, databases: list[dict] | None) -> dict:
    users = [d for d in databases or [] if not d["is_system_database"]]
    return {
        **instance,
        "encryption_protector": protector,
        "customer_managed_key": (
            None if protector is None else lower(protector.get("server_key_type")) == SERVER_KEY_TYPE_CMK
        ),
        "databases_collected": databases is not None,
        "databases": databases or [],
        "total_user_databases": len(users),
        "tde_enabled_user_databases": sum(1 for d in users if d["tde_enabled"] is True),
        "tde_disabled_user_databases": sum(1 for d in users if d["tde_enabled"] is False),
        "all_user_databases_tde_enabled": all(d["tde_enabled"] is True for d in users) if users else None,
    }


def summarize(instances: list[dict]) -> dict:
    return {
        "total_managed_instances": len(instances),
        "instances_customer_managed_key": sum(1 for i in instances if i["customer_managed_key"]),
        "instances_key_auto_rotation": sum(
            1 for i in instances if (i["encryption_protector"] or {}).get("auto_rotation_enabled")
        ),
        "total_user_databases": sum(i["total_user_databases"] for i in instances),
        "tde_enabled_user_databases": sum(i["tde_enabled_user_databases"] for i in instances),
        "tde_disabled_user_databases": sum(i["tde_disabled_user_databases"] for i in instances),
    }


# --- collection (lazy azure imports) ---

def collect(subscription_id, cred, collector: Collector) -> list[dict]:
    client = sql_client(subscription_id, cred, collector)
    if client is None:
        return []

    records = []
    for instance in list_instances(client, collector, project_instance):
        group, name = instance["resource_group"], instance["name"]
        protector = collector.guard(
            f"sql.managed_instance_encryption_protectors.get ({name})",
            lambda: project_protector(
                client.managed_instance_encryption_protectors.get(group, name, CURRENT)
            ),
        )
        databases = list_databases(client, collector, instance)
        rows = []
        for database in databases or []:
            if database["is_system_database"]:
                rows.append(database_record(database, None))
                continue
            db = database["name"]
            tde = collector.guard(
                f"sql.managed_database_transparent_data_encryption.get ({name}/{db})",
                lambda: client.managed_database_transparent_data_encryption.get(
                    group, name, db, CURRENT
                ),
            )
            rows.append(database_record(database, model_attr(tde, "state")))
        records.append(
            instance_record(
                instance,
                protector,
                None if databases is None else sorted(rows, key=lambda d: d.get("id") or ""),
            )
        )

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
        f"azure_sql_managed_instance_encryption_"
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
