#!/usr/bin/env python3
"""Azure SQL Managed Instance backup retention, backup storage redundancy and failover groups."""

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
    get_optional,
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

logger = logging.getLogger("azure_sql_managed_instance_backups")

MINIMUM_RETENTION_DAYS = 7
ZONE_REDUNDANT_STORAGE = ("zone", "geozone")
GEO_REDUNDANT_STORAGE = ("geo", "geozone")
POLICY_NAME = "default"


def ltr_tier_on(duration) -> bool:
    return lower(duration) not in ("", "pt0s", "p0d", "p0w", "p0m", "p0y")


# --- projection: azure-mgmt models in, flat dicts out ---

def project_instance(instance) -> dict:
    return {
        "id": model_attr(instance, "id"),
        "name": model_attr(instance, "name"),
        "location": model_attr(instance, "location"),
        "state": model_attr(instance, "state"),
        "provisioning_state": model_attr(instance, "provisioning_state"),
        "pricing_model": model_attr(instance, "pricing_model"),
        "requested_backup_storage_redundancy": model_attr(
            instance, "requested_backup_storage_redundancy"
        ),
        "current_backup_storage_redundancy": model_attr(
            instance, "current_backup_storage_redundancy"
        ),
        "zone_redundant": model_attr(instance, "zone_redundant"),
    }


def project_ltr_policy(policy) -> dict:
    return {
        "weekly_retention": model_attr(policy, "weekly_retention"),
        "monthly_retention": model_attr(policy, "monthly_retention"),
        "yearly_retention": model_attr(policy, "yearly_retention"),
        "week_of_year": model_attr(policy, "week_of_year"),
    }


def project_failover_group(group) -> dict:
    endpoint = model_attr(group, "read_write_endpoint")
    return {
        "id": model_attr(group, "id"),
        "name": model_attr(group, "name"),
        "replication_role": model_attr(group, "replication_role"),
        "replication_state": model_attr(group, "replication_state"),
        "secondary_type": model_attr(group, "secondary_type"),
        "failover_policy": model_attr(endpoint, "failover_policy"),
        "failover_with_data_loss_grace_period_minutes": model_attr(
            endpoint, "failover_with_data_loss_grace_period_minutes"
        ),
        "managed_instance_pairs": [
            {
                "primary_managed_instance_id": model_attr(pair, "primary_managed_instance_id"),
                "partner_managed_instance_id": model_attr(pair, "partner_managed_instance_id"),
            }
            for pair in (model_attr(group, "managed_instance_pairs") or [])
        ],
        "partner_regions": [
            {
                "location": model_attr(region, "location"),
                "replication_role": model_attr(region, "replication_role"),
            }
            for region in (model_attr(group, "partner_regions") or [])
        ],
    }


# --- pure transforms (flat dicts in, evidence records out) ---

def database_record(database: dict, retention_days, policy_found, ltr: dict | None) -> dict:
    ltr = ltr or {}
    tiers = ("weekly_retention", "monthly_retention", "yearly_retention")
    return {
        **database,
        "short_term_retention_policy_found": policy_found,
        "short_term_retention_days": retention_days,
        "short_term_retention_at_least_7_days": (
            isinstance(retention_days, int) and retention_days >= MINIMUM_RETENTION_DAYS
        ),
        "long_term_retention": {
            **{tier: ltr.get(tier) for tier in tiers},
            "week_of_year": ltr.get("week_of_year"),
            "configured": any(ltr_tier_on(ltr.get(tier)) for tier in tiers),
        },
    }


def instance_ids_in(group: dict) -> set:
    ids = set()
    for pair in group.get("managed_instance_pairs") or []:
        for key in ("primary_managed_instance_id", "partner_managed_instance_id"):
            if pair.get(key):
                ids.add(pair[key].lower())
    return ids


def instance_record(
    instance: dict, databases: list[dict] | None, failover_groups: list[dict]
) -> dict:
    resource_id = instance.get("id")
    requested = instance.get("requested_backup_storage_redundancy")
    current = instance.get("current_backup_storage_redundancy")
    groups = [g["name"] for g in failover_groups if lower(resource_id) in instance_ids_in(g)]
    user_databases = [d for d in databases or [] if not d["is_system_database"]]
    return {
        **instance,
        "backup_storage_zone_redundant": lower(current) in ZONE_REDUNDANT_STORAGE,
        "backup_storage_geo_redundant": lower(current) in GEO_REDUNDANT_STORAGE,
        "backup_storage_redundancy_change_pending": bool(
            requested and current and lower(requested) != lower(current)
        ),
        "zone_redundant": bool(instance.get("zone_redundant") or False),
        "failover_groups": sorted(groups),
        "in_failover_group": bool(groups),
        "databases_collected": databases is not None,
        "databases": databases or [],
        "total_user_databases": len(user_databases),
        "databases_below_7_days": sum(
            1 for d in user_databases if d["short_term_retention_policy_found"]
            and not d["short_term_retention_at_least_7_days"]
        ),
    }


def summarize(instances: list[dict], failover_groups: list[dict]) -> dict:
    databases = [d for i in instances for d in i["databases"] if not d["is_system_database"]]
    redundancy: dict[str, int] = {}
    for i in instances:
        key = i.get("current_backup_storage_redundancy") or "unknown"
        redundancy[key] = redundancy.get(key, 0) + 1
    return {
        "total_managed_instances": len(instances),
        "total_user_databases": len(databases),
        "databases_retention_at_least_7_days": sum(
            1 for d in databases if d["short_term_retention_at_least_7_days"]
        ),
        "databases_retention_below_7_days": sum(i["databases_below_7_days"] for i in instances),
        "databases_missing_retention_policy": sum(
            1 for d in databases if d["short_term_retention_policy_found"] is False
        ),
        "databases_with_long_term_retention": sum(
            1 for d in databases if d["long_term_retention"]["configured"]
        ),
        "instances_by_current_backup_storage_redundancy": redundancy,
        "instances_backup_storage_zone_redundant": sum(
            1 for i in instances if i["backup_storage_zone_redundant"]
        ),
        "instances_stopped": sum(1 for i in instances if lower(i.get("state")) == "stopped"),
        "instances_zone_redundant": sum(1 for i in instances if i["zone_redundant"]),
        "instances_in_failover_group": sum(1 for i in instances if i["in_failover_group"]),
        "total_instance_failover_groups": len(failover_groups),
        "failover_groups_manual_policy": sum(
            1 for g in failover_groups if lower(g.get("failover_policy")) == "manual"
        ),
    }


# --- collection (lazy azure imports) ---

def collect(subscription_id, cred, collector: Collector) -> tuple[list[dict], list[dict]]:
    client = sql_client(subscription_id, cred, collector)
    if client is None:
        return [], []
    projected = list_instances(client, collector, project_instance)

    failover_groups: dict[str, dict] = {}
    for group_name, location in sorted({(i["resource_group"], i.get("location")) for i in projected}):
        if not location:
            continue
        for group in collector.guard(
            f"sql.instance_failover_groups.list_by_location ({group_name}, {location})",
            lambda: [
                project_failover_group(g)
                for g in client.instance_failover_groups.list_by_location(group_name, location)
            ],
            default=[],
        ):
            failover_groups[lower(group.get("id"))] = {
                **group,
                "resource_group": group_name,
                "location": location,
            }
    groups = sorted(failover_groups.values(), key=lambda g: g.get("id") or "")

    instances: list[dict] = []
    for instance in projected:
        group_name, name = instance["resource_group"], instance["name"]
        databases = list_databases(client, collector, instance)
        records = []
        for database in databases or []:
            db = database["name"]
            if database["is_system_database"]:
                records.append(database_record(database, None, None, None))
                continue
            policy, found = get_optional(
                collector,
                f"sql.managed_backup_short_term_retention_policies.get ({name}/{db})",
                lambda: client.managed_backup_short_term_retention_policies.get(
                    group_name, name, db, POLICY_NAME
                ),
            )
            ltr, _ = get_optional(
                collector,
                f"sql.managed_instance_long_term_retention_policies.get ({name}/{db})",
                lambda: project_ltr_policy(
                    client.managed_instance_long_term_retention_policies.get(
                        group_name, name, db, POLICY_NAME
                    )
                ),
            )
            records.append(database_record(database, model_attr(policy, "retention_days"), found, ltr))
        instances.append(
            instance_record(
                instance,
                None if databases is None else sorted(records, key=lambda d: d.get("id") or ""),
                groups,
            )
        )

    return sorted(instances, key=lambda i: i.get("id") or ""), groups


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
    groups: list[dict] = []
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
        instances, groups = collect(subscription_id, cred, collector)
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
            "instance_failover_groups": groups,
            "provider_registration_status": registration,
        },
        summary={**summarize(instances, groups), "provider_registration_status": registration},
    )

    filename = (
        f"azure_sql_managed_instance_backups_"
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
