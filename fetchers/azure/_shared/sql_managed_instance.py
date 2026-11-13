"""Shared reads for the Azure SQL Managed Instance fetchers."""

from __future__ import annotations

from typing import Callable, Optional

from azure_common import (
    Collector,
    arm_client_kwargs,
    model_attr,
    resource_group_from_id,
)

SYSTEM_DATABASES = ("master", "model", "msdb", "tempdb")


def lower(value) -> str:
    return str(value or "").lower()


def sql_client(subscription_id, cred, collector: Collector):
    def _client():
        from azure.mgmt.sql import SqlManagementClient  # lazy

        return SqlManagementClient(
            credential=cred, subscription_id=subscription_id, **arm_client_kwargs()
        )

    return collector.guard("sql.SqlManagementClient (init)", _client)


def list_instances(client, collector: Collector, project: Callable) -> list[dict]:
    """Every instance, projected, with `resource_group`; one without a group is recorded and dropped."""
    projected = collector.guard(
        "sql.managed_instances.list",
        lambda: [project(i) for i in client.managed_instances.list()],
        default=[],
    )
    instances = []
    for instance in projected:
        group = resource_group_from_id(instance.get("id"))
        if not group or not instance.get("name"):
            collector.record(
                "sql.managed_instances.list",
                RuntimeError(f"managed instance {instance.get('name')!r} has no resource group in its id"),
            )
            continue
        instances.append({**instance, "resource_group": group})
    return instances


def project_database(database) -> dict:
    name = model_attr(database, "name")
    return {
        "id": model_attr(database, "id"),
        "name": name,
        "status": model_attr(database, "status"),
        "creation_date": model_attr(database, "creation_date"),
        "earliest_restore_point": model_attr(database, "earliest_restore_point"),
        "failover_group_id": model_attr(database, "failover_group_id"),
        "is_system_database": lower(name) in SYSTEM_DATABASES,
    }


def list_databases(client, collector: Collector, instance: dict) -> Optional[list[dict]]:
    """None when the list failed (recorded), so "no databases" and "not collected" differ."""
    group, name = instance["resource_group"], instance["name"]
    return collector.guard(
        f"sql.managed_databases.list_by_instance ({name})",
        lambda: [project_database(d) for d in client.managed_databases.list_by_instance(group, name)],
    )
