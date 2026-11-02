#!/usr/bin/env python3
"""Azure SQL Managed Instance backup retention, backup storage redundancy, failover groups and failover history."""

import logging
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
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
    monitor_client,
    provider_registration_status,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    write_evidence,
)
from resource_exclusions import ResourceExclusions  # noqa: E402
from scope_exclusions import excluded_item  # noqa: E402
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

FAILOVER_DAYS_ENV = "AZURE_SQL_MI_FAILOVER_HISTORY_DAYS"
# The Activity Log keeps 90 days.
ACTIVITY_LOG_MAX_DAYS = 90
# The window starts this far inside retention, so its oldest edge is still served when a long paged read reaches it.
ACTIVITY_LOG_RETENTION_MARGIN = timedelta(hours=1)
ACTIVITY_LOG_MAX_EVENTS = 200_000
# operation -> (what failed over, whether data loss was allowed; None where that doesn't apply).
FAILOVER_OPERATIONS = {
    "microsoft.sql/locations/instancefailovergroups/failover/action": ("failover_group", False),
    "microsoft.sql/locations/instancefailovergroups/forcefailoverallowdataloss/action": ("failover_group", True),
    "microsoft.sql/managedinstances/failover/action": ("managed_instance", None),
}
FINAL_STATUSES = ("succeeded", "failed", "canceled")
_GROUP_ID = re.compile(r"/providers/microsoft\.sql/locations/([^/]+)/instancefailovergroups/([^/]+)", re.IGNORECASE)
_INSTANCE_ID = re.compile(r"/providers/microsoft\.sql/managedinstances/([^/]+)", re.IGNORECASE)


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


def _iso(value):
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return value


def project_event(event) -> dict:
    """Read an Activity Log `EventData`; of its claims only the identity type is kept."""
    claims = model_attr(event, "claims") or {}
    return {
        "operation": model_attr(model_attr(event, "operation_name"), "value"),
        "status": model_attr(model_attr(event, "status"), "value"),
        "caller": model_attr(event, "caller"),
        "caller_type": claims.get("idtyp") if isinstance(claims, dict) else None,
        "resource_id": model_attr(event, "resource_id"),
        "correlation_id": model_attr(event, "correlation_id"),
        "event_id": model_attr(event, "event_data_id"),
        "time": _iso(model_attr(event, "event_timestamp")),
    }


# --- pure transforms (flat dicts in, evidence records out) ---

def meets_minimum(retention_days, policy_found) -> bool | None:
    if policy_found is False:
        return False
    if policy_found is None or not isinstance(retention_days, int):
        return None
    return retention_days >= MINIMUM_RETENTION_DAYS


def database_record(
    database: dict, retention_days, policy_found, ltr: dict | None, ltr_found
) -> dict:
    ltr = ltr or {}
    tiers = ("weekly_retention", "monthly_retention", "yearly_retention")
    return {
        **database,
        "short_term_retention_policy_found": policy_found,
        "short_term_retention_days": retention_days,
        "short_term_retention_at_least_7_days": meets_minimum(retention_days, policy_found),
        "long_term_retention": {
            "policy_found": ltr_found,
            **{tier: ltr.get(tier) for tier in tiers},
            "week_of_year": ltr.get("week_of_year"),
            "configured": (
                None if ltr_found is None else any(ltr_tier_on(ltr.get(tier)) for tier in tiers)
            ),
        },
    }


def instance_ids_in(group: dict) -> set:
    ids = set()
    for pair in group.get("managed_instance_pairs") or []:
        for key in ("primary_managed_instance_id", "partner_managed_instance_id"):
            if pair.get(key):
                ids.add(pair[key].lower())
    return ids


def merge_failover_group_views(views: list[dict]) -> dict:
    """One record per group: Azure lists a group once from each region it spans, each with its own id."""
    unique = sorted({lower(v.get("id")): v for v in views}.values(), key=lambda v: v.get("id") or "")
    primary = next((v for v in unique if lower(v.get("replication_role")) == "primary"), unique[0])
    return {
        **primary,
        "regional_views": [
            {
                "id": v.get("id"),
                "resource_group": v.get("resource_group"),
                "location": v.get("location"),
                "replication_role": v.get("replication_role"),
            }
            for v in unique
        ],
    }


def instance_record(
    instance: dict,
    databases: list[dict] | None,
    failover_groups: list[dict],
    failover_groups_collected: bool,
) -> dict:
    resource_id = instance.get("id")
    requested = instance.get("requested_backup_storage_redundancy")
    current = instance.get("current_backup_storage_redundancy")
    groups = sorted({g["name"] for g in failover_groups if lower(resource_id) in instance_ids_in(g)})
    users = None if databases is None else [d for d in databases if not d["is_system_database"]]
    return {
        **instance,
        "backup_storage_zone_redundant": lower(current) in ZONE_REDUNDANT_STORAGE,
        "backup_storage_geo_redundant": lower(current) in GEO_REDUNDANT_STORAGE,
        "backup_storage_redundancy_change_pending": bool(
            requested and current and lower(requested) != lower(current)
        ),
        "zone_redundant": bool(instance.get("zone_redundant") or False),
        "failover_groups": groups,
        "in_failover_group": True if groups else (False if failover_groups_collected else None),
        "databases_collected": databases is not None,
        "databases": databases or [],
        "total_user_databases": None if users is None else len(users),
        "databases_below_7_days": None if users is None else sum(
            1 for d in users if d["short_term_retention_policy_found"]
            and d["short_term_retention_at_least_7_days"] is False
        ),
    }


def split_failover_groups(
    groups: list[dict], listed: set, excluded: list[dict]
) -> tuple[list[dict], list[dict]]:
    """A group follows its instances: it leaves scope only when every instance of it this run listed is excluded."""
    out = {lower(e["id"]): e for e in excluded}
    kept, dropped = [], []
    for group in groups:
        local = sorted(instance_ids_in(group) & listed)
        if local and all(i in out for i in local):
            entry = out[local[0]]
            dropped.append(excluded_item(
                "instance_failover_group", group.get("name"), entry["pattern"], "managed_instance_matched",
                id=group.get("id"), resource_group=group.get("resource_group"), location=group.get("location"),
                matched_id=entry["id"]))
        else:
            kept.append(group)
    return kept, dropped


def summarize(
    instances: list[dict], failover_groups: list[dict], failover_groups_collected: bool
) -> dict:
    databases = [d for i in instances for d in i["databases"] if not d["is_system_database"]]
    redundancy: dict[str, int] = {}
    for i in instances:
        key = i.get("current_backup_storage_redundancy") or "unknown"
        redundancy[key] = redundancy.get(key, 0) + 1
    all_listed = all(i["databases_collected"] for i in instances)
    return {
        "total_managed_instances": len(instances),
        "total_user_databases": len(databases) if all_listed else None,
        "databases_retention_at_least_7_days": sum(
            1 for d in databases if d["short_term_retention_at_least_7_days"] is True
        ),
        "databases_retention_below_7_days": sum(i["databases_below_7_days"] or 0 for i in instances),
        "databases_missing_retention_policy": sum(
            1 for d in databases if d["short_term_retention_policy_found"] is False
        ),
        "databases_retention_unknown": sum(
            1 for d in databases if d["short_term_retention_at_least_7_days"] is None
        ),
        "databases_with_long_term_retention": sum(
            1 for d in databases if d["long_term_retention"]["configured"] is True
        ),
        "databases_long_term_retention_unknown": sum(
            1 for d in databases if d["long_term_retention"]["configured"] is None
        ),
        "instances_by_current_backup_storage_redundancy": redundancy,
        "instances_backup_storage_zone_redundant": sum(
            1 for i in instances if i["backup_storage_zone_redundant"]
        ),
        "instances_stopped": sum(1 for i in instances if lower(i.get("state")) == "stopped"),
        "instances_zone_redundant": sum(1 for i in instances if i["zone_redundant"]),
        "instances_in_failover_group": sum(1 for i in instances if i["in_failover_group"] is True),
        "instances_failover_group_unknown": sum(1 for i in instances if i["in_failover_group"] is None),
        "total_instance_failover_groups": len(failover_groups) if failover_groups_collected else None,
        "failover_groups_manual_policy": sum(
            1 for g in failover_groups if lower(g.get("failover_policy")) == "manual"
        ) if failover_groups_collected else None,
    }


def _minutes(start, end) -> float | None:
    if not start or not end:
        return None
    begin, finish = (datetime.fromisoformat(str(t).replace("Z", "+00:00")) for t in (start, end))
    return round((finish - begin).total_seconds() / 60, 2)


def failover_target(resource_id) -> tuple:
    """(kind, failover group or instance name, the failover group's region in the id) for a failover event's resource."""
    group = _GROUP_ID.search(str(resource_id or ""))
    if group:
        return "failover_group", group.group(2), group.group(1)
    instance = _INSTANCE_ID.search(str(resource_id or ""))
    return ("managed_instance", instance.group(1), None) if instance else (None, None, None)


def failover_records(events: list[dict]) -> list[dict]:
    """One record per request (correlation id and target); a group failover is sent to the region that takes over."""
    grouped: dict = defaultdict(list)
    for event in events:
        if lower(event.get("operation")) not in FAILOVER_OPERATIONS:
            continue
        kind, name, _ = failover_target(event.get("resource_id"))
        grouped[(event.get("correlation_id") or event.get("event_id"), lower(event.get("operation")), lower(name))].append(event)
    records = []
    for (_, operation, _), group in grouped.items():
        group.sort(key=lambda e: e.get("time") or "")
        kind, data_loss = FAILOVER_OPERATIONS[operation]
        final = next((e for e in reversed(group) if lower(e.get("status")) in FINAL_STATUSES), None)
        requester = next((e for e in group if e.get("caller_type") or "@" in str(e.get("caller") or "")), group[0])
        _, name, location = failover_target(requester.get("resource_id"))
        status = (final or group[-1]).get("status")
        start, end = group[0].get("time"), (final or {}).get("time")
        records.append({
            "kind": kind,
            "operation": group[0].get("operation"),
            "allows_data_loss": data_loss,
            "resource_id": requester.get("resource_id"),
            "failover_group": name if kind == "failover_group" else None,
            "managed_instance": name if kind == "managed_instance" else None,
            "new_primary_location": location,
            "start_time": start,
            "end_time": end,
            "duration_minutes": _minutes(start, end),
            "status": status,
            "succeeded": lower(status) == "succeeded",
            "caller": requester.get("caller"),
            "caller_type": requester.get("caller_type"),
            "correlation_id": requester.get("correlation_id"),
        })
    return sorted(records, key=lambda r: r.get("start_time") or "", reverse=True)


def attach_failovers(records: list[dict] | None, instances: list[dict], groups: list[dict], excluded: list[dict],
                     exclusions: ResourceExclusions | None) -> tuple[list[dict] | None, list[dict]]:
    """(in-scope failovers joined to their target, excluded entries); a failover follows the group or instance it moved,
    and one whose target isn't listed any more leaves only when a pattern matches its resource id."""
    if records is None:
        return None, []
    out_entries = [e for e in excluded if e["kind"] == "instance_failover_group"]
    by_group = {key: g for g in groups for key in _group_keys(g)}
    out_groups = {key: e for e in out_entries for key in _group_keys(e)}
    by_instance = {lower(i.get("id")): i for i in instances}
    out_instances = {lower(e.get("id")): e for e in excluded if e["kind"] == "managed_instance"}
    kept, dropped = [], []
    for record in records:
        if record["kind"] == "failover_group":
            key = (lower(resource_group_from_id(record["resource_id"])), lower(record["failover_group"]))
            target, entry = by_group.get(key), out_groups.get(key)
            if target is None and entry is None:
                # A resource group no listed view names: the name decides, but only when one group has it.
                same = ([(g, None) for g in groups if lower(g.get("name")) == key[1]]
                        + [(None, e) for e in out_entries if lower(e.get("name")) == key[1]])
                if len(same) == 1:
                    target, entry = same[0]
        else:
            match = re.match(r".*?/providers/microsoft\.sql/managedinstances/[^/]+", lower(record["resource_id"]))
            instance_id = match.group(0) if match else lower(record["resource_id"])
            target, entry = by_instance.get(instance_id), out_instances.get(instance_id)
        pattern, reason = (entry["pattern"], f"{record['kind']}_excluded") if entry else (None, None)
        if target is None and entry is None and exclusions:
            pattern, reason = exclusions.match(record["resource_id"]), "resource_matched"
        if pattern:
            dropped.append(excluded_item(
                "failover", record["failover_group"] or record["managed_instance"], pattern, reason,
                id=record["resource_id"], resource_group=resource_group_from_id(record["resource_id"]),
                location=record["new_primary_location"], correlation_id=record["correlation_id"]))
            continue
        is_group = record["kind"] == "failover_group"
        kept.append({
            **record,
            "target_found": target is not None,
            "failover_group_id": (target or {}).get("id") if is_group else None,
            "failover_policy": (target or {}).get("failover_policy") if is_group else None,
        })
    return kept, dropped


def _group_keys(group: dict) -> set:
    """(resource group, name) for every region Azure lists a failover group from; a failover is sent to one of them."""
    views = group.get("regional_views") or [group]
    return {(lower(v.get("resource_group") or resource_group_from_id(v.get("id"))), lower(group.get("name")))
            for v in views}


def group_failover_fields(group: dict, failovers: list[dict] | None) -> dict:
    """A failover group's failovers in the window; null when the history wasn't read in full."""
    if failovers is None:
        return {**group, "failovers_in_window": None, "succeeded_failovers_in_window": None,
                "latest_succeeded_failover_time": None}
    mine = [f for f in failovers if f.get("failover_group_id") and lower(f["failover_group_id"]) == lower(group.get("id"))]
    succeeded = [f for f in mine if f["succeeded"]]
    return {
        **group,
        "failovers_in_window": len(mine),
        "succeeded_failovers_in_window": len(succeeded),
        "latest_succeeded_failover_time": max((f["end_time"] or f["start_time"] for f in succeeded), default=None),
    }


def _failover_group_key(failover: dict):
    """The group a failover moved: its listed id, else the resource group and name, since a name is unique per DNS zone."""
    if failover.get("failover_group_id"):
        return lower(failover["failover_group_id"])
    return lower(resource_group_from_id(failover.get("resource_id"))), lower(failover.get("failover_group"))


def summarize_failovers(failovers: list[dict] | None, window: dict, now: datetime) -> dict:
    """Failover counts over the window; all but the window fields are null when the history wasn't read in full."""
    read = failovers is not None
    failovers = failovers or []
    succeeded = [f for f in failovers if f["succeeded"]]
    latest = max((f["end_time"] or f["start_time"] for f in succeeded), default=None)
    durations = [f["duration_minutes"] for f in succeeded if f["duration_minutes"] is not None]
    fields = {
        "total_failovers": len(failovers),
        "failover_group_failovers": sum(1 for f in failovers if f["kind"] == "failover_group"),
        "forced_failovers_allowing_data_loss": sum(1 for f in failovers if f["allows_data_loss"] is True),
        "managed_instance_failovers": sum(1 for f in failovers if f["kind"] == "managed_instance"),
        "succeeded_failovers": len(succeeded),
        "failed_failovers": sum(1 for f in failovers if lower(f["status"]) == "failed"),
        "failover_groups_with_succeeded_failover": len(
            {_failover_group_key(f) for f in succeeded if f["kind"] == "failover_group"}),
        "latest_succeeded_failover_time": latest,
        "days_since_latest_succeeded_failover": round(
            (now - datetime.fromisoformat(latest.replace("Z", "+00:00"))).total_seconds() / 86400, 1) if latest else None,
        "longest_succeeded_failover_minutes": max(durations) if durations else None,
    }
    return {
        "failover_history_days": window.get("days"),
        "failover_history_read": read,
        **{k: (v if read else None) for k, v in fields.items()},
    }


# --- collection (lazy azure imports) ---

def failover_history_days() -> int:
    raw = os.environ.get(FAILOVER_DAYS_ENV) or str(ACTIVITY_LOG_MAX_DAYS)
    try:
        days = int(raw)
    except ValueError:
        logger.warning("%s=%r is not a whole number; using %d", FAILOVER_DAYS_ENV, raw, ACTIVITY_LOG_MAX_DAYS)
        return ACTIVITY_LOG_MAX_DAYS
    if not 1 <= days <= ACTIVITY_LOG_MAX_DAYS:
        logger.warning("%s=%d is outside 1-%d; clamped", FAILOVER_DAYS_ENV, days, ACTIVITY_LOG_MAX_DAYS)
    return min(max(days, 1), ACTIVITY_LOG_MAX_DAYS)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def read_failover_history(subscription_id, cred, collector: Collector, days: int, now: datetime):
    """Microsoft.Sql failover events in [now - days, now]; events is None on a failed or cut read, which would undercount."""
    start = now - min(timedelta(days=days), timedelta(days=ACTIVITY_LOG_MAX_DAYS) - ACTIVITY_LOG_RETENTION_MARGIN)
    window: dict = {"days": days, "start_time": _iso(start), "end_time": _iso(now), "complete": False,
                    "cut_reason": None, "events_read": 0}
    monitor = collector.guard("monitor.MonitorManagementClient (init)", lambda: monitor_client(subscription_id, cred))
    if monitor is None:
        window["cut_reason"] = "read_failed"
        return None, window
    # An explicit end time: with only a start the Activity Log returns just a few hours.
    query = (f"eventTimestamp ge '{start:%Y-%m-%dT%H:%M:%SZ}' and eventTimestamp le '{now:%Y-%m-%dT%H:%M:%SZ}' "
             "and resourceProvider eq 'Microsoft.Sql'")
    events = []
    try:
        for event in monitor.activity_logs.list(filter=query):
            if window["events_read"] >= ACTIVITY_LOG_MAX_EVENTS:
                window["cut_reason"] = "max_events"
                logger.warning("Activity Log read stopped at %d events; failover counts read null", ACTIVITY_LOG_MAX_EVENTS)
                return None, window
            window["events_read"] += 1
            projected = project_event(event)
            if lower(projected["operation"]) in FAILOVER_OPERATIONS:
                events.append(projected)
    except Exception as exc:  # noqa: BLE001 — record it; the counts are unknown, not zero
        collector.record("monitor.activity_logs.list", exc)
        window["cut_reason"] = "read_failed"
        return None, window
    window["complete"] = True
    return events, window


def list_failover_groups(client, group_name: str, location: str) -> list[dict]:
    return [project_failover_group(g) for g in client.instance_failover_groups.list_by_location(group_name, location)]


def collect(subscription_id, cred, collector: Collector, exclusions: ResourceExclusions | None = None,
            excluded: list | None = None) -> tuple[list[dict], list[dict], set]:
    """Failover groups are listed and matched across every instance; excluded instances get no database reads."""
    client = sql_client(subscription_id, cred, collector)
    if client is None:
        return [], [], set()
    projected = list_instances(client, collector, project_instance)
    in_scope, out = exclusions.split(projected, "managed_instance") if exclusions else (projected, [])
    in_scope_pairs = {(i["resource_group"], i.get("location")) for i in in_scope}

    views: dict[tuple, list[dict]] = {}
    unlisted: set = set()
    for group_name, location in sorted({(i["resource_group"], i.get("location")) for i in projected}):
        operation = f"sql.instance_failover_groups.list_by_location ({group_name}, {location})"
        listed = None
        if location and (group_name, location) in in_scope_pairs:
            listed = collector.guard(operation, lambda: list_failover_groups(client, group_name, location))
        elif location:
            # Only excluded instances here: a failed list is a warning and leaves no in-scope count unknown.
            try:
                listed = list_failover_groups(client, group_name, location)
            except Exception as exc:  # noqa: BLE001
                logger.warning("%s failed, but every instance there is excluded: %s", operation, exc)
        if listed is None:
            if (group_name, location) in in_scope_pairs:
                unlisted.add((group_name, location))
            continue
        for group in listed:
            key = (lower(group.get("name")), tuple(sorted(instance_ids_in(group))))
            views.setdefault(key, []).append(
                {**group, "resource_group": group_name, "location": location}
            )
    groups = sorted(
        (merge_failover_group_views(v) for v in views.values()), key=lambda g: g.get("id") or ""
    )

    instances: list[dict] = []
    for instance in in_scope:
        group_name, name = instance["resource_group"], instance["name"]
        databases = list_databases(client, collector, instance)
        records = []
        for database in databases or []:
            db = database["name"]
            if database["is_system_database"]:
                records.append(database_record(database, None, None, None, None))
                continue
            policy, found = get_optional(
                collector,
                f"sql.managed_backup_short_term_retention_policies.get ({name}/{db})",
                lambda: client.managed_backup_short_term_retention_policies.get(
                    group_name, name, db, POLICY_NAME
                ),
            )
            ltr, ltr_found = get_optional(
                collector,
                f"sql.managed_instance_long_term_retention_policies.get ({name}/{db})",
                lambda: project_ltr_policy(
                    client.managed_instance_long_term_retention_policies.get(
                        group_name, name, db, POLICY_NAME
                    )
                ),
            )
            records.append(
                database_record(database, model_attr(policy, "retention_days"), found, ltr, ltr_found)
            )
        instances.append(
            instance_record(
                instance,
                None if databases is None else sorted(records, key=lambda d: d.get("id") or ""),
                groups,
                (group_name, instance.get("location")) not in unlisted,
            )
        )

    out.sort(key=lambda e: e["id"] or "")
    groups, dropped = split_failover_groups(groups, {lower(i.get("id")) for i in projected}, out)
    if excluded is not None:
        excluded += out + dropped
    return sorted(instances, key=lambda i: i.get("id") or ""), groups, unlisted


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
    unlisted: set = set()
    excluded: list[dict] = []
    exclusions = ResourceExclusions.from_env()
    registration = REGISTRATION_UNKNOWN
    now = utc_now()
    events: list[dict] | None = None
    window: dict = {"days": failover_history_days(), "complete": False, "cut_reason": "not_read"}
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
        instances, groups, unlisted = collect(subscription_id, cred, collector, exclusions, excluded)
        events, window = read_failover_history(subscription_id, cred, collector, window["days"], now)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    exclusions.record_invalid(collector)
    failovers, out = attach_failovers(
        None if events is None else failover_records(events), instances, groups, excluded, exclusions)
    excluded += out
    groups = [group_failover_fields(g, failovers) for g in groups]
    exclusions.warn_unmatched(logger)

    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "managed_instances": instances,
            "instance_failover_groups": groups,
            "failovers": failovers,
            "failover_history_window": window,
            "provider_registration_status": registration,
            "excluded": excluded,
        },
        summary={
            **summarize(instances, groups, not unlisted),
            **summarize_failovers(failovers, window, now),
            "provider_registration_status": registration,
            **exclusions.summary(excluded, ("managed_instance", "instance_failover_group", "failover"), {
                "managed_instances": len(instances), "instance_failover_groups": len(groups),
                "failovers": None if failovers is None else len(failovers)}),
        },
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
