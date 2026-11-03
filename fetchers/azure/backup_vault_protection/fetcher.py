#!/usr/bin/env python3
"""Azure Backup vaults (Microsoft.DataProtection): each vault's own protection settings, its policies' schedule and retention, and whether every backup instance has a recent recovery point."""

import logging
import os
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    NOT_REGISTERED,
    REGISTERED,
    REGISTRATION_UNKNOWN,
    Collector,
    arm_id_key,
    basename,
    coverage_percentage,
    resource_group_from_id,
    sorted_counts,
)
from azure_rest import ArmError, int_config, parse_time, run_subscription  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402

NAME = "azure_backup_vault_protection"
logger = logging.getLogger(NAME)

NAMESPACE = "Microsoft.DataProtection"
PROVIDERS_API = "2021-04-01"
# The newest stable version this projection was written against. A cloud that does not
# list it (Azure Government lags) gets the newest stable version it does list below it.
PREFERRED_API = "2025-07-01"
WORKERS = 4

RETENTION_THRESHOLD_ENV = "AZURE_BACKUP_RETENTION_THRESHOLD_DAYS"
WINDOW_ENV = "AZURE_BACKUP_RECOVERY_POINT_WINDOW_HOURS"
LOOKBACK_ENV = "AZURE_BACKUP_RECOVERY_POINT_LOOKBACK_DAYS"
RPO_ENV = "AZURE_BACKUP_RPO_HOURS"
DEFAULT_RETENTION_THRESHOLD_DAYS = 30
DEFAULT_WINDOW_HOURS = 48
DEFAULT_LOOKBACK_DAYS = 35

# Compared case-folded: the service spells these in mixed case.
PROTECTED_STATES = frozenset({"protectionconfigured"})
ERROR_STATES = frozenset({"protectionerror", "configuringprotectionfailed"})
SOFT_DELETE_ON = frozenset({"on", "alwayson"})
IMMUTABLE_STATES = frozenset({"unlocked", "locked"})
VAULT_STORE = "vaultstore"
OPERATIONAL_STORE = "operationalstore"
# The wire value, plus the CLI's alias for it.
BLOB_DATASOURCE_TYPES = frozenset({"microsoft.storage/storageaccounts/blobservices", "azureblob"})

RECOVERY_POINTS_READ = "read"
RECOVERY_POINTS_NOT_APPLICABLE = "not_applicable"
RECOVERY_POINTS_ERROR = "error"

# ISO 8601 durations: P1W, P30D, P1Y, PT4H, P1DT12H. Months and years are approximate by
# design (30 and 365 days); the raw string is kept beside every converted number.
_DURATION = re.compile(
    r"^P(?:(?P<y>\d+)Y)?(?:(?P<mo>\d+)M)?(?:(?P<w>\d+)W)?(?:(?P<d>\d+)D)?"
    r"(?:T(?:(?P<h>\d+)H)?(?:(?P<mi>\d+)M)?(?:(?P<s>\d+(?:\.\d+)?)S)?)?$"
)


# --- pure transforms ---

def duration_hours(value: Any) -> Optional[float]:
    """Hours in an ISO 8601 duration; None when it cannot be read."""
    match = _DURATION.match(str(value or "").strip().upper())
    if not match or not any(match.groupdict().values()):
        return None
    part = {k: float(v or 0) for k, v in match.groupdict().items()}
    days = part["y"] * 365 + part["mo"] * 30 + part["w"] * 7 + part["d"]
    return days * 24 + part["h"] + part["mi"] / 60 + part["s"] / 3600


def duration_days(value: Any) -> Optional[int]:
    hours = duration_hours(value)
    return None if hours is None else int(hours // 24)


def interval_hours(repeating: Any) -> Optional[float]:
    """Hours between backups from a repeating interval such as R/2024-01-01T00:00:00Z/P1D."""
    parts = str(repeating or "").split("/")
    return duration_hours(parts[-1]) if len(parts) >= 2 else None


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _data_store(obj: Any) -> Optional[str]:
    return (obj or {}).get("dataStoreType") if isinstance(obj, dict) else None


def policy_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    backup_rules, retention_rules = [], []
    for rule in props.get("policyRules") or []:
        kind = _lower(rule.get("objectType"))
        if kind == "azurebackuprule":
            trigger = rule.get("trigger") or {}
            schedule = trigger.get("schedule") or {}
            intervals = [i for i in (schedule.get("repeatingTimeIntervals") or []) if i]
            hours = [h for h in (interval_hours(i) for i in intervals) if h]
            backup_rules.append({
                "name": rule.get("name"),
                "backup_type": (rule.get("backupParameters") or {}).get("backupType"),
                "data_store": _data_store(rule.get("dataStore")),
                "trigger_type": trigger.get("objectType"),
                "schedule_intervals": intervals,
                "time_zone": schedule.get("timeZone"),
                "interval_hours": min(hours) if hours else None,
            })
        elif kind == "azureretentionrule":
            lifecycles = []
            for cycle in rule.get("lifecycles") or []:
                delete_after = (cycle.get("deleteAfter") or {}).get("duration")
                lifecycles.append({
                    "source_data_store": _data_store(cycle.get("sourceDataStore")),
                    "delete_after": delete_after,
                    "delete_after_days": duration_days(delete_after),
                    "copies_to": [
                        _data_store(c.get("dataStore")) for c in (cycle.get("targetDataStoreCopySettings") or [])
                    ],
                })
            retention_rules.append({"name": rule.get("name"), "is_default": bool(rule.get("isDefault")),
                                    "lifecycles": lifecycles})
    days = [c["delete_after_days"] for r in retention_rules for c in r["lifecycles"] if c["delete_after_days"] is not None]
    default_days = [c["delete_after_days"] for r in retention_rules if r["is_default"]
                    for c in r["lifecycles"] if c["delete_after_days"] is not None]
    hours = [r["interval_hours"] for r in backup_rules if r["interval_hours"]]
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "datasource_types": list(props.get("datasourceTypes") or []),
        "backup_rules": backup_rules,
        "retention_rules": retention_rules,
        "vaulted": any(_lower(r["data_store"]) == VAULT_STORE for r in backup_rules),
        "backup_interval_hours": min(hours) if hours else None,
        "default_retention_days": max(default_days) if default_days else None,
        "max_retention_days": max(days) if days else None,
    }


def with_threshold(policy: Dict[str, Any], threshold_days: int) -> Dict[str, Any]:
    days = policy["max_retention_days"]
    return {**policy, "retention_threshold_days": threshold_days,
            "meets_retention_threshold": days is not None and days >= threshold_days}


def _error(detail: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(detail, dict) or not (detail.get("code") or detail.get("message")):
        return None
    return {"code": detail.get("code"), "message": detail.get("message"),
            "recommended_action": detail.get("recommendedAction")}


def instance_record(raw: Dict[str, Any], policies_by_id: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    source = props.get("dataSourceInfo") or {}
    status = props.get("protectionStatus") or {}
    policy_id = (props.get("policyInfo") or {}).get("policyId")
    policy = policies_by_id.get(arm_id_key(policy_id)) or {}
    state = _lower(props.get("currentProtectionState")) or _lower(status.get("status"))
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "friendly_name": props.get("friendlyName"),
        "datasource_type": source.get("datasourceType"),
        "datasource_resource_id": source.get("resourceID"),
        "datasource_resource_type": source.get("resourceType"),
        "datasource_resource_name": source.get("resourceName"),
        "datasource_location": source.get("resourceLocation") or None,
        "policy_id": policy_id,
        "policy_name": policy.get("name") or basename(policy_id),
        "policy_vaulted": policy.get("vaulted"),
        "policy_backup_interval_hours": policy.get("backup_interval_hours"),
        "policy_max_retention_days": policy.get("max_retention_days"),
        # Null, not false, when the policy was not read: an unread policy is not a short one.
        "meets_retention_threshold": policy.get("meets_retention_threshold"),
        "protection_status": status.get("status"),
        "current_protection_state": props.get("currentProtectionState"),
        "protected": state in PROTECTED_STATES,
        "protection_error": _error(props.get("protectionErrorDetails")) or _error(status.get("errorDetails")),
        "provisioning_state": props.get("provisioningState"),
    }


def recovery_points_applicable(instance: Dict[str, Any]) -> bool:
    """Operational (continuous) blob backup restores to a point in time and lists no recovery points."""
    blob = any(_lower(instance.get(k)) in BLOB_DATASOURCE_TYPES for k in ("datasource_type", "datasource_resource_type"))
    return not (blob and instance.get("policy_vaulted") is False)


def recovery_point_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    return {
        "id": raw.get("id"),
        "recovery_point_time": props.get("recoveryPointTime"),
        "recovery_point_type": props.get("recoveryPointType"),
        "recovery_point_state": props.get("recoveryPointState"),
        "expiry_time": props.get("expiryTime"),
        "data_stores": sorted({str(d.get("type")) for d in (props.get("recoveryPointDataStoresDetails") or [])
                               if isinstance(d, dict) and d.get("type")}),
    }


def with_recovery_points(instance: Dict[str, Any], status: str, points: Optional[List[Dict[str, Any]]],
                         settings: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    """The instance with its newest recovery point judged against the window, its policy's interval and the RPO."""
    newest, age, count = None, None, None
    if status == RECOVERY_POINTS_READ:
        timed = [(parse_time(p["recovery_point_time"]), p) for p in points or []]
        timed = [(t, p) for t, p in timed if t is not None]
        cutoff = now - timedelta(hours=settings["window_hours"])
        count = sum(1 for t, _ in timed if t >= cutoff)
        if timed:
            when, newest = max(timed, key=lambda tp: tp[0])
            age = round((now - when).total_seconds() / 3600, 1)
    read = status == RECOVERY_POINTS_READ
    interval = instance.get("policy_backup_interval_hours")
    # Overdue can only be judged when the lookback reaches back twice the interval.
    judge_overdue = bool(interval) and 2 * interval <= settings["lookback_days"] * 24
    rpo = settings.get("rpo_hours")
    return {
        **instance,
        "recovery_points_status": status,
        "recovery_points_in_window": count,
        "latest_recovery_point": newest,
        "latest_recovery_point_age_hours": age,
        # Within the window means a usable point exists; overdue means at least one scheduled
        # backup has been missed, judged by the policy's own interval.
        "backed_up_in_window": (age is not None and age <= settings["window_hours"]) if read else None,
        "recovery_point_overdue": (age is None or age > 2 * interval) if read and judge_overdue else None,
        "meets_recovery_point_objective": (age is not None and age <= rpo) if read and rpo else None,
    }


def vault_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    security = props.get("securitySettings") or {}
    soft_delete = security.get("softDeleteSettings") or {}
    immutability = security.get("immutabilitySettings") or {}
    features = props.get("featureSettings") or {}
    stores = [{"datastore_type": s.get("datastoreType"), "type": s.get("type")}
              for s in (props.get("storageSettings") or []) if isinstance(s, dict)]
    vault_store = next((s["type"] for s in stores if _lower(s["datastore_type"]) == VAULT_STORE), None)
    crr = _lower((features.get("crossRegionRestoreSettings") or {}).get("state"))
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "location": raw.get("location"),
        "resource_group": resource_group_from_id(raw.get("id")),
        "identity_type": (raw.get("identity") or {}).get("type"),
        "provisioning_state": props.get("provisioningState"),
        "storage_settings": stores,
        "vault_store_redundancy": vault_store,
        "soft_delete_state": soft_delete.get("state"),
        "soft_delete_enabled": _lower(soft_delete.get("state")) in SOFT_DELETE_ON,
        "soft_delete_retention_days": soft_delete.get("retentionDurationInDays"),
        "immutability_state": immutability.get("state"),
        "immutability_enabled": _lower(immutability.get("state")) in IMMUTABLE_STATES,
        "cross_region_restore": (features.get("crossRegionRestoreSettings") or {}).get("state"),
        "cross_region_restore_enabled": crr == "enabled",
        "cross_subscription_restore": (features.get("crossSubscriptionRestoreSettings") or {}).get("state"),
        "resource_guard_protected": bool(props.get("isVaultProtectedByResourceGuard")),
        "replicated_regions": list(props.get("replicatedRegions") or []),
        "bcdr_security_level": props.get("bcdrSecurityLevel"),
        "secure_score": props.get("secureScore"),
        "backup_policies": [],
        "backup_instances": [],
        "policies_read": None,
        "instances_read": None,
        "total_backup_policies": None,
        "total_backup_instances": None,
    }


def _flag(values: List[Optional[bool]]) -> Optional[bool]:
    """True when every value is true, false when any is false, null when none decided or there are no values."""
    if not values or any(v is None for v in values):
        return False if any(v is False for v in values) else None
    return all(values)


def summarize(vaults: List[Dict[str, Any]], settings: Dict[str, Any]) -> Dict[str, Any]:
    policies = [p for v in vaults for p in v["backup_policies"]]
    instances = [i for v in vaults for i in v["backup_instances"]]
    read = [i for i in instances if i["recovery_points_status"] == RECOVERY_POINTS_READ]
    ages = [i["latest_recovery_point_age_hours"] for i in read if i["latest_recovery_point_age_hours"] is not None]
    adequate = sum(1 for i in instances if i["meets_retention_threshold"] is True)
    applicable = [i for i in instances if i["recovery_points_status"] != RECOVERY_POINTS_NOT_APPLICABLE]
    rpo = settings.get("rpo_hours")
    # A vault whose instance list failed may protect anything, so vault-level verdicts go null.
    instances_listed = all(v["instances_read"] for v in vaults)
    all_backed_up = _flag([i["backed_up_in_window"] for i in applicable]) if instances_listed else None
    all_rpo = _flag([i["meets_recovery_point_objective"] for i in applicable]) if instances_listed else None
    return {
        "total_backup_vaults": len(vaults),
        "vaults_instances_listed": instances_listed,
        "vaults_with_backup_instances": sum(1 for v in vaults if v["total_backup_instances"]) if instances_listed else None,
        "vaults_without_backup_instances": sum(
            1 for v in vaults if v["total_backup_instances"] == 0) if instances_listed else None,
        "vaults_by_vault_store_redundancy": sorted_counts(Counter(str(v["vault_store_redundancy"]) for v in vaults)),
        "soft_delete_enabled_vaults": sum(1 for v in vaults if v["soft_delete_enabled"]),
        "immutability_enabled_vaults": sum(1 for v in vaults if v["immutability_enabled"]),
        "cross_region_restore_vaults": sum(1 for v in vaults if v["cross_region_restore_enabled"]),
        "resource_guard_protected_vaults": sum(1 for v in vaults if v["resource_guard_protected"]),
        "total_backup_policies": len(policies),
        "retention_threshold_days": settings["retention_threshold_days"],
        "policies_meeting_retention_threshold": sum(1 for p in policies if p["meets_retention_threshold"]),
        "policies_without_readable_retention": sum(1 for p in policies if p["max_retention_days"] is None),
        "total_backup_instances": len(instances),
        "backup_instances_by_datasource_type": sorted_counts(Counter(str(i["datasource_type"]) for i in instances)),
        "backup_instances_by_protection_state": sorted_counts(
            Counter(str(i["current_protection_state"] or i["protection_status"]) for i in instances)),
        "backup_instances_protected": sum(1 for i in instances if i["protected"]),
        "backup_instances_in_error": sum(
            1 for i in instances if _lower(i["current_protection_state"]) in ERROR_STATES or i["protection_error"]),
        "backup_instances_without_policy": sum(1 for i in instances if not i["policy_id"]),
        "backup_instances_meeting_retention_threshold": adequate,
        "backup_instances_retention_unknown": sum(1 for i in instances if i["meets_retention_threshold"] is None),
        "retention_threshold_percentage": coverage_percentage(adequate, len(instances)),
        "recovery_point_window_hours": settings["window_hours"],
        "recovery_point_lookback_days": settings["lookback_days"],
        "backup_instances_recovery_points_read": len(read),
        "backup_instances_recovery_points_not_applicable": len(instances) - len(applicable),
        "backup_instances_recovery_points_unknown": sum(
            1 for i in applicable if i["recovery_points_status"] != RECOVERY_POINTS_READ),
        "backup_instances_backed_up_in_window": sum(1 for i in read if i["backed_up_in_window"]),
        "backup_instances_not_backed_up_in_window": sum(1 for i in read if i["backed_up_in_window"] is False),
        "backup_instances_without_recovery_point": sum(1 for i in read if i["latest_recovery_point"] is None),
        "backup_instances_overdue": sum(1 for i in read if i["recovery_point_overdue"]),
        "max_latest_recovery_point_age_hours": max(ages) if ages else None,
        "all_backup_instances_backed_up": all_backed_up,
        "recovery_point_objective_hours": rpo,
        "backup_instances_meeting_recovery_point_objective": sum(
            1 for i in read if i["meets_recovery_point_objective"]) if rpo else None,
        "backup_instances_missing_recovery_point_objective": sum(
            1 for i in read if i["meets_recovery_point_objective"] is False) if rpo else None,
        "all_backup_instances_meet_recovery_point_objective": all_rpo if rpo else None,
    }


def settings_from_env(collector: Optional[Collector] = None) -> Dict[str, Any]:
    """The settings, with a bad_config failure recorded for an RPO that is not a positive integer or a lookback too
    short for the window or the RPO (which would read every instance as not backed up)."""
    raw_rpo = (os.environ.get(RPO_ENV) or "").strip()
    rpo = int(raw_rpo) if raw_rpo.isdigit() and int(raw_rpo) > 0 else None
    settings = {
        "retention_threshold_days": int_config(RETENTION_THRESHOLD_ENV, DEFAULT_RETENTION_THRESHOLD_DAYS),
        "window_hours": int_config(WINDOW_ENV, DEFAULT_WINDOW_HOURS),
        "lookback_days": int_config(LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS),
        "rpo_hours": rpo,
    }
    if collector is not None:
        if raw_rpo and rpo is None:
            collector.record(f"config {RPO_ENV}", ValueError(f"{RPO_ENV}={raw_rpo!r} is not a positive integer"))
        lookback_hours = settings["lookback_days"] * 24
        for label, hours in (("window", settings["window_hours"]), ("recovery point objective", rpo or 0)):
            if hours > lookback_hours:
                collector.record(f"config {LOOKBACK_ENV}", ValueError(
                    f"config conflict: the {label} ({hours} hours) is longer than the recovery point lookback "
                    f"({settings['lookback_days']} days), so no instance could count as backed up"))
    return settings


def choose_api_version(listed: List[str], preferred: str = PREFERRED_API) -> str:
    """The newest stable version at or below `preferred` that the cloud lists; `preferred` when it lists none."""
    stable = sorted(v for v in listed if "preview" not in v.lower() and v <= preferred)
    return stable[-1] if stable else preferred


# --- collection ---

def read_provider(client, subscription_id: str, collector: Collector) -> Dict[str, Any]:
    """Registration state and the API version to use, from one providers GET."""
    body = collector.guard(
        f"providers.get({NAMESPACE})",
        lambda: client.get(f"/subscriptions/{subscription_id}/providers/{NAMESPACE}", PROVIDERS_API),
    )
    if body is None:
        return {"registration": REGISTRATION_UNKNOWN, "api_version": PREFERRED_API, "api_versions_listed": None}
    versions: List[str] = []
    for rt in body.get("resourceTypes") or []:
        if _lower(rt.get("resourceType")) == "backupvaults":
            versions = list(rt.get("apiVersions") or [])
    state = _lower(body.get("registrationState"))
    return {
        "registration": REGISTERED if state == "registered" else NOT_REGISTERED,
        "api_version": choose_api_version(versions),
        "api_versions_listed": sorted(versions),
    }


def _filter(now: datetime, lookback_days: int) -> str:
    start = (now - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"startDate eq '{start}' and endDate eq '{end}'"


def read_recovery_points(client, api: str, instance: Dict[str, Any], settings: Dict[str, Any], now: datetime,
                         collector: Collector) -> Dict[str, Any]:
    if not recovery_points_applicable(instance):
        return with_recovery_points(instance, RECOVERY_POINTS_NOT_APPLICABLE, None, settings, now)
    path = f"{instance['id']}/recoveryPoints"
    try:
        try:
            raw = client.list(path, api, {"$filter": _filter(now, settings["lookback_days"])})
        except ArmError as exc:
            if exc.status != 400:
                raise
            # A cloud that rejects the date filter: read every recovery point instead.
            logger.warning("recovery point filter refused for %s (%s); listing all", instance["id"], exc)
            raw = client.list(path, api)
        points = [recovery_point_record(p) for p in raw]
    except Exception as exc:  # noqa: BLE001 — record, keep the instance
        collector.record(f"dataprotection.recoveryPoints.list ({instance.get('name')})", exc)
        return with_recovery_points(instance, RECOVERY_POINTS_ERROR, None, settings, now)
    cutoff = now - timedelta(days=settings["lookback_days"])
    points = [p for p in points if (parse_time(p["recovery_point_time"]) or now) >= cutoff]
    return with_recovery_points(instance, RECOVERY_POINTS_READ, points, settings, now)


def collect_vault(client, api: str, vault: Dict[str, Any], settings: Dict[str, Any], now: datetime,
                  collector: Collector, exclusions: ResourceExclusions, excluded: List[dict]) -> Dict[str, Any]:
    name = vault["name"]
    policies = collector.guard(
        f"dataprotection.backupPolicies.list ({name})",
        lambda: [with_threshold(policy_record(p), settings["retention_threshold_days"])
                 for p in client.list(f"{vault['id']}/backupPolicies", api)],
        default=None,
    )
    policies_read = policies is not None
    policies = sorted(policies or [], key=lambda p: arm_id_key(p["id"]))
    by_id = {arm_id_key(p["id"]): p for p in policies if p.get("id")}
    instances = collector.guard(
        f"dataprotection.backupInstances.list ({name})",
        lambda: [instance_record(i, by_id) for i in client.list(f"{vault['id']}/backupInstances", api)],
        default=None,
    )
    instances_read = instances is not None
    instances = sorted(instances or [], key=lambda i: arm_id_key(i["id"]))
    # An instance leaves by its own id or by the resource it protects; it then gets no recovery point calls.
    instances, out = exclusions.split(instances, "backup_instance", location=lambda i: i.get("datasource_location"))
    excluded += out
    instances, out = exclusions.split(instances, "backup_instance", resource_id=lambda i: i.get("datasource_resource_id"),
                                      location=lambda i: None, resource_group=lambda i: None)
    excluded += out
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        instances = list(pool.map(lambda i: read_recovery_points(client, api, i, settings, now, collector), instances))
    # Null, not 0, when a list failed: an unread vault is not an empty one.
    return {**vault, "backup_policies": policies, "backup_instances": instances,
            "policies_read": policies_read, "instances_read": instances_read,
            "total_backup_policies": len(policies) if policies_read else None,
            "total_backup_instances": len(instances) if instances_read else None}


def collect(client, subscription_id: str, collector: Collector, exclusions: Optional[ResourceExclusions] = None,
            now: Optional[datetime] = None) -> tuple:
    exclusions = exclusions if exclusions is not None else ResourceExclusions()
    now = now or datetime.now(timezone.utc)
    settings = settings_from_env(collector)
    provider = read_provider(client, subscription_id, collector)
    api = provider["api_version"]
    vaults: List[Dict[str, Any]] = []
    excluded: List[dict] = []
    if provider["registration"] == NOT_REGISTERED:
        logger.warning("%s is not registered on subscription %s; no Backup vaults in use", NAMESPACE, subscription_id)
    else:
        raw = collector.guard(
            "dataprotection.backupVaults.list",
            lambda: [vault_record(v) for v in client.list(
                f"/subscriptions/{subscription_id}/providers/{NAMESPACE}/backupVaults", api)],
            default=None,
        )
        vaults = sorted(raw or [], key=lambda v: arm_id_key(v["id"]))
        vaults, out = exclusions.split(vaults, "backup_vault")
        excluded += out
        vaults = [collect_vault(client, api, v, settings, now, collector, exclusions, excluded) for v in vaults]
    exclusions.record_invalid(collector)
    exclusions.warn_unmatched(logger)
    results = {
        "backup_vaults": vaults,
        "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "api_version": api,
        "api_versions_listed": provider["api_versions_listed"],
        "provider_registration_status": provider["registration"],
        "excluded": sorted(excluded, key=lambda e: arm_id_key(e.get("id"))),
    }
    summary = {
        **summarize(vaults, settings),
        "api_version": api,
        "provider_registration_status": provider["registration"],
        **exclusions.summary(excluded, ("backup_vault", "backup_instance"), {
            "backup_vaults": len(vaults),
            "backup_instances": sum(v["total_backup_instances"] or 0 for v in vaults),
        }),
    }
    return results, summary


def collect_subscription(client, subscription_id: str, collector: Collector) -> tuple:
    return collect(client, subscription_id, collector, ResourceExclusions.from_env())


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect_subscription)


if __name__ == "__main__":
    sys.exit(main())
