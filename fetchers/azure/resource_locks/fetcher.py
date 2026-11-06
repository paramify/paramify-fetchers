#!/usr/bin/env python3
"""Management locks at every scope of the subscription, and whether each resource of a protected type is locked against deletion."""

import logging
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    arm_id_key,
    coverage_percentage,
    resource_group_from_id,
    sorted_counts,
)
from azure_rest import run_subscription  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402

NAME = "azure_resource_locks"
logger = logging.getLogger(NAME)

LOCKS_API = "2020-05-01"
RESOURCES_API = "2021-04-01"
PROTECTED_TYPES_ENV = "AZURE_LOCK_PROTECTED_TYPES"
# Resources whose deletion destroys logs, backups, keys or the evidence trail itself.
DEFAULT_PROTECTED_TYPES = (
    "microsoft.operationalinsights/workspaces",
    "microsoft.dataprotection/backupvaults",
    "microsoft.recoveryservices/vaults",
    "microsoft.keyvault/vaults",
    "microsoft.storage/storageaccounts",
)
CAN_NOT_DELETE, READ_ONLY = "cannotdelete", "readonly"
LOCK_MARKER = "/providers/microsoft.authorization/locks/"
SUBSCRIPTION, RESOURCE_GROUP, RESOURCE = "subscription", "resource_group", "resource"


def _lower(value: Any) -> str:
    return str(value or "").lower()


def protected_types(collector: Optional[Collector] = None) -> List[str]:
    """The configured types, or the defaults; an entry that is not provider/type fails the run as bad_config."""
    raw = os.environ.get(PROTECTED_TYPES_ENV)
    if raw is None or not raw.strip():
        return list(DEFAULT_PROTECTED_TYPES)
    types = sorted({t.strip().lower() for t in raw.replace(",", " ").split() if t.strip()})
    # provider/type, or provider/type/child for a nested type such as microsoft.sql/servers/databases
    bad = [t for t in types if len(t.split("/")) < 2 or not all(t.split("/"))]
    if (bad or not types) and collector is not None:
        collector.record(f"config {PROTECTED_TYPES_ENV}", ValueError(
            f"invalid setting {PROTECTED_TYPES_ENV}: {len(bad) or 1} entry(ies) are not of the form provider/type, "
            "such as microsoft.keyvault/vaults, or the list is empty"))
    return types


# --- locks ---

def lock_scope(lock_id: Optional[str]) -> str:
    key = arm_id_key(lock_id)
    return key.split(LOCK_MARKER, 1)[0] if LOCK_MARKER in key else ""


def scope_kind(scope: str) -> str:
    parts = [p for p in scope.split("/") if p]
    if len(parts) == 2:
        return SUBSCRIPTION
    if len(parts) == 4 and parts[2] == "resourcegroups":
        return RESOURCE_GROUP
    return RESOURCE


def lock_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    scope = lock_scope(raw.get("id"))
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "level": _lower(props.get("level")) or "unknown",
        "scope": scope,
        "scope_kind": scope_kind(scope),
        "resource_group": resource_group_from_id(scope) if scope_kind(scope) != SUBSCRIPTION else None,
        "notes": props.get("notes"),
        "owners": sorted(str(o.get("applicationId")) for o in props.get("owners") or [] if o.get("applicationId")),
    }


def covers(scope: str, resource_id: str) -> bool:
    """A lock at a scope covers the scope itself and everything beneath it, never a parent."""
    key = arm_id_key(resource_id)
    return bool(scope) and (key == scope or key.startswith(scope + "/"))


def resource_record(raw: Dict[str, Any], locks: Optional[List[Dict[str, Any]]], protected: List[str]) -> Dict[str, Any]:
    """Lock fields read null, not unlocked, when the lock list was not read."""
    applying = [lock for lock in locks if covers(lock["scope"], raw.get("id"))] if locks is not None else None
    levels = sorted({lock["level"] for lock in applying}) if applying is not None else None
    kind = _lower(raw.get("type"))
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "type": kind,
        "resource_group": resource_group_from_id(raw.get("id")),
        "location": raw.get("location"),
        "protected_type": kind in protected,
        "locks": [{"name": lock["name"], "level": lock["level"], "scope_kind": lock["scope_kind"]} for lock in applying]
        if applying is not None else None,
        "lock_levels": levels,
        "delete_locked": any(level in (CAN_NOT_DELETE, READ_ONLY) for level in levels) if levels is not None else None,
        "read_only": (READ_ONLY in levels) if levels is not None else None,
    }


# --- summary ---

def _breakdown(documented, values) -> Dict[str, int]:
    """Every documented key at 0 or more, plus any other value seen, so a missing key never has to be read as 0."""
    counts = Counter({key: 0 for key in documented})
    counts.update(values)
    return sorted_counts(counts)


def summarize(locks: Optional[List[Dict[str, Any]]], resources: Optional[List[Dict[str, Any]]],
              resource_groups: Optional[List[str]], protected: List[str]) -> Dict[str, Any]:
    locks_list = locks or []
    sub_levels = sorted({lock["level"] for lock in locks_list if lock["scope_kind"] == SUBSCRIPTION})
    rg_locked = {lock["resource_group"] for lock in locks_list if lock["scope_kind"] == RESOURCE_GROUP and lock["resource_group"]}
    known = locks is not None and resources is not None
    res = resources or []
    prot = [r for r in res if r["protected_type"]]
    by_type: Dict[str, Dict[str, int]] = {}
    for kind in protected:
        of_kind = [r for r in prot if r["type"] == kind]
        by_type[kind] = {"resources": len(of_kind), "delete_locked": sum(1 for r in of_kind if r["delete_locked"])} \
            if known else {"resources": None, "delete_locked": None}
    locked = sum(1 for r in prot if r["delete_locked"])
    return {
        "locks_read": locks is not None,
        "locks": len(locks_list) if locks is not None else None,
        # Every documented level and scope kind is listed, at 0 when no lock has it.
        "locks_by_level": _breakdown((CAN_NOT_DELETE, READ_ONLY, "unknown"), (lock["level"] for lock in locks_list))
        if locks is not None else None,
        "locks_by_scope_kind": _breakdown((SUBSCRIPTION, RESOURCE_GROUP, RESOURCE), (lock["scope_kind"] for lock in locks_list))
        if locks is not None else None,
        "subscription_lock_levels": sub_levels if locks is not None else None,
        "subscription_delete_locked": (any(level in (CAN_NOT_DELETE, READ_ONLY) for level in sub_levels)
                                       if locks is not None else None),
        "resource_groups": len(resource_groups) if resource_groups is not None else None,
        "resource_groups_delete_locked": len(rg_locked) if locks is not None else None,
        "protected_resource_types": list(protected),
        "protected_resource_types_unmatched": sorted(k for k in protected if not any(r["type"] == k for r in res))
        if resources is not None else None,
        "resources_read": resources is not None,
        "resources": len(res) if resources is not None else None,
        "resources_delete_locked": sum(1 for r in res if r["delete_locked"]) if known else None,
        "resources_read_only": sum(1 for r in res if r["read_only"]) if known else None,
        "protected_resources": len(prot) if resources is not None else None,
        "protected_resources_delete_locked": locked if known else None,
        "protected_resources_unlocked": (len(prot) - locked) if known else None,
        "protected_resources_by_type": by_type,
        "protected_resource_lock_percentage": coverage_percentage(locked, len(prot)) if known else None,
        "all_protected_resources_locked": (len(prot) == locked) if known and prot else None,
    }


# --- collection ---

def collect(client, subscription_id: str, collector: Collector, exclusions: Optional[ResourceExclusions] = None,
            protected: Optional[List[str]] = None) -> tuple:
    exclusions = exclusions if exclusions is not None else ResourceExclusions()
    protected = protected if protected is not None else protected_types(collector)
    base = f"/subscriptions/{subscription_id}"
    raw_locks = collector.guard("authorization.managementLocks.listAtSubscriptionLevel",
                                lambda: client.list(f"{base}/providers/Microsoft.Authorization/locks", LOCKS_API))
    raw_resources = collector.guard("resources.list", lambda: client.list(f"{base}/resources", RESOURCES_API))
    raw_groups = collector.guard("resourceGroups.list", lambda: client.list(f"{base}/resourcegroups", RESOURCES_API))
    locks = sorted((lock_record(raw) for raw in raw_locks), key=lambda lk: (lk["scope"], arm_id_key(lk["id"]))) \
        if raw_locks is not None else None

    resources: Optional[List[Dict[str, Any]]] = None
    excluded: List[Dict[str, Any]] = []
    if raw_resources is not None:
        kept, excluded = exclusions.split(raw_resources, "resource")
        resources = sorted((resource_record(raw, locks, protected) for raw in kept), key=lambda r: arm_id_key(r["id"]))
    exclusions.record_invalid(collector)
    exclusions.warn_unmatched(logger)
    if resources is not None:
        for kind in protected:
            if not any(r["type"] == kind for r in resources):
                logger.warning("protected type %r matches no resource in the subscription", kind)
    groups = sorted(_lower(g.get("name")) for g in raw_groups) if raw_groups is not None else None

    results = {
        "locks": locks,
        "protected_resources": [r for r in resources if r["protected_type"]] if resources is not None else None,
        "other_locked_resources": [r for r in resources if not r["protected_type"] and r["locks"]]
        if resources is not None and locks is not None else None,
        "resource_groups": groups,
        "excluded": sorted(excluded, key=lambda e: arm_id_key(e.get("id"))),
    }
    summary = {**summarize(locks, resources, groups, protected),
               **exclusions.summary(excluded, ("resource",), {"resources": len(resources) if resources is not None else None})}
    return results, summary


def collect_subscription(client, subscription_id: str, collector: Collector) -> tuple:
    return collect(client, subscription_id, collector, ResourceExclusions.from_env())


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect_subscription)


if __name__ == "__main__":
    sys.exit(main())
