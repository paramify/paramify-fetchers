#!/usr/bin/env python3
"""
Wiz Cloud Resource Inventory

One record per cloud resource Wiz has discovered (``cloudResourcesV2``, the
Inventory > Cloud Resources page), written under ``data`` so a Paramify
inventory pipeline attached to the evidence set can turn each record into an
Inventory item. Records are flat and use one name per inventory field, so the
pipeline maps them one-to-one and its rules can test environment, owner or
internet exposure directly.

Verified 2026-10-06 against a Wiz for Gov tenant with a read-only service
account: the query, every selected field, and the type, account and project
filters. read:resources is the only scope it needs.

Speaks to KSI-PIY-GIV. Read it with wiz_scan_coverage: an account Wiz is not
connected to has no resources here and raises no error.
"""

import logging
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from wiz_client import (  # type: ignore  # noqa: E402
    WizClient,
    collect_guarded,
    env_int,
    env_list,
    evidence,
    run_fetcher,
)

logger = logging.getLogger("wiz_inventory")

DEFAULT_RESOURCE_TYPES = [
    "VIRTUAL_MACHINE", "CONTAINER", "CONTAINER_IMAGE", "KUBERNETES_CLUSTER", "DB_SERVER", "DATABASE",
    "BUCKET", "SERVERLESS", "LOAD_BALANCER", "GATEWAY", "FIREWALL", "VIRTUAL_NETWORK", "SUBNET", "VOLUME",
    "ENCRYPTION_KEY", "SECRET",
]

# typeFields is a union, so each member is asked only for its own fields.
RESOURCE_FIELDS = """
      id name externalId providerUniqueId type nativeType cloudPlatform status region
      firstSeen lastSeen isAccessibleFromInternet hasSensitiveData
      tags { key value }
      cloudAccount { externalId name }
      resourceGroup { name }
      technology { name }
      owners { graphEntity { name } }
      typeFields {
        __typename
        ... on CloudResourceV2VirtualMachine { instanceType operatingSystem ipAddresses image { name } kubernetesCluster { name } }
        ... on CloudResourceV2ContainerImage { operatingSystemDistribution { name } }
        ... on CloudResourceV2Database { kind }
      }
"""

RESOURCES_QUERY = (
    "query WizInventoryResources($first: Int, $after: String, $filterBy: CloudResourceV2Filters) {\n"
    "  cloudResourcesV2(first: $first, after: $after, filterBy: $filterBy) {\n"
    f"    nodes {{{RESOURCE_FIELDS}    }}\n"
    "    pageInfo { hasNextPage endCursor }\n"
    "  }\n"
    "}\n"
)


def raw_list(name: str, default: List[str]) -> List[str]:
    """Comma-separated env var with case kept (account IDs, project IDs and tag keys are not enums)."""
    raw = os.environ.get(name, "")
    values = [p.strip() for p in raw.split(",") if p.strip()]
    return values or list(default)


def resource_filter(types: List[str], account_ids: List[str], project_ids: List[str]) -> Dict[str, Any]:
    f: Dict[str, Any] = {}
    if types != ["ALL"]:
        f["type"] = {"equals": types}
    if account_ids:
        f["cloudAccountV2"] = {"externalId": {"equals": account_ids}}
    if project_ids:
        f["project"] = {"idV2": {"equals": project_ids}}
    return f


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    return default if not raw else raw in {"1", "true", "yes", "on"}


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _name(value: Any) -> Optional[str]:
    name = _dict(value).get("name")
    return name if isinstance(name, str) else None


def tag_value(tags: List[Dict[str, Any]], keys: List[str]) -> Optional[str]:
    """Value of the first tag in ``keys`` order, matching keys case-insensitively."""
    by_key = {str(t.get("key") or "").lower(): str(t.get("value") or "").strip() for t in tags}
    for key in keys:
        if by_key.get(key.lower()):
            return by_key[key.lower()]
    return None


def shape(node: Dict[str, Any], env_keys: List[str], owner_keys: List[str], include_tags: bool) -> Dict[str, Any]:
    tags = [t for t in _list(node.get("tags")) if isinstance(t, dict)]
    tf = _dict(node.get("typeFields"))
    account = _dict(node.get("cloudAccount"))
    ips = [ip for ip in _list(tf.get("ipAddresses")) if isinstance(ip, str) and ip]
    wiz_owners = [n for n in (_name(_dict(o).get("graphEntity")) for o in _list(node.get("owners"))) if n]
    return {
        # externalId is the cloud's own ID (ARN on AWS, resource ID on Azure).
        "unique_asset_identifier": node.get("externalId") or node.get("providerUniqueId") or node.get("id"),
        "name": node.get("name"),
        "wiz_id": node.get("id"),
        "provider_unique_id": node.get("providerUniqueId"),
        "asset_type": node.get("type"),
        "native_type": node.get("nativeType"),
        "technology": _name(node.get("technology")),
        "operating_system": tf.get("operatingSystem") or _name(tf.get("operatingSystemDistribution")),
        "instance_type": tf.get("instanceType"),
        "image": _name(tf.get("image")),
        "database_kind": tf.get("kind"),
        "kubernetes_cluster": _name(tf.get("kubernetesCluster")),
        "cloud_platform": node.get("cloudPlatform"),
        "cloud_account_id": account.get("externalId"),
        "cloud_account_name": account.get("name"),
        "region": node.get("region"),
        "resource_group": _name(node.get("resourceGroup")),
        "ip_addresses": ips,
        "primary_ip_address": ips[0] if ips else None,
        "public": node.get("isAccessibleFromInternet"),
        "virtual": True,
        "has_sensitive_data": node.get("hasSensitiveData"),
        "environment": tag_value(tags, env_keys),
        "owner": tag_value(tags, owner_keys) or (wiz_owners[0] if wiz_owners else None),
        # Tags are free text and can hold anything, so they are copied only on request.
        "tags": sorted(f"{t.get('key')}={t.get('value')}" if t.get("value") else str(t.get("key"))
                       for t in tags) if include_tags else [],
        "status": node.get("status"),
        "first_seen": node.get("firstSeen"),
        "last_seen": node.get("lastSeen"),
    }


def summarize(records: List[Dict[str, Any]], duplicates: int) -> Dict[str, Any]:
    def count(field: str) -> Dict[str, int]:
        return dict(Counter(r[field] if isinstance(r[field], str) and r[field] else "unknown"
                            for r in records).most_common())

    return {
        "resource_count": len(records),
        "duplicates_collapsed": duplicates,
        "by_asset_type": count("asset_type"),
        "by_cloud_account": count("cloud_account_name"),
        "by_region": count("region"),
        "internet_accessible_count": sum(1 for r in records if r["public"]),
        "missing_environment_count": sum(1 for r in records if r["environment"] is None),
        "missing_owner_count": sum(1 for r in records if r["owner"] is None),
    }


def body(client: WizClient) -> Dict[str, Any]:
    types = env_list("WIZ_INVENTORY_RESOURCE_TYPES", DEFAULT_RESOURCE_TYPES)
    account_ids = raw_list("WIZ_INVENTORY_CLOUD_ACCOUNT_IDS", [])
    project_ids = raw_list("WIZ_INVENTORY_PROJECT_IDS", [])
    env_keys = raw_list("WIZ_ENVIRONMENT_TAG_KEYS", ["Environment", "env"])
    owner_keys = raw_list("WIZ_OWNER_TAG_KEYS", ["Owner"])
    include_tags = env_bool("WIZ_INVENTORY_INCLUDE_TAGS", False)

    nodes = client.paginate("cloudResourcesV2", RESOURCES_QUERY, "cloudResourcesV2",
                            variables={"filterBy": resource_filter(types, account_ids, project_ids)},
                            max_records=env_int("WIZ_MAX_RECORDS", 50000))

    # A resource can appear twice if the estate changes while paging; the
    # later copy is newer. A node without an id cannot be inventoried, so it
    # fails the run rather than silently shrinking the estate.
    unique: Dict[str, Dict[str, Any]] = {}
    malformed = 0
    for n in nodes:
        if isinstance(n, dict) and isinstance(n.get("id"), str) and n["id"]:
            unique[n["id"]] = n
        else:
            malformed += 1
    duplicates = len(nodes) - malformed - len(unique)
    if malformed:
        client.api_failures.append({"operation": "cloudResourcesV2", "type": "MalformedResource",
                                    "message": f"{malformed} resource(s) came back without an id"})
    if duplicates > len(unique):
        # A few repeats are normal churn; more repeats than resources is not an inventory.
        client.api_failures.append({"operation": "cloudResourcesV2", "type": "DuplicateIds",
                                    "message": f"{duplicates} repeated ids for {len(unique)} resources"})

    records = []
    for n in unique.values():
        try:
            records.append(shape(n, env_keys, owner_keys, include_tags))
        except (TypeError, ValueError, AttributeError) as e:
            client.api_failures.append({"operation": "cloudResourcesV2", "type": "MalformedResource",
                                        "message": f"resource {n['id']!r} could not be read: {type(e).__name__}"})
    records.sort(key=lambda r: (str(r["asset_type"] or ""), str(r["unique_asset_identifier"] or "")))

    extra: Dict[str, Any] = {}
    if client.api_failures:
        extra = {"status": "error", "error_code": "partial_failure",
                 "message": "Collection incomplete; records withheld so no partial inventory is uploaded."}
    return evidence(
        client=client,
        operations=["cloudResourcesV2"],
        records=records,
        analysis=summarize(records, duplicates),
        empty_message="Wiz returned no cloud resources for this filter. Check WIZ_INVENTORY_RESOURCE_TYPES, the "
                      "account and project filters, and that the service account has read:resources.",
        # An inventory pipeline treats the file as the whole estate, so an
        # incomplete collection ships counts but no records.
        include_records=not client.api_failures,
        scope={
            "resource_types": types,
            "cloud_account_ids": account_ids or "ALL",
            "project_ids": project_ids or "ALL",
            "tags_included": include_tags,
        },
        **extra,
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_inventory.json", logger))
