#!/usr/bin/env python3
"""
Wiz Cloud Resource Inventory

One record per cloud resource Wiz has discovered (``cloudResourcesV2``, the
Inventory > Cloud Resources page), joined with that resource's Inventory
Management findings (``inventoryFindings``, the Findings > Inventory
Management Findings page: tag enforcement, agent coverage and custom
governance rules).

Why this fetcher exists: Paramify builds Inventory records with an inventory
pipeline attached to an evidence set. When this file is uploaded to the
evidence set, the pipeline reads the records under ``payload.data`` and its
field configuration and advanced-configuration rules (the condition engine)
turn them into Inventory. The records are therefore flat and named for the
inventory fields they usually feed, and the values a rule is likely to test
(environment, owner, internet exposure, open governance findings) are top-level
fields rather than buried in tag lists.

What was checked against a live Wiz for Gov tenant (2026-10-06, read-only, via
schema introspection and the two queries below): the root fields
``cloudResourcesV2`` and ``inventoryFindings``, every node field selected here,
the filter inputs used (type, cloudPlatform, cloudAccountV2.externalId,
project.idV2, includeDeleted; status, projects), and that
``inventoryFindings.resource.id`` equals ``cloudResourcesV2.id`` so the join
holds. Not yet checked: a run with a service-account token, so the exact Wiz
scope that grants ``inventoryFindings`` is unconfirmed. A missing scope shows up
as a failed run naming the operation, never as an inventory without findings.

Speaks to KSI-PIY-GIV. It reports what Wiz sees; whether every account in the
boundary is connected is wiz_scan_coverage's job, and the two belong together.
"""

import logging
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from wiz_client import (  # type: ignore  # noqa: E402
    WizClient,
    WizConfigError,
    collect_guarded,
    env_int,
    evidence,
    run_fetcher,
)

logger = logging.getLogger("wiz_inventory")

DEFAULT_RESOURCE_TYPES = [
    "VIRTUAL_MACHINE", "CONTAINER", "CONTAINER_IMAGE", "KUBERNETES_CLUSTER", "DB_SERVER", "DATABASE",
    "BUCKET", "SERVERLESS", "LOAD_BALANCER", "GATEWAY", "FIREWALL", "VIRTUAL_NETWORK", "SUBNET", "VOLUME",
    "ENCRYPTION_KEY", "SECRET",
]
DEFAULT_FINDING_STATUSES = ["OPEN", "IN_PROGRESS"]
FINDING_STATUSES = {"OPEN", "IN_PROGRESS", "RESOLVED", "REJECTED"}
SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# The node selection. Every field here exists on CloudResourceV2 in the live
# schema; typeFields is a union, so each member is asked only for its own fields.
RESOURCE_FIELDS = """
      id name externalId providerUniqueId type nativeType cloudPlatform status region regionLocation
      createdAt updatedAt deletedAt firstSeen lastSeen
      isAccessibleFromInternet isOpenToAllInternet hasSensitiveData hasAdminPrivileges
      tags { key value }
      cloudAccount { id externalId name cloudProvider }
      resourceGroup { id externalId name }
      projects { id name }
      technology { id name categories { name } }
      owners { type graphEntity { id name type } }
      typeFields {
        __typename
        ... on CloudResourceV2VirtualMachine {
          instanceType operatingSystem ipAddresses image { name } kubernetesCluster { name }
        }
        ... on CloudResourceV2Container { image { name } virtualMachine { name } }
        ... on CloudResourceV2ContainerImage { operatingSystemDistribution { name } containerRepository { name } }
        ... on CloudResourceV2Database { kind }
      }
"""

# Used for a page that keeps failing at the smallest page size: the identity
# and placement fields survive, the heavy nested ones are dropped, and the
# evidence counts how many pages came back this way.
RESOURCE_FIELDS_LIGHT = """
      id name externalId providerUniqueId type nativeType cloudPlatform status region regionLocation
      createdAt updatedAt deletedAt firstSeen lastSeen
      tags { key value }
      cloudAccount { id externalId name cloudProvider }
"""


def _resources_query(fields: str) -> str:
    return (
        "query WizInventoryResources($first: Int, $after: String, $filterBy: CloudResourceV2Filters) {\n"
        "  cloudResourcesV2(first: $first, after: $after, filterBy: $filterBy) {\n"
        f"    nodes {{{fields}    }}\n"
        "    pageInfo { hasNextPage endCursor }\n"
        "  }\n"
        "}\n"
    )


RESOURCES_QUERY = _resources_query(RESOURCE_FIELDS)
RESOURCES_QUERY_LIGHT = _resources_query(RESOURCE_FIELDS_LIGHT)

RESOURCES_COUNT_QUERY = """
query WizInventoryResourceCount($filterBy: CloudResourceV2Filters) {
  cloudResourcesV2(first: 1, filterBy: $filterBy) { totalCount }
}
"""

FINDINGS_QUERY = """
query WizInventoryFindings($first: Int, $after: String, $filterBy: InventoryFindingFilters) {
  inventoryFindings(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id status severity createdAt updatedAt
      rule { id name ruleType severity }
      resource { id type name externalId }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

ENUM_QUERY = '{ __type(name: "%s") { enumValues { name } } }'


# --- configuration ----------------------------------------------------------

def raw_list(name: str, default: Iterable[str] = ()) -> List[str]:
    """Comma-separated env var, case kept (cloud platforms and IDs are case-sensitive)."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return list(default)
    seen: List[str] = []
    for part in raw.replace("\n", ",").split(","):
        part = part.strip()
        if part and part not in seen:
            seen.append(part)
    return seen


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise WizConfigError(f"{name} must be true or false (got {raw!r})")


def enum_values(client: WizClient, type_name: str) -> Optional[Set[str]]:
    """Values of a GraphQL enum, or None when introspection is unavailable. Never a collection failure."""
    before = len(client.api_failures)
    data = client.graphql("__type", ENUM_QUERY % type_name)
    del client.api_failures[before:]
    values = ((data or {}).get("__type") or {}).get("enumValues")
    if not values:
        return None
    return {v.get("name") for v in values if v.get("name")}


def resolve_enum(requested: List[str], known: Optional[Set[str]], setting: str) -> List[str]:
    """
    Map requested values onto the enum case-insensitively and refuse unknown
    ones up front. Wiz rejects the whole query for one bad enum value, so a typo
    would otherwise fail every page with a less useful message.
    """
    if known is None:
        return requested
    by_lower = {k.lower(): k for k in known}
    resolved, unknown = [], []
    for value in requested:
        match = by_lower.get(value.lower())
        (resolved if match else unknown).append(match or value)
    if unknown:
        raise WizConfigError(f"{setting}: Wiz does not recognise {', '.join(unknown)}")
    return resolved


def build_config(client: WizClient) -> Dict[str, Any]:
    types = [t.upper() for t in raw_list("WIZ_INVENTORY_RESOURCE_TYPES", DEFAULT_RESOURCE_TYPES)]
    all_types = any(t == "ALL" for t in types)
    if all_types and len(types) > 1:
        raise WizConfigError("WIZ_INVENTORY_RESOURCE_TYPES: ALL cannot be combined with other types")
    if not all_types:
        types = resolve_enum(types, enum_values(client, "GraphEntityTypeValue"), "WIZ_INVENTORY_RESOURCE_TYPES")

    platforms = raw_list("WIZ_INVENTORY_CLOUD_PLATFORMS")
    if platforms:
        platforms = resolve_enum(platforms, enum_values(client, "CloudPlatform"), "WIZ_INVENTORY_CLOUD_PLATFORMS")

    statuses = [s.upper() for s in raw_list("WIZ_INVENTORY_FINDING_STATUSES", DEFAULT_FINDING_STATUSES)]
    bad = [s for s in statuses if s not in FINDING_STATUSES]
    if bad:
        raise WizConfigError(f"WIZ_INVENTORY_FINDING_STATUSES: unknown status {', '.join(bad)} "
                             f"(expected {', '.join(sorted(FINDING_STATUSES))})")

    return {
        "resource_types": None if all_types else types,
        "cloud_platforms": platforms,
        "cloud_account_ids": raw_list("WIZ_INVENTORY_CLOUD_ACCOUNT_IDS"),
        "project_ids": raw_list("WIZ_INVENTORY_PROJECT_IDS"),
        "include_deleted": env_bool("WIZ_INVENTORY_INCLUDE_DELETED", False),
        "include_findings": env_bool("WIZ_INVENTORY_INCLUDE_FINDINGS", True),
        "finding_statuses": statuses,
        "environment_tag_keys": raw_list("WIZ_ENVIRONMENT_TAG_KEYS", ["Environment", "env"]),
        "owner_tag_keys": raw_list("WIZ_OWNER_TAG_KEYS", ["Owner"]),
        "max_records": env_int("WIZ_MAX_RECORDS", 50000),
    }


def resource_filter(cfg: Dict[str, Any]) -> Dict[str, Any]:
    f: Dict[str, Any] = {}
    if cfg["resource_types"]:
        f["type"] = {"equals": cfg["resource_types"]}
    if cfg["cloud_platforms"]:
        f["cloudPlatform"] = {"equals": cfg["cloud_platforms"]}
    if cfg["cloud_account_ids"]:
        f["cloudAccountV2"] = {"externalId": {"equals": cfg["cloud_account_ids"]}}
    if cfg["project_ids"]:
        f["project"] = {"idV2": {"equals": cfg["project_ids"]}}
    if cfg["include_deleted"]:
        f["includeDeleted"] = True
    return f


def finding_filter(cfg: Dict[str, Any]) -> Dict[str, Any]:
    f: Dict[str, Any] = {"status": {"equals": cfg["finding_statuses"]}}
    if cfg["project_ids"]:
        f["projects"] = {"equals": cfg["project_ids"]}
    return f


# --- shaping ----------------------------------------------------------------

def _name(obj: Any) -> Optional[str]:
    return obj.get("name") if isinstance(obj, dict) else None


def tag_value(tags: List[Dict[str, Any]], keys: List[str]) -> Optional[str]:
    """First tag whose key matches one of ``keys`` (in ``keys`` order), case-insensitively."""
    by_key: Dict[str, str] = {}
    for t in tags:
        k = str(t.get("key") or "").strip().lower()
        if k and k not in by_key:
            by_key[k] = str(t.get("value") or "")
    for key in keys:
        value = by_key.get(key.lower())
        if value is not None and value.strip():
            return value.strip()
    return None


def max_severity(severities: Iterable[Optional[str]]) -> Optional[str]:
    ranked = [s for s in severities if s in SEVERITY_ORDER]
    return max(ranked, key=SEVERITY_ORDER.index) if ranked else None


def shape_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    rule = f.get("rule") or {}
    return {
        "id": f.get("id"),
        "rule": rule.get("name"),
        "rule_id": rule.get("id"),
        "rule_type": rule.get("ruleType"),
        "severity": f.get("severity"),
        "status": f.get("status"),
        "created_at": f.get("createdAt"),
        "updated_at": f.get("updatedAt"),
    }


def shape_resource(node: Dict[str, Any], findings: List[Dict[str, Any]], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    One inventory record. Field names follow the FedRAMP Integrated Inventory
    Workbook columns where one exists (unique asset identifier, IP address,
    virtual, public, OS, asset type, location, owner), so mapping them in the
    pipeline's field configuration is one-to-one.
    """
    tags = [t for t in (node.get("tags") or []) if isinstance(t, dict)]
    account = node.get("cloudAccount") or {}
    tf = node.get("typeFields") or {}
    technology = node.get("technology") or {}
    owners = [o for o in (node.get("owners") or []) if isinstance(o, dict)]
    owner_names = []
    for o in owners:
        n = _name(o.get("graphEntity"))
        if n and n not in owner_names:
            owner_names.append(n)

    ips = [ip for ip in (tf.get("ipAddresses") or []) if isinstance(ip, str) and ip]
    operating_system = tf.get("operatingSystem") or _name(tf.get("operatingSystemDistribution"))
    image = _name(tf.get("image"))

    environment = tag_value(tags, cfg["environment_tag_keys"])
    owner_from_tag = tag_value(tags, cfg["owner_tag_keys"])

    shaped_findings = sorted((shape_finding(f) for f in findings),
                             key=lambda x: (-SEVERITY_ORDER.index(x["severity"]) if x["severity"] in SEVERITY_ORDER else 0,
                                            x["rule"] or ""))
    rules = sorted({f["rule"] for f in shaped_findings if f["rule"]})

    return {
        # Identity. externalId is the cloud's own ID (an ARN on AWS, a resource
        # ID on Azure) and is what scanners and the SSP name the asset by, so it
        # is the unique asset identifier; the Wiz IDs are kept for traceability.
        "unique_asset_identifier": node.get("externalId") or node.get("providerUniqueId") or node.get("id"),
        "name": node.get("name"),
        "wiz_id": node.get("id"),
        "external_id": node.get("externalId"),
        "provider_unique_id": node.get("providerUniqueId"),
        # What it is.
        "asset_type": node.get("type"),
        "native_type": node.get("nativeType"),
        "technology": technology.get("name"),
        "technology_categories": sorted({c.get("name") for c in (technology.get("categories") or [])
                                         if isinstance(c, dict) and c.get("name")}),
        "operating_system": operating_system,
        "instance_type": tf.get("instanceType"),
        "image": image,
        "database_kind": tf.get("kind"),
        "kubernetes_cluster": _name(tf.get("kubernetesCluster")),
        "host_virtual_machine": _name(tf.get("virtualMachine")),
        "container_repository": _name(tf.get("containerRepository")),
        # Where it is.
        "cloud_platform": node.get("cloudPlatform"),
        "cloud_provider": account.get("cloudProvider"),
        "cloud_account_id": account.get("externalId"),
        "cloud_account_name": account.get("name"),
        "region": node.get("region"),
        "region_location": node.get("regionLocation"),
        "resource_group": _name(node.get("resourceGroup")),
        "projects": sorted({p.get("name") for p in (node.get("projects") or []) if isinstance(p, dict) and p.get("name")}),
        # Network.
        "ip_addresses": ips,
        "ip_address_count": len(ips),
        "primary_ip_address": ips[0] if ips else None,
        "virtual": True,
        "public": node.get("isAccessibleFromInternet"),
        "open_to_all_internet": node.get("isOpenToAllInternet"),
        # Risk context for pipeline rules.
        "has_sensitive_data": node.get("hasSensitiveData"),
        "has_admin_privileges": node.get("hasAdminPrivileges"),
        # Ownership and tags.
        "environment": environment,
        "owner": owner_from_tag or (owner_names[0] if owner_names else None),
        "owners": owner_names,
        "missing_environment_tag": environment is None,
        "missing_owner_tag": owner_from_tag is None,
        "tags": sorted(f"{t.get('key')}={t.get('value')}" if t.get("value") else str(t.get("key")) for t in tags),
        "tag_keys": sorted({str(t.get("key")) for t in tags if t.get("key")}),
        # Lifecycle.
        "status": node.get("status"),
        "deleted": bool(node.get("deletedAt")),
        "deleted_at": node.get("deletedAt"),
        "first_seen": node.get("firstSeen"),
        "last_seen": node.get("lastSeen"),
        "created_at": node.get("createdAt"),
        "updated_at": node.get("updatedAt"),
        # False when this record came from the light fallback query, so OS,
        # IPs, owners and technology were not collected for it.
        "detail_complete": "typeFields" in node,
        # Inventory Management findings on this resource.
        "inventory_finding_count": len(shaped_findings),
        "inventory_finding_max_severity": max_severity(f["severity"] for f in shaped_findings),
        "inventory_finding_rules": rules,
        "inventory_finding_rule_types": sorted({f["rule_type"] for f in shaped_findings if f["rule_type"]}),
        "inventory_findings": shaped_findings,
    }


def summarize(records: List[Dict[str, Any]], unmatched: List[Dict[str, Any]], findings_collected: Optional[int],
              wiz_total: Optional[int]) -> Dict[str, Any]:
    with_findings = [r for r in records if r["inventory_finding_count"]]
    rule_counts: Counter = Counter()
    sev_counts: Counter = Counter()
    for r in records:
        for f in r["inventory_findings"]:
            rule_counts[f["rule"] or "unknown"] += 1
            sev_counts[f["severity"] or "unknown"] += 1
    analysis: Dict[str, Any] = {
        "resource_count": len(records),
        "wiz_reported_total": wiz_total,
        "collected_matches_wiz_total": None if wiz_total is None else wiz_total == len(records),
        "by_asset_type": dict(Counter(r["asset_type"] or "unknown" for r in records).most_common()),
        "by_cloud_platform": dict(Counter(r["cloud_platform"] or "unknown" for r in records).most_common()),
        "by_cloud_account": dict(Counter(r["cloud_account_name"] or r["cloud_account_id"] or "unknown"
                                         for r in records).most_common()),
        "by_region": dict(Counter(r["region"] or "unknown" for r in records).most_common()),
        "by_status": dict(Counter(r["status"] or "unknown" for r in records).most_common()),
        "internet_accessible_count": sum(1 for r in records if r["public"]),
        "missing_environment_tag_count": sum(1 for r in records if r["missing_environment_tag"]),
        "missing_owner_tag_count": sum(1 for r in records if r["missing_owner_tag"]),
        "deleted_count": sum(1 for r in records if r["deleted"]),
        "records_missing_detail_count": sum(1 for r in records if not r["detail_complete"]),
        "boundary_note": "Compare by_cloud_account against the authorization boundary and read this with "
                         "wiz_scan_coverage; an account Wiz is not connected to has no resources here.",
    }
    if findings_collected is not None:
        outside = Counter((u.get("resource") or {}).get("type") or "unknown" for u in unmatched)
        analysis.update({
            "inventory_findings_collected": findings_collected,
            "inventory_findings_on_inventory": sum(r["inventory_finding_count"] for r in records),
            "resources_with_findings_count": len(with_findings),
            "findings_by_rule": dict(rule_counts.most_common()),
            "findings_by_severity": dict(sev_counts.most_common()),
            "findings_outside_inventory_count": len(unmatched),
            "findings_outside_inventory_by_resource_type": dict(outside.most_common()),
        })
    return analysis


# --- collection -------------------------------------------------------------

def body(client: WizClient) -> Dict[str, Any]:
    cfg = build_config(client)
    r_filter = resource_filter(cfg)
    operations = ["cloudResourcesV2"]

    # The count is a pre-flight and a cross-check, not evidence: if Wiz will
    # not answer it, the paging below still decides whether the run is whole.
    before = len(client.api_failures)
    count = client.graphql("cloudResourcesV2.totalCount", RESOURCES_COUNT_QUERY, {"filterBy": r_filter})
    del client.api_failures[before:]
    wiz_total = ((count or {}).get("cloudResourcesV2") or {}).get("totalCount")
    if not isinstance(wiz_total, int):
        wiz_total = None
    if isinstance(wiz_total, int) and wiz_total > cfg["max_records"]:
        # Paging 400 pages only to fail at the cap wastes the tenant's shared
        # rate limit; say so before starting.
        raise WizConfigError(
            f"Wiz reports {wiz_total} resources for this filter, above WIZ_MAX_RECORDS={cfg['max_records']}. "
            "Narrow WIZ_INVENTORY_RESOURCE_TYPES / accounts / projects, or raise the cap.")

    nodes = client.paginate("cloudResourcesV2", RESOURCES_QUERY, "cloudResourcesV2",
                            variables={"filterBy": r_filter}, max_records=cfg["max_records"],
                            fallback_queries=[RESOURCES_QUERY_LIGHT])

    # A resource can appear twice if the estate changes while paging.
    unique: Dict[str, Dict[str, Any]] = {}
    for n in nodes:
        if isinstance(n, dict) and n.get("id") and n["id"] not in unique:
            unique[n["id"]] = n

    by_resource: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    unmatched: List[Dict[str, Any]] = []
    findings_collected: Optional[int] = None
    if cfg["include_findings"]:
        operations.append("inventoryFindings")
        findings = client.paginate("inventoryFindings", FINDINGS_QUERY, "inventoryFindings",
                                   variables={"filterBy": finding_filter(cfg)}, max_records=cfg["max_records"])
        findings_collected = len(findings)
        for f in findings:
            rid = ((f or {}).get("resource") or {}).get("id")
            if rid in unique:
                by_resource[rid].append(f)
            else:
                unmatched.append(f)

    records = [shape_resource(n, by_resource.get(rid, []), cfg) for rid, n in unique.items()]
    records.sort(key=lambda r: (r["asset_type"] or "", r["cloud_account_id"] or "", r["unique_asset_identifier"] or ""))

    return evidence(
        client=client,
        operations=operations,
        records=records,
        analysis=summarize(records, unmatched, findings_collected, wiz_total),
        empty_message="Wiz returned no cloud resources for this filter. Check WIZ_INVENTORY_RESOURCE_TYPES, the "
                      "account and project filters, and that the service account has read:resources on every "
                      "project in scope.",
        scope={
            "resource_types": cfg["resource_types"] or "ALL",
            "cloud_platforms": cfg["cloud_platforms"] or "ALL",
            "cloud_account_ids": cfg["cloud_account_ids"] or "ALL",
            "project_ids": cfg["project_ids"] or "ALL",
            "include_deleted": cfg["include_deleted"],
            "inventory_findings_included": cfg["include_findings"],
            "finding_statuses": cfg["finding_statuses"] if cfg["include_findings"] else None,
            "environment_tag_keys": cfg["environment_tag_keys"],
            "owner_tag_keys": cfg["owner_tag_keys"],
            "pages_served_by_light_query": client.fallback_pages,
        },
        pipeline_hint={
            "data_path": "payload.data",
            "unique_asset_identifier": "unique_asset_identifier",
            "note": "Attach a Paramify inventory pipeline to this evidence set and point its data path at "
                    "payload.data; each element is one resource.",
        },
    )


collect = collect_guarded(body)

if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "wiz_inventory.json", logger))
