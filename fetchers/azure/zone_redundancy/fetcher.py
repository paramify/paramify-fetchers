#!/usr/bin/env python3
"""Availability-zone and region redundancy of the subscription's compute, network, storage, database and backup resources, and which regions in use support zones."""

import logging
import sys
from collections import Counter, defaultdict
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
from resource_graph import query_all, resource_graph_client  # noqa: E402

NAME = "azure_zone_redundancy"
logger = logging.getLogger(NAME)

LOCATIONS_API = "2022-12-01"

ZONE_REDUNDANT = "zone_redundant"
ZONAL = "zonal"
REGIONAL = "regional"
MIXED = "mixed"
UNKNOWN = "unknown"
CONFIGURATIONS = (ZONE_REDUNDANT, ZONAL, REGIONAL, MIXED, UNKNOWN)

# Resource types assessed, each with how its zone configuration is read.
ZONES_TYPES = (
    "microsoft.compute/virtualmachinescalesets",
    "microsoft.network/applicationgateways",
    "microsoft.network/publicipaddresses",
    "microsoft.network/natgateways",
    "microsoft.network/azurefirewalls",
    "microsoft.network/bastionhosts",
)
REDIS = "microsoft.cache/redis"
NAT_GATEWAY = "microsoft.network/natgateways"
VM = "microsoft.compute/virtualmachines"
DISK = "microsoft.compute/disks"
AKS = "microsoft.containerservice/managedclusters"
LOAD_BALANCER = "microsoft.network/loadbalancers"
PUBLIC_IP = "microsoft.network/publicipaddresses"
STORAGE = "microsoft.storage/storageaccounts"
APP_SERVICE_PLAN = "microsoft.web/serverfarms"
BACKUP_VAULT = "microsoft.dataprotection/backupvaults"
RECOVERY_VAULT = "microsoft.recoveryservices/vaults"
COSMOS = "microsoft.documentdb/databaseaccounts"
POSTGRES = "microsoft.dbforpostgresql/flexibleservers"
MYSQL = "microsoft.dbformysql/flexibleservers"
SQL_DATABASE = "microsoft.sql/servers/databases"
TYPES = (*ZONES_TYPES, REDIS, VM, DISK, AKS, LOAD_BALANCER, STORAGE, APP_SERVICE_PLAN, BACKUP_VAULT, RECOVERY_VAULT,
         COSMOS, POSTGRES, MYSQL, SQL_DATABASE)

# Only the properties the classification reads, so a large cluster or account does not bloat the page.
RESOURCES_QUERY = (
    "Resources | where type in~ (" + ", ".join(f"'{t}'" for t in TYPES) + ")"
    " | where type !~ 'microsoft.sql/servers/databases' or name !~ 'master'"
    " | project id = tostring(id), name, type = tolower(type), location = tolower(location), resourceGroup, kind,"
    " zones, sku, detail = pack("
    "'agentPoolProfiles', properties.agentPoolProfiles, 'frontendIPConfigurations', properties.frontendIPConfigurations,"
    " 'zoneRedundant', properties.zoneRedundant, 'storageSettings', properties.storageSettings,"
    " 'redundancySettings', properties.redundancySettings, 'locations', properties.locations,"
    " 'enableMultipleWriteLocations', properties.enableMultipleWriteLocations,"
    " 'highAvailability', properties.highAvailability, 'availabilityZone', properties.availabilityZone,"
    " 'availabilitySet', properties.availabilitySet, 'virtualMachineScaleSet', properties.virtualMachineScaleSet,"
    " 'zoneBalance', properties.zoneBalance, 'orchestrationMode', properties.orchestrationMode,"
    " 'platformFaultDomainCount', properties.platformFaultDomainCount,"
    " 'zonalAllocationPolicy', properties.zonalAllocationPolicy)"
    " | order by id asc"
)


# --- pure transforms ---

def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _zones(value: Any) -> List[str]:
    return sorted({str(z) for z in value if z not in (None, "")}) if isinstance(value, list) else []


def by_zone_count(zones: List[str]) -> str:
    """Two or more zones is zone-redundant, one is zonal, none is regional."""
    return ZONE_REDUNDANT if len(zones) >= 2 else ZONAL if zones else REGIONAL


def combine(parts: List[str]) -> str:
    """One verdict for a resource made of parts (node pools, frontends, replicas)."""
    kinds = set(parts)
    if not kinds or UNKNOWN in kinds:
        return UNKNOWN
    return parts[0] if len(kinds) == 1 else MIXED


def _redundancy(value: Any) -> Dict[str, Any]:
    """LocallyRedundant / ZoneRedundant / GeoRedundant into a zone verdict and a geo flag."""
    text = _lower(value)
    return {
        "configuration": ZONE_REDUNDANT if text == "zoneredundant" else REGIONAL if text else UNKNOWN,
        "geo_redundant": text == "georedundant" if text else None,
    }


def classify(row: Dict[str, Any], public_ips: Dict[str, List[str]]) -> Dict[str, Any]:
    """{configuration, geo_redundant, detail} for one Resource Graph row."""
    kind, zones = row.get("type") or "", _zones(row.get("zones"))
    sku = row.get("sku") if isinstance(row.get("sku"), dict) else {}
    detail: Dict[str, Any] = {k: v for k, v in (row.get("detail") or {}).items() if v not in (None, "", [])} \
        if isinstance(row.get("detail"), dict) else {}
    out: Dict[str, Any] = {"configuration": UNKNOWN, "geo_redundant": None, "detail": {}}

    if kind in ZONES_TYPES:
        out["configuration"] = by_zone_count(zones)
        out["detail"] = {k: v for k, v in {
            "sku": sku.get("name") or sku.get("tier"), "capacity": sku.get("capacity"),
            "zone_balance": detail.get("zoneBalance"), "orchestration_mode": detail.get("orchestrationMode"),
            "platform_fault_domain_count": detail.get("platformFaultDomainCount"),
        }.items() if v is not None}
        if kind == PUBLIC_IP and _lower(sku.get("name")) == "basic":
            out["detail"]["note"] = "Basic SKU: zones not supported"
    elif kind == REDIS:
        # Automatic places replicas across zones without filling the zones array (API 2024-03-01+).
        policy = _lower(detail.get("zonalAllocationPolicy"))
        out["configuration"] = ZONE_REDUNDANT if policy == "automatic" else REGIONAL if policy == "nozones" \
            else by_zone_count(zones)
        out["detail"] = {"sku": sku.get("name"), "zonal_allocation_policy": detail.get("zonalAllocationPolicy")}
    elif kind == VM:
        availability_set = (detail.get("availabilitySet") or {}).get("id") if isinstance(detail.get("availabilitySet"), dict) else None
        scale_set = (detail.get("virtualMachineScaleSet") or {}).get("id") if isinstance(detail.get("virtualMachineScaleSet"), dict) else None
        out["configuration"] = by_zone_count(zones)
        out["detail"] = {k: v for k, v in {"availability_set_id": availability_set, "scale_set_id": scale_set}.items() if v}
    elif kind == DISK:
        name = _lower(sku.get("name"))
        out["configuration"] = ZONE_REDUNDANT if name.endswith("_zrs") else by_zone_count(zones)
        out["detail"] = {"sku": sku.get("name")}
    elif kind == AKS:
        pools = []
        for pool in detail.get("agentPoolProfiles") or []:
            if not isinstance(pool, dict):
                continue
            pool_zones = _zones(pool.get("availabilityZones"))
            pools.append({"name": pool.get("name"), "mode": pool.get("mode"), "count": pool.get("count"),
                          "zones": pool_zones, "configuration": by_zone_count(pool_zones)})
        out["configuration"] = combine([p["configuration"] for p in pools])
        out["detail"] = {"sku_tier": sku.get("tier"), "node_pools": pools}
    elif kind == LOAD_BALANCER:
        frontends = []
        for fe in detail.get("frontendIPConfigurations") or []:
            if not isinstance(fe, dict):
                continue
            props = fe.get("properties") or {}
            pip = (props.get("publicIPAddress") or {}).get("id") if isinstance(props.get("publicIPAddress"), dict) else None
            if pip:
                found = public_ips.get(arm_id_key(pip))
                fe_zones = found if found is not None else None
                source = "public_ip"
            else:
                fe_zones, source = _zones(fe.get("zones")), "frontend"
            frontends.append({"name": fe.get("name"), "zones_source": source, "public_ip_id": pip,
                              "zones": fe_zones, "configuration": by_zone_count(fe_zones) if fe_zones is not None else UNKNOWN})
        if _lower(sku.get("name")) == "basic":
            out["configuration"] = REGIONAL
            out["detail"] = {"sku": sku.get("name"), "note": "Basic SKU: zones not supported", "frontends": frontends}
        else:
            out["configuration"] = combine([f["configuration"] for f in frontends])
            out["detail"] = {"sku": sku.get("name"), "frontends": frontends}
    elif kind == STORAGE:
        name = _lower(sku.get("name"))
        out["configuration"] = ZONE_REDUNDANT if "zrs" in name else REGIONAL if name else UNKNOWN
        out["geo_redundant"] = ("grs" in name or "gzrs" in name) if name else None
        out["detail"] = {"sku": sku.get("name"), "kind": row.get("kind")}
    elif kind == APP_SERVICE_PLAN:
        flag = detail.get("zoneRedundant")
        out["configuration"] = ZONE_REDUNDANT if flag is True else REGIONAL if flag is False or flag is None else UNKNOWN
        out["detail"] = {"sku": sku.get("name"), "sku_tier": sku.get("tier"), "capacity": sku.get("capacity")}
    elif kind == BACKUP_VAULT:
        stores = [s for s in (detail.get("storageSettings") or []) if isinstance(s, dict)]
        vault_store = next((s.get("type") for s in stores if _lower(s.get("datastoreType")) == "vaultstore"), None)
        out.update(_redundancy(vault_store))
        out["detail"] = {"vault_store_redundancy": vault_store}
    elif kind == RECOVERY_VAULT:
        settings = detail.get("redundancySettings") if isinstance(detail.get("redundancySettings"), dict) else {}
        out.update(_redundancy(settings.get("standardTierStorageRedundancy")))
        out["detail"] = {"standard_tier_storage_redundancy": settings.get("standardTierStorageRedundancy"),
                         "cross_region_restore": settings.get("crossRegionRestore")}
    elif kind == COSMOS:
        locations = [loc for loc in (detail.get("locations") or []) if isinstance(loc, dict)]
        replicas = [{"location": _lower(loc.get("locationName")), "zone_redundant": loc.get("isZoneRedundant"),
                     "failover_priority": loc.get("failoverPriority")} for loc in locations]
        out["configuration"] = combine([ZONE_REDUNDANT if r["zone_redundant"] else REGIONAL for r in replicas])
        out["geo_redundant"] = len({r["location"] for r in replicas}) >= 2
        out["detail"] = {"replicas": replicas, "multiple_write_locations": detail.get("enableMultipleWriteLocations")}
    elif kind in (POSTGRES, MYSQL):
        ha = detail.get("highAvailability") if isinstance(detail.get("highAvailability"), dict) else {}
        mode = _lower(ha.get("mode"))
        if mode == "zoneredundant":
            out["configuration"] = ZONE_REDUNDANT
        elif mode == "samezone" or detail.get("availabilityZone"):
            out["configuration"] = ZONAL
        else:
            out["configuration"] = REGIONAL
        out["detail"] = {"high_availability_mode": ha.get("mode"), "high_availability_state": ha.get("state"),
                         "availability_zone": detail.get("availabilityZone"),
                         "standby_availability_zone": ha.get("standbyAvailabilityZone")}
    elif kind == SQL_DATABASE:
        flag = detail.get("zoneRedundant")
        out["configuration"] = ZONE_REDUNDANT if flag is True else REGIONAL
        out["detail"] = {"sku": sku.get("name"), "sku_tier": sku.get("tier")}
    return out


# Types with no zone-redundant mode of their own: a VM or NAT gateway sits in at most one zone, and a disk follows
# its VM. They are classified, but not held to zone redundancy.
NOT_ZONE_REDUNDANT_CAPABLE = frozenset({VM, DISK, NAT_GATEWAY})


def zone_redundant_capable(kind: str, verdict: Dict[str, Any]) -> bool:
    return kind not in NOT_ZONE_REDUNDANT_CAPABLE and "Basic SKU" not in str((verdict.get("detail") or {}).get("note") or "")


def resource_record(row: Dict[str, Any], public_ips: Dict[str, List[str]], regions: Optional[Dict[str, dict]]) -> Dict[str, Any]:
    verdict = classify(row, public_ips)
    location = _lower(row.get("location"))
    region = (regions or {}).get(location)
    supports = None if regions is None or region is None else bool(region["availability_zones"])
    return {
        "id": row.get("id"),
        "name": row.get("name"),
        "type": row.get("type"),
        "resource_group": row.get("resourceGroup") or resource_group_from_id(row.get("id")),
        "location": location or None,
        "region_supports_zones": supports,
        "zones": _zones(row.get("zones")),
        "zone_configuration": verdict["configuration"],
        "zone_redundant_capable": zone_redundant_capable(row.get("type") or "", verdict),
        "geo_redundant": verdict["geo_redundant"],
        "detail": verdict["detail"],
    }


def region_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    meta = raw.get("metadata") or {}
    return {
        "name": _lower(raw.get("name")),
        "display_name": raw.get("displayName"),
        "region_type": meta.get("regionType"),
        "geography": meta.get("geography"),
        "availability_zones": len(raw.get("availabilityZoneMappings") or []),
        "paired_regions": sorted(_lower(p.get("name")) for p in (meta.get("pairedRegion") or []) if isinstance(p, dict)),
    }


def summarize(resources: List[Dict[str, Any]], regions: Optional[Dict[str, dict]]) -> tuple:
    """(summary, regions in use) from the in-scope resource records."""
    in_use: Dict[str, Dict[str, Any]] = {}
    for r in resources:
        loc = r["location"] or "unknown"
        entry = in_use.setdefault(loc, {
            **((regions or {}).get(loc) or {"name": loc, "display_name": None, "region_type": None, "geography": None,
                                           "availability_zones": None, "paired_regions": []}),
            "supports_zones": r["region_supports_zones"], "resources": 0, "zone_redundant_resources": 0,
        })
        entry["resources"] += 1
        entry["zone_redundant_resources"] += r["zone_configuration"] == ZONE_REDUNDANT
    region_list = [in_use[k] for k in sorted(in_use)]
    configs = Counter(r["zone_configuration"] for r in resources)
    capable = [r for r in resources if r["region_supports_zones"] and r["zone_redundant_capable"]] \
        if regions is not None else None
    redundant_capable = sum(1 for r in capable if r["zone_configuration"] == ZONE_REDUNDANT) if capable is not None else None
    by_type: Dict[str, Counter] = defaultdict(Counter)
    for r in resources:
        by_type[r["type"]][r["zone_configuration"]] += 1
    all_redundant = None
    if capable:
        unknown = any(r["zone_configuration"] == UNKNOWN for r in capable)
        all_redundant = None if unknown else redundant_capable == len(capable)
    summary = {
        "resources_assessed": len(resources),
        "resource_types_assessed": list(TYPES),
        "resources_by_type": sorted_counts(Counter(r["type"] for r in resources)),
        "resources_by_zone_configuration": {c: configs[c] for c in CONFIGURATIONS},
        "resources_by_type_and_zone_configuration": {t: sorted_counts(by_type[t]) for t in sorted(by_type)},
        "zone_redundant_resources": configs[ZONE_REDUNDANT],
        "zonal_resources": configs[ZONAL],
        "regional_resources": configs[REGIONAL],
        "zonal_or_zone_redundant_resources": configs[ZONE_REDUNDANT] + configs[ZONAL],
        "mixed_resources": configs[MIXED],
        "unknown_resources": configs[UNKNOWN],
        "region_support_read": regions is not None,
        "regions_in_use": len(region_list),
        "regions": [r["name"] for r in region_list],
        "multi_region": len(region_list) >= 2,
        "regions_with_zone_support_in_use": sum(1 for r in region_list if r["supports_zones"]),
        "regions_without_zone_support_in_use": sum(1 for r in region_list if r["supports_zones"] is False),
        "resources_in_regions_without_zone_support": sum(1 for r in resources if r["region_supports_zones"] is False),
        "resources_in_unlisted_regions": sum(1 for r in resources if regions is not None and r["region_supports_zones"] is None),
        "zone_redundant_capable_resources": sum(1 for r in resources if r["zone_redundant_capable"]),
        "zone_capable_resources": len(capable) if capable is not None else None,
        "zone_redundant_in_zone_capable_regions": redundant_capable,
        "zone_redundant_percentage": coverage_percentage(redundant_capable, len(capable)) if capable is not None else None,
        "all_zone_capable_resources_zone_redundant": all_redundant,
        "geo_redundant_resources": sum(1 for r in resources if r["geo_redundant"]),
    }
    return summary, region_list


# --- collection ---

def read_regions(client, subscription_id: str, collector: Collector) -> Optional[Dict[str, dict]]:
    """Every region of the cloud keyed by name, with its zone count; None when the list failed."""
    raw = collector.guard(
        "subscriptions.locations.list",
        lambda: client.list(f"/subscriptions/{subscription_id}/locations", LOCATIONS_API),
    )
    if raw is None:
        return None
    regions = (region_record(r) for r in raw if _lower(r.get("type")) in ("", "region"))
    return {r["name"]: r for r in regions if r["name"]}


def collect(client, subscription_id: str, collector: Collector, exclusions: Optional[ResourceExclusions] = None) -> tuple:
    exclusions = exclusions if exclusions is not None else ResourceExclusions()
    regions = read_regions(client, subscription_id, collector)
    graph = collector.guard("resourcegraph.ResourceGraphClient (init)", lambda: resource_graph_client(client.cred))
    result = collector.guard("resourcegraph.resources (zone redundancy)",
                             lambda: query_all(graph, subscription_id, RESOURCES_QUERY)) if graph is not None else None
    rows = result["rows"] if result else []
    public_ips = {arm_id_key(r.get("id")): _zones(r.get("zones")) for r in rows if _lower(r.get("type")) == PUBLIC_IP}
    resources = [resource_record(r, public_ips, regions) for r in rows]
    resources, excluded = exclusions.split(resources, "resource")
    exclusions.record_invalid(collector)
    exclusions.warn_unmatched(logger)
    summary, region_list = summarize(resources, regions)
    results = {
        "resources": resources,
        "regions": region_list,
        "resource_graph": {"rows": len(rows), "total_records_reported": result["total_records"], "pages": result["pages"]}
        if result else None,
        "excluded": sorted(excluded, key=lambda e: arm_id_key(e.get("id"))),
    }
    summary = {**summary, "resource_list_read": result is not None,
               **exclusions.summary(excluded, ("resource",), {"resources": len(resources)})}
    return results, summary


def collect_subscription(client, subscription_id: str, collector: Collector) -> tuple:
    return collect(client, subscription_id, collector, ResourceExclusions.from_env())


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect_subscription)


if __name__ == "__main__":
    sys.exit(main())
