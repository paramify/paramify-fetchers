"""azure_zone_redundancy: per-type zone classification, region zone support, summary. Synthetic Resource Graph rows, no SDK or network."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_zone_redundancy_under_test", AZURE / "zone_redundancy" / "fetcher.py")
zr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zr)
azure_rest = sys.modules["azure_rest"]
azure_common = sys.modules["azure_common"]
ResourceExclusions = sys.modules["resource_exclusions"].ResourceExclusions

SUB = "/subscriptions/s1"
RG = f"{SUB}/resourceGroups/rg1"
VA, AZ = "usgovvirginia", "usgovarizona"
PIP_ZR = f"{RG}/providers/Microsoft.Network/publicIPAddresses/pip-zr"
PIP_ZONAL = f"{RG}/providers/Microsoft.Network/publicIPAddresses/pip-z1"
REGIONS = {
    VA: {"name": VA, "display_name": "USGov Virginia", "region_type": "Physical", "geography": "usgov",
         "availability_zones": 3, "paired_regions": ["usgovtexas"]},
    AZ: {"name": AZ, "display_name": "USGov Arizona", "region_type": "Physical", "geography": "usgov",
         "availability_zones": 0, "paired_regions": ["usgovtexas"]},
}


def row(kind, name="r", location=VA, zones=None, sku=None, detail=None, rg="rg1"):
    return {"id": f"{SUB}/resourceGroups/{rg}/providers/{kind}/{name}", "name": name, "type": kind.lower(),
            "location": location, "resourceGroup": rg, "kind": None, "zones": zones, "sku": sku, "detail": detail or {}}


def config(kind, **kwargs):
    return zr.classify(row(kind, **kwargs), {})["configuration"]


@pytest.mark.parametrize("zones, expected", [
    (["1", "2", "3"], zr.ZONE_REDUNDANT), (["1", "2"], zr.ZONE_REDUNDANT), (["2"], zr.ZONAL), ([], zr.REGIONAL),
    (None, zr.REGIONAL), ([1, 1], zr.ZONAL),
])
def test_zones_array_decides_scale_sets_gateways_and_ips(zones, expected):
    for kind in ("Microsoft.Compute/virtualMachineScaleSets", "Microsoft.Network/applicationGateways",
                 "Microsoft.Network/publicIPAddresses", "Microsoft.Network/natGateways",
                 "Microsoft.Network/azureFirewalls", "Microsoft.Network/bastionHosts"):
        assert config(kind, zones=zones) == expected, kind


@pytest.mark.parametrize("policy, zones, expected", [
    ("Automatic", None, zr.ZONE_REDUNDANT), ("NoZones", ["1", "2"], zr.REGIONAL),
    ("UserDefined", ["1", "2"], zr.ZONE_REDUNDANT), (None, ["1"], zr.ZONAL), (None, None, zr.REGIONAL),
])
def test_redis_reads_its_zonal_allocation_policy_before_zones(policy, zones, expected):
    assert config("Microsoft.Cache/Redis", zones=zones, detail={"zonalAllocationPolicy": policy}) == expected


@pytest.mark.parametrize("kind, sku, capable", [
    ("Microsoft.Compute/virtualMachineScaleSets", None, True), ("Microsoft.Compute/virtualMachines", None, False),
    ("Microsoft.Compute/disks", None, False), ("Microsoft.Network/natGateways", None, False),
    ("Microsoft.Network/publicIPAddresses", {"name": "Basic"}, False),
    ("Microsoft.Network/publicIPAddresses", {"name": "Standard"}, True),
    ("Microsoft.Network/loadBalancers", {"name": "Basic"}, False),
    ("Microsoft.Storage/storageAccounts", {"name": "Standard_LRS"}, True),
])
def test_only_types_with_a_zone_redundant_mode_are_held_to_it(kind, sku, capable):
    assert zr.resource_record(row(kind, sku=sku), {}, REGIONS)["zone_redundant_capable"] is capable


def test_scale_set_detail_keeps_balance_and_capacity():
    verdict = zr.classify(row("Microsoft.Compute/virtualMachineScaleSets", zones=["1", "2", "3"],
                              sku={"name": "Standard_D2s_v5", "tier": "Standard", "capacity": 6},
                              detail={"zoneBalance": True, "orchestrationMode": "Flexible", "platformFaultDomainCount": 1}), {})
    assert verdict["detail"] == {"sku": "Standard_D2s_v5", "capacity": 6, "zone_balance": True,
                                 "orchestration_mode": "Flexible", "platform_fault_domain_count": 1}


def test_virtual_machine_is_zonal_or_regional_with_its_set_and_scale_set_named():
    zonal = zr.classify(row("Microsoft.Compute/virtualMachines", zones=["1"]), {})
    assert (zonal["configuration"], zonal["detail"]) == (zr.ZONAL, {})
    in_set = zr.classify(row("Microsoft.Compute/virtualMachines", detail={"availabilitySet": {"id": f"{RG}/as1"},
                                                                          "virtualMachineScaleSet": {"id": f"{RG}/vmss1"}}), {})
    assert (in_set["configuration"], in_set["detail"]) == (zr.REGIONAL, {"availability_set_id": f"{RG}/as1",
                                                                         "scale_set_id": f"{RG}/vmss1"})


@pytest.mark.parametrize("sku, zones, expected", [
    ("Premium_ZRS", None, zr.ZONE_REDUNDANT), ("StandardSSD_ZRS", None, zr.ZONE_REDUNDANT),
    ("Premium_LRS", ["1"], zr.ZONAL), ("Premium_LRS", None, zr.REGIONAL),
])
def test_disks_read_zrs_sku_before_zones(sku, zones, expected):
    assert config("Microsoft.Compute/disks", zones=zones, sku={"name": sku}) == expected


def pools(*zone_lists):
    return {"agentPoolProfiles": [{"name": f"pool{i}", "mode": "System" if i == 0 else "User", "count": 3,
                                   "availabilityZones": z} for i, z in enumerate(zone_lists)]}


@pytest.mark.parametrize("zone_lists, expected", [
    ((["1", "2", "3"], ["1", "2", "3"]), zr.ZONE_REDUNDANT),
    ((["1"], ["1"]), zr.ZONAL),
    (([], None), zr.REGIONAL),
    ((["1", "2", "3"], []), zr.MIXED),
    ((), zr.UNKNOWN),
])
def test_aks_cluster_follows_its_node_pools(zone_lists, expected):
    verdict = zr.classify(row("Microsoft.ContainerService/managedClusters", sku={"name": "Base", "tier": "Standard"},
                              detail=pools(*zone_lists)), {})
    assert verdict["configuration"] == expected
    assert verdict["detail"]["sku_tier"] == "Standard"
    assert [p["configuration"] for p in verdict["detail"]["node_pools"]] == [zr.by_zone_count(zr._zones(z)) for z in zone_lists]


def frontend(name, pip=None, zones=None):
    fe = {"name": name, "properties": {}}
    if pip:
        fe["properties"]["publicIPAddress"] = {"id": pip}
    if zones is not None:
        fe["zones"] = zones
    return fe


def test_load_balancer_public_frontends_take_their_public_ips_zones():
    public_ips = {PIP_ZR.lower(): ["1", "2", "3"], PIP_ZONAL.lower(): ["1"]}
    lb = row("Microsoft.Network/loadBalancers", sku={"name": "Standard"},
             detail={"frontendIPConfigurations": [frontend("fe1", pip=PIP_ZR.upper())]})
    assert zr.classify(lb, public_ips)["configuration"] == zr.ZONE_REDUNDANT
    lb["detail"]["frontendIPConfigurations"].append(frontend("fe2", pip=PIP_ZONAL))
    verdict = zr.classify(lb, public_ips)
    assert verdict["configuration"] == zr.MIXED
    assert [f["zones_source"] for f in verdict["detail"]["frontends"]] == ["public_ip", "public_ip"]


def test_load_balancer_internal_frontends_use_their_own_zones_and_an_unresolved_ip_is_unknown():
    lb = row("Microsoft.Network/loadBalancers", sku={"name": "Standard"},
             detail={"frontendIPConfigurations": [frontend("fe1", zones=["1", "2", "3"]), frontend("fe2", zones=[])]})
    assert zr.classify(lb, {})["configuration"] == zr.MIXED
    lb["detail"]["frontendIPConfigurations"] = [frontend("fe1", pip=f"{RG}/providers/Microsoft.Network/publicIPAddresses/elsewhere")]
    verdict = zr.classify(lb, {})
    assert (verdict["configuration"], verdict["detail"]["frontends"][0]["zones"]) == (zr.UNKNOWN, None)


def test_basic_load_balancer_and_public_ip_are_regional():
    lb = row("Microsoft.Network/loadBalancers", sku={"name": "Basic"},
             detail={"frontendIPConfigurations": [frontend("fe1", zones=["1"])]})
    assert zr.classify(lb, {})["configuration"] == zr.REGIONAL
    pip = zr.classify(row("Microsoft.Network/publicIPAddresses", sku={"name": "Basic"}), {})
    assert (pip["configuration"], pip["detail"]["note"]) == (zr.REGIONAL, "Basic SKU: zones not supported")


@pytest.mark.parametrize("sku, expected, geo", [
    ("Standard_ZRS", zr.ZONE_REDUNDANT, False), ("Standard_GZRS", zr.ZONE_REDUNDANT, True),
    ("Standard_RAGZRS", zr.ZONE_REDUNDANT, True), ("Standard_GRS", zr.REGIONAL, True),
    ("Standard_RAGRS", zr.REGIONAL, True), ("Standard_LRS", zr.REGIONAL, False), ("Premium_LRS", zr.REGIONAL, False),
])
def test_storage_accounts_read_their_sku(sku, expected, geo):
    verdict = zr.classify(row("Microsoft.Storage/storageAccounts", sku={"name": sku}), {})
    assert (verdict["configuration"], verdict["geo_redundant"]) == (expected, geo)


@pytest.mark.parametrize("flag, expected", [(True, zr.ZONE_REDUNDANT), (False, zr.REGIONAL), (None, zr.REGIONAL)])
def test_app_service_plans_and_sql_databases_read_zone_redundant(flag, expected):
    assert config("Microsoft.Web/serverfarms", detail={"zoneRedundant": flag}) == expected
    assert config("Microsoft.Sql/servers/databases", detail={"zoneRedundant": flag}) == expected


@pytest.mark.parametrize("store, expected, geo", [
    ("ZoneRedundant", zr.ZONE_REDUNDANT, False), ("GeoRedundant", zr.REGIONAL, True),
    ("LocallyRedundant", zr.REGIONAL, False), (None, zr.UNKNOWN, None),
])
def test_vaults_read_their_storage_redundancy(store, expected, geo):
    settings = [{"datastoreType": "VaultStore", "type": store}] if store else []
    backup = zr.classify(row("Microsoft.DataProtection/backupVaults", detail={"storageSettings": settings}), {})
    assert (backup["configuration"], backup["geo_redundant"]) == (expected, geo)
    rsv = zr.classify(row("Microsoft.RecoveryServices/vaults", detail={"redundancySettings": {
        "standardTierStorageRedundancy": store, "crossRegionRestore": "Enabled"}}), {})
    assert (rsv["configuration"], rsv["geo_redundant"], rsv["detail"]["cross_region_restore"]) == (expected, geo, "Enabled")


def test_cosmos_follows_its_replicas_and_counts_regions():
    one = zr.classify(row("Microsoft.DocumentDB/databaseAccounts", detail={"locations": [
        {"locationName": "USGov Virginia", "isZoneRedundant": True, "failoverPriority": 0}]}), {})
    assert (one["configuration"], one["geo_redundant"]) == (zr.ZONE_REDUNDANT, False)
    two = zr.classify(row("Microsoft.DocumentDB/databaseAccounts", detail={"locations": [
        {"locationName": "USGov Virginia", "isZoneRedundant": True, "failoverPriority": 0},
        {"locationName": "USGov Texas", "isZoneRedundant": False, "failoverPriority": 1}],
        "enableMultipleWriteLocations": False}), {})
    assert (two["configuration"], two["geo_redundant"], two["detail"]["multiple_write_locations"]) == (zr.MIXED, True, False)


@pytest.mark.parametrize("ha, zone, expected", [
    ({"mode": "ZoneRedundant", "state": "Healthy", "standbyAvailabilityZone": "2"}, "1", zr.ZONE_REDUNDANT),
    ({"mode": "SameZone"}, "1", zr.ZONAL),
    ({"mode": "Disabled"}, "1", zr.ZONAL),
    ({"mode": "Disabled"}, None, zr.REGIONAL),
    ({}, None, zr.REGIONAL),
])
def test_flexible_servers_read_high_availability(ha, zone, expected):
    for kind in ("Microsoft.DBforPostgreSQL/flexibleServers", "Microsoft.DBforMySQL/flexibleServers"):
        assert config(kind, detail={"highAvailability": ha, "availabilityZone": zone}) == expected


def test_resource_record_knows_its_regions_zone_support():
    in_va = zr.resource_record(row("Microsoft.Compute/virtualMachines", zones=["1"]), {}, REGIONS)
    in_az = zr.resource_record(row("Microsoft.Compute/virtualMachines", location=AZ), {}, REGIONS)
    unread = zr.resource_record(row("Microsoft.Compute/virtualMachines"), {}, None)
    unlisted = zr.resource_record(row("Microsoft.Compute/virtualMachines", location="nowhere"), {}, REGIONS)
    assert (in_va["region_supports_zones"], in_az["region_supports_zones"], unread["region_supports_zones"],
            unlisted["region_supports_zones"]) == (True, False, None, None)
    assert (in_va["zone_configuration"], in_va["zones"], in_va["resource_group"]) == (zr.ZONAL, ["1"], "rg1")


def test_region_record_counts_zones_and_pairs():
    record = zr.region_record({"name": "USGovVirginia", "displayName": "USGov Virginia", "type": "Region",
                               "availabilityZoneMappings": [{"logicalZone": "1"}, {"logicalZone": "2"}, {"logicalZone": "3"}],
                               "metadata": {"regionType": "Physical", "geography": "usgov",
                                            "pairedRegion": [{"name": "USGovTexas"}]}})
    assert record == {"name": "usgovvirginia", "display_name": "USGov Virginia", "region_type": "Physical",
                      "geography": "usgov", "availability_zones": 3, "paired_regions": ["usgovtexas"]}


def records():
    return [zr.resource_record(r, {}, REGIONS) for r in (
        row("Microsoft.Compute/virtualMachineScaleSets", "vmss-zr", zones=["1", "2", "3"]),
        row("Microsoft.Compute/virtualMachineScaleSets", "vmss-regional"),
        row("Microsoft.Storage/storageAccounts", "stgrs", sku={"name": "Standard_GRS"}),
        row("Microsoft.Compute/virtualMachines", "vm-az", location=AZ),
    )]


def test_summary_measures_zone_redundancy_against_zone_capable_regions():
    summary, regions = zr.summarize(records(), REGIONS)
    assert {k: summary[k] for k in (
        "resources_assessed", "zone_redundant_resources", "regional_resources", "regions_in_use", "multi_region",
        "regions_with_zone_support_in_use", "regions_without_zone_support_in_use",
        "resources_in_regions_without_zone_support", "zone_capable_resources", "zone_redundant_in_zone_capable_regions",
        "zone_redundant_percentage", "all_zone_capable_resources_zone_redundant", "geo_redundant_resources",
        "region_support_read")} == {
        "resources_assessed": 4, "zone_redundant_resources": 1, "regional_resources": 3, "regions_in_use": 2,
        "multi_region": True, "regions_with_zone_support_in_use": 1, "regions_without_zone_support_in_use": 1,
        "resources_in_regions_without_zone_support": 1, "zone_capable_resources": 3,
        "zone_redundant_in_zone_capable_regions": 1, "zone_redundant_percentage": 33,
        "all_zone_capable_resources_zone_redundant": False, "geo_redundant_resources": 1, "region_support_read": True}
    assert (summary["zone_redundant_capable_resources"], summary["zonal_or_zone_redundant_resources"],
            summary["resources_in_unlisted_regions"]) == (3, 1, 0)
    assert summary["resources_by_type_and_zone_configuration"]["microsoft.compute/virtualmachinescalesets"] == {
        "regional": 1, "zone_redundant": 1}
    assert [(r["name"], r["supports_zones"], r["resources"], r["zone_redundant_resources"]) for r in regions] == [
        (AZ, False, 1, 0), (VA, True, 3, 1)]


def test_summary_without_the_region_list_leaves_capability_null():
    summary, regions = zr.summarize([zr.resource_record(r, {}, None) for r in (
        row("Microsoft.Compute/virtualMachineScaleSets", zones=["1", "2", "3"]),)], None)
    assert (summary["zone_capable_resources"], summary["zone_redundant_percentage"],
            summary["all_zone_capable_resources_zone_redundant"], summary["region_support_read"],
            summary["zone_redundant_resources"]) == (None, None, None, False, 1)
    assert regions[0]["supports_zones"] is None


def test_all_zone_capable_is_null_with_an_unknown_and_true_when_all_are_redundant():
    zr_row = zr.resource_record(row("Microsoft.Compute/virtualMachineScaleSets", "a", zones=["1", "2"]), {}, REGIONS)
    unknown = zr.resource_record(row("Microsoft.ContainerService/managedClusters", "b", detail={}), {}, REGIONS)
    assert zr.summarize([zr_row, unknown], REGIONS)[0]["all_zone_capable_resources_zone_redundant"] is None
    assert zr.summarize([zr_row], REGIONS)[0]["all_zone_capable_resources_zone_redundant"] is True
    assert zr.summarize([], REGIONS)[0]["all_zone_capable_resources_zone_redundant"] is None


def test_query_names_every_assessed_type_and_orders_by_id():
    for kind in zr.TYPES:
        assert f"'{kind}'" in zr.RESOURCES_QUERY
    assert zr.RESOURCES_QUERY.endswith("| order by id asc") and "project id = tostring(id)" in zr.RESOURCES_QUERY
    assert "zonalAllocationPolicy" in zr.RESOURCES_QUERY


# --- collection through fakes ---

class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text = status, body, "", json.dumps(body)
        self.headers: dict = {}

    def json(self):
        return self._body


class _Arm:
    def __init__(self, locations_status=200):
        self.locations_status, self.urls = locations_status, []

    def get(self, url, params=None, headers=None, timeout=None):
        self.urls.append(url)
        if urlparse(url).path.endswith("/locations"):
            if self.locations_status != 200:
                return _Resp(self.locations_status, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            return _Resp(200, {"value": [
                {"name": "usgovvirginia", "displayName": "USGov Virginia", "type": "Region",
                 "availabilityZoneMappings": [{"logicalZone": "1"}, {"logicalZone": "2"}, {"logicalZone": "3"}],
                 "metadata": {"regionType": "Physical", "pairedRegion": [{"name": "usgovtexas"}]}},
                {"name": "usgovarizona", "displayName": "USGov Arizona", "type": "Region",
                 "metadata": {"regionType": "Physical", "pairedRegion": [{"name": "usgovtexas"}]}},
                {"name": "usgovvirginia-edge", "type": "EdgeZone"},
            ]})
        return _Resp(404, {"error": {"code": "NotFound", "message": url}})


class _Cred:
    def get_token(self, scope):
        return namedtuple("T", "token expires_on")("tok", 9_999_999_999)


GRAPH_ROWS = [
    row("Microsoft.Compute/virtualMachineScaleSets", "vmss1", zones=["1", "2", "3"], sku={"capacity": 3}),
    row("Microsoft.Network/publicIPAddresses", "pip-zr", zones=["1", "2", "3"], sku={"name": "Standard"}),
    row("Microsoft.Network/loadBalancers", "lb1", sku={"name": "Standard"},
        detail={"frontendIPConfigurations": [frontend("fe", pip=PIP_ZR)]}),
    row("Microsoft.Compute/virtualMachines", "vm-az", location=AZ, rg="rg-lab"),
]


@pytest.fixture
def arm(monkeypatch, tmp_path):
    def serve(graph_ok=True, **kwargs):
        session = _Arm(**kwargs)
        monkeypatch.setattr("requests.Session", lambda: session)
        monkeypatch.setattr(zr, "resource_graph_client", lambda cred: object())
        if graph_ok:
            monkeypatch.setattr(zr, "query_all", lambda client, sub, query: {
                "rows": [dict(r) for r in GRAPH_ROWS], "total_records": len(GRAPH_ROWS), "pages": 1})
        else:
            def _boom(client, sub, query):
                raise RuntimeError("Resource Graph reported the result as truncated")
            monkeypatch.setattr(zr, "query_all", _boom)
        return session

    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: _Cred())
    monkeypatch.setattr(azure_rest, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "s1")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    for env in ("AZURE_AUTHORITY_HOST", "AZURE_TENANT_ID", "AZURE_ENVIRONMENT", "AZURE_RESOURCE_EXCLUSIONS"):
        monkeypatch.delenv(env, raising=False)
    return serve


def _evidence(tmp_path):
    [path] = tmp_path.glob("azure_zone_redundancy_s1.json")
    return json.loads(path.read_text())


def test_main_joins_regions_public_ips_and_resources(arm, tmp_path, assert_summary_documented):
    arm()
    assert zr.main() == 0
    evidence = _evidence(tmp_path)
    assert evidence["metadata"]["partial_failure"] is False
    summary = evidence["summary"]
    assert_summary_documented("azure/zone_redundancy", summary)
    assert (summary["resources_assessed"], summary["zone_redundant_resources"], summary["regions_in_use"],
            summary["multi_region"], summary["zone_capable_resources"], summary["zone_redundant_percentage"],
            summary["resources_in_regions_without_zone_support"], summary["resource_list_read"],
            summary["all_zone_capable_resources_zone_redundant"]) == (
        4, 3, 2, True, 3, 100, 1, True, True)
    by_name = {r["name"]: r for r in evidence["results"]["resources"]}
    assert by_name["lb1"]["zone_configuration"] == zr.ZONE_REDUNDANT
    assert by_name["lb1"]["detail"]["frontends"][0]["zones"] == ["1", "2", "3"]
    assert [r["name"] for r in evidence["results"]["regions"]] == ["usgovarizona", "usgovvirginia"]
    assert evidence["results"]["regions"][1]["paired_regions"] == ["usgovtexas"]
    assert evidence["results"]["resource_graph"] == {"rows": 4, "total_records_reported": 4, "pages": 1}


def test_a_refused_region_list_fails_the_run_but_still_classifies(arm, tmp_path):
    arm(locations_status=403)
    assert zr.main() == 1
    evidence = _evidence(tmp_path)
    summary = evidence["summary"]
    assert (summary["region_support_read"], summary["zone_redundant_resources"], summary["zone_capable_resources"]) == (
        False, 3, None)
    assert all(r["region_supports_zones"] is None for r in evidence["results"]["resources"])
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


def test_a_failed_resource_graph_query_leaves_every_resource_count_null(arm, tmp_path):
    arm(graph_ok=False)
    assert zr.main() == 1
    evidence = _evidence(tmp_path)
    summary = evidence["summary"]
    assert (summary["resource_list_read"], summary["region_support_read"]) == (False, True)
    # An unread subscription is not an empty one: nothing that comes from the resources reads as a known 0 or false.
    for key in ("resources_assessed", "regions_in_use", "multi_region", "zone_capable_resources",
                "zone_redundant_percentage", "zone_redundant_resources", "resources_by_zone_configuration",
                "geo_redundant_resources", "regions", "in_scope_resources"):
        assert summary[key] is None, key
    assert summary["resource_types_assessed"] == list(zr.TYPES)
    assert (evidence["results"]["resources"], evidence["results"]["regions"]) == (None, None)


def test_a_failed_resource_graph_query_leaves_the_unmatched_patterns_null(arm, tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "rg:typo")
    arm(graph_ok=False)
    assert zr.main() == 1
    summary = _evidence(tmp_path)["summary"]
    assert (summary["resource_exclusion_patterns"], summary["resource_exclusion_patterns_unmatched"]) == (["rg:typo"], None)
    assert "matched nothing" not in caplog.text


def test_exclusions_take_a_resource_group_out_of_every_count(arm, tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_RESOURCE_EXCLUSIONS", "rg:rg-lab")
    arm()
    assert zr.main() == 0
    evidence = _evidence(tmp_path)
    summary = evidence["summary"]
    assert (summary["resources_assessed"], summary["excluded_resources"], summary["in_scope_resources"],
            summary["regions_in_use"], summary["resources_in_regions_without_zone_support"]) == (3, 1, 3, 1, 0)
    assert [e["name"] for e in evidence["results"]["excluded"]] == ["vm-az"]
