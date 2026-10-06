"""Cover for wiz_inventory against an in-process fake Wiz GraphQL API.

No network and no credentials. The fake answers the token URL, enum
introspection (``__type``), ``cloudResourcesV2`` (count and pages) and
``inventoryFindings`` with node shapes taken from the live Wiz for Gov schema
(introspected 2026-10-06; values are synthetic).

What this proves: the filters sent to Wiz, enum validation before any paging,
the resource/finding join, the record shape a Paramify inventory pipeline maps
from, de-duplication, the pre-flight record cap, and the exit-code contract
(a failed findings pull fails the run; a failed count does not). What it
cannot prove: which Wiz scope grants ``inventoryFindings`` to a service
account. That needs one live run.

Run: ``pytest tests/test_wiz_inventory.py``
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WIZ = REPO_ROOT / "fetchers" / "wiz"
sys.path.insert(0, str(WIZ / "_shared"))

import wiz_client  # noqa: E402

API = "https://api.us2.app.wiz.us/graphql"
AUTH = "https://auth.app.wiz.us/oauth/token"
SECRET = "s3cr3t-value-that-must-never-appear-91ab"

ENTITY_TYPES = ["VIRTUAL_MACHINE", "CONTAINER", "CONTAINER_IMAGE", "KUBERNETES_CLUSTER", "DB_SERVER", "DATABASE",
                "BUCKET", "SERVERLESS", "LOAD_BALANCER", "GATEWAY", "FIREWALL", "VIRTUAL_NETWORK", "SUBNET",
                "VOLUME", "ENCRYPTION_KEY", "SECRET", "NETWORK_ADDRESS", "RAW_ACCESS_POLICY"]
PLATFORMS = ["AWS", "Azure", "GCP", "OCI"]


class FakeResponse:
    def __init__(self, status: int, body: Any):
        self.status_code = status
        self._body = body
        self.headers: Dict[str, str] = {}
        self.text = json.dumps(body)

    def json(self) -> Any:
        return self._body


class FakeWiz:
    def __init__(self) -> None:
        self.resource_pages: List[List[Dict[str, Any]]] = [[]]
        self.finding_pages: List[List[Dict[str, Any]]] = [[]]
        self.total: Optional[int] = None          # None: answer with the real number of nodes
        self.errors: Dict[str, str] = {}           # operation name -> GraphQL error message
        self.enums: Dict[str, Optional[List[str]]] = {"GraphEntityTypeValue": ENTITY_TYPES,
                                                      "CloudPlatform": PLATFORMS}
        self.calls: List[Dict[str, Any]] = []

    def ops(self, name: str) -> List[Dict[str, Any]]:
        return [c for c in self.calls if f"query {name}(" in c["query"]]

    def __call__(self, url, data=None, json=None, headers=None, timeout=None, allow_redirects=True):
        assert allow_redirects is False
        if url == AUTH:
            return FakeResponse(200, {"access_token": "tok1", "expires_in": 900})
        assert url == API and headers["Authorization"] == "Bearer tok1"
        query = json["query"]
        variables = json.get("variables") or {}
        self.calls.append({"query": query, "variables": variables})
        assert not query.lstrip().startswith("mutation")

        if "__type(" in query:
            name = query.split('__type(name: "', 1)[1].split('"', 1)[0]
            values = self.enums.get(name)
            if values is None:
                return FakeResponse(200, {"data": {"__type": None}})
            return FakeResponse(200, {"data": {"__type": {"enumValues": [{"name": v} for v in values]}}})

        for op in ("WizInventoryResourceCount", "WizInventoryResources", "WizInventoryFindings"):
            if f"query {op}(" in query and op in self.errors:
                return FakeResponse(200, {"data": None, "errors": [{"message": self.errors[op]}]})

        if "query WizInventoryResourceCount(" in query:
            total = self.total if self.total is not None else sum(len(p) for p in self.resource_pages)
            return FakeResponse(200, {"data": {"cloudResourcesV2": {"totalCount": total}}})

        root, pages = (("cloudResourcesV2", self.resource_pages) if "cloudResourcesV2(" in query
                       else ("inventoryFindings", self.finding_pages))
        idx = int(variables.get("after") or 0)
        has_next = idx + 1 < len(pages)
        nodes = pages[idx]
        if root == "cloudResourcesV2" and "typeFields" not in query:
            # A real server returns only what was selected.
            light = {"typeFields", "owners", "technology", "projects", "resourceGroup", "isAccessibleFromInternet",
                     "isOpenToAllInternet", "hasSensitiveData", "hasAdminPrivileges"}
            nodes = [{k: v for k, v in n.items() if k not in light} for n in nodes]
        return FakeResponse(200, {"data": {root: {
            "nodes": nodes,
            "pageInfo": {"hasNextPage": has_next, "endCursor": str(idx + 1) if has_next else None},
        }}})


@pytest.fixture
def fake(monkeypatch, tmp_path) -> FakeWiz:
    f = FakeWiz()
    monkeypatch.setattr(wiz_client.requests, "post", f)
    monkeypatch.setattr(wiz_client.time, "sleep", lambda s: None)
    monkeypatch.setattr(wiz_client, "load_dotenv", lambda *a, **k: False)
    for k in ("WIZ_INVENTORY_RESOURCE_TYPES", "WIZ_INVENTORY_CLOUD_PLATFORMS", "WIZ_INVENTORY_CLOUD_ACCOUNT_IDS",
              "WIZ_INVENTORY_PROJECT_IDS", "WIZ_INVENTORY_INCLUDE_DELETED", "WIZ_INVENTORY_INCLUDE_FINDINGS",
              "WIZ_INVENTORY_FINDING_STATUSES", "WIZ_ENVIRONMENT_TAG_KEYS", "WIZ_OWNER_TAG_KEYS", "WIZ_MAX_RECORDS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("WIZ_CLIENT_ID", "id")
    monkeypatch.setenv("WIZ_CLIENT_SECRET", SECRET)
    monkeypatch.setenv("WIZ_API_ENDPOINT_URL", API)
    monkeypatch.setenv("WIZ_AUTH_URL", AUTH)
    monkeypatch.setenv("WIZ_MIN_REQUEST_INTERVAL", "0")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    return f


def load() -> Any:
    path = WIZ / "inventory" / "fetcher.py"
    spec = importlib.util.spec_from_file_location("wiz_inventory_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(tmp_path: Path) -> tuple[int, Dict[str, Any]]:
    module = load()
    code = wiz_client.run_fetcher(module.collect, "wiz_inventory.json", module.logger)
    return code, json.loads((tmp_path / "wiz_inventory.json").read_text())


def status_code(tmp_path: Path) -> Optional[str]:
    p = tmp_path / "status.json"
    return json.loads(p.read_text()).get("code") if p.exists() else None


# --- synthetic nodes (shapes from the live schema) ------------------------------

def vm(rid: str, *, tags=None, ips=None, owners=None, account="111111111111", public=False) -> Dict[str, Any]:
    return {
        "id": rid, "name": f"vm-{rid}", "externalId": f"arn:aws:ec2:us-gov-west-1:{account}:instance/i-{rid}",
        "providerUniqueId": f"i-{rid}", "type": "VIRTUAL_MACHINE", "nativeType": "virtualMachine",
        "cloudPlatform": "AWS", "status": "Active", "region": "us-gov-west-1", "regionLocation": "US",
        "createdAt": "2026-09-01T00:00:00Z", "updatedAt": "2026-10-05T00:00:00Z", "deletedAt": None,
        "firstSeen": "2026-09-01T00:00:00Z", "lastSeen": "2026-10-06T00:00:00Z",
        "isAccessibleFromInternet": public, "isOpenToAllInternet": False, "hasSensitiveData": False,
        "hasAdminPrivileges": False,
        "tags": tags if tags is not None else [],
        "cloudAccount": {"id": "ca-1", "externalId": account, "name": "gov-prod", "cloudProvider": "AWS"},
        "resourceGroup": None,
        "projects": [{"id": "p1", "name": "FedRAMP Boundary"}],
        "technology": {"id": "t1", "name": "AWS EC2 Instance", "categories": [{"name": "Compute"}]},
        "owners": owners or [],
        "typeFields": {"__typename": "CloudResourceV2VirtualMachine", "instanceType": "m6i.large",
                       "operatingSystem": "LINUX", "ipAddresses": ips if ips is not None else ["10.0.0.5"],
                       "image": {"name": "ami-hardened"}, "kubernetesCluster": None},
    }


def image(rid: str) -> Dict[str, Any]:
    return {
        "id": rid, "name": f"repo/app:{rid}", "externalId": f"sha256:{rid}", "providerUniqueId": None,
        "type": "CONTAINER_IMAGE", "nativeType": "ContainerImage", "cloudPlatform": "AWS", "status": None,
        "region": "us-gov-west-1", "regionLocation": "US", "createdAt": None, "updatedAt": "2026-10-05T00:00:00Z",
        "deletedAt": None, "firstSeen": "2026-09-01T00:00:00Z", "lastSeen": "2026-10-06T00:00:00Z",
        "tags": [], "cloudAccount": {"id": "ca-1", "externalId": "111111111111", "name": "gov-prod",
                                     "cloudProvider": "AWS"},
        "projects": [], "technology": None, "owners": [],
        "typeFields": {"__typename": "CloudResourceV2ContainerImage",
                       "operatingSystemDistribution": {"name": "Alpine Linux"},
                       "containerRepository": {"name": "repo/app"}},
    }


def finding(fid: str, rid: str, rule: str, *, severity="LOW", rule_type="TAG_ENFORCEMENT",
            rtype="VIRTUAL_MACHINE") -> Dict[str, Any]:
    return {"id": fid, "status": "OPEN", "severity": severity, "createdAt": "2026-10-01T00:00:00Z",
            "updatedAt": "2026-10-01T00:00:00Z",
            "rule": {"id": f"r-{rule}", "name": rule, "ruleType": rule_type, "severity": severity},
            "resource": {"id": rid, "type": rtype, "name": f"res-{rid}", "externalId": f"ext-{rid}"}}


OWNER_RULE = "All taggable resources must have an owner tag"
ENV_RULE = "Resources should have a valid environment tag"
KEY_RULE = "Encryption keys and secrets not updated in 90 days should be rotated or revoked"


# --- tests ------------------------------------------------------------------

def test_inventory_joined_with_findings(fake, tmp_path):
    fake.resource_pages = [
        [vm("1", tags=[{"key": "environment", "value": "prod"}, {"key": "OWNER", "value": "platform-team"}],
            ips=["10.0.0.5", "10.0.0.6"], public=True)],
        [vm("2", owners=[{"type": "TAG", "graphEntity": {"id": "u1", "name": "soya", "type": "USER_ACCOUNT"}}]),
         image("3")],
    ]
    fake.finding_pages = [
        [finding("f1", "2", OWNER_RULE), finding("f2", "2", ENV_RULE, severity="MEDIUM")],
        [finding("f3", "ext-ip", OWNER_RULE, rtype="NETWORK_ADDRESS")],
    ]
    code, ev = run(tmp_path)
    assert code == 0, ev.get("api_failures")
    assert ev["status"] == "success" and ev["record_count"] == 3

    recs = {r["wiz_id"]: r for r in ev["data"]}
    one, two, img = recs["1"], recs["2"], recs["3"]

    # Identity: the cloud's own ID is the unique asset identifier.
    assert one["unique_asset_identifier"].startswith("arn:aws:ec2:") and one["provider_unique_id"] == "i-1"
    # Tags are matched case-insensitively and lifted to top-level fields.
    assert one["environment"] == "prod" and one["owner"] == "platform-team"
    assert one["missing_environment_tag"] is False and one["missing_owner_tag"] is False
    assert one["tags"] == ["OWNER=platform-team", "environment=prod"]
    assert one["ip_addresses"] == ["10.0.0.5", "10.0.0.6"] and one["primary_ip_address"] == "10.0.0.5"
    assert one["public"] is True and one["operating_system"] == "LINUX" and one["virtual"] is True
    assert one["cloud_account_id"] == "111111111111" and one["projects"] == ["FedRAMP Boundary"]
    assert one["inventory_finding_count"] == 0 and one["inventory_finding_max_severity"] is None
    assert one["detail_complete"] is True

    # No owner tag: falls back to the owner Wiz attributes, but still flagged as missing the tag.
    assert two["owner"] == "soya" and two["missing_owner_tag"] is True and two["environment"] is None
    assert two["inventory_finding_count"] == 2
    assert two["inventory_finding_max_severity"] == "MEDIUM"
    assert two["inventory_finding_rules"] == sorted([OWNER_RULE, ENV_RULE])
    assert two["inventory_findings"][0]["severity"] == "MEDIUM"  # most severe first

    # Container images report their OS distribution.
    assert img["operating_system"] == "Alpine Linux" and img["container_repository"] == "repo/app"
    assert img["ip_addresses"] == [] and img["primary_ip_address"] is None

    a = ev["analysis"]
    assert a["resource_count"] == 3 and a["wiz_reported_total"] == 3 and a["collected_matches_wiz_total"] is True
    assert a["by_asset_type"] == {"VIRTUAL_MACHINE": 2, "CONTAINER_IMAGE": 1}
    assert a["inventory_findings_collected"] == 3 and a["inventory_findings_on_inventory"] == 2
    assert a["findings_outside_inventory_count"] == 1
    assert a["findings_outside_inventory_by_resource_type"] == {"NETWORK_ADDRESS": 1}
    assert a["resources_with_findings_count"] == 1 and a["internet_accessible_count"] == 1
    assert ev["pipeline_hint"]["data_path"] == "payload.data"
    assert SECRET not in json.dumps(ev)


def test_default_filter_and_finding_filter_sent(fake, tmp_path):
    fake.resource_pages = [[vm("1")]]
    code, _ = run(tmp_path)
    assert code == 0
    page = fake.ops("WizInventoryResources")[0]["variables"]
    assert page["filterBy"] == {"type": {"equals": load().DEFAULT_RESOURCE_TYPES}}
    assert page["first"] == 100
    assert fake.ops("WizInventoryFindings")[0]["variables"]["filterBy"] == {
        "status": {"equals": ["OPEN", "IN_PROGRESS"]}}


def test_scope_filters_resolved_and_sent(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_INVENTORY_RESOURCE_TYPES", "virtual_machine, db_server")
    monkeypatch.setenv("WIZ_INVENTORY_CLOUD_PLATFORMS", "aws,azure")
    monkeypatch.setenv("WIZ_INVENTORY_CLOUD_ACCOUNT_IDS", "111111111111,222222222222")
    monkeypatch.setenv("WIZ_INVENTORY_PROJECT_IDS", "proj-a")
    monkeypatch.setenv("WIZ_INVENTORY_INCLUDE_DELETED", "true")
    monkeypatch.setenv("WIZ_INVENTORY_FINDING_STATUSES", "open")
    fake.resource_pages = [[vm("1")]]
    code, ev = run(tmp_path)
    assert code == 0
    f = fake.ops("WizInventoryResources")[0]["variables"]["filterBy"]
    assert f == {"type": {"equals": ["VIRTUAL_MACHINE", "DB_SERVER"]},
                 "cloudPlatform": {"equals": ["AWS", "Azure"]},  # enum case comes from Wiz, not the user
                 "cloudAccountV2": {"externalId": {"equals": ["111111111111", "222222222222"]}},
                 "project": {"idV2": {"equals": ["proj-a"]}},
                 "includeDeleted": True}
    assert fake.ops("WizInventoryResourceCount")[0]["variables"]["filterBy"] == f
    assert fake.ops("WizInventoryFindings")[0]["variables"]["filterBy"] == {
        "status": {"equals": ["OPEN"]}, "projects": {"equals": ["proj-a"]}}
    assert ev["scope"]["cloud_platforms"] == ["AWS", "Azure"] and ev["scope"]["include_deleted"] is True


def test_unknown_resource_type_refused_before_paging(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_INVENTORY_RESOURCE_TYPES", "VIRTUAL_MACHINE,SECURITY_GROUP")
    code, ev = run(tmp_path)
    assert code == 1 and ev["error_code"] == "bad_config" and "SECURITY_GROUP" in ev["message"]
    assert not fake.ops("WizInventoryResources")


def test_unknown_platform_and_status_refused(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_INVENTORY_CLOUD_PLATFORMS", "AWS,Mainframe")
    code, ev = run(tmp_path)
    assert code == 1 and ev["error_code"] == "bad_config" and "Mainframe" in ev["message"]
    monkeypatch.setenv("WIZ_INVENTORY_CLOUD_PLATFORMS", "")
    monkeypatch.setenv("WIZ_INVENTORY_FINDING_STATUSES", "OPEN,CLOSED")
    code, ev = run(tmp_path)
    assert code == 1 and ev["error_code"] == "bad_config" and "CLOSED" in ev["message"]


def test_all_types_sends_no_type_filter(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_INVENTORY_RESOURCE_TYPES", "ALL")
    fake.resource_pages = [[vm("1")]]
    code, ev = run(tmp_path)
    assert code == 0 and "type" not in fake.ops("WizInventoryResources")[0]["variables"]["filterBy"]
    assert ev["scope"]["resource_types"] == "ALL"
    monkeypatch.setenv("WIZ_INVENTORY_RESOURCE_TYPES", "ALL,VIRTUAL_MACHINE")
    code, ev = run(tmp_path)
    assert code == 1 and ev["error_code"] == "bad_config"


def test_introspection_unavailable_passes_values_through(fake, tmp_path, monkeypatch):
    fake.enums = {"GraphEntityTypeValue": None, "CloudPlatform": None}
    monkeypatch.setenv("WIZ_INVENTORY_RESOURCE_TYPES", "VIRTUAL_MACHINE")
    fake.resource_pages = [[vm("1")]]
    code, ev = run(tmp_path)
    assert code == 0 and ev["api_failures"] == []
    assert fake.ops("WizInventoryResources")[0]["variables"]["filterBy"]["type"] == {"equals": ["VIRTUAL_MACHINE"]}


def test_findings_failure_fails_run_but_keeps_inventory(fake, tmp_path):
    fake.resource_pages = [[vm("1"), vm("2")]]
    fake.errors["WizInventoryFindings"] = "You are not authorized to perform this action"
    code, ev = run(tmp_path)
    assert code == 1
    assert ev["record_count"] == 2 and ev["metadata"]["partial_failure"] is True
    assert ev["api_failures"][0]["operation"] == "inventoryFindings"
    assert status_code(tmp_path) == "not_authorized"


def test_findings_can_be_turned_off(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_INVENTORY_INCLUDE_FINDINGS", "false")
    fake.resource_pages = [[vm("1")]]
    fake.errors["WizInventoryFindings"] = "must not be called"
    code, ev = run(tmp_path)
    assert code == 0 and not fake.ops("WizInventoryFindings")
    assert ev["operations"] == ["cloudResourcesV2"] and "inventory_findings_collected" not in ev["analysis"]
    assert ev["scope"]["finding_statuses"] is None


def test_count_failure_does_not_fail_run(fake, tmp_path):
    fake.resource_pages = [[vm("1")]]
    fake.errors["WizInventoryResourceCount"] = "an internal error has occurred"
    code, ev = run(tmp_path)
    assert code == 0 and ev["api_failures"] == []
    assert ev["analysis"]["wiz_reported_total"] is None and ev["analysis"]["collected_matches_wiz_total"] is None


def test_resource_failure_is_a_failure(fake, tmp_path):
    fake.errors["WizInventoryResources"] = "You are not authorized to perform this action"
    code, ev = run(tmp_path)
    assert code == 1 and ev["api_failures"]
    assert status_code(tmp_path) == "not_authorized"


def test_preflight_cap_refuses_oversized_pull(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_MAX_RECORDS", "10")
    fake.total = 3574
    code, ev = run(tmp_path)
    assert code == 1 and ev["error_code"] == "bad_config" and "3574" in ev["message"]
    assert not fake.ops("WizInventoryResources")


def test_cap_reached_while_paging_is_a_failure(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_MAX_RECORDS", "2")
    fake.total = 1  # Wiz under-reported; the paging guard still catches it
    fake.resource_pages = [[vm("1"), vm("2")], [vm("3")]]
    code, ev = run(tmp_path)
    assert code == 1 and ev["api_failures"][0]["type"] == "RecordCapReached"


def test_duplicates_across_pages_are_collapsed(fake, tmp_path):
    fake.resource_pages = [[vm("1"), vm("2")], [vm("2")]]
    code, ev = run(tmp_path)
    assert code == 0 and ev["record_count"] == 2
    assert ev["analysis"]["collected_matches_wiz_total"] is False  # 3 reported, 2 unique


def test_empty_inventory_is_not_a_failure(fake, tmp_path):
    code, ev = run(tmp_path)
    assert code == 0 and ev["status"] == "partial_or_empty" and "read:resources" in ev["message"]


def test_light_query_fallback_is_counted(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_PAGE_SIZE", "10")
    fake.resource_pages = [[vm("1")]]
    real = fake.__call__

    def heavy_fails(url, data=None, json=None, headers=None, timeout=None, allow_redirects=True):
        if json and "query WizInventoryResources(" in json["query"] and "typeFields" in json["query"]:
            return FakeResponse(200, {"data": None, "errors": [{"message": "query too complex"}]})
        return real(url, data=data, json=json, headers=headers, timeout=timeout, allow_redirects=allow_redirects)

    monkeypatch.setattr(wiz_client.requests, "post", heavy_fails)
    code, ev = run(tmp_path)
    assert code == 0 and ev["record_count"] == 1
    assert ev["scope"]["pages_served_by_light_query"] == 1
    rec = ev["data"][0]
    assert rec["operating_system"] is None and rec["detail_complete"] is False  # the light query has no detail
    assert rec["unique_asset_identifier"].startswith("arn:aws:ec2:")  # identity survives
    assert ev["analysis"]["records_missing_detail_count"] == 1


def test_queries_are_read_only_and_well_formed():
    m = load()
    for q in (m.RESOURCES_QUERY, m.RESOURCES_QUERY_LIGHT, m.RESOURCES_COUNT_QUERY, m.FINDINGS_QUERY):
        wiz_client.WizClient._assert_read_only(q)
        assert q.count("{") == q.count("}")
