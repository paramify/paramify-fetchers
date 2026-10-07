"""Cover for wiz_inventory against an in-process fake Wiz GraphQL API.

No network and no credentials. The fake answers the token URL and
``cloudResourcesV2`` with node shapes taken from the live Wiz for Gov schema
(introspected 2026-10-06; values are synthetic).

What this proves: the filters sent to Wiz, the record shape a Paramify
inventory pipeline maps from, de-duplication, the light-query fallback, and the
exit-code contract. Run: ``pytest tests/test_wiz_inventory.py``
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WIZ = REPO_ROOT / "fetchers" / "wiz"
sys.path.insert(0, str(WIZ / "_shared"))

import wiz_client  # noqa: E402

API = "https://api.us2.app.wiz.us/graphql"
AUTH = "https://auth.app.wiz.us/oauth/token"
SECRET = "s3cr3t-value-that-must-never-appear-91ab"


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
        self.pages: List[List[Dict[str, Any]]] = [[]]
        self.error: str | None = None
        self.heavy_error: str | None = None   # fail only the full (typeFields) query
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, url, data=None, json=None, headers=None, timeout=None, allow_redirects=True):
        assert allow_redirects is False
        if url == AUTH:
            return FakeResponse(200, {"access_token": "tok1", "expires_in": 900})
        assert url == API and headers["Authorization"] == "Bearer tok1"
        query, variables = json["query"], json.get("variables") or {}
        self.calls.append({"query": query, "variables": variables})
        heavy = "typeFields" in query
        if self.error or (heavy and self.heavy_error):
            return FakeResponse(200, {"data": None, "errors": [{"message": self.error or self.heavy_error}]})
        idx = int(variables.get("after") or 0)
        nodes = self.pages[idx]
        if not heavy:  # a real server returns only what was selected
            keep = set(selected_fields(query))
            nodes = [{k: v for k, v in n.items() if k in keep} for n in nodes]
        has_next = idx + 1 < len(self.pages)
        return FakeResponse(200, {"data": {"cloudResourcesV2": {
            "nodes": nodes, "pageInfo": {"hasNextPage": has_next, "endCursor": str(idx + 1) if has_next else None}}}})


def selected_fields(query: str) -> List[str]:
    """Top-level node field names in a query (good enough for the light query)."""
    inner = query.split("nodes {", 1)[1]
    return [w for w in inner.replace("{", " { ").replace("}", " } ").split() if w.isidentifier()]


@pytest.fixture
def fake(monkeypatch, tmp_path) -> FakeWiz:
    f = FakeWiz()
    monkeypatch.setattr(wiz_client.requests, "post", f)
    monkeypatch.setattr(wiz_client.time, "sleep", lambda s: None)
    monkeypatch.setattr(wiz_client, "load_dotenv", lambda *a, **k: False)
    for k in ("WIZ_INVENTORY_RESOURCE_TYPES", "WIZ_INVENTORY_CLOUD_ACCOUNT_IDS", "WIZ_INVENTORY_PROJECT_IDS",
              "WIZ_ENVIRONMENT_TAG_KEYS", "WIZ_OWNER_TAG_KEYS", "WIZ_MAX_RECORDS", "WIZ_PAGE_SIZE"):
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
    spec = importlib.util.spec_from_file_location("wiz_inventory_under_test", WIZ / "inventory" / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(tmp_path: Path) -> tuple[int, Dict[str, Any]]:
    module = load()
    code = wiz_client.run_fetcher(module.collect, "wiz_inventory.json", module.logger)
    return code, json.loads((tmp_path / "wiz_inventory.json").read_text())


def vm(rid: str, *, tags=None, ips=None, owners=None, public=False) -> Dict[str, Any]:
    return {
        "id": rid, "name": f"vm-{rid}", "externalId": f"arn:aws:ec2:us-gov-west-1:111111111111:instance/i-{rid}",
        "providerUniqueId": f"i-{rid}", "type": "VIRTUAL_MACHINE", "nativeType": "virtualMachine",
        "cloudPlatform": "AWS", "status": "Active", "region": "us-gov-west-1",
        "firstSeen": "2026-09-01T00:00:00Z", "lastSeen": "2026-10-06T00:00:00Z",
        "isAccessibleFromInternet": public, "hasSensitiveData": False,
        "tags": tags or [],
        "cloudAccount": {"externalId": "111111111111", "name": "gov-prod"},
        "resourceGroup": None,
        "technology": {"name": "AWS EC2 Instance"},
        "owners": owners or [],
        "typeFields": {"__typename": "CloudResourceV2VirtualMachine", "instanceType": "m6i.large",
                       "operatingSystem": "LINUX", "ipAddresses": ips if ips is not None else ["10.0.0.5"],
                       "image": {"name": "ami-hardened"}, "kubernetesCluster": None},
    }


def image(rid: str) -> Dict[str, Any]:
    n = vm(rid)
    n.update({"type": "CONTAINER_IMAGE", "externalId": f"sha256:{rid}", "providerUniqueId": None,
              "technology": None,
              "typeFields": {"__typename": "CloudResourceV2ContainerImage",
                             "operatingSystemDistribution": {"name": "Alpine Linux"}}})
    return n


def test_records_shaped_for_the_inventory_pipeline(fake, tmp_path):
    fake.pages = [
        [vm("1", tags=[{"key": "environment", "value": "prod"}, {"key": "OWNER", "value": "platform-team"}],
            ips=["10.0.0.5", "10.0.0.6"], public=True)],
        [vm("2", owners=[{"graphEntity": {"name": "jane.doe"}}]), image("3")],
    ]
    code, ev = run(tmp_path)
    assert code == 0 and ev["status"] == "success" and ev["record_count"] == 3
    recs = {r["wiz_id"]: r for r in ev["data"]}

    one = recs["1"]
    assert one["unique_asset_identifier"].startswith("arn:aws:ec2:") and one["provider_unique_id"] == "i-1"
    assert one["environment"] == "prod" and one["owner"] == "platform-team"   # tag keys case-insensitive
    assert one["tags"] == ["OWNER=platform-team", "environment=prod"]
    assert one["ip_addresses"] == ["10.0.0.5", "10.0.0.6"] and one["primary_ip_address"] == "10.0.0.5"
    assert one["public"] is True and one["operating_system"] == "LINUX" and one["image"] == "ami-hardened"
    assert one["cloud_account_id"] == "111111111111" and one["detail_complete"] is True

    assert recs["2"]["owner"] == "jane.doe" and recs["2"]["environment"] is None   # Wiz's own owner as fallback
    assert recs["3"]["operating_system"] == "Alpine Linux" and recs["3"]["primary_ip_address"] is None

    a = ev["analysis"]
    assert a["resource_count"] == 3 and a["by_asset_type"] == {"VIRTUAL_MACHINE": 2, "CONTAINER_IMAGE": 1}
    assert a["internet_accessible_count"] == 1 and a["missing_environment_count"] == 2
    assert SECRET not in json.dumps(ev)


def test_every_record_has_the_same_keys(fake, tmp_path):
    fake.pages = [[vm("1"), image("2")]]
    _, ev = run(tmp_path)
    assert len({tuple(r) for r in ev["data"]}) == 1


def test_default_filter_is_the_type_list(fake, tmp_path):
    fake.pages = [[vm("1")]]
    run(tmp_path)
    assert fake.calls[0]["variables"]["filterBy"] == {"type": {"equals": load().DEFAULT_RESOURCE_TYPES}}


def test_account_and_project_filters(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_INVENTORY_RESOURCE_TYPES", "virtual_machine, db_server")
    monkeypatch.setenv("WIZ_INVENTORY_CLOUD_ACCOUNT_IDS", "111111111111,222222222222")
    monkeypatch.setenv("WIZ_INVENTORY_PROJECT_IDS", "proj-a")
    fake.pages = [[vm("1")]]
    code, ev = run(tmp_path)
    assert code == 0
    assert fake.calls[0]["variables"]["filterBy"] == {
        "type": {"equals": ["VIRTUAL_MACHINE", "DB_SERVER"]},
        "cloudAccountV2": {"externalId": {"equals": ["111111111111", "222222222222"]}},
        "project": {"idV2": {"equals": ["proj-a"]}},
    }
    assert ev["scope"]["project_ids"] == ["proj-a"]


def test_all_types_sends_no_type_filter(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_INVENTORY_RESOURCE_TYPES", "ALL")
    fake.pages = [[vm("1")]]
    code, _ = run(tmp_path)
    assert code == 0 and fake.calls[0]["variables"]["filterBy"] == {}


def test_wiz_error_fails_the_run_and_says_why(fake, tmp_path):
    fake.error = "access denied, at least one of the following is required: [read:resources]"
    code, ev = run(tmp_path)
    assert code == 1 and ev["api_failures"]
    assert "access denied" in json.loads((tmp_path / "status.json").read_text())["error"]


def test_record_cap_is_a_failure(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_MAX_RECORDS", "2")
    fake.pages = [[vm("1"), vm("2")], [vm("3")]]
    code, ev = run(tmp_path)
    assert code == 1 and ev["api_failures"][0]["type"] == "RecordCapReached"


def test_duplicates_across_pages_are_collapsed(fake, tmp_path):
    fake.pages = [[vm("1"), vm("2")], [vm("2")]]
    code, ev = run(tmp_path)
    assert code == 0 and ev["record_count"] == 2


def test_empty_inventory_is_not_a_failure(fake, tmp_path):
    code, ev = run(tmp_path)
    assert code == 0 and ev["status"] == "partial_or_empty" and "read:resources" in ev["message"]


def test_light_query_keeps_identity_and_flags_missing_detail(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_PAGE_SIZE", "10")
    fake.pages = [[vm("1")]]
    fake.heavy_error = "query too complex"
    code, ev = run(tmp_path)
    assert code == 0 and ev["scope"]["pages_served_by_light_query"] == 1
    rec = ev["data"][0]
    assert rec["unique_asset_identifier"].startswith("arn:aws:ec2:") and rec["detail_complete"] is False
    assert rec["operating_system"] is None and ev["analysis"]["records_missing_detail_count"] == 1


def test_queries_are_read_only():
    m = load()
    for q in (m.RESOURCES_QUERY, m.RESOURCES_QUERY_LIGHT):
        wiz_client.WizClient._assert_read_only(q)
        assert q.count("{") == q.count("}")
