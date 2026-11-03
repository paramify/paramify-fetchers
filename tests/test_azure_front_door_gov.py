"""Front Door fetchers on Azure Government: the Microsoft.Cdn api-version follows the cloud, and the WAF
coverage fetcher reports what that version can't show as unknown, never as unprotected.

No network, no tenant: the SDK client is replaced with a recorder.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

import frontdoor as fd  # noqa: E402

GOV_AUTHORITY = "https://login.microsoftonline.us"
GOV = fd.GOVERNMENT_CDN_API_VERSION
FETCHERS = ("front_door_origins", "front_door_tls", "front_door_waf_coverage")
SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_gov_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


coverage = _load("front_door_waf_coverage")
origins = _load("front_door_origins")


class _FakeCredential:
    def get_token(self, *args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("tests must not authenticate")


class _RecordingCdnClient:
    """Stands in for CdnManagementClient: records api_version and base_url, lists no profiles."""

    built: list = []

    def __init__(self, credential=None, subscription_id=None, api_version=None, base_url=None, **kwargs):
        _RecordingCdnClient.built.append((api_version, base_url))
        self.profiles = self

    def list(self):
        return []


class _Model(dict):
    """An SDK model stand-in: snake_case attributes and wire keys, like the hybrid models."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None


@pytest.fixture
def recorder(monkeypatch):
    # A stand-in module, so these tests also run in the CI test job, which does not
    # install the azure extra. test_azure_sdk_surface.py pins the real SDK surface.
    _RecordingCdnClient.built = []
    monkeypatch.setitem(sys.modules, "azure.mgmt.cdn", ModuleType("azure.mgmt.cdn"))
    sys.modules["azure.mgmt.cdn"].CdnManagementClient = _RecordingCdnClient
    # front_door_waf_coverage also builds a Monitor client; with no profiles it is never called.
    monkeypatch.setitem(sys.modules, "azure.mgmt.monitor", ModuleType("azure.mgmt.monitor"))
    sys.modules["azure.mgmt.monitor"].MonitorManagementClient = lambda **kwargs: object()
    return _RecordingCdnClient


@pytest.mark.parametrize(
    "authority, expected",
    [
        (GOV_AUTHORITY, True),
        (GOV_AUTHORITY + "/", True),
        ("login.microsoftonline.us", True),
        ("https://login.microsoftonline.com", False),
        ("", False),
    ],
)
def test_is_government_cloud(monkeypatch, authority, expected) -> None:
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", authority)
    assert fd.is_government_cloud() is expected


def test_api_version_follows_the_cloud(monkeypatch) -> None:
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    assert fd.cdn_api_version("2026-07-01") == "2026-07-01"
    assert fd.cdn_api_version(None) is None
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", GOV_AUTHORITY)
    assert fd.cdn_api_version("2026-07-01") == GOV
    assert fd.cdn_api_version(None) == GOV


@pytest.mark.parametrize("name", FETCHERS)
def test_every_cdn_client_uses_gov_version_on_gov(name, recorder, monkeypatch) -> None:
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", GOV_AUTHORITY)
    module = _load(name)
    module.collect_profiles(SUBSCRIPTION_ID, _FakeCredential(), module.Collector(logging.getLogger("test")))
    assert recorder.built, f"{name}: no Microsoft.Cdn client was built"
    assert {v for v, _ in recorder.built} == {GOV}
    assert {u for _, u in recorder.built} == {fd.GOVERNMENT_ARM_ENDPOINT}


@pytest.mark.parametrize("name, pinned", [
    ("front_door_origins", {None, "2026-07-01"}),
    ("front_door_tls", {None}),
    ("front_door_waf_coverage", {None, "2026-07-01"}),
])
def test_public_cloud_versions_are_unchanged(name, pinned, recorder, monkeypatch) -> None:
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    module = _load(name)
    module.collect_profiles(SUBSCRIPTION_ID, _FakeCredential(), module.Collector(logging.getLogger("test")))
    assert {v for v, _ in recorder.built} <= pinned
    assert GOV not in {v for v, _ in recorder.built}


def test_reported_versions_are_the_ones_used(monkeypatch) -> None:
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    assert coverage.summarize([], {}, [], [], [], [])["security_policies_api_version"] == "2026-07-01"
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", GOV_AUTHORITY)
    assert coverage.summarize([], {}, [], [], [], [])["security_policies_api_version"] == GOV
    assert origins.cdn_api_version(origins.ORIGIN_API_VERSION) == GOV


@pytest.mark.parametrize("version, expected", [
    (None, True), ("2026-07-01", True), ("2026-10-01", True), ("2026-04-01-preview", True), ("2025-12-01", False),
])
def test_has_scope_fields(version, expected) -> None:
    assert fd.has_scope_fields(version) is expected


def _policy_model():
    return _Model(
        id="/sp/1", name="sp1",
        properties=_Model(deployment_status=None, provisioning_state="Succeeded", parameters=_Model(
            type="WebApplicationFirewall", waf_policy=_Model(id="/waf/1"), isProfileLevel=True,
            associations=[_Model(domains=[_Model(id="/domains/d1", is_active=True)], routes=[{"id": "/routes/r1"}],
                                 patterns_to_match=["/*"])],
        )),
    )


def test_unread_scope_fields_are_none_not_false() -> None:
    read = coverage.project_security_policy(_policy_model())
    assert read["is_profile_level"] is True and read["associations"][0]["routes"] == ["/routes/r1"]
    unread = coverage.project_security_policy(_policy_model(), scope_fields=False)
    assert unread["is_profile_level"] is None and unread["associations"][0]["routes"] is None
    assert unread["associations"][0]["domains"] == [{"id": "/domains/d1", "is_active": True}]


def _sp(domains, routes, is_profile_level):
    return {"id": "sp", "name": "sp", "type": "WebApplicationFirewall", "is_profile_level": is_profile_level,
            "waf_policy_id": "/waf/1",
            "associations": [{"domains": [{"id": d, "is_active": True} for d in domains], "routes": routes,
                              "patterns_to_match": ["/*"]}]}


def _record(host_id, security_policies, waf_by_key=None):
    return coverage.host_route_record(
        {"name": "p", "sku": "Premium_AzureFrontDoor"},
        {"id": "/endpoints/e", "name": "e", "host_name": "e.azurefd.net", "enabled_state": "Enabled"},
        {"id": "/routes/r1", "name": "r1", "enabled_state": "Enabled", "supported_protocols": ["Https"],
         "https_redirect": None},
        {"id": host_id, "host_name": "app.example.com", "kind": "custom_domain", "is_active": True},
        security_policies, waf_by_key or {},
    )


def test_unlisted_host_is_unknown_when_scope_fields_unread() -> None:
    record = _record("/domains/other", [_sp(["/domains/d1"], None, None)])
    assert record["effective_scope"] == "unknown"
    assert record["protected"] is None and record["waf_blocking"] is None
    assert record["unprotected_reasons"] == []


def test_listed_host_still_resolves_to_domain_when_scope_fields_unread() -> None:
    record = _record("/domains/d1", [_sp(["/domains/d1"], None, None)])
    assert record["effective_scope"] == "domain"


def test_no_waf_policy_at_all_is_still_none() -> None:
    record = _record("/domains/d1", [])
    assert record["effective_scope"] == "none"
    assert record["protected"] is False and record["unprotected_reasons"] == ["no_waf"]


def test_read_scope_fields_keep_none_scope() -> None:
    record = _record("/domains/other", [_sp(["/domains/d1"], [], False)])
    assert record["effective_scope"] == "none" and record["protected"] is False


def test_summary_counts_unknown_apart() -> None:
    unknown = _record("/domains/other", [_sp(["/domains/d1"], None, None)])
    none = _record("/domains/d1", [])
    summary = coverage.summarize([], {}, [unknown, none], [], [], [])
    assert summary["serving_host_routes"] == 2
    assert summary["unknown_host_routes"] == 1 and summary["host_routes_unknown_scope"] == 1
    assert summary["unprotected_host_routes"] == 1 and summary["host_routes_without_waf"] == 1
    assert summary["protected_host_route_percentage"] is None

    public = coverage.summarize([], {}, [none], [], [], [])
    assert public["unknown_host_routes"] == 0 and public["host_routes_unknown_scope"] == 0
    assert public["protected_host_route_percentage"] == 0
