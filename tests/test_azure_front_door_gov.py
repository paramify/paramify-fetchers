"""Azure Government Front Door variants: every Microsoft.Cdn client is pinned to the Gov API version.

No network, no tenant: the SDK client is replaced with a recorder.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

import frontdoor_gov  # noqa: E402

ORIGINALS = ("front_door_origins", "front_door_tls", "front_door_waf_coverage")
GOV = frontdoor_gov.GOV_CDN_API_VERSION
SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"


class _FakeCredential:
    def get_token(self, *args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("tests must not authenticate")


class _RecordingCdnClient:
    """Stands in for CdnManagementClient: records api_version, lists no profiles."""

    built: list = []

    def __init__(self, credential=None, subscription_id=None, api_version=None, **kwargs):
        _RecordingCdnClient.built.append(api_version)
        self.profiles = self

    def list(self):
        return []


def _load_original(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_original_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


@pytest.mark.parametrize("original", ORIGINALS)
def test_every_cdn_client_uses_gov_version(original, recorder) -> None:
    module = frontdoor_gov.load_gov_variant(original)
    collector = module.Collector(logging.getLogger("test"))
    module.collect_profiles(SUBSCRIPTION_ID, _FakeCredential(), collector)
    assert recorder.built, f"{original}: no Microsoft.Cdn client was built"
    assert set(recorder.built) == {GOV}, f"{original}: built clients with {recorder.built}, expected only {GOV}"


@pytest.mark.parametrize("original", ORIGINALS)
def test_explicit_version_is_overridden(original, recorder) -> None:
    module = frontdoor_gov.load_gov_variant(original)
    collector = module.Collector(logging.getLogger("test"))
    module.cdn_client(SUBSCRIPTION_ID, _FakeCredential(), collector, api_version="2026-07-01")
    assert recorder.built == [GOV]


@pytest.mark.parametrize("original", ORIGINALS)
def test_reported_versions_match_gov(original) -> None:
    module = frontdoor_gov.load_gov_variant(original)
    for name in frontdoor_gov.PINNED_VERSION_CONSTANTS:
        if hasattr(module, name):
            assert getattr(module, name) == GOV


def test_public_cloud_fetchers_are_untouched() -> None:
    """Loading a Gov variant must not change the public-cloud fetchers' pins."""
    for original in ORIGINALS:
        frontdoor_gov.load_gov_variant(original)
    origins = _load_original("front_door_origins")
    coverage = _load_original("front_door_waf_coverage")
    assert origins.ORIGIN_API_VERSION != GOV
    assert coverage.SECURITY_POLICY_API_VERSION != GOV


@pytest.mark.parametrize("original", ORIGINALS)
def test_gov_contract_mirrors_original(original) -> None:
    base = yaml.safe_load((AZURE / original / "fetcher.yaml").read_text())
    gov = yaml.safe_load((AZURE / f"{original}_gov" / "fetcher.yaml").read_text())
    assert gov["name"] == f"azure_{original}_gov"
    assert gov["category"] == base["category"] == "azure"
    assert gov["evidence_set"]["reference_id"] == base["evidence_set"]["reference_id"]
    assert gov["ksis"] == base["ksis"]
    assert gov["target_schema"] == base["target_schema"]
    assert gov["config_schema"] == base["config_schema"]
    assert GOV in gov["description"]
    assert f"azure/{original}_gov/fetcher.py" in gov["evidence_set"]["instructions"]


@pytest.mark.parametrize(
    "authority, expected",
    [
        ("https://login.microsoftonline.us", True),
        ("https://login.microsoftonline.us/", True),
        ("login.microsoftonline.us", True),
        ("https://login.microsoftonline.com", False),
        ("", False),
    ],
)
def test_is_gov_authority(authority, expected) -> None:
    assert frontdoor_gov.is_gov_authority(authority) is expected


def test_run_gov_variant_calls_original_main(monkeypatch) -> None:
    class _Fake:
        def main(self):
            return 7

    monkeypatch.setattr(frontdoor_gov, "load_gov_variant", lambda original: _Fake())
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.us")
    assert frontdoor_gov.run_gov_variant("front_door_tls") == 7
