"""Strict mixed Entra reads fail closed before unverified directory data is read."""

import importlib.util
import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "fetchers/azure/_shared"))
from azure_common import Collector, build_payload
from azure_rest import ArmError, AzureRestClient

SUB = "11111111-1111-4111-8111-111111111111"
TENANT = "22222222-2222-4222-8222-222222222222"
FOREIGN = "33333333-3333-4333-8333-333333333333"
ARM = "https://management.usgovcloudapi.net"
GRAPH = "https://graph.microsoft.us"


class Session:
    def __init__(self, subscription_tenant=TENANT, graph_tenant=TENANT, errors=None):
        self.subscription_tenant = subscription_tenant
        self.graph_tenant = graph_tenant
        self.errors = errors or {}
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        path = urlsplit(url).path
        status = self.errors.get(path, 200)
        if status != 200:
            body = {"error": {"code": "UnsupportedReport", "message": "Report unavailable in this cloud"}}
        elif path == f"/subscriptions/{SUB}":
            body = {"id": path, "tenantId": self.subscription_tenant}
        elif path == "/v1.0/organization":
            body = {"value": [{"id": self.graph_tenant}] if self.graph_tenant else []}
        else:
            body = {"value": []}
        return SimpleNamespace(status_code=status, json=lambda: body, reason="Error", text="Error")


class Credential:
    def __init__(self):
        self.scopes = []

    def get_token(self, scope):
        self.scopes.append(scope)
        return SimpleNamespace(token="synthetic-only", expires_on=9999999999)


@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setenv("AZURE_TARGET_SUBSCRIPTION_ONLY", "true")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    monkeypatch.setenv("AZURE_TENANT_ID", TENANT)
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.us")
    monkeypatch.delenv("ENTRA_EMERGENCY_ACCOUNTS", raising=False)
    monkeypatch.delenv("SENTINEL_WORKSPACES", raising=False)


@pytest.fixture(params=["entra_emergency_accounts", "entra_dormant_identities"])
def source(request):
    path = ROOT / "fetchers/azure" / request.param / "fetcher.py"
    spec = importlib.util.spec_from_file_location("strict_" + request.param, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_strict_subscription_root_get_can_read_its_tenant(strict):
    session, credential = Session(), Credential()
    client = AzureRestClient(credential, session)
    assert client.get(f"/subscriptions/{SUB}", "2022-12-01")["tenantId"] == TENANT
    assert [url for url, _ in session.calls] == [ARM + f"/subscriptions/{SUB}"]
    assert session.calls[0][1]["allow_redirects"] is False
    assert credential.scopes == [ARM + "/.default"]


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_strict_subscription_root_does_not_allow_source_writes(strict, method):
    session, credential = Session(), Credential()
    client = AzureRestClient(credential, session)
    with pytest.raises(ValueError, match="scope"):
        client._send(method, ARM + f"/subscriptions/{SUB}", ARM)
    assert session.calls == [] and credential.scopes == []


@pytest.mark.parametrize("link", [
    ARM + f"/subscriptions/{FOREIGN}/items",
    "https://untrusted.example/subscriptions/" + SUB + "/items",
])
def test_strict_foreign_continuation_fails_before_second_send(strict, link):
    session, credential = Session(), Credential()
    client = AzureRestClient(credential, session)
    original = session.get

    def first(url, **kwargs):
        original(url, **kwargs)
        return SimpleNamespace(status_code=200, json=lambda: {"value": [], "nextLink": link})

    session.get = first
    with pytest.raises(ValueError):
        client.list(f"/subscriptions/{SUB}/items", "x")
    assert len(session.calls) == 1


def test_strict_subscription_root_redirect_is_not_followed(strict):
    session, credential = Session(errors={f"/subscriptions/{SUB}": 302}), Credential()
    client = AzureRestClient(credential, session)
    with pytest.raises(ArmError, match="Redirect"):
        client.get(f"/subscriptions/{SUB}", "2022-12-01")
    assert len(session.calls) == 1 and session.calls[0][1]["allow_redirects"] is False


@pytest.mark.parametrize("configured,subscription,graph,expected_paths", [
    (None, TENANT, TENANT, [f"/subscriptions/{SUB}"]),
    (TENANT, None, TENANT, [f"/subscriptions/{SUB}"]),
    (TENANT, FOREIGN, TENANT, [f"/subscriptions/{SUB}"]),
    (TENANT, TENANT, None, [f"/subscriptions/{SUB}", "/v1.0/organization"]),
    (TENANT, TENANT, FOREIGN, [f"/subscriptions/{SUB}", "/v1.0/organization"]),
])
def test_unverified_tenant_blocks_directory_data(
    strict, monkeypatch, source, configured, subscription, graph, expected_paths
):
    if configured is None:
        monkeypatch.delenv("AZURE_TENANT_ID")
    else:
        monkeypatch.setenv("AZURE_TENANT_ID", configured)
    session = Session(subscription, graph)
    collector = Collector(logging.getLogger("strict-tenant-test"))
    results, summary = source.collect(AzureRestClient(Credential(), session), SUB, collector)
    assert [urlsplit(url).path for url, _ in session.calls] == expected_paths
    assert collector.ok is False and collector.failures
    payload = build_payload(subscription_id=SUB, subscription_source="target", collector=collector,
                            results=results, summary=summary)
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"] == collector.failures
    assert results.get("users", results.get("emergency_accounts")) == []


def test_refused_graph_tenant_blocks_directory_data(strict, source):
    session = Session(errors={"/v1.0/organization": 403})
    collector = Collector(logging.getLogger("strict-tenant-test"))
    results, summary = source.collect(AzureRestClient(Credential(), session), SUB, collector)
    assert [urlsplit(url).path for url, _ in session.calls] == [f"/subscriptions/{SUB}", "/v1.0/organization"]
    assert collector.ok is False
    assert any("UnsupportedReport" in failure["message"] for failure in collector.failures)


def test_matching_government_tenant_permits_scoped_reads(strict, source):
    session, credential = Session(), Credential()
    collector = Collector(logging.getLogger("strict-tenant-test"))
    results, summary = source.collect(AzureRestClient(credential, session), SUB, collector)
    assert collector.ok is True
    assert results["tenant_id"] == TENANT
    paths = [urlsplit(url).path for url, _ in session.calls]
    assert paths[:2] == [f"/subscriptions/{SUB}", "/v1.0/organization"]
    assert len(paths) > 2
    assert all(url.startswith(GRAPH + "/") or url.startswith(ARM + f"/subscriptions/{SUB}")
               for url, _ in session.calls)
    assert all(options["allow_redirects"] is False for _, options in session.calls)
    assert set(credential.scopes) == {ARM + "/.default", GRAPH + "/.default"}


def test_government_unsupported_dormancy_report_remains_a_visible_failure(strict):
    spec = importlib.util.spec_from_file_location(
        "strict_dormant_failure", ROOT / "fetchers/azure/entra_dormant_identities/fetcher.py"
    )
    source = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(source)
    session = Session(errors={"/beta/reports/servicePrincipalSignInActivities": 404})
    collector = Collector(logging.getLogger("strict-tenant-test"))
    results, summary = source.collect(AzureRestClient(Credential(), session), SUB, collector)
    assert summary["tenant_readable"] is True
    assert summary["service_principal_sign_in_activity"] == "not_read"
    assert summary["dormant_service_principals_holding_roles"] is None
    assert collector.ok is False
    assert len(collector.failures) == 1
    assert "UnsupportedReport" in collector.failures[0]["message"]


def test_unverified_tenant_writes_failed_native_evidence(strict, source, monkeypatch, tmp_path):
    import azure_rest

    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: Credential())
    session = Session(subscription_tenant=None)
    exit_code = azure_rest.run_subscription(
        fetcher=source.NAME, logger=logging.getLogger("strict-native-test"),
        collect=source.collect, session=session,
    )
    assert exit_code == 1
    evidence = json.loads((tmp_path / f"{source.NAME}_{SUB}.json").read_text())
    assert evidence["metadata"]["subscription_source"] == "target"
    assert evidence["metadata"]["partial_failure"] is True
    assert evidence["metadata"]["api_failures"]
    assert evidence["results"]["read_scope"] == "target_subscription"
    assert [urlsplit(url).path for url, _ in session.calls] == [f"/subscriptions/{SUB}"]
