"""azure_devops_service_connections, driven without Azure DevOps.

FakeADO stands in for requests.Session and serves one organization with two
projects sharing a workload-identity connection, plus connections holding a
service principal secret or certificate, a password, a publish profile, a NuGet
API key and a Kubernetes token, variable groups (one Key Vault-linked) and a
secure file. Bodies follow the Azure DevOps REST 7.1 reference samples; every
credential in them carries MARK, and run() checks that none reaches the evidence.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "devops_service_connections" / "fetcher.py"
spec = importlib.util.spec_from_file_location("azure_devops_service_connections_under_test", FETCHER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
dr = sys.modules["devops_rest"]

ORG = "https://dev.azure.com/contoso"
WEB, OPS = "p-web", "p-ops"
NOW = datetime.now(timezone.utc)
TENANT = "00000000-0000-0000-0000-0000000000aa"
SUB = "00000000-0000-0000-0000-000000000001"
WIF_APP = "1A2B3C4D-0000-4000-8000-00000000000F"
OTHER_TENANT = "00000000-0000-0000-0000-0000000000bb"
SECRET_APP = "5e6f7a8b-0000-4000-8000-000000000001"
CERT_APP = "9c0d1e2f-0000-4000-8000-000000000002"
WIF_ID, SECRET_ID, GENERIC_ID = "e-wif", "e-secret", "e-generic"
CERT_ID, PUBLISH_ID, NUGET_ID, AKS_ID = "e-cert", "e-publish", "e-nuget", "e-aks"
MARK = "must-not-appear"
SPN_KEY = f"spn-key-{MARK}"
PASSWORD = f"pass/word-{MARK}"
CERTIFICATE = f"-----BEGIN CERTIFICATE-----{MARK}"
PUBLISH_PROFILE = f"<publishData userPWD='{MARK}'/>"
NUGET_KEY = f"oy2-{MARK}"
API_TOKEN = f"eyJ-{MARK}"
SECRET_VALUE = f"variable-value-{MARK}"
PLAIN_VALUE = f"plain-value-{MARK}"
# The raw authenticationType values and WIF claims are mapped or dropped, never echoed.
NEVER_WRITTEN = (MARK, "spnKey", "spnCertificate", "workloadIdentityFederationSubject", "/eid1/", "svc:", "pa?ss")


def ago(**kw):
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%S.%f0Z")


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body = status, body
        self.headers = headers or {}
        self.text = json.dumps(body)
        self.reason = "OK" if status < 400 else "Error"

    def json(self):
        return self._body


def err(status, message, type_key="Exception"):
    return Resp(status, {"$id": "1", "message": message, "typeKey": type_key, "errorCode": 0})


def project_ref(pid, name, own="shared"):
    return {"projectReference": {"id": pid, "name": name}, "name": own}


def endpoints(*projects):
    wif = {
        "id": WIF_ID, "name": "prod-wif", "type": "azurerm", "url": "https://management.azure.com/", "owner": "Library",
        "data": {"environment": "AzureCloud", "scopeLevel": "Subscription", "subscriptionId": SUB,
                 "subscriptionName": "Production", "creationMode": "Automatic", "spnObjectId": "obj-1",
                 "appObjectId": "app-obj-1", "azureSpnRoleAssignmentId": "ra-1"},
        "authorization": {"scheme": "WorkloadIdentityFederation", "parameters": {
            "serviceprincipalid": WIF_APP, "tenantid": TENANT,
            "workloadIdentityFederationIssuer": "https://login.microsoftonline.com/tenant/v2.0",
            "workloadIdentityFederationSubject": "/eid1/c/pub/t/x/a/y/sc/z"}},
        "isShared": True, "isReady": True,
        "createdBy": {"id": "u1", "displayName": "Ada Admin", "uniqueName": "ada@example.com"},
        "serviceEndpointProjectReferences": [project_ref(WEB, "Web", "prod-wif"),
                                             project_ref(OPS, "Ops", "prod-wif-ops")],
    }
    secret = {
        "id": SECRET_ID, "name": "legacy-spn", "type": "azurerm", "url": "https://management.azure.com/",
        "data": {"scopeLevel": "ManagementGroup", "managementGroupId": "mg-root", "creationMode": "Manual"},
        "authorization": {"scheme": "ServicePrincipal", "parameters": {
            "serviceprincipalid": SECRET_APP, "tenantid": TENANT, "authenticationType": "spnKey",
            "serviceprincipalkey": SPN_KEY}},
        "isShared": False, "isReady": True, "serviceEndpointProjectReferences": [project_ref(WEB, "Web")],
    }
    generic = {
        "id": GENERIC_ID, "name": "artifact-feed", "type": "Generic",
        "url": f"https://svc:{PASSWORD}@feed.example.com/path?sig={MARK}",
        "authorization": {"scheme": "UsernamePassword", "parameters": {"username": "svc", "password": PASSWORD}},
        "isShared": False, "isReady": False, "serviceEndpointProjectReferences": [project_ref(WEB, "Web")],
    }
    cert = {
        "id": CERT_ID, "name": "signing-spn", "type": "azurerm", "url": "https://management.azure.com/",
        "data": {"scopeLevel": "Subscription", "subscriptionId": SUB, "creationMode": "Manual"},
        "authorization": {"scheme": "ServicePrincipal", "parameters": {
            "serviceprincipalid": CERT_APP, "tenantid": TENANT, "authenticationType": "spnCertificate",
            "servicePrincipalCertificate": CERTIFICATE}},
        "isShared": False, "isReady": True, "serviceEndpointProjectReferences": [project_ref(OPS, "Ops")],
    }
    publish = {
        "id": PUBLISH_ID, "name": "web-deploy", "type": "azurerm", "url": "https://management.azure.com/",
        "data": {"scopeLevel": "Subscription", "subscriptionId": SUB},
        "authorization": {"scheme": "PublishProfile", "parameters": {"publishProfile": PUBLISH_PROFILE}},
        "isShared": False, "isReady": True, "serviceEndpointProjectReferences": [project_ref(OPS, "Ops")],
    }
    nuget = {
        "id": NUGET_ID, "name": "nuget-feed", "type": "externalnugetfeed",
        "url": f"https://svc:pa?ss-{MARK}@nuget.example.com/v3/index.json",
        "authorization": {"scheme": "None", "parameters": {"nugetkey": NUGET_KEY}},
        "isShared": False, "isReady": True, "serviceEndpointProjectReferences": [project_ref(OPS, "Ops")],
    }
    aks = {
        "id": AKS_ID, "name": "aks-deployer", "type": "kubernetes", "url": "https://aks.example.com:443",
        "authorization": {"scheme": "Token", "parameters": {
            "apitoken": API_TOKEN, "serviceAccountCertificate": CERTIFICATE, "isCreatedFromSecretYaml": "true"}},
        "isShared": False, "isReady": True, "serviceEndpointProjectReferences": [project_ref(OPS, "Ops")],
    }
    by_project = {WEB: [wif, secret, generic], OPS: [wif, cert, publish, nuget, aks]}
    return {p: Resp(body={"count": len(by_project[p]), "value": by_project[p]}) for p in projects}


KV_GROUP = {
    "id": 2, "type": "AzureKeyVault", "name": "kv-secrets",
    "providerData": {"serviceEndpointId": WIF_ID, "vault": "kv-prod", "lastRefreshedOn": ago(days=1)},
    "variables": {"sql-admin": {"value": None, "isSecret": True, "enabled": True, "contentType": "",
                                "expires": ago(days=5)},
                  "storage-key": {"value": None, "isSecret": True, "enabled": True, "contentType": "",
                                  "expires": None}},
    "isShared": True, "variableGroupProjectReferences": [project_ref(WEB, "Web"), project_ref(OPS, "Ops")],
}


def execution(id_, plan, definition, owner_id, owner_name, start, result="succeeded", project="Web"):
    kind = "_build/results?buildId=" if plan == "Build" else "_releaseProgress?releaseId="
    return {"endpointId": "x", "data": {
        "id": id_, "planType": plan, "result": result, "startTime": start, "finishTime": start,
        "definition": {"id": definition[0], "name": definition[1]},
        "owner": {} if owner_id is None else {
            "id": owner_id, "name": owner_name,
            "_links": {"web": {"href": f"https://dev.azure.com/contoso/{project}/{kind}{owner_id}"}}}}}


class FakeADO:
    """Routes by URL path; a route is a Resp, a dict of Resps by continuation token, or a callable."""

    def __init__(self):
        self.calls = []
        eps = endpoints(WEB, OPS)
        self.routes = {
            "/contoso/_apis/connectionData": Resp(body={"authenticatedUser": {
                "id": "u0", "providerDisplayName": "Evidence Reader",
                "properties": {"Account": {"$type": "System.String", "$value": "reader@example.com"}}}}),
            "/contoso/_apis/projects": Resp(body={"value": [{"id": WEB, "name": "Web"}, {"id": OPS, "name": "Ops"}]}),
            f"/contoso/{WEB}/_apis/serviceendpoint/endpoints": eps[WEB],
            f"/contoso/{OPS}/_apis/serviceendpoint/endpoints": eps[OPS],
            f"/contoso/{WEB}/_apis/pipelines/pipelinepermissions/endpoint/{WIF_ID}": Resp(body={
                "resource": {"type": "endpoint", "id": WIF_ID},
                "pipelines": [{"id": 12, "authorized": True}, {"id": 13, "authorized": False}]}),
            f"/contoso/{OPS}/_apis/pipelines/pipelinepermissions/endpoint/{WIF_ID}": Resp(body={
                "resource": {"type": "endpoint", "id": WIF_ID}, "pipelines": [],
                "allPipelines": {"authorized": True, "authorizedOn": ago(days=100)}}),
            f"/contoso/{WEB}/_apis/pipelines/pipelinepermissions/endpoint/{SECRET_ID}": Resp(body={
                "resource": {"type": "endpoint", "id": SECRET_ID}, "pipelines": []}),
            f"/contoso/{WEB}/_apis/pipelines/pipelinepermissions/endpoint/{GENERIC_ID}": Resp(body={
                "resource": {"type": "endpoint", "id": GENERIC_ID}, "pipelines": []}),
            f"/contoso/{WEB}/_apis/serviceendpoint/{WIF_ID}/executionhistory": {
                None: Resp(body={"count": 2, "value": [
                    execution(901, "Release", (4, "infra-release"), 77, "Release-77", ago(hours=2)),
                    execution(900, "Build", (12, "web-ci"), 1500, "2026.1500", ago(days=3), "failed"),
                ]}, headers={"x-ms-continuationtoken": "899"}),
                "899": Resp(body={"count": 2, "value": [
                    execution(899, "ServiceEndpointProxy", (None, None), None, None, ago(days=4)),
                    execution(850, "Build", (12, "web-ci"), 1400, "2026.1400", ago(days=60)),
                ]}, headers={"x-ms-continuationtoken": "849"}),
                # Never read: the previous page reached past the window.
                "849": Resp(500, {"message": "should not be read"}),
            },
            # A shared connection's history read from the other project repeats a record.
            f"/contoso/{OPS}/_apis/serviceendpoint/{WIF_ID}/executionhistory": Resp(body={"value": [
                execution(901, "Release", (4, "infra-release"), 77, "Release-77", ago(hours=2)),
                execution(950, "Release", (5, "ops-release"), 80, "Release-80", ago(days=1), project="Ops"),
            ]}),
            f"/contoso/{WEB}/_apis/serviceendpoint/{SECRET_ID}/executionhistory": Resp(body={"value": [
                execution(700, "Build", (12, "web-ci"), 1000, "2026.1000", ago(days=200)),
            ]}),
            f"/contoso/{WEB}/_apis/serviceendpoint/{GENERIC_ID}/executionhistory": Resp(body={"value": []}),
            f"/contoso/{WEB}/_apis/distributedtask/variablegroups": Resp(body={"value": [
                {"id": 1, "type": "Vsts", "name": "app-settings",
                 "variables": {"DbPassword": {"value": None, "isSecret": True},
                               "ApiKey": {"value": SECRET_VALUE, "isSecret": True},
                               "Region": {"value": PLAIN_VALUE}},
                 "createdOn": ago(days=400), "modifiedOn": ago(days=10),
                 "modifiedBy": {"id": "u2", "displayName": "Bo Builder", "uniqueName": "bo@example.com"},
                 "variableGroupProjectReferences": [project_ref(WEB, "Web")]},
                KV_GROUP,
            ]}),
            f"/contoso/{OPS}/_apis/distributedtask/variablegroups": Resp(body={"value": [KV_GROUP]}),
            f"/contoso/{WEB}/_apis/distributedtask/securefiles": Resp(body={"value": [
                {"id": "f1", "name": "signing.pfx", "createdOn": ago(days=30), "modifiedOn": ago(days=30),
                 "ticket": f"download-ticket-{MARK}", "properties": {"x": "y"}}]}),
            f"/contoso/{OPS}/_apis/distributedtask/securefiles": Resp(body={"value": []}),
        }
        for cid in (CERT_ID, PUBLISH_ID, NUGET_ID, AKS_ID):
            self.routes[f"/contoso/{OPS}/_apis/pipelines/pipelinepermissions/endpoint/{cid}"] = Resp(body={
                "resource": {"type": "endpoint", "id": cid}, "pipelines": []})
            self.routes[f"/contoso/{OPS}/_apis/serviceendpoint/{cid}/executionhistory"] = Resp(body={"value": []})

    def request(self, method, url, headers=None, params=None, timeout=None, allow_redirects=True, json=None):
        params = dict(params or {})
        path = urlsplit(url).path
        self.calls.append((method, path, params))
        route = self.routes.get(path)
        if route is None:
            raise AssertionError(f"unexpected request {method} {path} {params}")
        if callable(route):
            return route(params)
        if isinstance(route, dict):
            token = params.get("continuationToken")
            if token not in route:
                raise AssertionError(f"unexpected page {token!r} of {path}")
            return route[token]
        return route


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    for key in ("AZURE_DEVOPS_PROJECTS", mod.LOOKBACK_ENV):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AZURE_DEVOPS_ORG_URL", ORG)
    monkeypatch.setenv("AZURE_DEVOPS_PAT", "pat")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setattr(dr.time, "sleep", lambda s: None)


def run(tmp_path, fake=None):
    fake = fake or FakeADO()
    code = dr.run_org(fetcher=mod.NAME, logger=mod.logger, collect=mod.collect, session=fake)
    path = tmp_path / "azure_devops_service_connections_contoso.json"
    status = tmp_path / "status.json"
    for written in (path, status):
        text = written.read_text() if written.exists() else ""
        assert not [s for s in NEVER_WRITTEN if s in text], f"credential material in {written.name}"
    return code, json.loads(path.read_text()), json.loads(status.read_text()) if status.exists() else None, fake, path


def connection(evidence, name):
    return next(c for c in evidence["results"]["service_connections"] if c["name"] == name)


def test_collects_the_organization_and_exits_zero(tmp_path):
    code, evidence, status, _, _ = run(tmp_path)
    assert code == 0 and status is None
    assert evidence["metadata"]["partial_failure"] is False
    s = evidence["summary"]
    assert s["projects_collected"] == 2
    assert s["service_connections_total"] == 7  # the shared connection once
    assert s["service_connections_by_auth_method"] == {
        "none": 1, "publish_profile": 1, "service_principal_certificate": 1, "service_principal_secret": 1,
        "token": 1, "username_password": 1, "workload_identity_federation": 1}
    assert s["azure_service_connections"] == 4
    assert s["azure_service_connections_using_workload_identity_federation"] == 1
    assert s["azure_service_connections_with_stored_secret"] == ["legacy-spn", "signing-spn", "web-deploy"]
    assert s["service_connections_with_stored_credential"] == [
        "aks-deployer", "artifact-feed", "legacy-spn", "nuget-feed", "signing-spn", "web-deploy"]
    assert s["service_connections_open_to_all_pipelines"] == ["prod-wif"]
    assert s["service_connections_not_ready"] == ["artifact-feed"]
    assert s["service_connections_used_in_window"] == 1
    assert s["service_connections_unused_in_window"] == [
        "aks-deployer", "artifact-feed", "legacy-spn", "nuget-feed", "signing-spn", "web-deploy"]
    assert s["service_principals"] == 3
    assert s["pipeline_runs_using_service_connections"] == 3


def test_no_credential_or_variable_value_is_written(tmp_path):
    _, _, _, _, path = run(tmp_path)
    text = path.read_text()
    for secret in (SPN_KEY, PASSWORD, CERTIFICATE, PUBLISH_PROFILE, NUGET_KEY, API_TOKEN, SECRET_VALUE, PLAIN_VALUE):
        assert secret not in text


def test_only_ids_are_kept_from_the_authorization_parameters(tmp_path):
    _, evidence, _, _, _ = run(tmp_path)
    wif = connection(evidence, "prod-wif")
    assert wif["service_principal_id"] == WIF_APP  # as given, not lowercased
    assert wif["tenant_id"] == TENANT
    assert wif["authorization_scheme"] == "WorkloadIdentityFederation"
    assert wif["auth_method"] == "workload_identity_federation" and wif["stored_credential"] is False
    assert wif["azure"]["subscription_id"] == SUB and wif["azure"]["creation_mode"] == "Automatic"
    assert "azureSpnRoleAssignmentId" not in json.dumps(wif)
    assert wif["projects"] == [{"id": OPS, "name": "Ops", "name_in_project": "prod-wif-ops"},
                               {"id": WEB, "name": "Web", "name_in_project": "prod-wif"}]
    legacy = connection(evidence, "legacy-spn")["azure"]
    assert (legacy["scope_level"], legacy["management_group_id"], legacy["subscription_id"]) == (
        "ManagementGroup", "mg-root", None)
    generic = connection(evidence, "artifact-feed")
    assert generic["url"] == "https://feed.example.com"
    assert generic["azure"] is None and generic["service_principal_id"] is None
    assert connection(evidence, "nuget-feed")["url"] == "https://nuget.example.com"
    assert connection(evidence, "nuget-feed")["stored_credential"] is True
    assert connection(evidence, "aks-deployer")["url"] == "https://aks.example.com:443"


@pytest.mark.parametrize("url,scrubbed", [
    (f"https://svc:pa/ss-{MARK}@feed.example.com/path", "https://feed.example.com"),
    (f"https://svc:pa?ss-{MARK}@host.example.com/", "https://host.example.com"),
    (f"https://svc:p@ss#{MARK}@host.example.com", "https://host.example.com"),
    (f"https://hooks.example.com/services/T0/B0/{MARK}", "https://hooks.example.com"),
    (f"HTTPS://Feed.Example.com?sig={MARK}", "https://feed.example.com"),
    ("https://[2001:db8::1]:8443/x", "https://[2001:db8::1]:8443"),
    (f"https://user:{MARK}@/path", None),
    (f"https://{MARK} space/", None),
    ("feed.example.com/path", None),
    ("", None),
    (None, None),
])
def test_scrub_url_keeps_scheme_and_host_only(url, scrubbed):
    assert mod.scrub_url(url) == scrubbed


def test_history_is_read_newest_first_and_stops_at_the_window(tmp_path):
    _, evidence, _, fake, _ = run(tmp_path)
    wif = connection(evidence, "prod-wif")
    pages = [p.get("continuationToken") for _, path, p in fake.calls
             if path == f"/contoso/{WEB}/_apis/serviceendpoint/{WIF_ID}/executionhistory"]
    assert pages == [None, "899"]
    assert all(p.get("api-version") == mod.PREVIEW_API and p.get("top") == mod.HISTORY_PAGE
               for _, path, p in fake.calls if path.endswith("/executionhistory"))
    assert [r["execution_id"] for r in wif["executions"]] == [901, 950, 900, 899]
    assert wif["executions_in_window"] == 4 and wif["pipeline_runs_in_window"] == 3
    assert wif["executions_complete"] is True
    assert all("includeDetails" not in p for _, path, p in fake.calls if path.endswith("/serviceendpoint/endpoints"))


def test_a_release_with_several_stages_counts_as_one_run(tmp_path):
    fake = FakeADO()
    page = fake.routes[f"/contoso/{WEB}/_apis/serviceendpoint/{WIF_ID}/executionhistory"][None]
    page._body["value"].insert(0, execution(902, "Release", (4, "infra-release"), 77, "Release-77", ago(hours=1)))
    _, evidence, _, _, _ = run(tmp_path, fake)
    wif = connection(evidence, "prod-wif")
    assert wif["executions_in_window"] == 5 and wif["pipeline_runs_in_window"] == 3
    group = next(g for g in evidence["results"]["service_principals"] if g["service_principal_id"] == WIF_APP)
    assert (group["executions_in_window"], group["pipeline_runs_in_window"]) == (5, 3)
    assert evidence["summary"]["pipeline_runs_using_service_connections"] == 3


def test_an_execution_names_the_run_that_used_the_connection(tmp_path):
    _, evidence, _, _, _ = run(tmp_path)
    release = connection(evidence, "prod-wif")["executions"][0]
    assert release == {
        "project": "Web", "plan_type": "Release", "pipeline_run": True, "execution_id": 901,
        "definition_id": 4, "definition": "infra-release", "run_id": 77, "run_name": "Release-77",
        "run_url": "https://dev.azure.com/contoso/Web/_releaseProgress?releaseId=77", "result": "succeeded",
        "start_time": release["start_time"], "finish_time": release["finish_time"]}
    proxy = connection(evidence, "prod-wif")["executions"][3]
    assert proxy["plan_type"] == "ServiceEndpointProxy" and proxy["pipeline_run"] is False
    assert proxy["project"] is None and proxy["run_url"] is None
    assert connection(evidence, "prod-wif")["executions"][1]["project"] == "Ops"


@pytest.mark.parametrize("link,project", [
    ("https://dev.azure.com/contoso/Web%20App/_build/results?buildId=1", "Web App"),
    ("https://contoso.visualstudio.com/Web/_releaseProgress?releaseId=2", "Web"),
    ("https://dev.azure.com/contoso/_build/results?buildId=1", None),
    ("https://vsrm.dev.azure.com/contoso/Web/_release?releaseId=3", "Web"),
    ("https://vsrm.dev.azure.com/contoso/_release?releaseId=3", None),
    (None, None),
])
def test_link_project(link, project):
    assert mod.link_project(link) == project


def test_last_use_is_kept_even_when_older_than_the_window(tmp_path):
    _, evidence, _, _, _ = run(tmp_path)
    legacy = connection(evidence, "legacy-spn")
    assert legacy["executions"] == [] and legacy["executions_collected"] is True
    assert legacy["last_used"] is not None and legacy["last_used"] == legacy["last_pipeline_run"]
    assert connection(evidence, "artifact-feed")["last_used"] is None


def test_history_reads_past_the_window_until_it_finds_a_pipeline_run(tmp_path):
    fake = FakeADO()
    path = f"/contoso/{WEB}/_apis/serviceendpoint/{SECRET_ID}/executionhistory"
    fake.routes[path] = {
        None: Resp(body={"value": [execution(1, "ServiceEndpointProxy", (None, None), None, None, ago(days=40))]},
                   headers={"x-ms-continuationtoken": "t1"}),
        "t1": Resp(body={"value": [execution(2, "Build", (12, "web-ci"), 9, "9", ago(days=45))]},
                   headers={"x-ms-continuationtoken": "t2"}),
        "t2": Resp(500, {"message": "should not be read"}),
    }
    _, evidence, _, fake, _ = run(tmp_path, fake)
    legacy = connection(evidence, "legacy-spn")
    assert legacy["executions"] == [] and legacy["executions_complete"] is True
    assert legacy["last_used"] is not None and legacy["last_pipeline_run"] is not None
    assert legacy["last_pipeline_run"] < legacy["last_used"]
    assert [p.get("continuationToken") for _, called, p in fake.calls if called == path] == [None, "t1"]


def test_the_cap_past_the_window_leaves_the_window_complete(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "MAX_HISTORY_RECORDS", 2)
    fake = FakeADO()
    fake.routes[f"/contoso/{WEB}/_apis/serviceendpoint/{SECRET_ID}/executionhistory"] = Resp(body={"value": [
        execution(i, "ServiceEndpointProxy", (None, None), None, None, ago(days=days))
        for i, days in ((1, 1), (2, 40), (3, 50))]})
    _, evidence, _, _, _ = run(tmp_path, fake)
    legacy = connection(evidence, "legacy-spn")
    assert legacy["executions_in_window"] == 1 and legacy["executions_complete"] is True
    assert legacy["last_pipeline_run"] is None


def test_service_principals_group_connections_case_insensitively(tmp_path):
    fake = FakeADO()
    body = fake.routes[f"/contoso/{WEB}/_apis/serviceendpoint/endpoints"]._body
    body["value"][1]["authorization"]["parameters"]["serviceprincipalid"] = f" {WIF_APP.lower()} "
    _, evidence, _, _, _ = run(tmp_path, fake)
    principals = [g for g in evidence["results"]["service_principals"] if g["service_principal_id"] != CERT_APP]
    assert len(principals) == 1
    group = principals[0]
    assert group["service_principal_id"] in (WIF_APP, f" {WIF_APP.lower()} ")
    assert sorted(group["connections"]) == [SECRET_ID, WIF_ID]
    assert group["auth_methods"] == ["service_principal_secret", "workload_identity_federation"]
    assert group["pipeline_runs_in_window"] == 3
    assert connection(evidence, "legacy-spn")["service_principal_id"] == f" {WIF_APP.lower()} "


def test_one_app_id_in_two_tenants_is_two_service_principals(tmp_path):
    fake = FakeADO()
    body = fake.routes[f"/contoso/{OPS}/_apis/serviceendpoint/endpoints"]._body
    cert = next(c for c in body["value"] if c["id"] == CERT_ID)
    cert["authorization"]["parameters"].update(serviceprincipalid=SECRET_APP.upper(), tenantid=OTHER_TENANT)
    _, evidence, _, _, _ = run(tmp_path, fake)
    groups = [g for g in evidence["results"]["service_principals"] if g["service_principal_id"].lower() == SECRET_APP]
    assert sorted((g["tenant_id"], g["connections"]) for g in groups) == [
        (TENANT, [SECRET_ID]), (OTHER_TENANT, [CERT_ID])]
    assert evidence["summary"]["service_principals"] == 3


def test_pipeline_permissions_per_project(tmp_path):
    _, evidence, _, _, _ = run(tmp_path)
    wif = connection(evidence, "prod-wif")
    assert wif["pipeline_permissions"] == [
        {"project": "Ops", "all_pipelines_authorized": True, "authorized_pipeline_ids": []},
        {"project": "Web", "all_pipelines_authorized": False, "authorized_pipeline_ids": [12]},
    ]
    assert wif["open_to_all_pipelines"] is True and wif["pipeline_permissions_collected"] is True
    assert connection(evidence, "legacy-spn")["open_to_all_pipelines"] is False


def test_variable_groups_count_secrets_and_key_vault_expiry(tmp_path):
    _, evidence, _, _, _ = run(tmp_path)
    groups = {g["name"]: g for g in evidence["results"]["variable_groups"]}
    assert len(groups) == 2  # the shared group once
    app = groups["app-settings"]
    assert (app["variables"], app["secret_variables"], app["secret_variables_outside_key_vault"]) == (3, 2, 2)
    assert app["key_vault_linked"] is False and app["key_vault_secrets"] == []
    kv = groups["kv-secrets"]
    assert kv["key_vault_linked"] is True and kv["key_vault"] == "kv-prod"
    assert kv["key_vault_service_connection_id"] == WIF_ID
    assert kv["secret_variables_outside_key_vault"] == 0
    assert [(s["name"], s["expires"] is not None) for s in kv["key_vault_secrets"]] == [
        ("sql-admin", True), ("storage-key", False)]
    s = evidence["summary"]
    assert s["variable_groups_with_secrets_outside_key_vault"] == ["app-settings"]
    assert (s["secret_variables_total"], s["secret_variables_outside_key_vault"]) == (4, 2)
    assert (s["key_vault_secrets_expired"], s["key_vault_secrets_without_expiry"]) == (1, 1)


def test_secure_files_are_listed_by_name(tmp_path):
    _, evidence, _, fake, _ = run(tmp_path)
    web = next(p for p in evidence["results"]["projects"] if p["name"] == "Web")
    assert [f["name"] for f in web["secure_files"]] == ["signing.pfx"]
    assert set(web["secure_files"][0]) == {"id", "name", "project", "created_on", "modified_on", "modified_by"}
    assert evidence["summary"]["secure_files_total"] == 1
    assert {p["api-version"] for _, path, p in fake.calls if path.endswith("/securefiles")} == {mod.SECURE_FILES_API}


def test_a_missing_scope_fails_the_run_and_names_it(tmp_path):
    fake = FakeADO()
    fake.routes[f"/contoso/{WEB}/_apis/distributedtask/variablegroups"] = err(
        401, "TF400813: The user 'x' is not authorized to access this resource.", "UnauthorizedRequestException")
    code, evidence, status, _, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "auth_failed"
    failure = evidence["metadata"]["api_failures"][0]
    assert failure["operation"] == "distributedtask.variablegroups.list(Web)"
    assert "PAT scope needed: Variable Groups (Read)" in failure["message"]
    assert evidence["summary"]["service_connections_total"] == 7  # the rest is still collected


def test_a_refused_history_read_is_a_failure_not_an_unused_connection(tmp_path):
    fake = FakeADO()
    fake.routes[f"/contoso/{WEB}/_apis/serviceendpoint/{SECRET_ID}/executionhistory"] = err(
        403, "Access denied.", "AccessDeniedException")
    code, evidence, status, _, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "not_authorized"
    legacy = connection(evidence, "legacy-spn")
    assert legacy["executions_collected"] is False
    assert "legacy-spn" not in evidence["summary"]["service_connections_unused_in_window"]
    assert "PAT scope needed: Service Connections (Read)" in evidence["metadata"]["api_failures"][0]["message"]


def test_as_an_entra_identity_a_refusal_names_the_missing_permission(tmp_path, monkeypatch):
    monkeypatch.delenv("AZURE_DEVOPS_PAT")
    monkeypatch.setattr(dr, "entra_credential", lambda: SimpleNamespace(
        get_token=lambda scope: SimpleNamespace(token="t", expires_on=NOW.timestamp() + 3600)))
    fake = FakeADO()
    fake.routes[f"/contoso/{OPS}/_apis/pipelines/pipelinepermissions/endpoint/{WIF_ID}"] = err(
        403, "TF400813: not authorized.")
    code, evidence, _, _, _ = run(tmp_path, fake)
    assert code == 1 and evidence["metadata"]["auth_mode"] == "entra"
    assert "Entra identity lacks permission" in evidence["metadata"]["api_failures"][0]["message"]
    wif = connection(evidence, "prod-wif")
    # The refused project grants every pipeline; unknown, not false.
    assert wif["open_to_all_pipelines"] is None and wif["pipeline_permissions_collected"] is False
    assert evidence["summary"]["service_connections_open_to_all_pipelines"] == []


def test_history_past_the_cap_is_marked_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "MAX_HISTORY_RECORDS", 2)
    _, evidence, _, _, _ = run(tmp_path)
    wif = connection(evidence, "prod-wif")
    assert wif["executions_complete"] is False


def test_an_exactly_full_last_page_at_the_cap_is_complete(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "MAX_HISTORY_RECORDS", 2)
    fake = FakeADO()
    fake.routes[f"/contoso/{WEB}/_apis/serviceendpoint/{SECRET_ID}/executionhistory"] = Resp(body={"value": [
        execution(i, "Build", (12, "web-ci"), i, str(i), ago(days=i)) for i in (1, 2)]})
    _, evidence, _, _, _ = run(tmp_path, fake)
    legacy = connection(evidence, "legacy-spn")
    assert legacy["executions_in_window"] == 2 and legacy["executions_complete"] is True


def test_history_out_of_order_is_read_to_the_end(tmp_path):
    fake = FakeADO()
    fake.routes[f"/contoso/{WEB}/_apis/serviceendpoint/{SECRET_ID}/executionhistory"] = {
        None: Resp(body={"value": [
            execution(1, "Build", (12, "web-ci"), 1, "1", ago(days=2)),
            execution(2, "Build", (12, "web-ci"), 2, "2", ago(days=1)),
            execution(3, "Build", (12, "web-ci"), 3, "3", ago(days=90))]}, headers={"x-ms-continuationtoken": "t"}),
        "t": Resp(body={"value": [execution(4, "Build", (12, "web-ci"), 4, "4", ago(days=3))]}),
    }
    _, evidence, _, _, _ = run(tmp_path, fake)
    assert [r["execution_id"] for r in connection(evidence, "legacy-spn")["executions"]] == [2, 1, 4]


def test_a_missing_organization_is_bad_config(tmp_path):
    fake = FakeADO()
    fake.routes["/contoso/_apis/projects"] = Resp(404, {"message": "The resource cannot be found."})
    code, _, status, _, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "bad_config"


def test_invalid_lookback_is_bad_config(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.LOOKBACK_ENV, "a month")
    code, _, status, _, _ = run(tmp_path)
    assert code == 1 and status["code"] == "bad_config"


@pytest.mark.parametrize("scheme,params,method,stored", [
    ("WorkloadIdentityFederation", {}, "workload_identity_federation", False),
    ("ManagedServiceIdentity", {}, "managed_identity", False),
    ("ServicePrincipal", {"authenticationtype": "spnCertificate"}, "service_principal_certificate", True),
    ("ServicePrincipal", {}, "service_principal", True),
    ("Token", {}, "token", True),
    ("InstallationToken", {}, "github_app", False),
    ("Kubernetes", {"kubeconfig": None}, "kubernetes", True),
    ("None", {"nugetkey": None}, "none", True),
    ("None", {"tenantid": TENANT}, "none", None),
    ("None", {}, "none", None),
    ("SomethingNew", {"x": None}, "somethingnew", None),
    (None, {}, None, None),
])
def test_auth_method(scheme, params, method, stored):
    found = mod.auth_method(scheme, params)
    assert found == method and mod.stored_credential(found, params) is stored


def test_task_result_reads_the_enum_as_number_or_name():
    assert mod.task_result(2) == "failed" and mod.task_result("SucceededWithIssues") == "succeededWithIssues"
    assert (mod.task_result(6), mod.task_result(7)) == ("manuallyQueued", "dependentOnManualQueue")
    assert mod.task_result(None) is None


def test_an_evidence_sample_keeps_every_not_collected_entry():
    from framework import samples
    assert samples.trim({"not_collected": dict(mod.NOT_COLLECTED)})["not_collected"] == mod.NOT_COLLECTED
