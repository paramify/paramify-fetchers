"""The shared Azure DevOps REST client (fetchers/azure/_shared/devops_rest.py), driven by a fake session."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))
import devops_rest as dr  # noqa: E402

ORG = "https://dev.azure.com/contoso"


class Resp:
    def __init__(self, status=200, body=None, headers=None, text=None):
        self.status_code, self._body = status, body
        self.headers = headers or {}
        self.text = text if text is not None else json.dumps(body)
        self.reason = "OK" if status < 400 else "Error"

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


class FakeSession:
    """Answers queued per URL path (and continuation token); records every request."""

    def __init__(self, routes):
        self.routes = {k: list(v) if isinstance(v, list) else [v] for k, v in routes.items()}
        self.calls = []

    def request(self, method, url, headers=None, params=None, timeout=None, allow_redirects=True, json=None):
        self.calls.append({"method": method, "url": url, "params": dict(params or {}), "headers": headers,
                           "allow_redirects": allow_redirects, "json": json})
        key = (urlsplit(url).netloc + urlsplit(url).path, (params or {}).get("continuationToken"))
        queue = self.routes.get(key) or self.routes.get(key[0])
        if not queue:
            raise AssertionError(f"unexpected request {method} {url} {params}")
        answer = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(dr.time, "sleep", lambda s: None)


def client(routes):
    session = FakeSession(routes)
    return dr.DevOpsClient(ORG, "secret-pat", session), session


def test_pat_is_sent_as_basic_auth_and_redirects_are_never_followed():
    c, s = client({"dev.azure.com/contoso/_apis/projects": Resp(body={"value": []})})
    c.list("_apis/projects")
    call = s.calls[0]
    assert call["headers"]["Authorization"] == "Basic " + base64.b64encode(b":secret-pat").decode()
    assert call["allow_redirects"] is False
    assert call["params"]["api-version"] == "7.1"


def test_header_continuation_token_reads_every_page():
    path = "dev.azure.com/contoso/_apis/projects"
    c, s = client({
        (path, None): Resp(body={"value": [{"id": 1}]}, headers={"x-ms-continuationtoken": "t2"}),
        (path, "t2"): Resp(body={"value": [{"id": 2}]}),
    })
    assert [p["id"] for p in c.list("_apis/projects", params={"$top": 1})] == [1, 2]
    assert s.calls[1]["params"] == {"$top": 1, "api-version": "7.1", "continuationToken": "t2"}


def test_body_continuation_token_stops_on_has_more_false():
    path = "auditservice.dev.azure.com/contoso/_apis/audit/auditlog"
    c, s = client({
        (path, None): Resp(body={"decoratedAuditLogEntries": [{"id": "a"}], "continuationToken": "n", "hasMore": True}),
        (path, "n"): Resp(body={"decoratedAuditLogEntries": [{"id": "b"}], "continuationToken": "z", "hasMore": False}),
    })
    items = c.list("_apis/audit/auditlog", "7.1-preview.1", service="auditservice", item_key="decoratedAuditLogEntries")
    assert [i["id"] for i in items] == ["a", "b"]
    assert len(s.calls) == 2


def test_iter_lets_a_caller_stop_before_the_next_page():
    path = "dev.azure.com/contoso/_apis/projects"
    c, s = client({(path, None): Resp(body={"value": [{"id": 1}, {"id": 2}]}, headers={"x-ms-continuationtoken": "t2"})})
    assert next(c.iter("_apis/projects"))["id"] == 1
    assert len(s.calls) == 1


def test_same_host_next_link_is_followed():
    c, s = client({
        "dev.azure.com/contoso/_apis/things": Resp(body={"value": [1], "nextLink": f"{ORG}/_apis/things2?skip=1"}),
        "dev.azure.com/contoso/_apis/things2": Resp(body={"value": [2]}),
    })
    assert c.list("_apis/things") == [1, 2]
    assert s.calls[1]["params"] == {}


@pytest.mark.parametrize("link", ["https://evil.example/contoso/_apis/things?skip=1",
                                  "http://dev.azure.com/contoso/_apis/things?skip=1"])
def test_next_link_to_another_host_or_scheme_is_refused_before_sending_the_pat(link):
    c, s = client({"dev.azure.com/contoso/_apis/things": Resp(body={"value": [1], "nextLink": link})})
    with pytest.raises(dr.DevOpsError) as err:
        c.list("_apis/things")
    assert err.value.code == "UntrustedNextLink"
    assert len(s.calls) == 1


def test_a_repeated_continuation_token_raises_instead_of_looping():
    path = "dev.azure.com/contoso/_apis/projects"
    c, _ = client({path: Resp(body={"value": [1]}, headers={"x-ms-continuationtoken": "same"})})
    with pytest.raises(dr.DevOpsError, match="ContinuationLoop"):
        c.list("_apis/projects")


def test_ado_error_code_and_type_key_are_kept():
    body = {"$id": "1", "message": "TF400813: The user 'x' is not authorized to access this resource.",
            "typeKey": "UnauthorizedRequestException", "errorCode": 0}
    c, _ = client({"dev.azure.com/contoso/_apis/projects": Resp(401, body)})
    with pytest.raises(dr.DevOpsError) as err:
        c.get("_apis/projects")
    e = err.value
    assert (e.status, e.code, e.type_key, e.failure_code) == (401, "TF400813", "UnauthorizedRequestException", "auth_failed")
    assert str(e) == "(401) TF400813: The user 'x' is not authorized to access this resource."


def test_type_key_is_the_code_when_the_message_has_none():
    body = {"message": "Pipeline not found.", "typeKey": "PipelineNotFoundException"}
    c, _ = client({"dev.azure.com/contoso/p/_apis/pipelines/9": Resp(404, body)})
    with pytest.raises(dr.DevOpsError) as err:
        c.get("p/_apis/pipelines/9")
    assert err.value.code == "PipelineNotFoundException"
    assert err.value.failure_code == "internal_error"


def test_project_not_found_or_hidden_is_not_authorized():
    body = {"message": "VS800075: The project with id 'x' does not exist, or you do not have permission to access it.",
            "typeKey": "ProjectDoesNotExistException"}
    c, _ = client({"dev.azure.com/contoso/x/_apis/build/definitions": Resp(404, body)})
    with pytest.raises(dr.DevOpsError) as err:
        c.list("x/_apis/build/definitions")
    assert err.value.failure_code == "not_authorized"


def test_sign_in_page_with_203_is_an_auth_failure():
    c, _ = client({"dev.azure.com/contoso/_apis/projects": Resp(203, None, text="<html>Sign In</html>")})
    with pytest.raises(dr.DevOpsError) as err:
        c.get("_apis/projects")
    assert err.value.failure_code == "auth_failed"


def test_redirect_is_an_auth_failure():
    c, _ = client({"dev.azure.com/contoso/_apis/projects": Resp(302, None, {"Location": "https://login.example/x"}, "")})
    with pytest.raises(dr.DevOpsError) as err:
        c.get("_apis/projects")
    assert (err.value.code, err.value.failure_code) == ("Redirect", "auth_failed")


def test_throttling_and_dropped_connections_are_retried():
    c, s = client({"dev.azure.com/contoso/_apis/projects": [
        Resp(429, {"message": "slow down"}, {"Retry-After": "1"}),
        requests.ConnectionError("reset"),
        Resp(body={"value": [1]}),
    ]})
    assert c.list("_apis/projects") == [1]
    assert len(s.calls) == 3


def test_post_sends_the_body_and_api_version():
    c, s = client({"dev.azure.com/contoso/p/_apis/pipelines/4/preview": Resp(body={"finalYaml": "steps: []"})})
    assert c.post("p/_apis/pipelines/4/preview", {"previewRun": True}) == {"finalYaml": "steps: []"}
    assert s.calls[0]["method"] == "POST" and s.calls[0]["json"] == {"previewRun": True}


@pytest.mark.parametrize("raw,org,base", [
    ("contoso", "contoso", "https://dev.azure.com/contoso"),
    ("https://dev.azure.com/contoso/Some%20Project", "contoso", "https://dev.azure.com/contoso"),
    ("https://contoso.visualstudio.com/", "contoso", "https://contoso.visualstudio.com"),
])
def test_org_url_forms(raw, org, base):
    assert dr.parse_org_url(raw) == (org, base)


@pytest.mark.parametrize("raw", ["", "http://dev.azure.com/contoso", "https://evil.example/contoso",
                                 "https://dev.azure.com/", "https://a.b.visualstudio.com"])
def test_org_url_rejects_anything_else(raw):
    with pytest.raises(ValueError):
        dr.parse_org_url(raw)


def test_service_hosts_follow_the_org_url_form():
    assert dr.DevOpsClient(ORG, "p").service_url("auditservice") == "https://auditservice.dev.azure.com/contoso"
    legacy = dr.DevOpsClient("https://contoso.visualstudio.com", "p")
    assert legacy.service_url("vsrm") == "https://contoso.vsrm.visualstudio.com"


def test_parse_time_handles_seven_fractional_digits():
    assert dr.iso(dr.parse_time("2015-02-23T12:51:06.8575412Z")) == "2015-02-23T12:51:06Z"
    assert dr.parse_time("not a time") is None


def projects_routes():
    return {"dev.azure.com/contoso/_apis/projects": Resp(body={"value": [
        {"id": "p1", "name": "Web"}, {"id": "p2", "name": "Infra"}]})}


def test_list_projects_narrows_and_reports_a_missing_name(monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_PROJECTS", "infra, Nope")
    c, _ = client(projects_routes())
    collector = dr.DevOpsCollector(dr._LOGGER)
    assert [p["name"] for p in dr.list_projects(c, collector)] == ["Infra"]
    assert collector.failures[0]["operation"] == "AZURE_DEVOPS_PROJECTS lookup"


def run(monkeypatch, tmp_path, collect, routes=None, env=None):
    for key in ("AZURE_DEVOPS_ORG_URL", "AZURE_DEVOPS_PAT", "AZURE_DEVOPS_PROJECTS"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    for key, value in (env or {"AZURE_DEVOPS_ORG_URL": ORG, "AZURE_DEVOPS_PAT": "pat"}).items():
        monkeypatch.setenv(key, value)
    code = dr.run_org(fetcher="azure_devops_test", logger=dr._LOGGER, collect=collect, session=FakeSession(routes or {}))
    files = sorted(tmp_path.glob("azure_devops_test_*.json"))
    status = tmp_path / "status.json"
    return code, json.loads(files[0].read_text()), json.loads(status.read_text()) if status.exists() else None


def test_run_org_writes_evidence_and_exits_zero(monkeypatch, tmp_path):
    code, evidence, status = run(monkeypatch, tmp_path, lambda c, col: ({"x": 1}, {"n": 1}))
    assert code == 0 and status is None
    assert evidence["metadata"]["organization"] == "contoso"
    assert evidence["results"] == {"x": 1} and evidence["summary"] == {"n": 1}


def test_run_org_without_a_pat_still_writes_evidence_and_reports_bad_config(monkeypatch, tmp_path):
    code, evidence, status = run(monkeypatch, tmp_path, lambda c, col: ({}, {}), env={"AZURE_DEVOPS_ORG_URL": ORG})
    assert code == 1
    assert evidence["metadata"]["partial_failure"] is True
    assert status["code"] == "bad_config" and "AZURE_DEVOPS_PAT" in status["error"]


def test_run_org_reports_the_ado_failure_code(monkeypatch, tmp_path):
    def collect(c, col):
        col.guard("core.projects.list", lambda: c.list("_apis/projects"))
        return {}, {}

    routes = {"dev.azure.com/contoso/_apis/projects": Resp(403, {"message": "VS403403: denied"})}
    code, evidence, status = run(monkeypatch, tmp_path, collect, routes)
    assert code == 1 and status["code"] == "not_authorized"
    assert "VS403403" in evidence["metadata"]["api_failures"][0]["message"]


@pytest.mark.parametrize("exc,code", [
    (RuntimeError("(403) InsufficientAccessError: The provided credentials have insufficient access"), "not_authorized"),
    (RuntimeError("(429) TooManyRequests"), "rate_limited"),
    (KeyError("boom"), "internal_error"),
])
def test_azure_side_errors_keep_their_contract_code(exc, code):
    assert dr.failure_code(exc) == code


def test_run_org_turns_an_unexpected_exception_into_internal_error(monkeypatch, tmp_path):
    def collect(c, col):
        raise KeyError("boom")

    code, _, status = run(monkeypatch, tmp_path, collect)
    assert code == 1 and status["code"] == "internal_error"
