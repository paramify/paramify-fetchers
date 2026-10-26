"""Offline tests for the servicenow Scripted REST engine and its fetchers.

A fake requests.Session answers each GET from a list of canned responses, so
these check the failure codes, retries, response checks and paging, not a live
instance.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVICENOW = REPO_ROOT / "fetchers" / "servicenow"
FETCHERS = ("cases", "changes")
URL = "https://example.servicenowservices.com/api/x_scope/app/records"

sys.path.insert(0, str(SERVICENOW / "_shared"))

import scripted_rest  # noqa: E402
from scripted_rest import Endpoint, LimitOffset  # noqa: E402


class FakeResponse:
    def __init__(self, status: int, body=None, *, text: str | None = None, headers: dict | None = None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else json.dumps(body)
        self.headers = {"Content-Type": "application/json" if text is None else "text/html", **(headers or {})}

    def json(self):
        if self._body is None:
            raise ValueError("not JSON")
        return self._body


def ok(records=(), **extra):
    return FakeResponse(200, {"result": {"status": "success", "evidence": list(records), **extra}})


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"servicenow_{name}", SERVICENOW / name / "fetcher.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PLAIN = Endpoint(
    label="records",
    output="servicenow_records.json",
    url_env="SERVICENOW_RECORDS_API_URL",
    since_env="SERVICENOW_RECORDS_SINCE",
    since_param="since",
)
PAGED = Endpoint(
    label="records",
    output="servicenow_records.json",
    url_env="SERVICENOW_RECORDS_API_URL",
    paging=LimitOffset(limit=2),
    records_path=("result", "evidence"),
)


@pytest.fixture
def harness(monkeypatch, tmp_path):
    """Run an Endpoint against canned responses; return (exit, output, calls, status, sleeps)."""
    sleeps: list[float] = []
    monkeypatch.setattr("time.sleep", sleeps.append)
    for k, v in {
        "SERVICENOW_USERNAME": "svc",
        "SERVICENOW_PASSWORD": "pw",
        "SERVICENOW_RECORDS_API_URL": URL,
        "EVIDENCE_DIR": str(tmp_path / "evidence"),
        "FETCHER_STATUS_FILE": str(tmp_path / "status.json"),
    }.items():
        monkeypatch.setenv(k, v)

    def _run(responses, endpoint: Endpoint = PLAIN, env: dict | None = None):
        calls: list[dict] = []
        queue = list(responses)

        def fake_request(self, method, url, params=None, timeout=None, **kw):
            assert method == "GET"
            assert kw.get("allow_redirects") is False, "redirects must never be followed"
            assert self.auth == ("svc", "pw")
            calls.append({"url": url, "params": dict(params or {})})
            item = queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        monkeypatch.setattr(requests.Session, "request", fake_request)
        for k, v in (env or {}).items():
            if v is None:
                monkeypatch.delenv(k, raising=False)
            else:
                monkeypatch.setenv(k, v)

        code = scripted_rest.run(endpoint)
        out_path = tmp_path / "evidence" / endpoint.output
        out = json.loads(out_path.read_text()) if out_path.exists() else None
        status_path = tmp_path / "status.json"
        status = json.loads(status_path.read_text()) if status_path.exists() else None
        assert not queue, "every canned response should be used"
        return code, out, calls, status, sleeps

    return _run


# ---------- success ----------

def test_writes_the_parsed_body(harness):
    code, out, calls, status, _ = harness([ok([{"number": "R1"}], returned_count=1)])
    assert code == 0
    assert out == {"result": {"status": "success", "evidence": [{"number": "R1"}], "returned_count": 1}}
    assert calls == [{"url": URL, "params": {}}]
    assert status is None


def test_body_without_result_status_is_not_checked(harness):
    code, out, *_ = harness([FakeResponse(200, {"records": []})])
    assert code == 0
    assert out == {"records": []}


def test_watermark_is_sent_when_set(harness):
    code, _, calls, *_ = harness([ok()], env={"SERVICENOW_RECORDS_SINCE": "2026-08-01T00:00:00Z"})
    assert code == 0
    assert calls[0]["params"] == {"since": "2026-08-01T00:00:00Z"}


def test_trailing_slash_is_dropped(harness):
    _, _, calls, *_ = harness([ok()], env={"SERVICENOW_RECORDS_API_URL": URL + "/"})
    assert calls[0]["url"] == URL


# ---------- settings ----------

@pytest.mark.parametrize("env", ["SERVICENOW_USERNAME", "SERVICENOW_PASSWORD", "SERVICENOW_RECORDS_API_URL"])
def test_missing_setting_is_bad_config(harness, env):
    code, out, calls, status, _ = harness([], env={env: None})
    assert (code, out, calls) == (1, None, [])
    assert status == {"error": f"{env} is not set", "code": "bad_config"}


def test_plain_http_url_is_refused(harness):
    code, _, calls, status, _ = harness([], env={"SERVICENOW_RECORDS_API_URL": URL.replace("https", "http")})
    assert (code, calls) == (1, [])
    assert status["code"] == "bad_config"


def test_endpoint_rejects_half_a_watermark():
    with pytest.raises(ValueError):
        Endpoint(label="x", output="x.json", url_env="X", since_env="X_SINCE")


def test_paged_endpoint_needs_records_path():
    with pytest.raises(ValueError):
        Endpoint(label="x", output="x.json", url_env="X", paging=LimitOffset(limit=10))


# ---------- HTTP failures ----------

@pytest.mark.parametrize(
    ("status", "code"),
    [(401, "auth_failed"), (403, "not_authorized"), (400, "bad_config"), (404, "bad_config")],
)
def test_status_codes_that_are_not_retried(harness, status, code):
    result, out, calls, reported, sleeps = harness([FakeResponse(status, {"error": "x"})])
    assert (result, out, len(calls), sleeps) == (1, None, 1, [])
    assert reported["code"] == code


def test_redirect_is_not_followed(harness):
    resp = FakeResponse(302, None, text="", headers={"Location": "https://sso.example.com/login"})
    code, out, calls, status, _ = harness([resp])
    assert (code, out, len(calls)) == (1, None, 1)
    assert status["code"] == "bad_config"
    assert "sso.example.com" in status["error"]


@pytest.mark.parametrize(("status", "code"), [(429, "rate_limited"), (503, "target_unreachable")])
def test_retryable_status_gives_up_with_its_code(harness, status, code):
    responses = [FakeResponse(status, {})] * (scripted_rest.MAX_RETRIES + 1)
    result, out, calls, reported, sleeps = harness(responses)
    assert (result, out) == (1, None)
    assert len(calls) == scripted_rest.MAX_RETRIES + 1
    assert len(sleeps) == scripted_rest.MAX_RETRIES
    assert reported["code"] == code


def test_retry_recovers(harness):
    code, out, calls, _, sleeps = harness([FakeResponse(502, {}), ok([{"number": "R1"}])])
    assert code == 0
    assert out["result"]["evidence"] == [{"number": "R1"}]
    assert len(calls) == 2
    assert sleeps == [scripted_rest.BACKOFF_BASE_SECONDS]


def test_retry_after_header_is_used(harness):
    _, _, _, _, sleeps = harness([FakeResponse(429, {}, headers={"Retry-After": "7"}), ok()])
    assert sleeps == [7.0]


def test_connection_error_gives_up_as_unreachable(harness):
    errors = [requests.ConnectionError("dns")] * (scripted_rest.MAX_EXCEPTION_RETRIES + 1)
    code, out, calls, status, _ = harness(errors)
    assert (code, out) == (1, None)
    assert len(calls) == scripted_rest.MAX_EXCEPTION_RETRIES + 1
    assert status["code"] == "target_unreachable"


# ---------- 200 responses that are failures ----------

def test_html_body_is_a_failure(harness):
    code, out, _, status, _ = harness([FakeResponse(200, None, text="<html>Log in</html>")])
    assert (code, out) == (1, None)
    assert status["code"] == "bad_config"
    assert "text/html" in status["error"]


def test_error_status_in_body_is_a_failure(harness):
    resp = FakeResponse(200, {"result": {"status": "error", "message": "query failed"}})
    code, out, _, status, _ = harness([resp])
    assert (code, out) == (1, None)
    assert "query failed" in status["error"]


def test_write_error_is_internal_error(harness, tmp_path):
    (tmp_path / "file").write_text("")
    code, _, _, status, _ = harness([ok()], env={"EVIDENCE_DIR": str(tmp_path / "file")})
    assert code == 1
    assert status["code"] == "internal_error"


# ---------- paging ----------

def test_walks_pages_until_a_short_page(harness):
    pages = [ok([{"n": 1}, {"n": 2}]), ok([{"n": 3}, {"n": 4}]), ok([{"n": 5}])]
    code, out, calls, *_ = harness(pages, endpoint=PAGED)
    assert code == 0
    assert out == {"record_count": 5, "page_count": 3, "records": [{"n": i} for i in range(1, 6)]}
    assert [c["params"] for c in calls] == [
        {"limit": 2, "offset": 0},
        {"limit": 2, "offset": 2},
        {"limit": 2, "offset": 4},
    ]


def test_exact_multiple_ends_on_an_empty_page(harness):
    code, out, calls, *_ = harness([ok([{"n": 1}, {"n": 2}]), ok([])], endpoint=PAGED)
    assert code == 0
    assert out["record_count"] == 2
    assert len(calls) == 2


def test_failed_page_fails_the_whole_run(harness):
    pages = [ok([{"n": 1}, {"n": 2}])] + [FakeResponse(500, {})] * (scripted_rest.MAX_RETRIES + 1)
    code, out, _, status, _ = harness(pages, endpoint=PAGED)
    assert (code, out) == (1, None)
    assert status["code"] == "target_unreachable"


def test_page_without_a_record_list_is_a_failure(harness):
    code, out, _, status, _ = harness([FakeResponse(200, {"result": {"status": "success"}})], endpoint=PAGED)
    assert (code, out) == (1, None)
    assert status["code"] == "bad_config"


def test_endpoint_that_ignores_offset_is_a_failure(harness):
    same = [{"n": 1}, {"n": 2}]
    code, out, _, status, _ = harness([ok(same), ok(same)], endpoint=PAGED)
    assert (code, out) == (1, None)
    assert "offset" in status["error"]


# ---------- the fetchers ----------

@pytest.mark.parametrize("name", FETCHERS)
def test_fetcher_env_vars_are_declared_in_its_contract(name):
    endpoint = load(name).ENDPOINT
    contract = yaml.safe_load((SERVICENOW / name / "fetcher.yaml").read_text())
    secrets = {s["env"] for s in contract["secrets"]}
    config = {c["env"] for c in contract.get("config_schema", {}).values()}
    assert {scripted_rest.USERNAME_ENV, scripted_rest.PASSWORD_ENV, endpoint.url_env} <= secrets
    if endpoint.since_env:
        assert endpoint.since_env in config
    assert endpoint.output == contract["output"]["path"]


@pytest.mark.parametrize("name", FETCHERS)
def test_fetcher_runs_end_to_end(name, harness, monkeypatch):
    endpoint = load(name).ENDPOINT
    monkeypatch.setenv(endpoint.url_env, URL)
    code, out, *_ = harness([ok([{"number": "X1"}])], endpoint=endpoint)
    assert code == 0
    assert out["result"]["evidence"] == [{"number": "X1"}]
