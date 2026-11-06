"""Tests for framework.paramify: error classification, retries, version check."""
import json

import pytest
import requests

from framework.paramify import ApiError, Client, ErrorKind
from framework.paramify.client import base_url_error, classify
from framework.paramify.version import Capability, delivery_capability

BASE = "https://api.example.com/v0"


class FakeResponse:
    def __init__(self, status_code=200, body=None, text=None, headers=None):
        self.status_code = status_code
        self._body = body
        if text is None:
            text = "" if body is None else json.dumps(body)
        self.text = text
        self.headers = headers or {}

    def json(self):
        if not self.text:
            raise ValueError("empty")
        return json.loads(self.text)


class FakeSession:
    """Scripted: each item is a FakeResponse or an exception to raise."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.headers = {}

    def request(self, method, url, params=None, json=None, files=None, timeout=None):
        self.calls.append(
            {"method": method, "url": url, "params": params, "json": json, "files": files, "timeout": timeout}
        )
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make(script, **kw):
    sleeps = []
    session = FakeSession(script)
    c = Client("tok", BASE, session=session, sleep=sleeps.append, **kw)
    return c, session, sleeps


@pytest.mark.parametrize("method,path,status,body,upload,kind", [
    ("POST", "/batches/b/artifacts/upload", 403, "Forbidden", True, ErrorKind.PERMANENT),
    ("POST", "/batches/b/artifacts/upload", 403, '{"requestId":"r1"}', True, ErrorKind.FATAL),
    ("POST", "/custom-tags/evidence/e", 403, "", False, ErrorKind.WARNING),
    ("POST", "/batches/b/artifacts/upload", 413, "", True, ErrorKind.PERMANENT),
    ("POST", "/batches/b/artifacts/upload", 400, "", True, ErrorKind.PERMANENT),
    ("POST", "/batches/b/submit", 409, "", False, ErrorKind.CONFLICT),
    ("GET", "/evidence", 401, "", False, ErrorKind.FATAL),
    ("GET", "/evidence", 403, "", False, ErrorKind.FATAL),
    ("GET", "/evidence/x", 404, "", False, ErrorKind.MISSING),
    ("GET", "/evidence", 429, "", False, ErrorKind.TEMPORARY),
    ("GET", "/batches", 503, "", False, ErrorKind.TEMPORARY),
    # A refused write fails only its own action; a refused read still stops planning.
    ("POST", "/evidence", 400, "", False, ErrorKind.REJECTED),
    ("POST", "/batches", 422, "", False, ErrorKind.REJECTED),
    ("PATCH", "/evidence/e", 405, "", False, ErrorKind.REJECTED),
    ("POST", "/batches/b/submit", 415, "", False, ErrorKind.REJECTED),
    ("POST", "/evidence", 403, "", False, ErrorKind.FATAL),
    ("POST", "/evidence", 401, "", False, ErrorKind.FATAL),
    ("GET", "/evidence", 400, "", False, ErrorKind.FATAL),
    # Tags never break an upload: every refusal but a 401 is a warning.
    ("POST", "/custom-tags/evidence/e", 422, "", False, ErrorKind.WARNING),
    ("POST", "/custom-tags/evidence/e", 400, "", False, ErrorKind.WARNING),
    ("POST", "/custom-tags/evidence/e", 404, "", False, ErrorKind.WARNING),
    ("POST", "/custom-tags/evidence/e", 409, "", False, ErrorKind.WARNING),
    ("POST", "/custom-tags/evidence/e", 401, "", False, ErrorKind.FATAL),
])
def test_classify(method, path, status, body, upload, kind):
    assert classify(method, path, status, body, upload) is kind


def test_fatal_property():
    assert ApiError("x", status=401, kind=ErrorKind.FATAL, method="GET", path="/a").fatal is True
    assert ApiError("x", status=404, kind=ErrorKind.MISSING, method="GET", path="/a").fatal is False
    with pytest.raises(AttributeError):
        ApiError("x", status=1, kind=ErrorKind.FATAL, method="GET", path="/a").fatal = False  # type: ignore[misc]


def test_success_returns_decoded_body_and_none_for_empty():
    c, s, _ = make([FakeResponse(200, {"a": 1}), FakeResponse(204)])
    assert c.get("/evidence", {"referenceId": "x"}) == {"a": 1}
    assert c.post_json("/evidence", {"n": 1}) is None
    assert s.calls[0]["url"] == f"{BASE}/evidence"
    assert s.calls[0]["params"] == {"referenceId": "x"}
    assert s.calls[1]["json"] == {"n": 1}
    assert s.calls[1]["method"] == "POST"


def test_auth_header_and_timeout():
    c, s, _ = make([FakeResponse(200, {})], )
    assert s.headers == {"Authorization": "Bearer tok"}
    c.get("/x")
    assert s.calls[0]["timeout"] == 30


def test_post_file_matches_uploader_multipart():
    c, s, _ = make([FakeResponse(201, {"id": "a"})])
    assert c.post_file("/batches/b/artifacts/upload", "f.json", b"{}", {"title": "t"}) == {"id": "a"}
    files = s.calls[0]["files"]
    assert files["file"] == ("f.json", b"{}", "application/json")
    assert files["artifact"] == ("artifact.json", json.dumps({"title": "t"}), "application/json")


def test_post_file_403_without_request_id_is_permanent():
    c, _, sleeps = make([FakeResponse(403, text="Forbidden")])
    with pytest.raises(ApiError) as ei:
        c.post_file("/batches/b/artifacts/upload", "f.json", b"x", {})
    assert ei.value.kind is ErrorKind.PERMANENT and ei.value.status == 403
    assert ei.value.method == "POST" and ei.value.path == "/batches/b/artifacts/upload"
    assert sleeps == []


def test_error_kinds_raise_without_retry():
    c, s, sleeps = make([FakeResponse(404, text="nope")])
    with pytest.raises(ApiError) as ei:
        c.get("/evidence/x")
    assert ei.value.kind is ErrorKind.MISSING
    assert len(s.calls) == 1 and sleeps == []


def test_retry_after_is_honoured():
    c, s, sleeps = make([FakeResponse(429, headers={"Retry-After": "7"}), FakeResponse(200, {"ok": 1})])
    assert c.get("/evidence") == {"ok": 1}
    assert sleeps == [7]


def test_backoff_is_exponential_and_capped():
    script = [FakeResponse(503)] * 7 + [FakeResponse(200, {})]
    c, _, sleeps = make(script, retry_budget_s=1000)
    c.get("/x")
    assert sleeps == [1, 2, 4, 8, 16, 30, 30]


def test_connection_errors_retry():
    c, _, sleeps = make([requests.ConnectionError("x"), requests.Timeout("y"), FakeResponse(200, {"a": 1})])
    assert c.get("/x") == {"a": 1}
    assert sleeps == [1, 2]


def test_budget_exhausted_raises_temporary():
    c, s, sleeps = make([FakeResponse(503)] * 10, retry_budget_s=5)
    with pytest.raises(ApiError) as ei:
        c.get("/x")
    assert ei.value.kind is ErrorKind.TEMPORARY and ei.value.status == 503
    assert sum(sleeps) <= 5
    assert sleeps == [1, 2]


def test_budget_is_shared_across_calls():
    c, _, sleeps = make([FakeResponse(503), FakeResponse(200, {}), FakeResponse(503), FakeResponse(503)], retry_budget_s=1.5)
    c.get("/a")
    assert sleeps == [1]
    with pytest.raises(ApiError) as ei:
        c.get("/b")
    assert ei.value.kind is ErrorKind.TEMPORARY
    assert sleeps == [1]


def test_exhausted_connection_error_raises_temporary():
    c, _, _ = make([requests.ConnectionError("x")] * 3, retry_budget_s=0)
    with pytest.raises(ApiError) as ei:
        c.get("/x")
    assert ei.value.kind is ErrorKind.TEMPORARY and ei.value.status is None


def test_http_refused_for_non_localhost():
    with pytest.raises(ValueError, match="https"):
        Client("t", "http://api.example.com", session=FakeSession([]))
    Client("t", "http://localhost:8080", session=FakeSession([]))
    assert base_url_error("https://x.y") is None
    assert base_url_error("http://x.y") is not None


_FLAG_OFF_BODY = ('{"requestId":"r-1","statusMessage":"Forbidden","error":{"message":'
                  '"Artifact requests are not enabled for this workspace.","path":"/api/v0/batches"}}')


def test_delivery_capability_ok():
    c, s, _ = make([FakeResponse(200, {"batches": []})])
    assert delivery_capability(c) == Capability(True, None)
    assert s.calls[0]["params"] == {"pageSize": 1}
    assert s.calls[0]["url"] == f"{BASE}/batches"


def test_delivery_capability_old_api():
    c, _, _ = make([FakeResponse(404, text="nf")])
    assert delivery_capability(c) == Capability(False, "the API has no batch routes")


def test_delivery_capability_flag_off():
    c, _, _ = make([FakeResponse(403, text=_FLAG_OFF_BODY)])
    cap = delivery_capability(c)
    assert cap.batches is False
    assert cap.reason == "Artifact requests are not enabled for this workspace."


def test_delivery_capability_other_403_raises():
    c, _, _ = make([FakeResponse(403, text='{"error":{"message":"Insufficient scope"}}')])
    with pytest.raises(ApiError) as ei:
        delivery_capability(c)
    assert ei.value.kind is ErrorKind.FATAL


def test_retry_after_zero_cannot_spin():
    c, _, sleeps = make([FakeResponse(429, headers={"Retry-After": "0"})] * 50, retry_budget_s=3)
    with pytest.raises(ApiError) as ei:
        c.get("/x")
    assert ei.value.kind is ErrorKind.TEMPORARY
    assert sleeps == [1.0, 1.0, 1.0]


@pytest.mark.parametrize("value", ["-5", "nan"])
def test_retry_after_negative_or_nan_is_floored(value):
    c, _, sleeps = make([FakeResponse(429, headers={"Retry-After": value}), FakeResponse(200, {})])
    c.get("/x")
    assert sleeps == [1.0]


def test_retry_after_http_date_falls_back_to_backoff():
    hdr = {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}
    c, _, sleeps = make([FakeResponse(503, headers=hdr), FakeResponse(503, headers=hdr), FakeResponse(200, {})])
    c.get("/x")
    assert sleeps == [1, 2]


def test_post_502_is_not_retried():
    c, s, sleeps = make([FakeResponse(502), FakeResponse(200, {})])
    with pytest.raises(ApiError) as ei:
        c.post_json("/batches", {})
    assert ei.value.kind is ErrorKind.TEMPORARY and ei.value.status == 502
    assert len(s.calls) == 1 and sleeps == []


def test_post_timeout_is_not_retried():
    c, s, sleeps = make([requests.Timeout("t"), FakeResponse(200, {})])
    with pytest.raises(ApiError) as ei:
        c.post_file("/batches/b/artifacts/upload", "f", b"x", {})
    assert ei.value.kind is ErrorKind.TEMPORARY and len(s.calls) == 1 and sleeps == []


def test_post_503_then_200_retries_once():
    c, s, sleeps = make([FakeResponse(503), FakeResponse(200, {"ok": 1})])
    assert c.post_json("/batches", {}) == {"ok": 1}
    assert len(s.calls) == 2 and sleeps == [1]


def test_post_connection_error_retries():
    c, _, sleeps = make([requests.ConnectionError("x"), FakeResponse(200, {"ok": 1})])
    assert c.post_json("/batches", {}) == {"ok": 1}
    assert sleeps == [1]


def test_get_502_then_200_succeeds():
    c, s, sleeps = make([FakeResponse(502), FakeResponse(200, {"ok": 1})])
    assert c.get("/x") == {"ok": 1}
    assert sleeps == [1]


def test_other_request_exception_becomes_temporary_api_error():
    c, s, _ = make([requests.exceptions.InvalidURL("bad")])
    with pytest.raises(ApiError) as ei:
        c.get("/x")
    assert ei.value.kind is ErrorKind.TEMPORARY and len(s.calls) == 1


def test_invalid_json_on_success_becomes_fatal_api_error():
    c, _, _ = make([FakeResponse(200, text="<html>not json")])
    with pytest.raises(ApiError) as ei:
        c.get("/x")
    assert ei.value.kind is ErrorKind.FATAL and ei.value.status == 200
