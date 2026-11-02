"""The Datadog fetchers' paging: a failed page is never reported as success.

No network and no credentials. `requests.request`, which the shared helper in
fetchers/datadog/_shared/datadog_paging.py makes every call through, is
replaced by a fake Datadog that serves a fixed number of records with each
endpoint's own paging scheme (page number, offset, start/count or cursor) and
fails on a chosen page.

What this proves, for every fetcher that pages:
  - a full walk collects every record and reports success (exit 0);
  - an error on a later page keeps the records collected so far, marks the
    evidence partial_failure with the page reached, and exits 1 with the
    partial_failure code;
  - a 401 on the first page is a failure (auth_failed, exit 1), never "empty";
  - a Cloud SIEM 403 or 404 on the first page reads as "not enabled" only when
    the content pack states report onboarding; otherwise it is a failure, and
    the same status on a later page is a partial failure.

What it cannot prove: that a live Datadog tenant pages exactly the way the API
reference says it does. That needs one run against a real organization.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
DATADOG = REPO_ROOT / "fetchers" / "datadog"
sys.path.insert(0, str(DATADOG / "_shared"))

import datadog_paging  # noqa: E402

BASE_URL = "https://api.datadog.example.invalid"


# --- a fake Datadog ------------------------------------------------------------


class FakeResponse:
    def __init__(self, status: int, body: Any) -> None:
        self.status_code = status
        self._body = body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code} Error", response=self)  # type: ignore[arg-type]

    def json(self) -> Any:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class Scheme:
    """How one endpoint pages, and how it shapes a page body."""

    def __init__(
        self,
        method: str,
        path: str,
        page_size: int,
        index: Callable[[Dict[str, Any], Dict[str, Any], int], int],
        body: Callable[[List[Dict[str, Any]], int, bool], Any],
    ) -> None:
        self.method = method
        self.path = path
        self.page_size = page_size
        self.index = index
        self.body = body


def by_number(param: str) -> Callable[[Dict[str, Any], Dict[str, Any], int], int]:
    return lambda params, _body, _size: int(params[param])


def by_offset(param: str) -> Callable[[Dict[str, Any], Dict[str, Any], int], int]:
    def index(params: Dict[str, Any], _body: Dict[str, Any], size: int) -> int:
        offset = int(params[param])
        assert offset % size == 0, f"offset {offset} is not on a page boundary"
        return offset // size

    return index


def by_cursor(_params: Dict[str, Any], body: Dict[str, Any], _size: int) -> int:
    cursor = body["page"].get("cursor")
    return int(cursor[1:]) if cursor else 0


class FakeDatadog:
    """Serves `total` records; page `fail_at` answers `fail_status` or raises `fail_exc`."""

    def __init__(
        self,
        scheme: Scheme,
        total: int,
        make_record: Callable[[int], Dict[str, Any]],
        fail_at: Optional[Any] = None,
        fail_status: Optional[int] = None,
        fail_exc: Optional[Exception] = None,
    ) -> None:
        self.scheme = scheme
        self.records = [make_record(i) for i in range(total)]
        self.fail_at = fail_at
        self.fail_status = fail_status
        self.fail_exc = fail_exc
        self.pages_served: List[int] = []

    def _fail(self) -> FakeResponse:
        if self.fail_exc is not None:
            raise self.fail_exc
        return FakeResponse(self.fail_status or 500, {"errors": ["synthetic failure"]})

    def __call__(self, method: str, url: str, headers: Any = None, params: Any = None,
                 json: Any = None, timeout: Any = None) -> FakeResponse:
        assert url == BASE_URL + self.scheme.path, url
        assert method == self.scheme.method
        assert headers["DD-API-KEY"] == "test-api-key"
        params = params or {}
        # GET /api/v1/hosts?count=1 is infra_agent_checks' total-count request.
        if params == {"count": 1}:
            if self.fail_at == "total":
                return self._fail()
            return FakeResponse(200, {"total_matching": len(self.records), "host_list": self.records[:1]})
        size = self.scheme.page_size
        idx = self.scheme.index(params, json or {}, size)
        if idx == self.fail_at:
            return self._fail()
        self.pages_served.append(idx)
        chunk = self.records[idx * size:(idx + 1) * size]
        more = (idx + 1) * size < len(self.records)
        return FakeResponse(200, self.scheme.body(chunk, idx, more))


# --- the fetchers under test ---------------------------------------------------


def data_body(chunk: List[Dict[str, Any]], _idx: int, _more: bool) -> Any:
    return {"data": chunk}


def incidents_body(chunk: List[Dict[str, Any]], idx: int, _more: bool) -> Any:
    # The documented meta.pagination has no `total`.
    return {"data": chunk, "meta": {"pagination": {"offset": idx * 100, "next_offset": (idx + 1) * 100, "size": 100}}}


def signals_body(chunk: List[Dict[str, Any]], idx: int, more: bool) -> Any:
    return {"data": chunk, "meta": {"page": {"after": f"c{idx + 1}" if more else None}}}


def hosts_body(chunk: List[Dict[str, Any]], _idx: int, _more: bool) -> Any:
    return {"host_list": chunk, "total_returned": len(chunk)}


FETCHERS: Dict[str, Dict[str, Any]] = {
    "apm_services": {
        "scheme": Scheme("GET", "/api/v2/services/definitions", 100, by_number("page[number]"), data_body),
        "record": lambda i: {"attributes": {"schema": {"dd-service": f"svc-{i}", "team": "team-a"}}},
        "total": 250,
    },
    "monitors_list": {
        "scheme": Scheme("GET", "/api/v1/monitor", 100, by_number("page"), lambda c, _i, _m: c),
        "record": lambda i: {"id": i, "name": f"monitor-{i}", "type": "metric alert", "overall_state": "OK"},
        "total": 250,
    },
    "incidents_list": {
        "scheme": Scheme("GET", "/api/v2/incidents", 100, by_offset("page[offset]"), incidents_body),
        "record": lambda i: {"id": f"inc-{i}", "attributes": {"title": f"incident {i}"}},
        "total": 250,
    },
    "siem_detection_rules": {
        "scheme": Scheme("GET", "/api/v2/security_monitoring/rules", 100, by_number("page[number]"), data_body),
        "record": lambda i: {"id": f"rule-{i}", "name": f"rule {i}", "isEnabled": True},
        "total": 250,
    },
    "siem_signals": {
        "scheme": Scheme("POST", "/api/v2/security_monitoring/signals/search", 100, by_cursor, signals_body),
        "record": lambda i: {"id": f"sig-{i}", "attributes": {"status": "open"}},
        "total": 250,
    },
    "infra_agent_checks": {
        "scheme": Scheme("GET", "/api/v1/hosts", 1000, by_offset("start"), hosts_body),
        "record": lambda i: {"name": f"host-{i}", "meta": {"agent_checks": [["disk", "disk", "", "OK", "", "", []]]}},
        "total": 2500,
    },
}


def load(short: str) -> Any:
    path = DATADOG / short / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"datadog_{short}_under_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("DATADOG_API_KEY", "test-api-key")
    monkeypatch.setenv("DATADOG_APP_KEY", "test-app-key")
    monkeypatch.setenv("DATADOG_BASE_URL", BASE_URL)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    return tmp_path


def run(short: str, fake: FakeDatadog, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    module = load(short)
    # main() reads a .env file; keep the test off the working tree.
    monkeypatch.setattr(module, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(datadog_paging.requests, "request", fake)
    code = module.main()
    evidence = json.loads((tmp_path / f"datadog_{short}.json").read_text())
    status_file = tmp_path / "status.json"
    status = json.loads(status_file.read_text()) if status_file.exists() else None
    return code, evidence, status


def fake_for(short: str, **kwargs: Any) -> FakeDatadog:
    spec = FETCHERS[short]
    return FakeDatadog(spec["scheme"], kwargs.pop("total", spec["total"]), spec["record"], **kwargs)


ALL = sorted(FETCHERS)


# --- a full walk -------------------------------------------------------------


@pytest.mark.parametrize("short", ALL)
def test_full_walk_reports_success(short: str, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = fake_for(short)
    code, evidence, status = run(short, fake, monkeypatch, env)

    assert code == 0
    assert status is None
    assert evidence["status"] == "success"
    assert evidence["record_count"] == FETCHERS[short]["total"]
    assert evidence["metadata"] == {"partial_failure": False, "api_failures": []}
    assert fake.pages_served == [0, 1, 2]


# --- a failure part-way through ---------------------------------------------


@pytest.mark.parametrize("short", ALL)
def test_mid_pagination_error_is_partial_failure(short: str, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = fake_for(short, fail_at=1, fail_status=500)
    code, evidence, status = run(short, fake, monkeypatch, env)

    page_size = FETCHERS[short]["scheme"].page_size
    assert code == 1
    assert evidence["status"] == "partial_failure"
    # The first page's records are kept, not thrown away and not padded.
    assert evidence["record_count"] == page_size
    assert evidence["metadata"]["partial_failure"] is True
    [failure] = evidence["metadata"]["api_failures"]
    assert failure["status_code"] == 500
    assert failure["pages_completed"] == 1
    assert failure["page"] in {"page 1", f"page[offset]={page_size}", f"start={page_size}"}
    assert failure["page"] in evidence["message"]
    assert status is not None and status["code"] == "partial_failure"
    assert failure["page"] in status["error"]


@pytest.mark.parametrize("short", ALL)
def test_mid_pagination_connection_error_is_partial_failure(
    short: str, env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = fake_for(short, fail_at=2, fail_exc=requests.exceptions.ConnectionError("connection reset"))
    code, evidence, status = run(short, fake, monkeypatch, env)

    assert code == 1
    assert evidence["status"] == "partial_failure"
    assert evidence["record_count"] == 2 * FETCHERS[short]["scheme"].page_size
    assert evidence["metadata"]["api_failures"][0]["type"] == "ConnectionError"
    assert status is not None and status["code"] == "partial_failure"


@pytest.mark.parametrize("short", ALL)
def test_mid_pagination_bad_json_is_partial_failure(short: str, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = fake_for(short)
    real_call = fake.__call__

    def broken_second_page(*args: Any, **kwargs: Any) -> FakeResponse:
        response = real_call(*args, **kwargs)
        if fake.pages_served == [0, 1]:
            return FakeResponse(200, ValueError("Expecting value: line 1 column 1"))
        return response

    code, evidence, _status = run(short, broken_second_page, monkeypatch, env)  # type: ignore[arg-type]
    assert code == 1
    assert evidence["status"] == "partial_failure"


# --- a failure on the first page ---------------------------------------------


@pytest.mark.parametrize("short", ALL)
def test_first_page_401_is_failure_not_empty(short: str, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fail_at: Any = "total" if short == "infra_agent_checks" else 0
    fake = fake_for(short, fail_at=fail_at, fail_status=401)
    code, evidence, status = run(short, fake, monkeypatch, env)

    assert code == 1
    assert evidence["status"] == "error"
    assert "record_count" not in evidence
    assert status == {"code": "auth_failed", "error": evidence["message"]}


@pytest.mark.parametrize("short", ["apm_services", "incidents_list", "infra_agent_checks", "monitors_list"])
def test_first_page_403_is_failure_where_no_feature_gate(
    short: str, env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = fake_for(short, fail_at=0, fail_status=403)
    code, evidence, status = run(short, fake, monkeypatch, env)

    assert code == 1
    assert evidence["status"] == "error"
    assert status is not None and status["code"] == "not_authorized"


def test_infra_host_count_timeout_is_failure_not_no_hosts(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = fake_for("infra_agent_checks", fail_at="total", fail_exc=requests.exceptions.ReadTimeout("timed out"))
    code, evidence, status = run("infra_agent_checks", fake, monkeypatch, env)

    assert code == 1
    assert evidence["status"] == "error"
    assert evidence.get("message") != "No hosts found"
    assert status is not None and status["code"] == "target_unreachable"


def test_infra_host_count_bad_json_is_failure(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(method: str, url: str, **kwargs: Any) -> FakeResponse:
        return FakeResponse(200, ValueError("Expecting value"))

    code, evidence, _status = run("infra_agent_checks", fake, monkeypatch, env)  # type: ignore[arg-type]
    assert code == 1
    assert evidence["status"] == "error"


# --- genuine emptiness and the SIEM feature gate ------------------------------


@pytest.mark.parametrize("short", ["apm_services", "monitors_list", "incidents_list", "infra_agent_checks"])
def test_genuinely_empty_is_still_partial_or_empty(short: str, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, evidence, status = run(short, fake_for(short, total=0), monkeypatch, env)

    assert code == 0
    assert status is None
    assert evidence["status"] == "partial_or_empty"


CONTENT_PACKS = "/api/v2/security_monitoring/content_packs/states"


def with_content_packs(fake: FakeDatadog, detail_type: str = "", status: int = 200) -> Callable[..., FakeResponse]:
    """`fake`, plus a content pack states endpoint that reports `detail_type`."""
    def call(method: str, url: str, headers: Any = None, params: Any = None,
             json: Any = None, timeout: Any = None) -> FakeResponse:
        if url == BASE_URL + CONTENT_PACKS:
            if status != 200:
                return FakeResponse(status, {"errors": ["synthetic failure"]})
            pack = {"attributes": {"details": {"type": detail_type}}}
            return FakeResponse(200, {"data": [pack, pack], "meta": {"sku": "test"}})
        return fake(method, url, headers, params, json, timeout)
    return call


@pytest.mark.parametrize("short", ["siem_detection_rules", "siem_signals"])
@pytest.mark.parametrize("http_status", [403, 404])
def test_siem_off_on_first_page_is_not_available_only_on_the_onboarding_signal(
    short: str, http_status: int, env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = with_content_packs(fake_for(short, fail_at=0, fail_status=http_status), "onboarding")
    code, evidence, status = run(short, fake, monkeypatch, env)

    assert code == 0
    assert status is None
    assert evidence["status"] == "not_available"
    assert evidence["data"]["siem_state"]["enabled"] is False


@pytest.mark.parametrize("short", ["siem_detection_rules", "siem_signals"])
def test_siem_403_with_siem_active_is_not_authorized(short: str, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = with_content_packs(fake_for(short, fail_at=0, fail_status=403), "security_monitoring")
    code, evidence, status = run(short, fake, monkeypatch, env)

    assert code == 1
    assert evidence["status"] == "error"
    assert evidence["error_code"] == "not_authorized"
    assert evidence["siem_state"]["enabled"] is True
    assert status is not None and status["code"] == "not_authorized"


@pytest.mark.parametrize("short", ["siem_detection_rules", "siem_signals"])
def test_siem_404_with_unknown_siem_state_is_a_failure(short: str, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = with_content_packs(fake_for(short, fail_at=0, fail_status=404), status=404)
    code, evidence, _status = run(short, fake, monkeypatch, env)

    assert code == 1
    assert evidence["status"] == "error"
    assert evidence["siem_state"]["enabled"] is None
    assert evidence["siem_state"]["status_code"] == 404


@pytest.mark.parametrize("short", ["siem_detection_rules", "siem_signals"])
def test_siem_403_after_first_page_is_partial_failure(short: str, env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, evidence, status = run(short, fake_for(short, fail_at=1, fail_status=403), monkeypatch, env)

    assert code == 1
    assert evidence["status"] == "partial_failure"
    assert evidence["record_count"] == 100
    assert status is not None and status["code"] == "partial_failure"


# --- the helper on its own -------------------------------------------------------


def test_incidents_walk_does_not_need_a_total(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The incidents meta.pagination has no `total`; reading one stopped the walk after page 0."""
    fake = fake_for("incidents_list", total=230)
    code, evidence, _status = run("incidents_list", fake, monkeypatch, env)

    assert code == 0
    assert evidence["record_count"] == 230
    assert fake.pages_served == [0, 1, 2]


def test_walk_stops_at_the_page_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """A server that ignores the paging parameters cannot loop forever, or read as success."""
    monkeypatch.setattr(datadog_paging, "MAX_PAGES", 3)

    def same_full_page(state: int):
        return [{"id": state}], state + 1

    records = datadog_paging.walk("Datadog list things", same_full_page, 0, lambda s: f"page {s}")
    assert len(records) == 3
    assert records.error is not None
    assert records.error.pages_completed == 3
    result = datadog_paging.with_paging_status({"status": "success"}, records)
    assert result["status"] == "partial_failure"


def test_a_non_list_page_body_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        datadog_paging.requests, "request",
        lambda *a, **k: FakeResponse(200, {"errors": ["not a list"]}),
    )
    with pytest.raises(datadog_paging.PagingError) as caught:
        datadog_paging.paginate_page_number(
            BASE_URL + "/api/v1/monitor", {}, operation="Datadog list monitors",
            page_size=100, size_param="page_size", number_param="page", records_key=None,
        )
    assert caught.value.pages_completed == 0
    assert isinstance(caught.value.cause, ValueError)
