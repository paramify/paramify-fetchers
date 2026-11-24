"""tenable_vuln_scan: export one Tenable.io scan run as an unmodified .nessus file.

Mocks only the HTTP boundary (requests.request), so the fetcher's own retry,
history selection, polling, download and empty-report checks all run.
"""

from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "tenable" / "vuln_scan" / "fetcher.py"
API = "https://cloud.tenable.com"
SCAN = "42"

NESSUS = (b'<?xml version="1.0" ?>\n<NessusClientData_v2><Report name="weekly">'
          b'<ReportHost name="10.0.0.1"><ReportItem pluginID="19506" severity="0"/></ReportHost>'
          b"</Report></NessusClientData_v2>\n")
NO_HOSTS = b'<?xml version="1.0" ?>\n<NessusClientData_v2><Report name="weekly"></Report></NessusClientData_v2>\n'


def load():
    spec = importlib.util.spec_from_file_location("tenable_vuln_scan_under_test", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tenable = load()


class Resp:
    def __init__(self, status: int = 200, body: Any = None, content: bytes = b"",
                 headers: Optional[Dict[str, str]] = None, text: Optional[str] = None,
                 chunk: int = 1024 * 1024, fail_after: Optional[int] = None):
        self.status_code = status
        self._body = body
        self._content = content
        self._chunk = chunk
        self._fail_after = fail_after
        self.headers = requests.structures.CaseInsensitiveDict(headers or {})
        self.text = text if text is not None else (json.dumps(body) if body is not None else "")
        self.closed = False

    def json(self):
        if self._body is None:
            return json.loads(self.text)
        return self._body

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._content), self._chunk):
            if self._fail_after is not None and i >= self._fail_after:
                raise requests.exceptions.ChunkedEncodingError("connection broken")
            yield self._content[i:i + self._chunk]

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def run(run_id: int, status: str = "completed", days_ago: float = 1.0) -> dict:
    end = int(time.time() - days_ago * 86400)
    return {"id": run_id, "scan_uuid": f"uuid-{run_id}", "status": status,
            "time_start": end - 3600, "time_end": end}


class FakeTenable:
    """Routes by method and path; each route is a list of responses used in turn (last one repeats)."""

    def __init__(self):
        self.calls: List[dict] = []
        self.routes: Dict[tuple, List[Any]] = {
            ("GET", f"/scans/{SCAN}/history"): [Resp(body={"history": [run(7, days_ago=2), run(6, days_ago=9)],
                                                         "pagination": {"total": 2}})],
            ("POST", f"/scans/{SCAN}/export"): [Resp(body={"file": "F1", "temp_token": "t"})],
            ("GET", f"/scans/{SCAN}/export/F1/status"): [Resp(body={"status": "ready"})],
            ("GET", f"/scans/{SCAN}/export/F1/download"): [Resp(content=NESSUS, chunk=7)],
        }

    def set(self, method: str, path: str, *responses: Any) -> None:
        self.routes[(method, path)] = list(responses)

    def __call__(self, method, url, headers=None, params=None, json=None, **kw):
        assert url.startswith(API), url
        path = url[len(API):]
        self.calls.append({"method": method, "path": path, "params": params, "json": json, "headers": headers})
        queue = self.routes[(method, path)]
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        if isinstance(item, Callable):
            return item(params)
        return item

    def paths(self) -> List[str]:
        return [f"{c['method']} {c['path']}" for c in self.calls]


@pytest.fixture
def fake(monkeypatch, tmp_path):
    f = FakeTenable()
    monkeypatch.setattr(tenable.requests, "request", f)
    # A fake clock that sleeping advances, so a polling bug fails fast instead of hanging.
    clock = [0.0]

    def sleep(seconds):
        f.calls.append({"method": "SLEEP", "path": seconds})
        clock[0] += seconds

    monkeypatch.setattr(tenable, "_sleep", sleep)
    monkeypatch.setattr(tenable, "_monotonic", lambda: clock[0])
    for key in ("TENABLE_API_BASE_URL", "TENABLE_MAX_SCAN_AGE_DAYS", "TENABLE_EXPORT_WAIT_SECONDS",
                "TENABLE_ALLOW_EMPTY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "ak")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "sk")
    monkeypatch.setenv("TENABLE_SCAN_ID", SCAN)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    return f


OUT = f"tenable_vuln_scan_{SCAN}.nessus"


def status(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "status.json").read_text())


def reports(tmp_path: Path) -> List[str]:
    return sorted(p.name for p in tmp_path.iterdir() if p.name != "status.json")


# ------------------------------------------------------------------ success

def test_ready_export_is_written_byte_for_byte(fake, tmp_path):
    assert tenable.main() == 0
    assert (tmp_path / OUT).read_bytes() == NESSUS
    assert reports(tmp_path) == [OUT]
    assert not (tmp_path / "status.json").exists()


def test_export_is_pinned_to_the_newest_completed_run(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/history", Resp(body={"history": [
        run(9, "aborted", days_ago=0.5), run(8, "running", days_ago=0.1),
        run(6, days_ago=9), run(7, days_ago=2)], "pagination": {"total": 4}}))
    assert tenable.main() == 0
    export = next(c for c in fake.calls if c["method"] == "POST")
    assert export["params"] == {"history_id": 7}
    assert export["json"] == {"format": "nessus"}


def test_api_keys_go_in_the_x_apikeys_header(fake, tmp_path):
    assert tenable.main() == 0
    assert all(c["headers"]["X-ApiKeys"] == "accessKey=ak; secretKey=sk"
               for c in fake.calls if c["method"] != "SLEEP")


def test_loading_is_polled_until_ready(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/export/F1/status",
             Resp(body={"status": "loading"}), Resp(body={"status": "loading"}), Resp(body={"status": "ready"}))
    assert tenable.main() == 0
    assert fake.paths().count(f"GET /scans/{SCAN}/export/F1/status") == 3
    assert [c["path"] for c in fake.calls if c["method"] == "SLEEP"] == [10, 10]


def test_report_host_tag_split_across_chunks_is_found(fake, tmp_path):
    start = NESSUS.index(b"<ReportHost")
    # Every chunk boundary lands inside the tag for some chunk size from 2 to 11.
    for size in range(2, 12):
        fake.set("GET", f"/scans/{SCAN}/export/F1/download", Resp(content=NESSUS, chunk=size))
        (tmp_path / OUT).unlink(missing_ok=True)
        assert tenable.main() == 0, f"chunk size {size}, tag at {start}"
        assert (tmp_path / OUT).read_bytes() == NESSUS


# ------------------------------------------------------------- run checks

def test_no_completed_run_fails(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/history", Resp(body={"history": [run(9, "aborted"), run(8, "canceled")]}))
    assert tenable.main() == 1
    assert "no completed run" in status(tmp_path)["error"]
    assert status(tmp_path)["code"] == "partial_failure"
    assert "POST" not in [c["method"] for c in fake.calls]


def test_stale_run_is_refused(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/history", Resp(body={"history": [run(7, days_ago=40)]}))
    assert tenable.main() == 1
    assert "max_scan_age_days" in status(tmp_path)["error"]
    assert reports(tmp_path) == []


def test_max_scan_age_is_configurable(fake, tmp_path, monkeypatch):
    fake.set("GET", f"/scans/{SCAN}/history", Resp(body={"history": [run(7, days_ago=40)]}))
    monkeypatch.setenv("TENABLE_MAX_SCAN_AGE_DAYS", "45")
    assert tenable.main() == 0


@pytest.mark.parametrize("value", ["0", "-1", "soon"])
def test_bad_max_scan_age_is_bad_config(fake, tmp_path, monkeypatch, value):
    monkeypatch.setenv("TENABLE_MAX_SCAN_AGE_DAYS", value)
    assert tenable.main() == 1
    assert status(tmp_path)["code"] == "bad_config"
    assert fake.calls == []


def test_history_oldest_first_reads_every_page(fake, tmp_path, monkeypatch):
    # If Tenable ignores the sort, the newest run is on the last page.
    monkeypatch.setattr(tenable, "HISTORY_PAGE_SIZE", 2)
    pages = {0: [run(1, days_ago=30), run(2, days_ago=20)], 2: [run(3, days_ago=3)]}
    fake.set("GET", f"/scans/{SCAN}/history",
             lambda params: Resp(body={"history": pages[params["offset"]], "pagination": {"total": 3}}))
    assert tenable.main() == 0
    assert fake.paths().count(f"GET /scans/{SCAN}/history") == 2
    export = next(c for c in fake.calls if c["method"] == "POST")
    assert export["params"] == {"history_id": 3}


def test_history_newest_first_stops_after_one_page(fake, tmp_path, monkeypatch):
    monkeypatch.setattr(tenable, "HISTORY_PAGE_SIZE", 2)
    fake.set("GET", f"/scans/{SCAN}/history",
             Resp(body={"history": [run(9, days_ago=1), run(8, days_ago=8)], "pagination": {"total": 300}}))
    assert tenable.main() == 0
    assert fake.paths().count(f"GET /scans/{SCAN}/history") == 1


def test_no_hosts_report_is_refused_and_deleted(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/export/F1/download", Resp(content=NO_HOSTS))
    assert tenable.main() == 1
    assert "no hosts" in status(tmp_path)["error"]
    assert status(tmp_path)["code"] == "partial_failure"
    assert reports(tmp_path) == []


def test_allow_empty_accepts_a_no_hosts_report(fake, tmp_path, monkeypatch):
    fake.set("GET", f"/scans/{SCAN}/export/F1/download", Resp(content=NO_HOSTS))
    monkeypatch.setenv("TENABLE_ALLOW_EMPTY", "true")
    assert tenable.main() == 0
    assert (tmp_path / OUT).read_bytes() == NO_HOSTS


def test_zero_byte_download_is_refused(fake, tmp_path, monkeypatch):
    fake.set("GET", f"/scans/{SCAN}/export/F1/download", Resp(content=b""))
    monkeypatch.setenv("TENABLE_ALLOW_EMPTY", "true")
    assert tenable.main() == 1
    assert reports(tmp_path) == []


# ---------------------------------------------------------------- failures

def test_export_error_status_fails_at_once(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/export/F1/status", Resp(body={"status": "error"}))
    assert tenable.main() == 1
    assert "reported an error" in status(tmp_path)["error"]
    assert fake.paths().count(f"GET /scans/{SCAN}/export/F1/status") == 1
    assert not any(c["method"] == "SLEEP" for c in fake.calls)


def test_export_not_ready_in_time_names_the_setting(fake, tmp_path, monkeypatch):
    fake.set("GET", f"/scans/{SCAN}/export/F1/status", Resp(body={"status": "loading"}))
    monkeypatch.setenv("TENABLE_EXPORT_WAIT_SECONDS", "30")
    assert tenable.main() == 1
    assert "export_wait_seconds" in status(tmp_path)["error"]
    # Checked at 0, 10, 20 and 30 seconds.
    assert fake.paths().count(f"GET /scans/{SCAN}/export/F1/status") == 4


def test_export_wait_over_the_limit_is_bad_config(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("TENABLE_EXPORT_WAIT_SECONDS", "5000")
    assert tenable.main() == 1
    assert status(tmp_path)["code"] == "bad_config"


def test_429_then_200_succeeds_after_retry_after(fake, tmp_path):
    fake.set("POST", f"/scans/{SCAN}/export",
             Resp(429, text="<html>429</html>", headers={"retry-after": "7"}),
             Resp(body={"file": "F1", "temp_token": "t"}))
    assert tenable.main() == 0
    assert {"method": "SLEEP", "path": 7.0} in fake.calls


@pytest.mark.parametrize("code", [502, 503, 504])
def test_5xx_while_polling_is_retried(fake, tmp_path, code):
    fake.set("GET", f"/scans/{SCAN}/export/F1/status", Resp(code, text="busy"), Resp(body={"status": "ready"}))
    assert tenable.main() == 0


def test_429_every_time_is_rate_limited(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/history", Resp(429, text="slow down"))
    assert tenable.main() == 1
    assert status(tmp_path)["code"] == "rate_limited"
    assert fake.paths().count(f"GET /scans/{SCAN}/history") == tenable.RETRIES + 1


def test_long_retry_after_fails_instead_of_waiting(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/history", Resp(429, headers={"retry-after": "900"}))
    assert tenable.main() == 1
    assert status(tmp_path)["code"] == "rate_limited"
    assert not any(c["method"] == "SLEEP" for c in fake.calls)


def test_connection_error_is_target_unreachable(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/history", requests.exceptions.ConnectionError("no route"))
    assert tenable.main() == 1
    assert status(tmp_path)["code"] == "target_unreachable"


def test_truncated_download_leaves_no_file(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/export/F1/download", Resp(content=NESSUS, chunk=16, fail_after=32))
    assert tenable.main() == 1
    assert status(tmp_path)["code"] == "target_unreachable"
    assert "cut off" in status(tmp_path)["error"]
    assert reports(tmp_path) == []


def test_download_http_error_leaves_no_file(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/export/F1/download", Resp(500, text="oops"))
    assert tenable.main() == 1
    assert reports(tmp_path) == []


@pytest.mark.parametrize("code,expected", [(401, "auth_failed"), (403, "not_authorized"), (404, "bad_config")])
def test_http_errors_map_to_status_codes(fake, tmp_path, code, expected):
    fake.set("GET", f"/scans/{SCAN}/history", Resp(code, text="no"))
    assert tenable.main() == 1
    assert status(tmp_path)["code"] == expected


def test_html_instead_of_json_reports_the_body(fake, tmp_path):
    fake.set("GET", f"/scans/{SCAN}/history", Resp(200, text="<html><title>Login</title></html>"))
    assert tenable.main() == 1
    assert "not JSON" in status(tmp_path)["error"]
    assert "<html>" in status(tmp_path)["error"]


def test_failure_reason_reaches_stderr(fake, tmp_path, caplog):
    fake.set("GET", f"/scans/{SCAN}/export/F1/status", Resp(body={"status": "error"}))
    assert tenable.main() == 1
    assert any("reported an error" in r.getMessage() for r in caplog.records if r.levelname == "ERROR")


# ------------------------------------------------------------------ config

@pytest.mark.parametrize("scan_id", ["12/../34", "abc", "0", "1 2", "9" * 25])
def test_non_numeric_scan_id_fails_before_any_request(fake, tmp_path, monkeypatch, scan_id):
    monkeypatch.setenv("TENABLE_SCAN_ID", scan_id)
    assert tenable.main() == 1
    assert status(tmp_path)["code"] == "bad_config"
    assert fake.calls == []


@pytest.mark.parametrize("url", ["http://cloud.tenable.com", "https://user:pw@cloud.tenable.com",
                                 "cloud.tenable.com", "https://cloud.tenable.com?x=1"])
def test_base_url_must_be_plain_https(fake, tmp_path, monkeypatch, url):
    monkeypatch.setenv("TENABLE_API_BASE_URL", url)
    assert tenable.main() == 1
    assert status(tmp_path)["code"] == "bad_config"
    assert fake.calls == []


def test_missing_keys_is_bad_config(fake, tmp_path, monkeypatch):
    monkeypatch.delenv("TENABLE_SECRET_KEY")
    assert tenable.main() == 1
    assert status(tmp_path)["code"] == "bad_config"
    assert fake.calls == []
