"""nist_cmvp_module_validation_status against a local HTTP server.

The pages under tests/fixtures/nist_cmvp/ are trimmed from the live certificate
pages on csrc.nist.gov (4816 Active, 4282 Historical, 1381 Revoked), as served
on 2026-11-13. The other cases are edits of the 4816 page.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "nist_cmvp"
_spec = importlib.util.spec_from_file_location(
    "nist_cmvp_module_validation_status",
    REPO_ROOT / "fetchers" / "nist_cmvp" / "module_validation_status" / "fetcher.py",
)
cmvp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cmvp)

NOW = datetime(2026, 11, 13, 18, 0, tzinfo=timezone.utc)
ACTIVE = (FIXTURES / "cert_4816.html").read_text()
HISTORICAL = (FIXTURES / "cert_4282.html").read_text()
REVOKED = (FIXTURES / "cert_1381.html").read_text()


def edit(page: str, number: int, **swap: str) -> str:
    """The 4816 page renumbered, with each old=new text swap applied."""
    page = page.replace("Certificate #4816", f"Certificate #{number}")
    for old, new in swap.values():
        assert old in page, old
        page = page.replace(old, new)
    return page


STATUS_ROW = '<div class="col-md-3">Status</div>\n              <div class="col-md-9">Active</div>'
PAGES: Dict[int, str] = {
    4816: ACTIVE,
    4282: HISTORICAL,
    1381: REVOKED,
    # FIPS 140-2 certificates sunset on 9/21/2026; one still shown Active must not pass.
    1001: edit(ACTIVE, 1001, std=("FIPS 140-3", "FIPS 140-2"), sunset=("9/30/2029", "9/21/2026")),
    1002: edit(ACTIVE, 1002, status=(STATUS_ROW, "")),
    1003: edit(ACTIVE, 1003, status=(">Active<", ">In Review<")),
    1004: edit(ACTIVE, 1004, sunset=("9/30/2029", "TBD")),
    1005: edit(ACTIVE, 1005, std=("FIPS 140-3", "FIPS 140-1")),
    1006: edit(ACTIVE, 1006, heading=("<h3>Certificate #1006</h3>", "")),
    1007: "<html><body><h3>Certificate #1007</h3><p>Something went wrong",
    1009: "<html><body><h2>Search results</h2><p>No modules match.</p></body></html>",
    1008: edit(ACTIVE, 1008, sunset=("9/30/2029", "11/13/2026")),  # sunset today still counts
    5000: ACTIVE,  # serves another certificate's page
}

Routes = Dict[str, Tuple[int, str]]


class _Handler(BaseHTTPRequestHandler):
    routes: Routes = {}
    hits: Dict[str, int] = {}
    user_agents: list = []

    def do_GET(self) -> None:  # noqa: N802
        _Handler.hits[self.path] = _Handler.hits.get(self.path, 0) + 1
        _Handler.user_agents.append(self.headers.get("User-Agent"))
        status, body = self.routes.get(self.path, (404, "<title>Page Not Found | CSRC</title>"))
        if isinstance(status, list):  # a sequence of statuses, one per request
            status = status.pop(0) if len(status) > 1 else status[0]
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        pass


def path(number: int) -> str:
    return cmvp.CERT_PATH.format(number=number)


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture
def site(server, monkeypatch):
    _Handler.routes = {path(n): (200, page) for n, page in PAGES.items()}
    _Handler.hits, _Handler.user_agents = {}, []
    monkeypatch.setattr(cmvp, "RETRY_BACKOFF_SECONDS", 0)
    return server


def check(site: str, number: int) -> dict:
    evidence, _ = cmvp.collect([(None, number)], site, NOW)
    return evidence["certificates"][0]


def test_live_active_page_parses():
    page = cmvp.parse_certificate_page(ACTIVE)
    assert page == {
        "page_certificate_number": 4816,
        "has_details": True,
        "module_name": "AWS-LC Cryptographic Module (static)",
        "standard": "FIPS 140-3",
        "status": "Active",
        "historical_reason": None,
        "sunset_date": "9/30/2029",
        "overall_level": "1",
        "caveat": "When operated in approved mode. No assurance of the minimum strength of generated SSPs (e.g., keys)",
        "security_level_exceptions": ["Physical security: N/A", "Non-invasive security: N/A"],
        "module_type": "Software",
        "embodiment": "Multi-Chip Stand Alone",
        "vendor": "Amazon Web Services Inc.",
        "validation_history": [{"date": "2024-10-01", "type": "Initial", "lab": "atsec information security corporation"}],
    }


def test_live_historical_and_revoked_pages_parse():
    historical = cmvp.parse_certificate_page(HISTORICAL)
    assert (historical["status"], historical["historical_reason"], historical["sunset_date"]) == (
        "Historical", "Moved to historical list due to sunsetting", None)
    revoked = cmvp.parse_certificate_page(REVOKED)
    assert (revoked["status"], revoked["historical_reason"], revoked["vendor"]) == ("Revoked", "Revoked", "Accellion, Inc.")


@pytest.mark.parametrize("number,reason", [
    (4816, None),
    (1008, None),
    (4282, "historical"),
    (1381, "revoked"),
    (1001, "sunset_passed"),
    (1002, "status_unknown"),
    (1003, "status_unknown"),
    (1005, "status_unknown"),
    (1004, "parse_error"),
    (1006, "parse_error"),
    (1007, "parse_error"), # names the certificate, but no Details rows
    (1009, "not_found"),   # an unrelated page
    (5000, "not_found"),   # the page is for 4816
    (9999, "not_found"),   # HTTP 404, as NIST answers an unknown number
])
def test_verdicts(site, number, reason):
    record = check(site, number)
    assert record["reason"] == reason, record["reason_detail"]
    assert record["validated"] is (reason is None)


def test_validated_record(site):
    record = check(site, 4816)
    assert record["sunset_date"] == "2029-09-30"
    assert record["validation_dates"] == ["2024-10-01"]
    assert record["url"] == f"{site}/projects/cryptographic-module-validation-program/certificate/4816"
    assert record["vendor"] == "Amazon Web Services Inc."
    assert _Handler.user_agents == ["paramify-fetchers nist_cmvp_module_validation_status/0.1.0"]


def test_server_errors_are_retried_then_fail_as_fetch_error(site):
    _Handler.routes[path(4816)] = ([503, 503, 200], ACTIVE)
    assert check(site, 4816)["validated"] is True
    _Handler.routes[path(4816)] = ([500], "")
    record = check(site, 4816)
    assert (record["reason"], record["http_status"]) == ("fetch_error", None)
    assert _Handler.hits[path(4816)] == 3 + cmvp.RETRIES + 1


def test_one_failed_certificate_does_not_stop_the_others(site):
    _Handler.routes[path(4282)] = ([500], "")
    evidence, failures = cmvp.collect([("AWS-LC", 4816), (None, 4282), (None, 1381)], site, NOW)
    assert [r["reason"] for r in evidence["certificates"]] == [None, "fetch_error", "revoked"]
    assert evidence["certificates"][0]["label"] == "AWS-LC"
    assert len(failures) == 1
    assert evidence["metadata"]["api_failures"][0]["type"] == "fetch_error"


def test_main_writes_summary_and_reports_partial_failure(site, monkeypatch, tmp_path, assert_summary_documented):
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.setenv("NIST_CMVP_BASE_URL", site + "/")
    monkeypatch.setenv("NIST_CMVP_CERTIFICATES", "AWS-LC=4816, #4282, 1381, 1001, 1004, 9999")
    assert cmvp.main() == 1
    evidence = json.loads((tmp_path / "nist_cmvp_module_validation_status.json").read_text())
    summary = evidence["summary"]
    assert (summary["certificates_total"], summary["certificates_validated"], summary["certificates_not_validated"]) == (6, 1, 5)
    assert summary["not_validated_by_reason"] == {
        "historical": 1, "revoked": 1, "sunset_passed": 1, "status_unknown": 0,
        "not_found": 1, "parse_error": 1, "fetch_error": 0,
    }
    assert json.loads(status_file.read_text())["code"] == "partial_failure"
    assert_summary_documented("nist_cmvp/module_validation_status", summary)


def test_main_exits_zero_when_every_page_was_read(site, monkeypatch, tmp_path):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("NIST_CMVP_BASE_URL", site)
    monkeypatch.setenv("NIST_CMVP_CERTIFICATES", "4282, 9999")  # not validated is a verdict, not a failure
    assert cmvp.main() == 0
    assert "metadata" not in json.loads((tmp_path / "nist_cmvp_module_validation_status.json").read_text())


def test_unreachable_base_url_still_writes_json(monkeypatch, tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    status_file = tmp_path / "status.json"
    monkeypatch.setattr(cmvp, "RETRY_BACKOFF_SECONDS", 0)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.setenv("NIST_CMVP_BASE_URL", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("NIST_CMVP_CERTIFICATES", "4816, 4282")
    assert cmvp.main() == 1
    evidence = json.loads((tmp_path / "nist_cmvp_module_validation_status.json").read_text())
    assert evidence["summary"]["not_validated_by_reason"]["fetch_error"] == 2
    assert evidence["metadata"]["partial_failure"] is True
    assert json.loads(status_file.read_text())["code"] == "target_unreachable"


@pytest.mark.parametrize("raw,expected", [
    ("4816, 4282", [(None, 4816), (None, 4282)]),
    ("AWS-LC=4816;#4282\n", [("AWS-LC", 4816), (None, 4282)]),
])
def test_parse_certificates(raw, expected):
    assert cmvp.parse_certificates(raw) == expected


@pytest.mark.parametrize("raw", ["", " , ", "AWS-LC", "48a6"])
def test_bad_config_fails_with_json(monkeypatch, tmp_path, raw):
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))
    monkeypatch.setenv("NIST_CMVP_CERTIFICATES", raw)
    assert cmvp.main() == 1
    assert json.loads((tmp_path / "nist_cmvp_module_validation_status.json").read_text())["certificates"] == []
    assert json.loads(status_file.read_text())["code"] == "bad_config"
