"""wiz_issues_report and wiz_vulnerability_findings: read-only issue reports.

Mocks only the HTTP boundary (requests.post in the shared Wiz client, and
requests.get for the report download), so the real client, its read-only
guard, paging and failure tracking all run.
"""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
WIZ = REPO_ROOT / "fetchers" / "wiz"
AUTH = "https://auth.app.wiz.us/oauth/token"
API = "https://api.us2.app.wiz.us/graphql"
DOWNLOAD = "https://wiz-reports.s3.amazonaws.com/rep-1.csv?X-Amz-Signature=abc"
ISSUES_CSV = (b"Created At,Title,Severity,Status,Issue ID\n"
              b'2026-09-01T00:00:00Z,"Public bucket, 0",HIGH,OPEN,issue-0000\n')
PROJECT = "96a0d4ea-88bf-486c-8461-5952b83b4ad4"


def load(path: Path, name: str):
    sys.path.insert(0, str(WIZ / "_shared"))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


issues = load(WIZ / "issues_report" / "fetcher.py", "wiz_issues_report_under_test")
vulns = load(WIZ / "vulnerability_findings" / "fetcher.py", "wiz_vuln_findings_under_test")
wiz_client = sys.modules["wiz_client"]


class Resp:
    def __init__(self, status: int, body: Any = None, content: bytes = b"", fail_midway: bool = False):
        self.status_code = status
        self._body = body
        self._content = content
        self._fail_midway = fail_midway
        self.headers: Dict[str, str] = {}
        self.text = json.dumps(body)

    def json(self):
        return self._body

    def iter_content(self, chunk_size=1):
        yield self._content[:10]
        if self._fail_midway:
            raise requests.exceptions.ConnectionError("connection reset")
        yield self._content[10:]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def iso(hours_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def vuln_node(i: int) -> dict:
    return {
        "id": f"vf-{i:05d}", "name": f"CVE-2024-{1000 + i}", "CVEDescription": "d",
        "CVSSSeverity": "HIGH", "score": 7.5, "severity": "HIGH", "nvdSeverity": "HIGH",
        "status": "OPEN", "hasExploit": False, "hasFix": True, "hasCisaKevExploit": False,
        "firstDetectedAt": "2026-08-01T00:00:00Z", "lastDetectedAt": "2026-09-30T00:00:00Z",
        "resolvedAt": None, "description": "d", "remediation": "upgrade",
        "detailedName": "openssl", "version": "1.1.1", "fixedVersion": "3.0.0",
        "detectionMethod": "PACKAGE", "link": "https://nvd", "portalUrl": "https://app.wiz.us/x",
        "epssSeverity": "LOW", "epssPercentile": 0.5, "epssProbability": 0.01,
        "relatedIssueAnalytics": {"issueCount": 1, "criticalSeverityCount": 0, "highSeverityCount": 1,
                                  "mediumSeverityCount": 0, "lowSeverityCount": 0},
        "vulnerableAsset": {"id": f"asset-{i % 7}", "type": "VIRTUAL_MACHINE", "name": f"vm-{i % 7}",
                            "region": "us-east-1", "providerUniqueId": f"i-{i % 7}", "cloudPlatform": "AWS",
                            "status": "Active", "subscriptionName": "prod", "subscriptionExternalId": "1",
                            "tags": {"env": "prod"}, "hasWideInternetExposure": False,
                            "operatingSystem": "Linux", "ipAddresses": ["10.0.0.1"]},
    }


class FakeWiz:
    def __init__(self) -> None:
        self.reports: List[Dict[str, Any]] = [{"id": "rep-1", "name": "Paramify-Wiz-Issues"}]
        self.last_run: Optional[Dict[str, Any]] = {"status": "COMPLETED", "url": DOWNLOAD, "runAt": iso(2)}
        self.report_missing = False
        self.errors: Dict[str, str] = {}
        self.download = Resp(200, content=ISSUES_CSV)
        self.downloads: List[Dict[str, Any]] = []
        self.vuln_count = 250
        self.vuln_break_page = 0
        self.vuln_error_page = 0
        self.vuln_filters: List[Any] = []
        self.queries: List[str] = []

    def post(self, url, data=None, json=None, headers=None, timeout=None, allow_redirects=True):
        if url == AUTH:
            if (data or {}).get("client_secret") != "s3cret":
                return Resp(401, {"error": "invalid_client"})
            return Resp(200, {"access_token": "tok", "expires_in": 900})
        assert url == API
        q = json["query"]
        # Read-only: every document this category sends is a query.
        assert q.lstrip().startswith("query ")
        self.queries.append(q)
        v = json.get("variables") or {}
        for op, message in self.errors.items():
            if op in q:
                return Resp(200, {"data": None, "errors": [{"message": message}]})
        if "FindReports" in q:
            nodes = [{**r, "type": {"id": "ISSUES"}} for r in self.reports if v["search"] in r["name"]]
            return Resp(200, {"data": {"reports": {"nodes": nodes}}})
        if "ReportDownloadUrl" in q:
            if self.report_missing:
                return Resp(200, {"data": {"report": None}})
            return Resp(200, {"data": {"report": {"lastRun": self.last_run}}})
        if "VulnerabilityFindingsPage" in q:
            self.vuln_filters.append(v.get("filterBy"))
            start = int(v.get("after") or 0)
            page_no = start // v["first"] + 1
            # Keyed on the cursor, not the page size: the client halves the page
            # and retries the same cursor before it gives up.
            if self.vuln_error_page and start == (self.vuln_error_page - 1) * 100:
                return Resp(200, {"data": None, "errors": [{"message": "boom"}]})
            end = min(start + v["first"], self.vuln_count)
            more = end < self.vuln_count
            cursor = None if self.vuln_break_page == page_no else (str(end) if more else None)
            return Resp(200, {"data": {"vulnerabilityFindings": {
                "nodes": [vuln_node(i) for i in range(start, end)],
                "pageInfo": {"hasNextPage": more, "endCursor": cursor}}}})
        raise AssertionError(f"unexpected query: {q[:60]}")

    def get(self, url, **kwargs):
        self.downloads.append({"url": url, **kwargs})
        return self.download


@pytest.fixture
def fake(monkeypatch, tmp_path):
    f = FakeWiz()
    monkeypatch.setattr(wiz_client.requests, "post", f.post)
    monkeypatch.setattr(requests, "get", f.get)
    monkeypatch.setattr(wiz_client.time, "sleep", lambda s: None)
    for k in [k for k in os.environ if k.startswith("WIZ_")]:
        monkeypatch.delenv(k)
    for k, val in {"WIZ_CLIENT_ID": "id", "WIZ_CLIENT_SECRET": "s3cret", "WIZ_API_ENDPOINT_URL": API,
                   "WIZ_AUTH_URL": AUTH, "WIZ_MIN_REQUEST_INTERVAL": "0",
                   "EVIDENCE_DIR": str(tmp_path / "issue-reports"),
                   "FETCHER_STATUS_FILE": str(tmp_path / "status.json")}.items():
        monkeypatch.setenv(k, val)
    return f


def files(tmp_path) -> List[str]:
    out = tmp_path / "issue-reports"
    return sorted(p.name for p in out.iterdir()) if out.exists() else []


def status(tmp_path) -> Optional[dict]:
    p = tmp_path / "status.json"
    return json.loads(p.read_text()) if p.exists() else None


# --------------------------------------------------------------------------- wiz_issues_report

ISSUES_OUT = "wiz_issues_report.csv"


def test_issues_downloads_the_last_run_byte_for_byte(fake, tmp_path):
    assert issues.main() == 0
    assert files(tmp_path) == [ISSUES_OUT]               # no .part left behind
    assert (tmp_path / "issue-reports" / ISSUES_OUT).read_bytes() == ISSUES_CSV
    assert status(tmp_path) is None
    # The presigned URL never receives the Wiz bearer token.
    assert len(fake.downloads) == 1 and "headers" not in fake.downloads[0]


def test_issues_never_creates_updates_or_reruns_a_report(fake, tmp_path):
    assert issues.main() == 0
    ops = [q.split("(", 1)[0].split()[-1] for q in fake.queries]
    assert ops == ["FindReports", "ReportDownloadUrl"]


def test_issues_report_id_skips_the_name_lookup(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_REPORT_ID", "rep-1")
    assert issues.main() == 0
    assert not any("FindReports" in q for q in fake.queries)


def test_issues_missing_report_says_to_create_it(fake, tmp_path):
    fake.reports = []
    assert issues.main() == 1
    assert files(tmp_path) == [] and fake.downloads == []
    assert status(tmp_path)["code"] == "bad_config"
    assert "Create it once in Wiz" in status(tmp_path)["error"]


def test_issues_name_must_match_exactly_not_as_a_substring(fake, tmp_path):
    fake.reports = [{"id": "rep-9", "name": "Paramify-Wiz-Issues-retired-2026"}]
    assert issues.main() == 1
    assert status(tmp_path)["code"] == "bad_config" and fake.downloads == []


def test_issues_two_reports_with_the_name_is_ambiguous(fake, tmp_path):
    fake.reports = [{"id": "rep-1", "name": "Paramify-Wiz-Issues"}, {"id": "rep-2", "name": "Paramify-Wiz-Issues"}]
    assert issues.main() == 1
    assert status(tmp_path)["code"] == "bad_config"
    assert "set report_id" in status(tmp_path)["error"]


def test_issues_report_id_that_does_not_exist(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_REPORT_ID", "rep-gone")
    fake.report_missing = True
    assert issues.main() == 1
    assert status(tmp_path)["code"] == "bad_config" and fake.downloads == []


def test_issues_report_that_never_ran(fake, tmp_path):
    fake.last_run = None
    assert issues.main() == 1
    assert status(tmp_path)["code"] == "bad_config"
    assert "never run" in status(tmp_path)["error"]


@pytest.mark.parametrize("run_status", ["IN_PROGRESS", "FAILED", "EXPIRED"])
def test_issues_last_run_not_completed_is_not_downloaded(fake, tmp_path, run_status):
    fake.last_run = {"status": run_status, "url": None, "runAt": iso(1)}
    assert issues.main() == 1
    assert files(tmp_path) == [] and fake.downloads == []
    assert status(tmp_path)["code"] == "partial_failure"
    assert run_status in status(tmp_path)["error"]


def test_issues_stale_last_run_is_refused(fake, tmp_path):
    fake.last_run = {"status": "COMPLETED", "url": DOWNLOAD, "runAt": iso(30)}
    assert issues.main() == 1
    assert files(tmp_path) == [] and fake.downloads == []
    assert "hours old" in status(tmp_path)["error"]


def test_issues_max_report_age_is_configurable(fake, tmp_path, monkeypatch):
    fake.last_run = {"status": "COMPLETED", "url": DOWNLOAD, "runAt": iso(30)}
    monkeypatch.setenv("WIZ_MAX_REPORT_AGE_HOURS", "48")
    assert issues.main() == 0
    assert files(tmp_path) == [ISSUES_OUT]


@pytest.mark.parametrize("value", ["soon", "0", "-5"])
def test_issues_bad_max_report_age_is_bad_config(fake, tmp_path, monkeypatch, value):
    monkeypatch.setenv("WIZ_MAX_REPORT_AGE_HOURS", value)
    assert issues.main() == 1
    assert status(tmp_path)["code"] == "bad_config" and fake.queries == []


def test_issues_unreadable_run_time_is_refused(fake, tmp_path):
    fake.last_run = {"status": "COMPLETED", "url": DOWNLOAD, "runAt": "yesterday"}
    assert issues.main() == 1
    assert fake.downloads == []


def test_issues_download_http_error_leaves_no_file(fake, tmp_path):
    fake.download = Resp(403, content=b"denied")
    assert issues.main() == 1
    assert files(tmp_path) == []
    assert "HTTP 403" in status(tmp_path)["error"]


def test_issues_download_cut_off_midway_leaves_no_partial_file(fake, tmp_path):
    fake.download = Resp(200, content=ISSUES_CSV, fail_midway=True)
    assert issues.main() == 1
    assert files(tmp_path) == []                          # no .part, no truncated CSV
    assert status(tmp_path)["code"] == "target_unreachable"
    assert "X-Amz-Signature" not in status(tmp_path)["error"]


def test_issues_plaintext_download_url_is_refused(fake, tmp_path):
    fake.last_run = {"status": "COMPLETED", "url": "http://wiz-reports.example/r.csv", "runAt": iso(1)}
    assert issues.main() == 1
    assert fake.downloads == [] and files(tmp_path) == []


def test_issues_header_only_report_is_refused(fake, tmp_path):
    fake.download = Resp(200, content=b"Created At,Title,Severity,Status,Issue ID\n")
    assert issues.main() == 1
    assert files(tmp_path) == []
    assert "no rows" in status(tmp_path)["error"]


def test_issues_allow_empty_accepts_a_header_only_report(fake, tmp_path, monkeypatch):
    fake.download = Resp(200, content=b"Created At,Title,Severity,Status,Issue ID\n")
    monkeypatch.setenv("WIZ_ALLOW_EMPTY", "true")
    assert issues.main() == 0
    assert files(tmp_path) == [ISSUES_OUT]


def test_issues_missing_scope_is_not_authorized(fake, tmp_path):
    fake.errors["FindReports"] = "You are not authorized to perform this action"
    assert issues.main() == 1
    assert status(tmp_path)["code"] == "not_authorized" and fake.downloads == []


def test_issues_non_wiz_auth_url_sends_nothing(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_AUTH_URL", "https://attacker.example/oauth/token")
    monkeypatch.setattr(wiz_client.requests, "post", lambda *a, **k: pytest.fail("network call made"))
    assert issues.main() == 1
    assert status(tmp_path)["code"] == "bad_config"


def test_issues_wrong_secret_is_an_auth_failure(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_CLIENT_SECRET", "wrong")
    assert issues.main() == 1
    assert status(tmp_path)["code"] == "auth_failed"
    assert "wrong" not in status(tmp_path)["error"]


# --------------------------------------------------------------------------- wiz_vulnerability_findings

VULN_OUT = "wiz_vulnerability_findings.csv"


def vuln_rows(tmp_path) -> List[Dict[str, str]]:
    text = (tmp_path / "issue-reports" / VULN_OUT).read_text(encoding="utf-8")
    return list(csv.DictReader(io.StringIO(text)))


def test_vulns_every_page_lands_in_the_legacy_columns(fake, tmp_path):
    fake.vuln_count = 250                                   # 3 pages of 100
    assert vulns.main() == 0
    assert files(tmp_path) == [VULN_OUT]
    rows = vuln_rows(tmp_path)
    assert len(rows) == 250
    assert rows[0]["ID"] == "vf-00000" and rows[-1]["ID"] == "vf-00249"
    assert list(rows[0]) == vulns.CSV_COLUMNS
    assert rows[0]["Asset Tags"] == '{"env": "prod"}'
    assert rows[0]["Asset IP Addresses"] == "10.0.0.1"


def test_vulns_missing_cursor_fails_with_no_file(fake, tmp_path):
    fake.vuln_break_page = 2                                # hasNextPage with no endCursor
    assert vulns.main() == 1
    assert files(tmp_path) == []
    assert status(tmp_path)["code"] == "partial_failure"
    assert "no report written" in status(tmp_path)["error"]


def test_vulns_graphql_error_midway_fails_with_no_file(fake, tmp_path):
    fake.vuln_error_page = 2
    assert vulns.main() == 1
    assert files(tmp_path) == []
    assert "after 100 findings" in status(tmp_path)["error"]


def test_vulns_zero_findings_is_refused_by_default(fake, tmp_path):
    fake.vuln_count = 0
    assert vulns.main() == 1
    assert files(tmp_path) == [] and status(tmp_path)["code"] == "partial_failure"


def test_vulns_allow_empty_writes_a_header_only_file(fake, tmp_path, monkeypatch):
    fake.vuln_count = 0
    monkeypatch.setenv("WIZ_ALLOW_EMPTY", "true")
    assert vulns.main() == 0
    lines = (tmp_path / "issue-reports" / VULN_OUT).read_text().splitlines()
    assert len(lines) == 1 and lines[0].startswith("ID,Name,")


@pytest.mark.parametrize("project, sent", [("", {}), ("*", {}), (PROJECT, {"projectId": [PROJECT]})])
def test_vulns_project_filter_rides_every_page(fake, tmp_path, monkeypatch, project, sent):
    if project:
        monkeypatch.setenv("WIZ_PROJECT_ID", project)
    assert vulns.main() == 0
    assert len(fake.vuln_filters) == 3
    assert all(f == sent for f in fake.vuln_filters)


def test_vulns_unverified_filter_field_is_flagged_in_source():
    assert "UNVERIFIED against real Wiz schema" in (WIZ / "vulnerability_findings" / "fetcher.py").read_text()


def test_vulns_missing_endpoint_fails_before_any_request(fake, tmp_path, monkeypatch):
    monkeypatch.delenv("WIZ_API_ENDPOINT_URL")
    assert vulns.main() == 1
    assert status(tmp_path)["code"] == "bad_config" and fake.queries == []
