"""Cover for the wiz fetchers against an in-process fake Wiz GraphQL API.

No network and no credentials: ``requests.post`` is replaced with a small fake
that answers the token URL and the GraphQL endpoint with response shapes taken
from a live Wiz for Gov tenant (read-only probe, 2026-09-22).

What this proves: the collect path (token exchange, 15-minute token renewal,
Relay paging, GraphQL errors on HTTP 200, the read-only guard), the asset
bucketing and the summary maths, and the exit-code contract. What it cannot
prove: that every filter field is accepted by a real tenant. That still needs
one live run per fetcher.

Run: ``pytest tests/test_wiz_fetchers.py``
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
WIZ = REPO_ROOT / "fetchers" / "wiz"
sys.path.insert(0, str(WIZ / "_shared"))

import wiz_client  # noqa: E402
import vuln_summary  # noqa: E402

API = "https://api.us2.app.wiz.us/graphql"
AUTH = "https://auth.app.wiz.us/oauth/token"
NOW = datetime.now(timezone.utc)


def iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeResponse:
    def __init__(self, status: int, body: Any, headers: Dict[str, str] | None = None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.text = json.dumps(body)

    def json(self) -> Any:
        return self._body


class FakeWiz:
    """Answers auth + GraphQL. `pages[root]` is a list of node lists (one per page)."""

    def __init__(self) -> None:
        self.pages: Dict[str, List[List[Dict[str, Any]]]] = {}
        self.errors: Dict[str, str] = {}
        self.auth_status = 200
        self.token_calls = 0
        self.graphql_calls: List[Dict[str, Any]] = []
        self.fail_once_429 = False
        self.health_count = 0

    def __call__(self, url: str, data: Any = None, json: Any = None, headers: Any = None, timeout: Any = None):
        if url == AUTH:
            self.token_calls += 1
            if self.auth_status != 200:
                return FakeResponse(self.auth_status, {"error": "access_denied"})
            assert data["audience"] == "wiz-api" and data["grant_type"] == "client_credentials"
            return FakeResponse(200, {"access_token": f"tok{self.token_calls}", "expires_in": 900})
        assert url == API
        assert headers["Authorization"].startswith("Bearer tok")
        self.graphql_calls.append(json)
        if self.fail_once_429:
            self.fail_once_429 = False
            return FakeResponse(429, {}, {"Retry-After": "0"})
        query = json["query"]
        if "systemHealthIssues(" in query:
            return FakeResponse(200, {"data": {"systemHealthIssues": {"totalCount": self.health_count}}})
        root = next(r for r in ("cloudAccounts", "connectors", "issuesV2", "vulnerabilityFindings", "securityFrameworks",
                                "configurationFindings", "hostConfigurationRuleAssessments") if r + "(" in query)
        if root in self.errors:
            return FakeResponse(200, {"data": None, "errors": [{"message": self.errors[root]}]})
        pages = self.pages.get(root, [[]])
        after = json["variables"].get("after")
        idx = int(after) if after else 0
        has_next = idx + 1 < len(pages)
        return FakeResponse(200, {"data": {root: {
            "nodes": pages[idx],
            "pageInfo": {"hasNextPage": has_next, "endCursor": str(idx + 1) if has_next else None},
        }}})


@pytest.fixture
def fake(monkeypatch, tmp_path) -> FakeWiz:
    f = FakeWiz()
    monkeypatch.setattr(wiz_client.requests, "post", f)
    monkeypatch.setattr(wiz_client.time, "sleep", lambda s: None)
    # run_fetcher calls load_dotenv(), which walks up to a real repo-root .env
    # and would refill any variable a test deliberately removed.
    monkeypatch.setattr(wiz_client, "load_dotenv", lambda *a, **k: False)
    monkeypatch.setenv("WIZ_CLIENT_ID", "id")
    monkeypatch.setenv("WIZ_CLIENT_SECRET", "secret")
    monkeypatch.setenv("WIZ_API_ENDPOINT_URL", "https://api.us2.app.wiz.us")  # no /graphql on purpose
    monkeypatch.setenv("WIZ_AUTH_URL", AUTH)
    monkeypatch.setenv("WIZ_MIN_REQUEST_INTERVAL", "0")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    return f


def load(name: str) -> Any:
    path = WIZ / name / "fetcher.py"
    spec = importlib.util.spec_from_file_location(f"wiz_{name}_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(name: str, tmp_path: Path) -> tuple[int, Dict[str, Any]]:
    module = load(name)
    code = wiz_client.run_fetcher(module.collect, f"wiz_{name}.json", module.logger)
    return code, json.loads((tmp_path / f"wiz_{name}.json").read_text())


# --- client ---------------------------------------------------------------


def test_endpoint_normalized_and_gov_detected(fake, tmp_path):
    fake.pages["cloudAccounts"] = [[{"id": "a", "name": "prod", "cloudProvider": "AWS", "status": "CONNECTED",
                                     "lastScannedAt": iso(0), "resourceCount": 10}]]
    code, ev = run("scan_coverage", tmp_path)
    assert code == 0
    assert ev["tenant"]["api_endpoint_url"] == API
    assert ev["tenant"]["environment"] == "gov" and ev["tenant"]["data_center"] == "us2"
    assert ev["tenant"]["token_lifetime_seconds"] == 900


def test_mutation_is_refused():
    with pytest.raises(ValueError):
        wiz_client.WizClient._assert_read_only("mutation { deleteIssue(id: 1) { id } }")
    wiz_client.WizClient._assert_read_only("query { issuesV2 { nodes { id } } }")


def test_token_renewed_before_expiry(fake, monkeypatch):
    client = wiz_client.build_client()
    assert fake.token_calls == 1
    client._token_expires_at = 0  # simulate the 15 minutes passing mid-walk
    client.graphql("cloudAccounts", "query { cloudAccounts(first:1){ nodes{ id } pageInfo{ hasNextPage endCursor } } }")
    assert fake.token_calls == 2


def test_graphql_error_on_200_is_a_failure(fake, tmp_path):
    fake.errors["cloudAccounts"] = "You are not authorized to perform this action"
    code, ev = run("scan_coverage", tmp_path)
    assert code == 1
    assert ev["metadata"]["partial_failure"] is True
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["code"] == "not_authorized"


def test_rate_limit_is_retried(fake, tmp_path):
    fake.fail_once_429 = True
    fake.pages["cloudAccounts"] = [[{"id": "a", "name": "prod", "status": "CONNECTED", "lastScannedAt": iso(1)}]]
    code, ev = run("scan_coverage", tmp_path)
    assert code == 0 and ev["record_count"] == 1


def test_bad_auth_is_clean_error(fake, tmp_path):
    fake.auth_status = 401
    code, ev = run("scan_coverage", tmp_path)
    assert code == 1 and ev["status"] == "error" and ev["error_code"] == "auth_failed"
    assert "secret" not in json.dumps(ev)


def test_missing_config_is_bad_config(fake, tmp_path, monkeypatch):
    monkeypatch.delenv("WIZ_API_ENDPOINT_URL")
    code, ev = run("scan_coverage", tmp_path)
    assert code == 1 and ev["error_code"] == "bad_config"


def test_all_pages_collected_and_stalled_cursor_flagged(fake):
    client = wiz_client.build_client()
    fake.pages["cloudAccounts"] = [[{"id": "1"}], [{"id": "2"}], [{"id": "3"}]]
    q = load("scan_coverage").ACCOUNTS_QUERY
    assert [n["id"] for n in client.paginate("cloudAccounts", q, "cloudAccounts")] == ["1", "2", "3"]
    assert client.api_failures == []

    def stalled(url, data=None, json=None, headers=None, timeout=None):
        if url == AUTH:
            return FakeResponse(200, {"access_token": "tokX", "expires_in": 900})
        return FakeResponse(200, {"data": {"cloudAccounts": {"nodes": [{"id": "x"}],
                                   "pageInfo": {"hasNextPage": True, "endCursor": "same"}}}})
    wiz_client.requests.post = stalled
    client.paginate("cloudAccounts", q, "cloudAccounts")
    assert client.api_failures[-1]["type"] == "PaginationCursorStalled"


def test_record_cap_is_a_failure_not_silent(fake, monkeypatch, tmp_path):
    monkeypatch.setenv("WIZ_MAX_RECORDS", "2")
    fake.pages["vulnerabilityFindings"] = [[{"id": "1"}, {"id": "2"}], [{"id": "3"}]]
    code, ev = run("infrastructure_vulnerabilities", tmp_path)
    assert code == 1 and ev["api_failures"][0]["type"] == "RecordCapReached"


# --- scan coverage ----------------------------------------------------------


def test_scan_coverage_flags_stale_and_disconnected(fake, tmp_path):
    fake.pages["cloudAccounts"] = [[
        {"id": "a", "name": "prod", "cloudProvider": "AWS", "status": "CONNECTED", "lastScannedAt": iso(0),
         "resourceCount": 1774, "virtualMachineCount": 5, "containerCount": 2},
        {"id": "b", "name": "old", "cloudProvider": "Azure", "status": "CONNECTED", "lastScannedAt": iso(20)},
        {"id": "c", "name": "broken", "cloudProvider": "Azure", "status": "ERROR", "lastScannedAt": None},
    ]]
    fake.pages["connectors"] = [[{"id": "k1", "name": "aws", "enabled": True, "status": "CONNECTED"},
                                 {"id": "k2", "name": "az", "enabled": False, "status": "DISABLED"}]]
    code, ev = run("scan_coverage", tmp_path)
    a = ev["analysis"]
    assert code == 0
    assert a["cloud_account_count"] == 3 and a["not_connected_count"] == 1
    assert a["stale_scan_count"] == 1 and a["stale_scan_accounts"][0]["name"] == "old"
    assert a["never_scanned_count"] == 1 and a["total_resources"] == 1774
    assert a["connectors_disabled"] == ["az"]


def test_scan_coverage_empty_is_not_success(fake, tmp_path):
    code, ev = run("scan_coverage", tmp_path)
    assert code == 0 and ev["status"] == "partial_or_empty" and "no cloud accounts" in ev["message"]


# --- vulnerabilities --------------------------------------------------------


def _vuln(i, sev, age, asset_type, kev=False, fix="1.2"):
    return {"id": f"v{i}", "name": f"CVE-2026-{i}", "severity": sev, "status": "OPEN",
            "firstDetectedAt": iso(age), "lastDetectedAt": iso(0), "detectionMethod": "PACKAGE",
            "fixedVersion": fix, "hasCisaKevExploit": kev,
            "vulnerableAsset": {"id": f"asset-{asset_type}-{i % 2}", "type": asset_type, "name": "x"}}


def test_vulns_bucketed_and_summarized(fake, tmp_path):
    fake.pages["vulnerabilityFindings"] = [[
        _vuln(1, "CRITICAL", 45, "VIRTUAL_MACHINE", kev=True),
        _vuln(2, "HIGH", 10, "VIRTUAL_MACHINE", fix=None),
        _vuln(3, "CRITICAL", 5, "CONTAINER_IMAGE"),
    ], [
        _vuln(4, "LOW", 200, "SERVERLESS"),
        _vuln(5, "MEDIUM", 1, "REPOSITORY_BRANCH"),
    ]]
    code, ev = run("infrastructure_vulnerabilities", tmp_path)
    a = ev["analysis"]
    assert code == 0
    assert ev["scope"]["findings_by_bucket"] == {"infrastructure": 3, "container": 1, "code": 1}
    assert a["open_findings"] == 3 and a["open_by_severity"] == {"CRITICAL": 1, "HIGH": 1, "LOW": 1}
    assert a["cisa_kev_open"] == 1 and a["fix_available_count"] == 2
    assert a["past_remediation_window_by_severity"] == {"CRITICAL": 1, "LOW": 1}
    assert a["highest_risk_sample"][0]["cve"] == "CVE-2026-1"
    # status filter actually sent
    assert fake.graphql_calls[0]["variables"]["filterBy"] == {"status": ["OPEN"]}

    code, ev = run("container_vulnerabilities", tmp_path)
    assert code == 0 and ev["analysis"]["open_findings"] == 1 and ev["analysis"]["by_asset_type"] == {"CONTAINER_IMAGE": 1}


def test_raw_findings_can_be_omitted(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_INCLUDE_RAW_FINDINGS", "false")
    fake.pages["vulnerabilityFindings"] = [[_vuln(1, "HIGH", 1, "VIRTUAL_MACHINE")]]
    code, ev = run("infrastructure_vulnerabilities", tmp_path)
    assert code == 0 and ev["data"] == [] and ev["record_count"] == 1 and ev["records_included"] is False


def test_bucket_rules():
    assert vuln_summary.asset_bucket("CONTAINER_IMAGE") == "container"
    assert vuln_summary.asset_bucket("VIRTUAL_MACHINE") == "infrastructure"
    assert vuln_summary.asset_bucket("REPOSITORY_BRANCH") == "code"
    assert vuln_summary.asset_bucket(None) == "unknown"


# --- posture issues ---------------------------------------------------------


def _issue(i, sev, age, status="OPEN", ticket=False, resolved_after=None, due_days=None):
    return {"id": f"i{i}", "type": "CLOUD_CONFIGURATION", "status": status, "severity": sev,
            "createdAt": iso(age), "statusChangedAt": iso(0),
            "resolvedAt": iso(age - resolved_after) if resolved_after is not None else None,
            "dueAt": iso(-due_days) if due_days is not None else None,
            "serviceTickets": [{"externalId": "INC1", "name": "t", "url": "https://sn/INC1"}] if ticket else [],
            "sourceRules": [{"__typename": "CloudConfigurationRule", "id": "r", "name": "S3 bucket public"}],
            "entitySnapshot": {"type": "BUCKET", "nativeType": "s3", "cloudPlatform": "AWS", "subscriptionName": "prod"}}


def test_posture_issues_summary(fake, tmp_path):
    calls = {"n": 0}
    open_page = [_issue(1, "CRITICAL", 40, ticket=True), _issue(2, "HIGH", 3, due_days=-2), _issue(3, "LOW", 1)]
    resolved_page = [_issue(9, "HIGH", 20, status="RESOLVED", resolved_after=6)]
    real = fake.__call__

    def routed(url, data=None, json=None, headers=None, timeout=None):
        if url == API and "issuesV2" in json["query"]:
            calls["n"] += 1
            statuses = json["variables"]["filterBy"]["status"]
            nodes = resolved_page if statuses == ["RESOLVED"] else open_page
            return FakeResponse(200, {"data": {"issuesV2": {"nodes": nodes,
                                       "pageInfo": {"hasNextPage": False, "endCursor": None}}}})
        return real(url, data=data, json=json, headers=headers, timeout=timeout)

    wiz_client.requests.post = routed
    code, ev = run("posture_issues", tmp_path)
    a = ev["analysis"]
    assert code == 0 and calls["n"] == 2
    assert a["open_issue_count"] == 3
    assert a["critical_high_open"] == 2 and a["critical_high_ticketed"] == 1 and a["critical_high_ticketed_pct"] == 50.0
    assert a["past_remediation_window_by_severity"] == {"CRITICAL": 1}
    assert a["overdue_by_due_date_count"] == 1
    assert a["resolved_in_window"] == 1 and a["median_days_to_resolve"] == 6
    assert ev["filter"]["types"] == ["CLOUD_CONFIGURATION", "TOXIC_COMBINATION"]


def test_scan_coverage_reports_system_health(fake, tmp_path):
    fake.health_count = 19
    fake.pages["cloudAccounts"] = [[{"id": "a", "name": "prod", "status": "CONNECTED", "lastScannedAt": iso(0)}]]
    code, ev = run("scan_coverage", tmp_path)
    assert code == 0 and ev["analysis"]["system_health_issue_count"] == 19


# --- cloud configuration posture -------------------------------------------


def _cfg(i, result, sev, status, age, account="prod"):
    return {"id": f"c{i}", "name": f"rule {i % 3}", "result": result, "severity": sev, "status": status,
            "firstSeenAt": iso(age), "analyzedAt": iso(0),
            "rule": {"id": f"r{i % 3}", "shortId": f"R-{i % 3}", "name": f"rule {i % 3}"},
            "resource": {"id": f"res{i}", "name": f"res{i}", "type": "BUCKET", "nativeType": "s3",
                         "region": "us-gov-west-1", "cloudPlatform": "AWS",
                         "subscription": {"name": account, "externalId": "123"}}}


def test_cloud_config_posture(fake, tmp_path):
    fake.pages["securityFrameworks"] = [[{"id": "wf-id-39", "name": "FedRAMP (High, Moderate, and Low levels)", "enabled": False},
                                          {"id": "wf-id-4", "name": "NIST SP 800-53 Revision 5", "enabled": False}]]
    fake.pages["configurationFindings"] = [[
        _cfg(1, "PASS", "HIGH", "RESOLVED", 1), _cfg(2, "PASS", "LOW", "RESOLVED", 1),
        _cfg(3, "FAIL", "HIGH", "OPEN", 45), _cfg(4, "FAIL", "MEDIUM", "OPEN", 5, account="dev"),
    ]]
    code, ev = run("cloud_configuration_posture", tmp_path)
    a = ev["analysis"]
    assert code == 0
    assert ev["framework"] == {"requested": "NIST SP 800-53 Revision 5", "id": "wf-id-4",
                               "name": "NIST SP 800-53 Revision 5", "enabled_in_tenant": False}
    cfg_call = [c for c in fake.graphql_calls if "configurationFindings(" in c["query"]][0]
    assert cfg_call["variables"]["filterBy"] == {"securityFramework": "wf-id-4", "result": ["PASS", "FAIL"]}
    assert a["pass_rate_pct"] == 50.0 and a["open_failures"] == 2
    assert a["open_failures_past_window_by_severity"] == {"HIGH": 1}
    assert a["by_account"]["dev"] == {"FAIL": 1}


def test_cloud_config_unknown_framework_fails_loudly(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_SECURITY_FRAMEWORK", "No Such Framework")
    fake.pages["securityFrameworks"] = [[{"id": "wf-id-4", "name": "NIST SP 800-53 Revision 5", "enabled": True}]]
    code, ev = run("cloud_configuration_posture", tmp_path)
    assert code == 1 and ev["api_failures"][0]["type"] == "FrameworkNotFound"


def test_cloud_config_10k_cap_flagged(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_PAGE_SIZE", "500")
    fake.pages["securityFrameworks"] = [[{"id": "wf-id-4", "name": "NIST SP 800-53 Revision 5", "enabled": True}]]
    fake.pages["configurationFindings"] = [[_cfg(i, "PASS", "LOW", "RESOLVED", 1) for i in range(500)]] * 20
    code, ev = run("cloud_configuration_posture", tmp_path)
    assert code == 1 and ev["api_failures"][-1]["type"] == "WizRowCapReached"


# --- host configuration posture --------------------------------------------


def _host(i, result, sev, bench, host="vm-1", age=2):
    return {"id": f"h{i}", "result": result, "severity": sev, "status": "OPEN" if result == "FAIL" else "RESOLVED",
            "firstSeen": iso(age), "analyzedAt": iso(0),
            "rule": {"id": f"hr{i}", "name": f"host rule {i}", "shortName": "x", "externalId": f"V-{i}",
                     "securitySubCategories": [{"category": {"framework": {"name": bench}}}]},
            "resource": {"id": host, "name": host, "type": "VIRTUAL_MACHINE"}}


def test_host_config_filters_to_disa(fake, tmp_path):
    rhel = "DISA Red Hat Enterprise Linux 9 STIG Benchmark v002.009"
    fake.pages["hostConfigurationRuleAssessments"] = [[
        _host(1, "PASS", "HIGH", rhel), _host(2, "FAIL", "HIGH", rhel, age=40), _host(3, "FAIL", "LOW", rhel, host="vm-2"),
        _host(4, "FAIL", "HIGH", "CIS Red Hat Enterprise Linux 9 Benchmark"),
    ]]
    code, ev = run("host_configuration_posture", tmp_path)
    a = ev["analysis"]
    assert code == 0
    assert ev["scope"]["assessments_in_tenant_query"] == 4
    assert ev["scope"]["assessments_by_benchmark"] == {rhel: 3, "CIS Red Hat Enterprise Linux 9 Benchmark": 1}
    assert a["assessments_evaluated"] == 3 and a["hosts_assessed"] == 2
    assert a["benchmarks"][rhel]["pass_rate_pct"] == 33.3
    assert a["open_failures_past_window_by_severity"] == {"HIGH": 1}
