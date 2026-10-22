"""Offline tests for jira_remediation_items, jira_audit_records and jira_access_roles.

A fake requests.Session answers each call from a routing table shaped like the
Jira Cloud REST v3 responses (field names taken from the published OpenAPI spec),
so these check parsing, paging, rollups and failure reporting, not the live API.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
JIRA = REPO_ROOT / "fetchers" / "jira"


class FakeResponse:
    def __init__(self, status: int, body):
        self.status_code = status
        self._body = body
        self.headers = {"Content-Type": "application/json"}
        self.reason = "x"
        self.text = json.dumps(body)

    def json(self):
        return self._body


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"jira_{name}", JIRA / name / "fetcher.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def run(monkeypatch, tmp_path):
    def _run(name: str, router, env: dict | None = None):
        calls = []
        monkeypatch.setattr("time.sleep", lambda s: None)  # retries must not wait offline

        def fake_request(self, method, url, params=None, json=None, timeout=None, **kw):
            assert kw.get("allow_redirects") is False, "redirects must never be followed"
            path = url.split(".atlassian.net", 1)[1]
            calls.append((method, path, params, json))
            status, body = router(method, path, params or {}, json or {})
            return FakeResponse(status, body)

        monkeypatch.setattr(requests.Session, "request", fake_request)
        for k, v in {
            "JIRA_BASE_URL": "https://example.atlassian.net",
            "JIRA_EMAIL": "svc@example.com",
            "JIRA_API_TOKEN": "t",
            "EVIDENCE_DIR": str(tmp_path),
            "FETCHER_STATUS_FILE": str(tmp_path / "status.json"),
            **(env or {}),
        }.items():
            monkeypatch.setenv(k, v)
        mod = load(name)
        code = mod.main()
        out = json.loads((tmp_path / mod.OUTPUT_FILE).read_text())
        status = tmp_path / "status.json"
        return code, out, calls, (json.loads(status.read_text()) if status.exists() else None)

    return _run


ME = {"accountId": "svc", "displayName": "Paramify Collector", "accountType": "atlassian", "active": True}


# ---------- remediation_items ----------

def _issue(i, status, cat, due=None, resolved=None, assignee="Ann"):
    return {
        "id": str(100 + i),
        "key": f"OPS-{i}",
        "fields": {
            "summary": f"finding {i}",
            "project": {"key": "OPS"},
            "issuetype": {"name": "Task"},
            "status": {"name": status, "statusCategory": {"key": cat}},
            "priority": {"name": "High"},
            "assignee": {"displayName": assignee} if assignee else None,
            "created": "2026-01-01T00:00:00.000+0000",
            "updated": "2026-02-01T00:00:00.000+0000",
            "resolutiondate": resolved,
            "duedate": due,
            "labels": ["cp-test-finding"],
            "components": [],
            "issuelinks": [{"type": {"outward": "relates to"}, "outwardIssue": {"key": "OPS-99"}}],
        },
    }


def test_remediation_items_paging_history_and_rollups(run):
    page1 = [_issue(1, "Done", "done", due="2026-01-20", resolved="2026-01-11T00:00:00.000+0000")]
    page2 = [_issue(2, "To Do", "new", due="2026-01-15", assignee=None), _issue(3, "In Progress", "indeterminate")]

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/search/jql":
            assert body["jql"] == "labels = cp-test-finding"
            assert "duedate" in body["fields"]
            if not body.get("nextPageToken"):
                return 200, {"issues": page1, "nextPageToken": "p2"}
            return 200, {"issues": page2, "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            assert body["fieldIds"] == ["status"]
            # bulkfetch returns epoch milliseconds here (measured against a live site)
            hist = {"id": "h1", "created": 1767571200000, "author": {"displayName": "Ann"},
                    "items": [{"field": "status", "fieldId": "status", "fromString": "To Do", "toString": "Done"}]}
            if not body.get("nextPageToken"):
                return 200, {"issueChangeLogs": [{"issueId": "101", "changeHistories": [hist]}], "nextPageToken": "c2"}
            # duplicate on the next page must be dropped
            return 200, {"issueChangeLogs": [{"issueId": "101", "changeHistories": [hist]}]}
        raise AssertionError(path)

    code, out, calls, status = run("remediation_items", router, {"JIRA_REMEDIATION_JQL": "labels = cp-test-finding"})
    assert code == 0 and status is None
    s = out["summary"]
    assert (s["total"], s["open"], s["closed"]) == (3, 2, 1)
    assert s["open_overdue"] == 1 and s["open_unassigned"] == 1 and s["open_without_due_date"] == 1
    assert s["days_to_close"]["median"] == 10.0
    first = out["items"][0]
    assert first["status_change_count"] == 1 and first["status_transitions"][0]["to"] == "Done"
    assert first["status_transitions"][0]["at"] == "2026-01-05T00:00:00.000+00:00"
    assert first["linked_issues"] == [{"relation": "relates to", "key": "OPS-99"}]
    assert out["metadata"]["status_history_complete"] is True


def test_remediation_items_requires_jql(monkeypatch, tmp_path):
    monkeypatch.delenv("JIRA_REMEDIATION_JQL", raising=False)
    for k, v in {"JIRA_BASE_URL": "https://x.atlassian.net", "JIRA_EMAIL": "e", "JIRA_API_TOKEN": "t",
                 "EVIDENCE_DIR": str(tmp_path), "FETCHER_STATUS_FILE": str(tmp_path / "s.json")}.items():
        monkeypatch.setenv(k, v)
    assert load("remediation_items").main() == 1
    assert json.loads((tmp_path / "s.json").read_text())["code"] == "bad_config"


# ---------- audit_records ----------

def test_audit_records_pages_until_total(run):
    def rec(i, cat):
        return {"id": i, "created": f"2026-10-0{i}T00:00:00.000+0000", "category": cat, "summary": "s",
                "authorAccountId": f"u{i % 2}", "objectItem": {"typeName": "USER", "name": "x"},
                "changedValues": [{"fieldName": "email", "changedFrom": "a", "changedTo": "<script>" + "b" * 300}]}

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        assert path == "/rest/api/3/auditing/record"
        assert params["limit"] == 1000 and params["from"] < params["to"]
        if params["offset"] == 0:
            return 200, {"offset": 0, "limit": 1000, "total": 3, "records": [rec(1, "permissions"), rec(2, "user management")]}
        return 200, {"offset": 2, "limit": 1000, "total": 3, "records": [rec(3, "dashboards")]}

    code, out, calls, _ = run("audit_records", router)
    assert code == 0
    assert out["summary"]["total"] == 3
    assert out["summary"]["sensitive_changes"]["total"] == 2
    assert out["summary"]["unclassified_categories"] == {"dashboards": 1}
    assert out["summary"]["oldest_record"].startswith("2026-10-01")
    cv = out["records"][0]["changed_values"][0]
    assert cv["field"] == "email" and cv["from"] == "a"
    assert cv["to"].startswith("&lt;script&gt;") and cv["to"].endswith("...") and len(cv["to"]) <= 203
    assert "<script>" not in json.dumps(out)
    # a non-sensitive record keeps the field name only
    assert out["records"][2]["changed_values"] == [{"field": "email"}]
    assert len([c for c in calls if c[1] == "/rest/api/3/auditing/record"]) == 2


def test_audit_records_403_is_reported(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        return 403, {"errorMessages": ["You do not have permission"]}

    code, out, _, status = run("audit_records", router)
    assert code == 1
    assert status["code"] == "not_authorized"
    assert out["metadata"]["partial_failure"] is True


# ---------- access_roles ----------

def test_access_roles_resolves_privileged_users(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/group/bulk":
            if params.get("accessType") == "site-admin":
                return 200, {"isLast": True, "values": [{"groupId": "g-site", "name": "site-admins"}]}
            if params.get("accessType") == "admin":
                return 200, {"isLast": True, "values": [{"groupId": "g-adm", "name": "jira-admins"}]}
        if path == "/rest/api/3/group/member":
            members = {
                "g-site": [{"accountId": "a1", "displayName": "Alice", "accountType": "atlassian", "active": True}],
                "g-adm": [{"accountId": "a2", "displayName": "Bob", "accountType": "atlassian", "active": False}],
                "g-ccb": [{"accountId": "a3", "displayName": "Cara", "accountType": "atlassian", "active": True}],
            }[params["groupId"]]
            return 200, {"isLast": True, "values": members}
        if path == "/rest/api/3/applicationrole":
            return 200, [{"key": "jira-software", "name": "Jira", "groups": ["jira-users"], "defaultGroups": ["jira-users"], "userCount": 5}]
        if path == "/rest/api/3/project/search":
            return 200, {"isLast": True, "values": [{"key": "CCB", "name": "Change Board", "projectTypeKey": "service_desk",
                                                      "lead": {"accountId": "a9", "displayName": "Lead"}}]}
        if path == "/rest/api/3/project/CCB/permissionscheme":
            assert params["expand"] == "all"
            return 200, {"id": 10000, "name": "Default", "permissions": [
                {"permission": "ADMINISTER_PROJECTS", "holder": {"type": "projectRole", "parameter": "10002", "projectRole": {"name": "Administrators"}}},
                {"permission": "DELETE_ISSUES", "holder": {"type": "applicationRole", "parameter": ""}},
                {"permission": "BROWSE_PROJECTS", "holder": {"type": "group", "parameter": "jira-users", "value": "g-users"}},
                {"permission": "SET_ISSUE_SECURITY", "holder": {"type": "projectLead"}},
            ]}
        if path == "/rest/api/3/project/CCB/role":
            return 200, {"Administrators": "https://example.atlassian.net/rest/api/3/project/CCB/role/10002"}
        if path == "/rest/api/3/project/CCB/role/10002":
            return 200, {"name": "Administrators", "actors": [
                {"type": "atlassian-user-role-actor", "displayName": "Dan", "actorUser": {"accountId": "a4"}},
                {"type": "atlassian-group-role-actor", "displayName": "ccb-admins", "actorGroup": {"name": "ccb-admins", "groupId": "g-ccb"}},
            ]}
        raise AssertionError(path)

    code, out, calls, _ = run("access_roles", router)
    assert code == 0
    s = out["summary"]
    assert s["admin_groups"] == 2 and s["distinct_admin_users"] == 2 and s["inactive_admin_users"] == 1
    assert s["projects_with_broad_privileged_grants"] == ["CCB"]
    proj = out["projects"][0]
    assert {g["permission"] for g in proj["privileged_grants"]} == {"ADMINISTER_PROJECTS", "DELETE_ISSUES", "SET_ISSUE_SECURITY"}
    ids = {u["account_id"] for u in proj["privileged_users"]}
    assert ids == {"a3", "a4", "a9"}
    assert s["distinct_project_admin_users"] == 2
    assert "ccb-admins" in out["group_memberships"]


def test_access_roles_falls_back_to_application_key(run):
    seen = []

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/group/bulk":
            seen.append(dict(params))
            if "applicationKey" not in params:
                return 400, {"errorMessages": ["applicationKey is required"]}
            if params["applicationKey"] == "jira-software" and params["accessType"] == "admin":
                return 200, {"isLast": True, "values": [{"groupId": "g1", "name": "jira-admins"}]}
            return 200, {"isLast": True, "values": []}
        if path == "/rest/api/3/group/member":
            return 200, {"isLast": True, "values": []}
        if path == "/rest/api/3/applicationrole":
            return 200, []
        if path == "/rest/api/3/project/search":
            return 200, {"isLast": True, "values": []}
        raise AssertionError(path)

    code, out, _, _ = run("access_roles", router)
    assert code == 0
    assert [g["name"] for g in out["admin_groups"]] == ["jira-admins"]
    assert any(p.get("applicationKey") == "jira-core" for p in seen)


def test_access_roles_non_admin_401_on_roles_does_not_abort(run):
    """A non-admin gets 401 (not 403) from /project/{key}/role; that is a permission gap, not a bad token."""
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/group/bulk":
            return 200, {"isLast": True, "values": [{"groupId": "g1", "name": "jira-admins"}]}
        if path == "/rest/api/3/group/member":
            return 200, {"isLast": True, "values": [{"accountId": "a1", "displayName": "A", "accountType": "app", "active": True}]}
        if path == "/rest/api/3/applicationrole":
            return 403, {"errorMessages": ["admin only"]}
        if path == "/rest/api/3/project/search":
            return 200, {"isLast": True, "values": [{"key": "SEC", "name": "Security"}, {"key": "HR", "name": "HR"}]}
        if path.endswith("/permissionscheme"):
            return 403, {"errorMessages": ["admin only"]}
        if path.endswith("/role"):
            return 401, {"errorMessages": ["Client must be authenticated"]}
        raise AssertionError(path)

    code, out, calls, status = run("access_roles", router)
    assert code == 1 and status["code"] == "not_authorized"
    assert [p["key"] for p in out["projects"]] == ["SEC", "HR"]
    assert out["summary"]["distinct_admin_users"] == 1
    assert out["summary"]["admin_users_by_account_type"] == {"app": 1}


# ---------- security hardening ----------

@pytest.mark.parametrize("url", [
    "https://example.atlassian.net@evil.example",
    "https://evil.example#.atlassian.net",
    "https://evil.example?x=.atlassian.net",
    "https://svc:pw@example.atlassian.net",
    "http://example.atlassian.net",
    "https://example.atlassian.net.evil.example",
    "https://evilatlassian.net",
    "https://atlassian.net",
    "https://example.atlassian.net:8443",
    "https://example.atlassian.net/extra/path",
    "https://api.atlassian.com/ex/jira/../../admin",
    "https://api.atlassian.com/",
    "https://evil.com\\.atlassian.net",
    "https://a..atlassian.net",
    "https://x%2fy.atlassian.net",
    "https://site\u3002atlassian.net",
    "https://site.atlassian.net.",
])
def test_base_url_rejects_hosts_that_could_receive_the_token(url):
    sys.path.insert(0, str(JIRA / "_shared"))
    from jira_common import validate_base_url
    normalized, error = validate_base_url(url)
    assert normalized is None and error
    assert "pw" not in error and "svc" not in error


@pytest.mark.parametrize("url,expected", [
    ("https://example.atlassian.net", "https://example.atlassian.net"),
    ("https://Example.atlassian.net/", "https://example.atlassian.net"),
    ("https://api.atlassian.com/ex/jira/eadac007-8666-4024-a026-0bfb4d34aa2e",
     "https://api.atlassian.com/ex/jira/eadac007-8666-4024-a026-0bfb4d34aa2e"),
    ("https://example.atlassian-us-gov-mod.net", "https://example.atlassian-us-gov-mod.net"),
    ("https://example.jira.com", "https://example.jira.com"),
])
def test_base_url_accepts_site_and_gateway(url, expected):
    sys.path.insert(0, str(JIRA / "_shared"))
    from jira_common import validate_base_url
    assert validate_base_url(url) == (expected, None)


@pytest.mark.parametrize("name", ["remediation_items", "audit_records", "access_roles", "site_inventory"])
def test_bad_base_url_fails_before_any_call(monkeypatch, tmp_path, name):
    def no_network(*a, **k):
        raise AssertionError("no request may be made with a refused base URL")
    monkeypatch.setattr(requests.Session, "request", no_network)
    for k, v in {"JIRA_BASE_URL": "https://example.atlassian.net@evil.example", "JIRA_EMAIL": "e",
                 "JIRA_API_TOKEN": "t", "JIRA_REMEDIATION_JQL": "labels = x",
                 "EVIDENCE_DIR": str(tmp_path), "FETCHER_STATUS_FILE": str(tmp_path / "s.json")}.items():
        monkeypatch.setenv(k, v)
    assert load(name).main() == 1
    status = json.loads((tmp_path / "s.json").read_text())
    assert status["code"] == "bad_config" and "evil.example" not in status["error"]


def test_redirect_is_not_followed_and_fails(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 302, {}
        return 200, {"offset": 0, "total": 0, "records": []}

    code, out, _, status = run("audit_records", router)
    assert code == 1 and status["code"] == "bad_config"
    assert out["metadata"]["api_failures"][0]["type"] == "HTTP302"
    assert out["metadata"]["complete"] is False


def test_audit_records_truncation_is_reported(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        start = params["offset"]
        batch = [{"id": i, "created": "2026-10-01T00:00:00.000+0000", "category": "permissions"}
                 for i in range(start, min(start + 1000, 2000))]
        return 200, {"offset": start, "limit": 1000, "total": 2000, "records": batch}

    code, out, _, status = run("audit_records", router, {"JIRA_AUDIT_MAX_RECORDS": "1500"})
    assert out["metadata"]["records_collected"] == 1500
    assert out["metadata"]["records_truncated"] is True
    assert out["metadata"]["complete"] is False
    assert code == 1 and status["code"] == "partial_failure"
    assert "JIRA_AUDIT_MAX_RECORDS=1500" in status["error"]


def test_audit_records_exactly_at_cap_is_complete(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        start = params["offset"]
        batch = [{"id": i, "created": "2026-10-01T00:00:00.000+0000"} for i in range(start, min(start + 1000, 1000))]
        return 200, {"offset": start, "total": 1000, "records": batch}

    code, out, _, status = run("audit_records", router, {"JIRA_AUDIT_MAX_RECORDS": "1000"})
    assert code == 0 and status is None
    assert out["metadata"]["records_truncated"] is False and out["metadata"]["complete"] is True


def test_remediation_items_cap_is_reported(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [_issue(i, "To Do", "new") for i in range(body["maxResults"])],
                         "nextPageToken": "more"}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    code, out, _, status = run("remediation_items", router,
                               {"JIRA_REMEDIATION_JQL": "labels = x", "JIRA_REMEDIATION_MAX_ITEMS": "3"})
    assert out["metadata"]["items_truncated"] is True and out["metadata"]["complete"] is False
    assert code == 1 and status["code"] == "partial_failure"


def test_remediation_items_cap_holds_when_server_ignores_max_results(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [_issue(i, "To Do", "new") for i in range(50)], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    code, out, _, status = run("remediation_items", router,
                               {"JIRA_REMEDIATION_JQL": "labels = x", "JIRA_REMEDIATION_MAX_ITEMS": "10"})
    assert out["metadata"]["items_collected"] == 10
    assert out["metadata"]["items_truncated"] is True and code == 1


# ---------- change_requests ----------

CF = {"Change Type": "cf1", "Change Risk": "cf2", "CCB Approver": "cf3", "CCB Approval Date": "cf4",
      "Security Impact Analysis": "cf5", "Test Results": "cf6", "Deployed At": "cf7",
      "Exception Expiry": "cf8", "Last Reviewed": "cf9", "Severity": "cf10", "Incident Category": "cf11",
      "Detected At": "cf12", "Reported At": "cf13", "Incident Phase": "cf14"}
FIELD_LIST = [{"id": v, "name": k, "custom": True} for k, v in CF.items()]
STATUS_LIST = [{"id": "1", "name": "Backlog", "statusCategory": {"key": "new"}},
               {"id": "2", "name": "Approved", "statusCategory": {"key": "indeterminate"}},
               {"id": "3", "name": "In Progress", "statusCategory": {"key": "indeterminate"}},
               {"id": "4", "name": "Reopened", "statusCategory": {"key": "indeterminate"}},
               {"id": "5", "name": "Done", "statusCategory": {"key": "done"}},
               {"id": "6", "name": "Deployed", "statusCategory": {"key": "done"}},
               {"id": "7", "name": "Closed", "statusCategory": {"key": "done"}}]
APPROVER = {"accountId": "a1", "displayName": "CCB Chair", "emailAddress": "chair@example.com"}


def _ticket(n, itype, status, cat, f, watch=1, comments=1):
    return {"id": str(500 + n), "key": f"CCB-{n}", "fields": {
        "summary": f"ticket {n}", "project": {"key": "CCB"}, "issuetype": {"name": itype},
        "status": {"name": status, "statusCategory": {"key": cat}},
        "created": "2026-10-01T00:00:00.000+0000",
        "resolutiondate": "2026-10-06T18:00:00.000+0000" if cat == "done" else None,
        "watches": {"watchCount": watch}, "comment": {"total": comments, "comments": [{"body": "secret"}]},
        "issuelinks": [], **f}}


def test_change_requests_findings(run):
    sel = lambda v: {"value": v}  # noqa: E731
    tickets = [
        _ticket(1, "Change Request", "Done", "done", {"cf1": sel("Normal"), "cf3": APPROVER,
                "cf4": "2026-10-05T08:00:00.000-0600", "cf6": sel("Passed"), "cf7": "2026-10-06T12:00:00.000-0600"}),
        _ticket(2, "Change Request", "Done", "done", {"cf1": sel("Emergency"), "cf3": APPROVER,
                "cf4": "2026-10-09T20:00:00.000+0000", "cf6": sel("Passed"), "cf7": "2026-10-09T16:00:00.000+0000"}),
        _ticket(3, "Change Request", "Done", "done", {"cf1": sel("Normal"), "cf6": sel("Passed")}, comments=0),
        _ticket(4, "Change Request", "Done", "done", {"cf1": sel("Standard"), "cf6": sel("Passed")}),
        _ticket(5, "Change Request", "Done", "done", {"cf1": sel("Normal"), "cf3": APPROVER,
                "cf4": "2026-10-01T00:00:00.000+0000", "cf6": sel("Failed")}),
        _ticket(6, "Change Request", "Done", "done", {"cf1": sel("Normal"), "cf6": sel("Passed")}),
        _ticket(7, "Internal Connection", "Done", "done", {"cf3": APPROVER, "cf4": "2026-10-01T00:00:00.000+0000",
                "cf5": sel("Not completed"), "cf6": sel("Passed")}),
        _ticket(8, "Configuration Exception", "Backlog", "new", {"cf3": APPROVER, "cf4": "2026-06-01T00:00:00.000+0000",
                "cf8": "2026-09-01", "cf9": "2026-06-01"}),
        _ticket(9, "Configuration Exception", "Backlog", "new", {"cf3": APPROVER, "cf4": "2025-05-01T00:00:00.000+0000",
                "cf8": "2099-01-01", "cf9": "2020-01-01"}),
        _ticket(10, "Configuration Exception", "Backlog", "new", {}),
        _ticket(11, "Configuration Exception", "Done", "done", {"cf3": APPROVER, "cf4": "2025-01-10T00:00:00.000+0000"}),
    ]
    hist6 = [{"id": "h1", "created": "2026-10-03T00:00:00.000+00:00", "author": {"displayName": "Chair"},
              "items": [{"fieldId": "status", "fromString": "Backlog", "toString": "Approved"}]},
             {"id": "h2", "created": "2026-10-04T00:00:00.000+00:00", "author": {"displayName": "Dev"},
              "items": [{"fieldId": "status", "fromString": "Approved", "toString": "Done"}]}]

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            assert "cf3" in body["fields"] and "watches" in body["fields"]
            return 200, {"issues": tickets, "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            assert len(body["fieldIds"]) <= 10
            return 200, {"issueChangeLogs": [{"issueId": "506", "changeHistories": hist6}]}
        raise AssertionError(path)

    code, out, _, status = run("change_requests", router,
                               {"JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_APPROVED_STATUSES": "Approved"})
    assert code == 0 and status is None
    by_key = {t["key"]: t for t in out["tickets"]}
    assert by_key["CCB-1"]["findings"] == [] and by_key["CCB-1"]["approved_before_deploy"] is True
    assert by_key["CCB-1"]["approver"] == "CCB Chair"
    assert "chair@example.com" not in json.dumps(out) and "secret" not in json.dumps(out)
    assert "approved_after_deploy" in by_key["CCB-2"]["findings"]
    # one watcher (the reporter) and no comments is not a notification trail
    assert by_key["CCB-3"]["findings"] == ["deployed_without_approval", "deployed_without_notification_trail"]
    assert by_key["CCB-4"]["findings"] == [] and by_key["CCB-4"]["preapproved"] is True
    assert "deployed_with_failed_tests" in by_key["CCB-5"]["findings"]
    assert by_key["CCB-6"]["approval_source"] == "status" and by_key["CCB-6"]["findings"] == []
    assert by_key["CCB-7"]["findings"] == ["connection_without_security_review", "connection_without_risk"]
    assert by_key["CCB-8"]["findings"] == ["exception_open_past_expiry"]
    assert by_key["CCB-9"]["findings"] == ["exception_review_overdue"]
    assert set(by_key["CCB-10"]["findings"]) == {"exception_without_approval", "exception_review_overdue"}
    assert by_key["CCB-11"]["findings"] == []
    s = out["summary"]
    assert s["exceptions_total"] == 4 and s["exceptions_open"] == 3
    assert s["changes_deployed"] == 7 and s["changes_deployed_preapproved"] == 1


def test_change_requests_unresolved_fields_are_reported(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, [{"id": "cf3", "name": "CCB Approver", "custom": True}]
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [], "isLast": True}
        raise AssertionError(path)

    code, out, _, _ = run("change_requests", router, {"JIRA_CHANGE_JQL": "project = CCB"})
    assert code == 1
    assert out["metadata"]["fields_resolved"] == {"approver": ["cf3"]}
    assert out["metadata"]["field_problems"]["risk"] == "unresolved"
    assert out["metadata"]["complete"] is False
    assert "risk (unresolved)" in out["metadata"]["incomplete_reason"]


def test_change_requests_ambiguous_field_fails_loudly_and_lists_candidates(run):
    fields = [
        {"id": "customfield_10043", "name": "Change Type", "schema": {"custom": "com.atlassian.jira.plugin.system.customfieldtypes:select"}},
        {"id": "customfield_10005", "name": "Change type", "schema": {"custom": "com.atlassian.servicedesk:sd-change-type"}},
        {"id": "cf3", "name": "CCB Approver"},
    ]

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, fields
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [], "isLast": True}
        raise AssertionError(path)

    env = {"JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_APPROVED_STATUSES": "Approved",
           "JIRA_CHANGE_FIELDS": '{"risk": "", "approved_at": "", "security_review": "", "test_results": "", '
                                 '"deployed_at": "", "exception_expiry": "", "last_reviewed": ""}'}
    code, out, _, _ = run("change_requests", router, env)
    meta = out["metadata"]
    assert code == 1 and meta["complete"] is False and meta["partial_failure"] is True
    assert set(meta["checks_disabled"]) == {"connection_without_risk", "connection_without_security_review",
                                            "deployed_with_failed_tests", "deployed_without_passing_tests",
                                            "exception_open_past_expiry", "exception_review_overdue"}
    assert meta["field_problems"]["change_type"] == "ambiguous"
    assert meta["field_problems"]["risk"] == "disabled"
    assert [c["id"] for c in meta["field_candidates"]["change_type"]] == ["customfield_10043", "customfield_10005"]
    assert "change_type (ambiguous)" in meta["incomplete_reason"]
    assert "risk" not in meta["incomplete_reason"]

    env["JIRA_CHANGE_FIELDS"] = env["JIRA_CHANGE_FIELDS"][:-1] + ', "change_type": "customfield_10043"}'
    code, out, _, _ = run("change_requests", router, env)
    assert code == 0 and out["metadata"]["complete"] is True
    assert out["metadata"]["fields_resolved"]["change_type"] == ["customfield_10043"]
    assert out["metadata"]["field_candidates"] == {}


def test_change_requests_rejects_unknown_field_role(monkeypatch, tmp_path):
    for k, v in {"JIRA_BASE_URL": "https://x.atlassian.net", "JIRA_EMAIL": "e", "JIRA_API_TOKEN": "t",
                 "JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_FIELDS": '{"aprover": "X"}',
                 "EVIDENCE_DIR": str(tmp_path), "FETCHER_STATUS_FILE": str(tmp_path / "s.json")}.items():
        monkeypatch.setenv(k, v)
    assert load("change_requests").main() == 1
    assert json.loads((tmp_path / "s.json").read_text())["code"] == "bad_config"


# ---------- incident_postmortems ----------

def _incident(n, f, cat="done", links=()):
    return {"id": str(700 + n), "key": f"IR-{n}", "fields": {
        "summary": f"incident {n}", "project": {"key": "IR"}, "issuetype": {"name": "Incident"},
        "status": {"name": "Done" if cat == "done" else "In Progress", "statusCategory": {"key": cat}},
        "created": "2026-10-01T00:00:00.000+0000", "resolutiondate": None,
        "issuelinks": [{"type": {"name": "Relates", "outward": "relates to"},
                        "outwardIssue": {"key": k, "fields": {"issuetype": {"name": "Post-mortem"}}}} for k in links],
        **f}}


def test_incident_postmortems_findings(run):
    sel = lambda v: {"value": v}  # noqa: E731
    incidents = [
        _incident(1, {"cf10": sel("SEV 2"), "cf11": sel("CAT 2 User Level Intrusion"),
                      "cf12": "2026-10-01T10:00:00.000-0600", "cf13": "2026-10-01T10:40:00.000-0600",
                      "cf14": sel("Lessons Learned")}, links=["IR-7"]),
        _incident(2, {"cf10": sel("SEV 1"), "cf11": sel("CAT 4 Denial of Service"),
                      "cf12": "2026-10-02T09:00:00.000+0000", "cf13": "2026-10-02T09:50:00.000+0000"}, links=["IR-8"]),
        _incident(3, {"cf10": sel("SEV 3"), "cf11": sel("CAT 3 Unsuccessful Activity Attempt"),
                      "cf12": "2026-10-03T08:00:00.000+0000", "cf13": "2026-10-03T10:30:00.000+0000"}, links=["IR-9"]),
        _incident(4, {"cf10": sel("SEV 2"), "cf11": sel("CAT 7 Malicious Logic"),
                      "cf12": "2026-10-05T12:00:00.000+0000", "cf13": "2026-10-05T12:30:00.000+0000"}),
        _incident(5, {"cf10": sel("SEV 4"), "cf11": sel("CAT 6 Reconnaissance"), "cf12": "2026-10-14T07:00:00.000+0000",
                      "cf13": "2026-10-14T07:20:00.000+0000"}, cat="indeterminate"),
        _incident(6, {"cf10": sel("SEV 3"), "cf11": sel("CAT 5 Non-Compliance Activity"),
                      "cf13": "2026-10-13T09:00:00.000+0000"}),
    ]
    pms = {k: {"key": k, "fields": {"issuetype": {"name": "Post-mortem"}, "status": {"name": "Done"},
                                    "summary": "pm", "subtasks": [{"key": s} for s in subs]}}
           for k, subs in {"IR-7": ["IR-10", "IR-11", "IR-12"], "IR-8": [], "IR-9": ["IR-13"]}.items()}

    def action(key, parent, done, assignee, due):
        return {"key": key, "fields": {"parent": {"key": parent}, "summary": "ai", "duedate": due,
                "status": {"name": "Done" if done else "To Do", "statusCategory": {"key": "done" if done else "new"}},
                "assignee": {"displayName": "Owner"} if assignee else None}}
    actions = {"IR-10": action("IR-10", "IR-7", True, True, "2026-10-08"),
               "IR-11": action("IR-11", "IR-7", True, True, "2026-10-09"),
               "IR-12": action("IR-12", "IR-7", False, True, "2026-10-10"),
               "IR-13": action("IR-13", "IR-9", False, False, "2099-12-01")}
    phase_hist = [{"id": f"p{i}", "created": f"2026-10-01T1{i}:00:00.000+00:00", "author": {"displayName": "IR"},
                   "items": [{"fieldId": "cf14", "fromString": a, "toString": b}]}
                  for i, (a, b) in enumerate([("Identification", "Containment"), ("Containment", "Eradication"),
                                              ("Eradication", "Recovery"), ("Recovery", "Lessons Learned")])]

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": incidents, "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            assert body["fieldIds"] == ["status", "cf14"]
            return 200, {"issueChangeLogs": [{"issueId": "701", "changeHistories": phase_hist}]}
        if path == "/rest/api/3/issue/bulkfetch":
            keys = body["issueIdsOrKeys"]
            pool = {**pms, **actions}
            return 200, {"issues": [pool[k] for k in keys if k in pool], "issueErrors": []}
        raise AssertionError(path)

    env = {"JIRA_INCIDENT_JQL": "project = IR AND issuetype = Incident",
           "JIRA_INCIDENT_CATEGORY_TARGETS": '{"CAT 1": 120, "CAT 2": 120, "CAT 3": 240, "CAT 4": 15, "CAT 5": 240, "CAT 6": 240, "CAT 7": 120}',
           "JIRA_POSTMORTEM_REQUIRED_SEVERITIES": "SEV 1,SEV 2"}
    code, out, _, status = run("incident_postmortems", router, env)
    assert code == 0 and status is None
    by_key = {i["key"]: i for i in out["incidents"]}
    assert by_key["IR-1"]["minutes_to_report"] == 40.0
    assert by_key["IR-1"]["phases_seen"] == ["Identification", "Containment", "Eradication", "Recovery", "Lessons Learned"]
    assert by_key["IR-1"]["phases_missing"] == []
    assert by_key["IR-1"]["findings"] == ["overdue_action_items"]
    assert set(by_key["IR-2"]["findings"]) == {"category_notification_target_missed", "postmortem_without_action_items"}
    assert set(by_key["IR-3"]["findings"]) == {"reported_late", "unassigned_action_items"}
    assert by_key["IR-4"]["findings"] == ["resolved_without_postmortem"]
    assert by_key["IR-5"]["findings"] == []
    assert by_key["IR-6"]["findings"] == ["missing_detected_time"]
    s = out["summary"]
    assert (s["incidents"], s["open"], s["resolved"]) == (6, 1, 5)
    assert s["reported_within_window"] == 4 and s["reported_late"] == 1
    assert s["postmortem_required"] == 3 and s["resolved_without_postmortem"] == 1
    assert s["action_items"] == {"total": 4, "open": 2, "done": 2, "open_unassigned": 1, "overdue": 1}


def test_change_requests_date_only_approval_after_deploy_is_caught(run):
    t = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf3": APPROVER,
                "cf4": "2026-10-10", "cf6": {"value": "Passed"}, "cf7": "2026-10-01T12:00:00.000+0000"})
    cancelled = _ticket(2, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}})
    cancelled["fields"]["resolution"] = {"name": "Won't Do"}

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [t, cancelled], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    code, out, _, _ = run("change_requests", router, {"JIRA_CHANGE_JQL": "project = CCB"})
    by_key = {r["key"]: r for r in out["tickets"]}
    assert "approved_after_deploy" in by_key["CCB-1"]["findings"]
    assert by_key["CCB-2"]["cancelled"] is True and by_key["CCB-2"]["findings"] == []
    assert out["summary"]["changes_cancelled"] == 1 and out["summary"]["changes_deployed"] == 1


def test_change_requests_unexpected_shape_still_writes_and_reports(run):
    bad = _ticket(1, "Change Request", "Done", "done", {})
    bad["fields"]["status"] = "Done"  # a string where an object belongs

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [bad], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    code, out, _, status = run("change_requests", router, {"JIRA_CHANGE_JQL": "project = CCB"})
    assert code == 1 and status["code"] == "internal_error"
    assert out["metadata"]["complete"] is False


def test_incident_category_prefix_needs_word_boundary():
    sys.path.insert(0, str(JIRA / "incident_postmortems"))
    mod = load("incident_postmortems")
    targets = {"CAT 1": 10, "CAT 4": 15}
    assert mod._category_target("CAT 10 Something", targets) is None
    assert mod._category_target("cat 4 Denial of Service", targets) == 15
    assert mod._category_target("CAT 1 Root Level Intrusion", targets) == 10


def test_incident_hidden_postmortem_is_not_reported_as_missing(run):
    inc = _incident(4, {"cf10": {"value": "SEV 2"}, "cf11": {"value": "CAT 7"},
                        "cf12": "2026-10-05T12:00:00.000+0000", "cf13": "2026-10-05T12:30:00.000+0000"},
                    links=["IR-99"])

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [inc], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        if path == "/rest/api/3/issue/bulkfetch":
            return 200, {"issues": [], "issueErrors": [{"errorMessages": ["not visible"]}]}
        raise AssertionError(path)

    code, out, _, status = run("incident_postmortems", router, {"JIRA_INCIDENT_JQL": "project = IR"})
    assert out["incidents"][0]["findings"] == []
    assert out["incidents"][0]["unknown"] == ["postmortem_not_visible"]
    assert out["summary"]["findings"] == {} and out["summary"]["unknown"] == {"postmortem_not_visible": 1}
    assert out["metadata"]["related_issues_not_visible"] == ["IR-99"]
    assert code == 1 and status["code"] == "partial_failure"


def test_incident_negative_report_time_is_flagged(run):
    inc = _incident(1, {"cf10": {"value": "SEV 4"}, "cf11": {"value": "CAT 6"},
                        "cf12": "2026-10-05T12:00:00.000+0000", "cf13": "2026-10-05T11:00:00.000+0000"}, cat="new")

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [inc], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    code, out, _, _ = run("incident_postmortems", router, {"JIRA_INCIDENT_JQL": "project = IR"})
    assert out["incidents"][0]["findings"] == ["reported_before_detected"]
    assert out["summary"]["reported_within_window"] == 0


def test_incident_required_phases(run):
    inc = _incident(2, {"cf10": {"value": "SEV 3"}, "cf11": {"value": "CAT 3"}, "cf14": {"value": "Lessons Learned"},
                        "cf12": "2026-10-05T12:00:00.000+0000", "cf13": "2026-10-05T12:10:00.000+0000"})

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [inc], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    code, out, _, _ = run("incident_postmortems", router, {
        "JIRA_INCIDENT_JQL": "project = IR", "JIRA_POSTMORTEM_REQUIRED_SEVERITIES": "SEV 1",
        "JIRA_INCIDENT_REQUIRED_PHASES": "Identification,Containment,Lessons Learned"})
    i = out["incidents"][0]
    assert i["phases_missing"] == ["Identification", "Containment"] and i["findings"] == ["phases_missing"]


# ---------- PR #174 review: disabled fields, conflicting settings, honest metadata ----------

def _cr_router(tickets, histories=None):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": tickets, "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": histories or []}
        raise AssertionError(path)
    return router


def _ir_router(incidents, bulk=None):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": incidents, "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        if path == "/rest/api/3/issue/bulkfetch":
            return bulk(body) if bulk else (200, {"issues": [], "issueErrors": []})
        raise AssertionError(path)
    return router


def test_change_requests_disabled_last_reviewed_does_not_flag_review_overdue(run):
    # An approved open exception with a far-future expiry and no review field at all.
    ex = _ticket(1, "Configuration Exception", "Backlog", "new",
                 {"cf3": APPROVER, "cf4": "2026-06-01T00:00:00.000+0000", "cf8": "2099-01-01"})
    env = {"JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_FIELDS": '{"last_reviewed": ""}'}
    code, out, _, status = run("change_requests", _cr_router([ex]), env)
    assert code == 0 and status is None
    t = out["tickets"][0]
    assert t["findings"] == []
    assert t["exception"]["review_overdue"] is None
    assert "exception_review_overdue" in out["metadata"]["checks_disabled"]


def test_incident_disabled_fields_do_not_flag_missing_values(run):
    inc = _incident(1, {"cf13": "2026-10-05T12:30:00.000+0000"}, cat="new")
    env = {"JIRA_INCIDENT_JQL": "project = IR",
           "JIRA_INCIDENT_FIELDS": '{"detected_at": "", "severity": "", "category": ""}'}
    code, out, _, status = run("incident_postmortems", _ir_router([inc]), env)
    assert code == 0 and status is None
    assert out["incidents"][0]["findings"] == []
    assert set(out["metadata"]["checks_disabled"]) >= {
        "missing_detected_time", "missing_severity", "missing_category",
        "reported_late", "category_notification_target_missed",
    }
    assert out["summary"]["reported_within_window"] == 0
    assert out["summary"]["incidents_without_report_timing"] == 1


@pytest.mark.parametrize("env", [
    {"JIRA_INCIDENT_FIELDS": '{"severity": ""}', "JIRA_POSTMORTEM_REQUIRED_SEVERITIES": "SEV 1"},
    {"JIRA_INCIDENT_FIELDS": '{"phase": ""}', "JIRA_INCIDENT_REQUIRED_PHASES": "Identification"},
    {"JIRA_INCIDENT_FIELDS": '{"category": ""}', "JIRA_INCIDENT_CATEGORY_TARGETS": '{"CAT 1": 15}'},
    {"JIRA_INCIDENT_FIELDS": '{"detected_at": ""}', "JIRA_INCIDENT_CATEGORY_TARGETS": '{"CAT 1": 15}'},
    {"JIRA_INCIDENT_FIELDS": '{"detected_at": ""}', "JIRA_INCIDENT_REPORT_MINUTES": "30"},
])
def test_incident_conflicting_settings_are_bad_config(monkeypatch, tmp_path, env):
    for k, v in {"JIRA_BASE_URL": "https://x.atlassian.net", "JIRA_EMAIL": "e", "JIRA_API_TOKEN": "t",
                 "JIRA_INCIDENT_JQL": "project = IR", "EVIDENCE_DIR": str(tmp_path),
                 "FETCHER_STATUS_FILE": str(tmp_path / "s.json"), **env}.items():
        monkeypatch.setenv(k, v)
    assert load("incident_postmortems").main() == 1
    assert json.loads((tmp_path / "s.json").read_text())["code"] == "bad_config"
    assert not (tmp_path / "jira_incident_postmortems.json").exists()


@pytest.mark.parametrize("fields", ['{"approver": ""}', '{"approved_at": ""}', '{"approver": "", "approved_at": ""}'])
def test_change_requests_no_approval_source_is_bad_config(monkeypatch, tmp_path, fields):
    for k, v in {"JIRA_BASE_URL": "https://x.atlassian.net", "JIRA_EMAIL": "e", "JIRA_API_TOKEN": "t",
                 "JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_FIELDS": fields,
                 "EVIDENCE_DIR": str(tmp_path), "FETCHER_STATUS_FILE": str(tmp_path / "s.json")}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("JIRA_CHANGE_APPROVED_STATUSES", raising=False)
    assert load("change_requests").main() == 1
    assert json.loads((tmp_path / "s.json").read_text())["code"] == "bad_config"


def test_change_requests_status_approval_allows_disabled_approval_fields(run):
    t = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf6": {"value": "Passed"}})
    hist = [{"issueId": "501", "changeHistories": [
        {"id": "h1", "created": "2026-10-03T00:00:00.000+00:00", "author": {"displayName": "Chair"},
         "items": [{"fieldId": "status", "fromString": "Backlog", "toString": "Approved"}]},
        {"id": "h2", "created": "2026-10-04T00:00:00.000+00:00", "author": {"displayName": "Dev"},
         "items": [{"fieldId": "status", "fromString": "Approved", "toString": "Done"}]}]}]
    env = {"JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_APPROVED_STATUSES": "Approved",
           "JIRA_CHANGE_FIELDS": '{"approver": "", "approved_at": ""}'}
    code, out, _, _ = run("change_requests", _cr_router([t], hist), env)
    assert code == 0 and out["tickets"][0]["findings"] == []
    assert out["tickets"][0]["approval_source"] == "status"


def test_partial_failure_is_true_whenever_the_run_is_incomplete(run):
    # Truncation: no API call failed, but the evidence is incomplete.
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [_issue(i, "To Do", "new") for i in range(3)], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    code, out, _, _ = run("remediation_items", router,
                          {"JIRA_REMEDIATION_JQL": "labels = x", "JIRA_REMEDIATION_MAX_ITEMS": "2"})
    assert code == 1
    assert out["metadata"]["complete"] is False
    assert out["metadata"]["partial_failure"] is True
    assert out["metadata"]["api_failures"] == []

    # Field problem: same contract.
    def router2(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, [{"id": "cf3", "name": "CCB Approver"}]
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [], "isLast": True}
        raise AssertionError(path)

    code, out, _, _ = run("change_requests", router2, {"JIRA_CHANGE_JQL": "project = CCB"})
    assert code == 1 and out["metadata"]["partial_failure"] is True


def test_incident_failed_bulkfetch_is_not_visible_not_missing(run):
    inc = _incident(4, {"cf10": {"value": "SEV 2"}, "cf11": {"value": "CAT 7"},
                        "cf12": "2026-10-05T12:00:00.000+0000", "cf13": "2026-10-05T12:30:00.000+0000"},
                    links=["IR-99"])
    code, out, _, status = run(
        "incident_postmortems",
        _ir_router([inc], bulk=lambda body: (403, {"errorMessages": ["no permission"]})),
        {"JIRA_INCIDENT_JQL": "project = IR"})
    assert out["incidents"][0]["findings"] == []
    assert out["incidents"][0]["unknown"] == ["postmortem_not_visible"]
    assert out["metadata"]["related_issues_not_visible"] == ["IR-99"]
    assert out["metadata"]["related_issues_complete"] is False
    # A refused read is not "0 action items": that block is null, the rest stays measured.
    assert out["summary"]["action_items"] == {
        "total": None, "open": None, "done": None, "open_unassigned": None, "overdue": None
    }
    assert out["summary"]["incidents"] == 1
    assert code == 1 and out["metadata"]["partial_failure"] is True
    assert out["summary"]["resolved_without_postmortem"] == 0


def test_change_requests_reopened_ticket_uses_first_deployment(run):
    # Deployed day 1, approved day 3, reopened and closed again day 10: the approval was late.
    t = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf3": APPROVER,
                "cf4": "2026-10-03T00:00:00.000+0000", "cf6": {"value": "Passed"}})
    t["fields"]["resolutiondate"] = "2026-10-10T00:00:00.000+0000"
    hist = [{"issueId": "501", "changeHistories": [
        {"id": "h1", "created": "2026-10-01T00:00:00.000+00:00", "author": {"displayName": "Dev"},
         "items": [{"fieldId": "status", "fromString": "In Progress", "toString": "Done"}]},
        {"id": "h2", "created": "2026-10-05T00:00:00.000+00:00", "author": {"displayName": "Dev"},
         "items": [{"fieldId": "status", "fromString": "Done", "toString": "Reopened"}]},
        {"id": "h3", "created": "2026-10-10T00:00:00.000+00:00", "author": {"displayName": "Dev"},
         "items": [{"fieldId": "status", "fromString": "Reopened", "toString": "Done"}]}]}]
    code, out, _, _ = run("change_requests", _cr_router([t], hist), {"JIRA_CHANGE_JQL": "project = CCB"})
    r = out["tickets"][0]
    assert r["deployed_at"] == "2026-10-01T00:00:00.000+00:00"
    assert r["last_done_at"] == "2026-10-10T00:00:00.000+00:00"
    assert r["reopened"] is True
    assert "approved_after_deploy" in r["findings"]


def test_incident_unreadable_action_items_are_not_reported_as_none(run):
    inc = _incident(1, {"cf10": {"value": "SEV 1"}, "cf11": {"value": "CAT 1"},
                        "cf12": "2026-10-05T12:00:00.000+0000", "cf13": "2026-10-05T12:10:00.000+0000"},
                    links=["IR-7"])
    pm = {"key": "IR-7", "fields": {"issuetype": {"name": "Post-mortem"}, "status": {"name": "Done"},
                                    "summary": "pm", "subtasks": [{"key": "IR-10"}, {"key": "IR-11"}]}}

    def bulk(body):
        keys = body["issueIdsOrKeys"]
        if "IR-7" in keys:
            return 200, {"issues": [pm], "issueErrors": []}
        return 200, {"issues": [], "issueErrors": [{"errorMessages": ["not visible"]}]}

    code, out, _, _ = run("incident_postmortems", _ir_router([inc], bulk=bulk), {"JIRA_INCIDENT_JQL": "project = IR"})
    i = out["incidents"][0]
    assert i["findings"] == [] and i["unknown"] == ["action_items_not_visible"]
    assert out["summary"]["action_items"]["total"] is None
    assert i["postmortems"][0]["action_item_count"] == 2 and i["action_items"] == []
    assert out["metadata"]["related_issues_not_visible"] == ["IR-10", "IR-11"]
    assert code == 1 and out["metadata"]["partial_failure"] is True


# ---------- retries and timeouts (review item 4) ----------

@pytest.fixture
def run_raw(monkeypatch, tmp_path):
    """Like `run`, but the router returns a full FakeResponse (headers) or raises."""
    def _run(name: str, router, env: dict | None = None):
        sleeps = []
        monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))

        def fake_request(self, method, url, params=None, json=None, timeout=None, **kw):
            assert kw.get("allow_redirects") is False
            return router(method, url.split(".atlassian.net", 1)[1], params or {}, json or {})

        monkeypatch.setattr(requests.Session, "request", fake_request)
        for k, v in {"JIRA_BASE_URL": "https://example.atlassian.net", "JIRA_EMAIL": "svc@example.com",
                     "JIRA_API_TOKEN": "t", "EVIDENCE_DIR": str(tmp_path),
                     "FETCHER_STATUS_FILE": str(tmp_path / "status.json"), **(env or {})}.items():
            monkeypatch.setenv(k, v)
        mod = load(name)
        code = mod.main()
        out_path = tmp_path / mod.OUTPUT_FILE
        out = json.loads(out_path.read_text()) if out_path.exists() else None
        status = tmp_path / "status.json"
        return code, out, sleeps, (json.loads(status.read_text()) if status.exists() else None)
    return _run


def test_429_is_retried_after_the_retry_after_header(run_raw):
    seen = {"search": 0}

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return FakeResponse(200, ME)
        if path == "/rest/api/3/search/jql":
            seen["search"] += 1
            if seen["search"] == 1:
                r = FakeResponse(429, {"errorMessages": ["rate limit"]})
                r.headers["Retry-After"] = "3"
                return r
            return FakeResponse(200, {"issues": [], "isLast": True})
        if path == "/rest/api/3/changelog/bulkfetch":
            return FakeResponse(200, {"issueChangeLogs": []})
        raise AssertionError(path)

    code, out, sleeps, status = run_raw("remediation_items", router, {"JIRA_REMEDIATION_JQL": "labels = x"})
    assert code == 0 and status is None
    assert seen["search"] == 2 and sleeps == [3.0]
    assert out["metadata"]["api_failures"] == [] and out["metadata"]["complete"] is True


def test_5xx_gives_up_after_backoff_and_is_recorded(run_raw):
    calls = {"n": 0}

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return FakeResponse(200, ME)
        if path == "/rest/api/3/search/jql":
            calls["n"] += 1
            return FakeResponse(503, {"errorMessages": ["down"]})
        raise AssertionError(path)

    code, out, sleeps, status = run_raw("remediation_items", router, {"JIRA_REMEDIATION_JQL": "labels = x"})
    assert calls["n"] == 5 and sleeps == [2.0, 4.0, 8.0, 16.0]
    assert code == 1 and status["code"] == "partial_failure"
    assert out["metadata"]["api_failures"][0]["type"] == "HTTP503"
    assert out["metadata"]["partial_failure"] is True


def test_timeout_after_a_success_is_one_failed_call_not_an_abort(run_raw):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return FakeResponse(200, ME)
        if path == "/rest/api/3/search/jql":
            return FakeResponse(200, {"issues": [_issue(1, "To Do", "new")], "isLast": True})
        if path == "/rest/api/3/changelog/bulkfetch":
            raise requests.ReadTimeout("slow")
        raise AssertionError(path)

    code, out, sleeps, status = run_raw("remediation_items", router, {"JIRA_REMEDIATION_JQL": "labels = x"})
    assert sleeps == [2.0, 4.0], "a raising request is retried twice, each attempt can take the full timeout"
    assert out is not None and out["summary"]["total"] == 1, "the run kept its evidence"
    assert out["metadata"]["status_history_complete"] is False
    assert out["metadata"]["api_failures"][0]["type"] == "ReadTimeout"
    assert "slow" not in json.dumps(out), "exception text is not echoed"
    assert code == 1 and status["code"] == "partial_failure"


def test_unreachable_host_before_any_success_aborts(run_raw):
    def router(method, path, params, body):
        raise requests.ConnectionError("nope")

    code, out, sleeps, status = run_raw("remediation_items", router, {"JIRA_REMEDIATION_JQL": "labels = x"})
    assert code == 1 and status["code"] == "target_unreachable" and sleeps == [2.0, 4.0]


# ---------- access_roles: call count, unresolved holders, absent products (review item 6, Q1) ----------

def _access_router(role_index_allowed: bool):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/group/bulk":
            if "applicationKey" not in params:
                return 400, {"errorMessages": ["applicationKey is required"]}
            if params["applicationKey"] == "jira-software":
                return 200, {"isLast": True, "values": [{"groupId": "g-adm", "name": "jira-admins"}]}
            # products the site does not have
            return (404 if params["applicationKey"] == "jira-servicedesk" else 400), {"errorMessages": ["no such product"]}
        if path == "/rest/api/3/group/member":
            return 200, {"isLast": True, "values": [{"accountId": "a2", "displayName": "Bob", "accountType": "atlassian", "active": True}]}
        if path == "/rest/api/3/applicationrole":
            return 200, []
        if path == "/rest/api/3/project/search":
            return 200, {"isLast": True, "values": [{"key": "CCB", "name": "Change Board", "projectTypeKey": "software",
                                                      "lead": {"accountId": "a9", "displayName": "Lead"}}]}
        if path == "/rest/api/3/project/CCB/permissionscheme":
            return 200, {"id": 1, "name": "Default", "permissions": [
                {"permission": "ADMINISTER_PROJECTS", "holder": {"type": "projectRole", "parameter": "10002", "projectRole": {"name": "Administrators"}}},
                {"permission": "DELETE_ISSUES", "holder": {"type": "reporter"}},
                {"permission": "MODIFY_REPORTER", "holder": {"type": "userCustomField", "parameter": "customfield_10050"}},
                {"permission": "BROWSE_PROJECTS", "holder": {"type": "projectRole", "parameter": "10001"}},
            ]}
        if path == "/rest/api/3/project/CCB/role":
            assert role_index_allowed, "the role index must not be read unless JIRA_ACCESS_ALL_ROLES is set"
            return 200, {"Administrators": "https://example.atlassian.net/rest/api/3/project/CCB/role/10002",
                         "Developers": "https://example.atlassian.net/rest/api/3/project/CCB/role/10001"}
        if path == "/rest/api/3/project/CCB/role/10002":
            return 200, {"name": "Administrators", "actors": [{"type": "atlassian-user-role-actor", "displayName": "Dan", "actorUser": {"accountId": "a4"}}]}
        if path == "/rest/api/3/project/CCB/role/10001":
            return 200, {"name": "Developers", "actors": []}
        raise AssertionError(path)
    return router


def test_access_roles_reads_only_granted_roles_and_lists_unresolved_holders(run):
    code, out, calls, status = run("access_roles", _access_router(role_index_allowed=False))
    assert code == 0 and status is None, "an absent product (400/404 per applicationKey) is not a failure"
    role_calls = [p for _, p, _, _ in calls if p.startswith("/rest/api/3/project/CCB/role")]
    assert role_calls == ["/rest/api/3/project/CCB/role/10002"]
    proj = out["projects"][0]
    assert [r["name"] for r in proj["roles"]] == ["Administrators"]
    assert {u["account_id"] for u in proj["privileged_users"]} == {"a4"}
    assert proj["unresolved_privileged_grants"] == [
        {"permission": "DELETE_ISSUES", "holder_type": "reporter", "parameter": None},
        {"permission": "MODIFY_REPORTER", "holder_type": "userCustomField", "parameter": "customfield_10050"},
    ]
    assert out["summary"]["projects_with_unresolved_privileged_grants"] == ["CCB"]
    assert out["metadata"]["organization_admins_included"] is False
    assert [g["name"] for g in out["admin_groups"]] == ["jira-admins"]


def test_access_roles_all_roles_setting_reads_the_index(run):
    code, out, calls, _ = run("access_roles", _access_router(role_index_allowed=True), {"JIRA_ACCESS_ALL_ROLES": "true"})
    assert code == 0
    assert "/rest/api/3/project/CCB/role" in [p for _, p, _, _ in calls]
    assert {r["name"] for r in out["projects"][0]["roles"]} == {"Developers", "Administrators"}


# ---------- site_inventory on the shared client (review item 10) ----------

def _inventory_router(issues, project_type="software", desks=None, fail_after_success=False):
    def router(method, path, params, body):
        if path == "/rest/api/3/serverInfo":
            return 200, {"baseUrl": "https://example.atlassian.net", "deploymentType": "Cloud", "version": "1001.0.0"}
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/project/search":
            return 200, {"isLast": True, "values": [{"id": "1", "key": "OPS", "name": "Ops", "projectTypeKey": project_type,
                                                      "lead": {"displayName": "Lead"}, "issueTypes": [{"name": "Task"}]}]}
        if path == "/rest/api/3/issuetype":
            return 200, [{"id": "1", "name": "Task", "subtask": False}]
        if path == "/rest/api/3/priority/search":
            return 200, {"isLast": True, "values": [{"id": "3", "name": "Medium", "isDefault": True}]}
        if path == "/rest/api/3/status":
            return 200, [{"id": "1", "name": "To Do", "statusCategory": {"key": "new"}}]
        if path == "/rest/servicedeskapi/servicedesk":
            return (200, {"isLastPage": True, "values": desks}) if desks is not None else (404, {})
        if path == "/rest/api/3/search/jql":
            if fail_after_success:
                return 401, {"errorMessages": ["no project permission"]}
            return 200, {"issues": issues, "isLast": True}
        raise AssertionError(path)
    return router


def test_site_inventory_uses_shared_client_and_write_and_finish(run):
    issues = [_issue(1, "Done", "done", resolved="2026-01-02T00:00:00.000+0000"), _issue(2, "To Do", "new")]
    for i in issues:
        i["fields"]["issuetype"] = {"name": "Incident"}
    code, out, calls, status = run("site_inventory", _inventory_router(issues, "service_desk",
                                                                        desks=[{"id": "1", "projectKey": "OPS", "projectName": "Ops"}]))
    assert code == 0 and status is None
    assert out["metadata"]["complete"] is True and out["metadata"]["partial_failure"] is False
    assert out["service_management"] == {"available": True, "service_desks": [{"id": "1", "project_key": "OPS", "project_name": "Ops"}]}
    assert out["summary"]["issues"]["total"] == 2 and out["summary"]["incident_issues"]["total"] == 2
    assert out["summary"]["issues"]["resolution_hours"]["overall"]["count"] == 1
    assert out["issues"][0]["hours_to_resolve"] == 24.0
    assert "/rest/servicedeskapi/servicedesk" in [p for _, p, _, _ in calls]


def test_site_inventory_without_jsm_does_not_call_the_service_desk_api(run):
    code, out, calls, _ = run("site_inventory", _inventory_router([]))
    assert code == 0
    assert out["service_management"] == {"available": False, "service_desks": []}
    assert "/rest/servicedeskapi/servicedesk" not in [p for _, p, _, _ in calls]


def test_site_inventory_cap_is_partial_and_401_after_success_does_not_abort(run):
    issues = [_issue(i, "To Do", "new") for i in range(3)]
    code, out, _, status = run("site_inventory", _inventory_router(issues), {"JIRA_MAX_ISSUES": "2"})
    assert code == 1 and status["code"] == "partial_failure"
    assert out["metadata"]["issues_collected"] == 2 and out["metadata"]["issues_truncated"] is True
    assert out["metadata"]["partial_failure"] is True and "JIRA_MAX_ISSUES" in out["metadata"]["incomplete_reason"]

    code, out, _, status = run("site_inventory", _inventory_router([], fail_after_success=True))
    assert code == 1 and status["code"] == "not_authorized"
    assert out["projects"], "everything before the failed call is still in the file"
    assert out["metadata"]["api_failures"][0]["type"] == "HTTP401"


# ---------- team-managed projects: one role, several field ids (review item 9) ----------

def test_change_requests_role_pinned_to_several_ids_reads_each_project(run):
    # Two team-managed projects each have their own "Change Type" field.
    a = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Standard"}, "cf6": {"value": "Passed"}})
    b = _ticket(2, "Change Request", "Done", "done", {"cf20": {"value": "Standard"}, "cf6": {"value": "Passed"}})
    b["key"] = "OPS-2"
    seen = {}

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST + [{"id": i, "name": "Change Type", "custom": True}
                                      for i in ("customfield_10043", "customfield_10120", "customfield_10044")]
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            seen["fields"] = body["fields"]
            return 200, {"issues": [a, b], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            seen.setdefault("history_fields", []).append(body["fieldIds"])
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    env = {"JIRA_CHANGE_JQL": "project in (CCB, OPS)", "JIRA_CHANGE_APPROVED_STATUSES": "Approved",
           "JIRA_CHANGE_FIELDS": '{"change_type": "customfield_10043, customfield_10120", "risk": ["customfield_10044"]}'}
    a["fields"]["customfield_10043"] = {"value": "Standard"}
    b["fields"]["customfield_10120"] = {"value": "Standard"}
    code, out, _, _ = run("change_requests", router, env)
    assert code == 0, out["metadata"]
    assert out["metadata"]["checks_disabled"] == [], "a list pin is not a turned-off role"
    assert out["metadata"]["field_problems"] == {}
    assert out["metadata"]["fields_resolved"]["change_type"] == ["customfield_10043", "customfield_10120"]
    assert out["metadata"]["fields_resolved"]["risk"] == ["customfield_10044"]
    by_key = {t["key"]: t for t in out["tickets"]}
    assert by_key["CCB-1"]["preapproved"] is True and by_key["OPS-2"]["preapproved"] is True
    assert {"customfield_10043", "customfield_10120"} <= set(seen["fields"])
    # 11 field ids (status + 10) are fetched in two groups, never silently cut to 10
    assert len(seen["history_fields"]) == 2 and sum(len(g) for g in seen["history_fields"]) == 11


def test_bulk_changelogs_merges_items_of_one_history_across_field_groups():
    sys.path.insert(0, str(JIRA / "_shared"))
    import jira_common

    client = jira_common.JiraClient("https://example.atlassian.net", "e", "t")
    pages = []

    def fake(method, path, operation, params=None, body=None, **kw):
        pages.append(body["fieldIds"])
        fid = body["fieldIds"][0]
        return {"issueChangeLogs": [{"issueId": "1", "changeHistories": [
            {"id": "h1", "created": 1767571200000, "items": [{"fieldId": fid, "toString": "x"}]}]}]}

    client.request = fake
    out, complete, unknown = client.bulk_changelogs(["1"], [f"f{i}" for i in range(12)])
    assert unknown == set()
    assert complete and len(pages) == 2 and [len(p) for p in pages] == [10, 2]
    assert len(out["1"]) == 1, "one history, not one per field group"
    assert [i["fieldId"] for i in out["1"][0]["items"]] == ["f0", "f10"]
    assert out["1"][0]["created"] == "2026-01-05T00:00:00.000+00:00"


# ---------- second review round: pinned ids are checked, lists are not "off", conflicts ----------

def test_mistyped_pinned_field_id_fails_loudly_instead_of_reading_nothing(run):
    t = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf3": APPROVER,
                "cf4": "2026-10-01T00:00:00.000+0000", "cf6": {"value": "Passed"}})
    env = {"JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_FIELDS": '{"test_results": "customfield_99999"}'}
    code, out, _, status = run("change_requests", _cr_router([t]), env)
    assert code == 1 and status["code"] == "partial_failure"
    assert out["metadata"]["field_problems"]["test_results"] == "unresolved"
    assert out["metadata"]["field_candidates"]["test_results"][0]["id"] == "customfield_99999"
    assert "deployed_without_passing_tests" not in out["tickets"][0]["findings"], "no finding from an unread field"


@pytest.mark.parametrize("env", [
    {"JIRA_CHANGE_FIELDS": '{"approver": ["customfield_10045"], "approved_at": ["customfield_10046"]}'},
    {"JIRA_CHANGE_FIELDS": '{"approver": "customfield_10045, customfield_10146"}'},
])
def test_list_pins_are_not_treated_as_turned_off(run, env):
    t = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf6": {"value": "Passed"},
                "customfield_10045": APPROVER, "customfield_10046": "2026-10-01T00:00:00.000+0000"})
    t["fields"]["cf4"] = "2026-10-01T00:00:00.000+0000"
    extra = [{"id": i, "name": n, "custom": True} for i, n in
             (("customfield_10045", "CCB Approver"), ("customfield_10046", "CCB Approval Date"), ("customfield_10146", "CCB Approver"))]

    def router(method, path, params, body):
        if path == "/rest/api/3/field":
            return 200, [f for f in FIELD_LIST if f["name"] not in ("CCB Approver", "CCB Approval Date")] + extra
        return _cr_router([t])(method, path, params, body)

    code, out, _, status = run("change_requests", router, {"JIRA_CHANGE_JQL": "project = CCB", **env})
    assert code == 0 and status is None, (out["metadata"], status)
    assert out["metadata"]["checks_disabled"] == []
    assert out["tickets"][0]["approval_source"] == "fields" and out["tickets"][0]["findings"] == []


@pytest.mark.parametrize("fields", ['{"risk": 5}', '{"risk": true}', '{"risk": ["Change Risk", "x"]}', '{"risk": {"a": 1}}'])
def test_non_name_non_id_field_values_are_bad_config(monkeypatch, tmp_path, fields):
    for k, v in {"JIRA_BASE_URL": "https://x.atlassian.net", "JIRA_EMAIL": "e", "JIRA_API_TOKEN": "t",
                 "JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_FIELDS": fields,
                 "EVIDENCE_DIR": str(tmp_path), "FETCHER_STATUS_FILE": str(tmp_path / "s.json")}.items():
        monkeypatch.setenv(k, v)
    assert load("change_requests").main() == 1
    assert json.loads((tmp_path / "s.json").read_text())["code"] == "bad_config"


def test_change_type_off_with_preapproved_types_is_bad_config(monkeypatch, tmp_path):
    for k, v in {"JIRA_BASE_URL": "https://x.atlassian.net", "JIRA_EMAIL": "e", "JIRA_API_TOKEN": "t",
                 "JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_FIELDS": '{"change_type": ""}',
                 "EVIDENCE_DIR": str(tmp_path), "FETCHER_STATUS_FILE": str(tmp_path / "s.json")}.items():
        monkeypatch.setenv(k, v)
    assert load("change_requests").main() == 1
    assert json.loads((tmp_path / "s.json").read_text())["code"] == "bad_config"


def test_change_type_off_is_allowed_when_nothing_is_preapproved(run):
    t = _ticket(1, "Change Request", "Done", "done", {"cf3": APPROVER, "cf4": "2026-10-01T00:00:00.000+0000",
                "cf6": {"value": "Passed"}})
    env = {"JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_FIELDS": '{"change_type": ""}',
           "JIRA_CHANGE_PREAPPROVED_TYPES": ""}
    code, out, _, _ = run("change_requests", _cr_router([t]), env)
    assert code == 0 and out["tickets"][0]["findings"] == []


def test_bulk_changelogs_stops_on_a_repeated_page_token():
    sys.path.insert(0, str(JIRA / "_shared"))
    import jira_common

    client = jira_common.JiraClient("https://example.atlassian.net", "e", "t")
    calls = []

    def fake(method, path, operation, params=None, body=None, **kw):
        calls.append(body.get("nextPageToken"))
        return {"issueChangeLogs": [], "nextPageToken": "same"}

    client.request = fake
    out, complete, unknown = client.bulk_changelogs(["1"], ["status"])
    assert unknown == {"1"}
    assert complete is False and calls == [None, "same"]
    assert client.api_failures[0]["type"] == "RepeatedPageToken"


def _hist(moves):
    """Status histories from (date, from_name, from_id, to_name, to_id) tuples."""
    return [{"issueId": "501", "changeHistories": [
        {"id": f"h{i}", "created": f"2026-10-{d:02d}T00:00:00.000+00:00", "author": {"displayName": "Dev"},
         "items": [{"fieldId": "status", "fromString": fn, "from": fi, "toString": tn, "to": ti}]}
        for i, (d, fn, fi, tn, ti) in enumerate(moves)]}]


def test_change_requests_deployment_is_the_first_entry_into_the_done_category(run):
    # Deployed (done) on day 1, approved day 3, then moved on to Closed (also done) day 5.
    t = _ticket(1, "Change Request", "Closed", "done", {"cf1": {"value": "Normal"}, "cf3": APPROVER,
                "cf4": "2026-10-03T00:00:00.000+0000", "cf6": {"value": "Passed"}})
    t["fields"]["resolutiondate"] = "2026-10-05T00:00:00.000+0000"
    hist = _hist([(1, "In Progress", "3", "Deployed", "6"), (5, "Deployed", "6", "Closed", "7")])
    code, out, _, _ = run("change_requests", _cr_router([t], hist), {"JIRA_CHANGE_JQL": "project = CCB"})
    r = out["tickets"][0]
    assert r["deployed_at"] == "2026-10-01T00:00:00.000+00:00" and r["reopened"] is False
    assert "approved_after_deploy" in r["findings"]
    assert out["metadata"]["done_statuses_known"] is True


def test_change_requests_renamed_done_status_is_still_recognised_by_id(run):
    # The status was called "Done" at the time; it is "Released" now (same id 5).
    t = _ticket(1, "Change Request", "Released", "done", {"cf1": {"value": "Normal"}, "cf3": APPROVER,
                "cf4": "2026-10-03T00:00:00.000+0000", "cf6": {"value": "Passed"}})
    t["fields"]["resolutiondate"] = "2026-10-10T00:00:00.000+0000"
    hist = _hist([(1, "In Progress", "3", "Done", "5"), (5, "Done", "5", "Reopened", "4"), (10, "Reopened", "4", "Done", "5")])
    code, out, _, _ = run("change_requests", _cr_router([t], hist), {"JIRA_CHANGE_JQL": "project = CCB"})
    r = out["tickets"][0]
    assert r["deployed_at"] == "2026-10-01T00:00:00.000+00:00" and r["reopened"] is True
    assert r["last_done_at"] == "2026-10-10T00:00:00.000+00:00"
    assert "approved_after_deploy" in r["findings"]


def test_change_requests_without_the_status_catalog_falls_back_to_the_current_status_name(run):
    t = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf3": APPROVER,
                "cf4": "2026-10-03T00:00:00.000+0000", "cf6": {"value": "Passed"}})
    hist = _hist([(1, "In Progress", "3", "Done", "5")])
    base = _cr_router([t], hist)

    def router(method, path, params, body):
        if path == "/rest/api/3/status":
            return 403, {"errorMessages": ["nope"]}
        return base(method, path, params, body)

    code, out, _, status = run("change_requests", router, {"JIRA_CHANGE_JQL": "project = CCB"})
    assert code == 1 and out["metadata"]["done_statuses_known"] is False
    assert out["tickets"][0]["deployed_at"] == "2026-10-01T00:00:00.000+00:00"
    assert "approved_after_deploy" in out["tickets"][0]["findings"]


def test_audit_records_short_paging_is_not_complete(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if params["offset"] == 0:
            return 200, {"total": 5, "records": [{"id": 1, "category": "permissions", "created": "2026-10-01T00:00:00.000+0000"},
                                                 {"id": 2, "category": "permissions", "created": "2026-10-02T00:00:00.000+0000"}]}
        return 200, {"total": 5, "records": []}

    code, out, _, status = run("audit_records", router)
    assert code == 1 and status["code"] == "partial_failure"
    assert out["metadata"]["records_collected"] == 2 and out["metadata"]["records_truncated"] is False
    assert out["metadata"]["complete"] is False and "2 of 5" in out["metadata"]["incomplete_reason"]


def test_access_roles_zero_admin_groups_is_a_failure(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/group/bulk":
            return 400, {"errorMessages": ["bad request"]}
        if path == "/rest/api/3/applicationrole":
            return 200, []
        if path == "/rest/api/3/project/search":
            return 200, {"isLast": True, "values": []}
        raise AssertionError(path)

    code, out, _, status = run("access_roles", router)
    assert code == 1 and status["code"] == "partial_failure"
    assert out["summary"]["admin_groups"] is None, "a failed section is null, never 0"
    assert out["summary"]["distinct_admin_users"] is None
    assert out["summary"]["projects_scanned"] == 0, "the project section succeeded and stays a number"
    assert out["metadata"]["partial_failure"] is True
    assert out["metadata"]["api_failures"][0]["type"] == "NoAdminGroups"


def test_site_inventory_bad_token_is_auth_failed(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/serverInfo":
            return 200, {"deploymentType": "Cloud"}  # answers anonymously
        return 401, {"errorMessages": ["bad token"]}

    code, out, calls, status = run("site_inventory", router)
    assert code == 1 and status["code"] == "auth_failed"
    assert [p for _, p, _, _ in calls] == ["/rest/api/3/myself"], "aborts on the first 401, nothing else is tried"


def test_incident_duplicate_links_and_missing_parent_are_handled(run):
    inc = _incident(1, {"cf10": {"value": "SEV 1"}, "cf11": {"value": "CAT 1"},
                        "cf12": "2026-10-05T12:00:00.000+0000", "cf13": "2026-10-05T12:10:00.000+0000"},
                    links=["IR-7", "IR-7"])
    pm = {"key": "IR-7", "fields": {"issuetype": {"name": "Post-mortem"}, "status": {"name": "Done"},
                                    "summary": "pm", "subtasks": [{"key": "IR-10"}]}}
    ai = {"key": "IR-10", "fields": {"summary": "ai", "duedate": "2099-01-01",
                                     "status": {"name": "To Do", "statusCategory": {"key": "new"}},
                                     "assignee": {"displayName": "Owner"}}}  # no parent field

    def bulk(body):
        pool = {"IR-7": pm, "IR-10": ai}
        return 200, {"issues": [pool[k] for k in body["issueIdsOrKeys"] if k in pool], "issueErrors": []}

    code, out, _, _ = run("incident_postmortems", _ir_router([inc], bulk=bulk), {"JIRA_INCIDENT_JQL": "project = IR"})
    i = out["incidents"][0]
    assert code == 0 and i["findings"] == []
    assert len(i["postmortems"]) == 1 and len(i["action_items"]) == 1
    assert i["action_items"][0]["postmortem"] == "IR-7"
    assert out["summary"]["action_items"]["total"] == 1


# ---------- Bruce's review: null not zero on failure, paging, failures partway ----------

def test_summary_is_null_when_the_ticket_search_fails_partway(run):
    """Page 1 succeeds, page 2 fails: the counts would be low, so they are not measured."""
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            if not body.get("nextPageToken"):
                return 200, {"issues": [_ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}})], "nextPageToken": "p2"}
            return 503, {"errorMessages": ["down"]}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    code, out, _, status = run("change_requests", router, {"JIRA_CHANGE_JQL": "project = CCB"})
    assert code == 1 and status["code"] == "partial_failure"
    assert out["metadata"]["search_complete"] is False and out["metadata"]["items_collected"] == 1
    assert out["tickets"][0]["key"] == "CCB-1", "what was read is still in the file"
    assert out["summary"]["total"] is None and out["summary"]["changes_deployed"] is None
    assert out["summary"]["findings"] is None and out["summary"]["by_kind"] is None


def test_audit_summary_is_null_when_the_endpoint_is_refused(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        return 403, {"errorMessages": ["no permission"]}

    code, out, _, status = run("audit_records", router)
    assert code == 1 and status["code"] == "not_authorized"
    assert out["summary"]["total"] is None and out["summary"]["sensitive_changes"]["total"] is None


def test_incident_and_remediation_summaries_are_null_on_a_failed_search(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/search/jql":
            return 403, {"errorMessages": ["no browse"]}
        raise AssertionError(path)

    code, out, _, _ = run("incident_postmortems", router, {"JIRA_INCIDENT_JQL": "project = IR"})
    assert code == 1 and out["summary"]["incidents"] is None and out["summary"]["action_items"]["total"] is None
    code, out, _, _ = run("remediation_items", router, {"JIRA_REMEDIATION_JQL": "labels = x"})
    assert code == 1 and out["summary"]["total"] is None and out["summary"]["open_overdue"] is None


def test_paged_values_follows_start_at_until_is_last_and_stops_on_a_failed_page(run):
    pages = {0: ([{"key": "P1"}, {"key": "P2"}], False), 2: ([{"key": "P3"}], True)}
    seen = []

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/group/bulk":
            return 200, {"isLast": True, "values": [{"groupId": "g", "name": "jira-admins"}]}
        if path == "/rest/api/3/group/member":
            return 200, {"isLast": True, "values": []}
        if path == "/rest/api/3/applicationrole":
            return 200, []
        if path == "/rest/api/3/project/search":
            seen.append(params["startAt"])
            values, last = pages[params["startAt"]]
            return 200, {"isLast": last, "values": [{"key": v["key"], "name": v["key"], "projectTypeKey": "software"} for v in values]}
        if path.endswith("/permissionscheme"):
            if "P3" in path:
                return 503, {"errorMessages": ["down"]}
            return 200, {"id": 1, "name": "Default", "permissions": []}
        raise AssertionError(path)

    code, out, _, status = run("access_roles", router)
    assert seen == [0, 2], "startAt advances by the page size received until isLast"
    assert [p["key"] for p in out["projects"]] == ["P1", "P2", "P3"]
    assert code == 1 and out["metadata"]["permission_schemes_unread"] == 1
    assert out["summary"]["projects_scanned"] is None, "one unread scheme makes the project section not measured"
    assert out["summary"]["admin_groups"] == 1, "the admin section succeeded and keeps its number"


def test_search_issues_stops_on_a_repeated_token_or_an_empty_page_with_a_token(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [], "nextPageToken": "again"}
        raise AssertionError(path)

    code, out, calls, status = run("remediation_items", router, {"JIRA_REMEDIATION_JQL": "labels = x"})
    assert len([c for c in calls if c[1] == "/rest/api/3/search/jql"]) == 1
    assert code == 1 and out["metadata"]["api_failures"][0]["type"] == "BadPaging"
    assert out["summary"]["total"] is None


def test_access_roles_unexpected_shape_still_writes_evidence(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/group/bulk":
            return 200, "not an object"
        raise AssertionError(path)

    code, out, _, status = run("access_roles", router)
    assert code == 1 and status["code"] == "internal_error"
    assert out["metadata"]["complete"] is False and out["summary"]["admin_groups"] is None


def test_remediation_done_without_resolutiondate_uses_the_status_history(run):
    done = _issue(1, "Done", "done", due="2026-01-05")
    done["fields"]["resolutiondate"] = None
    hist = {"id": "h1", "created": "2026-01-20T00:00:00.000+00:00", "author": {"displayName": "Ann"},
            "items": [{"fieldId": "status", "fromString": "In Progress", "toString": "Done"}]}
    no_hist = _issue(2, "Done", "done", due="2026-01-05")
    no_hist["fields"]["resolutiondate"] = None

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [done, no_hist], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": [{"issueId": "101", "changeHistories": [hist]}]}
        raise AssertionError(path)

    code, out, _, _ = run("remediation_items", router, {"JIRA_REMEDIATION_JQL": "labels = x"})
    by_key = {i["key"]: i for i in out["items"]}
    assert by_key["OPS-1"]["closed_at"] == "2026-01-20T00:00:00.000+00:00"
    assert by_key["OPS-1"]["closed_at_source"] == "status_history" and by_key["OPS-1"]["days_to_close"] == 19.0
    assert by_key["OPS-2"]["closed_at"] is None and by_key["OPS-2"]["closed_at_source"] is None
    s = out["summary"]
    assert s["closed_after_due_date"] == 1, "the late closure is no longer hidden"
    assert s["closed_without_close_time"] == 1 and s["days_to_close"]["count"] == 1


# ---------- Bruce's review: date-only values ----------

def test_change_requests_date_only_approval_on_the_deployment_day_is_unknown_not_a_finding(run):
    same_day = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf3": APPROVER,
                       "cf4": "2026-10-06", "cf6": {"value": "Passed"}, "cf7": "2026-10-06T15:00:00.000+0000"})
    day_before = _ticket(2, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf3": APPROVER,
                         "cf4": "2026-10-05", "cf6": {"value": "Passed"}, "cf7": "2026-10-06T15:00:00.000+0000"})
    day_after = _ticket(3, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf3": APPROVER,
                        "cf4": "2026-10-07", "cf6": {"value": "Passed"}, "cf7": "2026-10-06T15:00:00.000+0000"})
    code, out, _, _ = run("change_requests", _cr_router([same_day, day_before, day_after]), {"JIRA_CHANGE_JQL": "project = CCB"})
    by_key = {t["key"]: t for t in out["tickets"]}
    assert by_key["CCB-1"]["approved_before_deploy"] is None and by_key["CCB-1"]["findings"] == []
    assert by_key["CCB-1"]["approval_order_granularity"] == "day"
    assert by_key["CCB-2"]["approved_before_deploy"] is True
    assert by_key["CCB-3"]["approved_before_deploy"] is False and "approved_after_deploy" in by_key["CCB-3"]["findings"]
    assert out["summary"]["changes_approval_order_unknown"] == 1
    assert out["summary"]["changes_approved_before_deploy"] == 1


def test_incident_date_only_detected_time_is_not_measurable_not_late(run):
    inc = _incident(1, {"cf10": {"value": "SEV 3"}, "cf11": {"value": "CAT 3"},
                        "cf12": "2026-10-05", "cf13": "2026-10-05T15:00:00.000+0000"}, cat="new")
    code, out, _, _ = run("incident_postmortems", _ir_router([inc]), {"JIRA_INCIDENT_JQL": "project = IR"})
    i = out["incidents"][0]
    assert i["minutes_to_report"] is None and i["findings"] == ["report_time_not_measurable"]
    assert out["summary"]["reported_late"] == 0 and out["summary"]["incidents_without_report_timing"] == 1


# ---------- third review round: a refused read is unknown, never a finding or a zero ----------

def test_change_requests_failed_history_makes_status_approval_unknown_not_a_finding(run):
    # Approval is a status move; the history read fails, so the approval is unknown.
    t = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf6": {"value": "Passed"}})
    pre = _ticket(2, "Change Request", "Done", "done", {"cf1": {"value": "Standard"}, "cf6": {"value": "Passed"}})
    ex = _ticket(3, "Configuration Exception", "Backlog", "new", {"cf8": "2099-01-01", "cf9": "2026-10-01"})

    def router(method, path, params, body):
        if path == "/rest/api/3/changelog/bulkfetch":
            return 503, {"errorMessages": ["down"]}
        return _cr_router([t, pre, ex])(method, path, params, body)

    env = {"JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_APPROVED_STATUSES": "Approved"}
    code, out, _, status = run("change_requests", router, env)
    by_key = {r["key"]: r for r in out["tickets"]}
    assert by_key["CCB-1"]["findings"] == [] and by_key["CCB-1"]["unknown"] == ["approval_unknown"]
    assert by_key["CCB-1"]["status_history_known"] is False and by_key["CCB-1"]["reopened"] is None
    assert by_key["CCB-2"]["unknown"] == [], "a pre-approved change needs no approval"
    assert by_key["CCB-3"]["findings"] == [] and by_key["CCB-3"]["unknown"] == ["approval_unknown"]
    assert out["summary"]["findings"] == {} and out["summary"]["unknown"] == {"approval_unknown": 2}
    assert out["summary"]["tickets_with_unknown_checks"] == 2
    assert out["metadata"]["status_history_complete"] is False
    assert code == 1 and status["code"] == "partial_failure"


def test_change_requests_history_times_are_compared_in_the_ticket_offset(run):
    # The approval date field is 2026-10-06; the deployment move happened at
    # 2026-10-05 20:00 -0700, which bulkfetch reports as epoch ms (03:00 UTC on the 6th).
    # Rendered in the ticket's own offset (-0700) it is the 5th: approval after deploy.
    t = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf3": APPROVER,
                "cf4": "2026-10-06", "cf6": {"value": "Passed"}})
    t["fields"]["created"] = "2026-10-01T00:00:00.000-0700"
    t["fields"]["resolutiondate"] = "2026-10-05T20:00:00.000-0700"
    epoch_ms = 1791255600000  # 2026-10-06T03:00:00Z
    hist = [{"issueId": "501", "changeHistories": [{"id": "h1", "created": epoch_ms, "author": {"displayName": "Dev"},
             "items": [{"fieldId": "status", "fromString": "In Progress", "from": "3", "toString": "Done", "to": "10001"}]}]}]
    code, out, _, _ = run("change_requests", _cr_router([t], hist), {"JIRA_CHANGE_JQL": "project = CCB"})
    r = out["tickets"][0]
    assert r["deployed_at"] == "2026-10-05T20:00:00.000-07:00"
    assert r["approved_before_deploy"] is False and "approved_after_deploy" in r["findings"]


def test_change_requests_capped_search_has_a_null_summary(run):
    tickets = [_ticket(i, "Change Request", "Done", "done", {"cf1": {"value": "Standard"}}) for i in range(1, 4)]
    code, out, _, status = run("change_requests", _cr_router(tickets), {"JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_MAX_ITEMS": "2"})
    assert out["metadata"]["items_truncated"] is True and out["metadata"]["items_collected"] == 2
    assert out["summary"]["total"] is None and out["summary"]["by_kind"] is None
    assert code == 1 and status["code"] == "partial_failure"


def test_change_requests_unexpected_shape_has_a_null_summary(run):
    bad = _ticket(1, "Change Request", "Done", "done", {})
    bad["fields"]["status"] = "Done"
    code, out, _, status = run("change_requests", _cr_router([bad]), {"JIRA_CHANGE_JQL": "project = CCB"})
    assert status["code"] == "internal_error" and out["summary"]["total"] is None


def test_incident_failed_history_makes_phases_unknown_not_missing(run):
    inc = _incident(1, {"cf10": {"value": "SEV 2"}, "cf11": {"value": "CAT 7"},
                        "cf12": "2026-10-05T12:00:00.000+0000", "cf13": "2026-10-05T12:30:00.000+0000",
                        "cf14": {"value": "Lessons Learned"}}, links=["IR-7"])
    pm = {"id": "707", "key": "IR-7", "fields": {"issuetype": {"name": "Post-mortem"}, "summary": "pm",
          "status": {"name": "Done"}, "created": "2026-10-06T00:00:00.000+0000", "subtasks": []}}

    def router(method, path, params, body):
        if path == "/rest/api/3/changelog/bulkfetch":
            return 503, {"errorMessages": ["down"]}
        if path == "/rest/api/3/issue/bulkfetch":
            return 200, {"issues": [pm], "issueErrors": []}
        return _ir_router([inc])(method, path, params, body)

    env = {"JIRA_INCIDENT_JQL": "project = IR", "JIRA_INCIDENT_REQUIRED_PHASES": "Identification,Containment,Lessons Learned"}
    code, out, _, status = run("incident_postmortems", router, env)
    i = out["incidents"][0]
    assert "phases_missing" not in i["findings"] and "phases_unknown" in i["unknown"]
    assert i["phases_missing"] is None and i["status_history_known"] is False
    assert out["summary"]["unknown"]["phases_unknown"] == 1
    assert code == 1 and status["code"] == "partial_failure"


def test_incident_capped_search_has_a_null_summary(run):
    incs = [_incident(n, {"cf10": {"value": "SEV 4"}}, cat="new") for n in range(1, 4)]
    code, out, _, status = run("incident_postmortems", _ir_router(incs), {"JIRA_INCIDENT_JQL": "project = IR", "JIRA_INCIDENT_MAX_ITEMS": "2"})
    assert out["metadata"]["incidents_truncated"] is True and out["summary"]["incidents"] is None
    assert code == 1 and status["code"] == "partial_failure"


def test_remediation_failed_history_makes_the_close_time_unknown_not_absent(run):
    done = _issue(1, "Done", "done", due="2026-01-10")  # no resolutiondate
    done["fields"]["issuelinks"] = []

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [done], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 503, {"errorMessages": ["down"]}
        raise AssertionError(path)

    code, out, _, status = run("remediation_items", router, {"JIRA_REMEDIATION_JQL": "project = OPS"})
    item = out["items"][0]
    assert item["closed_at"] is None and item["closed_at_source"] == "unknown"
    assert item["status_history_known"] is False and item["status_change_count"] is None
    assert out["summary"]["closed_without_close_time"] == 0
    assert out["summary"]["closed_close_time_unknown"] == 1
    assert out["summary"]["closed_after_due_date"] == 0
    assert code == 1 and status["code"] == "partial_failure"


def test_remediation_history_close_time_is_compared_in_the_ticket_offset(run):
    # Due 2026-01-05; closed 2026-01-05 20:00 -0700 (= 03:00Z on the 6th, as epoch ms).
    # In the ticket's own offset that is the due day, so it is not late.
    done = _issue(1, "Done", "done", due="2026-01-05")
    done["fields"]["created"] = "2026-01-01T00:00:00.000-0700"
    epoch_ms = 1767668400000  # 2026-01-06T03:00:00Z
    hist = {"id": "h1", "created": epoch_ms, "author": {"displayName": "Ann"},
            "items": [{"fieldId": "status", "fromString": "In Progress", "toString": "Done"}]}

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [done], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": [{"issueId": "101", "changeHistories": [hist]}]}
        raise AssertionError(path)

    code, out, _, _ = run("remediation_items", router, {"JIRA_REMEDIATION_JQL": "project = OPS"})
    item = out["items"][0]
    assert item["closed_at"] == "2026-01-05T20:00:00.000-07:00" and item["closed_at_source"] == "status_history"
    assert out["summary"]["closed_after_due_date"] == 0 and code == 0


def test_remediation_capped_search_and_bad_shape_have_null_summaries(run):
    def capped(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [_issue(i, "To Do", "new") for i in range(body["maxResults"])],
                         "nextPageToken": "more"}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    code, out, _, status = run("remediation_items", capped, {"JIRA_REMEDIATION_JQL": "x", "JIRA_REMEDIATION_MAX_ITEMS": "3"})
    assert out["metadata"]["items_truncated"] is True and out["summary"]["total"] is None

    bad = _issue(1, "Done", "done")
    bad["fields"]["issuelinks"] = [None]

    def odd(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [bad], "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    code, out, _, status = run("remediation_items", odd, {"JIRA_REMEDIATION_JQL": "x"})
    assert code == 1 and status["code"] == "internal_error"
    assert out["summary"]["total"] is None and out["metadata"]["complete"] is False


def test_audit_records_truncated_or_failed_later_page_has_a_null_summary(run):
    def truncated(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        start = params["offset"]
        batch = [{"id": i, "created": "2026-10-01T00:00:00.000+0000", "category": "permissions"}
                 for i in range(start, min(start + 1000, 2000))]
        return 200, {"offset": start, "limit": 1000, "total": 2000, "records": batch}

    code, out, _, _ = run("audit_records", truncated, {"JIRA_AUDIT_MAX_RECORDS": "1500"})
    assert out["metadata"]["records_collected"] == 1500 and out["summary"]["total"] is None

    def later_page_fails(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if params["offset"] == 0:
            batch = [{"id": i, "created": "2026-10-01T00:00:00.000+0000", "category": "permissions"} for i in range(1000)]
            return 200, {"offset": 0, "limit": 1000, "records": batch}  # no total key
        return 503, {"errorMessages": ["down"]}

    code, out, _, status = run("audit_records", later_page_fails)
    assert out["metadata"]["records_collected"] == 1000 and out["summary"]["total"] is None
    assert code == 1 and status["code"] == "partial_failure"

    def odd(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        return 200, {"offset": 0, "total": 1, "records": [None]}

    code, out, _, status = run("audit_records", odd)
    assert status["code"] == "internal_error" and out["summary"]["total"] is None


def test_access_roles_failed_role_read_nulls_the_project_section_only(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/project/CCB/role/10002":
            return 403, {"errorMessages": ["no permission"]}
        return _access_router(role_index_allowed=False)(method, path, params, body)

    code, out, _, status = run("access_roles", router)
    assert out["summary"]["admin_groups"] == 1 and out["summary"]["distinct_admin_users"] == 1
    assert out["summary"]["distinct_project_admin_users"] is None
    assert out["summary"]["privileged_users_per_project"] is None
    assert out["summary"]["projects_scanned"] is None
    assert out["projects"][0]["roles_read_completely"] is False
    assert out["metadata"]["projects_with_unread_roles"] == 1
    assert code == 1 and status["code"] == "not_authorized"


def test_access_roles_failed_role_index_nulls_the_project_section(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/project/CCB/role":
            return 503, {"errorMessages": ["down"]}
        return _access_router(role_index_allowed=True)(method, path, params, body)

    code, out, _, _ = run("access_roles", router, {"JIRA_ACCESS_ALL_ROLES": "true"})
    assert out["summary"]["distinct_project_admin_users"] is None and out["summary"]["admin_groups"] == 1


def test_access_roles_failed_project_group_membership_nulls_only_the_project_section(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/project/CCB/permissionscheme":
            return 200, {"id": 1, "name": "Default", "permissions": [
                {"permission": "ADMINISTER_PROJECTS", "holder": {"type": "group", "parameter": "proj-admins",
                                                                  "group": {"name": "proj-admins", "groupId": "g-proj"}}},
            ]}
        if path == "/rest/api/3/group/member" and params["groupId"] == "g-proj":
            return 503, {"errorMessages": ["down"]}
        return _access_router(role_index_allowed=False)(method, path, params, body)

    code, out, _, status = run("access_roles", router)
    assert out["summary"]["admin_groups"] == 1 and out["summary"]["distinct_admin_users"] == 1
    assert out["summary"]["distinct_project_admin_users"] is None
    assert out["metadata"]["groups_with_incomplete_membership"] == ["proj-admins"]
    assert code == 1 and status["code"] == "partial_failure"


def test_access_roles_failed_admin_group_membership_nulls_only_the_admin_section(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/group/member" and params["groupId"] == "g-adm":
            return 503, {"errorMessages": ["down"]}
        return _access_router(role_index_allowed=False)(method, path, params, body)

    code, out, _, _ = run("access_roles", router)
    assert out["summary"]["admin_groups"] is None and out["summary"]["distinct_admin_users"] is None
    assert out["summary"]["distinct_project_admin_users"] == 1 and out["summary"]["projects_scanned"] == 1


def test_access_roles_partly_listed_admin_groups_are_not_the_admin_population(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/group/bulk" and params.get("applicationKey") == "jira-software" and params["accessType"] == "admin":
            return 503, {"errorMessages": ["down"]}
        return _access_router(role_index_allowed=False)(method, path, params, body)

    code, out, _, status = run("access_roles", router)
    assert out["summary"]["admin_groups"] is None and out["summary"]["distinct_admin_users"] is None
    assert out["summary"]["projects_scanned"] == 1
    assert code == 1 and status["code"] == "partial_failure"

    def named_fails(method, path, params, body):
        if path == "/rest/api/3/group/bulk" and params.get("groupName") == "ops-admins":
            return 503, {"errorMessages": ["down"]}
        return _access_router(role_index_allowed=False)(method, path, params, body)

    code, out, _, _ = run("access_roles", named_fails, {"JIRA_ADMIN_GROUPS": "ops-admins"})
    assert out["summary"]["admin_groups"] is None


def test_access_roles_unexpected_shape_midway_nulls_both_sections(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/project/search":
            return 200, {"isLast": True, "values": [
                {"key": "P1", "name": "One", "projectTypeKey": "software", "lead": {}},
                {"key": "P2", "name": "Two", "projectTypeKey": "software", "lead": {}},
            ]}
        if path == "/rest/api/3/project/P1/permissionscheme":
            return 200, {"id": 1, "name": "Default", "permissions": []}
        if path == "/rest/api/3/project/P2/permissionscheme":
            return 200, ["not", "a", "scheme"]  # truthy, wrong shape
        return _access_router(role_index_allowed=False)(method, path, params, body)

    code, out, _, status = run("access_roles", router)
    assert status["code"] == "internal_error"
    assert out["summary"]["projects_scanned"] is None and out["summary"]["admin_groups"] is None
    assert [p["key"] for p in out["projects"]] == ["P1"]


def test_is_date_only_needs_a_real_date():
    import jira_common as jc
    assert jc.is_date_only("2026-10-05") is True
    assert jc.is_date_only("10/05/2026") is False
    assert jc.is_date_only("2026-10-05T00:00:00.000+0000") is False
    assert jc.in_offset_of(1791255600000, "2026-10-01T00:00:00.000-0700") == "2026-10-05T20:00:00.000-07:00"
    assert jc.in_offset_of("2026-10-06T03:00:00.000+0000", None) == "2026-10-06T03:00:00.000+00:00"
    assert jc.in_offset_of("garbage", "2026-10-01T00:00:00.000-0700") == "garbage"


def test_incident_unparseable_ten_character_time_is_unparseable_not_unmeasurable(run):
    inc = _incident(1, {"cf10": {"value": "SEV 3"}, "cf11": {"value": "CAT 3"},
                        "cf12": "10/05/2026", "cf13": "2026-10-05T15:00:00.000+0000"}, cat="new")
    code, out, _, _ = run("incident_postmortems", _ir_router([inc]), {"JIRA_INCIDENT_JQL": "project = IR"})
    assert out["incidents"][0]["findings"] == ["detected_or_reported_time_unparseable"]


def test_search_issues_stops_on_a_repeated_token(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [_issue(len([1]), "To Do", "new")], "nextPageToken": "t1"}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    code, out, calls, status = run("remediation_items", router, {"JIRA_REMEDIATION_JQL": "labels = x"})
    assert len([c for c in calls if c[1] == "/rest/api/3/search/jql"]) == 2
    assert out["metadata"]["api_failures"][0]["type"] == "BadPaging"
    assert out["metadata"]["items_collected"] == 2 and out["summary"]["total"] is None
