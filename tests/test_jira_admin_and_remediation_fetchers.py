"""Offline tests for jira_remediation_items, jira_audit_records and jira_access_roles.

A fake requests.Session answers each call from a routing table shaped like the
Jira Cloud REST v3 responses (field names taken from the published OpenAPI spec),
so these check parsing, paging, rollups and failure reporting, not the live API.
"""

from __future__ import annotations

import importlib.util
import json
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

        def fake_request(self, method, url, params=None, json=None, timeout=None):
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
            hist = {"id": "h1", "created": "2026-01-05T00:00:00.000+0000", "author": {"displayName": "Ann"},
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
                "changedValues": [{"fieldName": "email", "changedFrom": "a", "changedTo": "b"}]}

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
    assert out["summary"]["oldest_record"].startswith("2026-10-01")
    assert out["records"][0]["changed_values"][0] == {"field": "email", "from": "a", "to": "b"}
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
