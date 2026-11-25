"""Offline tests for how jira_site_inventory reports service desks that are outside the
selection, not visible to the collector, or declared out of scope.

Uses the fake Jira session of test_jira_admin_and_remediation_fetchers.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

_spec = importlib.util.spec_from_file_location(
    "jira_inventory_base", Path(__file__).with_name("test_jira_admin_and_remediation_fetchers.py")
)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
JIRA, ME = base.JIRA, base.ME
run = base.run  # the fixture

DESK_API = "/rest/servicedeskapi/servicedesk"


def _project(i, key, name, kind="software"):
    return {"id": str(i), "key": key, "name": name, "projectTypeKey": kind, "lead": {"displayName": "Lead"},
            "issueTypes": [{"id": "1", "name": "Task"}]}


SOFT = [_project(1, "CHG", "Change Board"), _project(2, "INC", "Incident Board")]
HELP = _project(3, "HELP", "Help Desk", "service_desk")
DESK = {"id": "9", "projectKey": "HELP", "projectName": "Help Desk"}


def _router(projects, desks=None):
    def router(method, path, params, body):
        if path == "/rest/api/3/serverInfo":
            return 200, {"baseUrl": "https://example.atlassian.net", "deploymentType": "Cloud", "version": "1001.0.0"}
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/project/search":
            return 200, {"isLast": True, "values": projects}
        if path == "/rest/api/3/issuetype":
            return 200, [{"id": "1", "name": "Task", "subtask": False}]
        if path == "/rest/api/3/priority/search":
            return 200, {"isLast": True, "values": [{"id": "3", "name": "Medium", "isDefault": True}]}
        if path == "/rest/api/3/status" or path.endswith("/statuses"):
            st = {"id": "1", "name": "To Do", "statusCategory": {"key": "new"}}
            return 200, ([{"name": "Task", "statuses": [st]}] if path.endswith("/statuses") else [st])
        if path == DESK_API:
            if isinstance(desks, tuple):
                return desks
            return (200, {"isLastPage": True, "values": desks}) if desks is not None else (404, {})
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": [], "isLast": True}
        raise AssertionError(path)

    return router


def _called(calls):
    return DESK_API in [p for _, p, _, _ in calls]


def test_no_service_desk_visible_and_none_declared_is_not_available(run):
    code, out, calls, status = run("site_inventory", _router(SOFT))
    sm = out["service_management"]
    assert code == 0 and status is None and not _called(calls)
    assert sm == {"available": False, "basis": "no_service_desk_project_visible", "service_desks": [],
                  "service_desks_left_out": 0, "declared_out_of_scope": None}


def test_service_desk_outside_the_selection_is_left_out_not_absent(run):
    """Before, a JIRA_PROJECTS selection with no service desk in it reported the site as having none."""
    code, out, calls, status = run("site_inventory", _router(SOFT + [HELP], [DESK]), {"JIRA_PROJECTS": "CHG,INC"})
    sm = out["service_management"]
    assert code == 0 and status is None and _called(calls)
    assert (sm["available"], sm["basis"], sm["service_desks"], sm["service_desks_left_out"]) == (True, "service_desk_api", [], 1)
    assert [p["key"] for p in out["projects"]] == ["CHG", "INC"] and out["summary"]["service_desks"] == 0


def test_declared_desks_the_account_cannot_see_leave_availability_unstated(run):
    env = {"JIRA_PROJECTS": "CHG,INC", "JIRA_OUT_OF_SCOPE_SERVICE_DESKS": " SD1 , Second Desk, SD1"}
    code, out, calls, status = run("site_inventory", _router(SOFT), env)
    sm = out["service_management"]
    assert code == 0 and status is None and not _called(calls)
    assert (sm["available"], sm["basis"], sm["service_desks"]) == (None, "declared_not_visible", [])
    assert sm["declared_out_of_scope"] == [
        {"name": "SD1", "source": "configuration", "visible_to_collector": False, "project_key": None, "project_type": None},
        {"name": "Second Desk", "source": "configuration", "visible_to_collector": False, "project_key": None,
         "project_type": None},
    ]
    assert out["metadata"]["partial_failure"] is False and out["metadata"]["complete"] is True


@pytest.mark.parametrize("named", ["HELP", "help desk"])
def test_declared_desk_that_is_visible_but_outside_the_selection(run, named):
    env = {"JIRA_PROJECTS": "CHG,INC", "JIRA_OUT_OF_SCOPE_SERVICE_DESKS": named}
    code, out, _, status = run("site_inventory", _router(SOFT + [HELP], [DESK]), env)
    sm = out["service_management"]
    assert code == 0 and status is None
    assert (sm["available"], sm["basis"], sm["service_desks_left_out"]) == (True, "service_desk_api", 1)
    assert sm["declared_out_of_scope"] == [
        {"name": named, "source": "configuration", "visible_to_collector": True, "project_key": "HELP",
         "project_type": "service_desk"}
    ]


@pytest.mark.parametrize("env", [
    {"JIRA_OUT_OF_SCOPE_SERVICE_DESKS": "HELP"},  # no selection: every visible project is collected
    {"JIRA_PROJECTS": "CHG,HELP", "JIRA_OUT_OF_SCOPE_SERVICE_DESKS": "Help Desk"},
])
def test_a_project_cannot_be_collected_and_out_of_scope(monkeypatch, tmp_path, env):
    import json

    import requests

    monkeypatch.setattr("time.sleep", lambda s: None)
    router = _router(SOFT + [HELP], [DESK])

    def fake(self, method, url, params=None, json=None, timeout=None, **kw):
        status, body = router(method, url.split(".atlassian.net", 1)[1], params or {}, json or {})
        return base.FakeResponse(status, body)

    monkeypatch.setattr(requests.Session, "request", fake)
    for k, v in {"JIRA_BASE_URL": "https://example.atlassian.net", "JIRA_EMAIL": "svc@example.com", "JIRA_API_TOKEN": "t",
                 "EVIDENCE_DIR": str(tmp_path), "FETCHER_STATUS_FILE": str(tmp_path / "status.json"), **env}.items():
        monkeypatch.setenv(k, v)
    assert base.load("site_inventory").main() == 1
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["code"] == "bad_config" and "JIRA_OUT_OF_SCOPE_SERVICE_DESKS" in str(status)
    assert not (tmp_path / "jira_site_inventory.json").exists()


def test_failed_service_desk_read_is_unknown_not_absent(run):
    code, out, _, status = run("site_inventory", _router(SOFT + [HELP], (500, {"errorMessages": ["boom"]})),
                               {"JIRA_OUT_OF_SCOPE_SERVICE_DESKS": "SD1", "JIRA_PROJECTS": "CHG"})
    sm = out["service_management"]
    assert code == 1 and status["code"] == "partial_failure"
    assert (sm["available"], sm["basis"], sm["service_desks"], sm["service_desks_left_out"]) == (None, "unknown", None, None)
    assert sm["declared_out_of_scope"][0]["visible_to_collector"] is False


def test_declared_setting_has_no_default_and_runs_with_the_schema_defaults_exported(run):
    schema = yaml.safe_load((JIRA / "site_inventory" / "fetcher.yaml").read_text())["config_schema"]
    assert "default" not in schema["out_of_scope_service_desks"]
    defaults = {spec["env"]: str(spec["default"]) for spec in schema.values() if spec.get("default") is not None}
    code, out, _, status = run("site_inventory", _router(SOFT), {**defaults, "JIRA_OUT_OF_SCOPE_SERVICE_DESKS": ""})
    assert code == 0 and status is None and out["service_management"]["declared_out_of_scope"] is None
