"""Offline tests for jira_change_requests: deployment by status and the emergency breakdown.

Uses the fake Jira session and helpers of test_jira_admin_and_remediation_fetchers.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

_spec = importlib.util.spec_from_file_location(
    "jira_change_base", Path(__file__).with_name("test_jira_admin_and_remediation_fetchers.py")
)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
JIRA, ME, APPROVER, _ticket = base.JIRA, base.ME, base.APPROVER, base._ticket
run = base.run  # the fixture

EMERGENCY = {"id": "cf20", "name": "Emergency", "custom": True}
FIELD_LIST = base.FIELD_LIST + [EMERGENCY]
STATUS_LIST = base.STATUS_LIST + [{"id": "8", "name": "Implemented", "statusCategory": {"key": "indeterminate"}}]
# Approval by fields; the roles no ticket here uses are off so they raise no finding.
FIELDS = {"test_results": "", "security_review": "", "risk": "", "deployed_at": ""}
ENV = {"JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_FIELDS": json.dumps(FIELDS)}
DEPLOY = {**ENV, "JIRA_CHANGE_DEPLOYED_STATUSES": "implemented"}
APPROVED = {"cf1": {"value": "Normal"}, "cf3": APPROVER, "cf4": "2026-10-02T00:00:00.000+0000"}


def _router(tickets, histories=None, status=None, history=None):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, ME
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return status or (200, STATUS_LIST)
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": tickets, "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return history or (200, {"issueChangeLogs": histories or []})
        raise AssertionError(path)

    return router


def _hist(issue_id, moves):
    """Status histories from (created, from, to) tuples."""
    return {"issueId": issue_id, "changeHistories": [
        {"id": f"{issue_id}-{n}", "created": at, "author": {"displayName": "Dev"},
         "items": [{"fieldId": "status", "fromString": a, "toString": b}]}
        for n, (at, a, b) in enumerate(moves)]}


def _schema_defaults() -> dict:
    """Every default the framework exports for this fetcher on a run."""
    schema = yaml.safe_load((JIRA / "change_requests" / "fetcher.yaml").read_text())["config_schema"]
    return {spec["env"]: str(spec["default"]) for spec in schema.values() if spec.get("default") is not None}


def test_without_the_settings_nothing_changes_and_the_new_fields_are_null(run):
    tickets = [_ticket(1, "Change Request", "Done", "done", APPROVED), _ticket(2, "Change Request", "Backlog", "new", APPROVED)]
    code, out, calls, status = run("change_requests", _router(tickets), ENV)
    assert code == 0 and status is None
    s, m = out["summary"], out["metadata"]
    assert (s["changes_deployed"], s["changes_open"]) == (1, 1)
    assert (s["changes_closed_without_deployment"], s["emergency"], s["changes_deployment_unknown"]) == (None, None, 0)
    assert (m["deployed_statuses"], m["deployed_statuses_not_on_site"], m["emergency_values"]) == (None, None, None)
    assert m["emergency_values_unmatched"] is None
    assert [t["emergency"] for t in out["tickets"]] == [None, None]
    assert sum(1 for c in calls if c[1] == "/rest/api/3/status") == 1


def test_deployment_is_the_first_move_into_a_deployed_status(run):
    tickets = [
        _ticket(1, "Change Request", "Implemented", "indeterminate", APPROVED),  # deployed, still open in Jira
        _ticket(2, "Change Request", "Closed", "done", APPROVED),  # implemented, then closed days later
        _ticket(3, "Change Request", "Closed", "done", APPROVED),  # closed without ever being implemented
        _ticket(4, "Change Request", "Approved", "indeterminate", APPROVED),  # not deployed yet
        _ticket(5, "Change Request", "Closed", "done", {**APPROVED, "resolution": {"name": "Rejected"}}),
        _ticket(6, "Change Request", "Implemented", "indeterminate", {"cf1": {"value": "Normal"}}),  # no approval
    ]
    histories = [
        _hist("501", [("2026-10-03T00:00:00.000+00:00", "Approved", "Implemented")]),
        _hist("502", [("2026-10-01T12:00:00.000+00:00", "Approved", "Implemented"),
                      ("2026-10-09T00:00:00.000+00:00", "Implemented", "Closed")]),
        _hist("503", [("2026-10-04T00:00:00.000+00:00", "Approved", "Closed")]),
        _hist("506", [("2026-10-03T00:00:00.000+00:00", "Backlog", "Implemented")]),
    ]
    code, out, calls, status = run("change_requests", _router(tickets, histories), DEPLOY)
    assert code == 0 and status is None
    by = {t["key"]: t for t in out["tickets"]}
    assert [by[f"CCB-{n}"]["deployed"] for n in range(1, 7)] == [True, True, False, False, False, True]
    assert by["CCB-1"]["deployed_at"] == "2026-10-03T00:00:00.000+00:00" and by["CCB-1"]["approved_before_deploy"] is True
    # Deployed on the 1st, approved on the 2nd: the close on the 9th must not hide the late approval.
    assert by["CCB-2"]["deployed_at"] == "2026-10-01T12:00:00.000+00:00"
    assert by["CCB-2"]["findings"] == ["approved_after_deploy"]
    assert by["CCB-3"]["findings"] == [] and by["CCB-3"]["deployed_at"] is None
    assert by["CCB-6"]["findings"] == ["deployed_without_approval"]
    s = out["summary"]
    assert (s["changes_deployed"], s["changes_open"], s["changes_cancelled"]) == (3, 1, 1)
    assert (s["changes_closed_without_deployment"], s["changes_deployment_unknown"]) == (1, 0)
    assert out["metadata"]["deployed_statuses"] == ["implemented"]
    assert out["metadata"]["deployed_statuses_not_on_site"] == []


def test_a_change_implemented_twice_is_dated_at_the_first_time(run):
    """Deployed on the 1st, approved on the 2nd, rolled back and implemented again on the 5th: still approved late."""
    t = _ticket(1, "Change Request", "Implemented", "indeterminate", APPROVED)
    hist = [_hist("501", [("2026-10-05T00:00:00.000+00:00", "In Progress", "Implemented"),
                          ("2026-10-01T12:00:00.000+00:00", "Approved", "Implemented"),
                          ("2026-10-03T00:00:00.000+00:00", "Implemented", "In Progress")])]
    code, out, _, _ = run("change_requests", _router([t], hist), DEPLOY)
    rec = out["tickets"][0]
    assert rec["deployed_at"] == "2026-10-01T12:00:00.000+00:00" and rec["findings"] == ["approved_after_deploy"]


def test_deployed_status_with_no_move_on_record_is_deployed_at_an_unknown_time(run):
    t = _ticket(1, "Change Request", "Implemented", "indeterminate", APPROVED)
    code, out, _, status = run("change_requests", _router([t]), DEPLOY)
    assert code == 0 and status is None
    rec = out["tickets"][0]
    assert rec["deployed"] is True and rec["deployed_at"] is None and rec["approved_before_deploy"] is None
    assert rec["unknown"] == ["deployment_time_unknown"] and rec["findings"] == []
    assert out["summary"]["changes_approval_order_unknown"] == 1


def test_failed_history_makes_deployment_unknown_not_absent(run):
    tickets = [
        _ticket(1, "Change Request", "Closed", "done", APPROVED),  # may have passed through Implemented
        _ticket(2, "Change Request", "Implemented", "indeterminate", APPROVED),  # the status itself says deployed
    ]
    code, out, _, status = run(
        "change_requests", _router(tickets, history=(500, {"errorMessages": ["boom"]})), DEPLOY
    )
    assert code == 1 and status["code"] == "partial_failure"
    by = {t["key"]: t for t in out["tickets"]}
    assert by["CCB-1"]["deployed"] is None and by["CCB-1"]["unknown"] == ["deployment_unknown"]
    assert by["CCB-1"]["findings"] == []
    assert by["CCB-2"]["deployed"] is True and by["CCB-2"]["unknown"] == ["deployment_time_unknown"]
    s = out["summary"]
    assert (s["changes_deployed"], s["changes_deployment_unknown"]) == (1, 1)
    assert (s["changes_open"], s["changes_closed_without_deployment"]) == (0, 0)


@pytest.mark.parametrize("status", [(200, STATUS_LIST), (500, {"errorMessages": ["boom"]})])
def test_a_deployed_status_that_is_not_on_the_site_fails_the_run(run, status):
    """A mistyped status would report every change as not deployed, with no finding."""
    t = _ticket(1, "Change Request", "Implemented", "indeterminate", APPROVED)
    env = {**ENV, "JIRA_CHANGE_DEPLOYED_STATUSES": "Implemented,Implmented"}
    code, out, _, st = run("change_requests", _router([t], status=status), env)
    assert code == 1 and st["code"] == "partial_failure"
    if status[0] == 200:
        assert out["metadata"]["deployed_statuses_not_on_site"] == ["implmented"]
        assert "JIRA_CHANGE_DEPLOYED_STATUSES names no status" in str(st)
    else:
        assert out["metadata"]["deployed_statuses_not_on_site"] is None  # not checked, and the run says it failed


def test_exceptions_are_not_changes_and_take_no_deployment_marks(run):
    ex = _ticket(1, "Configuration Exception", "Implemented", "indeterminate", {**APPROVED, "cf8": "2099-01-01", "cf9": "2099-01-01"})
    code, out, _, _ = run("change_requests", _router([ex], history=(500, {"errorMessages": ["boom"]})), DEPLOY)
    rec = out["tickets"][0]
    assert rec["deployed"] is False and rec["unknown"] == [] and out["summary"]["changes_deployment_unknown"] == 0


def _emergency_env(**fields):
    return {**ENV, "JIRA_CHANGE_FIELDS": json.dumps({**FIELDS, "emergency": "Emergency", **fields}),
            "JIRA_CHANGE_EMERGENCY_VALUES": "yes"}


def test_emergency_changes_are_flagged_and_summarized_on_their_own(run):
    yes, no = {"cf20": {"value": "Yes"}}, {"cf20": {"value": "No"}}
    late = {"cf1": {"value": "Normal"}, "cf3": APPROVER, "cf4": "2026-10-09T00:00:00.000+0000"}
    tickets = [
        _ticket(1, "Change Request", "Done", "done", {**late, **yes}),  # emergency, approved after deployment
        _ticket(2, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, **yes}),  # emergency, no approval
        _ticket(3, "Change Request", "Backlog", "new", {**APPROVED, "cf20": [{"value": "Yes"}]}),  # checkbox shape
        _ticket(4, "Change Request", "Done", "done", {**late, **no}),
        _ticket(5, "Change Request", "Done", "done", APPROVED),  # field empty
    ]
    code, out, _, status = run("change_requests", _router(tickets), _emergency_env())
    assert code == 0 and status is None
    assert [t["emergency"] for t in out["tickets"]] == [True, True, True, False, False]
    e = out["summary"]["emergency"]
    assert (e["total"], e["deployed"], e["open"]) == (3, 2, 1)
    assert (e["deployed_with_approval"], e["approved_after_deploy"], e["deployed_without_approval"]) == (1, 1, 1)
    assert e["keys"] == ["CCB-1", "CCB-2", "CCB-3"]
    assert e["findings"] == {"approved_after_deploy": 1, "deployed_without_approval": 1}
    # The findings are the same for every change: an emergency one is not excused.
    assert out["summary"]["findings"]["approved_after_deploy"] == 2
    assert out["metadata"]["emergency_values_unmatched"] == []


def test_emergency_value_that_no_ticket_holds_is_named(run):
    t = _ticket(1, "Change Request", "Done", "done", {**APPROVED, "cf20": {"value": "True"}})
    code, out, _, status = run("change_requests", _router([t]), _emergency_env())
    assert code == 0 and out["tickets"][0]["emergency"] is False
    assert out["metadata"]["emergency_values_unmatched"] == ["yes"] and out["summary"]["emergency"]["total"] == 0


@pytest.mark.parametrize(
    "env",
    [
        {**ENV, "JIRA_CHANGE_EMERGENCY_VALUES": "Yes"},  # values with no field
        {**ENV, "JIRA_CHANGE_FIELDS": json.dumps({**FIELDS, "emergency": "Emergency"})},  # field with no values
        {**ENV, "JIRA_CHANGE_FIELDS": json.dumps({**FIELDS, "emergency": ""}), "JIRA_CHANGE_EMERGENCY_VALUES": "Yes"},
        {**ENV, "JIRA_CHANGE_FIELDS": json.dumps({**FIELDS, "emergency": 5}), "JIRA_CHANGE_EMERGENCY_VALUES": "Yes"},
    ],
)
def test_emergency_field_and_values_must_be_set_together(monkeypatch, tmp_path, env):
    for k, v in {"JIRA_BASE_URL": "https://example.atlassian.net", "JIRA_EMAIL": "svc@example.com",
                 "JIRA_API_TOKEN": "t", "EVIDENCE_DIR": str(tmp_path),
                 "FETCHER_STATUS_FILE": str(tmp_path / "status.json"), **env}.items():
        monkeypatch.setenv(k, v)
    assert base.load("change_requests").main() == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"


def test_emergency_field_left_empty_is_off(run):
    t = _ticket(1, "Change Request", "Done", "done", APPROVED)
    env = {**ENV, "JIRA_CHANGE_FIELDS": json.dumps({**FIELDS, "emergency": ""})}
    code, out, _, status = run("change_requests", _router([t]), env)
    assert code == 0 and status is None and out["summary"]["emergency"] is None
    assert "emergency" not in out["metadata"]["field_names"]


def test_unresolved_emergency_field_gives_no_emergency_counts(run):
    t = _ticket(1, "Change Request", "Done", "done", {**APPROVED, "cf20": {"value": "Yes"}})
    code, out, _, status = run("change_requests", _router([t]), _emergency_env(emergency="Emergncy"))
    assert code == 1 and status["code"] == "partial_failure"
    assert out["tickets"][0]["emergency"] is None and out["summary"]["emergency"] is None
    assert out["metadata"]["field_problems"]["emergency"] == "unresolved"


def test_summary_is_null_when_the_search_did_not_finish(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/search/jql":
            return 500, {"errorMessages": ["boom"]}
        return _router([])(method, path, params, body)

    env = {**_emergency_env(), "JIRA_CHANGE_DEPLOYED_STATUSES": "Implemented"}
    code, out, _, _ = run("change_requests", router, env)
    s = out["summary"]
    assert code == 1 and s["changes_closed_without_deployment"] is None and s["changes_deployment_unknown"] is None
    assert s["emergency"] is None or all(v is None for v in s["emergency"].values())


@pytest.mark.parametrize("extra", [{}, {"JIRA_CHANGE_DEPLOYED_STATUSES": "Implemented"}, {"JIRA_CHANGE_DEPLOYED_STATUSES": ""}])
def test_runs_with_every_schema_default_exported_the_way_the_framework_does(run, extra):
    t = _ticket(1, "Change Request", "Implemented", "indeterminate", APPROVED)
    hist = [_hist("501", [("2026-10-03T00:00:00.000+00:00", "Approved", "Implemented")])]
    code, out, _, status = run("change_requests", _router([t], hist), {**_schema_defaults(), **ENV, **extra})
    assert code == 0 and status is None
    assert out["summary"]["changes_deployed"] == (1 if extra.get("JIRA_CHANGE_DEPLOYED_STATUSES") else 0)
    code, out, _, status = run("change_requests", _router([t], hist), {**_schema_defaults(), **_emergency_env(), **extra})
    assert code == 0 and status is None and out["summary"]["emergency"]["total"] == 0


def test_new_settings_declare_no_default():
    schema = yaml.safe_load((JIRA / "change_requests" / "fetcher.yaml").read_text())["config_schema"]
    for name in ("deployed_statuses", "emergency_values"):
        assert "default" not in schema[name]
