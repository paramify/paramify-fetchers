"""Offline tests for the jira_remediation_items due-date field and risk-accepted settings.

Uses the fake Jira session and helpers of test_jira_admin_and_remediation_fetchers.
Dates are far in the past or the future so the checks do not depend on today.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

_spec = importlib.util.spec_from_file_location(
    "jira_remediation_base", Path(__file__).with_name("test_jira_admin_and_remediation_fetchers.py")
)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
JIRA, ME, STATUS_LIST, _issue = base.JIRA, base.ME, base.STATUS_LIST, base._issue
run = base.run  # the fixture

JQL = {"JIRA_REMEDIATION_JQL": "project = OPS"}
TARGET = {"id": "customfield_500", "name": "Target date", "schema": {"type": "date"}}
FIELDS = [{"id": "duedate", "name": "Due date", "schema": {"type": "date"}}, TARGET]
PAST, FUTURE = "2020-01-15", "2999-01-15"


def _router(items, fields=(200, FIELDS), seen=None):
    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, {**ME, "timeZone": "America/Los_Angeles"}
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/field":
            return fields
        if path == "/rest/api/3/search/jql":
            if seen is not None:
                seen.append(body["fields"])
            return 200, {"issues": items, "isLast": True}
        if path == "/rest/api/3/changelog/bulkfetch":
            return 200, {"issueChangeLogs": []}
        raise AssertionError(path)

    return router


def _with(issue, **fields):
    issue["fields"].update(fields)
    return issue


def _schema_defaults() -> dict:
    """Every default the framework would export for this fetcher (see executor.merge config)."""
    schema = yaml.safe_load((JIRA / "remediation_items" / "fetcher.yaml").read_text())["config_schema"]
    return {spec["env"]: str(spec["default"]) for spec in schema.values() if spec.get("default") is not None}


def test_default_reads_the_builtin_due_date_and_leaves_the_new_checks_off(run):
    items = [_issue(1, "To Do", "new", due=PAST), _issue(2, "Done", "done", resolved="2020-01-11T00:00:00.000+0000")]
    seen = []
    code, out, calls, status = run("remediation_items", _router(items, seen=seen), JQL)
    assert code == 0 and status is None
    assert not any(c[1] == "/rest/api/3/field" for c in calls)
    assert "customfield_500" not in seen[0]
    m, s = out["metadata"], out["summary"]
    assert (m["due_date_field"], m["due_date_field_ids"], m["due_date_known"]) == ("duedate", ["duedate"], True)
    assert m["risk_accepted_statuses"] is None and m["risk_accepted_values_unmatched"] is None
    assert s["open_overdue"] == 1
    assert (s["risk_accepted"], s["closed_risk_accepted"], s["closed_excluding_risk_accepted"]) == (None, None, None)
    assert [i["risk_accepted"] for i in out["items"]] == [None, None]


@pytest.mark.parametrize("setting", ["Target date", "target DATE", "customfield_500"])
def test_configured_due_field_replaces_the_builtin_one(run, setting):
    items = [
        _with(_issue(1, "To Do", "new", due=FUTURE), customfield_500=PAST),  # overdue by the configured field only
        _with(_issue(2, "To Do", "new", due=PAST), customfield_500=FUTURE),  # overdue by the built-in field only
        _issue(3, "To Do", "new", due=PAST),  # the configured field is empty
    ]
    seen = []
    code, out, _, status = run(
        "remediation_items", _router(items, seen=seen), {**JQL, "JIRA_REMEDIATION_DUE_DATE_FIELD": setting}
    )
    assert code == 0 and status is None
    assert "customfield_500" in seen[0]
    assert [(i["due_date"], i["overdue"]) for i in out["items"]] == [(PAST, True), (FUTURE, False), (None, False)]
    s = out["summary"]
    assert (s["open_overdue"], s["open_without_due_date"], s["open_due_date_unparseable"]) == (1, 1, 0)
    assert out["metadata"]["due_date_field_ids"] == ["customfield_500"]


@pytest.mark.parametrize(
    "setting, fields, problem",
    [
        ("Target dat", (200, FIELDS), "unresolved"),
        ("customfield_999", (200, FIELDS), "unresolved"),
        ("Target date", (200, FIELDS + [{**TARGET, "id": "customfield_501"}]), "ambiguous"),
        ("Target date", (500, {"errorMessages": ["boom"]}), "unresolved"),
        ("Target date", (403, {"errorMessages": ["no"]}), "not_authorized"),
    ],
)
def test_unresolved_due_field_states_nothing_about_due_dates(run, setting, fields, problem):
    """The built-in duedate must not stand in for a field that was asked for and not found."""
    items = [_issue(1, "To Do", "new", due=PAST), _issue(2, "Done", "done", due=PAST, resolved="2021-01-01T00:00:00.000+0000")]
    code, out, _, status = run(
        "remediation_items", _router(items, fields), {**JQL, "JIRA_REMEDIATION_DUE_DATE_FIELD": setting}
    )
    assert code == 1 and status["code"] == ("not_authorized" if problem == "not_authorized" else "partial_failure")
    assert "JIRA_REMEDIATION_DUE_DATE_FIELD" in str(status) and "built-in Due date" in str(status)
    assert out["metadata"]["due_date_known"] is False and out["metadata"]["complete"] is False
    assert [(i["due_date"], i["overdue"], i["due_date_known"]) for i in out["items"]] == [(None, None, False)] * 2
    s = out["summary"]
    assert (s["open_overdue"], s["open_without_due_date"], s["closed_after_due_date"]) == (None, None, None)
    assert s["open_due_date_unparseable"] is None
    assert (s["total"], s["open"], s["closed"]) == (2, 1, 1)  # the counts that do not need a due date stay
    if problem == "ambiguous":
        assert {c["id"] for c in out["metadata"]["field_candidates"]["due_date"]} == {"customfield_500", "customfield_501"}


@pytest.mark.parametrize("setting", ["12345", "customfield_500, Target date"])
def test_due_field_setting_shapes(run, monkeypatch, tmp_path, setting):
    """A number or a mix of ids and names is looked up as a name and reported as not found."""
    code, out, _, status = run(
        "remediation_items", _router([_issue(1, "To Do", "new", due=PAST)]), {**JQL, "JIRA_REMEDIATION_DUE_DATE_FIELD": setting}
    )
    assert code == 1 and out["metadata"]["due_date_known"] is False and out["summary"]["open_overdue"] is None


def test_due_values_with_a_time_and_values_that_are_not_dates(run):
    done = "2020-03-10T09:00:00.000-0700"
    items = [
        _with(_issue(1, "To Do", "new"), customfield_500="2020-01-15T10:00:00.000-0800"),
        _with(_issue(2, "To Do", "new"), customfield_500="2999-01-15T10:00:00.000-0800"),
        _with(_issue(3, "To Do", "new"), customfield_500="next sprint"),
        _with(_issue(4, "Done", "done", resolved=done), customfield_500="2020-03-10"),  # closed on the due day
        _with(_issue(5, "Done", "done", resolved=done), customfield_500="2020-03-09"),
        _with(_issue(6, "Done", "done", resolved=done), customfield_500="2020-03-10T08:59:00.000-0700"),
        _with(_issue(7, "Done", "done", resolved=done), customfield_500="2020-03-10T09:01:00.000-0700"),
        _with(_issue(8, "Done", "done", resolved=done), customfield_500="soon"),
    ]
    code, out, _, status = run(
        "remediation_items", _router(items), {**JQL, "JIRA_REMEDIATION_DUE_DATE_FIELD": "customfield_500"}
    )
    assert code == 0 and status is None
    by = {i["key"]: i for i in out["items"]}
    assert [by[f"OPS-{n}"]["overdue"] for n in (1, 2, 3)] == [True, False, None]
    assert by["OPS-3"]["due_date"] == "next sprint" and by["OPS-3"]["due_date_unparseable"] is True
    s = out["summary"]
    assert (s["open_overdue"], s["open_without_due_date"], s["open_due_date_unparseable"]) == (1, 0, 1)
    assert s["closed_after_due_date"] == 2  # OPS-5 and OPS-6


def test_date_only_due_is_judged_in_the_collector_timezone(run, monkeypatch):
    """At 03:00 UTC on the 16th it is still the 15th in Los Angeles: a ticket due the 15th is not overdue."""
    from datetime import datetime, timezone

    base.load("remediation_items")  # puts the shared module on the path
    jira_common = sys.modules["jira_common"]

    for now, expected in ((datetime(2026, 5, 16, 3, tzinfo=timezone.utc), False), (datetime(2026, 5, 16, 8, tzinfo=timezone.utc), True)):
        monkeypatch.setattr(jira_common, "utc_now", lambda now=now: now)
        code, out, _, _ = run("remediation_items", _router([_issue(1, "To Do", "new", due="2026-05-15")]), JQL)
        assert code == 0 and out["items"][0]["overdue"] is expected


def test_risk_accepted_by_status_or_resolution_is_counted_apart(run):
    statuses = STATUS_LIST + [{"id": "9", "name": "Risk Accepted", "statusCategory": {"key": "done"}}]
    resolved = "2020-02-01T00:00:00.000+0000"
    items = [
        _issue(1, "Done", "done", resolved=resolved),
        _issue(2, "Risk Accepted", "done", resolved=resolved),
        _with(_issue(3, "Closed", "done", resolved=resolved), resolution={"name": "Accepted Risk"}),
        _with(_issue(4, "Closed", "done", resolved=resolved), resolution={"name": "Done"}),
        _issue(5, "To Do", "new"),
    ]

    def router(method, path, params, body):
        if path == "/rest/api/3/status":
            return 200, statuses
        return _router(items)(method, path, params, body)

    env = {
        **JQL,
        "JIRA_REMEDIATION_RISK_ACCEPTED_STATUSES": " risk accepted , Waived",
        "JIRA_REMEDIATION_RISK_ACCEPTED_RESOLUTIONS": "ACCEPTED RISK",
    }
    code, out, _, status = run("remediation_items", router, env)
    assert code == 0 and status is None
    assert [i["risk_accepted"] for i in out["items"]] == [False, True, True, False, False]
    s = out["summary"]
    assert (s["closed"], s["risk_accepted"], s["closed_risk_accepted"], s["closed_excluding_risk_accepted"]) == (4, 2, 2, 2)
    assert out["metadata"]["risk_accepted_values_unmatched"] == ["Waived"]
    assert out["metadata"]["risk_accepted_statuses"] == ["risk accepted", "Waived"]


def test_risk_accepted_status_only_does_not_match_resolutions_and_the_reverse(run):
    """A status setting is compared with statuses only, so a resolution of the same name is not flagged."""
    resolved = "2020-02-01T00:00:00.000+0000"
    items = [_with(_issue(1, "Closed", "done", resolved=resolved), resolution={"name": "Risk Accepted"})]
    code, out, _, _ = run("remediation_items", _router(items), {**JQL, "JIRA_REMEDIATION_RISK_ACCEPTED_STATUSES": "Risk Accepted"})
    assert out["items"][0]["risk_accepted"] is False and out["summary"]["closed_excluding_risk_accepted"] == 1
    code, out, _, _ = run("remediation_items", _router(items), {**JQL, "JIRA_REMEDIATION_RISK_ACCEPTED_RESOLUTIONS": "Risk Accepted"})
    assert out["items"][0]["risk_accepted"] is True and out["summary"]["closed_excluding_risk_accepted"] == 0


def test_risk_counts_are_null_when_the_search_did_not_finish(run):
    def router(method, path, params, body):
        if path == "/rest/api/3/search/jql":
            return 500, {"errorMessages": ["boom"]}
        return _router([])(method, path, params, body)

    env = {**JQL, "JIRA_REMEDIATION_RISK_ACCEPTED_STATUSES": "Risk Accepted", "JIRA_REMEDIATION_DUE_DATE_FIELD": "Target date"}
    code, out, _, status = run("remediation_items", router, env)
    assert code == 1
    s = out["summary"]
    assert (s["risk_accepted"], s["closed_excluding_risk_accepted"], s["open_overdue"], s["total"]) == (None,) * 4


@pytest.mark.parametrize(
    "extra",
    [
        {},
        {"JIRA_REMEDIATION_DUE_DATE_FIELD": "Target date"},
        {"JIRA_REMEDIATION_RISK_ACCEPTED_STATUSES": "Risk Accepted"},
        {"JIRA_REMEDIATION_DUE_DATE_FIELD": "", "JIRA_REMEDIATION_RISK_ACCEPTED_STATUSES": "", "JIRA_REMEDIATION_RISK_ACCEPTED_RESOLUTIONS": ""},
    ],
)
def test_runs_with_every_schema_default_exported_the_way_the_framework_does(run, extra):
    items = [_with(_issue(1, "To Do", "new", due=PAST), customfield_500=PAST)]
    code, out, _, status = run("remediation_items", _router(items), {**_schema_defaults(), **JQL, **extra})
    assert code == 0 and status is None and out["summary"]["open_overdue"] == 1


def test_new_settings_declare_no_default():
    """A default would be exported on every run and switch the setting on for everyone."""
    schema = yaml.safe_load((JIRA / "remediation_items" / "fetcher.yaml").read_text())["config_schema"]
    for name in ("due_date_field", "risk_accepted_statuses", "risk_accepted_resolutions"):
        assert "default" not in schema[name]
