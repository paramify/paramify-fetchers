"""Offline tests for jira_change_requests: who approved, the emergency approval exemption,
and notification tickets linked to a change.

Uses the fake Jira session and helpers of test_jira_admin_and_remediation_fetchers.
Due dates are far in the past or the future so the checks do not depend on today.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import requests
import yaml

_spec = importlib.util.spec_from_file_location(
    "jira_change_note_base", Path(__file__).with_name("test_jira_admin_and_remediation_fetchers.py")
)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
JIRA, ME, APPROVER, _ticket = base.JIRA, base.ME, base.APPROVER, base._ticket
run = base.run  # the fixture

FIELD_LIST = base.FIELD_LIST + [
    {"id": "cf20", "name": "Emergency", "custom": True},
    {"id": "cf21", "name": "Notification due", "custom": True},
    {"id": "cf22", "name": "Notification completion date", "custom": True},
]
STATUS_LIST = base.STATUS_LIST + [{"id": "8", "name": "Implemented", "statusCategory": {"key": "indeterminate"}}]
OFF = {"test_results": "", "security_review": "", "risk": "", "deployed_at": ""}
ENV = {"JIRA_CHANGE_JQL": "project = CCB", "JIRA_CHANGE_FIELDS": json.dumps(OFF)}
APPROVED = {"cf1": {"value": "Normal"}, "cf3": APPROVER, "cf4": "2026-10-02T00:00:00.000+0000"}
NOTE_ENV = {
    "JIRA_CHANGE_JQL": "project = CCB",
    "JIRA_CHANGE_FIELDS": json.dumps({**OFF, "notification_due": "Notification due", "notification_sent": "Notification completion date"}),
    "JIRA_CHANGE_NOTIFICATION_ISSUE_TYPES": "notification",
    "JIRA_CHANGE_NOTIFICATION_REQUIRED_TYPES": "Adaptive, transformative",
}
PAST, FUTURE = "2020-01-15", "2999-01-15"


def _router(tickets, histories=None, notes=None, note_fetch=None, note_history=None):
    notes = {n["key"]: n for n in notes or []}
    note_ids = {n["id"] for n in notes.values()}

    def router(method, path, params, body):
        if path == "/rest/api/3/myself":
            return 200, {**ME, "timeZone": "America/New_York"}
        if path == "/rest/api/3/field":
            return 200, FIELD_LIST
        if path == "/rest/api/3/status":
            return 200, STATUS_LIST
        if path == "/rest/api/3/search/jql":
            return 200, {"issues": tickets, "isLast": True}
        if path == "/rest/api/3/issue/bulkfetch":
            if note_fetch:
                return note_fetch
            return 200, {"issues": [notes[k] for k in body["issueIdsOrKeys"] if k in notes]}
        if path == "/rest/api/3/changelog/bulkfetch":
            asked = set(body["issueIdsOrKeys"])
            if note_history and asked <= note_ids:
                return note_history
            return 200, {"issueChangeLogs": [h for h in histories or [] if h["issueId"] in asked]}
        raise AssertionError(path)

    return router


def _hist(issue_id, moves, by="Dev"):
    """Status histories from (created, from, to) tuples."""
    return {"issueId": issue_id, "changeHistories": [
        {"id": f"{issue_id}-{n}", "created": at, "author": {"displayName": by},
         "items": [{"fieldId": "status", "fromString": a, "toString": b}]}
        for n, (at, a, b) in enumerate(moves)]}


def _link(key, itype="Notification", typed=True):
    other = {"key": key}
    if typed:
        other["fields"] = {"issuetype": {"name": itype}, "status": {"name": "x"}}
    return {"type": {"name": "Relates", "inward": "relates to", "outward": "relates to"}, "inwardIssue": other}


def _change(n, change_type, links=(), status="Done", cat="done", extra=None):
    f = {**APPROVED, "cf1": {"value": change_type}, "issuelinks": list(links), **(extra or {})}
    return _ticket(n, "Change Request", status, cat, f)


def _note(n, status="Done", cat="done", due=None, sent=None, resolved="2026-10-08T12:00:00.000+0000", resolution=None):
    return {"id": str(900 + n), "key": f"CCB-{90 + n}", "fields": {
        "summary": f"notify {n}", "issuetype": {"name": "Notification"},
        "status": {"name": status, "statusCategory": {"key": cat}}, "created": "2026-10-06T00:00:00.000+0000",
        "resolutiondate": resolved if cat == "done" else None, "resolution": {"name": resolution} if resolution else None,
        "labels": [], "cf21": due, "cf22": sent}}


# ---------- defaults and who approved ----------

def test_without_the_settings_the_new_checks_are_off_and_the_old_trail_check_still_runs(run):
    quiet = _ticket(1, "Change Request", "Done", "done", APPROVED, comments=0)
    code, out, calls, status = run("change_requests", _router([quiet]), ENV)
    assert code == 0 and status is None
    t, s, m = out["tickets"][0], out["summary"], out["metadata"]
    assert t["findings"] == ["deployed_without_notification_trail"] and t["exempted"] == []
    assert (t["notifications"], t["notification_required"], t["approval_exempt"]) == (None, None, None)
    assert (s["notifications"], s["exempted"]) == (None, {})
    assert (m["notification_issue_types"], m["notification_tickets_complete"], m["emergency_approval_exempt"]) == (None, None, False)
    assert not any(c.startswith("notification") for c in m["checks_disabled"])
    assert not any(c[1] == "/rest/api/3/issue/bulkfetch" for c in calls)


def test_approved_by_is_the_approver_field_or_whoever_made_the_approving_move(run):
    env = {**ENV, "JIRA_CHANGE_FIELDS": json.dumps({**OFF, "approver": "", "approved_at": ""}),
           "JIRA_CHANGE_APPROVED_STATUSES": "Approved", "JIRA_CHANGE_PREAPPROVED_TYPES": ""}
    by_move = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}})
    never = _ticket(2, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}})
    hist = [_hist("501", [("2026-10-02T00:00:00.000+0000", "Backlog", "Approved"),
                          ("2026-10-03T00:00:00.000+0000", "Approved", "Done")], by="Board Chair")]
    code, out, _, _ = run("change_requests", _router([by_move, never], hist), env)
    assert [(t["approval_source"], t["approved_by"]) for t in out["tickets"]] == [("status", "Board Chair"), (None, None)]
    code, out, _, _ = run("change_requests", _router([_ticket(3, "Change Request", "Done", "done", APPROVED)]), ENV)
    assert (out["tickets"][0]["approval_source"], out["tickets"][0]["approved_by"]) == ("fields", "CCB Chair")


# ---------- emergency approval exemption ----------

def _exempt_env(flag="true"):
    return {**ENV, "JIRA_CHANGE_FIELDS": json.dumps({**OFF, "emergency": "Emergency"}),
            "JIRA_CHANGE_EMERGENCY_VALUES": "Yes", "JIRA_CHANGE_EMERGENCY_APPROVAL_EXEMPT": flag}


def _exempt_tickets():
    yes, no = {"cf20": {"value": "Yes"}}, {"cf20": {"value": "No"}}
    late = {"cf1": {"value": "Normal"}, "cf3": APPROVER, "cf4": "2026-10-09T00:00:00.000+0000"}
    return [
        _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, **yes}),  # emergency, never approved
        _ticket(2, "Change Request", "Done", "done", {**late, **yes}),  # emergency, approved after deployment
        _ticket(3, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, **no}),  # not an emergency
        _ticket(4, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}}),  # emergency field empty
    ]


def test_exempt_emergency_changes_are_recorded_as_exempted_not_as_findings(run):
    code, out, _, status = run("change_requests", _router(_exempt_tickets()), _exempt_env())
    assert code == 0 and status is None
    t = out["tickets"]
    assert [(x["approval_exempt"], x["findings"], x["exempted"]) for x in t] == [
        (True, [], ["deployed_without_approval"]),
        (True, [], ["approved_after_deploy"]),
        (False, ["deployed_without_approval"], []),
        (False, ["deployed_without_approval"], []),
    ]
    s = out["summary"]
    assert s["findings"] == {"deployed_without_approval": 2}
    assert s["exempted"] == {"deployed_without_approval": 1, "approved_after_deploy": 1}
    e = s["emergency"]
    assert (e["total"], e["deployed_without_approval"], e["approved_after_deploy"]) == (2, 1, 1)
    assert e["findings"] == {} and e["exempted"] == {"deployed_without_approval": 1, "approved_after_deploy": 1}
    assert out["metadata"]["emergency_approval_exempt"] is True


@pytest.mark.parametrize("flag", ["false", "", "no", "0"])
def test_exemption_off_keeps_the_findings_on_emergency_changes(run, flag):
    code, out, _, _ = run("change_requests", _router(_exempt_tickets()), _exempt_env(flag))
    assert code == 0
    assert [x["findings"] for x in out["tickets"]][:2] == [["deployed_without_approval"], ["approved_after_deploy"]]
    assert all(x["exempted"] == [] and x["approval_exempt"] is None for x in out["tickets"])


def test_exemption_does_not_cover_a_change_whose_approval_could_not_be_read(run):
    """Unknown stays unknown: an emergency change with an unread history is not called exempt of a finding it may not have."""
    env = {**_exempt_env(), "JIRA_CHANGE_FIELDS": json.dumps({**OFF, "approver": "", "approved_at": "", "emergency": "Emergency"}),
           "JIRA_CHANGE_APPROVED_STATUSES": "Approved", "JIRA_CHANGE_PREAPPROVED_TYPES": ""}
    t = _ticket(1, "Change Request", "Done", "done", {"cf1": {"value": "Normal"}, "cf20": {"value": "Yes"}})

    def router(method, path, params, body):
        if path == "/rest/api/3/changelog/bulkfetch":
            return 500, {"errorMessages": ["boom"]}
        return _router([t])(method, path, params, body)

    code, out, _, status = run("change_requests", router, env)
    x = out["tickets"][0]
    assert code == 1 and (x["findings"], x["exempted"], x["unknown"]) == ([], [], ["approval_unknown"])


def _bad_config(monkeypatch, tmp_path, env):
    monkeypatch.setattr("time.sleep", lambda s: None)

    def fake(self, method, url, params=None, json=None, timeout=None, **kw):
        raise AssertionError("no call may be made with a refused configuration")

    monkeypatch.setattr(requests.Session, "request", fake)
    for k, v in {"JIRA_BASE_URL": "https://example.atlassian.net", "JIRA_EMAIL": "svc@example.com", "JIRA_API_TOKEN": "t",
                 "EVIDENCE_DIR": str(tmp_path), "FETCHER_STATUS_FILE": str(tmp_path / "status.json"), **env}.items():
        monkeypatch.setenv(k, v)
    assert base.load("change_requests").main() == 1
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["code"] == "bad_config"
    return str(status)


@pytest.mark.parametrize("env, names", [
    ({**ENV, "JIRA_CHANGE_EMERGENCY_APPROVAL_EXEMPT": "true"}, "JIRA_CHANGE_EMERGENCY_APPROVAL_EXEMPT"),
    ({**_exempt_env("maybe")}, "JIRA_CHANGE_EMERGENCY_APPROVAL_EXEMPT"),
    ({**ENV, "JIRA_CHANGE_NOTIFICATION_REQUIRED_TYPES": "Adaptive"}, "JIRA_CHANGE_NOTIFICATION_ISSUE_TYPES"),
    ({**ENV, "JIRA_CHANGE_FIELDS": json.dumps({**OFF, "notification_due": "Notification due"})}, "JIRA_CHANGE_NOTIFICATION_ISSUE_TYPES"),
    ({**NOTE_ENV, "JIRA_CHANGE_FIELDS": json.dumps({**OFF, "change_type": ""}), "JIRA_CHANGE_PREAPPROVED_TYPES": ""},
     "JIRA_CHANGE_NOTIFICATION_REQUIRED_TYPES"),
])
def test_settings_that_cannot_work_together_are_refused(monkeypatch, tmp_path, env, names):
    assert names in _bad_config(monkeypatch, tmp_path, env)


# ---------- notification tickets ----------

def test_linked_notification_tickets_are_read_and_replace_the_trail_check(run):
    tickets = [
        _change(1, "Adaptive", [_link("CCB-91")]),  # sent, date from the field
        _change(2, "Transformative", [_link("CCB-92"), _link("CCB-93")]),  # two notifications
        _change(3, "Adaptive"),  # deployed with none linked
        _change(4, "Routine", [_link("CCB-99", "Task")]),  # type that needs none; an unrelated link
        _change(5, "Adaptive", status="Backlog", cat="new"),  # not deployed yet
    ]
    for t in tickets:
        t["fields"]["comment"]["total"] = 0  # the old trail check would fire on every one
    notes = [
        _note(1, due=FUTURE, sent="2026-10-07"),
        _note(2, due=FUTURE),  # done, no sent field: time from the status history
        _note(3, "To Do", "new", due=FUTURE),
    ]
    hist = [_hist("902", [("2026-10-08T09:00:00.000+0000", "To Do", "Done")])]
    code, out, calls, status = run("change_requests", _router(tickets, hist, notes), NOTE_ENV)
    assert code == 0 and status is None
    t = {x["key"]: x for x in out["tickets"]}
    assert [t[f"CCB-{n}"]["findings"] for n in range(1, 6)] == [[], [], ["notification_missing"], [], []]
    assert [t[f"CCB-{n}"]["notification_required"] for n in range(1, 6)] == [True, True, True, False, True]
    n1 = t["CCB-1"]["notifications"][0]
    assert (n1["key"], n1["read"], n1["sent"], n1["sent_at"], n1["sent_at_source"], n1["relation"]) == (
        "CCB-91", True, True, "2026-10-07", "field", "relates to")
    assert (n1["due"], n1["overdue"], n1["sent_late"]) == (FUTURE, False, False)
    n2, n3 = t["CCB-2"]["notifications"]
    assert (n2["sent"], n2["sent_at_source"], n2["sent_at"][:19]) == (True, "status_history", "2026-10-08T05:00:00")
    assert (n3["sent"], n3["sent_at"], n3["overdue"], n3["sent_late"]) == (False, None, False, None)
    assert t["CCB-4"]["notifications"] == [] and t["CCB-3"]["notifications"] == []
    assert t["CCB-4"]["linked_issues"] == [{"relation": "relates to", "key": "CCB-99", "issue_type": "Task"}]
    n = out["summary"]["notifications"]
    assert (n["changes_requiring"], n["changes_requiring_with_notification"],
            n["changes_deployed_without_required_notification"]) == (4, 2, 1)
    assert (n["tickets"], n["tickets_not_read"], n["tickets_sent"], n["tickets_open"], n["tickets_overdue"]) == (3, 0, 2, 1, 0)
    m = out["metadata"]
    assert "deployed_without_notification_trail" in m["checks_disabled"]
    assert m["notification_tickets_complete"] is True and m["notification_required_change_types_unmatched"] == []
    fetch = [c for c in calls if c[1] == "/rest/api/3/issue/bulkfetch"]
    assert len(fetch) == 1 and fetch[0][3]["issueIdsOrKeys"] == ["CCB-91", "CCB-92", "CCB-93"]
    assert {"cf21", "cf22"} <= set(fetch[0][3]["fields"])


def test_overdue_late_and_cancelled_notifications(run):
    tickets = [_change(n, "Adaptive", [_link(f"CCB-9{n}")]) for n in range(1, 6)]
    notes = [
        _note(1, "To Do", "new", due=PAST),  # open past its due date
        _note(2, due="2026-10-07", sent="2026-10-09"),  # sent two days late
        _note(3, due="2026-10-08", sent="2026-10-08"),  # sent on the due day
        _note(4, resolution="Won't Do", due=PAST),  # cancelled: not sent, and not overdue
        _note(5, due="2026-10-08T12:00:00.000+0000", resolved="2026-10-08T12:00:01.000+0000"),  # a second late, by resolution
    ]
    code, out, _, status = run("change_requests", _router(tickets, None, notes), NOTE_ENV)
    assert code == 0 and status is None
    t = {x["key"]: x for x in out["tickets"]}
    assert [t[f"CCB-{n}"]["findings"] for n in range(1, 6)] == [
        ["notification_overdue"], ["notification_sent_late"], [], [], ["notification_sent_late"]]
    n4, n5 = t["CCB-4"]["notifications"][0], t["CCB-5"]["notifications"][0]
    assert (n4["cancelled"], n4["sent"], n4["overdue"], n4["sent_late"]) == (True, False, False, None)
    assert n5["sent_at_source"] == "resolutiondate"
    n = out["summary"]["notifications"]
    assert (n["tickets_sent"], n["tickets_open"], n["tickets_cancelled"], n["tickets_overdue"], n["tickets_sent_late"]) == (
        3, 1, 1, 1, 2)


def test_due_checks_are_off_without_the_due_field(run):
    env = {**NOTE_ENV, "JIRA_CHANGE_FIELDS": json.dumps(OFF)}
    code, out, _, status = run("change_requests", _router([_change(1, "Adaptive", [_link("CCB-91")])], None,
                                                           [_note(1, "To Do", "new", due=PAST)]), env)
    n = out["tickets"][0]["notifications"][0]
    assert code == 0 and status is None and out["tickets"][0]["findings"] == []
    assert (n["due"], n["overdue"], n["sent_late"], n["sent_field_value"]) == (None, None, None, None)
    assert {"notification_overdue", "notification_sent_late"} <= set(out["metadata"]["checks_disabled"])


def test_notification_missing_is_off_without_the_required_types(run):
    env = {k: v for k, v in NOTE_ENV.items() if k != "JIRA_CHANGE_NOTIFICATION_REQUIRED_TYPES"}
    code, out, _, status = run("change_requests", _router([_change(1, "Adaptive")]), env)
    t = out["tickets"][0]
    assert code == 0 and (t["findings"], t["notification_required"], t["notifications"]) == ([], None, [])
    assert "notification_missing" in out["metadata"]["checks_disabled"]
    assert out["summary"]["notifications"]["changes_requiring"] is None


@pytest.mark.parametrize("failure", [
    {"note_fetch": (500, {"errorMessages": ["boom"]})},
    {"note_fetch": (200, {"issues": []})},  # the linked ticket is hidden from the collector
])
def test_a_notification_that_could_not_be_read_is_unknown_never_missing_or_sent(run, failure):
    code, out, _, status = run("change_requests", _router([_change(1, "Adaptive", [_link("CCB-91")])], **failure), NOTE_ENV)
    t = out["tickets"][0]
    assert code == 1 and status["code"] == "partial_failure"
    assert (t["findings"], t["unknown"]) == ([], ["notifications_not_read"])
    assert t["notifications"] == [{"key": "CCB-91", "read": False, "relation": "relates to"}]
    assert out["metadata"]["notification_tickets_complete"] is False
    n = out["summary"]["notifications"]
    assert (n["tickets"], n["tickets_not_read"], n["tickets_sent"]) == (1, 1, 0)


def test_failed_notification_history_falls_back_to_the_resolution_date_and_is_partial(run):
    router = _router([_change(1, "Adaptive", [_link("CCB-91")])], None, [_note(1, due=FUTURE)],
                     note_history=(500, {"errorMessages": ["boom"]}))
    code, out, _, status = run("change_requests", router, NOTE_ENV)
    n = out["tickets"][0]["notifications"][0]
    assert code == 1 and status["code"] == "partial_failure"
    assert (n["sent"], n["sent_at_source"], n["status_history_known"]) == (True, "resolutiondate", False)


def test_a_link_with_no_issue_type_is_unknown_not_a_missing_notification(run):
    code, out, _, status = run("change_requests", _router([_change(1, "Adaptive", [_link("CCB-91", typed=False)])]), NOTE_ENV)
    t = out["tickets"][0]
    assert code == 0 and (t["findings"], t["unknown"]) == ([], ["notification_link_type_unknown"])


def test_one_notification_linked_to_two_changes_is_counted_once_and_exceptions_take_no_checks(run):
    tickets = [
        _change(1, "Adaptive", [_link("CCB-91")]),
        _change(2, "Adaptive", [_link("CCB-91")]),
        _ticket(3, "Configuration Exception", "Backlog", "new", {**APPROVED, "cf1": {"value": "Adaptive"},
                                                                 "issuelinks": [_link("CCB-91")]}),
    ]
    env = {**NOTE_ENV, "JIRA_CHANGE_FIELDS": json.dumps({**OFF, "exception_expiry": "", "last_reviewed": "",
                                                        "notification_due": "Notification due", "notification_sent": "Notification completion date"})}
    code, out, _, status = run("change_requests", _router(tickets, None, [_note(1, "To Do", "new", due=PAST)]), env)
    assert code == 0 and status is None
    t = out["tickets"]
    assert [x["findings"] for x in t] == [["notification_overdue"], ["notification_overdue"], []]
    assert (t[2]["notifications"], t[2]["notification_required"]) == (None, None)
    assert out["summary"]["notifications"]["tickets"] == 1 and out["summary"]["notifications"]["tickets_overdue"] == 1


def test_required_change_type_that_no_ticket_holds_is_named(run):
    code, out, _, _ = run("change_requests", _router([_change(1, "Adaptive", [_link("CCB-91")])], None, [_note(1)]), NOTE_ENV)
    assert out["metadata"]["notification_required_change_types_unmatched"] == ["transformative"]


# ---------- the framework exports every schema default ----------

def _schema():
    return yaml.safe_load((JIRA / "change_requests" / "fetcher.yaml").read_text())["config_schema"]


def test_new_settings_declare_no_default():
    for name in ("emergency_approval_exempt", "notification_issue_types", "notification_required_change_types"):
        assert "default" not in _schema()[name]


@pytest.mark.parametrize("extra", [{}, {"JIRA_CHANGE_EMERGENCY_APPROVAL_EXEMPT": ""}, NOTE_ENV])
def test_runs_with_every_schema_default_exported_the_way_the_framework_does(run, extra):
    defaults = {spec["env"]: str(spec["default"]) for spec in _schema().values() if spec.get("default") is not None}
    code, out, _, status = run("change_requests", _router([_change(1, "Adaptive", [_link("CCB-91")])], None, [_note(1)]),
                               {**defaults, **ENV, **extra})
    assert code == 0 and status is None and out["tickets"][0]["approved_by"] == "CCB Chair"
