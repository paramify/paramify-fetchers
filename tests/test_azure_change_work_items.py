"""azure_change_work_items, on fake azure_change_provenance and azure_devops_work_items evidence.

Each test writes the two inputs' envelopes and the runner's index to tmp_path and
calls the comparator's check through the shared reader, or its main() for what
reaches the file and the status file.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPARATOR = REPO_ROOT / "comparators" / "azure" / "change_work_items" / "fetcher.py"
spec = importlib.util.spec_from_file_location("azure_change_work_items_under_test", COMPARATOR)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
ci = sys.modules["comparator_inputs"]

SERVICE = "11111111-2222-3333-4444-555555555555"  # a service that manages resources for the customer
APP = "99999999-8888-7777-6666-555555555555"
ALICE, BOB = "alice@contoso.com", "bob@contoso.com"
RG = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers"
NIC = f"{RG}/Microsoft.Network/networkInterfaces/nic-1"
SITE = f"{RG}/Microsoft.Web/sites/app-1"
WINDOW = {"start": "2026-08-01T00:00:00Z", "end": "2026-10-28T00:00:00Z", "lookback_days": 90}


def change(cid, at, by=ALICE, by_type="User", origin="direct", target=SITE, client="Azure Portal"):
    return {"change_id": cid, "timestamp": at, "changed_by": by, "changed_by_type": by_type, "origin": origin,
            "target_resource_id": target, "operation": "Microsoft.Web/sites/write", "client_type": client}


def who(login):
    return {"display_name": login.split("@")[0].title(), "login": login}


def item(wid, created="2026-10-01T09:00:00Z", assigned=ALICE, type_="Task", state="Done", open_=False,
         closed="2026-10-03T17:00:00Z", approval=None, approval_read=True, history=None, **extra):
    category = {"Done": "Completed", "Removed": "Removed", "Doing": "InProgress"}.get(state)
    return {"id": wid, "project": "web", "type": type_, "state": state, "state_category": category, "open": open_,
            "created_date": created, "closed_date": closed, "resolved_date": None, "changed_date": closed or created,
            "assigned_to": who(assigned) if assigned else None, "created_by": None, "changed_by": None,
            "resolved_by": None, "closed_by": None, "state_history": history or [],
            "approval": approval, "approval_read": approval_read, **extra}


def approved(by=BOB, at="2026-10-01T10:00:00Z"):
    return {"at": at, "by": who(by), "source": "comment", "state": None}


def envelope(path: Path, name, results, partial=False, target=None) -> str:
    path.write_text(json.dumps({"schema_version": "1.0",
                                "metadata": {"fetcher_name": name, "run_id": "r1", "status": "success",
                                             "target": target},
                                "payload": {"metadata": {"partial_failure": partial}, "results": results,
                                            "summary": {}}}))
    return str(path)


def inv(path, target=None):
    return {"target": target, "status": "success", "exit_code": 0, "error": None, "error_code": None,
            "files": [path]}


def index(tmp_path, changes, items, *, types=("Task", "Hotfix"), window=WINDOW, partial=False,
          change_files=None, work_items_in_manifest=True) -> Path:
    change_invs = change_files or [inv(envelope(tmp_path / "changes.json", mod.CHANGES, {"changes": changes}))]
    work = envelope(tmp_path / "work.json", mod.WORK_ITEMS,
                    {"window": window, "selection": {"work_item_types": list(types)}, "work_items": items},
                    partial=partial, target={"organization_url": "https://dev.azure.com/contoso"})
    path = tmp_path / "index.json"
    path.write_text(json.dumps({"run_id": "r1", "inputs": {
        mod.CHANGES: {"in_manifest": True, "invocations": change_invs},
        mod.WORK_ITEMS: {"in_manifest": work_items_in_manifest,
                         "invocations": [inv(work)] if work_items_in_manifest else []},
    }}))
    return path


def compare(tmp_path, monkeypatch, changes, items, env=None, **kw):
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    results, summary = mod.check_with(mod.settings())(ci.load_inputs(index(tmp_path, changes, items, **kw)))
    return {r["change_id"]: r for r in results}, summary


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for env in ("CHANGE_RECORD_ORIGINS", "CHANGE_RECORD_EXCLUDED_CALLERS", "CHANGE_RECORD_ENVIRONMENTS",
                "CHANGE_RECORD_TYPES", "CHANGE_RECORD_PEOPLE", "CHANGE_RECORD_HOURS_BEFORE",
                "CHANGE_RECORD_HOURS_AFTER"):
        monkeypatch.delenv(env, raising=False)


def test_every_status_and_the_counts_a_validator_reads(tmp_path, monkeypatch):
    changes = [
        change("matched", "2026-10-02T12:00:00Z"),
        change("ambiguous", "2026-10-12T12:00:00Z", by=BOB),
        change("unmatched", "2026-10-20T12:00:00Z"),
        change("excluded", "2026-10-02T12:00:00Z", by=SERVICE, by_type="Application", target=NIC),
        change("not_a_person", "2026-10-02T12:00:00Z", by=APP, by_type="Application", client=".NET SDK"),
        change("no_caller", "2026-10-02T12:00:00Z", by="Unspecified", by_type="Unspecified",
               target=f"{RG}/Microsoft.Web/serverfarms/plan-1"),
        change("deployment", "2026-10-02T12:00:00Z", origin="deployment"),
    ]
    items = [
        item(1, approval=approved()),
        item(2, assigned=BOB, created="2026-10-10T09:00:00Z", closed="2026-10-14T09:00:00Z"),
        item(3, assigned=BOB, type_="Hotfix", created="2026-10-11T09:00:00Z", closed="2026-10-13T09:00:00Z",
             approval=approved(ALICE)),
    ]
    results, summary = compare(tmp_path, monkeypatch, changes, items, env={"CHANGE_RECORD_EXCLUDED_CALLERS": SERVICE})

    assert {cid: r["status"] for cid, r in results.items()} == {s: s for s in mod.STATUSES}
    assert results["matched"]["work_items"] == [{
        "organization": "https://dev.azure.com/contoso", "project": "web", "id": 1, "type": "Task",
        "state": "Done", "approved": True, "approved_at": "2026-10-01T10:00:00Z"}]
    assert results["matched"]["approved"] is True
    assert [w["id"] for w in results["ambiguous"]["work_items"]] == [2, 3]
    assert results["ambiguous"]["approved"] is False  # one of the two candidates was never approved
    assert results["unmatched"]["work_items"] == [] and results["unmatched"]["approved"] is None
    assert summary == {
        "changes_checked": 6, "changes_excluded": 1, "changes_needing_record": 5,
        "changes_matched": 1, "changes_ambiguous": 1, "changes_unmatched": 1, "changes_not_by_a_person": 1,
        "changes_without_caller": 1, "changes_recorded": 2, "changes_without_record": 3,
        "changes_without_approved_record": 4, "percent_recorded": 40,
        "changes_without_record_by_caller": {APP: 1, ALICE: 1, "unknown": 1},
        "changes_excluded_by_caller": {SERVICE: 1},
        "record_types": ["hotfix", "task"], "record_types_not_selected": [], "record_work_items": 3,
        "work_items_cover_changes": True,
    }


def test_a_callerless_row_takes_its_caller_from_the_same_resource(tmp_path, monkeypatch):
    changes = [
        change("named", "2026-10-02T12:00:00Z", by=SERVICE, by_type="Application", target=NIC),
        # Same resource id in another case, 9 minutes later: the service's own change, so excluded too.
        change("system", "2026-10-02T12:09:00Z", by="System", by_type="System", target=NIC.upper()),
        change("too_late", "2026-10-02T12:11:00Z", by="System", by_type="System", target=NIC),
        change("user_partner", "2026-10-02T13:00:00Z", target=SITE),
        change("empty", "2026-10-02T13:05:00Z", by="", by_type="", target=SITE),
    ]
    results, summary = compare(tmp_path, monkeypatch, changes, [item(1)],
                               env={"CHANGE_RECORD_EXCLUDED_CALLERS": SERVICE.upper()})
    assert (results["system"]["status"], results["system"]["caller"], results["system"]["caller_from"]) == \
        ("excluded", SERVICE, "same_resource")
    assert results["too_late"]["status"] == "no_caller" and results["too_late"]["caller"] is None
    assert (results["empty"]["status"], results["empty"]["caller"]) == ("matched", ALICE)
    assert summary["changes_excluded_by_caller"] == {SERVICE: 2}


@pytest.mark.parametrize(("at", "status"), [
    ("2026-09-30T09:00:00Z", "matched"),     # 24 hours before the item was created
    ("2026-09-30T08:59:59Z", "unmatched"),
    ("2026-10-04T17:00:00Z", "matched"),     # 24 hours after it was closed
    ("2026-10-04T17:00:01Z", "unmatched"),
])
def test_the_window_runs_from_hours_before_creation_to_hours_after_finishing(tmp_path, monkeypatch, at, status):
    results, _ = compare(tmp_path, monkeypatch, [change("c", at)], [item(1)])
    assert results["c"]["status"] == status


def test_the_window_hours_come_from_config(tmp_path, monkeypatch):
    env = {"CHANGE_RECORD_HOURS_BEFORE": "0", "CHANGE_RECORD_HOURS_AFTER": "72"}
    results, _ = compare(tmp_path, monkeypatch, [change("before", "2026-10-01T08:00:00Z"),
                                                 change("after", "2026-10-06T16:00:00Z")], [item(1)], env=env)
    assert (results["before"]["status"], results["after"]["status"]) == ("unmatched", "matched")


def test_an_open_item_or_one_in_an_unknown_state_covers_every_later_change(tmp_path, monkeypatch):
    items = [item(1, state="Doing", open_=True, closed=None),
             item(2, assigned=BOB, state="Initial scoping", open_=None, closed=None)]
    results, _ = compare(tmp_path, monkeypatch, [change("a", "2026-10-27T00:00:00Z"),
                                                 change("b", "2026-10-27T00:00:00Z", by=BOB)], items)
    assert results["a"]["status"] == results["b"]["status"] == "matched"


def test_a_finished_item_without_a_closed_date_ends_when_it_entered_its_state(tmp_path, monkeypatch):
    history = [{"at": "2026-10-01T09:00:00Z", "to": "To Do", "by": who(ALICE)},
               {"at": "2026-10-02T09:00:00Z", "to": "Done", "by": who(ALICE)}]
    results, _ = compare(tmp_path, monkeypatch, [change("c", "2026-10-03T10:00:00Z")],
                         [item(1, closed=None, history=history, changed_date="2026-10-20T00:00:00Z")])
    assert results["c"]["status"] == "unmatched"


def test_removed_items_and_other_types_never_record_a_change(tmp_path, monkeypatch):
    items = [item(1, state="Removed"), item(2, type_="Bug"), item(3, assigned=None)]
    results, summary = compare(tmp_path, monkeypatch, [change("c", "2026-10-02T12:00:00Z")], items)
    assert results["c"]["status"] == "unmatched" and summary["record_work_items"] == 1


@pytest.mark.parametrize(("people", "status"), [
    (None, "matched"),                     # the default includes state_history
    ("assigned_to", "unmatched"),
    ("approver", "matched"),
    ("assigned_to,changed_by", "unmatched"),
])
def test_which_people_count_comes_from_config(tmp_path, monkeypatch, people, status):
    history = [{"at": "2026-10-01T09:00:00Z", "to": "Done", "by": who(ALICE)}]
    env = {"CHANGE_RECORD_PEOPLE": people} if people else {}
    results, _ = compare(tmp_path, monkeypatch, [change("c", "2026-10-02T12:00:00Z")],
                         [item(1, assigned=BOB, history=history, approval=approved(ALICE))], env=env)
    assert results["c"]["status"] == status


def test_logins_match_without_regard_to_case(tmp_path, monkeypatch):
    results, _ = compare(tmp_path, monkeypatch, [change("c", "2026-10-02T12:00:00Z", by=ALICE.upper())], [item(1)])
    assert results["c"]["status"] == "matched"


def test_record_types_default_to_the_fetchers_selection_and_config_overrides_them(tmp_path, monkeypatch):
    items = [item(1, type_="Change Request")]
    results, summary = compare(tmp_path, monkeypatch, [change("c", "2026-10-02T12:00:00Z")], items,
                               types=("Change Request",))
    assert results["c"]["status"] == "matched" and summary["record_types"] == ["change request"]

    results, summary = compare(tmp_path, monkeypatch, [change("c", "2026-10-02T12:00:00Z")], items,
                               types=("Change Request",), env={"CHANGE_RECORD_TYPES": "Hotfix"})
    assert results["c"]["status"] == "unmatched"
    assert summary["record_types"] == ["hotfix"] and summary["record_types_not_selected"] == ["hotfix"]


def test_origins_come_from_config(tmp_path, monkeypatch):
    changes = [change("direct", "2026-10-02T12:00:00Z"), change("manual", "2026-10-02T12:00:00Z",
                                                                origin="manual_deployment")]
    results, summary = compare(tmp_path, monkeypatch, changes, [item(1)],
                               env={"CHANGE_RECORD_ORIGINS": "direct,manual_deployment"})
    assert set(results) == {"direct", "manual"} and summary["changes_checked"] == 2


def test_environments_pick_which_change_targets_are_checked(tmp_path, monkeypatch):
    files = [inv(envelope(tmp_path / f"{env}.json", mod.CHANGES, {"changes": [change(env, "2026-10-02T12:00:00Z")]},
                          target={"environment": env}), {"environment": env}) for env in ("prod", "test")]
    results, _ = compare(tmp_path, monkeypatch, [], [item(1)], change_files=files,
                         env={"CHANGE_RECORD_ENVIRONMENTS": "PROD"})
    assert set(results) == {"prod"}


def test_work_items_that_start_too_late_do_not_cover_the_changes(tmp_path, monkeypatch):
    window = {**WINDOW, "start": "2026-10-02T00:00:00Z"}
    _, summary = compare(tmp_path, monkeypatch, [change("c", "2026-10-02T12:00:00Z")], [item(1)], window=window)
    assert summary["work_items_cover_changes"] is False


def test_an_unread_approval_is_not_counted_as_approved(tmp_path, monkeypatch):
    results, summary = compare(tmp_path, monkeypatch, [change("c", "2026-10-02T12:00:00Z")],
                               [item(1, approval=None, approval_read=False)])
    assert results["c"]["work_items"][0]["approved"] is None and results["c"]["approved"] is False
    assert summary["changes_without_approved_record"] == 1


def test_nothing_to_check_reads_zero_not_null(tmp_path, monkeypatch):
    _, summary = compare(tmp_path, monkeypatch, [], [])
    assert summary["changes_needing_record"] == 0 and summary["percent_recorded"] == 0
    assert summary["work_items_cover_changes"] is True


# --------------------------------------------------------------------------- #
# main(): the file, the status file and the shared input policy
# --------------------------------------------------------------------------- #


@pytest.fixture
def run_env(tmp_path, monkeypatch):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))

    def written():
        status = tmp_path / "status.json"
        out = tmp_path / "evidence" / mod.OUTPUT
        return (json.loads(out.read_text()) if out.exists() else None,
                json.loads(status.read_text()) if status.exists() else None)
    return written


def test_main_writes_the_verdicts(tmp_path, monkeypatch, run_env):
    monkeypatch.setenv(ci.INPUTS_ENV, str(index(tmp_path, [change("c", "2026-10-02T12:00:00Z")], [item(1)])))
    assert mod.main() == 0
    payload, status = run_env()
    assert status is None and payload["summary"]["changes_matched"] == 1 and payload["summary"]["inputs_complete"]


def test_a_partial_input_is_compared_and_reported_as_input_failed(tmp_path, monkeypatch, run_env):
    monkeypatch.setenv(ci.INPUTS_ENV, str(index(tmp_path, [change("c", "2026-10-02T12:00:00Z")], [item(1)],
                                                partial=True)))
    assert mod.main() == 1
    payload, status = run_env()
    assert payload["summary"]["changes_matched"] == 1 and payload["summary"]["inputs_complete"] is False
    assert status["code"] == "input_failed" and mod.WORK_ITEMS in status["error"]


def test_a_missing_input_nulls_every_count(tmp_path, monkeypatch, run_env):
    monkeypatch.setenv(ci.INPUTS_ENV, str(index(tmp_path, [change("c", "2026-10-02T12:00:00Z")], [],
                                                work_items_in_manifest=False)))
    assert mod.main() == 1
    payload, status = run_env()
    assert payload["results"] == [] and set(payload["summary"]) == {*mod.SUMMARY_KEYS, "inputs_complete"}
    assert all(payload["summary"][k] is None for k in mod.SUMMARY_KEYS)
    assert status["code"] == "input_failed"


def _staged_input(root: Path, short: str, results) -> None:
    d = root / "fetchers" / "azure" / short
    d.mkdir(parents=True)
    (d / "fetcher.yaml").write_text(
        f"name: azure_{short}\nversion: 0.1.0\ndescription: d\ncategory: azure\n"
        "runtime:\n  type: python\n  entry: fetcher.py\n"
        f"output:\n  type: json\n  path: azure_{short}.json\nsecrets: []\n"
        f"evidence_set:\n  reference_id: EVD-{short.upper()}\n  name: {short}\n")
    body = json.dumps({"metadata": {"partial_failure": False, "api_failures": []}, "results": results})
    (d / "fetcher.py").write_text(
        f"import os, pathlib\npathlib.Path(os.environ['EVIDENCE_DIR'], 'azure_{short}.json').write_text({body!r})\n")


def test_the_runner_runs_it_after_its_inputs_with_its_entrys_config(tmp_path):
    from framework import api

    for sub in ("framework/schemas", "fetchers/_lib", "comparators/_lib", "comparators/azure/change_work_items"):
        shutil.copytree(REPO_ROOT / sub, tmp_path / sub)
    _staged_input(tmp_path, "change_provenance", {"changes": [
        change("person", "2026-10-02T12:00:00Z"),
        change("service", "2026-10-02T12:00:00Z", by=SERVICE, by_type="Application", target=NIC)]})
    _staged_input(tmp_path, "devops_work_items", {"window": WINDOW, "selection": {"work_item_types": ["Task"]},
                                                  "work_items": [item(1)]})
    m = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [
        {"use": "azure_change_work_items", "config": {"excluded_callers": SERVICE}},
        {"use": mod.CHANGES}, {"use": mod.WORK_ITEMS}]}}

    assert api.validate(m, tmp_path) == []
    summary = api.run(m, tmp_path)
    assert summary["ok"], summary
    out = json.loads((Path(summary["run_dir"]) / mod.OUTPUT).read_text())
    assert [i["fetcher_name"] for i in out["metadata"]["inputs"]] == [mod.CHANGES, mod.WORK_ITEMS]
    assert {r["change_id"]: r["status"] for r in out["payload"]["results"]} == {"person": "matched",
                                                                                 "service": "excluded"}
    assert out["payload"]["summary"]["inputs_complete"] is True


@pytest.mark.parametrize(("env", "value", "message"), [
    ("CHANGE_RECORD_PEOPLE", "assigned_to,owner", "['owner']"),
    ("CHANGE_RECORD_PEOPLE", " , ", "nothing"),
    ("CHANGE_RECORD_HOURS_BEFORE", "-1", "whole number"),
    ("CHANGE_RECORD_HOURS_AFTER", "a day", "whole number"),
])
def test_a_bad_setting_is_bad_config(tmp_path, monkeypatch, run_env, env, value, message):
    monkeypatch.setenv(ci.INPUTS_ENV, str(index(tmp_path, [], [])))
    monkeypatch.setenv(env, value)
    assert mod.main() == 1
    payload, status = run_env()
    assert payload is None and status["code"] == "bad_config" and env in status["error"] and message in status["error"]
