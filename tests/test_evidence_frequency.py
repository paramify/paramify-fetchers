"""Evidence set frequency: where it comes from, and how sync changes a set that exists."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework import api
from framework.paramify.client import Client
from framework.paramify.resources import Reader, Resources
from framework.runner.manifest_loader import parse_manifest, schema_errors
from framework.sync import engine
from framework.sync.model import UNKNOWN, Outcome, Plan, SyncContext
from framework.sync.providers.desired import (
    desired_from_run,
    resolve_frequency,
    settings_notes,
)
from framework.sync.providers.evidence_sets import (
    EvidenceFrequencyProvider,
    group_by_reference,
)
from framework.sync.render import confirm_lines, render_outcomes
from framework.sync.upload import manifest_notes
from framework.tui.screens.paramify_events import upload_event_lines
from tests.test_api_upload_engine import fake, no_env, root, two_files  # noqa: F401 — fixtures
from tests.test_provider_evidence_sets import (
    FakeParamify,
    entry,
    observed_set,
    provider,
)
from tests.test_sync_desired import build, env, inv

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---- precedence --------------------------------------------------------------

def test_first_set_source_wins():
    assert resolve_frequency("WEEKLY") == ("WEEKLY", "fetcher")
    assert resolve_frequency(None) == ("THREE_DAY", "fetcher")
    assert resolve_frequency("WEEKLY", schedule_every="DAILY") == ("DAILY", "schedule")
    assert resolve_frequency("WEEKLY", upload_default="MONTHLY", schedule_every="DAILY") == (
        "MONTHLY", "upload.yaml defaults")
    assert resolve_frequency("WEEKLY", fetcher_override="ANNUAL", upload_default="MONTHLY") == (
        "ANNUAL", "upload.yaml")
    assert resolve_frequency("WEEKLY", entry="BIWEEKLY", fetcher_override="ANNUAL") == ("BIWEEKLY", "entry")


def _run(tmp_path, *, paramify=None, schedule=None):
    body = env(ref="EVD-X")
    body["metadata"]["evidence_set"]["frequency"] = "WEEKLY"
    build(tmp_path, {"a.json": body}, [inv("x", ["a.json"])], paramify or {"x": {"use": "x"}})
    if schedule is not None:
        meta = json.loads((tmp_path / "_run_metadata.json").read_text())
        meta["schedule"] = schedule
        (tmp_path / "_run_metadata.json").write_text(json.dumps(meta))


@pytest.mark.parametrize("upload_cfg, paramify, schedule, want", [
    ({}, None, None, ("WEEKLY", "fetcher")),
    ({}, None, {"every": "DAILY", "at": "02:00"}, ("DAILY", "schedule")),
    ({"defaults": {"frequency": "MONTHLY"}}, None, {"every": "DAILY"}, ("MONTHLY", "upload.yaml defaults")),
    ({"overrides": {"x": {"frequency": "ANNUAL"}}, "defaults": {"frequency": "MONTHLY"}}, None, None,
     ("ANNUAL", "upload.yaml")),
    ({"overrides": {"x": {"frequency": "ANNUAL"}}}, {"x": {"use": "x", "frequency": "BIWEEKLY"}},
     {"every": "DAILY"}, ("BIWEEKLY", "entry")),
])
def test_desired_resolves_the_frequency(tmp_path, upload_cfg, paramify, schedule, want):
    _run(tmp_path, paramify=paramify, schedule=schedule)
    [e] = desired_from_run(tmp_path, upload_cfg)
    assert (e.evidence_set["frequency"], e.frequency_source) == want


# ---- the evidence_sets and evidence_frequency providers ---------------------------

def _seen(frequency="THREE_DAY"):
    seen = observed_set()
    return type(seen)(**{**seen.__dict__, "frequency": frequency})


def _chosen(key="e", frequency="DAILY", source="schedule", problem=None):
    e = entry(key, frequency=frequency)
    return type(e)(**{**e.__dict__, "frequency_source": source, "frequency_problem": problem})


def test_a_chosen_frequency_updates_a_set_that_exists():
    sets = group_by_reference([_chosen()])
    noop, _tag = provider().diff(sets, {"EVD-A": _seen()})
    assert noop.verb == "noop" and noop.id == "evidence_sets/EVD-A"  # what delivery and tags name
    [update] = EvidenceFrequencyProvider().diff(sets, {"EVD-A": _seen()})
    assert update.verb == "update" and update.id == "evidence_frequency/EVD-A"
    assert update.summary == "EVD-A: frequency every 3 days → daily"
    assert update.payload == {"id": "ev-9", "body": {"frequency": "DAILY"}}
    assert confirm_lines(Plan([update])) == ["~ EVD-A: frequency every 3 days → daily"]


def test_the_fetchers_default_never_changes_a_set():
    sets = group_by_reference([entry(frequency="THREE_DAY")])
    assert EvidenceFrequencyProvider().diff(sets, {"EVD-A": _seen("DAILY")}) == []


def test_frequency_runs_after_delivery():
    assert EvidenceFrequencyProvider.runs_after == ("delivery",)


def test_entries_sharing_a_set_get_the_shortest_chosen_frequency():
    a = _chosen("a", "WEEKLY", "entry")
    b = _chosen("b", "DAILY", "entry")
    c = entry("c", frequency="THREE_DAY")  # the fetcher's default: not a choice
    [rec] = group_by_reference([c, a, b])
    assert rec.frequency == "DAILY" and rec.frequency_explicit


@pytest.mark.parametrize("order", [0, 1])
def test_a_written_frequency_beats_another_entrys_schedule(order):
    written = _chosen("a", "WEEKLY", "upload.yaml")
    scheduled = _chosen("b", "DAILY", "schedule")
    [rec] = group_by_reference([written, scheduled] if order == 0 else [scheduled, written])
    assert rec.frequency == "WEEKLY" and rec.frequency_explicit


def _plan_apply(fp, entries):
    res = Resources(Client("t", "https://api.example.test", session=fp.session))
    p = EvidenceFrequencyProvider()
    p.desired = lambda ctx: group_by_reference(entries)  # type: ignore[method-assign]
    pl = engine.plan([p], SyncContext(None, {}), Reader(res))
    return pl, engine.apply(pl, [p], res)


def test_apply_patches_the_frequency():
    fp = FakeParamify()
    ev = fp.add_evidence("EVD-A", channels=[fp.add_stack("s").id], name="Set A", frequency="THREE_DAY")
    plan, outs = _plan_apply(fp, [_chosen()])
    assert plan.actions[0].verb == "update"
    assert outs[0].status == "applied" and outs[0].result["id"] == ev.id
    assert ("PATCH", f"/evidence/{ev.id}") in [c[:2] for c in fp.calls]
    assert next(r for r in fp._evidence if r["id"] == ev.id)["frequency"] == "DAILY"


def test_a_key_that_cant_edit_sets_skips_the_change_with_a_warning():
    fp = FakeParamify()
    fp.add_evidence("EVD-A", name="Set A", frequency="THREE_DAY")
    fp.fail_route("PATCH", r"/evidence/.*", 403, "Missing Write Evidences")
    _, [out] = _plan_apply(fp, [_chosen()])
    assert out.status == "noop" and out.result["state"] == "warning"
    assert out.message == "Couldn't change EVD-A's frequency to daily: this key can't edit evidence sets."
    assert render_outcomes([out]) == [f"warning evidence_frequency/EVD-A: {out.message}"]


@pytest.mark.parametrize("status", [400, 404])
def test_any_other_refused_change_is_a_failure(status):
    fp = FakeParamify()
    fp.add_evidence("EVD-A", name="Set A", frequency="THREE_DAY")
    fp.fail_route("PATCH", r"/evidence/.*", status, "nope")
    _, [out] = _plan_apply(fp, [_chosen()])
    assert out.status == "failed" and out.message.startswith("Couldn't change EVD-A's frequency to daily: ")
    assert render_outcomes([out])[0].startswith("failed evidence_frequency/EVD-A: Couldn't change")


def test_an_unknown_set_plans_no_change():
    assert EvidenceFrequencyProvider().diff(group_by_reference([_chosen()]), {"EVD-A": UNKNOWN}) == []


def _scheduled_run(tmp_path, every="DAILY", paramify=None):
    run = two_files(tmp_path, paramify)
    meta = json.loads((run / "_run_metadata.json").read_text())
    meta["schedule"] = {"every": every, "at": "02:00"}
    (run / "_run_metadata.json").write_text(json.dumps(meta))
    return run


def test_upload_delivers_then_changes_the_frequency(fake, root, tmp_path):  # noqa: F811
    st = fake.add_stack("Prod")
    ev = fake.add_evidence("EVD-X", channels=[st.id], name="Set X", frequency="THREE_DAY")
    run = _scheduled_run(tmp_path)
    plan = api.plan_upload(run, root, online=True)
    assert "~ EVD-X: frequency every 3 days → daily" in confirm_lines(plan)
    ids = [a.id for a in plan.actions]
    assert ids.index("evidence_frequency/EVD-X") > max(i for i, a in enumerate(ids) if a.startswith("delivery/"))
    out = api.upload_run(run, root)
    assert out["uploaded"] == 2 and out["ok"]
    # The PATCH comes after every write delivery made (the batch, its files, its submit).
    writes = [c[:2] for c in fake.calls if c[0] in ("POST", "PATCH", "PUT")]
    assert writes[-1] == ("PATCH", f"/evidence/{ev.id}"), writes
    assert next(r for r in fake._evidence if r["id"] == ev.id)["frequency"] == "DAILY"
    # The next upload has nothing to change.
    assert not [x for x in confirm_lines(api.plan_upload(run, root, online=True)) if x.startswith("~")]


def test_upload_says_when_the_key_cant_change_the_frequency(fake, root, tmp_path):  # noqa: F811
    st = fake.add_stack("Prod")
    fake.add_evidence("EVD-X", channels=[st.id], name="Set X", frequency="THREE_DAY")
    fake.fail_route("PATCH", r"/evidence/.*", 403, "Missing Write Evidences")
    events: list = []
    out = api.upload_run(_scheduled_run(tmp_path), root, on_event=events.append)
    assert out["uploaded"] == 2 and out["ok"] and out["errors"] == 0
    lines = render_outcomes([Outcome(**o) for o in out["outcomes"]])
    assert lines[-1] == ("warning evidence_frequency/EVD-X: Couldn't change EVD-X's frequency "
                         "to daily: this key can't edit evidence sets."), lines
    assert lines[0].startswith("delivered x"), lines
    tui = [str(t) for ev in events for t in upload_event_lines(ev, "file")]
    assert "  [WARN] Couldn't change EVD-X's frequency to daily: this key can't edit evidence sets." in tui


def test_upload_fails_a_change_paramify_refuses_but_keeps_the_files(fake, root, tmp_path):  # noqa: F811
    st = fake.add_stack("Prod")
    fake.add_evidence("EVD-X", channels=[st.id], name="Set X", frequency="THREE_DAY")
    fake.fail_route("PATCH", r"/evidence/.*", 400, "bad frequency")
    events: list = []
    out = api.upload_run(_scheduled_run(tmp_path), root, on_event=events.append)
    assert out["uploaded"] == 2 and out["entries"]["x"]["state"] == "delivered"
    assert out["ok"] is False and out["errors"] == 1
    tui = [str(t) for ev in events for t in upload_event_lines(ev, "file")]
    assert any(t.startswith("  [FAIL] Couldn't change EVD-X's frequency to daily: ") for t in tui), tui


def test_a_refused_delivery_leaves_the_frequency_alone(fake, root, tmp_path):  # noqa: F811
    st1, st2 = fake.add_stack("Prod"), fake.add_stack("Gov")
    fake.add_evidence("EVD-X", channels=[st1.id, st2.id], name="Set X", frequency="THREE_DAY")
    out = api.upload_run(_scheduled_run(tmp_path), root)  # two channels and no stack: refused
    assert out["entries"]["x"]["state"] == "refused"
    assert not [a for a in out["plan"]["actions"] if a["provider"] == "evidence_frequency"]
    assert not [c for c in fake.calls if c[0] == "PATCH"]


# ---- upload.yaml values ------------------------------------------------------------

def test_upload_yaml_values_are_upper_cased(tmp_path):
    _run(tmp_path)
    [e] = desired_from_run(tmp_path, {"defaults": {"frequency": "daily"}})
    assert (e.evidence_set["frequency"], e.frequency_source, e.frequency_problem) == (
        "DAILY", "upload.yaml defaults", None)


@pytest.mark.parametrize("upload_cfg, where", [
    ({"defaults": {"frequency": "dayly"}}, "defaults.frequency: dayly"),
    ({"overrides": {"x": {"frequency": "hourly"}}}, "overrides.x.frequency: hourly"),
])
def test_a_bad_upload_yaml_value_is_a_problem(tmp_path, upload_cfg, where):
    _run(tmp_path)
    [e] = desired_from_run(tmp_path, upload_cfg)
    assert e.frequency_problem == (f"upload.yaml sets {where}, which isn't a frequency; use one of "
                                   "NOT_SET, DAILY, THREE_DAY, WEEKLY, BIWEEKLY, MONTHLY, QUARTERLY, BIANNUAL, ANNUAL")


def _bad_config(tmp_path):
    path = tmp_path / "upload.yaml"
    path.write_text("defaults:\n  frequency: dayly\n")
    return path


def test_a_bad_upload_yaml_value_refuses_a_new_set_and_sends_nothing(fake, root, tmp_path):  # noqa: F811
    run, config = two_files(tmp_path), _bad_config(tmp_path)
    lines = confirm_lines(api.plan_upload(run, root, config, online=True))
    assert "✗ EVD-X: evidence set EVD-X: upload.yaml's frequency isn't valid" in lines, lines
    assert any("upload.yaml sets defaults.frequency: dayly" in x for x in lines), lines
    out = api.upload_run(run, root, config)
    assert out["ok"] is False and out["uploaded"] == 0
    assert not [c for c in fake.calls if c[0] == "POST" and c[1] == "/evidence"]


def test_a_bad_upload_yaml_value_refuses_the_change_to_a_set_that_exists(fake, root, tmp_path):  # noqa: F811
    st = fake.add_stack("Prod")
    fake.add_evidence("EVD-X", channels=[st.id], name="Set X", frequency="THREE_DAY")
    run, config = two_files(tmp_path), _bad_config(tmp_path)
    out = api.upload_run(run, root, config)
    refused = [o for o in out["outcomes"] if o["action_id"] == "evidence_frequency/EVD-X"]
    assert refused and refused[0]["status"] == "refused" and "dayly" in refused[0]["message"]
    assert out["uploaded"] == 2 and out["ok"] is False  # the files go; the config still needs a fix
    assert not [c for c in fake.calls if c[0] == "PATCH"]


def test_a_bad_upload_yaml_value_is_refused_offline_too(tmp_path):
    _run(tmp_path)
    upload_cfg = {"defaults": {"frequency": "dayly"}}
    p = provider()
    [refuse] = p.diff(p.desired(SyncContext(tmp_path, upload_cfg)), {"EVD-X": UNKNOWN})
    assert refuse.verb == "refuse" and "dayly" in (refuse.fix or "")


# ---- notes: the manifest changed since the run ------------------------------------

def test_a_changed_schedule_is_noted():
    notes = settings_notes({}, {}, run_schedule={"every": "DAILY"}, manifest_schedule={"every": "WEEKLY"})
    assert notes == ["the manifest now sets frequency weekly; this run was made with daily. "
                     "Run the manifest again to use it."]
    assert settings_notes({}, {}, run_schedule=None, manifest_schedule={"every": "DAILY", "at": "02:00"}) == [
        "the manifest now sets frequency daily; this run was made with none. Run the manifest again to use it."]
    assert settings_notes({}, {}, run_schedule={"every": "DAILY", "at": "01:00"},
                          manifest_schedule={"every": "DAILY", "at": "02:00"}) == []  # the time isn't a frequency


def test_a_changed_entry_frequency_is_noted():
    notes = settings_notes({"x": {"use": "x", "frequency": "WEEKLY"}}, {"x": {"use": "x"}})
    assert notes == ["the manifest now sets frequency none for x; this run was made with weekly. "
                     "Run the manifest again to use it."]


def test_manifest_notes_compare_the_schedule(tmp_path, root):  # noqa: F811
    run = _scheduled_run(tmp_path, "DAILY")
    manifest = tmp_path / "m.yaml"
    manifest.write_text("run:\n  schedule:\n    every: MONTHLY\n  fetchers:\n    - use: x\n")
    assert manifest_notes(run, root, manifest, None) == [
        "the manifest now sets frequency monthly; this run was made with daily. Run the manifest again to use it."]
    assert "the manifest now sets frequency monthly" in "\n".join(
        confirm_lines(api.plan_upload(run, root, online=False, manifest_path=manifest)))


# ---- the manifest ----------------------------------------------------------------

def test_the_schedule_validates_and_parses():
    m = {"run": {"schedule": {"every": "DAILY", "at": "02:00"},
                 "fetchers": [{"use": "x", "paramify": {"frequency": "WEEKLY"}}]}}
    assert schema_errors(m, REPO_ROOT) == []
    assert parse_manifest(m).schedule == {"every": "DAILY", "at": "02:00"}


@pytest.mark.parametrize("run, where", [
    ({"schedule": {"every": "HOURLY"}}, "run.schedule.every"),
    ({"schedule": {"at": "02:00"}}, "run.schedule"),
    ({"schedule": {"every": "DAILY", "at": "2am"}}, "run.schedule.at"),
    ({"schedule": {"every": "DAILY", "at": "24:00"}}, "run.schedule.at"),
    ({"paramify": {"frequency": "DAILY"}}, "run.paramify"),  # run-wide, it is the schedule's
    ({"schedule": {"every": "NOT_SET"}}, "run.schedule.every"),  # a schedule always has a cadence
    ({"fetchers": [{"use": "x", "paramify": {"frequency": "NOT_SET"}}]}, "run.fetchers"),
])
def test_a_bad_schedule_is_refused(run, where):
    errors = schema_errors({"run": {"fetchers": [], **run}}, REPO_ROOT)
    assert errors and errors[0].startswith(where), errors


@pytest.mark.parametrize("use", [None, "x"])
def test_set_frequency_refuses_not_set(use):
    m = {"run": {"fetchers": [{"use": "x"}]}}
    with pytest.raises(ValueError, match="isn't a frequency; use one of DAILY, "):
        api.set_frequency(m, "not_set", use=use)
    assert m == {"run": {"fetchers": [{"use": "x"}]}}


def test_entry_frequency_reads_a_given_upload_yaml_and_not_the_file(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "default_upload_values", lambda _root: pytest.fail("read the file"))
    m = {"run": {"schedule": {"every": "DAILY"}, "fetchers": [{"use": "x"}]}}
    got = api.entry_frequency(m, m["run"]["fetchers"][0], "WEEKLY", tmp_path,
                              upload_cfg={"overrides": {"x": {"frequency": "monthly"}}})
    assert got == ("MONTHLY", "upload.yaml")
