"""Evidence set frequency: where it comes from, and how sync changes a set that exists."""
from __future__ import annotations

from pathlib import Path

import json

import pytest

from framework import api
from framework.paramify.client import Client
from framework.paramify.resources import Reader, Resources
from framework.runner.manifest_loader import parse_manifest, schema_errors
from framework.sync import engine
from framework.sync.model import Plan, SyncContext
from framework.sync.providers.desired import desired_from_run, resolve_frequency
from framework.sync.providers.evidence_sets import group_by_reference
from framework.sync.render import confirm_lines
from tests.test_api_upload_engine import fake, no_env, root, two_files  # noqa: F401 — fixtures
from tests.test_provider_evidence_sets import FakeParamify, entry, observed_set, provider
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


# ---- the evidence_sets provider -------------------------------------------------

def test_a_chosen_frequency_updates_a_set_that_exists():
    seen = observed_set()
    seen = type(seen)(**{**seen.__dict__, "frequency": "THREE_DAY"})
    e = entry(frequency="DAILY")
    e = type(e)(**{**e.__dict__, "frequency_source": "schedule"})
    update, _tag = provider().diff(group_by_reference([e]), {"EVD-A": seen})
    assert update.verb == "update" and update.id == "evidence_sets/EVD-A"
    assert update.summary == "EVD-A: frequency every 3 days → daily"
    assert update.payload["body"] == {"frequency": "DAILY"} and update.payload["id"] == "ev-9"
    assert confirm_lines(Plan([update])) == ["~ EVD-A: frequency every 3 days → daily"]


def test_the_fetchers_default_never_changes_a_set():
    seen = observed_set()
    seen = type(seen)(**{**seen.__dict__, "frequency": "DAILY"})
    noop, _ = provider().diff(group_by_reference([entry(frequency="THREE_DAY")]), {"EVD-A": seen})
    assert noop.verb == "noop"


def test_entries_sharing_a_set_get_the_shortest_chosen_frequency():
    a = entry("a", frequency="WEEKLY")
    b = entry("b", frequency="DAILY")
    c = entry("c", frequency="THREE_DAY")  # the fetcher's default: not a choice
    a, b = (type(x)(**{**x.__dict__, "frequency_source": "entry"}) for x in (a, b))
    [rec] = group_by_reference([c, a, b])
    assert rec.frequency == "DAILY" and rec.frequency_explicit


def _plan_apply(fake, entries):
    res = Resources(Client("t", "https://api.example.test", session=fake.session))
    p = provider()
    p.desired = lambda ctx: group_by_reference(entries)  # type: ignore[method-assign]
    pl = engine.plan([p], SyncContext(None, {}), Reader(res))
    return pl, engine.apply(pl, [p], res)


def _scheduled(frequency="DAILY"):
    e = entry(frequency=frequency)
    return type(e)(**{**e.__dict__, "frequency_source": "schedule"})


def test_apply_patches_the_frequency_and_keeps_the_id():
    fake = FakeParamify()
    ev = fake.add_evidence("EVD-A", channels=[fake.add_stack("s").id], name="Set A", frequency="THREE_DAY")
    plan, outs = _plan_apply(fake, [_scheduled()])
    assert plan.actions[0].verb == "update"
    assert outs[0].status == "applied" and outs[0].result["id"] == ev.id
    assert ("PATCH", f"/evidence/{ev.id}") in [c[:2] for c in fake.calls]
    assert next(r for r in fake._evidence if r["id"] == ev.id)["frequency"] == "DAILY"


def _scheduled_run(tmp_path, every="DAILY"):
    run = two_files(tmp_path)
    meta = json.loads((run / "_run_metadata.json").read_text())
    meta["schedule"] = {"every": every, "at": "02:00"}
    (run / "_run_metadata.json").write_text(json.dumps(meta))
    return run


def test_upload_changes_the_frequency_then_delivers(fake, root, tmp_path):  # noqa: F811
    st = fake.add_stack("Prod")
    ev = fake.add_evidence("EVD-X", channels=[st.id], name="Set X", frequency="THREE_DAY")
    run = _scheduled_run(tmp_path)
    lines = confirm_lines(api.plan_upload(run, root, online=True))
    assert "~ EVD-X: frequency every 3 days → daily" in lines, lines
    out = api.upload_run(run, root)
    assert out["uploaded"] == 2
    assert next(r for r in fake._evidence if r["id"] == ev.id)["frequency"] == "DAILY"
    # The next upload has nothing to change.
    assert not [x for x in confirm_lines(api.plan_upload(run, root, online=True)) if x.startswith("~")]


def test_a_refused_patch_still_lets_delivery_use_the_set():
    fake = FakeParamify()
    ev = fake.add_evidence("EVD-A", name="Set A", frequency="THREE_DAY")
    fake.fail_route("PATCH", r"/evidence/.*", 403, "Missing Write Evidences")
    _, outs = _plan_apply(fake, [_scheduled()])
    assert outs[0].status == "noop" and outs[0].result["id"] == ev.id
    assert outs[0].message.startswith("frequency not changed")


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
])
def test_a_bad_schedule_is_refused(run, where):
    errors = schema_errors({"run": {**run, "fetchers": []}}, REPO_ROOT)
    assert errors and errors[0].startswith(where), errors
