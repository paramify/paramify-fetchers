"""api.upload_run / api.plan_upload on the sync engine, against the in-process fake API.

The facade keeps the legacy summary keys and events (`upload_start`,
`upload_file`, `upload_complete`) and adds `plan` and `entries`.
"""
from __future__ import annotations

import functools
import importlib.util
import json
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List

import pytest
import requests

from framework import api
from framework.paramify import client as client_mod
from framework.paramify.client import ApiError, Client, ErrorKind
from framework.paramify_auth import BASE_URL_ENV, READ_TOKEN_ENV, UPLOAD_TOKEN_ENV
from framework.sync import render
from framework.sync import upload as upload_mod
from framework.sync.model import Outcome
from framework.sync.state import RunState
from tests.test_sync_desired import build, env, inv

_spec = importlib.util.spec_from_file_location("paramify_fake", Path(__file__).with_name("paramify_fake.py"))
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("paramify_fake", _mod)
_spec.loader.exec_module(_mod)
FakeParamify = _mod.FakeParamify

URL = "https://api.example.test"
LEGACY = {"uploaded", "skipped_duplicate", "skipped_failed", "errors", "ok"}


@pytest.fixture
def no_env(monkeypatch):
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.delenv(UPLOAD_TOKEN_ENV, raising=False)
    monkeypatch.delenv(READ_TOKEN_ENV, raising=False)
    monkeypatch.delenv("PARAMIFY_CUSTOM_TAGS", raising=False)
    monkeypatch.setenv(BASE_URL_ENV, URL)


@pytest.fixture
def fake(no_env, monkeypatch):
    f = FakeParamify()
    f.set_today(date.today())
    monkeypatch.setenv(UPLOAD_TOKEN_ENV, "tok")
    monkeypatch.setattr(upload_mod, "Client", functools.partial(
        Client, session=f.session, sleep=lambda _s: None, retry_budget_s=3))
    return f


@pytest.fixture
def root(tmp_path) -> Path:
    r = tmp_path / "root"
    r.mkdir()
    return r


def two_files(tmp_path: Path, paramify=None) -> Path:
    run = tmp_path / "run-1"
    run.mkdir()
    return build(run, {"a.json": env(fetcher="x"), "b.json": env(fetcher="x")},
                 [inv("x", ["a.json", "b.json"])], paramify or {"x": {"use": "x"}})


def file_events(events: List[Dict[str, Any]]) -> List[tuple]:
    return [(e["file"], e["outcome"]) for e in events if e["event"] == "upload_file"]


def submits(fake) -> List[str]:
    return [c[1] for c in fake.calls if c[0] == "POST" and c[1].endswith("/submit")]


# ---- dry run ------------------------------------------------------------------

def test_dry_run_makes_no_http_calls(no_env, root, tmp_path, monkeypatch):
    def refuse(self, *a, **k):
        raise AssertionError("a dry run made an HTTP request")

    monkeypatch.setattr(requests.sessions.Session, "request", refuse)
    run = tmp_path / "run-1"
    run.mkdir()
    build(run, {"a.json": env(fetcher="x"), "b.json": env(fetcher="x"),
                "c.json": env(fetcher="y", ref="EVD-Y", inventory={"complete": False})},
          [inv("x", ["a.json", "b.json"]), inv("y", ["c.json"], fetcher="y")])
    events: List[Dict[str, Any]] = []
    out = api.upload_run(run, root, dry_run=True, on_event=events.append)
    assert LEGACY <= set(out) and "plan" in out
    assert (out["uploaded"], out["skipped_duplicate"], out["skipped_failed"], out["errors"]) == (0, 0, 1, 0)
    assert out["ok"] is True and out["dry_run"] is True
    assert [e["event"] for e in events if e["event"].startswith("upload_")] == [
        "upload_start", "upload_file", "upload_file", "upload_file", "upload_complete"]
    assert file_events(events) == [("a.json", "would_upload"), ("b.json", "would_upload"),
                                   ("c.json", "skipped_failed")]
    first = next(e for e in events if e["event"] == "upload_file")
    assert first["reference_id"] == "EVD-X" and first["tags"] == ["Automated by Paramify Fetchers"]
    assert events[0]["files"] == 3 and events[0]["dry_run"] is True
    assert not (run / "upload_log.json").exists()


def test_dry_run_counts_a_refusal_as_an_error(no_env, root, tmp_path):
    run = tmp_path / "run-1"
    run.mkdir()
    bad = env(fetcher="x")
    bad["payload"] = {"cmd": "/bin/sh -c x"}
    build(run, {"a.json": bad}, [inv("x", ["a.json"])])
    out = api.upload_run(run, root, dry_run=True)
    assert out["ok"] is False and out["errors"] == 1
    assert out["entries"]["x"]["state"] == "refused"


def test_plan_upload_offline_needs_no_token(no_env, root, tmp_path):
    plan = api.plan_upload(two_files(tmp_path), root, online=False)
    [d] = [a for a in plan.actions if a.provider == "delivery"]
    assert d.verb == "deliver" and "routing unknown offline" in d.summary


def test_plan_upload_online_reads_only(fake, root, tmp_path):
    plan = api.plan_upload(two_files(tmp_path), root, online=True)
    assert [a.id for a in plan.actions] == ["evidence_sets/EVD-X", "evidence_sets/tags/EVD-X", "delivery/x"]
    assert all(c[0] == "GET" for c in fake.calls)


# ---- online -------------------------------------------------------------------

def test_upload_summary_keeps_legacy_keys(fake, root, tmp_path):
    run = two_files(tmp_path)
    events: List[Dict[str, Any]] = []
    out = api.upload_run(run, root, on_event=events.append)
    assert LEGACY <= set(out) and {"plan", "entries", "run_dir", "base_url", "files", "tags", "log_path"} <= set(out)
    assert (out["uploaded"], out["skipped_duplicate"], out["skipped_failed"], out["errors"]) == (2, 0, 0, 0)
    assert out["ok"] is True
    entry = out["entries"]["x"]
    assert entry["state"] == "delivered" and entry["batch_id"] == "bt-1" and entry["status"] == "APPROVED"
    assert file_events(events) == [("a.json", "uploaded"), ("b.json", "uploaded")]
    up = next(e for e in events if e["event"] == "upload_file")
    assert up["action_id"] == "delivery/x" and up["reference_id"] == "EVD-X"
    kinds = [e["event"] for e in events]
    assert kinds[0] == "upload_start" and kinds[-1] == "upload_complete"
    assert "action_start" in kinds and "delivery_file" in kinds
    assert out["tags"]["applied"] == 1 and fake.tags
    json.dumps(out, default=str)


def test_second_upload_of_same_run_is_noop(fake, root, tmp_path):
    run = two_files(tmp_path)
    api.upload_run(run, root)
    events: List[Dict[str, Any]] = []
    out = api.upload_run(run, root, on_event=events.append)
    assert (out["uploaded"], out["skipped_duplicate"], out["errors"]) == (0, 2, 0)
    assert out["ok"] is True and out["entries"]["x"]["state"] == "noop"
    assert file_events(events) == [("a.json", "skipped_duplicate"), ("b.json", "skipped_duplicate")]
    assert len(fake._batches) == 1 and len(submits(fake)) == 1


def test_retry_resumes_and_submits_once(fake, root, tmp_path):
    run = two_files(tmp_path)
    fake.fail_upload("a.json", 502)
    events: List[Dict[str, Any]] = []
    first = api.upload_run(run, root, on_event=events.append)
    assert first["ok"] is False and first["entries"]["x"]["state"] == "held"
    assert (first["uploaded"], first["errors"]) == (1, 1)
    held = next(e for e in events if e["event"] == "upload_file" and e["file"] == "a.json")
    assert held["outcome"] == "error" and "502" in held["reason"]
    assert submits(fake) == []

    del fake._fail_all["a.json"]
    second = api.upload_run(run, root)
    assert second["ok"] is True and second["entries"]["x"]["state"] == "delivered"
    assert (second["uploaded"], second["skipped_duplicate"]) == (1, 1)
    assert len(fake._batches) == 1 and submits(fake) == ["/batches/bt-1/submit"]


def test_validators_run_before_delivery(fake, root, tmp_path, monkeypatch):
    calls: List[Dict[str, Any]] = []

    def sync(root_arg, **kw):
        calls.append({"root": root_arg, **kw})
        return {"ok": True, "created": 0}

    monkeypatch.setattr(api, "sync_validators", sync)
    events: List[Dict[str, Any]] = []
    out = api.upload_run(two_files(tmp_path), root, with_validators=True, on_event=events.append)
    assert out["ok"] is True
    starts = [e["action_id"] for e in events if e["event"] == "action_start"]
    assert starts.index("evidence_sets/EVD-X") < starts.index("validators/registry") < starts.index("delivery/x")
    [call] = calls
    assert call["root"] == root and call["reference_ids"] == ["EVD-X"]
    assert call["dry_run"] is False and call["custom_tags"] is True


def test_validators_are_a_noop_in_a_dry_run(no_env, root, tmp_path, monkeypatch):
    monkeypatch.setattr(api, "sync_validators", lambda *a, **k: pytest.fail("synced in a dry run"))
    out = api.upload_run(two_files(tmp_path), root, dry_run=True, with_validators=True)
    [v] = [a for a in out["plan"]["actions"] if a["provider"] == "validators"]
    assert v["verb"] == "noop" and v["summary"] == "sync validators for 1 evidence set"


def test_failed_validator_sync_stops_before_any_batch_is_submitted(fake, root, tmp_path, monkeypatch):
    monkeypatch.setattr(api, "sync_validators", lambda *a, **k: {"ok": False, "errors": 1})
    out = api.upload_run(two_files(tmp_path), root, with_validators=True)
    assert out["ok"] is False and out["uploaded"] == 0
    assert out["entries"]["x"]["state"] == "skipped"
    assert submits(fake) == [] and not fake._batches


def test_upload_log_records_batch_and_stack(fake, root, tmp_path):
    st = fake.add_stack("Prod")
    ev = fake.add_evidence("EVD-X", channels=[st.id])
    today = date.today()
    fake.add_request(ev.id, ev.channels[0].id, today - timedelta(days=5), today + timedelta(days=5))
    run = two_files(tmp_path, {"x": {"use": "x", "stack": st.id}})
    out = api.upload_run(run, root)
    log = json.loads((run / "upload_log.json").read_text())
    assert out["log_path"] == str(run / "upload_log.json")
    assert {"uploaded_at", "run_dir", "uploaded", "skipped_duplicate", "skipped_failed", "errors",
            "tags", "results"} <= set(log)
    assert log["uploaded"] == 2 and [r["file"] for r in log["results"]] == ["a.json", "b.json"]
    entry = log["entries"]["x"]
    assert entry["state"] == "delivered" and entry["batch_id"] == "bt-1"
    assert entry["stack"] == {"id": st.id, "name": "Prod"}
    assert entry["channel"] == "CH-1"
    assert entry["artifact_request"]["reference_id"] == "AR-1"


def test_upload_log_is_written_when_planning_fails(fake, root, tmp_path, monkeypatch):
    run = two_files(tmp_path)

    def boom(self, refs):
        raise ApiError("GET /evidence failed (HTTP 401)", status=401, kind=ErrorKind.FATAL,
                       method="GET", path="/evidence")

    monkeypatch.setattr(upload_mod.Resources, "evidence_by_reference", boom)
    with pytest.raises(ApiError):
        api.upload_run(run, root)
    log = json.loads((run / "upload_log.json").read_text())
    assert "HTTP 401" in log["error"] and log["uploaded"] == 0


def test_concurrent_upload_of_same_run_refused(fake, root, tmp_path):
    run = two_files(tmp_path)
    with RunState(run).lock():
        with pytest.raises(ValueError, match="another upload of this run is in progress"):
            api.upload_run(run, root)
    assert fake.calls == [] and not (run / "upload_log.json").exists()


def test_missing_token_is_a_setup_error(no_env, root, tmp_path):
    with pytest.raises(ValueError, match=UPLOAD_TOKEN_ENV):
        api.upload_run(two_files(tmp_path), root)


def test_api_without_batches_stops_before_planning(fake, root, tmp_path):
    fake.without_batches()
    with pytest.raises(ApiError, match="0.14.0 or later is required"):
        api.upload_run(two_files(tmp_path), root)
    assert [c[1] for c in fake.calls] == ["/batches"]


def test_refused_entry_is_an_error_and_not_ok(fake, root, tmp_path):
    st1, st2 = fake.add_stack("Prod"), fake.add_stack("Gov")
    fake.add_evidence("EVD-X", channels=[st1.id, st2.id])
    run = two_files(tmp_path)  # two channels and no stack: refused
    events: List[Dict[str, Any]] = []
    out = api.upload_run(run, root, on_event=events.append)
    assert out["ok"] is False and out["errors"] == 1 and out["uploaded"] == 0
    assert out["entries"]["x"]["state"] == "refused" and out["entries"]["x"]["message"]
    assert file_events(events) == [("a.json", "error"), ("b.json", "error")]


def test_engine_caught_failure_is_failed_with_its_message(fake, root, tmp_path, monkeypatch):
    def boom(self, *a, **k):
        raise RuntimeError("provider bug")

    monkeypatch.setattr(upload_mod.DeliveryProvider, "_deliver", boom)
    events: List[Dict[str, Any]] = []
    out = api.upload_run(two_files(tmp_path), root, on_event=events.append)
    assert out["entries"]["x"]["state"] == "failed" and out["entries"]["x"]["message"] == "provider bug"
    assert out["ok"] is False and out["errors"] == 2
    assert file_events(events) == [("a.json", "error"), ("b.json", "error")]


def test_stack_override_reaches_delivery(fake, root, tmp_path):
    st1, st2 = fake.add_stack("Prod"), fake.add_stack("Gov")
    ev = fake.add_evidence("EVD-X", channels=[st1.id, st2.id])
    today = date.today()
    fake.add_request(ev.id, ev.channels[1].id, today - timedelta(days=5), today + timedelta(days=5))
    out = api.upload_run(two_files(tmp_path), root, stack=st2.id, dry_run=False)
    assert out["entries"]["x"]["state"] == "delivered"
    assert out["entries"]["x"]["stack"] == {"id": st2.id, "name": "Gov"}
    assert out["entries"]["x"]["channel"] == "CH-2"


def test_no_tags_turns_tags_off(fake, root, tmp_path):
    out = api.upload_run(two_files(tmp_path), root, custom_tags=False)
    assert out["tags"]["enabled"] is False and out["tags"]["reason"] == "--no-tags"
    assert fake.tags == {}


def test_skips_and_drops_are_counted_and_reported_per_file(fake, root, tmp_path):
    run = tmp_path / "run-1"
    run.mkdir()
    bad = env(fetcher="x")
    bad["payload"] = {"cmd": "/bin/sh -c x"}
    build(run, {"a.json": env(fetcher="x"), "b.json": bad,
                "c.json": env(fetcher="x", inventory={"complete": False})},
          [inv("x", ["a.json", "b.json", "c.json"])])
    events: List[Dict[str, Any]] = []
    out = api.upload_run(run, root, on_event=events.append)
    assert (out["uploaded"], out["skipped_failed"], out["errors"]) == (1, 1, 1)
    assert out["entries"]["x"]["state"] == "delivered_with_drops" and out["ok"] is True
    assert sorted(file_events(events)) == [("a.json", "uploaded"), ("b.json", "error"),
                                           ("c.json", "skipped_failed")]
    drop = next(e for e in events if e["event"] == "upload_file" and e["file"] == "b.json")
    assert drop["reason"].startswith("blocked by the production WAF")


def test_preflight_stays_offline_and_keeps_its_shape(no_env, root, tmp_path, monkeypatch):
    monkeypatch.setattr(client_mod.requests, "Session", lambda: pytest.fail("preflight built a session"))
    pf = api.upload_preflight(two_files(tmp_path), root, dry_run=True)
    assert set(pf) == {"ok", "run_dir", "base_url", "base_url_source", "base_url_label", "config_path",
                       "file_count", "token_present", "token_source", "dry_run", "errors"}
    assert pf["ok"] is True and pf["file_count"] == 2 and pf["token_present"] is False
    assert api.upload_preflight(tmp_path / "run-1", root)["errors"][0].startswith(UPLOAD_TOKEN_ENV)


# ---- render -------------------------------------------------------------------

def test_render_plan_groups_by_provider_and_totals(no_env, root, tmp_path):
    run = tmp_path / "run-1"
    run.mkdir()
    bad = env(fetcher="y", ref="EVD-Y")
    bad["payload"] = {"cmd": "/bin/sh -c x"}
    build(run, {"a.json": env(fetcher="x"), "b.json": bad}, [inv("x", ["a.json"]), inv("y", ["b.json"], fetcher="y")])
    lines = render.render_plan(api.plan_upload(run, root, online=False))
    assert lines[0] == "evidence_sets"
    assert "  noop EVD-X: evidence set EVD-X: state unknown (offline)" in lines
    assert lines.index("delivery") > lines.index("evidence_sets")
    i = lines.index("  refuse y: every file was dropped")
    assert lines[i + 1].startswith("    ! dropped b.json: blocked by the production WAF")
    assert lines[i + 2].startswith("    → fix: remove the strings")
    assert lines[-1] == "1 deliver · 0 noop · 1 refuse"  # offline plans no tag actions
    assert not any("\x1b" in line for line in lines)


def test_render_plan_shows_warnings():
    from framework.sync.model import Action, Plan

    plan = Plan([Action("delivery/x", "delivery", "x", "deliver", "deliver 1 file to AR-1",
                        warnings=["late submission to AR-1 (due 2026-10-28)"]),
                 Action("evidence_sets/EVD-X", "evidence_sets", "EVD-X", "create", "create evidence set EVD-X")])
    lines = render.render_plan(plan)
    assert lines == ["delivery", "  deliver x: deliver 1 file to AR-1",
                     "    ! late submission to AR-1 (due 2026-10-28)",
                     "evidence_sets", "  create EVD-X: create evidence set EVD-X",
                     "1 deliver · 0 noop · 0 refuse · 1 create"]


def test_render_outcomes_one_line_per_entry():
    outcomes = [
        Outcome("evidence_sets/EVD-X", "applied", {"id": "ev-1"}),
        Outcome("delivery/x", "applied", {"state": "delivered", "batch_reference": "BCH-1"}, "BCH-1 APPROVED"),
        Outcome("delivery/y", "refused", {}, "two channels"),
        Outcome("delivery/z", "failed", {}, "provider bug"),
        Outcome("validators/registry", "failed", {}, "validator sync had errors"),
    ]
    assert render.render_outcomes(outcomes) == [
        "delivered x BCH-1: BCH-1 APPROVED",
        "refused y: two channels",
        "failed z: provider bug",
        "failed validators/registry: validator sync had errors",
    ]


# ---- explicit config, token, base URL and deprecations (legacy wrapper) --------

def test_upload_cfg_replaces_reading_the_config_file(no_env, root, tmp_path):
    """An in-memory config wins over the file; the file is not read at all."""
    cfg_file = tmp_path / "bad.yaml"
    cfg_file.write_text("this: [is: not valid")
    out = api.upload_run(two_files(tmp_path), root, cfg_file, dry_run=True,
                         upload_cfg={"paramify": {"base_url": "https://cfg.example.test"}})
    assert out["base_url"] == "https://cfg.example.test"
    assert not list(tmp_path.glob("*.json")) and out["ok"] is True


def test_base_url_argument_beats_the_environment(no_env, root, tmp_path):
    out = api.upload_run(two_files(tmp_path), root, dry_run=True, base_url="https://arg.example.test")
    assert out["base_url"] == "https://arg.example.test"


def test_token_and_base_url_arguments_reach_the_client(fake, root, tmp_path, monkeypatch):
    seen = {}

    def spy(token, base_url, **kw):
        seen.update(token=token, base_url=base_url)
        return Client(token, base_url, session=fake.session, sleep=lambda _s: None, retry_budget_s=3)

    monkeypatch.setattr(upload_mod, "Client", spy)
    api.upload_run(two_files(tmp_path), root, token="explicit-tok", base_url="https://arg.example.test")
    assert seen == {"token": "explicit-tok", "base_url": "https://arg.example.test"}


def test_token_argument_stands_in_for_a_missing_environment_token(no_env, root, tmp_path, monkeypatch):
    seen = {}

    class Stop(Exception):
        pass

    def spy(token, base_url, **kw):
        seen["token"] = token
        raise Stop

    monkeypatch.setattr(upload_mod, "Client", spy)
    with pytest.raises(Stop):
        api.upload_run(two_files(tmp_path), root, token="only-arg")
    assert seen["token"] == "only-arg"


def test_deprecations_land_in_the_log(fake, root, tmp_path):
    run = two_files(tmp_path)
    api.upload_run(run, root, deprecations=["use 'paramify upload'"])
    assert json.loads((run / "upload_log.json").read_text())["deprecations"] == ["use 'paramify upload'"]


def test_no_deprecations_key_by_default(fake, root, tmp_path):
    run = two_files(tmp_path)
    api.upload_run(run, root)
    assert "deprecations" not in json.loads((run / "upload_log.json").read_text())


# ---- files that are errors, not decisions --------------------------------------

def _raw_plus_good(tmp_path: Path, raw: str, extra: Dict[str, Any]) -> Path:
    run = tmp_path / "run-1"
    run.mkdir()
    build(run, {"a.json": env(fetcher="x"), **extra}, [inv("x", ["a.json", "z.json"])])
    (run / "z.json").write_text(raw)
    return run


@pytest.mark.parametrize("raw, reason", [
    ('{"just": "data"}', "not envelope-wrapped"),
    ("{not json", "cannot read as JSON"),
])
def test_unreadable_or_non_envelope_file_is_an_error_and_the_rest_delivers(fake, root, tmp_path, raw, reason):
    run = _raw_plus_good(tmp_path, raw, {})
    events: List[Dict[str, Any]] = []
    out = api.upload_run(run, root, on_event=events.append)
    assert out["uploaded"] == 1 and out["errors"] == 1 and out["skipped_failed"] == 0
    assert out["ok"] is False
    assert out["entries"]["x"]["state"] == "delivered_with_drops"
    assert sorted(file_events(events)) == [("a.json", "uploaded"), ("z.json", "error")]
    bad = next(e for e in events if e["event"] == "upload_file" and e["file"] == "z.json")
    assert reason in bad["reason"]


def test_a_missing_evidence_set_is_an_error_and_the_rest_delivers(fake, root, tmp_path):
    no_set = env(fetcher="x")
    del no_set["metadata"]["evidence_set"]
    run = tmp_path / "run-1"
    run.mkdir()
    build(run, {"a.json": env(fetcher="x"), "z.json": no_set}, [inv("x", ["a.json", "z.json"])])
    out = api.upload_run(run, root)
    assert (out["uploaded"], out["errors"], out["skipped_failed"]) == (1, 1, 0)
    assert out["ok"] is False


def test_dry_run_reports_the_same_error_and_ok_false(no_env, root, tmp_path):
    out = api.upload_run(_raw_plus_good(tmp_path, "{not json", {}), root, dry_run=True)
    assert out["errors"] == 1 and out["ok"] is False


def test_a_decision_skip_still_leaves_ok_true(fake, root, tmp_path):
    run = tmp_path / "run-1"
    run.mkdir()
    build(run, {"a.json": env(fetcher="x"), "z.json": env(fetcher="x", inventory={"complete": False})},
          [inv("x", ["a.json", "z.json"])])
    out = api.upload_run(run, root)
    assert (out["skipped_failed"], out["errors"], out["ok"]) == (1, 0, True)
