"""The CLI surface of the upload engine: `upload --plan`, `--stack`, `stacks`, `manifest set-stack`, `validate --online`.

The facade is pointed at the in-process fake API (see test_api_upload_engine).
Runs and manifests live under tmp_path; nothing is written into the repo.
"""
from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml
from typer.testing import CliRunner

from framework import api, paramify_auth
from framework.cli import app
from framework.paramify.client import ApiError, ErrorKind
from framework.sync import upload as upload_mod
from tests.test_api_upload_engine import fake, no_env, root, submits, two_files  # noqa: F401  (fixtures)

runner = CliRunner()


def cli(*args: str):
    return runner.invoke(app, list(args))


def calls(fake) -> List[str]:
    return [f"{c[0]} {c[1]}" for c in fake.calls]


def manifest_file(tmp_path: Path, *uses: str) -> Path:
    path = tmp_path / "m.yaml"
    path.write_text(yaml.safe_dump({"run": {"output_dir": "./evidence", "fetchers": [{"use": u} for u in uses]}}))
    return path


def a_fetcher() -> str:
    return sorted(api.discover_fetchers(api.find_repo_root()))[0]


# ---- upload --plan ---------------------------------------------------------------

def test_plan_prints_entries_and_totals_and_applies_nothing(fake, tmp_path):  # noqa: F811
    run = two_files(tmp_path)
    res = cli("upload", str(run), "--plan")
    assert res.exit_code == 0, res.output
    assert "delivery" in res.output and "  deliver x:" in res.output
    assert "1 deliver · 0 noop · 0 refuse" in res.output
    assert all(c.startswith("GET ") for c in calls(fake))
    assert not (run / "upload_log.json").exists()


def test_plan_says_first_that_batches_are_off(fake, tmp_path):  # noqa: F811
    fake.batches_flag_off()
    run = two_files(tmp_path)
    res = cli("upload", str(run), "--plan")
    assert res.exit_code == 0, res.output
    plan_lines = [line for line in res.output.splitlines() if not line.startswith("Planning upload to ")]
    assert plan_lines[0] == (
        "! batches are off for this workspace (Artifact requests are not enabled for this workspace.); "
        "every entry is sent direct, as before batches")
    assert "  deliver x: deliver 2 files to EVD-X direct (no channel): batches are off for this workspace" \
        in res.output
    js = cli("upload", str(run), "--plan", "--json")
    assert json.loads(js.output)["plan"]["notes"][0].startswith("batches are off for this workspace")
    assert not (run / "upload_log.json").exists()


def test_plan_with_a_403_on_the_batches_probe_falls_back_to_direct(fake, tmp_path):  # noqa: F811
    # Any 403 on GET /batches (not only "not enabled") turns batches off for
    # this run; it must not stop the upload before planning.
    fake.fail_route("GET", "/batches", 403,
                    json.dumps({"requestId": "r-9", "error": {"message": "Insufficient scope", "path": "/batches"}}))
    run = two_files(tmp_path)
    res = cli("upload", str(run), "--plan")
    assert res.exit_code == 0, res.output
    assert ("! batches are off for this workspace (Insufficient scope); "
            "every entry is sent direct, as before batches") in res.output
    assert "  deliver x: deliver 2 files to EVD-X direct (no channel)" in res.output


def test_plan_with_a_refusal_is_still_a_preview_and_exits_0(fake, tmp_path):  # noqa: F811
    st1, st2 = fake.add_stack("Prod"), fake.add_stack("Gov")
    fake.add_evidence("EVD-X", channels=[st1.id, st2.id])
    res = cli("upload", str(two_files(tmp_path)), "--plan")
    assert res.exit_code == 0, res.output
    assert "refuse x" in res.output and "→ fix:" in res.output and "0 deliver · 0 noop · 1 refuse" in res.output


def test_plan_json_carries_the_plan(fake, tmp_path):  # noqa: F811
    res = cli("upload", str(two_files(tmp_path)), "--plan", "--json")
    assert res.exit_code == 0, res.output
    out = json.loads(res.output)
    assert out["ok"] is True and [a["id"] for a in out["plan"]["actions"]][-1] == "delivery/x"


def test_plan_that_cannot_be_made_exits_1(no_env, tmp_path):  # noqa: F811
    res = cli("upload", str(two_files(tmp_path)), "--plan", "--json")
    assert res.exit_code == 1
    assert json.loads(res.output)["ok"] is False


def test_plan_and_dry_run_together_is_a_usage_error(no_env, tmp_path):  # noqa: F811
    res = cli("upload", str(two_files(tmp_path)), "--plan", "--dry-run")
    assert res.exit_code == 2


# ---- upload (apply) --------------------------------------------------------------

def test_apply_prints_plan_then_events_then_outcomes(fake, tmp_path):  # noqa: F811
    res = cli("upload", str(two_files(tmp_path)))
    assert res.exit_code == 0, res.output
    out = res.output
    assert out.index("1 deliver · 0 noop · 0 refuse") < out.index("[OK] a.json") < out.index("delivered x BCH")
    assert submits(fake) == ["/batches/bt-1/submit"]


def test_apply_plans_exactly_once_and_prints_that_plan(fake, tmp_path):  # noqa: F811
    res = cli("upload", str(two_files(tmp_path)))
    assert res.exit_code == 0, res.output
    assert len([c for c in calls(fake) if c.startswith("GET /evidence")]) == 1
    assert res.output.count("1 deliver · 0 noop · 0 refuse") == 1


def test_apply_exits_1_when_an_entry_is_refused(fake, tmp_path):  # noqa: F811
    st1, st2 = fake.add_stack("Prod"), fake.add_stack("Gov")
    fake.add_evidence("EVD-X", channels=[st1.id, st2.id])
    res = cli("upload", str(two_files(tmp_path)))
    assert res.exit_code == 1
    assert "refused x" in res.output and submits(fake) == []


def test_apply_json_adds_plan_and_entries_and_prints_nothing_else(fake, tmp_path):  # noqa: F811
    res = cli("upload", str(two_files(tmp_path)), "--json")
    assert res.exit_code == 0, res.output
    out = json.loads(res.output)
    assert {"uploaded", "skipped_duplicate", "skipped_failed", "errors", "ok", "plan", "entries"} <= set(out)


def test_dry_run_prints_the_offline_plan_without_a_token(no_env, tmp_path):  # noqa: F811
    res = cli("upload", str(two_files(tmp_path)), "--dry-run")
    assert res.exit_code == 0, res.output
    assert "routing unknown offline" in res.output and "[DRY] a.json" in res.output


def test_dry_run_with_validators_names_the_planned_sync(no_env, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(api, "sync_validators", lambda *a, **k: pytest.fail("synced in a dry run"))
    run = two_files(tmp_path)
    res = cli("upload", str(run), "--dry-run", "--with-validators")
    assert res.exit_code == 0, res.output
    assert "validators: sync validators for 1 evidence set (dry run: nothing synced)" in res.output
    js = cli("upload", str(run), "--dry-run", "--with-validators", "--json")
    assert json.loads(js.output)["validators"]["planned"] == "sync validators for 1 evidence set"


def test_done_line_counts_dropped_files(fake, tmp_path):  # noqa: F811
    fake.fail_upload("a.json", 413)
    res = cli("upload", str(two_files(tmp_path)))
    assert res.exit_code == 0, res.output
    assert "errors=0 dropped=1" in res.output


def test_stack_and_validators_reach_upload_run(no_env, tmp_path, monkeypatch):  # noqa: F811
    seen: Dict[str, Any] = {}

    def fake_upload(run_dir, root, config_path, **kw):
        seen.update(kw)
        return {"ok": True, "uploaded": 0, "skipped_duplicate": 0, "skipped_failed": 0, "errors": 0}

    monkeypatch.setattr(api, "upload_run", fake_upload)
    monkeypatch.setattr(api, "sync_validators", lambda *a, **k: pytest.fail("synced after the upload"))
    res = cli("upload", str(two_files(tmp_path)), "--dry-run", "--stack", "Prod", "--with-validators", "--no-tags")
    assert res.exit_code == 0, res.output
    assert seen["stack"] == "Prod" and seen["with_validators"] is True and seen["custom_tags"] is False


def test_stack_override_is_applied(fake, tmp_path):  # noqa: F811
    st1, st2 = fake.add_stack("Prod"), fake.add_stack("Gov")
    ev = fake.add_evidence("EVD-X", channels=[st1.id, st2.id])
    today = date.today()
    fake.add_request(ev.id, ev.channels[1].id, today - timedelta(days=5), today + timedelta(days=5))
    res = cli("upload", str(two_files(tmp_path)), "--stack", st2.id)
    assert res.exit_code == 0, res.output


def test_validators_sync_once_and_before_delivery(fake, tmp_path, monkeypatch):  # noqa: F811
    seen: List[Any] = []
    monkeypatch.setattr(api, "sync_validators", lambda root, **kw: seen.append(kw["reference_ids"]) or {"ok": True})
    res = cli("upload", str(two_files(tmp_path)), "--with-validators")
    assert res.exit_code == 0, res.output
    assert seen == [["EVD-X"]]


def test_validators_summary_and_progress_survive(fake, tmp_path, monkeypatch):  # noqa: F811
    def sync(root, **kw):
        kw["on_event"]({"event": "sync_start", "validators": 2, "base_url": "https://x", "dry_run": False})
        kw["on_event"]({"event": "sync_validator", "key": "v1", "outcome": "created"})
        return {"ok": True, "created": 2}

    monkeypatch.setattr(api, "sync_validators", sync)
    run = str(two_files(tmp_path))
    human = cli("upload", run, "--with-validators")
    assert human.exit_code == 0, human.output
    assert "Sync 2 validator(s) → https://x" in human.output and "[OK] v1  created" in human.output
    fake2 = cli("upload", run, "--with-validators", "--json")
    assert json.loads(fake2.output)["validators"] == {"ok": True, "created": 2}


def test_a_rejected_token_is_named_in_human_and_json_output(no_env, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv(paramify_auth.UPLOAD_TOKEN_ENV, "bad")

    def reject(client):
        raise ApiError("GET /batches failed (HTTP 401)", status=401, kind=ErrorKind.FATAL, method="GET", path="/batches")

    monkeypatch.setattr(upload_mod, "delivery_capability", reject)
    want = f"Paramify rejected the API token (HTTP 401); check {paramify_auth.UPLOAD_TOKEN_ENV}"
    run = str(two_files(tmp_path))
    for args in (["upload", run], ["upload", run, "--plan"]):
        human = cli(*args)
        assert human.exit_code == 1 and want in human.output
        js = cli(*args, "--json")
        assert js.exit_code == 1 and json.loads(js.output)["errors"] == [want]


# ---- stacks ----------------------------------------------------------------------

def test_stacks_json_sorted_by_name(fake):  # noqa: F811
    fake.add_stack("Zeta"), fake.add_stack("Alpha")
    res = cli("stacks", "--json")
    assert res.exit_code == 0, res.output
    assert [s["name"] for s in json.loads(res.output)["stacks"]] == ["Alpha", "Zeta"]
    human = cli("stacks")
    assert human.output.index("Alpha") < human.output.index("Zeta")


def test_stacks_without_a_token_names_the_variable(no_env):  # noqa: F811
    res = cli("stacks", "--json")
    assert res.exit_code == 1 and paramify_auth.UPLOAD_TOKEN_ENV in json.loads(res.output)["errors"][0]


# ---- manifest set-stack ----------------------------------------------------------

def read(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def test_set_stack_by_name_writes_id_and_name(fake, tmp_path):  # noqa: F811
    st = fake.add_stack("Prod")
    path = manifest_file(tmp_path, a_fetcher())
    res = cli("manifest", "set-stack", str(path), "Prod")
    assert res.exit_code == 0, res.output
    assert read(path)["run"]["paramify"] == {"stack": st.id, "stack_name": "Prod"}


def test_set_stack_by_id_and_for_one_fetcher(fake, tmp_path):  # noqa: F811
    st = fake.add_stack("Prod")
    use = a_fetcher()
    path = manifest_file(tmp_path, use)
    res = cli("manifest", "set-stack", str(path), st.id, "--fetcher", use)
    assert res.exit_code == 0, res.output
    m = read(path)
    assert m["run"]["fetchers"][0]["paramify"] == {"stack": st.id, "stack_name": "Prod"}
    assert "paramify" not in m["run"]


def test_set_stack_unknown_and_ambiguous_names_are_errors(fake, tmp_path):  # noqa: F811
    a, b = fake.add_stack("Dup"), fake.add_stack("Dup")
    path = manifest_file(tmp_path, a_fetcher())
    res = cli("manifest", "set-stack", str(path), "Dup")
    assert res.exit_code == 1 and a.id in res.output and b.id in res.output
    assert cli("manifest", "set-stack", str(path), "dup").exit_code == 1  # case-sensitive
    assert "paramify" not in read(path)["run"]


def test_set_stack_without_a_token_stores_as_given_with_a_note(no_env, tmp_path):  # noqa: F811
    path = manifest_file(tmp_path, a_fetcher())
    res = cli("manifest", "set-stack", str(path), "Prod")
    assert res.exit_code == 0, res.output
    assert read(path)["run"]["paramify"] == {"stack": "Prod"}
    assert "not checked" in res.output


def test_set_stack_targets_each_of_two_entries_with_the_same_fetcher(fake, tmp_path):  # noqa: F811
    fake.add_stack("Prod"), fake.add_stack("Gov")
    use = a_fetcher()
    path = manifest_file(tmp_path, use, use)
    assert cli("manifest", "set-stack", str(path), "Prod", "--fetcher", use).exit_code == 0
    assert cli("manifest", "set-stack", str(path), "Gov", "--fetcher", f"{use}#1").exit_code == 0
    first, second = read(path)["run"]["fetchers"]
    assert first["paramify"]["stack_name"] == "Prod" and second["paramify"]["stack_name"] == "Gov"


def test_set_stack_fetcher_matching_none_names_the_entries(fake, tmp_path):  # noqa: F811
    fake.add_stack("Prod")
    use = a_fetcher()
    path = manifest_file(tmp_path, use, use)
    none = cli("manifest", "set-stack", str(path), "Prod", "--fetcher", "nope")
    assert none.exit_code == 1 and "matches no entry" in none.output
    assert cli("manifest", "set-stack", str(path), "Prod", "--fetcher", f"{use}#1").exit_code == 0
    assert read(path)["run"]["fetchers"][1]["paramify"]["stack_name"] == "Prod"


# ---- validate --online -----------------------------------------------------------

def test_validate_online_flags_an_unknown_stack(fake, tmp_path):  # noqa: F811
    st = fake.add_stack("Prod")
    use = a_fetcher()
    path = tmp_path / "m.yaml"
    path.write_text(yaml.safe_dump({"run": {
        "output_dir": "./evidence", "paramify": {"stack": st.id},
        "fetchers": [{"use": use, "paramify": {"stack": "Ghost"}}]}}))
    res = cli("validate", str(path), "--online", "--json")
    assert res.exit_code == 1
    errors = json.loads(res.output)["errors"]
    assert any(f"fetchers[{use}].paramify.stack" in e and "Ghost" in e for e in errors)
    assert not any("run.paramify.stack" in e for e in errors)


def test_validate_online_accepts_a_stack_by_name(fake, tmp_path):  # noqa: F811
    fake.add_stack("Prod")
    path = tmp_path / "m.yaml"
    path.write_text(yaml.safe_dump({"run": {"output_dir": "./evidence", "paramify": {"stack": "Prod"}, "fetchers": []}}))
    errors = json.loads(cli("validate", str(path), "--online", "--json").output)["errors"]
    assert not any("stack" in e for e in errors)


def test_validate_without_online_makes_no_calls(fake, tmp_path):  # noqa: F811
    path = tmp_path / "m.yaml"
    path.write_text(yaml.safe_dump({"run": {"output_dir": "./evidence", "paramify": {"stack": "Ghost"}, "fetchers": []}}))
    cli("validate", str(path), "--json")
    assert fake.calls == []


# ---- the manifest's Paramify settings against the run's ---------------------------

STACK_NOTE = ("the manifest now sets stack E2E-A for x; this run was made with none. "
              "Run the manifest again, or upload with --stack E2E-A.")


def paramify_manifest(path: Path, run_paramify=None, entry_paramify=None, use="x") -> Path:
    entry: Dict[str, Any] = {"use": use}
    if entry_paramify:
        entry["paramify"] = entry_paramify
    run: Dict[str, Any] = {"output_dir": "./evidence", "fetchers": [entry]}
    if run_paramify:
        run["paramify"] = run_paramify
    path.write_text(yaml.safe_dump({"run": run}))
    return path


def test_plan_notes_a_stack_the_manifest_now_sets(fake, tmp_path):  # noqa: F811
    m = paramify_manifest(tmp_path / "m.yaml", {"stack": "E2E-A"})
    res = cli("upload", str(two_files(tmp_path)), "--plan", "-f", str(m))
    assert res.exit_code == 0, res.output
    assert f"! {STACK_NOTE}" in res.output.splitlines()


def test_dry_run_and_a_real_upload_print_the_note(fake, tmp_path):  # noqa: F811
    m = paramify_manifest(tmp_path / "m.yaml", {"stack": "E2E-A"})
    run = two_files(tmp_path)
    dry = cli("upload", str(run), "--dry-run", "-f", str(m))
    assert dry.exit_code == 0, dry.output
    assert f"! {STACK_NOTE}" in dry.output.splitlines()
    real = cli("upload", str(run), "-f", str(m))
    assert f"! {STACK_NOTE}" in real.output.splitlines(), real.output


def test_same_settings_give_no_note(no_env, root, tmp_path):  # noqa: F811
    run = two_files(tmp_path, {"x": {"use": "x", "stack": "st-2", "stack_name": "Gov", "delivery": "direct"}})
    m = paramify_manifest(tmp_path / "m.yaml", {"stack": "st-2", "stack_name": "Gov"}, {"delivery": "direct"})
    assert api.plan_upload(run, root, online=False, manifest_path=m).notes == []


def test_unset_and_default_are_the_same_setting(no_env, root, tmp_path):  # noqa: F811
    run = two_files(tmp_path, {"x": {"use": "x"}})
    m = paramify_manifest(tmp_path / "m.yaml", entry_paramify={
        "approval": "SUBMISSION", "no_request": "direct", "delivery": "auto"})
    assert api.plan_upload(run, root, online=False, manifest_path=m).notes == []


def test_a_stack_label_names_the_stack_and_the_flag_takes_its_id(no_env, root, tmp_path):  # noqa: F811
    run = two_files(tmp_path, {"x": {"use": "x", "stack": "st-1", "stack_name": "Prod"}})
    m = paramify_manifest(tmp_path / "m.yaml", {"stack": "st-2", "stack_name": "Gov"})
    assert api.plan_upload(run, root, online=False, manifest_path=m).notes == [
        "the manifest now sets stack Gov for x; this run was made with Prod. "
        "Run the manifest again, or upload with --stack st-2."]


def test_each_other_setting_gets_its_own_note(no_env, root, tmp_path):  # noqa: F811
    run = two_files(tmp_path, {"x": {"use": "x", "approval": "MANUAL"}})
    m = paramify_manifest(tmp_path / "m.yaml", entry_paramify={"no_request": "evidence", "delivery": "direct"})
    assert api.plan_upload(run, root, online=False, manifest_path=m).notes == [
        "the manifest now sets approval: SUBMISSION for x; this run was made with MANUAL. "
        "Run the manifest again to use it.",
        "the manifest now sets no_request: evidence for x; this run was made with direct. "
        "Run the manifest again to use it.",
        "the manifest now sets delivery: direct for x; this run was made with auto. "
        "Run the manifest again to use it.",
    ]


def test_a_stack_override_drops_only_the_stack_note(no_env, root, tmp_path):  # noqa: F811
    run = two_files(tmp_path)
    m = paramify_manifest(tmp_path / "m.yaml", {"stack": "E2E-A"}, {"delivery": "direct"})
    notes = api.plan_upload(run, root, online=False, manifest_path=m, stack="Prod").notes
    assert notes == ["the manifest now sets delivery: direct for x; this run was made with auto. "
                     "Run the manifest again to use it."]
    out = api.upload_run(run, root, dry_run=True, manifest_path=m, stack="Prod")
    assert out["plan"]["notes"] == notes


def test_the_runs_own_manifest_is_used_when_none_is_given(no_env, root, tmp_path):  # noqa: F811
    run = two_files(tmp_path)
    paramify_manifest(root / "m.yaml", {"stack": "E2E-A"})
    meta = json.loads((run / "_run_metadata.json").read_text())
    (run / "_run_metadata.json").write_text(json.dumps({**meta, "manifest": "m.yaml"}))
    assert api.plan_upload(run, root, online=False).notes == [STACK_NOTE]
    assert api.upload_run(run, root, dry_run=True)["plan"]["notes"] == [STACK_NOTE]


def test_no_manifest_to_compare_gives_no_note(no_env, root, tmp_path):  # noqa: F811
    run = two_files(tmp_path)
    assert api.plan_upload(run, root, online=False).notes == []
    meta = json.loads((run / "_run_metadata.json").read_text())
    (run / "_run_metadata.json").write_text(json.dumps({**meta, "manifest": "gone.yaml"}))
    assert api.plan_upload(run, root, online=False).notes == []
    assert api.plan_upload(run, root, online=False, manifest_path=tmp_path / "missing.yaml").notes == []


def test_an_entry_key_in_only_one_side_or_for_another_fetcher_is_not_compared(no_env, root, tmp_path):  # noqa: F811
    run = two_files(tmp_path)
    other = paramify_manifest(tmp_path / "other.yaml", {"stack": "E2E-A"}, use="y")
    assert api.plan_upload(run, root, online=False, manifest_path=other).notes == []
