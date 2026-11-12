"""What a run tells a script: the `--json` summary and `paramify run --print-run-dir`.

An entry can end a run without an invocation: it is skipped (not found, a
dependency problem), or its setup fails before the fetcher starts. A run can
also leave a note (a dropped credential, an unset config reference). Each of
these reaches a script, by name and with its reason, and so does the reason a
fetcher gave for a failure.

The tests stage a small repo in tmp_path with real subprocess fetchers.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from framework import api
from framework.cli import app

REPO_ROOT = Path(__file__).resolve().parent.parent
UNSET = "PF_RUN_SUMMARY_TEST_UNSET"


def _fetcher(root: Path, short: str, script: str, extra: str = "") -> str:
    d = root / "fetchers" / "testcat" / short
    d.mkdir(parents=True)
    (d / "fetcher.yaml").write_text(
        f"name: testcat_{short}\nversion: 0.1.0\ndescription: d\ncategory: testcat\n"
        "runtime:\n  type: python\n  entry: fetcher.py\n"
        f"output:\n  type: json\n  path: {short}.json\n"
        "secrets: []\n"
        f"evidence_set:\n  reference_id: EVD-{short.upper()}\n  name: {short}\n" + extra
    )
    (d / "fetcher.py").write_text(script)
    return f"testcat_{short}"


WRITE = ("import os, pathlib\n"
         "pathlib.Path(os.environ['EVIDENCE_DIR'], '{short}.json').write_text("
         "'{{\"metadata\": {{\"partial_failure\": false, \"api_failures\": []}}, \"results\": []}}')\n")


@pytest.fixture
def staged(tmp_path, monkeypatch):
    """A repo with one fetcher of each outcome, and a manifest that runs them all."""
    monkeypatch.delenv(UNSET, raising=False)
    (tmp_path / "framework" / "schemas").mkdir(parents=True)
    for src in (REPO_ROOT / "framework" / "schemas").glob("*.json"):
        (tmp_path / "framework" / "schemas" / src.name).write_bytes(src.read_bytes())
    shutil.copytree(REPO_ROOT / "fetchers" / "_lib", tmp_path / "fetchers" / "_lib")

    ok = _fetcher(tmp_path, "ok", WRITE.format(short="ok"))
    bad = _fetcher(tmp_path, "bad", (
        "import json, os, sys\n"
        "print('starting', file=sys.stderr)\n"
        "json.dump({'error': 'token rejected (HTTP 401)', 'code': 'auth_failed'},"
        " open(os.environ['FETCHER_STATUS_FILE'], 'w'))\n"
        "print('Traceback: noise', file=sys.stderr)\n"
        "raise SystemExit(1)\n"
    ))
    needs = _fetcher(tmp_path, "needs", WRITE.format(short="needs"),
                     "config_schema:\n  url:\n    type: string\n    required: true\n    env: NEEDS_URL\n")
    noted = _fetcher(tmp_path, "noted", WRITE.format(short="noted"),
                     "config_schema:\n  pattern:\n    type: string\n    required: false\n"
                     "    default: qa.*\n    env: NOTED_PATTERN\n")
    m = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [
        {"use": ok},
        {"use": "testcat_ghost"},
        {"use": bad},
        {"use": needs},
        {"use": noted, "config": {"pattern": "${env:" + UNSET + "}"}},
    ]}}
    (tmp_path / "manifests").mkdir()
    (tmp_path / "manifests" / "all.yaml").write_text(json.dumps(m))
    monkeypatch.chdir(tmp_path)
    return tmp_path, m, {"ok": ok, "bad": bad, "needs": needs, "noted": noted}


def test_the_summary_names_skipped_errored_and_noted_entries(staged):
    root, m, f = staged
    summary = api.run(m, root)

    assert summary["ok"] is False
    assert summary["skipped"] == [
        {"entry_key": "testcat_ghost", "fetcher": "testcat_ghost", "reason": "not discovered"}]
    [error] = summary["errors"]
    assert (error["entry_key"], error["fetcher"]) == (f["needs"], f["needs"])
    assert "url" in error["error"]
    [note] = summary["notes"]
    assert (note["entry_key"], note["fetcher"]) == (f["noted"], f["noted"])
    assert UNSET in note["note"]


def test_a_failed_invocation_records_why(staged):
    """The reason the fetcher reported via $FETCHER_STATUS_FILE, as the fetcher_result event has it."""
    root, m, f = staged
    summary = api.run(m, root)

    by_key = {r["entry_key"]: r for r in summary["invocations"]}
    assert by_key[f["bad"]]["error"] == "token rejected (HTTP 401)"
    assert by_key[f["bad"]]["error_code"] == "auth_failed"
    assert "error" not in by_key[f["ok"]] and "error_code" not in by_key[f["ok"]]
    meta = json.loads(Path(summary["metadata_path"]).read_text())
    assert meta["invocations"] == summary["invocations"]


def test_the_summary_lists_are_empty_on_a_clean_run(staged):
    root, m, f = staged
    m["run"]["fetchers"] = [{"use": f["ok"]}]
    summary = api.run(m, root)
    assert (summary["skipped"], summary["errors"], summary["notes"]) == ([], [], [])


def test_print_run_dir_puts_only_the_run_dir_on_stdout(staged):
    """What the deploy scripts read: stdout is the run directory, stderr is the full progress log."""
    root, _m, f = staged
    r = CliRunner().invoke(app, ["run", "manifests/all.yaml", "--print-run-dir"])

    assert r.exit_code == 1
    [run_dir] = r.stdout.splitlines()
    assert Path(run_dir).is_dir() and Path(run_dir).name.startswith("run-")
    err = r.stderr
    assert "SKIP  testcat_ghost (not discovered)" in err
    assert f"RUN   {f['needs']}" in err and "runner error:" in err and "url" in err
    assert "NOTE" in err and UNSET in err
    assert f"RUN   {f['bad']}" in err and "[FAIL] exit=1" in err
    assert "token rejected (HTTP 401)" in err
    assert "[OK] exit=0" in err


def test_print_run_dir_and_json_are_refused_together(staged):
    r = CliRunner().invoke(app, ["run", "manifests/all.yaml", "--print-run-dir", "--json"])
    assert r.exit_code != 0
    assert not (staged[0] / "out").exists()
