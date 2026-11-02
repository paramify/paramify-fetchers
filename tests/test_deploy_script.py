"""deploy/run-and-upload.sh uploads the run it just made, through `paramify upload`.

A stub `paramify` first on PATH records its argv; `run --json` prints a summary
naming a run directory. No fetcher runs.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "deploy" / "run-and-upload.sh"

STUB = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
case "$1" in
  run) printf '%s\\n' "$STUB_RUN_SUMMARY"; exit "${STUB_RUN_RC:-0}" ;;
  upload) exit "${STUB_UPLOAD_RC:-0}" ;;
esac
"""


@pytest.fixture
def harness(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "paramify"
    stub.write_text(STUB)
    stub.chmod(0o755)
    log = tmp_path / "calls.log"
    run_dir = tmp_path / "evidence" / "run-20260101-000000-ab12"
    env = {
        **os.environ,
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "STUB_LOG": str(log),
        "STUB_RUN_SUMMARY": json.dumps({"run_dir": str(run_dir), "ok": True}),
    }

    # The script cds to its own repo root: give it a throwaway one, so the test
    # never reads or writes the working tree.
    fake_root = tmp_path / "root"
    (fake_root / "deploy").mkdir(parents=True)
    shutil.copy(SCRIPT, fake_root / "deploy" / "run-and-upload.sh")
    manifest = fake_root / "manifests" / "m.yaml"
    manifest.parent.mkdir()
    manifest.write_text("run: {}\n")

    def go(*args, **extra):
        args = tuple(str(manifest) if a == "MANIFEST" else a for a in args)
        p = subprocess.run(["bash", str(fake_root / "deploy" / "run-and-upload.sh"), *args],
                           env={**env, **extra}, capture_output=True, text=True)
        calls = log.read_text().splitlines() if log.exists() else []
        return p, calls, str(run_dir)

    return go


def test_upload_receives_the_run_dir_from_run_json(harness):
    p, calls, run_dir = harness("MANIFEST")
    assert p.returncode == 0, p.stderr
    assert calls[0].startswith("run ") and "--json" in calls[0]
    assert calls[1] == f"upload {run_dir}"


def test_second_argument_becomes_the_stack(harness):
    p, calls, run_dir = harness("MANIFEST", "Production")
    assert p.returncode == 0, p.stderr
    assert calls[1] == f"upload {run_dir} --stack Production"


def test_collect_failure_still_uploads_and_exits_with_the_collect_code(harness):
    p, calls, run_dir = harness("MANIFEST", STUB_RUN_RC="1")
    assert p.returncode == 1
    assert calls[1] == f"upload {run_dir}"
    assert "collect exited 1" in p.stderr


def test_upload_failure_is_the_exit_code(harness):
    p, _calls, _ = harness("MANIFEST", STUB_UPLOAD_RC="1")
    assert p.returncode == 1


def test_no_manifest_is_a_usage_error(harness):
    p, calls, _ = harness()
    assert p.returncode == 2 and calls == []
    assert "usage" in p.stderr


def test_a_run_without_a_summary_does_not_upload(harness):
    p, calls, _ = harness("MANIFEST", STUB_RUN_SUMMARY="not json")
    assert p.returncode != 0
    assert not any(c.startswith("upload") for c in calls)


SUMMARY_WITH_INVOCATIONS = {
    "ok": False,
    "invocations": [
        {"fetcher_name": "aws_x", "entry_key": "aws_x", "target": {"region": "us-east-1"}, "exit_code": 0},
        {"fetcher_name": "okta_y", "entry_key": "okta_y", "target": None, "exit_code": 1,
         "stderr_tail": "starting\nauth failed: HTTP 401\n"},
    ],
}


def _collect_summary_is_on_stderr(stderr: str, run_dir: str) -> None:
    lines = stderr.splitlines()
    assert any("aws_x" in ln and '"region":"us-east-1"' in ln and "exit 0" in ln for ln in lines), stderr
    assert any("okta_y" in ln and "exit 1: auth failed: HTTP 401" in ln for ln in lines), stderr
    assert any(run_dir in ln for ln in lines), stderr


def test_collect_summary_goes_to_stderr(harness, tmp_path):
    run_dir = str(tmp_path / "evidence" / "run-20260101-000000-ab12")
    p, calls, _ = harness("MANIFEST", STUB_RUN_RC="1",
                          STUB_RUN_SUMMARY=json.dumps({**SUMMARY_WITH_INVOCATIONS, "run_dir": run_dir}))
    assert p.returncode == 1
    _collect_summary_is_on_stderr(p.stderr, run_dir)
    assert calls[1] == f"upload {run_dir}"


def test_root_script_uploads_the_run_it_collected(tmp_path):
    """./run_and_upload.sh calls .venv/bin/paramify; a stub stands in for it."""
    root = tmp_path / "root"
    (root / ".venv" / "bin").mkdir(parents=True)
    stub = root / ".venv" / "bin" / "paramify"
    stub.write_text(STUB)
    stub.chmod(0o755)
    py = root / ".venv" / "bin" / "python"
    py.symlink_to(shutil.which("python3"))
    shutil.copy(REPO_ROOT / "run_and_upload.sh", root / "run_and_upload.sh")
    log = tmp_path / "calls.log"
    run_dir = tmp_path / "run-x"
    env = {**os.environ, "STUB_LOG": str(log),
           "STUB_RUN_SUMMARY": json.dumps({**SUMMARY_WITH_INVOCATIONS, "run_dir": str(run_dir)})}
    p = subprocess.run(["bash", str(root / "run_and_upload.sh")], env=env, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    calls = log.read_text().splitlines()
    assert calls[0].startswith("run ") and "--json" in calls[0]
    assert calls[1] == f"upload {run_dir}"
    _collect_summary_is_on_stderr(p.stderr, str(run_dir))
