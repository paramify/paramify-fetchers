"""deploy/run-and-upload.sh uploads the run it just made, through `paramify upload`.

A stub `paramify` first on PATH records its argv; `run --print-run-dir` prints
a progress log to stderr and a run directory to stdout. No fetcher runs.
tests/test_run_summary.py checks what the real `--print-run-dir` prints.
"""
from __future__ import annotations

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
  run) printf '%s\\n' "$STUB_RUN_LOG" >&2; printf '%s' "$STUB_RUN_DIR"; exit "${STUB_RUN_RC:-0}" ;;
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
        "STUB_RUN_DIR": f"{run_dir}\n",
        "STUB_RUN_LOG": "",
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


def test_upload_receives_the_run_dir_the_collect_printed(harness):
    p, calls, run_dir = harness("MANIFEST")
    assert p.returncode == 0, p.stderr
    assert calls[0].startswith("run ") and calls[0].endswith(" --print-run-dir")
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


def test_a_run_without_a_run_dir_does_not_upload(harness):
    p, calls, _ = harness("MANIFEST", STUB_RUN_DIR="", STUB_RUN_RC="1",
                          STUB_RUN_LOG="Setup failed: no such manifest")
    assert p.returncode == 1
    assert not any(c.startswith("upload") for c in calls)
    assert "Setup failed: no such manifest" in p.stderr
    assert "nothing to upload" in p.stderr


# What `paramify run --print-run-dir` writes to stderr for a skip, a setup
# error, a note and a failed invocation (see tests/test_run_summary.py).
COLLECT_LOG = """\
  SKIP  okta_ghost (not discovered)
  RUN   aws_x
        runner error: aws_x: required config 'url' has no value
  RUN   aws_y
        NOTE  1 optional secret not injected
        [OK] exit=0 duration=0.1s
  RUN   okta_y
        [FAIL] exit=1 duration=0.2s
        auth failed: HTTP 401"""


def test_the_collect_log_reaches_the_cron_log(harness):
    p, calls, run_dir = harness("MANIFEST", STUB_RUN_RC="1", STUB_RUN_LOG=COLLECT_LOG)
    assert p.returncode == 1
    assert COLLECT_LOG in p.stderr
    assert calls[1] == f"upload {run_dir}"


def test_root_script_uploads_the_run_it_collected(tmp_path):
    """./run_and_upload.sh calls .venv/bin/paramify; a stub stands in for it. It needs no Python."""
    root = tmp_path / "root"
    (root / ".venv" / "bin").mkdir(parents=True)
    stub = root / ".venv" / "bin" / "paramify"
    stub.write_text(STUB)
    stub.chmod(0o755)
    shutil.copy(REPO_ROOT / "run_and_upload.sh", root / "run_and_upload.sh")
    log = tmp_path / "calls.log"
    run_dir = tmp_path / "run-x"
    env = {**os.environ, "STUB_LOG": str(log), "STUB_RUN_RC": "1",
           "STUB_RUN_DIR": f"{run_dir}\n", "STUB_RUN_LOG": COLLECT_LOG}
    p = subprocess.run(["bash", str(root / "run_and_upload.sh")], env=env, capture_output=True, text=True)
    assert p.returncode == 1, p.stderr
    calls = log.read_text().splitlines()
    assert calls[0] == "run manifest.yaml --print-run-dir"
    assert calls[1] == f"upload {run_dir}"
    assert COLLECT_LOG in p.stderr
