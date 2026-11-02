"""The per-run batch cache and run lock."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from framework.run_files import UPLOAD_LOCK_FILE, UPLOAD_STATE_FILE, is_evidence_file
from framework.sync import state as state_mod
from framework.sync.state import RunLocked, RunState


def test_record_then_read_back(tmp_path: Path) -> None:
    rs = RunState(tmp_path)
    assert rs.batch_for("a") is None
    rs.record_batch("a", "b-1")
    rs.record_batch("b", "b-2")
    fresh = RunState(tmp_path)
    assert fresh.batch_for("a") == "b-1"
    assert fresh.batch_for("b") == "b-2"
    assert json.loads((tmp_path / UPLOAD_STATE_FILE).read_text()) == {
        "batches": {"a": "b-1", "b": "b-2"}
    }


def test_corrupt_file_reads_as_missing(tmp_path: Path, caplog: Any) -> None:
    (tmp_path / UPLOAD_STATE_FILE).write_text("{not json")
    assert RunState(tmp_path).batch_for("a") is None
    assert "warning" in {r.levelname.lower() for r in caplog.records}


def test_crash_before_replace_keeps_old_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rs = RunState(tmp_path)
    rs.record_batch("a", "b-1")
    before = (tmp_path / UPLOAD_STATE_FILE).read_text()

    def boom(*_a: Any, **_k: Any) -> None:
        raise OSError("crash")

    monkeypatch.setattr(state_mod.os, "replace", boom)
    with pytest.raises(OSError):
        rs.record_batch("b", "b-2")
    monkeypatch.undo()
    assert (tmp_path / UPLOAD_STATE_FILE).read_text() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == [UPLOAD_STATE_FILE]


_HOLD = """
import sys
from pathlib import Path
from framework.sync.state import RunState
with RunState(Path(sys.argv[1])).lock():
    print("held", flush=True)
    sys.stdin.readline()
"""


def test_lock_is_exclusive_across_processes(tmp_path: Path) -> None:
    # A fresh interpreter (spawn-like), independent of how pytest imports tests.
    repo = Path(__file__).resolve().parent.parent
    child = subprocess.Popen(
        [sys.executable, "-c", _HOLD, str(tmp_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        cwd=repo,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "held"
        with pytest.raises(RunLocked, match="another upload of this run"):
            with RunState(tmp_path).lock():
                pass
    finally:
        if child.stdin:
            child.stdin.write("\n")
            child.stdin.close()
        try:
            child.wait(10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
    with RunState(tmp_path).lock():
        pass


def test_bookkeeping_files_are_not_evidence(tmp_path: Path) -> None:
    assert not is_evidence_file(tmp_path / UPLOAD_STATE_FILE)
    assert not is_evidence_file(tmp_path / UPLOAD_LOCK_FILE)
