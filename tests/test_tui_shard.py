"""--shard I/N (tests/conftest.py): the tui job's shards run every TUI test exactly once.

The tui matrix runs the suite as several jobs. If the shards overlapped, a job
would waste time; if they missed a test, it would run nowhere and the job
would still go green. A snapshot module must stay whole, so the snapshot
plugin sees all of a file's snapshots in one run.

Each shard is collected in a subprocess, as CI runs it.

Run: ``pytest tests/test_tui_shard.py``
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("textual")
pytest.importorskip("pytest_textual_snapshot")

REPO_ROOT = Path(__file__).resolve().parent.parent
TUI_TESTS = sorted(
    str(p.relative_to(REPO_ROOT))
    for p in [*REPO_ROOT.glob("tests/test_tui_*.py"),
              REPO_ROOT / "tests" / "test_manifest_autosave.py",
              REPO_ROOT / "tests" / "test_target_editor.py"]
)
SNAPSHOTS = "tests/test_tui_snapshots.py"


def _collect(*args: str) -> list:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_")}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *args, *TUI_TESTS],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return [line for line in proc.stdout.splitlines() if "::" in line]


def test_the_shards_run_every_test_once_and_keep_snapshots_whole():
    count = 3  # TUI_SHARDS in .github/workflows/ci.yml
    everything = _collect()
    shards = [_collect("--shard", f"{i}/{count}") for i in range(1, count + 1)]

    assert sorted(t for shard in shards for t in shard) == sorted(everything)
    snapshots = [t for t in everything if t.startswith(SNAPSHOTS)]
    assert snapshots, "no snapshot tests collected, so this checks nothing"
    assert [sum(t.startswith(SNAPSHOTS) for t in shard) for shard in shards].count(len(snapshots)) == 1
    sizes = [len(shard) for shard in shards]
    assert max(sizes) - min(sizes) <= len(snapshots)


def test_a_shard_outside_the_count_is_refused():
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_")}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "--shard", "4/3", "tests/test_tui_shard.py"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == pytest.ExitCode.USAGE_ERROR
    assert "I must be from 1 to N" in proc.stderr
