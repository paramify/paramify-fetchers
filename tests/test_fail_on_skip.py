"""--fail-on-skip (tests/conftest.py) fails any run that skipped or xfailed something."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

PROBES = {
    "skip": "import pytest\n\ndef test_it():\n    pytest.skip('probe')\n",
    "module_skip": "import pytest\n\npytest.importorskip('no_such_module_anywhere')\n",
    "xfail_marker": "import pytest\n\n@pytest.mark.xfail(reason='probe')\ndef test_it():\n    assert False\n",
    "xfail_call": "import pytest\n\ndef test_it():\n    pytest.xfail('probe')\n",
    "clean": "def test_it():\n    pass\n",
}


def _exit_code(tmp_path: Path, probe: str, *flags: str) -> int:
    shutil.copy(Path(__file__).with_name("conftest.py"), tmp_path / "conftest.py")
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    pass\n")
    (tmp_path / "test_probe.py").write_text(PROBES[probe])
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *flags],
        cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        capture_output=True, text=True, timeout=120,
    )
    return proc.returncode


@pytest.mark.parametrize("probe", ["skip", "module_skip", "xfail_marker", "xfail_call"])
def test_a_run_that_did_not_run_everything_fails(tmp_path, probe):
    assert _exit_code(tmp_path, probe) == 0
    assert _exit_code(tmp_path, probe, "--fail-on-skip") == 1


def test_a_clean_run_passes(tmp_path):
    assert _exit_code(tmp_path, "clean", "--fail-on-skip") == 0
