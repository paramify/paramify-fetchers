"""Launch the real TUI in a pseudo-terminal, press q, expect a clean exit.

The pilot tests drive FetcherApp in-process; this covers what they skip: the
entry points, argument parsing, the terminal driver and teardown.
"""

from __future__ import annotations

import os
import re
import select
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")
pty = pytest.importorskip("pty", reason="needs a POSIX pseudo-terminal")

import fcntl  # noqa: E402
import termios  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
ROWS, COLS = 50, 160
TIMEOUT = 60.0
_ESCAPES = re.compile(rb"\x1b(\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)|[PX^_][^\x1b]*\x1b\\|.)")

WORKSPACE = "paramify fetcher"
WELCOME = "collect compliance evidence"


def _paramify() -> str:
    beside = Path(sys.executable).with_name("paramify")
    return str(beside) if beside.exists() else (shutil.which("paramify") or str(beside))


def _launch(argv: list, ready: str) -> tuple:
    """Run argv on a pty until `ready` is drawn, press q; return (exit code or None, seen, text)."""
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    env = {**os.environ, "TERM": "xterm-256color", "PYTHON_DOTENV_DISABLED": "1"}
    proc = subprocess.Popen(argv, cwd=REPO_ROOT, env=env, stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    raw = bytearray()
    deadline = time.monotonic() + TIMEOUT
    seen = False
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:  # EIO: the child closed the pty
                    break
                if not chunk:
                    break
                raw.extend(chunk)
            if not seen and ready.encode() in _ESCAPES.sub(b"", bytes(raw)):
                seen = True
                os.write(master, b"q")
            if proc.poll() is not None and not select.select([master], [], [], 0)[0]:
                break
        try:
            code = proc.wait(timeout=max(deadline - time.monotonic(), 1))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            code = None
    finally:
        os.close(master)
    return code, seen, _ESCAPES.sub(b"", bytes(raw)).decode("utf-8", "replace")


@pytest.mark.parametrize(
    "argv, ready",
    [
        ([_paramify(), "tui", "--manifest", "examples/demo.yaml"], WORKSPACE),
        ([sys.executable, "-m", "framework.tui", "--manifest", "examples/demo.yaml"], WORKSPACE),
        ([sys.executable, "-m", "framework.tui"], WELCOME),
    ],
    ids=["paramify-tui", "module-manifest", "module-welcome"],
)
def test_launch_and_quit(argv, ready):
    code, seen, screen = _launch(argv, ready)
    tail = screen[-2000:]
    assert seen, f"{ready!r} never appeared within {TIMEOUT:.0f}s:\n{tail}"
    assert code == 0, f"exit code {code}:\n{tail}"
    assert "Traceback" not in screen, tail
