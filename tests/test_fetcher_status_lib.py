"""The shared failure-reporting helpers in `fetchers/_lib/`.

Both runtimes must behave identically, because a fetcher author picks one by
language and the contract promises the same thing either way
(docs/fetcher_contract_guide.md, step 6). So every behavioural test here runs against
the Python helper AND the bash one, from the same table.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LIB = REPO_ROOT / "fetchers" / "_lib"

CODES = {
    "auth_failed",
    "not_authorized",
    "target_unreachable",
    "rate_limited",
    "bad_config",
    "partial_failure",
    "internal_error",
    "input_failed",
}


# --------------------------------------------------------------------------- #
# Drivers: run report_failure in each runtime, return (status_dict_or_None, stderr)
# --------------------------------------------------------------------------- #

def _as_fetcher_path(tmp_path, as_fetcher, suffix):
    """Materialise <tmp>/fetchers/<category>/<name>/fetcher.<ext> so the helper's
    label derivation has a real path shaped like a fetcher to read."""
    category, name = as_fetcher.split("/")
    d = tmp_path / "fetchers" / category / name
    d.mkdir(parents=True, exist_ok=True)
    return d / f"fetcher.{suffix}"


def _run_python(tmp_path, reason, code, set_status_file=True, as_fetcher=None):
    status = tmp_path / "status.json"
    script = (
        "import sys; sys.path.insert(0, %r)\n"
        "import logging; logging.basicConfig(level='INFO', format='%%(levelname)s %%(name)s %%(message)s')\n"
        "from fetcher_status import report_failure\n"
        "report_failure(%r, %s)\n" % (str(LIB), reason, repr(code) if code else "None")
    )
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin"}
    if set_status_file:
        env["FETCHER_STATUS_FILE"] = str(status)
    if as_fetcher:
        entry = _as_fetcher_path(tmp_path, as_fetcher, "py")
        entry.write_text(script)
        cmd = [sys.executable, str(entry)]
    else:
        cmd = [sys.executable, "-c", script]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    return (json.loads(status.read_text()) if status.exists() else None), proc.stderr


def _run_bash(tmp_path, reason, code, set_status_file=True, as_fetcher=None):
    status = tmp_path / "status.json"
    body = 'source "%s/status.sh"\nreport_failure "$1" ${2:+"$2"}\n' % LIB
    if as_fetcher:
        sh = _as_fetcher_path(tmp_path, as_fetcher, "sh")
    else:
        sh = tmp_path / "drive.sh"
    sh.write_text(body)
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin"}
    # $FETCHER is what the category scripts set; unset it when we are testing the
    # path-derived fallback, which is the case that was broken.
    if not as_fetcher:
        env["FETCHER"] = "test_fetcher"
    if set_status_file:
        env["FETCHER_STATUS_FILE"] = str(status)
    args = ["bash", str(sh), reason] + ([code] if code else [])
    proc = subprocess.run(args, capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    return (json.loads(status.read_text()) if status.exists() else None), proc.stderr


RUNTIMES = pytest.mark.parametrize("run", [_run_python, _run_bash], ids=["python", "bash"])


# --------------------------------------------------------------------------- #

@RUNTIMES
def test_writes_error_and_code(tmp_path, run):
    status, _ = run(tmp_path, "GitLab API read timeout after 30s", "target_unreachable")
    assert status == {"error": "GitLab API read timeout after 30s", "code": "target_unreachable"}


@RUNTIMES
def test_code_is_optional(tmp_path, run):
    status, _ = run(tmp_path, "collection failed", None)
    assert status == {"error": "collection failed"}
    assert "code" not in status


@RUNTIMES
@pytest.mark.parametrize("code", sorted(CODES))
def test_every_contract_code_survives(tmp_path, run, code):
    status, _ = run(tmp_path, "boom", code)
    assert status["code"] == code


@RUNTIMES
def test_unrecognized_code_is_dropped_not_written(tmp_path, run):
    """A typo must not invent a category that downstream code reads."""
    status, stderr = run(tmp_path, "boom", "not_a_real_code")
    assert "code" not in status
    assert status["error"] == "boom"
    assert "not_a_real_code" in stderr  # and it says so


@RUNTIMES
def test_multiline_error_is_collapsed_to_one_line(tmp_path, run):
    """`error` is a single-line field; API errors wrap."""
    status, _ = run(tmp_path, "line one\nline two\n\tline three", "internal_error")
    assert status["error"] == "line one line two line three"
    assert "\n" not in status["error"]


@RUNTIMES
def test_empty_reason_gets_a_usable_default(tmp_path, run):
    status, _ = run(tmp_path, "   ", None)
    assert status["error"] == "collection failed"


@RUNTIMES
def test_long_error_is_bounded_and_marked(tmp_path, run):
    status, _ = run(tmp_path, "x" * 5000, None)
    assert len(status["error"]) < 5000
    assert status["error"].endswith("...")


@RUNTIMES
def test_no_status_file_env_is_a_silent_no_op(tmp_path, run):
    """Running a fetcher by hand must not fail, and must still log."""
    status, stderr = run(tmp_path, "ran by hand", None, set_status_file=False)
    assert status is None
    assert "ran by hand" in stderr


@RUNTIMES
def test_the_reason_reaches_stderr(tmp_path, run):
    """report_failure is the WHOLE failure path — it logs as well as reports,
    so callers don't need their own log_error and the reason is last on stderr."""
    _, stderr = run(tmp_path, "the actual cause", "auth_failed")
    assert "the actual cause" in stderr
    assert "ERROR" in stderr.upper()


@RUNTIMES
def test_unwritable_status_path_does_not_fail_the_run(tmp_path, run):
    """The exit code is the authoritative signal; the status channel must never
    turn a reportable failure into a crash."""
    bad = tmp_path / "not-a-dir"
    bad.write_text("i am a file")
    status_file = bad / "nested" / "status.json"
    # Drive it manually so we can point at an impossible path.
    if run is _run_python:
        script = (
            "import sys; sys.path.insert(0, %r)\n"
            "from fetcher_status import report_failure\n"
            "report_failure('boom', 'internal_error')\n" % str(LIB)
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin", "FETCHER_STATUS_FILE": str(status_file)},
        )
    else:
        sh = tmp_path / "d.sh"
        sh.write_text('source "%s/status.sh"\nreport_failure boom internal_error\n' % LIB)
        proc = subprocess.run(
            ["bash", str(sh)],
            capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin:/usr/local/bin", "FETCHER_STATUS_FILE": str(status_file)},
        )
    assert proc.returncode == 0, proc.stderr
    assert "boom" in proc.stderr


# --------------------------------------------------------------------------- #
# The two runtimes must not drift apart.
# --------------------------------------------------------------------------- #

def test_python_and_bash_agree_on_the_code_set():
    sys.path.insert(0, str(LIB))
    import fetcher_status

    assert set(fetcher_status.STATUS_CODES) == CODES
    sh = (LIB / "status.sh").read_text()
    for code in CODES:
        assert code in sh, f"{code} missing from the bash case statement"


@RUNTIMES
@pytest.mark.parametrize(
    "raw,expected",
    [
        # Callers join a failure log with `tr '\n' ';'`, which leaves a dangling
        # separator on the last entry.
        ("2 failures; first: call A failed;call B failed;", "2 failures; first: call A failed;call B failed"),
        # A blank line in the log becomes an empty segment.
        ("first: call A failed;;call B failed", "first: call A failed;call B failed"),
        ("a;;;b", "a;b"),
        (";leading", "leading"),
    ],
)
def test_separator_noise_is_collapsed(tmp_path, run, raw, expected):
    """100+ call sites build the reason by joining a log file. Normalising here
    means each one doesn't have to get the joining exactly right."""
    status, _ = run(tmp_path, raw, None)
    assert status["error"] == expected


@RUNTIMES
def test_log_line_is_attributed_to_the_fetcher_not_the_helper(tmp_path, run):
    """Every entry script is named fetcher.py/fetcher.sh, so a basename is always
    the useless string "fetcher" — the identity is in the enclosing directories."""
    status, stderr = run(tmp_path, "boom", None, as_fetcher="aws/guard_duty")
    assert "aws_guard_duty" in stderr, stderr
    assert " fetcher " not in stderr, stderr


@pytest.mark.parametrize(
    "reason,code",
    [
        ("plain", None),
        ("with code", "rate_limited"),
        ("multi\nline", "bad_config"),
        ("   ", None),
        ("x" * 3000, "partial_failure"),
        ("bogus code", "nope"),
    ],
)
def test_identical_output_across_runtimes(tmp_path, reason, code):
    py, _ = _run_python(tmp_path / "py", reason, code)
    sh, _ = _run_bash(tmp_path / "sh", reason, code)
    assert py == sh, f"runtimes disagree for {reason!r}/{code!r}"


@pytest.fixture(autouse=True)
def _mkdirs(tmp_path):
    (tmp_path / "py").mkdir(exist_ok=True)
    (tmp_path / "sh").mkdir(exist_ok=True)
