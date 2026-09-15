"""Every fetcher must say WHY it failed — the guard against issue #24 returning.

The bug: a fetcher caught its exception into the payload, logged an unconditional
"Evidence saved to ..." at INFO, then exited non-zero. The runner takes the tail
of stderr as the envelope's ``metadata.error``, so the only thing on stderr at
exit was that INFO line — and a *failed* collection reported a success message as
its failure reason. Paramify shows that field to whoever is triaging, so it
pointed them away from the real problem.

That was never one fetcher's mistake. It was the contract not saying where a
failure reason goes, so 16 fetchers independently invented the same wrong answer.
The contract says it now (docs/fetcher_contract.md § Output), and this file is
what keeps it true — an unenforced rule is a suggestion, and the next fetcher
someone writes has no memory of this.

Two layers:

  1. A STATIC scan of every shipped fetcher: no non-zero exit path may be silent.
     Fast, no network, no credentials — so it can gate every commit.
  2. A RUNTIME check that drives a real shipped fetcher to a real failure and
     asserts the envelope carries the actual cause.

The static scan is a heuristic over source, so it is itself tested: see
``test_the_checker_actually_detects_the_bug`` — a conformance check that cannot
fail is worse than none, because it reads as coverage.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHERS = REPO_ROOT / "fetchers"

# Calls that count as "told someone why this failed": ONLY a report through
# $FETCHER_STATUS_FILE, via the shared `report_failure` helper in fetchers/_lib/.
#
# This used to also credit an error-level log or any write to stderr
# (`logger.error`, `log_error`, `>&2`). That was the loophole: all 80 AWS
# fetchers logged a bare "Encountered 3 API failures during collection" to
# stderr and passed this test for months while reporting no cause at all. An
# operator saw the count and nothing else. Logging is necessary but not
# sufficient — the runner's stderr-tail fallback is a heuristic, and the
# envelope's metadata.error is the field Paramify actually shows.
#
# `write_status` is the deprecated alias azure_common and gcp_common still
# expose; 46 azure and gcp call sites use it. It is accepted here so this scan
# could be tightened without renaming those in the same change. Remove it from
# this tuple in the pass that renames them — see docs/fetcher_contract.md
# § Output, which names `report_failure` as the one name.
_PY_REPORT_NAMES = ("report_failure", "write_status")
_SH_REPORT = re.compile(r"report_failure|FETCHER_STATUS_FILE")

# Justified exceptions. Keep this list SHORT and cite the line that does the
# reporting — a growing allowlist means the rule isn't working.
# Empty, and worth keeping that way. It previously exempted the two checkov
# fetchers' clone-failure `exit 1`, on the grounds that clone.sh logged the
# reason itself and the scanner cannot see across files. Both now call
# `report_failure` directly, so the exemptions are gone rather than merely
# re-pointed — and the entries had already gone stale, since those exits moved
# to different line numbers.
_ALLOWED: set[tuple[str, int]] = set()


# --------------------------------------------------------------------------- #
# The checker
# --------------------------------------------------------------------------- #

def _is_report_call(call: ast.Call) -> bool:
    """A bare call to the shared helper. Attribute calls (`logger.error(...)`)
    and `print(..., file=sys.stderr)` deliberately do NOT count — see the note
    on _PY_REPORT_NAMES for why crediting them made this scan pass 80 fetchers
    that reported nothing."""
    f = call.func
    return isinstance(f, ast.Name) and f.id in _PY_REPORT_NAMES


def _py_reports(stmt: ast.AST) -> bool:
    """Is this statement *itself* a report of why the run failed?

    Deliberately NOT a subtree walk. An error log nested inside a conditional
    only fires on that condition, so crediting it for a later unconditional exit
    hides exactly the shape sentinelone had:

        if result.get("api_failures"):      # empty when the exception came from
            logger.error(...)               # outside the paginator
            return 1
        return 0 if status in {...} else 1  # ...so this exits 1 having logged
                                            #    nothing but the INFO line
    """
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) \
        and _is_report_call(stmt.value)


def _nonzero_int(node) -> bool:
    """A literal non-zero int. Excludes bools: `return True` is a helper's
    answer, not an exit code, and bool is an int subclass in Python."""
    return (isinstance(node, ast.Constant) and isinstance(node.value, int)
            and not isinstance(node.value, bool) and node.value != 0)


def _returns_nonzero(node) -> bool:
    """A return that can hand back a non-zero exit code.

    Covers the ternary the bug wore: `return 0 if status == "success" else 1`.
    That is an IfExp, not a Constant, so a checker that only matched literals
    would have missed all 16 original offenders.
    """
    if _nonzero_int(node):
        return True
    if isinstance(node, ast.IfExp):
        return _nonzero_int(node.body) or _nonzero_int(node.orelse)
    return False


def _entry_function(tree: ast.Module) -> str:
    """The function whose return value becomes the process exit code.

    `sys.exit(main())` at module level makes `main`'s returns exit codes. A bare
    `return 1` anywhere else is just a value — scanning those produced false
    positives on helpers like `return True` / `return "aws"`.
    """
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "exit":
            if n.args and isinstance(n.args[0], ast.Call) and isinstance(n.args[0].func, ast.Name):
                return n.args[0].func.id
    return "main"


def silent_python_exits(source: str) -> list[int]:
    """Line numbers of non-zero exits with no failure reason reported first."""
    tree = ast.parse(source)
    entry = _entry_function(tree)
    bad: list[int] = []

    def is_exit(stmt, in_entry: bool) -> bool:
        if in_entry and isinstance(stmt, ast.Return) and _returns_nonzero(stmt.value):
            return True
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            f = stmt.value.func
            if isinstance(f, ast.Attribute) and f.attr == "exit":
                return bool(stmt.value.args) and _nonzero_int(stmt.value.args[0])
        return False

    def scan(body, in_entry: bool, reported: bool) -> None:
        for i, stmt in enumerate(body):
            if is_exit(stmt, in_entry) and not (reported or any(_py_reports(s) for s in body[:i + 1])):
                bad.append(stmt.lineno)
            # A report before this branch covers exits inside it.
            outer = reported or any(_py_reports(s) for s in body[:i])
            for field in ("body", "orelse", "finalbody"):
                sub = getattr(stmt, field, None)
                if isinstance(sub, list):
                    scan(sub, in_entry, outer)
            for handler in getattr(stmt, "handlers", []):
                scan(handler.body, in_entry, outer)

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scan(node.body, node.name == entry, False)
        else:
            scan([node], False, False)
    return bad


def silent_bash_exits(source: str) -> list[int]:
    """Same, for bash. Comments are stripped first — an `exit 1` mentioned in a
    prose comment is not an exit path (that produced two false positives)."""
    lines = [re.sub(r"(^|\s)#.*$", "", ln) for ln in source.splitlines()]
    bad: list[int] = []
    for i, line in enumerate(lines):
        if re.search(r"\bexit\s+[1-9]", line):
            window = "\n".join(lines[max(0, i - 6):i + 1])
            if not _SH_REPORT.search(window):
                bad.append(i + 1)
    return bad


# --------------------------------------------------------------------------- #
# The checker is itself tested — it must be able to FAIL
# --------------------------------------------------------------------------- #

_THE_BUG = '''\
import logging, sys
logger = logging.getLogger("x")

def main() -> int:
    result = collect()
    logger.info("Evidence saved to %s", "out.json")
    return 0 if result.get("status") == "success" else 1

if __name__ == "__main__":
    sys.exit(main())
'''

# A log alone is NOT the fix any more — that is what _THE_HALF_FIX below is for.
_THE_FIX = '''\
import logging, sys
logger = logging.getLogger("x")

def main() -> int:
    result = collect()
    logger.info("Evidence saved to %s", "out.json")
    if result.get("status") != "success":
        report_failure(result["message"], "partial_failure")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
'''

# The shape that used to satisfy this scan: it tells a human on stderr but hands
# the runner nothing, so metadata.error still falls back to the stderr tail --
# here the "Evidence saved" INFO line. 80 AWS fetchers sat in exactly this state.
_THE_HALF_FIX = '''\
import logging, sys
logger = logging.getLogger("x")

def main() -> int:
    result = collect()
    logger.info("Evidence saved to %s", "out.json")
    if result.get("status") != "success":
        logger.error("collection failed: %s", result["message"])
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
'''


def test_the_checker_actually_detects_the_bug():
    """Issue #24's exact shape must be flagged, or this whole file is theater."""
    assert silent_python_exits(_THE_BUG), "the checker missed the bug it exists to catch"


def test_the_checker_accepts_the_fix():
    assert silent_python_exits(_THE_FIX) == []


def test_a_log_alone_is_not_a_report():
    """The loophole this scan used to have, pinned shut.

    Logging the reason is necessary but not sufficient: the runner reads
    $FETCHER_STATUS_FILE, and only falls back to the stderr *tail* when nothing
    wrote one. If a mere `logger.error` satisfies this checker again, every
    category can drift back to reporting a bare count.
    """
    assert silent_python_exits(_THE_HALF_FIX), \
        "a stderr log with no status-file report must NOT count as reporting why"


def test_checker_ignores_helper_return_values():
    """`return True` / `return "aws"` in a helper is an answer, not an exit code."""
    src = 'import sys\ndef looks_like_aws(h):\n    return True\ndef main():\n    return 0\n'
    assert silent_python_exits(src) == []


def test_checker_catches_bare_sys_exit_too():
    assert silent_python_exits("import sys\nsys.exit(1)\n") == [2]


def test_bash_checker_detects_and_accepts():
    assert silent_bash_exits('if [ -z "$TOKEN" ]; then\n    exit 1\nfi\n')
    assert silent_bash_exits(
        'if [ -z "$TOKEN" ]; then\n    report_failure "no token" bad_config\n    exit 1\nfi\n'
    ) == []


def test_bash_log_error_alone_is_not_a_report():
    """Same loophole, bash side: `log_error` reaches a human tailing the run,
    not the runner. This is the exact shape all 80 AWS fetchers had."""
    assert silent_bash_exits(
        'if [ "$failures" -gt 0 ]; then\n'
        '    log_error "Encountered $failures API failures during collection"\n'
        '    exit 1\nfi\n'
    ), "log_error with no status-file report must NOT count as reporting why"


def test_bash_checker_ignores_exit_mentioned_in_a_comment():
    assert silent_bash_exits("# only a real failure gets logged (exit 1)\nfoo\n") == []


# --------------------------------------------------------------------------- #
# The scan over every shipped fetcher
# --------------------------------------------------------------------------- #

def _fetchers(suffix: str):
    return sorted(FETCHERS.glob(f"*/*/fetcher.{suffix}"))


def _shared_shell_libs():
    """The per-category _shared/*.sh a fetcher sources.

    These have to be scanned too. When the AWS epilogue moved out of all 80
    fetchers into aws_finish, the `exit 1` moved with it — and the per-fetcher
    scan below stopped seeing it, because its glob only matches fetcher.sh.
    Coverage went from 80 files to 3 without a single test failing. An
    extraction must not be able to empty this check out.
    """
    return sorted(FETCHERS.glob("*/_shared/*.sh"))


@pytest.mark.parametrize("path", _fetchers("py"), ids=lambda p: f"{p.parent.parent.name}/{p.parent.name}")
def test_python_fetcher_reports_why_it_failed(path):
    silent = [ln for ln in silent_python_exits(path.read_text())
              if (str(path.relative_to(FETCHERS)), ln) not in _ALLOWED]
    assert not silent, (
        f"{path.relative_to(REPO_ROOT)} exits non-zero at line(s) {silent} without "
        "logging why.\n\nThe runner falls back to the TAIL of stderr for "
        "metadata.error, so if your last log line is an INFO message, that is what "
        "an operator sees as the failure reason (issue #24). Log the reason at "
        "error level AFTER any 'Evidence saved' line, and write it to "
        "$FETCHER_STATUS_FILE. See docs/porting_playbook.md § 'Say why you failed'."
    )


@pytest.mark.parametrize("path", _fetchers("sh"), ids=lambda p: f"{p.parent.parent.name}/{p.parent.name}")
def test_bash_fetcher_reports_why_it_failed(path):
    silent = [ln for ln in silent_bash_exits(path.read_text())
              if (str(path.relative_to(FETCHERS)), ln) not in _ALLOWED]
    assert not silent, (
        f"{path.relative_to(REPO_ROOT)} exits non-zero at line(s) {silent} without "
        "writing to stderr. Use the log_error helper and report_failure — see "
        "docs/porting_playbook.md § 'Say why you failed'."
    )


@pytest.mark.parametrize("path", _shared_shell_libs(),
                         ids=lambda p: f"{p.parent.parent.name}/{p.name}")
def test_shared_shell_lib_reports_why_it_exits(path):
    """A helper that exits non-zero owes the same explanation a fetcher does.

    aws_finish is the case in point: it is the last line of all 80 AWS
    fetchers, and its `exit 1` is now the only one most of them have.
    """
    silent = [ln for ln in silent_bash_exits(path.read_text())
              if (str(path.relative_to(FETCHERS)), ln) not in _ALLOWED]
    assert not silent, (
        f"{path.relative_to(REPO_ROOT)} exits non-zero at line(s) {silent} without "
        "reporting why. Every fetcher sourcing this inherits that silence."
    )


def test_the_scan_actually_covered_the_fetcher_tree():
    """A glob that silently matches nothing would make every test above vacuous."""
    assert len(_fetchers("py")) >= 30
    assert len(_fetchers("sh")) >= 80
    assert len(_shared_shell_libs()) >= 2


# --------------------------------------------------------------------------- #
# Runtime: a REAL shipped fetcher, driven to a real failure, end to end
# --------------------------------------------------------------------------- #

def test_real_fetcher_failure_reports_the_real_cause(tmp_path):
    """The whole chain on the fetcher from the bug report.

    Static analysis proves a reason gets logged; only this proves the reason
    survives the runner into `metadata.error` — the field Paramify shows the
    person triaging. Points at an RFC 2606 `.invalid` host, so it fails on DNS
    without contacting anything.
    """
    pytest.importorskip("requests")
    pytest.importorskip("dotenv")

    import os

    from framework.config_loader import discover_fetchers
    from framework.contract import ManifestEntry, TargetInstance
    from framework.envelope import wrap_outputs
    from framework.runner.executor import run_entry

    fetcher = discover_fetchers(REPO_ROOT)["gitlab_merge_request_summary"]
    entry = ManifestEntry(
        use=fetcher.name,
        targets=[TargetInstance(
            values={"project_id": "paramify/trust-center", "url": "https://gitlab.invalid"},
            # api_token is per_target: true, so it resolves from the target
            secrets={"api_token": "${env:PYTEST_FAKE_GITLAB_TOKEN}"},
        )],
    )

    os.environ["PYTEST_FAKE_GITLAB_TOKEN"] = "not-a-real-token"
    try:
        run_dir = tmp_path / "run"
        result = run_entry(fetcher, entry, run_dir)[0]
    finally:
        os.environ.pop("PYTEST_FAKE_GITLAB_TOKEN", None)

    assert result.exit_code != 0, "an unreachable host must fail the collection"

    wrap_outputs(result, fetcher, "test-run", run_dir)
    envelopes = [json.loads(p.read_text()) for p in run_dir.glob("*.json")]
    assert envelopes, "the fetcher wrote no evidence file to envelope"
    meta = envelopes[0]["metadata"]

    assert meta["status"] == "failed"

    # The regression itself: this field used to read "Evidence saved to ...".
    assert "Evidence saved" not in meta["error"], (
        "metadata.error is reporting a success message — issue #24 is back"
    )
    assert "gitlab.invalid" in meta["error"] or "resolve" in meta["error"].lower(), \
        f"expected the connection failure, got: {meta['error']!r}"

    # This fetcher reports through $FETCHER_STATUS_FILE, so the field is the bare
    # reason — not a slice of the log. If this starts failing, the fetcher has
    # fallen back to the stderr tail and the reason is buried in log lines again.
    assert not re.match(r"^\d{4}-\d{2}-\d{2} ", meta["error"]), \
        f"metadata.error looks like a log tail, not a reported reason: {meta['error'][:120]!r}"
    assert meta["error"].count("\n") == 0, "expected a single-line reason"


def test_allowlist_entries_still_exist():
    """A stale allowlist entry hides a real regression at that path.

    Checking only that the line number is *within* the file was too weak: both
    original entries had drifted onto unrelated lines and this still passed. An
    entry has to point at an actual non-zero exit to be exempting anything.
    """
    for rel, line in _ALLOWED:
        path = FETCHERS / rel
        assert path.exists(), f"allowlisted {rel} no longer exists — drop the entry"
        lines = path.read_text().splitlines()
        assert line <= len(lines), \
            f"allowlisted {rel}:{line} is past end of file — the code moved, re-verify it"
        target = re.sub(r"(^|\s)#.*$", "", lines[line - 1])
        pattern = r"\bexit\s+[1-9]" if path.suffix == ".sh" else r"return\s+[1-9]|sys\.exit\(\s*[1-9]"
        assert re.search(pattern, target), (
            f"allowlisted {rel}:{line} is not a non-zero exit any more — it reads "
            f"{target.strip()!r}. The code moved; re-verify and re-point or drop the entry."
        )


# --------------------------------------------------------------------------- #
# One spelling of the failure path
# --------------------------------------------------------------------------- #

def test_no_fetcher_reports_through_the_old_write_status_alias():
    """`report_failure` is the contract name; `write_status` was an alias.

    azure_common and gcp_common each aliased write_status = report_failure with
    a comment saying it was kept "until they are moved over". All 46 of their
    fetchers still called the alias, so the migration never happened and the
    corpus had two names for one function. The alias is now gone.
    """
    offenders = []
    for p in list(_fetchers("py")) + _shared_shell_libs() + list(FETCHERS.glob("*/_shared/*.py")):
        if re.search(r"\bwrite_status\b", p.read_text()):
            offenders.append(str(p.relative_to(FETCHERS)))
    assert not offenders, f"still using the removed write_status alias: {offenders}"


def test_no_fetcher_logs_the_failure_reason_twice():
    """report_failure logs the reason itself — callers must not log it first.

    Its docstring says so explicitly, and the reason it gives matters: logging
    inside report_failure is what guarantees the reason is the LAST thing on
    stderr, which is where the runner's fallback reads from.

    27 Azure fetchers logged a count with no cause ("Encountered N Azure API
    failure(s)") and 19 GCP fetchers logged the identical reason string, both
    immediately before the call. The count was redundant too: failure_reason()
    already begins "N Azure API failure(s); first: ...".
    """
    dupe = re.compile(r"logger\.error\((?:[^()]|\([^()]*\))*\)\s*\n\s*report_failure\(", re.M)
    offenders = [str(p.relative_to(FETCHERS)) for p in _fetchers("py")
                 if dupe.search(p.read_text())]
    assert not offenders, (
        f"these log the reason before report_failure, which logs it again: {offenders}"
    )
