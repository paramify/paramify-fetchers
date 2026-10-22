#!/usr/bin/env python3
"""Check the demo's `paramify run`/`validate`/`upload --dry-run` output against tests/goldens/cli/."""

from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from dotenv import dotenv_values

from framework.custom_tags import ENV_SWITCH
from framework.paramify_auth import BASE_URL_ENV, READ_TOKEN_ENV, UPLOAD_TOKEN_ENV

REPO_ROOT = Path(__file__).resolve().parent.parent
GOLDENS = REPO_ROOT / "tests" / "goldens" / "cli"
EVIDENCE = REPO_ROOT / "evidence"

# paramify(), offline_env() and normalise() are shared with the TUI tests via the cli_tools fixture.
PARAMIFY_ENV = (UPLOAD_TOKEN_ENV, READ_TOKEN_ENV, BASE_URL_ENV, ENV_SWITCH)
RUN_ID = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
ASCTIME = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}")
_DURATION = re.compile(r"duration=\d+(?:\.\d+)?s")
_RUN_LINE = re.compile(r"^Run \S+ → (.+)$", re.MULTILINE)


def paramify() -> str:
    """The paramify script beside this interpreter, else the one on PATH."""
    beside = Path(sys.executable).with_name("paramify")
    return str(beside) if beside.exists() else (shutil.which("paramify") or str(beside))


def _dotenv_names() -> set:
    """What the .env a bare load_dotenv() here finds sets: the nearest one up from the repo."""
    for folder in (REPO_ROOT, *REPO_ROOT.parents):
        if (folder / ".env").is_file():
            return set(dotenv_values(folder / ".env"))
    return set()


def offline_env() -> dict:
    """os.environ without PARAMIFY_*/AZURE_* or .env; the Paramify names stay set, empty."""
    # An earlier load_dotenv() in this process may have copied any .env name into os.environ.
    dotenv = _dotenv_names()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("PARAMIFY_", "AZURE_")) and k not in dotenv}
    # Empty, not unset: python-dotenv never overrides a variable that is set.
    env.update(dict.fromkeys(PARAMIFY_ENV, ""), PYTHON_DOTENV_DISABLED="1")
    return env


def normalise(text: str, roots, root: str = "<repo>", run_id: str = "<run-id>",
              timestamp: str = "<timestamp>", asctime: str = "<asctime>") -> str:
    """Replace the root paths, run ids and timestamps in text with fixed values."""
    for path in sorted(roots, key=len, reverse=True):
        text = _whole_path(path).sub(lambda _: root, text)
    for pattern, fixed in ((RUN_ID, run_id), (TIMESTAMP, timestamp), (ASCTIME, asctime)):
        text = pattern.sub(fixed, text)
    return text


def _whole_path(path: str) -> re.Pattern:
    """path where it stands on its own, not inside a longer name or a URL (/app in https://app.…)."""
    end = "" if path.endswith("/") else r"(?![\w-]|\.\w)"
    return re.compile(r"(?<![\w./:-])" + re.escape(path) + end)


def _paramify(args: list) -> subprocess.CompletedProcess:
    env = {**offline_env(), "NO_COLOR": "1"}
    env.pop("FORCE_COLOR", None)
    return subprocess.run(
        [paramify(), *args], cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120,
    )


def _capture(args: list, proc: subprocess.CompletedProcess) -> tuple:
    shown = " ".join(["paramify", *args])
    text = f"$ {shown}\nexit {proc.returncode}\n--- stdout\n{proc.stdout}--- stderr\n{proc.stderr}"
    text = normalise(text, {str(REPO_ROOT), str(REPO_ROOT.resolve())})
    return _DURATION.sub("duration=<n>s", text), proc.returncode


def _announced_run(stdout) -> Path | None:
    """The run directory `paramify run` printed, if it got that far and it is under evidence/."""
    if isinstance(stdout, bytes):  # TimeoutExpired can carry bytes
        stdout = stdout.decode(errors="replace")
    match = _RUN_LINE.search(stdout or "")
    run_dir = Path(match.group(1)).resolve() if match else None
    return run_dir if run_dir and run_dir.parent == EVIDENCE.resolve() else None


def _outputs() -> dict:
    had_evidence = EVIDENCE.exists()
    run_dir = None
    try:
        args = ["run", "examples/demo.yaml"]
        try:
            proc = _paramify(args)
        except subprocess.TimeoutExpired as exc:
            run_dir = _announced_run(exc.stdout)
            raise
        run_dir = _announced_run(proc.stdout)
        outputs = {"run": _capture(args, proc)}
        if run_dir is None or not run_dir.is_dir():
            raise SystemExit(f"`paramify run` did not make the run directory it announced:\n"
                             f"{outputs['run'][0]}")
        for name, args in (
            ("validate", ["validate", "examples/demo.yaml"]),
            ("upload_dry_run", ["upload", "--dry-run", str(run_dir.relative_to(REPO_ROOT))]),
        ):
            outputs[name] = _capture(args, _paramify(args))
    finally:
        # Only the run this script started: another run in the checkout may be writing beside it.
        if run_dir is not None:
            shutil.rmtree(run_dir, ignore_errors=True)
        if not had_evidence and EVIDENCE.is_dir() and not any(EVIDENCE.iterdir()):
            EVIDENCE.rmdir()
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--update", action="store_true", help="rewrite the goldens")
    parser.add_argument("--force", action="store_true",
                        help="with --update, also write goldens for commands that exited non-zero")
    args = parser.parse_args()

    if (REPO_ROOT / "upload.yaml").exists():
        print("upload.yaml at the repo root changes `paramify upload`; move it aside first.",
              file=sys.stderr)
        return 2

    outputs = _outputs()
    if args.update:
        failed = [name for name, (_, code) in outputs.items() if code != 0]
        if failed and not args.force:
            for name in failed:
                print(outputs[name][0])
            print(f"not updating: {', '.join(failed)} exited non-zero (--force to write anyway)")
            return 1
        GOLDENS.mkdir(parents=True, exist_ok=True)
        for name, (text, _) in outputs.items():
            (GOLDENS / f"{name}.txt").write_text(text)
        print(f"wrote {len(outputs)} goldens to {GOLDENS.relative_to(REPO_ROOT)}/")
        return 0

    changed = 0
    for name, (text, _) in outputs.items():
        golden = GOLDENS / f"{name}.txt"
        expected = golden.read_text() if golden.exists() else ""
        if text != expected:
            changed += 1
            sys.stdout.writelines(difflib.unified_diff(
                expected.splitlines(keepends=True), text.splitlines(keepends=True),
                fromfile=str(golden.relative_to(REPO_ROOT)), tofile=f"{name} (this run)",
            ))
    if changed:
        print(f"\n{changed} CLI golden(s) differ. If the change is intended: "
              "python tools/cli_goldens.py --update")
        return 1
    print(f"cli goldens ok: {len(outputs)} outputs match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
