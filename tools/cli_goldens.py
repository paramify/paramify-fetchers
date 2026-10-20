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


def paramify() -> str:
    """The paramify script beside this interpreter, else the one on PATH."""
    beside = Path(sys.executable).with_name("paramify")
    return str(beside) if beside.exists() else (shutil.which("paramify") or str(beside))


def offline_env() -> dict:
    """os.environ without PARAMIFY_*/AZURE_* or .env; the Paramify names stay set, empty."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PARAMIFY_", "AZURE_"))}
    # Empty, not unset: python-dotenv never overrides a variable that is set.
    env.update(dict.fromkeys(PARAMIFY_ENV, ""), PYTHON_DOTENV_DISABLED="1")
    return env


def normalise(text: str, roots, root: str = "<repo>", run_id: str = "<run-id>",
              timestamp: str = "<timestamp>", asctime: str = "<asctime>") -> str:
    """Replace the root paths, run ids and timestamps in text with fixed values."""
    for path in sorted(roots, key=len, reverse=True):
        text = text.replace(path, root)
    for pattern, fixed in ((RUN_ID, run_id), (TIMESTAMP, timestamp), (ASCTIME, asctime)):
        text = pattern.sub(fixed, text)
    return text


def _capture(args: list) -> tuple:
    env = {**offline_env(), "NO_COLOR": "1"}
    env.pop("FORCE_COLOR", None)
    proc = subprocess.run(
        [paramify(), *args], cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120,
    )
    shown = " ".join(["paramify", *args])
    text = f"$ {shown}\nexit {proc.returncode}\n--- stdout\n{proc.stdout}--- stderr\n{proc.stderr}"
    text = normalise(text, {str(REPO_ROOT), str(REPO_ROOT.resolve())})
    return _DURATION.sub("duration=<n>s", text), proc.returncode


def _outputs() -> dict:
    had_evidence = EVIDENCE.exists()
    before = set(EVIDENCE.glob("run-*"))
    outputs = {"run": _capture(["run", "examples/demo.yaml"])}
    made = sorted(set(EVIDENCE.glob("run-*")) - before)
    try:
        if len(made) != 1:
            raise SystemExit(f"expected `paramify run` to make one run directory, found {made}:\n"
                             f"{outputs['run'][0]}")
        run_dir = made[0].relative_to(REPO_ROOT)
        outputs["validate"] = _capture(["validate", "examples/demo.yaml"])
        outputs["upload_dry_run"] = _capture(["upload", "--dry-run", str(run_dir)])
    finally:
        for path in made:
            shutil.rmtree(path)
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
