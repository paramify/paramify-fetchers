"""Render the docs screenshot of `paramify update` to docs/img/update/update.svg.

    python tools/update_screenshots.py

Runs the real command against a scratch clone of this repo whose `main` sits
BEHIND commits behind its origin, with one synthetic manifest. Only two things
are faked: pip (a reinstall would repoint your venv at the scratch clone) and
the y at the prompt.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs/img/update"
WIDTH = 100
BEHIND = 60  # first-parent commits, about two weeks of main

MANIFEST = """\
run:
  output_dir: ./evidence
  fetchers:
    - use: okta_least_privilege
      secrets:
        api_token: ${env:OKTA_API_TOKEN}
        org_url: ${env:OKTA_ORG_URL}
    - use: aws_iam_mfa_status
    - use: aws_iam_password_policy
    - use: datadog_siem_signals
      secrets:
        api_key: ${env:DATADOG_API_KEY}
        app_key: ${env:DATADOG_APP_KEY}
        base_url: ${env:DATADOG_BASE_URL}
        signals_lookback_days: ${env:DATADOG_SIGNALS_LOOKBACK_DAYS}
    - use: azure_alert_rules
    - use: azure_policy_compliance
    - use: azure_entra_privileged_roles
"""


def sh(cwd: Path, *args: str) -> str:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


def scenario(tmp: Path) -> Path:
    """A clone on main, BEHIND commits behind an origin that is this tree's HEAD."""
    sh(tmp, "git", "clone", "-q", "--bare", str(REPO), str(tmp / "origin.git"))
    head = sh(REPO, "git", "rev-parse", "HEAD").strip()
    sh(tmp / "origin.git", "git", "update-ref", "refs/heads/main", head)
    sh(tmp / "origin.git", "git", "symbolic-ref", "HEAD", "refs/heads/main")
    clone = tmp / "paramify-fetchers"
    sh(tmp, "git", "clone", "-q", "--branch", "main", str(tmp / "origin.git"), str(clone))
    sh(clone, "git", "reset", "-q", "--hard", f"HEAD~{BEHIND}")
    (clone / "manifests").mkdir(exist_ok=True)
    (clone / "manifests/prod.yaml").write_text(MANIFEST)
    return clone


def shoot(name: str, args: list) -> None:
    """Run `paramify <args>` in-process with a recording console, save the SVG."""
    from rich.console import Console
    from rich.text import Text

    from framework import update as up
    from framework import update_cli as uc
    from framework import update_view as view
    from framework.cli import app

    console = Console(record=True, force_terminal=True, color_system="truecolor", width=WIDTH,
                      highlight=False, file=open(os.devnull, "w"))
    saved = (view.make_console, up.reinstall, uc._confirmed)
    view.make_console = lambda **kw: console
    up.reinstall = lambda root, extras, python=sys.executable: {"ok": True, "command": ["pip"], "error": None}

    def confirmed(run, question, yes, what):
        console.print()
        console.print(Text(f"  {question} [y/N]: ").append("y", style="cyan"))

    uc._confirmed = confirmed
    try:
        console.print(Text("$ paramify " + " ".join(args), style="dim"))
        console.print()
        app(args, prog_name="paramify", standalone_mode=False)
    except SystemExit:
        pass
    finally:
        view.make_console, up.reinstall, uc._confirmed = saved
    OUT.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(OUT / f"{name}.svg"), title="paramify update", clear=False)
    print(f"wrote {OUT / name}.svg")
    print(console.export_text())


def main() -> None:
    sys.path.insert(0, str(REPO))
    tmp = Path(tempfile.mkdtemp(prefix="paramify-update-shots-"))
    here = Path.cwd()
    try:
        os.chdir(scenario(tmp))
        shoot("update", ["update"])
    finally:
        os.chdir(here)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
