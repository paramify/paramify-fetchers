"""Render the docs screenshots of `paramify update` to docs/img/update/*.svg.

    python tools/update_screenshots.py

Runs the real command against a scratch clone of this repo, moved back to
v0.5.1-beta, with two synthetic manifests: one the v0.6.0-beta upgrade leaves
valid, one it breaks. The scratch clone gets this tree's releases/ files
committed onto v0.6.0-beta, so the card shows what users will see once a
release carries them. Only two things are faked: pip (reinstall would repoint
your venv at the scratch clone) and the y at the prompt.

Needs the v0.5.1-beta and v0.6.0-beta tags locally (`git fetch --tags`).
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
WIDTH = 82

PROD = """\
run:
  output_dir: ./evidence
  fetchers:
    - use: okta_least_privilege
      secrets:
        api_token: ${env:OKTA_API_TOKEN}
        org_url: ${env:OKTA_ORG_URL}
    - use: aws_iam_mfa_status
    - use: aws_iam_password_policy
"""
# A lower-case ${env:} name passed before 0.6.0 and is refused from it on.
QUARTERLY = """\
run:
  output_dir: ./evidence
  fetchers:
    - use: okta_non_user_accounts_authentication
      secrets:
        api_token: ${env:okta_api_token}
        org_url: ${env:OKTA_ORG_URL}
"""


def sh(cwd: Path, *args: str) -> str:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


def scenario(tmp: Path) -> Path:
    clone = tmp / "paramify-fetchers"
    sh(tmp, "git", "clone", "-q", str(REPO), str(clone))
    sh(clone, "git", "switch", "-q", "--detach", "v0.6.0-beta")
    shutil.copytree(REPO / "releases", clone / "releases", dirs_exist_ok=True)
    sh(clone, "git", "add", "releases")
    sh(clone, "git", "-c", "user.name=docs", "-c", "user.email=docs@example.com",
       "-c", "commit.gpgsign=false", "commit", "-qm", "highlights")
    sh(clone, "git", "tag", "-f", "v0.6.0-beta")
    for tag in sh(clone, "git", "tag", "-l", "archive/*").split():
        sh(clone, "git", "tag", "-d", tag)
    sh(tmp, "git", "clone", "-q", "--bare", str(clone), str(tmp / "origin.git"))
    sh(clone, "git", "remote", "set-url", "origin", str(tmp / "origin.git"))
    sh(clone, "git", "switch", "-q", "--detach", "v0.5.1-beta")
    (clone / "manifests").mkdir()
    (clone / "manifests/prod.yaml").write_text(PROD)
    (clone / "manifests/okta-quarterly.yaml").write_text(QUARTERLY)
    return clone


def shoot(name: str, args: list, env: dict | None = None) -> None:
    """Run `paramify <args>` in-process with a recording console, save the SVG."""
    from rich.console import Console

    from framework import update as up
    from framework import update_cli as uc
    from framework import update_view as view
    from framework.cli import app

    console = Console(record=True, force_terminal=True, color_system="truecolor", width=WIDTH,
                      highlight=False, file=open(os.devnull, "w"))
    saved = (view.make_console, up.reinstall, uc._confirm, up.environment)
    view.make_console = lambda **kw: console
    # Show the venv a user would have (.venv in their clone), not this one.
    up.environment = lambda: {"python": sys.executable, "python_version": "3.12.8",
                              "venv": str(Path.cwd() / ".venv")}
    up.reinstall = lambda root, extras, python=sys.executable: {"ok": True, "command": ["pip"], "error": None}

    def confirm(run, question, yes):
        line = view.Text(f"  {question} [y/N]: ", style=run.look.fg)
        line.append("y", style=run.look.info)
        console.print(line)
        return True

    uc._confirm = confirm
    old_env = {k: os.environ.get(k) for k in (env or {})}
    os.environ.update(env or {})
    try:
        console.print(view.Text("$ paramify " + " ".join(args), style=view.SUBTLE))
        console.print()
        app(args, prog_name="paramify", standalone_mode=False)
    except SystemExit:
        pass
    finally:
        view.make_console, up.reinstall, uc._confirm, up.environment = saved
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    OUT.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(OUT / f"{name}.svg"), title="paramify update", theme=view.SVG_THEME)
    print(f"wrote {OUT / name}.svg")


def main() -> None:
    sys.path.insert(0, str(REPO))
    tmp = Path(tempfile.mkdtemp(prefix="paramify-update-shots-"))
    here = Path.cwd()
    try:
        clone = scenario(tmp)
        os.chdir(clone)
        shoot("check", ["update", "--check"])
        shoot("update", ["update"])
        shoot("rollback", ["update", "--rollback"])
        (clone / "framework/cli.py").write_text((clone / "framework/cli.py").read_text() + "\n# local edit\n")
        (clone / "fetchers/custom").mkdir()
        shoot("dirty", ["update"])
        shoot("container", ["update"], env={"PARAMIFY_CONTAINER": "1"})
    finally:
        os.chdir(here)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
