"""The `paramify update` command: the order of the steps, the prompts, --json.

framework/update.py does the work and framework/update_view.py draws it; this
module decides what happens next. It lives outside cli.py, which is already
long, and cli.py registers it like any other command.

Exit codes: 0 done (or nothing to do), 1 refused or failed. `--check` follows
`paramify status`: 0 up to date, 1 an update is waiting, 2 can't tell.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional, Tuple

import typer

from framework import api
from framework import update as up
from framework import update_view as view

MAX_NEW = 5  # non-breaking rows shown; the rest are counted


def _emit(doc: dict, code: int) -> NoReturn:
    typer.echo(json.dumps(doc, indent=2, default=str))
    raise typer.Exit(code)


class _Run:
    """One invocation's output channel: lines in a terminal, JSON otherwise."""

    def __init__(self, json_out: bool) -> None:
        self.json = json_out
        self.console = view.make_console()
        self.doc: Dict[str, Any] = {"ok": False, "errors": []}

    def show(self, *renderables: Any) -> None:
        if self.json:
            return
        width = min(self.console.width, view.WIDTH)
        for r in renderables:
            if isinstance(r, view.Text):
                # print() joins bare Text into a new one and drops its no_wrap,
                # so a row is cut here; anything else (an error) wraps as it likes.
                self.console.print(r, width=width, no_wrap=True, overflow="ellipsis")
            else:
                self.console.print(r, width=width)

    def section(self, lines: List[Any]) -> None:
        """A block of lines with a blank line before it; nothing when empty."""
        if lines and not self.json:
            self.console.print()
            self.show(*lines)

    def step(self, label: str):
        return _Silent() if self.json else view.step(self.console, label)

    def fail(self, msg: str, code: int = 1, **extra: Any) -> NoReturn:
        self.doc.update(extra)
        self.doc["ok"] = False
        self.doc["errors"].append(msg)
        if self.json:
            _emit(self.doc, code)
        self.show(view.fail(msg))
        raise typer.Exit(code)


class _Silent:
    """A step that draws nothing, for --json."""

    def __enter__(self) -> "_Silent":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def done(self, *a: Any, **k: Any) -> None: ...
    def fail(self, *a: Any, **k: Any) -> None: ...
    def warn(self, *a: Any, **k: Any) -> None: ...
    def add(self, *a: Any, **k: Any) -> None: ...


def _confirmed(run: _Run, question: str, yes: bool, what: str) -> None:
    """Return when the user agrees; otherwise end the run having changed nothing."""
    if yes:
        return
    if run.json or not sys.stdin.isatty():
        run.fail(f"{what} needs confirmation: pass --yes")
    run.console.print()
    if not typer.confirm(f"  {question}", default=False):
        run.show(view.note("Nothing changed."))
        raise typer.Exit(1)


def update_cmd(
    to: Optional[str] = typer.Option(None, "--to", metavar="main|vX.Y.Z-beta",
                                     help="Pin a release, or go back to following main"),
    check: bool = typer.Option(False, "--check", help="Only report whether an update is waiting (exit 1 if so)"),
    rollback: bool = typer.Option(False, "--rollback", help="Return to where you were before the last update"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation"),
    allow_breaking: bool = typer.Option(
        False, "--allow-breaking",
        help="With --yes or --json: go ahead even when a breaking change or a failing manifest touches you",
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Bring this clone up to date: say what changes for you, check, move, reinstall, validate.

    A clone on a branch (normally main) is fast-forwarded to its remote branch;
    a clone pinned to a release moves to the newest release. Before anything
    changes, the target's own `paramify validate` runs against each of your
    manifests in a temporary worktree. Your own fetchers stay put.
    """
    if sum(map(bool, (to, check, rollback))) > 1:
        raise typer.BadParameter("pick one of --to, --check, --rollback")
    run = _Run(json_out)
    root = api.find_repo_root()

    if up.is_container(root):
        advice = up.container_advice(root)
        if check:
            if json_out:
                _emit({**advice, "update_available": None}, 2)
            typer.echo("No git clone here (container), so update can't check. "
                       "Run `paramify update --check` on the host.", err=True)
            raise typer.Exit(2)
        if json_out:
            _emit(advice, 1)
        run.show(*view.container(advice))
        raise typer.Exit(1)

    if check:
        _check(run, root)
    if rollback:
        _rollback(run, root, yes)
    _update(run, root, to=to, yes=yes, allow_breaking=allow_breaking)


def _fetch(root: Path) -> Tuple[bool, str]:
    try:
        up.fetch(root)
        return True, ""
    except up.UpdateError as e:
        return False, str(e)


OFFLINE = "couldn't reach origin, so this compares against what this clone last fetched"


# --------------------------------------------------------------------------- #
# --check
# --------------------------------------------------------------------------- #

def _check(run: _Run, root: Path) -> NoReturn:
    fetched, _ = _fetch(root)
    try:
        info = up.update_status(root)
    except up.UpdateError as e:
        run.fail(str(e), 2, update_available=None, fetched=fetched)
    code = 1 if info["update_available"] else 0
    if run.json:
        _emit({"ok": True, "errors": [], "fetched": fetched, **info}, code)
    if info["update_available"]:
        run.show(view.line(("↑ ", "bold cyan"), (info["waiting"], "bold"), ("  ·  run ", "dim"), ("paramify update", "cyan")))
    else:
        run.show(view.ok(f"Up to date: {info['current']}."))
    if not fetched:
        run.show(view.note(OFFLINE))
    raise typer.Exit(code)


# --------------------------------------------------------------------------- #
# update
# --------------------------------------------------------------------------- #

def _refuse_if_blocked(run: _Run, root: Path, sha: str) -> None:
    blocking = up.blocking_changes(root, sha)
    if blocking["tracked"] or blocking["untracked"]:
        if run.json:
            run.fail("local files are in the way of this update; commit, move or remove them first",
                     blocking=blocking)
        run.show(*view.blocked(blocking))
        raise typer.Exit(1)


def _update(run: _Run, root: Path, *, to: Optional[str], yes: bool, allow_breaking: bool) -> NoReturn:
    with run.step("fetch from origin") as s:
        fetched, why = _fetch(root)
        if not fetched:
            s.warn(f"offline ({why})")
    if not fetched:
        run.show(view.note(OFFLINE))
    pos = up.position(root)
    run.doc.update(current={**pos, "label": up.describe(pos)}, fetched=fetched)

    try:
        target = up.choose_target(root, pos, up.list_releases(root), to=to)
    except up.UpdateError as e:
        run.fail(str(e))
    run.doc.update(channel=target.channel, target=target.to_json())
    if target.sha == pos["sha"] and target.branch == pos["branch"]:
        run.doc.update(ok=True, up_to_date=True)
        if run.json:
            _emit(run.doc, 0)
        run.show(view.ok(f"Nothing to do: {up.describe(pos)} is up to date."))
        raise typer.Exit(0)
    _refuse_if_blocked(run, root, target.sha)

    manifests = up.user_manifests(root)
    rows = up.curated_rows(root, "HEAD", target.sha)
    span = up.span(root, "HEAD", target.sha)
    forward = bool(span["commits"]) or target.sha == pos["sha"]
    plan = {"current": run.doc["current"], "target": target.to_json(), "span": span,
            "direction": "forward" if forward else "back"}
    run.doc.update(span=span, direction=plan["direction"], manifests=[m["label"] for m in manifests])
    run.section([view.header(plan)])

    if not run.json:
        run.console.print()
    with run.step("check your manifests") as s:
        try:
            check = up.check_target(root, target, manifests)
        except up.UpdateError as e:
            s.fail(str(e))
            run.fail(f"the check before moving failed: {e}")
        state, summary = view.check_summary(check)
        s.done(summary, state)
        for detail in view.check_details(check):
            s.add(detail)
    breaking = up.breaking_for(rows, manifests, check["has_local_fetchers"])
    new = [r for r in rows if r["tag"] != "breaking"]
    run.doc.update(check=check, fetchers=check["fetchers"], breaking=breaking, highlights=new[:MAX_NEW])
    used = len({u for m in manifests for u in m["uses"]})
    run.section(view.your_fetchers(check["fetchers"], used, breaking))
    run.section(view.breaking(breaking))
    run.section(view.whats_new(new[:MAX_NEW]))
    touching = [b for b in breaking if b["touches"]]
    run.section(view.rest(check["fetchers"], len(breaking) - len(touching), max(0, len(new) - MAX_NEW),
                          up.changelog_url(root, target)))
    if not run.json:
        run.console.print()

    if check["python_required"]:
        run.fail(f"{target.label} needs Python {check['python_required']}; make a venv with a newer Python first")
    breaks = [m["manifest"] for m in check["manifests"] if m["status"] == "breaks"]
    if (yes or run.json) and not allow_breaking and (breaks or touching):
        reasons = []
        if breaks:
            reasons.append(f"{view.plural(len(breaks), 'manifest')} would break")
        if touching:
            reasons.append(f"{view.plural(len(touching), 'breaking change')} {'touches' if len(touching) == 1 else 'touch'} this clone")
        run.fail(f"stopped: {' and '.join(reasons)}. Read them above, then rerun with --allow-breaking (or without --yes)")
    question = f"Update {target.label}?" if target.branch == pos["branch"] else f"Switch to {target.label}?"
    if breaks:
        question += f" {view.plural(len(breaks), 'manifest')} would break."
    _confirmed(run, question, yes, "switching")

    tries = [h["try"] for h in new if h.get("try")]
    _apply(run, root, pos, manifests, label=target.label, new_sha=target.sha, tries=tries,
           go=lambda: up.move(root, target), verb=f"move to {target.label}")


def _built_image(root: Path) -> bool:
    """Has this machine built the deploy image? Only then is "rebuild the image"
    worth saying after an update. The image name comes from
    deploy/docker-compose.yml; no docker, no compose file, a daemon that is not
    running or slow to answer all mean no."""
    import yaml

    compose = root / "deploy" / "docker-compose.yml"
    docker = shutil.which("docker")
    if not docker or not compose.is_file():
        return False
    try:
        services = (yaml.safe_load(compose.read_text()) or {}).get("services") or {}
    except (OSError, yaml.YAMLError):
        return False
    images = [s["image"] for s in services.values() if isinstance(s, dict) and isinstance(s.get("image"), str)]
    for image in images:
        try:
            done = subprocess.run([docker, "image", "inspect", image], capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return False
        if done.returncode == 0:
            return True
    return False


def _apply(run: _Run, root: Path, pos: dict, manifests: List[dict], *, label: str, new_sha: str,
           tries: List[str], go: Any, verb: str, rolling_back: bool = False) -> NoReturn:
    """Move, reinstall if pyproject.toml changed, validate. Shared by update and --rollback."""
    extras = up.detect_extras()
    env = up.environment()
    reinstalling = up.needs_reinstall(root, pos["sha"], new_sha)
    run.doc["environment"] = {**env, "extras": extras}

    # Recorded before the move, so a move cut short can still be rolled back.
    replaced = None if rolling_back else up.remember_previous(root, pos, new_sha)
    with run.step(verb) as s:
        try:
            go()
        except up.UpdateError as e:
            if not rolling_back:
                up.set_previous(root, replaced)
            s.fail(str(e))
            run.fail(f"git refused the move: {e}")
        s.done(new_sha[:7])
    run.doc["switched"] = True

    with run.step("reinstall") as s:
        if not reinstalling:
            res: Dict[str, Any] = {"ok": True, "skipped": True, "command": None, "error": None}
            s.done("not needed: pyproject.toml didn't change", "skip")
        else:
            res = {"skipped": False, **up.reinstall(root, extras)}
            if res["ok"]:
                chosen = ["all"] if extras is None else extras
                s.done(f".[{','.join(chosen)}]" if chosen else "the base install")
            else:
                s.fail("pip failed")
                for err in (res.get("error") or "").splitlines()[-4:]:
                    s.add(view.line((err, "dim"), indent=6))
        run.doc["reinstall"] = res
    if not res["ok"]:
        _revert(run, root, pos, extras, rolling_back)
    if rolling_back:
        up.forget_previous(root)  # only now: a rollback that failed can be tried again

    with run.step("validate manifests") as s:
        val = up.validate_all(root, manifests)
        run.doc["validate"] = val
        before = {m["label"] for m in manifests if m["errors_now"]}
        bad = [r for r in val["manifests"] if r["ok"] is False]
        new_bad = [r for r in bad if r["manifest"] not in before]
        if not manifests:
            s.done("no manifests", "skip")
        elif new_bad:
            s.fail(f"{len(new_bad)} of {view.plural(len(manifests), 'manifest')} fail")
            for r in new_bad:
                for detail in view.manifest_errors(r["manifest"], "fails", "red", r["errors"]):
                    s.add(detail)
        elif bad:
            s.warn(f"{len(bad)} {'was' if len(bad) == 1 else 'were'} already failing; nothing new")
        else:
            s.done(f"{view.plural(len(manifests), 'manifest')} valid")

    run.doc["version"] = label
    run.section(view.done(label, tries, rollback=not rolling_back, container=_built_image(root)))
    if new_bad:
        # The move happened, but a script must not read this as a clean update.
        n = len(new_bad)
        back = "" if rolling_back else ", or go back with paramify update --rollback"
        run.fail(f"you're on {label}, but {view.plural(n, 'manifest')} fail{'s' if n == 1 else ''} on the new code. "
                 f"Fix what validate names{back}")
    run.doc["ok"] = True
    if run.json:
        _emit(run.doc, 0)
    raise typer.Exit(0)


def _revert(run: _Run, root: Path, pos: dict, extras: Optional[List[str]], rolling_back: bool) -> NoReturn:
    """The reinstall failed: put the code back where it was so `paramify` still starts."""
    where, problem = up.describe(pos), ""
    with run.step("put the code back") as s:
        try:
            up.restore(root, pos)
            if not rolling_back:
                up.forget_previous(root)
            again = up.reinstall(root, extras)
            s.done(f"back on {where}" + ("" if again["ok"] else ", but its reinstall failed too"),
                   "ok" if again["ok"] else "warn")
        except up.UpdateError as e:
            problem = str(e)
            s.fail(problem)
    run.doc.update(switched=bool(problem), reverted=not problem)
    if problem:
        run.fail(f"the reinstall failed, and the code could not be put back ({problem}). "
                 f"The pip error is above; check git status before running anything else")
    if rolling_back:
        run.fail(f"the reinstall failed, so rollback left you on {where}; the pip error is above. "
                 f"Fix it and run paramify update --rollback again")
    run.fail("the reinstall failed, so update put your previous version back; the pip error is above")


# --------------------------------------------------------------------------- #
# --rollback
# --------------------------------------------------------------------------- #

def _rollback(run: _Run, root: Path, yes: bool) -> NoReturn:
    prev = up.read_state(root).get("previous")
    if not prev:
        run.fail("nothing to roll back to: no update has been recorded here (or it was already rolled back)")
    pos = up.position(root)
    if prev.get("after") and pos["sha"] != prev["after"]:
        run.fail(f"this clone has moved since the update (it is at {pos['short']}; the update left it at "
                 f"{prev['after'][:7]}), so rolling back would discard that work. To go back anyway: "
                 f"git switch --detach {prev['sha'][:7]}")
    _refuse_if_blocked(run, root, prev["sha"])
    manifests = up.user_manifests(root)
    label = prev.get("describe") or prev["sha"][:7]
    current = {**pos, "label": up.describe(pos)}
    run.doc.update(current=current, target=prev, direction="rollback")
    run.show(view.header({"current": current, "target": {"label": label}, "direction": "rollback"}))
    _confirmed(run, f"Go back to {label}?", yes, "rolling back")
    if not run.json:
        run.console.print()
    _apply(run, root, pos, manifests, label=label, new_sha=prev["sha"], tries=[],
           go=lambda: up.restore(root, prev), verb="go back", rolling_back=True)


# --------------------------------------------------------------------------- #
# The once-a-day notice
# --------------------------------------------------------------------------- #

def maybe_notice(subcommand: Optional[str]) -> None:
    """One dim line after a command when an update is waiting.

    At most once a day, never under --json, and only when both streams are a
    terminal, so it can't land in a pipe or a log. Any failure is swallowed:
    a notice is never worth breaking the command it follows.
    """
    try:
        if subcommand in (None, "update", "tui") or "--json" in sys.argv[1:]:
            return
        if not (sys.stdout.isatty() and sys.stderr.isatty()):
            return
        root = api.find_repo_root()
        if not up.notice_due(root):
            return
        info = api.check_for_update(root)
        up.mark_notice(root)
        if not info or not info["update_available"]:
            return
        view.make_console(stderr=True).print(
            view.line((f"{info['waiting']} (you run {info['current']}) · ", "dim"), ("paramify update", "cyan"), indent=0)
        )
    except Exception:  # noqa: BLE001
        return
