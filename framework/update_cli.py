"""The `paramify update` command: the order of the steps, the prompts, --json.

framework/update.py does the work and framework/update_view.py draws it; this
module decides what happens next. It lives outside cli.py, which is already
long, and cli.py registers it like any other command.

Exit codes: 0 done (or nothing to do), 1 refused or failed. `--check` follows
`paramify status`: 0 up to date, 1 an update is waiting, 2 can't tell.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional

import typer

from framework import api
from framework import update as up
from framework import update_view as view


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
    expect: Optional[str] = typer.Option(
        None, "--expect", metavar="SHA",
        help="Move only to this commit: refuse if the target has moved since a plan was shown",
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Bring this clone up to date: say what changes for you, check, move, reinstall, validate.

    A clone on a branch (normally main) is fast-forwarded to its remote branch;
    a clone pinned to a release moves to the newest release. Before anything
    changes, the target's own `paramify validate` runs against each of your
    manifests in a temporary worktree. Your own fetchers stay put.
    """
    if sum(map(bool, (to or expect, check, rollback))) > 1:
        raise typer.BadParameter("pick one of --to/--expect, --check, --rollback")
    run = _Run(json_out)
    root = api.find_repo_root()

    if up.is_container(root):
        advice = up.container_advice()
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
    _update(run, root, to=to, expect=expect, yes=yes, allow_breaking=allow_breaking)


# --------------------------------------------------------------------------- #
# --check
# --------------------------------------------------------------------------- #

def _check(run: _Run, root: Path) -> NoReturn:
    fetched, _ = up.try_fetch(root)
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
        run.show(view.offline(up.REMOTE))
    raise typer.Exit(code)


# --------------------------------------------------------------------------- #
# update
# --------------------------------------------------------------------------- #

def _refuse_if_blocked(run: _Run, blocking: dict) -> None:
    if blocking["tracked"] or blocking["untracked"]:
        if run.json:
            run.fail("local files are in the way of this update; commit, move or remove them first",
                     blocking=blocking)
        run.show(*view.blocked(blocking))
        raise typer.Exit(1)


def _update(run: _Run, root: Path, *, to: Optional[str], expect: Optional[str], yes: bool,
            allow_breaking: bool) -> NoReturn:
    with run.step(f"fetch from {up.REMOTE}") as s:
        fetched, why = up.try_fetch(root)
        if not fetched:
            s.warn(f"offline ({why})")
    if not fetched:
        run.show(view.offline(up.REMOTE))
    try:
        located = up.locate(root, to, fetched=fetched)
    except up.UpdateError as e:
        run.fail(str(e))
    run.doc.update(up.public(located))
    target, pos = located["target"], located["current"]
    if expect is not None and not re.fullmatch(r"[0-9a-fA-F]{7,40}", expect):
        run.fail(f"--expect takes a commit sha (7 to 40 hex characters), not {expect!r}")
    if expect and not target["sha"].startswith(expect.lower()):
        run.fail(f"{target['label']} has moved since the plan was made (it is at {target['sha'][:7]} now, "
                 f"not {expect[:7]}). Look at the new plan before applying it")
    if located["up_to_date"]:
        run.doc["ok"] = True
        if run.json:
            _emit(run.doc, 0)
        run.show(view.ok(f"Nothing to do: {pos['label']} is up to date."))
        raise typer.Exit(0)
    if located["state"] == "blocked":
        _refuse_if_blocked(run, located["blocking"])
    run.section([view.header(located)])

    if not run.json:
        run.console.print()
    with run.step("check your manifests") as s:
        try:
            plan = up.assess(root, located)
        except up.UpdateError as e:
            s.fail(str(e))
            run.fail(f"the check before moving failed: {e}")
        view.settle_check(s, plan["check"])
    run.doc.update(up.public(plan))
    run.section(view.your_fetchers(plan["fetchers"], plan["used"], plan["breaking"]))
    run.section(view.breaking(plan["breaking"]))
    run.section(view.whats_new(plan["highlights"], plan.get("releases") or []))
    run.section(view.rest(plan))
    if not run.json:
        run.console.print()

    stops = plan["stops"]
    if plan["state"] == "unrunnable":
        run.fail(f"{target['label']} needs Python {stops['python_required']}; make a venv with a newer Python first")
    if (yes or run.json) and not allow_breaking and plan["needs_allow_breaking"]:
        run.fail(f"stopped: {view.stop_reasons(stops)}. Read them above, then rerun with --allow-breaking "
                 f"(or without --yes)")
    question = f"Update {target['label']}?" if target["branch"] == pos["branch"] else f"Switch to {target['label']}?"
    if stops["breaks"]:
        question += f" {view.plural(len(stops['breaks']), 'manifest')} would break."
    _confirmed(run, question, yes, "switching")

    with run.step(f"move to {target['label']}") as s:
        try:
            with up.recorded_move(root, pos, target["sha"]) as replaced:
                up.move(root, up.Target(**target))
        except up.UpdateError as e:
            s.fail(str(e))
            run.fail(f"git refused the move: {e}")
        s.done(target["sha"][:7])
    run.doc["switched"] = True
    if _reinstall(run, root, pos, target["sha"]):
        up.forget_previous(root, replaced)  # the move is undone; the way back from the last good update stays
        run.fail("the reinstall failed, so update put your previous version back; the pip error is above")
    _validate_and_report(run, root, plan["manifests"], target["label"], plan["tries"], offer_rollback=True)


def _reinstall(run: _Run, root: Path, pos: dict, new_sha: str) -> bool:
    """Reinstall if pyproject.toml changed. If pip fails, put the code back at
    `pos` (so `paramify` still starts) and return True; if even that fails,
    end the run."""
    extras = up.detect_extras()
    run.doc["environment"] = {**up.environment(), "extras": extras}
    with run.step("reinstall") as s:
        if not up.needs_reinstall(root, pos["sha"], new_sha):
            res: Dict[str, Any] = {"ok": True, "skipped": True, "command": None, "error": None}
            s.done("not needed: pyproject.toml didn't change", "skip")
        else:
            res = {"skipped": False, **up.reinstall(root, extras)}
            if res["ok"]:
                s.done(up.install_label(extras))
            else:
                s.fail("pip failed")
                for err in (res.get("error") or "").splitlines()[-4:]:
                    s.add(view.line((err, "dim"), indent=6))
        run.doc["reinstall"] = res
    if res["ok"]:
        return False
    with run.step("put the code back") as s:
        try:
            up.restore(root, pos)
        except up.UpdateError as e:
            s.fail(str(e))
            run.doc.update(switched=True, reverted=False)
            run.fail(f"the reinstall failed, and the code could not be put back ({e}). "
                     f"The pip error is above; check git status before running anything else")
        again = up.reinstall(root, extras)
        s.done(f"back on {up.describe(pos)}" + ("" if again["ok"] else ", but its reinstall failed too"),
               "ok" if again["ok"] else "warn")
    run.doc.update(switched=False, reverted=True)
    return True


def _validate_and_report(run: _Run, root: Path, manifests: List[dict], label: str, tries: List[str], *,
                         offer_rollback: bool) -> NoReturn:
    """Validate with the code now checked out, say where the clone is, and exit.
    A manifest that newly fails is a failed run: the move happened, but a
    script must not read it as a clean update."""
    with run.step("validate manifests") as s:
        val = up.validate_all(root, manifests)
        run.doc["validate"] = val
        new_bad = [r for r in val["manifests"] if r["status"] == "breaks"]
        old_bad = [r for r in val["manifests"] if r["status"] == "still_failing"]
        if not manifests:
            s.done("no manifests", "skip")
        elif new_bad:
            s.fail(f"{len(new_bad)} of {view.plural(len(manifests), 'manifest')} fail")
            for r in new_bad:
                for detail in view.manifest_errors(r["manifest"], "fails", "red", r["errors"]):
                    s.add(detail)
        elif old_bad:
            s.warn(f"{len(old_bad)} {'was' if len(old_bad) == 1 else 'were'} already failing; nothing new")
        else:
            s.done(f"{view.plural(len(manifests), 'manifest')} valid")

    run.doc["version"] = label
    run.section(view.done(label, tries, rollback=offer_rollback,
                          rebuild=up.COMPOSE_BUILD if up.built_image(root) else None))
    if new_bad:
        n = len(new_bad)
        back = ", or go back with paramify update --rollback" if offer_rollback else ""
        run.fail(f"you're on {label}, but {view.plural(n, 'manifest')} fail{'s' if n == 1 else ''} on the new code. "
                 f"Fix what validate names{back}")
    run.doc["ok"] = True
    if run.json:
        _emit(run.doc, 0)
    raise typer.Exit(0)


# --------------------------------------------------------------------------- #
# --rollback
# --------------------------------------------------------------------------- #

def _rollback(run: _Run, root: Path, yes: bool) -> NoReturn:
    refusal = up.rollback_refusal(root)
    if refusal:
        run.fail(refusal)
    prev = up.read_state(root)["previous"]
    pos = up.position(root)
    _refuse_if_blocked(run, up.blocking_changes(root, prev["sha"]))
    manifests = up.user_manifests(root)
    label = prev.get("describe") or prev["sha"][:7]
    current = {**pos, "label": up.describe(pos)}
    target = {"sha": prev["sha"], "branch": prev.get("branch"), "label": label}
    run.doc.update(current=current, target=target, direction="rollback")
    run.show(view.header({"current": current, "target": target, "direction": "rollback"}))
    _confirmed(run, f"Go back to {label}?", yes, "rolling back")
    if not run.json:
        run.console.print()
    with run.step("go back") as s:
        try:
            up.restore(root, prev)
        except up.UpdateError as e:
            s.fail(str(e))
            run.fail(f"git refused the move: {e}")
        s.done(prev["sha"][:7])
    run.doc["switched"] = True
    if _reinstall(run, root, pos, prev["sha"]):
        run.fail(f"the reinstall failed, so rollback left you on {up.describe(pos)}; the pip error is above. "
                 f"Fix it and run paramify update --rollback again")
    up.forget_previous(root)
    _validate_and_report(run, root, manifests, label, [], offer_rollback=False)


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
        info = up.check_for_update(root)
        up.mark_notice(root)
        if not info or not info["update_available"]:
            return
        view.make_console(stderr=True).print(
            view.line((f"{info['waiting']} (you run {info['current']}) · ", "dim"), ("paramify update", "cyan"), indent=0)
        )
    except Exception:  # noqa: BLE001
        return
