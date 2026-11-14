"""The `paramify update` command: the order of the steps, the prompts, --json.

framework/update.py does the work and framework/update_view.py draws it; this
module decides what happens next. It lives outside cli.py, which is already
long, and cli.py registers it like any other command.

Exit codes: 0 done (or nothing to do), 1 refused or failed. `--check` follows
`paramify status`: 0 up to date, 1 an update is available, 2 can't tell.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional, Tuple

import typer

from framework import api
from framework import update as up
from framework import update_view as view


def _emit(doc: dict, code: int) -> NoReturn:
    typer.echo(json.dumps(doc, indent=2, default=str))
    raise typer.Exit(code)


class _Run:
    """One invocation's output channel: rich in a terminal, JSON otherwise."""

    def __init__(self, json_out: bool) -> None:
        self.json = json_out
        self.console = view.make_console()
        self.look = view.Look(self.console)
        self.doc: Dict[str, Any] = {"ok": False, "errors": []}

    def show(self, *renderables: Any) -> None:
        # Everything sits in one column the width of the cards, so a wide
        # terminal doesn't stretch rows away from the panels above them.
        if not self.json:
            for r in renderables:
                if r is not None:
                    self.console.print(r, width=min(self.console.width, view.WIDTH))

    def gap(self) -> None:
        if not self.json:
            self.console.print()

    def step(self, label: str):
        if self.json:
            return _Silent()
        return view.step(self.look, label)

    def fail(self, msg: str, code: int = 1, **extra: Any) -> NoReturn:
        self.doc.update(extra)
        self.doc["ok"] = False
        self.doc["errors"].append(msg)
        if self.json:
            _emit(self.doc, code)
        self.show(view.verdict(self.look, False, msg))
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


def _confirm(run: _Run, question: str, yes: bool) -> bool:
    if yes:
        return True
    if run.json or not sys.stdin.isatty():
        return False
    return typer.confirm(f"  {question}", default=False)


def update_cmd(
    to: Optional[str] = typer.Option(None, "--to", metavar="vX.Y.Z-beta", help="Move to this release"),
    next_release: bool = typer.Option(False, "--next", help="Step exactly one release forward"),
    check: bool = typer.Option(False, "--check", help="Only report whether an update is available (exit 1 if so)"),
    rollback: bool = typer.Option(False, "--rollback", help="Return to the version you ran before the last update"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation"),
    allow_breaking: bool = typer.Option(
        False, "--allow-breaking",
        help="With --yes or --json: switch even across breaking changes or manifests that would break",
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """Move this clone to a newer release: show what changed, check, switch, reinstall, validate.

    Only release tags are targets, never main. Before anything changes, the
    target's own `paramify validate` runs against each of your manifests in a
    temporary worktree. Untracked files, such as your own fetchers, stay put.
    """
    if sum(map(bool, (to, next_release, check, rollback))) > 1:
        raise typer.BadParameter("pick one of --to, --next, --check, --rollback")
    run = _Run(json_out)
    root = api.find_repo_root()

    if up.is_container(root):
        advice = up.container_advice(root)
        if check:
            # No git, so no way to tell; say so in the exit code, not a wall of text.
            if json_out:
                _emit({**advice, "update_available": None}, 2)
            typer.echo("No git clone here (container), so update can't check. "
                       "Run `paramify update --check` on the host.", err=True)
            raise typer.Exit(2)
        if json_out:
            _emit(advice, 1)
        run.show(view.container_panel(run.look, advice))
        raise typer.Exit(1)

    view.preload()
    if check:
        _check(run, root)
    if rollback:
        _rollback(run, root, yes)
    _update(run, root, to=to, next_release=next_release, yes=yes, allow_breaking=allow_breaking)


# --------------------------------------------------------------------------- #
# --check
# --------------------------------------------------------------------------- #

def _check(run: _Run, root: Path) -> NoReturn:
    try:
        up.fetch_tags(root)
        fetched = True
    except up.UpdateError:
        fetched = False  # still compare the tags we have; say they may be stale
    try:
        releases = up.list_releases(root)
        pos = up.position(root)
    except up.UpdateError as e:
        run.fail(str(e), 2)
    latest = releases[-1] if releases else None
    base = up.parse_release(pos["tag"] or "")
    available = bool(latest and (base is None or latest.key > base.key))
    doc = {
        "ok": True, "errors": [], "update_available": available, "fetched": fetched,
        "current": up.describe(pos), "current_tag": pos["tag"], "on_release": pos["exact"],
        "latest": latest.version if latest else None, "latest_tag": latest.tag if latest else None,
    }
    if latest is None:
        doc.update(ok=False, errors=["no release tags found"])
    code = 2 if latest is None else (1 if available else 0)
    if run.json:
        _emit(doc, code)
    look = run.look
    if latest is None:
        run.show(view.verdict(look, False, "No release tags found, so there's nothing to compare."))
    elif available:
        t = view.Text("  ")
        t.append("↑ ", style=view.Style(color=look.accent, bold=True))
        t.append(f"{up.describe(pos)}  →  ", style=look.fg)
        t.append_text(look.gradient(latest.version))
        t.append("   run ", style=look.muted)
        t.append("paramify update", style=look.info)
        run.show(t)
    else:
        where = "the newest release" if pos["exact"] else f"past the newest release ({latest.version})"
        run.show(view.verdict(look, True, f"Up to date: {up.describe(pos)} is {where}."))
    if not fetched:
        run.show(view.note(look, "couldn't reach origin, so this compares the tags you already have"))
    raise typer.Exit(code)


# --------------------------------------------------------------------------- #
# update
# --------------------------------------------------------------------------- #

def _refuse_if_dirty(run: _Run, root: Path) -> dict:
    status = up.worktree_status(root)
    if status["tracked"]:
        run.doc["dirty"] = status
        if run.json:
            run.fail("tracked files have changes; commit them or move them to a branch first", dirty=status)
        run.show(view.dirty(run.look, status))
        raise typer.Exit(1)
    return status


def _plan(root: Path, releases: List[up.Release], pos: dict, target: up.Release,
          manifests: List[dict]) -> dict:
    base = up.parse_release(pos["tag"] or "")
    forward = base is None or target.key > base.key
    passed = up.crossed(releases, pos, target) if forward else []
    notes = up.release_notes(root, target, passed or [target])
    target_note = notes[0] if notes else {}
    return {
        "current": {**pos, "label": up.describe(pos)},
        "target": {**target.to_json(), "date": target_note.get("date")},
        "direction": "forward" if forward else "back",
        "releases": notes if passed else [],
        "breaking": up.pair_breaking(notes, manifests) if passed else [],
        "used_fetchers": sorted({u for m in manifests for u in m["uses"]}),
        "manifests": [m["label"] for m in manifests],
    }


def _tries(plan: dict) -> List[Tuple[str, str]]:
    seen, out = set(), []
    for n in plan["releases"]:
        for h in n["highlights"]:
            if h.get("try") and h["try"] not in seen:
                seen.add(h["try"])
                out.append((h["try"], h["title"]))
    return out


def _update(run: _Run, root: Path, *, to: Optional[str], next_release: bool, yes: bool,
            allow_breaking: bool) -> NoReturn:
    look = run.look
    status = _refuse_if_dirty(run, root)

    with run.step("fetch release tags") as s:
        try:
            up.fetch_tags(root)
            fetched = True
        except up.UpdateError as e:
            fetched, why = False, str(e)
        releases = up.list_releases(root)
        newest = releases[-1].version if releases else "none"
        if fetched:
            s.done(f"{view._plural(len(releases), 'release')} · newest {newest}")
        else:
            s.warn(f"offline ({why}); using the {len(releases)} tags you have")
    pos = up.position(root)
    run.doc.update(current={**pos, "label": up.describe(pos)}, fetched=fetched)

    try:
        target = up.choose_target(releases, pos, to=to, next_release=next_release)
    except up.UpdateError as e:
        run.fail(str(e))
    base = up.parse_release(pos["tag"] or "")
    if target is None or (pos["exact"] and base and target.key == base.key):
        run.doc.update(ok=True, up_to_date=True, target=target.to_json() if target else None)
        if run.json:
            _emit(run.doc, 0)
        what = "no newer release than" if next_release else "already on"
        run.gap()
        run.show(view.verdict(look, True, f"Nothing to do: {what} {up.describe(pos)}."))
        raise typer.Exit(0)

    if not pos["exact"]:
        where = pos["branch"] or "a detached commit"
        past = f"{pos['ahead']} commits past {pos['tag']}" if pos["tag"] else "with no release behind it"
        run.show(view.note(look, f"You're on {where}, {past}. That's unreleased work; releases are tags."))
        run.doc["off_release"] = True

    manifests = up.user_manifests(root)
    plan = _plan(root, releases, pos, target, manifests)
    run.doc.update({k: v for k, v in plan.items() if k != "current"})
    run.gap()
    run.show(view.header(look, plan))
    news = view.whats_new(look, plan)
    if news is not None:
        run.gap()
        run.show(news)
    brk = view.breaking(look, plan)
    if brk is not None:
        run.gap()
        run.show(brk)
    run.gap()

    with run.step("check in a temp worktree") as s:
        try:
            result = up.check_target(root, target, manifests)
        except up.UpdateError as e:
            s.fail(str(e))
            run.fail(f"the pre-switch check failed: {e}")
        state, summary = view.check_summary(result)
        s.done(summary, state)
        for line in view.check_details(look, result):
            s.add(line)
    run.doc["check"] = result
    run.gap()
    run.show(view.your_fetchers(look, result["fetchers"]))
    if status["untracked"]:
        run.show(view.untracked_note(look, status["untracked"]))
    run.gap()

    if result["python_required"]:
        run.fail(f"{target.tag} needs Python {result['python_required']}; make a venv with a newer Python first")
    breaks = [m["manifest"] for m in result["manifests"] if m["status"] == "breaks"]
    unattended = yes or run.json
    if unattended and not allow_breaking and (plan["breaking"] or breaks):
        why = (f"{view._plural(len(breaks), 'manifest')} would break" if breaks
               else f"{view._plural(len(plan['breaking']), 'breaking change')} between here and {target.version}")
        run.fail(f"stopped: {why}. Read them above, then rerun with --allow-breaking (or without --yes)")
    if run.json and not yes:
        run.fail("switching needs confirmation: pass --yes")
    question = (f"Switch to {target.tag}? {view._plural(len(breaks), 'manifest')} would break." if breaks
                else f"Move back to {target.tag}?" if plan["direction"] == "back" else f"Switch to {target.tag}?")
    if not _confirm(run, question, yes):
        if not sys.stdin.isatty() and not yes:
            run.fail("switching needs confirmation: pass --yes")
        run.show(view.note(look, "Nothing changed."))
        raise typer.Exit(1)
    if not run.json:
        run.gap()

    _apply(run, root, pos, target.tag, manifests, version=target.version, tries=_tries(plan))


def _apply(run: _Run, root: Path, pos: dict, ref: str, manifests: List[dict], *, version: str,
           tries: List[Tuple[str, str]], branch: bool = False, rolling_back: bool = False) -> NoReturn:
    """Switch, reinstall, validate. Shared by update and --rollback."""
    look = run.look
    extras = up.detect_extras()
    env = up.environment()
    run.doc["environment"] = {**env, "extras": extras}

    with run.step(f"switch to {ref if branch or ref.startswith('v') else ref[:7]}") as s:
        try:
            up.switch(root, ref, branch=branch)
        except up.UpdateError as e:
            s.fail(str(e))
            run.fail(f"git refused the switch: {e}")
        s.done("on the branch" if branch else "detached at the tag" if ref.startswith("v") else "detached")
    if rolling_back:
        up.forget_previous(root)
    else:
        up.remember_previous(root, pos)
    run.doc["switched"] = True

    where = _env_label(root, env)
    with run.step("reinstall") as s:
        res = up.reinstall(root, extras)
        run.doc["reinstall"] = res
        if res["ok"]:
            s.done(f"{_extras_label(extras)} into {where}")
        else:
            s.fail("pip failed")
            for line in (res.get("error") or "").splitlines()[-4:]:
                s.add(view.indent(view.Text(line, style=look.muted), 6))
    if not res["ok"]:
        _revert(run, root, pos, extras)

    with run.step("validate manifests") as s:
        val = up.validate_all(root, manifests)
        run.doc["validate"] = val
        bad = [r for r in val["manifests"] if r["ok"] is False]
        if not manifests:
            s.done("no manifests", "skip")
        elif bad:
            s.fail(f"{len(bad)} of {view._plural(len(manifests), 'manifest')} fail")
            for r in bad:
                for line in view.manifest_errors(look, r["manifest"], "fails", look.fail, r["errors"]):
                    s.add(line)
        else:
            s.done(f"{view._plural(len(manifests), 'manifest')} valid")

    run.doc["ok"] = True
    run.doc["version"] = version
    if run.json:
        _emit(run.doc, 0)
    run.gap()
    run.show(view.done_panel(look, version, tries, rollback=not rolling_back,
                             container=(root / "deploy").is_dir()))
    if bad:
        run.show(view.note(look, "Fix what validate names above, or go back with ", "paramify update --rollback"))
    raise typer.Exit(0)


def _revert(run: _Run, root: Path, pos: dict, extras: Optional[List[str]]) -> NoReturn:
    """The reinstall failed: put the old code back so `paramify` still starts."""
    with run.step("switch back") as s:
        try:
            up.switch(root, pos["branch"] or pos["sha"], branch=bool(pos["branch"]))
            up.forget_previous(root)
            again = up.reinstall(root, extras)
            s.done(f"back on {up.describe(pos)}" + ("" if again["ok"] else ", but its reinstall failed too"),
                   "ok" if again["ok"] else "warn")
        except up.UpdateError as e:
            s.fail(str(e))
    run.fail("the reinstall failed, so update put your previous version back; the pip error is above")


def _extras_label(extras: Optional[List[str]]) -> str:
    chosen = ["all"] if extras is None else extras
    return f".[{','.join(chosen)}]" if chosen else "."


def _env_label(root: Path, env: dict) -> str:
    """The venv relative to the clone (.venv), else with ~ for home."""
    if env["venv"]:
        venv = Path(env["venv"]).resolve()
        try:
            return str(venv.relative_to(root.resolve()))
        except ValueError:
            return "…/" + "/".join(venv.parts[-2:])
    return f"Python {env['python_version']}"


# --------------------------------------------------------------------------- #
# --rollback
# --------------------------------------------------------------------------- #

def _rollback(run: _Run, root: Path, yes: bool) -> NoReturn:
    prev = up.read_state(root).get("previous")
    if not prev:
        run.fail("nothing to roll back to: no update has been recorded here (or it was already rolled back)")
    _refuse_if_dirty(run, root)
    pos = up.position(root)
    manifests = up.user_manifests(root)
    label = prev.get("describe") or prev["ref"]
    run.doc.update(current={**pos, "label": up.describe(pos)}, target=prev)
    plan = {"current": {"label": up.describe(pos)}, "target": {"version": label, "date": None},
            "direction": "rollback", "releases": [], "breaking": []}
    run.show(view.header(run.look, plan))
    run.gap()
    if run.json and not yes:
        run.fail("rolling back needs confirmation: pass --yes")
    if not _confirm(run, f"Go back to {label}?", yes):
        if not sys.stdin.isatty() and not yes:
            run.fail("rolling back needs confirmation: pass --yes")
        run.show(view.note(run.look, "Nothing changed."))
        raise typer.Exit(1)
    run.gap()
    ref = prev["branch"] or prev["sha"]
    _apply(run, root, pos, ref, manifests, version=label, tries=[], branch=bool(prev["branch"]),
           rolling_back=True)


# --------------------------------------------------------------------------- #
# The once-a-day notice
# --------------------------------------------------------------------------- #

def maybe_notice(subcommand: Optional[str]) -> None:
    """One dim line after a command when a newer release exists.

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
        console = view.make_console(stderr=True)
        look = view.Look(console)
        t = view.Text(f"paramify {info['latest']} is out (you run {info['current']}) · ", style=look.muted)
        t.append("paramify update", style=look.info)
        console.print(t)
    except Exception:  # noqa: BLE001
        return
