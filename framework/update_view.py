"""How `paramify update` looks in a terminal.

Plain lines in the terminal's own colors, like the rest of the CLI, so it sits
in whatever theme the reader runs. Every line is one row, cut with an ellipsis
rather than wrapped, except a breaking change and its fix: those wrap, hanging
under their text, because they are the part a reader must not miss. Nothing is
wider than WIDTH. Without a terminal (a pipe, a CI log, NO_COLOR) rich drops
the color, the width is WIDTH, and the steps print once, when they settle,
instead of spinning.
"""

from __future__ import annotations

import datetime
import fnmatch
from contextlib import contextmanager
from typing import Any, Iterator, List, Optional, Sequence, Tuple

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.padding import Padding
from rich.spinner import Spinner
from rich.text import Text

WIDTH = 100           # nothing prints wider than this, however wide the terminal
LEADER_TO = 28        # step labels pad out to this column with dots
MAX_NOTES = 3         # release notes listed under one fetcher before "+N earlier"
NAME_MAX = 44         # the fetcher-name column grows to the longest name, up to this
MARKS = {"ok": ("✓", "green"), "fail": ("✗", "red"), "warn": ("!", "yellow"), "skip": ("–", "dim")}


def make_console(**kw: Any) -> Console:
    console = Console(highlight=False, soft_wrap=False, **kw)
    if "width" not in kw and not console.is_terminal:
        console.width = WIDTH  # a pipe or a log is not 80 columns wide; rich would assume it is
    return console


def line(*parts: Tuple[str, str], indent: int = 2) -> Text:
    """One row built from (text, style) pairs, never wrapped."""
    t = Text(" " * indent, no_wrap=True, overflow="ellipsis")
    for text, style in parts:
        t.append(text, style=style or None)
    return t


class _Wrapped:
    """See `wrapped`."""

    def __init__(self, lead: Tuple[str, str], body: Text, indent: int) -> None:
        self.lead, self.body, self.indent = lead, body, indent

    def __rich_console__(self, console: Console, options: Any) -> Any:
        hang = self.indent + len(self.lead[0])
        for i, row in enumerate(self.body.wrap(console, max(20, options.max_width - hang))):
            head = Text(" " * self.indent)
            head.append(self.lead[0] if i == 0 else " " * len(self.lead[0]), style=self.lead[1] if i == 0 else "")
            row.rstrip()
            yield head + row


def wrapped(lead: Tuple[str, str], *parts: Tuple[str, str], indent: int = 2) -> RenderableType:
    """A row whose text wraps instead of being cut, each wrapped line hanging
    under the text rather than under `lead` (a mark, or a label like "fix: ")."""
    body = Text()
    for text, style in parts:
        body.append(text, style=style or None)
    return _Wrapped(lead, body, indent)


def plural(n: int, word: str, many: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


# --------------------------------------------------------------------------- #
# Live steps
# --------------------------------------------------------------------------- #

class Step:
    """One line that spins while its work runs and settles to a mark and a value."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.state: Optional[str] = None
        self.value = ""
        self.below: List[RenderableType] = []
        self._spinner = Spinner("dots", style="dim")

    def done(self, value: str = "", state: str = "ok") -> None:
        self.state, self.value = state, value

    def fail(self, value: str = "") -> None:
        self.done(value, "fail")

    def warn(self, value: str = "") -> None:
        self.done(value, "warn")

    def add(self, renderable: RenderableType) -> None:
        """A detail line shown under the step once it settles."""
        self.below.append(renderable)

    def __rich_console__(self, console: Console, options: Any) -> Any:
        head = line((self.label + " ", ""), ("·" * max(2, LEADER_TO - len(self.label) - 1) + " ", "dim"))
        if self.state is None:
            frame = self._spinner.render(console.get_time())
            head.append_text(frame if isinstance(frame, Text) else Text(str(frame)))
            yield head
            return
        mark, color = MARKS[self.state]
        head.append(mark, style=color)
        if self.value:
            head.append(" " + self.value, style="" if self.state == "ok" else color)
        yield Group(head, *self.below) if self.below else head


@contextmanager
def step(console: Console, label: str) -> Iterator[Step]:
    """Run a block as a live step. An exception inside marks it failed and re-raises."""
    s = Step(label)
    width = min(console.width, WIDTH)
    animate = console.is_terminal and not console.is_dumb_terminal and not console.record
    live = Live(s, console=console, refresh_per_second=12.5, transient=True) if animate else None
    if live:
        live.start()
    try:
        yield s
    except BaseException:
        if s.state is None:
            s.fail("interrupted")
        raise
    finally:
        if s.state is None:
            s.done()
        if live:
            live.stop()
        console.print(s, width=width)


# --------------------------------------------------------------------------- #
# The plan
# --------------------------------------------------------------------------- #

def header(plan: dict) -> Text:
    """Where you are, where you're going, and how far that is."""
    cur, tgt, span = plan["current"], plan["target"], plan.get("span") or {}
    if plan["direction"] != "rollback" and tgt.get("channel") == "branch" and cur.get("branch") == tgt.get("branch"):
        parts = [(tgt["label"] + "  ", "bold"), (cur["short"], ""), ("  ━━▶  ", "dim"), (tgt["sha"][:7], "bold cyan")]
    else:
        parts = [(cur["label"], ""), ("  ━━▶  ", "dim"), (tgt["label"], "bold cyan")]
    if span.get("commits"):
        counts = f"{plural(span['commits'], 'commit')}, {plural(span['days'], 'day')}"
        if span.get("releases", 0) > 1:
            counts += f", {span['releases']} releases"
        parts.append((f"   ·  {counts}", "dim"))
    elif plan["direction"] == "back":
        parts.append(("   ·  older than what you run", "yellow"))
    return line(*parts)


def _heading(title: str, tail: str = "") -> Text:
    return line((title, "bold"), ("   " + tail if tail else "", "dim"))


def versions(row: dict) -> str:
    if row["change"] == "removed":
        return "removed"
    if row["change"] == "added":
        return f"new {row['to']}" if row["to"] else "new"
    if row["from"] == row["to"]:
        return row["to"] or ""
    return f"{row['from'] or '?'} → {row['to'] or '?'}"


def broken_patterns(breaking: Sequence[dict]) -> List[str]:
    """The fetcher patterns named by breaking changes that touch this clone."""
    return [p for b in breaking if b["touches"] for m in b["manifests"] for p in m["fetchers"]]


def is_broken(row: dict, broken: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(row["name"], p) for p in broken)


def fetcher_note(row: dict, broken: Sequence[str]) -> Text:
    """What changed in one of your fetchers: a breaking mark, then the newest
    release note (and how many earlier ones there are), or, with no notes, the
    reason a commit gives and how many other commits touched it."""
    note = Text()
    if is_broken(row, broken):
        note.append("⚠ breaking  ", style="yellow")
    notes = row.get("notes") or []
    if notes:
        note.append(f"{notes[0]['release']}  {notes[0]['note']}")
        if len(notes) > 1:
            note.append(f"  +{len(notes) - 1} earlier", style="dim")
    elif row["reason"]:
        note.append(row["reason"])
        if row["more"]:
            note.append(f"  +{row['more']} more", style="dim")
    elif row["more"]:
        note.append(plural(row["more"], "commit"), style="dim")
    return note


def your_fetchers(changes: dict, used: int, breaking: Sequence[dict]) -> List[Text]:
    """The fetchers your manifests use that change, one line each."""
    yours = changes["yours"]
    out = [_heading("Your fetchers", f"{len(yours)} of {used} changed" if yours else "")]
    if not yours:
        out.append(line(("● ", "green"), ("none of the fetchers you use changed", "")))
    broken = broken_patterns(breaking)
    name_to = min(NAME_MAX, max((len(r["name"]) for r in yours), default=0))
    for row in yours:
        color = "red" if row["change"] == "removed" else "cyan"
        text = line(("● ", color), (row["name"].ljust(name_to) + "  ", ""), (versions(row).ljust(15) + " ", "dim"))
        notes = row.get("notes") or []
        if notes:
            # CLI: every release's note on its own line, so none is hidden behind the newest.
            if is_broken(row, broken):
                text.append("⚠ breaking", style="yellow")
            out.append(text)
            for n in notes[:MAX_NOTES]:
                out.append(line((n["release"] + "  ", "dim"), (n["note"], ""), indent=4))
            if len(notes) > MAX_NOTES:
                out.append(line((f"+{len(notes) - MAX_NOTES} earlier", "dim"), indent=4))
        else:
            text.append_text(fetcher_note(row, broken))
            out.append(text)
    return out


def breaking(rows: Sequence[dict]) -> List[RenderableType]:
    """Breaking changes that touch this clone, each with what to do about it.
    These wrap: a cut-off fix is a fix nobody can follow."""
    mine = [b for b in rows if b["touches"]]
    if not mine:
        return []
    out: List[RenderableType] = [_heading("Breaking", f"{len(mine)} {touches(len(mine))} you")]
    for b in mine:
        who = (", ".join(m["manifest"] for m in b["manifests"]) if b["why"] == "fetchers"
               else "your own fetchers" if b["why"] == "custom" else "everyone")
        who += f" · {b.get('release') or 'unreleased'}"  # the release it came from, as New names them
        out.append(wrapped(("⚠ ", "yellow"), (b["title"], "bold"), ("   " + who, "dim")))
        if b.get("fix"):
            out.append(wrapped(("fix: ", "dim"), (b["fix"], ""), indent=4))
    return out


def _release_heading(version: str, releases: Sequence[dict]) -> str:
    if version == "unreleased":
        return version
    date = next((r.get("date") for r in releases if r["version"] == version), None)
    if not date:
        return version
    try:
        day = datetime.date.fromisoformat(date)
    except (TypeError, ValueError):
        return version
    return f"{version} · {day.strftime('%b')} {day.day}"


def whats_new(rows: Sequence[dict], releases: Sequence[dict] = ()) -> List[Text]:
    """New highlights, grouped under the release that shipped them: unreleased
    first, then newest release first (`releases` is already newest first)."""
    if not rows:
        return []
    groups: dict = {}
    for h in rows:
        groups.setdefault(h.get("release") or "unreleased", []).append(h)
    order = [v for v in ["unreleased"] + [r["version"] for r in releases] if v in groups]
    order += [v for v in groups if v not in order]
    out = [_heading("New")]
    for version in order:
        out.append(line((_release_heading(version, releases), "dim")))
        for h in groups[version]:
            out.append(line(("+ ", "green"), (h["title"], "")))
            if h.get("detail"):
                out.append(line((h["detail"], "dim"), indent=4))
    return out


def rest(plan: dict) -> List[Text]:
    """Everything that isn't about you, as counts, and where the full list is."""
    changes = plan["fetchers"]
    bits = []
    if changes["others"]:
        bits.append(f"{plural(len(changes['others']), 'other fetcher')} changed")
    if changes["added"]:
        bits.append(f"{len(changes['added'])} added")
    if changes["removed"]:
        bits.append(f"{len(changes['removed'])} removed")
    out = [line((" · ".join(bits), "dim"))] if bits else []
    other = sum(not b["touches"] for b in plan["breaking"])
    if other:
        out.append(line((f"{plural(other, 'other breaking change')} that "
                         f"{'does' if other == 1 else 'do'}n't touch you", "dim")))
    if plan.get("hidden_highlights"):
        out.append(line((f"{plural(plan['hidden_highlights'], 'more highlight')} in the changelog", "dim")))
    if plan.get("changelog"):
        out.append(line(("full changelog  ", "dim"), (plan["changelog"], "dim underline")))
    return out


def touches(n: int) -> str:
    return "touches" if n == 1 else "touch"


def stop_reasons(stops: dict) -> str:
    """Why an unattended run stops, and why the TUI asks twice: one sentence."""
    reasons = []
    if stops["breaks"]:
        reasons.append(f"{plural(len(stops['breaks']), 'manifest')} would break")
    if stops["touching"]:
        n = len(stops["touching"])
        reasons.append(f"{plural(n, 'breaking change')} {touches(n)} this clone")
    return " and ".join(reasons)


# --------------------------------------------------------------------------- #
# The check, refusals and the ending
# --------------------------------------------------------------------------- #

def manifest_errors(label: str, word: str, color: str, lines: Sequence[str]) -> List[Text]:
    out = [line((label, ""), (f"  {word}", color), indent=6)]
    out += [line((e, "dim"), indent=8) for e in list(lines)[:4]]
    if len(lines) > 4:
        out.append(line((f"… and {len(lines) - 4} more", "dim"), indent=8))
    return out


def settle_check(step: Step, check: dict) -> None:
    """Settle the "check your manifests" step with its summary and details."""
    state, summary = check_summary(check)
    step.done(summary, state)
    for detail in check_details(check):
        step.add(detail)


def check_summary(check: dict) -> Tuple[str, str]:
    rows = check["manifests"]
    breaks = sum(r["status"] == "breaks" for r in rows)
    if check.get("python_required"):
        return "fail", f"needs Python {check['python_required']}"
    if not rows:
        return "skip", "no manifests to check"
    if breaks:
        return "fail", f"{breaks} of {plural(len(rows), 'manifest')} would break"
    if all(r["status"] == "unchecked" for r in rows):
        return "warn", f"couldn't check {plural(len(rows), 'manifest')}"
    failing = sum(r["status"] == "still_failing" for r in rows)
    if failing:
        return "warn", f"nothing new breaks · {failing} of {plural(len(rows), 'manifest')} already failing"
    return "ok", f"{plural(len(rows), 'manifest')} pass{'es' if len(rows) == 1 else ''} on the new code"


def check_details(check: dict) -> List[Text]:
    """Lines under the check step: one per manifest that isn't simply fine."""
    out: List[Text] = []
    if check.get("python_required"):
        out.append(line((f"needs Python {check['python_required']}; this is {check['python']}", "red"), indent=6))
    words = {"breaks": ("red", "would break"), "still_failing": ("yellow", "fails now and after"),
             "fixed": ("green", "fails now, passes after"), "unchecked": ("dim", "not checked")}
    for m in check["manifests"]:
        if m["status"] == "ok":
            continue
        color, word = words[m["status"]]
        errors = m["errors"] if m["status"] in ("breaks", "still_failing") else [m["reason"]] if m.get("reason") else []
        out += manifest_errors(m["manifest"], word, color, errors)
    return out


def blocked(blocking: dict) -> List[RenderableType]:
    """Why git would refuse the move, and what to do."""
    out = [fail("Some of your local files are in the way of this update.")]
    if blocking["tracked"]:
        out.append(line(("You changed these, and so does the update:", "")))
        out += [line((p, "yellow"), indent=4) for p in blocking["tracked"][:12]]
    if blocking["untracked"]:
        out.append(line(("These are yours, and the update adds files there:", "")))
        out += [line((p, "yellow"), indent=4) for p in blocking["untracked"][:12]]
    out.append(line(("Commit, move or remove them, then run ", "dim"), ("paramify update", "cyan"), (" again.", "dim")))
    return out


def done(label: str, tries: Sequence[str], *, rollback: bool, rebuild: Optional[str]) -> List[Text]:
    """The ending. `tries` are the new highlights' commands; their titles were
    shown under New, so only the commands are repeated here."""
    out = [ok(f"You're on {label}.")]
    for cmd in list(tries)[:4]:
        out.append(line(("try  ", "dim"), (cmd, "cyan")))
    if rollback:
        out.append(line(("Changed your mind? ", "dim"), ("paramify update --rollback", "cyan")))
    if rebuild:
        out.append(line(("Run it in Docker too? Rebuild the image: ", "dim"), (rebuild, "cyan")))
    return out


def container(advice: dict) -> List[RenderableType]:
    out = [fail("There is no git clone here, so there is nothing to update in place.")]
    out.append(line(("This looks like the container image. Update the clone on the host, then rebuild:", "")))
    out += [line((cmd, "cyan"), indent=4) for cmd in advice["commands"]]
    return out


def ok(text: str) -> Text:
    return line(("✓ ", "green"), (text, ""))


def fail(text: str) -> RenderableType:
    """An error is shown whole, wrapped under itself, however long it is."""
    t = Text("✗ ", style="red")
    t.append(text, style="default")
    return Padding(t, (0, 0, 0, 2), expand=False)


def note(text: str) -> Text:
    return line((text, "dim"))


def offline(remote: str) -> Text:
    """Said when the fetch failed: the plan is still real, but possibly stale."""
    return note(f"couldn't reach {remote}, so this compares against what this clone last fetched")
