"""How `paramify update` looks in a terminal.

The rest of the CLI writes the terminal's own 16 colors (framework/cli_style.py)
so it sits in whatever theme the reader runs. This command is the exception: it
is the one moment the tool talks about itself, so it wears the TUI's Tokyo
Night palette, the same blue-to-purple ramp as the welcome screen's logo, and
the same pills. Three things pull it back to plain:

* PARAMIFY_THEME=light, or a terminal that says its background is light
  (COLORFGBG), swaps the pastel hex colors for the terminal's named ones, which
  every light theme defines legibly. Pills become reversed text.
* NO_COLOR, or output that isn't a terminal, drops color entirely (rich does
  this itself). Pills become [bracketed] words so they still read as labels.
* A non-terminal never animates: each step prints once, when it settles.

The hex values are copied from framework/tui/palette.py rather than imported,
because importing anything under framework.tui pulls in textual, which the base
install doesn't have. tests/test_update.py checks the two stay identical.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from rich import box
from rich.console import Console, Group, RenderableType
from rich.constrain import Constrain
from rich.live import Live
from rich.padding import Padding
from rich.panel import Panel
from rich.spinner import Spinner
from rich.style import Style
from rich.table import Table
from rich.terminal_theme import TerminalTheme
from rich.text import Text

# --------------------------------------------------------------------------- #
# Palette (mirrors framework/tui/palette.py)
# --------------------------------------------------------------------------- #

BG = "#1A1B26"
FG = "#C0CAF5"
SUBTLE = "#565F89"
BLUE = "#7AA2F7"
PURPLE = "#BB9AF7"
CYAN = "#7DCFFF"
GREEN = "#9ECE6A"
YELLOW = "#E0AF68"
RED = "#F7768E"
ORANGE = "#FF9E64"
OK_TEXT, OK_MUTED = "#BEDE9C", "#41503A"
WARN_TEXT, WARN_MUTED = "#EACA9B", "#554739"
FAIL_TEXT, FAIL_MUTED = "#F9A4B4", "#5C3645"

DOTS = "#3B4261"      # leader dots, dimmer than SUBTLE (welcome screen)
SPIN = "#9AA5CE"      # spinner glyph (welcome screen)
SPINNER = "dots"      # ⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏, the welcome screen's frames

WIDTH = 76            # the card width; narrower terminals get their own width
LEADER_TO = 28        # step labels pad out to this column with dots


def _mix(a: str, b: str, t: float) -> str:
    """Blend hex color a toward b by t (0..1)."""
    pa = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    pb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02X}" for x, y in zip(pa, pb))


def _pill_pair(hue: str) -> Tuple[str, str]:
    """Readable text on a muted swatch of the same hue, derived the way the
    palette's frozen OK/WARN/FAIL pairs were, for hues it has no pair for."""
    return _mix(hue, "#FFFFFF", 0.35), _mix(BG, hue, 0.27)


# tag -> (label, hue, ansi name). Labels are at most 8 characters so the pill
# column is one fixed width and every title starts in the same place.
TAGS: Dict[str, Tuple[str, str, str]] = {
    "new": ("NEW", PURPLE, "magenta"),
    "fetcher": ("FETCHER", BLUE, "blue"),
    "cli": ("CLI", CYAN, "cyan"),
    "tui": ("TUI", CYAN, "cyan"),
    "improved": ("IMPROVED", GREEN, "green"),
    "security": ("SECURITY", ORANGE, "yellow"),
    "fix": ("FIX", GREEN, "green"),
    "deprecated": ("RETIRING", YELLOW, "yellow"),
    "breaking": ("BREAKING", RED, "red"),
}
PILL_WIDTH = 10

_FROZEN = {GREEN: (OK_TEXT, OK_MUTED), YELLOW: (WARN_TEXT, WARN_MUTED), RED: (FAIL_TEXT, FAIL_MUTED)}

# The SVGs in docs/img/update/ are rendered with this terminal theme, so the
# screenshots show the colors a Tokyo Night terminal would.
SVG_THEME = TerminalTheme(
    (0x1A, 0x1B, 0x26), (0xC0, 0xCA, 0xF5),
    [(0x15, 0x16, 0x1E), (0xF7, 0x76, 0x8E), (0x9E, 0xCE, 0x6A), (0xE0, 0xAF, 0x68),
     (0x7A, 0xA2, 0xF7), (0xBB, 0x9A, 0xF7), (0x7D, 0xCF, 0xFF), (0xA9, 0xB1, 0xD6)],
    [(0x41, 0x48, 0x68), (0xF7, 0x76, 0x8E), (0x9E, 0xCE, 0x6A), (0xE0, 0xAF, 0x68),
     (0x7A, 0xA2, 0xF7), (0xBB, 0x9A, 0xF7), (0x7D, 0xCF, 0xFF), (0xC0, 0xCA, 0xF5)],
)


def light_terminal() -> bool:
    """PARAMIFY_THEME wins; otherwise trust COLORFGBG ("15;0" is light on dark,
    "0;15" dark on light), which rxvt, Konsole and iTerm2 can set."""
    theme = os.environ.get("PARAMIFY_THEME", "").strip().lower()
    if theme in ("light", "ansi"):
        return True
    if theme == "dark":
        return False
    bg = os.environ.get("COLORFGBG", "").split(";")[-1]
    return bg.isdigit() and int(bg) in (7, 15)


class Look:
    """Every color decision in one place, resolved once per console."""

    def __init__(self, console: Console, light: Optional[bool] = None) -> None:
        self.console = console
        self.plain = console.no_color or console.color_system is None
        self.light = light_terminal() if light is None else light
        ansi = self.light
        self.fg = "default" if ansi else FG
        self.muted = "bright_black" if ansi else SUBTLE
        self.dots = "bright_black" if ansi else DOTS
        self.spin = "blue" if ansi else SPIN
        self.accent = "magenta" if ansi else PURPLE
        self.info = "cyan" if ansi else CYAN
        self.blue = "blue" if ansi else BLUE
        self.ok = "green" if ansi else GREEN
        self.warn = "yellow" if ansi else YELLOW
        self.fail = "red" if ansi else RED

    # ---- pieces ----------------------------------------------------------- #

    def gradient(self, text: str, bold: bool = True) -> Text:
        """The welcome logo's blue-to-purple ramp, one color per character."""
        if self.light or self.plain:
            return Text(text, style=Style(color=self.accent, bold=bold))
        out = Text()
        n = max(len(text) - 1, 1)
        for i, ch in enumerate(text):
            out.append(ch, style=Style(color=_mix(BLUE, PURPLE, i / n), bold=bold))
        return out

    def pill(self, tag: str) -> Text:
        label, hue, ansi = TAGS.get(tag, (tag.upper()[:8], SUBTLE, "white"))
        if self.plain:
            return Text(f"[{label.lower()}]".ljust(PILL_WIDTH))
        if self.light:
            return Text(label.center(PILL_WIDTH), style=Style(color=ansi, reverse=True, bold=True))
        fg, bg = _FROZEN.get(hue) or _pill_pair(hue)
        return Text(label.center(PILL_WIDTH), style=Style(color=fg, bgcolor=bg, bold=True))

    def mark(self, state: str) -> Text:
        glyph, color = {"ok": ("✓", self.ok), "fail": ("✗", self.fail),
                        "warn": ("!", self.warn), "skip": ("–", self.muted)}[state]
        return Text(glyph, style=Style(color=color, bold=True))

    def leader(self, label: str, width: int = LEADER_TO) -> Text:
        t = Text("  ")
        t.append(label, style=self.fg)
        t.append(" " + "·" * max(2, width - len(label)) + " ", style=self.dots)
        return t

    def link(self, text: str, url: str) -> Text:
        return Text(text, style=Style(color=self.info, link=url, underline=not self.plain))


def make_console(**kw: Any) -> Console:
    return Console(highlight=False, soft_wrap=False, **kw)


def preload() -> None:
    """Import everything rendering needs before the checkout changes.

    rich loads some modules lazily (spinner frames, box drawing). Those live in
    site-packages, so they're safe, but this keeps every import this command
    makes happening before `git switch`, never between the old and new code.
    """
    from rich import _spinners, spinner  # noqa: F401


# --------------------------------------------------------------------------- #
# Live steps
# --------------------------------------------------------------------------- #

class Step:
    """One line that spins while its work runs and settles to ✓/✗ with a value."""

    def __init__(self, look: Look, label: str) -> None:
        self.look = look
        self.label = label
        self.state: Optional[str] = None
        self.value: Text = Text("")
        self.below: List[RenderableType] = []
        self._spinner = Spinner(SPINNER, style=look.spin)

    def done(self, value: str = "", state: str = "ok") -> None:
        self.state, self.value = state, Text(value, style=self.look.fg if state == "ok" else
                                             {"fail": self.look.fail, "warn": self.look.warn}.get(state, self.look.muted))

    def fail(self, value: str = "") -> None:
        self.done(value, "fail")

    def warn(self, value: str = "") -> None:
        self.done(value, "warn")

    def add(self, renderable: RenderableType) -> None:
        """A detail line shown under the step once it settles."""
        self.below.append(renderable)

    def _line(self, spinning: bool) -> RenderableType:
        line = self.look.leader(self.label)
        if spinning:
            return _Join(line, self._spinner)
        line.append_text(self.look.mark(self.state or "ok"))
        if self.value.plain:
            line.append(" ")
            line.append_text(self.value)
        line.no_wrap, line.overflow = True, "ellipsis"  # a step is one line, always
        return Group(line, *self.below) if self.below else line

    def __rich__(self) -> RenderableType:
        return self._line(self.state is None)


class _Join:
    """A Text followed by a live Spinner on the same line."""

    def __init__(self, text: Text, spinner: Spinner) -> None:
        self.text, self.spinner = text, spinner

    def __rich_console__(self, console: Console, options: Any) -> Any:
        frame = self.spinner.render(console.get_time())
        out = self.text.copy()
        out.append_text(frame if isinstance(frame, Text) else Text(str(frame)))
        yield out


@contextmanager
def step(look: Look, label: str) -> Iterator[Step]:
    """Run a block as a live step. An exception inside marks it ✗ and re-raises."""
    s = Step(look, label)
    console = look.console
    animate = console.is_terminal and not console.is_dumb_terminal and not console.record
    if not animate:
        try:
            yield s
        except BaseException:
            if s.state is None:
                s.fail("interrupted")
            console.print(Constrain(s, WIDTH))
            raise
        if s.state is None:
            s.done()
        console.print(Constrain(s, WIDTH))
        return
    with Live(Constrain(s, WIDTH), console=console, refresh_per_second=12.5, transient=False) as live:
        try:
            yield s
        except BaseException:
            if s.state is None:
                s.fail("interrupted")
            live.update(Constrain(s, WIDTH), refresh=True)
            raise
        if s.state is None:
            s.done()
        live.update(Constrain(s, WIDTH), refresh=True)


# --------------------------------------------------------------------------- #
# The plan
# --------------------------------------------------------------------------- #

def _plural(n: int, word: str, many: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _card_width(look: Look) -> int:
    return min(look.console.width, WIDTH)


def header(look: Look, plan: dict) -> RenderableType:
    """The version jump: where you are, where you're going, and when it shipped."""
    cur, tgt = plan["current"], plan["target"]
    notes = plan["releases"]
    jump = Text("  ")
    jump.append(cur["label"], style=Style(color=look.fg))
    arrow_len = 14
    jump.append("  ")
    if look.light or look.plain:
        jump.append("━" * arrow_len + "▶", style=look.accent)
    else:
        for i in range(arrow_len):
            jump.append("━", style=_mix(SUBTLE, BLUE, i / arrow_len))
        jump.append("▶", style=BLUE)
    jump.append("  ")
    jump.append_text(look.gradient(tgt["version"]))

    facts: List[Text] = []
    if tgt.get("date"):
        facts.append(Text(f"released {tgt['date']}", style=look.muted))
    if plan["direction"] == "forward":
        facts.append(Text(_plural(len(notes), "release") + " ahead", style=look.muted))
    elif plan["direction"] == "back":
        facts.append(Text("older than what you run", style=look.warn))
    elif plan["direction"] == "rollback":
        facts.append(Text("back to the version before your last update", style=look.muted))
    if plan["breaking"]:
        facts.append(Text(_plural(len(plan["breaking"]), "breaking change"), style=Style(color=look.fail, bold=True)))
    sub = Text("  ")
    for i, f in enumerate(facts):
        if i:
            sub.append("  ·  ", style=look.dots)
        sub.append_text(f)

    body = Group(Text(""), jump, sub, Text(""))
    title = Text(" ")
    title.append_text(look.gradient("paramify update"))
    title.append(" ")
    return Panel(body, title=title, title_align="left", box=box.ROUNDED,
                 border_style=look.muted, width=_card_width(look), padding=(0, 1))


def _yours(h: dict, used: set) -> bool:
    import fnmatch

    return any(fnmatch.fnmatchcase(u, p) for p in h.get("fetchers") or [] for u in used)


def whats_new(look: Look, plan: dict, max_releases: int = 3) -> Optional[RenderableType]:
    """Highlight rows per crossed release, newest first."""
    notes = plan["releases"]
    if not notes:
        return None
    used = set(plan.get("used_fetchers") or [])
    parts: List[RenderableType] = [Text("  What's new", style=Style(color=look.fg, bold=True))]
    many = len(notes) > 1
    for n in notes[:max_releases]:
        if many:
            sub = Text("\n  ")
            sub.append(n["version"], style=Style(color=look.accent, bold=True))
            if n.get("date"):
                sub.append(f"  {n['date']}", style=look.muted)
            parts.append(sub)
        if not n["has_highlights"]:
            row = Text("    no highlights for this release, see the ", style=look.muted)
            row.append_text(look.link("changelog", n["changelog_url"]))
            parts.append(row)
            continue
        grid = Table.grid(padding=(0, 1))
        grid.add_column(width=2)
        grid.add_column(width=PILL_WIDTH)
        grid.add_column(ratio=1)
        for h in n["highlights"]:
            title = Text(h["title"], style=look.fg)
            if _yours(h, used):
                title.append("  ◆ yours", style=look.accent)
            cell: List[RenderableType] = [title]
            if h.get("detail"):
                cell.append(Text(h["detail"], style=look.muted))
            if grid.row_count:
                grid.add_row("", "", "")
            grid.add_row("", look.pill(h["tag"]), Group(*cell))
        parts.append(Text(""))
        parts.append(grid)
    if len(notes) > max_releases:
        rest = Text(f"\n    and {_plural(len(notes) - max_releases, 'older release')}: see the ", style=look.muted)
        rest.append_text(look.link("changelog", notes[-1]["changelog_url"]))
        parts.append(rest)
    return Group(*parts)


def breaking(look: Look, plan: dict) -> Optional[RenderableType]:
    """Each breaking change with its fix and the manifests it touches.

    A change scoped to fetchers none of the user's manifests run folds into a
    count at the end: it is real, but it isn't theirs to act on. Changes with
    no fetcher scope (Python, CLI behaviour) are always shown.
    """
    items = plan["breaking"]
    if not items:
        return None
    shown = [b for b in items if not b.get("scoped") or b.get("manifests")]
    folded = len(items) - len(shown)
    head = Text("  ")
    head.append_text(look.pill("breaking"))
    head.append(f"  {_plural(len(items), 'change')} to read before you switch",
                style=Style(color=look.fail, bold=True))
    grid = Table.grid(padding=(0, 1))
    grid.add_column(width=3, justify="right")
    grid.add_column(ratio=1)
    many = len({b["release"] for b in items}) > 1
    for b in shown:
        title = Text(b["title"], style=Style(color=look.fg, bold=True))
        if many:
            title.append(f"  {b['release']}", style=look.muted)
        cell: List[RenderableType] = [title]
        if b.get("fix"):
            cell.append(Text(b["fix"], style=look.muted))
        if b.get("manifests"):
            hit = Text("affects ", style=look.warn)
            for i, m in enumerate(b["manifests"]):
                if i:
                    hit.append(", ", style=look.muted)
                hit.append(m["manifest"], style=Style(color=look.warn, bold=True))
            cell.append(hit)
        if grid.row_count:
            grid.add_row("", "")
        grid.add_row(Text("▲", style=look.fail), Group(*cell))
    parts: List[RenderableType] = [head, Text(""), grid]
    if folded:
        parts.append(Text(f"\n    + {folded} more for fetchers your manifests don't use",
                          style=look.muted))
    if any(b["source"] == "changelog" for b in items):
        note_ = Text("    each CHANGELOG entry says what to do: ", style=look.muted)
        url = next(n["changelog_url"] for n in plan["releases"] if n["changelog_breaking"])
        note_.append_text(look.link("changelog", url))
        parts.append(note_)
    return Group(*parts)


def indent(renderable: RenderableType, n: int) -> RenderableType:
    """Indent a block so a wrapped line keeps its margin, unlike leading spaces."""
    return Padding(renderable, (0, 0, 0, n))


def manifest_errors(look: Look, label: str, word: str, color: str, lines: Sequence[str]) -> List[RenderableType]:
    t = Text(label, style=Style(color=look.fg, bold=True))
    t.append(f"  {word}", style=color)
    out: List[RenderableType] = [indent(t, 6)]
    for e in lines[:4]:
        out.append(indent(Text(e, style=look.muted), 8))
    if len(lines) > 4:
        out.append(indent(Text(f"… and {len(lines) - 4} more", style=look.muted), 8))
    return out


def check_details(look: Look, check: dict) -> List[RenderableType]:
    """Lines under the check step: one per manifest that isn't simply fine."""
    out: List[RenderableType] = []
    if check.get("python_required"):
        out.append(indent(Text(f"needs Python {check['python_required']}; this is {check['python']}",
                               style=look.fail), 6))
    for m in check["manifests"]:
        if m["status"] == "ok":
            continue
        color, word = {
            "breaks": (look.fail, "would break"),
            "still_failing": (look.warn, "fails now and after"),
            "fixed": (look.ok, "fails now, passes after"),
            "unchecked": (look.muted, "not checked"),
        }[m["status"]]
        lines = m["errors"] if m["status"] in ("breaks", "still_failing") else (
            [m["reason"]] if m["status"] == "unchecked" and m.get("reason") else [])
        out += manifest_errors(look, m["manifest"], word, color, lines)
    return out


def check_summary(check: dict) -> Tuple[str, str]:
    rows = check["manifests"]
    breaks = sum(r["status"] == "breaks" for r in rows)
    if check.get("python_required"):
        return "fail", f"needs Python {check['python_required']}"
    if not rows:
        return "skip", "no manifests to check"
    if breaks:
        return "fail", f"{breaks} of {_plural(len(rows), 'manifest')} would break"
    unchecked = sum(r["status"] == "unchecked" for r in rows)
    if unchecked == len(rows):
        return "warn", f"couldn't check {_plural(len(rows), 'manifest')}"
    return "ok", f"{_plural(len(rows), 'manifest')} pass on the new version"


def your_fetchers(look: Look, changes: dict) -> RenderableType:
    """The changed-fetcher split: yours by name, everyone else's as counts."""
    yours, others = changes["yours"], changes["others"]
    parts: List[RenderableType] = [Text("  Your fetchers", style=Style(color=look.fg, bold=True))]
    grid = Table.grid(padding=(0, 1))
    grid.add_column(width=3, justify="right")
    grid.add_column(ratio=1)
    if yours:
        names = Text(_plural(len(yours), "fetcher") + " you use changed  ", style=Style(color=look.fg))
        for i, f in enumerate(yours[:8]):
            if i:
                names.append(", ", style=look.muted)
            names.append(f["name"], style=look.accent)
            if f["change"] == "removed":
                names.append(" (removed)", style=look.fail)
        if len(yours) > 8:
            names.append(f", +{len(yours) - 8} more", style=look.muted)
        grid.add_row(Text("●", style=look.accent), names)
    else:
        grid.add_row(Text("●", style=look.ok), Text("none of the fetchers you use changed", style=look.fg))
    bits = [_plural(len(others), "other") + " changed"]
    if changes["added"]:
        bits.append(f"{len(changes['added'])} new")
    if changes["removed"]:
        bits.append(f"{len(changes['removed'])} removed")
    grid.add_row(Text("○", style=look.muted), Text(" · ".join(bits), style=look.muted))
    parts.append(grid)
    return Group(*parts)


def dirty(look: Look, status: dict) -> RenderableType:
    """Why update won't switch, and what survives a switch anyway."""
    t = Text("  ")
    t.append_text(look.mark("fail"))
    t.append(" Your checkout has changes to tracked files, so update won't switch.",
             style=Style(color=look.fg, bold=True))
    parts: List[RenderableType] = [t, indent(Text("A switch would carry them onto code they weren't "
                                                  "written for, or stop halfway.", style=look.muted), 4),
                                   Text("")]
    for p in status["tracked"][:12]:
        parts.append(Text(f"      {p}", style=look.warn))
    if len(status["tracked"]) > 12:
        parts.append(Text(f"      … and {len(status['tracked']) - 12} more", style=look.muted))
    fix = Text("Commit them, or move them to a branch, then run ", style=look.fg)
    fix.append("paramify update", style=look.info)
    fix.append(" again.", style=look.fg)
    parts += [Text(""), indent(fix, 4)]
    if status["untracked"]:
        parts.append(untracked_note(look, status["untracked"]))
    return Group(*parts)


def untracked_note(look: Look, untracked: Sequence[str]) -> RenderableType:
    n = len(untracked)
    return indent(Text(f"{_plural(n, 'untracked path')} (custom fetchers, notes) "
                       f"{'stays where it is' if n == 1 else 'stay where they are'}.", style=look.muted), 4)


def done_panel(look: Look, version: str, tries: Sequence[Tuple[str, str]], *, rollback: bool = True,
               container: bool = False, title_word: str = "you're on") -> RenderableType:
    """The closing card: the version you're on and what to try first."""
    rows = [("try" if i == 0 else "", cmd, why) for i, (cmd, why) in enumerate(tries[:3])]
    if rollback:
        rows.append(("undo", "paramify update --rollback", "back to where you were"))
    elif not rows:
        rows.append(("next", "paramify update --check", "see what's newer, when you're ready"))
    # Exact widths, with the descriptions cut by hand: when a grid overflows,
    # rich shrinks its first columns to nothing rather than the last one.
    cmd_w = max((len(r[1]) for r in rows), default=0)
    why_w = max(0, _card_width(look) - 2 - 4 - 4 - 2 - cmd_w - 2)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=look.muted, no_wrap=True, width=4)
    grid.add_column(no_wrap=True, width=cmd_w)
    grid.add_column(style=look.muted, no_wrap=True, width=why_w)
    for label, cmd, why in rows:
        grid.add_row(label, Text(cmd, style=look.info), why if len(why) <= why_w else why[: why_w - 1] + "…")
    body: List[RenderableType] = [grid]
    if container:
        # The image is a copy of the clone made at build time, so it is still
        # on the old version until someone rebuilds it.
        body += [Text(""), Text("Deploy with the container? Rebuild the image too:", style=look.muted),
                 Text("docker compose -f deploy/docker-compose.yml build", style=look.info)]
    title = Text(" ")
    title.append_text(look.mark("ok"))
    title.append(f" {title_word} ", style=Style(color=look.fg, bold=True))
    title.append_text(look.gradient(version))
    title.append(" ")
    return Panel(Group(*body), title=title, title_align="left", box=box.ROUNDED, border_style=look.ok,
                 width=_card_width(look), padding=(1, 2))


def container_panel(look: Look, advice: dict) -> RenderableType:
    """`update` inside the deploy image: what to run, and where."""
    # Plain lines, not a grid: the compose command is long, and a grid that
    # overflows a narrow panel collapses its first column to nothing.
    intro = Text("This copy has no git history, so there is nothing here to update. "
                 "The image is built from your clone: update the clone, then rebuild.", style=look.fg)
    steps: List[RenderableType] = [intro, Text("")]
    for n, (where, cmd) in enumerate(zip(("On the host, in your clone", "Then rebuild the image"),
                                         advice["commands"]), 1):
        steps.append(Text(f"{n}  {where}", style=look.muted))
        steps.append(Text(f"   {cmd}", style=look.info))
    if advice.get("version"):
        steps.append(Text(f"\nthis image runs paramify-fetchers {advice['version']}", style=look.muted))
    body = Group(*steps)
    title = Text(" ")
    title.append_text(look.gradient("paramify update"))
    title.append(" · running in a container ", style=look.muted)
    return Panel(body, title=title, title_align="left", box=box.ROUNDED, border_style=look.muted,
                 width=_card_width(look), padding=(1, 2))


def verdict(look: Look, good: bool, text: str) -> Text:
    t = Text("  ")
    t.append_text(look.mark("ok" if good else "fail"))
    t.append(" " + text, style=Style(color=look.ok if good else look.fail, bold=True))
    return t


def note(look: Look, text: str, cmd: Optional[str] = None) -> Text:
    t = Text("  " + text, style=look.muted)
    if cmd:
        t.append(cmd, style=look.info)
    return t

