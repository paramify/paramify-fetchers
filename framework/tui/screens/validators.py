"""The Validators tab (4): choose which validators each fetcher tracks.

Left: the manifest's fetchers, with how many Paramify-made and community-made
validators each one tracks. Right: every validator available for the
highlighted fetcher, in a Paramify section and a community section; space
tracks or untracks one and the manifest is saved straight away. Each validator
shows its latest result in Paramify (read for the highlighted fetcher, like the
Paramify tab's artifact dates). enter opens the validator window: that result,
a test on your latest run, Ask Claude when it fails, then the regex and rules.

Saved shape: an entry with no `validators:` tracks the defaults (every
Paramify-made validator for its set); the first change writes the exact list.
Untracking only stops counting a validator; nothing is removed from Paramify.
"""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

from rich.console import Group
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Label, Static

from framework import api, ask_claude
from framework.config_loader import discover_fetchers
from framework.tui import palette
from framework.tui.components.table import DataTable
from framework.tui.modals import ConfirmModal, ReportModal
from framework.tui.screens.paramify_events import output_dir
from framework.validator_eval import evaluate, node_available
from framework.validators import (
    available_for,
    default_keys,
    discover_validators,
    write_regex,
)

# Each source gets its own hue, used everywhere it appears: the section pill,
# the edge bar on each row, the fetcher counts and the detail pane.
SOURCE = {
    "paramify": {"label": "PARAMIFY", "fg": palette.BLUE, "pill": palette.PARAMIFY_PILL,
                 "blurb": "Made and maintained by Paramify. Tracked by default."},
    "community": {"label": "COMMUNITY", "fg": palette.ORANGE, "pill": palette.COMMUNITY_PILL,
                  "blurb": "Made by the community, not Paramify. Not tracked unless you tick it."},
}
ORDER = ("paramify", "community")


def _dim(text: str) -> Text:
    return Text(text, style=palette.MUTED)


_CODE = re.compile(r"`([^`]+)`")
_LABEL = re.compile(r"^(Why|Regex):", re.M)


def render_answer(text: str) -> Text:
    """Claude's answer as Rich text: `code` in cyan and the Why/Regex labels in
    the accent (the error card's renderer, cut to what this answer uses)."""
    out = Text()
    pos = 0
    for m in _CODE.finditer(text):
        out.append(text[pos:m.start()])
        out.append(m.group(1), style=f"bold {palette.INFO}")
        pos = m.end()
    out.append(text[pos:])
    for m in _LABEL.finditer(out.plain):
        out.stylize(f"bold {palette.ACCENT}", m.start(), m.end())
    return out


class ResultsReady(Message):
    """One evidence set's latest validator results in Paramify, from the worker."""

    def __init__(self, ref: str, results: dict) -> None:
        self.ref, self.results = ref, results
        super().__init__()


def fit(text: str, width: int) -> str:
    """Cut text to width with an ellipsis (width < 1 = no room known yet: leave it)."""
    if width < 1 or len(text) <= width:
        return text
    return text[: max(width - 1, 1)] + "…"


def source_pill(source: str) -> Text:
    spec = SOURCE.get(source)
    if spec is None:
        return Text(source.upper(), style=palette.MUTED)
    text = Text()
    text.append(f" {spec['label']} ", style=spec["pill"])
    return text


_OPS = {"MATCH_COUNT": "number of matches", "MATCH_TEXT": "matched text"}


def describe_rule(rule: dict, groups: list) -> str:
    """One validation rule in plain words: 'group 1 (vendors_unresolved) equals 0'."""
    op = (rule.get("regexOperation") or {})
    kind = op.get("type", "?")
    def group(n) -> str:
        name = groups[n - 1] if isinstance(n, int) and 0 < n <= len(groups) else None
        return f"group {n}" + (f" ({name})" if name else "")

    if kind == "MATCH_GROUP":
        subject = group(op.get("groupNumber"))
    else:
        subject = _OPS.get(kind, kind.lower().replace("_", " "))
    value = rule.get("value") or {}
    shown = value.get("customText")
    if value.get("type") == "MATCH_GROUP":
        shown = group(value.get("groupNumber"))
    elif shown is None:
        shown = (value.get("type") or "").lower().replace("_", " ")
    else:
        shown = f'"{shown}"' if not str(shown).lstrip("-").isdigit() else str(shown)
    return f"{subject} {str(rule.get('criteria', '?')).lower().replace('_', ' ')} {shown}"


_RANK = {"PASS": 0, "FAIL": 2, "ERROR": 3, "COMPILE_ERROR": 4}
VACUOUS_RANK = 1  # a PASS that read nothing: worse than a clean PASS, better than a FAIL
NO_NODE = ("Node isn't installed, so the regex can't run here. Paramify runs validators as "
           "JavaScript. Install Node (brew install node, or nodejs.org), then press t.")
CONFIRM_SEND = "Send this to Claude using your Claude Code login?"
verdict_pill = palette.verdict_pill


def _payload(v, regex: str | None = None) -> dict:
    return {"key": v.key, "regex": regex if regex is not None else v.regex,
            "validation_rules": v.validation_rules}


def _rank(result: dict) -> int:
    if result["verdict"] == "PASS" and result.get("vacuous"):
        return VACUOUS_RANK
    return _RANK.get(result["verdict"], 9)


def run_local_test(v, files: list, regex: str | None = None) -> dict:
    """Evaluate `v` (or `regex` in its place) on each evidence file, as a live
    tenant does today. Returns {"state": "ok", "verdict", "shown": (path, result),
    "failing": n, "files": n, "vacuous": n} or {"state": "no_node"}. A PASS
    that read nothing (vacuous) counts as failing and ranks below a clean PASS.
    The shown file is the first one with the worst result, so its trace explains
    the verdict."""
    if not node_available():
        return {"state": "no_node"}
    worst = None
    failing = vacuous = 0
    for path in files:
        result = evaluate(_payload(v, regex), Path(path).read_text(), mode="api-today")
        empty = result["verdict"] == "PASS" and bool(result.get("vacuous"))
        vacuous += empty
        failing += result["verdict"] != "PASS" or empty
        if worst is None or _rank(result) > _rank(worst[1]):
            worst = (path, result)
    return {"state": "ok", "verdict": worst[1]["verdict"], "shown": worst,
            "failing": failing, "files": len(files), "vacuous": vacuous}


def _read(value) -> str:
    """A value a rule read, the way the evidence holds it."""
    if value is None:
        return "nothing"
    plain = str(value)
    return plain if plain.lstrip("-").isdigit() or plain in ("true", "false") else f'"{plain}"'


class ValidatorModal(ModalScreen[bool]):
    """One validator, and whether it works: its latest result in Paramify, a
    test on your latest run (validator_eval, the same ECMAScript engine), and,
    when that fails, Ask Claude for a fix that is tested before it is shown.
    Then its regex, rules, evidence sets and file.

    space asks the page to track / untrack it (dismisses True); esc / q close.
    """

    BINDINGS = [
        Binding("escape,q,enter", "close", "Close"),
        Binding("space", "toggle", "Track"),
        Binding("t", "test", "Test"),
        Binding("a", "ask", "Ask Claude"),
        Binding("c", "copy_report", "Copy report"),
        Binding("w", "write", "Write fix"),
    ]

    DEFAULT_CSS = """
    ValidatorModal { align: center middle; }
    #vm-card { width: 90%; max-width: 130; height: 90%; border: round $primary; background: $surface; padding: 0 1; }
    #vm-title { height: auto; padding: 1 0 0 0; }
    #vm-body { height: 1fr; }
    #vm-claude { display: none; height: auto; margin-top: 1; padding-top: 1; border-top: dashed $primary 40%; }
    #vm-claude.shown { display: block; }
    #vm-foot { height: 1; color: $text-muted; }
    """

    def __init__(self, v, tracked: bool, ref: str, root, *, fetcher=None, output_dir: str | None = None,
                 paramify: dict | None = None) -> None:
        super().__init__()
        self.v, self.tracked, self.ref, self.root = v, tracked, ref, root
        self.fetcher, self.output_dir = fetcher, output_dir
        # Paramify's latest result: None while the page reads it.
        self.paramify = paramify
        # The local test: None while it runs.
        self.local: dict | None = None
        self._files: list = []
        # Ask Claude, read by tests and the screenshot tool.
        self.asking = False
        self.answer = ""
        self.proposal: dict | None = None  # {"regex", "test"}
        self.saved = False
        self._cancel = threading.Event()
        self._started = 0.0
        self._step = ""
        self._ticker = None

    # -- layout ------------------------------------------------------------ #

    def compose(self) -> ComposeResult:
        v = self.v
        with Vertical(id="vm-card"):
            title = source_pill(v.source)
            title.append(f"  {v.name}", style="bold")
            title.append(f"\n{v.key}   {v.type.lower()} · {v.role or 'no role'}   ", style=palette.MUTED)
            title.append("tracked" if self.tracked else "not tracked",
                         style=palette.OK if self.tracked else palette.MUTED)
            yield Label(title, id="vm-title")
            with VerticalScroll(id="vm-body"):
                yield Static(self._top(), id="vm-top")
                yield Static("", id="vm-claude")
                yield Static(self._rest(), id="vm-rest")
            yield Label(self._foot(), id="vm-foot")

    def on_mount(self) -> None:
        self.action_test()

    def on_unmount(self) -> None:
        self._cancel.set()  # never leave a claude running behind a closed window

    def _section(self, name: str) -> Text:
        return Text(f"\n{name}", style=f"bold {palette.INFO}")

    def _groups(self, regex: str | None = None) -> list:
        return re.findall(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>", regex if regex is not None else self.v.regex or "")

    def _rule_lines(self, result: dict | None, regex: str | None = None) -> list:
        """Each rule in plain words, marked held / failed when `result` has a trace."""
        groups = self._groups(regex)
        trace = (result or {}).get("rules") or []
        lines = []
        for i, rule in enumerate(self.v.validation_rules or []):
            ran = trace[i] if i < len(trace) else None
            line = Text("  ")
            if ran is None:
                line.append("•  ")
            elif ran.get("held"):
                line.append("✓  ", style=palette.OK)
            else:
                line.append("✗  ", style=f"bold {palette.FAIL}")
            line.append(describe_rule(rule, groups))
            if ran is not None:
                read = _read(ran.get("lhs"))
                if (rule.get("value") or {}).get("type") == "MATCH_GROUP":
                    read += f" and {_read(ran.get('rhs'))}"
                line.append(f"   read {read}", style=palette.MUTED)
            lines.append(line)
        return lines

    def _results_table(self) -> Table:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=palette.MUTED, no_wrap=True)
        grid.add_column(no_wrap=True)
        grid.add_column()
        grid.add_row("in Paramify", *self._paramify_cells())
        grid.add_row("on your last run", *self._local_cells())
        return grid

    def _paramify_cells(self) -> list:
        p = self.paramify
        if p is None:
            return [_dim("…"), _dim("reading the workspace")]
        state = p.get("state")
        if state == "error":
            return [Text("?", style=palette.WARN), Text(f"Couldn't read it: {p.get('error')}", style=palette.WARN)]
        if state == "no_token":
            return [_dim("—"), _dim("Not read: no Paramify API token.")]
        if state == "no_set":
            return [_dim("—"), _dim(f"{self.ref} isn't in Paramify yet.")]
        entry = (p.get("results") or {}).get(self.v.key)
        if entry is None:
            return [_dim("—"), _dim("No result yet: not paired, or nothing uploaded since.")]
        return [verdict_pill(entry["result"]), Text(f"on the newest upload, {entry['at']}")]

    def _local_cells(self) -> list:
        local = self.local
        if not self.v.regex:
            return [_dim("—"), _dim(f"Nothing to test: a {self.v.type.lower()} validator has no regex.")]
        if local is None:
            return [_dim("…"), _dim("testing")]
        state = local.get("state")
        if state == "no_node":
            return [Text("—", style=palette.WARN), Text(NO_NODE, style=palette.WARN)]
        if state == "no_file":
            return [_dim("—"), Text(f"No evidence from {self.fetcher.name if self.fetcher else 'this fetcher'} "
                                    "yet. Run it on the Run tab (2), then press t.")]
        if state == "error":
            return [Text("?", style=palette.WARN), Text(f"Couldn't test it: {local.get('error')}", style=palette.WARN)]
        path, result = local["shown"]
        where = Text(Path(path).name)
        where.append(f"  ·  {Path(path).parent.name}", style=palette.MUTED)
        if local["files"] > 1:
            where.append(f"\nfails on {local['failing']} of {local['files']} files; this is the worst one"
                         if local["failing"] else f"\npasses on all {local['files']} files", style=palette.MUTED)
        note = self._why(result)
        if note:
            where.append(f"\n{note}", style=palette.WARN)
        return [verdict_pill(result["verdict"]), where]

    @staticmethod
    def _why(result: dict) -> str:
        """The plain reason behind a verdict that needs one."""
        if result["verdict"] == "COMPILE_ERROR":
            return f"The regex doesn't compile: {result.get('compileError')}"
        if result["verdict"] != "PASS" and not result.get("matchCount"):
            return "The regex found nothing in this file."
        if result.get("vacuous"):
            return "It passed without reading anything: a rule compared a missing value."
        return ""

    def _top(self) -> Group:
        v = self.v
        parts = [self._section("claims"), Text(v.statement), self._section("result"), self._results_table()]
        if v.regex:
            parts += [self._section("regex"), Text(v.regex, style=palette.YELLOW)]
            groups = self._groups()
            if groups:
                parts.append(Text("named groups: " + ", ".join(f"{i}={g}" for i, g in enumerate(groups, 1)),
                                  style=palette.MUTED))
            if v.validation_rules:
                tested = (self.local or {}).get("shown")
                parts.append(self._section("passes when" + ("  (on your last run)" if tested else "")))
                parts += self._rule_lines(tested[1] if tested else None)
        else:
            parts += [self._section("regex"), Text(f"none ({v.type.lower()} validator)", style=palette.MUTED)]
        return Group(*parts)

    def _rest(self) -> Group:
        v = self.v
        parts = [self._section(f"evidence sets ({len(v.evidence_sets)})")]
        for ref in v.evidence_sets:
            line = Text(f"  {ref}")
            if ref == self.ref:
                line.append("   ← this fetcher", style=palette.MUTED)
            parts.append(line)
        if v.path and Path(v.path).exists():
            parts.append(self._section(f"file  {self._rel()}"))
            parts.append(Syntax(Path(v.path).read_text(), "yaml", theme="monokai",
                                word_wrap=True, background_color=self.app.current_theme.surface))
        return Group(*parts)

    def _rel(self) -> Path:
        path = Path(self.v.path)
        try:
            return path.relative_to(self.root) if self.root else path
        except ValueError:
            return path

    def _how_to_send(self) -> str:
        """Where a written fix goes from here: the Paramify tab's sync (v)
        previews it as an update and sends it on a yes."""
        if not self.tracked:
            return ("This manifest doesn't track it, so press space to track it. Then press v on the "
                    "Paramify tab (5) to send it.")
        return "To send it, press v on the Paramify tab (5): it shows what changed and updates it on a yes."

    def _failing(self) -> bool:
        local = self.local or {}
        return local.get("state") == "ok" and (local["verdict"] != "PASS" or local["shown"][1].get("vacuous"))

    def _can_ask(self) -> bool:
        return self._failing() and ask_claude.enabled()

    def _can_write(self) -> bool:
        """Only a proposal that passes cleanly on every file: no FAIL, and no
        file where it passed without reading anything."""
        test = (self.proposal or {}).get("test") or {}
        return (test.get("state") == "ok" and test["verdict"] == "PASS" and not test.get("failing")
                and not test["shown"][1].get("vacuous"))

    def _foot(self) -> Text:
        keys = []
        if self.v.regex:
            keys.append(("t", "test again"))
        if self._can_ask() and not self.asking:
            if ask_claude.find_claude() is None:
                # Say so before the key is pressed, not after.
                keys.append(("a", "ask Claude (not installed)"))
            else:
                keys.append(("a", "ask Claude why" if not self.answer else "ask again"))
        if self._failing() and not self.asking:
            # The same report Ask Claude would send, for any AI tool or a colleague. Works without
            # Claude Code and with PARAMIFY_ASK_CLAUDE=0.
            keys.append(("c", "copy report"))
        if self._can_write():
            keys.append(("w", "write the fix"))
        keys += [("space", "untrack" if self.tracked else "track"), ("esc", "stop Claude" if self.asking else "close")]
        foot = Text()
        for i, (key, what) in enumerate(keys):
            foot.append(("    " if i else "") + key, style=f"bold {palette.ACCENT}")
            foot.append(f" {what}", style=palette.MUTED)
        return foot

    def _redraw(self) -> None:
        self.query_one("#vm-top", Static).update(self._top())
        self.query_one("#vm-foot", Label).update(self._foot())

    def show_paramify(self, results: dict) -> None:
        """The page read Paramify's results: show this validator's."""
        self.paramify = results
        self._redraw()

    # -- the local test ---------------------------------------------------- #

    def action_test(self) -> None:
        if not self.v.regex or self.asking:
            return
        self.local = None
        self._redraw()
        self._test_worker()

    @work(thread=True, exclusive=True, group="vm-test")
    def _test_worker(self) -> None:
        try:
            found = api.newest_pipeline_files(self.output_dir or "./evidence", self.fetcher) if self.fetcher else []
            self._files = [p for p, _env in found]
            local = run_local_test(self.v, self._files) if self._files else {"state": "no_file"}
        except Exception as exc:  # noqa: BLE001 — shown where the verdict would be
            local = {"state": "error", "error": str(exc)}
        self.app.call_from_thread(self._tested, local)

    def _tested(self, local: dict) -> None:
        self.local = local
        self._redraw()

    # -- Ask Claude -------------------------------------------------------- #

    def action_copy_report(self) -> None:
        """Copy what Ask Claude would send (the validator, the evidence it read,
        the verdict), for when Claude Code isn't there or isn't allowed."""
        if not self._failing() or self.asking:
            return
        self.app.copy_to_clipboard(self._prompt())
        self.notify("Copied the report: the validator, the evidence it read and the verdict. "
                    "Paste it into any AI tool or send it to someone.")

    def _prompt(self) -> str:
        path, result = self.local["shown"]
        groups = self._groups()
        rules = [describe_rule(r, groups) for r in self.v.validation_rules or []]
        v = self.v
        return ask_claude.build_validator_prompt(
            {"key": v.key, "name": v.name, "statement": v.statement, "regex": v.regex},
            rules, result, Path(path).name, Path(path).read_text())

    def action_ask(self) -> None:
        if not self._can_ask():
            return
        if self.asking:
            self.notify("Claude is already on it. esc stops it.")
            return
        exe = ask_claude.find_claude()
        if exe is None:
            self._show_claude(Text("ask claude", style=f"bold {palette.INFO}"),
                              Text(ask_claude.INSTALL_HINT + " Meanwhile, c copies the same report to "
                                   "paste into any AI tool or send to someone.", style=palette.WARN))
            return
        prompt = self._prompt()
        if getattr(self.app, "ask_claude_confirmed", False):
            self._start_ask(exe, prompt)
            return

        def done(ok: bool | None) -> None:
            if ok:
                self.app.ask_claude_confirmed = True  # once per session
                self._start_ask(exe, prompt)

        self.app.push_screen(ReportModal(
            prompt, "Ask Claude",
            "This is everything that is sent: the validator, how it failed, and your evidence file. "
            "Claude gets no tools and runs in an empty folder without your .env or the manifest's "
            "secrets, so it can't read anything else of yours.",
            CONFIRM_SEND, "Send"), done)

    def _start_ask(self, exe: str, prompt: str) -> None:
        self.asking = True
        self.answer, self.proposal = "", None
        self._cancel = threading.Event()
        self._started = time.monotonic()
        self._step = "starting claude -p"
        self._show_claude(Text("ask claude", style=f"bold {palette.INFO}"), self._status())
        self._ticker = self.set_interval(0.5, self._tick)
        self._ask_worker(exe, prompt)

    @work(thread=True, exclusive=True, group="vm-ask")
    def _ask_worker(self, exe: str, prompt: str) -> None:
        # No tools, an empty folder, and none of the fetchers' secrets: the report is all it gets.
        outcome = ask_claude.ask(
            prompt, exe=exe, cancel=self._cancel,
            model=os.environ.get(ask_claude.ENV_MODEL) or None,
            drop=ask_claude.secret_names(self.root, getattr(self.app, "manifest", None)),
            on_event=lambda ev: self.app.call_from_thread(self._on_event, ev),
        )
        proposal = None
        regex = ask_claude.proposed_regex(outcome.answer) if outcome.ok else None
        if regex:
            # Never shown untested: the fix runs on the same files first.
            self.app.call_from_thread(self._set_step, "testing Claude's regex on your run")
            try:
                proposal = {"regex": regex, "test": run_local_test(self.v, self._files, regex=regex)}
            except Exception as exc:  # noqa: BLE001
                proposal = {"regex": regex, "test": {"state": "error", "error": str(exc)}}
        self.app.call_from_thread(self._on_done, outcome, proposal)

    def _status(self) -> Text:
        secs = int(time.monotonic() - self._started) if self._started else 0
        t = Text()
        t.append("● ", style=palette.WARN)
        t.append(f"{self._step}…  ")
        t.append(f"{secs}s · read-only · esc stops", style=palette.MUTED)
        return t

    def _set_step(self, step: str) -> None:
        self._step = step
        self._tick()

    def _tick(self) -> None:
        if self.asking:
            self._show_claude(Text("ask claude", style=f"bold {palette.INFO}"), self._status(),
                              render_answer(self.answer), scroll=False)

    def _on_event(self, ev) -> None:
        if not self.asking:
            return
        if ev.kind == "turn":
            self.answer, self._step = "", "thinking"
        elif ev.kind == "text":
            self.answer += ev.text
            self._step = "writing"
        elif ev.kind in ("text_full", "final"):
            self.answer = ev.text or self.answer
        elif ev.kind == "tool":
            self._step = ev.text
        self._tick()

    def _on_done(self, outcome, proposal: dict | None) -> None:
        if self._ticker is not None:
            self._ticker.stop()
            self._ticker = None
        if not self.asking:
            return
        self.asking = False
        head = Text("ask claude", style=f"bold {palette.INFO}")
        if outcome.ok:
            self.answer, self.proposal = outcome.answer, proposal
            secs = int(time.monotonic() - self._started)
            status = Text(f"claude -p · read-only · {secs}s", style=palette.MUTED)
            # The proposal shows below with its test, so the answer drops its Regex: line.
            shown = ask_claude.REGEX_LINE.sub("", self.answer).strip() if proposal else self.answer
            self._show_claude(head, status, render_answer(shown), *self._proposal_lines())
        elif outcome.cancelled:
            self._show_claude(head, Text("Stopped.", style=palette.WARN))
        elif outcome.timed_out:
            self._show_claude(head, Text(f"Claude didn't answer in time ({outcome.error}).", style=palette.WARN))
        else:
            self._show_claude(head, Text(f"Claude couldn't answer: {outcome.error}", style=palette.WARN))
        self.query_one("#vm-foot", Label).update(self._foot())

    def _proposal_lines(self) -> list:
        if self.proposal is None:
            return [Text("\nNo regex proposed. If the evidence really shows the control isn't met, "
                         "fix the system, not the validator.", style=palette.MUTED)]
        test = self.proposal["test"]
        head = Text("\nproposed regex  ", style=f"bold {palette.INFO}")
        if test.get("state") != "ok":
            head.append(NO_NODE if test.get("state") == "no_node" else f"Couldn't test it: {test.get('error')}",
                        style=palette.WARN)
            return [head, Text(self.proposal["regex"], style=palette.YELLOW)]
        path, result = test["shown"]
        head.append_text(verdict_pill(result["verdict"]))
        head.append(f"  on {Path(path).name}", style=palette.MUTED)
        lines = [head, Text(self.proposal["regex"], style=palette.YELLOW),
                 *self._rule_lines(result, self.proposal["regex"])]
        why = self._why(result)
        if why:
            lines.append(Text(why, style=palette.WARN))
        if self._can_write():
            tip = Text("\nw", style=f"bold {palette.ACCENT}")
            tip.append(f" writes it to {self._rel()}. {self._how_to_send()}", style=palette.MUTED)
            lines.append(tip)
        else:
            lines.append(Text("\nNot offered: it doesn't pass cleanly on your run. a asks again.",
                              style=palette.MUTED))
        return lines

    def _show_claude(self, head: Text, status: Text, *body, scroll: bool = True) -> None:
        panel = self.query_one("#vm-claude", Static)
        panel.add_class("shown")
        panel.update(Group(head, status, *body))
        self.query_one("#vm-foot", Label).update(self._foot())
        if scroll:
            self.call_after_refresh(self.query_one("#vm-body", VerticalScroll).scroll_to_widget, panel,
                                    animate=False, top=True)

    # -- writing the fix --------------------------------------------------- #

    def action_write(self) -> None:
        if not self._can_write():
            return
        regex = self.proposal["regex"]

        def done(ok: bool | None) -> None:
            if not ok:
                return
            try:
                write_regex(self.v.path, regex)
            except (OSError, ValueError) as exc:
                self.notify(f"Couldn't write the fix: {exc}", severity="error")
                return
            self.v.regex = regex
            self.saved = True
            self.proposal = None
            self.query_one("#vm-claude", Static).remove_class("shown")
            self.query_one("#vm-rest", Static).update(self._rest())
            self.notify(f"Saved {self._rel()}. {self._how_to_send()}", timeout=10)
            self.action_test()

        self.app.push_screen(ConfirmModal(f"Write this regex to {self._rel()}?\n\n{regex}"), done)

    # -- closing ----------------------------------------------------------- #

    def action_close(self) -> None:
        if self.asking:
            self._cancel.set()
            self._set_step("stopping")
            return
        self.dismiss(False)

    def action_toggle(self) -> None:
        if not self.asking:
            self.dismiss(True)


class ValidatorsPage(Vertical):
    HINTS = [("space", "track / untrack"), ("enter", "test & details"), ("a", "back to defaults"),
             ("←→", "fetchers / validators")]

    BINDINGS = [
        Binding("space", "toggle", "Track", show=False),
        Binding("a", "defaults", "Defaults", show=False),
        # Priority: the tables bind left / right to their own cell cursor.
        Binding("right", "to_validators", show=False, priority=True),
        Binding("left", "to_fetchers", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    ValidatorsPage { padding: 1 1 0 1; }
    #vs-head { height: 1; margin-bottom: 1; color: $text-muted; }
    #vs-body { height: 1fr; }
    #vs-left { width: 2fr; max-width: 78; min-width: 36; border: round $panel-lighten-2; border-title-color: $text-muted; }
    #vs-left:focus-within { border: round $primary; }
    #vs-right { width: 3fr; border: round $panel-lighten-2; border-title-color: $text-muted; }
    #vs-right:focus-within { border: round $primary; }
    #vs-fetchers, #vs-validators { height: 1fr; }
    #vs-detail { height: auto; max-height: 12; padding: 1 1 0 1; border-top: solid $panel-lighten-2; }
    """

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self._fetchers: list = []  # [{entry, name, ref, available}]
        self._shown: list = []  # validators in the right table, in order
        self._rows: list = []  # one per table row: a validator, or a section name (str), or None
        # {reference id: api.validator_results(...)}; None while it is read. Cleared
        # each time the tab is shown, so a sync or an upload shows on the way back.
        self._results: dict = {}

    def compose(self) -> ComposeResult:
        yield Static(id="vs-head")
        with Horizontal(id="vs-body"):
            with Vertical(id="vs-left"):
                yield DataTable(id="vs-fetchers", cursor_type="row", zebra_stripes=False)
            with Vertical(id="vs-right"):
                yield DataTable(id="vs-validators", cursor_type="row", zebra_stripes=False)
                yield Static(id="vs-detail")

    def on_mount(self) -> None:
        self.query_one("#vs-left").border_title = "fetchers"
        self.query_one("#vs-validators", DataTable).show_header = False
        self.rebuild()

    def on_resize(self) -> None:
        # Names are cut to the width the panels get, so redraw when it changes.
        if self._fetchers:
            self._draw_fetchers()

    def focus_default(self) -> None:
        self._results = {}
        self.rebuild()
        self.query_one("#vs-fetchers", DataTable).focus()

    # ---- data ------------------------------------------------------------- #

    def rebuild(self) -> None:
        root = self.app.root_path
        manifest = self.app.manifest or {}
        if root is None:
            return
        fetchers = discover_fetchers(root)
        registry = list(discover_validators(root).values())
        self._fetchers = []
        for entry in (manifest.get("run") or {}).get("fetchers") or []:
            name = entry.get("use") if isinstance(entry, dict) else None
            fetcher = fetchers.get(name) if name else None
            if not fetcher or not fetcher.evidence_set or fetcher.is_pipeline:
                continue
            ref = fetcher.evidence_set.reference_id
            avail = sorted(available_for(ref, registry),
                           key=lambda v: (v.source != "paramify", v.role != "completeness", v.key))
            self._fetchers.append({"entry": entry, "name": name, "ref": ref, "available": avail,
                                   "source": fetcher.source, "fetcher": fetcher})
        self._draw_fetchers()

    def _want_results(self, item: dict) -> None:
        """Read the set's latest results in Paramify once, in a worker."""
        if item["ref"] in self._results or not item["available"]:
            return
        self._results[item["ref"]] = None
        self._results_worker(item["ref"], list(item["available"]))

    @work(thread=True, group="vs-results")
    def _results_worker(self, ref: str, available: list) -> None:
        try:
            results = api.validator_results(self.app.root_path, ref, available)
        except Exception as exc:  # noqa: BLE001 — shown in the validator window
            results = {"state": "error", "error": str(exc), "results": {}}
        self.post_message(ResultsReady(ref, results))

    def on_results_ready(self, message: ResultsReady) -> None:
        self._results[message.ref] = message.results
        item = self._current()
        if item is not None and item["ref"] == message.ref:
            vtable = self.query_one("#vs-validators", DataTable)
            row, scroll = vtable.cursor_row, vtable.scroll_y
            self._draw_validators()
            vtable.move_cursor(row=row)
            vtable.scroll_to(y=scroll, animate=False)
        # The window may be under Ask Claude's report or the write confirmation.
        for screen in self.app.screen_stack:
            if isinstance(screen, ValidatorModal) and screen.ref == message.ref:
                screen.show_paramify(message.results)

    def _result(self, item: dict, v) -> dict | None:
        """v's latest result in Paramify, when it has been read and has one."""
        return ((self._results.get(item["ref"]) or {}).get("results") or {}).get(v.key)

    def _tracked(self, item: dict) -> set:
        chosen = item["entry"].get("validators")
        return set(default_keys(item["available"]) if chosen is None else chosen)

    def _current(self) -> dict | None:
        table = self.query_one("#vs-fetchers", DataTable)
        if not self._fetchers:
            return None
        return self._fetchers[min(table.cursor_row, len(self._fetchers) - 1)]

    # ---- drawing ---------------------------------------------------------- #

    def _draw_fetchers(self) -> None:
        table = self.query_one("#vs-fetchers", DataTable)
        keep = table.cursor_row if table.row_count else 0
        # Columns too: a cleared table keeps the widths of its widest rows so far.
        table.clear(columns=True)
        table.add_columns(Text("paramify", style=palette.BLUE), Text("community", style=palette.ORANGE), "fetcher")
        for item in self._fetchers:
            table.add_row(*self._fetcher_cells(item))
        if self._fetchers:
            table.move_cursor(row=min(keep, len(self._fetchers) - 1))
        head = source_pill("paramify")
        head.append(" tracked by default  ·  ", style=palette.MUTED)
        head.append_text(source_pill("community"))
        head.append(" opt in  ·  ", style=palette.MUTED)
        head.append("*", style=palette.INFO)
        head.append(" changed (a resets)  ·  ", style=palette.MUTED)
        head.append_text(verdict_pill("PASS"))
        head.append(" ", style=palette.MUTED)
        head.append_text(verdict_pill("FAIL"))
        head.append(" in Paramify", style=palette.MUTED)
        self.query_one("#vs-head", Static).update(head)
        self._draw_validators()

    def _fetcher_cells(self, item: dict) -> list:
        tracked = self._tracked(item)
        cells = []
        for source in ORDER:
            avail = [v for v in item["available"] if v.source == source]
            if not avail:
                cells.append(Text("  —", style=palette.MUTED))
                continue
            n = sum(1 for v in avail if v.key in tracked)
            cells.append(Text(f"{n:>3}/{len(avail)}", style=SOURCE[source]["fg"] if n else palette.MUTED))
        pinned = item["entry"].get("validators") is not None
        community = item.get("source") == "community"
        # count columns + cell padding + scrollbar (+ the community label)
        room = self.query_one("#vs-left").content_size.width - 25 - (3 if pinned else 0) - (13 if community else 0)
        name = Text(fit(item["name"], room))
        if community:
            name.append("  ")
            name.append_text(palette.community_tag("community"))
        if pinned:
            name.append("  *", style=palette.INFO)
        return [*cells, name]

    def _draw_validators(self) -> None:
        table = self.query_one("#vs-validators", DataTable)
        keep = table.cursor_row if table.row_count else 0
        table.clear(columns=True)
        table.add_columns("", "", "", "")
        item = self._current()
        right = self.query_one("#vs-right")
        if item is None:
            right.border_title = "validators"
            self.query_one("#vs-detail", Static).update("")
            return
        tracked = self._tracked(item)
        self._shown = list(item["available"])
        self._want_results(item)
        right.border_title = f"{item['name']}  ·  {item['ref']}" + (
            f"  ·  [{palette.ORANGE}]community fetcher[/]" if item.get("source") == "community" else "")
        self._rows = []
        for source in ORDER:
            group = [v for v in self._shown if v.source == source]
            if not group:
                continue
            if self._rows:
                self._rows.append(None)
                table.add_row("", "", "", "")
            n = sum(1 for v in group if v.key in tracked)
            head = source_pill(source)
            head.append(f"  {n} of {len(group)} tracked", style=SOURCE[source]["fg"])
            self._rows.append(source)
            table.add_row("", "", head, "")
            for v in group:
                self._rows.append(v)
                table.add_row(*self._validator_cells(v, v.key in tracked, item))
        if self._rows:
            row = min(keep, len(self._rows) - 1)
            if self._rows[row] is None or isinstance(self._rows[row], str):
                row = self._first_validator_row()
            table.move_cursor(row=row)
        self._draw_detail()

    def _first_validator_row(self) -> int:
        return next((i for i, r in enumerate(self._rows) if r is not None and not isinstance(r, str)), 0)

    def _row_validator(self):
        table = self.query_one("#vs-validators", DataTable)
        if not self._rows:
            return None
        r = self._rows[min(table.cursor_row, len(self._rows) - 1)]
        return r

    def _validator_cells(self, v, on: bool, item: dict) -> list:
        hue = SOURCE.get(v.source, {}).get("fg", palette.MUTED)
        edge = Text("▌", style=hue)
        box = Text("[x]" if on else "[ ]", style=hue if on else palette.MUTED)
        changed = item["entry"].get("validators") is not None and on != (v.source == "paramify")
        # edge + box columns + cell padding + scrollbar, the result column's padding
        # (always there), and its pill once results are read
        read = (self._results.get(item["ref"]) or {}).get("results")
        room = self.query_one("#vs-right").content_size.width - 14 - (3 if changed else 0) - (11 if read else 0)
        name = Text(fit(v.name, room), style="bold" if on else palette.MUTED)
        # * = differs from the default (Paramify on, community off), same mark as the fetcher list.
        if changed:
            name.append("  *", style=palette.INFO)
        result = self._result(item, v)
        return [edge, box, name, verdict_pill(result["result"]) if result else Text("")]

    def _draw_detail(self) -> None:
        detail = self.query_one("#vs-detail", Static)
        if not self._shown:
            detail.update(Text("No validators for this evidence set yet.", style=palette.MUTED))
            return
        v = self._row_validator()
        if v is None or isinstance(v, str):
            source = v or "paramify"
            text = source_pill(source)
            text.append("\n" + SOURCE[source]["blurb"], style=palette.MUTED)
            detail.update(text)
            return
        text = source_pill(v.source)
        text.append(f"  {v.name}", style="bold")
        text.append("\n" + v.statement)
        meta = f"\n{v.type.lower()} · {v.role or 'no role'}"
        others = [r for r in v.evidence_sets if r != self._current()["ref"]]
        if others:
            meta += f" · also used by {len(others)} other evidence set{'s' if len(others) != 1 else ''}"
        text.append(meta, style=palette.MUTED)
        result = self._result(self._current(), v)
        if result:
            text.append("\nin Paramify  ", style=palette.MUTED)
            text.append_text(verdict_pill(result["result"]))
            text.append(f"  on the newest upload, {result['at']}", style=palette.MUTED)
        detail.update(text)

    # ---- events / actions ------------------------------------------------- #

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "vs-fetchers":
            self._draw_validators()
        else:
            self._draw_detail()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "vs-fetchers":
            self.action_to_validators()
        else:
            self.action_inspect()

    def action_inspect(self) -> None:
        item = self._current()
        v = self._row_validator()
        if item is None or v is None or isinstance(v, str):
            return

        def done(toggle: bool | None) -> None:
            if modal.saved:
                self.rebuild()  # the registry changed on disk
            if toggle:
                self.action_toggle()

        self._want_results(item)
        modal = ValidatorModal(v, v.key in self._tracked(item), item["ref"], self.app.root_path,
                               fetcher=item["fetcher"], output_dir=output_dir(self.app),
                               paramify=self._results.get(item["ref"]))
        self.app.push_screen(modal, done)

    def action_to_validators(self) -> None:
        if self.query_one("#vs-fetchers", DataTable).has_focus:
            self.query_one("#vs-validators", DataTable).focus()

    def action_to_fetchers(self) -> None:
        self.query_one("#vs-fetchers", DataTable).focus()

    def action_toggle(self) -> None:
        item = self._current()
        vtable = self.query_one("#vs-validators", DataTable)
        if item is None or not self._shown:
            return
        if not vtable.has_focus:
            vtable.focus()
            return
        v = self._row_validator()
        if v is None or isinstance(v, str):
            return
        tracked = self._tracked(item)
        tracked ^= {v.key}
        # Keep registry order so the saved list reads like the tab.
        item["entry"]["validators"] = [x.key for x in item["available"] if x.key in tracked]
        if v.key in tracked:
            self._save(f"Tracking {v.name}.")
        else:
            self._save(f"Stopped tracking {v.name}. Nothing is removed from Paramify.")

    def action_defaults(self) -> None:
        item = self._current()
        if item is None or item["entry"].get("validators") is None:
            return
        item["entry"].pop("validators", None)
        self._save(f"{item['name']} is back to the defaults.")

    def _save(self, what: str) -> None:
        try:
            api.dump_manifest(self.app.manifest, self.app.manifest_path, self.app.root_path)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"Couldn't save the manifest: {exc}", severity="error")
            return
        self.notify(what, timeout=3)
        # The Paramify tab re-reads the workspace the next time it is shown.
        try:
            from framework.tui.screens.paramify import ParamifyPage
            self.screen.query_one(ParamifyPage)._stale = True
        except Exception:  # noqa: BLE001
            pass
        ftable = self.query_one("#vs-fetchers", DataTable)
        row = ftable.cursor_row
        for col, cell in enumerate(self._fetcher_cells(self._fetchers[row])):
            ftable.update_cell_at((row, col), cell, update_width=True)
        vtable = self.query_one("#vs-validators", DataTable)
        vrow, scroll = vtable.cursor_row, vtable.scroll_y
        self._draw_validators()
        vtable.move_cursor(row=vrow)
        vtable.scroll_to(y=scroll, animate=False)
