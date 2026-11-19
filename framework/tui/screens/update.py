"""UpdateScreen: what `paramify update` would do, and a way to do it or undo it.

It shows the plan the CLI prints (`paramify update --json`) with the CLI's own
wording (framework/update_view.py): where you are and where you'd go, whether
your manifests still pass, which of your fetchers change, what breaks, what is
new. Apply asks once; breaking changes that touch this clone ask a second time,
by count, like `--allow-breaking`. The move itself runs in a subprocess
(api.apply_update), so this process never loads half-updated code, and says so:
restart the TUI afterwards.
"""

from __future__ import annotations

import fnmatch
from typing import List, Optional

from rich.console import Group
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Static

from framework import api
from framework import update_view as view
from framework.tui import palette
from framework.tui.components.keys import BUTTON_ROW_BINDINGS, ButtonRowNav
from framework.tui.components.table import DataTable
from framework.tui.modals import ConfirmModal

_RESTART = "Restart the TUI to load the {what} code."


def _versions(row: dict) -> str:
    if row["change"] == "removed":
        return "removed"
    if row["change"] == "added":
        return f"new {row['to']}" if row["to"] else "new"
    if row["from"] == row["to"]:
        return row["to"] or ""
    return f"{row['from'] or '?'} → {row['to'] or '?'}"


def _lines(rows: List[Text]) -> Text:
    out = Text()
    for i, row in enumerate(rows):
        if i:
            out.append("\n")
        out.append_text(row)
    return out


class UpdateScreen(ButtonRowNav, Screen):
    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("q", "close", "Close", show=False),
        *BUTTON_ROW_BINDINGS,
    ]

    def __init__(self, plan: dict) -> None:
        super().__init__()
        self.plan = plan
        self._busy = False

    # -- what the plan says ------------------------------------------------ #

    @property
    def _errors(self) -> List[str]:
        return [] if self.plan.get("ok", True) else list(self.plan.get("errors") or ["the update could not be planned"])

    @property
    def _actionable(self) -> bool:
        return bool(self.plan.get("ok")) and "target" in self.plan and not self.plan.get("up_to_date")

    @property
    def _touching(self) -> List[dict]:
        return [b for b in self.plan.get("breaking") or [] if b.get("touches")]

    @property
    def _breaks(self) -> List[str]:
        rows = (self.plan.get("check") or {}).get("manifests") or []
        return [m["manifest"] for m in rows if m.get("status") == "breaks"]

    # -- layout ------------------------------------------------------------ #

    def compose(self) -> ComposeResult:
        with Vertical(id="update-root"):
            yield Static(Text("Update", style="bold"), id="update-title")
            with VerticalScroll(id="update-body"):
                yield Static(self._header_text(), id="update-header")
                if self._actionable:
                    yield Static(self._check_text(), id="update-check")
                    yield Static(Text("Your fetchers", style="bold"), id="update-fetchers-title", classes="update-heading")
                    yield DataTable(id="update-fetchers")
                    yield Static(self._breaking_text(), id="update-breaking")
                    yield Static(self._new_text(), id="update-new")
                    yield Static(self._rest_text(), id="update-rest")
            yield Static("", id="update-result")
            with Horizontal(id="update-buttons"):
                if self._actionable:
                    yield Button("Apply", variant="primary", id="update-apply")
                if self.plan.get("can_roll_back"):
                    yield Button("Roll back", id="update-rollback")
                yield Button("Close", id="update-close")

    def on_mount(self) -> None:
        if self._actionable:
            table = self.query_one("#update-fetchers", DataTable)
            table.cursor_type = "row"
            table.add_columns("fetcher", "version", "what changed")
            for row in self._fetcher_rows():
                table.add_row(*row)
            self.query_one("#update-fetchers-title", Static).update(self._fetchers_title())
            if not table.row_count:
                table.display = False
        for button_id in ("#update-apply", "#update-rollback", "#update-close"):
            found = self.query(button_id)
            if found:
                found.first().focus()
                break

    def _header_text(self) -> Text:
        if self._errors:
            out = Text()
            for i, err in enumerate(self._errors):
                if i:
                    out.append("\n")
                out.append("✗ ", style="red")
                out.append(err)
            return out
        if self.plan.get("up_to_date"):
            label = (self.plan.get("current") or {}).get("label") or "this clone"
            return Text(f"✓ Up to date: {label}.", style="green")
        return view.header(self.plan)

    def _check_text(self) -> Text:
        state, summary = view.check_summary(self.plan["check"])
        mark, color = view.MARKS[state]
        out = Text()
        out.append(f"  {mark} ", style=color)
        out.append("check your manifests  ", style="")
        out.append(summary, style=color if state != "ok" else "dim")
        for detail in view.check_details(self.plan["check"]):
            out.append("\n")
            out.append_text(detail)
        return out

    def _fetchers(self) -> dict:
        return self.plan.get("fetchers") or {}

    def _fetchers_title(self) -> Text:
        yours = self._fetchers().get("yours") or []
        title = Text("Your fetchers", style="bold")
        title.append(f"   {len(yours)} changed" if yours else "   none of the fetchers you use changed",
                     style="dim")
        return title

    def _fetcher_rows(self) -> List[tuple]:
        broken = [p for b in self._touching for m in b.get("manifests") or [] for p in m.get("fetchers") or []]
        rows = []
        for row in self._fetchers().get("yours") or []:
            note = Text()
            if any(fnmatch.fnmatchcase(row["name"], p) for p in broken):
                note.append("⚠ breaking  ", style=palette.WARN)
            if row.get("reason"):
                note.append(row["reason"])
                if row.get("more"):
                    note.append(f"  +{row['more']} more", style=palette.MUTED)
            elif row.get("more"):
                note.append(view.plural(row["more"], "commit"), style=palette.MUTED)
            color = palette.FAIL if row["change"] == "removed" else palette.INFO
            rows.append((Text(row["name"], style=color), Text(_versions(row), style=palette.MUTED), note))
        return rows

    def _breaking_text(self) -> Group:
        # A Group, not one Text: the fix lines wrap with a hanging indent here too.
        return Group(*view.breaking(self.plan.get("breaking") or []))

    def _new_text(self) -> Text:
        return _lines(view.whats_new(self.plan.get("highlights") or []))

    def _rest_text(self) -> Text:
        changes = self._fetchers()
        bits = []
        if changes.get("others"):
            bits.append(f"{view.plural(len(changes['others']), 'other fetcher')} changed")
        if changes.get("added"):
            bits.append(f"{len(changes['added'])} added")
        if changes.get("removed"):
            bits.append(f"{len(changes['removed'])} removed")
        other = len(self.plan.get("breaking") or []) - len(self._touching)
        if other:
            bits.append(f"{view.plural(other, 'other breaking change')} that "
                        f"{'does' if other == 1 else 'do'}n't touch you")
        return Text(" · ".join(bits), style="dim")

    # -- actions ----------------------------------------------------------- #

    def action_close(self) -> None:
        if not self._busy:
            self.app.pop_screen()

    @on(Button.Pressed, "#update-close")
    def _close(self) -> None:
        self.action_close()

    def _label(self) -> str:
        return (self.plan.get("target") or {}).get("label") or "the new version"

    @on(Button.Pressed, "#update-apply")
    def _ask_apply(self) -> None:
        if self._busy:
            return
        span = self.plan.get("span") or {}
        commits = f" ({view.plural(span['commits'], 'commit')})" if span.get("commits") else ""
        self.app.push_screen(ConfirmModal(f"Update to {self._label()}{commits}?"), self._first_answer)

    def _first_answer(self, yes: Optional[bool]) -> None:
        if not yes:
            return
        touching, breaks = self._touching, self._breaks
        if not (touching or breaks):
            self._apply(False)
            return
        reasons = []
        if touching:
            reasons.append(f"{view.plural(len(touching), 'breaking change')} "
                           f"{'touches' if len(touching) == 1 else 'touch'} this clone")
        if breaks:
            reasons.append(f"{view.plural(len(breaks), 'manifest')} would break")
        self.app.push_screen(
            ConfirmModal(f"{' and '.join(reasons).capitalize()}. Apply anyway?"), self._second_answer
        )

    def _second_answer(self, yes: Optional[bool]) -> None:
        if yes:
            self._apply(True)

    @on(Button.Pressed, "#update-rollback")
    def _ask_rollback(self) -> None:
        if self._busy:
            return
        self.app.push_screen(
            ConfirmModal("Go back to where this clone was before the last update?"), self._rollback_answer
        )

    def _rollback_answer(self, yes: Optional[bool]) -> None:
        if yes:
            self._rollback()

    def _working(self, text: str) -> None:
        self._busy = True
        for button in self.query(Button):
            button.disabled = True
        self.query_one("#update-result", Static).update(Text(text, style=palette.MUTED))

    @work(thread=True, exclusive=True, group="update-apply")
    def _apply(self, allow_breaking: bool) -> None:
        self.app.call_from_thread(self._working, "Updating…")
        try:
            out = api.apply_update(self.app.root_path, allow_breaking)
        except Exception as exc:
            out = {"ok": False, "errors": [str(exc)]}
        self.app.call_from_thread(self._finished, out, "Updated.", "new")

    @work(thread=True, exclusive=True, group="update-apply")
    def _rollback(self) -> None:
        self.app.call_from_thread(self._working, "Rolling back…")
        try:
            out = api.rollback_update(self.app.root_path)
        except Exception as exc:
            out = {"ok": False, "errors": [str(exc)]}
        self.app.call_from_thread(self._finished, out, "Rolled back.", "old")

    def _finished(self, out: dict, done: str, what: str) -> None:
        self._busy = False
        result = self.query_one("#update-result", Static)
        if out.get("ok"):
            # The buttons stay off: the plan above is out of date now, and the code on disk is not what is running.
            self.query_one("#update-close", Button).disabled = False
            self.query_one("#update-close", Button).focus()
            result.update(Text(f"{done} {_RESTART.format(what=what)}", style=palette.OK))
            return
        for button in self.query(Button):
            button.disabled = False
        errors = out.get("errors") or ["the update failed"]
        text = Text()
        for i, err in enumerate(errors):
            if i:
                text.append("\n")
            text.append("✗ ", style=palette.FAIL)
            text.append(err)
        result.update(text)
