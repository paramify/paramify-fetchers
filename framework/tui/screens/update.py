"""UpdateScreen: what `paramify update` would do, and a way to do it or undo it.

It shows the plan the CLI prints (framework.update.plan) with the CLI's own
drawing (framework/update_view.py): where you are and where you'd go, whether
your manifests still pass, which of your fetchers change, what breaks, what is
new. Apply asks once; breaking changes that touch this clone ask a second time,
by count, like `--allow-breaking`. The move itself runs in a subprocess
(api.apply_update) pinned to the commit shown here, so this process never loads
half-updated code and never lands commits it didn't show; restart the TUI
afterwards.
"""

from __future__ import annotations

from typing import List, Optional

from rich.console import Group
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Static

from framework import api, update
from framework import update_view as view
from framework.tui import palette
from framework.tui.components.keys import BUTTON_ROW_BINDINGS, ButtonRowNav
from framework.tui.components.table import DataTable
from framework.tui.modals import ConfirmModal

_RESTART = "Restart the TUI to load the {what} code."


def _errors_text(errors: List[str]) -> Group:
    return Group(*(view.fail(e) for e in errors))


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
        return [] if self.plan.get("ok", True) else list(self.plan.get("errors") or ["the update couldn't be planned"])

    @property
    def _ready(self) -> bool:
        """A whole plan to show: assessed, whether or not it can be applied."""
        return bool(self.plan.get("ok")) and self.plan.get("state") in ("ready", "unrunnable")

    @property
    def _actionable(self) -> bool:
        """A plan Apply can carry out (an unrunnable one, a Python too old, is shown, not offered)."""
        return bool(self.plan.get("ok")) and self.plan.get("state") == "ready"

    # -- layout ------------------------------------------------------------ #

    def compose(self) -> ComposeResult:
        with Vertical(id="update-root"):
            yield Static(Text("Update", style="bold"), id="update-title")
            with VerticalScroll(id="update-body"):
                yield Static(self._header_text(), id="update-header")
                if self.plan.get("ok") and self.plan.get("state") == "blocked":
                    yield Static(Group(*view.blocked(self.plan["blocking"])), id="update-blocked")
                if self._ready:
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
        if self._ready:
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

    def _header_text(self):
        if self._errors:
            return _errors_text(self._errors)
        if self.plan.get("up_to_date"):
            label = (self.plan.get("current") or {}).get("label") or "this clone"
            return Group(view.ok(f"Up to date: {label}."), *self._offline())
        return Group(view.header(self.plan), *self._offline())

    def _offline(self) -> List[Text]:
        return [view.offline(update.REMOTE)] if self.plan.get("fetched") is False else []

    def _check_text(self) -> view.Step:
        step = view.Step("check your manifests")
        view.settle_check(step, self.plan["check"])
        return step

    def _fetchers_title(self) -> Text:
        fetchers = self.plan.get("fetchers") or {"yours": []}
        return view.your_fetchers(fetchers, self.plan.get("used") or 0, self.plan.get("breaking") or [])[0]

    def _fetcher_rows(self) -> List[tuple]:
        broken = view.broken_patterns(self.plan.get("breaking") or [])
        rows = []
        for row in (self.plan.get("fetchers") or {}).get("yours") or []:
            color = palette.FAIL if row["change"] == "removed" else palette.INFO
            rows.append((Text(row["name"], style=color), Text(view.versions(row), style=palette.MUTED),
                         view.fetcher_note(row, broken)))
        return rows

    def _breaking_text(self) -> Group:
        # A Group, not one Text: the fix lines wrap with a hanging indent here too.
        return Group(*view.breaking(self.plan.get("breaking") or []))

    def _new_text(self) -> Group:
        return Group(*view.whats_new(self.plan.get("highlights") or [], self.plan.get("releases") or []))

    def _rest_text(self) -> Group:
        return Group(*view.rest(self.plan))

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
        if not self.plan.get("needs_allow_breaking"):
            self._apply(False)
            return
        self.app.push_screen(
            ConfirmModal(f"{view.stop_reasons(self.plan['stops']).capitalize()}. Apply anyway?"), self._second_answer
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
            out = api.apply_update(self.app.root_path, self.plan["target"]["sha"], allow_breaking)
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
        errors = out.get("errors") or ["the update failed"]
        if not (out.get("ok") or out.get("switched")):
            for button in self.query(Button):
                button.disabled = False
            result.update(_errors_text(errors))
            return
        # The code on disk changed, even when what followed failed: the plan above is out of
        # date and isn't what is running, so Apply stays off and the TUI needs a restart.
        restart = _RESTART.format(what=what)
        close = self.query_one("#update-close", Button)
        close.disabled = False
        close.focus()
        if what == "new":
            self.app.show_update_notice(None)  # nothing is waiting any more
        if out.get("ok"):
            result.update(Text(f"{done} {restart}", style=palette.OK))
            return
        result.update(Group(_errors_text(errors), Text(restart, style=palette.MUTED)))
        if what == "new":  # moved, then failed (a manifest, or a reinstall that couldn't be undone): offer the way back
            found = self.query("#update-rollback")
            if found:
                found.first().disabled = False
            else:
                self.query_one("#update-buttons").mount(Button("Roll back", id="update-rollback"), before=close)
