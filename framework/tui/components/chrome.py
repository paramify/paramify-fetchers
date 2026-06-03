"""Shared chrome — the Go-TUI design language as reusable widgets.

AppHeader  : persistent top bar — "paramify fetcher" title • breadcrumb • clock.
HintFooter : bottom key/desc hint bar, set per active screen.

Panels (titled boxes whose border follows focus) are pure CSS — see the .panel /
.panel:focus-within rules in styles/index.tcss.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static

from framework.tui import palette


class AppHeader(Horizontal):
    """Title • centered breadcrumb • live clock, with a rule beneath (CSS)."""

    def __init__(self, crumb: str = "") -> None:
        super().__init__(id="app-header")
        self._crumb = crumb

    def compose(self) -> ComposeResult:
        yield Static(
            f"[b]paramify fetcher[/]  [{palette.ORANGE}]•[/]  [{palette.SUBTLE}]evidence tui[/]",
            id="app-header-left",
        )
        yield Static(self._crumb, id="app-header-crumb")
        yield Static("", id="app-header-clock")

    def on_mount(self) -> None:
        self._tick()
        self.set_interval(1.0, self._tick)

    def _tick(self) -> None:
        self.query_one("#app-header-clock", Static).update(datetime.now().strftime("%H:%M:%S"))

    def set_crumb(self, crumb: str) -> None:
        self._crumb = crumb
        self.query_one("#app-header-crumb", Static).update(crumb)


class HintFooter(Static):
    """Key/desc hint bar (rule above via CSS). Call set_hints() per screen."""

    def __init__(self) -> None:
        super().__init__("", id="app-footer")

    def set_hints(self, hints: List[Tuple[str, str]]) -> None:
        text = Text()
        for i, (key, desc) in enumerate(hints):
            if i:
                text.append("    ")
            text.append(key, style=f"{palette.ACCENT} bold")
            text.append(" ")
            text.append(desc, style=palette.MUTED)
        self.update(text)
