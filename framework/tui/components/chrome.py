"""Shared chrome — the Go-TUI design language as reusable widgets.

AppHeader  : persistent top bar — "paramify fetcher" title • breadcrumb • clock.
HintFooter : bottom key/desc hint bar, set per active screen.

Panels (titled boxes whose border follows focus) are pure CSS — see the .panel /
.panel:focus-within rules in styles/index.tcss.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static

from framework.tui import palette

UPDATE_KEY = "U"


class UpdateNotice(Static):
    """One quiet line when an update is waiting; takes no room until there is one.

    The app fills every notice on the screen stack when its background check
    comes back, and a notice mounted later reads what the app already knows.
    Alone (the welcome screen) it says it in full; in the header, the header
    picks the wording that fits, or hides it.
    """

    def __init__(self, **kw) -> None:
        super().__init__("", **kw)
        self.display = False
        self._waiting: Optional[str] = None
        self.wording: Optional[str] = "long"  # "long", "short" or None (no room); the header sets it

    def on_mount(self) -> None:
        self.set_waiting(getattr(self.app, "update_waiting", None))

    def set_waiting(self, waiting: Optional[str]) -> None:
        self._waiting = waiting
        if isinstance(self.parent, AppHeader):
            self.parent.refit()
        else:
            self.redraw()

    def text(self, wording: str) -> Optional[Text]:
        if not self._waiting:
            return None
        short = wording == "short"
        out = Text(no_wrap=True, overflow="ellipsis")
        out.append("↑ ", style=f"{palette.ACCENT} bold")
        out.append("update" if short else self._waiting, style=palette.MUTED)
        out.append(f" · {UPDATE_KEY}" if short else f" · press {UPDATE_KEY}", style=palette.MUTED)
        return out

    def width(self, wording: str) -> int:
        text = self.text(wording)
        return text.cell_len + 2 if text else 0  # and its padding

    def redraw(self) -> None:
        text = self.text(self.wording) if self.wording else None
        if text is None:
            self.display = False
            return
        self.update(text)
        self.display = True


class AppHeader(Horizontal):
    """Title • centered breadcrumb • live clock, with a rule beneath (CSS)."""

    def __init__(self, crumb: str = "") -> None:
        super().__init__(id="app-header")
        self._crumb = crumb

    def compose(self) -> ComposeResult:
        yield Static(
            "[b]paramify fetchers[/]",
            id="app-header-left",
        )
        yield UpdateNotice(id="app-header-update")
        yield Static(self._crumb, id="app-header-crumb")
        yield Static("", id="app-header-clock")

    def on_mount(self) -> None:
        self._tick()
        self.set_interval(1.0, self._tick)
        self.refit()

    def on_resize(self, event) -> None:
        self.refit()

    # When the row is short of room the update notice shortens, then gives way, then the
    # crumb shrinks (down to CRUMB_MIN columns). Title and clock stay.
    CRUMB_MIN = 6
    CRUMB_ROOM = 20  # the long notice only when the crumb keeps this much more besides
    _fit_pending = False

    def refit(self) -> None:
        """Re-decide what the row shows, once laid out. Every change goes through here: mount,
        resize, and the update notice's text arriving or going after mount."""
        if not self._fit_pending:
            self._fit_pending = True
            self.call_after_refresh(self._fit)

    def _fit(self) -> None:
        self._fit_pending = False
        if not self.is_attached:
            return
        notice = self.query_one(UpdateNotice)
        used = self.query_one("#app-header-left").outer_size.width + self.query_one("#app-header-clock").outer_size.width
        room = self.size.width - 2 - used - self.CRUMB_MIN  # 2: the header's own padding
        notice.wording = ("long" if notice.width("long") <= room - self.CRUMB_ROOM
                          else "short" if notice.width("short") <= room else None)
        notice.redraw()

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
