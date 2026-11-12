"""Messages between the Fetchers page and the panels it hosts.

A panel never writes a detail pane it does not own. It posts ShowDetail; a
panel that has its own pane handles the message itself, and one that shares
the page's pane lets it bubble to the page.
"""

from __future__ import annotations

from rich.console import RenderableType
from textual.message import Message


class ShowDetail(Message):
    """What the detail pane should show for the panel's highlighted row."""

    def __init__(self, renderable: RenderableType) -> None:
        self.renderable = renderable
        super().__init__()


class AddRequested(Message):
    """The catalog asks the page to add these fetchers to the manifest."""

    def __init__(self, names: list) -> None:
        self.names = list(names)
        super().__init__()
