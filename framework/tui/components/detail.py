"""Messages between the Fetchers page and the panels it hosts.

A panel never writes a detail pane it does not own. It posts ShowDetail; a
panel that has its own pane handles the message itself, and one that shares
the page's pane lets it bubble to the page.
"""

from __future__ import annotations

from typing import Any

from rich.console import RenderableType
from textual.message import Message


class ShowDetail(Message):
    """What the detail pane should show for the panel's highlighted row."""

    def __init__(self, renderable: RenderableType, source: Any = None) -> None:
        self.renderable = renderable
        self.source = source  # the panel that posted it, so a host can tell its lists apart
        super().__init__()


class AddRequested(Message):
    """The catalog asks the page to add these fetchers to the manifest."""

    def __init__(self, names: list) -> None:
        self.names = list(names)
        super().__init__()


class ManifestChanged(Message):
    """The manifest panel rebuilt; names are the fetchers now in the manifest."""

    def __init__(self, names: set) -> None:
        self.names = set(names)
        super().__init__()


class FocusCatalog(Message):
    """`a` on the manifest list: the page should move focus to the catalog filter."""
