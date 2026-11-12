"""Fetchers page — the catalog and the manifest on one screen.

The catalog of every discovered fetcher sits on top; the manifest's settings
and entries sit below it, sized to fit; one detail pane on the right shows the
contract of the highlighted catalog fetcher or the detail of the highlighted
manifest entry, whichever list the user is in. `a` on a catalog fetcher adds it
to the manifest without leaving the catalog.

The two lists are the same CatalogPanel and ManifestPanel widgets that used to
be tabs of their own, hosted with detail=False: they post ShowDetail, and this
page decides which one the pane shows.
"""

from __future__ import annotations

from typing import Optional

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widget import Widget
from textual.widgets import Static

from framework.tui import render
from framework.tui.components.detail import (
    AddRequested,
    FocusCatalog,
    ManifestChanged,
    ShowDetail,
)
from framework.tui.components.table import DataTable
from framework.tui.screens.catalog import CatalogPanel
from framework.tui.screens.manifest import ManifestPanel


class FetchersPage(Horizontal):
    HINTS = [("tab", "area")]

    BINDINGS = [Binding("tab", "next_area", "area", show=False)]

    # The list whose detail the pane shows: the one the user was last in. A
    # class default, because the manifest panel posts its first detail while
    # it mounts, before this page's on_mount runs.
    _active: Optional[Widget] = None

    # The manifest list fits its entries: at least MIN_ROWS table rows, at most
    # MAX_SHARE of the left column. The catalog takes the rest.
    MIN_ROWS = 10
    MAX_SHARE = 0.6

    def compose(self) -> ComposeResult:
        with Vertical(id="fetchers-left"):
            yield CatalogPanel(detail=False, id="catalog-panel")
            yield ManifestPanel(detail=False, id="manifest-panel")
        with VerticalScroll(id="fetchers-detail-scroll", classes="panel"):
            yield Static(render.empty_detail(), id="fetchers-detail")

    def on_mount(self) -> None:
        scroll = self.query_one("#fetchers-detail-scroll", VerticalScroll)
        scroll.can_focus = True
        scroll.border_title = "detail"
        self._active = self.query_one(CatalogPanel)
        self.call_after_refresh(self._fit_manifest)

    # -- the two lists ---------------------------------------------------- #

    @property
    def _catalog(self) -> CatalogPanel:
        return self.query_one(CatalogPanel)

    @property
    def _manifest(self) -> ManifestPanel:
        return self.query_one(ManifestPanel)

    def rebuild(self) -> None:
        """Re-read the manifest; its ManifestChanged refreshes the catalog's marks."""
        self._manifest.rebuild()

    def _panel_of(self, widget: Optional[Widget]) -> Optional[Widget]:
        for node in (widget.ancestors_with_self if widget is not None else []):
            if isinstance(node, (CatalogPanel, ManifestPanel)):
                return node
        return None

    # -- messages from the panels ------------------------------------------ #

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        panel = self._panel_of(self.app.focused)
        if panel is not None and panel is not self._active:
            self._active = panel
            self._show(panel.current_detail())

    def on_show_detail(self, event: ShowDetail) -> None:
        event.stop()
        # A list the user is not in can move its cursor (the manifest does on an
        # add); that must not replace the detail they are reading.
        if event.source is None or event.source is self._active:
            self._show(event.renderable)

    def on_add_requested(self, event: AddRequested) -> None:
        event.stop()
        manifest = self._manifest
        present = manifest.in_manifest()
        new = [name for name in event.names if name not in present]
        if new:
            manifest.add_fetchers(new)
            return
        name = event.names[-1]
        self.notify(f"{name} is already in the manifest.")
        manifest.select(name)

    def on_manifest_changed(self, event: ManifestChanged) -> None:
        event.stop()
        self._catalog.set_marked(event.names)
        self.call_after_refresh(self._fit_manifest)

    def on_resize(self, event: events.Resize) -> None:
        self.call_after_refresh(self._fit_manifest)

    def _fit_manifest(self) -> None:
        """Size the manifest panel to its rows, between MIN_ROWS and half the column.

        Done here, not in CSS: a table sized to its content never scrolls, so a
        CSS max-height would cut rows off instead of letting the table scroll.
        Everything in the panel but the table (or its empty hint) has a fixed
        height, so that overhead is the panel's height less the table slot's.
        """
        panel = self._manifest
        column = self.query_one("#fetchers-left", Vertical)
        table = panel.query_one("#manifest-entries", DataTable)
        slot = table if table.display else panel.query_one("#manifest-empty-hint")
        if not column.size.height or not panel.size.height:
            return
        overhead = panel.outer_size.height - slot.outer_size.height
        rows = max(self.MIN_ROWS, table.row_count) + 1  # + the header row
        height = min(overhead + rows, int(column.size.height * self.MAX_SHARE))
        if panel.styles.height is None or panel.styles.height.cells != height:
            panel.styles.height = height

    def on_focus_catalog(self, event: FocusCatalog) -> None:
        event.stop()
        self.focus_search()

    def _show(self, renderable) -> None:
        self.query_one("#fetchers-detail", Static).update(renderable)

    # -- focus ------------------------------------------------------------- #

    def action_next_area(self) -> None:
        """Tab: catalog tree -> manifest table -> output dir -> stack/owner/Save
        row -> detail pane -> catalog tree. Left/right walk the button row.

        The table comes before the settings above it: entries are edited often
        and the settings are set once, and "tab, then e" must reach an entry.
        """
        table = self.query_one("#manifest-entries", DataTable)
        areas = [
            self.query_one("#catalog-tree"),
            # An empty manifest hides its table; its hint is the stop instead.
            table if table.display else self.query_one("#manifest-empty-hint"),
            self.query_one("#manifest-output-dir"),
            self.query_one("#manifest-stack"),
            self.query_one("#fetchers-detail-scroll", VerticalScroll),
        ]
        focused = self.app.focused
        here = -1  # the catalog filter, and anything unknown, sit before the tree
        if focused is not None:
            chain = list(focused.ancestors_with_self)
            here = next((i for i, area in enumerate(areas) if area in chain), -1)
            if here == -1 and any(w.id == "manifest-settings" for w in chain):
                here = 3  # owner and Save share the stack button's stop
        for step in range(1, len(areas) + 1):
            target = areas[(here + step) % len(areas)]
            if target.display and target.focusable:  # an empty manifest hides its table
                target.focus()
                return

    def focus_default(self) -> None:
        """Escape and tab switches land in the list the user was last in."""
        (self._active if isinstance(self._active, ManifestPanel) else self._catalog).focus_default()

    def focus_search(self) -> None:
        self._catalog.focus_search()
