"""Catalog browser — read-only view of every discovered fetcher.

Backed entirely by the App's cached `api.catalog(root)`. Left panel: a category
-> fetcher Tree with a live search filter. Right panel: the selected fetcher's
contract. Panels are titled and their border follows focus (.panel CSS).
"""

from __future__ import annotations

from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Input, Static, Tree

from framework.tui import render


class CatalogPage(Horizontal):
    """Two-pane fetcher catalog: tree on the left, contract detail on the right."""

    HINTS = [("↑↓/jk", "navigate"), ("/", "filter"), ("tab", "pane"), ("1-4", "tabs"), ("q", "quit")]

    BINDINGS = [
        Binding("tab", "next_pane", "pane", show=False),
        Binding("j", "tree_down", "down", show=False),
        Binding("k", "tree_up", "up", show=False),
    ]

    _filter: str = ""

    def compose(self) -> ComposeResult:
        with Vertical(id="catalog-left", classes="panel"):
            yield Static("fetchers", id="catalog-left-title", classes="panel-title")
            yield Input(placeholder="/ filter fetchers…", id="catalog-search")
            yield Tree("fetchers", id="catalog-tree")
        with VerticalScroll(id="catalog-detail-scroll", classes="panel"):
            yield Static("contract", id="catalog-detail-title", classes="panel-title")
            yield Static(render.empty_detail(), id="catalog-detail")

    def on_mount(self) -> None:
        self.query_one("#catalog-tree", Tree).show_root = False
        self.query_one("#catalog-detail-scroll", VerticalScroll).can_focus = True
        self.rebuild()

    # -- data ------------------------------------------------------------- #

    def rebuild(self) -> None:
        """Repopulate the tree from the App's cached catalog, applying the filter."""
        data = getattr(self.app, "catalog_data", None)
        tree = self.query_one("#catalog-tree", Tree)
        title = self.query_one("#catalog-left-title", Static)
        tree.clear()

        if not data:
            title.update("fetchers (none discovered)")
            return

        flt = self._filter.strip().lower()
        total = 0
        for cat in data["categories"]:
            matches = [f for f in cat["fetchers"] if _matches(f, flt)]
            if not matches:
                continue
            cat_node = tree.root.add(f"{cat['name']}  ({len(matches)})", expand=bool(flt))
            for fetcher in matches:
                cat_node.add_leaf(fetcher["name"], data=fetcher)
                total += 1

        tree.root.expand()
        title.update(f"fetchers ({total})")

    # -- events ----------------------------------------------------------- #

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "catalog-search":
            self._filter = event.value
            self.rebuild()

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        self._show(event.node.data)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        self._show(event.node.data)

    # -- actions ---------------------------------------------------------- #

    def action_next_pane(self) -> None:
        tree = self.query_one("#catalog-tree", Tree)
        right = self.query_one("#catalog-detail-scroll", VerticalScroll)
        on_left = tree.has_focus or self.query_one("#catalog-search", Input).has_focus
        (right if on_left else tree).focus()

    def action_tree_down(self) -> None:
        self.query_one("#catalog-tree", Tree).action_cursor_down()

    def action_tree_up(self) -> None:
        self.query_one("#catalog-tree", Tree).action_cursor_up()

    # -- helpers ---------------------------------------------------------- #

    def _show(self, fetcher: Optional[dict]) -> None:
        detail = self.query_one("#catalog-detail", Static)
        detail.update(render.fetcher_detail(fetcher) if fetcher else render.empty_detail())

    def focus_search(self) -> None:
        self.query_one("#catalog-search", Input).focus()

    def focus_default(self) -> None:
        self.query_one("#catalog-tree").focus()


def _matches(fetcher: dict, flt: str) -> bool:
    if not flt:
        return True
    return flt in fetcher["name"].lower() or flt in (fetcher.get("description") or "").lower()
