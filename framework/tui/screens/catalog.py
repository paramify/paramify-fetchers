"""Catalog browser — read-only view of every discovered fetcher.

Backed entirely by the App's cached `api.catalog(root)`. Left panel: a kind ->
category -> fetcher Tree with a live search filter. Kind comes first because it,
not the platform, decides where a fetcher's output goes (see tui/kinds.py), and
a platform that ships both kinds would otherwise mix them in one folder. Right
panel: the selected fetcher's contract, or what a kind is when its heading is
highlighted. Panels are titled and their border follows focus (.panel CSS).
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Input, Static, Tree

from framework.tui import kinds, render
from framework.tui.components.keys import FILTER_NAV_BINDINGS, FilterListNav


class CatalogPage(FilterListNav, Horizontal):
    """Two-pane fetcher catalog: tree on the left, contract detail on the right."""

    HINTS = [("↑↓/jk", "navigate"), ("/", "filter"), ("tab", "pane")]

    BINDINGS = [
        Binding("tab", "next_pane", "pane", show=False),
        Binding("j", "tree_down", "down", show=False),
        Binding("k", "tree_up", "up", show=False),
        # up/down are unbound on Input, so they only reach here from the filter;
        # the tree and the detail pane both bind them and keep their own.
        *FILTER_NAV_BINDINGS,
    ]
    FILTER_NAV = ("#catalog-search", "#catalog-tree")

    _filter: str = ""

    def compose(self) -> ComposeResult:
        with Vertical(id="catalog-left", classes="panel"):
            yield Input(placeholder="/ filter fetchers…", id="catalog-search")
            yield Tree("fetchers", id="catalog-tree")
        with VerticalScroll(id="catalog-detail-scroll", classes="panel"):
            yield Static(render.empty_detail(), id="catalog-detail")

    def on_mount(self) -> None:
        self.query_one("#catalog-tree", Tree).show_root = False
        detail = self.query_one("#catalog-detail-scroll", VerticalScroll)
        detail.can_focus = True
        detail.border_title = "contract"
        self.rebuild()

    # -- data ------------------------------------------------------------- #

    def rebuild(self) -> None:
        """Repopulate the tree from the App's cached catalog, applying the filter."""
        data = getattr(self.app, "catalog_data", None)
        tree = self.query_one("#catalog-tree", Tree)
        panel = self.query_one("#catalog-left", Vertical)
        tree.clear()

        if not data:
            panel.border_title = "fetchers (none discovered)"
            return

        flt = self._filter.strip().lower()
        total = 0
        for kind, groups in kinds.sections(data, keep=lambda f: _matches(f, flt)):
            count = sum(len(fetchers) for _, fetchers in groups)
            # The heading's data is the kind itself, so highlighting it can say
            # what the section holds; categories carry none.
            kind_node = tree.root.add(
                f"{kinds.heading(kind)}  ({count})", data=(kind, count), expand=True
            )
            for category, fetchers in groups:
                cat_node = kind_node.add(f"{category}  ({len(fetchers)})", expand=bool(flt))
                for fetcher in fetchers:
                    cat_node.add_leaf(fetcher["name"], data=fetcher)
            total += count

        tree.root.expand()
        panel.border_title = f"fetchers ({total})"

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
        self._nav(down=True)

    def action_tree_up(self) -> None:
        self._nav(down=False)

    def _nav(self, down: bool) -> None:
        # j/k drive whatever pane is focused: scroll the detail when it holds
        # focus, otherwise move the tree cursor (matches the arrow-key routing).
        right = self.query_one("#catalog-detail-scroll", VerticalScroll)
        if right.has_focus:
            right.action_scroll_down() if down else right.action_scroll_up()
        else:
            tree = self.query_one("#catalog-tree", Tree)
            tree.action_cursor_down() if down else tree.action_cursor_up()

    # -- helpers ---------------------------------------------------------- #

    def _show(self, data) -> None:
        detail = self.query_one("#catalog-detail", Static)
        if isinstance(data, dict):
            detail.update(render.fetcher_detail(data))
        elif isinstance(data, tuple):
            detail.update(render.kind_detail(*data))
        else:
            detail.update(render.empty_detail())

    def focus_search(self) -> None:
        self.query_one("#catalog-search", Input).focus()

    def focus_default(self) -> None:
        self.query_one("#catalog-tree").focus()


def _matches(fetcher: dict, flt: str) -> bool:
    if not flt:
        return True
    return flt in fetcher["name"].lower() or flt in (fetcher.get("description") or "").lower()
