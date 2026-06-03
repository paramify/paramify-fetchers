"""FetcherApp — the TUI shell.

Holds the shared state every page reads (repo root, the cached catalog, the
manifest dict + path) and hosts the four top-level tabs: Catalog, Manifest, Run,
and Evidence (see docs/tui_design.md).

Like the other front-ends, this talks only to framework.api.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import TabbedContent, TabPane

from framework import api
from framework.tui.components.chrome import AppHeader, HintFooter
from framework.tui.screens.catalog import CatalogPage
from framework.tui.screens.evidence import EvidencePage
from framework.tui.screens.manifest import ManifestPage
from framework.tui.screens.run import RunPage


class FetcherApp(App):
    """Terminal console for the fetcher framework."""

    CSS_PATH = "styles/index.tcss"
    TITLE = "paramify-fetchers"

    TAB_IDS = ["tab-catalog", "tab-manifest", "tab-run", "tab-evidence"]

    BINDINGS = [
        Binding("1", "go_tab(0)", "Catalog"),
        Binding("2", "go_tab(1)", "Manifest"),
        Binding("3", "go_tab(2)", "Run"),
        Binding("4", "go_tab(3)", "Evidence"),
        Binding("slash", "focus_search", "Search"),
        Binding("escape", "unfocus", "Unfocus", show=False),
        Binding("r", "refresh", "Refresh"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(
        self, manifest_path: str = "manifest.yaml", root_override: Optional[str] = None
    ) -> None:
        super().__init__()
        self.manifest_path = Path(manifest_path)
        self._root_override = Path(root_override) if root_override else None
        # Shared state read by the pages:
        self.root_path: Optional[Path] = None
        self.catalog_data: Optional[dict] = None
        self.manifest: Optional[dict] = None

    def compose(self) -> ComposeResult:
        yield AppHeader()
        with TabbedContent(initial="tab-catalog"):
            with TabPane("Catalog", id="tab-catalog"):
                yield CatalogPage(id="catalog-page")
            with TabPane("Manifest", id="tab-manifest"):
                yield ManifestPage(id="manifest-page")
            with TabPane("Run", id="tab-run"):
                yield RunPage(id="run-page")
            with TabPane("Evidence", id="tab-evidence"):
                yield EvidencePage(id="evidence-page")
        yield HintFooter()

    def on_mount(self) -> None:
        self.theme = "tokyo-night"
        self._load_catalog()
        self._load_manifest()
        self._update_chrome()

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        self._update_chrome()

    def _update_chrome(self) -> None:
        """Sync the header breadcrumb + footer hints to the active tab."""
        tabs = self.query_one(TabbedContent)
        active = tabs.active or ""
        self.query_one(AppHeader).set_crumb(active.removeprefix("tab-"))
        hints = []
        pane = tabs.active_pane
        if pane is not None:
            for child in pane.walk_children():
                if getattr(child, "HINTS", None):
                    hints = child.HINTS
                    break
        self.query_one(HintFooter).set_hints(hints)

    def _load_catalog(self) -> None:
        try:
            self.root_path = api.find_repo_root(self._root_override)
            self.catalog_data = api.catalog(self.root_path)
        except Exception as exc:  # repo-root discovery / fetcher load failures
            self.catalog_data = None
            self.sub_title = "catalog unavailable"
            self.notify(f"Could not load catalog: {exc}", severity="error", timeout=10)
            return

        n = self.catalog_data["fetcher_count"]
        c = len(self.catalog_data["categories"])
        self.sub_title = f"{self.manifest_path}  ·  {n} fetchers / {c} categories"
        self.query_one(CatalogPage).rebuild()

    def _load_manifest(self) -> None:
        try:
            self.manifest = api.read_manifest(self.manifest_path)
        except Exception as exc:  # malformed YAML, etc.
            self.manifest = api.init_manifest()
            self.notify(f"Manifest unreadable ({exc}); starting a fresh one.", severity="warning")
        self.query_one(ManifestPage).rebuild()

    # -- actions ---------------------------------------------------------- #

    def _go_to_tab(self, tab_id: str, focus_default: bool = True) -> None:
        # Blur first: Textual reverts an `active` change made while focus is
        # trapped inside the outgoing tab pane, so drop focus before switching.
        self.set_focus(None)
        self.query_one(TabbedContent).active = tab_id
        # Once the switch settles, focus the new page's primary widget so
        # keyboard navigation works without an extra click.
        if focus_default:
            self.call_after_refresh(self._focus_active_pane)

    def _focus_active_pane(self) -> None:
        pane = self.query_one(TabbedContent).active_pane
        if pane is None:
            return
        for child in pane.walk_children():
            if hasattr(child, "focus_default"):
                child.focus_default()
                return

    def action_go_tab(self, index: int) -> None:
        if 0 <= index < len(self.TAB_IDS):
            self._go_to_tab(self.TAB_IDS[index])

    def action_unfocus(self) -> None:
        self.set_focus(None)

    def action_refresh(self) -> None:
        self._load_catalog()
        if self.catalog_data is not None:
            self.notify("Catalog reloaded.")

    def action_focus_search(self) -> None:
        self._go_to_tab("tab-catalog", focus_default=False)
        self.call_after_refresh(lambda: self.query_one(CatalogPage).focus_search())
