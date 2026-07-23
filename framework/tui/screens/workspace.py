"""WorkspaceScreen — the five-tab fetcher workspace.

Hosts the shared chrome (AppHeader + HintFooter) and the Catalog / Manifest /
Run / Evidence / Paramify tabs. The App pushes this once a manifest is chosen
(from the welcome front door, or directly via --manifest). The active manifest can be
swapped in place with the quick-picker (`m`), which reloads the pages.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import TabbedContent, TabPane

from framework.tui.components.chrome import AppHeader, HintFooter
from framework.tui.screens.catalog import CatalogPage
from framework.tui.screens.evidence import EvidencePage
from framework.tui.screens.manifest import ManifestPage
from framework.tui.screens.run import RunPage
from framework.tui.screens.upload import UploadPage


class WorkspaceScreen(Screen):
    TAB_IDS = ["tab-catalog", "tab-manifest", "tab-run", "tab-evidence", "tab-upload"]

    # A one-shot callable that overrides the default focus for the next pane
    # activation (used by the search shortcut to land on the filter box instead
    # of the pane default). Consumed by _focus_active_pane.
    _focus_override = None

    # Screen-level bindings shown on every tab's footer (after the page-specific
    # hints). Keep in sync with BINDINGS below.
    WORKSPACE_HINTS = [("1-5", "tabs"), ("m", "manifest"), ("q", "quit")]

    BINDINGS = [
        Binding("1", "go_tab(0)", "Catalog"),
        Binding("2", "go_tab(1)", "Manifest"),
        Binding("3", "go_tab(2)", "Run"),
        Binding("4", "go_tab(3)", "Evidence"),
        Binding("5", "go_tab(4)", "Paramify"),
        Binding("slash", "focus_search", "Search"),
        Binding("escape", "unfocus", "Unfocus", show=False),
        Binding("m", "switch_manifest", "Manifest…"),
        Binding("r", "refresh", "Refresh", show=False),
        Binding("q", "app.quit", "Quit"),  # app.* — a bare "quit" resolves in the screen namespace (no-op)
    ]

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
            with TabPane("Paramify", id="tab-upload"):
                yield UploadPage(id="upload-page")
        yield HintFooter()

    def on_mount(self) -> None:
        self.query_one(CatalogPage).rebuild()
        self.reload()
        # Land focus inside the opening pane so its key bindings are live from
        # the first keystroke (not only after the user clicks into it).
        self.call_after_refresh(self._focus_active_pane)

    def reload(self) -> None:
        """Refresh the manifest-dependent pages + chrome (after load / switch)."""
        self.query_one(ManifestPage).rebuild()
        try:
            self.query_one(EvidencePage).rebuild_runs()
        except Exception:
            pass
        try:
            self.query_one(UploadPage).rebuild()
        except Exception:
            pass
        self.query_one(RunPage).reset_state()  # clear stale run state (no-op if running)
        self._update_chrome()

    # -- chrome / tabs ---------------------------------------------------- #

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        self._update_chrome()
        # Focus the pane's default on every activation — keyboard *and* mouse —
        # so page-level bindings (ctrl+r, etc.) fire however the tab was entered.
        self.call_after_refresh(self._focus_active_pane)

    def _update_chrome(self) -> None:
        tabs = self.query_one(TabbedContent)
        tab = (tabs.active or "").removeprefix("tab-")
        name = self.app.manifest_path.name if self.app.manifest_path else "?"
        self.query_one(AppHeader).set_crumb(f"{name}  ›  {tab}")
        page_hints: list = []
        pane = tabs.active_pane
        if pane is not None:
            for child in pane.walk_children():
                if getattr(child, "HINTS", None):
                    page_hints = list(child.HINTS)
                    break
        self.query_one(HintFooter).set_hints(page_hints + self.WORKSPACE_HINTS)

    def _go_to_tab(self, tab_id: str) -> None:
        self.set_focus(None)  # Textual reverts an active-change while focus is in the outgoing pane
        self.query_one(TabbedContent).active = tab_id
        # Focus follows via on_tabbed_content_tab_activated (fires for programmatic
        # changes too), so this is the single place pane focus is decided.

    def _focus_active_pane(self) -> None:
        # A pending one-shot override (e.g. the search box) wins once, then clears.
        override, self._focus_override = self._focus_override, None
        if override is not None:
            override()
            return
        pane = self.query_one(TabbedContent).active_pane
        if pane is None:
            return
        for child in pane.walk_children():
            if hasattr(child, "focus_default"):
                try:
                    child.focus_default()
                except Exception:
                    pass  # a not-yet-ready pane will be refocused on the next activation
                return

    # -- actions ---------------------------------------------------------- #

    def action_go_tab(self, index: int) -> None:
        if 0 <= index < len(self.TAB_IDS):
            self._go_to_tab(self.TAB_IDS[index])

    def action_unfocus(self) -> None:
        # Escape returns to the pane default rather than clearing focus entirely,
        # so global + page bindings both stay live (and a captured Input releases).
        self._focus_active_pane()

    def action_refresh(self) -> None:
        self.app.refresh_catalog()
        self.query_one(CatalogPage).rebuild()

    def action_focus_search(self) -> None:
        self._focus_override = lambda: self.query_one(CatalogPage).focus_search()
        tabs = self.query_one(TabbedContent)
        if tabs.active == "tab-catalog":
            # No TabActivated fires when already here; run the override directly.
            self.call_after_refresh(self._focus_active_pane)
        else:
            self.set_focus(None)
            tabs.active = "tab-catalog"  # TabActivated → _focus_active_pane consumes the override

    def action_switch_manifest(self) -> None:
        self.app.open_manifest_picker()
