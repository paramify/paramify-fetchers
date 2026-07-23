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

    def _go_to_tab(self, tab_id: str, focus_default: bool = True) -> None:
        self.set_focus(None)  # Textual reverts an active-change while focus is in the outgoing pane
        self.query_one(TabbedContent).active = tab_id
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

    # -- actions ---------------------------------------------------------- #

    def action_go_tab(self, index: int) -> None:
        if 0 <= index < len(self.TAB_IDS):
            self._go_to_tab(self.TAB_IDS[index])

    def action_unfocus(self) -> None:
        self.set_focus(None)

    def action_refresh(self) -> None:
        self.app.refresh_catalog()
        self.query_one(CatalogPage).rebuild()

    def action_focus_search(self) -> None:
        self._go_to_tab("tab-catalog", focus_default=False)
        self.call_after_refresh(lambda: self.query_one(CatalogPage).focus_search())

    def action_switch_manifest(self) -> None:
        self.app.open_manifest_picker()
