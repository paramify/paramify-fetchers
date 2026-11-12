"""WorkspaceScreen — the four-tab fetcher workspace.

Hosts the shared chrome (AppHeader + HintFooter) and the Fetchers / Run /
Evidence / Paramify tabs. Fetchers holds the catalog and the manifest on one
page. The App pushes this once a manifest is chosen
(from the welcome front door, or directly via --manifest). The active manifest can be
swapped in place with the quick-picker (`m`), which reloads the pages.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import TabbedContent, TabPane

from framework.tui.components.chrome import AppHeader, HintFooter
from framework.tui.screens.catalog import CatalogPanel
from framework.tui.screens.evidence import EvidencePage
from framework.tui.screens.fetchers import FetchersPage
from framework.tui.screens.manifest import ManifestPanel
from framework.tui.screens.run import RunPage
from framework.tui.screens.upload import UploadPage


class WorkspaceScreen(Screen):
    TAB_IDS = ["tab-fetchers", "tab-run", "tab-evidence", "tab-upload"]

    # A one-shot callable that overrides the default focus for the next pane
    # activation (used by the search shortcut to land on the filter box instead
    # of the pane default). Consumed by _focus_active_pane.
    _focus_override = None

    # Screen-level bindings shown on every tab's footer (after the page-specific
    # hints). Keep in sync with BINDINGS below.
    # esc is listed because it is the only way out of a focused text field back
    # to the shortcut keys: an Input consumes every printable key, so while one
    # holds focus none of the hints above it are live.
    WORKSPACE_HINTS = [("1-4", "tabs"), ("m", "manifest"), ("esc", "leave field"), ("q", "quit")]

    BINDINGS = [
        Binding("1", "go_tab(0)", "Fetchers"),
        Binding("2", "go_tab(1)", "Run"),
        Binding("3", "go_tab(2)", "Evidence"),
        Binding("4", "go_tab(3)", "Paramify"),
        Binding("slash", "focus_search", "Search"),
        Binding("escape", "unfocus", "Unfocus", show=False),
        Binding("m", "switch_manifest", "Manifest…"),
        Binding("r", "refresh", "Refresh", show=False),
        Binding("q", "app.quit", "Quit"),  # app.* — a bare "quit" resolves in the screen namespace (no-op)
    ]

    def compose(self) -> ComposeResult:
        yield AppHeader()
        with TabbedContent(initial="tab-fetchers"):
            with TabPane("Fetchers", id="tab-fetchers"):
                yield FetchersPage(id="fetchers-page")
            with TabPane("Run", id="tab-run"):
                yield RunPage(id="run-page")
            with TabPane("Evidence", id="tab-evidence"):
                yield EvidencePage(id="evidence-page")
            with TabPane("Paramify", id="tab-upload"):
                yield UploadPage(id="upload-page")
        yield HintFooter()

    def on_mount(self) -> None:
        self.query_one(CatalogPanel).rebuild()
        self.reload()
        # Land focus inside the opening pane so its key bindings are live from
        # the first keystroke (not only after the user clicks into it).
        self.call_after_refresh(self._focus_active_pane)

    def reload(self) -> None:
        """Refresh the manifest-dependent pages + chrome (after load / switch)."""
        self.query_one(ManifestPanel).rebuild()
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
        self.query_one(HintFooter).set_hints(self._hints(tabs.active_pane) + self.WORKSPACE_HINTS)

    def _hints(self, pane) -> list:
        """The keys that work where focus is: the HINTS of the nearest widget
        around the focused one that has them, then the page's own.

        A page can hold more than one list (the Fetchers page holds the catalog
        and the manifest), so the page's first HINTS would advertise keys that
        do nothing in the other list.
        """
        if pane is None:
            return []
        page = next((c for c in pane.walk_children() if getattr(c, "HINTS", None)), None)
        focused = self.focused
        near = None
        if focused is not None and focused in pane.walk_children():
            near = next((w for w in focused.ancestors_with_self if getattr(w, "HINTS", None)), None)
        hints = list(near.HINTS) if near is not None else []
        if page is not None and page is not near:
            hints += list(page.HINTS)
        return hints

    def on_descendant_focus(self, event) -> None:
        self._update_chrome()

    def _go_to_tab(self, tab_id: str) -> None:
        tabs = self.query_one(TabbedContent)
        if tabs.active == tab_id:
            # Assigning the active tab it already has fires no TabActivated, so
            # nothing would restore focus after set_focus(None) below — pressing
            # the number of the tab you're on would silently kill every page
            # binding. Re-home focus directly instead.
            self.call_after_refresh(self._focus_active_pane)
            return
        self.set_focus(None)  # Textual reverts an active-change while focus is in the outgoing pane
        tabs.active = tab_id
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
        self.query_one(CatalogPanel).rebuild()

    def action_focus_search(self) -> None:
        self._focus_override = lambda: self.query_one(CatalogPanel).focus_search()
        tabs = self.query_one(TabbedContent)
        if tabs.active == "tab-fetchers":
            # No TabActivated fires when already here; run the override directly.
            self.call_after_refresh(self._focus_active_pane)
        else:
            self.set_focus(None)
            tabs.active = "tab-fetchers"  # TabActivated → _focus_active_pane consumes the override

    def action_switch_manifest(self) -> None:
        self.app.open_manifest_picker()
