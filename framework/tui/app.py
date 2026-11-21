"""FetcherApp — the TUI application shell / router.

Owns the shared state every screen reads (repo root, cached catalog, the active
manifest dict + path) and routes between two screens: a WelcomeScreen front door
(pick a manifest) and the WorkspaceScreen (the five tabs). `--manifest PATH`
skips the front door and enters the workspace directly.

Like the other front-ends, this talks only to framework.api.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from textual import on, work
from textual.app import App
from textual.binding import Binding
from textual.screen import ModalScreen

from framework import api
from framework.tui.components.chrome import UPDATE_KEY, UpdateNotice
from framework.tui.modals import EnvironmentModal, PickerModal
from framework.tui.screens.update import UpdateScreen
from framework.tui.screens.welcome import ManifestSelected, WelcomeScreen
from framework.tui.screens.workspace import WorkspaceScreen
from framework.tui.words import plural


class FetcherApp(App):
    """Terminal console for the fetcher framework."""

    CSS_PATH = "styles/index.tcss"
    TITLE = "paramify-fetchers"
    # Textual binds ctrl+p to its command palette as a *priority* binding, which
    # is checked before the focused widget, so it swallowed the pages' own ctrl+p.
    # We register no command providers, so the palette only offers Textual's own
    # built-ins; turn it off and keep the key free.
    ENABLE_COMMAND_PALETTE = False

    # U opens the update screen everywhere; so does u, except on the Paramify tab, where u is the
    # page's "upload run" (even while upload is switched off). The notice says U, the key that
    # works on every screen.
    BINDINGS = [
        Binding(UPDATE_KEY, "open_update", "Update", show=False),
        Binding(UPDATE_KEY.lower(), "open_update_lowercase", "Update", show=False),
    ]

    def __init__(
        self, manifest_path: Optional[str] = None, root_override: Optional[str] = None
    ) -> None:
        super().__init__()
        self._initial_manifest = manifest_path  # None -> show the welcome front door
        self._root_override = Path(root_override) if root_override else None
        # Shared state read by the screens/pages:
        self.root_path: Optional[Path] = None
        self.catalog_data: Optional[dict] = None
        self.manifest: Optional[dict] = None
        self.manifest_path: Optional[Path] = None
        self.update_waiting: Optional[str] = None  # "12 new commits on main", once the check is back
        self._opening_update = False

    def on_mount(self) -> None:
        self.theme = "tokyo-night"
        self._discover()
        if self._initial_manifest:
            self.enter_workspace(self._initial_manifest)
        else:
            self.push_screen(WelcomeScreen())
        self._load_update_notice()

    # -- update ------------------------------------------------------------ #

    @work(thread=True, exclusive=True, group="update-notice")
    def _load_update_notice(self) -> None:
        """Ask in the background, so the first screen never waits on git. Silent on None or any failure."""
        if self.root_path is None:
            return
        try:
            waiting = api.update_notice(self.root_path)
            if waiting:
                self.call_from_thread(self.show_update_notice, waiting)
        except Exception:
            return  # no notice, or the app is shutting down under us

    def show_update_notice(self, waiting: Optional[str]) -> None:
        self.update_waiting = waiting
        for screen in self.screen_stack:
            for notice in screen.query(UpdateNotice):
                notice.set_waiting(waiting)

    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        if action == "open_update_lowercase":
            from textual.widgets import TabbedContent

            for tabs in self.screen.query(TabbedContent):
                if tabs.active == "tab-paramify":
                    return False
        return True

    def action_open_update_lowercase(self) -> None:
        self.action_open_update()

    def action_open_update(self) -> None:
        if self.root_path is None or self._opening_update:
            return
        if isinstance(self.screen, (ModalScreen, UpdateScreen)):
            return
        self._opening_update = True
        self.notify("Reading what the update changes…", timeout=3)
        self._read_update_plan()

    @work(thread=True, exclusive=True, group="update-plan")
    def _read_update_plan(self) -> None:
        try:
            try:
                plan = api.update_plan(self.root_path)
            except Exception as exc:
                plan = {"ok": False, "errors": [str(exc)]}
            self.call_from_thread(self._show_update_screen, plan)
        except Exception as exc:  # the app is shutting down under us, or the screen would not open
            try:
                self.call_from_thread(self._update_failed, str(exc))
            except Exception:
                pass

    def _update_failed(self, why: str) -> None:
        self._opening_update = False
        self.notify(f"Couldn't open the update screen: {why}", severity="error")

    def _show_update_screen(self, plan: dict) -> None:
        self._opening_update = False
        self.push_screen(UpdateScreen(plan))

    # -- shared loads ----------------------------------------------------- #

    def _discover(self) -> None:
        try:
            self.root_path = api.find_repo_root(self._root_override)
            self.catalog_data = api.catalog(self.root_path)
        except Exception as exc:  # repo-root discovery / fetcher load failures
            self.catalog_data = None
            self.notify(f"Couldn't load the catalog: {exc}", severity="error", timeout=10)

    def refresh_catalog(self) -> None:
        try:
            self.catalog_data = api.catalog(self.root_path)
            self.notify("Catalog reloaded.")
        except Exception as exc:
            self.notify(f"Couldn't reload the catalog: {exc}", severity="error")

    def load_manifest(self, path) -> None:
        self.manifest_path = Path(path)
        try:
            self.manifest = api.read_manifest(self.manifest_path)
        except Exception as exc:  # malformed YAML, etc.
            self.manifest = api.init_manifest()
            self.notify(f"Couldn't read the manifest ({exc}), so this is a fresh one.", severity="warning")

    # -- screen routing --------------------------------------------------- #

    def enter_workspace(self, path) -> None:
        """Load `path` and show the workspace (used on startup / --manifest)."""
        self.load_manifest(path)
        self.push_screen(WorkspaceScreen())

    @on(ManifestSelected)
    def _on_manifest_selected(self, event: ManifestSelected) -> None:
        """A manifest was chosen on the welcome front door -> enter the workspace."""
        self.load_manifest(event.path)
        self.switch_screen(WorkspaceScreen())

    def open_manifest_picker(self) -> None:
        """Quick-picker overlay to swap the active manifest without leaving the workspace."""
        if self.root_path is None:
            return
        options = []
        for m in api.list_manifests(self.root_path):
            flag = f"  ⚠ {m['issues']}" if m["issues"] else ""
            options.append((m["path"], f"{m['name']}   {plural(m['fetcher_count'], 'fetcher')}{flag}"))
        if not options:
            self.notify("No manifests found under manifests/.")
            return

        def done(path: Optional[str]) -> None:
            if path and path != str(self.manifest_path):
                self.load_manifest(path)
                screen = self.screen
                if hasattr(screen, "reload"):
                    screen.reload()
                self.notify(f"Switched to {Path(path).name}.")

        self.push_screen(
            PickerModal("Switch manifest", options), done
        )

    def open_environment(self, notice: str = "") -> None:
        """The environment view for the open manifest: which variables a run
        reads have a value (never the values). Opened from the manifest's env
        button and by a run that stopped on a missing one (`notice` says so)."""
        if self.root_path is None or self.manifest is None:
            return
        root = self.root_path

        def done(_: None) -> None:
            # .env may have changed under the view: the manifest's env button and rows follow it.
            for panel in self.screen.query("ManifestPanel"):
                panel.rebuild()

        name = self.manifest_path.name if self.manifest_path else "manifest"
        self.push_screen(
            EnvironmentModal(
                name,  # the manifest file name: "Everything <name> reads"
                read=lambda: api.generate_env(root, self.manifest),
                write=lambda: api.generate_env(root, self.manifest, write=True),
                notice=notice,
            ),
            done,
        )
