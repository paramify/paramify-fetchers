"""FetcherApp — the TUI application shell / router.

Owns the shared state every screen reads (repo root, cached catalog, the active
manifest dict + path) and routes between two screens: a WelcomeScreen front door
(pick a manifest) and the WorkspaceScreen (the four tabs). `--manifest PATH`
skips the front door and enters the workspace directly.

Like the other front-ends, this talks only to framework.api.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from textual import on
from textual.app import App

from framework import api
from framework.tui.modals import PickerModal
from framework.tui.screens.welcome import ManifestSelected, WelcomeScreen
from framework.tui.screens.workspace import WorkspaceScreen


class FetcherApp(App):
    """Terminal console for the fetcher framework."""

    CSS_PATH = "styles/index.tcss"
    TITLE = "paramify-fetchers"

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

    def on_mount(self) -> None:
        self.theme = "tokyo-night"
        self._discover()
        if self._initial_manifest:
            self.enter_workspace(self._initial_manifest)
        else:
            self.push_screen(WelcomeScreen())

    # -- shared loads ----------------------------------------------------- #

    def _discover(self) -> None:
        try:
            self.root_path = api.locate_root(self._root_override)
            self.catalog_data = api.catalog(self.root_path)
        except Exception as exc:  # repo-root discovery / fetcher load failures
            self.catalog_data = None
            self.notify(f"Could not load catalog: {exc}", severity="error", timeout=10)

    def refresh_catalog(self) -> None:
        try:
            self.catalog_data = api.catalog(self.root_path)
            self.notify("Catalog reloaded.")
        except Exception as exc:
            self.notify(f"Catalog reload failed: {exc}", severity="error")

    def load_manifest(self, path) -> None:
        self.manifest_path = Path(path)
        try:
            self.manifest = api.read_manifest(self.manifest_path)
        except Exception as exc:  # malformed YAML, etc.
            self.manifest = api.init_manifest()
            self.notify(f"Manifest unreadable ({exc}); starting a fresh one.", severity="warning")

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
        options = []
        for m in api.list_manifests(self.root_path):
            flag = f"  ⚠ {m['issues']}" if m["issues"] else ""
            options.append((m["path"], f"{m['name']}   {m['fetcher_count']} fetchers{flag}"))
        if not options:
            self.notify("No manifests found under manifests/.")
            return

        def done(path: Optional[str]) -> None:
            if path and path != str(self.manifest_path):
                self.load_manifest(path)
                screen = self.screen
                if hasattr(screen, "reload"):
                    screen.reload()
                self.notify(f"Switched to {Path(path).name}")

        self.push_screen(
            PickerModal("Switch manifest", options, subtitle="Pick a manifest to work on"), done
        )
