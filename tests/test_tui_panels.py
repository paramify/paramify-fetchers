"""TUI: the catalog and manifest panels, which can share one detail pane.

Each panel posts ShowDetail instead of writing its own detail pane. A panel
made with detail=True keeps its own pane and handles the message itself; with
detail=False it lets the message bubble to the page that hosts it.
"""

from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.console import Console  # noqa: E402
from textual.app import App  # noqa: E402
from textual.widgets import Static, Tree  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.components.detail import ShowDetail  # noqa: E402
from framework.tui.screens.catalog import CatalogPanel  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


class _Host(App):
    """A bare app that hosts one panel and records every ShowDetail reaching it."""

    def __init__(self, panel) -> None:
        super().__init__()
        self.catalog_data = api.catalog(REPO_ROOT)
        self._panel = panel
        self.details: list = []

    def compose(self):
        yield self._panel

    def on_show_detail(self, event: ShowDetail) -> None:
        self.details.append(event)


def _text(renderable) -> str:
    """Plain text of any Rich renderable (a Group does not str() to its text)."""
    console = Console(file=io.StringIO(), width=200, record=True, color_system=None)
    console.print(renderable)
    return console.export_text()


def _leaf(tree: Tree, name: str):
    def walk(node):
        for child in node.children:
            if isinstance(child.data, dict) and child.data.get("name") == name:
                return child
            found = walk(child)
            if found is not None:
                return found
        return None

    return walk(tree.root)


def _host(panel, body):
    async def main():
        app = _Host(panel)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            return await body(app, pilot)

    return asyncio.run(main())


async def _highlight(app, pilot, name: str):
    panel = app.query_one(CatalogPanel)
    panel._filter = name  # the filter expands the matching branches
    panel.rebuild()
    await pilot.pause()
    tree = panel.query_one("#catalog-tree", Tree)
    node = _leaf(tree, name)
    assert node is not None, f"{name} is not in the catalog"
    tree.move_cursor(node)
    await pilot.pause()
    await pilot.pause()


def test_catalog_panel_without_detail_has_no_detail_pane():
    async def body(app, pilot):
        return len(app.query("#catalog-detail-scroll"))

    assert _host(CatalogPanel(detail=False), body) == 0


def test_catalog_panel_posts_show_detail_on_highlight():
    async def body(app, pilot):
        await _highlight(app, pilot, "demo_hello")
        return [_text(e.renderable) for e in app.details]

    texts = _host(CatalogPanel(detail=False), body)
    assert texts and "demo_hello" in texts[-1]


def test_catalog_panel_with_detail_renders_its_own():
    async def body(app, pilot):
        await _highlight(app, pilot, "demo_hello")
        shown = _text(app.query_one("#catalog-detail", Static).content)
        return shown, len(app.details)

    shown, reached_app = _host(CatalogPanel(detail=True), body)
    assert "demo_hello" in shown
    assert reached_app == 0, "a panel with its own detail pane let ShowDetail bubble"


# --------------------------------------------------------------------------- #
# ManifestPanel: needs the real app (it reads app.manifest and app.root_path)
# --------------------------------------------------------------------------- #

def _manifest_with(tmp_path: Path, *names: str) -> Path:
    m = api.init_manifest()
    api.set_output_dir(m, str(tmp_path / "evidence"))
    for name in names:
        api.add_entry(m, name)
    path = tmp_path / "panels.yaml"
    api.dump_manifest(m, path, REPO_ROOT)
    return path


def test_manifest_panel_posts_show_detail(tmp_path, monkeypatch, run_tui):
    from framework.tui.screens.manifest import ManifestPanel
    from framework.tui.screens.workspace import WorkspaceScreen

    seen: list = []
    monkeypatch.setattr(WorkspaceScreen, "on_show_detail", lambda self, e: seen.append(e), raising=False)

    async def body(app, pilot):
        probe = ManifestPanel(detail=False, id="probe")
        await app.screen.mount(probe)
        await pilot.pause()
        probe.rebuild()
        await pilot.pause()
        return len(probe.query("#manifest-detail-scroll")), [_text(e.renderable) for e in seen]

    panes, texts = run_tui(body, _manifest_with(tmp_path, "demo_hello"))
    assert panes == 0
    assert texts and "demo_hello" in texts[-1]


def test_manifest_panel_with_detail_is_unchanged(tmp_path, run_tui):
    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        return _text(app.screen.query_one("#manifest-detail", Static).content)

    assert "demo_hello" in run_tui(body, _manifest_with(tmp_path, "demo_hello"))
