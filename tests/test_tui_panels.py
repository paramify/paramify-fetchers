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
from textual.widgets import Input, Static, Tree  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.components.detail import AddRequested, ShowDetail  # noqa: E402
from framework.tui.screens.catalog import CatalogPanel  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


class _Host(App):
    """A bare app that hosts one panel and records every ShowDetail reaching it."""

    def __init__(self, panel) -> None:
        super().__init__()
        self.catalog_data = api.catalog(REPO_ROOT)
        self._panel = panel
        self.details: list = []
        self.adds: list = []

    def compose(self):
        yield self._panel

    def on_show_detail(self, event: ShowDetail) -> None:
        self.details.append(event)

    def on_add_requested(self, event: AddRequested) -> None:
        self.adds.append(event.names)


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
# CatalogPanel: marks and add requests (the Fetchers page)
# --------------------------------------------------------------------------- #

async def _focus_leaf(app, pilot, name: str) -> Tree:
    await _highlight(app, pilot, name)
    tree = app.query_one("#catalog-tree", Tree)
    tree.focus()
    await pilot.pause()
    return tree


def test_a_on_a_leaf_requests_an_add():
    async def body(app, pilot):
        await _focus_leaf(app, pilot, "demo_hello")
        await pilot.press("a")
        await pilot.pause()
        return app.adds

    assert _host(CatalogPanel(detail=False), body) == [["demo_hello"]]


def test_enter_on_a_leaf_requests_an_add_and_on_a_heading_expands():
    async def body(app, pilot):
        tree = await _focus_leaf(app, pilot, "demo_hello")
        await pilot.press("enter")
        await pilot.pause()
        leaf_adds = list(app.adds)
        heading = tree.cursor_node.parent  # the platform node above the leaf
        tree.move_cursor(heading)
        await pilot.pause()
        was_expanded = heading.is_expanded
        await pilot.press("enter")
        await pilot.pause()
        return leaf_adds, app.adds, was_expanded, heading.is_expanded

    leaf_adds, all_adds, before, after = _host(CatalogPanel(detail=False), body)
    assert leaf_adds == [["demo_hello"]]
    assert all_adds == [["demo_hello"]], "enter on a heading asked to add"
    assert before != after, "enter on a heading did not expand or collapse it"


def test_a_click_selects_without_adding():
    async def body(app, pilot):
        tree = await _focus_leaf(app, pilot, "demo_hello")
        await tree.run_action("select_cursor")  # the action a mouse click runs
        await pilot.pause()
        return app.adds

    assert _host(CatalogPanel(detail=False), body) == []


def test_a_on_a_heading_requests_nothing():
    async def body(app, pilot):
        tree = await _focus_leaf(app, pilot, "demo_hello")
        tree.move_cursor(tree.cursor_node.parent)
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        return app.adds

    assert _host(CatalogPanel(detail=False), body) == []


def test_set_marked_adds_a_check_and_keeps_filter_and_cursor():
    async def body(app, pilot):
        panel = app.query_one(CatalogPanel)
        search = panel.query_one("#catalog-search", Input)
        search.value = "hello"
        await pilot.pause()
        tree = panel.query_one("#catalog-tree", Tree)
        tree.move_cursor(_leaf(tree, "demo_hello"))
        await pilot.pause()
        panel.set_marked({"demo_hello"})
        await pilot.pause()
        node = tree.cursor_node
        return search.value, node.data["name"], str(node.label)

    value, name, label = _host(CatalogPanel(detail=False), body)
    assert value == "hello"
    assert name == "demo_hello"
    assert label.rstrip().endswith("✓")


def test_detail_says_add_or_in_manifest():
    async def body(app, pilot):
        await _highlight(app, pilot, "demo_hello")
        panel = app.query_one(CatalogPanel)
        before = _text(panel.current_detail())
        panel.set_marked({"demo_hello"})
        await pilot.pause()
        return before, _text(panel.current_detail()), _text(app.details[-1].renderable)

    before, after, last_posted = _host(CatalogPanel(detail=False), body)
    assert "a add" in before
    assert "✓ in manifest" in after
    assert "✓ in manifest" in last_posted, "set_marked did not refresh the shown detail"


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


# --------------------------------------------------------------------------- #
# ManifestPanel: the add API the Fetchers page calls
# --------------------------------------------------------------------------- #

def _cursor_key(app) -> str:
    from framework.tui.components.table import DataTable

    dt = app.screen.query_one("#manifest-entries", DataTable)
    return dt.coordinate_to_cell_key(dt.cursor_coordinate).row_key.value


def _uses(path: Path) -> set:
    import yaml

    return {e["use"] for e in yaml.safe_load(path.read_text())["run"]["fetchers"]}


def _panel(app):
    from framework.tui.screens.manifest import ManifestPanel

    return app.screen.query_one(ManifestPanel)


def _record_notices(app) -> list:
    notices: list = []
    real = app.notify

    def notify(message, *a, **kw):
        notices.append((str(message), kw.get("severity", "information")))
        return real(message, *a, **kw)

    app.notify = notify
    return notices


def test_add_fetchers_writes_and_selects_the_new_row(tmp_path, run_tui):
    path = _manifest_with(tmp_path, "demo_hello")

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        assert _cursor_key(app) == "demo_hello"
        added = _panel(app).add_fetchers(["demo_policy_check"])
        await pilot.pause()
        # The new row, not the row that was selected before the add.
        return added, _cursor_key(app)

    added, cursor = run_tui(body, path)
    assert added == ["demo_policy_check"]
    assert cursor == "demo_policy_check"
    assert _uses(path) == {"demo_hello", "demo_policy_check"}


def test_add_fetchers_brings_comparator_inputs(tmp_path, run_tui):
    path = _manifest_with(tmp_path)

    async def body(app, pilot):
        notices = _record_notices(app)
        added = _panel(app).add_fetchers(["demo_policy_check"])
        await pilot.pause()
        return added, notices

    added, notices = run_tui(body, path)
    assert set(added) == {"demo_policy_check", "demo_hello"}
    assert _uses(path) == {"demo_policy_check", "demo_hello"}
    assert any("Added demo_policy_check + 1 input" in text for text, _ in notices), notices


def test_add_fetchers_keeps_the_entry_when_autosave_fails(tmp_path, monkeypatch, run_tui):
    path = _manifest_with(tmp_path)

    def refuse(*_a, **_k):
        raise OSError("read-only file system")

    async def body(app, pilot):
        notices = _record_notices(app)
        monkeypatch.setattr(api, "dump_manifest", refuse)
        _panel(app).add_fetchers(["demo_hello"])
        await pilot.pause()
        uses = {e["use"] for e in app.manifest["run"]["fetchers"]}
        return uses, _panel(app).in_manifest(), notices

    uses, marked, notices = run_tui(body, path)
    assert uses == {"demo_hello"} and marked == {"demo_hello"}
    assert any(sev == "error" and "not saved" in text for text, sev in notices), notices
    assert _uses(path) == set(), "the file changed although the save failed"


def test_rebuild_posts_manifest_changed(tmp_path, monkeypatch, run_tui):
    from framework.tui.screens.workspace import WorkspaceScreen

    seen: list = []
    monkeypatch.setattr(WorkspaceScreen, "on_manifest_changed", lambda self, e: seen.append(e.names), raising=False)

    async def body(app, pilot):
        _panel(app).rebuild()
        await pilot.pause()
        return seen

    assert run_tui(body, _manifest_with(tmp_path, "demo_hello"))[-1] == {"demo_hello"}


def test_select_moves_the_cursor_to_an_entry(tmp_path, run_tui):
    async def body(app, pilot):
        _panel(app).select("demo_hello")
        await pilot.pause()
        return _cursor_key(app)

    assert run_tui(body, _manifest_with(tmp_path, "demo_policy_check", "demo_hello")) == "demo_hello"


def test_a_on_a_shared_manifest_panel_asks_for_the_catalog(tmp_path, monkeypatch, run_tui):
    from framework.tui.screens.manifest import ManifestPanel
    from framework.tui.screens.workspace import WorkspaceScreen

    asked: list = []
    monkeypatch.setattr(WorkspaceScreen, "on_focus_catalog", lambda self, e: asked.append(e), raising=False)

    async def body(app, pilot):
        probe = ManifestPanel(detail=False, id="probe")
        await app.screen.mount(probe)
        await pilot.pause()
        hint = _text(probe.query_one("#manifest-empty-hint", Static).content)
        probe.query_one("#manifest-entries").focus()
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        return hint, len(asked), type(app.screen).__name__

    hint, n, screen = run_tui(body, _manifest_with(tmp_path))
    assert "press a on a fetcher to add it" in hint
    assert n == 1 and screen == "WorkspaceScreen", "a opened the picker instead of asking for the catalog"
