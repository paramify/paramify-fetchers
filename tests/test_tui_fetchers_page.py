"""TUI: the Fetchers page, where the catalog and the manifest share one screen.

The catalog sits on top and the manifest below it; one detail pane on the right
follows the list that has focus. `a` on a catalog fetcher adds it in place.
"""

from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest
import yaml

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.console import Console  # noqa: E402
from textual.widgets import Input, Static, TabbedContent, Tree  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.components.table import DataTable  # noqa: E402
from framework.tui.screens.catalog import CatalogPanel  # noqa: E402
from framework.tui.screens.manifest import ManifestPanel  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


def _manifest_with(tmp_path: Path, *names: str, file: str = "page.yaml") -> Path:
    m = api.init_manifest()
    api.set_output_dir(m, str(tmp_path / "evidence"))
    for name in names:
        api.add_entry(m, name)
    path = tmp_path / file
    api.dump_manifest(m, path, REPO_ROOT)
    return path


def _uses(path: Path) -> set:
    return {e["use"] for e in yaml.safe_load(path.read_text())["run"]["fetchers"]}


def _text(renderable) -> str:
    console = Console(file=io.StringIO(), width=200, record=True, color_system=None)
    console.print(renderable)
    return console.export_text()


def _detail(app) -> str:
    return _text(app.screen.query_one("#fetchers-detail", Static).content)


def _focus_id(app) -> str:
    return app.focused.id if app.focused is not None else ""


def _leaf_label(app, name: str) -> str:
    tree = app.screen.query_one("#catalog-tree", Tree)

    def walk(node):
        for child in node.children:
            if isinstance(child.data, dict) and child.data["name"] == name:
                return str(child.label)
            found = walk(child)
            if found is not None:
                return found
        return None

    return walk(tree.root) or ""


def _cursor_key(app) -> str:
    dt = app.screen.query_one("#manifest-entries", DataTable)
    return dt.coordinate_to_cell_key(dt.cursor_coordinate).row_key.value


async def _settle(app, pilot):
    await app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


async def _find(app, pilot, name: str):
    """Filter the catalog to one fetcher and put the tree cursor on it."""
    await pilot.press("1")
    await pilot.pause()
    search = app.screen.query_one("#catalog-search", Input)
    search.value = name
    await pilot.pause()
    tree = app.screen.query_one("#catalog-tree", Tree)
    tree.focus()
    await pilot.pause()
    for _ in range(12):  # past the kind and platform headings
        node = tree.cursor_node
        if node is not None and isinstance(node.data, dict) and node.data["name"] == name:
            return
        await pilot.press("down")
        await pilot.pause()
    raise AssertionError(f"{name} is not reachable in the filtered catalog")


def test_tabs_are_fetchers_run_evidence_paramify(tmp_path, run_tui):
    async def body(app, pilot):
        tabs = app.screen.query_one(TabbedContent)
        labels = [str(t.label) for t in tabs.query("Tab")]
        await pilot.press("1")
        await pilot.pause()
        return labels, tabs.active, _focus_id(app)

    labels, active, focus = run_tui(body, _manifest_with(tmp_path))
    assert labels == ["Fetchers", "Run", "Evidence", "Paramify"]
    assert active == "tab-fetchers" and focus == "catalog-tree"


def test_a_adds_in_place_and_keeps_focus_in_the_catalog(tmp_path, run_tui):
    path = _manifest_with(tmp_path)

    async def body(app, pilot):
        await _find(app, pilot, "demo_hello")
        await pilot.press("a")
        await _settle(app, pilot)
        return _leaf_label(app, "demo_hello"), _cursor_key(app), _focus_id(app), _detail(app)

    label, cursor, focus, detail = run_tui(body, path)
    assert _uses(path) == {"demo_hello"}
    assert label.rstrip().endswith("✓")
    assert cursor == "demo_hello"
    assert focus == "catalog-tree"
    assert "✓ in manifest" in detail, "the catalog detail did not update after the add"


def test_a_on_a_fetcher_in_the_manifest_jumps_to_it(tmp_path, run_tui):
    path = _manifest_with(tmp_path, "demo_hello", "demo_policy_check")
    before = path.read_text()

    async def body(app, pilot):
        notices: list = []
        real = app.notify
        app.notify = lambda m, *a, **k: (notices.append(str(m)), real(m, *a, **k))[1]
        await _find(app, pilot, "demo_hello")
        await pilot.press("a")
        await _settle(app, pilot)
        return notices, _cursor_key(app)

    notices, cursor = run_tui(body, path)
    assert path.read_text() == before, "adding a fetcher already in the manifest wrote the file"
    assert any("demo_hello is already in the manifest" in n for n in notices), notices
    assert cursor == "demo_hello"


def test_detail_follows_the_focused_list(tmp_path, run_tui):
    path = _manifest_with(tmp_path, "demo_policy_check")

    async def body(app, pilot):
        await _find(app, pilot, "demo_hello")
        catalog_view = _detail(app)
        await pilot.press("a")  # moves the manifest cursor while the catalog has focus
        await _settle(app, pilot)
        after_add = _detail(app)
        await pilot.press("tab")
        await pilot.pause()
        return catalog_view, after_add, _focus_id(app), _detail(app)

    catalog_view, after_add, focus, manifest_view = run_tui(body, path)
    assert "a add to the manifest" in catalog_view
    assert "✓ in manifest" in after_add, "an inactive-list highlight replaced the catalog detail"
    assert focus == "manifest-entries"
    assert "✓ in manifest" not in manifest_view and "demo_hello" in manifest_view


def test_tab_cycles_three_areas(tmp_path, run_tui):
    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        seen = [_focus_id(app)]
        for _ in range(3):
            await pilot.press("tab")
            await pilot.pause()
            seen.append(_focus_id(app))
        return seen

    assert run_tui(body, _manifest_with(tmp_path, "demo_hello")) == [
        "catalog-tree", "manifest-entries", "fetchers-detail-scroll", "catalog-tree",
    ]


def test_empty_manifest_hint(tmp_path, run_tui):
    async def body(app, pilot):
        return _text(app.screen.query_one("#manifest-empty-hint", Static).content)

    assert "press a on a fetcher to add it" in run_tui(body, _manifest_with(tmp_path))


def test_switching_manifest_moves_the_marks(tmp_path, run_tui):
    first = _manifest_with(tmp_path, "demo_hello", file="first.yaml")
    second = _manifest_with(tmp_path, "demo_policy_check", file="second.yaml")

    async def body(app, pilot):
        before = _leaf_label(app, "demo_hello")
        app.load_manifest(second)
        app.screen.reload()
        await _settle(app, pilot)
        return before, _leaf_label(app, "demo_hello"), _leaf_label(app, "demo_policy_check")

    before, hello, policy = run_tui(body, first)
    assert before.rstrip().endswith("✓")
    assert not hello.rstrip().endswith("✓"), "the old manifest's mark stayed after the switch"
    assert policy.rstrip().endswith("✓")


def test_removing_an_entry_clears_its_mark(tmp_path, run_tui):
    path = _manifest_with(tmp_path, "demo_hello")

    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        before = _leaf_label(app, "demo_hello")
        app.screen.query_one("#manifest-entries", DataTable).focus()
        await pilot.pause()
        await pilot.press("x")
        await pilot.pause()
        await pilot.press("y")
        await _settle(app, pilot)
        return before, _leaf_label(app, "demo_hello")

    before, after = run_tui(body, path)
    assert before.rstrip().endswith("✓"), "the entry was never marked"
    assert not after.rstrip().endswith("✓")
    assert _uses(path) == set()


def test_a_on_the_manifest_list_goes_to_the_catalog_filter(tmp_path, run_tui):
    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        app.screen.query_one("#manifest-entries", DataTable).focus()
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        return _focus_id(app)

    assert run_tui(body, _manifest_with(tmp_path, "demo_hello")) == "catalog-search"


def test_narrow_terminal_keeps_both_lists(tmp_path):
    path = _manifest_with(tmp_path, "demo_hello")

    async def main():
        app = FetcherApp(manifest_path=str(path), root_override=str(REPO_ROOT))
        async with app.run_test(size=(120, 35)) as pilot:
            await _settle(app, pilot)
            tree = app.screen.query_one("#catalog-tree", Tree)
            stack = app.screen.query_one("#manifest-stack")
            table = app.screen.query_one("#manifest-entries", DataTable)
            return tree.region.height, stack.region.height, table.region.height

    tree_h, stack_h, table_h = asyncio.run(main())
    assert tree_h >= 5, f"the catalog is squeezed to {tree_h} rows"
    assert stack_h > 0, "the manifest settings row is off the page"
    assert table_h >= 2, f"the manifest table is squeezed to {table_h} rows"


def test_panels_are_hosted_without_their_own_detail(tmp_path, run_tui):
    async def body(app, pilot):
        return (
            len(app.screen.query("#catalog-detail-scroll")),
            len(app.screen.query("#manifest-detail-scroll")),
            len(app.screen.query(CatalogPanel)),
            len(app.screen.query(ManifestPanel)),
        )

    assert run_tui(body, _manifest_with(tmp_path)) == (0, 0, 1, 1)
