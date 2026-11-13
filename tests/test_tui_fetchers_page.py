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


def test_the_pipelines_tab_carries_a_beta_tag(tmp_path, run_tui):
    """"beta" is a tag after the name, in the theme's warning color, and not part
    of the tab's id."""
    async def body(app, pilot):
        tabs = app.screen.query_one(TabbedContent)
        tab = tabs.get_tab("tab-pipelines")
        label = tab.label
        spans = [(label.plain[s.start:s.end], str(s.style)) for s in label.spans]
        return label.plain, spans

    plain, spans = run_tui(body, _manifest_with(tmp_path))
    assert plain == "Pipelines beta"
    assert spans == [("beta", "$warning")]


def test_tabs_are_fetchers_run_evidence_paramify(tmp_path, run_tui):
    async def body(app, pilot):
        tabs = app.screen.query_one(TabbedContent)
        labels = [str(t.label) for t in tabs.query("Tab")]
        await pilot.press("1")
        await pilot.pause()
        return labels, tabs.active, _focus_id(app)

    labels, active, focus = run_tui(body, _manifest_with(tmp_path))
    assert labels == ["Fetchers", "Run", "Evidence", "Paramify", "Pipelines beta"]
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
    assert label == "[x] demo_hello"
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
        return notices, _cursor_key(app), _detail(app)

    notices, cursor, detail = run_tui(body, path)
    assert path.read_text() == before, "adding a fetcher already in the manifest wrote the file"
    assert any("demo_hello is already in the manifest" in n for n in notices), notices
    assert cursor == "demo_hello"
    # select() moved the manifest cursor; the catalog the user is in keeps the pane.
    assert "✓ in manifest" in detail, "the manifest's cursor move replaced the catalog detail"


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


def test_tab_reaches_every_part_of_the_page(tmp_path, run_tui):
    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        seen = [_focus_id(app)]
        for _ in range(5):
            await pilot.press("tab")
            await pilot.pause()
            seen.append(_focus_id(app))
        return seen

    assert run_tui(body, _manifest_with(tmp_path, "demo_hello")) == [
        "catalog-tree", "manifest-entries", "manifest-output-dir", "manifest-stack",
        "fetchers-detail-scroll", "catalog-tree",
    ]


def test_arrows_walk_the_stack_owner_save_row(tmp_path, run_tui):
    async def body(app, pilot):
        app.screen.query_one("#manifest-stack").focus()
        await pilot.pause()
        seen = [_focus_id(app)]
        for key in ("right", "right", "right"):
            await pilot.press(key)
            await pilot.pause()
            seen.append(_focus_id(app))
        return seen

    assert run_tui(body, _manifest_with(tmp_path, "demo_hello")) == [
        "manifest-stack", "manifest-owner", "btn-save", "manifest-stack",
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
    assert before == "[x] demo_hello"
    assert hello == "[ ] demo_hello", "the old manifest's mark stayed after the switch"
    assert policy == "[x] demo_policy_check"


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
        hint_h = app.screen.query_one("#manifest-empty-hint").region.height
        return before, _leaf_label(app, "demo_hello"), hint_h

    before, after, hint_h = run_tui(body, path)
    assert 1 <= hint_h <= 3, "the emptied manifest did not shrink to its hint"
    assert before == "[x] demo_hello", "the entry was never marked"
    assert after == "[ ] demo_hello"
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
    assert table_h >= 5, f"the manifest table is squeezed to {table_h} rows"


def test_reload_goes_through_the_fetchers_page(tmp_path, run_tui, monkeypatch):
    from framework.tui.screens.fetchers import FetchersPage

    calls: list = []
    real = FetchersPage.rebuild
    monkeypatch.setattr(FetchersPage, "rebuild", lambda self: (calls.append(self.id), real(self))[1])

    async def body(app, pilot):
        calls.clear()
        app.screen.reload()
        await _settle(app, pilot)
        return calls

    assert run_tui(body, _manifest_with(tmp_path, "demo_hello")) == ["fetchers-page"]


def test_panels_are_hosted_without_their_own_detail(tmp_path, run_tui):
    async def body(app, pilot):
        return (
            len(app.screen.query("#catalog-detail-scroll")),
            len(app.screen.query("#manifest-detail-scroll")),
            len(app.screen.query(CatalogPanel)),
            len(app.screen.query(ManifestPanel)),
        )

    assert run_tui(body, _manifest_with(tmp_path)) == (0, 0, 1, 1)


def _footer(app) -> str:
    return _text(app.screen.query_one("#app-footer", Static).content)


def test_footer_hints_follow_focus(tmp_path, run_tui):
    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        in_catalog = _footer(app)
        await pilot.press("tab")
        await pilot.pause()
        return in_catalog, _footer(app)

    in_catalog, in_manifest = run_tui(body, _manifest_with(tmp_path, "demo_hello"))
    assert "add" in in_catalog and "filter" in in_catalog
    assert "targets" not in in_catalog, "the catalog's footer lists the manifest's keys"
    assert "targets" in in_manifest and "validate" in in_manifest
    # `a` in the manifest moves to the catalog filter; the hint says so.
    assert "a find to add" in in_manifest and "a add" not in in_manifest
    assert "1-5" in in_catalog and "1-5" in in_manifest  # the workspace keys stay


def _sizes(path: Path, size: tuple) -> dict:
    async def main():
        app = FetcherApp(manifest_path=str(path), root_override=str(REPO_ROOT))
        async with app.run_test(size=size) as pilot:
            await _settle(app, pilot)
            await pilot.pause()  # a short page re-fits once its blank rows are gone
            q = app.screen.query_one
            page = q("#fetchers-page")
            panel = q("#manifest-panel")
            return {
                "page_w": page.region.width, "column_h": page.region.height,
                "panel_w": panel.region.width, "panel_right": panel.region.right,
                "panel_y": panel.region.y,
                "catalog_w": q("#catalog-panel").region.width,
                "detail_w": q("#fetchers-detail-scroll").region.width,
                "detail_bottom": q("#fetchers-detail-scroll").region.bottom,
                "panel_h": panel.region.height,
                "table_h": q("#manifest-entries", DataTable).region.height,
                "tree_h": q("#catalog-tree", Tree).region.height,
                "buttons_right": max(q(f"#{b}").region.right for b in ("manifest-stack", "manifest-owner", "btn-save")),
                "dir_w": q("#manifest-output-dir").region.width,
                "hint_h": q("#manifest-empty-hint").region.height,
                "issues_bottom": q("#manifest-issues").region.bottom,
                "page_bottom": page.region.bottom,
            }

    return asyncio.run(main())


def test_the_manifest_spans_the_page_under_catalog_and_detail(tmp_path):
    s = _sizes(_manifest_with(tmp_path, "demo_hello"), (180, 50))
    assert s["panel_w"] >= s["page_w"] - 2, s  # the full width, less the page padding
    assert s["detail_bottom"] <= s["panel_y"], s  # the detail sits beside the catalog, above it
    assert s["catalog_w"] < s["detail_w"], s


def test_the_settings_row_fits_the_page(tmp_path):
    for size in ((120, 35), (180, 50)):
        s = _sizes(_manifest_with(tmp_path, "demo_hello", file=f"fit{size[0]}.yaml"), size)
        assert s["buttons_right"] <= s["panel_right"], (size, s)
        assert s["dir_w"] >= 16, (size, s)


def test_a_short_manifest_still_gets_twelve_rows(tmp_path):
    s = _sizes(_manifest_with(tmp_path, "demo_hello"), (180, 50))
    assert s["table_h"] >= 13, s  # twelve rows and the header


def test_an_empty_manifest_takes_only_its_hint(tmp_path):
    s = _sizes(_manifest_with(tmp_path), (180, 50))
    assert s["hint_h"] <= 3, s  # the hint and its padding, not twelve hatched rows
    assert s["tree_h"] >= 25, s


@pytest.mark.parametrize("size", [(80, 24), (100, 30)], ids=["80x24", "100x30"])
@pytest.mark.parametrize("names", [(), ("demo_hello",)], ids=["empty", "one-entry"])
def test_a_short_page_keeps_the_catalog(tmp_path, size, names):
    """On a short page the manifest's twelve-row floor gives way, and nothing runs off the page."""
    s = _sizes(_manifest_with(tmp_path, *names), size)
    assert s["issues_bottom"] <= s["page_bottom"], f"the manifest runs off the page: {s}"
    if names:
        assert s["table_h"] >= 3, s  # the header and at least two rows
        assert s["tree_h"] >= 5, s
    else:
        assert s["hint_h"] >= 1, s
        assert s["tree_h"] >= 7, s
    assert s["tree_h"] >= s["panel_h"] - 6, f"the catalog is squeezed: {s}"


def test_the_short_layout_goes_when_the_page_grows(tmp_path):
    path = _manifest_with(tmp_path, "demo_hello")

    async def main():
        app = FetcherApp(manifest_path=str(path), root_override=str(REPO_ROOT))
        async with app.run_test(size=(80, 24)) as pilot:
            await _settle(app, pilot)
            page = app.screen.query_one("#fetchers-page")
            short = page.has_class("short")
            await pilot.resize_terminal(180, 50)
            await _settle(app, pilot)
            await pilot.pause()
            table = app.screen.query_one("#manifest-entries", DataTable)
            return short, page.has_class("short"), table.region.height

    short, still_short, table_h = asyncio.run(main())
    assert short and not still_short
    assert table_h >= 13, "the twelve-row floor did not come back on a tall page"


def test_a_long_manifest_takes_at_most_sixty_five_percent(tmp_path):
    names = [f["name"] for c in api.catalog(REPO_ROOT)["categories"] for f in c["fetchers"]
             if f["name"].startswith("aws_")][:30]
    s = _sizes(_manifest_with(tmp_path, *names), (180, 50))
    assert s["column_h"] * 0.6 <= s["panel_h"] <= s["column_h"] * 0.65 + 1, s
    assert s["tree_h"] >= 5, s


def _fetcher_with_wired_secret() -> str:
    for c in api.catalog(REPO_ROOT)["categories"]:
        for f in c["fetchers"]:
            if any(not s.get("per_target") and s.get("env") for s in f.get("secrets", [])):
                return f["name"]
    raise AssertionError("no fetcher has an entry-level secret with a default env var")


def test_the_add_notice_says_how_to_reach_the_entry(tmp_path, run_tui):
    name = _fetcher_with_wired_secret()

    async def body(app, pilot):
        notices: list = []
        real = app.notify
        app.notify = lambda m, *a, **k: (notices.append(str(m)), real(m, *a, **k))[1]
        await _find(app, pilot, name)
        await pilot.press("a")
        await _settle(app, pilot)
        return notices

    notices = run_tui(body, _manifest_with(tmp_path))
    wired = [n for n in notices if "secrets wired" in n]
    assert wired, notices
    assert "tab, then e" in wired[-1], "the notice names a key that does nothing in the catalog"


def test_enter_in_the_filter_goes_to_the_first_match(tmp_path, run_tui):
    path = _manifest_with(tmp_path)

    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        await pilot.press("slash", *"demo_hello", "enter")
        await pilot.pause()
        tree = app.screen.query_one("#catalog-tree", Tree)
        landed = _focus_id(app), tree.cursor_node.data["name"]
        await pilot.press("enter")  # and enter again adds it
        await _settle(app, pilot)
        return landed

    assert run_tui(body, path) == ("catalog-tree", "demo_hello")
    assert _uses(path) == {"demo_hello"}


def test_tab_from_the_filter_goes_to_the_tree(tmp_path, run_tui):
    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        app.screen.query_one("#catalog-search", Input).focus()
        await pilot.pause()
        await pilot.press("tab")
        await pilot.pause()
        return _focus_id(app)

    assert run_tui(body, _manifest_with(tmp_path, "demo_hello")) == "catalog-tree"


def test_escape_stays_in_the_list_you_were_in(tmp_path, run_tui):
    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        app.screen.query_one("#manifest-output-dir", Input).focus()
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        from_field = _focus_id(app)
        await pilot.press("escape")
        await pilot.pause()
        return from_field, _focus_id(app)

    assert run_tui(body, _manifest_with(tmp_path, "demo_hello")) == ("manifest-entries", "manifest-entries")


def test_the_scan_report_help_names_the_fetchers_tab():
    from framework.tui import kinds, render

    text = _text(render.kind_detail(kinds.SCAN_REPORT, 1))
    assert "Manifest tab" not in text
    assert "Fetchers tab" in text


def _rgb(color) -> tuple:
    return (color.r, color.g, color.b)


def test_only_the_focused_panel_has_an_accent_border(tmp_path, run_tui):
    from textual.color import Color

    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        focused = app.screen.query_one("#catalog-left").styles.border_top[1]
        at_rest = app.screen.query_one("#manifest-entries-panel").styles.border_top[1]
        return focused, at_rest, Color.parse(app.current_theme.primary)

    focused, at_rest, primary = run_tui(body, _manifest_with(tmp_path, "demo_hello"))
    assert _rgb(focused) == _rgb(primary)
    assert _rgb(at_rest) != _rgb(primary), "a panel without focus still has an accent border"


def test_a_list_without_focus_has_a_dim_cursor(tmp_path, run_tui):
    from textual.color import Color

    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        table = app.screen.query_one("#manifest-entries", DataTable)
        tree = app.screen.query_one("#catalog-tree", Tree)
        table_blurred = table.get_component_styles("datatable--cursor").background
        table.focus()
        await pilot.pause()
        tree_blurred = tree.get_component_styles("tree--cursor").background
        table_focused = table.get_component_styles("datatable--cursor").background
        return table_blurred, tree_blurred, table_focused, Color.parse(app.current_theme.primary)

    table_blurred, tree_blurred, table_focused, primary = run_tui(body, _manifest_with(tmp_path, "demo_hello"))
    assert _rgb(table_blurred) != _rgb(primary), "the manifest cursor stays bright without focus"
    assert _rgb(tree_blurred) != _rgb(primary), "the catalog cursor stays bright without focus"
    assert _rgb(table_focused) != _rgb(table_blurred), "focus does not change the cursor"


def test_the_catalog_cursor_stays_bright_while_the_filter_drives_it(tmp_path, run_tui):
    """Up/down in the filter move the tree cursor and enter picks its row, so
    the cursor keeps the accent while the filter has focus."""
    from textual.color import Color

    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        app.screen.query_one("#catalog-search", Input).focus()
        await pilot.pause()
        tree = app.screen.query_one("#catalog-tree", Tree)
        in_filter = tree.get_component_styles("tree--cursor").background
        app.screen.query_one("#manifest-entries", DataTable).focus()
        await pilot.pause()
        elsewhere = tree.get_component_styles("tree--cursor").background
        return _focus_id(app), in_filter, elsewhere, Color.parse(app.current_theme.primary)

    focus, in_filter, elsewhere, primary = run_tui(body, _manifest_with(tmp_path, "demo_hello"))
    assert focus == "manifest-entries"
    assert _rgb(in_filter) == _rgb(primary), "the catalog cursor is gray while the filter drives it"
    assert _rgb(elsewhere) != _rgb(primary), "the catalog cursor stays bright with focus in the manifest"
