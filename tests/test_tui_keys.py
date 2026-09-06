"""TUI key-routing regression tests, driven through Textual's pilot.

The footer hint bar is a promise: every key it advertises must reach its action
from the focus the app actually lands on. That promise is easy to break silently,
because a page's BINDINGS only fire while focus is *inside* that page — so a
dropped focus, a stolen key, or an unhandled Enter turns a documented shortcut
into a no-op with no error anywhere. These lock in the invariants:

  * each tab focuses a widget inside its own page (so page keys are live)
  * pressing the number of the tab you're already on keeps that focus
  * ctrl+p belongs to the Paramify page, not Textual's command palette
  * enter does something wherever the footer says it does
  * enter in a confirm dialog means the safe answer
  * a focused text field eats the global keys (documented, not fixed — esc is
    the way out, which is why the footer lists it)
  * left/right walk a button row, and up/down walk the list a filter filters —
    without stealing either from the widgets that already bind them

Written sync (asyncio.run per test) so the suite needs no async pytest plugin.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from textual.widgets import Button, DataTable, Input, TabbedContent, Tree  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.modals import ConfirmModal, FormModal, MultiPickerModal  # noqa: E402
from framework.tui.screens.manifest import ManifestPage  # noqa: E402
from framework.tui.screens.upload import UploadPage  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SIZE = (180, 50)


def _write_manifest(tmp_path: Path, fetchers: int = 1) -> Path:
    """A real, schema-valid manifest with `fetchers` discovered entries and its
    evidence under tmp_path (nothing here touches the repo's own evidence/)."""
    catalog = api.catalog(REPO_ROOT)
    names = [f["name"] for c in catalog["categories"] for f in c["fetchers"]][:fetchers]
    assert names, "no fetchers discovered — cannot build a test manifest"
    manifest = api.init_manifest()
    api.set_output_dir(manifest, str(tmp_path / "evidence"))
    for name in names:
        api.add_entry(manifest, name)
    path = tmp_path / "keys-test.yaml"
    api.dump_manifest(manifest, path, REPO_ROOT)
    return path


def _fake_run(tmp_path: Path, *, files: int = 1) -> None:
    """Plant one completed run under the manifest's output dir, as api.list_runs
    expects to find it (metadata + the output files its invocations name)."""
    run_dir = tmp_path / "evidence" / "run-2026-07-30T00-00-00Z"
    run_dir.mkdir(parents=True)
    outputs = [f"evidence_{i}.json" for i in range(files)]
    for name in outputs:
        (run_dir / name).write_text(json.dumps({"payload": {"ok": True}}))
    (run_dir / "_run_metadata.json").write_text(
        json.dumps({
            "started_at": "2026-07-30T00:00:00Z",
            "completed_at": "2026-07-30T00:00:10Z",
            "invocations": [
                {"fetcher_name": "test_fetcher", "exit_code": 0, "outputs": outputs}
            ],
        })
    )


def _run(coro_fn, manifest: Path):
    """Boot the app on `manifest` and hand (app, pilot) to an async callback."""

    async def main():
        app = FetcherApp(manifest_path=str(manifest), root_override=str(REPO_ROOT))
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            return await coro_fn(app, pilot)

    return asyncio.run(main())


def _focus_id(app) -> str | None:
    return None if app.focused is None else app.focused.id


# --------------------------------------------------------------------------- #
# focus: every tab must land inside its own page, or its BINDINGS are dead
# --------------------------------------------------------------------------- #

def test_each_tab_focuses_a_widget_in_its_own_page(tmp_path):
    manifest = _write_manifest(tmp_path)

    async def body(app, pilot):
        landed = {}
        for key, tab in zip("12345", app.screen.TAB_IDS):
            await pilot.press(key)
            await pilot.pause()
            assert app.screen.query_one(TabbedContent).active == tab
            assert app.focused is not None, f"tab {tab} left focus cleared"
            landed[tab] = _focus_id(app)
            # the focused widget must live inside the active pane, so the page's
            # own bindings (a/e/x, ctrl+r, ...) resolve
            pane = app.screen.query_one(TabbedContent).active_pane
            assert app.focused in pane.walk_children(), f"{tab} focused outside its pane"
        return landed

    landed = _run(body, manifest)
    assert landed == {
        "tab-catalog": "catalog-tree",
        "tab-manifest": "manifest-entries",
        "tab-run": "btn-run",
        "tab-evidence": "evidence-runs",
        "tab-upload": "scripts-preview",
    }


def test_repeat_tab_press_keeps_pane_focus(tmp_path):
    """Pressing the number of the tab you're on used to clear focus, killing
    every page binding until you pressed escape or another tab."""
    manifest = _write_manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("2")
        await pilot.pause()
        assert _focus_id(app) == "manifest-entries"
        # and a page-level binding still resolves
        await pilot.press("a")
        await pilot.pause()
        return isinstance(app.screen, MultiPickerModal)

    assert _run(body, manifest) is True


def test_escape_returns_focus_to_the_pane_default(tmp_path):
    manifest = _write_manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        app.screen.query_one("#manifest-output-dir", Input).focus()
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        return _focus_id(app)

    assert _run(body, manifest) == "manifest-entries"


# --------------------------------------------------------------------------- #
# bindings: keys the footer advertises must reach their action
# --------------------------------------------------------------------------- #

def test_preview_keys_are_ours_not_the_command_palette(tmp_path, monkeypatch):
    """Textual claims ctrl+p for its command palette as a priority binding, which
    outranks the focused widget — ENABLE_COMMAND_PALETTE=False gives it back."""
    manifest = _write_manifest(tmp_path)
    calls = []
    monkeypatch.setattr(UploadPage, "action_preview_scripts", lambda self: calls.append(1))

    async def body(app, pilot):
        await pilot.press("5")
        await pilot.pause()
        await pilot.press("ctrl+p")
        await pilot.pause()
        await pilot.press("p")
        await pilot.pause()
        # no palette overlay was pushed over the workspace
        return len(calls), [type(s).__name__ for s in app.screen_stack]

    count, stack = _run(body, manifest)
    assert count == 2, "ctrl+p and p should both reach the page's preview action"
    assert stack == ["Screen", "WorkspaceScreen"]


def test_enter_on_a_manifest_row_opens_the_editor(tmp_path, monkeypatch):
    manifest = _write_manifest(tmp_path)
    calls = []
    monkeypatch.setattr(ManifestPage, "action_edit_entry", lambda self: calls.append(1))

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        assert app.screen.query_one("#manifest-entries", DataTable).row_count == 1
        await pilot.press("enter")
        await pilot.pause()
        return len(calls)

    assert _run(body, manifest) == 1


def test_enter_on_a_run_drills_into_its_files(tmp_path):
    manifest = _write_manifest(tmp_path)
    _fake_run(tmp_path, files=2)

    async def body(app, pilot):
        await pilot.press("4")
        await pilot.pause()
        assert _focus_id(app) == "evidence-runs"
        assert app.screen.query_one("#evidence-files", DataTable).row_count == 2
        await pilot.press("enter")
        await pilot.pause()
        return _focus_id(app)

    assert _run(body, manifest) == "evidence-files"


# --------------------------------------------------------------------------- #
# the Input trap: documented behaviour, asserted so it can't drift silently
# --------------------------------------------------------------------------- #

def test_a_focused_field_swallows_the_global_keys(tmp_path):
    """Every printable global (1-5, m, q, /) types into a focused Input instead
    of firing. Left as-is deliberately — priority bindings would make the filter
    boxes untypeable — which is why the footer advertises esc."""
    manifest = _write_manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        field = app.screen.query_one("#manifest-output-dir", Input)
        field.focus()
        await pilot.pause()
        await pilot.press("3", "q")
        await pilot.pause()
        return app.screen.query_one(TabbedContent).active, field.value, app.is_running

    tab, value, running = _run(body, manifest)
    assert tab == "tab-manifest", "a global tab key fired from inside a text field"
    assert "3" in value and "q" in value
    assert running, "'q' quit the app from inside a text field"


def test_output_dir_survives_focus_and_commits_on_blur(tmp_path):
    """select_on_focus off (the first keystroke no longer wipes the path), and an
    edit that was never submitted is committed on blur instead of reverted."""
    manifest = _write_manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        field = app.screen.query_one("#manifest-output-dir", Input)
        original = field.value
        field.focus()
        await pilot.pause()
        await pilot.press("x")
        after_one_key = field.value
        # leave the field without pressing enter
        app.screen.query_one("#manifest-entries", DataTable).focus()
        await pilot.pause()
        committed = (app.manifest.get("run") or {}).get("output_dir")
        return original, after_one_key, committed

    original, after_one_key, committed = _run(body, manifest)
    assert original and original in after_one_key, "focus+keystroke replaced the whole path"
    assert committed == after_one_key, "an unsubmitted edit was lost on blur"


# --------------------------------------------------------------------------- #
# safety: enter must not mean "yes, delete it"
# --------------------------------------------------------------------------- #

def test_confirm_modal_enter_means_no(tmp_path):
    manifest = _write_manifest(tmp_path)

    async def body(app, pilot):
        results = []
        app.push_screen(ConfirmModal("Remove 'x' from the manifest?"), results.append)
        await pilot.pause()
        focused = _focus_id(app)
        await pilot.press("enter")
        await pilot.pause()
        return focused, results

    focused, results = _run(body, manifest)
    assert focused == "no"
    assert results == [False]


def test_confirm_modal_y_still_confirms(tmp_path):
    manifest = _write_manifest(tmp_path)

    async def body(app, pilot):
        results = []
        app.push_screen(ConfirmModal("Remove 'x' from the manifest?"), results.append)
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        return results

    assert _run(body, manifest) == [True]


# --------------------------------------------------------------------------- #
# arrow keys: a button row is a left-right choice, a filter box is above a list
# --------------------------------------------------------------------------- #

def test_confirm_modal_arrows_walk_the_button_row(tmp_path):
    """Yes/No reads as a left-right choice, so it must answer to left and right.
    Textual gives Button no horizontal navigation — tab was the only way across."""
    manifest = _write_manifest(tmp_path)

    async def body(app, pilot):
        results = []
        app.push_screen(ConfirmModal("Remove 'x' from the manifest?"), results.append)
        await pilot.pause()
        seen = [_focus_id(app)]          # AUTO_FOCUS lands on the safe answer
        for key in ("left", "left", "right"):
            await pilot.press(key)
            await pilot.pause()
            seen.append(_focus_id(app))
        await pilot.press("enter")
        await pilot.pause()
        return seen, results

    seen, results = _run(body, manifest)
    assert seen == ["no", "yes", "no", "yes"], "arrows did not walk (and wrap) the row"
    assert results == [True], "enter did not press the button the arrows landed on"


def test_form_modal_arrows_walk_buttons_but_a_field_keeps_its_cursor(tmp_path):
    """The guard that makes the row bindings safe: they live on the modal, so an
    Input still claims left/right for its own cursor and never moves focus."""
    manifest = _write_manifest(tmp_path)
    spec = {"key": "region", "kind": "text", "value": "us-east-1"}

    async def body(app, pilot):
        app.push_screen(FormModal("Edit entry", {"config": [spec]}))
        await pilot.pause()
        field = app.screen.query_one("#field-input", Input)
        in_field = _focus_id(app)
        # Input selects its value on focus; end collapses that to a known cursor.
        await pilot.press("end")
        await pilot.pause()
        at_end = field.cursor_position
        await pilot.press("left")
        await pilot.pause()
        moved_cursor = field.cursor_position
        still_in_field = _focus_id(app)
        # now put focus on the row and check the arrows do work there
        app.screen.query_one("#save", Button).focus()
        await pilot.pause()
        await pilot.press("right")
        await pilot.pause()
        return in_field, at_end, moved_cursor, still_in_field, _focus_id(app)

    in_field, at_end, moved, still, on_row = _run(body, manifest)
    assert in_field == "field-input" and still == "field-input", "left stole focus from a field"
    assert moved == at_end - 1, "left did not move the text cursor"
    assert on_row == "cancel", "right did not cross the button row"


def test_disabled_buttons_are_skipped(tmp_path):
    """MultiPicker opens with nothing chosen, so Add is disabled — arrows must
    not strand focus on a button that cannot take it."""
    manifest = _write_manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, MultiPickerModal)
        assert app.screen.query_one("#confirm", Button).disabled
        app.screen.query_one("#cancel", Button).focus()
        await pilot.pause()
        await pilot.press("left")
        await pilot.pause()
        return _focus_id(app)

    assert _run(body, manifest) == "cancel"


def test_catalog_filter_arrows_walk_the_tree(tmp_path):
    """Typing in the filter, up/down move the result cursor without leaving the
    box — so the contract pane follows along and you can keep narrowing."""
    manifest = _write_manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("1")
        await pilot.pause()
        page = app.screen.query_one("#catalog-left").parent
        page.query_one("#catalog-search", Input).focus()
        await pilot.pause()
        tree = page.query_one("#catalog-tree", Tree)
        before = tree.cursor_line
        await pilot.press("down", "down")
        await pilot.pause()
        return before, tree.cursor_line, _focus_id(app)

    before, after, focused = _run(body, manifest)
    assert after == before + 2, "down did not move the catalog cursor from the filter"
    assert focused == "catalog-search", "down gave away the filter's focus"


def test_multipicker_filter_arrows_walk_the_tree(tmp_path):
    manifest = _write_manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, MultiPickerModal)
        tree = app.screen.query_one("#multi-pick-tree", Tree)
        before = tree.cursor_line
        await pilot.press("down")
        await pilot.pause()
        return before, tree.cursor_line, _focus_id(app)

    before, after, focused = _run(body, manifest)
    assert after == before + 1, "down did not move the picker cursor from the filter"
    assert focused == "multi-pick-filter"


# --------------------------------------------------------------------------- #
# The console resolves a manifest the same way the CLI does
# --------------------------------------------------------------------------- #

def test_launch_resolves_a_bare_manifest_name(monkeypatch, tmp_path):
    """--manifest demo must find manifests/demo.yaml, as -f demo does.

    The app took the string verbatim, and read_manifest returns an EMPTY
    manifest for a path that is not there — so the console opened blank with no
    warning and the first edit wrote a brand-new ./demo.
    """
    from framework.tui import __main__ as tui_main

    (tmp_path / "fetchers").mkdir()
    (tmp_path / "framework").mkdir()
    (tmp_path / "manifests").mkdir()
    real = tmp_path / "manifests" / "demo.yaml"
    real.write_text("run:\n  output_dir: ./evidence\n  fetchers: []\n")

    seen = {}
    monkeypatch.setattr(tui_main, "FetcherApp",
                        lambda **kw: type("A", (), {"run": lambda self: seen.update(kw)})())
    monkeypatch.chdir(tmp_path)

    tui_main.launch("demo")
    assert seen["manifest_path"] == str(real.resolve())


def test_launch_refuses_a_manifest_that_does_not_exist(monkeypatch, tmp_path):
    from framework.tui import __main__ as tui_main

    (tmp_path / "fetchers").mkdir()
    (tmp_path / "framework").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tui_main, "FetcherApp",
                        lambda **kw: type("A", (), {"run": lambda self: None})())

    with pytest.raises(SystemExit, match="no such manifest"):
        tui_main.launch("ghost")
