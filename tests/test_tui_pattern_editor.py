"""The entry editor's pattern lists: the text form, the inherited platform list, and what a save writes."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from framework import api, patterns

REPO_ROOT = Path(__file__).resolve().parents[1]
SIZE = (180, 50)
USE = "azure_key_vault_configuration"
BOUNDARY = [{"pattern": "location:regioneast", "reason": "Region outside the boundary"},
            "location:regionwest", "rg:rg-out-of-scope"]
BOUNDARY_LINES = "location:regioneast  # Region outside the boundary\nlocation:regionwest\nrg:rg-out-of-scope"


def test_editor_lines_round_trip_patterns_and_reasons():
    assert patterns.to_lines(BOUNDARY) == BOUNDARY_LINES
    items, problems = patterns.from_lines(BOUNDARY_LINES + "\n\n  rg:lab-*   #  Lab  \n")
    assert problems == []
    assert [it.as_manifest() for it in items] == [*BOUNDARY, {"pattern": "rg:lab-*", "reason": "Lab"}]
    assert patterns.from_lines("rg:a\n#  no pattern\n") == ([patterns.Item("rg:a")],
                                                            ["line 2 has a reason but no pattern"])


def test_an_emptied_list_stays_empty_only_while_the_category_lists_patterns():
    m = api.init_manifest()
    api.add_entry(m, USE)
    api.set_pattern_list(m, USE, "resource_exclusions", [patterns.Item("rg:a", "why")], "azure")
    assert m["run"]["fetchers"][0]["config"] == {"resource_exclusions": [{"pattern": "rg:a", "reason": "why"}]}
    api.set_pattern_list(m, USE, "resource_exclusions", [], "azure")
    assert m["run"]["fetchers"][0]["config"] == {}
    api.set_platform_config(m, "azure", "resource_exclusions", ["rg:b"])
    api.set_pattern_list(m, USE, "resource_exclusions", [], "azure")
    assert m["run"]["fetchers"][0]["config"] == {"resource_exclusions": []}


# --------------------------------------------------------------------------- #
# The TUI form
# --------------------------------------------------------------------------- #

def _manifest(tmp_path: Path, own=None) -> Path:
    m = api.init_manifest()
    api.set_output_dir(m, str(tmp_path / "evidence"))
    api.add_entry(m, USE)
    api.set_platform_config(m, "azure", "resource_exclusions", BOUNDARY)
    if own is not None:
        api.set_fetcher_config(m, USE, "resource_exclusions", own)
    path = tmp_path / "patterns-test.yaml"
    api.dump_manifest(m, path, REPO_ROOT)
    return path


def _edit(tmp_path: Path, own=None, text=None, save=True):
    """Open the entry form, optionally replace the list's text, save; return what it showed and the saved manifest."""
    pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")
    from textual.widgets import Label, TextArea

    from framework.tui.app import FetcherApp
    from framework.tui.modals import FormModal

    path = _manifest(tmp_path, own)

    async def main():
        app = FetcherApp(manifest_path=str(path), root_override=str(REPO_ROOT))
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await pilot.press("2")
            await pilot.pause()
            await pilot.press("e")
            await pilot.pause()
            assert isinstance(app.screen, FormModal)
            area = app.screen.query_one("#field-input", TextArea)
            shown = area.text, [str(lb.render()) for lb in app.screen.query(Label)]
            if text is not None:
                area.text = text
            if save:
                await pilot.press("ctrl+s")
                await pilot.pause()
            return shown, isinstance(app.screen, FormModal)

    shown, still_open = asyncio.run(main())
    m = api.read_manifest(path)
    return shown, still_open, m["run"]["fetchers"][0].get("config") or {}, m["run"]["platforms"]["azure"]["config"]


def test_an_entry_opens_on_the_platform_list_it_inherits_and_saving_it_unchanged_writes_nothing(tmp_path):
    (text, labels), still_open, entry, platform = _edit(tmp_path)
    assert text == BOUNDARY_LINES
    assert any("inherits platforms.azure (3 patterns) until edited here" in lb for lb in labels)
    assert any("rg:, location: or id: patterns" in lb for lb in labels)
    assert not still_open and entry == {} and platform["resource_exclusions"] == BOUNDARY


def test_an_edit_gives_the_entry_its_own_list_and_leaves_the_platform_list_alone(tmp_path):
    _, _, entry, platform = _edit(tmp_path, text=BOUNDARY_LINES + "\nrg:lab-*  # Lab")
    assert entry["resource_exclusions"] == [*BOUNDARY, {"pattern": "rg:lab-*", "reason": "Lab"}]
    assert platform["resource_exclusions"] == BOUNDARY


def test_clearing_an_inherited_list_writes_an_empty_one_so_the_platform_list_stops_applying(tmp_path):
    _, _, entry, _ = _edit(tmp_path, text="")
    assert entry == {"resource_exclusions": []}
    (text, labels), _, _, _ = _edit(tmp_path, own=[], save=False)
    assert text == "" and any("empty here: platforms.azure's 3 patterns don't apply" in lb for lb in labels)


def test_an_entry_with_its_own_list_opens_on_it_and_says_what_it_replaces(tmp_path):
    (text, labels), _, entry, _ = _edit(tmp_path, own=[{"pattern": "rg:a", "reason": "why"}], save=False)
    assert text == "rg:a  # why"
    assert any("this entry's own list; replaces platforms.azure's 3 patterns" in lb for lb in labels)


def test_a_pattern_the_field_refuses_keeps_the_form_open_and_writes_nothing(tmp_path):
    _, still_open, entry, _ = _edit(tmp_path, text="route:qa-*")
    assert still_open and entry == {}
