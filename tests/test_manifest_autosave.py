"""Manifest edits write through to disk, without an explicit save.

The page used to hold every change in memory until 's'. Nothing on screen said
the file and the view had diverged, so quitting — or simply not knowing the key —
discarded the work. These lock in that each mutation persists, and that a save
which cannot happen keeps the edit rather than losing it along with the write.

The manifest under test is built with the api into tmp_path; nothing here reads
or writes the repo's own manifests.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml

from framework import api

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from textual.widgets import Input  # noqa: E402

from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.modals import ConfirmModal, FormModal, TargetsModal  # noqa: E402
from framework.tui.screens.manifest import ManifestPage  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


def _manifest(tmp_path: Path):
    """One real fanout fetcher with two targets, saved to tmp_path."""
    catalog = api.catalog(REPO_ROOT)
    fetcher = next(
        f for c in catalog["categories"] for f in c["fetchers"]
        if f.get("supports_targets") and f.get("target_schema")
    )
    name = fetcher["name"]
    field = fetcher["target_schema"][0]["name"]
    m = api.init_manifest()
    api.set_output_dir(m, str(tmp_path / "evidence"))
    api.add_entry(m, name)
    api.add_target(m, name, {field: "first-value"})
    api.add_target(m, name, {field: "second-value"})
    path = tmp_path / "autosave.yaml"
    api.dump_manifest(m, path, REPO_ROOT)
    return path, name, field


def _on_disk(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _targets(path: Path, name: str) -> list:
    for entry in _on_disk(path)["run"]["fetchers"]:
        if entry["use"] == name:
            return entry.get("targets") or []
    return []


def _run(coro_fn, manifest: Path, size: tuple):
    async def main():
        app = FetcherApp(manifest_path=str(manifest), root_override=str(REPO_ROOT))
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            return await coro_fn(app, pilot)

    return asyncio.run(main())


async def _manifest_tab(pilot):
    await pilot.press("2")
    await pilot.pause()


# --------------------------------------------------------------------------- #
# Target edits
# --------------------------------------------------------------------------- #

def test_removing_a_target_is_on_disk_without_pressing_save(tmp_path, tui_size):
    path, name, field = _manifest(tmp_path)
    assert len(_targets(path, name)) == 2

    async def body(app, pilot):
        await _manifest_tab(pilot)
        await pilot.press("t")
        await pilot.pause()
        assert isinstance(app.screen, TargetsModal)
        await pilot.press("x")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        await pilot.press("y")
        await pilot.pause()

    _run(body, path, tui_size)
    remaining = _targets(path, name)
    assert len(remaining) == 1 and remaining[0][field] == "second-value"


def test_editing_a_target_is_on_disk_without_pressing_save(tmp_path, tui_size):
    path, name, field = _manifest(tmp_path)

    async def body(app, pilot):
        await _manifest_tab(pilot)
        await pilot.press("t")
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, FormModal)
        app.screen.query(Input).first().value = "edited-value"
        await pilot.pause()
        await pilot.press("ctrl+s")
        await pilot.pause()

    _run(body, path, tui_size)
    assert _targets(path, name)[0][field] == "edited-value"


def test_removing_a_fetcher_is_on_disk_without_pressing_save(tmp_path, tui_size):
    path, name, field = _manifest(tmp_path)

    async def body(app, pilot):
        await _manifest_tab(pilot)
        await pilot.press("x")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        await pilot.press("y")
        await pilot.pause()

    _run(body, path, tui_size)
    assert _on_disk(path)["run"]["fetchers"] == []


# --------------------------------------------------------------------------- #
# A save that cannot happen must not also cost the edit
# --------------------------------------------------------------------------- #

def test_a_failed_save_keeps_the_edit_in_memory_and_says_so(tmp_path, monkeypatch, tui_size):
    path, name, field = _manifest(tmp_path)

    def boom(*a, **kw):
        raise ValueError("schema says no")

    async def body(app, pilot):
        await _manifest_tab(pilot)
        monkeypatch.setattr(api, "dump_manifest", boom)
        await pilot.press("t")
        await pilot.pause()
        await pilot.press("x")
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        # the page lives on the workspace screen, under the modals on the stack
        page = next(
            p for screen in app.screen_stack for p in screen.query(ManifestPage)
        )
        in_memory = page._manifest["run"]["fetchers"][0].get("targets") or []
        notes = [str(n.message) for n in app._notifications]
        return len(in_memory), notes

    count, notes = _run(body, path, tui_size)
    assert count == 1                                   # the removal survived
    assert len(_targets(path, name)) == 2               # the file did not change
    assert any("not saved" in n.lower() for n in notes)
