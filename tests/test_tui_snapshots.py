"""SVG snapshots of every TUI screen and the key modals, on the offline demo workspace.

Each compares with tests/__snapshots__/test_tui_snapshots/<test>.svg. After an
intended UI change: pytest tests/test_tui_snapshots.py --snapshot-update
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")
pytest.importorskip("pytest_textual_snapshot", reason="snapshot tests need the 'snapshots' extra")

from textual.widgets import Input  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.components import chrome  # noqa: E402
from framework.tui.screens import welcome  # noqa: E402

SIZE = (160, 50)
MANIFEST = "manifests/demo.yaml"


class _Frozen(datetime):
    """An hour after the pinned demo run (conftest.DEMO_RUN_ID)."""

    @classmethod
    def now(cls, tz=None):
        return cls(2026, 1, 1, 1, 0, 0, tzinfo=tz)


@pytest.fixture
def shot(snap_compare, demo_workspace, monkeypatch):
    """Open the app on MANIFEST (or the welcome screen for None), press keys, compare."""
    monkeypatch.setattr(chrome, "datetime", _Frozen)
    monkeypatch.setattr(welcome, "datetime", _Frozen)
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(welcome, "time", SimpleNamespace(monotonic=lambda: clock.now))

    async def settle(pilot) -> None:
        app = pilot.app
        await app.workers.wait_for_complete()
        await pilot.pause()
        # Jump the welcome animation to its settled frame.
        clock.now = 10.0
        for screen in app.screen_stack:
            if isinstance(screen, welcome.WelcomeScreen):
                screen._tick()
        for field in app.screen.query(Input):
            field.cursor_blink = False
        await pilot.pause()

    def compare(*keys: str, manifest: str | None = MANIFEST) -> bool:
        app = FetcherApp(manifest_path=manifest, root_override=str(demo_workspace.root))

        async def run_before(pilot) -> None:
            await settle(pilot)
            for key in keys:
                await pilot.press(key)
                await settle(pilot)

        return snap_compare(app, terminal_size=SIZE, run_before=run_before)

    return compare


def test_welcome(shot):
    assert shot(manifest=None)


def test_welcome_new_manifest_form(shot):
    assert shot("n", manifest=None)


def test_workspace(shot):
    assert shot()


def test_workspace_switch_manifest_picker(shot):
    assert shot("m")


def test_catalog_fetcher_contract(shot):
    assert shot("slash", *"demo_hello", "down", "down", "down", "escape")


def test_manifest(shot):
    assert shot("2")


def test_manifest_add_fetchers_picker(shot):
    assert shot("2", "a")


def test_manifest_remove_confirm(shot):
    assert shot("2", "x")


def test_manifest_preview(shot):
    assert shot("2", "p")


def test_run_complete(shot, demo_workspace, monkeypatch):
    def replay(manifest, root, on_event=None, manifest_path=None):
        for event in demo_workspace.run_events:
            on_event(event)

    monkeypatch.setattr(api, "run", replay)
    assert shot("3", "ctrl+r")


def test_evidence(shot):
    assert shot("4")


def test_evidence_file_preview(shot):
    assert shot("4", "enter", "enter")


def test_paramify(shot):
    assert shot("5")


def test_paramify_scripts_preview(shot, no_network):
    assert shot("5", "p")
