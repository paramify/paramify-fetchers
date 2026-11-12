"""SVG snapshots of every TUI screen and key modal; refresh with --snapshot-update."""

from __future__ import annotations

import asyncio
import functools
import json
from datetime import date, datetime, timedelta
from types import SimpleNamespace

import pytest
import yaml

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")
pytest.importorskip("pytest_textual_snapshot", reason="snapshot tests need the 'snapshots' extra")

from textual.widgets import Input  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.components import chrome  # noqa: E402
from framework.tui.screens import welcome  # noqa: E402

MANIFEST = "manifests/demo.yaml"


class _Frozen(datetime):
    """An hour after the pinned demo run (conftest.DEMO_RUN_ID)."""

    @classmethod
    def now(cls, tz=None):
        return cls(2026, 1, 1, 1, 0, 0, tzinfo=tz)


@pytest.fixture
def shot(snap_compare, demo_workspace, no_network, monkeypatch, tui_size):
    """Open the app on MANIFEST (or the welcome screen for None), press keys, compare.

    Each step is a key, a tuple of keys typed in one go and settled once, or an
    async callable given the pilot (to click a button that has no key)."""
    monkeypatch.setattr(chrome, "datetime", _Frozen)
    monkeypatch.setattr(welcome, "datetime", _Frozen)
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(welcome, "time", SimpleNamespace(monotonic=lambda: clock.now))

    async def settle(pilot) -> None:
        app = pilot.app
        await asyncio.wait_for(app.workers.wait_for_complete(), 30)
        # Workers post their results; pause() drains them, then idle sizes the tables.
        await pilot.pause()
        await pilot.pause()
        # Jump each welcome animation to its settled frame, however late it mounted.
        for screen in app.screen_stack:
            if isinstance(screen, welcome.WelcomeScreen):
                clock.now = screen._t0 + 10.0
                screen._tick()
        for field in app.screen.query(Input):
            field.cursor_blink = False
        await pilot.pause()

    def compare(*steps: str | tuple, manifest: str | None = MANIFEST) -> bool:
        app = FetcherApp(manifest_path=manifest, root_override=str(demo_workspace.root))

        async def run_before(pilot) -> None:
            await settle(pilot)
            for step in steps:
                if callable(step):
                    await step(pilot)
                else:
                    await pilot.press(*((step,) if isinstance(step, str) else step))
                await settle(pilot)

        return snap_compare(app, terminal_size=tui_size, run_before=run_before)

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
    assert shot("slash", tuple("demo_hello"), "down", "down", "down", "escape")


def test_manifest(shot):
    assert shot("2")


def test_manifest_add_fetchers_picker(shot, demo_workspace):
    root = demo_workspace.root
    api.dump_manifest(api.init_manifest(), root / "manifests" / "empty.yaml", root)
    assert shot("2", "a", tuple("demo_hello"), "enter", manifest="manifests/empty.yaml")


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


def test_paramify_scripts_preview(shot):
    assert shot("5", "p")


@pytest.fixture
def workspace(demo_workspace, fake_paramify):
    """A fake Paramify for the demo: EVD-DEMO-HELLO has one channel on Prod with a current
    request; another set has one channel per owner. After demo_workspace, which clears the token."""
    fake = fake_paramify
    prod, staging = fake.add_stack("Prod"), fake.add_stack("Staging")
    hello = fake.add_evidence("EVD-DEMO-HELLO", channels=[prod.id], owners=["alice"],
                              name="Demo — Synthetic MFA Policy")
    fake.add_request(hello.id, hello.channels[0].id, date.today() - timedelta(days=5), date.today() + timedelta(days=5))
    fake.add_evidence("EVD-OTHER", channels=[prod.id, staging.id], owners=["alice", "bob"])
    return fake


async def _click(selector: str, pilot) -> None:
    await pilot.click(selector)


def test_manifest_stack_picker(shot, workspace):
    assert shot("2", functools.partial(_click, "#manifest-stack"))


def test_manifest_owner_picker(shot, workspace):
    assert shot("2", functools.partial(_click, "#manifest-owner"))


def test_paramify_upload_plan(shot, workspace, demo_workspace):
    # The demo manifest and its run with stack Prod set, so the plan names the whole route.
    root = demo_workspace.root
    manifest = root / MANIFEST
    m = yaml.safe_load(manifest.read_text())
    api.set_stack(m, "st-1", "Prod")
    api.dump_manifest(m, manifest, root)
    [meta] = (root / "evidence").glob("run-*/_run_metadata.json")
    run = json.loads(meta.read_text())
    run["paramify"]["demo_hello"].update(stack="st-1", stack_name="Prod")
    meta.write_text(json.dumps(run))
    assert shot("5", "ctrl+u")
    assert not [c for c in workspace.calls if c[0] != "GET"]
