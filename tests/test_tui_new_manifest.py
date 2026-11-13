"""TUI: `n` on the welcome screen asks for a name, then for the Paramify stack.

The stack list is faked at the framework.api boundary (no socket is opened); the
app, its modals and its workers run for real, in a copy of the demo root.
"""

from __future__ import annotations

import asyncio

import pytest
import yaml

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from textual.widgets import Button, Input, OptionList, Static  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.modals import FormModal, PickerModal  # noqa: E402
from framework.tui.screens.welcome import WelcomeScreen  # noqa: E402
from framework.tui.screens.workspace import WorkspaceScreen  # noqa: E402

STACKS = [{"id": "stk-1", "name": "Alpha"}, {"id": "stk-2", "name": "Beta"}]


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "tok")


async def _settle(app, pilot):
    await app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


def _drive(root, tui_size, body):
    async def main():
        app = FetcherApp(root_override=str(root))
        async with app.run_test(size=tui_size) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, WelcomeScreen)
            return await body(app, pilot)

    return asyncio.run(main())


async def _name(app, pilot, name: str):
    await pilot.press("n")
    await pilot.pause()
    assert isinstance(app.screen, FormModal)
    assert str(app.screen.query_one("#save", Button).label) == "Next"
    app.screen.query_one("#field-input", Input).value = name
    app.screen.query_one("#save", Button).press()
    await _settle(app, pilot)


def _run_block(root, name: str) -> dict:
    return yaml.safe_load((root / "manifests" / f"{name}.yaml").read_text())["run"]


def test_picking_a_stack_creates_the_manifest_with_it(demo_workspace, token, monkeypatch, tui_size):
    monkeypatch.setattr(api, "list_stacks", lambda *a, **k: STACKS)

    async def body(app, pilot):
        await _name(app, pilot, "aws-prod")
        assert isinstance(app.screen, PickerModal)
        # Nothing is written until the stack step resolves.
        assert not (demo_workspace.root / "manifests" / "aws-prod.yaml").exists()
        app.screen.dismiss("stk-2")
        await _settle(app, pilot)
        assert isinstance(app.screen, WorkspaceScreen)

    _drive(demo_workspace.root, tui_size, body)
    assert _run_block(demo_workspace.root, "aws-prod")["paramify"] == {"stack": "stk-2", "stack_name": "Beta"}


def test_skip_is_the_first_choice_and_writes_no_stack(demo_workspace, token, monkeypatch, tui_size):
    monkeypatch.setattr(api, "list_stacks", lambda *a, **k: STACKS)

    async def body(app, pilot):
        await _name(app, pilot, "aws-prod")
        assert isinstance(app.screen, PickerModal)
        await pilot.press("down", "enter")  # the cursor's first stop is skip
        await _settle(app, pilot)
        assert isinstance(app.screen, WorkspaceScreen)

    _drive(demo_workspace.root, tui_size, body)
    assert "paramify" not in _run_block(demo_workspace.root, "aws-prod")


def test_escape_on_the_stack_step_still_creates_the_manifest(demo_workspace, token, monkeypatch, tui_size):
    monkeypatch.setattr(api, "list_stacks", lambda *a, **k: STACKS)

    async def body(app, pilot):
        await _name(app, pilot, "aws-prod")
        assert isinstance(app.screen, PickerModal)
        await pilot.press("escape")
        await _settle(app, pilot)
        assert isinstance(app.screen, WorkspaceScreen)

    _drive(demo_workspace.root, tui_size, body)
    assert "paramify" not in _run_block(demo_workspace.root, "aws-prod")


def _notice(app) -> str:
    return str(app.screen.query_one("#picker-notice", Static).render())


def _only_choice(app) -> str:
    ol = app.screen.query_one("#picker-list", OptionList)
    assert ol.option_count == 1
    assert not app.screen.query_one("#picker-filter", Input).display  # nothing to filter
    return str(ol.get_option_at_index(0).prompt)


def test_without_a_token_the_stack_step_explains_why(demo_workspace, monkeypatch, tui_size):
    def refuse(*_a, **_k):
        raise AssertionError("listed stacks without a token")

    monkeypatch.setattr(api, "list_stacks", refuse)

    async def body(app, pilot):
        await _name(app, pilot, "aws-prod")
        # The step still shows, and says why there is no list.
        assert isinstance(app.screen, PickerModal)
        assert "No Paramify API token" in _notice(app)
        assert "PARAMIFY_UPLOAD_API_TOKEN" in _notice(app)
        assert "without a stack" in _only_choice(app)
        assert not (demo_workspace.root / "manifests" / "aws-prod.yaml").exists()
        await pilot.press("enter")
        await _settle(app, pilot)
        assert isinstance(app.screen, WorkspaceScreen)

    _drive(demo_workspace.root, tui_size, body)
    assert "paramify" not in _run_block(demo_workspace.root, "aws-prod")


def test_a_stack_list_error_is_explained_in_the_stack_step(demo_workspace, token, monkeypatch, tui_size):
    def fail(*_a, **_k):
        raise RuntimeError("401 Unauthorized")

    monkeypatch.setattr(api, "list_stacks", fail)

    async def body(app, pilot):
        await _name(app, pilot, "aws-prod")
        assert isinstance(app.screen, PickerModal)
        assert "Could not list" in _notice(app) and "401 Unauthorized" in _notice(app)
        assert "without a stack" in _only_choice(app)
        await pilot.press("escape")  # Escape is a skip here too
        await _settle(app, pilot)
        assert isinstance(app.screen, WorkspaceScreen)

    _drive(demo_workspace.root, tui_size, body)
    assert "paramify" not in _run_block(demo_workspace.root, "aws-prod")


def test_a_taken_name_is_refused_before_the_stack_step(demo_workspace, token, monkeypatch, tui_size):
    def refuse(*_a, **_k):
        raise AssertionError("listed stacks for a name that is taken")

    monkeypatch.setattr(api, "list_stacks", refuse)

    async def body(app, pilot):
        await _name(app, pilot, "demo")  # manifests/demo.yaml ships in the demo root
        # Back on the name form, with what was typed kept.
        assert isinstance(app.screen, FormModal)
        assert app.screen.query_one("#field-input", Input).value == "demo"

    _drive(demo_workspace.root, tui_size, body)
