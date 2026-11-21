"""TUI: the environment view. Which variables a run reads have a value, never the values.

The manifest's env button and its status column say what is missing; E opens the
view; w adds the missing names to .env (blank); ctrl+r stops before a run that
would fail on an empty variable and opens the view instead.
"""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.console import Console  # noqa: E402
from textual.widgets import Button, Label, Static  # noqa: E402

from framework import api  # noqa: E402
from framework.contract import effective_secrets, platform_for  # noqa: E402
from framework.tui.components.table import DataTable  # noqa: E402
from framework.tui.modals import EnvironmentModal  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SECRET = "do-not-show-this-value"


def _text(renderable) -> str:
    console = Console(file=io.StringIO(), width=200, record=True, color_system=None)
    console.print(renderable)
    return console.export_text()


@pytest.fixture
def okta(tmp_path, monkeypatch):
    """A manifest of two Okta fetchers wired as the TUI wires them; .env holds the
    org URL and a blank token; the shell holds none of them."""
    for name in list(os.environ):
        if name.startswith(("OKTA_", "PARAMIFY_", "AWS_")):
            monkeypatch.delenv(name)
    env = tmp_path / ".env"
    env.write_text(f"OKTA_ORG_URL={SECRET}\nOKTA_API_TOKEN=\n")
    monkeypatch.setattr(api, "env_file", lambda root: env)
    found = api.discover(REPO_ROOT)
    m = api.init_manifest()
    api.set_output_dir(m, str(tmp_path / "evidence"))
    for name in ("okta_least_privilege", "okta_authenticators"):
        api.add_entry(m, name, found["fetchers"])
        f = found["fetchers"][name]
        for s in effective_secrets(f, platform_for(f, found["platforms"])):
            if not s.per_target:
                api.set_secret(m, name, s.name, s.env)
    path = tmp_path / "okta.yaml"
    api.dump_manifest(m, path, REPO_ROOT)
    return path, env


async def _settle(pilot):
    await pilot.pause()
    await pilot.pause()


def test_the_manifest_names_what_is_missing(okta, run_tui):
    path, _ = okta

    async def body(app, pilot):
        await _settle(pilot)
        button = str(app.screen.query_one("#manifest-env", Button).label)
        dt = app.screen.query_one("#manifest-entries", DataTable)
        status = [_text(dt.get_row_at(i)[5]).strip() for i in range(dt.row_count)]
        issues = _text(app.screen.query_one("#manifest-issues", Static).content)
        return button, status, issues

    button, status, issues = run_tui(body, path)
    # The upload token counts here; it does not stop a run, so the rows leave it out.
    assert button == "✗ 2 missing"
    assert status == ["✗ needs OKTA_API_TOKEN"] * 2
    assert "1 variable needs a value before a run:  OKTA_API_TOKEN" in issues


def test_e_opens_the_view_which_never_shows_a_value(okta, run_tui):
    path, _ = okta

    async def body(app, pilot):
        await _settle(pilot)
        await pilot.press("E")
        await _settle(pilot)
        modal = app.screen
        title = _text(modal.query_one("#modal-title", Label).content)
        missing = _text(modal.query_one("#env-list", Static).content)
        others = _text(modal.query_one("#env-others", Static).content)
        focused = app.focused.id
        await pilot.press("escape")
        await _settle(pilot)
        return isinstance(modal, EnvironmentModal), title, missing, others, focused, app.screen is not modal

    is_modal, title, missing, others, focused, closed = run_tui(body, path)
    assert is_modal
    assert title.strip() == "2 variables need a value"
    # Only what's missing, split by what it blocks; what's set is one line under it.
    assert "To run" in missing and "To upload" in missing
    assert "OKTA_API_TOKEN" in missing and "OKTA_ORG_URL" not in missing
    assert "1 other is set" in others
    assert SECRET not in missing + others
    assert focused == "env-write"  # enter adds the lines; esc still closes
    assert closed


def test_the_button_adds_blank_lines_without_touching_values(okta, run_tui):
    path, env = okta

    async def body(app, pilot):
        await _settle(pilot)
        await pilot.press("E")
        await _settle(pilot)
        await pilot.press("enter")  # the focused Add button
        await _settle(pilot)
        return _text(app.screen.query_one("#env-others", Static).content)

    others = run_tui(body, path)
    text = env.read_text()
    assert text.startswith(f"OKTA_ORG_URL={SECRET}\nOKTA_API_TOKEN=\n")
    assert "PARAMIFY_UPLOAD_API_TOKEN=\n" in text
    assert "Already written to .env" in others  # the button stays; the line says it's done


def test_ctrl_r_stops_before_a_run_and_opens_the_view(okta, run_tui, monkeypatch):
    path, _ = okta
    started = []
    monkeypatch.setattr(api, "run", lambda *a, **k: started.append(1))

    async def body(app, pilot):
        await _settle(pilot)
        await pilot.press("2")
        await _settle(pilot)
        await pilot.press("ctrl+r")
        await _settle(pilot)
        modal = app.screen
        notice = _text(modal.query_one("#env-notice", Static).content)
        await pilot.press("escape")
        await _settle(pilot)
        banner = _text(app.screen.query_one("#run-banner", Static).content)
        return isinstance(modal, EnvironmentModal), notice, banner

    is_modal, notice, banner = run_tui(body, path)
    assert started == []
    assert is_modal
    assert "The run didn't start. OKTA_API_TOKEN needs a value first." in notice
    assert "Didn't start: 1 variable needs a value." in banner
