"""TUI: the Stack setting, the entry editor's Paramify group, and the plan in the upload confirm.

The Paramify API is faked at the framework.api boundary (no socket is opened); the
app, its modals and its workers run for real.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.text import Text  # noqa: E402
from textual.widgets import Button, Input, Select  # noqa: E402

from framework import api  # noqa: E402
from framework.sync.model import Action, Plan  # noqa: E402
from framework.tui.components.forms import _NULL as BLANK  # noqa: E402
from framework.tui.modals import ConfirmModal, FormModal, PickerModal  # noqa: E402
from framework.tui.screens.upload import UploadPage  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "run_selection_fixtures", Path(__file__).with_name("test_run_selection.py")
)
_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixtures)
evidence_run = _fixtures.evidence_run

STACKS = [{"id": "stk-1", "name": "Alpha"}, {"id": "stk-2", "name": "Beta"}]


def _manifest(tmp_path: Path):
    catalog = api.catalog(REPO_ROOT)
    name = next(f["name"] for c in catalog["categories"] for f in c["fetchers"])
    m = api.init_manifest()
    api.set_output_dir(m, str(tmp_path / "evidence"))
    api.add_entry(m, name)
    path = tmp_path / "plan-test.yaml"
    api.dump_manifest(m, path, REPO_ROOT)
    return path, name


def _run_block(path: Path) -> dict:
    return yaml.safe_load(path.read_text())["run"]


@pytest.fixture
def no_token(monkeypatch):
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.delenv("PARAMIFY_UPLOAD_API_TOKEN", raising=False)
    monkeypatch.delenv("PARAMIFY_API_TOKEN", raising=False)


async def _settle(app, pilot):
    await app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


def test_stack_row_shows_the_stack_name(tmp_path, run_tui):
    path, _ = _manifest(tmp_path)
    m = yaml.safe_load(path.read_text())
    api.set_stack(m, "stk-1", "Alpha")
    api.dump_manifest(m, path, REPO_ROOT)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        assert "Alpha" in str(app.screen.query_one("#manifest-stack", Button).label)

    run_tui(body, path)


def test_stack_picker_stores_id_and_name(tmp_path, monkeypatch, run_tui):
    path, _ = _manifest(tmp_path)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "tok")
    monkeypatch.setattr(api, "list_stacks", lambda *a, **k: STACKS)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        app.screen.query_one("#manifest-stack", Button).press()
        await _settle(app, pilot)
        assert isinstance(app.screen, PickerModal)
        app.screen.dismiss("stk-2")
        await _settle(app, pilot)

    run_tui(body, path)
    paramify = _run_block(path)["paramify"]
    assert paramify["stack"] == "stk-2" and paramify["stack_name"] == "Beta"


def test_stack_without_a_token_takes_typed_text(tmp_path, no_token, run_tui):
    path, _ = _manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        app.screen.query_one("#manifest-stack", Button).press()
        await _settle(app, pilot)
        assert isinstance(app.screen, FormModal)
        app.screen.query(Input).first().value = "typed-stack"
        await pilot.pause()
        await pilot.press("ctrl+s")
        await _settle(app, pilot)

    run_tui(body, path)
    paramify = _run_block(path)["paramify"]
    assert paramify["stack"] == "typed-stack" and "stack_name" not in paramify


def test_entry_editor_writes_and_clears_paramify_overrides(tmp_path, run_tui):
    path, name = _manifest(tmp_path)

    async def edit(app, pilot, approval, no_request, stack):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, FormModal)
        rows = {r.spec["key"]: r for r in app.screen.query("FieldRow") if r.group == "paramify"}
        rows["stack"].query_one(Input).value = stack
        rows["approval"].query_one(Select).value = approval
        rows["no_request"].query_one(Select).value = no_request
        await pilot.pause()
        await pilot.press("ctrl+s")
        await _settle(app, pilot)

    async def first(app, pilot):
        await edit(app, pilot, "MANUAL", "evidence", "stk-9")

    run_tui(first, path)
    entry = _run_block(path)["fetchers"][0]
    assert entry["paramify"] == {"stack": "stk-9", "approval": "MANUAL", "no_request": "evidence"}

    async def second(app, pilot):
        await edit(app, pilot, BLANK, BLANK, "")

    run_tui(second, path)
    assert "paramify" not in _run_block(path)["fetchers"][0]


def _upload_ready(tmp_path, monkeypatch, token: bool):
    out = tmp_path / "evidence"
    evidence_run(out, "2026-09-01T00-00-00Z")
    if token:
        monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "tok")
    return out


def _open_confirm(tmp_path, run_tui, check, monkeypatch):
    monkeypatch.setattr(UploadPage, "_rebuild_scripts", lambda page: None)
    path, _ = _manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("5")
        await pilot.pause()
        page = app.screen.query_one(UploadPage)
        page.query_one("#upload-submit", Button).disabled = False
        page.action_upload_run()
        await _settle(app, pilot)
        return check(app)

    return run_tui(body, path)


def _confirm_text(app) -> str:
    assert isinstance(app.screen, ConfirmModal)
    return str(app.screen._message)


def test_confirm_shows_the_plan_totals(tmp_path, monkeypatch, no_token, run_tui):
    _upload_ready(tmp_path, monkeypatch, token=True)
    seen = {}

    def fake_plan(run_dir, root, config_path=None, *, online, **kw):
        seen["online"] = online
        return Plan([Action(id="a1", provider="delivery", key="x", verb="deliver", summary="new set")])

    monkeypatch.setattr(api, "plan_upload", fake_plan)

    text = _open_confirm(tmp_path, run_tui, _confirm_text, monkeypatch)
    assert seen["online"] is True
    assert "1 deliver" in text and "evidence file(s)" in text


def test_confirm_without_a_token_plans_offline(tmp_path, monkeypatch, no_token, run_tui):
    _upload_ready(tmp_path, monkeypatch, token=False)
    real = api.upload_preflight
    # Preflight refuses an upload without a token; the plan itself must not.
    monkeypatch.setattr(api, "upload_preflight", lambda *a, **k: {**real(*a, **k), "ok": True})
    text = _open_confirm(tmp_path, run_tui, _confirm_text, monkeypatch)
    assert "unknown" in text, text


def test_a_planning_error_is_shown_and_never_uploads(tmp_path, monkeypatch, no_token, run_tui):
    _upload_ready(tmp_path, monkeypatch, token=True)

    def boom(*a, **k):
        raise ValueError("stack 'nope' not found")

    monkeypatch.setattr(api, "plan_upload", boom)
    monkeypatch.setattr(api, "upload_run", lambda *a, **k: pytest.fail("uploaded"))
    text = _open_confirm(tmp_path, run_tui, _confirm_text, monkeypatch)
    assert "stack 'nope' not found" in text


def test_log_panel_renders_delivery_file_progress(tmp_path, run_tui):
    path, _ = _manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("5")
        await pilot.pause()
        page = app.screen.query_one(UploadPage)
        page._begin_log(Text("uploading"))
        page._handle_upload_event({"event": "delivery_file", "action_id": "a", "file": "aws_iam.json",
                                   "outcome": "uploaded", "n": 3, "of": 12, "bytes": 10})
        page._handle_upload_event({"event": "delivery_file", "action_id": "a", "file": "b.json",
                                   "outcome": "dropped", "n": None, "of": 12, "bytes": 1, "reason": "WAF"})
        page._handle_upload_event({"event": "something_new"})
        log = page.query_one("#upload-log")
        for _ in range(40):  # the log writes once it has a size
            await pilot.pause(0.05)
            if log.lines:
                break
        text = "\n".join(strip.text for strip in log.lines)
        assert "  3/12 aws_iam.json uploaded" in text
        assert "b.json dropped" in text and "WAF" in text

    run_tui(body, path)
