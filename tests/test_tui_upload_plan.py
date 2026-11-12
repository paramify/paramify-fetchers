"""TUI: the Stack setting, the entry editor's Paramify group, and the plan in the upload confirm.

The Paramify API is faked at the framework.api boundary (no socket is opened); the
app, its modals and its workers run for real.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest
import yaml
from dotenv import dotenv_values

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


def test_stack_picker_finds_a_token_that_is_only_in_dotenv(tmp_path, no_token, monkeypatch, run_tui):
    # The picker asks upload_readiness, which loads `.env` the way list_stacks
    # does; api.load_dotenv is pointed at a tmp file (override=False semantics).
    path, _ = _manifest(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("PARAMIFY_UPLOAD_API_TOKEN=tok\n")
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "")
    monkeypatch.delenv("PARAMIFY_UPLOAD_API_TOKEN")  # recorded, so the loaded value is removed afterwards

    def load_dotenv(*_a, **_k) -> bool:
        values = {k: v for k, v in dotenv_values(env_file).items() if v is not None and k not in os.environ}
        os.environ.update(values)
        return bool(values)

    monkeypatch.setattr(api, "load_dotenv", load_dotenv)
    monkeypatch.setattr(api, "list_stacks", lambda *a, **k: STACKS)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        app.screen.query_one("#manifest-stack", Button).press()
        await _settle(app, pilot)
        assert isinstance(app.screen, PickerModal)
        app.screen.dismiss("stk-1")
        await _settle(app, pilot)

    run_tui(body, path)
    paramify = _run_block(path)["paramify"]
    assert paramify["stack"] == "stk-1" and paramify["stack_name"] == "Alpha"


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

    async def edit(app, pilot, approval, no_request, stack, delivery=BLANK):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, FormModal)
        rows = {r.spec["key"]: r for r in app.screen.query("FieldRow") if r.group == "paramify"}
        rows["stack"].query_one(Input).value = stack
        rows["approval"].query_one(Select).value = approval
        rows["no_request"].query_one(Select).value = no_request
        rows["delivery"].query_one(Select).value = delivery
        await pilot.pause()
        await pilot.press("ctrl+s")
        await _settle(app, pilot)

    async def first(app, pilot):
        await edit(app, pilot, "MANUAL", "evidence", "stk-9", "direct")

    run_tui(first, path)
    entry = _run_block(path)["fetchers"][0]
    assert entry["paramify"] == {"stack": "stk-9", "approval": "MANUAL", "no_request": "evidence",
                                 "delivery": "direct"}

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


def test_the_plan_compares_the_run_with_the_open_manifest(tmp_path, monkeypatch, no_token, run_tui):
    _upload_ready(tmp_path, monkeypatch, token=True)
    seen = {}

    def fake_plan(run_dir, root, config_path=None, *, online, **kw):
        seen["manifest_path"] = kw.get("manifest_path")
        return Plan([], notes=["the manifest now sets stack E2E-A for ev; this run was made with none. "
                               "Run the manifest again, or upload with --stack E2E-A."])

    monkeypatch.setattr(api, "plan_upload", fake_plan)

    text = _open_confirm(tmp_path, run_tui, _confirm_text, monkeypatch)
    assert Path(seen["manifest_path"]).resolve() == (tmp_path / "plan-test.yaml").resolve()
    assert "! the manifest now sets stack E2E-A for ev" in text


def test_a_run_another_manifest_made_is_not_compared_with_the_open_one(tmp_path, monkeypatch, no_token, run_tui):
    evidence_run(tmp_path / "evidence", "2026-09-01T00-00-00Z", manifest="manifests/other.yaml")
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "tok")
    seen = {}

    def fake_plan(run_dir, root, config_path=None, *, online, **kw):
        seen["manifest_path"] = kw.get("manifest_path", "absent")
        return Plan([])

    monkeypatch.setattr(api, "plan_upload", fake_plan)
    _open_confirm(tmp_path, run_tui, _confirm_text, monkeypatch)
    assert seen["manifest_path"] is None


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


def _rendered_confirm(app) -> str:
    """The confirm's text as drawn: markup in the message would be eaten here."""
    assert isinstance(app.screen, ConfirmModal)
    label = app.screen.query_one("#modal-title")
    return "\n".join(strip.text for strip in label.render_lines(label.region.reset_offset))


def test_confirm_shows_brackets_in_file_names_and_messages(tmp_path, monkeypatch, no_token, run_tui):
    _upload_ready(tmp_path, monkeypatch, token=True)

    def fake_plan(run_dir, root, config_path=None, *, online, **kw):
        return Plan([Action(id="delivery/x", provider="delivery", key="x", verb="deliver",
                            summary="deliver 1 file to [bold]EVD-X[/bold]",
                            payload={"dropped": [{"original_file_name": "report[x].json",
                                                  "reason": "blocked [red]by[/red] the WAF"}]})])

    monkeypatch.setattr(api, "plan_upload", fake_plan)
    text = _open_confirm(tmp_path, run_tui, _rendered_confirm, monkeypatch)
    assert "report[x].json" in text, text
    assert "[bold]EVD-X[/bold]" in text and "blocked [red]by[/red] the WAF" in text


def test_log_shows_brackets_in_file_names_and_reasons(tmp_path, run_tui):
    path, _ = _manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("5")
        await pilot.pause()
        page = app.screen.query_one(UploadPage)
        page._begin_log(Text("uploading"))
        page._handle_upload_event({"event": "upload_file", "action_id": "delivery/x", "file": "report[x].json",
                                   "outcome": "error", "reason": "HTTP 400: [bold]bad[/bold]"})
        log = page.query_one("#upload-log")
        for _ in range(40):
            await pilot.pause(0.05)
            if log.lines:
                break
        text = "\n".join(strip.text for strip in log.lines)
        assert "report[x].json" in text and "HTTP 400: [bold]bad[/bold]" in text

    run_tui(body, path)


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


def _two_entry_manifest(tmp_path: Path):
    catalog = api.catalog(REPO_ROOT)
    fetcher = next(f for c in catalog["categories"] for f in c["fetchers"] if f.get("config"))
    name, cfg_key = fetcher["name"], fetcher["config"][0]["name"]
    m = api.init_manifest()
    api.set_output_dir(m, str(tmp_path / "evidence"))
    api.add_entry(m, name)
    m["run"]["fetchers"].append({"use": name, "config": {cfg_key: "second-original"}})
    path = tmp_path / "two.yaml"
    path.write_text(yaml.safe_dump(m))
    return path, name, cfg_key


def test_entry_editor_edits_the_selected_duplicate_entry(tmp_path, run_tui):
    path, name, cfg_key = _two_entry_manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("down")
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, FormModal)
        for r in app.screen.query("FieldRow"):
            if r.group == "config" and r.spec["key"] == cfg_key:
                r.query_one(Input).value = "second-edited"
            if r.group == "paramify" and r.spec["key"] == "approval":
                r.query_one(Select).value = "MANUAL"
        await pilot.pause()
        await pilot.press("ctrl+s")
        await _settle(app, pilot)

    run_tui(body, path)
    first, second = _run_block(path)["fetchers"]
    assert "paramify" not in first and (first.get("config") or {}).get(cfg_key) != "second-edited"
    assert second["paramify"] == {"approval": "MANUAL"}
    assert second["config"][cfg_key] == "second-edited"


def test_entry_editor_opens_on_unknown_hand_edited_values(tmp_path, run_tui):
    path, name = _manifest(tmp_path)
    m = yaml.safe_load(path.read_text())
    m["run"]["fetchers"][0]["paramify"] = {"approval": "BOGUS", "no_request": "nope"}
    path.write_text(yaml.safe_dump(m))

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, FormModal)

    run_tui(body, path)
