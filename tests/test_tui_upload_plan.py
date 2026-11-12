"""TUI: the Stack and Owner settings, the entry editor's Paramify group, and the plan in the upload confirm.

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
from framework.tui.screens.manifest import ManifestPage  # noqa: E402
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
    # The demo fetcher: a real one would change what these tests exercise when it changes.
    name = "demo_hello"
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


@pytest.fixture
def token(no_token, monkeypatch):
    """An upload token and nothing else: no read-token fallback, no `.env`."""
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "tok")


async def _settle(app, pilot):
    await app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


async def _manifest_page(app, pilot):
    """Open the Manifest tab and wait for focus in it: page keys pressed before that go nowhere."""
    await pilot.press("2")
    page = app.screen.query_one(ManifestPage)
    for _ in range(200):
        focused = app.focused
        if focused is not None and page in focused.ancestors_with_self:
            return page
        await pilot.pause(0.05)
    raise AssertionError("focus never reached the Manifest page")


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


def test_stack_picker_stores_id_and_name(tmp_path, token, no_network, monkeypatch, run_tui):
    path, _ = _manifest(tmp_path)
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


OWNERS = [{"owner": "alice", "sets": 3}, {"owner": "bob", "sets": 1}]


def test_owner_picker_stores_the_owner_and_can_remove_it(tmp_path, token, no_network, monkeypatch, run_tui):
    path, _ = _manifest(tmp_path)
    monkeypatch.setattr(api, "list_channel_owners", lambda *a, **k: OWNERS)

    async def pick(app, pilot, choice):
        await pilot.press("2")
        await pilot.pause()
        app.screen.query_one("#manifest-owner", Button).press()
        await _settle(app, pilot)
        assert isinstance(app.screen, PickerModal)
        options = [label for _, label in app.screen._options]
        app.screen.dismiss(choice(app.screen._options))
        await _settle(app, pilot)
        return options

    async def first(app, pilot):
        options = await pick(app, pilot, lambda opts: "bob")
        assert options == ["alice  (3 evidence sets)", "bob  (1 evidence set)"]
        assert str(app.screen.query_one("#manifest-owner", Button).label) == "bob"

    run_tui(first, path)
    assert _run_block(path)["paramify"] == {"owner": "bob"}

    async def second(app, pilot):
        options = await pick(app, pilot, lambda opts: opts[-1][0])
        assert options[-1] == "(no owner)"

    run_tui(second, path)
    assert _run_block(path).get("paramify") in (None, {})


def test_owner_without_a_token_takes_typed_text(tmp_path, no_token, run_tui):
    path, _ = _manifest(tmp_path)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        app.screen.query_one("#manifest-owner", Button).press()
        await _settle(app, pilot)
        assert isinstance(app.screen, FormModal)
        app.screen.query(Input).first().value = " alice "
        await pilot.pause()
        await pilot.press("ctrl+s")
        await _settle(app, pilot)

    run_tui(body, path)
    assert _run_block(path)["paramify"] == {"owner": "alice"}


def test_entry_editor_writes_and_clears_paramify_overrides(tmp_path, run_tui):
    path, name = _manifest(tmp_path)

    async def edit(app, pilot, approval, no_request, stack, delivery=BLANK, owner=""):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, FormModal)
        rows = {r.spec["key"]: r for r in app.screen.query("FieldRow") if r.group == "paramify"}
        rows["stack"].query_one(Input).value = stack
        rows["owner"].query_one(Input).value = owner
        rows["approval"].query_one(Select).value = approval
        rows["no_request"].query_one(Select).value = no_request
        rows["delivery"].query_one(Select).value = delivery
        await pilot.pause()
        await pilot.press("ctrl+s")
        await _settle(app, pilot)

    async def first(app, pilot):
        await edit(app, pilot, "MANUAL", "evidence", "stk-9", "direct", owner="bob")

    run_tui(first, path)
    entry = _run_block(path)["fetchers"][0]
    assert entry["paramify"] == {"stack": "stk-9", "owner": "bob", "approval": "MANUAL",
                                 "no_request": "evidence", "delivery": "direct"}

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


def _notes(app) -> list:
    return [(str(n.message), n.severity) for n in app._notifications]


@pytest.mark.parametrize("button, lister, message", [
    ("#manifest-stack", "list_stacks", "Could not list stacks: HTTP 401: token expired"),
    ("#manifest-owner", "list_channel_owners", "Could not list channel owners: HTTP 401: token expired"),
])
def test_a_listing_error_is_shown_and_changes_nothing(tmp_path, token, no_network, monkeypatch, run_tui,
                                                      button, lister, message):
    path, _ = _manifest(tmp_path)
    before = path.read_text()

    def refused(*a, **k):
        raise ValueError("HTTP 401: token expired")

    monkeypatch.setattr(api, lister, refused)

    async def body(app, pilot):
        page = await _manifest_page(app, pilot)
        page.query_one(button, Button).press()
        await _settle(app, pilot)
        return type(app.screen).__name__, _notes(app), str(page.query_one(button, Button).label)

    screen, notes, label = run_tui(body, path)
    assert screen == "WorkspaceScreen" and label == "—"
    assert (message, "error") in notes
    assert path.read_text() == before


@pytest.mark.parametrize("button, lister, options, labels", [
    ("#manifest-stack", "list_stacks", STACKS, ["Alpha  (stk-1)", "Beta  (stk-2)"]),
    ("#manifest-owner", "list_channel_owners", OWNERS, ["alice  (3 evidence sets)", "bob  (1 evidence set)"]),
    ("#manifest-stack", "list_stacks", [], ["no matches"]),  # a workspace with no stacks
    ("#manifest-owner", "list_channel_owners", [], ["no matches"]),  # no channel has an owner
])
def test_escape_on_a_picker_changes_nothing(tmp_path, token, no_network, monkeypatch, run_tui,
                                            button, lister, options, labels):
    path, _ = _manifest(tmp_path)
    before = path.read_text()
    monkeypatch.setattr(api, lister, lambda *a, **k: options)

    async def body(app, pilot):
        page = await _manifest_page(app, pilot)
        page.query_one(button, Button).press()
        await _settle(app, pilot)
        assert isinstance(app.screen, PickerModal)
        shown = [str(o.prompt) for o in app.screen.query_one("#picker-list").options]
        await pilot.press("escape")
        await _settle(app, pilot)
        return shown, type(app.screen).__name__, _notes(app)

    shown, screen, notes = run_tui(body, path)
    assert shown == labels
    assert (screen, notes) == ("WorkspaceScreen", [])
    assert path.read_text() == before


def test_the_stack_button_names_what_is_stored(tmp_path, token, no_network, monkeypatch, run_tui):
    # Picked: the name. Typed later: the typed value, and the old name is gone.
    path, _ = _manifest(tmp_path)
    monkeypatch.setattr(api, "list_stacks", lambda *a, **k: STACKS)

    async def picked(app, pilot):
        page = await _manifest_page(app, pilot)
        page.query_one("#manifest-stack", Button).press()
        await _settle(app, pilot)
        await pilot.press(*"Beta", "enter")
        await _settle(app, pilot)
        return str(page.query_one("#manifest-stack", Button).label), _notes(app)

    label, notes = run_tui(picked, path)
    assert label == "Beta" and ("Stack updated.", "information") in notes

    monkeypatch.delenv("PARAMIFY_UPLOAD_API_TOKEN")

    async def typed(app, pilot):
        page = await _manifest_page(app, pilot)
        page.query_one("#manifest-stack", Button).press()
        await _settle(app, pilot)
        assert isinstance(app.screen, FormModal)
        assert app.screen.query(Input).first().value == "stk-2"  # the stored id, not the name
        app.screen.query(Input).first().value = "stk-9"
        await pilot.pause()
        await pilot.press("ctrl+s")
        await _settle(app, pilot)
        return str(page.query_one("#manifest-stack", Button).label)

    assert run_tui(typed, path) == "stk-9"
    assert _run_block(path)["paramify"] == {"stack": "stk-9"}


def test_a_blank_typed_owner_removes_it(tmp_path, no_token, no_network, run_tui):
    path, _ = _manifest(tmp_path)
    m = yaml.safe_load(path.read_text())
    api.set_owner(m, "alice")
    api.dump_manifest(m, path, REPO_ROOT)

    async def body(app, pilot):
        page = await _manifest_page(app, pilot)
        assert str(page.query_one("#manifest-owner", Button).label) == "alice"
        page.query_one("#manifest-owner", Button).press()
        await _settle(app, pilot)
        field = app.screen.query(Input).first()
        assert field.value == "alice"
        field.value = "  "
        await pilot.pause()
        await pilot.press("ctrl+s")
        await _settle(app, pilot)
        return str(page.query_one("#manifest-owner", Button).label), _notes(app)

    label, notes = run_tui(body, path)
    assert label == "—" and ("Owner removed.", "information") in notes
    assert _run_block(path).get("paramify") in (None, {})


def test_entry_editor_shows_the_entry_settings_and_drops_a_name_only_with_its_stack(
        tmp_path, no_token, no_network, run_tui):
    path, _ = _manifest(tmp_path)
    m = yaml.safe_load(path.read_text())
    settings = {"stack": "stk-1", "stack_name": "Alpha", "owner": "bob", "approval": "MANUAL",
                "no_request": "refuse", "delivery": "direct"}
    m["run"]["fetchers"][0]["paramify"] = dict(settings)
    path.write_text(yaml.safe_dump(m))

    async def edit(app, pilot, stack=None):
        await _manifest_page(app, pilot)
        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, FormModal)
        rows = {r.spec["key"]: r for r in app.screen.query("FieldRow") if r.group == "paramify"}
        shown = {k: (r.query_one(Input).value if r.spec["kind"] == "text" else r.query_one(Select).value)
                 for k, r in rows.items()}
        options = {k: [v for _, v in r.spec["options"]] for k, r in rows.items() if r.spec["kind"] == "select"}
        if stack is not None:
            rows["stack"].query_one(Input).value = stack
        await pilot.pause()
        await pilot.press("ctrl+s")
        await _settle(app, pilot)
        return shown, options

    shown, options = run_tui(edit, path)
    assert shown == {k: v for k, v in settings.items() if k != "stack_name"}
    assert options == {"approval": ["MANUAL", "SUBMISSION_WITH_PASSING_VALIDATORS", "SUBMISSION"],
                       "no_request": ["direct", "evidence", "refuse"], "delivery": ["auto", "direct"]}
    assert _run_block(path)["fetchers"][0]["paramify"] == settings  # saved unchanged, name kept

    run_tui(lambda app, pilot: edit(app, pilot, stack="stk-2"), path)
    assert _run_block(path)["fetchers"][0]["paramify"] == {
        **{k: v for k, v in settings.items() if k != "stack_name"}, "stack": "stk-2"}
