"""TUI: the Paramify page, a setup grid of what each manifest fetcher has in Paramify.

`api.paramify_status` is stubbed; the app, the page and its workers run for real.
"""

from __future__ import annotations

import io
import threading
from pathlib import Path

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.console import Console  # noqa: E402
from textual.widgets import Static, TabbedContent  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.components.table import DataTable  # noqa: E402
from framework.tui.screens.paramify import ParamifyPage  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


def _manifest(tmp_path: Path) -> Path:
    m = api.init_manifest()
    api.set_output_dir(m, str(tmp_path / "evidence"))
    api.add_entry(m, "demo_hello")
    path = tmp_path / "page.yaml"
    api.dump_manifest(m, path, REPO_ROOT)
    return path


def _validators(*paired: bool) -> list:
    return [{"key": f"k{i}", "role": "completeness" if i == 0 else "configuration",
             "name": f"check {i}", "paired": p} for i, p in enumerate(paired)]


def _row(name, *, set_id="ev", arts=1, script="in_sync", validators=None, pairs=None, ready=False):
    return {"name": name, "kind": "evidence",
            "evidence_set": {"reference_id": f"EVD-{name.upper()}", "name": name, "id": set_id,
                             "artifact_count": arts},
            "script": script, "validators": _validators() if validators is None else validators,
            "pairs": pairs or [], "ready": ready}


def _status(rows=None, *, token=True, capabilities=None, pipelines=0, errors=None) -> dict:
    if rows is None:
        rows = [
            _row("alpha", validators=_validators(True, True), ready=True,
                 pairs=[{"pair_id": "p1", "validator_key": "k0", "capability_id": "c1", "function": "PROVIDER"},
                        {"pair_id": "p2", "validator_key": "k1", "capability_id": "c1", "function": "PROVIDER"}]),
            _row("bravo", script="update", validators=_validators(True, False), arts=0),
            _row("charlie", set_id=None, script="create", validators=[], arts=0),
        ]
    return {"workspace": {"base_url": "https://app.paramify.com/api/v0", "base_url_source": "default",
                          "token": token},
            "fetchers": rows,
            "capabilities": capabilities if capabilities is not None else [
                {"id": "c1", "reference_id": "SC-AC-06", "name": "Least privilege",
                 "functions": [{"type": "PROVIDER", "pairs": []}]}],
            "pipelines_count": pipelines, "skipped": [], "errors": errors or {}}


def _stub(monkeypatch, *results):
    """paramify_status returns (or raises) each result in turn; the last repeats."""
    calls = []

    def fake(root, manifest_path, config_path=None):
        calls.append(manifest_path)
        result = results[min(len(calls), len(results)) - 1]
        if callable(result):
            result = result()
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(api, "paramify_status", fake)
    monkeypatch.setattr(api, "list_artifacts", lambda set_id: [])
    return calls


def _text(renderable) -> str:
    console = Console(file=io.StringIO(), width=220, record=True, color_system=None)
    console.print(renderable)
    return console.export_text()


async def _settle(app, pilot):
    await app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


async def _open(app, pilot) -> ParamifyPage:
    await pilot.press("4")
    await _settle(app, pilot)
    return app.screen.query_one(ParamifyPage)


def _cells(page, key) -> list:
    grid = page.query_one("#pf-grid", DataTable)
    return [_text(c).strip() for c in grid.get_row(key)]


def _summary(page) -> str:
    return _text(page.query_one("#pf-summary", Static).content)


def test_grid_cells_follow_the_status(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status())

    async def body(app, pilot):
        page = await _open(app, pilot)
        return _cells(page, "alpha"), _cells(page, "bravo"), _cells(page, "charlie")

    alpha, bravo, charlie = run_tui(body, _manifest(tmp_path))
    assert alpha == ["alpha", "✓", "✓", "2/2", "1", "1", "READY"]
    assert bravo[2:4] == ["update", "1/2"] and bravo[6] == "·"
    assert charlie[1:4] == ["+ create", "+ create", "none"]


def test_title_and_totals(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status())

    async def body(app, pilot):
        page = await _open(app, pilot)
        return (str(page.query_one("#pf-grid-panel").border_title),
                _text(page.query_one("#pf-totals", Static).content), _summary(page))

    title, totals, summary = run_tui(body, _manifest(tmp_path))
    assert title == "evidence sets (3)  ·  1 ready"
    assert "evidence sets 2/3" in totals and "scripts 1/3" in totals
    assert "validators 2/3" in totals and "uploaded 1/3" in totals
    assert "https://app.paramify.com/api/v0" in summary and "1/3 ready" in summary


def test_detail_follows_the_cursor(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status())

    async def body(app, pilot):
        page = await _open(app, pilot)
        first = _text(page.query_one("#pf-set", Static).content)
        caps = page.query_one("#pf-caps", DataTable)
        matrix = [_text(c).strip() for c in caps.get_row_at(0)]
        await pilot.press("down")
        await _settle(app, pilot)
        second = _text(page.query_one("#pf-set", Static).content)
        return first, matrix, second

    first, matrix, second = run_tui(body, _manifest(tmp_path))
    assert "alpha" in first and "EVD-ALPHA" in first
    assert matrix[0].startswith("SC-AC-06") and matrix[1] == "provider" and matrix[2:] == ["●", "●"]
    assert "bravo" in second and "update" in second


def test_no_token_shows_the_problem_bar(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status([_row("alpha", set_id=None, script=None, validators=_validators(False))],
                               token=False, capabilities=[]))

    async def body(app, pilot):
        page = await _open(app, pilot)
        summary = page.query_one("#pf-summary", Static)
        return (summary.has_class("problem"), _summary(page), _cells(page, "alpha"),
                _text(page.query_one("#pf-caps-empty", Static).content))

    problem, summary, cells, caps = run_tui(body, _manifest(tmp_path))
    assert problem
    assert "No Paramify API token found. Set PARAMIFY_UPLOAD_API_TOKEN" in summary
    assert cells[1:4] == ["—", "—", "1 in registry"]
    assert "Capabilities are read from Paramify." in caps


def test_a_read_error_keeps_the_last_grid(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status(), RuntimeError("HTTP 503"))

    async def body(app, pilot):
        page = await _open(app, pilot)
        await pilot.press("ctrl+r")
        await _settle(app, pilot)
        return page.query_one("#pf-grid", DataTable).row_count, _summary(page)

    rows, summary = run_tui(body, _manifest(tmp_path))
    assert rows == 3
    assert summary.startswith("Could not read the workspace: HTTP 503. This is the status from")
    assert "ctrl+r to try again." in summary


def test_empty_manifest_shows_the_hint(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status([]))

    async def body(app, pilot):
        page = await _open(app, pilot)
        return (page.query_one("#pf-grid-panel").has_class("empty"),
                _text(page.query_one("#pf-grid-empty", Static).content),
                page.query_one("#pf-detail").display)

    empty, hint, detail = run_tui(body, _manifest(tmp_path))
    assert empty and "No fetchers in this manifest yet." in hint and "Fetchers tab (1)" in hint
    assert detail is False


def test_only_scan_reports_points_at_pipelines(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status([], pipelines=2))

    async def body(app, pilot):
        page = await _open(app, pilot)
        return _text(page.query_one("#pf-grid-empty", Static).content)

    assert "They are on the Pipelines tab (5)." in run_tui(body, _manifest(tmp_path))


def test_a_refresh_does_not_pull_the_view_off_pipelines(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status())

    async def body(app, pilot):
        page = await _open(app, pilot)
        await pilot.press("5")
        await pilot.pause()
        page.request_status()
        await _settle(app, pilot)
        return app.screen.query_one(TabbedContent).active

    assert run_tui(body, _manifest(tmp_path)) == "tab-pipelines"


def test_a_status_for_another_manifest_is_dropped(tmp_path, monkeypatch, run_tui):
    gate = threading.Event()

    def slow():
        gate.wait(5)
        return _status()

    _stub(monkeypatch, slow)

    async def body(app, pilot):
        await pilot.press("4")
        await pilot.pause()
        app.manifest_path = tmp_path / "other.yaml"
        gate.set()
        await _settle(app, pilot)
        return app.screen.query_one(ParamifyPage).query_one("#pf-grid", DataTable).row_count

    assert run_tui(body, _manifest(tmp_path)) == 0


def test_many_validators_list_names_not_columns(tmp_path, monkeypatch, run_tui):
    validators = _validators(*([True] * 7))
    pairs = [{"pair_id": f"p{i}", "validator_key": f"k{i}", "capability_id": "c1", "function": "PROVIDER"}
             for i in (0, 6)]
    _stub(monkeypatch, _status([_row("alpha", validators=validators, pairs=pairs)]))

    async def body(app, pilot):
        page = await _open(app, pilot)
        caps = page.query_one("#pf-caps", DataTable)
        labels = [str(col.label) for col in caps.columns.values()]
        return labels, [_text(c).strip() for c in caps.get_row_at(0)]

    labels, row = run_tui(body, _manifest(tmp_path))
    assert "V7" not in labels and "validators in the pair" in labels
    assert row[-1] == "check 0 + check 6"


def test_reading_shows_while_the_worker_runs(tmp_path, monkeypatch, run_tui):
    gate = threading.Event()

    def slow():
        gate.wait(5)
        return _status()

    _stub(monkeypatch, _status(), slow)

    async def body(app, pilot):
        page = await _open(app, pilot)
        page.request_status()
        await pilot.pause()
        during = _summary(page), page.query_one("#pf-grid", DataTable).row_count
        gate.set()
        await _settle(app, pilot)
        return during

    summary, rows = run_tui(body, _manifest(tmp_path))
    assert "reading the workspace…" in summary and rows == 3


def _keys(page) -> list:
    grid = page.query_one("#pf-grid", DataTable)
    return [grid.coordinate_to_cell_key((i, 0)).row_key.value for i in range(grid.row_count)]


def _cursor(page) -> str:
    grid = page.query_one("#pf-grid", DataTable)
    return grid.coordinate_to_cell_key(grid.cursor_coordinate).row_key.value


def test_filter_matches_name_and_reference_id(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status())

    async def body(app, pilot):
        page = await _open(app, pilot)
        await pilot.press("slash")
        await pilot.pause()
        focused = app.focused.id
        await pilot.press(*"brav")
        await pilot.pause()
        by_name = _keys(page)
        page.query_one("#pf-filter").value = "evd-charl"
        await pilot.pause()
        return focused, by_name, _keys(page)

    focused, by_name, by_ref = run_tui(body, _manifest(tmp_path))
    assert focused == "pf-filter" and by_name == ["bravo"] and by_ref == ["charlie"]


def test_w_hides_ready_rows_and_totals_say_so(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status())

    async def body(app, pilot):
        page = await _open(app, pilot)
        await pilot.press("w")
        await pilot.pause()
        return _keys(page), _text(page.query_one("#pf-totals", Static).content)

    keys, totals = run_tui(body, _manifest(tmp_path))
    assert keys == ["bravo", "charlie"]
    assert totals.rstrip().endswith("showing 2 of 3")
    assert "scripts 1/3" in totals  # the totals still count every fetcher


def test_refresh_keeps_the_cursor_on_the_same_fetcher(tmp_path, monkeypatch, run_tui):
    first = _status()
    changed = _status()
    changed["fetchers"][1] = _row("bravo", validators=_validators(True, True), ready=True)
    _stub(monkeypatch, first, changed)

    async def body(app, pilot):
        page = await _open(app, pilot)
        await pilot.press("down")
        await pilot.pause()
        before = _cursor(page)
        await pilot.press("ctrl+r")
        await _settle(app, pilot)
        after = _cursor(page)
        await pilot.press("w")  # bravo is ready now, so it hides
        await pilot.pause()
        return before, after, _cursor(page)

    before, after, hidden = run_tui(body, _manifest(tmp_path))
    assert before == after == "bravo"
    assert hidden == "charlie"


def test_s_previews_then_syncs_then_refreshes(tmp_path, monkeypatch, run_tui):
    from framework.tui.modals import ConfirmModal

    status_calls = _stub(monkeypatch, _status())
    runs = []

    def scripts_sync(root, config_path=None, *, dry_run=False, include=None, on_event=None, **kw):
        runs.append((dry_run, sorted(include)))
        outcomes = [("alpha", "would_noop"), ("bravo", "would_update"), ("charlie", "would_create")]
        for name, outcome in outcomes:
            on_event({"event": "sync_item", "fetcher": name,
                      "outcome": outcome if dry_run else outcome.removeprefix("would_")})
        if not dry_run:
            on_event({"event": "sync_complete", "ok": True, "created": 1, "updated": 1})
        return {"ok": True}

    monkeypatch.setattr(api, "scripts_sync", scripts_sync)

    async def body(app, pilot):
        page = await _open(app, pilot)
        await pilot.press("s")
        await _settle(app, pilot)
        confirm = str(app.screen._message) if isinstance(app.screen, ConfirmModal) else ""
        await pilot.press("y")
        await _settle(app, pilot)
        return confirm, _text(page.query_one("#pf-activity", Static).content)

    confirm, activity = run_tui(body, _manifest(tmp_path))
    assert "1 create, 1 update" in confirm
    assert runs == [(True, ["alpha", "bravo", "charlie"]), (False, ["alpha", "bravo", "charlie"])]
    assert activity.startswith("scripts sync complete")
    assert len(status_calls) == 2, "the sync did not re-read the status"


def test_v_previews_validators(tmp_path, monkeypatch, run_tui):
    from framework.tui.modals import ConfirmModal

    _stub(monkeypatch, _status())
    runs = []

    def sync_validators(root, manifest_path=None, config_path=None, *, dry_run=False, on_event=None, **kw):
        runs.append(dry_run)
        on_event({"event": "sync_validator", "key": "k1", "outcome": "would_create" if dry_run else "created"})
        on_event({"event": "sync_validator", "key": "k0",
                  "outcome": "would_skip_exists" if dry_run else "skipped_exists"})
        on_event({"event": "sync_complete", "ok": True})
        return {"ok": True}

    monkeypatch.setattr(api, "sync_validators", sync_validators)

    async def body(app, pilot):
        await _open(app, pilot)
        await pilot.press("v")
        await _settle(app, pilot)
        confirm = str(app.screen._message) if isinstance(app.screen, ConfirmModal) else ""
        await pilot.press("n")
        await _settle(app, pilot)
        return confirm

    confirm = run_tui(body, _manifest(tmp_path))
    assert "Create 1 validator(s)" in confirm and "1 exist already" in confirm
    assert runs == [True], "a declined confirm still synced"


def test_u_opens_the_upload_confirm(tmp_path, monkeypatch, run_tui):
    from framework.sync.model import Action, Plan
    from framework.tui.modals import ConfirmModal
    from framework.tui.screens import paramify as page_module

    _stub(monkeypatch, _status())
    monkeypatch.setattr(page_module, "latest_run_scoped",
                        lambda app, kind: ({"dir": str(tmp_path / "run-1"), "run_id": "1"}, True))
    monkeypatch.setattr(api, "upload_preflight", lambda run_dir, root: {
        "ok": True, "token_present": True, "file_count": 3, "base_url": "https://x.test/api/v0", "errors": []})
    monkeypatch.setattr(api, "plan_upload", lambda *a, **k: Plan(
        [Action(id="a1", provider="delivery", key="x", verb="deliver", summary="new set")]))
    monkeypatch.setattr(api, "upload_run", lambda *a, **k: pytest.fail("uploaded without a yes"))

    async def body(app, pilot):
        await _open(app, pilot)
        await pilot.press("u")
        await _settle(app, pilot)
        return str(app.screen._message) if isinstance(app.screen, ConfirmModal) else ""

    confirm = run_tui(body, _manifest(tmp_path))
    assert "1 deliver" in confirm
    assert confirm.endswith("Upload 3 evidence file(s) to https://x.test/api/v0?")


def test_actions_are_off_without_a_token(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status(token=False, capabilities=[]))

    async def body(app, pilot):
        page = await _open(app, pilot)
        footer = _text(app.screen.query_one("#app-footer", Static).content)
        return [page.check_action(a, ()) for a in ("sync_scripts", "sync_validators", "upload_run")], footer

    allowed, footer = run_tui(body, _manifest(tmp_path))
    assert allowed == [False, False, False]
    assert "sync scripts" not in footer and "upload run" not in footer and "ctrl+r" in footer


def test_an_empty_manifest_keeps_focus_in_the_page(tmp_path, monkeypatch, run_tui):
    """The empty state hides the grid; the focus it held must not fall out of the
    page, or none of the page keys fire."""
    _stub(monkeypatch, _status([]))

    async def body(app, pilot):
        page = await _open(app, pilot)
        await pilot.pause()
        return app.focused is not None and app.focused in page.walk_children(), getattr(app.focused, "id", None)

    inside, focused = run_tui(body, _manifest(tmp_path))
    assert inside and focused == "pf-grid-empty"


# ---- review fixes ------------------------------------------------------------ #

def _second_manifest(tmp_path: Path) -> Path:
    m = api.init_manifest()
    api.add_entry(m, "demo_hello")
    path = tmp_path / "second.yaml"
    api.dump_manifest(m, path, REPO_ROOT)
    return path


def test_switching_the_manifest_on_the_tab_reads_the_new_one(tmp_path, monkeypatch, run_tui):
    other = _second_manifest(tmp_path)
    second = _status([_row("zulu")])
    calls = _stub(monkeypatch, _status(), second)

    async def body(app, pilot):
        page = await _open(app, pilot)
        app.load_manifest(other)
        app.screen.reload()
        await _settle(app, pilot)
        return _keys(page)

    assert run_tui(body, _manifest(tmp_path)) == ["zulu"]
    assert Path(calls[-1]) == other


def test_a_request_during_a_read_is_not_lost(tmp_path, monkeypatch, run_tui):
    gate = threading.Event()

    def slow():
        gate.wait(5)
        return _status()

    calls = _stub(monkeypatch, _status(), slow, _status([_row("zulu")]))

    async def body(app, pilot):
        page = await _open(app, pilot)
        page.request_status()          # a read that blocks
        await pilot.pause()
        page.request_status()          # e.g. an action ends during it
        gate.set()
        await _settle(app, pilot)
        await _settle(app, pilot)
        return _keys(page)

    assert run_tui(body, _manifest(tmp_path)) == ["zulu"]
    assert len(calls) == 3


def test_the_page_stays_a_running_message_pump(tmp_path, monkeypatch, run_tui):
    """Textual keeps its own _running on every widget; the page must not shadow it."""
    _stub(monkeypatch, _status())

    async def body(app, pilot):
        return (await _open(app, pilot)).is_running

    assert run_tui(body, _manifest(tmp_path)) is True


def test_the_activity_log_takes_the_detail_row_until_the_cursor_moves(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status())
    monkeypatch.setattr(api, "scripts_sync", lambda root, config_path=None, **kw: {"ok": True})

    async def body(app, pilot):
        page = await _open(app, pilot)
        await pilot.press("s")           # nothing to sync: the log shows the result
        await _settle(app, pilot)
        during = page.query_one("#pf-activity-panel").display, page.query_one("#pf-detail").display
        await pilot.press("down")
        await pilot.pause()
        after = page.query_one("#pf-activity-panel").display, page.query_one("#pf-detail").display
        return during, after

    during, after = run_tui(body, _manifest(tmp_path))
    assert during == (True, False), "the log must replace the detail row, not push the grid down"
    assert after == (False, True)


def test_v_says_when_sets_do_not_exist_yet(tmp_path, monkeypatch, run_tui):
    from framework.tui.modals import ConfirmModal

    _stub(monkeypatch, _status())   # charlie's set does not exist yet
    monkeypatch.setattr(api, "sync_validators", lambda root, manifest_path=None, config_path=None, *, dry_run=False,
                        on_event=None, **kw: on_event({"event": "sync_validator", "key": "k9",
                                                       "outcome": "would_create"}) or {"ok": True})

    async def body(app, pilot):
        await _open(app, pilot)
        await pilot.press("v")
        await _settle(app, pilot)
        return str(app.screen._message) if isinstance(app.screen, ConfirmModal) else ""

    confirm = run_tui(body, _manifest(tmp_path))
    assert "1 evidence set(s) do not exist yet" in confirm and "press s first" in confirm
    assert "and pair each one with its evidence sets" not in confirm


def test_v_says_how_to_pair_validators_that_exist(tmp_path, monkeypatch, run_tui):
    _stub(monkeypatch, _status())   # bravo has an unpaired validator that already exists
    monkeypatch.setattr(api, "sync_validators", lambda root, manifest_path=None, config_path=None, *, dry_run=False,
                        on_event=None, **kw: on_event({"event": "sync_validator", "key": "k1",
                                                       "outcome": "would_skip_exists"}) or {"ok": True})

    async def body(app, pilot):
        page = await _open(app, pilot)
        await pilot.press("v")
        await _settle(app, pilot)
        return _text(page.query_one("#pf-activity", Static).content)

    activity = run_tui(body, _manifest(tmp_path))
    assert "1 validator(s) exist but are not paired" in activity and "in Paramify" in activity
