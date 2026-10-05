"""TUI tests for the pipeline actions on the Paramify tab: jobs (`j`) and the
cycle close (`C`), plus the run console's hint that issue reports are waiting.

The API is faked at the framework.api boundary; the app, its modals and its
workers run for real.
"""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.text import Text  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.modals import ConfirmModal, PickerModal  # noqa: E402
from framework.tui.screens.run import RunPage  # noqa: E402
from framework.tui.screens.upload import UploadPage  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SIZE = (180, 50)

# Run fixtures shared with test_run_selection, loaded by path: tests/ is not a
# package, so importing it by name depends on how pytest was launched.
_spec = importlib.util.spec_from_file_location(
    "run_selection_fixtures", Path(__file__).with_name("test_run_selection.py")
)
_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixtures)
evidence_run, issue_run = _fixtures.evidence_run, _fixtures.issue_run


def _write_manifest(tmp_path: Path) -> Path:
    catalog = api.catalog(REPO_ROOT)
    name = next(f["name"] for c in catalog["categories"] for f in c["fetchers"])
    manifest = api.init_manifest()
    api.set_output_dir(manifest, str(tmp_path / "evidence"))
    api.add_entry(manifest, name)
    path = tmp_path / "pipeline-test.yaml"
    api.dump_manifest(manifest, path, REPO_ROOT)
    return path


def _run(coro_fn, manifest: Path):
    async def main():
        app = FetcherApp(manifest_path=str(manifest), root_override=str(REPO_ROOT))
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            return await coro_fn(app, pilot)

    return asyncio.run(main())


async def _settle(app, pilot):
    await app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


def _options(screen) -> list:
    return [label for _, label in screen._options]


def test_j_lists_pipeline_jobs(tmp_path, monkeypatch):
    jobs = [
        {"job_id": "job-failed", "status": "FAILED", "type": "PROCESS",
         "assessment_id": "A-1", "created_at": "2026-09-28T10:00:00Z",
         "counts": None, "error": "boom", "blocked_by": None},
        {"job_id": "job-done", "status": "COMPLETED", "type": "PROCESS_CLOSE",
         "assessment_id": "A-1", "created_at": "2026-09-27T10:00:00Z",
         "counts": {"issuesCreated": 3, "issuesAutoClosed": 1}, "blocked_by": None},
    ]
    monkeypatch.setattr(api, "issues_jobs", lambda root, **kw: jobs)

    async def body(app, pilot):
        await pilot.press("5")
        await pilot.pause()
        await pilot.press("j")
        await _settle(app, pilot)
        assert isinstance(app.screen, PickerModal)
        labels = _options(app.screen)
        assert any("FAILED" in label for label in labels)
        assert any("3 created" in label and "1 auto-closed" in label for label in labels)

    _run(body, _write_manifest(tmp_path))


def test_a_failed_job_offers_retry_and_cancel_behind_a_confirm(tmp_path, monkeypatch):
    job = {"job_id": "job-failed", "status": "FAILED", "type": "PROCESS",
           "assessment_id": "A-1", "created_at": "", "counts": None, "blocked_by": None}
    calls = []
    monkeypatch.setattr(api, "issues_jobs", lambda root, **kw: [job])
    monkeypatch.setattr(
        api, "issues_job_action",
        lambda root, job_id, action: calls.append((job_id, action)) or {**job, "status": "QUEUED"},
    )

    async def body(app, pilot):
        await pilot.press("5")
        await pilot.pause()
        await pilot.press("j")
        await _settle(app, pilot)
        app.screen.dismiss("job-failed")
        await pilot.pause()
        assert isinstance(app.screen, PickerModal)
        assert [oid for oid, _ in app.screen._options] == ["retry", "cancel"]
        app.screen.dismiss("retry")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        await pilot.press("y")
        await _settle(app, pilot)
        assert calls == [("job-failed", "retry")]

    _run(body, _write_manifest(tmp_path))


def test_shift_c_closes_a_manifest_assessment_after_a_warning(tmp_path, monkeypatch):
    closed = []
    monkeypatch.setattr(
        api, "issues_close",
        lambda root, aid, **kw: closed.append(aid) or {
            "job_id": "job-close", "status": "COMPLETED", "type": "CLOSE",
            "counts": {"issuesAutoClosed": 7},
        },
    )

    async def body(app, pilot):
        app.manifest["run"]["fetchers"][0]["config"] = {
            "assessment_id": "A-1", "assessment_name": "Monthly Scan",
        }
        await pilot.press("5")
        await pilot.pause()
        await pilot.press("C")
        await pilot.pause()
        assert isinstance(app.screen, PickerModal)
        assert app.screen._options == [("A-1", "Monthly Scan")]
        app.screen.dismiss("A-1")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        assert "auto-closed" in str(app.screen._message)
        await pilot.press("y")
        await _settle(app, pilot)
        assert closed == ["A-1"]

    _run(body, _write_manifest(tmp_path))


def test_shift_c_with_no_assessment_says_so(tmp_path):
    async def body(app, pilot):
        await pilot.press("5")
        await pilot.pause()
        await pilot.press("C")
        await pilot.pause()
        assert not isinstance(app.screen, PickerModal)

    _run(body, _write_manifest(tmp_path))


def test_run_console_points_at_waiting_issue_reports(tmp_path):
    async def body(app, pilot):
        page = app.screen.query_one(RunPage)
        page._finalize(True, "", issue_reports=2)
        await pilot.pause()
        banner = page.query_one("#run-banner")
        rendered = banner.render()
        text = rendered.plain if isinstance(rendered, Text) else str(rendered)
        assert "2 scan report(s) ready" in text

    _run(body, _write_manifest(tmp_path))


def test_each_panel_picks_the_newest_run_of_its_own_kind(tmp_path):
    """An evidence manifest and a pipeline manifest share the output dir; the
    issue-report panel must not go blank because the evidence run is newer."""
    out = tmp_path / "evidence"
    scans = issue_run(out, "2026-09-01T00-00-00Z")
    evidence = evidence_run(out, "2026-09-02T00-00-00Z")

    async def body(app, pilot):
        await pilot.press("5")
        await pilot.pause()
        page = app.screen.query_one(UploadPage)
        assert page._run_dir == str(evidence)
        assert page._issues_run_dir == str(scans)

    _run(body, _write_manifest(tmp_path))


def test_enter_in_the_picker_filter_takes_the_highlighted_option(tmp_path):
    """Up/down move the list's cursor from the filter box; Enter there has to
    take that option, not do nothing."""
    picked = []

    async def body(app, pilot):
        app.push_screen(
            PickerModal("Pick", [("a", "Alpha assessment"), ("b", "Beta assessment")]),
            picked.append,
        )
        await pilot.pause()
        await pilot.press("b", "e", "t")
        await pilot.pause()
        await pilot.press("enter")  # the only match, nothing highlighted yet
        await pilot.pause()
        app.push_screen(
            PickerModal("Pick", [("a", "Alpha assessment"), ("b", "Beta assessment")]),
            picked.append,
        )
        await pilot.pause()
        await pilot.press("down", "down", "enter")
        await pilot.pause()

    _run(body, _write_manifest(tmp_path))
    assert picked == ["b", "b"]


def test_paramify_tab_keys_work_on_a_pipeline_only_manifest(tmp_path, monkeypatch):
    """No evidence, no scripts: every button but Send is disabled. Focus still has
    to land in the page, or `i` does nothing."""
    out = tmp_path / "evidence"
    issue_run(out, "2026-09-01T00-00-00Z")

    def no_scripts(page):  # what a pipeline manifest sees: nothing to sync
        from textual.widgets import Button
        for bid in ("#scripts-preview", "#scripts-submit"):
            page.query_one(bid, Button).disabled = True

    monkeypatch.setattr(UploadPage, "_rebuild_scripts", no_scripts)
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "t")

    async def body(app, pilot):
        await pilot.press("5")
        await pilot.pause()
        page = app.screen.query_one(UploadPage)
        assert app.focused is not None and app.focused in page.walk_children()
        await pilot.press("i")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)

    _run(body, _write_manifest(tmp_path))


def test_a_on_an_empty_manifest_says_what_to_do(tmp_path):
    manifest = api.init_manifest()
    api.set_output_dir(manifest, str(tmp_path / "evidence"))
    path = tmp_path / "empty.yaml"
    api.dump_manifest(manifest, path, REPO_ROOT)

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        await pilot.press("A")
        await pilot.pause()
        assert not isinstance(app.screen, PickerModal)
        assert any("scan report first" in str(n.message) for n in app._notifications)

    _run(body, path)
