"""TUI tests for the pipeline actions on the Paramify tab: jobs (`j`) and the
cycle close (`C`), plus the run console's hint that issue reports are waiting.

The API is faked at the framework.api boundary; the app, its modals and its
workers run for real.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from rich.text import Text  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.modals import ConfirmModal, PickerModal  # noqa: E402
from framework.tui.screens.run import RunPage  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SIZE = (180, 50)


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
        assert "2 issue report(s) ready" in text

    _run(body, _write_manifest(tmp_path))
