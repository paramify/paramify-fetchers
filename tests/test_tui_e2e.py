"""Offline TUI path: welcome → demo manifest → add demo_hello → run → evidence → upload dry-run."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest
import yaml

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from textual.widgets import Button, DataTable, RichLog  # noqa: E402

from framework import api  # noqa: E402
from framework.paramify_auth import UPLOAD_TOKEN_ENV  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.modals import ConfirmModal, MultiPickerModal, PreviewModal  # noqa: E402
from framework.tui.screens.evidence import EvidencePage  # noqa: E402
from framework.tui.screens.manifest import ManifestPage  # noqa: E402
from framework.tui.screens.run import RunPage  # noqa: E402
from framework.tui.screens.upload import UploadPage  # noqa: E402
from framework.tui.screens.welcome import WelcomeScreen  # noqa: E402
from framework.tui.screens.workspace import WorkspaceScreen  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SIZE = (160, 50)


def _text(widget) -> str:
    rendered = widget.render()
    return getattr(rendered, "plain", str(rendered)).strip()


def _rows(table: DataTable) -> list:
    return [
        [getattr(cell, "plain", str(cell)).strip() for cell in table.get_row_at(i)]
        for i in range(table.row_count)
    ]


def _log(log: RichLog) -> str:
    return "\n".join(line.text for line in log.lines)


async def _until(pilot, done, what: str, timeout: float = 30.0) -> None:
    for _ in range(int(timeout / 0.05)):
        if done():
            return
        await pilot.pause(0.05)
    raise AssertionError(f"timed out waiting for {what}")


def _focused_in(page) -> bool:
    focused = page.app.focused
    return focused is not None and not focused.disabled and page in focused.ancestors_with_self


async def _tab(pilot, key: str, page_type):
    # Page keys only fire once focus lands in the page, which the app defers past a refresh.
    await pilot.press(key)
    page = pilot.app.screen.query_one(page_type)
    await _until(pilot, lambda: _focused_in(page), f"focus in {page_type.__name__}")
    return page


def test_demo_manifest_end_to_end(demo_workspace, no_network, monkeypatch):
    root = demo_workspace.root
    shutil.rmtree(root / "evidence")
    manifest = root / "manifests" / "demo.yaml"
    api.dump_manifest(api.init_manifest(), manifest, root)

    async def drive() -> None:
        app = FetcherApp(root_override=str(root))
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()

            # Welcome: the demo manifest is listed, empty and never run.
            assert isinstance(app.screen, WelcomeScreen)
            [listed] = _rows(app.screen.query_one("#welcome-manifests", DataTable))
            assert listed[0] == "demo.yaml" and listed[1] == "0" and listed[3] == "— never run"
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, WorkspaceScreen)

            # Manifest: add demo_hello through the picker; the edit is saved.
            page = await _tab(pilot, "2", ManifestPage)
            assert "manifest is empty" in _text(page.query_one("#manifest-empty-hint"))
            await pilot.press("a")
            assert isinstance(app.screen, MultiPickerModal)
            await pilot.press(*"demo_hello", "enter")
            assert "demo_hello" in _text(app.screen.query_one("#multi-pick-chosen"))
            await pilot.press("ctrl+s")
            await pilot.pause()
            assert [row[0] for row in _rows(page.query_one("#manifest-entries", DataTable))] == ["demo_hello"]
            assert _text(page.query_one("#manifest-issues")) == "✓ manifest is runnable"
            shipped = yaml.safe_load((REPO_ROOT / "examples" / "demo.yaml").read_text())
            assert yaml.safe_load(manifest.read_text())["run"] == shipped["run"]

            # Run: execute it for real.
            run = await _tab(pilot, "3", RunPage)
            await pilot.press("ctrl+r")
            banner = run.query_one("#run-banner")
            await _until(pilot, lambda: "run complete" in _text(banner), "the run")
            assert _text(banner).startswith("✓ run complete — ok=True")
            [status] = _rows(run.query_one("#run-status", DataTable))
            assert status[:3] == ["demo_hello", "single", "OK"]
            assert _text(run.query_one("#run-summary")).endswith("✓ 1   ✗ 0   ⊘ 0")
            [run_dir] = (root / "evidence").glob("run-*")

            # Evidence: the run and its file, then the enveloped evidence itself.
            evidence = await _tab(pilot, "4", EvidencePage)
            [listed_run] = _rows(evidence.query_one("#evidence-runs", DataTable))
            assert listed_run[0] == run_dir.name.removeprefix("run-")
            assert listed_run[2:] == ["1", "0"]
            await pilot.press("enter", "enter")
            assert isinstance(app.screen, PreviewModal)
            shown = _text(app.screen.query_one("#preview-text"))
            assert "demo_hello  v0.1.0  [demo]" in shown
            assert "status: success   exit 0" in shown
            assert "evidence set: EVD-DEMO-HELLO — Demo — Synthetic MFA Policy" in shown
            assert '"policy": "require-phishing-resistant-mfa"' in shown
            await pilot.press("escape")

            # Paramify: with no token the upload is refused before anything is sent.
            upload = await _tab(pilot, "5", UploadPage)
            ready = dict(row[:2] for row in _rows(upload.query_one("#evidence-summary", DataTable)))
            assert ready["selected run"] == listed_run[0]
            assert ready["result"] == "1/1 ok"
            assert ready["API token"] == "missing"
            assert ready["upload files"] == "1"
            assert upload.query_one("#upload-submit", Button).disabled

            # The scripts preview is a dry-run and needs no token.
            log = upload.query_one("#upload-log", RichLog)
            upload_banner = upload.query_one("#upload-banner")
            await pilot.press("p")
            await _until(pilot, lambda: "preview complete" in _text(upload_banner), "the scripts preview")
            assert "[create] demo_hello  set=EVD-DEMO-HELLO" in _log(log)
            assert _text(upload_banner) == "preview complete — create=1 update=0 drift=0 noop=0"
            await _until(pilot, lambda: _focused_in(upload), "focus back in the Paramify page")

            # Upload dry-run: the TUI has no switch, so fake a token and force dry_run=True.
            monkeypatch.setenv(UPLOAD_TOKEN_ENV, "unused")
            real_upload = api.upload_run
            monkeypatch.setattr(api, "upload_run", lambda *a, **kw: real_upload(*a, **{**kw, "dry_run": True}))
            await pilot.press("ctrl+r")
            assert not upload.query_one("#upload-submit", Button).disabled
            await pilot.press("ctrl+u")
            assert isinstance(app.screen, ConfirmModal)
            assert _text(app.screen.query_one("#modal-title")) == (
                "Upload 1 evidence file(s) to https://app.paramify.com/api/v0?"
            )
            await pilot.press("y")
            await _until(pilot, lambda: "upload complete" in _text(upload_banner), "the upload dry-run")
            assert "(dry-run)" in _log(log)
            assert "[SKIP] demo_hello.json  would_upload  set=EVD-DEMO-HELLO" in _log(log)
            assert _text(upload_banner) == "evidence upload complete — uploaded=0 duplicates=0 errors=0"
            assert not (run_dir / "upload_log.json").exists()

    asyncio.run(asyncio.wait_for(drive(), 120))
