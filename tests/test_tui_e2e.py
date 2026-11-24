"""Offline TUI paths: welcome → demo manifest → add demo_hello → run → evidence → upload dry-run;
and stack → owner → run → batch plan → upload dry-run against a fake Paramify."""

from __future__ import annotations

import asyncio
import json
import shutil
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from textual.widgets import Button, DataTable, RichLog  # noqa: E402

from framework import api  # noqa: E402
from framework.paramify_auth import UPLOAD_TOKEN_ENV  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.modals import ConfirmModal, PickerModal, PreviewModal  # noqa: E402
from framework.tui.screens.evidence import EvidencePage  # noqa: E402
from framework.tui.screens.fetchers import FetchersPage  # noqa: E402
from framework.tui.screens.manifest import ManifestPanel  # noqa: E402
from framework.tui.screens.paramify import ParamifyPage  # noqa: E402
from framework.tui.screens.run import RunPage  # noqa: E402
from framework.tui.screens.welcome import WelcomeScreen  # noqa: E402
from framework.tui.screens.workspace import WorkspaceScreen  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]


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


def test_demo_manifest_end_to_end(demo_workspace, no_network, monkeypatch, tui_size):
    root = demo_workspace.root
    shutil.rmtree(root / "evidence")
    manifest = root / "manifests" / "demo.yaml"
    api.dump_manifest(api.init_manifest(), manifest, root)

    async def drive() -> None:
        app = FetcherApp(root_override=str(root))
        async with app.run_test(size=tui_size) as pilot:
            await pilot.pause()

            # Welcome: the demo manifest is listed, empty and never run.
            assert isinstance(app.screen, WelcomeScreen)
            [listed] = _rows(app.screen.query_one("#welcome-manifests", DataTable))
            assert listed[0] == "demo.yaml" and listed[1] == "0" and listed[3] == "— never run"
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, WorkspaceScreen)

            # Fetchers: find demo_hello in the catalog and add it with a; the edit is saved.
            page = await _tab(pilot, "1", FetchersPage)
            assert "Press a on a fetcher to add it." in _text(page.query_one("#manifest-empty-hint"))
            await pilot.press("slash", *"demo_hello", "escape")
            await pilot.pause()
            tree = page.query_one("#catalog-tree")
            for _ in range(12):  # past the kind and platform headings to the fetcher
                if tree.cursor_node is not None and isinstance(tree.cursor_node.data, dict):
                    break
                await pilot.press("down")
                await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            assert str(tree.cursor_node.label) == "[x] demo_hello"
            assert [row[0] for row in _rows(page.query_one("#manifest-entries", DataTable))] == ["demo_hello"]
            # Ready to run; the line may go on to name an upload-only variable (the upload token).
            assert _text(page.query_one("#manifest-issues")).startswith("✓ ready to run")
            shipped = yaml.safe_load((REPO_ROOT / "examples" / "demo.yaml").read_text())
            assert yaml.safe_load(manifest.read_text())["run"] == shipped["run"]

            # Run: execute it for real.
            run = await _tab(pilot, "2", RunPage)
            await pilot.press("ctrl+r")
            banner = run.query_one("#run-banner")
            await _until(pilot, lambda: "Run complete." in _text(banner), "the run")
            assert _text(banner).startswith("✓ Run complete.")
            [status] = _rows(run.query_one("#run-status", DataTable))
            assert status[:3] == ["demo_hello", "single", "OK"]
            assert _text(run.query_one("#run-summary")).endswith("✓ 1   ✗ 0   ⊘ 0")
            [run_dir] = (root / "evidence").glob("run-*")

            # Evidence: the run and its file, then the enveloped evidence itself.
            evidence = await _tab(pilot, "3", EvidencePage)
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

            # Paramify: with no token the page says why, and the syncs and upload stay off.
            page = await _tab(pilot, "5", ParamifyPage)
            summary = page.query_one("#pf-summary")
            await _until(pilot, lambda: "No Paramify API token" in _text(summary), "the status read")
            [row] = _rows(page.query_one("#pf-grid", DataTable))
            assert row[0] == "demo_hello"
            assert not any(page.check_action(a, ()) for a in ("sync_scripts", "sync_validators", "upload_run"))
            # Here u is the page's own key, switched off: it must not fall through to the app's update.
            planned = []
            monkeypatch.setattr(api, "update_plan", lambda root: planned.append(root) or {"ok": False, "errors": []})
            await pilot.press("u")
            await pilot.pause()
            await app.workers.wait_for_complete()
            assert planned == [] and type(app.screen).__name__ != "UpdateScreen"

            # Upload dry-run: the TUI has no switch, so fake a token and force dry_run=True.
            monkeypatch.setenv(UPLOAD_TOKEN_ENV, "unused")
            # The fake token must not reach a real workspace: each status read fails fast.
            def offline(*a, **kw):
                raise RuntimeError("offline in this test")

            for read in ("list_evidence_sets", "list_capabilities", "scripts_sync"):
                monkeypatch.setattr(api, read, offline)
            real_upload, real_plan = api.upload_run, api.plan_upload
            # The confirm plans online when a token resolves; this one is fake, so plan offline.
            monkeypatch.setattr(api, "plan_upload", lambda *a, **kw: real_plan(*a, **{**kw, "online": False}))
            monkeypatch.setattr(api, "upload_run", lambda *a, **kw: real_upload(*a, **{**kw, "dry_run": True}))
            await pilot.press("ctrl+r")
            await _until(pilot, lambda: page.check_action("upload_run", ()), "the token to show")
            await pilot.press("u")
            await _until(pilot, lambda: isinstance(app.screen, ConfirmModal), "the upload confirm")
            confirm = _text(app.screen.query_one("#modal-title"))
            assert "demo_hello: 1 file to EVD-DEMO-HELLO" in confirm  # the plan's delivery line
            assert confirm.endswith("Upload 1 file to app.paramify.com?")
            await pilot.press("y")
            activity = page.query_one("#pf-activity")
            log = page.query_one("#pf-log", RichLog)
            await _until(pilot, lambda: "Dry run: nothing uploaded" in _text(activity), "the upload dry-run")
            assert "(dry-run)" in _log(log)
            assert "[SKIP] demo_hello.json  would_upload  → EVD-DEMO-HELLO" in _log(log)
            assert _text(activity) == "Dry run: nothing uploaded."
            assert not (run_dir / "upload_log.json").exists()

    asyncio.run(asyncio.wait_for(drive(), 120))


async def _pick(pilot, button: str, typed: str) -> list:
    """Click a picker button, type a filter and take the one match; return the options shown."""
    app = pilot.app
    await pilot.click(button)
    await _until(pilot, lambda: isinstance(app.screen, PickerModal), f"the {button} picker")
    # Keys typed before the filter has focus go nowhere.
    await _until(pilot, lambda: getattr(app.focused, "id", None) == "picker-filter", "the picker's filter")
    options = [label for _, label in app.screen._options]
    await pilot.press(*typed, "enter")
    await _until(pilot, lambda: not isinstance(app.screen, PickerModal), f"the {button} picker to close")
    return options


def test_demo_stack_owner_run_and_batch_plan_end_to_end(demo_workspace, no_network, fake_paramify,
                                                        monkeypatch, tui_size):
    """Manifest → pick a stack and an owner from the workspace → run → the upload plan routes the
    entry to the owner's channel in a new batch → confirm. The Paramify workspace is tests/paramify_fake.py."""
    root = demo_workspace.root
    shutil.rmtree(root / "evidence")
    manifest = root / "manifests" / "demo.yaml"
    fake = fake_paramify
    prod = fake.add_stack("Prod")
    fake.add_stack("Staging")
    hello = fake.add_evidence("EVD-DEMO-HELLO", channels=[prod.id, prod.id], owners=["alice", "bob"],
                              name="Demo — Synthetic MFA Policy")
    today = date.today()
    for channel in hello.channels:
        fake.add_request(hello.id, channel.id, today - timedelta(days=5), today + timedelta(days=5))

    async def drive() -> None:
        app = FetcherApp(manifest_path=str(manifest), root_override=str(root))
        async with app.run_test(size=tui_size) as pilot:
            await pilot.pause()

            # Manifest: the stack and owner pickers list the workspace's; each choice is saved.
            page = await _tab(pilot, "1", FetchersPage)
            await pilot.press("tab")  # from the catalog to the manifest list
            await _until(pilot, lambda: _focused_in(page.query_one(ManifestPanel)), "focus in the manifest list")
            assert await _pick(pilot, "#manifest-stack", "Prod") == ["Prod  (st-1)", "Staging  (st-2)"]
            assert await _pick(pilot, "#manifest-owner", "bob") == ["alice  (1 evidence set)", "bob  (1 evidence set)"]
            assert str(page.query_one("#manifest-stack", Button).label) == "Prod"
            assert str(page.query_one("#manifest-owner", Button).label) == "bob"
            assert yaml.safe_load(manifest.read_text())["run"]["paramify"] == {
                "stack": "st-1", "stack_name": "Prod", "owner": "bob"}

            # Run: the run records the settings the upload will use.
            run = await _tab(pilot, "2", RunPage)
            await pilot.press("ctrl+r")
            banner = run.query_one("#run-banner")
            await _until(pilot, lambda: "Run complete." in _text(banner), "the run")
            assert _text(banner).startswith("✓ Run complete.")
            [run_dir] = (root / "evidence").glob("run-*")
            recorded = json.loads((run_dir / "_run_metadata.json").read_text())["paramify"]
            assert recorded == {"demo_hello": {"use": "demo_hello", "stack": "st-1", "stack_name": "Prod",
                                               "owner": "bob"}}

            # Paramify: the plan puts the entry in a new batch on bob's channel's request.
            # The page's status reads do not go through the fake: each fails fast instead.
            def offline(*a, **kw):
                raise RuntimeError("offline in this test")

            for read in ("list_evidence_sets", "list_capabilities", "scripts_sync"):
                monkeypatch.setattr(api, read, offline)
            page = await _tab(pilot, "5", ParamifyPage)
            await _until(pilot, lambda: page.check_action("upload_run", ()), "the token to show")
            real_upload = api.upload_run
            # The TUI has no dry-run switch: force it, so the confirm's yes sends nothing.
            monkeypatch.setattr(api, "upload_run", lambda *a, **kw: real_upload(*a, **{**kw, "dry_run": True}))
            await pilot.press("u")
            await _until(pilot, lambda: isinstance(app.screen, ConfirmModal), "the upload confirm")
            plan = str(app.screen._message).splitlines()
            assert not [line for line in plan if line.startswith("!")]  # the run matches the manifest
            assert plan == [
                "demo_hello: 1 file to AR-2 (stack Prod, channel CH-2): new batch (approved on submit)",
                "Also tags 1 evidence set.",
                "",
                "Upload 1 file to api.example.test?",
            ]
            await pilot.press("y")
            activity = page.query_one("#pf-activity")
            log = page.query_one("#pf-log", RichLog)
            await _until(pilot, lambda: "Dry run: nothing uploaded" in _text(activity), "the upload dry-run")
            assert "(dry-run)" in _log(log)
            assert "[SKIP] demo_hello.json  would_upload  → EVD-DEMO-HELLO" in _log(log)
            assert _text(activity) == "Dry run: nothing uploaded."
            assert not (run_dir / "upload_log.json").exists()
            assert [c for c in fake.calls if c[0] != "GET"] == []

    asyncio.run(asyncio.wait_for(drive(), 120))
