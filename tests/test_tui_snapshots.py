"""SVG snapshots of every TUI screen and key modal; refresh with --snapshot-update."""

from __future__ import annotations

import asyncio
from datetime import datetime
from types import SimpleNamespace

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")
pytest.importorskip("pytest_textual_snapshot", reason="snapshot tests need the 'snapshots' extra")

from textual.widgets import Input  # noqa: E402

from framework import api  # noqa: E402
from framework.tui.app import FetcherApp  # noqa: E402
from framework.tui.components import chrome  # noqa: E402
from framework.tui.screens import welcome  # noqa: E402

MANIFEST = "manifests/demo.yaml"


class _Frozen(datetime):
    """An hour after the pinned demo run (conftest.DEMO_RUN_ID)."""

    @classmethod
    def now(cls, tz=None):
        return cls(2026, 1, 1, 1, 0, 0, tzinfo=tz)


@pytest.fixture
def shot(snap_compare, demo_workspace, no_network, monkeypatch, tui_size):
    """Open the app on MANIFEST (or the welcome screen for None), press keys, compare.

    Each step is a key, or a tuple of keys typed in one go and settled once."""
    monkeypatch.setattr(chrome, "datetime", _Frozen)
    monkeypatch.setattr(welcome, "datetime", _Frozen)
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(welcome, "time", SimpleNamespace(monotonic=lambda: clock.now))

    async def settle(pilot) -> None:
        app = pilot.app
        await asyncio.wait_for(app.workers.wait_for_complete(), 30)
        # Workers post their results; pause() drains them, then idle sizes the tables.
        await pilot.pause()
        await pilot.pause()
        # Jump each welcome animation to its settled frame, however late it mounted.
        for screen in app.screen_stack:
            if isinstance(screen, welcome.WelcomeScreen):
                clock.now = screen._t0 + 10.0
                screen._tick()
        for field in app.screen.query(Input):
            field.cursor_blink = False
        await pilot.pause()

    def compare(*steps: str | tuple, manifest: str | None = MANIFEST) -> bool:
        app = FetcherApp(manifest_path=manifest, root_override=str(demo_workspace.root))

        async def run_before(pilot) -> None:
            await settle(pilot)
            for step in steps:
                await pilot.press(*((step,) if isinstance(step, str) else step))
                await settle(pilot)

        return snap_compare(app, terminal_size=tui_size, run_before=run_before)

    return compare


def test_welcome(shot):
    assert shot(manifest=None)


def test_welcome_new_manifest_form(shot):
    assert shot("n", manifest=None)


def test_workspace(shot):
    assert shot()


def test_workspace_switch_manifest_picker(shot):
    assert shot("m")


def test_fetchers_catalog_detail(shot):
    assert shot("slash", tuple("demo_hello"), "down", "down", "down", "escape")


def test_fetchers_manifest_entry(shot):
    assert shot("1", "tab")


def test_fetchers_empty_manifest(shot, demo_workspace):
    root = demo_workspace.root
    api.dump_manifest(api.init_manifest(), root / "manifests" / "empty.yaml", root)
    assert shot("1", manifest="manifests/empty.yaml")


def test_fetchers_add_from_catalog(shot, demo_workspace):
    root = demo_workspace.root
    api.dump_manifest(api.init_manifest(), root / "manifests" / "empty.yaml", root)
    assert shot("slash", tuple("demo_hello"), "down", "down", "down", "escape", "a",
                manifest="manifests/empty.yaml")


def test_manifest_remove_confirm(shot):
    assert shot("1", "tab", "x")


def test_manifest_preview(shot):
    assert shot("1", "tab", "p")


def test_run_complete(shot, demo_workspace, monkeypatch):
    def replay(manifest, root, on_event=None, manifest_path=None):
        for event in demo_workspace.run_events:
            on_event(event)

    monkeypatch.setattr(api, "run", replay)
    assert shot("2", "ctrl+r")


def test_evidence(shot):
    assert shot("3")


def test_evidence_file_preview(shot):
    assert shot("3", "enter", "enter")


def test_paramify_no_token(shot):
    """The demo workspace has no token: the page reads nothing and says why."""
    assert shot("4")


def _setup_status() -> dict:
    """Seven fetchers at different steps of setup, two capabilities linked."""
    def row(name, ref, set_id, arts, script, paired, pairs=(), ready=False):
        validators = [{"key": f"{name}-{i}", "role": "completeness" if i == 0 else "configuration",
                       "name": label, "paired": ok}
                      for i, (label, ok) in enumerate(paired)]
        return {"name": name, "kind": "evidence",
                "evidence_set": {"reference_id": ref, "name": name, "id": set_id, "exists": set_id is not None,
                                 "artifact_count": arts},
                "script": script, "validators": validators,
                "pairs": [{"pair_id": f"{name}-p{i}", "validator_key": f"{name}-{v}", "capability_id": c,
                           "function": fn} for i, (c, fn, v) in enumerate(pairs)],
                "ready": ready}

    complete = ("completeness: every certificate", True)
    return {
        "workspace": {"base_url": "https://app.paramify.com/api/v0", "base_url_source": "default", "token": True},
        "fetchers": [
            row("aws_acm_certificate_status", "EVD-ACM-CERT", "ev-1", 4, "in_sync",
                [complete, ("TLS 1.2+ only", True), ("no cert expires < 30d", True)],
                [("c1", "PROVIDER", 0), ("c1", "PROVIDER", 1), ("c2", "INTEGRATOR", 0), ("c2", "INTEGRATOR", 2)],
                ready=True),
            row("aws_access_analyzer_findings", "EVD-ACCESS-ANALYZER", "ev-2", 4, "in_sync",
                [("completeness: every region", True), ("no public findings", True)],
                [("c3", "PROVIDER", 0), ("c3", "PROVIDER", 1)], ready=True),
            row("aws_cloudtrail_status", "EVD-CLOUDTRAIL", "ev-3", 2, "in_sync", [], ready=True),
            row("github_branch_protection", "EVD-GITHUB-BRANCH-PROTECTION", "ev-4", 1, "in_sync",
                [("completeness: every repo", True), ("reviews required", True), ("force push blocked", False)]),
            row("github_dependabot_alerts", "EVD-GITHUB-DEPENDABOT-ALERTS", "ev-5", 0, "update",
                [("completeness: every repo", True), ("alerts on every repo", False)]),
            row("okta_authenticators", "EVD-OKTA-AUTHENTICATORS", "ev-6", 0, "create",
                [("completeness: every user", False), ("MFA enforced", False)]),
            row("knowbe4_training_enrollments", "EVD-SECURITY-AWARENESS-TRAINING", None, 0, "create",
                [("completeness: every employee", False)]),
        ],
        "capabilities": [
            {"id": "c1", "reference_id": "SC-SC-08", "name": "Encryption in transit", "functions": []},
            {"id": "c2", "reference_id": "SC-SC-12", "name": "Key management", "functions": []},
            {"id": "c3", "reference_id": "SC-AC-06", "name": "Least privilege", "functions": []},
        ],
        "pipelines_count": 2, "skipped": [], "errors": {},
    }


def test_paramify_by_fetcher(shot, monkeypatch):
    monkeypatch.setattr(api, "paramify_status", lambda *a, **k: _setup_status())
    monkeypatch.setattr(api, "list_artifacts", lambda set_id: [])
    assert shot("4")


def test_paramify_by_capability(shot, monkeypatch):
    monkeypatch.setattr(api, "paramify_status", lambda *a, **k: _setup_status())
    monkeypatch.setattr(api, "list_artifacts", lambda set_id: [])
    assert shot("4", "right_square_bracket")


def test_pipelines(shot):
    assert shot("5")
