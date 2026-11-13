"""Every page of the demo workspace fits 160x50, below the 180x50 the other TUI tests use."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from textual.widgets import Button, Checkbox, DataTable, TabbedContent  # noqa: E402

from framework.tui.app import FetcherApp  # noqa: E402

SMALL = (160, 50)


def _problems(pane) -> list:
    """Panels squeezed to their border or off the page, controls outside their panel,
    tables that need sideways scrolling."""
    problems = []
    panels = [p for p in pane.query(".panel") if p.display and all(a.display for a in p.ancestors)]
    for panel in panels:
        if panel.content_region.height < 1:
            problems.append(f"#{panel.id} is squeezed to its border: {panel.region}")
        elif not pane.region.contains_region(panel.region):
            problems.append(f"#{panel.id} runs off the page: {panel.region} not in {pane.region}")
    for control in [*pane.query(Button), *pane.query(Checkbox)]:
        box = next((a for a in control.ancestors if a in panels), pane)
        if control.display and not box.content_region.contains_region(control.region):
            problems.append(f"#{control.id} sits outside #{box.id}: {control.region}")
    for table in pane.query(DataTable):
        if table.display and table.max_scroll_x > 0:
            problems.append(f"#{table.id} is {table.max_scroll_x} column(s) too wide")
    return problems


@pytest.mark.parametrize("keys", [("1",), ("2",), ("3",), ("4",), ("5",)],
                         ids=["fetchers", "run", "evidence", "paramify", "pipelines"])
def test_page_fits_160x50(keys, demo_workspace, no_network):
    async def drive() -> list:
        app = FetcherApp(manifest_path="manifests/demo.yaml", root_override=str(demo_workspace.root))
        async with app.run_test(size=SMALL) as pilot:
            for key in keys:
                await pilot.press(key)
                await asyncio.wait_for(app.workers.wait_for_complete(), 30)
                await pilot.pause()
            await pilot.pause()
            return _problems(app.screen.query_one(TabbedContent).active_pane)

    assert asyncio.run(asyncio.wait_for(drive(), 60)) == []


def _fifty() -> dict:
    """A 50-fetcher status with long names, linked capabilities and every state."""
    rows = []
    for i in range(50):
        validators = [{"key": f"k{j}", "role": "configuration", "name": f"check {j}", "paired": j <= i % 4}
                      for j in range(4)]
        rows.append({
            "name": f"azure_defender_regulatory_compliance_{i:02d}", "kind": "evidence",
            "evidence_set": {"reference_id": f"EVD-AZURE-DEFENDER-REGULATORY-{i:02d}", "name": "x",
                             "id": f"ev-{i}" if i % 5 else None, "exists": bool(i % 5),
                             "artifact_count": i % 7},
            "script": ("in_sync", "update", "create", "drift")[i % 4], "validators": validators,
            "pairs": [{"pair_id": "p", "validator_key": "k0", "capability_id": "c1", "function": "PROVIDER"}],
            "ready": i % 3 == 0,
        })
    return {"workspace": {"base_url": "https://app.paramify.com/api/v0", "base_url_source": "default", "token": True},
            "fetchers": rows,
            "capabilities": [{"id": "c1", "reference_id": "SC-AC-06", "name": "Least privilege",
                              "functions": [{"type": "PROVIDER", "pairs": []}]}],
            "pipelines_count": 2, "skipped": [], "errors": {}}


@pytest.mark.parametrize("size", [SMALL, (120, 35)], ids=["160x50", "120x35"])
def test_paramify_page_holds_fifty_fetchers(size, demo_workspace, no_network, monkeypatch):
    from framework import api

    monkeypatch.setattr(api, "paramify_status", lambda *a, **k: _fifty())
    monkeypatch.setattr(api, "list_artifacts", lambda set_id: [])

    async def drive():
        app = FetcherApp(manifest_path="manifests/demo.yaml", root_override=str(demo_workspace.root))
        async with app.run_test(size=size) as pilot:
            await pilot.press("4")
            await asyncio.wait_for(app.workers.wait_for_complete(), 30)
            await pilot.pause()
            await pilot.pause()
            pane = app.screen.query_one(TabbedContent).active_pane
            grid = pane.query_one("#pf-grid", DataTable)
            return grid.size.height - 1, _problems(pane)

    rows, problems = asyncio.run(asyncio.wait_for(drive(), 60))
    assert rows >= 6, f"the grid shows only {rows} rows"
    if size == SMALL:
        assert problems == []
    else:
        assert [p for p in problems if "too wide" not in p] == []


SHORT = (80, 24)


def _paramify_at(size, monkeypatch, demo_workspace, keys=()):
    """Open the Paramify tab at `size` with the fifty-fetcher status, press `keys`,
    and return the pane's regions and problems."""
    from framework import api

    monkeypatch.setattr(api, "paramify_status", lambda *a, **k: _fifty())
    monkeypatch.setattr(api, "list_artifacts", lambda set_id: [])

    async def drive():
        app = FetcherApp(manifest_path="manifests/demo.yaml", root_override=str(demo_workspace.root))
        async with app.run_test(size=size) as pilot:
            await pilot.press("4")
            await asyncio.wait_for(app.workers.wait_for_complete(), 30)
            await pilot.pause()
            for key in keys:
                await pilot.press(key)
                await asyncio.wait_for(app.workers.wait_for_complete(), 30)
                await pilot.pause()
            for _ in range(4):  # the layout is measured over a few refreshes
                await pilot.pause()
            pane = app.screen.query_one(TabbedContent).active_pane
            shown = {w.id: w.region for w in pane.query("#pf-detail, #pf-activity-panel") if w.display}
            return pane.query_one("#pf-grid", DataTable).size.height - 1, shown, _problems(pane)

    return asyncio.run(asyncio.wait_for(drive(), 60))


def test_paramify_grid_keeps_its_rows_on_80x24(demo_workspace, no_network, monkeypatch):
    """On a short terminal the detail gives way: the grid keeps its rows, and
    nothing runs off the page (80 columns is too narrow for every column)."""
    rows, shown, problems = _paramify_at(SHORT, monkeypatch, demo_workspace)
    assert rows >= 7, f"the grid shows only {rows} rows"
    assert "pf-detail" not in shown, "a detail with no room to show anything"
    assert [p for p in problems if "too wide" not in p] == []


def test_paramify_log_fits_on_80x24(demo_workspace, no_network, monkeypatch):
    """An action's log still shows on a short terminal, inside the page, and the
    grid keeps some rows."""
    from framework import api

    monkeypatch.setattr(api, "scripts_sync", lambda root, config_path=None, **kw: {"ok": True})
    rows, shown, problems = _paramify_at(SHORT, monkeypatch, demo_workspace, keys=("s",))
    assert "pf-activity-panel" in shown, "the log of s did not show"
    assert rows >= 3, f"the grid shows only {rows} rows"
    assert [p for p in problems if "too wide" not in p] == []


def test_paramify_detail_comes_back_on_100x30(demo_workspace, no_network, monkeypatch):
    rows, shown, problems = _paramify_at((100, 30), monkeypatch, demo_workspace)
    assert "pf-detail" in shown and shown["pf-detail"].height >= 5
    assert rows >= 7
    assert [p for p in problems if "too wide" not in p] == []
