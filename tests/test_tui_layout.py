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
    panels = [p for p in pane.query(".panel") if p.display]
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


@pytest.mark.parametrize("keys", [("1",), ("2",), ("3",), ("4",), ("5",), ("5", "p")],
                         ids=["catalog", "manifest", "run", "evidence", "paramify", "paramify-preview"])
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
