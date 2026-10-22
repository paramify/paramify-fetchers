"""A row painted before its DataTable sized the columns is redrawn at full width."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from textual.app import App, ComposeResult  # noqa: E402

from framework.tui.components.table import DataTable  # noqa: E402


class _OneTable(App):
    # A fixed height, like the scripts plan's 1fr: an auto-height table resizes as
    # rows arrive, and the resize happens to invalidate the stale cells.
    CSS = "DataTable { height: 4; }"

    def compose(self) -> ComposeResult:
        yield DataTable()


def test_a_row_painted_before_column_sizing_is_redrawn():
    async def drive() -> tuple:
        app = _OneTable()
        async with app.run_test(size=(60, 6)) as pilot:
            table = app.query_one(DataTable)
            table.add_column("fetcher")
            await pilot.pause()
            table.add_row("demo_hello")
            early = table.render_line(1).text  # before idle widens the column
            await pilot.pause()
            return early, table.render_line(1).text

    early, settled = asyncio.run(drive())
    # If Textual starts sizing columns before the first paint, components/table.py can go.
    assert "demo_hello" not in early, f"no longer reproduces: {early!r}"
    assert "demo_hello" in settled, f"the early paint stuck: {settled!r}"
