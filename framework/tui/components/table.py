"""The DataTable every page uses: Textual's, redrawn once its columns are sized.

Textual widens an auto-width column on idle, after a row posted from a worker
may already have been painted at the old width. Its cell cache is keyed on a
counter that the widening does not bump, so that row kept the old width — the
scripts plan's fetcher column read "demo_he" for "demo_hello" — until a hover
or a resize happened to invalidate it. Dropping the render caches once the
widths are known costs one repaint per batch of new rows.
"""

from __future__ import annotations

from typing import Iterable

from textual.widgets import DataTable as _DataTable
from textual.widgets.data_table import RowKey


class DataTable(_DataTable):
    def _update_dimensions(self, new_rows: Iterable[RowKey]) -> None:
        super()._update_dimensions(new_rows)
        self.notify_style_update()
