"""Reading the Action Update tab and writing an updated copy of the workbook.

The input file is never modified. The other four tabs are carried through
untouched — this export has no formulas, no defined names and no data
validation, so an openpyxl load/save round-trip preserves their content.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

try:
    import openpyxl
except ImportError as exc:  # pragma: no cover - dependency, not logic
    raise SystemExit(
        "openpyxl is required to read the Purview workbook.\n"
        "    pip install -e .        (from the repo root)\n"
        "    pip install openpyxl    (or just the one package)"
    ) from exc

from config import REQUIRED_COLUMNS, SHEET, WRITABLE_COLUMNS
from mapping import RowPlan


class WorkbookError(RuntimeError):
    """The workbook is not the export this tool knows how to update."""


def load(path: Path):
    if not path.exists():
        raise WorkbookError(f"workbook not found: {path}")
    return openpyxl.load_workbook(path)


def header_index(sheet) -> dict[str, int]:
    """Column header -> 1-based column number.

    Matched by header text, never by position: a future export that adds or
    reorders a column would otherwise write silently into the wrong field.
    """
    headers = {}
    for cell in sheet[1]:
        if cell.value is not None:
            headers[str(cell.value).strip()] = cell.column
    missing = [c for c in REQUIRED_COLUMNS if c not in headers]
    if missing:
        raise WorkbookError(
            f"the {SHEET!r} tab is missing required column(s): {', '.join(missing)}. "
            "Export from the Assessments page, which produces the full 15-column tab."
        )
    return headers


def action_sheet(workbook):
    if SHEET not in workbook.sheetnames:
        raise WorkbookError(
            f"workbook has no {SHEET!r} tab (found: {', '.join(workbook.sheetnames)})"
        )
    return workbook[SHEET]


def iter_rows(sheet, headers: dict[str, int]) -> Iterator[tuple[int, dict[str, Any]]]:
    """Every data row as (row_number, {header: value})."""
    for row in range(2, sheet.max_row + 1):
        values = {name: sheet.cell(row=row, column=col).value
                  for name, col in headers.items()}
        if all(v is None or str(v).strip() == "" for v in values.values()):
            continue
        yield row, values


def apply(sheet, headers: dict[str, int], plans: list[RowPlan],
          writable: tuple[str, ...] = WRITABLE_COLUMNS) -> int:
    """Write the accepted updates. Returns the number of cells changed.

    `writable` is the structural guard. It widens only when the caller opted
    into --on-date-conflict, so a bug elsewhere still cannot reach Test Status,
    Documents or Assigned To.
    """
    written = 0
    for plan in plans:
        for update in plan.updates:
            if not update.written:
                continue
            if update.column not in writable:
                # Structural guard, not a comment: only three columns may ever
                # be touched, and a bug that widened that set would corrupt the
                # client's Test Status or Documents on re-upload.
                raise WorkbookError(
                    f"refusing to write read-only column {update.column!r}"
                )
            sheet.cell(row=plan.row, column=headers[update.column]).value = update.new
            written += 1
    return written


def save(workbook, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(path)
    return path
