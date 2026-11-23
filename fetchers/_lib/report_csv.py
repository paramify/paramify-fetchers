"""CSV issue reports that a fetcher builds from an API: formula-safe cells, published whole or not at all.

Import it, don't copy it (see fetcher_status.py for the sys.path line). Stdlib only, like the rest of _lib.
"""

from __future__ import annotations

import csv
import errno
import tempfile
from pathlib import Path
from typing import Any, Iterable, List, Mapping


def csv_safe(value: Any) -> Any:
    """A leading apostrophe on a string a spreadsheet would read as a formula. CSV quoting alone does not stop it."""
    if isinstance(value, str) and value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def write_csv(dest: Path, columns: List[str], rows: Iterable[Mapping[str, Any]]) -> Path:
    """Write `rows` under a header of `columns` to `dest`, by rename only, and return `dest`.

    The staging file sits beside the output directory, not in it, so the runner (which records every new file in
    that directory) never sees a partial report, even after SIGKILL. A row with a key outside `columns` raises
    before anything is published. Fails with OSError when the rename would cross filesystems.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = dest.parent.resolve().parent
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=staging_dir,
                                     prefix=f".{dest.stem}-", suffix=".tmp", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            writer.writerows({key: csv_safe(value) for key, value in row.items()} for row in rows)
            stream.close()
            try:
                temporary.replace(dest)
            except OSError as exc:
                if exc.errno == errno.EXDEV:
                    raise OSError(exc.errno, "the output directory and its parent must be on one filesystem, "
                                             "so the report can be published by rename") from exc
                raise
        finally:
            temporary.unlink(missing_ok=True)
    return dest
