"""Cell values for an API-built CSV issue report, for any fetcher. Stdlib only.

Import it the same way as fetcher_status:

    sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
    from csv_cells import csv_safe   # noqa: E402
"""

from typing import Any

__all__ = ["csv_safe"]


def csv_safe(value: Any) -> Any:
    """A string that a spreadsheet would read as a formula, made literal.

    CSV quoting alone does not stop spreadsheet formula interpretation, so a cell
    that starts with =, +, - or @ (after any leading whitespace) gets a leading
    apostrophe. Every other value comes back unchanged.
    """
    if isinstance(value, str) and value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    return value
