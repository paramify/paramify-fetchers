"""Pure transforms: Paramify values in, Purview cell values out.

No I/O, no API, no workbook — so every rule below is unit-testable offline and
the tests are the specification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from config import (
    CELL_CHAR_LIMIT,
    STATUS_MAP,
    TEST_STATUS_ALLOWED,
)


@dataclass
class CellUpdate:
    """One proposed change to one cell, with the reason it was or was not made."""

    column: str
    old: Any
    new: Any
    written: bool
    reason: Optional[str] = None


@dataclass
class RowPlan:
    """What this tool intends to do to one Action Update row."""

    row: int
    action_id: str
    action_name: str
    updates: list[CellUpdate] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: Things written that a reviewer should know about, each tagged with a
    #: `kind` so the report can bucket them. An untyped list meant every
    #: advisory landed in whichever bucket the report happened to name.
    advisories: list[dict[str, str]] = field(default_factory=list)

    def advise(self, kind: str, message: str) -> None:
        self.advisories.append({"kind": kind, "message": message})

    @property
    def wrote_anything(self) -> bool:
        return any(u.written for u in self.updates)


# --------------------------------------------------------------------------- #
# Implementation Status
# --------------------------------------------------------------------------- #

def map_status(paramify_status: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Paramify status -> Purview enum. Returns (value, reason_if_unmapped).

    Accepts either spelling, because the value arrives from two places that do
    not agree: the Solution Capability API returns the enum (`NOT_IMPLEMENTED`)
    while an audit-log change entry may carry the display form
    (`Not Implemented`). Spaces and hyphens normalize to underscores so both
    resolve to the same key.
    """
    raw = (paramify_status or "").strip().upper()
    key = re.sub(r"[\s-]+", "_", raw)
    if not key:
        return None, "the solution capability reports no implementation status"
    mapped = STATUS_MAP.get(key)
    if mapped:
        return mapped, None
    if key == "PARTIALLY_IMPLEMENTED":
        return None, (
            "Paramify reports PARTIALLY_IMPLEMENTED and Purview has no partial state; "
            "every candidate mapping would overstate or understate the posture, so this "
            "row needs a human decision"
        )
    if key == "NOT_SET":
        return None, (
            "Paramify reports NOT_SET — the capability has not been assessed, so writing "
            "a status would assert an assessment that has not happened"
        )
    return None, f"unrecognized Paramify implementation status {paramify_status!r}"


def normalize_test_status(value: Any) -> str:
    """The cell's Test Status, with a blank cell reported as "" (absent).

    `None` is a real selectable Test Status value in Purview, distinct from an
    empty cell, so the two are NOT collapsed here — the allowed-value table
    treats "None" as a value and says nothing about absence.
    """
    return "" if value is None else str(value).strip()


def check_test_status(
    new_status: str, existing_test_status: Any, *, strict: bool = False
) -> tuple[Optional[str], Optional[str]]:
    """Whether writing `new_status` is safe for this row.

    Returns (blocking_reason, advisory_reason) — at most one is set.

    The rules tab constrains Test Status by Implementation Status. Two cases:

    * **A non-blank Test Status outside the allowed set is blocking.** Writing
      NotImplemented onto a row whose Test Status is `Passed` produces a
      workbook Purview rejects, and clearing the pass to make it fit would
      destroy the client's own test record. So the row is skipped for a human.

    * **A blank Test Status is ambiguous and is allowed by default.** The table
      lists permitted *values*; an empty cell is an absence, not a value, and
      nothing in the tab says a status may not be recorded before a test is. The
      export cannot settle it either way — this client always set both together
      — so the permissive reading is taken, every such row is counted as
      `unverified_blank_test_status` in the run report, and `--strict-test-status`
      refuses them instead. The first re-upload confirms the reading cheaply.
    """
    current = normalize_test_status(existing_test_status)
    allowed = TEST_STATUS_ALLOWED.get(new_status, set())
    if current and current in allowed:
        return None, None
    if current:
        return (
            f"Implementation Status {new_status!r} permits Test Status "
            f"{sorted(allowed)} but this row has {current!r}"
        ), None
    # Blank Test Status.
    if "None" in allowed:
        return None, None
    if strict:
        return (
            f"--strict-test-status: {new_status!r} permits Test Status "
            f"{sorted(allowed)} and this row's Test Status is blank"
        ), None
    return None, (
        f"Test Status is blank and {new_status!r} does not list \"None\" among its "
        f"permitted values {sorted(allowed)}; written on the reading that a blank "
        "cell is an absence rather than a value"
    )


# --------------------------------------------------------------------------- #
# Implementation Date
# --------------------------------------------------------------------------- #

#: The format Purview's own export emits, and therefore the one it round-trips:
#: M/D/YYYY H:MM:SS with no zero padding on month, day or hour.
def format_purview_datetime(value: datetime) -> str:
    return (
        f"{value.month}/{value.day}/{value.year} "
        f"{value.hour}:{value.minute:02d}:{value.second:02d}"
    )


_DATE_PATTERNS = (
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%m/%d/%Y",
)


def parse_purview_datetime(value: Any) -> Optional[datetime]:
    """Read a date back out of a cell. Returns None if it is absent or unparseable."""
    if isinstance(value, datetime):
        return value
    text = "" if value is None else str(value).strip()
    if not text:
        return None
    for pattern in _DATE_PATTERNS:
        try:
            return datetime.strptime(text, pattern)
        except ValueError:
            continue
    return None


def parse_iso8601(value: Any) -> Optional[datetime]:
    """Parse an audit-log timestamp. Tolerates the `Z` suffix and milliseconds."""
    text = "" if value is None else str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def to_local(value: datetime, tzinfo) -> datetime:
    """Render a UTC audit timestamp in the reporting timezone.

    Purview's date cells carry no timezone, so the choice is invisible in the
    workbook and has to be recorded in the run report instead.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(tzinfo)


def check_test_date(
    new_impl_date: datetime, existing_test_date: Any
) -> Optional[str]:
    """Purview requires Test Date >= Implementation Date. Report a violation."""
    existing = parse_purview_datetime(existing_test_date)
    if existing is None:
        return None
    naive_new = new_impl_date.replace(tzinfo=None)
    if existing >= naive_new:
        return None
    return (
        f"the derived Implementation Date {format_purview_datetime(naive_new)} is after "
        f"this row's Test Date {format_purview_datetime(existing)}, which Purview rejects"
    )


# --------------------------------------------------------------------------- #
# Implementation Notes
# --------------------------------------------------------------------------- #

#: Function types whose narrative is worth carrying, most authoritative first.
NARRATIVE_TYPE_ORDER = ("PROVIDER", "CUSTOMER", "SHARED")


#: Paramify renders a mention as `@Name` in its plain-text form. The `@` is
#: Paramify's own markup convention and means nothing in a Purview notes field,
#: so it is removed while the name it introduces is kept.
#:
#: The lookbehind protects an email address: in `user@example.com` the `@` is
#: preceded by a word character, so it is left alone.
_MENTION_AT = re.compile(r"(?<![\w.])@(?=[A-Za-z0-9])")

#: Paramify stores narratives twice — a rich-text document
#: (`[{"type":"p","children":[{"type":"mention", ...}]}]`) and a flattened
#: plain-text rendering. The API serves the flattened one, which is what this
#: tool expects. If the rich-text form ever arrives instead, it must NOT be
#: written: raw JSON in a client's compliance workbook is worse than a gap.
_RICH_TEXT_DOC = re.compile(r'^\s*\[?\s*\{\s*"(?:type|children|text)"\s*:')


def looks_like_rich_text(value: str) -> bool:
    """Whether this is Paramify's rich-text document rather than plain text."""
    return bool(_RICH_TEXT_DOC.match(str(value or "")))


def plain_text(value: str) -> str:
    """Normalize a Paramify narrative to plain English for a Purview cell.

    Two operations, both conservative:

    * the `@` introducing a mention is dropped, keeping the name, so
      "@Microsoft 365 … retains audit records" reads as ordinary prose;
    * whitespace is tidied — runs of spaces collapsed, lines trimmed, more than
      one blank line reduced to one, CRLF normalized.

    Paragraph breaks survive: they are meaningful, and Excel renders them.
    Nothing else is stripped. Scanning all 463 narratives in this program found
    no HTML, markdown, tabs, double spaces or non-ASCII characters, so removing
    those speculatively would only risk mangling wording it was meant to keep.
    """
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    text = _MENTION_AT.sub("", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = "\n".join(line.strip() for line in text.split("\n"))
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def render_notes(functions: list[dict[str, Any]]) -> tuple[Optional[str], list[str]]:
    """Build the Implementation Notes cell from a SolCap's function narratives.

    Returns (text, contributing_function_names). `None` means the capability has
    no narrative — and the caller must then leave the cell ALONE rather than
    write an empty string, because Purview's own rules say a written value
    overwrites, and blanking a client's note is data loss.
    """
    entries: list[tuple[int, str, str]] = []
    for function in functions or []:
        raw = function.get("narrative") or ""
        if looks_like_rich_text(raw):
            # Refuse rather than attempt to flatten: a half-parsed rich-text
            # document in a compliance note is worse than no note.
            continue
        narrative = plain_text(raw)
        if not narrative:
            continue
        kind = str(function.get("type") or "").strip().upper()
        rank = (
            NARRATIVE_TYPE_ORDER.index(kind)
            if kind in NARRATIVE_TYPE_ORDER
            else len(NARRATIVE_TYPE_ORDER)
        )
        entries.append((rank, str(function.get("name") or kind or "Function"), narrative))
    if not entries:
        return None, []

    entries.sort(key=lambda item: item[0])
    if len(entries) == 1:
        text = entries[0][2]
    else:
        text = "\n\n".join(f"{name}: {narrative}" for _, name, narrative in entries)

    if len(text) > CELL_CHAR_LIMIT:
        marker = " […truncated]"
        text = text[: CELL_CHAR_LIMIT - len(marker)] + marker
    return text, [name for _, name, _ in entries]
