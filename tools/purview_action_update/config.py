"""Purview Action Update field rules, and the Paramify enum they must satisfy.

Every rule here is transcribed from the "How To Update Actions" tab of the
Compliance Manager export itself, not from documentation — that tab is the
authority Purview validates the re-upload against.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

#: Production. Staging is https://stage.paramify.com/api/v0 — select it with
#: PARAMIFY_API_BASE_URL or --base-url.
DEFAULT_BASE_URL = "https://app.paramify.com/api/v0"


def base_url() -> str:
    """Resolve the API base URL at CALL time, not import time.

    A module-level constant would be frozen before `.env` is loaded in main(),
    so a base URL set there would be silently ignored while an exported one
    worked — and pointing production credentials at the wrong host fails as a
    401 that looks exactly like a bad token.
    """
    return (os.environ.get("PARAMIFY_API_BASE_URL") or DEFAULT_BASE_URL).strip().rstrip("/")

#: The sheet the re-upload actually reads. The other four tabs are reference
#: only and must survive the round-trip untouched.
SHEET = "Action Update"

# --------------------------------------------------------------------------- #
# Columns, by header text. Matched by header rather than index so a future
# export that adds or reorders a column does not silently write to the wrong one.
# --------------------------------------------------------------------------- #

COL_ACTION_ID = "Action Id"
COL_ACTION_NAME = "Improvement Action Name"
COL_IMPL_STATUS = "Implementation Status"
COL_IMPL_DATE = "Implementation Date"
COL_IMPL_NOTES = "Implementation Notes"
COL_TEST_STATUS = "Test Status"
COL_TEST_DATE = "Test Date"
COL_TESTING_TYPE = "Testing Type"

REQUIRED_COLUMNS = (
    COL_ACTION_ID,
    COL_ACTION_NAME,
    COL_IMPL_STATUS,
    COL_IMPL_DATE,
    COL_IMPL_NOTES,
    COL_TEST_STATUS,
    COL_TEST_DATE,
    COL_TESTING_TYPE,
)

#: The three columns this tool is allowed to write. Anything else is read-only,
#: enforced in workbook.py — a stray write to Test Status or Documents would
#: destroy client data on re-upload.
WRITABLE_COLUMNS = (COL_IMPL_STATUS, COL_IMPL_DATE, COL_IMPL_NOTES)

#: Test Date and Test Status become writable ONLY under --on-date-conflict,
#: which exists because Purview requires Test Date >= Implementation Date: a
#: newer implementation date cannot be recorded while a stale test sits in
#: front of it. Widening the set is deliberate and opt-in.
WRITABLE_WITH_TEST_RESOLUTION = WRITABLE_COLUMNS + (COL_TEST_DATE, COL_TEST_STATUS)

# --------------------------------------------------------------------------- #
# Validated-field vocabularies
# --------------------------------------------------------------------------- #

PURVIEW_STATUSES = (
    "Implemented",
    "AlternativeImplementation",
    "NotImplemented",
    "Planned",
    "NotInScope",
)

#: Paramify's `implementationStatus` enum, from the v0 OpenAPI document.
PARAMIFY_STATUSES = (
    "NOT_SET",
    "IMPLEMENTED",
    "PARTIALLY_IMPLEMENTED",
    "PLANNED",
    "ALTERNATIVE_IMPLEMENTATION",
    "NOT_APPLICABLE",
    "NOT_IMPLEMENTED",
)

#: Paramify -> Purview. Two Paramify values deliberately have NO mapping:
#:
#:   PARTIALLY_IMPLEMENTED — Purview has no partial state. Every candidate
#:     (Planned, NotImplemented) is a lossy claim about the client's posture,
#:     and both force Test Status to None, which would wipe a recorded pass.
#:   NOT_SET — the capability has not been assessed; writing anything would
#:     assert an assessment that has not happened.
#:
#: Unmapped rows are skipped and reported, never guessed.
STATUS_MAP = {
    "IMPLEMENTED": "Implemented",
    "ALTERNATIVE_IMPLEMENTATION": "AlternativeImplementation",
    "NOT_IMPLEMENTED": "NotImplemented",
    "PLANNED": "Planned",
    "NOT_APPLICABLE": "NotInScope",
}

#: Which Test Status values each Implementation Status permits, verbatim from
#: the workbook's own rules tab. Writing a status that invalidates the row's
#: existing Test Status makes the whole re-upload fail validation.
TEST_STATUS_ALLOWED = {
    "Implemented": {
        "Passed", "FailedLowRisk", "FailedMediumRisk", "FailedHighRisk",
        "InProgress", "NotInScope",
    },
    "AlternativeImplementation": {
        "Passed", "FailedLowRisk", "FailedMediumRisk", "FailedHighRisk",
        "InProgress", "NotInScope",
    },
    "NotImplemented": {"None"},
    "Planned": {"None"},
    "NotInScope": {"NotInScope"},
}

#: "None" is a real, selectable Test Status value in Purview -- the only one
#: permitted alongside NotImplemented and Planned. It is NOT the same thing as
#: an empty cell, and mapping.test_status_conflict keeps the two apart.
EXPLICIT_NONE = "None"

#: Excel's hard per-cell character limit.
CELL_CHAR_LIMIT = 32767


# --------------------------------------------------------------------------- #
# Timezone for the date cells
# --------------------------------------------------------------------------- #

class ConfigError(RuntimeError):
    """A setting is unusable."""


#: US zones, for the --timezone help text. Any IANA name is accepted.
US_TIMEZONES = (
    "America/New_York", "America/Chicago", "America/Denver", "America/Phoenix",
    "America/Los_Angeles", "America/Anchorage", "Pacific/Honolulu",
)


def resolve_timezone(name: Optional[str] = None) -> tuple[Any, str, str]:
    """The zone to render Purview dates in. Returns (tzinfo, name, how).

    Defaults to the OPERATOR'S OWN zone rather than UTC, because only the date
    has to be right and UTC gets the date wrong for US users for part of every
    day: an audit event at 2026-09-29T02:00Z is still 28 September everywhere
    from Eastern to Hawaii, but rendered in UTC it would be written as 9/29.

    Resolution order, most explicit first:

      1. `name` (the --timezone flag); "local" forces detection
      2. the TZ environment variable
      3. the system zone from the /etc/localtime symlink — an IANA name, so
         historical timestamps get the right DST offset
      4. the OS's current UTC offset, correct for recent events
      5. UTC
    """
    from datetime import datetime
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    def attempt(candidate: str, how: str):
        try:
            return ZoneInfo(candidate), candidate, how
        except (ZoneInfoNotFoundError, ValueError):
            return None

    if name and name.strip().lower() != "local":
        found = attempt(name.strip(), "--timezone")
        if found:
            return found
        raise ConfigError(
            f"unknown timezone {name!r}. US zones: " + ", ".join(US_TIMEZONES)
        )

    if not name:
        env = (os.environ.get("TZ") or "").strip()
        if env:
            found = attempt(env, "TZ environment variable")
            if found:
                return found

    link = Path("/etc/localtime")
    try:
        if link.is_symlink():
            parts = link.resolve().parts
            if "zoneinfo" in parts:
                candidate = "/".join(parts[parts.index("zoneinfo") + 1:])
                found = attempt(candidate, "system zone (/etc/localtime)")
                if found:
                    return found
    except OSError:
        pass

    now = datetime.now().astimezone()
    if now.tzinfo is not None:
        return now.tzinfo, now.tzname() or "local", "system UTC offset"
    return ZoneInfo("UTC"), "UTC", "fallback"
