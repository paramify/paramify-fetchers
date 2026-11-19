"""The timestamp the framework and uploaders write in every log, lock and record."""
from datetime import datetime, timezone


def utc_now() -> str:
    """Now in UTC, to the second: `2026-11-18T19:28:16Z`."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
