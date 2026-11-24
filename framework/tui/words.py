"""Small wording helpers every TUI screen shares, so counts and places read the same everywhere."""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from framework.contract import FREQUENCY_WORDS, SCHEDULE_FREQUENCIES
from framework.update_view import plural

__all__ = ["agree", "frequency", "host", "plural", "schedule", "FREQUENCY_CHOICES"]

#: (value, words) for a select, shortest first. NOT_SET is left out: a schedule always has a cadence.
FREQUENCY_CHOICES = [(v, FREQUENCY_WORDS[v]) for v in SCHEDULE_FREQUENCIES]


def frequency(value: Optional[str]) -> str:
    """DAILY -> "daily"; an unknown value is shown as it is."""
    return FREQUENCY_WORDS.get(str(value), str(value)) if value else "—"


def schedule(block: Optional[dict]) -> str:
    """run.schedule on one line: "daily at 02:00", "weekly", or "—" when unset."""
    if not block or not block.get("every"):
        return "—"
    at = block.get("at")
    return f"{frequency(block['every'])} at {at}" if at else frequency(block["every"])


def agree(n: int, one: str, many: str) -> str:
    """The wording that agrees with a count: agree(1, "is", "are") -> "is"."""
    return one if n == 1 else many


def host(url: Optional[str], default: str = "Paramify") -> str:
    """The host a URL points at ("app.paramify.com"), for messages; the URL itself if it has none."""
    if not url:
        return default
    return urlparse(url).netloc or url
