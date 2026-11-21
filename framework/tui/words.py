"""Small wording helpers every TUI screen shares, so counts and places read the same everywhere."""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from framework.update_view import plural

__all__ = ["agree", "host", "plural"]


def agree(n: int, one: str, many: str) -> str:
    """The wording that agrees with a count: agree(1, "is", "are") -> "is"."""
    return one if n == 1 else many


def host(url: Optional[str], default: str = "Paramify") -> str:
    """The host a URL points at ("app.paramify.com"), for messages; the URL itself if it has none."""
    if not url:
        return default
    return urlparse(url).netloc or url
