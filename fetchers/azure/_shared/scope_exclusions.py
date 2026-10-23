"""Scope exclusions: case-insensitive glob patterns that take named items out of a fetcher's verdicts while keeping them listed in the evidence."""

from __future__ import annotations

import logging
import os
import re
from fnmatch import fnmatchcase
from typing import Iterable, Optional

SEPARATORS = re.compile(r"[\s,]+")


def normalize(name: str) -> str:
    # DNS names compare without case or the root's trailing dot.
    return str(name).strip().lower().rstrip(".")


def split_kind(pattern: str) -> tuple[Optional[str], str]:
    """("route", "qa*") for "route:qa*"; (None, pattern) for a bare pattern, which matches host or record names only."""
    kind, sep, glob = pattern.partition(":")
    return (normalize(kind), normalize(glob)) if sep else (None, normalize(pattern))


def parse_patterns(raw: Optional[str]) -> list[str]:
    """Comma- or whitespace-separated globs, in configured order, duplicates (ignoring case) dropped."""
    patterns, seen = [], set()
    for part in SEPARATORS.split(raw or ""):
        key = normalize(part)
        if key and key not in seen:
            seen.add(key)
            patterns.append(part.strip())
    return patterns


class ScopeExclusions:
    """Answers whether a name is excluded and by which pattern, and remembers which patterns ever matched."""

    def __init__(self, patterns: Iterable[str] = ()):
        self.patterns = list(patterns)
        self._keys = [split_kind(p) for p in self.patterns]
        self._matched: set = set()

    @classmethod
    def from_env(cls, env_var: str) -> "ScopeExclusions":
        return cls(parse_patterns(os.environ.get(env_var)))

    def __bool__(self) -> bool:
        return bool(self.patterns)

    def match(self, *names: Optional[str], kind: Optional[str] = None) -> Optional[str]:
        """The first pattern of this kind (bare when None) matching any of the names, else None; every match counts as used."""
        keys = [normalize(n) for n in names if n]
        first = None
        for pattern, (pattern_kind, key) in zip(self.patterns, self._keys):
            if pattern_kind == kind and any(fnmatchcase(name, key) for name in keys):
                self._matched.add(pattern)
                first = first or pattern
        return first

    def unmatched(self) -> list[str]:
        return [p for p in self.patterns if p not in self._matched]

    def summary(self, excluded: list[dict], kinds: Iterable[str], in_scope: dict) -> dict:
        """The patterns, the ones that matched nothing, how many items of each kind were excluded, and how many of each
        stayed in scope (in_scope maps a plural name to a count), so a check can require some to remain."""
        return {
            "scope_exclusion_patterns": list(self.patterns),
            "scope_exclusion_patterns_unmatched": self.unmatched(),
            **{f"excluded_{kind}s": sum(1 for e in excluded if e["kind"] == kind) for kind in kinds},
            **{f"in_scope_{name}": count for name, count in in_scope.items()},
        }

    def warn_unmatched(self, logger: logging.Logger) -> None:
        for pattern in self.unmatched():
            logger.warning("scope exclusion pattern %r matched nothing", pattern)


def excluded_item(kind: str, name: Optional[str], pattern: Optional[str], reason: str = "name_matched", **context) -> dict:
    """One excluded item; `pattern` is None when the item is out of scope only because the items it serves are."""
    return {"kind": kind, "name": name, "pattern": pattern, "reason": reason, **context}
