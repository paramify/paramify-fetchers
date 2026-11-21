"""Resource exclusions: rg:, location: and id: glob patterns that take whole Azure resources out of a fetcher's scope
while keeping them listed in the evidence, for resources outside the authorization boundary."""

from __future__ import annotations

import logging
import os
from fnmatch import fnmatchcase
from typing import Iterable, Optional

from azure_common import resource_group_from_id
from scope_exclusions import excluded_item, parse_patterns

ENV = "AZURE_RESOURCE_EXCLUSIONS"
KINDS = ("rg", "location", "id")


def _key(kind: Optional[str], value: Optional[str]) -> str:
    # Regions compare without case or spaces, so "East US 2" and eastus2 are one region.
    text = str(value or "").strip().lower()
    return text.replace(" ", "") if kind == "location" else text.rstrip("/")


def _split(pattern: str) -> tuple[Optional[str], str]:
    kind, sep, glob = pattern.partition(":")
    kind = kind.strip().lower()
    return (kind, _key(kind, glob)) if sep else (None, _key(None, pattern))


def plural(kind: str) -> str:
    return kind[:-1] + "ies" if kind.endswith("y") and kind[-2:-1] not in "aeiou" else kind + "s"


def _id_and_parents(resource_id: str) -> list[str]:
    """The id and each parent resource's id, so excluding a vault also excludes its keys."""
    parts = _key("id", resource_id).split("/")
    return ["/".join(parts[:end]) for end in range(len(parts), 0, -2) if end > 4]


class ResourceExclusions:
    """Answers whether a resource is excluded and by which pattern, and remembers which patterns ever matched."""

    def __init__(self, patterns: Iterable[str] = ()):
        self.patterns = list(patterns)
        self._keys = [_split(p) for p in self.patterns]
        self._matched: set = set()
        self._unread = False

    @classmethod
    def from_env(cls) -> "ResourceExclusions":
        return cls(parse_patterns(os.environ.get(ENV)))

    def __bool__(self) -> bool:
        return bool(self.patterns)

    def match(self, resource_id: Optional[str] = None, location: Optional[str] = None,
              resource_group: Optional[str] = None, record: bool = True) -> Optional[str]:
        """The first configured pattern matching the resource, else None. The resource group comes from the id when
        not given; a location: pattern can only match a resource that has a location. Every match counts as used,
        unless record is False (a check about a reference, not a resource being taken out)."""
        names = {
            "rg": [_key("rg", resource_group or resource_group_from_id(resource_id))],
            "location": [_key("location", location)],
            "id": _id_and_parents(resource_id) if resource_id else [],
        }
        first = None
        for pattern, (kind, glob) in zip(self.patterns, self._keys):
            if kind in names and glob and any(n and fnmatchcase(n, glob) for n in names[kind]):
                if record:
                    self._matched.add(pattern)
                first = first or pattern
        return first

    def match_own_id(self, resource_id: Optional[str]) -> Optional[str]:
        """The first id: pattern naming this resource itself, else None. A pattern that also matches a parent's id
        names the parent (* crosses /, so id:*/watchers/w* matches w's children too) and doesn't count."""
        key, *parents = _id_and_parents(resource_id) if resource_id else [""]
        first = None
        for pattern, (kind, glob) in zip(self.patterns, self._keys):
            if kind == "id" and glob and key and fnmatchcase(key, glob) \
                    and not any(fnmatchcase(p, glob) for p in parents):
                self._matched.add(pattern)
                first = first or pattern
        return first

    def invalid(self) -> list[str]:
        """Bare patterns, unknown prefixes and empty globs; each fails the run rather than leave a resource in scope."""
        return [p for p, (kind, glob) in zip(self.patterns, self._keys) if kind not in KINDS or not glob]

    def record_invalid(self, collector) -> None:
        for pattern in self.invalid():
            collector.record(f"config {ENV}", ValueError(
                f"resource exclusion pattern {pattern!r} needs one of the prefixes rg:, location: or id: "
                "and something after it"))

    def mark_unread(self) -> None:
        """A resource list was not read: no pattern was compared to it, so none can be called unmatched."""
        self._unread = True

    def unmatched(self) -> Optional[list[str]]:
        """The patterns that matched nothing, or None once a list was marked unread (or summary() saw one)."""
        return None if self._unread else [p for p in self.patterns if p not in self._matched]

    def split(self, items: list, kind: str, *, resource_id=lambda r: r.get("id"),
              location=lambda r: r.get("location"), resource_group=lambda r: r.get("resource_group"),
              name=lambda r: r.get("name")) -> tuple[list, list[dict]]:
        """(in-scope items, excluded entries); each entry names the item, its id, resource group and location, and
        the pattern that removed it."""
        kept, excluded = [], []
        for item in items:
            rid, loc, rg = resource_id(item), location(item), resource_group(item)
            pattern = self.match(rid, loc, rg) if self.patterns else None
            if pattern is None:
                kept.append(item)
            else:
                excluded.append(excluded_item(kind, name(item), pattern, "resource_matched", id=rid,
                                              resource_group=rg or resource_group_from_id(rid), location=loc))
        return kept, excluded

    def summary(self, excluded: list[dict], kinds: Iterable[str], in_scope: dict) -> dict:
        """The patterns as given, the ones that matched nothing, how many items of each kind were excluded, and how
        many of each stayed in scope (in_scope maps a plural name to a count, or to None when that list wasn't read,
        which leaves its excluded count None too, and the unmatched patterns None)."""
        if any(count is None for count in in_scope.values()):
            self.mark_unread()
        return {
            "resource_exclusion_patterns": list(self.patterns),
            "resource_exclusion_patterns_unmatched": self.unmatched(),
            **{f"excluded_{plural(kind)}": None if plural(kind) in in_scope and in_scope[plural(kind)] is None
               else sum(1 for e in excluded if e["kind"] == kind) for kind in kinds},
            **{f"in_scope_{name}": count for name, count in in_scope.items()},
        }

    def warn_unmatched(self, logger: logging.Logger) -> None:
        for pattern in self.unmatched() or ():
            logger.warning("resource exclusion pattern %r matched nothing", pattern)
