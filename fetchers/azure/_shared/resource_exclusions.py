"""Resource scope: rg:, location:, id: and tag: glob patterns that take whole Azure resources out of a fetcher's scope
(resource_exclusions) or name the only ones in it (resource_inclusions), keeping every resource left out listed in
the evidence."""

from __future__ import annotations

import logging
import os
from fnmatch import fnmatchcase
from typing import Any, Callable, Iterable, Optional

from azure_common import resource_group_from_id, subscription_of
from scope_exclusions import excluded_item, parse_patterns

ENV = "AZURE_RESOURCE_EXCLUSIONS"
INCLUSIONS_ENV = "AZURE_RESOURCE_INCLUSIONS"
KINDS = ("rg", "location", "id", "tag")

# Q2: tag values compare without case, like every other pattern; tag names always do, as Azure treats them.
TAG_VALUES_IGNORE_CASE = True
# Q3: not-included resources listed per kind under results.excluded when the evidence is written; the rest are counted
# in not_included_<kind>s_not_listed.
NOT_INCLUDED_LIST_CAP = 1000
# Q4: log a warning when a kind has resources but inclusions leave none of them in scope.
WARN_NONE_INCLUDED = True

MISSING = object()
# A resource a readable index doesn't hold: deleted, or newer than the read. It stays in scope and is counted.
NOT_FOUND = object()
_log = logging.getLogger("resource_scope")


class ScopeOutcome(str):
    """match()'s answer for a resource no exclusion took out that is still out of scope; excluded_item reads it."""

    @property
    def scope_reason(self) -> str:
        return str(self)


NOT_INCLUDED = ScopeOutcome("not_included")
SCOPE_UNKNOWN = ScopeOutcome("scope_unknown")
OUT_OF_SCOPE_REASONS = (NOT_INCLUDED, SCOPE_UNKNOWN)


def _key(kind: Optional[str], value: Optional[str]) -> str:
    # Regions compare without case or spaces, so "East US 2" and eastus2 are one region.
    text = str(value or "").strip().lower()
    return text.replace(" ", "") if kind == "location" else text.rstrip("/")


def _unquoted_at(text: str, sep: str) -> int:
    """Index of the first `sep` outside double quotes, else -1."""
    quoted = False
    for i, ch in enumerate(text):
        if ch == '"':
            quoted = not quoted
        elif ch == sep and not quoted:
            return i
    return -1


def _tag_key(body: str) -> Optional[tuple]:
    """(name, value glob or None for any value) for Name=Glob, Name or "A name"="a value"; None when malformed."""
    if body.count('"') % 2:
        return None
    at = _unquoted_at(body, "=")
    name = (body if at < 0 else body[:at]).replace('"', "").strip().lower()
    if not name:
        return None
    if at < 0:
        return name, None
    value = body[at + 1:].replace('"', "").strip()
    return name, value.lower() if TAG_VALUES_IGNORE_CASE else value


def _split(pattern: str) -> tuple[Optional[str], Any]:
    kind, sep, glob = pattern.partition(":")
    kind = kind.strip().lower()
    if not sep:
        return None, _key(None, pattern)
    if kind == "tag":
        return kind, _tag_key(glob)
    return kind, _key(kind, glob.replace('"', ""))


def plural(kind: str) -> str:
    return kind[:-1] + "ies" if kind.endswith("y") and kind[-2:-1] not in "aeiou" else kind + "s"


def _id_and_parents(resource_id: str) -> list[str]:
    """The id and each parent resource's id, so excluding a vault also excludes its keys."""
    parts = _key("id", resource_id).split("/")
    return ["/".join(parts[:end]) for end in range(len(parts), 0, -2) if end > 4]


def _tag_hit(key: tuple, tags: dict) -> bool:
    name, glob = key
    if name not in tags:
        return False
    if glob is None:
        return True
    value = str(tags[name] if tags[name] is not None else "")
    return fnmatchcase(value.lower() if TAG_VALUES_IGNORE_CASE else value, glob)


def own_tags(raw: Any) -> Any:
    """A record's tags with lowercased names; {} for None (no tags), MISSING when the record doesn't carry them."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k).lower(): v for k, v in raw.items()}
    return MISSING


class ResourceScope:
    """Answers whether a resource is in scope: excluded by which pattern, not included, or unknown when a tag:
    pattern needs tags that can't be read. Remembers which patterns ever matched."""

    def __init__(self, patterns: Iterable[str] = (), inclusions: Iterable[str] = (), index=None):
        self.patterns = list(patterns)
        self.inclusions = list(inclusions)
        self._keys = [_split(p) for p in self.patterns]
        self._inclusion_keys = [_split(p) for p in self.inclusions]
        self._matched: set = set()
        self._included: set = set()
        self._unread = False
        self._index = index
        self._collector = None
        self._recorded = 0
        self._holding: dict = {}
        self._unknown: set = set()
        self._not_found: set = set()
        self._summarized = self._unknown_recorded = False
        self.uses_tags = any(k == "tag" for k, _ in self._keys + self._inclusion_keys)
        # Containers (the subscription, groups, management groups, the root) are judged apart when tags or inclusions
        # decide.
        self._containers = self.uses_tags or bool(self.inclusions)

    @classmethod
    def from_env(cls) -> "ResourceScope":
        return cls(parse_patterns(os.environ.get(ENV)), parse_patterns(os.environ.get(INCLUSIONS_ENV)))

    def __bool__(self) -> bool:
        return bool(self.patterns or self.inclusions)

    def _tag_index(self):
        if self._index is None:
            from tag_index import TagIndex  # lazy: built only when a tag: pattern or a container needs it

            self._index = TagIndex()
        return self._index

    def _tags(self, resource_id: Optional[str], record_tags: Any) -> Any:
        """The resource's own tags (a child the index doesn't hold takes its parent's), else the record's; NOT_FOUND
        when a readable index doesn't hold it, None when its subscription can't be read or parsed."""
        index = self._tag_index()
        tags = index.tags_of(resource_id) if resource_id else None
        self._flush()
        if tags is None and record_tags is not MISSING:
            return record_tags
        if tags is None and resource_id and index.entries(subscription_of(resource_id)) is not None:
            return NOT_FOUND
        return tags

    def _hits(self, keys, patterns, names, tags) -> tuple[list[str], bool, bool]:
        """The patterns matching, in configured order, and whether a tag: pattern went unjudged because the tags
        couldn't be read, or because the resource wasn't found."""
        hits, unknown, not_found = [], False, False
        for pattern, (kind, glob) in zip(patterns, keys):
            if kind == "tag":
                if not glob or tags is None:
                    continue
                current = tags()
                if current is None:
                    unknown = True
                elif current is NOT_FOUND:
                    not_found = True
                elif _tag_hit(glob, current):
                    hits.append(pattern)
            elif kind in names and glob and any(n and fnmatchcase(n, glob) for n in names[kind]):
                hits.append(pattern)
        return hits, unknown, not_found

    def match(self, resource_id: Optional[str] = None, location: Optional[str] = None,
              resource_group: Optional[str] = None, record: bool = True, tags: Any = MISSING) -> Optional[str]:
        """The first exclusion matching, else NOT_INCLUDED (inclusions set, none matches) or SCOPE_UNKNOWN (no readable
        subscription to judge its tags), else None. `tags` is the record's own, used when the index doesn't hold it.
        Matches count as used unless record is False (a check about a reference)."""
        names = {
            "rg": [_key("rg", resource_group or resource_group_from_id(resource_id))],
            "location": [_key("location", location)],
            "id": _id_and_parents(resource_id) if resource_id else [],
        }
        record_tags = own_tags(tags) if tags is not MISSING else MISSING
        if self._containers and resource_id:
            from tag_index import above_subscription, container_of

            container = container_of(resource_id)
            if container is not None and (container == _key("id", resource_id) or above_subscription(container)
                                          or not self.uses_tags or record_tags is MISSING
                                          and self._tag_index().held(resource_id) is False):
                return self._unknown_if(self._container(container, names, record), resource_id)
        cache: list = []

        def resource_tags():
            if not cache:
                cache.append(self._tags(resource_id, record_tags))
            return cache[0]

        answer, not_found = self._decide(names, resource_tags, record)
        if not_found and record:
            self._not_found.add(_key("id", resource_id))
        return self._unknown_if(answer, resource_id)

    def _unknown_if(self, answer: Optional[str], resource_id: Optional[str]) -> Optional[str]:
        if answer is SCOPE_UNKNOWN:
            self._unknown.add(_key("id", resource_id) or object())
        return answer

    def _decide(self, names: dict, tags, record: bool) -> tuple[Optional[str], bool]:
        """The answer, and whether it stands only because a tag: pattern couldn't judge a resource not found."""
        excluded_by, unknown, not_found = self._hits(self._keys, self.patterns, names, tags)
        included_by, inclusion_unknown, inclusion_not_found = \
            self._hits(self._inclusion_keys, self.inclusions, names, tags) if self.inclusions else ([], False, False)
        if record:
            self._matched.update(excluded_by)
            self._included.update(included_by)
        if excluded_by:
            return excluded_by[0], False
        if unknown:
            return SCOPE_UNKNOWN, False
        if not self.inclusions or included_by:
            return None, not_found
        if inclusion_unknown:
            return SCOPE_UNKNOWN, False
        return (None, True) if inclusion_not_found else (NOT_INCLUDED, False)

    def _container(self, container: str, names: dict, record: bool) -> Optional[str]:
        """Tags never take a container out; rg:, location: and id: exclusions do. With inclusions, one above the
        subscription stays (it reaches subscriptions this run can't see); the subscription or a group stays when an
        inclusion matches it, its own tags included, or while it holds an in-scope resource."""
        from tag_index import above_subscription, group_of

        excluded_by, *_ = self._hits(self._keys, self.patterns, names, None)
        if record:
            self._matched.update(excluded_by)
        if excluded_by:
            return excluded_by[0]
        if not self.inclusions or above_subscription(container):
            return None
        included_by, *_ = self._hits(self._inclusion_keys, self.inclusions, names,
                                    lambda: self._tag_index().tags_of(container))
        if record:
            self._included.update(included_by)
        if included_by:
            return None
        if group_of(container) == container and all(k == "rg" for k, _ in self._inclusion_keys):
            return NOT_INCLUDED  # under rg: alone, a group no pattern names holds nothing in scope
        holding = self._holders(subscription_of(container))
        self._flush()
        if holding is None:
            return SCOPE_UNKNOWN
        return None if container in holding else NOT_INCLUDED

    def _holders(self, subscription_id: Optional[str]) -> Optional[set]:
        """The resource groups and subscription holding an in-scope resource, judged on the index's own tags and
        regions; None when the subscription couldn't be read."""
        from tag_index import container_of, group_of

        if subscription_id not in self._holding:
            entries = self._tag_index().entries(subscription_id)
            holding = None if entries is None else set()
            for rid, (tags, location) in (entries or {}).items():
                if container_of(rid) == rid:
                    continue
                names = {"rg": [_key("rg", resource_group_from_id(rid))], "location": [_key("location", location)],
                         "id": _id_and_parents(rid)}
                if self._decide(names, lambda tags=tags: tags, record=False)[0] is None:
                    holding.add(f"/subscriptions/{subscription_id}")
                    holding.update(filter(None, [group_of(rid)]))
            self._holding[subscription_id] = holding
        return self._holding[subscription_id]

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

    def invalid_inclusions(self) -> list[str]:
        return [p for p, (kind, glob) in zip(self.inclusions, self._inclusion_keys) if kind not in KINDS or not glob]

    def record_invalid(self, collector) -> None:
        for env, label, bad in ((ENV, "exclusion", self.invalid()),
                                (INCLUSIONS_ENV, "inclusion", self.invalid_inclusions())):
            for pattern in bad:
                hint = ("tag:Name or tag:Name=value, in double quotes where a name or value holds a space, comma, "
                        "= or :" if _split(pattern)[0] == "tag" else
                        "one of the prefixes rg:, location:, id: or tag: and something after it")
                collector.record(f"config {env}", ValueError(f"resource {label} pattern {pattern!r} needs {hint}"))
        self._collector = collector
        self._flush()

    def _flush(self) -> None:
        """Hand index read failures, and once summarized any resource of unknown scope, to the collector, once it is
        known, so the run fails."""
        failures = self._index.failures if self._index is not None else []
        if self._collector is None:
            return
        for operation, exc in failures[self._recorded:]:
            self._collector.record(operation, exc)
        self._recorded = len(failures)
        if self._summarized and self._unknown and not self._unknown_recorded and not failures:
            self._unknown_recorded = True
            n = len(self._unknown)
            self._collector.record("resource scope", LookupError(
                f"{n} resource{'s' if n != 1 else ''} of unknown scope: no id, or an id outside any subscription"))

    def tags_unreadable(self) -> bool:
        return bool(self._index is not None and self._index.failures)

    def mark_unread(self) -> None:
        """A resource list was not read: no pattern was compared to it, so none can be called unmatched."""
        self._unread = True

    def unmatched(self) -> Optional[list[str]]:
        """The patterns that matched nothing, or None once a list was marked unread (or summary() saw one)."""
        return None if self._unread else [p for p in self.patterns if p not in self._matched]

    def inclusions_unmatched(self) -> Optional[list[str]]:
        return None if self._unread else [p for p in self.inclusions if p not in self._included]

    def split(self, items: list, kind: str, *, resource_id=lambda r: r.get("id"),
              location=lambda r: r.get("location"), resource_group=lambda r: r.get("resource_group"),
              name=lambda r: r.get("name"), tags: Callable = lambda r: r.get("tags", MISSING) if isinstance(r, dict) else MISSING,
              ) -> tuple[list, list[dict]]:
        """(in-scope items, excluded entries); each entry names the item, its id, resource group and location, and
        the pattern that removed it, or the reason not_included / scope_unknown."""
        kept, excluded = [], []
        for item in items:
            rid, loc, rg = resource_id(item), location(item), resource_group(item)
            pattern = self.match(rid, loc, rg, tags=tags(item) if self.uses_tags else MISSING) if self else None
            if pattern is None:
                kept.append(item)
                continue
            excluded.append(excluded_item(kind, name(item), pattern, "resource_matched", id=rid,
                                          resource_group=rg or resource_group_from_id(rid), location=loc))
        return kept, excluded

    def summary(self, excluded: list[dict], kinds: Iterable[str], in_scope: dict) -> dict:
        """The patterns as given, the ones that matched nothing, how many items of each kind were excluded, and how
        many of each stayed in scope (in_scope maps a plural name to a count, or to None when that list wasn't read,
        which leaves its excluded count None too, and the unmatched patterns None). With inclusions set, the same for
        them and the not-included counts; scope_unknown_<kind>s appear when tags for some resource couldn't be read.
        Unreadable tags leave every scope count None."""
        kinds = list(kinds)
        if any(count is None for count in in_scope.values()):
            self.mark_unread()
        self._summarized = True
        self._flush()
        failed = self.tags_unreadable()
        if failed:
            self.mark_unread()

        def unread(kind):
            return failed or plural(kind) in in_scope and in_scope[plural(kind)] is None

        def count(kind, reasons=None):
            return None if unread(kind) else sum(
                1 for e in excluded if e["kind"] == kind
                and (e.get("reason") not in OUT_OF_SCOPE_REASONS if reasons is None else e.get("reason") in reasons))

        out = {
            "resource_exclusion_patterns": list(self.patterns),
            "resource_exclusion_patterns_unmatched": self.unmatched(),
            **{f"excluded_{plural(kind)}": count(kind) for kind in kinds},
            **{f"in_scope_{name}": None if failed else n for name, n in in_scope.items()},
        }
        if self.inclusions:
            out["resource_inclusion_patterns"] = list(self.inclusions)
            out["resource_inclusion_patterns_unmatched"] = self.inclusions_unmatched()
            for kind in kinds:
                out[f"not_included_{plural(kind)}"] = count(kind, (NOT_INCLUDED,))
                # cap_not_included() sets it when the evidence is written.
                out[f"not_included_{plural(kind)}_not_listed"] = None if unread(kind) else 0
                if WARN_NONE_INCLUDED and out[f"not_included_{plural(kind)}"] and not in_scope.get(plural(kind), 1):
                    _log.warning("no %s are in scope: resource_inclusions match none of the %d read",
                                 plural(kind).replace("_", " "), out[f"not_included_{plural(kind)}"])
        if failed or any(e.get("reason") == SCOPE_UNKNOWN for e in excluded):
            out.update({f"scope_unknown_{plural(kind)}": count(kind, (SCOPE_UNKNOWN,)) for kind in kinds})
        if self.uses_tags:
        if self.tags_unreadable():
            return  # no pattern was judged
            out["scope_not_found_resources"] = None if failed else len(self._not_found)
            if self._not_found and not failed:
                _log.warning("%d resources Resource Graph didn't return (deleted, or newer than its read) are kept in "
                             "scope", len(self._not_found))
        return out

    def warn_unmatched(self, logger: logging.Logger) -> None:
        for pattern in self.unmatched() or ():
            logger.warning("resource exclusion pattern %r matched nothing", pattern)
        for pattern in (self.inclusions_unmatched() or ()) if self.inclusions else ():
            logger.warning("resource inclusion pattern %r matched nothing", pattern)


ResourceExclusions = ResourceScope


def cap_not_included(evidence: dict) -> None:
    """Lists at most NOT_INCLUDED_LIST_CAP not-included entries of each kind under results.excluded, in id order, and
    counts the rest in summary.not_included_<kind>s_not_listed. Exclusions are always listed in full."""
    results, summary = evidence.get("results"), evidence.get("summary")
    excluded = results.get("excluded") if isinstance(results, dict) else None
    if not isinstance(excluded, list) or not any(isinstance(e, dict) and e.get("reason") == NOT_INCLUDED
                                                 for e in excluded):
        return
    by_kind: dict = {}
    for e in excluded:
        if isinstance(e, dict) and e.get("reason") == NOT_INCLUDED:
            by_kind.setdefault(e.get("kind"), []).append(e)
    dropped = set()
    for kind, entries in by_kind.items():
        past = sorted(entries, key=lambda e: str(e.get("id") or e.get("name") or "").lower())[NOT_INCLUDED_LIST_CAP:]
        dropped.update(id(e) for e in past)
        if isinstance(summary, dict) and past:
            summary[f"not_included_{plural(str(kind))}_not_listed"] = len(past)
    results["excluded"] = [e for e in excluded if id(e) not in dropped]


def taken_out(answer: Any) -> bool:
    """Whether match()'s answer, or an excluded entry, is an exclusion a dependent resource follows; a parent left out
    only because no inclusion took it in never takes out a child that carries its own tags."""
    if isinstance(answer, dict):
        return answer.get("reason") not in OUT_OF_SCOPE_REASONS
    return answer is not None and not getattr(answer, "scope_reason", None)
