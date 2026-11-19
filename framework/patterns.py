"""Pattern-list config fields (`type: patterns`): glob patterns written in the manifest, each with an optional reason,
checked against the prefixes the field declares and handed to the fetcher as one comma-separated string."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple

TYPE = "patterns"
SEPARATORS = re.compile(r"[\s,]+")
# A run with no space or comma outside double quotes, so tag:"Cost Center"=Shared is one pattern.
TOKEN = re.compile(r'(?:"[^"]*"?|[^\s,"])+')
QUOTED = re.compile(r'"[^"]*"')
ITEM_KEYS = ("pattern", "reason")
ENV_REF_REFUSAL = "${env:} references aren't read for a pattern list; write its patterns in the manifest"


@dataclass(frozen=True)
class Item:
    pattern: str
    reason: Optional[str] = None

    def as_manifest(self):
        return {"pattern": self.pattern, "reason": self.reason} if self.reason else self.pattern


def _split_string(raw: str) -> List[str]:
    # Read as the fetchers' own parser reads it: "route: qa-*" is one pattern.
    parts: List[str] = []
    for part in TOKEN.findall(raw):
        if parts and parts[-1].endswith(":"):
            parts[-1] += part
        else:
            parts.append(part)
    return parts


def parse(value: Any) -> Tuple[List[Item], List[str]]:
    """The items a manifest value holds (a list of patterns or {pattern, reason} maps, or one comma- or
    space-separated string) and the problems with its shape."""
    if value is None:
        return [], []
    if isinstance(value, str):
        return [Item(p) for p in _split_string(value)], []
    if not isinstance(value, list):
        return [], [f"expected a list of patterns, got {type(value).__name__}"]
    items: List[Item] = []
    problems: List[str] = []
    for n, raw in enumerate(value, 1):
        if isinstance(raw, str):
            if raw.strip():
                items.append(Item(raw.strip()))
            else:
                problems.append(f"item {n} is empty")
            continue
        if not isinstance(raw, dict):
            problems.append(f"item {n} is {type(raw).__name__}; write a pattern or a pattern/reason pair")
            continue
        pattern, reason = raw.get("pattern"), raw.get("reason")
        unknown = sorted(str(k) for k in raw if k not in ITEM_KEYS)
        if unknown:
            problems.append(f"item {n} has {', '.join(unknown)}; an item takes only pattern and reason")
        elif not isinstance(pattern, str) or not pattern.strip():
            problems.append(f"item {n} has no pattern")
        elif reason is not None and not isinstance(reason, str):
            problems.append(f"item {n}'s reason is {type(reason).__name__}; write it as text")
        else:
            items.append(Item(pattern.strip(), (reason or "").strip() or None))
    return items, problems


def check(items: Sequence[Item], prefixes: Sequence[str] = (), bare: bool = True) -> List[str]:
    """Each pattern the field's grammar refuses; the fetcher would fail the run on it, or it would never match."""
    known = ", ".join(f"{p}:" for p in prefixes)
    problems: List[str] = []
    seen = set()
    for item in items:
        p = item.pattern
        kind, sep, glob = p.partition(":")
        if "${env:" in p:
            problems.append(f"pattern {p!r}: {ENV_REF_REFUSAL}")
        elif p.count('"') % 2:
            problems.append(f"pattern {p!r} has an unclosed double quote")
        elif SEPARATORS.search(QUOTED.sub("", p)):
            problems.append(f"pattern {p!r} has a space or a comma; write each pattern as its own item, with no spaces "
                            "outside double quotes")
        elif sep and kind.lower() not in prefixes:
            takes = f"this field takes {known}" if prefixes else "this field takes no prefixes"
            problems.append(f"pattern {p!r} has the unknown prefix {kind + ':'!r}; {takes}")
        elif sep and not glob:
            problems.append(f"pattern {p!r} has nothing after its prefix")
        elif sep and kind.lower() == "tag" and not _tag_name(glob):
            problems.append(f"pattern {p!r} has no tag name; write tag:Name or tag:Name=value")
        elif not sep and not bare:
            problems.append(f"pattern {p!r} needs one of the prefixes {known}")
        elif p.lower() in seen:
            problems.append(f"pattern {p!r} is listed twice")
        seen.add(p.lower())
    return problems


def _tag_name(body: str) -> str:
    """The tag name before the first = outside double quotes, unquoted, as the fetchers read it."""
    quoted = False
    for i, ch in enumerate(body):
        if ch == '"':
            quoted = not quoted
        elif ch == "=" and not quoted:
            body = body[:i]
            break
    return body.replace('"', "").strip()


def problems(value: Any, prefixes: Sequence[str] = (), bare: bool = True) -> List[str]:
    """Everything wrong with a manifest value for a patterns field; empty when the runner can hand it over."""
    if is_reference(value):
        return [ENV_REF_REFUSAL]
    items, shape = parse(value)
    return shape + check(items, prefixes, bare)


def is_reference(value: Any) -> bool:
    return isinstance(value, str) and "${env:" in value


def count(value: Any) -> int:
    """How many patterns a value holds; a reference holds none, since it is never read."""
    return 0 if is_reference(value) else len(parse(value)[0])


def to_env(value: Any) -> str:
    """The comma-separated string the fetcher reads from its env var."""
    return ",".join(item.pattern for item in parse(value)[0])


def display(value: Any) -> str:
    return ", ".join(item.pattern for item in parse(value)[0])


def to_lines(value: Any) -> str:
    """A value as editor text: one pattern per line, with its reason after `  # `, its own lines joined by spaces."""
    def line(item: Item) -> str:
        reason = " ".join(part.strip() for part in (item.reason or "").splitlines() if part.strip())
        return f"{item.pattern}  # {reason}" if reason else item.pattern
    return "\n".join(line(i) for i in parse(value)[0])


def _unquoted_hash(line: str) -> int:
    quoted = False
    for i, ch in enumerate(line):
        if ch == '"':
            quoted = not quoted
        elif ch == "#" and not quoted:
            return i
    return -1


def from_lines(text: str) -> Tuple[List[Item], List[str]]:
    """Editor text back into items: a line is `pattern` or `pattern  # reason`; blank lines are skipped."""
    items: List[Item] = []
    problems: List[str] = []
    for n, line in enumerate(text.splitlines(), 1):
        at = _unquoted_hash(line)
        pattern, reason = (line, "") if at < 0 else (line[:at], line[at + 1:])
        pattern, reason = pattern.strip(), reason.strip()
        if pattern:
            items.append(Item(pattern, reason or None))
        elif reason:
            problems.append(f"line {n} has a reason but no pattern")
    return items, problems


def from_cli(raw: str) -> List[Any]:
    """A comma- or space-separated CLI value as manifest list items."""
    return [item.as_manifest() for item in parse(raw)[0]]
