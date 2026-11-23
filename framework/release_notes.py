"""Pure release logic: versions, the CHANGELOG cut, note drafting and checks.

Nothing here runs git or touches the network. `tools/release.py` gathers the
facts (the last tag, the fetchers that changed, commit subjects) and passes them
in as strings and dicts; this module returns strings and dicts.

A release file (`releases/<version>.yaml`) holds `version`, `date`, `highlights`
(rows a user acts on) and `fetchers` (one line per fetcher that changed). A row
or line marked `draft: true` is one a person has not reviewed yet.
"""

from __future__ import annotations

import datetime
import re
from typing import Any, Callable, Collection, Dict, List, Optional, Sequence, Tuple

import yaml
from packaging.version import InvalidVersion, Version

from framework import update

NOTE_MAX = 110
TODO_NOTE = "TODO: say what changed for the user"
MINOR_TAGS = frozenset({"new", "fetcher", "cli", "tui"})

_HEADING = re.compile(r"^## \[([^\]]+)\](?:\s*-\s*(\S+))?\s*$")
_LINK_DEF = re.compile(r"^\[[^\]]+\]: ")
_UNRELEASED_LINK = re.compile(r"^\[Unreleased\]: (?P<base>.+)/compare/v(?P<prev>[^/]+?)\.\.\.HEAD\s*$", re.M)
_VERSION = r"\d+\.\d+\.\d+"
_LEAD_NAMES = re.compile(rf"^`[^`]+`(?:\s+{_VERSION})?(?:(?:,\s*(?:and\s+)?|\s+and\s+)`[^`]+`(?:\s+{_VERSION})?)*\s*")
# A sentence ends at ". " before a capital or a `name`, but not after e.g., i.e., etc. or vs.
_SENTENCE_END = re.compile(r"(?<=\.)(?<!e\.g\.)(?<!i\.e\.)(?<!etc\.)(?<!vs\.)\s+(?=[A-Z`])")


def changelog_sections(text: str) -> Dict[str, dict]:
    """{version: {"date": ..., "<Subheading>": top-level bullet count, "body": text}}.

    `body` is the section's text without its `## [version]` heading and without
    the link definitions at the foot of the file.
    """
    out: Dict[str, dict] = {}
    lines_by_version: Dict[str, List[str]] = {}
    cur: Optional[dict] = None
    key = ""
    sub: Optional[str] = None
    for line in text.splitlines():
        m = _HEADING.match(line)
        if m:
            cur, sub = out.setdefault(m[1], {"date": m[2]}), None
            lines_by_version.setdefault(m[1], [])
            key = m[1]
            continue
        if cur is None or _LINK_DEF.match(line):
            continue
        lines_by_version[key].append(line)
        if line.startswith("### "):
            sub = line[4:].strip()
            cur.setdefault(sub, 0)
        elif sub and line.startswith("- "):
            cur[sub] += 1
    for version, lines in lines_by_version.items():
        out[version]["body"] = "\n".join(lines).strip("\n") + "\n"
    return out


def cut_changelog(text: str, version: str, date: str) -> str:
    """Turn `## [Unreleased]` into `## [version] - date` under a fresh `## [Unreleased]`.

    Also moves the `[Unreleased]` compare link to `v{version}...HEAD` and adds
    a `[version]` link for `v{prev}...v{version}`; `prev` and the base URL come
    from the old `[Unreleased]` link. Raises ValueError when either is missing.
    """
    if not re.search(r"^## \[Unreleased\]\s*$", text, re.M):
        raise ValueError("CHANGELOG.md has no '## [Unreleased]' heading")
    link = _UNRELEASED_LINK.search(text)
    if not link:
        raise ValueError("CHANGELOG.md has no '[Unreleased]: .../compare/vX...HEAD' link")
    base, prev = link["base"], link["prev"]
    text = re.sub(r"^## \[Unreleased\]\s*$", f"## [Unreleased]\n\n## [{version}] - {date}", text, count=1, flags=re.M)
    new_links = f"[Unreleased]: {base}/compare/v{version}...HEAD\n[{version}]: {base}/compare/v{prev}...v{version}"
    return _UNRELEASED_LINK.sub(lambda _m: new_links, text, count=1)


def set_pyproject_version(text: str, version: str) -> str:
    """Set `version = "X.Y.Z"` in `[project]`, with any pre-release suffix stripped."""
    plain = str(Version(version).base_version)
    out: List[str] = []
    in_project = done = False
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("["):
            in_project = stripped == "[project]"
        elif in_project and not done and re.match(r"version\s*=", stripped):
            line = re.sub(r'"[^"]*"', f'"{plain}"', line, count=1)
            done = True
        out.append(line)
    if not done:
        raise ValueError("pyproject.toml has no version in [project]")
    return "".join(out)


def required_bump(notes: dict, added_fetchers: Collection[str], major: int) -> str:
    """The smallest bump the notes call for: "major", "minor" or "patch".

    While major is 0, a breaking row or an added fetcher or a `new`, `fetcher`,
    `cli` or `tui` row is a minor bump. From 1.0 a breaking row is a major bump.
    """
    tags = {h.get("tag") for h in notes.get("highlights") or []}
    if "breaking" in tags:
        return "major" if major >= 1 else "minor"
    if added_fetchers or tags & MINOR_TAGS:
        return "minor"
    return "patch"


def next_version(prev: str, bump: str) -> str:
    """`prev` raised by `bump`, keeping the pre-release suffix: 0.6.0-beta + minor = 0.7.0-beta."""
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(.*)", prev)
    if not m:
        raise ValueError(f"not a version: {prev}")
    major, minor, patch, suffix = int(m[1]), int(m[2]), int(m[3]), m[4]
    if bump == "major":
        major, minor, patch = major + 1, 0, 0
    elif bump == "minor":
        minor, patch = minor + 1, 0
    elif bump == "patch":
        patch += 1
    else:
        raise ValueError(f"unknown bump: {bump}")
    return f"{major}.{minor}.{patch}{suffix}"


def _release_numbers(version: str) -> Optional[Tuple[int, ...]]:
    try:
        numbers = Version(version).release
    except InvalidVersion:
        return None
    return numbers + (0,) * (3 - len(numbers))


def at_least(version: str, floor: str) -> bool:
    """Whether `version` is `floor` or later, by X.Y.Z only: for a floor of
    0.7.0-beta, 0.7.0, 0.7.0-rc and 1.0.0 pass, 0.6.9 and "next" do not."""
    found, least = _release_numbers(version), _release_numbers(floor)
    return found is not None and least is not None and found >= least


def _bullets(body: str) -> List[str]:
    """Top-level bullets of a CHANGELOG body, each as one line of text."""
    out: List[List[str]] = []
    for line in body.splitlines():
        if line.startswith("- "):
            out.append([line[2:].strip()])
        elif out and line.startswith(" ") and line.strip():
            out[-1].append(line.strip())
        elif not line.strip():
            continue
        else:
            out.append([])  # a heading or other text ends the bullet
    return [" ".join(parts) for parts in out if parts]


def _lead_note(name: str, body: str) -> Optional[str]:
    for bullet in _bullets(body):
        m = re.match(r"\*\*(.+?)\*\*", bullet)
        if not m or f"`{name}`" not in m[1]:
            continue
        lead = m[1]
        v = re.search(r"\d+\.\d+\.\d+: ", lead)
        if v:
            rest = lead[v.end():]
        elif ": " in lead:
            rest = lead.split(": ", 1)[1]
        else:
            # "**`name` can record X.**": drop the leading names ("`a` and `b`", "`a`, `b`, and `c`",
            # each with an optional version) and keep the rest.
            names = _LEAD_NAMES.match(lead)
            if not names or f"`{name}`" not in names[0]:
                continue
            rest = lead[names.end():]
        rest = rest.strip().rstrip(".").strip()
        if rest:
            return rest
    return None


def _list_note(name: str, body: str) -> Optional[str]:
    """The text of a plain (not bold) list bullet, nested or not: "- `name` 0.3.0: text"."""
    pattern = re.compile(rf"^\s*- `{re.escape(name)}`(?: \d+\.\d+\.\d+)?: (\S.*)$")
    lines = body.splitlines()
    for i, line in enumerate(lines):
        m = pattern.match(line)
        if not m:
            continue
        parts = [m[1].strip()]
        for nxt in lines[i + 1:]:  # a wrapped bullet continues on indented lines
            if not nxt.strip() or nxt.lstrip().startswith("- ") or not nxt.startswith(" "):
                break
            parts.append(nxt.strip())
        rest = _SENTENCE_END.split(" ".join(parts), maxsplit=1)[0].rstrip(".").strip()
        if rest:
            return rest
    return None


def _shorten(text: str) -> str:
    if len(text) <= NOTE_MAX:
        return text
    cut = text[: NOTE_MAX - 1]
    if text[NOTE_MAX - 1] != " " and " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip(" ,;:.") + "…"


def draft_note(
    name: str, changelog_body: str, subjects: Sequence[str], dir_name: Optional[str] = None
) -> str:
    """A first note for a fetcher line, for a person to edit.

    Takes the first of: the CHANGELOG bullet whose bold lead names the fetcher,
    a plain list bullet "`name` 1.2.0: text" (nested or not), the newest commit
    subject `update.fetcher_reason` accepts for the name, the same for
    `dir_name` (the fetcher's directory, which commits often use instead of the
    name), or a TODO. Cut to fit the 110-character limit.
    """
    note = (
        _lead_note(name, changelog_body)
        or _list_note(name, changelog_body)
        or update.fetcher_reason(name, subjects)
        or (update.fetcher_reason(dir_name, subjects) if dir_name and dir_name != name else None)
        or TODO_NOTE
    )
    return _shorten(note)


def draft_release(
    version: str,
    date: str,
    rows: List[dict],
    changed: Dict[str, str],
    notes_for: Callable[[str], str],
    previous: Optional[dict] = None,
    rows_since_base: Sequence[dict] = (),
) -> dict:
    """The release file for `version`, as a dict.

    First draft (`previous` is None): every row and every fetcher line is marked
    `draft: True`. Rebuild: the rows and lines a person already edited stay as
    they are, a row deleted by hand stays deleted, `rows_since_base` arrive
    marked, a line whose fetcher moved again keeps its note with the new version
    and a mark, and a line for a fetcher that no longer changed is dropped.
    `changed` is {fetcher name: new version} against the last tag.
    """
    if previous is None:
        highlights = [{**row, "draft": True} for row in rows]
        fetchers = [
            {"name": n, "version": changed[n], "note": notes_for(n), "draft": True} for n in sorted(changed)
        ]
    else:
        highlights = [dict(row) for row in previous.get("highlights") or []]
        highlights += [{**row, "draft": True} for row in rows_since_base]
        old = {line["name"]: line for line in previous.get("fetchers") or []}
        fetchers = []
        for n in sorted(changed):
            line = old.get(n)
            if line is None:
                fetchers.append({"name": n, "version": changed[n], "note": notes_for(n), "draft": True})
            elif line["version"] == changed[n]:
                fetchers.append(dict(line))
            else:
                fetchers.append({**line, "version": changed[n], "draft": True})
    return {"version": version, "date": date, "highlights": highlights, "fetchers": fetchers}


def dump_release(doc: dict) -> str:
    """The release file as YAML, with the header comment the shipped files have."""
    version = doc["version"]
    header = (
        f"# What `paramify update` shows for v{version}. The full list is the\n"
        f"# CHANGELOG's [{version}] section; this is the part a user acts on.\n"
        "# Format and rules: releases/README.md.\n"
    )
    ordered: Dict[str, Any] = {k: doc[k] for k in ("version", "date", "highlights", "fetchers") if k in doc}
    ordered.update({k: v for k, v in doc.items() if k not in ordered})
    if isinstance(ordered.get("date"), str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", ordered["date"]):
        ordered["date"] = datetime.date.fromisoformat(ordered["date"])  # written unquoted, as shipped files are
    body = yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True, width=10_000, default_flow_style=False)
    return header + body


def _bump_reason(notes: dict, added: Collection[str], major: int, bump: str) -> str:
    tags = {h.get("tag") for h in notes.get("highlights") or []}
    if bump == "patch":
        return "no breaking, new or added-fetcher changes → patch"
    why = []
    if "breaking" in tags:
        why.append("breaking rows")
    if added:
        why.append("added fetchers")
    if tags & MINOR_TAGS and "breaking" not in tags:
        why.append("new rows")
    return f"{' and '.join(why) or 'rows'} → {bump}"


def check_release(doc: dict, changed: Dict[str, str], added: Collection[str], prev_version: str) -> List[str]:
    """What to fix in a release file before it ships; an empty list means ready.

    Each message names the fetcher or version to fix: a changed fetcher with no
    line, a line for a fetcher that did not change, a line at another version
    than the fetcher's, a fetcher with more than one line, and a version below
    the one the rows call for. A higher version passes (a person can force one),
    and so does one without the previous release's pre-release suffix.
    """
    problems: List[str] = []
    lines: Dict[str, List[dict]] = {}
    for line in doc.get("fetchers") or []:
        lines.setdefault(line["name"], []).append(line)
    for name in sorted(changed):
        if name not in lines:
            problems.append(f"{name} {changed[name]} has no fetcher line")
    for name in sorted(lines):
        if len(lines[name]) > 1:
            problems.append(f"{name} has {len(lines[name])} fetcher lines; keep one")
        if name not in changed:
            problems.append(f"{name} has a line but did not change since v{prev_version}")
        elif all(line["version"] != changed[name] for line in lines[name]):
            says = ", ".join(sorted({str(line["version"]) for line in lines[name]}))
            problems.append(f"{name} line says {says} but the fetcher is {changed[name]}")
    major = Version(prev_version).major
    bump = required_bump(doc, added, major)
    expected = next_version(prev_version, bump)
    found = str(doc.get("version"))
    if not at_least(found, expected):
        problems.append(f"expected {expected} or later ({_bump_reason(doc, added, major, bump)}), found {found}")
    return problems
