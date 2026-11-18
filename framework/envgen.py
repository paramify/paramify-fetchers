"""The .env a manifest needs: only the variables its fetchers read, grouped by
tool, with a note on each, and never overwriting what the customer already has.

Names the fetchers declare come from the same place the runner reads them:
secrets through `contract.effective_secrets` (so category-level credentials such
as AWS or Azure are included) and config fields that name an `env`. Nothing here
reads or prints an existing value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from framework import paramify_auth
from framework.contract import effective_secrets, platform_for


@dataclass
class EnvVar:
    name: str
    note: str
    required: bool
    default: Optional[str] = None


@dataclass
class EnvGroup:
    title: str
    about: str
    vars: List[EnvVar] = field(default_factory=list)


@dataclass
class EnvLine:
    """One line of an existing .env: its text exactly as written, and the
    variable it assigns (None for comments, blanks and anything unparseable)."""
    text: str
    name: Optional[str] = None
    value: Optional[str] = None


_ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_ENV_REF = re.compile(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}")
_PLACEHOLDER = re.compile(r"^\s*#\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def parse(text: str) -> List[EnvLine]:
    """Parse .env text into lines that keep their original text."""
    out: List[EnvLine] = []
    for raw in text.splitlines():
        m = _ASSIGN.match(raw)
        if not m:
            out.append(EnvLine(raw))
            continue
        value = m.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        out.append(EnvLine(raw, m.group(1), value))
    return out


def assigned(text: str) -> Dict[str, str]:
    """{name: value} for every variable the text assigns (last one wins)."""
    return {ln.name: ln.value or "" for ln in parse(text) if ln.name}


def _first_sentence(text: Optional[str]) -> str:
    flat = " ".join((text or "").split())
    m = re.match(r"(.+?[.!?])(?:\s|$)", flat)
    return m.group(1) if m else flat


def _flat(text: Optional[str]) -> str:
    return " ".join((text or "").split())


def _note(description: Optional[str], fallback: str, required: bool, default: Optional[str]) -> str:
    what = (_first_sentence(description) or fallback).rstrip(".")
    m = re.match(r"(?i)optional[:,]?\s+(.+)", what)
    if m:
        what = m.group(1)[0].upper() + m.group(1)[1:]
    if len(what) > 100:
        cut = what[:97]
        cut = cut.rsplit(" ", 1)[0] if " " in cut and what[97] != " " else cut
        what = cut.rstrip(" ,;:") + "..."
    if required:
        return f"{what} - required"
    return f"{what} - optional (default {default})" if default not in (None, "") else f"{what} - optional"


def _paramify_group() -> EnvGroup:
    return EnvGroup(
        "Paramify",
        "Where evidence is uploaded. Create the API token in Paramify under Settings.",
        [
            EnvVar(paramify_auth.UPLOAD_TOKEN_ENV,
                   "Paramify API token used to upload evidence - required", True, None),
            EnvVar(paramify_auth.BASE_URL_ENV,
                   f"Paramify API address - optional (default {paramify_auth.DEFAULT_BASE_URL})",
                   False, paramify_auth.DEFAULT_BASE_URL),
        ],
    )


def _refs(value: Any) -> List[str]:
    """Every ${env:NAME} a manifest value references, in order."""
    if isinstance(value, str):
        return _ENV_REF.findall(value)
    if isinstance(value, Mapping):
        return [r for v in value.values() for r in _refs(v)]
    if isinstance(value, (list, tuple)):
        return [r for v in value for r in _refs(v)]
    return []


def env_groups(
    root: Path,
    entries: Sequence[Union[str, Mapping[str, Any]]],
    manifest_platforms: Optional[Mapping[str, Any]] = None,
) -> List[EnvGroup]:
    """Variables the given fetchers need, by tool. Paramify comes first; names
    seen twice appear once, and one place that requires a variable makes it
    required. Unknown fetcher names are skipped (validation reports them).

    Each entry is a fetcher name or a manifest entry (`{"use": ..., ...}`). For
    a manifest entry, the variables its `${env:}` references name win: a secret
    mapped to OKTA_PROD_TOKEN, or one token per target, gives those names, not
    the fetcher's declared default. Any other reference in the entry (a config
    value, a target field) is included as required. `manifest_platforms` is the
    manifest's `run.platforms` block: its config references are required, its
    `auth.passthrough_env` names optional."""
    from framework import api  # late: api imports this module

    found = api.discover(root)
    fetchers, platforms = found["fetchers"], found["platforms"]
    groups: List[EnvGroup] = [_paramify_group()]
    seen: Dict[str, EnvVar] = {v.name: v for v in groups[0].vars}
    by_cat: Dict[str, EnvGroup] = {}

    def add(cat: str, name: str, description: Optional[str], fallback: str, required: bool, default) -> None:
        existing = seen.get(name)
        if existing is not None:
            if required and not existing.required:
                existing.required, existing.default = True, None
                existing.note = _note(description, fallback, True, None)
            return
        spec = platforms.get(cat)
        g = by_cat.get(cat)
        if g is None:
            g = by_cat[cat] = EnvGroup(
                (spec.display_name if spec and spec.display_name else cat),
                _first_sentence(spec.description if spec else None),
            )
        default = None if default in (None, "") else str(default)
        var = EnvVar(name, _note(description, fallback, required, default), required, default)
        seen[name] = var
        g.vars.append(var)

    blocks: Mapping[str, Any] = manifest_platforms if isinstance(manifest_platforms, Mapping) else {}
    used_cats = set()
    for item in entries:
        entry: Mapping[str, Any] = item if isinstance(item, Mapping) else {"use": item}
        fname = entry.get("use")
        f = fetchers.get(fname) if isinstance(fname, str) else None
        if f is None:
            continue
        cat = f.category or "other"
        spec = platform_for(f, platforms)
        scopes = [entry, *(t for t in entry.get("targets") or [] if isinstance(t, Mapping))]
        used_cats.add(cat)
        raw = blocks.get(cat)
        block: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
        set_here = {k for sc in (*scopes, block) for k in (sc.get("config") or {})}
        for s in effective_secrets(f, spec):
            mapped = [r for sc in scopes for r in _refs((sc.get("secrets") or {}).get(s.name))]
            for env in dict.fromkeys(mapped or [s.env]):
                add(cat, env, s.description, f"{s.name.replace('_', ' ')} for {fname}", s.required, None)
        fields = list((spec.config_schema if spec else {}).values()) + list(f.config_schema.values())
        for c in fields:
            if c.env and c.name not in set_here:
                add(cat, c.env, c.description, f"{c.name.replace('_', ' ')} for {fname}",
                    bool(c.required and c.default is None), c.default)
        for sc in scopes:
            for key, value in sc.items():
                if key not in ("secrets", "targets"):
                    for env in _refs(value):
                        add(cat, env, None, f"Referenced by {fname} in the manifest", True, None)

    for cat in sorted(used_cats):
        pblock = blocks.get(cat)
        if not isinstance(pblock, Mapping):
            continue
        for env in _refs(pblock.get("config")):
            add(cat, env, None, f"Referenced by the {cat} platform config in the manifest", True, None)
        for env in (pblock.get("auth") or {}).get("passthrough_env") or []:
            if isinstance(env, str):
                add(cat, env, None, f"Passed through to the {cat} fetchers", False, None)

    groups.extend(sorted(by_cat.values(), key=lambda g: g.title.lower()))
    return groups


def _var_line(v: EnvVar) -> str:
    if v.required:
        return f"{v.name}="
    if v.default is not None:
        return f"{v.name}={v.default}"
    # Commented: an empty AWS_ACCESS_KEY_ID would hide the ambient credential chain.
    return f"# {v.name}="


def _block(g: EnvGroup, vars_: Sequence[EnvVar], header: bool = True) -> List[str]:
    lines: List[str] = []
    if header:
        lines.append(f"# --- {g.title} ---")
        if g.about:
            lines.append(f"# {g.about}")
    for v in vars_:
        lines.append(f"# {v.note}")
        lines.append(_var_line(v))
    return lines


_PREAMBLE = "# Generated by `paramify env`. Fill in the blank values; existing values are never changed."


def render(groups: Sequence[EnvGroup]) -> str:
    out: List[str] = [_PREAMBLE]
    for g in groups:
        out += ["", *_block(g, g.vars)]
    return "\n".join(out) + "\n"


_HEADER = re.compile(r"^# --- (.+?)(?: \(continued\))? ---\s*$")


def _sections(existing: str) -> List[str]:
    return [m.group(1) for line in existing.splitlines() if (m := _HEADER.match(line))]


def _is_last_section(existing: str, title: str) -> bool:
    """True when `title`'s section is the last one in the file, so lines
    appended at the end already sit under it."""
    secs = _sections(existing)
    return bool(secs) and secs[-1] == title


def _continued(g: EnvGroup, vars_: Sequence[EnvVar], existing: str) -> List[str]:
    """New variables for a group that has a section earlier in the file: a
    continuation header, so they do not land under whichever section is last.
    A group the file has never had gets its ordinary header."""
    if g.title not in _sections(existing):
        return _block(g, vars_)
    return [f"# --- {g.title} (continued) ---", *_block(g, vars_, header=False)]


def plan(existing: str, groups: Sequence[EnvGroup]) -> Tuple[str, List[str], List[str]]:
    """(text to append, names added, names already set). Never touches `existing`."""
    lines = parse(existing)
    have = {ln.name: ln.value for ln in lines if ln.name}
    placeholders = {m.group(1) for ln in lines if not ln.name and (m := _PLACEHOLDER.match(ln.text))}
    added: List[str] = []
    already: List[str] = []
    out: List[str] = []
    for g in groups:
        fresh = []
        for v in g.vars:
            if v.name in have:
                if (have[v.name] or "").strip():
                    already.append(v.name)
            elif v.name not in placeholders or v.required:
                fresh.append(v)
        if fresh:
            # Judged against what is already written plus what this call has appended.
            so_far = existing + "\n".join(out)
            out += ["", *_block(g, fresh, header=False)] if _is_last_section(so_far, g.title) else [
                "", *_continued(g, fresh, so_far)]
            added += [v.name for v in fresh]
    if not out:
        return "", added, already
    if not existing:
        out = [_PREAMBLE, *out]
    elif out[0] == "":
        out = out[1:] if existing.endswith("\n\n") else out
    return "\n".join(out) + "\n", added, already


def merge_into(path: Path, groups: Sequence[EnvGroup]) -> dict:
    """Append the variables `path` lacks, under their group; write atomically.
    Existing lines are left exactly as they are."""
    from framework import api

    path = Path(path)
    target = path.resolve() if path.is_symlink() else path  # write the file, keep the link
    existing = ""
    if target.is_file():
        with target.open(newline="") as fh:  # as written: a CRLF file stays CRLF
            existing = fh.read()
    addition, added, already = plan(existing.replace("\r\n", "\n"), groups)
    if addition:
        newline = "\r\n" if "\r\n" in existing else "\n"
        sep = newline if existing and not existing.endswith("\n") else ""
        api._atomic_write(target, existing + sep + addition.replace("\n", newline))
    return {"added": added, "already_set": already, "path": str(path)}
