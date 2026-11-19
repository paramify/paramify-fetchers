"""The .env a manifest needs: only the variables its fetchers read, grouped by
tool, with a note on each, and never overwriting what the customer already has.

Names the fetchers declare come from the same place the runner reads them:
secrets through `contract.effective_secrets` (so category-level credentials such
as AWS or Azure are included) and config fields that name an `env`. A file's
values are read with python-dotenv, as every run reads them. Nothing here prints
an existing value, touches a file, or scans the fetcher tree: the caller
(framework.api) passes the discovered fetchers in and does the writing.
"""

from __future__ import annotations

import io
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from dotenv import dotenv_values

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
class EnvPlan:
    """One merge into a .env: the text to append (the whole file when there
    was none, never existing content), and the names it adds, finds already
    set, and still finds empty (in the file and in the environment)."""
    text: str
    added: List[str]
    already_set: List[str]
    missing: List[str]


_ENV_REF = re.compile(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}")
_PLACEHOLDER = re.compile(r"^\s*#\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def assigned(text: str) -> Dict[str, str]:
    """{name: value} as python-dotenv reads `text`, which is how runs read it."""
    return {k: v or "" for k, v in dotenv_values(stream=io.StringIO(text)).items()}


def _first_sentence(text: Optional[str]) -> str:
    flat = " ".join((text or "").split())
    m = re.match(r"(.+?[.!?])(?:\s|$)", flat)
    return m.group(1) if m else flat


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
    default = paramify_auth.DEFAULT_BASE_URL
    return EnvGroup(
        "Paramify",
        "Where evidence is uploaded. Create the API token in Paramify under Settings.",
        [
            EnvVar(paramify_auth.UPLOAD_TOKEN_ENV, _note("Paramify API token used to upload evidence", "", True, None),
                   True, None),
            EnvVar(paramify_auth.BASE_URL_ENV, _note("Paramify API address", "", False, default), False, default),
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


def manifest_for(names: Sequence[str]) -> dict:
    """A manifest that runs these fetchers, for a caller that has only names."""
    return {"run": {"fetchers": [{"use": n} for n in names]}}


def env_groups(fetchers: Mapping[str, Any], platforms: Mapping[str, Any], manifest: Mapping[str, Any]) -> List[EnvGroup]:
    """Variables a manifest needs, by tool. Paramify comes first; names seen
    twice appear once, and one place that requires a variable makes it
    required. Unknown fetcher names are skipped (validation reports them).

    The manifest's own `${env:}` references win: a secret mapped to
    OKTA_PROD_TOKEN, or one token per target, gives those names, not the
    fetcher's declared default. Any other reference in an entry (a config
    value, a target field) is required. In `run.platforms`, config references
    are required and `auth.passthrough_env` names optional.
    """
    run = manifest.get("run") or {}
    entries = [e for e in run.get("fetchers") or [] if isinstance(e, Mapping) and e.get("use")]
    blocks: Mapping[str, Any] = run["platforms"] if isinstance(run.get("platforms"), Mapping) else {}
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

    used_cats = set()
    for entry in entries:
        fname = entry["use"]
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


def plan(existing: str, groups: Sequence[EnvGroup], environ: Optional[Mapping[str, str]] = None) -> EnvPlan:
    """What merging `groups` into `existing` (LF line endings) adds. Never
    changes `existing`. A required variable is missing when it is empty both
    in the file (as it will be) and in `environ` (default os.environ)."""
    environ = os.environ if environ is None else environ
    have = assigned(existing)
    placeholders = {m.group(1) for line in existing.splitlines() if (m := _PLACEHOLDER.match(line))}
    added: List[str] = []
    already: List[str] = []
    out: List[str] = []
    for g in groups:
        fresh = []
        for v in g.vars:
            if v.name in have:
                if have[v.name].strip():
                    already.append(v.name)
            elif v.name not in placeholders or v.required:
                fresh.append(v)
        if fresh:
            so_far = existing + "\n".join(out)
            out += ["", *_block(g, fresh, header=False)] if _is_last_section(so_far, g.title) else [
                "", *_continued(g, fresh, so_far)]
            added += [v.name for v in fresh]
    text = ""
    if out:
        if not existing:
            out = [_PREAMBLE, *out]
        elif out[0] == "" and existing.endswith("\n\n"):
            out = out[1:]
        text = "\n".join(out) + "\n"
    values = {**have, **assigned(text)}
    missing = [v.name for g in groups for v in g.vars
               if v.required and not values.get(v.name, "").strip() and not environ.get(v.name, "").strip()]
    return EnvPlan(text, added, already, missing)


def merged(existing: str, groups: Sequence[EnvGroup], environ: Optional[Mapping[str, str]] = None) -> Tuple[str, EnvPlan]:
    """`existing` exactly as written, with what `plan` adds appended in the
    file's own line endings (a CRLF file stays CRLF)."""
    result = plan(existing.replace("\r\n", "\n"), groups, environ)
    if not result.text:
        return existing, result
    newline = "\r\n" if "\r\n" in existing else "\n"
    sep = newline if existing and not existing.endswith("\n") else ""
    return existing + sep + result.text.replace("\n", newline), result
