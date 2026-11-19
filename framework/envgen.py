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

from framework import paramify_auth, patterns
from framework.contract import effective_secrets, platform_category, platform_for
from framework.runner import manifest_loader
from framework.runner.executor import merged_config
from framework.secret_resolver import env_var_name, is_env_ref_attempt


@dataclass
class EnvVar:
    name: str
    note: str
    required: bool
    default: Optional[str] = None
    fetchers: List[str] = field(default_factory=list)  # who reads it; empty for Paramify's own (the upload)


@dataclass
class EnvGroup:
    title: str
    about: str
    vars: List[EnvVar] = field(default_factory=list)


@dataclass
class EnvPlan:
    """One merge into a .env: the text to append (the whole file when there
    was none, never existing content), and the names it adds, finds already
    set, and still finds empty (required ones, in the file and in the
    environment), and every name that has a value in either."""
    text: str
    added: List[str]
    already_set: List[str]
    missing: List[str]
    has_value: List[str]  # every name with a value in the file or the environment


_PLACEHOLDER = re.compile(r"^\s*#\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def assigned(text: str) -> Dict[str, str]:
    """{name: value} as python-dotenv reads `text`, which is how runs read it."""
    return {k: v or "" for k, v in dotenv_values(stream=io.StringIO(text)).items()}


def _first_sentence(text: Optional[str]) -> str:
    flat = " ".join((text or "").split())
    for m in re.finditer(r"[.!?](?=\s|$)", flat):
        if not re.search(r"(?:^|[\s(])(?:e\.g|i\.e|etc|vs|approx)\.$", flat[:m.end()], re.I):
            return flat[:m.end()]
    return flat


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


@dataclass
class Unmapped:
    """A secret that stops the run whatever .env holds: a required one the
    manifest doesn't map yet, or any one mapped to a malformed reference. An entry-level secret is mapped with `paramify
    manifest set-secret`; a per-target one under that target's `secrets:`
    (`target` is its index, or None when the entry has no targets at all)."""
    fetcher: str
    secret: str
    env: str  # the fetcher's declared name, the usual choice
    per_target: bool = False
    target: Optional[int] = None
    malformed: bool = False  # mapped, but not as a ${env:NAME} the runner accepts: it stops either way


def env_groups(
    fetchers: Mapping[str, Any], platforms: Mapping[str, Any], manifest: Mapping[str, Any],
) -> Tuple[List[EnvGroup], List[Unmapped]]:
    """The variables a run of this manifest reads, by tool, and the secrets
    that would stop it whatever .env holds.

    Read the way the runner reads (framework/runner/executor.py), using its own
    functions where it has them: config through merged_config run against an
    empty environment, so every ${env:} reference it would look up is reported
    as unset, in its layer order, and refused ones (a secret's name, a
    non-string field, part of a value) are not; a config variable is required
    when its field is required and no layer gives it a value. Secrets through
    secret_resolver's rules, on the entry, or on each target for a per_target
    secret. Passthrough as _build_env computes it, per fetcher. A config
    field's own `env` name is not here: the runner sets it for the fetcher, and
    nothing reads it from the shell. Paramify comes first; names seen twice
    appear once, and one place that requires a variable makes it required.
    Unknown fetcher names are skipped (validation reports them).
    """
    run = manifest.get("run") or {}
    parsed = manifest_loader.parse_manifest({"run": {
        **run, "fetchers": [e for e in run.get("fetchers") or [] if isinstance(e, Mapping) and e.get("use")],
    }})
    groups: List[EnvGroup] = [_paramify_group()]
    seen: Dict[str, EnvVar] = {v.name: v for v in groups[0].vars}
    by_cat: Dict[str, EnvGroup] = {}
    unmapped: List[Unmapped] = []

    def add(cat: str, name: str, description: Optional[str], fallback: str, required: bool, who: str) -> None:
        existing = seen.get(name)
        if existing is not None:
            if who not in existing.fetchers:
                existing.fetchers.append(who)
            if required and not existing.required:
                existing.required = True
                existing.note = _note(description, fallback, True, None)
            return
        spec = platforms.get(cat)
        g = by_cat.get(cat)
        if g is None:
            g = by_cat[cat] = EnvGroup(
                (spec.display_name if spec and spec.display_name else cat),
                _first_sentence(spec.description if spec else None),
            )
        var = EnvVar(name, _note(description, fallback, required, None), required, fetchers=[who])
        seen[name] = var
        g.vars.append(var)

    def secret(cat: str, fname: str, s: Any, value: Any, target: Optional[int] = None) -> None:
        """One secret as resolve() reads it: absent, a ${env:NAME}, malformed, or a literal."""
        if value is None:
            if s.required:
                unmapped.append(Unmapped(fname, s.name, s.env, per_target=s.per_target, target=target))
        elif (env := env_var_name(value)) is not None:
            add(cat, env, s.description, f"{s.name.replace('_', ' ')} for {fname}", s.required, fname)
        elif is_env_ref_attempt(value):
            unmapped.append(Unmapped(fname, s.name, s.env, per_target=s.per_target, target=target, malformed=True))

    for entry in parsed.entries:
        f = fetchers.get(entry.use)
        if f is None:
            continue
        cat = f.category or "other"
        pcat = platform_category(f)  # None for a comparator: no platform block, no category secrets
        spec = platform_for(f, platforms)
        platform_cfg = parsed.platforms.get(pcat) if pcat else None
        for s in effective_secrets(f, spec):
            if not s.per_target:
                secret(cat, entry.use, s, entry.secrets.get(s.name))
            elif entry.targets:
                for i, t in enumerate(entry.targets):
                    secret(cat, entry.use, s, t.secrets.get(s.name), i)
            else:
                secret(cat, entry.use, s, None)

        merged = merged_config(f, spec, platform_cfg, entry, environ={})
        for field_name, env in merged.unset:
            fdef = merged.schema.get(field_name)
            required = bool(fdef and fdef.required and field_name not in merged.values)
            where = entry.use if field_name in entry.config else f"the {pcat} fetchers"
            add(cat, env, fdef.description if fdef else None, f"{field_name.replace('_', ' ')} for {where}", required,
                entry.use)

        passthrough = set(spec.passthrough_env if spec else []) | set(platform_cfg.passthrough_env if platform_cfg else [])
        passthrough -= {fdef.env for fdef in merged.schema.values() if fdef.type == patterns.TYPE and fdef.env}
        for env in sorted(passthrough):
            add(cat, env, None, f"Passed through to the {cat} fetchers when set", False, entry.use)

    groups.extend(sorted(by_cat.values(), key=lambda g: g.title.lower()))
    return groups, unmapped


def _var_line(v: EnvVar) -> str:
    if v.required:
        return f"{v.name}="
    # Commented: an empty AWS_ACCESS_KEY_ID would hide the ambient credential chain, and a
    # default written out would freeze today's default over a later one.
    return f"# {v.name}={v.default or ''}"


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


_PREAMBLE = (
    "# Generated by `paramify env`: the variables your manifest reads, for local testing.\n"
    "# In production, set them in your secret manager instead; a variable set in the\n"
    "# environment always wins over this file. Existing values here are never changed."
)


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
    has_value = [v.name for g in groups for v in g.vars
                 if values.get(v.name, "").strip() or environ.get(v.name, "").strip()]
    missing = [v.name for g in groups for v in g.vars if v.required and v.name not in has_value]
    return EnvPlan(text, added, already, missing, has_value)


def merged(existing: str, groups: Sequence[EnvGroup], environ: Optional[Mapping[str, str]] = None) -> Tuple[str, EnvPlan]:
    """`existing` exactly as written, with what `plan` adds appended in the
    file's own line endings (a CRLF file stays CRLF)."""
    result = plan(existing.replace("\r\n", "\n"), groups, environ)
    if not result.text:
        return existing, result
    newline = "\r\n" if "\r\n" in existing else "\n"
    sep = newline if existing and not existing.endswith("\n") else ""
    return existing + sep + result.text.replace("\n", newline), result
