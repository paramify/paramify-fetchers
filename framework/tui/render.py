"""Rich renderers for the JSON-able descriptors returned by framework.api.

These turn a `_fetcher_descriptor` dict (see framework/api.py) into Rich
renderables for display in a Textual `Static`. Kept separate from the screens so
later phases (the manifest editor) can reuse the same field rendering.
"""

import re
from typing import Any, List, Optional

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from framework import patterns
from framework.issue_reports import (
    ASSESSMENT_ID_FIELD,
    ASSESSMENT_NAME_FIELD,
    CLOSE_AFTER_RUN,
    CLOSE_CYCLE_FIELD,
    CLOSE_NEVER,
)
from framework.secret_resolver import (
    env_var_name,
    is_env_ref_attempt,
    view_runtime_value,
)
from framework.tui import kinds, palette, words
from framework.tui.words import agree


def _fmt_default(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _field_table(title: str, fields: List[dict]) -> RenderableType:
    """Render a list of config / secret / target_schema descriptors as a table."""
    heading = Text(title, style="bold")
    if not fields:
        return Group(heading, Text("  (none)", style="dim"))

    table = Table(box=None, pad_edge=False, expand=True, show_edge=False)
    table.add_column("name", style=palette.INFO, no_wrap=True)
    table.add_column("type", style="dim")
    table.add_column("req", justify="center")
    table.add_column("default")
    table.add_column("env var", style=palette.OK)
    table.add_column("description", style="dim", overflow="fold")

    for f in fields:
        required = f.get("required")
        req_cell = Text("yes", style=palette.WARN) if required else Text("no", style="dim")
        per_target = " ·per-target" if f.get("per_target") else ""
        table.add_row(
            f.get("name", ""),
            str(f.get("type", "")) + per_target,
            req_cell,
            _fmt_default(f.get("default")),
            f.get("env") or "",
            f.get("description") or "",
        )
    return Group(heading, table)


# --------------------------------------------------------------------------- #
# Kind and destination: what a fetcher produces and where it goes. The two
# kinds part ways at exactly this point (docs/issue_report_fetchers_guide.md), so
# every view of a fetcher states both before anything else about it.
# --------------------------------------------------------------------------- #

# Per kind: what it is, and how it reaches Paramify. Shown when the catalog's
# section heading is highlighted, so the difference is explained where it is drawn.
_KIND_ABOUT = {
    kinds.EVIDENCE: (
        "Shows a setting is in place, such as MFA being enforced, in a JSON file the fetcher builds.",
        "Uploaded to its evidence set with u on the Paramify tab.",
    ),
    kinds.INVENTORY: (
        "Lists every asset of one kind, one record each, for Paramify's Inventory.",
        "Uploaded with u like evidence, but only from a run that collected every asset.",
    ),
    kinds.SCAN_REPORT: (
        "Hands over a scanner's own report, such as a Nessus export, unchanged.",
        "Sent to an assessment's pipeline with i on the Pipelines tab. Pick the assessment with A on the Fetchers tab.",
    ),
}


def kind_pill(kind: str) -> Text:
    """The kind as a table cell: scan reports in the accent, so they stand out in a
    manifest that is mostly evidence; evidence plain, being the default."""
    if kind == kinds.SCAN_REPORT:
        return Text(kinds.noun(kind), style=f"bold {palette.ACCENT}")
    return Text(kinds.noun(kind), style="dim")


def kind_detail(kind: str, count: int) -> RenderableType:
    """What a catalog section holds, for its highlighted heading."""
    what, how = _KIND_ABOUT.get(kind, ("", ""))
    title = Text()
    title.append(kinds.heading(kind), style=f"bold {palette.FG}")
    title.append(f"  {count} fetcher{'' if count == 1 else 's'}", style="dim")
    return Group(title, Text(), Text(what, style="italic"), Text(), Text(how))


def _config_values(config_view: Optional[List[dict]]) -> dict:
    return {c["name"]: c.get("value") for c in config_view or [] if c.get("value") not in (None, "")}


def _close_policy(config_view: Optional[List[dict]]) -> Optional[str]:
    # A referenced policy counts once it resolves to a known one; the view itself shows the reference.
    policy = view_runtime_value(next((c for c in config_view or [] if c["name"] == CLOSE_CYCLE_FIELD), None))
    return policy if policy in (CLOSE_AFTER_RUN, CLOSE_NEVER) else None


def _close_label(policy: Optional[str]) -> Text:
    if policy == CLOSE_AFTER_RUN:
        return Text("after each complete run", style=palette.FG)
    if policy == CLOSE_NEVER:
        return Text("by hand (C on the Pipelines tab)", style=palette.FG)
    return Text("unset — press A", style=palette.WARN)


def destination_cell(descriptor: Optional[dict], config_view: Optional[List[dict]]) -> Text:
    """Where one manifest entry's output goes, in a table cell's width.

    Evidence goes where the fetcher says, so the cell is quiet. A scan report goes
    where the manifest says, and is sent nowhere until that is set — the one case
    worth a warning colour.
    """
    if kinds.kind_of(descriptor) == kinds.SCAN_REPORT:
        values = _config_values(config_view)
        aid = values.get(ASSESSMENT_ID_FIELD)
        if not aid:
            return Text("no assessment — press A", style=palette.WARN)
        cell = Text(str(values.get(ASSESSMENT_NAME_FIELD) or aid), style=palette.FG)
        policy = _close_policy(config_view)
        if policy:
            cell.append(f" · {policy}", style="dim")
        else:
            cell.append(" · close unset", style=palette.WARN)
        return cell
    es = (descriptor or {}).get("evidence_set")
    if es:
        cell = Text(es["reference_id"], style="dim")
        if (descriptor or {}).get("pipeline"):
            cell.append(" · pipeline", style="dim")
        return cell
    return Text("no evidence set", style=palette.WARN)


# Where an entry's frequency came from (desired.FREQUENCY_SOURCES), in words. The TUI
# reads the default upload.yaml, so it says so: an upload with --config may differ.
_FREQUENCY_FROM = {
    "entry": "set on this entry", "upload.yaml": "from the default upload.yaml",
    "upload.yaml defaults": "from the default upload.yaml's defaults",
    "schedule": "follows the schedule", "fetcher": "the fetcher's default",
}


def _destination(f: dict, config_view: Optional[List[dict]] = None, in_manifest: bool = False,
                 frequency: Optional[tuple] = None) -> RenderableType:
    """The "sends to" block. In the catalog a scan report's assessment is not chosen
    yet, so it says how to choose one; in the manifest it shows the choice."""
    rows: List[tuple] = []
    if kinds.kind_of(f) == kinds.SCAN_REPORT:
        ir = f.get("issue_report") or {}
        atype = (ir.get("assessment_type") or "any").lower()
        if in_manifest:
            values = _config_values(config_view)
            aid = values.get(ASSESSMENT_ID_FIELD)
            if aid:
                rows.append(("assessment", Text(str(values.get(ASSESSMENT_NAME_FIELD) or aid), style=palette.FG)))
            else:
                rows.append(("assessment", Text(f"unset — press A to pick a {atype} assessment", style=palette.WARN)))
            rows.append(("cycle closes", _close_label(_close_policy(config_view))))
        else:
            rows.append(("assessment", Text(f"a {atype} assessment, chosen per manifest", style=palette.FG)))
        fmt = ir.get("format")
        rows.append(("format", Text(f"{fmt + ', ' if fmt else ''}the tool's own file", style="dim")))
        rows.append(("send", Text("i on the Pipelines tab", style="dim")))
    else:
        es = f.get("evidence_set")
        if es:
            value = Text(es["reference_id"], style=palette.FG)
            if es.get("name"):
                value.append(f" — {es['name']}", style="dim")
            rows.append(("evidence set", value))
            if frequency:
                value, source = frequency
                cell = Text(words.frequency(value), style=palette.FG)
                cell.append(f"  {_FREQUENCY_FROM.get(source, source)}", style="dim")
                rows.append(("frequency", cell))
            pipe = f.get("pipeline")
            if pipe:
                rows.append(("pipeline", Text(
                    f"{pipe.get('type')} · {pipe.get('id_scheme') or '—'}", style=palette.FG)))
        else:
            rows.append(("evidence set", Text("none, so the upload skips it", style=palette.WARN)))
        rows.append(("send", Text("u on the Paramify tab", style="dim")))
    return Group(Text("sends to", style="bold"), _kv_table(rows))


def fetcher_detail(f: dict, in_manifest: Optional[bool] = None) -> RenderableType:
    """Full detail view for one fetcher descriptor.

    in_manifest adds a line under the title saying whether the fetcher is in the
    manifest, or how to add it. None leaves the line out.
    """
    title = Text()
    title.append(f.get("name", ""), style=f"bold {palette.FG}")
    if f.get("version"):
        title.append(f"  v{f['version']}", style="dim")
    community = f.get("source") == "community"
    if community:
        title.append("  ")
        title.append_text(palette.community_tag("community"))

    meta = Text()
    meta.append("kind: ", style="dim")
    meta.append_text(kind_pill(kinds.kind_of(f)))
    meta.append("    category: ", style="dim")
    meta.append(f.get("category") or "—", style=palette.FG)
    meta.append("    targets: ", style="dim")
    meta.append("yes" if f.get("supports_targets") else "no", style=palette.FG)

    description = Text(f.get("description") or "(no description)", style="italic")

    status = []
    if in_manifest is True:
        status = [Text("✓ in manifest", style=palette.OK)]
    elif in_manifest is False:
        status = [Text.assemble(("a", f"bold {palette.ACCENT}"), (" add to the manifest", "dim"))]

    provenance = [Text(palette.COMMUNITY_NOTE, style=palette.ORANGE)] if community else []

    return Group(
        title,
        meta,
        *status,
        *provenance,
        Text(),
        description,
        Text(),
        _destination(f),
        *_needs(f),
    )


def _needs(f: dict) -> List[RenderableType]:
    """The secrets, config and target fields a fetcher takes, as tables; the
    empty ones are named on one line instead of each showing "(none)"."""
    sections = (("secrets", f.get("secrets", [])), ("config", f.get("config", [])),
                ("target fields", f.get("target_schema", [])))
    out: List[RenderableType] = []
    for title, fields in sections:
        if fields:
            out += [Text(), _field_table(title, fields)]
    empty = [title for title, fields in sections if not fields]
    if empty:
        names = empty[0] if len(empty) == 1 else ", ".join(empty[:-1]) + " or " + empty[-1]
        out += [Text(), Text(f"Needs no {names}.", style="dim")]
    return out


def empty_detail(message: Optional[str] = None) -> RenderableType:
    return Text(message or "Select a fetcher to see what it needs.", style="dim italic")


# --------------------------------------------------------------------------- #
# Manifest-entry detail: a fetcher's contract overlaid with the values currently
# set in the manifest (used by the manifest editor, Phase 2).
# --------------------------------------------------------------------------- #



def _kv_table(rows: List[tuple]) -> Table:
    table = Table(box=None, pad_edge=False, expand=True, show_edge=False, show_header=False)
    table.add_column(style=palette.INFO, no_wrap=True)
    table.add_column()
    for name, value in rows:
        table.add_row(name, value)
    return table


def _config_value(c: dict) -> str:
    return patterns.display(c["value"]) if c.get("type") == patterns.TYPE else str(c["value"])


def _status(set_: bool, required: bool) -> Text:
    if set_:
        return Text("set", style=palette.OK)
    return Text("required — unset", style=palette.WARN) if required else Text("unset", style="dim")


def entry_detail(
    descriptor: Optional[dict],
    entry: dict,
    errors: Optional[List[str]] = None,
    config_view: Optional[List[dict]] = None,
    frequency: Optional[tuple] = None,
) -> RenderableType:
    """Render one manifest entry: its current config/secrets/targets vs the contract.

    `frequency` is (value, source) from api.entry_frequency: what its evidence set expects.
    """
    use = entry.get("use", "?")
    if descriptor is None:
        return Group(
            Text(use, style=f"bold {palette.FG}"),
            Text("Unknown fetcher: it isn't in the catalog.", style=palette.WARN),
        )

    fanout = descriptor.get("supports_targets")
    header = Text()
    header.append(use, style=f"bold {palette.FG}")
    header.append("  ")
    header.append_text(kind_pill(kinds.kind_of(descriptor)))
    header.append("  [fanout]" if fanout else "  [single]", style="dim")
    community = descriptor.get("source") == "community"
    if community:
        header.append("  ")
        header.append_text(palette.community_tag("community"))

    secs = entry.get("secrets") or {}
    parts: List[RenderableType] = [header]
    if community:
        parts.append(Text(palette.COMMUNITY_NOTE, style=palette.ORANGE))
    parts += [Text(), _destination(descriptor, config_view, in_manifest=True, frequency=frequency), Text()]

    # secrets (non per-target live at entry level)
    top_secrets = [s for s in descriptor.get("secrets", []) if not s.get("per_target")]
    if top_secrets:
        rows = []
        for s in top_secrets:
            raw = secs.get(s["name"])
            current = env_var_name(raw)
            if current:
                value = Text(f"${{env:{current}}}", style=palette.OK)
            elif is_env_ref_attempt(raw):
                # Malformed reference. Showing the var name we guessed out of
                # it would render it as correctly set; the run will refuse it.
                value = Text(f"{raw}  (malformed)", style=palette.FAIL)
            else:
                value = _status(False, s.get("required", True))
            rows.append((s["name"], value))
        parts += [Text("secrets", style="bold"), _kv_table(rows), Text()]

    # config — api.effective_config()'s merged view (platform defaults <- platform
    # values <- entry values), so a value set once at the category level shows as
    # set, and says where it came from, on every entry inheriting it. Empty when
    # the merge failed: no config block beats a knowingly-wrong one.
    config_fields = config_view or []
    if config_fields:
        rows = []
        for c in config_fields:
            source = c.get("source")
            ref = c.get("reference")
            if ref:
                # Shown as written, like a secret: never the variable's value.
                state = c.get("reference_state")
                style = {"set": palette.OK, "unset": palette.WARN}.get(state, palette.FAIL)
                value = Text(ref if state == "set" else f"{ref}  ({state})", style=style)
                if state == "set" and source != "entry":
                    value.append(f"  ({source})", style="dim")
                elif state == "unset" and source:
                    value.append(f"  → {c['value']} ({source})", style="dim")
                rows.append((c["name"], value))
            elif source == "entry":
                rows.append((c["name"], Text(_config_value(c), style=palette.FG)))
            elif source and source.startswith("platforms."):
                value = Text(_config_value(c), style=palette.FG)
                value.append(f"  ({source})", style="dim")
                rows.append((c["name"], value))
            elif source == "default":
                rows.append((c["name"], Text(f"{c['value']}  (default)", style="dim")))
            else:
                rows.append((c["name"], _status(False, c.get("required", False))))
        parts += [Text("config", style="bold"), _kv_table(rows), Text()]

    # targets
    if fanout:
        targets = entry.get("targets") or []
        parts.append(Text(f"targets ({len(targets)})", style="bold"))
        if not targets:
            parts.append(Text("  none yet (t to add one)", style=palette.WARN))
        for i, t in enumerate(targets):
            values = {k: v for k, v in t.items() if k != "secrets"}
            summary = "  ".join(f"{k}={v}" for k, v in values.items()) or "(empty)"
            line = Text(f"  [{i}] ", style="dim")
            line.append(summary, style=palette.FG)
            tsec = t.get("secrets") or {}
            if tsec:
                line.append("  " + ", ".join(f"{k}→{env_var_name(v) or v}" for k, v in tsec.items()), style=palette.OK)
            parts.append(line)
        parts.append(Text())

    if errors:
        parts.append(Text("issues", style=f"bold {palette.FAIL}"))
        for e in errors:
            parts.append(Text(f"  ✗ {e}", style=palette.WARN))

    return Group(*parts)


# --------------------------------------------------------------------------- #
# Environment: the variables a run reads (api.generate_env's `variables`), by
# tool. Presence only: a value is never passed in, so none can be shown.
# --------------------------------------------------------------------------- #

_NOTE_TAIL = re.compile(r" - (?:required|optional.*)$")
# The tool's heading already names the fetchers a passthrough variable reaches.
_PASSTHROUGH = re.compile(r"^Passed through to the \S+ fetchers when set$")


def _env_note(note: str) -> str:
    note = _NOTE_TAIL.sub("", note)
    return "Used when set" if _PASSTHROUGH.match(note) else note


def _read_by(fetchers: List[str]) -> str:
    if not fetchers:
        return "upload"
    if len(fetchers) == 1:
        return fetchers[0]
    return f"{len(fetchers)} fetchers"


def env_missing(variables: List[dict], use: Optional[str] = None, run: bool = False) -> List[str]:
    """Required variables with no value: every one, those fetcher `use` reads,
    or (run) those any fetcher reads. The last two leave Paramify's own out: a
    run collects without the upload token, as `paramify run` does."""
    return [v["name"] for v in variables
            if v["required"] and not v["set"]
            and (use is None or use in v["fetchers"]) and (not run or v["fetchers"])]


def env_list(variables: List[dict], show_optional: bool = False) -> RenderableType:
    """One block per tool: ✓ set, ✗ required and empty, · optional and empty.
    Optional variables nobody set fold into one line unless show_optional."""
    table = Table.grid(padding=(0, 2), expand=True)
    table.add_column(width=1)
    table.add_column(no_wrap=True)
    table.add_column(ratio=1, overflow="fold")  # wraps: a cut-off note hides where to get the value
    table.add_column(no_wrap=True, justify="right")
    tools: List[str] = []
    for v in variables:
        if v["tool"] not in tools:
            tools.append(v["tool"])
    for i, tool in enumerate(tools):
        rows = [v for v in variables if v["tool"] == tool]
        shown = [v for v in rows if show_optional or v["required"] or v["set"]]
        folded = len(rows) - len(shown)
        if i:
            table.add_row()
        table.add_row("", Text(tool, style=f"bold {palette.ACCENT}"), "", "")
        for v in shown:
            if v["set"]:
                mark = Text("✓", style=palette.OK)
            elif v["required"]:
                mark = Text("✗", style=palette.FAIL)
            else:
                mark = Text("·", style=palette.MUTED)
            name = Text(v["name"], style=palette.FG if v["set"] or v["required"] else palette.MUTED)
            note = Text(_env_note(v["note"]), style="dim")
            if not v["required"]:
                note.append("  optional", style=palette.MUTED)
            table.add_row(mark, name, note, Text(_read_by(v["fetchers"]), style=palette.MUTED))
        if folded:
            table.add_row(Text("·", style=palette.MUTED), Text(f"{folded} more", style=palette.MUTED),
                          Text(f"optional, not set  (o shows {agree(folded, 'it', 'them')})", style=palette.MUTED), "")
    return table


def _used_by(fetchers: List[str]) -> str:
    if not fetchers:
        return ""
    if len(fetchers) == 1:
        return f"Used by {fetchers[0]}."
    return f"Used by {len(fetchers)} fetchers."


def env_needed(variables: List[dict]) -> RenderableType:
    """Only the required variables with no value, split by what they block: a run
    (a fetcher reads it) or an upload (Paramify's own). Each is its name, then
    where to get it, so the note is the content rather than a squeezed column."""
    sections = (
        ("To run", [v for v in variables if v["required"] and not v["set"] and v["fetchers"]]),
        ("To upload", [v for v in variables if v["required"] and not v["set"] and not v["fetchers"]]),
    )
    parts: List[RenderableType] = []
    for heading, rows in sections:
        if not rows:
            continue
        if parts:
            parts.append(Text(""))
        parts.append(Text(heading, style=f"bold {palette.ACCENT}"))
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(width=1)
        table.add_column(ratio=1)
        for v in rows:
            body = Text(v["name"], style=f"bold {palette.FG}")
            note = _env_note(v["note"]).rstrip(".")
            used = _used_by(v["fetchers"])
            body.append("\n" + (f"{note}. {used}" if note else used).strip(), style="dim")
            table.add_row(Text("✗", style=palette.FAIL), body)
        parts.append(table)
    return Group(*parts)
