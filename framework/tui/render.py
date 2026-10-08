"""Rich renderers for the JSON-able descriptors returned by framework.api.

These turn a `_fetcher_descriptor` dict (see framework/api.py) into Rich
renderables for display in a Textual `Static`. Kept separate from the screens so
later phases (the manifest editor) can reuse the same field rendering.
"""

from typing import Any, List, Optional

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from framework.issue_reports import (
    ASSESSMENT_ID_FIELD,
    ASSESSMENT_NAME_FIELD,
    CLOSE_AFTER_RUN,
    CLOSE_CYCLE_FIELD,
    CLOSE_NEVER,
)
from framework.secret_resolver import env_var_name, is_env_ref_attempt
from framework.tui import kinds, palette


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
# kinds part ways at exactly this point (docs/issue_report_fetchers.md), so
# every view of a fetcher states both before anything else about it.
# --------------------------------------------------------------------------- #

# Per kind: what it is, and how it reaches Paramify. Shown when the catalog's
# section heading is highlighted, so the difference is explained where it is drawn.
_KIND_ABOUT = {
    kinds.EVIDENCE: (
        "Asserts a configuration state — MFA is enforced, buckets are encrypted — "
        "as a JSON payload the fetcher builds.",
        "Wrapped in the standard envelope and uploaded to the evidence set the "
        "fetcher names. Upload with ctrl+u on the Paramify tab.",
    ),
    kinds.SCAN_REPORT: (
        "Hands over findings a scanner already computed — a Nessus export, a Wiz "
        "CSV, a STIG report — as the tool's own file, never rewritten.",
        "Sent to an assessment's pipeline, which turns it into issues. Each one "
        "needs an assessment, chosen per manifest with A on the Manifest tab; "
        "send with i on the Paramify tab. Usually kept in a manifest of its own.",
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


def _close_label(policy: Optional[str]) -> Text:
    if policy == CLOSE_AFTER_RUN:
        return Text("after each complete run (after_run)", style=palette.FG)
    if policy == CLOSE_NEVER:
        return Text("by hand — C on the Paramify tab (never)", style=palette.FG)
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
        policy = values.get(CLOSE_CYCLE_FIELD)
        if policy in (CLOSE_AFTER_RUN, CLOSE_NEVER):
            cell.append(f" · {policy}", style="dim")
        else:
            cell.append(" · close unset", style=palette.WARN)
        return cell
    es = (descriptor or {}).get("evidence_set")
    if es:
        return Text(es["reference_id"], style="dim")
    return Text("no evidence set", style=palette.WARN)


def _destination(f: dict, config_view: Optional[List[dict]] = None, in_manifest: bool = False) -> RenderableType:
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
            rows.append(("cycle closes", _close_label(values.get(CLOSE_CYCLE_FIELD))))
        else:
            rows.append(("assessment", Text(f"a {atype} assessment, chosen per manifest", style=palette.FG)))
        fmt = ir.get("format")
        rows.append(("format", Text(f"{fmt + ' — ' if fmt else ''}the tool's own file, never enveloped", style="dim")))
        rows.append(("send", Text("i on the Paramify tab, to the assessment's pipeline", style="dim")))
    else:
        es = f.get("evidence_set")
        if es:
            value = Text(es["reference_id"], style=palette.FG)
            if es.get("name"):
                value.append(f" — {es['name']}", style="dim")
            rows.append(("evidence set", value))
        else:
            rows.append(("evidence set", Text(
                "none declared — the upload skips it unless the uploader config names one",
                style=palette.WARN,
            )))
        rows.append(("send", Text("ctrl+u on the Paramify tab, enveloped JSON", style="dim")))
    return Group(Text("sends to", style="bold"), _kv_table(rows))


def fetcher_detail(f: dict) -> RenderableType:
    """Full detail view for one fetcher descriptor."""
    title = Text()
    title.append(f.get("name", ""), style=f"bold {palette.FG}")
    if f.get("version"):
        title.append(f"  v{f['version']}", style="dim")

    meta = Text()
    meta.append("kind: ", style="dim")
    meta.append_text(kind_pill(kinds.kind_of(f)))
    meta.append("    category: ", style="dim")
    meta.append(f.get("category") or "—", style=palette.FG)
    meta.append("    targets: ", style="dim")
    meta.append("yes" if f.get("supports_targets") else "no", style=palette.FG)

    description = Text(f.get("description") or "(no description)", style="italic")

    return Group(
        title,
        meta,
        Text(),
        description,
        Text(),
        _destination(f),
        Text(),
        _field_table("secrets", f.get("secrets", [])),
        Text(),
        _field_table("config", f.get("config", [])),
        Text(),
        _field_table("target fields", f.get("target_schema", [])),
    )


def empty_detail(message: Optional[str] = None) -> RenderableType:
    return Text(message or "Select a fetcher to see its contract.", style="dim italic")


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


def _status(set_: bool, required: bool) -> Text:
    if set_:
        return Text("set", style=palette.OK)
    return Text("required — unset", style=palette.WARN) if required else Text("unset", style="dim")


def entry_detail(
    descriptor: Optional[dict],
    entry: dict,
    errors: Optional[List[str]] = None,
    config_view: Optional[List[dict]] = None,
) -> RenderableType:
    """Render one manifest entry: its current config/secrets/targets vs the contract."""
    use = entry.get("use", "?")
    if descriptor is None:
        return Group(
            Text(use, style=f"bold {palette.FG}"),
            Text("unknown fetcher — not discovered in the catalog", style=palette.WARN),
        )

    fanout = descriptor.get("supports_targets")
    header = Text()
    header.append(use, style=f"bold {palette.FG}")
    header.append("  ")
    header.append_text(kind_pill(kinds.kind_of(descriptor)))
    header.append("  [fanout]" if fanout else "  [single]", style="dim")

    secs = entry.get("secrets") or {}
    parts: List[RenderableType] = [
        header, Text(), _destination(descriptor, config_view, in_manifest=True), Text(),
    ]

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
            if source == "entry":
                rows.append((c["name"], Text(str(c["value"]), style=palette.FG)))
            elif source and source.startswith("platforms."):
                value = Text(str(c["value"]), style=palette.FG)
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
            parts.append(Text("  none — press 't' to add", style=palette.WARN))
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
