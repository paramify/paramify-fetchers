"""Rich renderers for the JSON-able descriptors returned by framework.api.

These turn a `_fetcher_descriptor` dict (see framework/api.py) into Rich
renderables for display in a Textual `Static`. Kept separate from the screens so
later phases (the manifest editor) can reuse the same field rendering.
"""

from typing import Any, List, Optional

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from framework.secret_resolver import env_var_name, is_env_ref_attempt
from framework.tui import palette


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


def fetcher_detail(f: dict) -> RenderableType:
    """Full detail view for one fetcher descriptor."""
    title = Text()
    title.append(f.get("name", ""), style=f"bold {palette.FG}")
    if f.get("version"):
        title.append(f"  v{f['version']}", style="dim")

    meta = Text()
    meta.append("category: ", style="dim")
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
    header.append("  [fanout]" if fanout else "  [single]", style="dim")

    secs = entry.get("secrets") or {}
    parts: List[RenderableType] = [header, Text()]

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
