"""The Validators tab (4): choose which validators each fetcher tracks.

Left: the manifest's fetchers, with how many Paramify-made and community-made
validators each one tracks. Right: every validator available for the
highlighted fetcher, in a Paramify section and a community section; space
tracks or untracks one and the manifest is saved straight away; enter opens
the full validator (claim, regex, rules in plain words, evidence sets, file).

Saved shape: an entry with no `validators:` tracks the defaults (every
Paramify-made validator for its set); the first change writes the exact list.
Untracking only stops counting a validator; nothing is removed from Paramify.
"""

from __future__ import annotations

import re
from pathlib import Path

from rich.console import Group
from rich.syntax import Syntax
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Label, Static

from framework import api
from framework.config_loader import discover_fetchers
from framework.tui import palette
from framework.tui.components.table import DataTable
from framework.validators import available_for, default_keys, discover_validators

# Each source gets its own hue, used everywhere it appears: the section pill,
# the edge bar on each row, the fetcher counts and the detail pane.
SOURCE = {
    "paramify": {"label": "PARAMIFY", "fg": palette.BLUE, "pill": palette.PARAMIFY_PILL,
                 "blurb": "Made and maintained by Paramify. Tracked by default."},
    "community": {"label": "COMMUNITY", "fg": palette.ORANGE, "pill": palette.COMMUNITY_PILL,
                  "blurb": "Made by the community, not Paramify. Not tracked unless you tick it."},
}
ORDER = ("paramify", "community")


def fit(text: str, width: int) -> str:
    """Cut text to width with an ellipsis (width < 1 = no room known yet: leave it)."""
    if width < 1 or len(text) <= width:
        return text
    return text[: max(width - 1, 1)] + "…"


def source_pill(source: str) -> Text:
    spec = SOURCE.get(source)
    if spec is None:
        return Text(source.upper(), style=palette.MUTED)
    text = Text()
    text.append(f" {spec['label']} ", style=spec["pill"])
    return text


_OPS = {"MATCH_COUNT": "number of matches", "MATCH_TEXT": "matched text"}


def describe_rule(rule: dict, groups: list) -> str:
    """One validation rule in plain words: 'group 1 (vendors_unresolved) equals 0'."""
    op = (rule.get("regexOperation") or {})
    kind = op.get("type", "?")
    if kind == "MATCH_GROUP":
        n = op.get("groupNumber")
        name = groups[n - 1] if isinstance(n, int) and 0 < n <= len(groups) else None
        subject = f"group {n}" + (f" ({name})" if name else "")
    else:
        subject = _OPS.get(kind, kind.lower().replace("_", " "))
    value = rule.get("value") or {}
    shown = value.get("customText")
    if shown is None:
        shown = (value.get("type") or "").lower().replace("_", " ")
    else:
        shown = f'"{shown}"' if not str(shown).lstrip("-").isdigit() else str(shown)
    return f"{subject} {str(rule.get('criteria', '?')).lower().replace('_', ' ')} {shown}"


class ValidatorModal(ModalScreen[bool]):
    """Everything about one validator: what it claims, its regex, its rules in
    plain words, where it applies, and the YAML file itself. space asks the
    page to track / untrack it (dismisses True); esc / enter / q close."""

    BINDINGS = [Binding("escape,q,enter", "close", "Close"), Binding("space", "toggle", "Track")]

    DEFAULT_CSS = """
    ValidatorModal { align: center middle; }
    #vm-card { width: 90%; max-width: 130; height: 90%; border: round $primary; background: $surface; padding: 0 1; }
    #vm-title { height: auto; padding: 1 0 0 0; }
    #vm-body { height: 1fr; }
    #vm-foot { height: 1; color: $text-muted; }
    """

    def __init__(self, v, tracked: bool, ref: str, root) -> None:
        super().__init__()
        self.v, self.tracked, self.ref, self.root = v, tracked, ref, root

    def compose(self) -> ComposeResult:
        v = self.v
        with Vertical(id="vm-card"):
            title = source_pill(v.source)
            title.append(f"  {v.name}", style="bold")
            title.append(f"\n{v.key}   {v.type.lower()} · {v.role or 'no role'}   ", style=palette.MUTED)
            title.append("tracked" if self.tracked else "not tracked",
                         style=palette.OK if self.tracked else palette.MUTED)
            yield Label(title, id="vm-title")
            with VerticalScroll(id="vm-body"):
                yield Static(self._body())
            foot = Text()
            foot.append("space", style=f"bold {palette.ACCENT}")
            foot.append(" untrack" if self.tracked else " track", style=palette.MUTED)
            foot.append("    esc", style=f"bold {palette.ACCENT}")
            foot.append(" close", style=palette.MUTED)
            yield Label(foot, id="vm-foot")

    def _section(self, name: str) -> Text:
        return Text(f"\n{name}", style=f"bold {palette.INFO}")

    def _body(self):
        v = self.v
        parts = [self._section("claims"), Text(v.statement)]
        if v.regex:
            groups = re.findall(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>", v.regex)
            parts += [self._section("regex"), Text(v.regex, style=palette.YELLOW)]
            if groups:
                parts.append(Text("named groups: " + ", ".join(f"{i}={g}" for i, g in enumerate(groups, 1)),
                                  style=palette.MUTED))
            rules = v.validation_rules or []
            if rules:
                parts.append(self._section("passes when"))
                for rule in rules:
                    line = Text("  • ")
                    line.append(describe_rule(rule, groups))
                    parts.append(line)
        else:
            parts += [self._section("regex"), Text(f"none ({v.type.lower()} validator)", style=palette.MUTED)]
        parts.append(self._section(f"evidence sets ({len(v.evidence_sets)})"))
        for ref in v.evidence_sets:
            line = Text(f"  {ref}")
            if ref == self.ref:
                line.append("   ← this fetcher", style=palette.MUTED)
            parts.append(line)
        if v.path and Path(v.path).exists():
            rel = Path(v.path).relative_to(self.root) if self.root else Path(v.path)
            parts.append(self._section(f"file  {rel}"))
            parts.append(Syntax(Path(v.path).read_text(), "yaml", theme="monokai",
                                word_wrap=True, background_color=self.app.current_theme.surface))
        return Group(*parts)

    def action_close(self) -> None:
        self.dismiss(False)

    def action_toggle(self) -> None:
        self.dismiss(True)


class ValidatorsPage(Vertical):
    HINTS = [("space", "track / untrack"), ("enter", "regex & rules"), ("a", "back to defaults"),
             ("←→", "fetchers / validators")]

    BINDINGS = [
        Binding("space", "toggle", "Track", show=False),
        Binding("a", "defaults", "Defaults", show=False),
        # Priority: the tables bind left / right to their own cell cursor.
        Binding("right", "to_validators", show=False, priority=True),
        Binding("left", "to_fetchers", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    ValidatorsPage { padding: 1 1 0 1; }
    #vs-head { height: 1; margin-bottom: 1; color: $text-muted; }
    #vs-body { height: 1fr; }
    #vs-left { width: 2fr; max-width: 78; min-width: 36; border: round $panel-lighten-2; border-title-color: $text-muted; }
    #vs-left:focus-within { border: round $primary; }
    #vs-right { width: 3fr; border: round $panel-lighten-2; border-title-color: $text-muted; }
    #vs-right:focus-within { border: round $primary; }
    #vs-fetchers, #vs-validators { height: 1fr; }
    #vs-detail { height: auto; max-height: 12; padding: 1 1 0 1; border-top: solid $panel-lighten-2; }
    """

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self._fetchers: list = []  # [{entry, name, ref, available}]
        self._shown: list = []  # validators in the right table, in order
        self._rows: list = []  # one per table row: a validator, or a section name (str), or None

    def compose(self) -> ComposeResult:
        yield Static(id="vs-head")
        with Horizontal(id="vs-body"):
            with Vertical(id="vs-left"):
                yield DataTable(id="vs-fetchers", cursor_type="row", zebra_stripes=False)
            with Vertical(id="vs-right"):
                yield DataTable(id="vs-validators", cursor_type="row", zebra_stripes=False)
                yield Static(id="vs-detail")

    def on_mount(self) -> None:
        self.query_one("#vs-left").border_title = "fetchers"
        self.query_one("#vs-validators", DataTable).show_header = False
        self.rebuild()

    def on_resize(self) -> None:
        # Names are cut to the width the panels get, so redraw when it changes.
        if self._fetchers:
            self._draw_fetchers()

    def focus_default(self) -> None:
        self.rebuild()
        self.query_one("#vs-fetchers", DataTable).focus()

    # ---- data ------------------------------------------------------------- #

    def rebuild(self) -> None:
        root = self.app.root_path
        manifest = self.app.manifest or {}
        if root is None:
            return
        fetchers = discover_fetchers(root)
        registry = list(discover_validators(root).values())
        self._fetchers = []
        for entry in (manifest.get("run") or {}).get("fetchers") or []:
            name = entry.get("use") if isinstance(entry, dict) else None
            fetcher = fetchers.get(name) if name else None
            if not fetcher or not fetcher.evidence_set or fetcher.is_pipeline:
                continue
            ref = fetcher.evidence_set.reference_id
            avail = sorted(available_for(ref, registry),
                           key=lambda v: (v.source != "paramify", v.role != "completeness", v.key))
            self._fetchers.append({"entry": entry, "name": name, "ref": ref, "available": avail,
                                   "source": fetcher.source})
        self._draw_fetchers()

    def _tracked(self, item: dict) -> set:
        chosen = item["entry"].get("validators")
        return set(default_keys(item["available"]) if chosen is None else chosen)

    def _current(self) -> dict | None:
        table = self.query_one("#vs-fetchers", DataTable)
        if not self._fetchers:
            return None
        return self._fetchers[min(table.cursor_row, len(self._fetchers) - 1)]

    # ---- drawing ---------------------------------------------------------- #

    def _draw_fetchers(self) -> None:
        table = self.query_one("#vs-fetchers", DataTable)
        keep = table.cursor_row if table.row_count else 0
        # Columns too: a cleared table keeps the widths of its widest rows so far.
        table.clear(columns=True)
        table.add_columns(Text("paramify", style=palette.BLUE), Text("community", style=palette.ORANGE), "fetcher")
        for item in self._fetchers:
            table.add_row(*self._fetcher_cells(item))
        if self._fetchers:
            table.move_cursor(row=min(keep, len(self._fetchers) - 1))
        head = source_pill("paramify")
        head.append(" tracked by default  ·  ", style=palette.MUTED)
        head.append_text(source_pill("community"))
        head.append(" opt in  ·  ", style=palette.MUTED)
        head.append("*", style=palette.INFO)
        head.append(" changed (a resets)", style=palette.MUTED)
        self.query_one("#vs-head", Static).update(head)
        self._draw_validators()

    def _fetcher_cells(self, item: dict) -> list:
        tracked = self._tracked(item)
        cells = []
        for source in ORDER:
            avail = [v for v in item["available"] if v.source == source]
            if not avail:
                cells.append(Text("  —", style=palette.MUTED))
                continue
            n = sum(1 for v in avail if v.key in tracked)
            cells.append(Text(f"{n:>3}/{len(avail)}", style=SOURCE[source]["fg"] if n else palette.MUTED))
        pinned = item["entry"].get("validators") is not None
        community = item.get("source") == "community"
        # count columns + cell padding + scrollbar (+ the community label)
        room = self.query_one("#vs-left").content_size.width - 25 - (3 if pinned else 0) - (13 if community else 0)
        name = Text(fit(item["name"], room))
        if community:
            name.append("  ")
            name.append_text(palette.community_tag("community"))
        if pinned:
            name.append("  *", style=palette.INFO)
        return [*cells, name]

    def _draw_validators(self) -> None:
        table = self.query_one("#vs-validators", DataTable)
        keep = table.cursor_row if table.row_count else 0
        table.clear(columns=True)
        table.add_columns("", "", "")
        item = self._current()
        right = self.query_one("#vs-right")
        if item is None:
            right.border_title = "validators"
            self.query_one("#vs-detail", Static).update("")
            return
        tracked = self._tracked(item)
        self._shown = list(item["available"])
        right.border_title = f"{item['name']}  ·  {item['ref']}" + (
            f"  ·  [{palette.ORANGE}]community fetcher[/]" if item.get("source") == "community" else "")
        self._rows = []
        for source in ORDER:
            group = [v for v in self._shown if v.source == source]
            if not group:
                continue
            if self._rows:
                self._rows.append(None)
                table.add_row("", "", "")
            n = sum(1 for v in group if v.key in tracked)
            head = source_pill(source)
            head.append(f"  {n} of {len(group)} tracked", style=SOURCE[source]["fg"])
            self._rows.append(source)
            table.add_row("", "", head)
            for v in group:
                self._rows.append(v)
                table.add_row(*self._validator_cells(v, v.key in tracked, item))
        if self._rows:
            row = min(keep, len(self._rows) - 1)
            if self._rows[row] is None or isinstance(self._rows[row], str):
                row = self._first_validator_row()
            table.move_cursor(row=row)
        self._draw_detail()

    def _first_validator_row(self) -> int:
        return next((i for i, r in enumerate(self._rows) if r is not None and not isinstance(r, str)), 0)

    def _row_validator(self):
        table = self.query_one("#vs-validators", DataTable)
        if not self._rows:
            return None
        r = self._rows[min(table.cursor_row, len(self._rows) - 1)]
        return r

    def _validator_cells(self, v, on: bool, item: dict) -> list:
        hue = SOURCE.get(v.source, {}).get("fg", palette.MUTED)
        edge = Text("▌", style=hue)
        box = Text("[x]" if on else "[ ]", style=hue if on else palette.MUTED)
        changed = item["entry"].get("validators") is not None and on != (v.source == "paramify")
        # edge + box columns + cell padding + scrollbar
        room = self.query_one("#vs-right").content_size.width - 12 - (3 if changed else 0)
        name = Text(fit(v.name, room), style="bold" if on else palette.MUTED)
        # * = differs from the default (Paramify on, community off), same mark as the fetcher list.
        if changed:
            name.append("  *", style=palette.INFO)
        return [edge, box, name]

    def _draw_detail(self) -> None:
        detail = self.query_one("#vs-detail", Static)
        if not self._shown:
            detail.update(Text("No validators for this evidence set yet.", style=palette.MUTED))
            return
        v = self._row_validator()
        if v is None or isinstance(v, str):
            source = v or "paramify"
            text = source_pill(source)
            text.append("\n" + SOURCE[source]["blurb"], style=palette.MUTED)
            detail.update(text)
            return
        text = source_pill(v.source)
        text.append(f"  {v.name}", style="bold")
        text.append("\n" + v.statement)
        meta = f"\n{v.type.lower()} · {v.role or 'no role'}"
        others = [r for r in v.evidence_sets if r != self._current()["ref"]]
        if others:
            meta += f" · also used by {len(others)} other evidence set{'s' if len(others) != 1 else ''}"
        text.append(meta, style=palette.MUTED)
        detail.update(text)

    # ---- events / actions ------------------------------------------------- #

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "vs-fetchers":
            self._draw_validators()
        else:
            self._draw_detail()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "vs-fetchers":
            self.action_to_validators()
        else:
            self.action_inspect()

    def action_inspect(self) -> None:
        item = self._current()
        v = self._row_validator()
        if item is None or v is None or isinstance(v, str):
            return

        def done(toggle: bool | None) -> None:
            if toggle:
                self.action_toggle()

        self.app.push_screen(ValidatorModal(v, v.key in self._tracked(item), item["ref"], self.app.root_path), done)

    def action_to_validators(self) -> None:
        if self.query_one("#vs-fetchers", DataTable).has_focus:
            self.query_one("#vs-validators", DataTable).focus()

    def action_to_fetchers(self) -> None:
        self.query_one("#vs-fetchers", DataTable).focus()

    def action_toggle(self) -> None:
        item = self._current()
        vtable = self.query_one("#vs-validators", DataTable)
        if item is None or not self._shown:
            return
        if not vtable.has_focus:
            vtable.focus()
            return
        v = self._row_validator()
        if v is None or isinstance(v, str):
            return
        tracked = self._tracked(item)
        tracked ^= {v.key}
        # Keep registry order so the saved list reads like the tab.
        item["entry"]["validators"] = [x.key for x in item["available"] if x.key in tracked]
        if v.key in tracked:
            self._save(f"Tracking {v.name}.")
        else:
            self._save(f"Stopped tracking {v.name}. Nothing is removed from Paramify.")

    def action_defaults(self) -> None:
        item = self._current()
        if item is None or item["entry"].get("validators") is None:
            return
        item["entry"].pop("validators", None)
        self._save(f"{item['name']} is back to the defaults.")

    def _save(self, what: str) -> None:
        try:
            api.dump_manifest(self.app.manifest, self.app.manifest_path, self.app.root_path)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"Couldn't save the manifest: {exc}", severity="error")
            return
        self.notify(what, timeout=3)
        # The Paramify tab re-reads the workspace the next time it is shown.
        try:
            from framework.tui.screens.paramify import ParamifyPage
            self.screen.query_one(ParamifyPage)._stale = True
        except Exception:  # noqa: BLE001
            pass
        ftable = self.query_one("#vs-fetchers", DataTable)
        row = ftable.cursor_row
        for col, cell in enumerate(self._fetcher_cells(self._fetchers[row])):
            ftable.update_cell_at((row, col), cell, update_width=True)
        vtable = self.query_one("#vs-validators", DataTable)
        vrow, scroll = vtable.cursor_row, vtable.scroll_y
        self._draw_validators()
        vtable.move_cursor(row=vrow)
        vtable.scroll_to(y=scroll, animate=False)
