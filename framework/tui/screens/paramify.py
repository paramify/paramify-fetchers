"""Paramify page — a setup grid of what each manifest fetcher has in Paramify.

One row per evidence fetcher: its evidence set, script, validators, linked
capabilities, artifacts, and whether it is ready. The data is one read-only
call, ``api.paramify_status``, run in a worker when the tab opens and on
ctrl+r. Below the grid, the highlighted fetcher's evidence set and the
capabilities its validator pairs prove.

The read is lazy: a manifest load or switch only marks the status stale, and
the page reads the workspace the next time it is shown. So the TUI does not
call Paramify at start-up, or while the user is on another tab.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import ContentSwitcher, Static, Tab, Tabs

from framework import api
from framework.tui import palette
from framework.tui.components.table import DataTable

NO_TOKEN = (
    "No Paramify API token found. Set PARAMIFY_UPLOAD_API_TOKEN (or PARAMIFY_API_TOKEN) in the "
    "environment, then press ctrl+r. Until then this page shows what the manifest and the registry hold."
)
EMPTY = "No fetchers in this manifest yet.\nAdd them on the Fetchers tab (1)."
ONLY_SCAN = "This manifest's fetchers all send scan reports. They are on the Pipelines tab (5)."
NO_LINKS = "No capability uses this evidence set yet.\nLink its validators to a capability in Paramify."
CAPS_OFFLINE = "Capabilities are read from Paramify.\nThey show once a token is set."
READING = "reading the workspace…"

# A set with more validators than this lists them by name in the
# linked-capabilities pane instead of one V column each.
MAX_V_COLUMNS = 6
# Opening the tab re-reads the workspace when the last read is older than this.
STALE_AFTER = 30.0

_SCRIPT_CELLS = {
    "in_sync": ("✓", palette.OK),
    "update": ("update", palette.WARN),
    "create": ("+ create", palette.INFO),
    "drift": ("drift", palette.WARN),
    "error": ("error", palette.FAIL),
}
_SCRIPT_DETAIL = {
    "in_sync": ("✓ in sync", palette.OK),
    "update": ("update: the local script is newer", palette.WARN),
    "create": ("+ create: not in Paramify yet", palette.INFO),
    "drift": ("drift: changed in Paramify (scripts sync --force overwrites)", palette.WARN),
    "error": ("error: see paramify scripts sync --dry-run", palette.FAIL),
}


class StatusReady(Message):
    """One api.paramify_status() result (or its error) from the worker thread."""

    def __init__(self, status: dict | None, manifest_path, error: str | None) -> None:
        self.status = status
        self.manifest_path = manifest_path
        self.error = error
        super().__init__()


class ArtifactsReady(Message):
    """The newest artifact date of one evidence set, from the worker thread."""

    def __init__(self, set_id: str, newest: str | None) -> None:
        self.set_id = set_id
        self.newest = newest
        super().__init__()


def _dim(text: str) -> Text:
    return Text(text, style=palette.MUTED)


def _fraction(have: int, want: int) -> Text:
    style = palette.OK if have == want else (palette.WARN if have else palette.FAIL)
    return Text(f"{have}/{want}", style=style)


def _capability_ids(row: dict) -> set:
    return {p["capability_id"] for p in row["pairs"]}


def grid_cells(row: dict, online: bool) -> list:
    """One status row as grid cells (spec §6.3)."""
    validators = row["validators"]
    if not online:
        return [
            row["name"], _dim("—"), _dim("—"),
            _dim(f"{len(validators)} in registry" if validators else "none"),
            _dim("—"), _dim("—"), _dim("·"),
        ]
    have = sum(v["paired"] for v in validators)
    script = _SCRIPT_CELLS.get(row["script"] or "")
    caps = len(_capability_ids(row))
    arts = row["evidence_set"]["artifact_count"]
    return [
        row["name"],
        Text("✓", style=palette.OK) if row["evidence_set"]["id"] else Text("+ create", style=palette.INFO),
        Text(script[0], style=script[1]) if script else _dim("—"),
        _fraction(have, len(validators)) if validators else _dim("none"),
        Text(str(caps)) if caps else _dim("—"),
        Text(str(arts), style=palette.OK) if arts else _dim("0"),
        palette.pill("READY", "ok") if row["ready"] else _dim("·"),
    ]


def totals_text(rows: list, shown: int) -> Text:
    """How far each setup step has come, across the fetchers."""
    n = len(rows)
    text = Text()

    def part(label: str, have: int) -> None:
        text.append(f"{label} ", style=palette.MUTED)
        text.append_text(_fraction(have, n) if n else Text("0/0"))
        text.append("     ")

    part("evidence sets", sum(r["evidence_set"]["id"] is not None for r in rows))
    part("scripts", sum(r["script"] == "in_sync" for r in rows))
    part("validators", sum(all(v["paired"] for v in r["validators"]) for r in rows))
    text.append("capabilities ", style=palette.MUTED)
    text.append(f"{sum(len(r['pairs']) for r in rows)} links")
    text.append("     ")
    part("uploaded", sum(r["evidence_set"]["artifact_count"] > 0 for r in rows))
    if shown != n:
        text.append(f"showing {shown} of {n}", style=palette.ACCENT)
    return text


class ParamifyPage(Vertical):
    BINDINGS = [
        Binding("ctrl+r", "refresh_status", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="pf-summary")
        yield Tabs(Tab("by fetcher", id="lens-fetcher"), Tab("by capability", id="lens-capability"),
                   id="pf-lens-tabs")
        with ContentSwitcher(initial="pf-by-fetcher", id="pf-lens"):
            with Vertical(id="pf-by-fetcher"):
                with Vertical(id="pf-grid-panel", classes="panel"):
                    yield DataTable(id="pf-grid", cursor_type="row")
                    yield Static("", id="pf-grid-empty", classes="empty-hint")
                    yield Static("", id="pf-totals")
                with Horizontal(id="pf-detail"):
                    with VerticalScroll(id="pf-set-panel", classes="panel"):
                        yield Static("", id="pf-set")
                    with Vertical(id="pf-caps-panel", classes="panel"):
                        yield DataTable(id="pf-caps", cursor_type="row")
                        yield Static("", id="pf-caps-empty", classes="empty-hint")
            with Vertical(id="pf-by-capability"):
                yield Static(_dim("Capabilities come in the next step."), id="pf-cap-placeholder")

    def on_mount(self) -> None:
        self._status: dict | None = None
        self._status_at: float | None = None
        self._status_clock: str = ""
        self._error: str | None = None
        self._reading = False
        self._stale = True
        self._newest: dict = {}
        self._rows: dict = {}
        self.query_one("#pf-lens-tabs", Tabs).can_focus = False
        grid = self.query_one("#pf-grid", DataTable)
        grid.add_columns("fetcher", "evidence set", "script", "validators", "capabilities", "artifacts", "")
        self.query_one("#pf-grid-panel").border_title = "evidence sets"
        self.query_one("#pf-set-panel").border_title = "evidence set"
        self.query_one("#pf-caps-panel").border_title = "linked capabilities"
        self._draw()

    def on_resize(self) -> None:
        # Spec §7: on a short terminal the grid keeps its rows; the detail gives way.
        self.query_one("#pf-detail").styles.height = 10 if self.app.size.height < 40 else 13

    # -- hints ------------------------------------------------------------ #

    @property
    def HINTS(self) -> list:  # noqa: N802 — the workspace reads HINTS off every page
        return [("↑↓", "fetcher"), ("ctrl+r", "refresh")]

    # -- reading ---------------------------------------------------------- #

    def rebuild(self) -> None:
        """After a manifest load or switch: drop the old status and read again
        the next time the page is shown (never from here — see the module doc)."""
        if self._status is not None and self._status_manifest != getattr(self.app, "manifest_path", None):
            self._status = None
            self._rows = {}
        self._stale = True
        self._draw()

    @property
    def _status_manifest(self):
        return getattr(self, "_read_for", None)

    def focus_default(self) -> None:
        if self._stale or self._status_at is None or time.monotonic() - self._status_at > STALE_AFTER:
            self.request_status()
        self.query_one("#pf-grid", DataTable).focus()

    def action_refresh_status(self) -> None:
        self.request_status()

    def request_status(self) -> None:
        if self._reading:
            return
        path = getattr(self.app, "manifest_path", None)
        if path is None:
            return
        self._reading = True
        self._stale = False
        self._draw_summary()
        self._status_worker(self.app.root_path, path)

    @work(thread=True, exclusive=True, group="paramify-status")
    def _status_worker(self, root, manifest_path) -> None:
        try:
            status, error = api.paramify_status(root, Path(manifest_path)), None
        except Exception as exc:  # noqa: BLE001 — shown in the problem bar
            status, error = None, str(exc)
        self.post_message(StatusReady(status, manifest_path, error))

    def on_status_ready(self, message: StatusReady) -> None:
        self._reading = False
        if message.manifest_path != getattr(self.app, "manifest_path", None):
            self._stale = True
            self._draw_summary()
            return  # read for a manifest that is no longer open
        if message.error is not None:
            self._error = message.error
        else:
            self._error = None
            self._status = message.status
            self._read_for = message.manifest_path
            self._status_at = time.monotonic()
            self._status_clock = datetime.now().strftime("%H:%M")
            self._newest = {}
        # Never focus from here: a read can land while the user is on another tab.
        self._draw()

    # -- rendering -------------------------------------------------------- #

    def _draw(self) -> None:
        self._draw_summary()
        self._draw_grid()

    def _online(self) -> bool:
        return bool(self._status and self._status["workspace"]["token"])

    def _draw_summary(self) -> None:
        summary = self.query_one("#pf-summary", Static)
        status = self._status
        problem: str | None = None
        if self._error is not None:
            since = f" This is the status from {self._status_clock}." if status else ""
            problem = f"Could not read the workspace: {self._error}.{since} ctrl+r to try again."
        elif status is not None and not status["workspace"]["token"]:
            problem = NO_TOKEN
        elif status is not None:
            parts = [f"Could not read {part.replace('_', ' ')}: {msg}." for part, msg in status["errors"].items()
                     if part in ("evidence_sets", "scripts")]
            if parts:
                problem = " ".join(parts) + " ctrl+r to try again."
        summary.set_class(problem is not None, "problem")

        line = Text()
        if status is not None:
            ws = status["workspace"]
            line.append(ws.get("base_url") or "", style=palette.INFO)
            if ws["token"]:
                line.append("    token ✓", style=palette.OK)
                rows = status["fetchers"]
                if rows:
                    ready = sum(r["ready"] for r in rows)
                    line.append(f"    {ready}/{len(rows)} ready", style=palette.OK if ready == len(rows) else palette.WARN)
            if status["pipelines_count"]:
                line.append(f"    {status['pipelines_count']} scan-report fetchers → Pipelines (5)", style=palette.MUTED)
            if status["skipped"]:
                line.append(f"    skipped: {', '.join(status['skipped'])}", style=palette.WARN)
        if self._reading:
            line.append(("    " if line.plain else "") + READING, style=palette.MUTED)
        if problem is not None:
            summary.update(Group(Text(problem), line) if line.plain and self._error is not None else Text(problem))
        else:
            summary.update(line)

    def _draw_grid(self) -> None:
        grid = self.query_one("#pf-grid", DataTable)
        panel = self.query_one("#pf-grid-panel", Vertical)
        detail = self.query_one("#pf-detail")
        status = self._status
        if status is None:
            return
        rows = status["fetchers"]
        online = self._online()
        self._rows = {r["name"]: r for r in rows}
        keep = self._cursor_key()
        grid.clear()
        for row in rows:
            grid.add_row(*grid_cells(row, online), key=row["name"])
        empty = not rows
        panel.set_class(empty, "empty")
        detail.display = not empty
        self.query_one("#pf-totals", Static).display = online and not empty
        if empty:
            hint = ONLY_SCAN if status["pipelines_count"] else EMPTY
            self.query_one("#pf-grid-empty", Static).update(Text(hint))
            panel.border_title = "evidence sets (0)"
            return
        ready = sum(r["ready"] for r in rows)
        panel.border_title = f"evidence sets ({len(rows)})" + (f"  ·  {ready} ready" if online else "")
        self.query_one("#pf-totals", Static).update(totals_text(rows, len(rows)))
        if keep in self._rows:
            grid.move_cursor(row=grid.get_row_index(keep))
        self._show(self._cursor_key())

    def _cursor_key(self) -> str | None:
        grid = self.query_one("#pf-grid", DataTable)
        if grid.row_count == 0:
            return None
        try:
            return grid.coordinate_to_cell_key(grid.cursor_coordinate).row_key.value
        except Exception:
            return None

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "pf-grid" and event.row_key is not None:
            self._show(event.row_key.value)

    # -- detail ----------------------------------------------------------- #

    def _show(self, key: str | None) -> None:
        row = self._rows.get(key) if key else None
        if row is None:
            return
        online = self._online()
        self.query_one("#pf-set", Static).update(self._set_info(row, online))
        self._show_caps(row, online)
        set_id = row["evidence_set"]["id"]
        if online and set_id and row["evidence_set"]["artifact_count"] and set_id not in self._newest:
            self._artifacts_worker(set_id)

    def _set_info(self, row: dict, online: bool) -> Group:
        info = Table.grid(padding=(0, 2))
        info.add_column(style=palette.MUTED)
        info.add_column()
        es = row["evidence_set"]
        if online:
            info.add_row("evidence set", Text(es["reference_id"], style=palette.INFO) if es["id"]
                         else Text(f"{es['reference_id']}  created by the scripts sync", style=palette.INFO))
            label, style = _SCRIPT_DETAIL.get(row["script"] or "", ("—", palette.MUTED))
            info.add_row("script", Text(label, style=style))
            arts = es["artifact_count"]
            newest = self._newest.get(es["id"])
            info.add_row("artifacts", Text(f"{arts}" + (f"  newest {newest}" if newest else ""))
                         if arts else _dim("none yet"))
        else:
            info.add_row("evidence set", Text(es["reference_id"]))
        body: list = [Text(row["name"], style="bold"), Text(""), info, Text("")]
        validators = row["validators"]
        if validators:
            table = Table.grid(padding=(0, 1))
            for i, v in enumerate(validators):
                mark = (Text("✓", style=palette.OK) if v["paired"] else Text("+", style=palette.INFO)) if online \
                    else _dim("·")
                table.add_row(Text(f"V{i + 1}", style=palette.ACCENT), mark, Text(v["name"]))
            body += [_dim("validators"), table]
        else:
            body.append(_dim("validators  none in the registry for this set"))
        return Group(*body)

    def _show_caps(self, row: dict, online: bool) -> None:
        table = self.query_one("#pf-caps", DataTable)
        panel = self.query_one("#pf-caps-panel", Vertical)
        empty = self.query_one("#pf-caps-empty", Static)
        table.clear(columns=True)
        status = self._status or {}
        error = (status.get("errors") or {}).get("capabilities")
        if not online or error or not row["pairs"]:
            panel.add_class("empty")
            if not online:
                empty.update(Text(CAPS_OFFLINE))
            elif error:
                empty.update(Text(f"Could not read the capabilities: {error}", style=palette.WARN))
            else:
                empty.update(Text(NO_LINKS))
            return
        panel.remove_class("empty")
        caps = {c["id"]: c for c in status.get("capabilities") or []}
        validators = row["validators"]
        index = {v["key"]: i for i, v in enumerate(validators)}
        groups: dict = {}
        for pair in row["pairs"]:
            groups.setdefault((pair["capability_id"], pair["function"]), []).append(pair["validator_key"])
        by_name = len(validators) > MAX_V_COLUMNS or any(k not in index for ks in groups.values() for k in ks)
        if by_name:
            table.add_columns("capability", "function", "validators in the pair")
        else:
            table.add_columns("capability", "function", *[f"V{i + 1}" for i in range(len(validators))])
        for (cap_id, function), keys in groups.items():
            cap = caps.get(cap_id) or {}
            label = Text(f"{cap.get('reference_id') or cap_id}  {cap.get('name') or ''}".rstrip())
            fn = _dim(function.lower().replace("_", " "))
            if by_name:
                names = [validators[index[k]]["name"] if k in index else "(not in the registry)" for k in keys]
                table.add_row(label, fn, " + ".join(names))
            else:
                marks = [Text("●", style=palette.ACCENT) if v["key"] in keys else _dim("·") for v in validators]
                table.add_row(label, fn, *marks)

    @work(thread=True, exclusive=True, group="paramify-artifacts")
    def _artifacts_worker(self, set_id: str) -> None:
        try:
            artifacts = api.list_artifacts(set_id)
        except Exception:  # noqa: BLE001 — the count still shows; only the date is lost
            artifacts = []
        created = (artifacts[0].get("created_at") or "") if artifacts else ""
        self.post_message(ArtifactsReady(set_id, created[:16].replace("T", " ") or None))

    def on_artifacts_ready(self, message: ArtifactsReady) -> None:
        self._newest[message.set_id] = message.newest
        row = self._rows.get(self._cursor_key() or "")
        if row is not None and row["evidence_set"]["id"] == message.set_id:
            self.query_one("#pf-set", Static).update(self._set_info(row, self._online()))
