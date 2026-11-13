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
from textual.widgets import (
    ContentSwitcher,
    Input,
    RichLog,
    Static,
    Tab,
    TabbedContent,
    Tabs,
)

from framework import api
from framework.sync.render import render_plan
from framework.tui import palette
from framework.tui.components.table import DataTable
from framework.tui.modals import ConfirmModal
from framework.tui.screens.paramify_events import (
    BUSY_NOTICE,
    ParamifyWriter,
    latest_run_scoped,
    upload_event_lines,
)

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

    def __init__(self, status: dict | None, manifest_path, error: str | None, setup: bool = False) -> None:
        self.status = status
        self.manifest_path = manifest_path
        self.error = error
        # True when the status could not be built from the local setup (an
        # unreadable manifest, registry or uploader config), not the workspace.
        self.setup = setup
        super().__init__()


class ActionEvent(Message):
    """One event of a running sync or upload ("scripts", "validators", "upload")
    from its worker thread."""

    def __init__(self, kind: str, ev: dict) -> None:
        self.kind = kind
        self.ev = ev
        super().__init__()


# A scripts-sync item outcome -> (plan category, log label, style).
_SCRIPT_MARKS = {
    "would_create": ("create", "create", palette.OK),
    "create": ("create", "created", palette.OK),
    "would_update": ("update", "update", palette.OK),
    "update": ("update", "updated", palette.OK),
    "would_noop": ("noop", "noop", "dim"),
    "noop": ("noop", "noop", "dim"),
    "would_drift": ("drift", "drift, kept", palette.WARN),
    "drift": ("drift", "drift, pushed", palette.WARN),
    "drift_skipped": ("drift", "drift, kept", palette.WARN),
    "error": ("error", "error", palette.FAIL),
}


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


def _unknown() -> Text:
    """A cell whose read failed: unknown, never a value that looks read."""
    return Text("?", style=palette.WARN)


def _capability_ids(row: dict) -> set:
    return {p["capability_id"] for p in row["pairs"]}


def grid_cells(row: dict, online: bool, errors: dict | None = None) -> list:
    """One status row as grid cells (spec §6.3). A cell whose read failed is
    "?", as in `paramify status`."""
    errors = errors or {}
    validators = row["validators"]
    if not online:
        return [
            row["name"], _dim("—"), _dim("—"),
            _dim(f"{len(validators)} in registry" if validators else "none"),
            _dim("—"), _dim("—"), _dim("·"),
        ]
    es = row["evidence_set"]
    sets_unknown = es.get("exists") is None
    have = sum(v["paired"] is True for v in validators)
    script = _SCRIPT_CELLS.get(row["script"] or "")
    caps = len(_capability_ids(row))
    arts = es["artifact_count"]
    if sets_unknown:
        set_cell = _unknown()
    else:
        set_cell = Text("✓", style=palette.OK) if es["exists"] else Text("+ create", style=palette.INFO)
    if row["script"] is None and "scripts" in errors:
        script_cell = _unknown()
    else:
        script_cell = Text(script[0], style=script[1]) if script else _dim("—")
    if not validators:
        validators_cell = _dim("none")
    elif any(v["paired"] is None for v in validators):
        validators_cell = Text(f"?/{len(validators)}", style=palette.WARN)
    else:
        validators_cell = _fraction(have, len(validators))
    if "capabilities" in errors or sets_unknown:
        caps_cell = _unknown()
    else:
        caps_cell = Text(str(caps)) if caps else _dim("—")
    if arts is None:
        arts_cell = _unknown()
    else:
        arts_cell = Text(str(arts), style=palette.OK) if arts else _dim("0")
    return [
        row["name"], set_cell, script_cell, validators_cell, caps_cell, arts_cell,
        palette.pill("READY", "ok") if row["ready"] else _dim("·"),
    ]


def totals_text(rows: list, shown: int, errors: dict | None = None) -> Text:
    """How far each setup step has come, across the fetchers. A count whose
    read failed is "?", as in `paramify status`."""
    errors = errors or {}
    n = len(rows)
    sets_known = "evidence_sets" not in errors
    text = Text()

    def part(label: str, have: int, known: bool = True) -> None:
        text.append(f"{label} ", style=palette.MUTED)
        if not known:
            text.append(f"?/{n}", style=palette.WARN)
        else:
            text.append_text(_fraction(have, n) if n else Text("0/0"))
        text.append("     ")

    part("evidence sets", sum(r["evidence_set"].get("exists") is True for r in rows), sets_known)
    part("scripts", sum(r["script"] == "in_sync" for r in rows), "scripts" not in errors)
    part("validators", sum(all(v["paired"] is True for v in r["validators"]) for r in rows), sets_known)
    text.append("capabilities ", style=palette.MUTED)
    if sets_known and "capabilities" not in errors:
        text.append(f"{sum(len(r['pairs']) for r in rows)} links")
    else:
        text.append("? links", style=palette.WARN)
    text.append("     ")
    part("uploaded", sum((r["evidence_set"]["artifact_count"] or 0) > 0 for r in rows), sets_known)
    if shown != n:
        text.append(f"showing {shown} of {n}", style=palette.ACCENT)
    return text


class ParamifyPage(ParamifyWriter, Vertical):
    BINDINGS = [
        Binding("ctrl+r", "refresh_status", "Refresh"),
        Binding("slash", "focus_filter", "Filter"),
        Binding("w", "needs_work", "Needs work"),
        Binding("s", "sync_scripts", "Sync scripts"),
        Binding("v", "sync_validators", "Sync validators"),
        Binding("u", "upload_run", "Upload run"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="pf-summary")
        yield Tabs(Tab("by fetcher", id="lens-fetcher"), Tab("by capability", id="lens-capability"),
                   id="pf-lens-tabs")
        with ContentSwitcher(initial="pf-by-fetcher", id="pf-lens"):
            with Vertical(id="pf-by-fetcher"):
                with Vertical(id="pf-grid-panel", classes="panel"):
                    yield Input(placeholder="/ filter evidence sets…", id="pf-filter")
                    yield DataTable(id="pf-grid", cursor_type="row")
                    yield Static("", id="pf-grid-empty", classes="empty-hint")
                    yield Static("", id="pf-totals")
                with Horizontal(id="pf-detail"):
                    with VerticalScroll(id="pf-set-panel", classes="panel"):
                        yield Static("", id="pf-set")
                    with Vertical(id="pf-caps-panel", classes="panel"):
                        yield DataTable(id="pf-caps", cursor_type="row")
                        yield Static("", id="pf-caps-empty", classes="empty-hint")
                # An action's log takes the detail row's place, so the grid keeps
                # its rows; moving the cursor brings the detail back.
                with Vertical(id="pf-activity-panel", classes="panel"):
                    yield Static("", id="pf-activity")
                    yield RichLog(id="pf-log", markup=False, wrap=True, highlight=False)
            with Vertical(id="pf-by-capability"):
                yield Static(_dim("Capabilities come in the next step."), id="pf-cap-placeholder")

    def on_mount(self) -> None:
        self._status: dict | None = None
        self._status_at: float | None = None
        self._status_clock: str = ""
        self._error: str | None = None
        self._error_setup = False
        self._reading = False
        self._reread = False
        self._stale = True
        self._newest: dict = {}
        self._rows: dict = {}
        self._filter = ""
        self._needs_work = False
        self._planning = False
        self._acting = False
        activity = self.query_one("#pf-activity-panel", Vertical)
        activity.border_title = "activity"
        activity.display = False
        self.query_one("#pf-lens-tabs", Tabs).can_focus = False
        # The empty-manifest hint takes focus, so the page keys still work.
        self.query_one("#pf-grid-empty", Static).can_focus = True
        grid = self.query_one("#pf-grid", DataTable)
        grid.add_columns("fetcher", "evidence set", "script", "validators", "capabilities", "artifacts", "")
        self.query_one("#pf-grid-panel").border_title = "evidence sets"
        self.query_one("#pf-set-panel").border_title = "evidence set"
        self.query_one("#pf-caps-panel").border_title = "linked capabilities"
        self._draw()

    def on_resize(self) -> None:
        # Spec §7: on a short terminal the grid keeps its rows; the detail gives way.
        height = 8 if self.app.size.height < 40 else 13
        self.query_one("#pf-detail").styles.height = height
        self.query_one("#pf-activity-panel").styles.height = height

    # -- hints ------------------------------------------------------------ #

    @property
    def HINTS(self) -> list:  # noqa: N802 — the workspace reads HINTS off every page
        hints = [("↑↓", "fetcher"), ("/", "filter"), ("w", "needs work")]
        if self._actions_on():
            hints += [("s", "sync scripts"), ("v", "sync validators"), ("u", "upload run")]
        return hints + [("ctrl+r", "refresh")]

    def _actions_on(self) -> bool:
        # Only this page's own work hides the keys. While the Pipelines tab
        # sends, they stay and answer with BUSY_NOTICE (see ParamifyWriter).
        return self._online() and not self._own_busy

    @property
    def _own_busy(self) -> bool:
        return self._planning or self._acting

    def check_action(self, action: str, parameters) -> bool | None:
        if action in ("sync_scripts", "sync_validators", "upload_run"):
            return self._actions_on()
        return True

    def _refresh_hints(self) -> None:
        update = getattr(self.screen, "_update_chrome", None)
        if update is not None:
            update()

    # -- reading ---------------------------------------------------------- #

    def rebuild(self) -> None:
        """After a manifest load or switch: drop the old status, and read again
        now when the page shows, else the next time it is shown."""
        changed = self._status_manifest != getattr(self.app, "manifest_path", None)
        if changed and (self._status is not None or self._error is not None):
            self._status = None
            self._rows = {}
            self._error = None
            self._newest = {}
            for table in ("#pf-grid", "#pf-caps"):
                self.query_one(table, DataTable).clear()
            self.query_one("#pf-set", Static).update("")
        self._stale = True
        self._draw()
        if changed and self._page_shown():
            self.request_status()

    def _page_shown(self) -> bool:
        try:
            return self.screen.query_one(TabbedContent).active == "tab-paramify"
        except Exception:  # noqa: BLE001 — not inside the workspace
            return False

    @property
    def _status_manifest(self):
        return getattr(self, "_read_for", None)

    def focus_default(self) -> None:
        if self._stale or self._status_at is None or time.monotonic() - self._status_at > STALE_AFTER:
            self.request_status()
        self._focus_target().focus()

    def _focus_target(self):
        grid = self.query_one("#pf-grid", DataTable)
        return self.query_one("#pf-grid-empty", Static) if self.query_one("#pf-grid-panel").has_class("empty") else grid

    def action_refresh_status(self) -> None:
        self.request_status()

    def request_status(self) -> None:
        if self._reading:
            self._reread = True  # read again when this one lands
            return
        path = getattr(self.app, "manifest_path", None)
        if path is None:
            return
        self._reading = True
        self._stale = False
        self._draw_summary()
        self._status_worker(self.app.root_path, path)

    # Not exclusive: _reading already keeps one read at a time, and an exclusive
    # group would cancel the read that just posted when the re-read starts.
    @work(thread=True, group="paramify-status")
    def _status_worker(self, root, manifest_path) -> None:
        setup = False
        try:
            status, error = api.paramify_status(root, Path(manifest_path)), None
        except ValueError as exc:  # an unreadable manifest, registry or uploader config
            status, error, setup = None, str(exc), True
        except Exception as exc:  # noqa: BLE001 — shown in the problem bar
            status, error = None, str(exc)
        self.post_message(StatusReady(status, manifest_path, error, setup))

    def on_status_ready(self, message: StatusReady) -> None:
        self._reading = False
        reread, self._reread = self._reread, False
        if message.manifest_path != getattr(self.app, "manifest_path", None):
            self._stale = True  # read for a manifest that is no longer open
            if reread:
                self.request_status()
            else:
                self._draw_summary()
            return
        self._error_setup = message.setup
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
        # When the redraw hides the grid (an empty manifest), Textual moves focus
        # to the next focusable widget: the hint, which takes focus for that.
        self._draw()
        self._refresh_hints()
        if reread:
            self.request_status()

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
            if self._error_setup:
                problem = f"{self._error.rstrip('.')}.{since} Fix it, then press ctrl+r."
            else:
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

    def _shown(self, rows: list) -> list:
        text = self._filter
        return [
            r for r in rows
            if not (self._needs_work and r["ready"])
            and (not text or text in r["name"].lower() or text in r["evidence_set"]["reference_id"].lower())
        ]

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
        shown = self._shown(rows)
        target = self._landing(keep, rows, shown)
        # clear() moves the cursor to row 0 and the rows come back one by one,
        # each move posting a RowHighlighted. Those are the redraw, not the user
        # moving off the row an action's log opened on, so they must not hide it;
        # the cursor goes back to its fetcher, and _show below draws its detail.
        with self.prevent(DataTable.RowHighlighted):
            grid.clear()
            for row in shown:
                grid.add_row(*grid_cells(row, online, status["errors"]), key=row["name"])
            if target is not None:
                grid.move_cursor(row=grid.get_row_index(target))
        empty = not rows
        panel.set_class(empty, "empty")
        detail.display = not empty and not self.query_one("#pf-activity-panel").display
        self.query_one("#pf-totals", Static).display = online and not empty
        if empty:
            hint = ONLY_SCAN if status["pipelines_count"] else EMPTY
            self.query_one("#pf-grid-empty", Static).update(Text(hint))
            panel.border_title = "evidence sets (0)"
            return
        ready = sum(r["ready"] for r in rows)
        panel.border_title = f"evidence sets ({len(rows)})" + (f"  ·  {ready} ready" if online else "")
        self.query_one("#pf-totals", Static).update(totals_text(rows, len(shown), status["errors"]))
        self._show(self._cursor_key())

    @staticmethod
    def _landing(keep: str | None, rows: list, shown: list) -> str | None:
        """Where the cursor goes after a redraw: the same fetcher when it is still
        shown, else the next shown one in manifest order, else the last."""
        names = [r["name"] for r in shown]
        if not names:
            return None
        if keep in names:
            return keep
        order = [r["name"] for r in rows]
        if keep in order:
            after = order[order.index(keep):]
            return next((n for n in after if n in names), names[-1])
        return names[0]

    def action_focus_filter(self) -> None:
        self.query_one("#pf-filter", Input).focus()

    def action_needs_work(self) -> None:
        self._needs_work = not self._needs_work
        self._draw_grid()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "pf-filter":
            self._filter = event.value.strip().lower()
            self._draw_grid()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "pf-filter":
            self.query_one("#pf-grid", DataTable).focus()

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
            # The user moved off the row the log opened on: the detail comes back.
            if (self.query_one("#pf-activity-panel").display and not self._own_busy
                    and event.row_key.value != getattr(self, "_activity_key", None)):
                self._show_activity(False)
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
        if online and set_id and (row["evidence_set"]["artifact_count"] or 0) and set_id not in self._newest:
            self._artifacts_worker(set_id)

    def _set_info(self, row: dict, online: bool) -> Group:
        info = Table.grid(padding=(0, 2))
        info.add_column(style=palette.MUTED)
        info.add_column()
        es = row["evidence_set"]
        if online:
            if es.get("exists") is None:
                info.add_row("evidence set", Text(f"{es['reference_id']}  ? not read", style=palette.WARN))
            else:
                info.add_row("evidence set", Text(es["reference_id"], style=palette.INFO) if es["exists"]
                             else Text(f"{es['reference_id']}  created by the scripts sync", style=palette.INFO))
            label, style = _SCRIPT_DETAIL.get(row["script"] or "", ("—", palette.MUTED))
            info.add_row("script", Text(label, style=style))
            arts = es["artifact_count"]
            newest = self._newest.get(es["id"])
            if arts is None:
                info.add_row("artifacts", _unknown())
            else:
                info.add_row("artifacts", Text(f"{arts}" + (f"  newest {newest}" if newest else ""))
                             if arts else _dim("none yet"))
        else:
            info.add_row("evidence set", Text(es["reference_id"]))
        body: list = [Text(row["name"], style="bold"), Text(""), info, Text("")]
        validators = row["validators"]
        if validators:
            table = Table.grid(padding=(0, 1))
            for i, v in enumerate(validators):
                if not online:
                    mark = _dim("·")
                elif v["paired"] is None:
                    mark = _unknown()
                else:
                    mark = Text("✓", style=palette.OK) if v["paired"] else Text("+", style=palette.INFO)
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
        errors = status.get("errors") or {}
        error = errors.get("capabilities")
        # The pairs come from the evidence-set read: unread, "no pairs" is unknown.
        sets_unknown = row["evidence_set"].get("exists") is None
        if not online or error or sets_unknown or not row["pairs"]:
            panel.add_class("empty")
            if not online:
                empty.update(Text(CAPS_OFFLINE))
            elif error:
                empty.update(Text(f"Could not read the capabilities: {error}", style=palette.WARN))
            elif sets_unknown:
                reason = errors.get("evidence_sets") or "not read"
                empty.update(Text(f"Could not read the evidence sets: {reason}", style=palette.WARN))
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

    # -- actions: shared -------------------------------------------------- #

    def _begin_log(self, banner) -> None:
        self.query_one("#pf-log", RichLog).clear()
        self._set_banner(banner)
        self._refresh_hints()

    def _set_banner(self, renderable) -> None:
        self._show_activity(True)
        self.query_one("#pf-activity", Static).update(renderable)

    def _show_activity(self, shown: bool) -> None:
        """The log and the detail row share one slot under the grid."""
        self.query_one("#pf-activity-panel", Vertical).display = shown
        has_rows = bool((self._status or {}).get("fetchers"))
        self.query_one("#pf-detail").display = not shown and has_rows
        if shown:
            self._activity_key = self._cursor_key()

    def _log(self, line: Text) -> None:
        self.query_one("#pf-log", RichLog).write(line)

    def _done(self, banner: Text) -> None:
        """An action ended: say how, re-read the workspace, and re-enable the keys."""
        self._planning = self._acting = False
        self._set_banner(banner)
        self.request_status()
        self._refresh_hints()

    def on_action_event(self, message: ActionEvent) -> None:
        handler = {"upload": self._handle_upload_event, "scripts": self._handle_scripts_event,
                   "validators": self._handle_validators_event}[message.kind]
        handler(message.ev)

    def _evidence_names(self) -> set:
        return {r["name"] for r in (self._status or {}).get("fetchers") or []}

    def _base_url(self) -> str:
        return ((self._status or {}).get("workspace") or {}).get("base_url") or "Paramify"

    # -- actions: upload (u) ---------------------------------------------- #

    def action_upload_run(self) -> None:
        """Upload the newest run with evidence: plan, confirm, then stream."""
        if self._busy:
            self.notify(BUSY_NOTICE)
            return
        try:
            latest, scoped = latest_run_scoped(self.app, "evidence")
        except Exception as exc:  # noqa: BLE001
            self.notify(f"Cannot list runs: {exc}", severity="error")
            return
        if latest is None:
            self.notify("No run with evidence yet. Collect it on the Run tab (2).")
            return
        try:
            preflight = api.upload_preflight(latest["dir"], self.app.root_path)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"Cannot check the upload: {exc}", severity="error")
            return
        if not preflight.get("ok"):
            self.notify(" ".join(preflight.get("errors") or ["The upload is not ready."]), severity="error", timeout=12)
            return
        # The manifest the plan compares the run's Paramify settings with: the
        # open one when the run is its own, or records none.
        manifest = getattr(self.app, "manifest_path", None) if (scoped or latest.get("manifest") is None) else None
        self._planning = True
        self._refresh_hints()
        self._plan_worker(
            latest["dir"], self.app.root_path, bool(preflight.get("token_present")),
            f"Upload {preflight['file_count']} evidence file(s) to {preflight['base_url']}?", manifest,
        )

    @work(thread=True, exclusive=True, group="paramify-action")
    def _plan_worker(self, run_dir: str, root, online: bool, question: str, manifest_path=None) -> None:
        try:
            lines = render_plan(api.plan_upload(run_dir, root, online=online, manifest_path=manifest_path))
            error = False
        except Exception as exc:  # noqa: BLE001 — shown in the confirm, never uploaded
            lines, error = [f"Cannot plan the upload: {exc}"], True
        self.app.call_from_thread(self._confirm_upload, run_dir, "\n".join(lines), question, error, manifest_path)

    def _confirm_upload(self, run_dir: str, body: str, question: str, error: bool, manifest_path) -> None:
        def go(ok: bool) -> None:
            if ok and not error:
                self._acting = True
                self._begin_log(Text("uploading to Paramify…", style=palette.WARN))
                self._upload_worker(run_dir, self.app.root_path, manifest_path)
            self._refresh_hints()

        try:
            self.app.push_screen(ConfirmModal(body if error else f"{body}\n\n{question}"), go)
        finally:
            self._planning = False

    @work(thread=True, exclusive=True, group="paramify-action")
    def _upload_worker(self, run_dir: str, root, manifest_path=None) -> None:
        def post(ev: dict) -> None:
            self.post_message(ActionEvent("upload", ev))

        try:
            api.upload_run(run_dir, root, on_event=post, manifest_path=manifest_path)
        except Exception as exc:  # noqa: BLE001
            post({"event": "_upload_failed", "error": str(exc)})

    def _handle_upload_event(self, ev: dict) -> None:
        etype = ev.get("event")
        noun = "evidence"
        for line in upload_event_lines(ev, noun):
            self._log(line)
        if etype == "upload_start":
            mode = " (dry-run)" if ev.get("dry_run") else ""
            self._set_banner(Text(f"uploading {ev.get('files', 0)} {noun}(s) to {ev.get('base_url', '')}{mode}",
                                  style=palette.WARN))
        elif etype == "upload_complete":
            self._finalize_upload(ev)
        elif etype == "_upload_failed":
            self._log(Text(f"upload failed: {ev.get('error', '')}", style=f"bold {palette.FAIL}"))
            self._done(Text(f"upload failed: {ev.get('error', '')}", style=palette.FAIL))

    def _finalize_upload(self, ev: dict) -> None:
        msg = Text(
            "evidence upload complete — "
            f"uploaded={ev.get('uploaded', 0)} "
            f"duplicates={ev.get('skipped_duplicate', 0)} "
            f"errors={ev.get('errors', 0)}"
            + (f" dropped={ev['dropped']}" if ev.get("dropped") else ""),
            style=palette.OK if ev.get("ok") else palette.FAIL,
        )
        if ev.get("halted"):
            msg.append(f"   stopped early: {ev['halted']}", style=palette.FAIL)
        if ev.get("log_path"):
            msg.append(f"   {ev['log_path']}", style="dim")
        self._done(msg)

    # -- actions: scripts (s) --------------------------------------------- #

    def action_sync_scripts(self) -> None:
        """Preview the scripts sync, confirm the plan, then sync and re-read."""
        if self._busy:
            self.notify(BUSY_NOTICE)
            return
        names = self._evidence_names()
        if not names:
            self.notify("No evidence fetchers in this manifest.")
            return
        self._planning = True
        self._begin_log(Text("previewing the scripts sync…", style=palette.WARN))
        self._scripts_preview_worker(self.app.root_path, names)

    @work(thread=True, exclusive=True, group="paramify-action")
    def _scripts_preview_worker(self, root, names: set) -> None:
        counts: dict = {}

        def tally(ev: dict) -> None:
            if ev.get("event") == "sync_item":
                category = _SCRIPT_MARKS.get(ev.get("outcome") or "", ("other",))[0]
                counts[category] = counts.get(category, 0) + 1

        try:
            api.scripts_sync(root, dry_run=True, include=names, on_event=tally)
        except Exception as exc:  # noqa: BLE001
            self.post_message(ActionEvent("scripts", {"event": "_failed", "error": str(exc)}))
            return
        self.app.call_from_thread(self._confirm_scripts, names, counts)

    def _confirm_scripts(self, names: set, counts: dict) -> None:
        self._planning = False
        create, update, drift = counts.get("create", 0), counts.get("update", 0), counts.get("drift", 0)
        kept = (f"\n\n{drift} script(s) changed in Paramify stay as they are. "
                "`paramify scripts sync --force` overwrites them.") if drift else ""
        if not create and not update:
            self._done(Text("scripts: nothing to sync" + (f", {drift} changed in Paramify (kept)" if drift else ""),
                            style=palette.OK))
            return

        def go(ok: bool) -> None:
            if ok:
                self._acting = True
                self._begin_log(Text("syncing scripts…", style=palette.WARN))
                self._scripts_worker(self.app.root_path, names)
            else:
                self._set_banner(Text("scripts sync cancelled", style=palette.MUTED))
            self._refresh_hints()

        self.app.push_screen(ConfirmModal(
            f"Sync {create + update} fetcher script(s) to {self._base_url()}: "
            f"{create} create, {update} update, and pair each one with its evidence set?{kept}"
        ), go)

    @work(thread=True, exclusive=True, group="paramify-action")
    def _scripts_worker(self, root, names: set) -> None:
        def post(ev: dict) -> None:
            self.post_message(ActionEvent("scripts", ev))

        try:
            api.scripts_sync(root, include=names, on_event=post)
        except Exception as exc:  # noqa: BLE001
            post({"event": "_failed", "error": str(exc)})

    def _handle_scripts_event(self, ev: dict) -> None:
        etype = ev.get("event")
        if etype == "sync_item":
            _, label, style = _SCRIPT_MARKS.get(ev.get("outcome") or "", ("other", ev.get("outcome", "?"), "white"))
            ref = f"  set={ev.get('reference_id')}" if ev.get("reference_id") else ""
            reason = ev.get("reason") or ev.get("error")
            self._log(Text(f"  [{label}] {ev.get('fetcher', '?')}{ref}" + (f"  {reason}" if reason else ""), style=style))
        elif etype == "sync_complete":
            self._done(Text(
                f"scripts sync complete — created={ev.get('created', 0)} updated={ev.get('updated', 0)} "
                f"associated={ev.get('associated', 0)} errors={ev.get('errors', 0)}",
                style=palette.OK if ev.get("ok") else palette.FAIL,
            ))
        elif etype == "_failed":
            self._log(Text(f"scripts sync failed: {ev.get('error', '')}", style=f"bold {palette.FAIL}"))
            self._done(Text(f"scripts sync failed: {ev.get('error', '')}", style=palette.FAIL))

    # -- actions: validators (v) ------------------------------------------ #

    def action_sync_validators(self) -> None:
        """Preview the validators sync, confirm, then create and pair them."""
        if self._busy:
            self.notify(BUSY_NOTICE)
            return
        path = getattr(self.app, "manifest_path", None)
        if path is None:
            return
        self._planning = True
        self._begin_log(Text("previewing the validators sync…", style=palette.WARN))
        self._validators_preview_worker(self.app.root_path, path)

    @work(thread=True, exclusive=True, group="paramify-action")
    def _validators_preview_worker(self, root, manifest_path) -> None:
        outcomes: list = []

        def tally(ev: dict) -> None:
            if ev.get("event") == "sync_validator":
                outcomes.append(ev.get("outcome") or "")

        try:
            api.sync_validators(root, Path(manifest_path), dry_run=True, on_event=tally)
        except Exception as exc:  # noqa: BLE001
            self.post_message(ActionEvent("validators", {"event": "_failed", "error": str(exc)}))
            return
        self.app.call_from_thread(self._confirm_validators, manifest_path, outcomes)

    def _confirm_validators(self, manifest_path, outcomes: list) -> None:
        self._planning = False
        create = outcomes.count("would_create")
        exist = sum(o.startswith("would_skip") for o in outcomes)
        rows = (self._status or {}).get("fetchers") or []
        missing = sum(1 for r in rows if r["evidence_set"].get("exists") is False)
        # The syncer pairs a validator only when it creates it, so a validator
        # that exists but is not paired stays that way.
        unpaired = sum(1 for r in rows if r["evidence_set"].get("exists") for v in r["validators"]
                       if v["paired"] is False)
        if not create:
            text = f"validators: nothing to create ({exist} in Paramify already)."
            if unpaired:
                text += (f" {unpaired} validator(s) exist but are not paired with their evidence set."
                         " Pair them in Paramify.")
            self._done(Text(text, style=palette.WARN if unpaired else palette.OK))
            return

        def go(ok: bool) -> None:
            if ok:
                self._acting = True
                self._begin_log(Text("syncing validators…", style=palette.WARN))
                self._validators_worker(self.app.root_path, manifest_path)
            else:
                self._set_banner(Text("validators sync cancelled", style=palette.MUTED))
            self._refresh_hints()

        if missing:
            ask = (f"Create {create} validator(s) in {self._base_url()}? {missing} evidence set(s) do not exist "
                   "yet, and a validator is paired only when it is created: press s first to create the sets.")
        else:
            ask = f"Create {create} validator(s) in {self._base_url()} and pair each one with its evidence sets?"
        self.app.push_screen(ConfirmModal(f"{ask} {exist} exist already and stay as they are."), go)

    @work(thread=True, exclusive=True, group="paramify-action")
    def _validators_worker(self, root, manifest_path) -> None:
        def post(ev: dict) -> None:
            self.post_message(ActionEvent("validators", ev))

        try:
            api.sync_validators(root, Path(manifest_path), on_event=post)
        except Exception as exc:  # noqa: BLE001
            post({"event": "_failed", "error": str(exc)})

    def _handle_validators_event(self, ev: dict) -> None:
        etype = ev.get("event")
        if etype == "sync_validator":
            outcome = ev.get("outcome") or "?"
            style = palette.FAIL if outcome == "error" else (palette.OK if outcome == "created" else "dim")
            reason = f"  {ev['error']}" if ev.get("error") else ""
            self._log(Text(f"  [{outcome}] {ev.get('key', '?')}{reason}", style=style))
        elif etype == "sync_complete":
            self._done(Text("validators sync complete", style=palette.OK if ev.get("ok", True) else palette.FAIL))
        elif etype == "_failed":
            self._log(Text(f"validators sync failed: {ev.get('error', '')}", style=f"bold {palette.FAIL}"))
            self._done(Text(f"validators sync failed: {ev.get('error', '')}", style=palette.FAIL))
