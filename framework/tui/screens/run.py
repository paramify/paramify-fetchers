"""Run console (Phase 3).

Executes the current manifest via api.run() on a thread worker and renders the
seven-event stream live: a per-fetcher status DataTable, a streaming RichLog, and
a pass/fail/skip summary bar. The event-application logic (_handle_event) is kept
free of the worker so it can be tested by feeding synthetic events.

There is no hard "stop": api.run has no cancel hook and the per-invocation 124
timeout is the only abort, so we don't offer a misleading stop button. Runs are
gated on api.validate (with a confirm to run anyway) and the Run control is
disabled while a run is in flight.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Dict

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, RichLog, Static

from framework import api
from framework.tui import palette
from framework.tui.modals import ConfirmModal

_BAR_WIDTH = 20


def _exit_label(code: int) -> str:
    return {0: "ok", 124: "timeout", 255: "setup-error"}.get(code, f"exit {code}")


class RunEvent(Message):
    """Carries one api.run() event dict from the worker thread to the UI thread."""

    def __init__(self, ev: dict) -> None:
        self.ev = ev
        super().__init__()


class RunPage(Vertical):
    HINTS = [("ctrl+r", "run")]

    BINDINGS = [Binding("ctrl+r", "run_manifest", "Run")]

    def compose(self) -> ComposeResult:
        with Horizontal(id="run-top"):
            yield Button("▶ Run", variant="primary", id="btn-run")
            yield Static("", id="run-banner")
        with Horizontal(id="run-body"):
            with Vertical(id="run-status-panel", classes="panel"):
                yield DataTable(id="run-status")
                yield Static(
                    f"no run yet — [bold {palette.ACCENT}]ctrl+r[/] executes the manifest",
                    classes="empty-hint",
                )
            with Vertical(id="run-log-panel", classes="panel"):
                yield RichLog(id="run-log", markup=False, wrap=True, highlight=False)
                yield Static("run output streams here, fetcher by fetcher", classes="empty-hint")
        yield Static("", id="run-summary")

    def on_mount(self) -> None:
        self._running: bool = False
        self._state: Dict[str, dict] = {}
        self._rows: dict = {}  # use -> RowKey, for in-place cell updates
        self.query_one("#run-status-panel", Vertical).border_title = "status"
        self.query_one("#run-log-panel", Vertical).border_title = "log"
        dt = self.query_one("#run-status", DataTable)
        dt.cursor_type = "row"
        dt.zebra_stripes = True
        self._cols = dt.add_columns("fetcher", "mode", "status", "info")
        self._set_banner(Text("press Ctrl+R (or Run) to execute the manifest", style="dim"))
        self._set_empty(True)

    def focus_default(self) -> None:
        self.query_one("#btn-run", Button).focus()

    def reset_state(self) -> None:
        """Clear the console for a freshly-switched manifest. No-op while a run
        is in flight — that run finishes and clears itself."""
        if self._running:
            return
        self._state = {}
        self._rows = {}
        self.query_one("#run-status", DataTable).clear()
        self.query_one("#run-log", RichLog).clear()
        self._set_banner(Text("press Ctrl+R (or Run) to execute the manifest", style="dim"))
        self._set_empty(True)
        self._refresh_summary()

    # -- run control ------------------------------------------------------ #

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-run":
            self.action_run_manifest()

    def action_run_manifest(self) -> None:
        if self._running:
            self.notify("A run is already in progress.")
            return
        if self.app.manifest is None:
            return
        errors = api.validate(self.app.manifest, self.app.root_path)
        if errors:
            def go(ok: bool) -> None:
                if ok:
                    self._start_run()
            self.app.push_screen(
                ConfirmModal(f"Manifest has {len(errors)} issue(s) — run anyway?"), go
            )
        else:
            self._start_run()

    def _set_empty(self, empty: bool) -> None:
        """Swap the status table / log for their hatched placeholders (and back)."""
        self.query_one("#run-status-panel", Vertical).set_class(empty, "empty")
        self.query_one("#run-log-panel", Vertical).set_class(empty, "empty")

    def _start_run(self) -> None:
        self._running = True
        self._state = {}
        self._rows = {}
        self._set_empty(False)
        self.query_one("#run-status", DataTable).clear()
        self.query_one("#run-log", RichLog).clear()
        self.query_one("#btn-run", Button).disabled = True
        self._set_banner(Text("running…", style=palette.WARN))
        self._refresh_summary()
        # Snapshot the manifest: the worker runs on another thread and the
        # Manifest tab can mutate the shared dict on the UI thread mid-run.
        self._run_worker(deepcopy(self.app.manifest), self.app.root_path, self.app.manifest_path)

    @work(thread=True, exclusive=True)
    def _run_worker(self, manifest: dict, root, manifest_path=None) -> None:
        try:
            api.run(
                manifest, root,
                on_event=lambda ev: self.post_message(RunEvent(ev)),
                manifest_path=manifest_path,
            )
        except Exception as exc:  # e.g. schema-invalid manifest -> ValueError
            self.post_message(RunEvent({"event": "_run_failed", "error": str(exc)}))

    # -- event handling (worker-free; unit-testable) --------------------- #

    def on_run_event(self, message: RunEvent) -> None:
        self._handle_event(message.ev)

    def _handle_event(self, ev: dict) -> None:
        etype = ev.get("event")
        log = self.query_one("#run-log", RichLog)

        if etype == "run_start":
            self._set_empty(False)  # the worker isn't the only caller: synthetic events too
            self._state = {
                use: {"status": "queued", "total": None, "ok": 0, "fail": 0, "fanout": False}
                for use in ev.get("fetchers", [])
            }
            self.query_one("#run-status", DataTable).clear()
            self._rows = {}
            self._set_banner(Text(f"running → {ev.get('run_dir', '')}", style=palette.WARN))
            log.write(Text(f"▶ run {ev.get('run_id', '')}  →  {ev.get('run_dir', '')}", style="bold"))
            for use in self._state:
                self._paint_row(use)

        elif etype == "fetcher_start":
            st = self._row(ev["fetcher"])
            st["status"] = "running"
            st["fanout"] = bool(ev.get("fanout"))
            st["total"] = ev.get("targets", 1)
            log.write(Text(f"  ▸ {ev['fetcher']} …", style=palette.INFO))
            self._paint_row(ev["fetcher"])

        elif etype == "log_line":
            log.write(f"    {ev.get('fetcher', '')}: {ev.get('line', '')}")

        elif etype == "fetcher_result":
            self._apply_result(ev, log)

        elif etype == "fetcher_skip":
            st = self._row(ev["fetcher"])
            st["status"] = "skipped"
            st["reason"] = ev.get("reason", "")
            log.write(Text(f"  ⊘ {ev['fetcher']} skipped — {ev.get('reason', '')}", style=palette.WARN))
            self._paint_row(ev["fetcher"])

        elif etype == "fetcher_error":
            use = ev.get("fetcher", "?")
            st = self._row(use)
            st["status"] = "error"
            st["reason"] = ev.get("error", "")
            log.write(Text(f"  ✗ {use} error — {ev.get('error', '')}", style=palette.FAIL))
            self._paint_row(use)

        elif etype == "run_complete":
            self._finalize(ev.get("ok"), ev.get("metadata_path", ""))

        elif etype == "_run_failed":
            log.write(Text(f"✗ run failed: {ev.get('error', '')}", style=f"bold {palette.FAIL}"))
            self._finalize(False, "")

    def _apply_result(self, ev: dict, log: RichLog) -> None:
        st = self._row(ev["fetcher"])
        code = ev.get("exit_code", 1)
        if code == 0:
            st["ok"] += 1
        else:
            st["fail"] += 1

        total = st.get("total") or 1
        if not st.get("fanout") and total <= 1:
            st["status"] = {0: "ok", 124: "timeout"}.get(code, "failed")
        else:
            done = st["ok"] + st["fail"]
            if done >= total:
                st["status"] = "ok" if st["fail"] == 0 else ("failed" if st["ok"] == 0 else "partial")
            else:
                st["status"] = "running"

        target = ev.get("target")
        tlabel = "  ".join(f"{k}={v}" for k, v in target.items()) if isinstance(target, dict) else ""
        icon, style = ("✓", palette.OK) if code == 0 else ("✗", palette.FAIL)
        line = Text(f"  {icon} {ev['fetcher']}", style=style)
        if tlabel:
            line.append(f" [{tlabel}]", style="dim")
        outs = ev.get("outputs") or []
        suffix = f"  {_exit_label(code)} ({ev.get('duration_sec', '?')}s)"
        if code == 0 and outs:
            suffix += f"  · {len(outs)} file(s)"
        line.append(suffix, style="dim")
        log.write(line)
        self._paint_row(ev["fetcher"])

    def _finalize(self, ok, metadata_path: str) -> None:
        self._running = False
        self.query_one("#btn-run", Button).disabled = False
        icon = "✓" if ok else "✗"
        style = palette.OK if ok else palette.FAIL
        msg = Text(f"{icon} run complete — ok={ok}", style=style)
        if metadata_path:
            msg.append(f"   {metadata_path}", style="dim")
        self._set_banner(msg)
        for use in self._state:
            self._paint_row(use)
        self._refresh_summary()

    # -- rendering -------------------------------------------------------- #

    def _row(self, use: str) -> dict:
        return self._state.setdefault(
            use, {"status": "running", "total": 1, "ok": 0, "fail": 0, "fanout": False}
        )

    def _info(self, st: dict) -> str:
        status = st.get("status")
        if status in ("skipped", "error"):
            return st.get("reason", "")
        total = st.get("total")
        done = st.get("ok", 0) + st.get("fail", 0)
        if status == "running" and total:
            return f"{done}/{total}…"
        if total and total > 1:
            info = f"{st.get('ok', 0)}/{total} ok"
            if st.get("fail"):
                info += f"  · {st['fail']} failed"
            return info
        return ""

    def _paint_row(self, use: str) -> None:
        """Update (or create) one status row in place — preserves cursor/scroll."""
        st = self._state.get(use)
        if st is None:
            return
        dt = self.query_one("#run-status", DataTable)
        status = st.get("status", "queued")
        cell = palette.status_pill(status)
        mode = "fanout" if st.get("fanout") else "single"
        info = self._info(st)
        if use in self._rows:
            row = self._rows[use]
            dt.update_cell(row, self._cols[1], mode, update_width=True)
            dt.update_cell(row, self._cols[2], cell, update_width=True)
            dt.update_cell(row, self._cols[3], info, update_width=True)
        else:
            self._rows[use] = dt.add_row(use, mode, cell, info, key=use)
        self._refresh_summary()

    def _refresh_summary(self) -> None:
        ok = sum(s.get("ok", 0) for s in self._state.values())
        fail = sum(s.get("fail", 0) for s in self._state.values())
        # An errored fetcher never produced a result, but it is a failure, not a
        # skip — count it toward ✗ so the summary doesn't hide it.
        errored = sum(1 for s in self._state.values() if s.get("status") == "error")
        skip = sum(1 for s in self._state.values() if s.get("status") == "skipped")
        fail_total = fail + errored
        summary = Text()
        total = ok + fail_total
        if total:
            nok = max(0, min(_BAR_WIDTH, round(_BAR_WIDTH * ok / total)))
            summary.append("█" * nok, style=palette.OK)
            summary.append("█" * (_BAR_WIDTH - nok), style=palette.FAIL)
            summary.append("   ")
        summary.append(f"✓ {ok}   ", style=palette.OK)
        summary.append(f"✗ {fail_total}   ", style=palette.FAIL)
        summary.append(f"⊘ {skip}", style=palette.WARN)
        self.query_one("#run-summary", Static).update(summary)

    def _set_banner(self, renderable) -> None:
        self.query_one("#run-banner", Static).update(renderable)
