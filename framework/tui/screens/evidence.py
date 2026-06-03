"""Evidence browser (Phase 4).

Browses the evidence produced by past runs under the manifest's output_dir,
backed by api.list_runs() / api.read_evidence() (so the TUI stays on the facade).
Left: a runs table (newest first). Right: the selected run's output files joined
with their invocation records. Enter on a file opens the enveloped evidence
(metadata + evidence_set + payload), or the raw content for legacy files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Static

from framework import api
from framework.tui.modals import PreviewModal


class EvidencePage(Vertical):
    HINTS = [("↑↓", "runs"), ("enter", "view"), ("ctrl+r", "refresh"), ("q", "quit")]

    BINDINGS = [Binding("ctrl+r", "refresh_runs", "Refresh")]

    def compose(self) -> ComposeResult:
        with Horizontal(id="evidence-top"):
            yield Static("", id="evidence-dir")
            yield Button("Refresh", id="evidence-refresh")
        with Horizontal(id="evidence-body"):
            with Vertical(id="evidence-left"):
                yield Static("runs", classes="pane-label")
                yield DataTable(id="evidence-runs")
            with Vertical(id="evidence-right"):
                yield Static("", id="evidence-run-header", classes="pane-label")
                yield DataTable(id="evidence-files")

    def on_mount(self) -> None:
        self._runs: List[dict] = []
        runs = self.query_one("#evidence-runs", DataTable)
        runs.cursor_type = "row"
        runs.zebra_stripes = True
        runs.add_columns("run", "completed", "ok", "fail")
        files = self.query_one("#evidence-files", DataTable)
        files.cursor_type = "row"
        files.zebra_stripes = True
        files.add_columns("file", "fetcher", "target", "exit")
        self.rebuild_runs()

    def focus_default(self) -> None:
        # Re-list on each visit so a just-finished run shows up.
        self.rebuild_runs()
        self.query_one("#evidence-runs", DataTable).focus()

    # -- data ------------------------------------------------------------- #

    def _output_dir(self) -> str:
        run = (getattr(self.app, "manifest", None) or {}).get("run") or {}
        return run.get("output_dir") or "./evidence"

    def rebuild_runs(self) -> None:
        out = self._output_dir()
        self.query_one("#evidence-dir", Static).update(Text(f"output dir: {out}", style="dim"))
        try:
            self._runs = api.list_runs(out)
        except Exception as exc:  # never let a disk/JSON issue kill the UI
            self._runs = []
            self.notify(f"Could not list runs: {exc}", severity="error")

        dt = self.query_one("#evidence-runs", DataTable)
        dt.clear()
        for r in self._runs:
            if not r.get("complete", True):
                when = Text("incomplete", style="yellow")  # no _run_metadata.json (aborted run)
            else:
                when = r.get("completed_at") or r.get("started_at") or ""
            fail_style = "red" if r["fail"] else "dim"
            dt.add_row(
                r["run_id"],
                when,
                Text(str(r["ok"]), style="green"),
                Text(str(r["fail"]), style=fail_style),
                key=r["dir"],
            )

        if self._runs:
            self._show_run(self._runs[0]["dir"])
        else:
            self.query_one("#evidence-run-header", Static).update(
                Text(f"no runs found under {out}", style="dim")
            )
            self.query_one("#evidence-files", DataTable).clear()

    def _show_run(self, run_dir: str) -> None:
        run = next((r for r in self._runs if r["dir"] == run_dir), None)
        files = self.query_one("#evidence-files", DataTable)
        files.clear()
        if run is None:
            return
        header = Text(f"{run['run_id']}   ", style="bold")
        header.append(f"✓ {run['ok']}  ✗ {run['fail']}   {run.get('completed_at') or ''}", style="dim")
        self.query_one("#evidence-run-header", Static).update(header)
        for f in run["files"]:
            tgt = f.get("target")
            tlabel = "  ".join(f"{k}={v}" for k, v in tgt.items()) if isinstance(tgt, dict) else ""
            code = f.get("exit_code")
            if code is None:
                ecell = Text("—", style="dim")
            elif code == 0:
                ecell = Text("0", style="green")
            else:
                ecell = Text(str(code), style="red")
            files.add_row(f["name"], f.get("fetcher") or "—", tlabel or "—", ecell, key=f["path"])

    # -- events ----------------------------------------------------------- #

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "evidence-runs" and event.row_key.value:
            self._show_run(event.row_key.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "evidence-files" and event.row_key.value:
            self._open_file(event.row_key.value)

    @on(Button.Pressed, "#evidence-refresh")
    def _on_refresh(self) -> None:
        self.action_refresh_runs()

    def action_refresh_runs(self) -> None:
        self.rebuild_runs()
        self.notify("Evidence reloaded.")

    # -- detail ----------------------------------------------------------- #

    def _open_file(self, path: str) -> None:
        try:
            ev = api.read_evidence(Path(path))
        except Exception as exc:
            self.notify(f"Cannot read evidence: {exc}", severity="error", timeout=8)
            return
        self.app.push_screen(PreviewModal(self._format(path, ev), title=Path(path).name))

    @staticmethod
    def _format(path: str, ev: dict) -> str:
        payload = json.dumps(ev.get("payload"), indent=2, default=str)
        if not ev.get("enveloped"):
            return f"{Path(path).name}   (raw — not enveloped)\n\n{payload}"

        md = ev.get("metadata") or {}
        lines = [
            f"{md.get('fetcher_name', '?')}  v{md.get('fetcher_version', '?')}  [{md.get('category', '?')}]",
            f"status: {md.get('status', '?')}   exit {md.get('exit_code', '?')}   collected {md.get('collected_at', '?')}",
        ]
        tgt = md.get("target")
        if isinstance(tgt, dict) and tgt:
            lines.append("target: " + "  ".join(f"{k}={v}" for k, v in tgt.items()))
        es = md.get("evidence_set")
        if isinstance(es, dict):
            lines.append(f"evidence set: {es.get('reference_id', '')} — {es.get('name', '')}")
            if es.get("instructions"):
                lines.append(f"  instructions: {es['instructions']}")
        if md.get("error"):
            lines.append(f"error: {md['error']}")
        lines += ["", "payload:", payload]
        return "\n".join(lines)
