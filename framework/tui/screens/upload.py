"""Paramify upload page.

This is the final TUI step after Evidence: users can inspect the collected run,
then explicitly upload that run to Paramify once the story looks right.
"""

from __future__ import annotations

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, RichLog, Static

from framework import api
from framework.tui import palette
from framework.tui.modals import ConfirmModal


class UploadEvent(Message):
    """Carries one api.upload_run() event dict from the worker thread."""

    def __init__(self, ev: dict) -> None:
        self.ev = ev
        super().__init__()


class UploadPage(Vertical):
    HINTS = [("ctrl+r", "refresh"), ("ctrl+u", "upload")]

    BINDINGS = [
        Binding("ctrl+r", "refresh_upload", "Refresh"),
        Binding("ctrl+u", "upload_run", "Upload"),
    ]

    def compose(self) -> ComposeResult:
        with Horizontal(id="upload-top"):
            yield Button("Refresh", id="upload-refresh")
            yield Button("Upload to Paramify", variant="primary", id="upload-submit", disabled=True)
            yield Static("", id="upload-banner")
        with Horizontal(id="upload-body"):
            with Vertical(id="upload-summary-panel", classes="panel"):
                yield DataTable(id="upload-summary")
            with Vertical(id="upload-log-panel", classes="panel"):
                yield RichLog(id="upload-log", markup=False, wrap=True, highlight=False)
                yield Static(
                    f"upload progress streams here — [bold {palette.ACCENT}]ctrl+u[/] to upload",
                    classes="empty-hint",
                )

    def on_mount(self) -> None:
        self._uploading = False
        self._run_dir: str | None = None
        self._preflight: dict | None = None
        self.query_one("#upload-summary-panel", Vertical).border_title = "ready to upload"
        log_panel = self.query_one("#upload-log-panel", Vertical)
        log_panel.border_title = "log"
        log_panel.set_class(True, "empty")
        table = self.query_one("#upload-summary", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("field", "value")
        self.rebuild()

    def focus_default(self) -> None:
        self.rebuild()
        button = self.query_one("#upload-submit", Button)
        if not button.disabled:
            button.focus()
        else:
            self.query_one("#upload-refresh", Button).focus()

    # -- data ------------------------------------------------------------- #

    def _output_dir(self) -> str:
        run = (getattr(self.app, "manifest", None) or {}).get("run") or {}
        return run.get("output_dir") or "./evidence"

    def rebuild(self) -> None:
        if self._uploading:
            return
        self._run_dir = None
        self._preflight = None
        table = self.query_one("#upload-summary", DataTable)
        table.clear()
        upload = self.query_one("#upload-submit", Button)
        upload.disabled = True

        out = self._output_dir()
        table.add_row("step", "Review evidence in tab 4, then upload the latest run here.")
        table.add_row("output dir", out)
        try:
            runs = api.list_runs(out)
        except Exception as exc:
            self._set_banner(Text(f"cannot list runs: {exc}", style=palette.FAIL))
            table.add_row("status", Text(f"cannot list runs: {exc}", style=palette.FAIL))
            return

        if not runs:
            self._set_banner(Text(f"no runs found under {out}", style="dim"))
            table.add_row("status", Text("no runs found", style="dim"))
            return

        latest = runs[0]
        self._run_dir = latest["dir"]
        table.add_row("selected run", latest["run_id"])
        table.add_row("completed", latest.get("completed_at") or latest.get("started_at") or "unknown")
        table.add_row("result", self._result_text(latest))
        table.add_row("evidence files", str(len(latest.get("files") or [])))

        try:
            preflight = api.upload_preflight(self._run_dir, self.app.root_path)
        except Exception as exc:
            self._set_banner(Text(f"upload setup failed: {exc}", style=palette.FAIL))
            table.add_row("preflight", Text(str(exc), style=palette.FAIL))
            return

        self._preflight = preflight
        table.add_row("Paramify API", preflight["base_url"])
        table.add_row("API token", palette.pill("present", "ok") if preflight["token_present"] else palette.pill("missing", "fail"))
        table.add_row("upload files", str(preflight["file_count"]))

        if preflight["ok"]:
            upload.disabled = False
            self._set_banner(Text("ready — upload after reviewing the evidence", style=palette.OK))
        else:
            for err in preflight["errors"]:
                table.add_row("preflight error", Text(err, style=palette.FAIL))
            self._set_banner(Text("upload preflight failed", style=palette.FAIL))

    @staticmethod
    def _result_text(run: dict) -> Text:
        fail = run.get("fail", 0)
        ok = run.get("ok", 0)
        total = ok + fail
        if not run.get("complete", True):
            return Text("incomplete", style=palette.WARN)
        if fail:
            return Text(f"{ok}/{total} ok, {fail} failed", style=palette.WARN)
        return Text(f"{ok}/{total} ok", style=palette.OK)

    # -- actions ---------------------------------------------------------- #

    @on(Button.Pressed, "#upload-refresh")
    def _on_refresh(self) -> None:
        self.action_refresh_upload()

    @on(Button.Pressed, "#upload-submit")
    def _on_upload(self) -> None:
        self.action_upload_run()

    def action_refresh_upload(self) -> None:
        self.rebuild()
        self.notify("Upload page refreshed.")

    def action_upload_run(self) -> None:
        if self._uploading:
            self.notify("An upload is already in progress.")
            return
        if not self._run_dir or not self._preflight or not self._preflight.get("ok"):
            self.notify("No upload-ready run selected.")
            return

        def go(ok: bool) -> None:
            if ok:
                self._start_upload(self._run_dir)

        self.app.push_screen(
            ConfirmModal(
                f"Upload {self._preflight['file_count']} evidence file(s) to {self._preflight['base_url']}?"
            ),
            go,
        )

    def _start_upload(self, run_dir: str) -> None:
        self._uploading = True
        self.query_one("#upload-refresh", Button).disabled = True
        self.query_one("#upload-submit", Button).disabled = True
        self.query_one("#upload-log-panel", Vertical).set_class(False, "empty")
        self.query_one("#upload-log", RichLog).clear()
        self._set_banner(Text("uploading to Paramify...", style=palette.WARN))
        self._upload_worker(run_dir, self.app.root_path)

    @work(thread=True, exclusive=True)
    def _upload_worker(self, run_dir: str, root) -> None:
        try:
            api.upload_run(
                run_dir,
                root,
                on_event=lambda ev: self.post_message(UploadEvent(ev)),
            )
        except Exception as exc:
            self.post_message(UploadEvent({"event": "_upload_failed", "error": str(exc)}))

    # -- events ----------------------------------------------------------- #

    def on_upload_event(self, message: UploadEvent) -> None:
        self._handle_upload_event(message.ev)

    def _handle_upload_event(self, ev: dict) -> None:
        etype = ev.get("event")
        log = self.query_one("#upload-log", RichLog)

        if etype == "upload_start":
            mode = " (dry-run)" if ev.get("dry_run") else ""
            self._set_banner(Text(f"uploading {ev.get('files', 0)} file(s) to {ev.get('base_url', '')}{mode}", style=palette.WARN))
            log.write(Text(f"upload {ev.get('files', 0)} file(s) from {ev.get('run_dir', '')}{mode}", style="bold"))

        elif etype == "upload_file":
            outcome = ev.get("outcome")
            if outcome == "uploaded":
                icon, style = "OK", palette.OK
            elif outcome in ("skipped_duplicate", "skipped_failed", "would_upload"):
                icon, style = "SKIP", palette.WARN
            else:
                icon, style = "FAIL", palette.FAIL
            ref = f"  set={ev.get('reference_id')}" if ev.get("reference_id") else ""
            reason = ev.get("reason") or ev.get("error")
            suffix = f"  {reason}" if reason else ""
            log.write(Text(f"  [{icon}] {ev.get('file', '?')}  {outcome}{ref}{suffix}", style=style))

        elif etype == "upload_complete":
            self._finalize_upload(ev)

        elif etype == "_upload_failed":
            self._uploading = False
            self.query_one("#upload-refresh", Button).disabled = False
            self.query_one("#upload-submit", Button).disabled = self._preflight is None or not self._preflight.get("ok")
            log.write(Text(f"upload failed: {ev.get('error', '')}", style=f"bold {palette.FAIL}"))
            self._set_banner(Text(f"upload failed: {ev.get('error', '')}", style=palette.FAIL))

    def _finalize_upload(self, ev: dict) -> None:
        self._uploading = False
        self.query_one("#upload-refresh", Button).disabled = False
        self.query_one("#upload-submit", Button).disabled = False
        ok = ev.get("ok")
        style = palette.OK if ok else palette.FAIL
        msg = Text(
            "upload complete — "
            f"uploaded={ev.get('uploaded', 0)} "
            f"duplicates={ev.get('skipped_duplicate', 0)} "
            f"errors={ev.get('errors', 0)}",
            style=style,
        )
        if ev.get("log_path"):
            msg.append(f"   {ev['log_path']}", style="dim")
        self._set_banner(msg)

    def _set_banner(self, renderable) -> None:
        self.query_one("#upload-banner", Static).update(renderable)
