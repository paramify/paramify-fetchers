"""Paramify page — push to Paramify.

Two write actions share this screen because they share all their plumbing
(token, base_url, overrides config, the event-stream shape):

  * Upload — attach a completed run's evidence to its evidence sets (run-scoped;
    follows Evidence in the tab flow).
  * Sync Scripts — push each fetcher's entry script and associate it to its
    evidence set (repo-scoped provisioning; independent of the selected run).
"""

from __future__ import annotations

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, Checkbox, DataTable, RichLog, Static

from framework import api
from framework.tui import palette
from framework.tui.modals import ConfirmModal


class UploadEvent(Message):
    """Carries one api.upload_run() event dict from the worker thread."""

    def __init__(self, ev: dict) -> None:
        self.ev = ev
        super().__init__()


class ScriptsSyncEvent(Message):
    """Carries one api.scripts_sync() event dict from the worker thread."""

    def __init__(self, ev: dict) -> None:
        self.ev = ev
        super().__init__()


class UploadPage(Vertical):
    HINTS = [("ctrl+r", "refresh"), ("ctrl+u", "upload"), ("ctrl+s", "sync scripts")]

    BINDINGS = [
        Binding("ctrl+r", "refresh_upload", "Refresh"),
        Binding("ctrl+u", "upload_run", "Upload"),
        Binding("ctrl+s", "sync_scripts", "Sync Scripts"),
    ]

    def compose(self) -> ComposeResult:
        with Horizontal(id="upload-top"):
            yield Button("Refresh", id="upload-refresh")
            yield Button("Upload to Paramify", variant="primary", id="upload-submit", disabled=True)
            yield Button("Sync Scripts", variant="primary", id="scripts-submit", disabled=True)
            yield Static("", id="upload-banner")
        with Horizontal(id="upload-options"):
            yield Static("scripts sync:", classes="options-label")
            yield Checkbox("dry-run", id="scripts-dry")
            yield Checkbox("force", id="scripts-force")
            yield Checkbox("reassociate", id="scripts-reassociate")
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
        self._syncing = False
        self._run_dir: str | None = None
        self._preflight: dict | None = None
        self._scripts_preflight: dict | None = None
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

    @property
    def _busy(self) -> bool:
        return self._uploading or self._syncing

    # -- data ------------------------------------------------------------- #

    def _output_dir(self) -> str:
        run = (getattr(self.app, "manifest", None) or {}).get("run") or {}
        return run.get("output_dir") or "./evidence"

    def rebuild(self) -> None:
        if self._busy:
            return
        table = self.query_one("#upload-summary", DataTable)
        table.clear()
        self._rebuild_evidence(table)
        table.add_row("", "")
        self._rebuild_scripts(table)

    def _rebuild_evidence(self, table: DataTable) -> None:
        """Evidence-upload readiness (run-scoped). Sets self._run_dir/_preflight
        and the upload button; never returns early from rebuild()."""
        self._run_dir = None
        self._preflight = None
        upload = self.query_one("#upload-submit", Button)
        upload.disabled = True

        out = self._output_dir()
        table.add_row("EVIDENCE", "attach a run's files to its evidence sets")
        table.add_row("output dir", out)
        try:
            runs = api.list_runs(out)
        except Exception as exc:
            self._set_banner(Text(f"cannot list runs: {exc}", style=palette.FAIL))
            table.add_row("status", Text(f"cannot list runs: {exc}", style=palette.FAIL))
            return
        if not runs:
            table.add_row("status", Text("no runs found — collect in the Run tab first", style="dim"))
            return

        latest = runs[0]
        self._run_dir = latest["dir"]
        table.add_row("selected run", latest["run_id"])
        table.add_row("result", self._result_text(latest))

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
            self._set_banner(Text("ready — upload evidence, or sync scripts", style=palette.OK))
        else:
            for err in preflight["errors"]:
                table.add_row("preflight error", Text(err, style=palette.FAIL))
            self._set_banner(Text("upload preflight failed", style=palette.FAIL))

    def _rebuild_scripts(self, table: DataTable) -> None:
        """Scripts-sync readiness (repo-scoped). Enabled whenever there are
        fetchers to sync — independent of any run selection."""
        self._scripts_preflight = None
        sync = self.query_one("#scripts-submit", Button)
        sync.disabled = True

        table.add_row("SCRIPTS", "push fetcher entry scripts + associate to sets")
        try:
            pf = api.scripts_sync_preflight(self.app.root_path, dry_run=False)
        except Exception as exc:
            self._set_banner(Text(f"scripts preflight failed: {exc}", style=palette.FAIL))
            table.add_row("scripts preflight", Text(str(exc), style=palette.FAIL))
            return

        self._scripts_preflight = pf
        table.add_row("fetchers", str(pf["fetcher_count"]))
        table.add_row("API token", palette.pill("present", "ok") if pf["token_present"] else palette.pill("missing (dry-run ok)", "warn"))
        table.add_row("Paramify API", pf["base_url"])
        # Enabled if there's anything to sync; a real (non-dry-run) sync still
        # checks for the token at click time.
        sync.disabled = pf["fetcher_count"] == 0

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

    # -- actions: evidence upload ---------------------------------------- #

    @on(Button.Pressed, "#upload-refresh")
    def _on_refresh(self) -> None:
        self.action_refresh_upload()

    @on(Button.Pressed, "#upload-submit")
    def _on_upload(self) -> None:
        self.action_upload_run()

    def action_refresh_upload(self) -> None:
        self.rebuild()
        self.notify("Paramify page refreshed.")

    def action_upload_run(self) -> None:
        if self._busy:
            self.notify("A Paramify operation is already in progress.")
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
        self._disable_actions()
        self.query_one("#upload-log-panel", Vertical).set_class(False, "empty")
        self.query_one("#upload-log", RichLog).clear()
        self._set_banner(Text("uploading to Paramify...", style=palette.WARN))
        self._upload_worker(run_dir, self.app.root_path)

    @work(thread=True, exclusive=True)
    def _upload_worker(self, run_dir: str, root) -> None:
        try:
            api.upload_run(run_dir, root, on_event=lambda ev: self.post_message(UploadEvent(ev)))
        except Exception as exc:
            self.post_message(UploadEvent({"event": "_upload_failed", "error": str(exc)}))

    # -- actions: scripts sync ------------------------------------------- #

    @on(Button.Pressed, "#scripts-submit")
    def _on_sync(self) -> None:
        self.action_sync_scripts()

    def action_sync_scripts(self) -> None:
        if self._busy:
            self.notify("A Paramify operation is already in progress.")
            return
        pf = self._scripts_preflight
        if not pf or pf.get("fetcher_count", 0) == 0:
            self.notify("No fetcher scripts to sync.")
            return
        dry = self.query_one("#scripts-dry", Checkbox).value
        if not dry and not pf.get("token_present"):
            self.notify("API token missing — check dry-run or set PARAMIFY_UPLOAD_API_TOKEN.")
            return

        if dry:
            self._start_scripts()  # read-only: no confirmation needed
            return

        def go(ok: bool) -> None:
            if ok:
                self._start_scripts()

        self.app.push_screen(
            ConfirmModal(
                f"Sync {pf['fetcher_count']} fetcher script(s) to {pf['base_url']} "
                "and associate them to their evidence sets?"
            ),
            go,
        )

    def _start_scripts(self) -> None:
        self._syncing = True
        self._disable_actions()
        self.query_one("#upload-log-panel", Vertical).set_class(False, "empty")
        self.query_one("#upload-log", RichLog).clear()
        self._set_banner(Text("syncing scripts to Paramify...", style=palette.WARN))
        self._scripts_worker(
            self.app.root_path,
            dry_run=self.query_one("#scripts-dry", Checkbox).value,
            force=self.query_one("#scripts-force", Checkbox).value,
            reassociate=self.query_one("#scripts-reassociate", Checkbox).value,
        )

    @work(thread=True, exclusive=True)
    def _scripts_worker(self, root, dry_run: bool, force: bool, reassociate: bool) -> None:
        try:
            api.scripts_sync(
                root,
                dry_run=dry_run,
                force=force,
                reassociate=reassociate,
                on_event=lambda ev: self.post_message(ScriptsSyncEvent(ev)),
            )
        except Exception as exc:
            self.post_message(ScriptsSyncEvent({"event": "_scripts_failed", "error": str(exc)}))

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
            self._restore_actions()
            log.write(Text(f"upload failed: {ev.get('error', '')}", style=f"bold {palette.FAIL}"))
            self._set_banner(Text(f"upload failed: {ev.get('error', '')}", style=palette.FAIL))

    def _finalize_upload(self, ev: dict) -> None:
        self._uploading = False
        self._restore_actions()
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

    def on_scripts_sync_event(self, message: ScriptsSyncEvent) -> None:
        self._handle_scripts_event(message.ev)

    _SCRIPT_MARKS = {
        "create": ("NEW", palette.OK), "update": ("UPD", palette.OK), "noop": ("OK", "dim"),
        "drift": ("DRIFT", palette.WARN), "drift_skipped": ("DRIFT", palette.WARN), "error": ("FAIL", palette.FAIL),
        "would_create": ("NEW?", palette.INFO), "would_update": ("UPD?", palette.INFO),
        "would_noop": ("OK?", "dim"), "would_drift": ("DRIFT?", palette.WARN),
    }

    def _handle_scripts_event(self, ev: dict) -> None:
        etype = ev.get("event")
        log = self.query_one("#upload-log", RichLog)

        if etype == "sync_start":
            mode = " (dry-run)" if ev.get("dry_run") else ""
            self._set_banner(Text(f"syncing {ev.get('fetchers', 0)} script(s) to {ev.get('base_url', '')}{mode}", style=palette.WARN))
            log.write(Text(f"sync {ev.get('fetchers', 0)} fetcher script(s){mode}", style="bold"))
        elif etype == "sync_item":
            icon, style = self._SCRIPT_MARKS.get(ev.get("outcome"), ("?", "white"))
            ref = f"  set={ev.get('reference_id')}" if ev.get("reference_id") else ""
            assoc = " +assoc" if ev.get("associated") else ""
            reason = ev.get("reason") or ev.get("error")
            suffix = f"  {reason}" if reason else ""
            log.write(Text(f"  [{icon}] {ev.get('fetcher', '?')}{ref}{assoc}{suffix}", style=style))
        elif etype == "sync_complete":
            self._finalize_scripts(ev)
        elif etype == "_scripts_failed":
            self._syncing = False
            self._restore_actions()
            log.write(Text(f"scripts sync failed: {ev.get('error', '')}", style=f"bold {palette.FAIL}"))
            self._set_banner(Text(f"scripts sync failed: {ev.get('error', '')}", style=palette.FAIL))

    def _finalize_scripts(self, ev: dict) -> None:
        self._syncing = False
        self._restore_actions()
        msg = Text(
            "scripts sync complete — "
            f"created={ev.get('created', 0)} "
            f"updated={ev.get('updated', 0)} "
            f"drift={ev.get('drift', 0)} "
            f"noop={ev.get('noop', 0)} "
            f"associated={ev.get('associated', 0)} "
            f"errors={ev.get('errors', 0)}",
            style=palette.OK if ev.get("ok") else palette.FAIL,
        )
        self._set_banner(msg)

    # -- button state ----------------------------------------------------- #

    def _disable_actions(self) -> None:
        for bid in ("#upload-refresh", "#upload-submit", "#scripts-submit"):
            self.query_one(bid, Button).disabled = True

    def _restore_actions(self) -> None:
        self.query_one("#upload-refresh", Button).disabled = False
        self.query_one("#upload-submit", Button).disabled = not (self._preflight and self._preflight.get("ok"))
        self.query_one("#scripts-submit", Button).disabled = not (
            self._scripts_preflight and self._scripts_preflight.get("fetcher_count", 0) > 0
        )

    def _set_banner(self, renderable) -> None:
        self.query_one("#upload-banner", Static).update(renderable)
