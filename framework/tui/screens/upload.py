"""Paramify page — push to Paramify.

Two write actions share this page because they share all their plumbing (token,
base_url, overrides config, the event-stream shape), stacked as panels. Scan
reports go to their assessments from the Pipelines page:

  * Evidence upload — attach a completed run's evidence to its evidence sets
    (run-scoped; follows Evidence in the tab flow).
  * Scripts sync — push each fetcher's entry script and associate it to its
    evidence set (repo-scoped provisioning; independent of the selected run).
    Preview runs a read-only --dry-run and surfaces the per-fetcher plan
    (create / update / drift / noop) so you can see what a real sync would do —
    including which drifted scripts only --force would push.
"""

from __future__ import annotations

from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Checkbox, RichLog, Static, TabbedContent

from framework import api
from framework.sync.render import render_plan
from framework.tui import palette
from framework.tui.components.keys import BUTTON_ROW_BINDINGS, ButtonRowNav
from framework.tui.components.table import DataTable
from framework.tui.modals import ConfirmModal
from framework.tui.screens.paramify_events import (
    BUSY_NOTICE,
    ParamifyWriter,
    ScriptsSyncEvent,
    UploadEvent,
    latest_run_scoped,
    output_dir,
    upload_event_lines,
)


class UploadPage(ParamifyWriter, ButtonRowNav, Vertical):
    HINTS = [("ctrl+u", "upload"), ("p", "preview"), ("ctrl+s", "sync"),
             ("ctrl+r", "refresh")]

    BINDINGS = [
        Binding("ctrl+u", "upload_run", "Upload"),
        # p mirrors the manifest list's preview key (this page has no Input to eat
        # it); ctrl+p stays as an alias, which needs App.ENABLE_COMMAND_PALETTE
        # off — Textual's palette claims ctrl+p as a priority binding.
        Binding("p,ctrl+p", "preview_scripts", "Preview"),
        Binding("ctrl+s", "sync_scripts", "Sync Scripts"),
        Binding("ctrl+r", "refresh_upload", "Refresh"),
        *BUTTON_ROW_BINDINGS,
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="evidence-panel", classes="panel"):
            yield DataTable(id="evidence-summary")
            yield Static("", id="evidence-notes", classes="panel-notes")
            with Horizontal(id="evidence-actions"):
                yield Button("Upload to Paramify", variant="primary", id="upload-submit", disabled=True)
        with Vertical(id="scripts-panel", classes="panel"):
            yield Static("", id="scripts-header")
            yield Static("", id="scripts-plan-summary")
            yield DataTable(id="scripts-plan")
            with Horizontal(id="scripts-actions"):
                yield Button("Preview", variant="primary", id="scripts-preview", disabled=True)
                yield Button("Sync Scripts", variant="primary", id="scripts-submit", disabled=True)
                yield Checkbox("force", id="scripts-force")
                yield Checkbox("reassociate", id="scripts-reassociate")
        with Vertical(id="upload-log-panel", classes="panel"):
            yield RichLog(id="upload-log", markup=False, wrap=True, highlight=False)
            yield Static(
                f"progress streams here — [bold {palette.ACCENT}]ctrl+u[/] upload · "
                f"[bold {palette.ACCENT}]ctrl+p[/] preview · [bold {palette.ACCENT}]ctrl+s[/] sync",
                classes="empty-hint",
            )
        yield Static("", id="upload-banner")

    def on_mount(self) -> None:
        self._uploading = False
        self._syncing = False
        self._busy_planning = False
        self._run_dir: str | None = None
        self._run_manifest = None  # see _rebuild_evidence
        self._preflight: dict | None = None
        self._scripts_preflight: dict | None = None
        self._plan_counts: dict[str, int] = {}
        # Which stage the shared log and banner are currently reporting on.
        self._upload_kind = "evidence"

        self.query_one("#evidence-panel", Vertical).border_title = "evidence upload"
        self.query_one("#scripts-panel", Vertical).border_title = "scripts sync"
        log_panel = self.query_one("#upload-log-panel", Vertical)
        log_panel.border_title = "log"
        log_panel.set_class(True, "empty")

        ev = self.query_one("#evidence-summary", DataTable)
        ev.cursor_type = "row"
        ev.zebra_stripes = True
        ev.add_columns("field", "value")

        plan = self.query_one("#scripts-plan", DataTable)
        plan.cursor_type = "row"
        plan.zebra_stripes = True
        plan.add_columns("fetcher", "action")

        self.rebuild()

    def focus_default(self) -> None:
        """Focus the first action that can run, else the evidence table.

        Something inside the page must hold focus or none of its keys fire.
        """
        self.rebuild()
        self._focus_first_action()

    def _focus_first_action(self) -> None:
        for bid in ("#upload-submit", "#scripts-preview"):
            button = self.query_one(bid, Button)
            if not button.disabled:
                button.focus()
                return
        self.query_one("#evidence-summary", DataTable).focus()

    def _refocus_if_lost(self) -> None:
        """Put focus back in this page after an operation, if it fell out.

        Starting a send disables every button, and the one that held focus
        takes it with it, so focus drops to the tab strip, where this page's keys do
        nothing until the user presses 4 again. So when an
        operation ends, return focus to the page. Left alone when the user has
        meanwhile moved to another tab or a modal is open, or when focus is
        still somewhere usable in the page.
        """
        if self.screen is not self.app.screen:
            return  # a modal is on top
        if self.screen.query_one(TabbedContent).active != "tab-upload":
            return  # the user went elsewhere; don't pull them back
        focused = self.app.focused
        if focused is not None and not focused.disabled and focused in self.walk_children():
            return
        self._focus_first_action()

    @property
    def _own_busy(self) -> bool:
        return self._uploading or self._syncing or self._busy_planning

    # -- data ------------------------------------------------------------- #

    def _output_dir(self) -> str:
        return output_dir(self.app)

    def _manifest_fetcher_names(self) -> set:
        """The fetchers the active manifest uses — scripts sync is scoped to these
        (you provision scripts for the evidence you actually collect), not the
        whole repo catalog."""
        manifest = getattr(self.app, "manifest", None) or {}
        entries = (manifest.get("run") or {}).get("fetchers") or []
        return {e.get("use") for e in entries if e.get("use")}

    def _latest_scoped(self, kind: str) -> tuple[dict | None, bool]:
        """_latest, and whether the run came from the active manifest's own runs."""
        return latest_run_scoped(self.app, kind)

    def rebuild(self) -> None:
        """Refresh readiness for both panels (cheap; no network). The scripts
        plan itself is populated on demand by Preview / Sync, not here."""
        if self._own_busy:
            return
        self._rebuild_evidence()
        self._rebuild_scripts()

    def _rebuild_evidence(self) -> None:
        """Evidence-upload readiness (run-scoped). Sets self._run_dir/_preflight
        and the upload button."""
        self._run_dir = None
        self._run_manifest = None
        self._preflight = None
        table = self.query_one("#evidence-summary", DataTable)
        table.clear()
        self._notes("evidence", [])
        upload = self.query_one("#upload-submit", Button)
        upload.disabled = True

        out = self._output_dir()
        table.add_row("output dir", out)
        try:
            latest, scoped = self._latest_scoped("evidence")
        except Exception as exc:
            self._notes("evidence", [("status", f"cannot list runs: {exc}", palette.FAIL)])
            return
        if latest is None:
            table.add_row("status", Text(
                "no run with evidence — collect in the Run tab first", style="dim",
            ))
            return

        self._run_dir = latest["dir"]
        # The manifest the plan compares the run's Paramify settings with: the
        # open one when the run is its own, or records none. A run another
        # manifest made gets None, and the upload reads that manifest from the run.
        if scoped or latest.get("manifest") is None:
            self._run_manifest = getattr(self.app, "manifest_path", None)
        table.add_row("selected run", latest["run_id"])
        table.add_row("result", self._result_text(latest))

        try:
            preflight = api.upload_preflight(self._run_dir, self.app.root_path)
        except Exception as exc:
            self._notes("evidence", [("preflight", str(exc), palette.FAIL)])
            return

        self._preflight = preflight
        table.add_row("Paramify API", preflight["base_url"])
        # Which config the upload will run on — base_url, overrides, and the
        # stack that picks a channel all come from it, and the page takes no
        # path, so naming it is the only way to see that it was found.
        table.add_row(
            "uploader config",
            preflight.get("config_path") or Text("none (built-in defaults)", style="dim"),
        )
        table.add_row("API token", palette.pill("present", "ok") if preflight["token_present"] else palette.pill("missing", "fail"))
        table.add_row("upload files", str(preflight["file_count"]))
        if preflight["ok"]:
            upload.disabled = False
        else:
            self._notes("evidence", [("preflight error", err, palette.FAIL) for err in preflight["errors"]])

    def _rebuild_scripts(self) -> None:
        """Scripts-sync readiness (repo-scoped). Preview/Sync enabled whenever
        there are fetchers to sync — independent of any run selection."""
        self._scripts_preflight = None
        preview = self.query_one("#scripts-preview", Button)
        sync = self.query_one("#scripts-submit", Button)
        preview.disabled = True
        sync.disabled = True
        header = self.query_one("#scripts-header", Static)

        try:
            pf = api.scripts_sync_preflight(
                self.app.root_path, dry_run=True, include=self._manifest_fetcher_names()
            )
        except Exception as exc:
            header.update(Text(f"scripts preflight failed: {exc}", style=palette.FAIL))
            return

        self._scripts_preflight = pf
        token = (
            palette.pill("token present", "ok") if pf["token_present"]
            else palette.pill("token missing — preview only", "warn")
        )
        hdr = Text(f"{pf['fetcher_count']} fetchers in manifest → {pf['base_url']}    ")
        hdr.append_text(token)
        header.update(hdr)

        enabled = pf["fetcher_count"] > 0
        preview.disabled = not enabled
        sync.disabled = not enabled

        # Prompt only while no plan has been computed yet this session.
        if self.query_one("#scripts-plan", DataTable).row_count == 0:
            self.query_one("#scripts-plan-summary", Static).update(
                Text("Preview (ctrl+p) computes the plan — which scripts create / update / drift", style="dim")
            )

    def _notes(self, panel: str, notes: list) -> None:
        """Show (label, message, style) lines under a panel's table, or hide the
        notes when there are none. Prose goes here, not in a row: a DataTable cell
        never wraps, so a long preflight error ran off the panel behind a
        horizontal scrollbar."""
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", no_wrap=True)
        grid.add_column()
        for label, message, style in notes:
            grid.add_row(label, Text(message, style=style))
        static = self.query_one(f"#{panel}-notes", Static)
        static.update(grid)
        static.display = bool(notes)

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

    @on(Button.Pressed, "#upload-submit")
    def _on_upload(self) -> None:
        self.action_upload_run()

    def action_refresh_upload(self) -> None:
        self.rebuild()
        self.notify("Paramify page refreshed.")

    def action_upload_run(self) -> None:
        if self._busy:
            self.notify(BUSY_NOTICE)
            return
        if not self._run_dir or not self._preflight or not self._preflight.get("ok"):
            self.notify("No upload-ready run selected.")
            return

        # Plan first, so the confirm shows what the upload will do. upload_run
        # plans again under its own lock; this one only informs the question.
        self._busy_planning = True
        self._plan_worker(
            self._run_dir, self.app.root_path, bool(self._preflight.get("token_present")),
            f"Upload {self._preflight['file_count']} evidence file(s) to {self._preflight['base_url']}?",
            self._run_manifest,
        )

    @work(thread=True, exclusive=True, group="plan")
    def _plan_worker(self, run_dir: str, root, online: bool, question: str, manifest_path=None) -> None:
        try:
            lines = render_plan(api.plan_upload(run_dir, root, online=online, manifest_path=manifest_path))
            error = False
        except Exception as exc:
            lines, error = [f"Cannot plan the upload: {exc}"], True
        self.app.call_from_thread(self._confirm_upload, run_dir, "\n".join(lines), question, error)

    def _confirm_upload(self, run_dir: str, body: str, question: str, error: bool) -> None:
        def go(ok: bool) -> None:
            if ok and not error:
                self._start_upload(run_dir)

        try:
            self.app.push_screen(ConfirmModal(body if error else f"{body}\n\n{question}"), go)
        finally:
            self._busy_planning = False

    def _start_upload(self, run_dir: str) -> None:
        self._uploading = True
        self._upload_kind = "evidence"
        self._begin_log(Text("uploading to Paramify...", style=palette.WARN))
        self._upload_worker(run_dir, self.app.root_path, self._run_manifest)

    @work(thread=True, exclusive=True)
    def _upload_worker(self, run_dir: str, root, manifest_path=None) -> None:
        try:
            api.upload_run(run_dir, root, on_event=lambda ev: self.post_message(UploadEvent(ev)),
                           manifest_path=manifest_path)
        except Exception as exc:
            self.post_message(UploadEvent({"event": "_upload_failed", "error": str(exc)}))

    def _begin_log(self, banner) -> None:
        self._disable_actions()
        self.query_one("#upload-log-panel", Vertical).set_class(False, "empty")
        self.query_one("#upload-log", RichLog).clear()
        self._set_banner(banner)

    # -- actions: scripts sync ------------------------------------------- #

    @on(Button.Pressed, "#scripts-preview")
    def _on_preview(self) -> None:
        self.action_preview_scripts()

    @on(Button.Pressed, "#scripts-submit")
    def _on_sync(self) -> None:
        self.action_sync_scripts()

    def action_preview_scripts(self) -> None:
        """Read-only dry-run: compute and surface the plan. No token required,
        no confirmation (it makes no writes)."""
        if self._busy:
            self.notify(BUSY_NOTICE)
            return
        pf = self._scripts_preflight
        if not pf or pf.get("fetcher_count", 0) == 0:
            self.notify("No fetcher scripts to plan.")
            return
        self._start_scripts(dry_run=True)

    def action_sync_scripts(self) -> None:
        if self._busy:
            self.notify(BUSY_NOTICE)
            return
        pf = self._scripts_preflight
        if not pf or pf.get("fetcher_count", 0) == 0:
            self.notify("No fetcher scripts to sync.")
            return
        if not pf.get("token_present"):
            self.notify("API token missing — set PARAMIFY_UPLOAD_API_TOKEN (Preview still works).")
            return

        force = self.query_one("#scripts-force", Checkbox).value
        extra = " (force: push drifted scripts)" if force else ""

        def go(ok: bool) -> None:
            if ok:
                self._start_scripts(dry_run=False)

        self.app.push_screen(
            ConfirmModal(
                f"Sync {pf['fetcher_count']} fetcher script(s) to {pf['base_url']} "
                f"and associate them to their evidence sets?{extra}"
            ),
            go,
        )

    def _start_scripts(self, *, dry_run: bool) -> None:
        self._syncing = True
        self._disable_actions()
        self.query_one("#upload-log-panel", Vertical).set_class(False, "empty")
        self.query_one("#upload-log", RichLog).clear()
        self._reset_plan()
        verb = "previewing" if dry_run else "syncing"
        self._set_banner(Text(f"{verb} scripts...", style=palette.WARN))
        self._scripts_worker(
            self.app.root_path,
            dry_run=dry_run,
            force=self.query_one("#scripts-force", Checkbox).value,
            reassociate=self.query_one("#scripts-reassociate", Checkbox).value,
            include=self._manifest_fetcher_names(),
        )

    @work(thread=True, exclusive=True)
    def _scripts_worker(self, root, dry_run: bool, force: bool, reassociate: bool, include: set) -> None:
        try:
            api.scripts_sync(
                root,
                dry_run=dry_run,
                force=force,
                reassociate=reassociate,
                include=include,
                on_event=lambda ev: self.post_message(ScriptsSyncEvent(ev)),
            )
        except Exception as exc:
            self.post_message(ScriptsSyncEvent({"event": "_scripts_failed", "error": str(exc)}))

    # -- events: evidence upload ----------------------------------------- #

    def on_upload_event(self, message: UploadEvent) -> None:
        self._handle_upload_event(message.ev)

    def _handle_upload_event(self, ev: dict) -> None:
        etype = ev.get("event")
        log = self.query_one("#upload-log", RichLog)
        noun = self._upload_kind
        for line in upload_event_lines(ev, noun):
            log.write(line)
        if etype == "upload_start":
            mode = " (dry-run)" if ev.get("dry_run") else ""
            self._set_banner(Text(f"uploading {ev.get('files', 0)} {noun}(s) to {ev.get('base_url', '')}{mode}", style=palette.WARN))
        elif etype == "job_queued":
            self._set_banner(Text(
                f"processing on {ev.get('assessment_id')} — job {ev.get('job_id')} queued",
                style=palette.WARN,
            ))
        elif etype == "job_status":
            self._set_banner(Text(
                f"job {ev.get('job_id')} {ev.get('status')} on {ev.get('assessment_id')}",
                style=palette.WARN,
            ))
        elif etype == "upload_complete":
            self._finalize_upload(ev)
        elif etype == "_upload_failed":
            self._uploading = False
            self._restore_actions()
            log.write(Text(f"upload failed: {ev.get('error', '')}", style=f"bold {palette.FAIL}"))
            self._set_banner(Text(f"upload failed: {ev.get('error', '')}", style=palette.FAIL))

    def _finalize_upload(self, ev: dict) -> None:
        self._uploading = False
        # An intake changes what the panel should say (those reports are now
        # duplicates), so re-read readiness rather than only re-enabling buttons.
        self.rebuild()
        self._restore_actions()
        ok = ev.get("ok")
        style = palette.OK if ok else palette.FAIL
        msg = Text(
            f"{self._upload_kind} upload complete — "
            f"uploaded={ev.get('uploaded', 0)} "
            f"duplicates={ev.get('skipped_duplicate', 0)} "
            f"errors={ev.get('errors', 0)}"
            + (f" dropped={ev['dropped']}" if ev.get("dropped") else "")
            + (f" jobs_failed={ev['jobs_failed']}" if ev.get("jobs_failed") else ""),
            style=style,
        )
        if ev.get("halted"):
            msg.append(f"   stopped early: {ev['halted']}", style=palette.FAIL)
        if ev.get("log_path"):
            msg.append(f"   {ev['log_path']}", style="dim")
        self._set_banner(msg)

    # -- events: scripts sync -------------------------------------------- #

    def on_scripts_sync_event(self, message: ScriptsSyncEvent) -> None:
        self._handle_scripts_event(message.ev)

    # outcome -> (plan category, action label, style). Covers both the dry-run
    # (would_*) and the applied (create/update/drift/…) event vocabularies.
    _PLAN_MARKS = {
        "would_create": ("create", "create", palette.OK),
        "create": ("create", "created", palette.OK),
        "would_update": ("update", "update", palette.OK),
        "update": ("update", "updated", palette.OK),
        "would_noop": ("noop", "noop", "dim"),
        "noop": ("noop", "noop", "dim"),
        "would_drift": ("drift", "drift — needs force", palette.WARN),
        "drift": ("drift", "drift — pushed (force)", palette.WARN),
        "drift_skipped": ("drift", "drift — skipped", palette.WARN),
        "error": ("error", "error", palette.FAIL),
    }

    def _reset_plan(self) -> None:
        self._plan_counts = {}
        self.query_one("#scripts-plan", DataTable).clear()
        self.query_one("#scripts-plan-summary", Static).update(Text(""))

    def _handle_scripts_event(self, ev: dict) -> None:
        etype = ev.get("event")
        log = self.query_one("#upload-log", RichLog)

        if etype == "sync_start":
            mode = " (dry-run)" if ev.get("dry_run") else ""
            self._set_banner(Text(f"{'preview' if ev.get('dry_run') else 'sync'}: {ev.get('fetchers', 0)} script(s) → {ev.get('base_url', '')}{mode}", style=palette.WARN))
            log.write(Text(f"sync {ev.get('fetchers', 0)} fetcher script(s){mode}", style="bold"))
        elif etype == "sync_item":
            self._record_plan_item(ev)
            log.write(self._plan_log_line(ev))
        elif etype == "sync_complete":
            self._finalize_scripts(ev)
        elif etype == "_scripts_failed":
            self._syncing = False
            self._restore_actions()
            log.write(Text(f"scripts sync failed: {ev.get('error', '')}", style=f"bold {palette.FAIL}"))
            self._set_banner(Text(f"scripts sync failed: {ev.get('error', '')}", style=palette.FAIL))

    def _record_plan_item(self, ev: dict) -> None:
        """Add one fetcher's planned/applied action to the plan table + counts."""
        category, label, style = self._PLAN_MARKS.get(ev.get("outcome"), ("other", ev.get("outcome", "?"), "white"))
        self._plan_counts[category] = self._plan_counts.get(category, 0) + 1
        assoc = "  +assoc" if ev.get("associated") else ""
        cell = Text(f"{label}{assoc}", style=style)
        self.query_one("#scripts-plan", DataTable).add_row(ev.get("fetcher", "?"), cell)
        self._render_plan_summary()

    def _plan_log_line(self, ev: dict) -> Text:
        _, label, style = self._PLAN_MARKS.get(ev.get("outcome"), ("other", ev.get("outcome", "?"), "white"))
        ref = f"  set={ev.get('reference_id')}" if ev.get("reference_id") else ""
        assoc = " +assoc" if ev.get("associated") else ""
        reason = ev.get("reason") or ev.get("error")
        suffix = f"  {reason}" if reason else ""
        return Text(f"  [{label}] {ev.get('fetcher', '?')}{ref}{assoc}{suffix}", style=style)

    def _render_plan_summary(self) -> None:
        c = self._plan_counts
        total = sum(c.values())
        summary = Text(f"{total} planned", style="dim")
        for key, style in (("create", palette.OK), ("update", palette.OK), ("drift", palette.WARN),
                           ("noop", "dim"), ("error", palette.FAIL)):
            if c.get(key):
                summary.append("  ·  ", style="dim")
                summary.append(f"{c[key]} {key}", style=style)
        if c.get("drift"):
            summary.append("    enable force to push drift", style=palette.WARN)
        self.query_one("#scripts-plan-summary", Static).update(summary)

    def _finalize_scripts(self, ev: dict) -> None:
        self._syncing = False
        self._restore_actions()
        if ev.get("dry_run"):
            # Dry-run counts are zero by design; the plan we accumulated per item
            # is the real signal, so summarise from that.
            c = self._plan_counts
            msg = Text(
                "preview complete — "
                f"create={c.get('create', 0)} update={c.get('update', 0)} "
                f"drift={c.get('drift', 0)} noop={c.get('noop', 0)}",
                style=palette.WARN if c.get("drift") else palette.OK,
            )
        else:
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
        for bid in ("#upload-submit", "#scripts-preview", "#scripts-submit"):
            self.query_one(bid, Button).disabled = True

    def _restore_actions(self) -> None:
        self.query_one("#upload-submit", Button).disabled = not (self._preflight and self._preflight.get("ok"))
        has_fetchers = bool(self._scripts_preflight and self._scripts_preflight.get("fetcher_count", 0) > 0)
        self.query_one("#scripts-preview", Button).disabled = not has_fetchers
        self.query_one("#scripts-submit", Button).disabled = not has_fetchers
        # After a refresh, so the modal that started the operation has handed
        # focus back (to a button that is disabled now) before we look.
        self.call_after_refresh(self._refocus_if_lost)

    def _set_banner(self, renderable) -> None:
        self.query_one("#upload-banner", Static).update(renderable)
