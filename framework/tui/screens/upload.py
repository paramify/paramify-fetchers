"""Paramify page — push to Paramify.

Three write actions share this page because they share all their plumbing (token,
base_url, overrides config, the event-stream shape), stacked as panels:

  * Evidence upload — attach a completed run's evidence to its evidence sets
    (run-scoped; follows Evidence in the tab flow).
  * Issue-report intake — post a run's raw scan reports to their assessments
    (run-scoped). A separate action because it is a separate endpoint: the same
    run can hold both kinds, and uploading evidence leaves the reports unsent.
    The panel stays empty for a run that collected none, which is most runs.
  * Scripts sync — push each fetcher's entry script and associate it to its
    evidence set (repo-scoped provisioning; independent of the selected run).
    Preview runs a read-only --dry-run and surfaces the per-fetcher plan
    (create / update / drift / noop) so you can see what a real sync would do —
    including which drifted scripts only --force would push.
"""

from __future__ import annotations

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, Checkbox, DataTable, RichLog, Static, TabbedContent

from framework import api
from framework.tui import palette
from framework.tui.components.keys import BUTTON_ROW_BINDINGS, ButtonRowNav
from framework.tui.modals import ConfirmModal, PickerModal


class UploadEvent(Message):
    """Carries one api.upload_run() event dict from the worker thread."""

    def __init__(self, ev: dict) -> None:
        self.ev = ev
        super().__init__()


class PipelineEvent(Message):
    """Carries one result of a pipeline action (jobs, retry/cancel, close) from a
    worker thread."""

    def __init__(self, ev: dict) -> None:
        self.ev = ev
        super().__init__()


class ScriptsSyncEvent(Message):
    """Carries one api.scripts_sync() event dict from the worker thread."""

    def __init__(self, ev: dict) -> None:
        self.ev = ev
        super().__init__()


_COUNT_LABELS = (
    ("issuesCreated", "created"),
    ("issuesUpdated", "updated"),
    ("issuesSeenClosed", "seen-closed"),
    ("issuesAutoClosed", "auto-closed"),
)


def _job_text(job: dict) -> Text:
    """One finished pipeline job as a log line: what it did, or why it stopped."""
    status = job.get("status") or "?"
    counts = job.get("counts") or {}
    shown = [f"{counts[k]} {label}" for k, label in _COUNT_LABELS if counts.get(k) is not None]
    # Same marks as the CLI: a queued or running job is waiting, not failed —
    # unless it is queued behind a failed one, which needs a person.
    if status == "COMPLETED":
        mark, style = "OK", palette.OK
    elif status == "FAILED" or job.get("blocked_by"):
        mark, style = "FAIL", palette.FAIL
    elif status == "CANCELLED":
        mark, style = "SKIP", palette.WARN
    else:
        mark, style = "WAIT", palette.WARN
    text = Text(f"  [{mark}] job {job.get('job_id')} {status}", style=style)
    if shown:
        text.append("  " + ", ".join(shown))
    if job.get("blocked_by"):
        text.append(
            f"  blocked by failed job {job['blocked_by']} — "
            f"paramify issues jobs --retry {job['blocked_by']}", style=palette.FAIL,
        )
    if job.get("timed_out"):
        text.append("  still running — check with `paramify issues jobs`", style=palette.WARN)
    for key in ("error", "poll_error"):
        if job.get(key):
            text.append(f"  {job[key]}", style="dim")
    return text


class UploadPage(ButtonRowNav, Vertical):
    HINTS = [("ctrl+u", "upload"), ("i", "send reports"), ("j", "jobs"),
             ("C", "close cycle"), ("p", "preview"), ("ctrl+s", "sync"),
             ("ctrl+r", "refresh")]

    BINDINGS = [
        Binding("ctrl+u", "upload_run", "Upload"),
        # Not ctrl+i: most terminals send the same byte for ctrl+i and Tab, so
        # the binding never fired. This page has no Input to eat a bare letter.
        Binding("i", "intake_issues", "Send reports"),
        Binding("j", "pipeline_jobs", "Jobs"),
        # Shifted on purpose: a close auto-closes every open issue the cycle
        # never saw, and cannot be undone.
        Binding("C", "close_cycle", "Close cycle"),
        # p mirrors the Manifest tab's preview key (this page has no Input to eat
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
            with Horizontal(id="evidence-actions"):
                yield Button("Upload to Paramify", variant="primary", id="upload-submit", disabled=True)
        with Vertical(id="issues-panel", classes="panel"):
            yield DataTable(id="issues-summary")
            with Horizontal(id="issues-actions"):
                yield Button("Send to Pipeline", variant="primary", id="issues-submit", disabled=True)
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
                f"[bold {palette.ACCENT}]i[/] send reports · "
                f"[bold {palette.ACCENT}]j[/] jobs · "
                f"[bold {palette.ACCENT}]C[/] close cycle · "
                f"[bold {palette.ACCENT}]ctrl+p[/] preview · [bold {palette.ACCENT}]ctrl+s[/] sync",
                classes="empty-hint",
            )
        yield Static("", id="upload-banner")

    def on_mount(self) -> None:
        self._uploading = False
        self._syncing = False
        self._run_dir: str | None = None
        self._issues_run_dir: str | None = None
        self._preflight: dict | None = None
        self._issues_preflight: dict | None = None
        self._scripts_preflight: dict | None = None
        self._plan_counts: dict[str, int] = {}
        # Which stage the shared log and banner are currently reporting on.
        self._upload_kind = "evidence"

        self.query_one("#evidence-panel", Vertical).border_title = "evidence upload"
        self.query_one("#issues-panel", Vertical).border_title = "issue reports"
        self.query_one("#scripts-panel", Vertical).border_title = "scripts sync"
        log_panel = self.query_one("#upload-log-panel", Vertical)
        log_panel.border_title = "log"
        log_panel.set_class(True, "empty")

        ev = self.query_one("#evidence-summary", DataTable)
        ev.cursor_type = "row"
        ev.zebra_stripes = True
        ev.add_columns("field", "value")

        issues = self.query_one("#issues-summary", DataTable)
        issues.cursor_type = "row"
        issues.zebra_stripes = True
        issues.add_columns("field", "value")

        plan = self.query_one("#scripts-plan", DataTable)
        plan.cursor_type = "row"
        plan.zebra_stripes = True
        plan.add_columns("fetcher", "action")

        self.rebuild()

    def focus_default(self) -> None:
        """Focus the first action that can run, else a panel's table.

        Something inside the page must hold focus or none of its keys fire. A
        pipeline manifest has no evidence to upload and no scripts to sync, so
        falling back only to the scripts Preview button — disabled there too —
        left focus nowhere and `i`, `j` and `C` dead on exactly the manifests
        they exist for.
        """
        self.rebuild()
        self._focus_first_action()

    def _focus_first_action(self) -> None:
        for bid in ("#upload-submit", "#issues-submit", "#scripts-preview"):
            button = self.query_one(bid, Button)
            if not button.disabled:
                button.focus()
                return
        self.query_one("#issues-summary", DataTable).focus()

    def _refocus_if_lost(self) -> None:
        """Put focus back in this page after an operation, if it fell out.

        Starting a send disables every button, and the one that held focus
        takes it with it, so focus drops to the tab strip, where `i`, `j` and `C`
        (this page's keys) do nothing until the user presses 5 again. So when an
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
    def _busy(self) -> bool:
        return self._uploading or self._syncing

    # -- data ------------------------------------------------------------- #

    def _output_dir(self) -> str:
        run = (getattr(self.app, "manifest", None) or {}).get("run") or {}
        return run.get("output_dir") or "./evidence"

    def _manifest_fetcher_names(self) -> set:
        """The fetchers the active manifest uses — scripts sync is scoped to these
        (you provision scripts for the evidence you actually collect), not the
        whole repo catalog."""
        manifest = getattr(self.app, "manifest", None) or {}
        entries = (manifest.get("run") or {}).get("fetchers") or []
        return {e.get("use") for e in entries if e.get("use")}

    def _latest(self, kind: str) -> dict | None:
        """The run a panel acts on: the newest one holding this kind.

        Evidence and pipeline manifests usually share an output dir, so each
        panel looks for its own kind rather than taking the newest run. Scoped
        to the active manifest's runs once it has any, so a pipeline manifest's
        evidence panel does not offer another manifest's evidence; runs from
        before run attribution existed are the fallback.
        """
        out = self._output_dir()
        path = getattr(self.app, "manifest_path", None)
        if path is not None:
            root = self.app.root_path
            if api.latest_run(out, manifest_path=path, root=root) is not None:
                return api.latest_run(out, kind=kind, manifest_path=path, root=root)
        return api.latest_run(out, kind=kind)

    def rebuild(self) -> None:
        """Refresh readiness for both panels (cheap; no network). The scripts
        plan itself is populated on demand by Preview / Sync, not here."""
        if self._busy:
            return
        self._rebuild_evidence()
        self._rebuild_issues()
        self._rebuild_scripts()

    def _rebuild_evidence(self) -> None:
        """Evidence-upload readiness (run-scoped). Sets self._run_dir/_preflight
        and the upload button."""
        self._run_dir = None
        self._preflight = None
        table = self.query_one("#evidence-summary", DataTable)
        table.clear()
        upload = self.query_one("#upload-submit", Button)
        upload.disabled = True

        out = self._output_dir()
        table.add_row("output dir", out)
        try:
            latest = self._latest("evidence")
        except Exception as exc:
            table.add_row("status", Text(f"cannot list runs: {exc}", style=palette.FAIL))
            return
        if latest is None:
            table.add_row("status", Text(
                "no run with evidence — collect in the Run tab first", style="dim",
            ))
            return

        self._run_dir = latest["dir"]
        table.add_row("selected run", latest["run_id"])
        table.add_row("result", self._result_text(latest))

        try:
            preflight = api.upload_preflight(self._run_dir, self.app.root_path)
        except Exception as exc:
            table.add_row("preflight", Text(str(exc), style=palette.FAIL))
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
            for err in preflight["errors"]:
                table.add_row("preflight error", Text(err, style=palette.FAIL))

    def _rebuild_issues(self) -> None:
        """Issue-report readiness for the newest run that collected any.

        Its own run, not the evidence panel's: a pipeline manifest's scan run and
        an evidence manifest's run usually sit side by side. With none, the panel
        says so and the button stays disabled — not an error. Preflight is only
        consulted when there is something to send.
        """
        self._issues_preflight = None
        self._issues_run_dir = None
        table = self.query_one("#issues-summary", DataTable)
        table.clear()
        submit = self.query_one("#issues-submit", Button)
        submit.disabled = True

        try:
            latest = self._latest("issue_report")
        except Exception as exc:
            table.add_row("status", Text(f"cannot list runs: {exc}", style=palette.FAIL))
            return
        if latest is None:
            table.add_row("status", Text("no run collected issue reports", style="dim"))
            return

        self._issues_run_dir = latest["dir"]
        table.add_row("selected run", latest["run_id"])
        table.add_row("reports", str(latest.get("issue_reports", 0)))
        try:
            preflight = api.issues_upload_preflight(self._issues_run_dir, self.app.root_path)
        except Exception as exc:
            table.add_row("preflight", Text(str(exc), style=palette.FAIL))
            return

        self._issues_preflight = preflight
        table.add_row("Paramify API", preflight["base_url"])
        table.add_row(
            "API token",
            palette.pill("present", "ok") if preflight["token_present"]
            else palette.pill("missing", "fail"),
        )
        # The plan: per assessment, what one upload will send. A close is the
        # row to read before confirming, so it gets the warning colour.
        for plan in preflight.get("assessments") or []:
            label = plan.get("assessment_name") or plan["assessment_id"]
            if plan.get("error"):
                value = Text(plan["error"], style=palette.FAIL)
            else:
                op = plan.get("operation") or "?"
                value = Text(
                    f"{plan['files']} file(s) → {op}",
                    style=palette.WARN if op == "PROCESS_CLOSE" else "",
                )
                if plan.get("close_skipped"):
                    value.append(f"   {plan['close_skipped']}", style="dim")
            table.add_row(label, value)
        # Non-gating: a report with no assessment is skipped by the uploader, not
        # a reason to refuse the batch. Shown so it is not a surprise afterwards.
        for warning in preflight.get("warnings") or []:
            table.add_row("warning", Text(warning, style=palette.WARN))
        if preflight["ok"]:
            submit.disabled = False
        else:
            for err in preflight["errors"]:
                table.add_row("preflight error", Text(err, style=palette.FAIL))

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
        self._upload_kind = "evidence"
        self._begin_log(Text("uploading to Paramify...", style=palette.WARN))
        self._upload_worker(run_dir, self.app.root_path)

    @work(thread=True, exclusive=True)
    def _upload_worker(self, run_dir: str, root) -> None:
        try:
            api.upload_run(run_dir, root, on_event=lambda ev: self.post_message(UploadEvent(ev)))
        except Exception as exc:
            self.post_message(UploadEvent({"event": "_upload_failed", "error": str(exc)}))

    # -- actions: issue-report intake ------------------------------------- #

    @on(Button.Pressed, "#issues-submit")
    def _on_intake(self) -> None:
        self.action_intake_issues()

    def action_intake_issues(self) -> None:
        if self._busy:
            self.notify("A Paramify operation is already in progress.")
            return
        pf = self._issues_preflight
        run_dir = self._issues_run_dir
        if not run_dir or not pf or not pf.get("ok"):
            self.notify("No issue reports ready to send.")
            return

        def go(ok: bool) -> None:
            if ok:
                self._start_intake(run_dir)

        closing = [
            p for p in pf.get("assessments") or [] if p.get("operation") == "PROCESS_CLOSE"
        ]
        question = (
            f"Send {pf['file_count']} issue report(s) into their Paramify "
            f"pipelines at {pf['base_url']} and process them?"
        )
        if closing:
            question += (
                f"\n\nThis also closes the cycle on {len(closing)} assessment(s). "
                "Open issues not in these files will be auto-closed as resolved."
            )
        self.app.push_screen(ConfirmModal(question), go)

    def _start_intake(self, run_dir: str) -> None:
        self._uploading = True
        self._upload_kind = "issue report"
        self._begin_log(Text("sending issue reports...", style=palette.WARN))
        self._issues_worker(run_dir, self.app.root_path)

    @work(thread=True, exclusive=True)
    def _issues_worker(self, run_dir: str, root) -> None:
        try:
            api.issues_upload_run(
                run_dir, root, on_event=lambda ev: self.post_message(UploadEvent(ev))
            )
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
            self.notify("A Paramify operation is already in progress.")
            return
        pf = self._scripts_preflight
        if not pf or pf.get("fetcher_count", 0) == 0:
            self.notify("No fetcher scripts to plan.")
            return
        self._start_scripts(dry_run=True)

    def action_sync_scripts(self) -> None:
        if self._busy:
            self.notify("A Paramify operation is already in progress.")
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
        if etype == "upload_start":
            mode = " (dry-run)" if ev.get("dry_run") else ""
            self._set_banner(Text(f"uploading {ev.get('files', 0)} {noun}(s) to {ev.get('base_url', '')}{mode}", style=palette.WARN))
            log.write(Text(f"upload {ev.get('files', 0)} {noun}(s) from {ev.get('run_dir', '')}{mode}", style="bold"))
        elif etype == "upload_file":
            outcome = ev.get("outcome")
            if outcome == "uploaded":
                icon, style = "OK", palette.OK
            elif outcome in ("skipped_duplicate", "skipped_failed", "would_upload"):
                icon, style = "SKIP", palette.WARN
            else:
                icon, style = "FAIL", palette.FAIL
            if ev.get("reference_id"):
                ref = f"  set={ev.get('reference_id')}"
            elif ev.get("assessment_id"):
                ref = f"  assessment={ev.get('assessment_id')}"
            else:
                ref = ""
            if ev.get("channel"):
                ref += f"  channel={ev.get('channel')}"
            reason = ev.get("reason") or ev.get("error")
            suffix = f"  {reason}" if reason else ""
            log.write(Text(f"  [{icon}] {ev.get('file', '?')}  {outcome}{ref}{suffix}", style=style))
        elif etype == "process_plan" and ev.get("operation"):
            log.write(Text(
                f"  [DRY] would {ev['operation']} {ev.get('artifacts', 0)} artifact(s)"
                f"  assessment={ev.get('assessment_id')}", style=palette.WARN,
            ))
        elif etype == "job_queued":
            why = f"  {ev['close_skipped']}" if ev.get("close_skipped") else ""
            self._set_banner(Text(
                f"processing on {ev.get('assessment_id')} — job {ev.get('job_id')} queued",
                style=palette.WARN,
            ))
            log.write(Text(
                f"  [OK] queued {ev.get('operation')} job {ev.get('job_id')}"
                f"  assessment={ev.get('assessment_id')}{why}", style=palette.OK,
            ))
            if ev.get("newer_cycles"):
                log.write(Text(
                    f"  [WARN] landed on cycle {ev.get('cycle_name')!r}, the oldest open "
                    f"cycle; {ev['newer_cycles']} newer cycle(s) show nothing until it is "
                    f"closed", style=palette.WARN,
                ))
        elif etype == "job_status":
            self._set_banner(Text(
                f"job {ev.get('job_id')} {ev.get('status')} on {ev.get('assessment_id')}",
                style=palette.WARN,
            ))
        elif etype == "job_complete":
            log.write(_job_text(ev))
        elif etype == "process_skipped":
            log.write(Text(
                f"  [SKIP] nothing new to process  assessment={ev.get('assessment_id')}"
                f"  {ev.get('reason', '')}", style=palette.WARN,
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
            + (f" jobs_failed={ev['jobs_failed']}" if ev.get("jobs_failed") else ""),
            style=style,
        )
        if ev.get("halted"):
            msg.append(f"   stopped early: {ev['halted']}", style=palette.FAIL)
        if ev.get("log_path"):
            msg.append(f"   {ev['log_path']}", style="dim")
        self._set_banner(msg)

    # -- pipeline jobs and cycle close ----------------------------------- #

    def action_pipeline_jobs(self) -> None:
        """List recent pipeline jobs; enter on one offers retry or cancel."""
        self.notify("Loading pipeline jobs…")
        self._jobs_worker(self.app.root_path)

    @work(thread=True, exclusive=True, group="pipeline")
    def _jobs_worker(self, root) -> None:
        try:
            jobs = api.issues_jobs(root, limit=30)
        except Exception as exc:
            self.post_message(PipelineEvent({"event": "failed", "what": "list jobs",
                                             "error": str(exc)}))
            return
        self.post_message(PipelineEvent({"event": "jobs", "jobs": jobs}))

    def _show_jobs(self, jobs: list) -> None:
        if not jobs:
            self.notify("No pipeline jobs visible to this API key.")
            return
        by_id = {j["job_id"]: j for j in jobs}
        # The API names an assessment only by id; the manifest knows the names
        # of the ones it feeds, which are the ones worth recognising here.
        names = dict(self._manifest_assessments())
        options = []
        for j in jobs:
            counts = j.get("counts") or {}
            done = ", ".join(
                f"{counts[k]} {label}" for k, label in _COUNT_LABELS if counts.get(k) is not None
            )
            aid = j.get("assessment_id") or ""
            detail = done
            if j.get("blocked_by"):
                detail = f"blocked by {j['blocked_by']}"
            elif j.get("error"):
                error = str(j["error"])
                detail = error if len(error) <= 70 else error[:69] + "…"
            options.append((j["job_id"], (
                f"{(j.get('created_at') or '')[:16]}  {j.get('status') or '?':<11} "
                f"{j.get('type') or '?':<13} {names.get(aid, aid)}"
                f"{chr(10) + '    ' + detail if detail else ''}"
            )))

        def chosen(job_id):
            if job_id is not None:
                self._offer_job_actions(by_id[job_id])

        self.app.push_screen(
            PickerModal("Pipeline jobs", options,
                        subtitle="newest first — enter on a failed or queued job to retry or cancel it"),
            chosen,
        )

    def _offer_job_actions(self, job: dict) -> None:
        status = job.get("status")
        actions = []
        if status == "FAILED":
            actions.append(("retry", "retry — run it again; the jobs behind it follow"))
        if status in ("FAILED", "QUEUED"):
            actions.append((
                "cancel", "cancel — also cancels every unfinished job queued behind it",
            ))
        if not actions:
            self.app.push_screen(ConfirmModal(
                f"Job {job['job_id']} is {status}; there is nothing to retry or cancel.\n\n"
                f"{_job_text(job).plain.strip()}"
            ))
            return

        def picked(action):
            if action is None:
                return

            def go(ok: bool) -> None:
                if ok:
                    self._job_action_worker(self.app.root_path, job["job_id"], action)

            self.app.push_screen(
                ConfirmModal(f"{action.capitalize()} pipeline job {job['job_id']}?"), go
            )

        self.app.push_screen(
            PickerModal(f"Job {job['job_id']} — {status}", actions), picked
        )

    @work(thread=True, exclusive=True, group="pipeline")
    def _job_action_worker(self, root, job_id: str, action: str) -> None:
        try:
            job = api.issues_job_action(root, job_id, action)
        except Exception as exc:
            self.post_message(PipelineEvent({"event": "failed", "what": f"{action} {job_id}",
                                             "error": str(exc)}))
            return
        self.post_message(PipelineEvent({"event": "job_done", "action": action, "job": job}))

    def _manifest_assessments(self) -> list:
        """(id, label) for every assessment the active manifest's issue-report
        entries point at, entry config first, then platform config."""
        run = (getattr(self.app, "manifest", None) or {}).get("run") or {}
        seen: dict = {}
        for cfg in [e.get("config") or {} for e in run.get("fetchers") or []] + [
            (p or {}).get("config") or {} for p in (run.get("platforms") or {}).values()
        ]:
            aid = cfg.get("assessment_id")
            if aid and aid not in seen:
                seen[aid] = cfg.get("assessment_name") or aid
        return list(seen.items())

    def action_close_cycle(self) -> None:
        """Close the current cycle of one of the manifest's assessments."""
        if self._busy:
            self.notify("A Paramify operation is already in progress.")
            return
        choices = self._manifest_assessments()
        if not choices:
            self.notify("No issue-report entry in this manifest points at an assessment.")
            return

        def chosen(aid):
            if aid is None:
                return
            label = dict(choices)[aid]

            def go(ok: bool) -> None:
                if ok:
                    self._uploading = True
                    self._disable_actions()
                    self._upload_kind = "cycle close"
                    self._begin_log(Text(f"closing the current cycle of {label}...",
                                         style=palette.WARN))
                    self._close_worker(self.app.root_path, aid)

            self.app.push_screen(ConfirmModal(
                f"Close the current cycle of {label}?\n\n"
                "Every open issue the cycle never saw will be auto-closed as resolved, "
                "and the next upload opens a new cycle. This cannot be undone."
            ), go)

        self.app.push_screen(
            PickerModal("Close which assessment's cycle?", choices,
                        subtitle="for assessments filled by several runs (close_cycle: never)"),
            chosen,
        )

    @work(thread=True, exclusive=True, group="pipeline")
    def _close_worker(self, root, assessment_id: str) -> None:
        try:
            job = api.issues_close(root, assessment_id)
        except Exception as exc:
            self.post_message(PipelineEvent({"event": "failed", "what": "close",
                                             "error": str(exc), "busy": True}))
            return
        self.post_message(PipelineEvent({"event": "closed", "job": job}))

    def on_pipeline_event(self, message: PipelineEvent) -> None:
        ev = message.ev
        kind = ev.get("event")
        log = self.query_one("#upload-log", RichLog)
        if kind == "jobs":
            self._show_jobs(ev["jobs"])
        elif kind == "job_done":
            self.query_one("#upload-log-panel", Vertical).set_class(False, "empty")
            log.write(Text(f"{ev['action']}:", style="bold"))
            log.write(_job_text(ev["job"]))
            self.notify(f"{ev['action']}: job {ev['job'].get('job_id')} is now "
                        f"{ev['job'].get('status')}")
        elif kind == "closed":
            self._uploading = False
            self._restore_actions()
            job = ev["job"]
            log.write(_job_text(job))
            ok = job.get("status") == "COMPLETED"
            self._set_banner(Text(
                f"cycle close {job.get('status')}", style=palette.OK if ok else palette.FAIL,
            ))
        elif kind == "failed":
            self.query_one("#upload-log-panel", Vertical).set_class(False, "empty")
            if ev.get("busy"):
                self._uploading = False
                self._restore_actions()
            log.write(Text(f"{ev['what']} failed: {ev['error']}", style=f"bold {palette.FAIL}"))
            self.notify(f"{ev['what']} failed: {ev['error']}", severity="error", timeout=12)

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
        for bid in ("#upload-submit", "#issues-submit", "#scripts-preview", "#scripts-submit"):
            self.query_one(bid, Button).disabled = True

    def _restore_actions(self) -> None:
        self.query_one("#upload-submit", Button).disabled = not (self._preflight and self._preflight.get("ok"))
        self.query_one("#issues-submit", Button).disabled = not (
            self._issues_preflight and self._issues_preflight.get("ok")
        )
        has_fetchers = bool(self._scripts_preflight and self._scripts_preflight.get("fetcher_count", 0) > 0)
        self.query_one("#scripts-preview", Button).disabled = not has_fetchers
        self.query_one("#scripts-submit", Button).disabled = not has_fetchers
        # After a refresh, so the modal that started the operation has handed
        # focus back (to a button that is disabled now) before we look.
        self.call_after_refresh(self._refocus_if_lost)

    def _set_banner(self, renderable) -> None:
        self.query_one("#upload-banner", Static).update(renderable)
