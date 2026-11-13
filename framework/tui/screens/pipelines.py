"""Pipelines page — scan reports into their assessments' Paramify pipelines.

Moved off the Paramify page, which is about evidence sets: a scan report goes to
a different endpoint (an assessment's intake), and its jobs and cycles have
nothing to do with an evidence set.

  * The manifest's scan-report fetchers, each with the assessment it feeds and
    its close-cycle policy.
  * Send (`i`) — post the newest scan run's reports to their assessments.
  * Jobs (`j`) — list recent pipeline jobs; retry or cancel one.
  * Close cycle (`C`) — close an assessment's current cycle by hand.
"""

from __future__ import annotations

from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, RichLog, Static, TabbedContent

from framework import api
from framework.tui import palette
from framework.tui.components.keys import BUTTON_ROW_BINDINGS, ButtonRowNav
from framework.tui.components.table import DataTable
from framework.tui.modals import ConfirmModal, PickerModal
from framework.tui.screens.paramify_events import (
    COUNT_LABELS,
    PipelineEvent,
    UploadEvent,
    job_text,
    latest_run_scoped,
    upload_event_lines,
)


class PipelinesPage(ButtonRowNav, Vertical):
    HINTS = [("i", "send reports"), ("j", "jobs"), ("C", "close cycle"), ("ctrl+r", "refresh")]

    BINDINGS = [
        # Not ctrl+i: most terminals send the same byte for ctrl+i and Tab, so
        # the binding never fired. This page has no Input to eat a bare letter.
        Binding("i", "intake_issues", "Send reports"),
        Binding("j", "pipeline_jobs", "Jobs"),
        # Shifted on purpose: a close auto-closes every open issue the cycle
        # never saw, and cannot be undone.
        Binding("C", "close_cycle", "Close cycle"),
        Binding("ctrl+r", "refresh_pipelines", "Refresh"),
        *BUTTON_ROW_BINDINGS,
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="pipelines-fetchers-panel", classes="panel"):
            yield DataTable(id="pipelines-fetchers")
        with Vertical(id="issues-panel", classes="panel"):
            yield DataTable(id="issues-summary")
            yield Static("", id="issues-notes", classes="panel-notes")
            with Horizontal(id="issues-actions"):
                yield Button("Send to Pipeline", variant="primary", id="issues-submit", disabled=True)
        with Vertical(id="pipelines-log-panel", classes="panel"):
            yield RichLog(id="pipelines-log", markup=False, wrap=True, highlight=False)
            yield Static("Sends, jobs and cycle closes show here.", classes="empty-hint")
        yield Static("", id="pipelines-banner")

    def on_mount(self) -> None:
        self._uploading = False
        self._issues_run_dir: str | None = None
        self._issues_preflight: dict | None = None
        # What the log and banner are reporting on: a send or a cycle close.
        self._upload_kind = "scan report"

        self.query_one("#issues-panel", Vertical).border_title = "send"
        log_panel = self.query_one("#pipelines-log-panel", Vertical)
        log_panel.border_title = "log"
        log_panel.set_class(True, "empty")

        fetchers = self.query_one("#pipelines-fetchers", DataTable)
        fetchers.cursor_type = "row"
        fetchers.add_columns("fetcher", "assessment", "close cycle")

        issues = self.query_one("#issues-summary", DataTable)
        issues.cursor_type = "row"
        issues.zebra_stripes = True
        issues.add_columns("field", "value")

        self.rebuild()

    def focus_default(self) -> None:
        """Focus Send when it can run, else the summary table.

        Something inside the page must hold focus or none of its keys fire.
        """
        self.rebuild()
        self._focus_first_action()

    def _focus_first_action(self) -> None:
        button = self.query_one("#issues-submit", Button)
        if not button.disabled:
            button.focus()
            return
        self.query_one("#issues-summary", DataTable).focus()

    def _refocus_if_lost(self) -> None:
        """Put focus back in this page after an operation, if it fell out.

        Starting a send disables the button that held focus, so focus drops to
        the tab strip, where `i`, `j` and `C` do nothing. Left alone when the
        user has meanwhile moved to another tab or a modal is open, or when
        focus is still somewhere usable in the page.
        """
        if self.screen is not self.app.screen:
            return  # a modal is on top
        if self.screen.query_one(TabbedContent).active != "tab-pipelines":
            return  # the user went elsewhere; don't pull them back
        focused = self.app.focused
        if focused is not None and not focused.disabled and focused in self.walk_children():
            return
        self._focus_first_action()

    @property
    def _busy(self) -> bool:
        return self._uploading

    # -- data ------------------------------------------------------------- #

    def rebuild(self) -> None:
        """Refresh the fetcher list and the send readiness (cheap; no network)."""
        if self._busy:
            return
        self._rebuild_fetchers()
        self._rebuild_issues()

    def _rebuild_fetchers(self) -> None:
        """The manifest's scan-report fetchers, with what each one feeds."""
        table = self.query_one("#pipelines-fetchers", DataTable)
        table.clear()
        manifest = getattr(self.app, "manifest", None) or {}
        kinds = {
            f["name"]: f.get("kind")
            for c in api.catalog(self.app.root_path)["categories"] for f in c["fetchers"]
        }
        count = 0
        for entry in (manifest.get("run") or {}).get("fetchers") or []:
            use = entry.get("use")
            if kinds.get(use) != "issue_report":
                continue
            config = entry.get("config") or {}
            table.add_row(
                use,
                config.get("assessment_name") or config.get("assessment_id") or Text("—", style="dim"),
                config.get("close_cycle") or "never",
            )
            count += 1
        self.query_one("#pipelines-fetchers-panel", Vertical).border_title = f"scan-report fetchers ({count})"

    def _rebuild_issues(self) -> None:
        """Send readiness for the newest run that collected scan reports.

        Its own run, not the evidence run: a pipeline manifest's scan run and
        an evidence manifest's run usually sit side by side. With none, the panel
        says so and the button stays disabled — not an error. Preflight is only
        consulted when there is something to send.
        """
        self._issues_preflight = None
        self._issues_run_dir = None
        table = self.query_one("#issues-summary", DataTable)
        table.clear()
        self._notes([])
        submit = self.query_one("#issues-submit", Button)
        submit.disabled = True

        try:
            latest, _ = latest_run_scoped(self.app, "issue_report")
        except Exception as exc:
            self._notes([("status", f"cannot list runs: {exc}", palette.FAIL)])
            return
        if latest is None:
            table.add_row("status", Text("no run collected scan reports", style="dim"))
            return

        self._issues_run_dir = latest["dir"]
        table.add_row("selected run", latest["run_id"])
        table.add_row("reports", str(latest.get("issue_reports", 0)))
        try:
            preflight = api.issues_upload_preflight(self._issues_run_dir, self.app.root_path)
        except Exception as exc:
            self._notes([("preflight", str(exc), palette.FAIL)])
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
        notes = [("warning", warning, palette.WARN) for warning in preflight.get("warnings") or []]
        if preflight["ok"]:
            submit.disabled = False
        else:
            notes += [("preflight error", err, palette.FAIL) for err in preflight["errors"]]
        self._notes(notes)

    def _notes(self, notes: list) -> None:
        """Show (label, message, style) lines under the send table, or hide them.
        Prose goes here, not in a row: a DataTable cell never wraps."""
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", no_wrap=True)
        grid.add_column()
        for label, message, style in notes:
            grid.add_row(label, Text(message, style=style))
        static = self.query_one("#issues-notes", Static)
        static.update(grid)
        static.display = bool(notes)

    def action_refresh_pipelines(self) -> None:
        self.rebuild()
        self.notify("Pipelines page refreshed.")

    # -- send ------------------------------------------------------------- #

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
            self.notify("No scan reports ready to send.")
            return

        def go(ok: bool) -> None:
            if ok:
                self._start_intake(run_dir)

        closing = [
            p for p in pf.get("assessments") or [] if p.get("operation") == "PROCESS_CLOSE"
        ]
        question = (
            f"Send {pf['file_count']} scan report(s) into their assessments' "
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
        self._upload_kind = "scan report"
        self._begin_log(Text("sending scan reports...", style=palette.WARN))
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
        self.query_one("#pipelines-log-panel", Vertical).set_class(False, "empty")
        self.query_one("#pipelines-log", RichLog).clear()
        self._set_banner(banner)

    def on_upload_event(self, message: UploadEvent) -> None:
        self._handle_upload_event(message.ev)

    def _handle_upload_event(self, ev: dict) -> None:
        etype = ev.get("event")
        log = self.query_one("#pipelines-log", RichLog)
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
        # A send changes what the panel should say (those reports are now
        # duplicates), so re-read readiness rather than only re-enabling buttons.
        self.rebuild()
        self._restore_actions()
        ok = ev.get("ok")
        msg = Text(
            f"{self._upload_kind} upload complete — "
            f"uploaded={ev.get('uploaded', 0)} "
            f"duplicates={ev.get('skipped_duplicate', 0)} "
            f"errors={ev.get('errors', 0)}"
            + (f" jobs_failed={ev['jobs_failed']}" if ev.get("jobs_failed") else ""),
            style=palette.OK if ok else palette.FAIL,
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
                f"{counts[k]} {label}" for k, label in COUNT_LABELS if counts.get(k) is not None
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
                f"{job_text(job).plain.strip()}"
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
            self.notify("No scan report in this manifest points at an assessment.")
            return

        def chosen(aid):
            if aid is None:
                return
            label = dict(choices)[aid]

            def go(ok: bool) -> None:
                if ok:
                    self._uploading = True
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
        log = self.query_one("#pipelines-log", RichLog)
        if kind == "jobs":
            self._show_jobs(ev["jobs"])
        elif kind == "job_done":
            self.query_one("#pipelines-log-panel", Vertical).set_class(False, "empty")
            log.write(Text(f"{ev['action']}:", style="bold"))
            log.write(job_text(ev["job"]))
            self.notify(f"{ev['action']}: job {ev['job'].get('job_id')} is now "
                        f"{ev['job'].get('status')}")
        elif kind == "closed":
            self._uploading = False
            self._restore_actions()
            job = ev["job"]
            log.write(job_text(job))
            ok = job.get("status") == "COMPLETED"
            self._set_banner(Text(
                f"cycle close {job.get('status')}", style=palette.OK if ok else palette.FAIL,
            ))
        elif kind == "failed":
            self.query_one("#pipelines-log-panel", Vertical).set_class(False, "empty")
            if ev.get("busy"):
                self._uploading = False
                self._restore_actions()
            log.write(Text(f"{ev['what']} failed: {ev['error']}", style=f"bold {palette.FAIL}"))
            self.notify(f"{ev['what']} failed: {ev['error']}", severity="error", timeout=12)

    # -- button state ----------------------------------------------------- #

    def _disable_actions(self) -> None:
        self.query_one("#issues-submit", Button).disabled = True

    def _restore_actions(self) -> None:
        self.query_one("#issues-submit", Button).disabled = not (
            self._issues_preflight and self._issues_preflight.get("ok")
        )
        # After a refresh, so the modal that started the operation has handed
        # focus back (to a button that is disabled now) before we look.
        self.call_after_refresh(self._refocus_if_lost)

    def _set_banner(self, renderable) -> None:
        self.query_one("#pipelines-banner", Static).update(renderable)
