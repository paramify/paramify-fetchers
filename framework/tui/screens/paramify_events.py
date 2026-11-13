"""What the Paramify-facing pages share: the worker messages, how an upload or
pipeline event reads as a log line, and which run a page acts on.

The Paramify page (evidence upload, scripts) and the Pipelines page (scan
reports) both stream ``api.upload_run``-shaped events, so the log line for each
event lives here once.
"""

from __future__ import annotations

from rich.text import Text
from textual.message import Message

from framework import api
from framework.tui import palette


class UploadEvent(Message):
    """Carries one api.upload_run() / issues_upload_run() event dict from a worker thread."""

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


COUNT_LABELS = (
    ("issuesCreated", "created"),
    ("issuesUpdated", "updated"),
    ("issuesSeenClosed", "seen-closed"),
    ("issuesAutoClosed", "auto-closed"),
)


def job_text(job: dict) -> Text:
    """One finished pipeline job as a log line: what it did, or why it stopped."""
    status = job.get("status") or "?"
    counts = job.get("counts") or {}
    shown = [f"{counts[k]} {label}" for k, label in COUNT_LABELS if counts.get(k) is not None]
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


def upload_event_lines(ev: dict, noun: str) -> list[Text]:
    """The log lines one upload event writes; [] for events that only move state."""
    etype = ev.get("event")
    if etype == "upload_start":
        mode = " (dry-run)" if ev.get("dry_run") else ""
        return [Text(f"upload {ev.get('files', 0)} {noun}(s) from {ev.get('run_dir', '')}{mode}", style="bold")]
    if etype == "delivery_file":
        n = ev.get("n")
        progress = f"{n}/{ev.get('of')} " if n is not None else ""
        outcome = ev.get("outcome")
        style = palette.OK if outcome == "uploaded" else palette.WARN
        reason = f"  {ev['reason']}" if ev.get("reason") else ""
        return [Text(f"  {progress}{ev.get('file', '?')} {outcome}{reason}", style=style)]
    if etype == "upload_file":
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
        return [Text(f"  [{icon}] {ev.get('file', '?')}  {outcome}{ref}{suffix}", style=style)]
    if etype == "process_plan" and ev.get("operation"):
        return [Text(
            f"  [DRY] would {ev['operation']} {ev.get('artifacts', 0)} artifact(s)"
            f"  assessment={ev.get('assessment_id')}", style=palette.WARN,
        )]
    if etype == "job_queued":
        why = f"  {ev['close_skipped']}" if ev.get("close_skipped") else ""
        lines = [Text(
            f"  [OK] queued {ev.get('operation')} job {ev.get('job_id')}"
            f"  assessment={ev.get('assessment_id')}{why}", style=palette.OK,
        )]
        if ev.get("newer_cycles"):
            lines.append(Text(
                f"  [WARN] landed on cycle {ev.get('cycle_name')!r}, the oldest open "
                f"cycle; {ev['newer_cycles']} newer cycle(s) show nothing until it is "
                f"closed", style=palette.WARN,
            ))
        return lines
    if etype == "job_complete":
        return [job_text(ev)]
    if etype == "process_skipped":
        return [Text(
            f"  [SKIP] nothing new to process  assessment={ev.get('assessment_id')}"
            f"  {ev.get('reason', '')}", style=palette.WARN,
        )]
    return []


def output_dir(app) -> str:
    """The active manifest's output dir, as the run tab and the uploaders read it."""
    run = (getattr(app, "manifest", None) or {}).get("run") or {}
    return run.get("output_dir") or "./evidence"


def latest_run_scoped(app, kind: str) -> tuple[dict | None, bool]:
    """The newest run holding this kind, and whether it came from the active
    manifest's own runs.

    Evidence and pipeline manifests usually share an output dir, so each page
    looks for its own kind rather than taking the newest run. Scoped to the
    active manifest's runs once it has any, so a pipeline manifest's evidence
    page does not offer another manifest's evidence; runs from before run
    attribution existed are the fallback.
    """
    out = output_dir(app)
    path = getattr(app, "manifest_path", None)
    if path is not None:
        root = app.root_path
        if api.latest_run(out, manifest_path=path, root=root) is not None:
            return api.latest_run(out, kind=kind, manifest_path=path, root=root), True
    return api.latest_run(out, kind=kind), False
