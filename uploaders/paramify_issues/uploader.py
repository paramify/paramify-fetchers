#!/usr/bin/env python3
"""Upload raw issue reports from a run directory into Paramify pipelines.

The sibling of [`paramify_evidence`](../paramify_evidence/uploader.py), for the
other collection kind. Where that uploader attaches an envelope-wrapped JSON file
to an evidence set, this one sends a scan report — the vendor's own CSV, XML, JSON
or Nessus file — into the assessment's pipeline, where Paramify's file intake
preset parses it into issues. A pipeline is identified by its assessment id.

Reads `<run>/issue-reports/_issue_reports.json` (written by the runner; see
framework/issue_reports.py). Like the evidence uploader it reads nothing from
fetcher source and needs only a run directory plus a token, so it can be pointed
at an old run to re-upload.

The unit of work is one assessment per run, not one file:

1. **Upload bare.** `POST /pipelines/{id}/intake` per report, with no operation
   and no cycle. The pipeline puts it on its current cycle — the oldest one still
   open — and returns the artifact id.
2. **Process once.** `POST /pipelines/{id}/process` naming exactly the artifact
   ids this run uploaded. Never the bare form: that sweeps every unprocessed file
   on the cycle, including ones someone else put there. `operation` on an intake
   sweeps the same way, which is why uploads carry none.
3. **Close only when allowed.** Closing auto-closes every open issue the cycle
   never saw, so a close after a partial run marks real issues resolved. The
   process call is `PROCESS_CLOSE` only when the assessment's `close_cycle` is
   `after_run` AND every target bound to it in this run succeeded and uploaded.
   Otherwise it is `PROCESS`, and the summary says why the close was skipped.
4. **Wait.** Poll the job until it completes, fails, or is blocked behind a
   failed job, and report its counts. A job that did not complete fails the run.

Two behaviors are forced by the endpoint, as before:

- **Files are sent byte-for-byte.** The preset parses the vendor's own structure,
  so the bytes on disk are the bytes posted. Identity travels in the `artifact`
  metadata part and the sidecar instead.
- **Dedup is local.** Intake adds an artifact every time and there is no way to
  list what a cycle already holds, so this uploader records what it sent — and
  the job it queued for it — in `<run>/issue-reports/_intake_log.json`, and a
  second run skips both. The log is the only thing making a re-run safe: delete
  it and a re-run WILL upload and process the reports again.

Auth: PARAMIFY_UPLOAD_API_TOKEN (source-agnostic env — .env, secret manager, CI).
The key needs PIPELINE_INTAKE, PIPELINE_PROCESS, and PIPELINE_CLOSE to close.

Endpoint contract per Paramify REST API v0 spec 0.10.0 (https://app.paramify.com/api/documentation/).
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

import requests
import yaml
from dotenv import load_dotenv

# Runnable directly (`python uploaders/paramify_issues/uploader.py`) from any cwd,
# where only its own directory lands on sys.path. Its position in the repo is
# fixed, so derive the root rather than duplicating the token-resolution rule.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from framework.issue_reports import (  # noqa: E402
    CLOSE_AFTER_RUN,
    CLOSE_CYCLE_FIELD,
    CLOSE_CYCLE_VALUES,
    INTAKE_LOG_NAME,
    ISSUE_REPORTS_DIR,
    SIDECAR_NAME,
)
from framework.paramify_auth import (  # noqa: E402
    READ_TOKEN_ENV,
    UPLOAD_TOKEN_ENV,
    resolve_base_url,
    resolve_upload_token,
)

logger = logging.getLogger("paramify_issues_uploader")

# Generous next to the evidence uploader's 30s: the endpoint accepts files up to
# 10 GB, and a full Nessus export is routinely hundreds of megabytes.
_REQUEST_TIMEOUT = 600

# requests buffers the entire multipart body in memory — RequestEncodingMixin
# ._encode_files calls .read() on file objects and hands the result to
# encode_multipart_formdata — so peak RSS is roughly twice the report and passing
# a file handle instead of bytes changes nothing. The endpoint accepts 10 GB; we
# refuse well below that so an oversized export is one clear message rather than
# an OOM kill partway through a batch.
#
# Lifting this means streaming the body: requests_toolbelt.MultipartEncoder (a new
# entry in pyproject.toml — it is not currently a declared dependency), or a
# hand-rolled generator body with an explicit multipart boundary.
_MAX_REPORT_BYTES = 512 * 1024 * 1024

# Content types the intake endpoint accepts, keyed by the fetcher's declared
# `output.type`. A report whose format is not here cannot be intaken at all, which
# the fetcher schema already refuses — this is the second line of that fence.
_CONTENT_TYPES = {
    "csv": "text/csv",
    "json": "application/json",
    "xml": "application/xml",
    # Nessus files are XML. Paramify keys the parser off the file extension, so
    # the generic XML type is correct and the .nessus name carries the meaning.
    "nessus": "application/xml",
}

PROCESS = "PROCESS"
PROCESS_CLOSE = "PROCESS_CLOSE"

# Job polling. Processing a large scan takes minutes, so start quick and back off.
DEFAULT_WAIT_TIMEOUT = 900
_POLL_FIRST = 5.0
_POLL_MAX = 30.0
_POLL_BACKOFF = 1.5
# Consecutive failed polls tolerated before giving up on a job. A poll is a GET,
# so retrying it is safe — unlike an intake, which adds an artifact every time.
_POLL_RETRIES = 3

JOB_COMPLETED = "COMPLETED"
JOB_FAILED = "FAILED"
JOB_CANCELLED = "CANCELLED"
JOB_QUEUED = "QUEUED"
_TERMINAL = frozenset({JOB_COMPLETED, JOB_FAILED, JOB_CANCELLED})

# Indirection so tests can drive the poll loop without real time passing.
_sleep = time.sleep
_monotonic = time.monotonic


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Paramify API client
# --------------------------------------------------------------------------- #
class ParamifyError(RuntimeError):
    pass


class IntakeNotEnabled(ParamifyError):
    """HTTP 501 — pipeline intake is not enabled for this workspace.

    Its own type because it is not a per-file problem: every subsequent upload in
    the batch will fail the same way, so the run stops instead of issuing one
    identical error per report.
    """


class AccessDenied(ParamifyError):
    """HTTP 401/403 — the key is missing a pipeline permission. Stops the batch:
    every later call with the same key fails the same way."""


class AssessmentRefused(ParamifyError):
    """HTTP 400/404 on an assessment — no preset, wrong id. Stops that assessment:
    its other reports would be refused identically, but other assessments may be
    fine."""


class NoCycleInProgress(ParamifyError):
    """HTTP 409 — the pipeline has no cycle in progress (the last one was closed
    and nothing has been uploaded since)."""


class ParamifyClient:
    """Thin client over the Paramify REST API v0 pipeline endpoints."""

    def __init__(self, token: str, base_url: str, timeout: int = _REQUEST_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def intake(
        self, assessment_id: str, filename: str, content: bytes, content_type: str,
        artifact_meta: Dict,
    ) -> Dict:
        """Upload one report to the pipeline's current cycle. Returns the artifact.

        Sent with no `operation`: processing is one explicit call per run, so it
        covers exactly this run's files (see the module docstring).
        """
        files = {
            # The spec asks for a URL-encoded filename ("certain special
            # characters may cause upload errors"); Paramify decodes it. safe=""
            # so a slash in a vendor-generated name cannot escape the field.
            "file": (quote(filename, safe=""), content, content_type),
            "artifact": ("artifact.json", json.dumps(artifact_meta), "application/json"),
        }
        r = self.session.post(
            f"{self.base_url}/pipelines/{assessment_id}/intake",
            files=files,
            timeout=self.timeout,
        )
        _raise_for(r, f"intake of {filename}", assessment_id, (200, 201, 202))
        body = _json(r)
        artifact = body.get("artifact") if isinstance(body, dict) else None
        return artifact if isinstance(artifact, dict) else {}

    def process(self, assessment_id: str, artifact_ids: List[str], operation: str) -> Dict:
        """Queue one job over exactly these artifacts. Returns the job."""
        r = self.session.post(
            f"{self.base_url}/pipelines/{assessment_id}/process",
            json={"artifactIds": list(artifact_ids), "operation": operation},
            timeout=self.timeout,
        )
        _raise_for(r, "process", assessment_id, (200, 202))
        return _json(r)

    def close(self, assessment_id: str) -> Dict:
        """Queue a close of the pipeline's current cycle. Returns the job."""
        r = self.session.post(
            f"{self.base_url}/pipelines/{assessment_id}/close", timeout=self.timeout
        )
        _raise_for(r, "close", assessment_id, (200, 202))
        return _json(r)

    def get_job(self, job_id: str) -> Dict:
        r = self.session.get(f"{self.base_url}/pipeline-jobs/{job_id}", timeout=self.timeout)
        _raise_for(r, f"read job {job_id}", None, (200,))
        return _json(r)

    def list_jobs(
        self, assessment_id: Optional[str] = None, status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict]:
        params: Dict[str, object] = {"limit": limit}
        if assessment_id:
            params["assessmentId"] = assessment_id
        if status:
            params["status"] = status
        r = self.session.get(
            f"{self.base_url}/pipeline-jobs", params=params, timeout=self.timeout
        )
        _raise_for(r, "list jobs", None, (200,))
        body = _json(r)
        jobs = body.get("pipelineJobs") if isinstance(body, dict) else None
        return jobs if isinstance(jobs, list) else []

    def retry_job(self, job_id: str) -> Dict:
        r = self.session.post(
            f"{self.base_url}/pipeline-jobs/{job_id}/retry", timeout=self.timeout
        )
        _raise_for(r, f"retry job {job_id}", None, (200, 202))
        return _json(r)

    def cancel_job(self, job_id: str) -> Dict:
        r = self.session.post(
            f"{self.base_url}/pipeline-jobs/{job_id}/cancel", timeout=self.timeout
        )
        _raise_for(r, f"cancel job {job_id}", None, (200, 202))
        return _json(r)


def _json(resp) -> Dict:
    try:
        body = resp.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _raise_for(resp, what: str, assessment_id: Optional[str], ok: Tuple[int, ...]) -> None:
    """Map a pipeline response to the error type that says how far it reaches."""
    code = resp.status_code
    if code in ok:
        return
    msg = _error_message(resp)
    if code == 501:
        raise IntakeNotEnabled(
            f"pipeline intake is not enabled for this workspace (HTTP 501): {msg}"
        )
    if code in (401, 403):
        raise AccessDenied(
            f"Paramify rejected the token for {what} (HTTP {code}). A pipeline key needs "
            f"PIPELINE_INTAKE, plus PIPELINE_PROCESS to process and PIPELINE_CLOSE to "
            f"close. {msg}"
        )
    if code == 404 and assessment_id:
        raise AssessmentRefused(
            f"assessment {assessment_id} not found (HTTP 404) — the id may belong to "
            f"another workspace, or the assessment was deleted. Re-pick it with "
            f"`paramify assessments select`. {msg}"
        )
    if code == 400 and assessment_id:
        raise AssessmentRefused(
            f"{what} refused for assessment {assessment_id} (HTTP 400). The usual cause "
            f"is an assessment with no file intake preset configured — set one up in "
            f"Paramify. {msg}"
        )
    if code == 409 and assessment_id:
        raise NoCycleInProgress(
            f"{what}: assessment {assessment_id} has no cycle in progress (HTTP 409). "
            f"{msg}"
        )
    raise ParamifyError(f"{what} failed (HTTP {code}): {msg}")


def _error_message(resp) -> str:
    """Pull Paramify's own error message out of a response, with the requestId.

    The requestId is the only thing that lets support find the failure, so it is
    always carried through to the operator rather than dropped for brevity.
    """
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:300]
    if not isinstance(body, dict):
        return str(body)[:300]
    error = body.get("error")
    msg = ""
    if isinstance(error, dict):
        msg = error.get("message") or ""
    msg = msg or body.get("statusMessage") or resp.text[:300]
    request_id = body.get("requestId")
    return f"{msg} (requestId={request_id})" if request_id else str(msg)


# --------------------------------------------------------------------------- #
# Jobs
# --------------------------------------------------------------------------- #
def job_summary(job: Dict) -> Dict:
    """The fields of a job worth recording and showing."""
    return {
        "job_id": job.get("id"),
        "type": job.get("type"),
        "status": job.get("status"),
        "counts": job.get("counts"),
        "error": job.get("error"),
        "blocked_by": job.get("blockedByJobId"),
        "cycle_id": job.get("cycleId"),
    }


def is_blocked(job: Dict) -> bool:
    return job.get("status") == JOB_QUEUED and bool(job.get("blockedByJobId"))


def wait_for_job(
    client: ParamifyClient,
    job_id: str,
    *,
    timeout: float = DEFAULT_WAIT_TIMEOUT,
    on_status: Optional[Callable[[Dict], None]] = None,
) -> Tuple[Dict, bool]:
    """Poll a job until it finishes, is blocked, or `timeout` passes.

    Returns (last job seen, timed_out). A job queued behind a failed one is
    returned at once rather than waited on: it cannot move until a person
    retries or cancels the blocker, and doing either automatically would be
    this uploader deciding what happens to someone else's job.
    """
    deadline = _monotonic() + timeout
    delay = _POLL_FIRST
    last_status = None
    misses = 0
    job: Dict = {"id": job_id}
    while True:
        try:
            job = client.get_job(job_id)
            misses = 0
        except (requests.RequestException, ParamifyError) as e:
            misses += 1
            if misses > _POLL_RETRIES:
                raise ParamifyError(f"could not read job {job_id}: {e}") from e
            logger.warning("reading job %s failed (%s); retrying", job_id, e)
        else:
            status = job.get("status")
            if status != last_status:
                last_status = status
                if on_status is not None:
                    on_status(job)
            if status in _TERMINAL or is_blocked(job):
                return job, False
        if _monotonic() + delay > deadline:
            return job, True
        _sleep(delay)
        delay = min(delay * _POLL_BACKOFF, _POLL_MAX)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def find_latest_run(output_dir: Path) -> Optional[Path]:
    """The newest run that collected issue reports — not simply the newest run,
    which is often an evidence manifest's sharing the same output dir."""
    if not output_dir.is_dir():
        return None
    runs = sorted((p for p in output_dir.glob("run-*") if p.is_dir()), reverse=True)
    return next((r for r in runs if (r / ISSUE_REPORTS_DIR / SIDECAR_NAME).is_file()), None)


def read_sidecar(run_dir: Path) -> Optional[dict]:
    """Read the run's issue-report index, or None when the run produced none."""
    path = Path(run_dir) / ISSUE_REPORTS_DIR / SIDECAR_NAME
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read {path}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("reports"), list):
        raise ValueError(f"{path} is not an issue-report index (no reports list)")
    return data


def _log_key(record: dict, assessment_id: str) -> str:
    """Dedup identity: this file, from this run, into this assessment.

    Deliberately the same shape as the evidence uploader's filename+run_id
    idempotency, so both uploaders answer "will re-running duplicate?" the same
    way. Keyed on the assessment too, so pointing a manifest at a second
    assessment and re-uploading correctly sends the report again.
    """
    return f"{assessment_id}|{record.get('run_id')}|{record.get('file')}"


def read_intake_log(run_dir: Path) -> Tuple[Dict[str, dict], Dict[str, List[dict]]]:
    """Read what this run already uploaded, and the jobs it already queued.

    Returns (uploaded, jobs): `uploaded` keyed by _log_key, `jobs` keyed by
    assessment id, oldest first.
    """
    path = Path(run_dir) / ISSUE_REPORTS_DIR / INTAKE_LOG_NAME
    if not path.exists():
        return {}, {}
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        # Fail loudly rather than silently re-uploading: a corrupt log that is
        # treated as empty duplicates every issue in the report.
        raise ValueError(
            f"cannot read {path} ({e}) — it records what was already intaken, and "
            f"ignoring it would duplicate. Inspect or delete it to proceed."
        ) from e
    if not isinstance(data, dict):
        return {}, {}
    uploaded = data.get("uploaded")
    jobs = data.get("jobs")
    return (
        uploaded if isinstance(uploaded, dict) else {},
        jobs if isinstance(jobs, dict) else {},
    )


def write_intake_log(
    run_dir: Path, uploaded: Dict[str, dict], jobs: Dict[str, List[dict]]
) -> Optional[Path]:
    path = Path(run_dir) / ISSUE_REPORTS_DIR / INTAKE_LOG_NAME
    body = {"updated_at": _utc_now(), "uploaded": uploaded, "jobs": jobs}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(body, indent=2))
    except OSError as e:
        logger.error(
            "could not write %s (%s) — a re-run will duplicate these uploads", path, e
        )
        return None
    return path


def build_artifact_meta(record: dict) -> Dict:
    """The `artifact` part: title, provenance note, and the effective date.

    `effectiveDate` is the collection time, not now: it is the date the scan
    describes. It does not choose a cycle — a pipeline always takes an upload
    onto its current cycle — so uploading an old run lands on whichever cycle is
    open, and the date is what still says when the scan was taken.
    """
    note_parts = [
        f"fetcher={record.get('fetcher_name')}",
        f"version={record.get('fetcher_version')}",
        f"run_id={record.get('run_id')}",
        f"status={record.get('status')}",
    ]
    if record.get("sha256"):
        note_parts.append(f"sha256={record['sha256']}")
    if record.get("target"):
        note_parts.append(f"target={json.dumps(record['target'], separators=(',', ':'))}")
    return {
        "title": record.get("title") or record.get("file"),
        "note": "; ".join(note_parts),
        "effectiveDate": record.get("collected_at") or _utc_now(),
    }


def load_config(path: Optional[str]) -> Dict:
    if not path:
        return {}
    data = yaml.safe_load(Path(path).read_text())
    return data or {}


def _emit(on_event: Optional[Callable[[dict], None]], event: dict) -> None:
    if on_event is not None:
        on_event(event)


def _base_url_error(base_url: str) -> Optional[str]:
    parsed = urlparse(base_url)
    if parsed.scheme != "https" and (parsed.hostname or "") not in ("localhost", "127.0.0.1", "::1"):
        return (
            "base_url must be https to protect the API token "
            f"(got {base_url!r}); only localhost may use http"
        )
    return None


# --------------------------------------------------------------------------- #
# Planning: which reports go to which assessment, and may its cycle close
# --------------------------------------------------------------------------- #
def _resolve(overrides: Dict, fetcher_name: Optional[str], item: dict, field: str):
    """An override from the uploader config wins over what the run recorded."""
    override = (overrides.get(fetcher_name) or {}) if fetcher_name else {}
    return override.get(field) or item.get(field)


def plan_assessments(index: dict, overrides: Optional[Dict] = None) -> Dict[str, dict]:
    """Group a run's reports by the assessment they go to.

    Returns {assessment_id: {"records", "invocations", "policies", "name"}},
    in the order assessments first appear. Reports with no assessment are
    grouped under "" so the caller can report them.

    `invocations` is None for a sidecar written before invocations were
    recorded: such a run cannot show that every target succeeded, so its cycle
    is never closed automatically.
    """
    overrides = overrides or {}
    groups: Dict[str, dict] = {}

    def group(aid: str) -> dict:
        return groups.setdefault(aid, {
            "records": [], "invocations": [] if "invocations" in index else None,
            "policies": set(), "name": None,
        })

    for record in index.get("reports") or []:
        fetcher = record.get("fetcher_name")
        aid = _resolve(overrides, fetcher, record, "assessment_id") or ""
        g = group(aid)
        g["records"].append(record)
        g["policies"].add(_resolve(overrides, fetcher, record, CLOSE_CYCLE_FIELD))
        g["name"] = g["name"] or record.get("assessment_name")
    for inv in index.get("invocations") or []:
        fetcher = inv.get("fetcher_name")
        aid = _resolve(overrides, fetcher, inv, "assessment_id") or ""
        g = group(aid)
        g["invocations"].append(inv)
        g["policies"].add(_resolve(overrides, fetcher, inv, CLOSE_CYCLE_FIELD))
    return groups


def close_decision(group: dict, files_ok: bool) -> Tuple[str, Optional[str]]:
    """(operation, why the close was skipped) for one assessment in one run.

    `files_ok`: every report bound to the assessment was uploaded (now or by an
    earlier attempt at this run) — none failed, none were skipped.
    """
    policies = group["policies"]
    if policies != {CLOSE_AFTER_RUN}:
        return PROCESS, None if policies == {"never"} else "close_cycle is not after_run for every fetcher"
    invocations = group["invocations"]
    if invocations is None:
        return PROCESS, (
            "close skipped: this run predates invocation tracking, so it cannot show "
            "every target succeeded — close it with `paramify issues close`"
        )
    if not invocations:
        # Reports with no invocation behind them (an override re-pointed them, or
        # the index was edited): nothing shows the run was complete.
        return PROCESS, "close skipped: no invocation record shows this run was complete"
    failed = [
        inv for inv in invocations if inv.get("status") != "success"
    ]
    if failed:
        names = sorted({
            f"{inv.get('fetcher_name')}{_target_label(inv.get('target'))}" for inv in failed
        })
        return PROCESS, f"close skipped: {len(failed)} target(s) failed ({', '.join(names)})"
    if not files_ok:
        return PROCESS, "close skipped: not every report for this assessment was uploaded"
    return PROCESS_CLOSE, None


def _target_label(target: Optional[dict]) -> str:
    if not target:
        return ""
    value = next((str(v) for v in target.values() if v), None)
    return f"[{value}]" if value else ""


def _processed_ids(jobs: List[dict]) -> set:
    """Artifacts already handed to a job this run queued, whatever became of it.

    A failed job is not re-queued here: `paramify issues jobs --retry` retries it
    in place, and queueing its artifacts again would process them twice once the
    retry succeeds.
    """
    return {aid for job in jobs for aid in job.get("artifact_ids") or []}


# --------------------------------------------------------------------------- #
# Upload
# --------------------------------------------------------------------------- #
def upload_run(
    run_dir: Path,
    *,
    config: Optional[Dict] = None,
    token: Optional[str] = None,
    base_url: Optional[str] = None,
    dry_run: bool = False,
    force: bool = False,
    wait: bool = True,
    wait_timeout: Optional[float] = None,
    on_event: Optional[Callable[[dict], None]] = None,
) -> Dict:
    """Send every issue report in one completed run into its assessment's pipeline.

    Returns a summary in the same shape as the evidence uploader's, so a
    front-end renders both with one code path, plus `assessments`: one entry per
    assessment with the operation sent and the job's outcome.

    `force` re-sends reports already listed in this run's `_intake_log.json`,
    and processes them again. Only use it when a previous intake was parsed
    incorrectly.
    """
    load_dotenv()
    config = config or {}
    paramify_cfg = config.get("paramify") or {}
    base_url, _ = resolve_base_url(paramify_cfg.get("base_url") or base_url)

    url_error = _base_url_error(base_url)
    if url_error:
        logger.error(url_error)
        raise ValueError(url_error)

    # Unlike the evidence uploader this defaults to True. A failed evidence fetch
    # still documents the attempt, but a truncated scan report is parsed into
    # issues: findings missing from a partial file read as resolved, silently
    # closing real vulnerabilities. Opt in per run if you know the file is whole.
    skip_failed = bool(config.get("skip_failed", True))
    overrides = config.get("overrides") or {}
    if wait_timeout is None:
        wait_timeout = float(config.get("wait_timeout_sec") or DEFAULT_WAIT_TIMEOUT)

    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        msg = f"No run directory to upload: {run_dir}"
        logger.error(msg)
        raise ValueError(msg)

    index = read_sidecar(run_dir)
    if index is None:
        msg = (
            f"{run_dir} has no {ISSUE_REPORTS_DIR}/{SIDECAR_NAME} — this run collected no "
            f"issue reports (a run of evidence fetchers only). Nothing to intake."
        )
        logger.error(msg)
        raise ValueError(msg)

    if not token:
        token, _ = resolve_upload_token()
    if not token and not dry_run:
        msg = f"{UPLOAD_TOKEN_ENV} is not set (or {READ_TOKEN_ENV} as a fallback)"
        logger.error(msg)
        raise ValueError(msg)

    records = index.get("reports") or []
    logger.info(
        "Intaking %d issue report(s) from %s%s",
        len(records), run_dir, " (dry-run)" if dry_run else "",
    )
    _emit(on_event, {
        "event": "upload_start",
        "run_dir": str(run_dir),
        "base_url": base_url,
        "dry_run": dry_run,
        "files": len(records),
    })

    client = None if dry_run else ParamifyClient(token, base_url)
    # Read the log in dry-run too. Skipping it made the preview promise to send
    # files the real run skips as duplicates — and predicting duplicates is the
    # main thing a preview is for. A corrupt log must still not crash a preview,
    # so that case degrades to "cannot predict duplicates" rather than propagating.
    try:
        already, jobs = read_intake_log(run_dir)
    except ValueError as e:
        if not dry_run:
            raise
        logger.warning("%s — this dry-run cannot predict duplicates", e)
        already, jobs = {}, {}

    results: List[Dict] = []
    assessments: List[Dict] = []
    uploaded = skipped_dup = skipped_failed = errors = jobs_failed = 0
    halted: Optional[str] = None

    def add_result(result: Dict) -> None:
        results.append(result)
        _emit(on_event, {"event": "upload_file", **result})

    def save_log() -> None:
        if not dry_run:
            write_intake_log(run_dir, already, jobs)

    for aid, group in plan_assessments(index, overrides).items():
        if halted:
            break
        group_records = group["records"]

        if not aid:
            for record in group_records:
                name = record.get("file") or "?"
                logger.error("%s: no assessment_id — collected but nowhere to send it", name)
                errors += 1
                add_result({
                    "file": name,
                    "outcome": "error",
                    "reason": (
                        f"no assessment_id for {record.get('fetcher_name')}; set one with "
                        f"`paramify assessments select {record.get('fetcher_name')}` and "
                        f"re-run, or pass an override in --config"
                    ),
                })
            continue

        entry: Dict = {
            "assessment_id": aid,
            "assessment_name": group["name"],
            "files": len(group_records),
            "uploaded": 0,
            "operation": None,
            "close_skipped": None,
            "job": None,
            "error": None,
        }
        assessments.append(entry)

        # The close policy is checked before anything is sent: once a report is
        # uploaded it sits on the cycle whether or not it is processed.
        bad = sorted({str(p) for p in group["policies"] if p not in CLOSE_CYCLE_VALUES})
        if bad:
            reason = (
                f"{CLOSE_CYCLE_FIELD} is {', '.join(bad)} for this assessment; set it to "
                f"after_run or never (`paramify assessments select --close-cycle`) and re-run"
            )
            logger.error("assessment %s: %s", aid, reason)
            entry["error"] = reason
            for record in group_records:
                errors += 1
                add_result({"file": record.get("file") or "?", "outcome": "error",
                            "assessment_id": aid, "reason": reason})
            continue

        files_ok = True
        would_send = 0
        stop_assessment: Optional[str] = None
        for record in group_records:
            name = record.get("file") or "?"
            if stop_assessment:
                files_ok = False
                errors += 1
                add_result({"file": name, "outcome": "error", "assessment_id": aid,
                            "reason": f"not sent: {stop_assessment}"})
                continue
            # Per-file isolation, same as the evidence uploader: one unreadable or
            # rejected report never aborts the batch.
            try:
                if record.get("status") == "failed" and skip_failed:
                    logger.info("%s: collection failed and skip_failed set; skipping", name)
                    skipped_failed += 1
                    files_ok = False
                    add_result({"file": name, "outcome": "skipped_failed",
                                "assessment_id": aid})
                    continue

                content_type = _CONTENT_TYPES.get(record.get("format") or "")
                if not content_type:
                    logger.error("%s: format %r cannot be intaken", name, record.get("format"))
                    errors += 1
                    files_ok = False
                    add_result({
                        "file": name,
                        "outcome": "error",
                        "reason": (
                            f"format {record.get('format')!r} is not one of "
                            f"{', '.join(sorted(_CONTENT_TYPES))}"
                        ),
                    })
                    continue

                path = run_dir / ISSUE_REPORTS_DIR / name
                if not path.is_file():
                    logger.error("%s: listed in the index but missing from disk", name)
                    errors += 1
                    files_ok = False
                    add_result({"file": name, "outcome": "error",
                                "reason": "listed in the index but not on disk"})
                    continue

                key = _log_key(record, aid)
                if key in already and not force:
                    logger.info("%s: already intaken into this assessment; skipping", name)
                    skipped_dup += 1
                    add_result({"file": name, "outcome": "skipped_duplicate",
                                "assessment_id": aid,
                                "artifact_id": already[key].get("artifact_id")})
                    continue

                meta = build_artifact_meta(record)
                if dry_run:
                    logger.info(
                        "would intake %s (%s, %s bytes) → assessment %s as %r",
                        name, record.get("format"), record.get("bytes"), aid, meta["title"],
                    )
                    would_send += 1
                    add_result({"file": name, "outcome": "would_upload",
                                "assessment_id": aid, "title": meta["title"]})
                    continue

                size = path.stat().st_size
                if size > _MAX_REPORT_BYTES:
                    logger.error("%s: %d bytes exceeds the in-memory intake limit", name, size)
                    errors += 1
                    files_ok = False
                    add_result({
                        "file": name,
                        "outcome": "error",
                        "reason": (
                            f"{size / 1048576:.0f} MB exceeds the "
                            f"{_MAX_REPORT_BYTES // 1048576} MB limit for a single report "
                            f"(the upload is buffered in memory; streaming intake is not "
                            f"implemented)"
                        ),
                    })
                    continue

                # Read as bytes and post unchanged — the whole point of an issue
                # report. Never json.load/dump a .json report here: re-serializing
                # would reorder keys and rewrite numbers, and the file is supposed
                # to be the vendor's own artifact.
                content = path.read_bytes()
                artifact = client.intake(aid, name, content, content_type, meta)
                artifact_id = artifact.get("id")
                uploaded += 1
                entry["uploaded"] += 1
                already[key] = {
                    "file": name,
                    "assessment_id": aid,
                    "artifact_id": artifact_id,
                    "sha256": record.get("sha256"),
                    "uploaded_at": _utc_now(),
                }
                # Written per file, not once at the end: a batch that dies halfway
                # through must not re-send what it already sent.
                save_log()
                logger.info("intaken %s → assessment %s (artifact %s)", name, aid, artifact_id)
                add_result({
                    "file": name,
                    "outcome": "uploaded",
                    "assessment_id": aid,
                    "artifact_id": artifact_id,
                })
            except (IntakeNotEnabled, AccessDenied) as e:
                # Workspace-wide, not per-file: every remaining report would fail
                # identically, so stop and say so once.
                logger.error("%s", e)
                errors += 1
                files_ok = False
                halted = str(e)
                add_result({"file": name, "outcome": "error", "error": str(e)[:300]})
                break
            except AssessmentRefused as e:
                logger.error("%s", e)
                errors += 1
                files_ok = False
                stop_assessment = str(e)[:300]
                entry["error"] = stop_assessment
                add_result({"file": name, "outcome": "error", "assessment_id": aid,
                            "error": stop_assessment})
            except Exception as e:  # noqa: BLE001 — one report's failure is not the batch's
                logger.error("%s: intake failed: %s", name, e)
                errors += 1
                files_ok = False
                add_result({"file": name, "outcome": "error", "error": str(e)[:300]})
                continue

        if halted:
            break

        # Everything this run has on the cycle for this assessment that no job
        # of ours has taken yet — including uploads from an earlier attempt that
        # died before its process call.
        assessment_jobs = jobs.setdefault(aid, [])
        taken = _processed_ids(assessment_jobs)
        pending = [
            v["artifact_id"] for v in already.values()
            if v.get("assessment_id") == aid and v.get("artifact_id")
            and v["artifact_id"] not in taken
        ]
        operation, close_skipped = close_decision(group, files_ok)
        entry["operation"] = operation
        entry["close_skipped"] = close_skipped

        if dry_run:
            count = len(pending) + would_send
            if count:
                logger.info("would process %d artifact(s) on %s with %s", count, aid, operation)
            _emit(on_event, {"event": "process_plan", "assessment_id": aid,
                             "artifacts": count, "operation": operation if count else None,
                             "close_skipped": close_skipped})
            continue

        if not pending:
            # Nothing new. A job an earlier attempt queued may still be running:
            # finish reporting it rather than claiming there is nothing to do.
            last = assessment_jobs[-1] if assessment_jobs else None
            if last and last.get("status") not in _TERMINAL and wait and client:
                job_state = _wait_and_record(client, aid, last, wait_timeout, on_event)
                entry["job"] = job_state
                if job_state.get("status") != JOB_COMPLETED:
                    jobs_failed += 1
                save_log()
            else:
                entry["operation"] = None
                entry["job"] = last
                _emit(on_event, {"event": "process_skipped", "assessment_id": aid,
                                 "reason": "nothing new to process"})
            continue

        try:
            job = client.process(aid, pending, operation)
        except (IntakeNotEnabled, AccessDenied) as e:
            logger.error("%s", e)
            errors += 1
            halted = str(e)
            entry["error"] = str(e)[:300]
            break
        except Exception as e:  # noqa: BLE001 — the files are up; say what did not happen
            logger.error("assessment %s: process failed: %s", aid, e)
            errors += 1
            entry["error"] = (
                f"uploaded {len(pending)} artifact(s) but could not queue processing: "
                f"{str(e)[:300]}. Re-run `paramify issues upload` to try the process "
                f"call again — the uploads are logged and will not be re-sent."
            )
            continue

        job_state = {
            **job_summary(job),
            "operation": operation,
            "artifact_ids": pending,
            "queued_at": _utc_now(),
        }
        assessment_jobs.append(job_state)
        save_log()
        logger.info(
            "queued %s job %s on assessment %s over %d artifact(s)%s",
            operation, job_state["job_id"], aid, len(pending),
            f" ({close_skipped})" if close_skipped else "",
        )
        _emit(on_event, {"event": "job_queued", "assessment_id": aid,
                         "job_id": job_state["job_id"], "operation": operation,
                         "artifacts": len(pending), "close_skipped": close_skipped})

        if wait:
            job_state = _wait_and_record(client, aid, job_state, wait_timeout, on_event)
            if job_state.get("status") != JOB_COMPLETED:
                jobs_failed += 1
            save_log()
        entry["job"] = job_state

    summary = {
        "run_dir": str(run_dir),
        "base_url": base_url,
        "dry_run": dry_run,
        "uploaded": uploaded,
        "skipped_duplicate": skipped_dup,
        "skipped_failed": skipped_failed,
        "errors": errors,
        "jobs_failed": jobs_failed,
        "files": len(records),
        "results": results,
        "assessments": assessments,
        "log_path": str(Path(run_dir) / ISSUE_REPORTS_DIR / INTAKE_LOG_NAME)
        if not dry_run and (uploaded or any(jobs.values())) else None,
        "ok": errors == 0 and jobs_failed == 0,
    }
    if halted:
        summary["halted"] = halted
    logger.info(
        "Done: uploaded=%d skipped_duplicate=%d skipped_failed=%d errors=%d jobs_failed=%d",
        uploaded, skipped_dup, skipped_failed, errors, jobs_failed,
    )
    _emit(on_event, {"event": "upload_complete", **summary})
    return summary


def _wait_and_record(
    client: ParamifyClient, aid: str, job_state: dict, timeout: float,
    on_event: Optional[Callable[[dict], None]],
) -> dict:
    """Wait on one job and fold its outcome into the logged job state (in place)."""
    def on_status(job: Dict) -> None:
        _emit(on_event, {"event": "job_status", "assessment_id": aid,
                         "job_id": job.get("id"), "status": job.get("status")})

    try:
        job, timed_out = wait_for_job(
            client, job_state["job_id"], timeout=timeout, on_status=on_status
        )
    except ParamifyError as e:
        job_state["poll_error"] = str(e)[:300]
        _emit(on_event, {"event": "job_complete", "assessment_id": aid, **job_state})
        return job_state
    job_state.update(job_summary(job))
    if timed_out:
        job_state["timed_out"] = True
    if job_state.get("status") != JOB_COMPLETED:
        logger.error(
            "job %s on assessment %s ended %s%s", job_state.get("job_id"), aid,
            job_state.get("status"),
            f" (blocked by {job_state['blocked_by']})" if job_state.get("blocked_by") else "",
        )
    _emit(on_event, {"event": "job_complete", "assessment_id": aid, **job_state})
    return job_state


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Send raw issue reports from a run directory into Paramify pipelines"
    )
    parser.add_argument("run_dir", nargs="?",
                        help="Run directory to upload (default: latest under --output-dir)")
    parser.add_argument("--output-dir", default="./evidence",
                        help="Base dir to find the latest run in (default ./evidence)")
    parser.add_argument("--config", help="Uploader config YAML (base_url, overrides, skip_failed)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Resolve and report what would be sent; no API calls")
    parser.add_argument("--force", action="store_true",
                        help="Re-send and re-process reports already listed in this run's "
                             "_intake_log.json")
    parser.add_argument("--no-wait", action="store_true",
                        help="Queue processing and exit without waiting for the job")
    parser.add_argument("--wait-timeout", type=float, default=None,
                        help=f"Seconds to wait for each job (default {DEFAULT_WAIT_TIMEOUT})")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir) if args.run_dir else find_latest_run(Path(args.output_dir))
    if not run_dir or not run_dir.is_dir():
        logger.error(
            "No run directory to upload (looked for %s)",
            args.run_dir or f"latest run-* under {args.output_dir}",
        )
        return 1
    try:
        summary = upload_run(
            run_dir, config=load_config(args.config), dry_run=args.dry_run, force=args.force,
            wait=not args.no_wait, wait_timeout=args.wait_timeout,
        )
    except ValueError:
        return 1
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
