"""Paramify pipelines: send a scan report into an assessment, process it, follow the job.

`Pipelines` wraps the shared `Client` for the pipeline endpoints. A failure comes
out as a `PipelineError` whose type says how far it reaches, because that is what
a caller has to decide on:

- `IntakeNotEnabled`, `AccessDenied`: the whole workspace; every later call fails
  the same way.
- `AssessmentRefused`: one assessment; others may be fine.
- `NoCycleInProgress`, `PipelineError`: one call.

Endpoint contract per Paramify REST API v0 spec 0.10.0.
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

from framework.paramify.client import ApiError, Client

PROCESS = "PROCESS"
PROCESS_CLOSE = "PROCESS_CLOSE"

JOB_COMPLETED = "COMPLETED"
JOB_FAILED = "FAILED"
JOB_CANCELLED = "CANCELLED"
JOB_QUEUED = "QUEUED"
TERMINAL = frozenset({JOB_COMPLETED, JOB_FAILED, JOB_CANCELLED})

# Processing a large scan takes minutes, so polling starts quick and backs off.
DEFAULT_WAIT_TIMEOUT = 900
_POLL_FIRST = 5.0
_POLL_MAX = 30.0
_POLL_BACKOFF = 1.5

# The intake endpoint accepts files up to 10 GB, and a full Nessus export is
# routinely hundreds of megabytes.
UPLOAD_TIMEOUT = 600


class PipelineError(RuntimeError):
    """A pipeline call failed; it affects that call only."""


class IntakeNotEnabled(PipelineError):
    """HTTP 501: pipeline intake is not enabled for this workspace."""


class AccessDenied(PipelineError):
    """HTTP 401/403: the key is missing a pipeline permission."""


class AssessmentRefused(PipelineError):
    """HTTP 400/404 on an assessment: no intake preset, or a wrong id."""


class NoCycleInProgress(PipelineError):
    """HTTP 409: the pipeline has no cycle in progress, or the work aimed at
    another cycle than the in-progress one."""


def _server_message(exc: ApiError) -> str:
    """Paramify's own message for a failure, with its requestId: the requestId
    is the only thing that lets support find the failure."""
    try:
        body = json.loads(exc.body)
    except ValueError:
        return exc.body[:300] or exc.message
    if not isinstance(body, dict):
        return str(body)[:300]
    error = body.get("error")
    msg = (error.get("message") if isinstance(error, dict) else "") or body.get("statusMessage") or exc.body[:300]
    request_id = body.get("requestId")
    return f"{msg} (requestId={request_id})" if request_id else str(msg)


def _pipeline_error(exc: ApiError, what: str, assessment_id: Optional[str]) -> PipelineError:
    code = exc.status
    if code is None:
        return PipelineError(f"{what} failed: {exc.message}")
    msg = _server_message(exc)
    if code == 501:
        return IntakeNotEnabled(f"pipeline intake is not enabled for this workspace (HTTP 501): {msg}")
    if code in (401, 403):
        return AccessDenied(
            f"Paramify rejected the token for {what} (HTTP {code}). A pipeline key needs "
            f"PIPELINE_INTAKE, plus PIPELINE_PROCESS to process and PIPELINE_CLOSE to "
            f"close. {msg}"
        )
    if code == 404 and assessment_id:
        return AssessmentRefused(
            f"assessment {assessment_id} not found (HTTP 404) — the id may belong to "
            f"another workspace, or the assessment was deleted. Re-pick it with "
            f"`paramify assessments select`. {msg}"
        )
    if code == 400 and assessment_id:
        return AssessmentRefused(
            f"{what} refused for assessment {assessment_id} (HTTP 400). The usual cause "
            f"is an assessment with no file intake preset configured — set one up in "
            f"Paramify. {msg}"
        )
    if code == 409 and assessment_id:
        # 409 covers more than "no cycle in progress"; Paramify's message says which.
        return NoCycleInProgress(
            f"{what} refused for assessment {assessment_id} (HTTP 409): {msg}. "
            f"Work can only be queued on the in-progress cycle (the oldest open one), "
            f"or there is no cycle in progress."
        )
    return PipelineError(f"{what} failed (HTTP {code}): {msg}")


class Pipelines:
    """The pipeline endpoints. `sleep` and `now` pace job polling."""

    def __init__(
        self,
        client: Client,
        *,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self.sleep = sleep
        self.now = now

    def _call(self, what: str, assessment_id: Optional[str], fn: Callable[[], Any]) -> Dict[str, Any]:
        """The response object, or {} when the call succeeded but its body is not
        one: the work happened, and the caller must not take it for a failure and
        send it again."""
        try:
            body = fn()
        except ApiError as exc:
            if exc.status is not None and exc.status < 400:
                return {}
            raise _pipeline_error(exc, what, assessment_id) from exc
        return body if isinstance(body, dict) else {}

    def intake(self, assessment_id: str, filename: str, content: bytes, content_type: str,
               artifact_meta: Dict[str, Any]) -> Dict[str, Any]:
        """Upload one report, byte for byte, to the pipeline's current cycle. Returns
        the artifact. Sent with no `operation`: an operation on an intake sweeps
        every unprocessed file on the cycle, not just this one."""
        # The spec asks for a URL-encoded filename; safe="" so a slash in a
        # vendor-generated name cannot escape the field.
        body = self._call(f"intake of {filename}", assessment_id, lambda: self._client.post_file(
            f"/pipelines/{assessment_id}/intake", quote(filename, safe=""), content, artifact_meta,
            content_type=content_type, timeout=UPLOAD_TIMEOUT,
        ))
        artifact = body.get("artifact")
        if not isinstance(artifact, dict) or not artifact.get("id"):
            # Without the id the file cannot be named in the process call, so it
            # would sit on the cycle unprocessed while the run reported success.
            raise PipelineError(
                f"intake of {filename} returned no artifact id; it may be on the cycle "
                f"unprocessed — check the assessment in Paramify before re-running, "
                f"which uploads it again"
            )
        return artifact

    def process(self, assessment_id: str, artifact_ids: List[str], operation: str) -> Dict[str, Any]:
        """Queue one job over exactly these artifacts. Returns the job."""
        return self._call("process", assessment_id, lambda: self._client.post_json(
            f"/pipelines/{assessment_id}/process",
            {"artifactIds": list(artifact_ids), "operation": operation},
        ))

    def close(self, assessment_id: str) -> Dict[str, Any]:
        """Queue a close of the pipeline's current cycle. Returns the job."""
        return self._call("close", assessment_id, lambda: self._client.post_json(
            f"/pipelines/{assessment_id}/close",
        ))

    def list_cycles(self, assessment_id: str) -> List[Dict[str, Any]]:
        body = self._call("list cycles", assessment_id,
                          lambda: self._client.get(f"/assessment/{assessment_id}/cycle"))
        cycles = body.get("cycles")
        return cycles if isinstance(cycles, list) else []

    def get_job(self, job_id: str) -> Dict[str, Any]:
        return self._call(f"read job {job_id}", None,
                          lambda: self._client.get(f"/pipeline-jobs/{job_id}"))

    def list_jobs(self, assessment_id: Optional[str] = None, status: Optional[str] = None,
                  limit: int = 50) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": limit}
        if assessment_id:
            params["assessmentId"] = assessment_id
        if status:
            params["status"] = status
        body = self._call("list jobs", None, lambda: self._client.get("/pipeline-jobs", params))
        jobs = body.get("pipelineJobs")
        return jobs if isinstance(jobs, list) else []

    def retry_job(self, job_id: str) -> Dict[str, Any]:
        return self._call(f"retry job {job_id}", None,
                          lambda: self._client.post_json(f"/pipeline-jobs/{job_id}/retry"))

    def cancel_job(self, job_id: str) -> Dict[str, Any]:
        return self._call(f"cancel job {job_id}", None,
                          lambda: self._client.post_json(f"/pipeline-jobs/{job_id}/cancel"))


def job_summary(job: Dict[str, Any]) -> Dict[str, Any]:
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


def is_blocked(job: Dict[str, Any]) -> bool:
    """A queued job waiting behind a failed one — an API job or a logged one."""
    return job.get("status") == JOB_QUEUED and bool(job.get("blockedByJobId") or job.get("blocked_by"))


def wait_for_job(
    pipelines: Pipelines,
    job_id: str,
    *,
    timeout: float = DEFAULT_WAIT_TIMEOUT,
    on_status: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Tuple[Dict[str, Any], bool]:
    """Poll a job until it finishes, is blocked, or `timeout` passes.

    Returns (last job seen, timed_out). A job queued behind a failed one is
    returned at once rather than waited on: it cannot move until a person
    retries or cancels the blocker, and doing either automatically would be
    deciding what happens to someone else's job. A read that fails after the
    client's own retries raises PipelineError.
    """
    deadline = pipelines.now() + timeout
    delay = _POLL_FIRST
    last_status = None
    while True:
        job = pipelines.get_job(job_id)
        status = job.get("status")
        if status != last_status:
            last_status = status
            if on_status is not None:
                on_status(job)
        if status in TERMINAL or is_blocked(job):
            return job, False
        if pipelines.now() + delay > deadline:
            return job, True
        pipelines.sleep(delay)
        delay = min(delay * _POLL_BACKOFF, _POLL_MAX)
