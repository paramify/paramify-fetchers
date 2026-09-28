"""Tests for the issue-report uploader (uploaders/paramify_issues/uploader.py).

Like the evidence uploader this pushes real customer data, so we mock ONLY the
HTTP boundary and let the uploader's own logic run. Four behaviors get the most
attention because they are the ones that cause damage rather than an error:

  - **the bytes.** The multipart body must carry the file exactly as it is on
    disk. A parse-and-rewrite would produce a file Paramify's intake can still
    open but reads differently, which is worse than a rejection.
  - **the dedup log.** Intake adds an artifact every time and there is no way to
    list what a cycle holds, so the local log is the only thing that makes a
    re-run safe. If it stops being honoured, every re-run doubles the issues.
  - **one process call per assessment, naming exactly this run's artifacts.**
    The bare form sweeps whatever else is unprocessed on the cycle.
  - **the close.** Closing auto-closes every open issue the cycle never saw, so
    a close after a partial run marks real issues resolved. PROCESS_CLOSE is sent
    only for `after_run` and a run in which every target succeeded and uploaded.

Mirrors tests/test_uploader.py, including loading the module by path (the CLI
loads it that way; it is not an importable package).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_UPLOADER_PATH = REPO_ROOT / "uploaders" / "paramify_issues" / "uploader.py"
_spec = importlib.util.spec_from_file_location("issues_uploader_under_test", _UPLOADER_PATH)
uploader = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uploader)

ASSESSMENT = "123e4567-e89b-12d3-a456-426614174000"
OTHER = "99999999-9999-4999-8999-999999999999"
# CRLF, a BOM and a trailing space: all survive a byte copy, none survive a
# parse-and-rewrite.
RAW_CSV = b"\xef\xbb\xbfPlugin ID,Severity\r\n19506,Info \r\n"
COUNTS = {"recordsProcessed": 1, "issuesCreated": 1, "issuesUpdated": 0,
          "issuesSeenClosed": 0, "issuesCreatedAndClosed": 0, "issuesExcuseClosed": 0}


@pytest.fixture(autouse=True)
def no_real_waiting(monkeypatch):
    """Drive the poll loop on a fake clock: each sleep advances it, none blocks."""
    clock = {"now": 0.0}
    monkeypatch.setattr(uploader, "_monotonic", lambda: clock["now"])
    monkeypatch.setattr(uploader, "_sleep", lambda s: clock.__setitem__("now", clock["now"] + s))
    return clock


# --------------------------------------------------------------------------- #
# Fakes for the HTTP boundary
# --------------------------------------------------------------------------- #

class FakeResponse:
    def __init__(self, status_code=201, json_data=None, text=""):
        self.status_code = status_code
        self._json = {"artifact": {"id": "art-1"}, "job": None} if json_data is None else json_data
        self.text = text

    def json(self):
        if self._json is _NO_JSON:
            raise ValueError("not json")
        return self._json


_NO_JSON = object()


class FakeSession:
    """Drop-in for requests.Session that records every request."""

    def __init__(self, responses=None):
        self.headers = {}
        self.posts = []
        self.gets = []
        self._responses = list(responses or [])

    def _next(self):
        return self._responses.pop(0) if self._responses else FakeResponse()

    def post(self, url, files=None, json=None, timeout=None):
        self.posts.append({"url": url, "files": files, "json": json})
        return self._next()

    def get(self, url, params=None, timeout=None):
        self.gets.append({"url": url, "params": params})
        return self._next()


class FakeClient:
    """Drop-in for ParamifyClient at the upload_run level.

    `job_statuses`: the statuses successive polls of each job report, last one
    repeated. Default: COMPLETED on the first poll.
    """

    def __init__(self, *, fail_files=(), raise_on=None, process_error=None,
                 job_statuses=None, job_extra=None, id_suffix=""):
        self.id_suffix = id_suffix
        self.fail_files = set(fail_files)
        self.raise_on = raise_on or {}
        self.process_error = process_error
        self.job_statuses = list(job_statuses or [uploader.JOB_COMPLETED])
        self.job_extra = job_extra or {}
        self.sent = []
        self.processed = []
        self.polls = 0

    def intake(self, assessment_id, filename, content, content_type, meta):
        if filename in self.raise_on:
            raise self.raise_on[filename]
        if filename in self.fail_files:
            raise uploader.ParamifyError(f"HTTP 500 on {filename}")
        self.sent.append({
            "assessment_id": assessment_id, "file": filename, "content": content,
            "content_type": content_type, "meta": meta,
        })
        return {"id": f"art-{assessment_id[:4]}-{filename}{self.id_suffix}"}

    def process(self, assessment_id, artifact_ids, operation):
        if self.process_error:
            raise self.process_error
        self.processed.append({"assessment_id": assessment_id,
                               "artifact_ids": list(artifact_ids), "operation": operation})
        return {"id": f"job-{len(self.processed)}", "status": "QUEUED",
                "type": operation, "cycleId": "cyc-1"}

    def get_job(self, job_id):
        i = min(self.polls, len(self.job_statuses) - 1)
        self.polls += 1
        status = self.job_statuses[i]
        job = {"id": job_id, "status": status, "type": "PROCESS",
               "counts": COUNTS if status == uploader.JOB_COMPLETED else None,
               "error": None, "blockedByJobId": None}
        job.update(self.job_extra)
        return job


def make_run(tmp_path, reports, *, run_id="RID", invocations="derive", close_cycle="never") -> Path:
    """Build a run dir with an issue-reports/ subdir and a sidecar index.

    `reports` is a list of dicts: {name, body?, assessment_id?, status?, format?,
    close_cycle?, fetcher_name?}. `invocations`: "derive" builds one per report
    (the common case), None writes a 1.0 sidecar with no invocations, or a list
    of extra invocation dicts appended to the derived ones.
    """
    run_dir = tmp_path / f"run-{run_id}"
    reports_dir = run_dir / "issue-reports"
    reports_dir.mkdir(parents=True)
    records, invs = [], []
    for spec in reports:
        name = spec["name"]
        body = spec.get("body", RAW_CSV)
        if spec.get("on_disk", True):
            (reports_dir / name).write_bytes(body)
        status = spec.get("status", "success")
        aid = spec.get("assessment_id", ASSESSMENT)
        policy = spec.get("close_cycle", close_cycle)
        records.append({
            "file": name,
            "fetcher_name": spec.get("fetcher_name", "t_scan"),
            "fetcher_version": "0.1.0",
            "run_id": run_id,
            "target": spec.get("target"),
            "collected_at": spec.get("collected_at", "2026-07-01T00:00:00Z"),
            "status": status,
            "exit_code": 0 if status == "success" else 1,
            "format": spec.get("format", "csv"),
            "title": spec.get("title", name),
            "assessment_id": aid,
            "assessment_name": "Monthly Scan",
            "close_cycle": policy,
            "assessment_type": "VULNERABILITY",
            "sha256": "deadbeef",
            "bytes": len(body),
        })
        invs.append({"fetcher_name": spec.get("fetcher_name", "t_scan"),
                     "target": spec.get("target"), "status": status,
                     "exit_code": 0 if status == "success" else 1, "files": [name],
                     "assessment_id": aid, "close_cycle": policy})
    index = {"schema_version": "1.1", "run_id": run_id, "reports": records}
    if invocations is None:
        index["schema_version"] = "1.0"
    else:
        index["invocations"] = invs + (invocations if isinstance(invocations, list) else [])
    (reports_dir / "_issue_reports.json").write_text(json.dumps(index))
    return run_dir


def run_upload(run_dir, client=None, *, config=None, dry_run=False, force=False,
               wait=True, on_event=None):
    """upload_run with the client injected and a token/base_url that pass the guards."""
    original = uploader.ParamifyClient
    if client is not None:
        uploader.ParamifyClient = lambda *a, **k: client
    try:
        return uploader.upload_run(
            run_dir, config=config, token="t", base_url="https://example.test/api/v0",
            dry_run=dry_run, force=force, wait=wait, on_event=on_event,
        )
    finally:
        uploader.ParamifyClient = original


def read_log(run_dir):
    return json.loads((run_dir / "issue-reports" / "_intake_log.json").read_text())


# --------------------------------------------------------------------------- #
# The bytes on the wire
# --------------------------------------------------------------------------- #

def test_file_is_read_from_disk_unchanged(tmp_path):
    """The property the whole feature exists to preserve, asserted through
    upload_run so the read itself is under test.

    RAW_CSV carries CRLF and a BOM on purpose: reading it as text (universal
    newlines) and re-encoding silently rewrites the line endings, producing a file
    intake still accepts but reads differently. Asserting on bytes handed to the
    client would miss that — the read has to be in the path.
    """
    run_dir = make_run(tmp_path, [{"name": "scan.csv", "body": RAW_CSV}])
    client = FakeClient()
    run_upload(run_dir, client)
    assert client.sent[0]["content"] == RAW_CSV, "the report was altered before upload"


def test_file_is_posted_byte_for_byte():
    """And the client puts those exact bytes in the multipart body."""
    session = FakeSession()
    client = uploader.ParamifyClient("token", "https://example.test/api/v0")
    client.session = session
    client.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {"title": "T"})

    files = session.posts[0]["files"]
    assert files["file"][1] == RAW_CSV, "the report was altered before upload"
    assert files["file"][2] == "text/csv"


def test_intake_goes_to_the_pipeline_with_no_operation():
    """Uploads never carry an operation: on an intake it sweeps every unprocessed
    file on the cycle, and processing is one explicit call per run instead."""
    session = FakeSession()
    client = uploader.ParamifyClient("token-abc", "https://example.test/api/v0")
    client.session = session
    client.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {"title": "T"})
    assert session.posts[0]["url"] == f"https://example.test/api/v0/pipelines/{ASSESSMENT}/intake"
    meta = json.loads(session.posts[0]["files"]["artifact"][1])
    assert "operation" not in meta and "cycle" not in meta


def test_intake_returns_the_artifact():
    session = FakeSession([FakeResponse(201, {"artifact": {"id": "a-9"}, "job": None})])
    client = uploader.ParamifyClient("t", "https://example.test/api/v0")
    client.session = session
    assert client.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})["id"] == "a-9"


def test_process_names_the_artifacts_and_the_operation():
    session = FakeSession([FakeResponse(202, {"id": "job-1", "status": "QUEUED"})])
    client = uploader.ParamifyClient("t", "https://example.test/api/v0")
    client.session = session
    job = client.process(ASSESSMENT, ["a-1", "a-2"], "PROCESS")
    assert session.posts[0]["url"] == f"https://example.test/api/v0/pipelines/{ASSESSMENT}/process"
    assert session.posts[0]["json"] == {"artifactIds": ["a-1", "a-2"], "operation": "PROCESS"}
    assert job["id"] == "job-1"


def test_token_goes_on_the_session_as_a_bearer():
    """Asserted on the real session the constructor built, before any fake
    replaces it — patching the session first would test the fake, not the client."""
    client = uploader.ParamifyClient("token-abc", "https://example.test/api/v0")
    assert client.session.headers["Authorization"] == "Bearer token-abc"


def test_filename_is_url_encoded():
    """The spec asks for it: "filenames containing certain special characters may
    cause upload errors. URL-encode your filename"."""
    session = FakeSession()
    client = uploader.ParamifyClient("t", "https://example.test/api/v0")
    client.session = session
    client.intake(ASSESSMENT, "scan report #1.csv", RAW_CSV, "text/csv", {})
    sent_name = session.posts[0]["files"]["file"][0]
    assert sent_name == "scan%20report%20%231.csv"


def test_artifact_part_is_sent_and_is_json():
    """The endpoint requires the `artifact` part even though every field in it is
    optional, so omitting it would fail every upload."""
    session = FakeSession()
    client = uploader.ParamifyClient("t", "https://example.test/api/v0")
    client.session = session
    client.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv",
                  {"title": "T", "note": "n", "effectiveDate": "2026-07-01T00:00:00Z"})
    part = session.posts[0]["files"]["artifact"]
    assert part[2] == "application/json"
    assert json.loads(part[1])["title"] == "T"


def test_effective_date_is_the_collection_time_not_now(tmp_path):
    """It no longer picks a cycle, but it is still the date the scan describes."""
    run_dir = make_run(tmp_path, [{"name": "scan.csv", "collected_at": "2026-02-15T00:00:00Z"}])
    client = FakeClient()
    run_upload(run_dir, client)
    assert client.sent[0]["meta"]["effectiveDate"] == "2026-02-15T00:00:00Z"


@pytest.mark.parametrize("fmt,expected", [
    ("csv", "text/csv"),
    ("json", "application/json"),
    ("xml", "application/xml"),
    ("nessus", "application/xml"),
])
def test_content_type_per_format(tmp_path, fmt, expected):
    run_dir = make_run(tmp_path, [{"name": f"scan.{fmt}", "format": fmt}])
    client = FakeClient()
    run_upload(run_dir, client)
    assert client.sent[0]["content_type"] == expected


def test_unintakeable_format_is_an_error_not_a_guess(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.html", "format": "html"}])
    client = FakeClient()
    summary = run_upload(run_dir, client)
    assert summary["errors"] == 1
    assert client.sent == []
    assert "html" in summary["results"][0]["reason"]


# --------------------------------------------------------------------------- #
# One process call per assessment
# --------------------------------------------------------------------------- #

def test_one_process_call_per_assessment_naming_exactly_its_artifacts(tmp_path):
    """Three framework CSVs for one assessment: three uploads, ONE job."""
    run_dir = make_run(tmp_path, [
        {"name": "a.csv"}, {"name": "b.csv"}, {"name": "c.csv"},
        {"name": "other.csv", "assessment_id": OTHER},
    ])
    client = FakeClient()
    summary = run_upload(run_dir, client)
    assert summary["ok"], summary
    assert len(client.processed) == 2
    by_aid = {p["assessment_id"]: p["artifact_ids"] for p in client.processed}
    assert by_aid[ASSESSMENT] == [f"art-{ASSESSMENT[:4]}-{n}" for n in ("a.csv", "b.csv", "c.csv")]
    assert by_aid[OTHER] == [f"art-{OTHER[:4]}-other.csv"]


def test_job_counts_reach_the_summary(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    summary = run_upload(run_dir, FakeClient())
    [entry] = summary["assessments"]
    assert entry["job"]["status"] == "COMPLETED"
    assert entry["job"]["counts"] == COUNTS
    assert entry["operation"] == "PROCESS"


def test_no_process_call_when_nothing_uploaded(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    client = FakeClient(fail_files={"scan.csv"})
    run_upload(run_dir, client)
    assert client.processed == []


# --------------------------------------------------------------------------- #
# The close
# --------------------------------------------------------------------------- #

def test_after_run_on_a_complete_run_processes_and_closes(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "a.csv"}, {"name": "b.csv"}], close_cycle="after_run")
    client = FakeClient()
    summary = run_upload(run_dir, client)
    assert [p["operation"] for p in client.processed] == ["PROCESS_CLOSE"]
    assert summary["assessments"][0]["close_skipped"] is None


def test_never_only_processes(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "a.csv"}], close_cycle="never")
    client = FakeClient()
    run_upload(run_dir, client)
    assert [p["operation"] for p in client.processed] == ["PROCESS"]


def test_a_failed_target_that_wrote_nothing_blocks_the_close(tmp_path):
    """The case invocation records exist for: the failed framework has no report
    record at all, and closing would auto-close every one of its issues."""
    run_dir = make_run(
        tmp_path, [{"name": "fw1.csv"}, {"name": "fw2.csv"}], close_cycle="after_run",
        invocations=[{"fetcher_name": "t_scan", "target": {"framework": "fw3"},
                      "status": "failed", "exit_code": 1, "files": [],
                      "assessment_id": ASSESSMENT, "close_cycle": "after_run"}],
    )
    client = FakeClient()
    summary = run_upload(run_dir, client)
    assert [p["operation"] for p in client.processed] == ["PROCESS"]
    reason = summary["assessments"][0]["close_skipped"]
    assert "1 target(s) failed" in reason and "t_scan[fw3]" in reason


def test_a_failed_upload_blocks_the_close(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "a.csv"}, {"name": "b.csv"}], close_cycle="after_run")
    client = FakeClient(fail_files={"b.csv"})
    summary = run_upload(run_dir, client)
    assert client.processed[0]["operation"] == "PROCESS"
    assert client.processed[0]["artifact_ids"] == [f"art-{ASSESSMENT[:4]}-a.csv"]
    assert "not every report" in summary["assessments"][0]["close_skipped"]


def test_a_skipped_failed_collection_blocks_the_close(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "a.csv"}, {"name": "b.csv", "status": "failed"}],
                       close_cycle="after_run")
    client = FakeClient()
    run_upload(run_dir, client)
    assert client.processed[0]["operation"] == "PROCESS"


def test_mixed_policies_on_one_assessment_do_not_close(tmp_path):
    run_dir = make_run(tmp_path, [
        {"name": "a.csv", "fetcher_name": "fa", "close_cycle": "after_run"},
        {"name": "b.csv", "fetcher_name": "fb", "close_cycle": "never"},
    ])
    client = FakeClient()
    summary = run_upload(run_dir, client)
    assert client.processed[0]["operation"] == "PROCESS"
    assert "not after_run for every fetcher" in summary["assessments"][0]["close_skipped"]


def test_an_old_sidecar_never_closes(tmp_path):
    """A 1.0 sidecar cannot show a failed target that wrote nothing."""
    run_dir = make_run(tmp_path, [{"name": "a.csv"}], close_cycle="after_run", invocations=None)
    client = FakeClient()
    summary = run_upload(run_dir, client)
    assert client.processed[0]["operation"] == "PROCESS"
    assert "paramify issues close" in summary["assessments"][0]["close_skipped"]


def test_missing_close_policy_sends_nothing_for_that_assessment(tmp_path):
    """Checked before upload: an uploaded file sits on the cycle either way."""
    run_dir = make_run(tmp_path, [
        {"name": "a.csv", "close_cycle": None},
        {"name": "b.csv", "assessment_id": OTHER},
    ])
    client = FakeClient()
    summary = run_upload(run_dir, client)
    assert [s["file"] for s in client.sent] == ["b.csv"]
    assert summary["errors"] == 1
    assert "--close-cycle" in summary["results"][0]["reason"]


def test_override_can_set_the_policy(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "a.csv", "close_cycle": None}])
    client = FakeClient()
    run_upload(run_dir, client, config={"overrides": {"t_scan": {"close_cycle": "never"}}})
    assert client.processed[0]["operation"] == "PROCESS"


# --------------------------------------------------------------------------- #
# Waiting on the job
# --------------------------------------------------------------------------- #

def test_a_failed_job_fails_the_run(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    client = FakeClient(job_statuses=["IN_PROGRESS", "FAILED"],
                        job_extra={"error": "preset mapping broke"})
    summary = run_upload(run_dir, client)
    assert not summary["ok"]
    assert summary["jobs_failed"] == 1
    assert summary["assessments"][0]["job"]["error"] == "preset mapping broke"


def test_a_blocked_job_is_reported_not_waited_on(tmp_path):
    """It cannot move until a person retries or cancels the blocker."""
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    client = FakeClient(job_statuses=["QUEUED"], job_extra={"blockedByJobId": "job-old"})
    summary = run_upload(run_dir, client)
    assert client.polls == 1
    assert not summary["ok"]
    assert summary["assessments"][0]["job"]["blocked_by"] == "job-old"


def test_a_job_still_running_at_the_cap_times_out(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    client = FakeClient(job_statuses=["IN_PROGRESS"])
    summary = uploader_run_with_timeout(run_dir, client, 60)
    assert summary["assessments"][0]["job"]["timed_out"]
    assert not summary["ok"]


def uploader_run_with_timeout(run_dir, client, timeout):
    original = uploader.ParamifyClient
    uploader.ParamifyClient = lambda *a, **k: client
    try:
        return uploader.upload_run(run_dir, token="t", base_url="https://example.test/api/v0",
                                   wait_timeout=timeout)
    finally:
        uploader.ParamifyClient = original


def test_no_wait_queues_and_returns(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    client = FakeClient()
    summary = run_upload(run_dir, client, wait=False)
    assert client.polls == 0
    assert summary["ok"]
    assert summary["assessments"][0]["job"]["status"] == "QUEUED"


def test_events_describe_the_job(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    events = []
    run_upload(run_dir, FakeClient(job_statuses=["IN_PROGRESS", "COMPLETED"]),
               on_event=events.append)
    kinds = [e["event"] for e in events]
    assert kinds[:2] == ["upload_start", "upload_file"]
    assert "job_queued" in kinds and "job_complete" in kinds
    assert [e["status"] for e in events if e["event"] == "job_status"] == ["IN_PROGRESS", "COMPLETED"]
    assert kinds[-1] == "upload_complete"


def test_wait_for_job_retries_a_failed_poll():
    class Flaky(FakeClient):
        def get_job(self, job_id):
            if self.polls == 0:
                self.polls += 1
                raise uploader.ParamifyError("HTTP 502")
            return super().get_job(job_id)

    job, timed_out = uploader.wait_for_job(Flaky(), "job-1", timeout=300)
    assert job["status"] == "COMPLETED" and not timed_out


# --------------------------------------------------------------------------- #
# Dedup and resume — the only thing making a re-run safe
# --------------------------------------------------------------------------- #

def test_second_run_does_not_re_upload_or_re_process(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    first = FakeClient()
    assert run_upload(run_dir, first)["uploaded"] == 1

    second = FakeClient()
    summary = run_upload(run_dir, second)
    assert summary["uploaded"] == 0
    assert summary["skipped_duplicate"] == 1
    assert second.sent == [], "a re-run would have duplicated every issue in the report"
    assert second.processed == [], "a re-run queued a second job over the same artifacts"


def test_a_run_that_died_before_processing_processes_on_re_run(tmp_path):
    """Uploaded, then the process call failed: the re-run sends nothing new and
    processes what is already on the cycle."""
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    summary = run_upload(run_dir, FakeClient(process_error=uploader.ParamifyError("HTTP 500")))
    assert not summary["ok"]
    assert "could not queue processing" in summary["assessments"][0]["error"]

    second = FakeClient()
    summary = run_upload(run_dir, second)
    assert second.sent == []
    assert second.processed[0]["artifact_ids"] == [f"art-{ASSESSMENT[:4]}-scan.csv"]
    assert summary["ok"]


def test_a_re_run_finishes_waiting_on_a_job_it_left_running(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    run_upload(run_dir, FakeClient(), wait=False)
    second = FakeClient()
    summary = run_upload(run_dir, second)
    assert second.processed == []
    assert second.polls >= 1
    assert summary["assessments"][0]["job"]["status"] == "COMPLETED"


def test_force_reuploads_and_reprocesses(tmp_path):
    """--force is the supported way to re-send; deleting the log would also
    re-send every other file in the run."""
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    run_upload(run_dir, FakeClient())
    second = FakeClient(id_suffix="-2")  # every intake creates a new artifact
    summary = run_upload(run_dir, second, force=True)
    assert summary["uploaded"] == 1
    assert len(second.sent) == 1 and second.sent[0]["content"] == RAW_CSV
    assert len(second.processed) == 1


def test_intake_log_is_written_per_file(tmp_path):
    """Written after each file, not once at the end: a batch that dies halfway
    through must not re-send what it already sent."""
    run_dir = make_run(tmp_path, [{"name": "a.csv"}, {"name": "b.csv"}])
    client = FakeClient(raise_on={"b.csv": uploader.IntakeNotEnabled("off (HTTP 501)")})
    run_upload(run_dir, client)
    keys = list(read_log(run_dir)["uploaded"])
    assert len(keys) == 1 and keys[0].endswith("|a.csv")


def test_the_log_records_the_job(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    run_upload(run_dir, FakeClient())
    [job] = read_log(run_dir)["jobs"][ASSESSMENT]
    assert job["job_id"] == "job-1"
    assert job["status"] == "COMPLETED"
    assert job["artifact_ids"] == [f"art-{ASSESSMENT[:4]}-scan.csv"]


def test_a_different_assessment_is_not_a_duplicate(tmp_path):
    """Pointing the manifest at another assessment and re-running should send the
    report again — a different destination is not a duplicate."""
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    run_upload(run_dir, FakeClient())
    client = FakeClient()
    summary = run_upload(run_dir, client, config={"overrides": {"t_scan": {"assessment_id": OTHER}}})
    assert summary["uploaded"] == 1
    assert client.sent[0]["assessment_id"] == OTHER


def test_dry_run_sends_nothing_and_writes_no_log(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}], close_cycle="after_run")
    client = FakeClient()
    events = []
    summary = run_upload(run_dir, client, dry_run=True, on_event=events.append)
    assert client.sent == [] and client.processed == []
    assert summary["results"][0]["outcome"] == "would_upload"
    assert not (run_dir / "issue-reports" / "_intake_log.json").exists()
    [plan] = [e for e in events if e["event"] == "process_plan"]
    assert plan["operation"] == "PROCESS_CLOSE" and plan["artifacts"] == 1


def test_dry_run_predicts_duplicates(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "a.csv"}, {"name": "b.csv"}])
    run_upload(run_dir, FakeClient(raise_on={"b.csv": uploader.IntakeNotEnabled("off")}))

    client = FakeClient()
    summary = run_upload(run_dir, client, dry_run=True)
    assert client.sent == [], "a dry-run still sends nothing"
    outcomes = {r["file"]: r["outcome"] for r in summary["results"]}
    assert outcomes == {"a.csv": "skipped_duplicate", "b.csv": "would_upload"}


def test_dry_run_survives_a_corrupt_log(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    (run_dir / "issue-reports" / "_intake_log.json").write_text("{not json")
    summary = run_upload(run_dir, FakeClient(), dry_run=True)
    assert summary["results"][0]["outcome"] == "would_upload"


def test_corrupt_intake_log_refuses_rather_than_re_uploading(tmp_path):
    """Treating an unreadable log as empty would silently duplicate everything."""
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    (run_dir / "issue-reports" / "_intake_log.json").write_text("{not json")
    with pytest.raises(ValueError, match="already intaken"):
        run_upload(run_dir, FakeClient())


# --------------------------------------------------------------------------- #
# Failure handling
# --------------------------------------------------------------------------- #

def test_missing_assessment_is_reported_with_the_fix(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv", "assessment_id": None}])
    client = FakeClient()
    summary = run_upload(run_dir, client)
    assert summary["errors"] == 1
    assert client.sent == []
    assert "assessments select" in summary["results"][0]["reason"]


@pytest.mark.parametrize("error", [
    uploader.IntakeNotEnabled("off (HTTP 501)"),
    uploader.AccessDenied("no PIPELINE_INTAKE (HTTP 403)"),
])
def test_workspace_wide_errors_halt_the_batch(tmp_path, error):
    """Every remaining report would fail the same way, so it stops once."""
    run_dir = make_run(tmp_path, [
        {"name": "a.csv"}, {"name": "b.csv"}, {"name": "c.csv", "assessment_id": OTHER},
    ])
    client = FakeClient(raise_on={"a.csv": error})
    summary = run_upload(run_dir, client)
    assert len(summary["results"]) == 1, "the batch kept going"
    assert "halted" in summary and not summary["ok"]
    assert client.processed == []


def test_a_refused_assessment_stops_only_that_assessment(tmp_path):
    """A 400 (no preset) or 404 is about the assessment: its other files would be
    refused the same way, but another assessment may be fine."""
    run_dir = make_run(tmp_path, [
        {"name": "a.csv"}, {"name": "b.csv"}, {"name": "c.csv", "assessment_id": OTHER},
    ])
    client = FakeClient(raise_on={"a.csv": uploader.AssessmentRefused("no preset (HTTP 400)")})
    summary = run_upload(run_dir, client)
    assert [s["file"] for s in client.sent] == ["c.csv"]
    outcomes = {r["file"]: r.get("reason") or r.get("error") for r in summary["results"]}
    assert "not sent" in outcomes["b.csv"]
    assert [p["assessment_id"] for p in client.processed] == [OTHER]


def test_one_failed_report_does_not_abort_the_batch(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "a.csv"}, {"name": "b.csv"}, {"name": "c.csv"}])
    client = FakeClient(fail_files={"b.csv"})
    summary = run_upload(run_dir, client)
    assert summary["uploaded"] == 2
    assert summary["errors"] == 1
    assert [s["file"] for s in client.sent] == ["a.csv", "c.csv"]
    assert not summary["ok"]


def test_failed_collection_is_skipped_by_default(tmp_path):
    """Opposite default to the evidence uploader, deliberately: a partial scan
    file is parsed into issues, and findings absent from it read as resolved."""
    run_dir = make_run(tmp_path, [{"name": "scan.csv", "status": "failed"}])
    client = FakeClient()
    summary = run_upload(run_dir, client)
    assert summary["skipped_failed"] == 1
    assert client.sent == []


def test_failed_collection_can_be_opted_in_but_never_closes(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv", "status": "failed"}],
                       close_cycle="after_run")
    client = FakeClient()
    summary = run_upload(run_dir, client, config={"skip_failed": False})
    assert summary["uploaded"] == 1
    assert client.processed[0]["operation"] == "PROCESS"


def test_oversized_report_is_one_clear_error_not_an_oom(tmp_path, monkeypatch):
    """requests buffers the whole multipart body, so an enormous export would be
    an OOM kill partway through a batch. It is refused with a message instead,
    and the siblings still go."""
    run_dir = make_run(tmp_path, [{"name": "huge.csv"}, {"name": "small.csv"}])
    monkeypatch.setattr(uploader, "_MAX_REPORT_BYTES", 10)  # RAW_CSV is larger
    (run_dir / "issue-reports" / "small.csv").write_bytes(b"x")
    client = FakeClient()
    summary = run_upload(run_dir, client)
    outcomes = {r["file"]: r["outcome"] for r in summary["results"]}
    assert outcomes == {"huge.csv": "error", "small.csv": "uploaded"}
    reason = next(r["reason"] for r in summary["results"] if r["file"] == "huge.csv")
    assert "exceeds" in reason and "streaming" in reason


def test_report_listed_but_missing_from_disk_is_an_error(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "gone.csv", "on_disk": False}])
    summary = run_upload(run_dir, FakeClient())
    assert summary["errors"] == 1
    assert "not on disk" in summary["results"][0]["reason"]


def test_run_with_no_sidecar_is_refused_clearly(tmp_path):
    run_dir = tmp_path / "run-empty"
    run_dir.mkdir()
    with pytest.raises(ValueError, match="collected no issue reports"):
        run_upload(run_dir, FakeClient())


def test_https_is_required_before_the_token_can_leave(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    with pytest.raises(ValueError, match="https"):
        uploader.upload_run(run_dir, token="t", base_url="http://evil.example.com/api/v0")


def test_localhost_may_use_http(tmp_path):
    """So a local stub server works, matching the evidence uploader's exemption."""
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    original = uploader.ParamifyClient
    uploader.ParamifyClient = lambda *a, **k: FakeClient()
    try:
        summary = uploader.upload_run(run_dir, token="t", base_url="http://localhost:8080/api/v0")
    finally:
        uploader.ParamifyClient = original
    assert summary["ok"]


# --------------------------------------------------------------------------- #
# Error message quality — the requestId is what support needs
# --------------------------------------------------------------------------- #

def test_error_message_carries_paramifys_message_and_request_id():
    resp = FakeResponse(
        400,
        {"requestId": "req-123", "statusMessage": "Bad Request",
         "error": {"message": "unsupported file format"}},
    )
    msg = uploader._error_message(resp)
    assert "unsupported file format" in msg
    assert "req-123" in msg


def test_error_message_falls_back_to_body_text_on_non_json():
    resp = FakeResponse(500, _NO_JSON, text="upstream exploded")
    assert "upstream exploded" in uploader._error_message(resp)


@pytest.mark.parametrize("status,error_type,expected", [
    (400, "AssessmentRefused", "file intake preset"),
    (404, "AssessmentRefused", "not found"),
    (401, "AccessDenied", "PIPELINE_INTAKE"),
    (403, "AccessDenied", "PIPELINE_CLOSE"),
    (409, "NoCycleInProgress", "no cycle in progress"),
    (501, "IntakeNotEnabled", "not enabled"),
    (500, "ParamifyError", "failed"),
])
def test_http_errors_explain_themselves(status, error_type, expected):
    client = uploader.ParamifyClient("t", "https://example.test/api/v0")
    client.session = FakeSession([FakeResponse(status, {"error": {"message": "x"}})])
    with pytest.raises(getattr(uploader, error_type), match=expected):
        client.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})
