"""The pipeline endpoints over the real Client, against a scripted HTTP session.

What reaches the wire matters most: the report's exact bytes, no `operation` on
an intake (it would sweep every unprocessed file on the cycle), the URL-encoded
filename, and a failure whose type says how far it reaches.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.paramify import pipelines as pl
from framework.paramify.client import Client

BASE = "https://api.example.test"
ASSESSMENT = "123e4567-e89b-12d3-a456-426614174000"
RAW_CSV = b"\xef\xbb\xbfPlugin ID,Severity\r\n19506,Info \r\n"


class Reply:
    def __init__(self, status=201, body=None, text=None):
        self.status_code = status
        self.text = text if text is not None else json.dumps(
            {"artifact": {"id": "art-1"}, "job": None} if body is None else body)
        self.headers = {}

    def json(self):
        return json.loads(self.text)


class Session:
    """Answers from `replies` in order (the last repeats) and records every request."""

    def __init__(self, *replies):
        self.headers = {}
        self.replies = list(replies) or [Reply()]
        self.sent = []

    def request(self, method, url, params=None, json=None, files=None, timeout=None):
        self.sent.append({"method": method, "path": url[len(BASE):], "json": json, "files": files,
                          "timeout": timeout})
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


def _pipelines(*replies):
    session = Session(*replies)
    return pl.Pipelines(Client("t", BASE, session=session, sleep=lambda _s: None)), session


def test_the_report_is_posted_byte_for_byte_with_its_content_type():
    p, session = _pipelines()
    p.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {"title": "T"})
    part = session.sent[0]["files"]["file"]
    assert part[1] == RAW_CSV, "the report was altered before upload"
    assert part[2] == "text/csv"


def test_intake_goes_to_the_pipeline_with_no_operation():
    p, session = _pipelines()
    p.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {"title": "T"})
    assert session.sent[0]["path"] == f"/pipelines/{ASSESSMENT}/intake"
    meta = json.loads(session.sent[0]["files"]["artifact"][1])
    assert "operation" not in meta and "cycle" not in meta


def test_the_artifact_part_is_sent_and_is_json():
    """The endpoint requires it even though every field in it is optional."""
    p, session = _pipelines()
    p.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {"title": "T", "note": "n"})
    part = session.sent[0]["files"]["artifact"]
    assert part[2] == "application/json" and json.loads(part[1])["title"] == "T"


def test_the_filename_is_url_encoded():
    """The spec: "filenames containing certain special characters may cause upload
    errors. URL-encode your filename"."""
    p, session = _pipelines()
    p.intake(ASSESSMENT, "scan report #1.csv", RAW_CSV, "text/csv", {})
    assert session.sent[0]["files"]["file"][0] == "scan%20report%20%231.csv"


def test_intake_returns_the_artifact():
    p, _ = _pipelines(Reply(201, {"artifact": {"id": "a-9"}, "job": None}))
    assert p.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})["id"] == "a-9"


def test_an_intake_without_an_artifact_id_is_an_error():
    """Unnamed, the file could never be processed while the run said ok."""
    p, _ = _pipelines(Reply(201, {"artifact": {}, "job": None}))
    with pytest.raises(pl.PipelineError, match="no artifact id"):
        p.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})


def test_process_names_the_artifacts_and_the_operation():
    p, session = _pipelines(Reply(202, {"id": "job-1", "status": "QUEUED"}))
    job = p.process(ASSESSMENT, ["a-1", "a-2"], pl.PROCESS)
    assert session.sent[0]["path"] == f"/pipelines/{ASSESSMENT}/process"
    assert session.sent[0]["json"] == {"artifactIds": ["a-1", "a-2"], "operation": "PROCESS"}
    assert job["id"] == "job-1"


@pytest.mark.parametrize("call", ["close", "retry_job", "cancel_job"])
def test_bodyless_posts_send_no_body(call):
    p, session = _pipelines(Reply(202, {"id": "job-1"}))
    getattr(p, call)("x")
    assert session.sent[0]["method"] == "POST" and session.sent[0]["json"] is None


@pytest.mark.parametrize("status, error_type, expected", [
    (400, pl.AssessmentRefused, "file intake preset"),
    (404, pl.AssessmentRefused, "not found"),
    (401, pl.AccessDenied, "PIPELINE_INTAKE"),
    (403, pl.AccessDenied, "PIPELINE_CLOSE"),
    (409, pl.NoCycleInProgress, r"refused .* \(HTTP 409\): x"),
    (501, pl.IntakeNotEnabled, "not enabled"),
    (500, pl.PipelineError, "failed"),
])
def test_http_errors_explain_themselves(status, error_type, expected):
    p, _ = _pipelines(Reply(status, {"error": {"message": "x"}}))
    with pytest.raises(error_type, match=expected):
        p.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})


def test_an_error_carries_paramifys_message_and_request_id():
    """The requestId is what support needs to find the failure."""
    p, _ = _pipelines(Reply(400, {"requestId": "req-123", "statusMessage": "Bad Request",
                                  "error": {"message": "unsupported file format"}}))
    with pytest.raises(pl.AssessmentRefused) as e:
        p.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})
    assert "unsupported file format" in str(e.value) and "req-123" in str(e.value)


def test_an_error_falls_back_to_the_body_text_when_it_is_not_json():
    p, _ = _pipelines(Reply(500, text="upstream exploded"))
    with pytest.raises(pl.PipelineError, match="upstream exploded"):
        p.process(ASSESSMENT, ["a-1"], pl.PROCESS)


def test_a_failed_job_poll_is_retried():
    """A poll is a GET, so retrying it is safe, unlike an intake."""
    p, _ = _pipelines(Reply(502, text="bad gateway"), Reply(200, {"id": "job-1", "status": "COMPLETED"}))
    job, timed_out = pl.wait_for_job(p, "job-1", timeout=300)
    assert job["status"] == "COMPLETED" and not timed_out


def test_an_intake_that_fails_is_not_repeated():
    """An upload that may have landed must not be sent twice: intake adds an
    artifact every time."""
    p, session = _pipelines(Reply(502, text="bad gateway"), Reply())
    with pytest.raises(pl.PipelineError):
        p.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})
    assert len(session.sent) == 1


def test_only_an_upload_waits_the_long_timeout():
    """A report can be hundreds of MB; a job read that hangs must not hold the
    run for the same 10 minutes per attempt."""
    p, session = _pipelines(Reply(201, {"artifact": {"id": "a-1"}}), Reply(200, {"id": "job-1"}))
    p.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})
    p.get_job("job-1")
    assert session.sent[0]["timeout"] == pl.UPLOAD_TIMEOUT
    assert session.sent[1]["timeout"] == 30


def test_a_process_that_landed_with_an_unreadable_body_is_not_a_failure():
    """It queued: calling it a failure invites a re-run that processes the same
    artifacts twice."""
    p, _ = _pipelines(Reply(202, text="<html>ok</html>"))
    assert p.process(ASSESSMENT, ["a-1"], pl.PROCESS) == {}


def test_an_intake_that_landed_with_an_unreadable_body_warns_before_a_re_run():
    p, _ = _pipelines(Reply(201, text="<html>ok</html>"))
    with pytest.raises(pl.PipelineError, match="may be on the cycle unprocessed"):
        p.intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})


@pytest.mark.parametrize("body", [[], "ok", 3])
def test_a_body_that_is_not_an_object_reads_as_empty(body):
    p, _ = _pipelines(Reply(200, body))
    assert p.get_job("job-1") == {} and p.list_jobs() == [] and p.list_cycles(ASSESSMENT) == []


# --------------------------------------------------------------------------- #
# The api commands that act on pipelines directly
# --------------------------------------------------------------------------- #

@pytest.fixture
def workspace(monkeypatch, tmp_path):
    """`issues jobs` / `close` / `--retry` against a scripted session, with the
    token and base URL from the environment as a user would set them."""
    from framework import api
    session = Session(Reply(200, {"pipelineJobs": [{"id": "job-1", "status": "COMPLETED",
                                                    "assessmentId": ASSESSMENT}]}))
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "t")
    monkeypatch.setenv("PARAMIFY_API_BASE_URL", BASE)
    monkeypatch.setattr("framework.paramify.client.requests.Session", lambda: session)
    monkeypatch.setattr(api, "_upload_config", lambda root, path: None)
    return api, session


def test_issues_jobs_lists_the_workspaces_jobs(workspace):
    api, session = workspace
    [job] = api.issues_jobs(Path("."), assessment_id=ASSESSMENT)
    assert (job["job_id"], job["status"], job["assessment_id"]) == ("job-1", "COMPLETED", ASSESSMENT)
    assert session.sent[0]["path"] == "/pipeline-jobs"


def test_issues_close_queues_and_waits_on_the_close(workspace):
    api, session = workspace
    session.replies = [Reply(202, {"id": "job-9", "status": "QUEUED"}),
                       Reply(200, {"id": "job-9", "status": "COMPLETED"})]
    result = api.issues_close(Path("."), ASSESSMENT)
    assert result["status"] == "COMPLETED"
    assert [c["path"] for c in session.sent] == [f"/pipelines/{ASSESSMENT}/close", "/pipeline-jobs/job-9"]


def test_issues_job_action_retries_and_refuses_an_unknown_action(workspace):
    api, session = workspace
    session.replies = [Reply(202, {"id": "job-1", "status": "QUEUED"})]
    assert api.issues_job_action(Path("."), "job-1", "retry")["status"] == "QUEUED"
    assert session.sent[0]["path"] == "/pipeline-jobs/job-1/retry"
    with pytest.raises(ValueError, match="unknown job action"):
        api.issues_job_action(Path("."), "job-1", "explode")
