"""Tests for the issue-report uploader (uploaders/paramify_issues/uploader.py).

Like the evidence uploader this pushes real customer data, so we mock ONLY the
HTTP boundary and let the uploader's own logic run. Two behaviors get the most
attention because they are the ones that cause damage rather than an error:

  - **the bytes.** The multipart body must carry the file exactly as it is on
    disk. A parse-and-rewrite would produce a file Paramify's intake can still
    open but reads differently, which is worse than a rejection.
  - **the dedup log.** The endpoint documents that it ADDS to a cycle's intake
    without replacing, and offers no way to list what is attached, so the local
    log is the only thing that makes a re-run safe. If it stops being honoured,
    every re-run doubles the issues from a scan.

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
# CRLF, a BOM and a trailing space: all survive a byte copy, none survive a
# parse-and-rewrite.
RAW_CSV = b"\xef\xbb\xbfPlugin ID,Severity\r\n19506,Info \r\n"


# --------------------------------------------------------------------------- #
# Fakes for the HTTP boundary
# --------------------------------------------------------------------------- #

class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = {"artifacts": [{"id": "art-1"}]} if json_data is None else json_data
        self.text = text

    def json(self):
        if self._json is _NO_JSON:
            raise ValueError("not json")
        return self._json


_NO_JSON = object()


class FakeSession:
    """Drop-in for requests.Session that records every multipart post."""

    def __init__(self, responses=None):
        self.headers = {}
        self.posts = []
        self._responses = list(responses or [])

    def post(self, url, files=None, timeout=None):
        self.posts.append({"url": url, "files": files})
        if self._responses:
            return self._responses.pop(0)
        return FakeResponse()


class FakeClient:
    """Drop-in for ParamifyClient at the upload_run level."""

    def __init__(self, *, fail_files=(), raise_501_on=None):
        self.fail_files = set(fail_files)
        self.raise_501_on = raise_501_on
        self.sent = []

    def submit_intake(self, assessment_id, filename, content, content_type, meta):
        if filename == self.raise_501_on:
            raise uploader.IntakeNotEnabled("intake is not enabled (HTTP 501)")
        if filename in self.fail_files:
            raise uploader.ParamifyError(f"HTTP 500 on {filename}")
        self.sent.append({
            "assessment_id": assessment_id, "file": filename, "content": content,
            "content_type": content_type, "meta": meta,
        })
        return {"artifacts": [{"id": f"art-{filename}"}]}


def make_run(tmp_path, reports, *, run_id="RID") -> Path:
    """Build a run dir with an issue-reports/ subdir and a sidecar index.

    `reports` is a list of dicts: {name, body?, assessment_id?, status?, format?}
    """
    run_dir = tmp_path / f"run-{run_id}"
    reports_dir = run_dir / "issue-reports"
    reports_dir.mkdir(parents=True)
    records = []
    for spec in reports:
        name = spec["name"]
        body = spec.get("body", RAW_CSV)
        if spec.get("on_disk", True):
            (reports_dir / name).write_bytes(body)
        records.append({
            "file": name,
            "fetcher_name": spec.get("fetcher_name", "t_scan"),
            "fetcher_version": "0.1.0",
            "run_id": run_id,
            "target": spec.get("target"),
            "collected_at": spec.get("collected_at", "2026-07-01T00:00:00Z"),
            "status": spec.get("status", "success"),
            "exit_code": 0 if spec.get("status", "success") == "success" else 1,
            "format": spec.get("format", "csv"),
            "title": spec.get("title", name),
            "assessment_id": spec.get("assessment_id", ASSESSMENT),
            "assessment_name": "Monthly Scan",
            "assessment_type": "VULNERABILITY",
            "sha256": "deadbeef",
            "bytes": len(body),
        })
    (reports_dir / "_issue_reports.json").write_text(
        json.dumps({"schema_version": "1.0", "run_id": run_id, "reports": records})
    )
    return run_dir


def run_upload(run_dir, client=None, **kwargs):
    """upload_run with the client injected and a token/base_url that pass the guards."""
    if client is not None:
        kwargs["_client"] = client
    return _upload(run_dir, **kwargs)


def _upload(run_dir, *, _client=None, config=None, dry_run=False, force=False, monkeypatch=None):
    if _client is not None:
        # Patch the class so upload_run's own construction yields our fake.
        original = uploader.ParamifyClient
        uploader.ParamifyClient = lambda *a, **k: _client
        try:
            return uploader.upload_run(
                run_dir, config=config, token="t", base_url="https://example.test/api/v0",
                dry_run=dry_run, force=force,
            )
        finally:
            uploader.ParamifyClient = original
    return uploader.upload_run(
        run_dir, config=config, token="t", base_url="https://example.test/api/v0",
        dry_run=dry_run, force=force,
    )


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
    client.submit_intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {"title": "T"})

    files = session.posts[0]["files"]
    assert files["file"][1] == RAW_CSV, "the report was altered before upload"
    assert files["file"][2] == "text/csv"


def test_url_follows_the_spec():
    session = FakeSession()
    client = uploader.ParamifyClient("token-abc", "https://example.test/api/v0")
    client.session = session
    client.submit_intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})
    assert session.posts[0]["url"] == (
        f"https://example.test/api/v0/assessment/{ASSESSMENT}/intake"
    )


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
    client.submit_intake(ASSESSMENT, "scan report #1.csv", RAW_CSV, "text/csv", {})
    sent_name = session.posts[0]["files"]["file"][0]
    assert " " not in sent_name and "#" not in sent_name
    assert sent_name == "scan%20report%20%231.csv"


def test_artifact_part_is_sent_and_is_json():
    """The endpoint requires the `artifact` part even though every field in it is
    optional, so omitting it would fail every upload."""
    session = FakeSession()
    client = uploader.ParamifyClient("t", "https://example.test/api/v0")
    client.session = session
    client.submit_intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv",
                         {"title": "T", "note": "n", "effectiveDate": "2026-07-01T00:00:00Z"})
    part = session.posts[0]["files"]["artifact"]
    assert part[2] == "application/json"
    assert json.loads(part[1])["title"] == "T"


def test_effective_date_is_the_collection_time_not_now(tmp_path):
    """The endpoint routes an artifact to the cycle its effective date falls in,
    so re-uploading an old run must land in that run's cycle."""
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
# Dedup — the only thing making a re-run safe
# --------------------------------------------------------------------------- #

def test_second_run_does_not_re_upload(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    first = FakeClient()
    assert run_upload(run_dir, first)["uploaded"] == 1

    second = FakeClient()
    summary = run_upload(run_dir, second)
    assert summary["uploaded"] == 0
    assert summary["skipped_duplicate"] == 1
    assert second.sent == [], "a re-run would have duplicated every issue in the report"


def test_force_reuploads_despite_the_log(tmp_path):
    """--force is the supported way to re-send; deleting the log would also
    re-send every other file in the run."""
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    first = FakeClient()
    run_upload(run_dir, first)
    second = FakeClient()
    summary = run_upload(run_dir, second, force=True)
    assert summary["uploaded"] == 1
    assert summary["skipped_duplicate"] == 0
    assert len(second.sent) == 1
    assert second.sent[0]["content"] == RAW_CSV


def test_intake_log_is_written_per_file(tmp_path):
    """Written after each file, not once at the end: a batch that dies halfway
    through must not re-send what it already sent."""
    run_dir = make_run(tmp_path, [{"name": "a.csv"}, {"name": "b.csv"}])
    client = FakeClient(raise_501_on="b.csv")
    run_upload(run_dir, client)

    log = json.loads((run_dir / "issue-reports" / "_intake_log.json").read_text())
    keys = list(log["uploaded"])
    assert len(keys) == 1 and keys[0].endswith("|a.csv")


def test_a_different_assessment_is_not_a_duplicate(tmp_path):
    """Pointing the manifest at another assessment and re-running should send the
    report again — a different destination is not a duplicate."""
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    run_upload(run_dir, FakeClient())

    other = "99999999-9999-4999-8999-999999999999"
    client = FakeClient()
    summary = run_upload(run_dir, client, config={"overrides": {"t_scan": {"assessment_id": other}}})
    assert summary["uploaded"] == 1
    assert client.sent[0]["assessment_id"] == other


def test_dry_run_sends_nothing_and_writes_no_log(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    client = FakeClient()
    summary = _upload(run_dir, _client=client, dry_run=True)
    assert client.sent == []
    assert summary["results"][0]["outcome"] == "would_upload"
    assert not (run_dir / "issue-reports" / "_intake_log.json").exists()


def test_corrupt_intake_log_refuses_rather_than_re_uploading(tmp_path):
    """Treating an unreadable log as empty would silently duplicate everything."""
    run_dir = make_run(tmp_path, [{"name": "scan.csv"}])
    (run_dir / "issue-reports" / "_intake_log.json").write_text("{not json")
    with pytest.raises(ValueError, match="already intaken"):
        _upload(run_dir, _client=FakeClient())


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


def test_501_halts_the_batch(tmp_path):
    """Workspace-wide, not per-file: every remaining report would fail the same
    way, so it stops instead of emitting one identical error per report."""
    run_dir = make_run(tmp_path, [{"name": "a.csv"}, {"name": "b.csv"}, {"name": "c.csv"}])
    client = FakeClient(raise_501_on="a.csv")
    summary = run_upload(run_dir, client)
    assert summary["errors"] == 1
    assert len(summary["results"]) == 1, "the batch kept going after a 501"
    assert "halted" in summary
    assert not summary["ok"]


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


def test_failed_collection_can_be_opted_in(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "scan.csv", "status": "failed"}])
    client = FakeClient()
    summary = run_upload(run_dir, client, config={"skip_failed": False})
    assert summary["uploaded"] == 1


def test_report_listed_but_missing_from_disk_is_an_error(tmp_path):
    run_dir = make_run(tmp_path, [{"name": "gone.csv", "on_disk": False}])
    client = FakeClient()
    summary = run_upload(run_dir, client)
    assert summary["errors"] == 1
    assert "not on disk" in summary["results"][0]["reason"]


def test_run_with_no_sidecar_is_refused_clearly(tmp_path):
    """An evidence-only run has no index; the uploader must say so rather than
    scanning a directory of unknown files."""
    run_dir = tmp_path / "run-empty"
    run_dir.mkdir()
    with pytest.raises(ValueError, match="collected no issue reports"):
        _upload(run_dir, _client=FakeClient())


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
        summary = uploader.upload_run(
            run_dir, token="t", base_url="http://localhost:8080/api/v0"
        )
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


@pytest.mark.parametrize("status,expected", [
    (404, "not found"),
    (401, "write scope"),
    (403, "write scope"),
    (500, "failed"),
])
def test_http_errors_explain_themselves(status, expected):
    client = uploader.ParamifyClient("t", "https://example.test/api/v0")
    client.session = FakeSession([FakeResponse(status, {"error": {"message": "x"}})])
    with pytest.raises(uploader.ParamifyError, match=expected):
        client.submit_intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})


def test_501_raises_its_own_type():
    """A distinct type so upload_run can stop the batch instead of retrying 200
    reports against a workspace where intake is switched off."""
    client = uploader.ParamifyClient("t", "https://example.test/api/v0")
    client.session = FakeSession([FakeResponse(501, {"error": {"message": "off"}})])
    with pytest.raises(uploader.IntakeNotEnabled):
        client.submit_intake(ASSESSMENT, "scan.csv", RAW_CSV, "text/csv", {})
