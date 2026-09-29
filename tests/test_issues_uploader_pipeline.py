"""Opt-in pipeline intake for the issue-report uploader.

`intake_api: pipeline` on a manifest entry routes a report to
POST /pipelines/{assessmentId}/intake instead of POST /assessment/{id}/intake,
and `pipeline_operation` asks Paramify to PROCESS (or PROCESS_CLOSE) the cycle in
the same request. A record without either field must behave exactly as before.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from framework.issue_reports import build_record, reserved_config_schema

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "issues_uploader_pipeline_under_test", REPO_ROOT / "uploaders" / "paramify_issues" / "uploader.py")
uploader = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uploader)

ASSESSMENT = "123e4567-e89b-12d3-a456-426614174000"
RAW = b"Record ID,Result\r\ncf-1:V-1,FAIL \r\n"


class Resp:
    def __init__(self, status=201, body=None, text=""):
        self.status_code = status
        self._body = body if body is not None else {"artifact": {"id": "art-9"}, "job": {"id": "job-7"}}
        self.text = text

    def json(self):
        return self._body


class Session:
    def __init__(self, resp=None):
        self.headers = {}
        self.posts = []
        self.resp = resp or Resp()

    def post(self, url, files=None, timeout=None):
        self.posts.append({"url": url, "files": files})
        return self.resp


def make_run(tmp_path, **extra):
    run = tmp_path / "run-R"
    d = run / "issue-reports"
    d.mkdir(parents=True)
    (d / "wiz_stig.csv").write_bytes(RAW)
    rec = {"file": "wiz_stig.csv", "fetcher_name": "wiz_stig_compliance_report", "fetcher_version": "0.1.0",
           "run_id": "R", "target": {"framework": "wf-id-305"}, "collected_at": "2026-09-24T00:00:00Z",
           "status": "success", "exit_code": 0, "format": "csv", "title": "Wiz STIG Compliance",
           "assessment_id": ASSESSMENT, "sha256": "x", "bytes": len(RAW), **extra}
    (d / "_issue_reports.json").write_text(json.dumps({"schema_version": "1.0", "run_id": "R", "reports": [rec]}))
    return run


def upload(run, session, **kw):
    original = uploader.requests.Session
    uploader.requests.Session = lambda: session
    try:
        return uploader.upload_run(run, token="t", base_url="https://example.test/api/v0", **kw)
    finally:
        uploader.requests.Session = original


def test_default_is_still_the_assessment_endpoint(tmp_path):
    s = Session(Resp(200, {"artifacts": [{"id": "a1"}]}))
    summary = upload(make_run(tmp_path), s)
    assert s.posts[0]["url"] == f"https://example.test/api/v0/assessment/{ASSESSMENT}/intake"
    assert "operation" not in json.loads(s.posts[0]["files"]["artifact"][1])
    assert summary["uploaded"] == 1 and "intake_api" not in summary["results"][0]


def test_pipeline_endpoint_with_process(tmp_path):
    s = Session()
    summary = upload(make_run(tmp_path, intake_api="pipeline", pipeline_operation="PROCESS"), s)
    post = s.posts[0]
    assert post["url"] == f"https://example.test/api/v0/pipelines/{ASSESSMENT}/intake"
    assert post["files"]["file"][1] == RAW  # bytes untouched
    meta = json.loads(post["files"]["artifact"][1])
    assert meta["operation"] == "PROCESS" and meta["title"] == "Wiz STIG Compliance"
    r = summary["results"][0]
    assert r["outcome"] == "uploaded" and r["artifact_id"] == "art-9" and r["job_id"] == "job-7"
    log = json.loads((tmp_path / "run-R" / "issue-reports" / "_intake_log.json").read_text())
    assert any(v.get("job_id") == "job-7" for v in (log.get("uploaded") or log).values() if isinstance(v, dict))


def test_pipeline_without_operation_only_attaches(tmp_path):
    s = Session(Resp(201, {"artifact": {"id": "art-1"}, "job": None}))
    summary = upload(make_run(tmp_path, intake_api="pipeline"), s)
    assert "operation" not in json.loads(s.posts[0]["files"]["artifact"][1])
    assert summary["results"][0]["job_id"] is None


def test_pipeline_rerun_is_deduplicated(tmp_path):
    run = make_run(tmp_path, intake_api="pipeline", pipeline_operation="PROCESS")
    upload(run, Session())
    s = Session()
    summary = upload(run, s)
    assert s.posts == [] and summary["skipped_duplicate"] == 1


def test_operation_without_pipeline_is_refused(tmp_path):
    s = Session()
    summary = upload(make_run(tmp_path, pipeline_operation="PROCESS"), s)
    assert s.posts == [] and summary["errors"] == 1


def test_unknown_intake_api_is_refused(tmp_path):
    s = Session()
    summary = upload(make_run(tmp_path, intake_api="pipelines"), s)
    assert s.posts == [] and summary["errors"] == 1


def test_config_override_can_switch_to_pipeline(tmp_path):
    s = Session()
    upload(make_run(tmp_path), s, config={"overrides": {"wiz_stig_compliance_report": {"intake_api": "pipeline"}}})
    assert "/pipelines/" in s.posts[0]["url"]


def test_dry_run_names_the_pipeline(tmp_path):
    summary = upload(make_run(tmp_path, intake_api="pipeline", pipeline_operation="PROCESS"), Session(),
                     dry_run=True)
    assert summary["results"][0]["intake_api"] == "pipeline"


@pytest.mark.parametrize("status,expected", [
    (400, "file intake preset"), (403, "PIPELINE_PROCESS"), (404, "not found"), (500, "HTTP 500")])
def test_pipeline_errors_explain_themselves(tmp_path, status, expected):
    summary = upload(make_run(tmp_path, intake_api="pipeline", pipeline_operation="PROCESS"),
                     Session(Resp(status, {"message": "nope"})))
    assert summary["errors"] == 1 and expected in summary["results"][0]["error"]


def test_reserved_fields_declared_and_only_recorded_when_set(tmp_path):
    schema = reserved_config_schema()
    assert {"intake_api", "pipeline_operation"} <= set(schema)
    assert not any(f.required for f in schema.values())

    class Result:
        fetcher_name, fetcher_version, target, completed_at, exit_code = "f", "0.1.0", None, "t", 0

    class Fetcher:
        category, output_type, issue_report = "wiz", "csv", None

    (tmp_path / "issue-reports").mkdir()
    plain = build_record("x.csv", Result, Fetcher, "R", tmp_path, {"assessment_id": "a"})
    assert "intake_api" not in plain and "pipeline_operation" not in plain
    piped = build_record("x.csv", Result, Fetcher, "R", tmp_path,
                         {"assessment_id": "a", "intake_api": "pipeline", "pipeline_operation": "PROCESS"})
    assert piped["intake_api"] == "pipeline" and piped["pipeline_operation"] == "PROCESS"
