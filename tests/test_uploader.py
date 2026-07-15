"""Tests for the Paramify evidence uploader (uploaders/paramify_evidence/uploader.py).

The uploader is the highest-stakes untested code: it pushes real customer
evidence to Paramify. We mock ONLY the HTTP boundary (a fake requests.Session /
a fake client) so the uploader's actual logic runs — get-or-create with the 400
fallback, the run_id token-boundary dedup, per-file partial-failure isolation,
the https guard, and the skip_failed default.

The module isn't an importable package (the CLI loads it by path), so we load it
the same way here.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
_UPLOADER_PATH = REPO_ROOT / "uploaders" / "paramify_evidence" / "uploader.py"
_spec = importlib.util.spec_from_file_location("uploader_under_test", _UPLOADER_PATH)
uploader = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uploader)


# --------------------------------------------------------------------------- #
# Fakes for the HTTP boundary
# --------------------------------------------------------------------------- #

class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = {} if json_data is None else json_data
        self.text = text

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))


class FakeSession:
    """Drop-in for requests.Session; scripted per test via get_handler/post_handler."""

    def __init__(self):
        self.headers = {}
        self.get_handler = None
        self.post_handler = None

    def get(self, url, params=None, timeout=None):
        return self.get_handler(url, params)

    def post(self, url, json=None, files=None, timeout=None):
        return self.post_handler(url, json, files)


class FakeClient:
    """Drop-in for ParamifyClient at the upload_run level: lets us drive
    duplicate/partial-failure behavior without any HTTP."""

    def __init__(self, *, fail_files=(), existing=()):
        self.fail_files = set(fail_files)
        self.existing = set(existing)
        self.uploaded = []

    def get_or_create_evidence_set(self, es):
        return "ev-" + es["reference_id"]

    def artifact_exists(self, evidence_id, filename, run_id):
        return filename in self.existing

    def upload_artifact(self, evidence_id, filename, content, meta):
        if filename in self.fail_files:
            raise uploader.ParamifyError(f"HTTP 500 on {filename}")
        self.uploaded.append(filename)
        return {"id": "art-" + filename}


def write_evidence(run_dir, name, *, reference_id="EVD-1", set_name="Set",
                   status="success", run_id="RID", target=None, enveloped=True,
                   exit_code=None, validation=None):
    if not enveloped:
        (run_dir / name).write_text(json.dumps({"just": "data"}))
        return
    env = {
        "schema_version": "1.0",
        "metadata": {
            "fetcher_name": "f", "fetcher_version": "0.1.0", "run_id": run_id,
            "collected_at": "2026-01-01T00:00:00Z", "status": status,
            "exit_code": exit_code if exit_code is not None else (0 if status == "success" else 1),
            "evidence_set": {"reference_id": reference_id, "name": set_name},
        },
        "payload": {"k": 1},
    }
    if validation is not None:
        env["metadata"]["validation"] = validation
    if target:
        env["metadata"]["target"] = target
    (run_dir / name).write_text(json.dumps(env))


# --------------------------------------------------------------------------- #
# ParamifyClient — get-or-create + the 400 "already exists" idempotency fallback
# --------------------------------------------------------------------------- #

def _client_with_session(get_handler=None, post_handler=None):
    c = uploader.ParamifyClient("tok", "https://app.example.com/api/v0")
    fs = FakeSession()
    fs.get_handler = get_handler
    fs.post_handler = post_handler
    c.session = fs
    return c


def test_find_returns_id_for_exact_reference_match():
    c = _client_with_session(get_handler=lambda url, params: FakeResponse(200, {"evidences": [
        {"id": "ev-other", "referenceId": "OTHER"},
        {"id": "ev-9", "referenceId": "EVD-9"},
    ]}))
    assert c.find_evidence_set("EVD-9") == "ev-9"


def test_get_or_create_uses_existing_and_never_posts():
    posts = []

    def post_handler(url, j, f):
        posts.append(url)
        return FakeResponse(201, {"id": "NEW"})

    c = _client_with_session(
        get_handler=lambda url, params: FakeResponse(200, {"evidences": [{"id": "ev-1", "referenceId": "EVD-1"}]}),
        post_handler=post_handler,
    )
    assert c.get_or_create_evidence_set({"reference_id": "EVD-1", "name": "n"}) == "ev-1"
    assert posts == []   # found it; must not have tried to create


def test_create_on_400_already_exists_falls_back_to_find():
    # initial find -> None; create -> 400 "already exists"; fallback find -> id
    gets = [FakeResponse(200, {"evidences": []}),
            FakeResponse(200, {"evidences": [{"id": "ev-7", "referenceId": "EVD-1"}]})]
    c = _client_with_session(
        get_handler=lambda url, params: gets.pop(0),
        post_handler=lambda url, j, f: FakeResponse(400, text="Evidence already exists"),
    )
    assert c.get_or_create_evidence_set({"reference_id": "EVD-1", "name": "n"}) == "ev-7"


def test_create_other_400_raises():
    c = _client_with_session(
        get_handler=lambda url, params: FakeResponse(200, {"evidences": []}),
        post_handler=lambda url, j, f: FakeResponse(400, text="validation: name required"),
    )
    with pytest.raises(uploader.ParamifyError):
        c.get_or_create_evidence_set({"reference_id": "EVD-1", "name": "n"})


# --------------------------------------------------------------------------- #
# artifact_exists — run_id is matched as a TOKEN, not a substring
# --------------------------------------------------------------------------- #

def test_artifact_exists_matches_run_id_on_token_boundary():
    c = _client_with_session(get_handler=lambda url, params: FakeResponse(200, {"artifacts": [
        {"originalFileName": "ev.json", "note": "fetcher=f; run_id=12; status=success"},
    ]}))
    # run_id "1" must NOT match the "run_id=12" token (the substring-bug guard)
    assert c.artifact_exists("ev-1", "ev.json", "1") is False
    # the exact token matches
    assert c.artifact_exists("ev-1", "ev.json", "12") is True
    # filename mismatch never matches
    assert c.artifact_exists("ev-1", "other.json", "12") is False
    # no run_id -> never dedups (always re-uploads)
    assert c.artifact_exists("ev-1", "ev.json", None) is False


# --------------------------------------------------------------------------- #
# upload_run — partial-failure isolation, dedup, skip_failed, https guard
# --------------------------------------------------------------------------- #

def test_partial_failure_uploads_good_files_and_reports_not_ok(tmp_path, monkeypatch):
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "good.json")
    write_evidence(run_dir, "bad.json")          # sorts first; fails
    fake = FakeClient(fail_files={"bad.json"})
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert summary["ok"] is False
    assert summary["uploaded"] == 1 and summary["errors"] == 1
    assert "good.json" in fake.uploaded and "bad.json" not in fake.uploaded   # batch continued


def test_unenveloped_file_is_error_but_batch_continues(tmp_path, monkeypatch):
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "ok.json")
    write_evidence(run_dir, "raw.json", enveloped=False)
    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert summary["errors"] == 1 and summary["uploaded"] == 1
    assert "ok.json" in fake.uploaded


def test_existing_artifact_is_skipped_as_duplicate(tmp_path, monkeypatch):
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json")
    fake = FakeClient(existing={"a.json"})
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert summary["skipped_duplicate"] == 1 and summary["uploaded"] == 0
    assert fake.uploaded == []


def test_skip_failed_skips_failed_status(tmp_path, monkeypatch):
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "f.json", status="failed")
    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0",
                                  config={"skip_failed": True})

    assert summary["skipped_failed"] == 1 and summary["uploaded"] == 0
    assert fake.uploaded == []


def test_failed_status_uploads_by_default(tmp_path, monkeypatch):
    """Characterizes the documented default: skip_failed is off, so a
    failed-status file IS uploaded (flagged failed) unless the operator opts in."""
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "f.json", status="failed")
    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert summary["uploaded"] == 1 and "f.json" in fake.uploaded


# --------------------------------------------------------------------------- #
# Schema-validation holds — eligibility filter for the verify stage
# --------------------------------------------------------------------------- #

def _failed_validation(schema_id="https://fixtures.paramify.invalid/schemas/sample-report.json"):
    return {
        "schema_id": schema_id, "pinned_version": "1.0.0",
        "validator": "jsonschema 4.23.0", "ok": False,
        "errors": [{"path": "/report_id", "message": "does not match pattern"}],
        "error_count": 1,
    }


def test_schema_failed_artifact_is_held_but_siblings_upload(tmp_path, monkeypatch):
    """Required case 6, uploader half: one held artifact never blocks the rest
    of the run, and the hold is reported distinctly from a generic error."""
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "bad.json", status="failed", exit_code=2,
                   validation=_failed_validation())
    write_evidence(run_dir, "good_a.json", reference_id="EVD-A")
    write_evidence(run_dir, "good_b.json", reference_id="EVD-B")
    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert sorted(fake.uploaded) == ["good_a.json", "good_b.json"]   # batch continued
    assert summary["held_validation"] == 1 and summary["uploaded"] == 2
    assert summary["errors"] == 0 and summary["ok"] is True   # a hold is not an error
    assert summary["held"] == [{"file": "bad.json",
                                "reason": summary["held"][0]["reason"]}]
    assert "failed schema validation" in summary["held"][0]["reason"]
    held_result = next(r for r in summary["results"] if r["file"] == "bad.json")
    assert held_result["outcome"] == "held_validation"


def test_passing_validation_block_uploads_normally(tmp_path, monkeypatch):
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    ok_validation = dict(_failed_validation(), ok=True, errors=[], error_count=0)
    write_evidence(run_dir, "a.json", validation=ok_validation)
    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert summary["uploaded"] == 1 and summary["held_validation"] == 0


def test_fetcher_own_exit_2_without_validation_block_is_not_held(tmp_path, monkeypatch):
    """A fetcher that exits 2 on its OWN (collection failure, no validation
    block) is an ordinary failed artifact, not a schema hold — the envelope's
    validation block is the authoritative signal, not the bare exit code."""
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "f.json", status="failed", exit_code=2)   # no validation block
    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert summary["held_validation"] == 0
    assert summary["uploaded"] == 1   # default skip_failed=False uploads failed files


def test_dry_run_reports_hold_not_would_upload(tmp_path):
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "bad.json", status="failed", exit_code=2,
                   validation=_failed_validation())
    write_evidence(run_dir, "good.json", reference_id="EVD-G")

    summary = uploader.upload_run(run_dir, base_url="https://app.example.com/api/v0",
                                  dry_run=True)

    outcomes = {r["file"]: r["outcome"] for r in summary["results"]}
    assert outcomes == {"bad.json": "held_validation", "good.json": "would_upload"}


def test_https_guard_rejects_http_remote(tmp_path):
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json")
    with pytest.raises(ValueError, match="https"):
        uploader.upload_run(run_dir, token="tok", base_url="http://evil.example.com", dry_run=True)


def test_https_guard_allows_localhost_http(tmp_path):
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json")
    # dry_run keeps it API-call-free; the point is the guard does NOT reject localhost http
    summary = uploader.upload_run(run_dir, base_url="http://localhost:8080", dry_run=True)
    assert summary["dry_run"] is True and summary["files"] == 1


def test_empty_run_dir_raises(tmp_path):
    run_dir = tmp_path / "run-empty"
    run_dir.mkdir()
    with pytest.raises(ValueError, match="no evidence files"):
        uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0", dry_run=True)
