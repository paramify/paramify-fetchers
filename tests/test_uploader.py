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


class TagSession:
    """The session the Tagger posts default custom tags through: records every
    POST and answers with one scripted status (200 unless told otherwise)."""

    def __init__(self, status=200):
        self.status = status
        self.posts = []

    def post(self, url, json=None, timeout=None, **_):
        self.posts.append((url, json))
        return FakeResponse(self.status)


class FakeClient:
    """Drop-in for ParamifyClient at the upload_run level: lets us drive
    duplicate/partial-failure behavior without any HTTP."""

    def __init__(self, *, fail_files=(), existing=(), channels=(), tag_status=200):
        self.fail_files = set(fail_files)
        self.existing = set(existing)
        self.channels = list(channels)
        self.uploaded = []
        self.meta = {}
        self.session = TagSession(tag_status)

    def get_or_create_evidence_set(self, es):
        return {
            "id": "ev-" + es["reference_id"],
            "referenceId": es["reference_id"],
            "channels": self.channels,
        }

    def artifact_exists(self, evidence_id, filename, run_id):
        return filename in self.existing

    def upload_artifact(self, evidence_id, filename, content, meta):
        if filename in self.fail_files:
            raise uploader.ParamifyError(f"HTTP 500 on {filename}")
        self.uploaded.append(filename)
        self.meta[filename] = meta
        return {"id": "art-" + filename}


def channel(ref, *, stack="stack-1", id_=None):
    return {"id": id_ or f"ch-{ref}", "referenceId": ref, "stackId": stack,
            "owner": {"type": "team", "name": "Team 1"}}


def write_evidence(run_dir, name, *, reference_id="EVD-1", set_name="Set",
                   status="success", run_id="RID", target=None, enveloped=True,
                   category=None):
    if not enveloped:
        (run_dir / name).write_text(json.dumps({"just": "data"}))
        return
    env = {
        "schema_version": "1.0",
        "metadata": {
            "fetcher_name": "f", "fetcher_version": "0.1.0", "run_id": run_id,
            "collected_at": "2026-01-01T00:00:00Z", "status": status,
            "exit_code": 0 if status == "success" else 1,
            "evidence_set": {"reference_id": reference_id, "name": set_name},
        },
        "payload": {"k": 1},
    }
    if target:
        env["metadata"]["target"] = target
    if category:
        env["metadata"]["category"] = category
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


def test_find_returns_record_for_exact_reference_match():
    c = _client_with_session(get_handler=lambda url, params: FakeResponse(200, {"evidences": [
        {"id": "ev-other", "referenceId": "OTHER"},
        {"id": "ev-9", "referenceId": "EVD-9", "channels": [channel("CHN-001")]},
    ]}))
    found = c.find_evidence_set("EVD-9")
    # The whole record, not the bare id — the channels ride along on this call.
    assert found["id"] == "ev-9"
    assert found["channels"] == [channel("CHN-001")]


def test_get_or_create_uses_existing_and_never_posts():
    posts = []

    def post_handler(url, j, f):
        posts.append(url)
        return FakeResponse(201, {"id": "NEW"})

    c = _client_with_session(
        get_handler=lambda url, params: FakeResponse(200, {"evidences": [{"id": "ev-1", "referenceId": "EVD-1"}]}),
        post_handler=post_handler,
    )
    assert c.get_or_create_evidence_set({"reference_id": "EVD-1", "name": "n"})["id"] == "ev-1"
    assert posts == []   # found it; must not have tried to create


def test_create_on_400_already_exists_falls_back_to_find():
    # initial find -> None; create -> 400 "already exists"; fallback find -> id
    gets = [FakeResponse(200, {"evidences": []}),
            FakeResponse(200, {"evidences": [{"id": "ev-7", "referenceId": "EVD-1"}]})]
    c = _client_with_session(
        get_handler=lambda url, params: gets.pop(0),
        post_handler=lambda url, j, f: FakeResponse(400, text="Evidence already exists"),
    )
    assert c.get_or_create_evidence_set({"reference_id": "EVD-1", "name": "n"})["id"] == "ev-7"


def test_create_other_400_raises():
    c = _client_with_session(
        get_handler=lambda url, params: FakeResponse(200, {"evidences": []}),
        post_handler=lambda url, j, f: FakeResponse(400, text="validation: name required"),
    )
    with pytest.raises(uploader.ParamifyError):
        c.get_or_create_evidence_set({"reference_id": "EVD-1", "name": "n"})


def _created_body(es):
    bodies = []

    def post_handler(url, j, f):
        bodies.append(j)
        return FakeResponse(201, {"id": "NEW"})

    c = _client_with_session(
        get_handler=lambda url, params: FakeResponse(200, {"evidences": []}),
        post_handler=post_handler,
    )
    c.get_or_create_evidence_set(es)
    return bodies[0]


def test_create_sends_the_envelope_frequency():
    body = _created_body({"reference_id": "EVD-1", "name": "n", "frequency": "WEEKLY"})
    assert body["frequency"] == "WEEKLY"


def test_create_defaults_frequency_for_an_envelope_without_one():
    # A run directory written before the field existed must still create the set
    # with the default, not NOT_SET.
    body = _created_body({"reference_id": "EVD-1", "name": "n"})
    assert body["frequency"] == "THREE_DAY"


def test_override_replaces_frequency():
    metadata = {"fetcher_name": "f",
                "evidence_set": {"reference_id": "EVD-1", "name": "n", "frequency": "THREE_DAY"}}
    es = uploader.resolve_evidence_set(metadata, {"f": {"frequency": "MONTHLY"}})
    assert es["frequency"] == "MONTHLY"


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


# --------------------------------------------------------------------------- #
# resolve_channel — which channel an artifact is uploaded through
#
# An artifact uploaded outside a configured channel is invisible to validation on
# the solution capability, so a set that has a channel must use it — and a set
# with more than one is refused rather than guessed at.
# --------------------------------------------------------------------------- #

def test_no_channels_uploads_unchanneled():
    assert uploader.resolve_channel([]) is None
    assert uploader.resolve_channel(None) is None


def test_the_sets_channel_is_used_without_any_config():
    ch = channel("CHN-001")
    assert uploader.resolve_channel([ch]) == ch


def test_several_channels_is_refused_not_guessed():
    with pytest.raises(uploader.ChannelError, match="not supported yet"):
        uploader.resolve_channel([channel("CHN-001"), channel("CHN-002")])


def test_the_refusal_names_the_channels_it_found():
    with pytest.raises(uploader.ChannelError, match="CHN-001, CHN-002"):
        uploader.resolve_channel([channel("CHN-001"), channel("CHN-002")])


# --------------------------------------------------------------------------- #
# upload_run — the channel reaches the artifact metadata and the log
# --------------------------------------------------------------------------- #

def test_channel_id_is_sent_on_the_artifact(tmp_path, monkeypatch):
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json")
    fake = FakeClient(channels=[channel("CHN-001")])
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert fake.meta["a.json"]["channelId"] == "ch-CHN-001"
    assert summary["results"][0]["channel"] == "CHN-001"


def test_no_channel_sends_no_channel_id(tmp_path, monkeypatch):
    """A set with no channels uploads exactly as it did before: the key is absent,
    not null — the API treats them the same, but an absent key is what every
    customer without channels has been sending all along."""
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json")
    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert "channelId" not in fake.meta["a.json"]


def test_an_unroutable_set_errors_that_file_and_continues(tmp_path, monkeypatch):
    run_dir = tmp_path / "run-x"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json", reference_id="EVD-1")
    write_evidence(run_dir, "b.json", reference_id="EVD-1")
    fake = FakeClient(channels=[channel("CHN-001"), channel("CHN-002")])
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert summary["ok"] is False and summary["errors"] == 2 and summary["uploaded"] == 0
    assert fake.uploaded == []
    assert "channel" in summary["results"][0]["reason"]


def test_channel_id_rides_in_the_artifact_part_of_the_multipart_body():
    """The channel is only ever seen on the wire: it goes in the `artifact` JSON
    part, and no artifact response echoes it back. FakeClient can't catch a
    regression here because it never builds the request."""
    sent = {}

    def post_handler(url, j, files):
        sent["url"] = url
        sent["artifact"] = json.loads(files["artifact"][1])
        return FakeResponse(201, {"id": "art-1"})

    c = _client_with_session(post_handler=post_handler)
    meta = uploader.build_artifact_meta(
        {"fetcher_name": "f", "run_id": "R", "status": "success"}, "Set", channel_id="ch-1"
    )
    c.upload_artifact("ev-1", "a.json", b"{}", meta)

    assert sent["url"].endswith("/evidence/ev-1/artifacts/upload")
    assert sent["artifact"]["channelId"] == "ch-1"


# --------------------------------------------------------------------------- #
# Default custom tags — provenance + the category's display name, every run
# --------------------------------------------------------------------------- #

def _tag_posts(fake):
    return [(url.rsplit("/custom-tags/", 1)[1], body["names"]) for url, body in fake.session.posts]


@pytest.fixture(autouse=True)
def _no_ambient_tag_switch(monkeypatch):
    monkeypatch.delenv("PARAMIFY_CUSTOM_TAGS", raising=False)


def test_every_set_is_tagged_once_per_run(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json", reference_id="EVD-A", category="aws")
    write_evidence(run_dir, "b.json", reference_id="EVD-A", category="aws", run_id="RID2")
    write_evidence(run_dir, "c.json", reference_id="EVD-C", category="okta")
    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert summary["ok"]
    assert _tag_posts(fake) == [
        ("evidence/ev-EVD-A", ["Automated by Paramify Fetchers", "AWS"]),
        ("evidence/ev-EVD-C", ["Automated by Paramify Fetchers", "Okta"]),
    ]
    by_file = {r["file"]: r for r in summary["results"]}
    assert by_file["a.json"]["tags"] == by_file["b.json"]["tags"] == ["Automated by Paramify Fetchers", "AWS"]
    assert summary["tags"] == {
        "enabled": True, "reason": None,
        "provenance": "Automated by Paramify Fetchers", "service": True,
        "applied": 2, "failed": 0, "skipped": 0, "disabled": None,
    }


def test_duplicate_artifact_still_gets_the_set_tagged(tmp_path, monkeypatch):
    """Re-asserting on every run is what backfills sets from earlier runs."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json", reference_id="EVD-A", category="aws")
    fake = FakeClient(existing=("a.json",))
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert summary["results"][0]["outcome"] == "skipped_duplicate"
    assert summary["results"][0]["tags"] == ["Automated by Paramify Fetchers", "AWS"]
    assert len(fake.session.posts) == 1


def test_tags_config_renames_and_disables(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json", reference_id="EVD-A", category="aws")
    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    cfg = {"tags": {"provenance": "Robots", "service": False}}
    uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0", config=cfg)
    assert _tag_posts(fake) == [("evidence/ev-EVD-A", ["Robots"])]

    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)
    summary = uploader.upload_run(
        run_dir, token="tok", base_url="https://app.example.com/api/v0", config={"tags": False}
    )
    assert fake.session.posts == []
    assert summary["tags"]["enabled"] is False and "tags: false" in summary["tags"]["reason"]
    assert summary["results"][0]["tags"] == []


def test_env_switch_turns_tags_off_for_the_run(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json", reference_id="EVD-A", category="aws")
    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)
    monkeypatch.setenv("PARAMIFY_CUSTOM_TAGS", "off")

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert summary["ok"] and summary["uploaded"] == 1
    assert fake.session.posts == []
    assert summary["tags"] == {
        "enabled": False, "reason": "PARAMIFY_CUSTOM_TAGS=off", "provenance": None,
        "service": False, "applied": 0, "failed": 0, "skipped": 0, "disabled": None,
    }


def test_no_tags_switch_turns_tags_off_for_the_run(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json", reference_id="EVD-A", category="aws")
    fake = FakeClient()
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(
        run_dir, token="tok", base_url="https://app.example.com/api/v0", custom_tags=False
    )
    assert fake.session.posts == []
    assert summary["tags"]["enabled"] is False and summary["tags"]["reason"] == "--no-tags"
    assert summary["results"][0]["tags"] == []


def test_malformed_tags_block_is_a_setup_error(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json")
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: FakeClient())
    with pytest.raises(ValueError, match="unknown key"):
        uploader.upload_run(
            run_dir, token="tok", base_url="https://app.example.com/api/v0",
            config={"tags": {"provenence": "x"}},
        )


def test_missing_tag_permission_warns_and_upload_still_succeeds(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json", reference_id="EVD-A", category="aws")
    write_evidence(run_dir, "b.json", reference_id="EVD-B", category="aws")
    fake = FakeClient(tag_status=403)
    monkeypatch.setattr(uploader, "ParamifyClient", lambda token, base_url: fake)

    summary = uploader.upload_run(run_dir, token="tok", base_url="https://app.example.com/api/v0")

    assert summary["ok"] and summary["uploaded"] == 2
    assert len(fake.session.posts) == 1, "one refusal switches tagging off for the run"
    assert summary["tags"]["disabled"] and summary["tags"]["applied"] == 0
    assert all(r["tags"] == [] for r in summary["results"])


def test_dry_run_plans_tags_and_posts_nothing(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    write_evidence(run_dir, "a.json", reference_id="EVD-A", category="aws")
    summary = uploader.upload_run(
        run_dir, token="tok", base_url="https://app.example.com/api/v0", dry_run=True
    )
    assert summary["results"][0]["outcome"] == "would_upload"
    assert summary["results"][0]["tags"] == ["Automated by Paramify Fetchers", "AWS"]
    assert summary["tags"]["applied"] == 0
