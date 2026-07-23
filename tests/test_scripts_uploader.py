"""Tests for the Paramify scripts uploader (uploaders/paramify_scripts/uploader.py).

Like the evidence uploader, this pushes to a real tenant, so we mock only the
HTTP boundary (a fake client) and let the reconcile logic run: the marker
round-trip, the create / update / drift / noop decision, the drift gate
(warn-skip vs --force), association on change, --reassociate, the https guard,
and per-fetcher error isolation.

The module isn't an importable package (loaded by path), so we do the same here.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_PATH = REPO_ROOT / "uploaders" / "paramify_scripts" / "uploader.py"
_spec = importlib.util.spec_from_file_location("scripts_uploader_under_test", _PATH)
uploader = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uploader)


# --------------------------------------------------------------------------- #
# Marker helpers
# --------------------------------------------------------------------------- #

def test_marker_roundtrip():
    desc = uploader.build_description("aws_vpc_flow_logs", "1.2.0", "deadbeef")
    m = uploader.parse_marker(desc)
    assert m["paramify-fetcher"] == "aws_vpc_flow_logs"
    assert m["version"] == "1.2.0"
    assert m["sha256"] == "deadbeef"


def test_code_hash_stable_and_sensitive():
    assert uploader.code_hash("abc") == uploader.code_hash("abc")
    assert uploader.code_hash("abc") != uploader.code_hash("abd")


# --------------------------------------------------------------------------- #
# Fake client at the sync_scripts boundary
# --------------------------------------------------------------------------- #

class FakeClient:
    def __init__(self, existing):
        # existing: list of {id, name, description}
        self._existing = existing
        self.created = []
        self.updated = []
        self.associated = []

    def list_scripts(self):
        return self._existing

    def create_script(self, name, description, code):
        sid = "sid-" + name
        self.created.append((sid, name))
        return {"id": sid, "name": name, "description": description, "code": code}

    def update_script(self, script_id, name, description, code):
        self.updated.append(script_id)
        return {"id": script_id}

    def get_or_create_evidence_set(self, reference_id, name):
        return "ev-" + reference_id

    def associate_script(self, evidence_id, script_id):
        self.associated.append((evidence_id, script_id))


SPECS = [
    {"fetcher_name": "f_new", "version": "1.0.0", "entry": "fetcher.py", "code": "NEW",
     "evidence_set": {"reference_id": "EVD-NEW", "name": "New"}},
    {"fetcher_name": "f_bump", "version": "2.0.0", "entry": "fetcher.py", "code": "BUMP",
     "evidence_set": {"reference_id": "EVD-BUMP", "name": "Bump"}},
    {"fetcher_name": "f_drift", "version": "1.0.0", "entry": "fetcher.py", "code": "NEWCODE",
     "evidence_set": {"reference_id": "EVD-DRIFT", "name": "Drift"}},
    {"fetcher_name": "f_noop", "version": "1.0.0", "entry": "fetcher.py", "code": "SAME",
     "evidence_set": {"reference_id": "EVD-NOOP", "name": "Noop"}},
]


def _existing_for_specs():
    """Tenant scripts: f_bump at an old version, f_drift at same version but old
    code, f_noop matching exactly. f_new is absent."""
    return [
        {"id": "sid-f_bump", "name": "Bump",
         "description": uploader.build_description("f_bump", "1.0.0", uploader.code_hash("BUMP"))},
        {"id": "sid-f_drift", "name": "Drift",
         "description": uploader.build_description("f_drift", "1.0.0", uploader.code_hash("OLDCODE"))},
        {"id": "sid-f_noop", "name": "Noop",
         "description": uploader.build_description("f_noop", "1.0.0", uploader.code_hash("SAME"))},
    ]


@pytest.fixture
def wired(monkeypatch):
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "test-token")
    monkeypatch.setattr(uploader, "_discover_specs", lambda root: list(SPECS))
    fake = FakeClient(_existing_for_specs())
    monkeypatch.setattr(uploader, "ParamifyScriptsClient", lambda token, base_url: fake)
    return fake


def _by_fetcher(summary):
    return {r["fetcher"]: r for r in summary["results"]}


def test_plan_actions_without_force(wired):
    summary = uploader.sync_scripts(".")
    r = _by_fetcher(summary)
    assert r["f_new"]["outcome"] == "create"
    assert r["f_bump"]["outcome"] == "update"
    assert r["f_drift"]["outcome"] == "drift_skipped"   # code changed, version didn't
    assert r["f_noop"]["outcome"] == "noop"
    assert summary["created"] == 1 and summary["updated"] == 1
    assert summary["drift"] == 1 and summary["noop"] == 1
    assert summary["ok"] is True


def test_association_only_on_change(wired):
    uploader.sync_scripts(".")
    associated_ids = {sid for _, sid in wired.associated}
    # create + update associate; drift (skipped) and noop do not. The created
    # script's id comes from create_script (called with the display name "New").
    assert associated_ids == {"sid-New", "sid-f_bump"}


def test_drift_pushed_with_force(wired):
    summary = uploader.sync_scripts(".", force=True)
    r = _by_fetcher(summary)
    assert r["f_drift"]["outcome"] == "drift"       # pushed, not skipped
    assert "sid-f_drift" in wired.updated
    assert ("ev-EVD-DRIFT", "sid-f_drift") in wired.associated


def test_reassociate_covers_noop(wired):
    uploader.sync_scripts(".", reassociate=True)
    associated_ids = {sid for _, sid in wired.associated}
    assert "sid-f_noop" in associated_ids   # noop normally skips association


def test_https_guard_rejects_http():
    with pytest.raises(ValueError):
        uploader.sync_scripts(".", base_url="http://not-secure.example.com", dry_run=True)


def test_error_isolation(monkeypatch):
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "test-token")
    monkeypatch.setattr(uploader, "_discover_specs", lambda root: list(SPECS))
    fake = FakeClient(_existing_for_specs())

    def boom(name, description, code):
        raise uploader.ParamifyError("kaboom")

    fake.create_script = boom  # f_new (the only create) blows up
    monkeypatch.setattr(uploader, "ParamifyScriptsClient", lambda token, base_url: fake)

    summary = uploader.sync_scripts(".")
    r = _by_fetcher(summary)
    assert r["f_new"]["outcome"] == "error"
    assert summary["errors"] == 1
    assert summary["ok"] is False
    # the other fetchers still processed
    assert r["f_bump"]["outcome"] == "update"
    assert r["f_noop"]["outcome"] == "noop"
