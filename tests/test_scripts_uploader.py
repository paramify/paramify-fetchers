"""Tests for the Paramify scripts uploader (uploaders/paramify_scripts/uploader.py).

Like the evidence uploader, this pushes to a real tenant, so only the HTTP
boundary is faked (the shared fake workspace behind the real Client) and the
reconcile logic runs: the create / update / drift / noop decision, the drift
gate (warn-skip vs --force), association on change, --reassociate, the https
guard, per-fetcher error isolation, and the default custom tags. Assertions are
on what ends up in the workspace.

The module isn't an importable package (loaded by path), so we do the same here.
"""

from __future__ import annotations

import importlib.util
from datetime import date
from pathlib import Path

import pytest

from framework.paramify.client import Client
from tests.paramify_fake import FakeParamify

REPO_ROOT = Path(__file__).resolve().parent.parent
_PATH = REPO_ROOT / "uploaders" / "paramify_scripts" / "uploader.py"
_spec = importlib.util.spec_from_file_location("scripts_uploader_under_test", _PATH)
uploader = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uploader)

PROVENANCE = "Automated by Paramify Fetchers"

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


def _workspace() -> FakeParamify:
    """f_bump at an old version, f_drift at the same version but old code, f_noop
    matching exactly; f_new absent. Scripts are named after their fetcher."""
    fake = FakeParamify()
    for name, version, code in (("f_bump", "1.0.0", "BUMP"), ("f_drift", "1.0.0", "OLDCODE"),
                                ("f_noop", "1.0.0", "SAME")):
        fake.add_script(name, uploader.build_description(name, version, uploader.code_hash(code)))
    return fake


def _client(fake: FakeParamify) -> Client:
    return Client("tok", "https://api.example.test", session=fake.session, sleep=lambda _s: None)


def _sync(fake: FakeParamify, root=".", **kw):
    return uploader.sync_scripts(root, client=_client(fake), **kw)


def _script_names(fake):
    return {s["id"]: s["name"] for s in fake.scripts}


def _linked(fake):
    """{(evidence set reference, script name)} for every script CONNECTed."""
    refs = {e["id"]: e["referenceId"] for e in fake._evidence}
    names = _script_names(fake)
    return {(refs[ev], names.get(sid, sid)) for ev, kind, sid in fake.associations if kind == "SCRIPT"}


def _tags(fake):
    """{"<entity>/<reference or script name>": tag names} for every tagged entity."""
    refs = {e["id"]: e["referenceId"] for e in fake._evidence}
    names = _script_names(fake)
    return {f"{kind}/{refs.get(eid) or names.get(eid, eid)}": tags for (kind, eid), tags in fake.tags.items()}


def _by_fetcher(summary):
    return {r["fetcher"]: r for r in summary["results"]}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    """No developer token or .env: a sync without an injected client must never
    reach a real workspace."""
    for name in ("PARAMIFY_CUSTOM_TAGS", "PARAMIFY_UPLOAD_API_TOKEN", "PARAMIFY_API_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")


@pytest.fixture
def specs(monkeypatch):
    monkeypatch.setattr(uploader, "_discover_specs", lambda root, include=None: [dict(s) for s in SPECS])
    return SPECS


def test_plan_actions_without_force(specs):
    summary = _sync(_workspace())
    r = _by_fetcher(summary)
    assert r["f_new"]["outcome"] == "create"
    assert r["f_bump"]["outcome"] == "update"
    assert r["f_drift"]["outcome"] == "drift_skipped"   # code changed, version didn't
    assert r["f_noop"]["outcome"] == "noop"
    assert summary["created"] == 1 and summary["updated"] == 1
    assert summary["drift"] == 1 and summary["noop"] == 1
    assert summary["ok"] is True


def test_association_only_on_change(specs):
    fake = _workspace()
    _sync(fake)
    # create + update associate; drift (skipped) and noop do not. A created script
    # is named after its evidence set.
    assert _linked(fake) == {("EVD-NEW", "New"), ("EVD-BUMP", "Bump")}


def test_drift_pushed_with_force(specs):
    fake = _workspace()
    r = _by_fetcher(_sync(fake, force=True))
    assert r["f_drift"]["outcome"] == "drift"       # pushed, not skipped
    drift = next(s for s in fake.scripts if "f_drift" in s["description"])
    assert drift["code"] == "NEWCODE"
    assert ("EVD-DRIFT", "Drift") in _linked(fake)


def test_reassociate_covers_noop(specs):
    fake = _workspace()
    _sync(fake, reassociate=True)
    assert ("EVD-NOOP", "f_noop") in _linked(fake)   # noop normally skips association


def test_a_second_run_reconnects_without_failing(specs):
    """The API has no association read-back, so --reassociate CONNECTs again;
    the 'already connected' refusal is the state we wanted."""
    fake = _workspace()
    _sync(fake, reassociate=True)
    summary = _sync(fake, reassociate=True)
    assert summary["ok"] and summary["errors"] == 0


def test_a_set_this_stage_creates_gets_the_evidence_uploaders_schedule(monkeypatch):
    """The evidence uploader never patches a set's frequency later, so a set the
    scripts stage creates first must get the frequency it would have: the
    fetcher's own, an override, or the default."""
    spec = {**SPECS[0], "evidence_set": {"reference_id": "EVD-NEW", "name": "New", "frequency": "WEEKLY"}}
    monkeypatch.setattr(uploader, "_discover_specs", lambda root, include=None: [spec])
    fake = FakeParamify()
    _sync(fake)
    made = next(e for e in fake._evidence if e["referenceId"] == "EVD-NEW")
    assert made["frequency"] == "WEEKLY"
    assert made["startDate"] == date.today().isoformat()   # the schedule counts from creation

    fake = FakeParamify()
    _sync(fake, config={"overrides": {"f_new": {"frequency": "DAILY"}}})
    assert fake._evidence[0]["frequency"] == "DAILY"

    monkeypatch.setattr(uploader, "_discover_specs", lambda root, include=None: [dict(SPECS[0])])
    fake = FakeParamify()
    _sync(fake)
    assert fake._evidence[0]["frequency"] == "THREE_DAY"


def test_an_existing_set_is_reused_not_recreated(specs):
    fake = _workspace()
    fake.add_evidence("EVD-NEW")
    _sync(fake)
    assert [e["referenceId"] for e in fake._evidence].count("EVD-NEW") == 1
    assert ("EVD-NEW", "New") in _linked(fake)


def test_https_guard_rejects_http():
    with pytest.raises(ValueError):
        uploader.sync_scripts(".", base_url="http://not-secure.example.com", dry_run=True)


def test_one_refused_fetcher_does_not_stop_the_sweep(specs):
    fake = _workspace()
    fake.fail_route("POST", "/scripts", 400, "kaboom")   # f_new is the only create
    summary = _sync(fake)
    r = _by_fetcher(summary)
    assert r["f_new"]["outcome"] == "error" and "kaboom" in r["f_new"]["error"]
    assert summary["errors"] == 1 and summary["ok"] is False
    assert r["f_bump"]["outcome"] == "update"
    assert r["f_noop"]["outcome"] == "noop"


def test_a_rejected_token_stops_the_sweep_and_says_which_fetcher(specs):
    """No later call can succeed, so the stage stops instead of failing every
    fetcher the same way, and the summary keeps what happened before it."""
    fake = _workspace()
    fake.fail_route("PATCH", r"/scripts/.*", 401, "Unauthorized")
    summary = _sync(fake)
    r = _by_fetcher(summary)
    assert r["f_new"]["outcome"] == "create"          # done before the 401
    assert r["f_bump"]["outcome"] == "error"          # the 401
    assert "f_drift" not in r and "f_noop" not in r   # never attempted
    assert summary["stopped"] and "401" in summary["stopped"] and summary["ok"] is False


def test_a_dry_run_with_a_token_reads_the_workspace_and_writes_nothing(specs, monkeypatch):
    fake = _workspace()
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "env-tok")
    monkeypatch.setenv("PARAMIFY_API_BASE_URL", "https://api.example.test")
    monkeypatch.setattr("framework.paramify.client.requests.Session", lambda: fake.session)
    summary = uploader.sync_scripts(".", dry_run=True)
    assert _by_fetcher(summary)["f_noop"]["outcome"] == "would_noop"   # it read the markers
    assert ("GET", "/scripts", {}) in fake.calls
    assert [c for c in fake.calls if c[0] != "GET"] == []


def test_include_scopes_the_sweep_to_named_fetchers():
    # demo_hello is credential-free and declares an evidence_set, so it always
    # discovers; scoping to it must yield exactly it.
    summary = uploader.sync_scripts(REPO_ROOT, include={"demo_hello"}, dry_run=True)
    assert [r["fetcher"] for r in summary["results"]] == ["demo_hello"]
    assert uploader.sync_scripts(REPO_ROOT, include={"not_a_fetcher"}, dry_run=True)["fetchers"] == 0
    everything = uploader.sync_scripts(REPO_ROOT, include=None, dry_run=True)
    assert everything["fetchers"] > 1


@pytest.mark.parametrize("named", [True, False])
def test_a_missing_manifest_is_refused_not_read_as_empty(tmp_path, monkeypatch, named):
    """Read as empty, it scoped the sweep to nothing and exited 0."""
    monkeypatch.chdir(tmp_path)
    argv = ["--root", str(tmp_path), "--dry-run"]
    if named:
        argv += ["--manifest", str(tmp_path / "nope.yaml")]
    assert uploader.main(argv) == 1


# --------------------------------------------------------------------------- #
# Default custom tags — every script the sweep sees, and the set it links to
# --------------------------------------------------------------------------- #

def test_every_script_is_tagged_including_noop_and_drift(specs):
    fake = _workspace()
    summary = _sync(fake)
    # SPECS carry no category, so only the provenance tag applies.
    assert _tags(fake) == {
        "scripts/New": [PROVENANCE],
        "evidence/EVD-NEW": [PROVENANCE],
        "scripts/Bump": [PROVENANCE],   # an update renames the script after its set
        "evidence/EVD-BUMP": [PROVENANCE],
        "scripts/f_drift": [PROVENANCE],
        "scripts/f_noop": [PROVENANCE],
    }
    by = _by_fetcher(summary)
    assert by["f_noop"]["tags"] == [PROVENANCE]
    assert by["f_drift"]["outcome"] == "drift_skipped" and by["f_drift"]["tags"]
    assert summary["tags"]["applied"] == 6 and summary["tags"]["disabled"] is None


def test_service_tag_uses_the_category_display_name(monkeypatch):
    spec = {**SPECS[0], "category": "aws"}
    monkeypatch.setattr(uploader, "_discover_specs", lambda root, include=None: [spec])
    fake = FakeParamify()
    _sync(fake, root=REPO_ROOT)   # display names come from the repo's category files
    assert _tags(fake)["scripts/New"] == [PROVENANCE, "AWS"]
    assert _tags(fake)["evidence/EVD-NEW"] == [PROVENANCE, "AWS"]


def test_dry_run_plans_tags_and_writes_nothing(specs):
    fake = _workspace()
    summary = _sync(fake, dry_run=True)
    assert [c for c in fake.calls if c[0] != "GET"] == []
    assert all(r["tags"] == [PROVENANCE] for r in summary["results"])


@pytest.mark.parametrize("off, reason", [
    ({"config": {"tags": False}}, "tags: false"),
    ({"custom_tags": False}, "--no-tags"),
    ({"env": "off"}, "PARAMIFY_CUSTOM_TAGS=off"),
])
def test_tags_switched_off_tag_nothing(specs, monkeypatch, off, reason):
    if "env" in off:
        monkeypatch.setenv("PARAMIFY_CUSTOM_TAGS", off.pop("env"))
    fake = _workspace()
    summary = _sync(fake, **off)
    assert fake.tags == {}
    assert summary["tags"]["enabled"] is False and reason in summary["tags"]["reason"]


def test_missing_tag_permission_does_not_fail_the_sync(specs):
    fake = _workspace()
    fake.fail_route("POST", r"/custom-tags/.*", 403, "forbidden")
    summary = _sync(fake)
    assert summary["ok"] and summary["errors"] == 0
    assert len([c for c in fake.calls if c[1].startswith("/custom-tags/")]) == 1
    assert summary["tags"]["disabled"]
