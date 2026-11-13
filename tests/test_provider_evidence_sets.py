"""evidence_sets provider: diff on hand-built fixtures, apply against the fake API."""
from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path

import pytest

from framework.paramify.client import ApiError, Client, ErrorKind
from framework.paramify.resources import Channel, EvidenceSet, Reader, Resources
from framework.sync import engine
from framework.sync.model import UNKNOWN, Ref, SyncContext
from framework.sync.providers.desired import EntryDesired
from framework.sync.providers.evidence_sets import (
    EvidenceSetsProvider,
    group_by_reference,
)
from tests.test_sync_desired import build, env, inv

_spec = importlib.util.spec_from_file_location("paramify_fake", Path(__file__).with_name("paramify_fake.py"))
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("paramify_fake", _mod)
_spec.loader.exec_module(_mod)
FakeParamify = _mod.FakeParamify

DEFAULT = "SUBMISSION"
TODAY = date(2026, 11, 1)


def entry(key="e", ref="EVD-A", approval=None, category="aws", **es):
    """`approval` None is the default, not set in the manifest; a value is set explicitly."""
    evidence_set = {"reference_id": ref, "name": "Set A", **es}
    return EntryDesired(
        entry_key=key, use=key, run_id="R", reference_id=ref, evidence_set=evidence_set,
        category=category, approval=approval or DEFAULT, stack=None, stack_name=None,
        no_request="refuse", files=(), recorded_batch_id=None, approval_explicit=approval is not None,
    )


def provider(tags=True, names=None):
    return EvidenceSetsProvider(tags, {"aws": "AWS"} if names is None else names, {}, today=lambda: TODAY)


def plan_for(p, entries, observed):
    return p.diff(group_by_reference(entries), observed)


def observed_set(ref="EVD-A", name="Set A", approval=DEFAULT):
    return EvidenceSet("ev-9", ref, name, approval, (Channel("ch-1", "CH-1", "st-1"),))


def test_class_shape():
    p = provider()
    assert p.name == "evidence_sets" and p.runs_after == ()


def test_missing_set_creates_with_exact_body_and_tags():
    acts = plan_for(provider(), [entry(description="D", instructions="I", frequency="DAILY")], {})
    create, tag = acts
    assert create.id == "evidence_sets/EVD-A" and create.verb == "create"
    assert create.payload["body"] == {
        "referenceId": "EVD-A", "name": "Set A", "description": "D", "instructions": "I",
        "frequency": "DAILY", "startDate": "2026-11-01", "whenToApproveArtifactRequest": DEFAULT,
    }
    assert tag.id == "evidence_sets/tags/EVD-A" and tag.verb == "tag"
    assert tag.payload == {
        "evidence_id": Ref("evidence_sets/EVD-A", "id"),
        "tags": ["Automated by Paramify Fetchers", "AWS"], "category": "aws",
    }


def test_empty_description_and_default_frequency_omitted():
    [create, _] = plan_for(provider(), [entry()], {})
    body = create.payload["body"]
    assert "description" not in body and "instructions" not in body
    assert body["frequency"] == "THREE_DAY"
    assert "automated" not in body and "whenToCreateAndUpdateProcessArtifactRequest" not in body


def test_existing_set_noop_with_drift_and_tags():
    seen = observed_set(name="Other", approval="MANUAL")
    noop, tag = plan_for(provider(), [entry(approval=DEFAULT)], {"EVD-A": seen})
    assert noop.verb == "noop"
    assert noop.warnings == [
        f"approval is MANUAL here; this upload's batches get {DEFAULT}",
        "name in Paramify is 'Other'; the fetcher calls it 'Set A'",
    ]
    assert noop.payload["id"] == "ev-9"
    assert tag.verb == "tag"


def test_existing_set_default_approval_is_no_drift():
    seen = observed_set(approval="MANUAL")
    [noop, _] = plan_for(provider(), [entry()], {"EVD-A": seen})
    assert noop.warnings == []


def test_existing_set_with_entries_that_disagree_is_not_refused():
    seen = observed_set(approval="MANUAL")
    noop, tag = plan_for(provider(), [entry("a", approval="SUBMISSION"), entry("b")], {"EVD-A": seen})
    assert noop.verb == "noop" and tag.verb == "tag"
    assert noop.warnings == ["approval is MANUAL here; this upload's batches get SUBMISSION"]


def test_existing_set_without_drift_has_no_warnings():
    [noop, _] = plan_for(provider(), [entry()], {"EVD-A": observed_set()})
    assert noop.warnings == []


def test_conflicting_approval_refuses_without_tags():
    acts = plan_for(provider(), [entry("a", approval="MANUAL"), entry("b")], {})
    [refuse] = acts
    assert refuse.verb == "refuse" and refuse.id == "evidence_sets/EVD-A"
    assert "a" in refuse.fix and "b" in refuse.fix and "MANUAL" in refuse.fix and DEFAULT in refuse.fix


def test_entries_sharing_a_set_make_one_record():
    acts = plan_for(provider(), [entry("a"), entry("b")], {})
    assert [a.id for a in acts] == ["evidence_sets/EVD-A", "evidence_sets/tags/EVD-A"]


def test_tags_disabled_plans_no_tag_actions():
    acts = plan_for(provider(tags=False), [entry()], {})
    assert [a.verb for a in acts] == ["create"]


def test_offline_observe_and_diff():
    p = provider()
    desired = group_by_reference([entry()])
    observed = p.observe(desired, None)
    assert observed == {"EVD-A": UNKNOWN}
    [noop] = p.diff(desired, observed)
    assert noop.verb == "noop" and noop.summary == "evidence set EVD-A: state unknown (offline)"


def test_desired_reads_run_dir_and_skips_undeliverable(tmp_path):
    build(tmp_path, {"a.json": env(ref="EVD-A"), "b.json": env(ref="EVD-B", status="failed")},
          [inv("x", ["a.json"]), inv("y", ["b.json"])], {"x": {"use": "x"}, "y": {"use": "y"}})
    got = provider().desired(SyncContext(tmp_path, {"skip_failed": True}))
    assert [d.reference_id for d in got] == ["EVD-A"]


# ---- apply against the fake ------------------------------------------------

@pytest.fixture
def fake():
    return FakeParamify()


@pytest.fixture
def res(fake):
    return Resources(Client("t", "https://api.example.test", session=fake.session))


def run(p, res, entries):
    p.desired = lambda ctx: group_by_reference(entries)  # type: ignore[method-assign]
    ctx = SyncContext(None, {})
    pl = engine.plan([p], ctx, Reader(res))
    return pl, engine.apply(pl, [p], res)


def test_apply_creates_and_tags_new_set(fake, res):
    _, outs = run(provider(), res, [entry(description="D")])
    create, tag = outs
    assert create.status == "applied" and tag.status == "applied"
    assert set(create.result) == {"id", "channels"}
    assert fake.tags[("evidence", create.result["id"])] == ["Automated by Paramify Fetchers", "AWS"]
    assert [c for c in fake.calls if c[:2] == ("POST", "/evidence")]


def test_apply_existing_set_noop_returns_id_and_still_tags(fake, res):
    stack = fake.add_stack("s")
    ev = fake.add_evidence("EVD-A", channels=[stack.id])
    _, outs = run(provider(), res, [entry()])
    assert outs[0].status == "noop"
    assert outs[0].result["id"] == ev.id
    assert outs[0].result["channels"] == [
        {"id": ev.channels[0].id, "reference_id": ev.channels[0].reference_id, "stack_id": stack.id}
    ]
    assert outs[1].status == "applied" and ("evidence", ev.id) in fake.tags
    assert not [c for c in fake.calls if c[:2] == ("POST", "/evidence")]


def test_apply_refused_set_is_refused(res):
    _, outs = run(provider(), res, [entry("a", approval="MANUAL"), entry("b")])
    assert [o.status for o in outs] == ["refused"]


def test_tag_403_warns_once_then_skips(fake, res, monkeypatch):
    calls = []

    def boom(entity, entity_id, tags):
        calls.append(entity_id)
        raise ApiError("forbidden", status=403, kind=ErrorKind.WARNING, method="POST",
                       path=f"/custom-tags/{entity}/{entity_id}")

    monkeypatch.setattr(res, "add_tags", boom)
    _, outs = run(provider(), res, [entry("a", "EVD-A"), entry("b", "EVD-B")])
    tags = [o for o in outs if "/tags/" in o.action_id]
    assert [o.status for o in tags] == ["applied", "noop"]
    assert all(o.message == "tags unavailable for this token" for o in tags)
    assert len(calls) == 1
    assert [o.status for o in outs if "/tags/" not in o.action_id] == ["applied", "applied"]


def test_other_tag_errors_fail_the_action(res, monkeypatch):
    def boom(entity, entity_id, tags):
        raise ApiError("bad", status=500, kind=ErrorKind.TEMPORARY, method="POST", path="/x")

    monkeypatch.setattr(res, "add_tags", boom)
    _, outs = run(provider(), res, [entry()])
    assert outs[1].status == "failed"


@pytest.mark.parametrize("kind,status", [
    (ErrorKind.TEMPORARY, 500), (ErrorKind.WARNING, 422), (ErrorKind.REJECTED, 400), (ErrorKind.MISSING, 404),
])
def test_tag_errors_other_than_401_never_stop_the_run(res, monkeypatch, kind, status):
    def boom(entity, entity_id, tags):
        raise ApiError("bad", status=status, kind=kind, method="POST", path=f"/custom-tags/{entity}/{entity_id}")

    monkeypatch.setattr(res, "add_tags", boom)
    _, outs = run(provider(), res, [entry("a", "EVD-A"), entry("b", "EVD-B")])
    assert [o.status for o in outs] == ["applied", "failed", "applied", "failed"]
    assert outs[1].message.startswith("tags not added")


def test_tag_401_stops_the_run(res, monkeypatch):
    def boom(entity, entity_id, tags):
        raise ApiError("no", status=401, kind=ErrorKind.FATAL, method="POST", path="/custom-tags/evidence/e")

    monkeypatch.setattr(res, "add_tags", boom)
    _, outs = run(provider(), res, [entry("a", "EVD-A"), entry("b", "EVD-B")])
    assert [o.status for o in outs] == ["applied", "failed", "skipped", "skipped"]
