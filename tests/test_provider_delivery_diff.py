"""delivery provider, plan side: routing (stack, channel, artifact request), batch
attribution from artifact notes, and the WAF pre-check. One test per row of the
spec's delivery diff tables, plus observe against the in-process fake API."""
from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Optional

import pytest

from framework.paramify.client import Client
from framework.paramify.resources import (
    Artifact,
    ArtifactRequest,
    Batch,
    Channel,
    EvidenceSet,
    Reader,
    Resources,
    Stack,
)
from framework.paramify.version import FLAG_OFF, Capability
from framework.sync.model import UNKNOWN, Plan, Ref, SyncContext
from framework.sync.providers import waf
from framework.sync.providers.delivery import DIRECT, DeliveryProvider, EntryObserved
from framework.sync.providers.delivery_routing import (
    DirectRoute,
    Refusal,
    attribute,
    delivered_files,
    resolve_channel,
    resolve_request,
)
from framework.sync.providers.desired import (
    DEFAULT_NO_REQUEST,
    DeliveryFile,
    EntryDesired,
)
from framework.sync.state import RunState
from tests.test_sync_desired import build, env, inv

_spec = importlib.util.spec_from_file_location("paramify_fake", Path(__file__).with_name("paramify_fake.py"))
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("paramify_fake", _mod)
_spec.loader.exec_module(_mod)
FakeParamify = _mod.FakeParamify

TODAY = date(2026, 11, 1)
PROD = Stack("st-1", "Prod")
GOV = Stack("st-2", "GovCloud")
CH_P = Channel("ch-1", "CHN-1", "st-1")
CH_G = Channel("ch-2", "CHN-2", "st-2")
AR_NOW = ArtifactRequest("ar-41", "AR-41", "ch-1", "ev-1", date(2026, 10, 15), date(2026, 11, 15))
AR_PAST = ArtifactRequest("ar-40", "AR-40", "ch-1", "ev-1", date(2026, 9, 15), date(2026, 10, 28))
AR_OLDER = ArtifactRequest("ar-39", "AR-39", "ch-1", "ev-1", date(2026, 8, 15), date(2026, 9, 28))
AR_FUTURE = ArtifactRequest("ar-42", "AR-42", "ch-1", "ev-1", date(2026, 12, 1), date(2026, 12, 15))
AR_OTHER_CHANNEL = ArtifactRequest("ar-77", "AR-77", "ch-2", "ev-1", date(2026, 10, 15), date(2026, 11, 15))


def evidence(*channels: Channel) -> EvidenceSet:
    return EvidenceSet("ev-1", "EVD-12", "Set 12", "SUBMISSION", tuple(channels))


def ev_with_channel(approval="SUBMISSION", validators=()) -> EvidenceSet:
    return EvidenceSet("ev-1", "EVD-12", "Set 12", approval, (CH_P,), tuple(validators))


def note(use="aws_x", run_id="R1", entry: Optional[str] = None) -> str:
    parts = [f"fetcher={use}", "version=0.1.0", f"run_id={run_id}", "status=success"]
    if entry:
        parts.append(f"entry={entry}")
    return "; ".join(parts)


def write_file(tmp_path: Path, name: str, payload=None, skip: Optional[str] = None, key="aws_x",
               skip_reason: Optional[str] = None) -> DeliveryFile:
    body = {"schema_version": "1.0", "metadata": {"fetcher_name": "aws_x"}, "payload": payload or {"k": 1}}
    path = tmp_path / name
    path.write_text(json.dumps(body))
    return DeliveryFile(path, name, f"Set 12 - {name}", note(entry=key), "evidence", skip or skip_reason)


def entry(tmp_path, key="aws_x", use="aws_x", *, files=("a.json", "b.json"), stack=None, stack_name=None,
          no_request="refuse", recorded=None, run_id="R1", ref="EVD-12", delivery="auto",
          owner=None, pipeline=None, approval="SUBMISSION_WITH_PASSING_VALIDATORS") -> EntryDesired:
    built = tuple(f if isinstance(f, DeliveryFile) else write_file(tmp_path, f, key=key) for f in files)
    return EntryDesired(
        entry_key=key, use=use, run_id=run_id, reference_id=ref, evidence_set={"reference_id": ref, "name": "Set 12"},
        category="aws", approval=approval, stack=stack, stack_name=stack_name,
        no_request=no_request, files=built, recorded_batch_id=recorded, delivery=delivery, owner=owner,
        pipeline=pipeline,
    )


def batch(bid="bt-12", ref="BCH-12", status="OPEN", ar="ar-41", count=1) -> Batch:
    return Batch(bid, ref, status, "ev-1", ar, count, "SUBMISSION")


def artifact(name="a.json", bid="bt-12", note_text=None, created="2026-10-29T10:00:00Z") -> Artifact:
    return Artifact(f"af-{name}-{bid}", name, note(entry="aws_x") if note_text is None else note_text, bid, created, ())


def observed(ev=None, *, stacks=(), requests=(AR_NOW,), current=("ar-41",), batches=(), artifacts=None, found=()):
    return EntryObserved(
        evidence=ev, stacks=list(stacks), requests=list(requests), current_ids=set(current),
        batches=list(batches), artifacts=dict(artifacts or {}), found=list(found),
    )


BATCHES_OFF = Capability(False, FLAG_OFF)


def provider(capability: Optional[Capability] = None) -> DeliveryProvider:
    return DeliveryProvider(today=lambda: TODAY, capability=capability)


def plan_one(e: EntryDesired, obs, capability: Optional[Capability] = None):
    [action] = provider(capability).diff([e], {e.entry_key: obs})
    return action


class RecordingReader:
    """A reader that records each method it is asked for and answers from canned data."""

    def __init__(self, ev: Optional[EvidenceSet], *, stacks=(), requests=(), current=(), found=()):
        self.ev, self.stacks_, self.requests, self.current = ev, list(stacks), list(requests), set(current)
        self.found = list(found)
        self.calls: list = []

    def evidence_by_reference(self, refs):
        self.calls.append("evidence_by_reference")
        return {self.ev.reference_id: self.ev} if self.ev is not None and self.ev.reference_id in refs else {}

    def stacks(self):
        self.calls.append("stacks")
        return self.stacks_

    def artifacts(self, evidence_id, **kw):
        self.calls.append("artifacts")
        return self.found

    def artifact_requests(self, evidence_id, *, current=None):
        self.calls.append("artifact_requests")
        return [r for r in self.requests if r.id in self.current] if current else self.requests

    def batches(self, **kw):
        self.calls.append("batches")
        return []

    def batch(self, batch_id):
        self.calls.append("batch")
        raise AssertionError("no batch is read in these tests")


def plan_read(e: EntryDesired, reader: RecordingReader, capability: Optional[Capability] = None):
    p = provider(capability)
    [action] = p.diff([e], p.observe([e], reader))
    return action


def test_class_shape():
    p = provider()
    assert p.name == "delivery" and p.runs_after == ("evidence_sets", "validators")


# ---- channels ---------------------------------------------------------------

def test_channels_none(tmp_path):
    a = plan_one(entry(tmp_path), observed(evidence()))
    assert a.id == "delivery/aws_x" and a.verb == "deliver"
    assert a.payload["target"] == "EVIDENCE" and a.payload["evidence_id"] == "ev-1"
    assert a.payload["artifact_request_id"] is None and a.payload["resume_batch_id"] is None
    assert a.changes["channel"] is None and a.changes["stack"] is None
    assert a.summary == "deliver 2 files to EVD-12 (evidence level): new batch (approved when its validators pass)"


def test_channels_one_no_stack_configured(tmp_path):
    a = plan_one(entry(tmp_path), observed(evidence(CH_P)))
    assert a.verb == "deliver" and a.payload["target"] == "ARTIFACT_REQUEST"
    assert a.payload["artifact_request_id"] == "ar-41" and a.payload["planned_current"] is True
    assert a.changes["channel"] == "CHN-1"
    assert a.summary == "deliver 2 files to AR-41 (channel CHN-1): new batch (approved when its validators pass)"


def test_channels_one_matching_stack(tmp_path):
    for configured in ("st-1", "Prod"):
        a = plan_one(entry(tmp_path, stack=configured), observed(evidence(CH_P), stacks=[PROD, GOV]))
        assert a.verb == "deliver" and a.payload["artifact_request_id"] == "ar-41"
        assert a.changes["stack"] == {"id": "st-1", "name": "Prod"}
        assert a.summary == "deliver 2 files to AR-41 (stack Prod, channel CHN-1): new batch (approved when its validators pass)"


def test_channels_one_on_configured_stack_id_missing_from_stack_list(tmp_path):
    gone = Channel("ch-9", "CHN-9", "st-gone")
    e = entry(tmp_path, stack="st-gone", no_request="evidence")
    assert resolve_channel(e, evidence(gone), [PROD]) == gone
    a = plan_one(e, observed(evidence(gone), stacks=[PROD], requests=[], current=[]))
    # The no_request fallback sends an evidence-level batch: it has no channel.
    assert a.verb == "deliver" and a.payload["target"] == "EVIDENCE"
    assert a.changes["channel"] is None and a.changes["stack"] is None


def test_channels_one_other_stack_refuses(tmp_path):
    a = plan_one(entry(tmp_path, stack="GovCloud"), observed(evidence(CH_P), stacks=[PROD, GOV]))
    assert a.verb == "refuse"
    assert a.summary == "EVD-12's only channel is on stack Prod; the manifest says GovCloud"
    assert "GovCloud" in a.fix


def test_channels_several_no_stack_refuses(tmp_path):
    a = plan_one(entry(tmp_path), observed(evidence(CH_P, CH_G), stacks=[PROD, GOV]))
    assert a.verb == "refuse"
    assert "EVD-12 has 2 channels" in a.summary and "no stack" in a.summary
    assert "Prod (st-1)" in a.fix and "GovCloud (st-2)" in a.fix


def test_channels_several_entry_override(tmp_path):
    a = plan_one(entry(tmp_path, stack="st-2"),
                 observed(evidence(CH_P, CH_G), stacks=[PROD, GOV], requests=[AR_OTHER_CHANNEL], current=["ar-77"]))
    assert a.verb == "deliver" and a.payload["artifact_request_id"] == "ar-77"
    assert a.changes["channel"] == "CHN-2" and a.changes["stack"] == {"id": "st-2", "name": "GovCloud"}


def test_channels_several_manifest_default(tmp_path):
    # The manifest-level stack reaches the entry through the run metadata the
    # collect step writes; observe reads stacks, channels and requests from the API.
    fake = FakeParamify()
    prod, gov = fake.add_stack("Prod"), fake.add_stack("GovCloud")
    ev = fake.add_evidence("EVD-X", channels=[prod.id, gov.id])
    fake.add_request(ev.id, ev.channels[1].id, date(2026, 10, 15), date(2026, 11, 15))
    build(tmp_path, {"a.json": env(fetcher="x")}, [inv("x", ["a.json"])],
          {"x": {"use": "x", "stack": "GovCloud"}})
    [a] = plan_run(fake, tmp_path)
    assert a.verb == "deliver" and a.changes["channel"] == ev.channels[1].reference_id
    assert a.changes["stack"] == {"id": gov.id, "name": "GovCloud"}


def test_stack_override_beats_recorded_stack(tmp_path):
    fake = FakeParamify()
    prod, gov = fake.add_stack("Prod"), fake.add_stack("GovCloud")
    ev = fake.add_evidence("EVD-X", channels=[prod.id, gov.id])
    fake.add_request(ev.id, ev.channels[0].id, date(2026, 10, 15), date(2026, 11, 15))
    build(tmp_path, {"a.json": env(fetcher="x")}, [inv("x", ["a.json"])],
          {"x": {"use": "x", "stack": "GovCloud"}})
    [a] = plan_run(fake, tmp_path, stack_override="Prod")
    assert a.verb == "deliver" and a.changes["stack"] == {"id": prod.id, "name": "Prod"}


def test_channels_several_workspace_has_one_stack(tmp_path):
    stale = Channel("ch-9", "CHN-9", "st-gone")
    a = plan_one(entry(tmp_path), observed(evidence(CH_P, stale), stacks=[PROD]))
    assert a.verb == "deliver" and a.changes["channel"] == "CHN-1"


def test_channels_unknown_stack_refuses(tmp_path):
    a = plan_one(entry(tmp_path, stack="Staging"), observed(evidence(CH_P, CH_G), stacks=[PROD, GOV]))
    assert a.verb == "refuse" and "Staging" in a.summary
    assert "Prod (st-1)" in a.fix and "GovCloud (st-2)" in a.fix


def test_ambiguous_stack_name_refuses(tmp_path):
    twin = Stack("st-3", "Prod")
    a = plan_one(entry(tmp_path, stack="Prod"), observed(evidence(CH_P, CH_G), stacks=[PROD, GOV, twin]))
    assert a.verb == "refuse" and "more than one stack" in a.summary


def test_channels_none_on_the_stack_refuses(tmp_path):
    a = plan_one(entry(tmp_path, stack="GovCloud"), observed(evidence(CH_P, CH_P), stacks=[PROD, GOV]))
    assert a.verb == "refuse"
    assert a.fix == "create a channel for stack GovCloud on EVD-12 in the app"


def test_channels_two_on_the_stack_refuses(tmp_path):
    twin = Channel("ch-3", "CHN-3", "st-2")
    a = plan_one(entry(tmp_path, stack="GovCloud"), observed(evidence(CH_P, CH_G, twin), stacks=[PROD, GOV]))
    assert a.verb == "refuse" and "CHN-2" in a.summary and "CHN-3" in a.summary


def test_channels_one_per_owner_on_the_stack_refuse_and_name_the_owners(tmp_path):
    a_ = Channel("ch-3", "CHN-3", "st-2", owner="Owner A")
    b_ = Channel("ch-4", "CHN-4", "st-2", owner="Owner B")
    a = plan_one(entry(tmp_path, stack="GovCloud"), observed(evidence(CH_P, a_, b_), stacks=[PROD, GOV]))
    assert a.verb == "refuse"
    assert a.summary == "EVD-12 has 2 channels on stack GovCloud, one per owner: CHN-3 (Owner A), CHN-4 (Owner B)"
    assert a.fix == ("set an owner to choose one (paramify manifest set-owner, or paramify upload --owner); "
                     "owners: Owner A, Owner B")


def test_a_channel_with_no_owner_shows_its_reference_id_only(tmp_path):
    a_ = Channel("ch-3", "CHN-3", "st-2", owner="Owner A")
    b_ = Channel("ch-4", "CHN-4", "st-2")
    refusal = resolve_channel(entry(tmp_path, stack="GovCloud"), evidence(a_, b_), [PROD, GOV])
    assert isinstance(refusal, Refusal)
    assert refusal.message == "EVD-12 has 2 channels on stack GovCloud, one per owner: CHN-3 (Owner A), CHN-4"


OWN_A = Channel("ch-3", "CHN-3", "st-2", owner="alice")
OWN_B = Channel("ch-4", "CHN-4", "st-2", owner="bob")
AR_BOB = ArtifactRequest("ar-50", "AR-50", "ch-4", "ev-1", date(2026, 10, 15), date(2026, 11, 15))


def test_the_owner_picks_its_channel_among_several_on_the_stack(tmp_path):
    a = plan_one(entry(tmp_path, stack="GovCloud", owner="bob"),
                 observed(evidence(CH_P, OWN_A, OWN_B), stacks=[PROD, GOV], requests=[AR_BOB], current=["ar-50"]))
    assert a.verb == "deliver" and a.payload["artifact_request_id"] == "ar-50"
    assert a.changes["channel"] == "CHN-4"


def test_a_new_batch_carries_the_entrys_approval_and_says_so(tmp_path):
    e = entry(tmp_path)  # approval SUBMISSION_WITH_PASSING_VALIDATORS
    a = plan_one(e, observed(evidence(CH_P), stacks=[PROD]))
    assert a.payload["when_to_approve"] == "SUBMISSION_WITH_PASSING_VALIDATORS"
    assert a.summary.endswith("new batch (approved when its validators pass)")


def test_the_owner_matches_without_regard_to_case(tmp_path):
    picked = resolve_channel(entry(tmp_path, stack="GovCloud", owner="Bob"), evidence(OWN_A, OWN_B), [PROD, GOV])
    assert picked == OWN_B


def test_the_owner_is_ignored_when_the_stack_has_one_channel(tmp_path):
    # A tiebreaker only: one owner for the whole manifest must not refuse the sets
    # whose only channel on the stack belongs to someone else.
    assert resolve_channel(entry(tmp_path, stack="GovCloud", owner="carol"), evidence(CH_P, OWN_A), [PROD, GOV]) == OWN_A
    assert resolve_channel(entry(tmp_path, owner="carol"), evidence(OWN_A), [PROD, GOV]) == OWN_A


def test_the_owner_does_not_choose_between_stacks(tmp_path):
    bob_on_prod = Channel("ch-5", "CHN-5", "st-1", owner="bob")
    refusal = resolve_channel(entry(tmp_path, owner="bob"), evidence(OWN_A, bob_on_prod), [PROD, GOV])
    assert isinstance(refusal, Refusal) and "no stack is configured" in refusal.message


def test_an_owner_with_no_channel_on_the_stack_refuses_and_names_the_owners(tmp_path):
    a = plan_one(entry(tmp_path, stack="GovCloud", owner="carol"),
                 observed(evidence(CH_P, OWN_A, OWN_B), stacks=[PROD, GOV]))
    assert a.verb == "refuse"
    assert a.summary == "EVD-12 has no channel on stack GovCloud owned by carol"
    assert a.fix == "set the owner to one of: alice, bob"


def test_owner_from_the_manifest_reaches_routing(tmp_path):
    fake = FakeParamify()
    fake.add_stack("Prod")
    gov = fake.add_stack("GovCloud")
    ev = fake.add_evidence("EVD-X", channels=[gov.id, gov.id], owners=["alice", "bob"])
    fake.add_request(ev.id, ev.channels[1].id, date(2026, 10, 15), date(2026, 11, 15))
    build(tmp_path, {"a.json": env(fetcher="x")}, [inv("x", ["a.json"])],
          {"x": {"use": "x", "stack": "GovCloud", "owner": "bob"}})
    [a] = plan_run(fake, tmp_path)
    assert a.verb == "deliver" and a.changes["channel"] == ev.channels[1].reference_id


def test_owner_override_beats_the_recorded_owner(tmp_path):
    fake = FakeParamify()
    gov = fake.add_stack("GovCloud")
    ev = fake.add_evidence("EVD-X", channels=[gov.id, gov.id], owners=["alice", "bob"])
    fake.add_request(ev.id, ev.channels[0].id, date(2026, 10, 15), date(2026, 11, 15))
    build(tmp_path, {"a.json": env(fetcher="x")}, [inv("x", ["a.json"])],
          {"x": {"use": "x", "owner": "bob"}})
    [a] = plan_run(fake, tmp_path, owner_override="alice")
    assert a.verb == "deliver" and a.changes["channel"] == ev.channels[0].reference_id


def test_stack_label_drift_warns(tmp_path):
    a = plan_one(entry(tmp_path, stack="st-1", stack_name="Production"), observed(evidence(CH_P), stacks=[PROD]))
    assert a.verb == "deliver"
    assert "stack st-1 is now named Prod (manifest label: Production)" in a.warnings
    same = plan_one(entry(tmp_path, stack="st-1", stack_name="Prod"), observed(evidence(CH_P), stacks=[PROD]))
    assert not any("now named" in w for w in same.warnings)


def test_resolve_channel_is_pure():
    e = EntryDesired("k", "k", "R", "EVD-12", {}, None, "MANUAL", None, None, "refuse", (), None)
    assert resolve_channel(e, None, []) is None
    assert resolve_channel(e, evidence(), []) is None
    assert resolve_channel(e, evidence(CH_P), []) == CH_P
    assert isinstance(resolve_channel(e, evidence(CH_P, CH_G), [PROD, GOV]), Refusal)


# ---- artifact requests ------------------------------------------------------

def test_requests_current(tmp_path):
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), requests=[AR_PAST, AR_NOW, AR_FUTURE]))
    assert a.payload["artifact_request_id"] == "ar-41" and a.payload["planned_current"] is True
    assert not a.warnings


def test_requests_only_past_is_late(tmp_path):
    a = plan_one(entry(tmp_path),
                 observed(evidence(CH_P), requests=[AR_OLDER, AR_PAST, AR_FUTURE, AR_OTHER_CHANNEL], current=["ar-77"]))
    assert a.verb == "deliver" and a.payload["artifact_request_id"] == "ar-40"
    assert a.payload["planned_current"] is False
    assert a.warnings == ["late submission to AR-40 (due 2026-10-28)"]


def test_requests_none_with_refuse(tmp_path):
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), requests=[AR_FUTURE], current=[]))
    assert a.verb == "refuse" and "CHN-1" in a.summary
    assert "remove no_request: refuse" in a.fix


def test_requests_none_with_evidence(tmp_path):
    a = plan_one(entry(tmp_path, no_request="evidence"), observed(evidence(CH_P), requests=[], current=[]))
    assert a.verb == "deliver" and a.payload["target"] == "EVIDENCE"
    assert a.payload["evidence_id"] == "ev-1" and a.payload["artifact_request_id"] is None
    assert a.warnings == ["evidence-level batch: does not count toward the solution capability"]


def test_resolve_request_none_with_direct_returns_direct_route():
    e = EntryDesired("k", "k", "R", "EVD-12", {}, None, "MANUAL", None, None, "direct", (), None)
    assert resolve_request(e, CH_P, [], set(), TODAY) == DirectRoute("CHN-1 has no artifact request")


def test_resolve_request_none_with_refuse_refuses():
    e = EntryDesired("k", "k", "R", "EVD-12", {}, None, "MANUAL", None, None, "refuse", (), None)
    r = resolve_request(e, CH_P, [], set(), TODAY)
    assert isinstance(r, Refusal)
    assert r.fix == ("create an artifact request on CHN-1 in the app, or remove no_request: refuse "
                     "from this entry to send it direct")


def test_resolve_request_is_pure():
    e = EntryDesired("k", "k", "R", "EVD-12", {}, None, "MANUAL", None, None, "refuse", (), None)
    assert resolve_request(e, CH_P, [AR_PAST, AR_NOW], {"ar-41"}, TODAY) == AR_NOW
    assert resolve_request(e, CH_P, [AR_OLDER, AR_PAST], set(), TODAY) == AR_PAST
    assert isinstance(resolve_request(e, CH_P, [AR_OTHER_CHANNEL], {"ar-77"}, TODAY), Refusal)
    lenient = EntryDesired("k", "k", "R", "EVD-12", {}, None, "MANUAL", None, None, "evidence", (), None)
    assert resolve_request(lenient, CH_P, [], set(), TODAY) is None


# ---- batches ----------------------------------------------------------------

def _with_batch(tmp_path, status, names=("a.json",), **kw):
    b = batch(status=status)
    arts = {b.id: [artifact(n) for n in names]}
    return plan_one(entry(tmp_path, **kw), observed(evidence(CH_P), batches=[b], artifacts=arts))


def test_batches_this_run_submitted_is_noop(tmp_path):
    a = _with_batch(tmp_path, "SUBMITTED", names=("a.json", "b.json"))
    assert a.verb == "noop" and a.summary == "already delivered in BCH-12"
    assert a.payload["batch_id"] == "bt-12" and a.payload["not_in_batch"] == []


def test_batches_this_run_approved_is_noop(tmp_path):
    a = _with_batch(tmp_path, "APPROVED", names=("a.json", "b.json"))
    assert a.verb == "noop" and a.summary == "already delivered in BCH-12"


def test_batches_this_run_submitted_without_a_file_reports_it_not_in_the_batch(tmp_path):
    # b.json was dropped on a permanent error when the batch was sent: it is not delivered.
    a = _with_batch(tmp_path, "SUBMITTED")
    assert a.verb == "noop"
    assert [f["original_file_name"] for f in a.payload["files"]] == ["a.json"]
    assert a.payload["not_in_batch"] == [
        {"original_file_name": "b.json", "reason": "not in submitted batch BCH-12"}]
    assert a.summary == "already delivered in BCH-12; not in it: b.json"


def test_batches_open_with_some_files_resumes(tmp_path):
    a = _with_batch(tmp_path, "OPEN")
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == "bt-12"
    assert [f["original_file_name"] for f in a.payload["files"]] == ["b.json"]
    assert a.summary == "deliver 1 file to AR-41 (channel CHN-1): resume BCH-12 (1 missing)"


def test_batches_open_with_all_files_submits_only(tmp_path):
    a = _with_batch(tmp_path, "OPEN", names=("a.json", "b.json"))
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == "bt-12" and a.payload["files"] == []
    assert a.summary == "deliver 0 files to AR-41 (channel CHN-1): resume BCH-12 (submit only)"


def test_batches_rejected_refuses(tmp_path):
    # A person rejected this run's evidence: a re-upload never resends it.
    a = _with_batch(tmp_path, "REJECTED")
    assert a.verb == "refuse" and a.summary == "this run's batch BCH-12 was rejected"
    assert a.fix == "BCH-12 was rejected in Paramify; collect again to send new evidence"
    assert a.payload["resume_batch_id"] is None
    assert a.changes["batch"] == {"id": "bt-12", "reference_id": "BCH-12", "status": "REJECTED"}


def test_attribute_prefers_a_rejected_batch_over_an_open_one_of_the_same_run(tmp_path):
    e = entry(tmp_path)
    rejected, stray = batch(status="REJECTED"), batch("bt-13", "BCH-13", "OPEN")
    arts = {"bt-12": [artifact("a.json")], "bt-13": [artifact("a.json", bid="bt-13")]}
    assert attribute([stray, rejected], arts, e).mine is rejected


def test_batches_empty_known_only_from_upload_state(tmp_path):
    empty, other_empty = batch(count=0), batch("bt-13", "BCH-13", count=0)
    a = plan_one(entry(tmp_path, recorded="bt-12"),
                 observed(evidence(CH_P), batches=[other_empty, empty], artifacts={"bt-12": [], "bt-13": []}))
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == "bt-12"
    assert len(a.payload["files"]) == 2
    b = plan_one(entry(tmp_path), observed(evidence(CH_P), batches=[empty], artifacts={"bt-12": []}))
    assert b.payload["resume_batch_id"] is None


def test_batches_another_runs_open_batch_warns(tmp_path):
    old = batch("bt-9", "BCH-9")
    arts = {"bt-9": [artifact(note_text=note(run_id="R0", entry="aws_x"), bid="bt-9", created="2026-10-29T08:00:00Z"),
                     artifact("b.json", "bt-9", note(run_id="R0", entry="aws_x"), "2026-10-30T08:00:00Z")]}
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), batches=[old], artifacts=arts))
    assert a.verb == "deliver" and a.payload["resume_batch_id"] is None
    assert a.warnings == ["BCH-9 from run R0 has been open 3 days"]


def test_batches_not_from_this_tool_ignored(tmp_path):
    foreign = batch("bt-5", "BCH-5", status="SUBMITTED")
    arts = {"bt-5": [artifact("a.json", "bt-5", "uploaded by hand"), artifact("b.json", "bt-5", "")]}
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), batches=[foreign], artifacts=arts))
    assert a.verb == "deliver" and a.payload["resume_batch_id"] is None and len(a.payload["files"]) == 2


def test_foreign_open_batch_is_not_mentioned(tmp_path):
    foreign = batch("bt-5", "BCH-5", status="OPEN")
    other_fetcher = batch("bt-6", "BCH-6", status="OPEN")
    arts = {"bt-5": [artifact("a.json", "bt-5", "manual upload", "2026-01-01T00:00:00Z")],
            "bt-6": [artifact("z.json", "bt-6", note(use="aws_y", run_id="R0", entry="aws_y"))]}
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), batches=[foreign, other_fetcher], artifacts=arts))
    assert a.verb == "deliver" and a.warnings == []


def test_attribute_reports_earlier_open_batch_with_its_run_id():
    old = batch("bt-9", "BCH-9")
    done = batch("bt-8", "BCH-8", status="APPROVED")
    e = EntryDesired("aws_x", "aws_x", "R1", "EVD-12", {}, None, "MANUAL", None, None, "refuse", (), None)
    arts = {"bt-9": [artifact(bid="bt-9", note_text=note(run_id="R0", entry="aws_x"))],
            "bt-8": [artifact(bid="bt-8", note_text=note(run_id="R-1", entry="aws_x"))]}
    got = attribute([old, done], arts, e)
    assert got.mine is None and got.earlier_open == [(old, "R0")]


def test_earlier_open_batch_with_no_readable_date_has_unknown_age(tmp_path):
    old = batch("bt-9", "BCH-9")
    arts = {"bt-9": [artifact(bid="bt-9", note_text=note(run_id="R0", entry="aws_x"), created="")]}
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), batches=[old], artifacts=arts))
    assert a.warnings == ["BCH-9 from run R0 is still open (age unknown)"]


def test_run_id_token_matches_whole_token_only():
    e = EntryDesired("aws_x", "aws_x", "R1", "EVD-12", {}, None, "MANUAL", None, None, "refuse", (), None)
    lookalike = batch("bt-7", "BCH-7", status="SUBMITTED")
    got = attribute([lookalike], {"bt-7": [artifact(bid="bt-7", note_text=note(run_id="R12", entry="aws_x"))]}, e)
    assert got.mine is None


def test_legacy_notes_without_entry_token_attribute_by_fetcher():
    e = EntryDesired("aws_x", "aws_x", "R1", "EVD-12", {}, None, "MANUAL", None, None, "refuse", (), None)
    b = batch(status="SUBMITTED")
    got = attribute([b], {"bt-12": [artifact(note_text=note(run_id="R1"))]}, e)
    assert got.mine == b
    other_key = EntryDesired("aws_x#1", "aws_x", "R1", "EVD-12", {}, None, "MANUAL", None, None, "refuse", (), None)
    assert attribute([b], {"bt-12": [artifact(note_text=note(run_id="R1"))]}, other_key).mine is None


def test_two_entries_same_use_attribute_separately(tmp_path):
    (tmp_path / "x0").mkdir()
    (tmp_path / "x1").mkdir()
    first = entry(tmp_path / "x0", key="aws_x", use="aws_x")
    second = entry(tmp_path / "x1", key="aws_x#1", use="aws_x")
    b_first = batch("bt-1", "BCH-1", status="SUBMITTED")
    b_second = batch("bt-2", "BCH-2", status="OPEN")
    arts = {"bt-1": [artifact("a.json", "bt-1", note(entry="aws_x")), artifact("b.json", "bt-1", note(entry="aws_x"))],
            "bt-2": [artifact("a.json", "bt-2", note(entry="aws_x#1"))]}
    obs = observed(evidence(CH_P), batches=[b_first, b_second], artifacts=arts)
    a1, a2 = provider().diff([first, second], {"aws_x": obs, "aws_x#1": obs})
    assert (a1.id, a1.verb, a1.payload["batch_id"]) == ("delivery/aws_x", "noop", "bt-1")
    assert (a2.id, a2.verb, a2.payload["resume_batch_id"]) == ("delivery/aws_x#1", "deliver", "bt-2")
    assert [f["original_file_name"] for f in a2.payload["files"]] == ["b.json"]
    assert a1.warnings == [] and a2.warnings == []


# ---- files ------------------------------------------------------------------

def test_files_skipped_files(tmp_path):
    skipped = write_file(tmp_path, "c.json", skip="status=failed and skip_failed set")
    a = plan_one(entry(tmp_path, files=("a.json", skipped)), observed(evidence()))
    assert a.verb == "deliver"
    assert [f["original_file_name"] for f in a.payload["files"]] == ["a.json"]
    assert a.payload["skipped"] == [{"original_file_name": "c.json", "reason": "status=failed and skip_failed set", "kind": "skipped"}]


def test_files_zero_sendable_files_plans_no_batch(tmp_path):
    skipped = write_file(tmp_path, "c.json", skip="not envelope-wrapped")
    a = plan_one(entry(tmp_path, files=(skipped,)), observed(evidence()))
    assert a.verb == "noop" and a.payload["files"] == [] and len(a.payload["skipped"]) == 1
    assert a.summary == "nothing to send: 1 file skipped"


def test_files_waf_match_dropped(tmp_path):
    bad = write_file(tmp_path, "bad.json", payload={"cmd": "cd ../etc"})
    a = plan_one(entry(tmp_path, files=("a.json", bad)), observed(evidence()))
    assert a.verb == "deliver"
    assert [f["original_file_name"] for f in a.payload["files"]] == ["a.json"]
    [drop] = a.payload["dropped"]
    assert drop["original_file_name"] == "bad.json"
    assert drop["reason"].startswith("blocked by the production WAF") and "'../'" in drop["reason"]


def test_all_files_dropped_creates_no_batch(tmp_path):
    bad = write_file(tmp_path, "bad.json", payload={"html": "<script>x</script>"})
    a = plan_one(entry(tmp_path, files=(bad,)), observed(evidence(CH_P)))
    assert a.verb == "refuse" and a.summary == "every file was dropped"
    assert a.fix and len(a.payload["dropped"]) == 1


def test_waf_in_payload_mode_scans_only_the_payload(tmp_path):
    body = {"schema_version": "1.0", "metadata": {"fetcher_name": "aws_x", "src": "/bin/sh"}, "payload": {"k": 1}}
    (tmp_path / "m.json").write_text(json.dumps(body))
    f = DeliveryFile(tmp_path / "m.json", "m.json", "t", note(entry="aws_x"), "evidence", None)
    p = provider()
    assert p.desired(SyncContext(None, {"artifact_payload": "payload"})) == []
    [a] = p.diff([entry(tmp_path, files=(f,))], {"aws_x": observed(evidence())})
    assert a.payload["dropped"] == []
    [b] = provider().diff([entry(tmp_path, files=(f,))], {"aws_x": observed(evidence())})
    assert b.verb == "refuse"


def test_waf_scan_signatures_and_note():
    assert [s for s, _ in waf.SIGNATURES] == ["../", "/etc/passwd", "/bin/sh", "/bin/bash", "<script"]
    assert all(rule for _, rule in waf.SIGNATURES)
    assert waf.scan(b'{"a": "/bin/bash -c x; /bin/sh"}', "fetcher=x") == ["/bin/sh", "/bin/bash"]
    assert waf.scan(b"{}", "target=../x") == ["../"]
    assert waf.scan(b"{}", "", title="a<script") == ["<script"]
    assert waf.scan(b"$( && rm -rf <b>", "") == []


# ---- a set created in this run ----------------------------------------------

def test_set_created_in_same_run_targets_ref(tmp_path):
    a = plan_one(entry(tmp_path, stack="Prod"), observed(None, stacks=[PROD]))
    assert a.verb == "deliver" and a.payload["target"] == "EVIDENCE"
    assert a.payload["evidence_id"] == Ref("evidence_sets/EVD-12", "id")
    assert a.summary == "deliver 2 files to EVD-12 (new evidence set, evidence level): new batch (approved when its validators pass)"
    # JSON-native payload: it round-trips through Plan.to_json.
    rt = Plan.from_json(json.loads(json.dumps(Plan([a]).to_json())))
    assert rt.actions[0].payload == a.payload


# ---- offline ----------------------------------------------------------------

def test_offline_plan_has_unknown_routing(tmp_path):
    bad = write_file(tmp_path, "bad.json", payload={"p": "/etc/passwd"})
    skipped = write_file(tmp_path, "c.json", skip="not envelope-wrapped")
    e = entry(tmp_path, files=("a.json", bad, skipped))
    p = provider()
    obs = p.observe([e], None)
    assert obs == {"aws_x": UNKNOWN}
    [a] = p.diff([e], obs)
    assert a.verb == "deliver"
    assert a.changes == {"stack": UNKNOWN, "channel": UNKNOWN, "target": UNKNOWN}
    assert [f["original_file_name"] for f in a.payload["files"]] == ["a.json"]
    assert [d["original_file_name"] for d in a.payload["dropped"]] == ["bad.json"]
    assert [s["original_file_name"] for s in a.payload["skipped"]] == ["c.json"]
    json.dumps(Plan([a]).to_json())
    all_bad = entry(tmp_path, key="k2", use="k2", files=(bad,))
    [r] = p.diff([all_bad], {"k2": UNKNOWN})
    assert r.verb == "refuse"


# ---- observe against the fake API -------------------------------------------

def plan_run(fake, run_dir, stack_override=None, owner_override=None):
    res = Resources(Client("t", "https://api.example.test", session=fake.session))
    p = DeliveryProvider(RunState(run_dir), today=lambda: fake.today)
    desired = p.desired(SyncContext(run_dir, {}, stack_override=stack_override, owner_override=owner_override))
    return p.diff(desired, p.observe(desired, Reader(res)))


def test_observe_resumes_this_runs_batch_from_the_api(tmp_path):
    fake = FakeParamify()
    st = fake.add_stack("Prod")
    ev = fake.add_evidence("EVD-X", channels=[st.id])
    ar = fake.add_request(ev.id, ev.channels[0].id, date(2026, 10, 15), date(2026, 11, 15))
    build(tmp_path, {"a.json": env(fetcher="x"), "b.json": env(fetcher="x")},
          [inv("x", ["a.json", "b.json"])], {"x": {"use": "x"}})
    res = Resources(Client("t", "https://api.example.test", session=fake.session))
    made = res.create_batch(artifact_request_id=ar.id)
    res.upload_to_batch(made.id, "a.json", b"{}", {"note": "fetcher=x; version=0.1.0; run_id=RID; status=success; entry=x"})
    fake.calls.clear()
    [a] = plan_run(fake, tmp_path)
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == made.id
    assert [f["original_file_name"] for f in a.payload["files"]] == ["b.json"]
    assert isinstance(a.payload["files"][0]["path"], str)
    assert ("GET", "/stacks", {}) not in fake.calls  # one channel and no stack configured
    assert ("GET", f"/evidence/{ev.id}/artifacts", {"batchId": made.id}) in fake.calls


def test_observe_new_set_reads_no_batches(tmp_path):
    fake = FakeParamify()
    build(tmp_path, {"a.json": env(fetcher="x")}, [inv("x", ["a.json"])], {"x": {"use": "x"}})
    [a] = plan_run(fake, tmp_path)
    assert a.payload["evidence_id"] == Ref("evidence_sets/EVD-X", "id")
    assert [c[1] for c in fake.calls] == ["/evidence"]


def test_observe_evidence_level_ignores_other_runs_batches_on_requests(tmp_path):
    fake = FakeParamify()
    st = fake.add_stack("Prod")
    ev = fake.add_evidence("EVD-X", channels=[st.id])
    ar = fake.add_request(ev.id, ev.channels[0].id, date(2026, 8, 1), date(2026, 8, 15))
    fake.set_today(date(2026, 7, 1))  # the only request is in the future: nothing current or past
    build(tmp_path, {"a.json": env(fetcher="x")}, [inv("x", ["a.json"])],
          {"x": {"use": "x", "no_request": "evidence"}})
    res = Resources(Client("t", "https://api.example.test", session=fake.session))
    on_request = res.create_batch(artifact_request_id=ar.id)
    res.upload_to_batch(on_request.id, "a.json", b"{}", {"note": "fetcher=x; run_id=R0; entry=x"})
    [a] = plan_run(fake, tmp_path)
    assert a.verb == "deliver" and a.payload["target"] == "EVIDENCE" and a.payload["resume_batch_id"] is None
    assert a.warnings == ["evidence-level batch: does not count toward the solution capability"]


# ---- cycle rollover between two uploads of one run (all batches of the set) --

def _old_request_batch(status, run_id="R1", ar="ar-40"):
    b = batch(status=status, ar=ar)
    arts = {b.id: [artifact("a.json", note_text=note(run_id=run_id, entry="aws_x"))]}
    return [b], arts


def test_rollover_this_runs_batch_approved_on_old_request_is_noop(tmp_path):
    batches, arts = _old_request_batch("APPROVED")
    arts["bt-12"].append(artifact("b.json"))
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), requests=[AR_PAST, AR_NOW], batches=batches,
                                           artifacts=arts))
    assert a.verb == "noop" and a.summary == "already delivered in BCH-12"
    assert a.payload["batch_id"] == "bt-12" and a.payload["artifact_request_id"] == "ar-40"


def test_rollover_this_runs_batch_open_on_old_request_resumes_there(tmp_path):
    batches, arts = _old_request_batch("OPEN")
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), requests=[AR_PAST, AR_NOW], batches=batches,
                                           artifacts=arts))
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == "bt-12"
    assert a.payload["target"] == "ARTIFACT_REQUEST" and a.payload["artifact_request_id"] == "ar-40"
    assert a.payload["planned_current"] is False
    assert a.warnings == ["late submission to AR-40 (due 2026-10-28)"]
    assert a.summary == "deliver 1 file to AR-40 (channel CHN-1): resume BCH-12 (1 missing)"


def test_rollover_resume_on_unobserved_request_says_earlier(tmp_path):
    batches, arts = _old_request_batch("OPEN", ar="ar-gone")
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), requests=[AR_NOW], batches=batches, artifacts=arts))
    assert a.verb == "deliver" and a.payload["artifact_request_id"] == "ar-gone"
    assert a.warnings == ["resuming BCH-12 on an earlier artifact request"]


def test_rollover_rejected_batch_on_old_request_refuses(tmp_path):
    batches, arts = _old_request_batch("REJECTED", ar="ar-gone")
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), requests=[AR_NOW], batches=batches, artifacts=arts))
    assert a.verb == "refuse" and a.fix == "BCH-12 was rejected in Paramify; collect again to send new evidence"


def test_rollover_resume_on_evidence_level_batch(tmp_path):
    batches, arts = _old_request_batch("OPEN", ar=None)
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), batches=batches, artifacts=arts))
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == "bt-12"
    assert a.payload["target"] == "EVIDENCE" and a.payload["artifact_request_id"] is None


def test_rollover_other_runs_open_batch_on_old_request_not_mentioned(tmp_path):
    batches, arts = _old_request_batch("OPEN", run_id="R0")
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), requests=[AR_PAST, AR_NOW], batches=batches,
                                           artifacts=arts))
    assert a.verb == "deliver" and a.payload["resume_batch_id"] is None
    assert a.payload["artifact_request_id"] == "ar-41" and a.warnings == []


def test_observe_rollover_finds_this_runs_batch_on_the_old_request(tmp_path):
    fake = FakeParamify()
    st = fake.add_stack("Prod")
    ev = fake.add_evidence("EVD-X", channels=[st.id], approval="MANUAL")
    old = fake.add_request(ev.id, ev.channels[0].id, date(2026, 10, 1), date(2026, 10, 20))
    fake.add_request(ev.id, ev.channels[0].id, date(2026, 10, 21), date(2026, 11, 15))
    build(tmp_path, {"a.json": env(fetcher="x")}, [inv("x", ["a.json"])], {"x": {"use": "x"}})
    res = Resources(Client("t", "https://api.example.test", session=fake.session))
    made = res.create_batch(artifact_request_id=old.id)
    res.upload_to_batch(made.id, "a.json", b"{}", {"note": "fetcher=x; run_id=RID; entry=x"})
    res.submit_batch(made.id)
    [a] = plan_run(fake, tmp_path)
    assert a.verb == "noop" and a.payload["batch_id"] == made.id
    assert ("GET", f"/evidence/{ev.id}/artifacts", {"originalFileName": ["a.json"]}) in fake.calls
    assert ("GET", f"/batches/{made.id}", {}) in fake.calls


def test_read_count_is_bounded_by_open_batches_on_the_target(tmp_path):
    fake = FakeParamify()
    st = fake.add_stack("Prod")
    ev = fake.add_evidence("EVD-X", channels=[st.id], approval="MANUAL")
    ch = ev.channels[0].id
    old = fake.add_request(ev.id, ch, date(2026, 9, 1), date(2026, 9, 20))
    now = fake.add_request(ev.id, ch, date(2026, 10, 21), date(2026, 11, 15))
    build(tmp_path, {"a.json": env(fetcher="x"), "b.json": env(fetcher="x")},
          [inv("x", ["a.json", "b.json"])], {"x": {"use": "x"}})
    res = Resources(Client("t", "https://api.example.test", session=fake.session))

    def history(n, ar=None, submit=True):
        b = res.create_batch(artifact_request_id=ar) if ar else res.create_batch(evidence_id=ev.id)
        res.upload_to_batch(b.id, "a.json", b"{}", {"note": f"fetcher=x; run_id=R{n}; entry=x"})
        if submit:
            res.submit_batch(b.id)
        return b

    for n in range(45):
        history(n, old.id)
    open_on_target = [history(n, now.id, submit=False) for n in range(45, 48)]
    history(48, now.id)
    history(49, submit=False)  # open, but evidence level: not the chosen target
    mine = res.create_batch(artifact_request_id=now.id)
    res.upload_to_batch(mine.id, "a.json", b"{}", {"note": "fetcher=x; run_id=RID; entry=x"})
    fake.calls.clear()

    [a] = plan_run(fake, tmp_path)
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == mine.id
    assert [f["original_file_name"] for f in a.payload["files"]] == ["b.json"]
    assert len(a.warnings) == 3 and all("is still open" in w or "has been open" in w for w in a.warnings)
    artifact_reads = [c for c in fake.calls if c[1] == f"/evidence/{ev.id}/artifacts"]
    open_count = len(open_on_target) + 1  # the other runs' open batches and this run's
    assert len(artifact_reads) == 1 + open_count
    assert artifact_reads[0][2] == {"originalFileName": ["a.json", "b.json"]}
    listings = [c[2] for c in fake.calls if c[1] == "/batches"]
    assert listings and all(p.get("status") == "OPEN" for p in listings)
    assert [c[1] for c in fake.calls if c[1].startswith("/batches/")] == [f"/batches/{mine.id}"]


def test_observe_recorded_empty_batch_is_resumed(tmp_path):
    fake = FakeParamify()
    ev = fake.add_evidence("EVD-X")
    build(tmp_path, {"a.json": env(fetcher="x")}, [inv("x", ["a.json"])], {"x": {"use": "x"}})
    res = Resources(Client("t", "https://api.example.test", session=fake.session))
    empty = res.create_batch(evidence_id=ev.id)
    RunState(tmp_path).record_batch("x", empty.id)
    [a] = plan_run(fake, tmp_path)
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == empty.id


def test_observe_stale_recorded_batch_is_ignored(tmp_path):
    fake = FakeParamify()
    fake.add_evidence("EVD-X")
    build(tmp_path, {"a.json": env(fetcher="x")}, [inv("x", ["a.json"])], {"x": {"use": "x"}})
    RunState(tmp_path).record_batch("x", "bt-from-another-workspace")
    [a] = plan_run(fake, tmp_path)
    assert a.verb == "deliver" and a.payload["resume_batch_id"] is None


@pytest.mark.parametrize("bad", ["../", "/etc/passwd", "/bin/sh", "/bin/bash", "<script"])
def test_every_signature_drops(tmp_path, bad):
    f = write_file(tmp_path, "x.json", payload={"v": f"a {bad} b"})
    a = plan_one(entry(tmp_path, files=("a.json", f)), observed(evidence()))
    assert [d["original_file_name"] for d in a.payload["dropped"]] == ["x.json"]


# ---- direct delivery --------------------------------------------------------

def test_direct_when_batches_off_sends_the_routed_channel_id(tmp_path):
    a = plan_one(entry(tmp_path, ref="EVD-X"), observed(evidence(CH_P)), BATCHES_OFF)
    assert a.verb == "deliver" and a.payload["target"] == "DIRECT"
    assert a.payload["channel_id"] == "ch-1"
    assert a.payload["direct_reason"] == "batches are off for this workspace"
    assert a.payload["evidence_id"] == "ev-1"
    assert a.payload["artifact_request_id"] is None and a.payload["planned_current"] is False
    assert a.payload["resume_batch_id"] is None
    assert [f["original_file_name"] for f in a.payload["files"]] == ["a.json", "b.json"]
    assert a.changes == {"stack": {"id": "st-1", "name": None}, "channel": "CHN-1", "target": "DIRECT"}
    assert a.summary == "deliver 2 files to EVD-X direct (channel CHN-1): batches are off for this workspace"
    assert a.warnings == []


def test_direct_when_batches_off_and_no_channel(tmp_path):
    a = plan_one(entry(tmp_path), observed(evidence()), BATCHES_OFF)
    assert a.verb == "deliver" and a.payload["target"] == "DIRECT"
    assert a.payload["channel_id"] is None
    assert a.changes == {"stack": None, "channel": None, "target": "DIRECT"}
    assert "(no channel)" in a.summary
    assert a.summary == "deliver 2 files to EVD-12 direct (no channel): batches are off for this workspace"


def test_direct_new_set_targets_ref_with_no_channel(tmp_path):
    a = plan_one(entry(tmp_path), observed(None), BATCHES_OFF)
    assert a.verb == "deliver" and a.payload["target"] == "DIRECT"
    assert a.payload["evidence_id"] == Ref("evidence_sets/EVD-12", "id")
    assert a.payload["channel_id"] is None
    rt = Plan.from_json(json.loads(json.dumps(Plan([a]).to_json())))
    assert rt.actions[0].payload == a.payload


def test_direct_mode_keeps_channel_refusals(tmp_path):
    a = plan_one(entry(tmp_path), observed(evidence(CH_P, CH_G), stacks=[PROD, GOV]), BATCHES_OFF)
    assert a.verb == "refuse"
    assert a.summary == "EVD-12 has 2 channels and no stack is configured"


def test_direct_mode_reads_no_requests_or_batches(tmp_path):
    reader = RecordingReader(evidence(CH_P, CH_G), stacks=[PROD, GOV], requests=[AR_NOW], current=["ar-41"])
    a = plan_read(entry(tmp_path, stack="Prod"), reader, BATCHES_OFF)
    assert a.verb == "deliver" and a.payload["target"] == "DIRECT" and a.payload["channel_id"] == "ch-1"
    assert reader.calls == ["evidence_by_reference", "stacks", "artifacts"]


def test_delivery_direct_setting_with_batches_on(tmp_path):
    reader = RecordingReader(evidence(CH_P), requests=[AR_NOW], current=["ar-41"])
    a = plan_read(entry(tmp_path, delivery="direct"), reader, Capability(True, None))
    assert a.verb == "deliver" and a.payload["target"] == "DIRECT"
    assert a.payload["direct_reason"] == "delivery: direct" and a.payload["channel_id"] == "ch-1"
    assert a.summary == "deliver 2 files to EVD-12 direct (channel CHN-1): delivery: direct"
    assert "artifact_requests" not in reader.calls
    assert "batches" not in reader.calls and "batch" not in reader.calls


def test_no_request_direct_falls_back_with_warning(tmp_path):
    reader = RecordingReader(evidence(CH_P), requests=[], current=[])
    a = plan_read(entry(tmp_path, no_request=DEFAULT_NO_REQUEST), reader)
    assert a.verb == "deliver" and a.payload["target"] == "DIRECT"
    assert a.payload["direct_reason"] == "CHN-1 has no artifact request"
    assert a.payload["channel_id"] == "ch-1"
    assert a.warnings == ["CHN-1 has no artifact request; sent direct, as before batches"]
    assert a.summary == "deliver 2 files to EVD-12 direct (channel CHN-1): CHN-1 has no artifact request"
    assert "artifact_requests" in reader.calls  # routing had to look
    assert "batches" not in reader.calls and "batch" not in reader.calls


def test_direct_noop_when_every_file_is_on_the_set(tmp_path):
    on_set = [artifact("a.json", bid=None), artifact("b.json", bid="bt-9")]
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), found=on_set), BATCHES_OFF)
    assert a.verb == "noop" and a.summary == "already delivered (2 files)"
    assert a.payload["target"] == "DIRECT" and a.payload["files"] == []


def test_direct_sends_only_missing_files(tmp_path):
    other_run = artifact("b.json", bid=None, note_text=note(run_id="R0", entry="aws_x"))
    on_set = [artifact("a.json", bid=None), other_run]
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), found=on_set), BATCHES_OFF)
    assert a.verb == "deliver" and a.payload["target"] == "DIRECT"
    assert [f["original_file_name"] for f in a.payload["files"]] == ["b.json"]
    assert a.summary == "deliver 1 file to EVD-12 direct (channel CHN-1): batches are off for this workspace"


def test_no_request_direct_noop_counts_every_file_on_the_set(tmp_path):
    on_set = [artifact("a.json", bid=None), artifact("b.json", bid="bt-9")]
    obs = observed(evidence(CH_P), requests=[], current=[], found=on_set)
    obs.before_batches = ["a.json"]  # as observe reads it: the file with no batch
    a = plan_one(entry(tmp_path, no_request="direct"), obs)
    assert a.verb == "noop" and a.summary == "already delivered (2 files)"
    assert a.payload["target"] == "DIRECT" and a.payload["files"] == []


def test_evidence_level_batch_still_reports_no_channel(tmp_path):
    a = plan_one(entry(tmp_path, stack="Prod", no_request="evidence"),
                 observed(evidence(CH_P), stacks=[PROD], requests=[], current=[]))
    assert a.verb == "deliver" and a.payload["target"] == "EVIDENCE"
    assert a.changes["channel"] is None and a.changes["stack"] is None
    assert "channel_id" not in a.payload


def test_delivered_files_counts_with_or_without_a_batch(tmp_path):
    e = entry(tmp_path)
    arts = [artifact("a.json", bid=None), artifact("b.json", bid="bt-9"),
            artifact("c.json", bid=None, note_text=note(run_id="R0", entry="aws_x")),
            artifact("a.json", bid="bt-10")]
    assert delivered_files(arts, e) == ["a.json", "b.json"]


def test_no_request_direct_reupload_of_files_sent_direct_is_a_direct_noop(tmp_path):
    # The first upload sent both files direct (no batch): the re-upload says so, on its channel.
    on_set = [artifact("a.json", bid=None), artifact("b.json", bid=None)]
    obs = observed(evidence(CH_P), requests=[], current=[], found=on_set)
    obs.before_batches = ["a.json", "b.json"]  # as observe reads them: no batch
    a = plan_one(entry(tmp_path, no_request="direct"), obs)
    assert a.verb == "noop" and a.summary == "already delivered (2 files)"
    assert a.payload["target"] == "DIRECT" and a.payload["files"] == []
    assert a.changes["channel"] == "CHN-1" and a.changes["target"] == "DIRECT"
    assert a.warnings == ["CHN-1 has no artifact request; sent direct, as before batches"]


def test_files_sent_before_batches_still_noop_ahead_of_a_refusal(tmp_path):
    # A batch entry keeps its order: the before-batches no-op comes before routing refuses.
    on_set = [artifact("a.json", bid=None), artifact("b.json", bid=None)]
    obs = observed(evidence(CH_P, CH_G), stacks=[PROD, GOV], found=on_set)
    obs.before_batches = ["a.json", "b.json"]
    a = plan_one(entry(tmp_path), obs)
    assert a.verb == "noop" and a.summary == "already delivered before batches (2 files)"


def test_direct_entry_warns_that_this_runs_open_batch_stays_open(tmp_path):
    on_set = [artifact("a.json", bid="bt-9")]
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), found=on_set), BATCHES_OFF)
    assert a.verb == "deliver" and [f["original_file_name"] for f in a.payload["files"]] == ["b.json"]
    assert a.warnings == [
        "this run's batch bt-9 stays open; its files count as delivered, and the direct upload does not submit it"]


def test_direct_entry_warns_about_the_recorded_batch_with_its_reference_when_observed(tmp_path):
    obs = observed(evidence(CH_P), batches=[batch("bt-9", "BCH-9")])
    a = plan_one(entry(tmp_path, recorded="bt-9", delivery="direct"), obs, Capability(True, None))
    assert a.verb == "deliver"
    assert a.warnings == [
        "this run's batch BCH-9 stays open; its files count as delivered, and the direct upload does not submit it"]


def test_direct_entry_without_a_batch_of_this_run_has_no_open_batch_warning(tmp_path):
    other_run = artifact("a.json", bid="bt-9", note_text=note(run_id="R0", entry="aws_x"))
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), found=[other_run]), BATCHES_OFF)
    assert a.verb == "deliver" and a.warnings == []


# -- pipeline entries ------------------------------------------------------ #
INV = {"type": "inventory", "id_scheme": "x-id"}


def test_pipeline_entry_with_no_request_goes_in_an_evidence_batch(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), observed(ev_with_channel(), requests=(), current=()))
    assert a.verb == "deliver" and a.payload["target"] == "EVIDENCE"


def test_pipeline_entry_refuses_delivery_direct(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, delivery="direct"), observed(ev_with_channel()))
    assert a.verb == "refuse" and "never goes direct" in a.summary


def test_pipeline_entry_refuses_no_request_direct(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="direct"), observed(ev_with_channel(), requests=(), current=()))
    assert a.verb == "refuse"


def test_pipeline_entry_goes_direct_with_a_note_when_batches_are_off(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), observed(ev_with_channel()), BATCHES_OFF)
    assert a.payload["target"] == DIRECT and any("no batches" in w for w in a.warnings)


def test_manual_set_does_not_warn_when_the_new_batch_approves_on_submit(tmp_path):
    # A new batch takes the entry's approval, not the set's.
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence", approval="SUBMISSION"),
                 observed(ev_with_channel(approval="MANUAL")))
    assert a.verb == "deliver" and not any("approves MANUAL" in w for w in a.warnings)
    assert a.summary.endswith("→ pipeline runs")


def test_manual_entry_approval_warns(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence", approval="MANUAL"), observed(ev_with_channel()))
    assert any(w.startswith("the new batch approves MANUAL") for w in a.warnings)
    assert not a.summary.endswith("pipeline runs")


def test_resumed_manual_batch_warns_even_when_the_entry_approves_on_submit(tmp_path):
    # A resumed batch keeps the approval it was created with.
    b = replace(batch(status="OPEN"), when_to_approve="MANUAL")
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence", approval="SUBMISSION"),
                 observed(evidence(CH_P), batches=[b], artifacts={b.id: [artifact("a.json")]}))
    assert a.verb == "deliver" and "resume BCH-12" in a.summary
    assert any(w.startswith("BCH-12 approves MANUAL") for w in a.warnings)


def test_manual_entry_does_not_warn_when_batches_are_off(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence", approval="MANUAL"), observed(ev_with_channel()),
                 BATCHES_OFF)
    assert a.payload["target"] == DIRECT
    assert not any("approves MANUAL" in w for w in a.warnings)


def test_manual_approval_on_a_new_set_warns(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence", approval="MANUAL"), observed(None))
    assert any("approves MANUAL" in w for w in a.warnings)


def test_set_with_validators_refuses(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), observed(ev_with_channel(validators=("VAL-1",))))
    assert a.verb == "refuse" and "VAL-1" in a.summary and "never approve" in a.summary


def test_incomplete_inventory_on_a_set_with_validators_is_noop(tmp_path):
    skipped = write_file(tmp_path, "a.json", key="aws_x", skip_reason="incomplete inventory not sent: x")
    a = plan_one(entry(tmp_path, pipeline=INV, files=(skipped,)), observed(ev_with_channel(validators=("VAL-1",))))
    assert a.verb == "noop"


def test_deliver_summary_says_the_pipeline_runs(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), observed(ev_with_channel()))
    assert a.summary.endswith("(approved when its validators pass) → pipeline runs")


def test_ordinary_evidence_with_no_request_still_goes_direct(tmp_path):
    a = plan_one(entry(tmp_path, no_request="direct"), observed(ev_with_channel(), requests=(), current=()))
    assert a.payload["target"] == DIRECT


# -- pipeline entries: files of this run that went direct before batches ---- #
RESEND = "{n} file(s) of this run went direct before; sending them again in a batch so the pipeline runs"


def test_pipeline_entry_resends_files_sent_direct_before_batches(tmp_path):
    on_set = [artifact("a.json", bid=None), artifact("b.json", bid=None)]
    obs = observed(ev_with_channel(), requests=(), current=(), found=on_set)
    obs.before_batches = ["a.json", "b.json"]  # as observe reads them: no batch
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), obs)
    assert a.verb == "deliver" and a.payload["target"] == "EVIDENCE"
    assert [f["original_file_name"] for f in a.payload["files"]] == ["a.json", "b.json"]
    assert "before_batches" not in a.payload
    assert RESEND.format(n=2) in a.warnings
    assert a.summary.startswith("deliver 2 files to EVD-12 (evidence level): new batch")


def test_pipeline_entry_resends_only_the_files_its_open_batch_lacks(tmp_path):
    # a.json went direct before; b.json is already in this run's open batch.
    found = [artifact("a.json", bid=None), artifact("b.json", bid="bt-12")]
    obs = observed(ev_with_channel(), requests=(), current=(), found=found,
                   batches=[batch(ar=None)], artifacts={"bt-12": [found[1]]})
    obs.before_batches = ["a.json"]
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), obs)
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == "bt-12"
    assert [f["original_file_name"] for f in a.payload["files"]] == ["a.json"]
    assert RESEND.format(n=1) in a.warnings


def test_pipeline_entry_with_batches_off_still_counts_files_sent_direct(tmp_path):
    on_set = [artifact("a.json", bid=None), artifact("b.json", bid=None)]
    obs = observed(ev_with_channel(), found=on_set)
    obs.before_batches = ["a.json", "b.json"]
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), obs, BATCHES_OFF)
    assert a.verb == "noop" and a.payload["target"] == DIRECT and a.summary == "already delivered (2 files)"
    assert not any("sending them again" in w for w in a.warnings)


def test_ordinary_entry_still_skips_files_sent_before_batches(tmp_path):
    found = [artifact("a.json", bid=None)]
    obs = observed(evidence(CH_P), found=found)
    obs.before_batches = ["a.json"]
    a = plan_one(entry(tmp_path), obs)
    assert a.verb == "deliver" and a.payload["before_batches"] == ["a.json"]
    assert [f["original_file_name"] for f in a.payload["files"]] == ["b.json"]
    assert not any("sending them again" in w for w in a.warnings)
    obs.before_batches = ["a.json", "b.json"]
    obs.found = [artifact("a.json", bid=None), artifact("b.json", bid=None)]
    a = plan_one(entry(tmp_path), obs)
    assert a.verb == "noop" and a.summary == "already delivered before batches (2 files)"


def test_already_delivered_pipeline_run_with_a_new_validator_is_noop(tmp_path):
    done = batch(status="APPROVED", ar=None)
    arts = [artifact("a.json", bid="bt-12"), artifact("b.json", bid="bt-12")]
    obs = observed(ev_with_channel(validators=("VAL-1",)), requests=(), current=(), found=arts,
                   batches=[done], artifacts={"bt-12": arts})
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), obs)
    assert a.verb == "noop" and a.summary == "already delivered in BCH-12"


def test_open_pipeline_batch_on_a_set_with_a_new_validator_still_refuses(tmp_path):
    arts = [artifact("a.json", bid="bt-12")]
    obs = observed(ev_with_channel(validators=("VAL-1",)), requests=(), current=(), found=arts,
                   batches=[batch(ar=None)], artifacts={"bt-12": arts})
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), obs)
    assert a.verb == "refuse" and "VAL-1" in a.summary
