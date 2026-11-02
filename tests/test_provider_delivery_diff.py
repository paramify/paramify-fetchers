"""delivery provider, plan side: routing (stack, channel, artifact request), batch
attribution from artifact notes, and the WAF pre-check. One test per row of the
spec's delivery diff tables, plus observe against the in-process fake API."""
from __future__ import annotations

import importlib.util
import json
import sys
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
from framework.sync.model import UNKNOWN, Plan, Ref, SyncContext
from framework.sync.providers import waf
from framework.sync.providers.delivery import DeliveryProvider, EntryObserved
from framework.sync.providers.delivery_routing import (
    Refusal,
    attribute,
    resolve_channel,
    resolve_request,
)
from framework.sync.providers.desired import DeliveryFile, EntryDesired
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


def note(use="aws_x", run_id="R1", entry: Optional[str] = None) -> str:
    parts = [f"fetcher={use}", "version=0.1.0", f"run_id={run_id}", "status=success"]
    if entry:
        parts.append(f"entry={entry}")
    return "; ".join(parts)


def write_file(tmp_path: Path, name: str, payload=None, skip: Optional[str] = None, key="aws_x") -> DeliveryFile:
    body = {"schema_version": "1.0", "metadata": {"fetcher_name": "aws_x"}, "payload": payload or {"k": 1}}
    path = tmp_path / name
    path.write_text(json.dumps(body))
    return DeliveryFile(path, name, f"Set 12 - {name}", note(entry=key), "evidence", skip)


def entry(tmp_path, key="aws_x", use="aws_x", *, files=("a.json", "b.json"), stack=None, stack_name=None,
          no_request="refuse", recorded=None, run_id="R1", ref="EVD-12") -> EntryDesired:
    built = tuple(f if isinstance(f, DeliveryFile) else write_file(tmp_path, f, key=key) for f in files)
    return EntryDesired(
        entry_key=key, use=use, run_id=run_id, reference_id=ref, evidence_set={"reference_id": ref, "name": "Set 12"},
        category="aws", approval="SUBMISSION_WITH_PASSING_VALIDATORS", stack=stack, stack_name=stack_name,
        no_request=no_request, files=built, recorded_batch_id=recorded,
    )


def batch(bid="bt-12", ref="BCH-12", status="OPEN", ar="ar-41", count=1) -> Batch:
    return Batch(bid, ref, status, "ev-1", ar, count, "SUBMISSION")


def artifact(name="a.json", bid="bt-12", note_text=None, created="2026-10-29T10:00:00Z") -> Artifact:
    return Artifact(f"af-{name}-{bid}", name, note(entry="aws_x") if note_text is None else note_text, bid, created, ())


def observed(ev=None, *, stacks=(), requests=(AR_NOW,), current=("ar-41",), batches=(), artifacts=None):
    return EntryObserved(
        evidence=ev, stacks=list(stacks), requests=list(requests), current_ids=set(current),
        batches=list(batches), artifacts=dict(artifacts or {}),
    )


def provider() -> DeliveryProvider:
    return DeliveryProvider(today=lambda: TODAY)


def plan_one(e: EntryDesired, obs):
    [action] = provider().diff([e], {e.entry_key: obs})
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
    assert a.summary == "deliver 2 files to EVD-12 (evidence level): new batch"


def test_channels_one_no_stack_configured(tmp_path):
    a = plan_one(entry(tmp_path), observed(evidence(CH_P)))
    assert a.verb == "deliver" and a.payload["target"] == "ARTIFACT_REQUEST"
    assert a.payload["artifact_request_id"] == "ar-41" and a.payload["planned_current"] is True
    assert a.changes["channel"] == "CHN-1"
    assert a.summary == "deliver 2 files to AR-41 (channel CHN-1): new batch"


def test_channels_one_matching_stack(tmp_path):
    for configured in ("st-1", "Prod"):
        a = plan_one(entry(tmp_path, stack=configured), observed(evidence(CH_P), stacks=[PROD, GOV]))
        assert a.verb == "deliver" and a.payload["artifact_request_id"] == "ar-41"
        assert a.changes["stack"] == {"id": "st-1", "name": "Prod"}
        assert a.summary == "deliver 2 files to AR-41 (stack Prod, channel CHN-1): new batch"


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
    assert "no_request: evidence" in a.fix


def test_requests_none_with_evidence(tmp_path):
    a = plan_one(entry(tmp_path, no_request="evidence"), observed(evidence(CH_P), requests=[], current=[]))
    assert a.verb == "deliver" and a.payload["target"] == "EVIDENCE"
    assert a.payload["evidence_id"] == "ev-1" and a.payload["artifact_request_id"] is None
    assert a.warnings == ["evidence-level batch: does not count toward the solution capability"]


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
    a = _with_batch(tmp_path, "SUBMITTED")
    assert a.verb == "noop" and a.summary == "already delivered in BCH-12"
    assert a.payload["batch_id"] == "bt-12"


def test_batches_this_run_approved_is_noop(tmp_path):
    a = _with_batch(tmp_path, "APPROVED")
    assert a.verb == "noop" and a.summary == "already delivered in BCH-12"


def test_batches_open_with_some_files_resumes(tmp_path):
    a = _with_batch(tmp_path, "OPEN")
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == "bt-12"
    assert [f["original_file_name"] for f in a.payload["files"]] == ["b.json"]
    assert a.summary == "deliver 1 file to AR-41 (channel CHN-1): resume BCH-12 (1 missing)"


def test_batches_open_with_all_files_submits_only(tmp_path):
    a = _with_batch(tmp_path, "OPEN", names=("a.json", "b.json"))
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == "bt-12" and a.payload["files"] == []
    assert a.summary == "deliver 0 files to AR-41 (channel CHN-1): resume BCH-12 (submit only)"


def test_batches_rejected_resumes(tmp_path):
    a = _with_batch(tmp_path, "REJECTED")
    assert a.verb == "deliver" and a.payload["resume_batch_id"] == "bt-12"
    assert [f["original_file_name"] for f in a.payload["files"]] == ["b.json"]


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
    assert a.payload["skipped"] == [{"original_file_name": "c.json", "reason": "status=failed and skip_failed set"}]


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
    assert a.summary == "deliver 2 files to EVD-12 (new evidence set, evidence level): new batch"
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

def plan_run(fake, run_dir, stack_override=None):
    res = Resources(Client("t", "https://api.example.test", session=fake.session))
    p = DeliveryProvider(RunState(run_dir), today=lambda: fake.today)
    desired = p.desired(SyncContext(run_dir, {}, stack_override=stack_override))
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
    batches, arts = _old_request_batch("REJECTED", ar="ar-gone")
    a = plan_one(entry(tmp_path), observed(evidence(CH_P), requests=[AR_NOW], batches=batches, artifacts=arts))
    assert a.verb == "deliver" and a.payload["artifact_request_id"] == "ar-gone"
    assert a.warnings == ["resuming BCH-12 on an earlier artifact request"]


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
    assert ("GET", "/batches", {"evidenceId": ev.id, "page": 1, "pageSize": 100}) in fake.calls


@pytest.mark.parametrize("bad", ["../", "/etc/passwd", "/bin/sh", "/bin/bash", "<script"])
def test_every_signature_drops(tmp_path, bad):
    f = write_file(tmp_path, "x.json", payload={"v": f"a {bad} b"})
    a = plan_one(entry(tmp_path, files=("a.json", f)), observed(evidence()))
    assert [d["original_file_name"] for d in a.payload["dropped"]] == ["x.json"]
