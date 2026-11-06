"""Round-trips of the typed resources against the in-process fake API."""
from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path

import pytest
import requests

from framework.paramify.client import ApiError, Client
from framework.paramify.resources import Reader, Resources

_spec = importlib.util.spec_from_file_location("paramify_fake", Path(__file__).with_name("paramify_fake.py"))
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
sys.modules["paramify_fake"] = _mod
_spec.loader.exec_module(_mod)
FakeParamify = _mod.FakeParamify


@pytest.fixture
def fake():
    return FakeParamify()


@pytest.fixture
def res(fake):
    return Resources(Client("t", "https://api.example.test", session=fake.session))


def _request_for(fake, ref="EVD-A", approval="SUBMISSION"):
    stack = fake.add_stack("prod")
    ev = fake.add_evidence(ref, channels=[stack.id], approval=approval)
    req = fake.add_request(ev.id, ev.channels[0].id, date(2026, 10, 1), date(2026, 12, 1))
    return ev, req


def test_stacks_and_evidence_by_reference(fake, res):
    stack = fake.add_stack("prod")
    fake.add_evidence("EVD-A", channels=[stack.id])
    assert [s.name for s in res.stacks()] == ["prod"]
    got = res.evidence_by_reference(["EVD-A", "EVD-MISSING"])
    assert list(got) == ["EVD-A"]
    assert got["EVD-A"].channels[0].stack_id == stack.id


def test_create_evidence_then_read_by_reference(res):
    made = res.create_evidence({"referenceId": "EVD-N", "name": "N"})
    assert res.evidence_by_reference(["EVD-N"])["EVD-N"] == made


def test_create_evidence_on_existing_reference_returns_existing(fake, res):
    existing = fake.add_evidence("EVD-A")
    assert res.create_evidence({"referenceId": "EVD-A", "name": "x"}).id == existing.id


def test_artifact_requests_current_filter(fake, res):
    ev, req = _request_for(fake)
    assert [r.id for r in res.artifact_requests(ev.id, current=True)] == [req.id]
    fake.set_today(date(2027, 1, 1))
    assert res.artifact_requests(ev.id, current=True) == []
    assert res.artifact_requests(ev.id)[0].due_date == date(2026, 12, 1)


def test_batch_upload_submit_round_trip(fake, res):
    ev, req = _request_for(fake)
    batch = res.create_batch(artifact_request_id=req.id)
    assert [b.id for b in res.batches(artifact_request_id=req.id)] == [batch.id]
    art = res.upload_to_batch(batch.id, "a.json", b"{}", {"title": "a"})
    assert [a.original_file_name for a in res.artifacts(ev.id, batch_id=batch.id)] == ["a.json"]
    assert art.batch_id == batch.id
    assert res.batch(batch.id).artifact_count == 1
    assert res.submit_batch(batch.id).status == "APPROVED"


def test_artifacts_filter_by_original_file_names(fake, res):
    ev, req = _request_for(fake)
    batch = res.create_batch(artifact_request_id=req.id)
    for name in ("a.json", "b.json", "c.json"):
        res.upload_to_batch(batch.id, name, b"{}", {})
    got = res.artifacts(ev.id, original_file_names=["a.json", "c.json"])
    assert [a.original_file_name for a in got] == ["a.json", "c.json"]
    assert fake.calls[-1] == ("GET", f"/evidence/{ev.id}/artifacts", {"originalFileName": ["a.json", "c.json"]})
    # The 0.14.0 parameter is an array in form style: one repeated key per name.
    url = requests.Request("GET", "https://x.test/a", params={"originalFileName": ["a.json", "c.json"]}).prepare().url
    assert url == "https://x.test/a?originalFileName=a.json&originalFileName=c.json"


def test_artifacts_by_name_go_out_50_names_per_request(fake, res):
    ev, req = _request_for(fake)
    batch = res.create_batch(artifact_request_id=req.id)
    names = [f"f{i:03}.json" for i in range(120)]
    for name in names[::10]:
        res.upload_to_batch(batch.id, name, b"{}", {})
    fake.calls.clear()
    got = res.artifacts(ev.id, original_file_names=names)
    assert [a.original_file_name for a in got] == names[::10]
    reads = [c[2]["originalFileName"] for c in fake.calls if c[1] == f"/evidence/{ev.id}/artifacts"]
    assert [len(r) for r in reads] == [50, 50, 20]
    assert [n for r in reads for n in r] == names


def test_artifacts_created_on_is_the_repeated_createdAt_parameter(fake, res):
    ev, req = _request_for(fake)
    batch = res.create_batch(artifact_request_id=req.id)
    res.upload_to_batch(batch.id, "a.json", b"{}", {})  # created on fake.today, 2026-11-01
    days = [date(2026, 10, 31), date(2026, 11, 1), date(2026, 11, 2)]
    got = res.artifacts(ev.id, original_file_names=["a.json"], created_on=days)
    assert [a.original_file_name for a in got] == ["a.json"]
    assert fake.calls[-1][2] == {"originalFileName": ["a.json"],
                                 "createdAt": ["2026-10-31", "2026-11-01", "2026-11-02"]}
    assert res.artifacts(ev.id, original_file_names=["a.json"], created_on=[date(2026, 10, 1)]) == []


def test_manual_approval_submits_to_submitted_and_closed_batch_refuses(fake, res):
    ev, _ = _request_for(fake, approval="MANUAL")
    batch = res.create_batch(evidence_id=ev.id)
    res.upload_to_batch(batch.id, "a.json", b"{}", {})
    assert res.submit_batch(batch.id).status == "SUBMITTED"
    with pytest.raises(ApiError) as e:
        res.upload_to_batch(batch.id, "b.json", b"{}", {})
    assert e.value.status == 409


def test_submit_empty_batch_is_a_conflict(fake, res):
    ev, _ = _request_for(fake)
    batch = res.create_batch(evidence_id=ev.id)
    with pytest.raises(ApiError) as e:
        res.submit_batch(batch.id)
    assert e.value.status == 409


def test_paging_walks_every_page(fake, res):
    ev, _ = _request_for(fake)
    for _ in range(150):
        res.create_batch(evidence_id=ev.id)
    assert len(res.batches(evidence_id=ev.id)) == 150


def test_fail_upload_once_then_succeeds(fake, res):
    ev, _ = _request_for(fake)
    batch = res.create_batch(evidence_id=ev.id)
    fake.fail_upload_once("a.json", 400)
    with pytest.raises(ApiError):
        res.upload_to_batch(batch.id, "a.json", b"{}", {})
    assert res.upload_to_batch(batch.id, "a.json", b"{}", {}).original_file_name == "a.json"


def test_without_batches_is_missing(fake, res):
    fake.without_batches()
    with pytest.raises(ApiError) as e:
        res.batches()
    assert e.value.status == 404


def test_add_tags_posts_names(fake, res):
    res.add_tags("evidence", "ev-1", ["x", "y"])
    assert fake.tags[("evidence", "ev-1")] == ["x", "y"]


def test_reader_memoizes_identical_calls(fake, res):
    fake.add_stack("prod")
    reader = Reader(res)
    reader.stacks()
    reader.stacks()
    assert [c for c in fake.calls if c[1] == "/stacks"] == [("GET", "/stacks", {})]
    reader.evidence_by_reference(["EVD-A"])
    reader.evidence_by_reference(["EVD-A"])
    assert len([c for c in fake.calls if c[1] == "/evidence"]) == 1
    assert not hasattr(reader, "create_batch")


def test_post_evidence_rejects_channels_and_automated(fake, res):
    for extra in ({"channels": []}, {"automated": True}):
        with pytest.raises(ApiError) as e:
            res.create_evidence({"referenceId": "EVD-X", "name": "X", **extra})
        assert e.value.status == 400


def test_post_evidence_requires_name(res):
    with pytest.raises(ApiError) as e:
        res.create_evidence({"referenceId": "EVD-X"})
    assert e.value.status == 400


def test_created_evidence_defaults_to_submission_and_has_no_channels(res):
    made = res.create_evidence({"referenceId": "EVD-X", "name": "X"})
    assert made.approval == "SUBMISSION"
    assert made.channels == ()
    assert FakeParamify().add_evidence("EVD-Y").approval == "SUBMISSION"


def test_unrecognized_duplicate_reply_is_not_swallowed(fake, res):
    fake.add_evidence("EVD-A")
    fake.duplicate_evidence_body = "nope"
    with pytest.raises(ApiError) as e:
        res.create_evidence({"referenceId": "EVD-A", "name": "A"})
    assert e.value.status == 409
    assert not [c for c in fake.calls if c[0] == "GET" and c[1] == "/evidence"]


def test_upload_to_evidence_posts_the_old_route(fake, res):
    ev = fake.add_evidence("EVD-A", channels=[fake.add_stack("S").id])
    ch = ev.channels[0].id
    fake.calls.clear()
    art = res.upload_to_evidence(ev.id, "a.json", b"{}", {"title": "a.json", "note": "run_id=R", "channelId": ch})
    assert ("POST", f"/evidence/{ev.id}/artifacts/upload") in [(m, p) for m, p, _ in fake.calls]
    assert art.batch_id is None and art.original_file_name == "a.json"
    assert fake._artifacts[-1]["_channelId"] == ch
    assert [a.original_file_name for a in res.artifacts(ev.id)] == ["a.json"]


def test_evidence_upload_rejects_unlisted_meta_keys(fake, res):
    ev = fake.add_evidence("EVD-A")
    with pytest.raises(ApiError) as ei:
        res.upload_to_evidence(ev.id, "a.json", b"{}", {"note": "n", "bogus": 1})
    assert ei.value.status == 400


def test_evidence_upload_honours_fail_upload_once(fake, res):
    ev = fake.add_evidence("EVD-A")
    fake.fail_upload_once("a.json", 400)
    with pytest.raises(ApiError):
        res.upload_to_evidence(ev.id, "a.json", b"{}", {"note": "n"})
    assert res.upload_to_evidence(ev.id, "a.json", b"{}", {"note": "n"}).id


def test_batches_flag_off_answers_403_and_can_be_undone(fake, res):
    fake.batches_flag_off()
    for call in (lambda: res.batches(), lambda: res.artifact_requests("ev-1")):
        with pytest.raises(ApiError) as ei:
            call()
        assert ei.value.status == 403
        assert "Artifact requests are not enabled for this workspace." in ei.value.message
    fake.batches_flag_off(False)
    assert list(res.batches()) == []
