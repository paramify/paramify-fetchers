"""delivery provider, apply side: create or resume the batch, upload each file,
drop or hold on failure, submit when nothing is held, and read the batch back.

Most tests run the real flow, `engine.plan` then `engine.apply` with the
evidence_sets and delivery providers, against the in-process fake API.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, Dict, List

import pytest

from framework.paramify.client import ApiError, Client, ErrorKind
from framework.paramify.resources import Reader, Resources
from framework.paramify.version import FLAG_OFF, Capability
from framework.sync import engine
from framework.sync.model import Action, SyncContext
from framework.sync.providers.delivery import DeliveryProvider
from framework.sync.providers.evidence_sets import EvidenceSetsProvider
from framework.sync.state import RunState
from tests.test_sync_desired import build, env, inv

_spec = importlib.util.spec_from_file_location("paramify_fake", Path(__file__).with_name("paramify_fake.py"))
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("paramify_fake", _mod)
_spec.loader.exec_module(_mod)
FakeParamify = _mod.FakeParamify

SWPV = "SUBMISSION_WITH_PASSING_VALIDATORS"
URL = "https://api.example.test"


class Harness:
    """One run directory, one fake workspace, and the two providers wired as the CLI will wire them."""

    def __init__(self, fake: Any, run_dir: Path, capability: Any = None, budget: float = 3,
                 upload_cfg: Any = None) -> None:
        self.fake = fake
        self.upload_cfg = upload_cfg or {}
        self.run_dir = run_dir
        self.events: List[Dict[str, Any]] = []
        self.sent: List[Any] = []  # the multipart parts of each upload
        session = fake.session
        real = session.request

        def spy(method, url, params=None, json=None, files=None, timeout=None):
            if files:
                self.sent.append(files)
            return real(method, url, params=params, json=json, files=files, timeout=timeout)

        session.request = spy
        self.res = Resources(Client("t", URL, session=session, retry_budget_s=budget, sleep=lambda _s: None))
        self.delivery = DeliveryProvider(RunState(run_dir), today=lambda: fake.today, on_event=self.events.append,
                                         capability=capability)
        self.providers = [EvidenceSetsProvider(False, {}, {}, today=lambda: fake.today), self.delivery]

    def plan(self):
        return engine.plan(self.providers, SyncContext(self.run_dir, self.upload_cfg), Reader(self.res))

    def apply(self, plan):
        return {o.action_id: o for o in engine.apply(plan, self.providers, self.res)}

    def run(self):
        return self.apply(self.plan())

    def uploads(self) -> List[str]:
        return [c[1] for c in self.fake.calls if c[0] == "POST" and c[1].endswith("/artifacts/upload")]

    def submits(self) -> List[str]:
        return [c[1] for c in self.fake.calls if c[0] == "POST" and c[1].endswith("/submit")]

    def file_events(self) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["event"] == "delivery_file"]


def two_files(tmp_path: Path, paramify=None) -> Path:
    return build(tmp_path, {"a.json": env(fetcher="x"), "b.json": env(fetcher="x")},
                 [inv("x", ["a.json", "b.json"])], paramify or {"x": {"use": "x"}})


def with_request(fake, approval="SUBMISSION", requested=date(2026, 10, 15), due=date(2026, 11, 15)):
    st = fake.add_stack("Prod")
    ev = fake.add_evidence("EVD-X", channels=[st.id], approval=approval)
    ar = fake.add_request(ev.id, ev.channels[0].id, requested, due)
    return ev, ar


def batch_row(fake, bid):
    return next(b for b in fake._batches if b["id"] == bid)


# ---- the happy path ---------------------------------------------------------

def test_full_run_creates_set_uploads_submits_and_reads_back_approved(tmp_path):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path))
    out = h.run()
    d = out["delivery/x"]
    assert out["evidence_sets/EVD-X"].status == "applied"
    assert d.status == "applied", d.message
    r = d.result
    assert r["state"] == "delivered" and r["status"] == "APPROVED"
    assert r["uploaded"] == ["a.json", "b.json"] and r["already_present"] == [] and r["dropped"] == []
    assert r["validators_failed"] == [] and r["batch_id"] == "bt-1" and r["batch_reference"] == "BCH-1"
    assert set(r) == {"state", "batch_id", "batch_reference", "status", "uploaded", "already_present",
                      "dropped", "validators_failed", "mode"}
    assert r["mode"] == "batch"
    json.dumps(r)
    assert batch_row(fake, "bt-1")["whenToApprove"] == "SUBMISSION"
    assert h.submits() == ["/batches/bt-1/submit"]
    assert RunState(tmp_path).batch_for("x") == "bt-1"


def test_upload_sends_the_planned_bytes_title_and_note(tmp_path):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path))
    h.run()
    name, content, _ = h.sent[0]["file"]
    meta = json.loads(h.sent[0]["artifact"][1])
    assert name == "a.json"
    assert content == json.dumps(json.loads((tmp_path / "a.json").read_text()), indent=2).encode()
    assert set(meta) == {"title", "note", "effectiveDate"}  # no channelId on a batch upload
    assert meta["title"] == "Set X" and "run_id=RID" in meta["note"] and "entry=x" in meta["note"]
    # The date of the run's collected_at, so a late upload keeps the collection date.
    # The batch route takes a date only (YYYY-MM-DD); a timestamp there is a 400.
    assert meta["effectiveDate"] == "2026-01-01"
    assert fake._artifacts[0]["effectiveDate"] == "2026-01-01"


def test_batch_effective_date_is_the_utc_date_of_collected_at(tmp_path):
    fake = FakeParamify()
    body = env(fetcher="x")
    body["metadata"]["collected_at"] = "2026-01-01T20:30:00-07:00"  # 2026-01-02 in UTC
    build(tmp_path, {"a.json": body}, [inv("x", ["a.json"])], {"x": {"use": "x"}})
    h = Harness(fake, tmp_path)
    h.run()
    assert json.loads(h.sent[0]["artifact"][1])["effectiveDate"] == "2026-01-02"
    assert fake._artifacts[0]["batchId"] == "bt-1"


def test_upload_without_collected_at_sends_the_upload_time_as_effective_date(tmp_path):
    fake = FakeParamify()
    body = env(fetcher="x")
    del body["metadata"]["collected_at"]
    build(tmp_path, {"a.json": body}, [inv("x", ["a.json"])], {"x": {"use": "x"}})
    h = Harness(fake, tmp_path)
    h.run()
    meta = json.loads(h.sent[0]["artifact"][1])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", meta["effectiveDate"])  # today, as a date: the batch route


def test_payload_mode_sends_only_the_payload(tmp_path):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path))
    plan = engine.plan(h.providers, SyncContext(tmp_path, {"artifact_payload": "payload"}), Reader(h.res))
    h.apply(plan)
    assert json.loads(h.sent[0]["file"][1]) == {"k": 1}


def test_events_count_files_and_bytes(tmp_path):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path))
    h.run()
    evs = h.file_events()
    size = len(json.dumps(json.loads((tmp_path / "a.json").read_text()), indent=2).encode())
    assert [(e["file"], e["outcome"], e["n"], e["of"]) for e in evs] == [
        ("a.json", "uploaded", 1, 2), ("b.json", "uploaded", 2, 2)]
    assert evs[0]["bytes"] == size and evs[0]["action_id"] == "delivery/x"


def test_noop_action_applies_as_noop_with_the_batch(tmp_path):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path))
    h.run()
    again = Harness(fake, tmp_path).run()["delivery/x"]
    assert again.status == "noop"
    assert again.result["state"] == "noop" and again.result["batch_id"] == "bt-1"
    assert again.result["status"] == "APPROVED"


def test_noop_reports_a_file_the_done_batch_does_not_have_as_dropped(tmp_path):
    fake = FakeParamify()
    fake.fail_upload("b.json", 400, "bad file")
    h = Harness(fake, two_files(tmp_path))
    assert h.run()["delivery/x"].result["state"] == "delivered_with_drops"
    fake.calls.clear()
    again = Harness(fake, tmp_path)
    d = again.run()["delivery/x"]
    assert d.status == "noop" and d.result["batch_id"] == "bt-1"
    assert d.result["dropped"] == [{"name": "b.json", "reason": "not in approved batch BCH-1"}]
    assert "b.json" in d.message
    assert [(e["file"], e["outcome"]) for e in again.file_events()] == [("b.json", "dropped")]
    assert again.uploads() == [] and again.submits() == []


# ---- resume -----------------------------------------------------------------

def test_resume_uploads_only_missing_files_then_submits(tmp_path):
    fake = FakeParamify()
    ev, ar = with_request(fake)
    h = Harness(fake, two_files(tmp_path))
    made = h.res.create_batch(artifact_request_id=ar.id)
    h.res.upload_to_batch(made.id, "a.json", b"{}", {"note": "fetcher=x; version=0.1.0; run_id=RID; entry=x"})
    fake.calls.clear()
    d = h.run()["delivery/x"]
    assert d.status == "applied", d.message
    assert d.result["already_present"] == ["a.json"] and d.result["uploaded"] == ["b.json"]
    assert d.result["batch_id"] == made.id and d.result["status"] == "APPROVED"
    assert h.uploads() == [f"/batches/{made.id}/artifacts/upload"]
    assert ("POST", "/batches", {}) not in fake.calls
    assert [(e["file"], e["outcome"], e["n"], e["of"]) for e in h.file_events()] == [
        ("a.json", "already_present", None, 1), ("b.json", "uploaded", 1, 1)]


def test_resume_skips_a_file_that_arrived_between_plan_and_apply(tmp_path):
    fake = FakeParamify()
    ev, ar = with_request(fake)
    h = Harness(fake, two_files(tmp_path))
    made = h.res.create_batch(artifact_request_id=ar.id)
    h.res.upload_to_batch(made.id, "a.json", b"{}", {"note": "fetcher=x; run_id=RID; entry=x"})
    plan = h.plan()
    h.res.upload_to_batch(made.id, "b.json", b"{}", {"note": "fetcher=x; run_id=RID; entry=x"})
    fake.calls.clear()
    d = h.apply(plan)["delivery/x"]
    assert d.result["already_present"] == ["a.json", "b.json"] and d.result["uploaded"] == []
    assert h.uploads() == [] and h.submits() == [f"/batches/{made.id}/submit"]


# ---- drop vs hold -----------------------------------------------------------

def test_waf_403_drops_the_file_and_submits_the_rest(tmp_path):
    fake = FakeParamify()
    fake.fail_upload("b.json", 403)
    h = Harness(fake, two_files(tmp_path))
    d = h.run()["delivery/x"]
    assert d.status == "applied"
    assert d.result["state"] == "delivered_with_drops" and d.result["status"] == "APPROVED"
    assert d.result["uploaded"] == ["a.json"]
    assert d.result["dropped"] == [{"name": "b.json", "reason": "blocked by the production WAF"}]
    assert "b.json" in d.message
    assert [e["outcome"] for e in h.file_events()] == ["uploaded", "dropped"]


def test_other_4xx_drops_with_the_api_message(tmp_path):
    fake = FakeParamify()
    fake.fail_upload("b.json", 413, "Payload Too Large")
    h = Harness(fake, two_files(tmp_path))
    d = h.run()["delivery/x"]
    assert d.result["state"] == "delivered_with_drops"
    [drop] = d.result["dropped"]
    assert drop["name"] == "b.json" and "HTTP 413" in drop["reason"] and "Payload Too Large" in drop["reason"]


def test_plan_time_waf_drops_are_named_in_the_outcome(tmp_path):
    fake = FakeParamify()
    bad = env(fetcher="x")
    bad["payload"] = {"cmd": "/bin/sh -c x"}
    build(tmp_path, {"a.json": env(fetcher="x"), "b.json": bad}, [inv("x", ["a.json", "b.json"])], {"x": {"use": "x"}})
    h = Harness(fake, tmp_path)
    d = h.run()["delivery/x"]
    assert d.result["state"] == "delivered_with_drops" and d.result["uploaded"] == ["a.json"]
    [drop] = d.result["dropped"]
    assert drop["name"] == "b.json" and drop["reason"].startswith("blocked by the production WAF: '/bin/sh'")


def test_temporary_failure_after_budget_holds_the_batch_open(tmp_path):
    fake = FakeParamify()
    fake.fail_upload("a.json", 503)
    h = Harness(fake, two_files(tmp_path))
    d = h.run()["delivery/x"]
    assert d.status == "failed"
    assert d.result["state"] == "held" and d.result["status"] == "OPEN"
    assert d.result["uploaded"] == ["b.json"] and d.result["dropped"] == []
    assert "a.json" in d.message and "BCH-1" in d.message
    assert batch_row(fake, "bt-1")["status"] == "OPEN" and h.submits() == []
    assert [e["outcome"] for e in h.file_events()] == ["held", "uploaded"]


def test_held_batch_resumes_on_the_next_upload(tmp_path):
    fake = FakeParamify()
    fake.fail_upload("a.json", 503)
    h = Harness(fake, two_files(tmp_path))
    assert h.run()["delivery/x"].result["state"] == "held"
    del fake._fail_all["a.json"]
    fake.calls.clear()
    d = Harness(fake, tmp_path).run()["delivery/x"]
    assert d.status == "applied" and d.result["batch_id"] == "bt-1"
    assert d.result["already_present"] == ["b.json"] and d.result["uploaded"] == ["a.json"]
    assert ("POST", "/batches", {}) not in fake.calls


def test_all_uploads_dropped_at_apply_fails_entry(tmp_path):
    fake = FakeParamify()
    fake.fail_upload("a.json", 403)
    fake.fail_upload("b.json", 400, "bad file")
    h = Harness(fake, two_files(tmp_path))
    d = h.run()["delivery/x"]
    assert d.status == "failed" and d.message == "every file was dropped"
    assert d.result["state"] == "failed" and d.result["uploaded"] == []
    assert [x["name"] for x in d.result["dropped"]] == ["a.json", "b.json"]
    assert h.submits() == []


def test_unreadable_file_at_apply_is_dropped(tmp_path):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path))
    plan = h.plan()
    (tmp_path / "b.json").unlink()
    d = h.apply(plan)["delivery/x"]
    assert d.result["state"] == "delivered_with_drops" and d.result["uploaded"] == ["a.json"]
    [drop] = d.result["dropped"]
    assert drop["name"] == "b.json" and drop["reason"].startswith("cannot read b.json")


# ---- conflicts, missing, fatal ----------------------------------------------

def test_409_after_an_in_app_submit_fails_with_the_batch_status(tmp_path):
    fake = FakeParamify()
    ev, ar = with_request(fake, approval="MANUAL")
    h = Harness(fake, two_files(tmp_path))
    made = h.res.create_batch(artifact_request_id=ar.id)
    h.res.upload_to_batch(made.id, "a.json", b"{}", {"note": "fetcher=x; run_id=RID; entry=x"})
    plan = h.plan()
    h.res.submit_batch(made.id)  # someone submits in the app
    d = h.apply(plan)["delivery/x"]
    assert d.status == "failed"
    assert d.result["state"] == "failed" and d.result["status"] == "SUBMITTED"
    assert d.result["batch_id"] == made.id and d.result["batch_reference"] == made.reference_id
    assert "SUBMITTED" in d.message and made.reference_id in d.message


def test_missing_target_on_create_fails_the_action(tmp_path):
    fake = FakeParamify()
    ev = fake.add_evidence("EVD-X")  # no channels: an evidence-level batch
    h = Harness(fake, two_files(tmp_path))
    plan = h.plan()
    fake._evidence.clear()  # deleted in the app between plan and apply
    d = h.apply(plan)["delivery/x"]
    assert d.status == "failed"
    assert d.message == f"evidence set {ev.id} no longer exists; plan the upload again"
    assert d.result["state"] == "failed" and d.result["batch_id"] is None


def test_batch_id_is_recorded_even_when_the_first_upload_raises(tmp_path):
    fake = FakeParamify()
    fake.fail_upload("a.json", 401)
    h = Harness(fake, two_files(tmp_path))
    out = engine.apply(h.plan(), h.providers, h.res)
    assert [o.status for o in out] == ["applied", "failed"]
    assert RunState(tmp_path).batch_for("x") == "bt-1"


def test_fatal_error_is_raised(tmp_path):
    fake = FakeParamify()
    fake.add_evidence("EVD-X")
    fake.fail_upload("a.json", 401)
    h = Harness(fake, two_files(tmp_path))
    [action] = [a for a in h.plan().actions if a.provider == "delivery"]
    with pytest.raises(ApiError) as exc:
        h.delivery.apply(action, h.res, lambda v: v)
    assert exc.value.kind is ErrorKind.FATAL


# ---- submit and read back ---------------------------------------------------

class ValidatingFake(FakeParamify):
    """Submit leaves the batch SUBMITTED with failing validators on its artifacts."""

    def _submit(self, batch):
        out = super()._submit(batch)
        batch["status"] = "SUBMITTED"
        for a in self._artifacts:
            if a["batchId"] == batch["id"]:
                a["validators"] = [
                    {"id": "v1", "name": "MFA enforced", "result": "FAIL"},
                    {"id": "v2", "name": "Encryption", "result": "PASS"},
                    {"id": "v3", "name": "Regex broke", "result": "ERROR"},
                ]
        return out


def test_submitted_with_passing_validators_lists_failing_validators(tmp_path):
    fake = ValidatingFake()
    h = Harness(fake, two_files(tmp_path, {"x": {"use": "x", "approval": SWPV}}))
    d = h.run()["delivery/x"]
    assert d.status == "applied"
    assert d.result["status"] == "SUBMITTED"
    assert d.result["validators_failed"] == ["MFA enforced", "Regex broke"]
    assert "MFA enforced" in d.message


def test_manual_approval_reports_submitted_waiting_for_review(tmp_path):
    fake = FakeParamify()
    with_request(fake, approval="MANUAL")
    h = Harness(fake, two_files(tmp_path, {"x": {"use": "x", "approval": "MANUAL"}}))
    d = h.run()["delivery/x"]
    assert d.result["status"] == "SUBMITTED" and d.result["validators_failed"] == []
    assert "waiting for review" in d.message and "MANUAL" in d.message


def test_submit_temporary_failure_holds(tmp_path, monkeypatch):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path))

    def boom(batch_id):
        raise ApiError("POST submit failed (HTTP 502)", status=502, kind=ErrorKind.TEMPORARY,
                       method="POST", path=f"/batches/{batch_id}/submit")

    monkeypatch.setattr(h.res, "submit_batch", boom)
    d = h.run()["delivery/x"]
    assert d.status == "failed" and d.result["state"] == "held" and d.result["status"] == "OPEN"
    assert d.result["uploaded"] == ["a.json", "b.json"]


def test_other_api_error_fails_the_entry_with_its_message(tmp_path, monkeypatch):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path))

    def warn(batch_id):
        raise ApiError("odd warning", status=403, kind=ErrorKind.WARNING, method="POST", path="/x")

    monkeypatch.setattr(h.res, "submit_batch", warn)
    d = h.run()["delivery/x"]
    assert d.status == "failed" and d.message == "odd warning" and d.result["state"] == "failed"


# ---- cycle rollover between plan and apply ----------------------------------

def test_rollover_between_plan_and_apply_replans_to_the_new_current_request(tmp_path):
    fake = FakeParamify()
    ev, old = with_request(fake, requested=date(2026, 10, 1), due=date(2026, 11, 5))
    new = fake.add_request(ev.id, ev.channels[0].id, date(2026, 11, 6), date(2026, 11, 30))
    h = Harness(fake, two_files(tmp_path))
    plan = h.plan()
    [act] = [a for a in plan.actions if a.provider == "delivery"]
    assert act.payload["artifact_request_id"] == old.id and act.payload["planned_current"] is True
    fake.set_today(date(2026, 11, 10))
    d = h.apply(plan)["delivery/x"]
    assert d.status == "applied", d.message
    assert batch_row(fake, d.result["batch_id"])["artifactRequestId"] == new.id
    assert "re-planned" in d.message


def test_rollover_with_no_new_request_goes_late_to_the_planned_one(tmp_path):
    fake = FakeParamify()
    ev, old = with_request(fake, requested=date(2026, 10, 1), due=date(2026, 11, 5))
    h = Harness(fake, two_files(tmp_path))
    plan = h.plan()
    fake.set_today(date(2026, 11, 10))
    d = h.apply(plan)["delivery/x"]
    assert d.status == "applied"
    assert batch_row(fake, d.result["batch_id"])["artifactRequestId"] == old.id


def test_rollover_check_is_skipped_when_resuming(tmp_path):
    fake = FakeParamify()
    ev, old = with_request(fake, requested=date(2026, 10, 1), due=date(2026, 11, 5))
    fake.add_request(ev.id, ev.channels[0].id, date(2026, 11, 6), date(2026, 11, 30))
    h = Harness(fake, two_files(tmp_path))
    made = h.res.create_batch(artifact_request_id=old.id)
    h.res.upload_to_batch(made.id, "a.json", b"{}", {"note": "fetcher=x; run_id=RID; entry=x"})
    plan = h.plan()
    fake.set_today(date(2026, 11, 10))
    fake.calls.clear()
    d = h.apply(plan)["delivery/x"]
    assert d.status == "applied" and d.result["batch_id"] == made.id
    assert not any(c[1] == "/artifact-requests" for c in fake.calls)
    assert ("POST", "/batches", {}) not in fake.calls


def test_rollover_replan_that_refuses_returns_refused(tmp_path):
    fake = FakeParamify()
    ev, old = with_request(fake, requested=date(2026, 10, 1), due=date(2026, 11, 5))
    h = Harness(fake, two_files(tmp_path, {"x": {"use": "x", "no_request": "refuse"}}))
    plan = h.plan()
    fake.set_today(date(2026, 11, 10))
    fake._requests.clear()  # the request was deleted: nothing current or past
    d = h.apply(plan)["delivery/x"]
    assert d.status == "refused" and "no current or past artifact request" in d.message
    assert ("POST", "/batches", {}) not in fake.calls


def test_rollover_replan_that_goes_direct_uploads_direct(tmp_path):
    fake = FakeParamify()
    ev, old = with_request(fake, requested=date(2026, 10, 1), due=date(2026, 11, 5))
    h = Harness(fake, two_files(tmp_path))  # no_request: the default, direct
    plan = h.plan()
    fake.set_today(date(2026, 11, 10))
    fake._requests.clear()  # the request was deleted: nothing current or past
    d = h.apply(plan)["delivery/x"]
    assert d.status == "applied", d.message
    assert ("POST", "/batches", {}) not in fake.calls and fake._batches == []
    assert h.uploads() == [f"/evidence/{ev.id}/artifacts/upload"] * 2
    assert d.result["mode"] == "direct" and d.result["batch_id"] is None
    assert [a["_channelId"] for a in fake._artifacts] == [ev.channels[0].id] * 2
    assert d.message.count("CH-1 has no artifact request") == 1
    assert d.message.startswith("re-planned, the artifact request rolled over: ")
    assert "CH-1 has no artifact request; sent direct, as before batches" in d.message


# ---- observe carry-over -----------------------------------------------------

def test_observe_entry_with_no_sendable_names_skips_the_artifacts_query(tmp_path):
    from framework.paramify.resources import EvidenceSet
    from framework.sync.providers.desired import DeliveryFile, EntryDesired

    calls: List[str] = []

    class R:
        def artifacts(self, *a, **k):
            calls.append("artifacts")
            return []

        def batches(self, **k):
            return []

    e = EntryDesired("x", "x", "RID", "EVD-X", {}, None, SWPV, None, None, "refuse",
                     (DeliveryFile(tmp_path / "a.json", "a.json", "t", "n", "evidence", "skipped"),), None)
    DeliveryProvider()._observe_entry(e, EvidenceSet("ev-1", "EVD-X", "X", SWPV, ()), R())
    assert calls == []


def test_unexpected_verb_fails():
    p = DeliveryProvider()
    out = p.apply(Action("delivery/x", "delivery", "x", "create", "s"), None, lambda v: v)
    assert out.status == "failed"


# ---- temporary failures before a batch exists, read-back, re-plan warnings ---

def _temporary(path: str) -> ApiError:
    return ApiError(f"GET {path} failed after retrying (HTTP 503)", status=503,
                    kind=ErrorKind.TEMPORARY, method="GET", path=path)


def test_temporary_failure_creating_the_batch_holds_with_no_batch(tmp_path, monkeypatch):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path))
    plan = h.plan()

    def boom(**_kw):
        raise _temporary("/batches")

    monkeypatch.setattr(h.res, "create_batch", boom)
    d = h.apply(plan)["delivery/x"]
    assert d.status == "failed"
    assert d.result["state"] == "held" and d.result["batch_id"] is None
    assert d.result["uploaded"] == [] and h.uploads() == []
    assert "no batch was recorded" in d.message and "HTTP 503" in d.message
    assert RunState(tmp_path).batch_for("x") is None


def test_temporary_failure_reading_a_resumed_batch_holds_it(tmp_path, monkeypatch):
    fake = FakeParamify()
    ev, ar = with_request(fake)
    h = Harness(fake, two_files(tmp_path))
    made = h.res.create_batch(artifact_request_id=ar.id)
    h.res.upload_to_batch(made.id, "a.json", b"{}", {"note": "fetcher=x; run_id=RID; entry=x"})
    plan = h.plan()

    def boom(*_a, **_kw):
        raise _temporary(f"/evidence/{ev.id}/artifacts")

    monkeypatch.setattr(h.res, "artifacts", boom)
    d = h.apply(plan)["delivery/x"]
    assert d.status == "failed" and d.result["state"] == "held"
    assert d.result["batch_id"] == made.id and h.submits() == []
    assert "stays OPEN" in d.message


def test_temporary_failure_in_the_rollover_check_holds_with_no_batch(tmp_path, monkeypatch):
    fake = FakeParamify()
    with_request(fake, requested=date(2026, 10, 1), due=date(2026, 11, 5))
    h = Harness(fake, two_files(tmp_path))
    plan = h.plan()

    def boom(*_a, **_kw):
        raise _temporary("/artifact-requests")

    monkeypatch.setattr(h.res, "artifact_requests", boom)
    fake.calls.clear()
    d = h.apply(plan)["delivery/x"]
    assert d.status == "failed"
    assert d.result["state"] == "held" and d.result["batch_id"] is None
    assert ("POST", "/batches", {}) not in fake.calls


def test_failed_read_back_after_submit_reports_the_submit_answer(tmp_path, monkeypatch):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path))
    plan = h.plan()

    def boom(batch_id):
        raise _temporary(f"/batches/{batch_id}")

    monkeypatch.setattr(h.res, "batch", boom)
    d = h.apply(plan)["delivery/x"]
    assert d.status == "applied"
    assert d.result["state"] == "delivered" and d.result["status"] == "APPROVED"
    assert d.message == "BCH-1 APPROVED"
    assert h.submits() == ["/batches/bt-1/submit"]


def test_failed_read_back_and_no_submit_status_reports_no_status(tmp_path, monkeypatch):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path))
    plan = h.plan()
    real_submit = h.res.submit_batch

    def boom(batch_id):
        raise _temporary(f"/batches/{batch_id}")

    def submit_without_status(batch_id):
        return dataclasses.replace(real_submit(batch_id), status="")

    monkeypatch.setattr(h.res, "batch", boom)
    monkeypatch.setattr(h.res, "submit_batch", submit_without_status)
    d = h.apply(plan)["delivery/x"]
    assert d.status == "applied"
    assert d.result["state"] == "delivered" and d.result["status"] is None
    assert d.result["uploaded"] == ["a.json", "b.json"]
    assert d.message == "submitted; status could not be read back"


class LaggingFake(FakeParamify):
    """Stage, once: the submit answers APPROVED but the next read still says SUBMITTED."""

    def __init__(self) -> None:
        super().__init__()
        self.lag: set = set()

    def _submit(self, batch):
        out = super()._submit(batch)
        self.lag.add(batch["id"])
        return out

    def _route(self, method, path, params, body, files):
        resp = super()._route(method, path, params, body, files)
        bid = path.rsplit("/", 1)[-1]
        if method == "GET" and path.startswith("/batches/") and bid in self.lag and resp.status_code == 200:
            self.lag.discard(bid)
            body = resp.json()
            body["status"] = "SUBMITTED"
            return type(resp)(200, body)
        return resp


def test_lagging_read_after_approve_on_submission_reports_approved(tmp_path):
    fake = LaggingFake()
    with_request(fake, approval="SUBMISSION")
    h = Harness(fake, two_files(tmp_path))
    d = h.run()["delivery/x"]
    assert d.status == "applied", d.message
    assert d.result["status"] == "APPROVED"
    assert "waiting for review" not in d.message and d.message.endswith("APPROVED")


class SlowApproveFake(FakeParamify):
    """Stage, 2026-11-12: the submit and the read just after it both say SUBMITTED
    for a batch approved on submission; it reads APPROVED a few seconds later."""

    def _submit(self, batch):
        out = super()._submit(batch)
        if batch["whenToApprove"] == "SUBMISSION" and out.status_code == 200:
            batch["status"] = "SUBMITTED"
            return type(out)(200, dict(batch))
        return out


def test_approve_on_submission_not_yet_approved_does_not_say_review(tmp_path):
    fake = SlowApproveFake()
    with_request(fake, approval="MANUAL")
    d = Harness(fake, two_files(tmp_path)).run()["delivery/x"]
    assert d.result["status"] == "SUBMITTED"
    assert "waiting for review" not in d.message
    assert "approved on submission; not approved yet when read back" in d.message


def test_validator_gated_batch_trusts_the_read_over_the_submit(tmp_path):
    fake = LaggingFake()
    with_request(fake, approval=SWPV)
    h = Harness(fake, two_files(tmp_path, {"x": {"use": "x", "approval": SWPV}}))
    d = h.run()["delivery/x"]
    assert d.result["status"] == "SUBMITTED"


def test_rollover_replan_warnings_reach_the_outcome_message(tmp_path):
    fake = FakeParamify()
    ev, old = with_request(fake, requested=date(2026, 10, 1), due=date(2026, 11, 5))
    h = Harness(fake, two_files(tmp_path))
    plan = h.plan()
    fake.set_today(date(2026, 11, 10))
    d = h.apply(plan)["delivery/x"]
    assert d.status == "applied"
    assert "re-planned" in d.message
    assert f"late submission to {old.reference_id} (due 2026-11-05)" in d.message


# ---- direct (the route before batches) ---------------------------------------

BATCHES_OFF = Capability(False, FLAG_OFF)


def flag_off_with_channel(fake):
    """A set with one channel, on a workspace whose batches flag is off."""
    fake.batches_flag_off()
    st = fake.add_stack("Prod")
    return fake.add_evidence("EVD-X", channels=[st.id])


def test_direct_apply_uploads_each_file_with_the_channel_id(tmp_path):
    fake = FakeParamify()
    ev = flag_off_with_channel(fake)
    h = Harness(fake, two_files(tmp_path), capability=BATCHES_OFF)
    d = h.run()["delivery/x"]
    assert d.status == "applied", d.message
    assert h.uploads() == [f"/evidence/{ev.id}/artifacts/upload"] * 2
    assert not [c for c in fake.calls if c[1].startswith(("/batches", "/artifact-requests"))]
    assert [a["_channelId"] for a in fake._artifacts] == [ev.channels[0].id] * 2
    assert [a["batchId"] for a in fake._artifacts] == [None, None]
    r = d.result
    assert r["mode"] == "direct" and r["state"] == "delivered" and r["batch_id"] is None
    assert r["status"] is None and r["uploaded"] == ["a.json", "b.json"]
    meta = json.loads(h.sent[0]["artifact"][1])
    assert {"title", "note", "effectiveDate", "channelId"} == set(meta)
    assert meta["effectiveDate"] == "2026-01-01T00:00:00Z"
    assert [(e["file"], e["outcome"], e["n"], e["of"]) for e in h.file_events()] == [
        ("a.json", "uploaded", 1, 2), ("b.json", "uploaded", 2, 2)]


def test_direct_apply_with_no_channel_sends_no_channel_id(tmp_path):
    fake = FakeParamify()
    fake.batches_flag_off()
    fake.add_evidence("EVD-X")
    h = Harness(fake, two_files(tmp_path), capability=BATCHES_OFF)
    d = h.run()["delivery/x"]
    assert d.result["state"] == "delivered" and d.result["mode"] == "direct"
    assert {"title", "note", "effectiveDate"} == set(json.loads(h.sent[0]["artifact"][1]))


def test_direct_apply_to_a_set_made_in_this_run(tmp_path):
    fake = FakeParamify()
    fake.batches_flag_off()
    h = Harness(fake, two_files(tmp_path), capability=BATCHES_OFF)
    out = h.run()
    assert out["evidence_sets/EVD-X"].status == "applied"
    assert out["delivery/x"].result["state"] == "delivered"
    ev_id = fake._evidence[0]["id"]
    assert h.uploads() == [f"/evidence/{ev_id}/artifacts/upload"] * 2


def test_direct_temporary_failure_holds_one_file_and_resends_only_it(tmp_path):
    fake = FakeParamify()
    flag_off_with_channel(fake)
    fake.fail_upload_once("b.json", 503)
    h = Harness(fake, two_files(tmp_path), capability=BATCHES_OFF, budget=0)
    d = h.run()["delivery/x"]
    assert d.status == "failed"
    assert d.result["state"] == "held" and d.result["mode"] == "direct" and d.result["batch_id"] is None
    assert d.result["uploaded"] == ["a.json"]
    assert d.message == "held: b.json failed temporarily; the next upload sends it"
    assert [e["outcome"] for e in h.file_events()] == ["uploaded", "held"]

    fake.calls.clear()
    h2 = Harness(fake, tmp_path, capability=BATCHES_OFF)
    again = h2.run()["delivery/x"]
    assert again.status == "applied" and again.result["state"] == "delivered"
    assert again.result["uploaded"] == ["b.json"]
    assert [p["file"][0] for p in h2.sent] == ["b.json"]
    assert not [c for c in fake.calls if c[1].startswith(("/batches", "/artifact-requests"))]


def test_direct_temporary_failure_of_two_files_says_them(tmp_path):
    fake = FakeParamify()
    flag_off_with_channel(fake)
    fake.fail_upload_once("a.json", 503)
    fake.fail_upload_once("b.json", 503)
    h = Harness(fake, two_files(tmp_path), capability=BATCHES_OFF, budget=0)
    d = h.run()["delivery/x"]
    assert d.result["state"] == "held"
    assert d.message == "held: a.json, b.json failed temporarily; the next upload sends them"


def test_direct_permanent_failure_drops_one_file(tmp_path):
    fake = FakeParamify()
    flag_off_with_channel(fake)
    fake.fail_upload("a.json", 413, "Payload Too Large")
    h = Harness(fake, two_files(tmp_path), capability=BATCHES_OFF)
    d = h.run()["delivery/x"]
    assert d.status == "applied"
    assert d.result["state"] == "delivered_with_drops" and d.result["mode"] == "direct"
    assert d.result["uploaded"] == ["b.json"]
    [drop] = d.result["dropped"]
    assert drop["name"] == "a.json" and "HTTP 413" in drop["reason"]
    assert "a.json" in d.message
    assert [a["originalFileName"] for a in fake._artifacts] == ["b.json"]


def test_direct_every_file_dropped_fails_the_entry(tmp_path):
    fake = FakeParamify()
    flag_off_with_channel(fake)
    fake.fail_upload("a.json", 403)
    fake.fail_upload("b.json", 400, "bad file")
    h = Harness(fake, two_files(tmp_path), capability=BATCHES_OFF)
    d = h.run()["delivery/x"]
    assert d.status == "failed" and d.message == "every file was dropped"
    assert d.result["state"] == "failed" and d.result["mode"] == "direct"
    assert d.result["dropped"][0] == {"name": "a.json", "reason": "blocked by the production WAF"}


def test_direct_fatal_error_is_raised(tmp_path):
    fake = FakeParamify()
    flag_off_with_channel(fake)
    fake.fail_upload("a.json", 401)
    h = Harness(fake, two_files(tmp_path), capability=BATCHES_OFF)
    [action] = [a for a in h.plan().actions if a.provider == "delivery"]
    assert action.payload["target"] == "DIRECT"
    with pytest.raises(ApiError) as exc:
        h.delivery.apply(action, h.res, lambda v: v)
    assert exc.value.kind is ErrorKind.FATAL


def test_direct_noop_applies_as_noop_with_no_batch(tmp_path):
    fake = FakeParamify()
    flag_off_with_channel(fake)
    Harness(fake, two_files(tmp_path), capability=BATCHES_OFF).run()
    again = Harness(fake, tmp_path, capability=BATCHES_OFF).run()["delivery/x"]
    assert again.status == "noop" and again.result["mode"] == "direct" and again.result["batch_id"] is None


# ---- pipeline entries ---------------------------------------------------------

INVENTORY = {"type": "inventory", "id_scheme": "x-id"}


def inventory_run(tmp_path: Path, paramify=None) -> Path:
    body = env(fetcher="x", pipeline=INVENTORY, inventory={"complete": True})
    return build(tmp_path, {"inv.json": body}, [inv("x", ["inv.json"])], paramify or {"x": {"use": "x"}})


def test_pipeline_file_is_sent_and_scanned_as_the_envelope(tmp_path, monkeypatch):  # Review Focus 2
    from framework.sync.providers import delivery as delivery_mod
    scanned: List[bytes] = []
    real_scan = delivery_mod.waf.scan
    monkeypatch.setattr(delivery_mod.waf, "scan", lambda content, *a: (scanned.append(content), real_scan(content, *a))[1])
    fake = FakeParamify()
    h = Harness(fake, inventory_run(tmp_path), upload_cfg={"artifact_payload": "payload"})
    out = h.run()
    assert out["delivery/x"].status == "applied", out["delivery/x"].message
    sent = [p["file"][1] for p in h.sent if p["file"][0] == "inv.json"]
    assert len(sent) == 1 and set(json.loads(sent[0])) == {"schema_version", "metadata", "payload"}
    assert scanned and all(set(json.loads(c)) == {"schema_version", "metadata", "payload"} for c in scanned)


def test_ordinary_file_is_still_sent_as_the_payload_when_asked(tmp_path):
    fake = FakeParamify()
    h = Harness(fake, two_files(tmp_path), upload_cfg={"artifact_payload": "payload"})
    h.run()
    assert json.loads(h.sent[0]["file"][1]) == {"k": 1}


def test_approved_pipeline_batch_says_the_pipeline_runs(tmp_path):
    fake = FakeParamify()
    outcome = Harness(fake, inventory_run(tmp_path)).run()["delivery/x"]
    assert outcome.status == "applied", outcome.message
    assert "APPROVED: pipeline runs now; check Monitoring → Inventory" in outcome.message
    assert outcome.result["pipeline"] == {"type": "inventory", "approved": True}


def test_submitted_pipeline_batch_is_not_success(tmp_path):
    fake = FakeParamify()
    outcome = Harness(fake, inventory_run(tmp_path, {"x": {"use": "x", "approval": "MANUAL"}})).run()["delivery/x"]
    assert "SUBMITTED: waiting for approval; the pipeline has not run" in outcome.message
    assert outcome.result["pipeline"]["approved"] is False


class SlowApprovalFake(FakeParamify):
    """A batch approved on submission whose approval has not landed by the read-back."""

    def _submit(self, batch):
        out = super()._submit(batch)
        if out.status_code == 200 and batch["whenToApprove"] == "SUBMISSION":
            batch["status"] = "SUBMITTED"
            return type(out)(200, dict(batch))
        return out


def test_pipeline_batch_approved_on_submission_but_not_yet_counts_as_approved(tmp_path):
    outcome = Harness(SlowApprovalFake(), inventory_run(tmp_path)).run()["delivery/x"]
    assert "approved on submission; not approved yet" in outcome.message
    assert "the pipeline runs once Paramify approves it" in outcome.message
    assert outcome.result["status"] == "SUBMITTED"
    assert outcome.result["pipeline"] == {"type": "inventory", "approved": True}


def test_ordinary_entry_result_has_no_pipeline_key(tmp_path):
    outcome = Harness(FakeParamify(), two_files(tmp_path)).run()["delivery/x"]
    assert "pipeline" not in outcome.result


def test_direct_pipeline_entry_reports_approved_null(tmp_path):
    fake = FakeParamify()
    fake.batches_flag_off()
    outcome = Harness(fake, inventory_run(tmp_path), capability=Capability(False, FLAG_OFF)).run()["delivery/x"]
    assert outcome.status == "applied", outcome.message
    assert outcome.result["mode"] == "direct"
    assert outcome.result["pipeline"] == {"type": "inventory", "approved": None}
    assert "sent direct: this workspace has no batches; the pipeline runs the pre-batch way" in outcome.message


def test_pipeline_entry_resends_files_sent_direct_before_batches(tmp_path):
    # The first upload went direct (batches off); with batches on, the re-upload sends it again in a batch.
    fake = FakeParamify()
    fake.batches_flag_off()
    run_dir = inventory_run(tmp_path)
    first = Harness(fake, run_dir, capability=Capability(False, FLAG_OFF)).run()["delivery/x"]
    assert first.status == "applied" and first.result["mode"] == "direct"
    fake.batches_flag_off(False)
    h = Harness(fake, run_dir)
    plan = h.plan()
    [action] = [a for a in plan.actions if a.provider == "delivery"]
    assert action.verb == "deliver"
    assert ("1 file(s) of this run went direct before; sending them again in a batch so the pipeline runs"
            in action.warnings)
    outcome = h.apply(plan)["delivery/x"]
    assert outcome.status == "applied", outcome.message
    assert outcome.result["uploaded"] == ["inv.json"] and outcome.result["mode"] == "batch"
    assert outcome.result["pipeline"] == {"type": "inventory", "approved": True}


def test_pipeline_noop_result_carries_the_pipeline(tmp_path):
    fake = FakeParamify()
    run_dir = inventory_run(tmp_path)
    Harness(fake, run_dir).run()
    again = Harness(fake, run_dir).run()["delivery/x"]
    assert again.status == "noop", again.message
    assert again.result["pipeline"] == {"type": "inventory", "approved": True}


def test_already_delivered_pipeline_run_with_a_new_validator_is_noop(tmp_path):
    fake = FakeParamify()
    run_dir = inventory_run(tmp_path)
    Harness(fake, run_dir).run()
    fake._evidence[0]["validators"] = [{"validatorEvidencePairId": "vp-0", "id": "vl-0", "name": "VAL-1",
                                        "type": "REGEX"}]
    again = Harness(fake, run_dir).run()["delivery/x"]
    assert again.status == "noop", again.message
    assert again.result["pipeline"] == {"type": "inventory", "approved": True}


def test_pipeline_entry_recorded_with_the_pipeline_defaults_goes_in_a_batch(tmp_path):
    # A run recorded under run.paramify no_request: direct holds the pipeline default for the inventory entry.
    fake = FakeParamify()
    with_request(fake)
    fake._requests.clear()  # a channel with no artifact request: where no_request: direct would send it direct
    h = Harness(fake, inventory_run(tmp_path, {"x": {"use": "x", "delivery": "auto", "no_request": "evidence"}}))
    plan = h.plan()
    [action] = [a for a in plan.actions if a.provider == "delivery"]
    assert action.verb == "deliver" and action.payload["target"] == "EVIDENCE"


def test_pipeline_entry_recorded_with_an_inherited_direct_says_how_to_fix_it(tmp_path):
    fake = FakeParamify()
    h = Harness(fake, inventory_run(tmp_path, {"x": {"use": "x", "no_request": "direct"}}))
    [action] = [a for a in h.plan().actions if a.provider == "delivery"]
    assert action.verb == "refuse"
    assert action.fix == ("set no_request: evidence on this entry, or remove direct from run.paramify, "
                          "then run again")
