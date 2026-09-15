"""Reconcile-engine unit tests for the validator syncer.

Drives sync_validators against an in-memory fake client (no network) to pin the
create-or-skip / associate-on-create-only / --update / --dry-run / lock behaviour.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNCER_PATH = REPO_ROOT / "uploaders" / "paramify_validators" / "syncer.py"


def _load_syncer():
    spec = importlib.util.spec_from_file_location("paramify_validators_syncer", SYNCER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


syncer = _load_syncer()

BASE = "https://example.test/api/v0"


class FakeClient:
    def __init__(self, existing=None, evidence_sets=None):
        self.existing = existing or []            # [{"id","name"}]
        self.evidence_sets = evidence_sets or {}  # reference_id -> evidence_id
        self.created, self.updated, self.associated = [], [], []
        self._n = 0

    def list_validators(self):
        return self.existing

    def create_validator(self, payload):
        self._n += 1
        vid = f"new-{self._n}"
        self.created.append((vid, payload))
        return vid

    def update_validator(self, vid, payload):
        self.updated.append((vid, payload))

    def find_evidence_set(self, ref):
        return self.evidence_sets.get(ref)

    def associate_validator(self, evidence_id, validator_id):
        self.associated.append((evidence_id, validator_id))


def _alb():
    return {
        "key": "alb_encryption_in_transit",
        "name": "ALB Encryption In Transit",
        "type": "AUTOMATED",
        "statement": "Ensures ALBs encrypt in transit.",
        "regex": r'"alb_total":\s*(\d+)',
        "validation_rules": [{"regexOperation": {"type": "MATCH_COUNT"}, "criteria": "GREATER_THAN", "value": {"type": "CUSTOM_TEXT", "customText": "0"}}],
        "attestation_rules": [],
        "evidence_sets": ["EVD-LB-ENC-STATUS"],
    }


def _run(validators, client, tmp_path, **kw):
    return syncer.sync_validators(
        validators, client=client, base_url=BASE,
        lock_path=str(tmp_path / "lock.json"), **kw,
    )


def test_build_payload_automated_maps_rules():
    p = syncer.build_payload(_alb())
    assert p["type"] == "AUTOMATED"
    assert "regex" in p and p["validationRules"] and "validation_rules" not in p
    assert "attestationRules" not in p


def test_build_payload_attestation():
    v = {"key": "k", "name": "N", "type": "ATTESTATION", "statement": "s",
         "attestation_rules": [{"question": "ok?", "yesDisposition": "PASS", "noDisposition": "FAIL", "nestedRules": []}],
         "evidence_sets": ["E"]}
    p = syncer.build_payload(v)
    assert p["type"] == "ATTESTATION" and p["attestationRules"] and "regex" not in p


def test_create_and_associate_on_create(tmp_path):
    c = FakeClient(evidence_sets={"EVD-LB-ENC-STATUS": "es-1"})
    s = _run([_alb()], c, tmp_path)
    assert s["created"] == 1 and s["associated"] == 1 and s["ok"]
    assert len(c.created) == 1 and c.associated == [("es-1", "new-1")]
    # lock persisted key -> minted id
    lock = json.loads((tmp_path / "lock.json").read_text())["validators"]
    assert lock["alb_encryption_in_transit"] == "new-1"


def test_skip_when_locked_no_writes(tmp_path):
    (tmp_path / "lock.json").write_text(json.dumps({"validators": {"alb_encryption_in_transit": "v1"}}))
    c = FakeClient(evidence_sets={"EVD-LB-ENC-STATUS": "es-1"})
    s = _run([_alb()], c, tmp_path)
    assert s["skipped"] == 1 and s["created"] == 0
    assert not c.created and not c.updated and not c.associated


def test_adopt_existing_by_name_no_create_no_associate(tmp_path):
    c = FakeClient(existing=[{"id": "ex-9", "name": "ALB Encryption In Transit"}],
                   evidence_sets={"EVD-LB-ENC-STATUS": "es-1"})
    s = _run([_alb()], c, tmp_path)
    assert s["skipped"] == 1 and s["created"] == 0
    assert not c.created and not c.associated  # adoption != creation -> no wiring
    lock = json.loads((tmp_path / "lock.json").read_text())["validators"]
    assert lock["alb_encryption_in_transit"] == "ex-9"  # id cached for next run


def test_update_patches_but_does_not_associate(tmp_path):
    (tmp_path / "lock.json").write_text(json.dumps({"validators": {"alb_encryption_in_transit": "v1"}}))
    c = FakeClient(evidence_sets={"EVD-LB-ENC-STATUS": "es-1"})
    s = _run([_alb()], c, tmp_path, update=True)
    assert s["updated"] == 1 and s["skipped"] == 0
    assert c.updated == [("v1", syncer.build_payload(_alb()))] and not c.associated


def test_dry_run_makes_no_writes(tmp_path):
    c = FakeClient(evidence_sets={"EVD-LB-ENC-STATUS": "es-1"})
    s = _run([_alb()], c, tmp_path, dry_run=True)
    assert s["created"] == 1 and s["dry_run"]
    assert not c.created and not c.associated and not c.updated
    assert not (tmp_path / "lock.json").exists()  # lock untouched in dry-run


def test_set_not_found_still_creates(tmp_path):
    c = FakeClient(evidence_sets={})  # set missing
    s = _run([_alb()], c, tmp_path)
    assert s["created"] == 1 and s["associated"] == 0 and s["set_not_found"] == 1
    assert len(c.created) == 1 and not c.associated


def test_per_validator_error_isolated(tmp_path):
    class Boom(FakeClient):
        def create_validator(self, payload):
            raise RuntimeError("api down")
    c = Boom()
    s = _run([_alb(), {**_alb(), "key": "second", "name": "Second"}], c, tmp_path)
    assert s["errors"] == 2 and s["ok"] is False  # both isolated, batch completes


def test_list_failure_fails_closed_no_duplicate_create(tmp_path):
    """If GET /validators fails, reconcile must NOT create duplicates — it fails
    closed (every not-yet-locked validator errors, none is created)."""
    class ListBoom(FakeClient):
        def list_validators(self):
            raise RuntimeError("HTTP 500")
    c = ListBoom(evidence_sets={"EVD-LB-ENC-STATUS": "es-1"})
    v2 = {**_alb(), "key": "second", "name": "Second"}
    s = _run([_alb(), v2], c, tmp_path)  # neither in lock -> both consult name_index
    assert s["created"] == 0 and s["errors"] == 2 and s["ok"] is False
    assert not c.created  # crucially, NO spurious creates


def test_associate_failure_isolated_not_double_counted(tmp_path):
    class AssocBoom(FakeClient):
        def associate_validator(self, evidence_id, validator_id):
            raise syncer.ParamifyError("assoc failed")
    c = AssocBoom(evidence_sets={"EVD-A": "es-a", "EVD-B": "es-b"})
    v = {**_alb(), "evidence_sets": ["EVD-A", "EVD-B"]}
    s = _run([v], c, tmp_path)
    assert s["created"] == 1 and s["errors"] == 0 and s["associate_errors"] == 2
    assert s["ok"] is False  # association failure surfaced, not swallowed
    r = s["results"][0]
    assert r["outcome"] == "created" and r["validator_id"] == "new-1"  # id preserved
    assert r.get("associate_failed") == ["EVD-A", "EVD-B"]
    lock = json.loads((tmp_path / "lock.json").read_text())["validators"]
    assert lock["alb_encryption_in_transit"] == "new-1"  # locked -> no re-create


def test_update_emits_per_item_event(tmp_path):
    (tmp_path / "lock.json").write_text(json.dumps({"validators": {"alb_encryption_in_transit": "v1"}}))
    events = []
    c = FakeClient()
    s = syncer.sync_validators(
        [_alb()], client=c, base_url=BASE, update=True,
        lock_path=str(tmp_path / "lock.json"), on_event=events.append,
    )
    assert s["updated"] == 1
    upd = [e for e in events if e.get("event") == "sync_validator" and e.get("outcome") == "updated"]
    assert len(upd) == 1 and upd[0]["validator_id"] == "v1"


def test_missing_key_isolated_not_crash(tmp_path):
    c = FakeClient(evidence_sets={"EVD-LB-ENC-STATUS": "es-1"})
    bad = {k: val for k, val in _alb().items() if k != "key"}
    s = _run([bad, _alb()], c, tmp_path)  # must not raise
    assert s["errors"] == 1 and s["created"] == 1
