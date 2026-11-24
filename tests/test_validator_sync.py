"""Reconcile-engine tests for the validator syncer.

Drives sync_validators against the shared fake workspace behind the real Client
(no network) to pin the create-or-skip / associate-on-create-only / --update /
--dry-run / lock behaviour, asserting on what ends up in the workspace.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from framework.paramify.client import Client
from tests.paramify_fake import FakeParamify

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNCER_PATH = REPO_ROOT / "uploaders" / "paramify_validators" / "syncer.py"


def _load_syncer():
    spec = importlib.util.spec_from_file_location("paramify_validators_syncer", SYNCER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


syncer = _load_syncer()

PROVENANCE = "Automated by Paramify Fetchers"
ALB_SET = "EVD-LB-ENC-STATUS"


def _alb():
    return {
        "key": "alb_encryption_in_transit",
        "name": "ALB Encryption In Transit",
        "type": "AUTOMATED",
        "statement": "Ensures ALBs encrypt in transit.",
        "regex": r'"alb_total":\s*(\d+)',
        "validation_rules": [{"regexOperation": {"type": "MATCH_COUNT"}, "criteria": "GREATER_THAN", "value": {"type": "CUSTOM_TEXT", "customText": "0"}}],
        "attestation_rules": [],
        "evidence_sets": [ALB_SET],
    }


def _workspace(*sets: str) -> FakeParamify:
    fake = FakeParamify()
    for ref in sets:
        fake.add_evidence(ref)
    return fake


def _run(validators, fake, tmp_path, **kw):
    # retry_budget_s=0: a failed read is an error at once, not after back-off.
    client = Client("tok", "https://api.example.test", session=fake.session,
                    sleep=lambda _s: None, retry_budget_s=0)
    return syncer.sync_validators(validators, client=client, lock_path=str(tmp_path / "lock.json"), **kw)


def _lock(tmp_path):
    return json.loads((tmp_path / "lock.json").read_text())["validators"]


def _linked(fake):
    refs = {e["id"]: e["referenceId"] for e in fake._evidence}
    return {(refs[ev], vid) for ev, kind, vid in fake.associations if kind == "VALIDATOR"}


def _writes(fake):
    return [(m, p) for m, p, _ in fake.calls if m != "GET"]


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for name in ("PARAMIFY_CUSTOM_TAGS", "PARAMIFY_UPLOAD_API_TOKEN", "PARAMIFY_API_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")


def test_create_sends_the_api_shape_and_associates(tmp_path):
    fake = _workspace(ALB_SET)
    s = _run([_alb()], fake, tmp_path)
    assert s["created"] == 1 and s["associated"] == 1 and s["ok"]
    [made] = fake.validators
    # Registry snake_case becomes the API's camelCase; repo-side fields stay home.
    assert made["validationRules"] and made["regex"] and made["type"] == "AUTOMATED"
    assert not {"validation_rules", "key", "evidence_sets", "attestationRules"} & set(made)
    assert _linked(fake) == {(ALB_SET, made["id"])}
    assert _lock(tmp_path)["alb_encryption_in_transit"] == made["id"]


def test_attestation_validator_sends_its_rules_and_no_regex(tmp_path):
    v = {"key": "k", "name": "N", "type": "ATTESTATION", "statement": "s",
         "attestation_rules": [{"question": "ok?", "yesDisposition": "PASS", "noDisposition": "FAIL", "nestedRules": []}],
         "evidence_sets": []}
    fake = FakeParamify()
    _run([v], fake, tmp_path)
    [made] = fake.validators
    assert made["attestationRules"] and "regex" not in made


def test_skip_when_locked_no_writes(tmp_path):
    (tmp_path / "lock.json").write_text(json.dumps({"validators": {"alb_encryption_in_transit": "v1"}}))
    fake = _workspace(ALB_SET)
    s = _run([_alb()], fake, tmp_path, config={"tags": False})
    assert s["skipped"] == 1 and s["created"] == 0
    assert _writes(fake) == []


def test_adopt_existing_by_name_no_create_no_associate(tmp_path):
    fake = _workspace(ALB_SET)
    existing = fake.add_validator("ALB Encryption In Transit")
    s = _run([_alb()], fake, tmp_path)
    assert s["skipped"] == 1 and s["created"] == 0
    assert fake.validators == [existing] and fake.associations == set()  # adoption != creation
    assert _lock(tmp_path)["alb_encryption_in_transit"] == existing["id"]  # cached for next run


def test_update_patches_but_does_not_associate(tmp_path):
    fake = _workspace(ALB_SET)
    existing = fake.add_validator("old name")
    (tmp_path / "lock.json").write_text(json.dumps({"validators": {"alb_encryption_in_transit": existing["id"]}}))
    s = _run([_alb()], fake, tmp_path, update=True)
    assert s["updated"] == 1 and s["skipped"] == 0
    assert fake.validators[0]["name"] == "ALB Encryption In Transit"
    assert fake.associations == set()


def test_dry_run_makes_no_writes(tmp_path):
    fake = _workspace(ALB_SET)
    s = _run([_alb()], fake, tmp_path, dry_run=True)
    assert s["created"] == 1 and s["dry_run"]
    assert _writes(fake) == []
    assert not (tmp_path / "lock.json").exists()  # lock untouched in dry-run


def test_set_not_found_still_creates(tmp_path):
    fake = FakeParamify()  # set missing
    s = _run([_alb()], fake, tmp_path)
    assert s["created"] == 1 and s["associated"] == 0 and s["set_not_found"] == 1
    assert len(fake.validators) == 1 and fake.associations == set()


def test_per_validator_error_isolated(tmp_path):
    fake = FakeParamify()
    fake.fail_route("POST", "/validators", 500, "api down")
    s = _run([_alb(), {**_alb(), "key": "second", "name": "Second"}], fake, tmp_path)
    assert s["errors"] == 2 and s["ok"] is False  # both isolated, batch completes


def test_list_failure_fails_closed_no_duplicate_create(tmp_path):
    """If GET /validators fails, reconcile must NOT create duplicates — it fails
    closed (every not-yet-locked validator errors, none is created)."""
    fake = _workspace(ALB_SET)
    fake.fail_route("GET", "/validators", 500, "boom")
    v2 = {**_alb(), "key": "second", "name": "Second"}
    s = _run([_alb(), v2], fake, tmp_path)  # neither in lock -> both consult the name index
    assert s["created"] == 0 and s["errors"] == 2 and s["ok"] is False
    assert fake.validators == []  # crucially, NO spurious creates


def test_associate_failure_isolated_not_double_counted(tmp_path):
    fake = _workspace("EVD-A", "EVD-B")
    fake.fail_route("POST", r"/evidence/[^/]+/associate", 500, "assoc failed")
    v = {**_alb(), "evidence_sets": ["EVD-A", "EVD-B"]}
    s = _run([v], fake, tmp_path)
    assert s["created"] == 1 and s["errors"] == 0 and s["associate_errors"] == 2
    assert s["ok"] is False  # association failure surfaced, not swallowed
    r = s["results"][0]
    made = fake.validators[0]["id"]
    assert r["outcome"] == "created" and r["validator_id"] == made  # id preserved
    assert r.get("associate_failed") == ["EVD-A", "EVD-B"]
    assert _lock(tmp_path)["alb_encryption_in_transit"] == made  # locked -> no re-create


def test_a_rejected_token_stops_the_sweep(tmp_path):
    fake = FakeParamify()
    fake.fail_route("POST", "/validators", 401, "Unauthorized")
    s = _run([_alb(), {**_alb(), "key": "second", "name": "Second"}], fake, tmp_path)
    assert s["stopped"] and "401" in s["stopped"] and s["ok"] is False
    assert len([c for c in fake.calls if c[:2] == ("POST", "/validators")]) == 1


def test_a_rejected_token_after_a_create_still_locks_and_reports_it(tmp_path):
    """The validator exists once created; losing its lock entry would leave the
    next run adopting it by name and never connecting it."""
    fake = _workspace(ALB_SET)
    fake.fail_route("POST", r"/evidence/[^/]+/associate", 403, "Forbidden")
    s = _run([_alb(), {**_alb(), "key": "second", "name": "Second"}], fake, tmp_path)
    made = fake.validators[0]["id"]
    assert s["stopped"] and len(fake.validators) == 1   # the second was never attempted
    assert s["results"][0]["outcome"] == "created" and s["results"][0]["associate_failed"] == [ALB_SET]
    assert _lock(tmp_path) == {"alb_encryption_in_transit": made}


def test_a_dry_run_with_a_token_reads_the_workspace_and_writes_nothing(tmp_path, monkeypatch):
    fake = _workspace(ALB_SET)
    fake.add_validator("ALB Encryption In Transit")
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "env-tok")
    monkeypatch.setenv("PARAMIFY_API_BASE_URL", "https://api.example.test")
    monkeypatch.setattr("framework.paramify.client.requests.Session", lambda: fake.session)
    s = syncer.sync_validators([_alb()], dry_run=True, lock_path=str(tmp_path / "lock.json"))
    assert s["results"][0]["outcome"] == "would_skip_exists"   # it read the workspace
    assert _writes(fake) == []


def test_update_emits_per_item_event(tmp_path):
    fake = FakeParamify()
    existing = fake.add_validator("ALB Encryption In Transit")
    (tmp_path / "lock.json").write_text(json.dumps({"validators": {"alb_encryption_in_transit": existing["id"]}}))
    events = []
    s = _run([_alb()], fake, tmp_path, update=True, on_event=events.append)
    assert s["updated"] == 1
    upd = [e for e in events if e.get("event") == "sync_validator" and e.get("outcome") == "updated"]
    assert len(upd) == 1 and upd[0]["validator_id"] == existing["id"]


def test_missing_key_isolated_not_crash(tmp_path):
    fake = _workspace(ALB_SET)
    bad = {k: val for k, val in _alb().items() if k != "key"}
    s = _run([bad, _alb()], fake, tmp_path)  # must not raise
    assert s["errors"] == 1 and s["created"] == 1


def test_missing_token_is_a_setup_error(tmp_path):
    with pytest.raises(ValueError, match="PARAMIFY_UPLOAD_API_TOKEN.*PARAMIFY_API_TOKEN"):
        syncer.sync_validators([], lock_path=str(tmp_path / "lock.json"))


# --------------------------------------------------------------------------- #
# Default custom tags — on create, on skip, on update; never in a dry run
# --------------------------------------------------------------------------- #

def test_created_validator_is_tagged_with_its_category(tmp_path):
    fake = _workspace(ALB_SET)
    s = _run([{**_alb(), "category": "aws"}], fake, tmp_path, display_names={"aws": "AWS"})
    made = fake.validators[0]["id"]
    assert fake.tags == {("validators", made): [PROVENANCE, "AWS"]}
    assert s["results"][0]["tags"] == [PROVENANCE, "AWS"]
    assert s["tags"]["applied"] == 1


@pytest.mark.parametrize("update, outcome", [(False, "skipped_exists"), (True, "updated")])
def test_existing_validator_is_tagged_on_skip_and_update(tmp_path, update, outcome):
    fake = FakeParamify()
    existing = fake.add_validator("ALB Encryption In Transit")
    s = _run([_alb()], fake, tmp_path, update=update)
    assert s["results"][0]["outcome"] == outcome
    assert fake.tags == {("validators", existing["id"]): [PROVENANCE]}


def test_dry_run_plans_tags_and_tags_nothing(tmp_path):
    fake = _workspace(ALB_SET)
    s = _run([_alb()], fake, tmp_path, dry_run=True)
    assert fake.tags == {}
    assert s["results"][0]["tags"] == [PROVENANCE]


@pytest.mark.parametrize("off, reason", [
    ({"config": {"tags": False}}, "tags: false"),
    ({"custom_tags": False}, "--no-tags"),
    ({"env": "off"}, "PARAMIFY_CUSTOM_TAGS=off"),
])
def test_tags_switched_off_tag_nothing(tmp_path, monkeypatch, off, reason):
    if "env" in off:
        monkeypatch.setenv("PARAMIFY_CUSTOM_TAGS", off.pop("env"))
    fake = _workspace(ALB_SET)
    s = _run([_alb()], fake, tmp_path, **off)
    assert fake.tags == {}
    assert s["tags"]["enabled"] is False and reason in s["tags"]["reason"]
    assert s["results"][0]["outcome"] == "created" and s["results"][0]["tags"] == []


def test_missing_tag_permission_keeps_the_sync_ok(tmp_path):
    fake = _workspace(ALB_SET)
    fake.fail_route("POST", r"/custom-tags/.*", 403, "forbidden")
    s = _run([_alb(), {**_alb(), "key": "second", "name": "Second"}], fake, tmp_path)
    assert s["ok"] and s["errors"] == 0 and len(fake.validators) == 2
    assert len([c for c in fake.calls if c[1].startswith("/custom-tags/")]) == 1
    assert s["tags"]["disabled"]


# --- pair_existing and content-aware --update (the TUI's [v] asks for both) ---

OTHER_SET = "EVD-SQS-ENC"


def _alb_as_paramify_stores_it():
    """The registry validator as the API returns it: rules gain a default disposition, text a newline."""
    v = _alb()
    rules = [dict(r, disposition="PASS") for r in v["validation_rules"]]
    return {"statement": v["statement"] + "\n", "type": v["type"], "regex": v["regex"],
            "validationRules": rules}


def test_pair_existing_pairs_an_existing_validator_with_its_set(tmp_path):
    fake = _workspace(ALB_SET)
    existing = fake.add_validator("ALB Encryption In Transit")
    s = _run([_alb()], fake, tmp_path, pair_existing=True)
    assert s["skipped"] == 1 and s["paired_existing"] == 1 and s["ok"]
    assert _linked(fake) == {(ALB_SET, existing["id"])}
    assert s["results"][0]["paired"] == [ALB_SET]


def test_pair_existing_leaves_an_already_paired_set_alone(tmp_path):
    fake = FakeParamify()
    existing = fake.add_validator("ALB Encryption In Transit")
    fake.add_evidence(ALB_SET, validators=["ALB Encryption In Transit"])
    s = _run([_alb()], fake, tmp_path, pair_existing=True, config={"tags": False})
    assert s["paired_existing"] == 0 and s["associate_errors"] == 0
    assert _writes(fake) == []
    assert "paired" not in s["results"][0]
    assert existing["id"]  # adopted, not recreated


def test_pair_existing_stays_inside_pair_sets(tmp_path):
    fake = _workspace(ALB_SET, OTHER_SET)
    existing = fake.add_validator("ALB Encryption In Transit")
    v = dict(_alb(), evidence_sets=[ALB_SET, OTHER_SET], pair_sets=[ALB_SET])
    _run([v], fake, tmp_path, pair_existing=True)
    assert _linked(fake) == {(ALB_SET, existing["id"])}  # not every set it lists


def test_a_dry_run_reports_what_it_would_pair_and_writes_nothing(tmp_path):
    fake = _workspace(ALB_SET)
    fake.add_validator("ALB Encryption In Transit")
    s = _run([_alb()], fake, tmp_path, pair_existing=True, dry_run=True)
    assert s["results"][0]["would_pair"] == [ALB_SET] and s["paired_existing"] == 1
    assert _writes(fake) == []


def test_update_leaves_a_validator_that_matches_the_registry(tmp_path):
    fake = _workspace(ALB_SET)
    fake.add_validator("ALB Encryption In Transit", **_alb_as_paramify_stores_it())
    s = _run([_alb()], fake, tmp_path, update=True, config={"tags": False})
    assert s["updated"] == 0 and s["skipped"] == 1
    assert s["results"][0]["differs"] is False
    assert _writes(fake) == []


def test_update_patches_a_validator_that_differs(tmp_path):
    fake = _workspace(ALB_SET)
    tuned = dict(_alb_as_paramify_stores_it(), regex=r'"alb_total":\s*(\d+)\s*,')
    existing = fake.add_validator("ALB Encryption In Transit", **tuned)
    s = _run([_alb()], fake, tmp_path, update=True)
    assert s["updated"] == 1 and s["results"][0]["differs"] is True
    assert existing["regex"] == _alb()["regex"]


def test_a_dry_run_says_which_validators_differ(tmp_path):
    fake = _workspace(ALB_SET)
    fake.add_validator("ALB Encryption In Transit", **dict(_alb_as_paramify_stores_it(), statement="tuned"))
    s = _run([_alb()], fake, tmp_path, update=True, dry_run=True)
    assert s["results"][0]["outcome"] == "would_update" and s["results"][0]["differs"] is True
    assert _writes(fake) == []


def test_a_remote_rule_with_a_field_the_registry_lacks_differs():
    local = {"name": "n", "validationRules": [{"criteria": "EQUALS"}]}
    assert syncer.differs(local, {"name": "n", "validationRules": [{"criteria": "EQUALS", "disposition": "PASS"}]}) is False
    assert syncer.differs(local, {"name": "n", "validationRules": [{"criteria": "EQUALS", "disposition": "FAIL"}]}) is True
    assert syncer.differs(local, {}) is None
