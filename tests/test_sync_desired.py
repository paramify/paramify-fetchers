"""desired_from_run: one EntryDesired per manifest entry, read from a run dir."""
import json

from framework.sync.providers.desired import desired_from_run
from framework.sync.state import RunState


def env(*, fetcher="x", ref="EVD-X", name="Set X", status="success", target=None,
        inventory=None, category="cat"):
    md = {
        "fetcher_name": fetcher, "fetcher_version": "0.1.0", "run_id": "RID",
        "collected_at": "2026-01-01T00:00:00Z", "status": status,
        "evidence_set": {"reference_id": ref, "name": name}, "category": category,
    }
    if target:
        md["target"] = target
    if inventory is not None:
        md["inventory"] = inventory
    return {"schema_version": "1.0", "metadata": md, "payload": {"k": 1}}


def build(tmp_path, files, invocations=None, paramify=None):
    for fname, body in files.items():
        (tmp_path / fname).write_text(body if isinstance(body, str) else json.dumps(body))
    if invocations is not None:
        meta = {"run_id": "RID", "manifest": None, "invocations": invocations}
        if paramify is not None:
            meta["paramify"] = paramify
        (tmp_path / "_run_metadata.json").write_text(json.dumps(meta))
    return tmp_path


def inv(key, outputs, fetcher="x"):
    return {"fetcher_name": fetcher, "fetcher_version": "0.1.0", "target": None,
            "exit_code": 0, "outputs": outputs, "entry_key": key}


def test_desired_groups_targets_into_one_entry(tmp_path):
    build(tmp_path, {"a.json": env(target={"id": "1"}), "b.json": env(target={"id": "2"})},
          [inv("x", ["a.json", "b.json"])], {"x": {"use": "x"}})
    [e] = desired_from_run(tmp_path, {})
    assert e.entry_key == "x" and e.use == "x" and e.run_id == "RID"
    assert [f.original_file_name for f in e.files] == ["a.json", "b.json"]
    assert e.reference_id == "EVD-X" and e.category == "cat"
    assert e.approval == "SUBMISSION" and e.no_request == "direct"


def test_entry_delivery_defaults_to_auto(tmp_path):
    build(tmp_path, {"a.json": env()}, [inv("x", ["a.json"])], {"x": {"use": "x"}})
    [e] = desired_from_run(tmp_path, {})
    assert e.delivery == "auto"


def test_entry_no_request_defaults_to_direct(tmp_path):
    build(tmp_path, {"a.json": env()}, [inv("x", ["a.json"])])
    [e] = desired_from_run(tmp_path, {})
    assert e.no_request == "direct"


def test_entry_delivery_direct_from_run_metadata(tmp_path):
    build(tmp_path, {"a.json": env()}, [inv("x", ["a.json"])], {"x": {"use": "x", "delivery": "direct"}})
    [e] = desired_from_run(tmp_path, {})
    assert e.delivery == "direct"


def test_desired_two_entries_same_use(tmp_path):
    build(tmp_path, {"a.json": env(ref="EVD-A"), "b.json": env(ref="EVD-B")},
          [inv("x", ["a.json"]), inv("x#1", ["b.json"])],
          {"x": {"use": "x", "stack": "S1", "approval": "MANUAL"},
           "x#1": {"use": "x", "stack_name": "Main", "no_request": "evidence"}})
    a, b = desired_from_run(tmp_path, {})
    assert (a.entry_key, a.reference_id, a.stack, a.approval) == ("x", "EVD-A", "S1", "MANUAL")
    assert (b.entry_key, b.stack_name, b.no_request) == ("x#1", "Main", "evidence")
    assert a.approval_explicit is True
    assert b.approval_explicit is False and b.approval == "SUBMISSION"


def test_desired_from_legacy_run(tmp_path):
    build(tmp_path, {"a.json": env(fetcher="f1"), "b.json": env(fetcher="f2", ref="EVD-2")},
          [{"fetcher_name": "f1", "outputs": ["a.json"], "exit_code": 0}])
    es = desired_from_run(tmp_path, {})
    assert [e.entry_key for e in es] == ["f1", "f2"]
    assert all(e.stack is None for e in es)
    assert es[0].use == "f1"


def test_legacy_run_without_metadata(tmp_path):
    build(tmp_path, {"a.json": env(fetcher="f1")})
    [e] = desired_from_run(tmp_path, {})
    assert e.entry_key == "f1" and e.run_id == "RID"


def test_stack_override_wins(tmp_path):
    build(tmp_path, {"a.json": env()}, [inv("x", ["a.json"])],
          {"x": {"use": "x", "stack": "S1", "stack_name": "Main"}})
    [e] = desired_from_run(tmp_path, {}, stack_override="S9")
    assert e.stack == "S9" and e.stack_name is None


def test_owner_comes_from_the_run_settings(tmp_path):
    build(tmp_path, {"a.json": env()}, [inv("x", ["a.json"])], {"x": {"use": "x", "owner": "alice"}})
    [e] = desired_from_run(tmp_path, {})
    assert e.owner == "alice"


def test_owner_override_wins(tmp_path):
    build(tmp_path, {"a.json": env()}, [inv("x", ["a.json"])], {"x": {"use": "x", "owner": "alice"}})
    [e] = desired_from_run(tmp_path, {}, owner_override="bob")
    assert e.owner == "bob"


def test_skip_reasons_match_uploader(tmp_path):
    build(tmp_path, {
        "failed.json": env(status="failed"),
        "inv.json": env(inventory={"complete": False, "incomplete_because": ["page 3 failed"]}),
        "plain.json": {"just": "data"},
        "bad.json": "{nope",
        "ok.json": env(),
    }, [inv("x", ["failed.json", "inv.json", "plain.json", "bad.json", "ok.json"])])
    [e] = desired_from_run(tmp_path, {"skip_failed": True})
    by = {f.original_file_name: f for f in e.files}
    assert by["failed.json"].skip_reason
    assert by["inv.json"].skip_reason == "incomplete inventory not sent: page 3 failed"
    assert by["inv.json"].kind == "inventory"
    assert by["plain.json"].skip_reason == "not envelope-wrapped"
    assert by["bad.json"].skip_reason.startswith("cannot read as JSON")
    assert by["ok.json"].skip_reason is None
    assert e.reference_id == "EVD-X"
    # failed status uploads by default
    [e2] = desired_from_run(tmp_path, {})
    assert {f.original_file_name: f.skip_reason for f in e2.files}["failed.json"] is None


def test_a_file_a_later_entry_overwrote_is_not_sent(tmp_path):
    # The file holds the later invocation's data, whatever its envelope says, so
    # it goes under that entry and is never sent. The run already failed it.
    later = dict(inv("x#1", []), exit_code=1, overwritten=["a.json"])
    build(tmp_path, {"a.json": env(), "b.json": env()}, [inv("x", ["a.json", "b.json"]), later])
    by = {e.entry_key: e for e in desired_from_run(tmp_path, {})}
    [f] = by["x#1"].files
    assert f.original_file_name == "a.json"
    assert (f.skip_kind, f.skip_reason) == ("error", "overwritten later in this run (entry x#1); not sent")
    assert [(g.original_file_name, g.skip_reason) for g in by["x"].files] == [("b.json", None)]


def test_a_file_a_later_target_overwrote_is_not_sent(tmp_path):
    first = dict(inv("x", ["out.json"]), target={"region": "a"})
    second = dict(inv("x", []), target={"region": "b"}, exit_code=1, overwritten=["out.json"])
    build(tmp_path, {"out.json": env(target={"region": "a"})}, [first, second])
    [e] = desired_from_run(tmp_path, {})
    [f] = e.files
    assert (f.skip_kind, f.skip_reason) == ("error", "overwritten later in this run (entry x); not sent")


def test_note_has_entry_token_and_the_effective_date_is_collected_at(tmp_path):
    build(tmp_path, {"a.json": env(target={"id": "7"})}, [inv("x#1", ["a.json"])])
    [e] = desired_from_run(tmp_path, {})
    f = e.files[0]
    assert f.note == ('fetcher=x; version=0.1.0; run_id=RID; status=success; '
                      'target={"id":"7"}; entry=x#1')
    assert f.title == "Set X - 7"
    assert f.effective_date == "2026-01-01T00:00:00Z"


def test_effective_date_is_none_without_collected_at(tmp_path):
    body = env()
    del body["metadata"]["collected_at"]
    build(tmp_path, {"a.json": body}, [inv("x", ["a.json"])])
    [e] = desired_from_run(tmp_path, {})
    assert e.files[0].effective_date is None


def test_recorded_batch_id_from_state(tmp_path):
    build(tmp_path, {"a.json": env()}, [inv("x", ["a.json"])])
    RunState(tmp_path).record_batch("x", "B1")
    [e] = desired_from_run(tmp_path, {})
    assert e.recorded_batch_id == "B1"


def test_overrides_and_only_file(tmp_path):
    build(tmp_path, {"a.json": env(), "b.json": env()}, [inv("x", ["a.json", "b.json"])])
    [e] = desired_from_run(tmp_path, {"overrides": {"x": {"reference_id": "EVD-O", "name": "N"}}},
                           only_file="b.json")
    assert [f.original_file_name for f in e.files] == ["b.json"]
    assert e.reference_id == "EVD-O" and e.evidence_set["name"] == "N"


def test_skip_kind_separates_errors_from_decisions(tmp_path):
    no_set = env()
    del no_set["metadata"]["evidence_set"]
    build(tmp_path, {"a.json": env(status="failed"), "b.json": "{not json", "c.json": '{"k": 1}',
                     "d.json": no_set, "e.json": env(inventory={"complete": False})},
          [inv("x", ["a.json", "b.json", "c.json", "d.json", "e.json"])], {"x": {"use": "x"}})
    [e] = desired_from_run(tmp_path, {"skip_failed": True})
    assert {f.original_file_name: f.skip_kind for f in e.files} == {
        "a.json": "skipped", "b.json": "error", "c.json": "error", "d.json": "error", "e.json": "skipped"}
