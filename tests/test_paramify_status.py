"""api.paramify_status: what each manifest fetcher has in the Paramify workspace.

The workspace reads (`list_evidence_sets`, `list_capabilities`) and the scripts
dry run are stubbed at the `api` boundary; the manifest, fetcher discovery and
the status logic run for real. The validator registry is stubbed, because
validator content mostly lives outside the repo.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework import api
from framework import validators as registry
from framework.contract import Validator

REPO_ROOT = Path(__file__).resolve().parents[1]


def _manifest(tmp_path: Path, *uses: str) -> Path:
    path = tmp_path / "status.yaml"
    entries = "".join(f"    - use: {u}\n" for u in uses)
    path.write_text(f"run:\n  output_dir: {tmp_path / 'evidence'}\n  fetchers:\n{entries}")
    return path


def _validator(key: str, name: str, ref: str, role: str = "configuration") -> Validator:
    return Validator(key=key, name=name, type="AUTOMATED", statement="s", evidence_sets=[ref],
                     role=role, path=REPO_ROOT / "validators" / "x" / f"{key}.yaml", category="x")


@pytest.fixture
def workspace(monkeypatch, tmp_path):
    """A token, a registry with two validators on demo_hello's set, and stubs
    for the three workspace reads. Tests change `state` before calling."""
    monkeypatch.setenv("PARAMIFY_UPLOAD_API_TOKEN", "tok")
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(registry, "discover_validators", lambda root: {
        "hello_complete": _validator("hello_complete", "Hello complete", "EVD-DEMO-HELLO", "completeness"),
        "hello_greets": _validator("hello_greets", "Hello greets", "EVD-DEMO-HELLO"),
    })
    state = {
        "sets": [{"id": "ev-1", "reference_id": "EVD-DEMO-HELLO", "name": "Hello", "artifact_count": 2,
                  "validators": [{"pair_id": "p-1", "id": "v-1", "name": "Hello complete", "type": "AUTOMATED"},
                                 {"pair_id": "p-2", "id": "v-2", "name": "Hello greets", "type": "AUTOMATED"}]}],
        "outcomes": {"demo_hello": "would_noop", "demo_policy_check": "would_create"},
        "caps": [{"id": "c-1", "reference_id": "SC-AC-06", "template_reference_id": "", "name": "Least privilege",
                  "functions": [{"type": "PROVIDER", "pairs": [
                      {"pair_id": "p-1", "validator_id": "v-1", "evidence_id": "ev-1"},
                      {"pair_id": "p-2", "validator_id": "v-2", "evidence_id": "ev-1"}]}]}],
    }

    def scripts_sync(root, config_path=None, *, dry_run=False, include=None, on_event=None, **kw):
        assert dry_run, "the status must never write"
        for name in sorted(include or ()):
            if name in state["outcomes"]:
                on_event({"event": "sync_item", "fetcher": name, "outcome": state["outcomes"][name]})
        return {"ok": True}

    monkeypatch.setattr(api, "list_evidence_sets", lambda: state["sets"])
    monkeypatch.setattr(api, "list_capabilities", lambda: state["caps"])
    monkeypatch.setattr(api, "scripts_sync", scripts_sync)
    return state


def _row(status: dict, name: str) -> dict:
    return next(r for r in status["fetchers"] if r["name"] == name)


def test_ready_needs_set_script_validators_and_an_artifact(tmp_path, workspace):
    path = _manifest(tmp_path, "demo_hello")
    assert _row(api.paramify_status(REPO_ROOT, path), "demo_hello")["ready"] is True

    workspace["outcomes"]["demo_hello"] = "would_update"
    assert _row(api.paramify_status(REPO_ROOT, path), "demo_hello")["ready"] is False
    workspace["outcomes"]["demo_hello"] = "would_noop"

    workspace["sets"][0]["artifact_count"] = 0
    assert _row(api.paramify_status(REPO_ROOT, path), "demo_hello")["ready"] is False
    workspace["sets"][0]["artifact_count"] = 2

    workspace["sets"][0]["validators"] = workspace["sets"][0]["validators"][:1]
    assert _row(api.paramify_status(REPO_ROOT, path), "demo_hello")["ready"] is False

    workspace["sets"] = []
    row = _row(api.paramify_status(REPO_ROOT, path), "demo_hello")
    assert row["evidence_set"]["id"] is None and row["ready"] is False


def test_script_outcomes_map_to_states(tmp_path, workspace):
    path = _manifest(tmp_path, "demo_hello")
    expected = {"would_noop": "in_sync", "would_update": "update", "would_create": "create",
                "would_drift": "drift", "error": "error"}
    for outcome, state in expected.items():
        workspace["outcomes"]["demo_hello"] = outcome
        assert _row(api.paramify_status(REPO_ROOT, path), "demo_hello")["script"] == state


def test_paired_reads_the_lock_then_the_name(tmp_path, workspace):
    path = _manifest(tmp_path, "demo_hello")
    # The Paramify name differs from the registry's; only the lock can pair it.
    workspace["sets"][0]["validators"][1]["name"] = "Renamed in Paramify"
    paired = {v["key"]: v["paired"] for v in _row(api.paramify_status(REPO_ROOT, path), "demo_hello")["validators"]}
    assert paired == {"hello_complete": True, "hello_greets": False}

    lock = tmp_path / ".paramify" / "validators-sync.lock.json"
    lock.parent.mkdir()
    lock.write_text(json.dumps({"validators": {"hello_greets": "v-2"}}))
    paired = {v["key"]: v["paired"] for v in _row(api.paramify_status(REPO_ROOT, path), "demo_hello")["validators"]}
    assert paired == {"hello_complete": True, "hello_greets": True}


def test_paired_falls_back_to_name_when_the_lock_is_bad(tmp_path, workspace):
    lock = tmp_path / ".paramify" / "validators-sync.lock.json"
    lock.parent.mkdir()
    lock.write_text("not json")
    path = _manifest(tmp_path, "demo_hello")
    paired = [v["paired"] for v in _row(api.paramify_status(REPO_ROOT, path), "demo_hello")["validators"]]
    assert paired == [True, True]


def test_pairs_join_capability_functions_to_the_set(tmp_path, workspace):
    status = api.paramify_status(REPO_ROOT, _manifest(tmp_path, "demo_hello"))
    pairs = _row(status, "demo_hello")["pairs"]
    assert {(p["capability_id"], p["function"], p["validator_key"]) for p in pairs} == {
        ("c-1", "PROVIDER", "hello_complete"), ("c-1", "PROVIDER", "hello_greets"),
    }
    assert status["capabilities"][0]["reference_id"] == "SC-AC-06"


def test_no_token_reads_nothing(tmp_path, workspace, monkeypatch):
    monkeypatch.delenv("PARAMIFY_UPLOAD_API_TOKEN")
    monkeypatch.delenv("PARAMIFY_API_TOKEN", raising=False)

    def boom(*a, **k):
        raise AssertionError("no token: nothing may call the workspace")

    for name in ("list_evidence_sets", "list_capabilities", "scripts_sync"):
        monkeypatch.setattr(api, name, boom)
    status = api.paramify_status(REPO_ROOT, _manifest(tmp_path, "demo_hello"))
    row = _row(status, "demo_hello")
    assert status["workspace"]["token"] is False
    assert status["capabilities"] == []
    assert row["script"] is None and row["evidence_set"]["id"] is None
    assert [v["paired"] for v in row["validators"]] == [False, False]
    assert row["ready"] is False


def test_one_failed_part_leaves_the_others(tmp_path, workspace, monkeypatch):
    def denied():
        raise RuntimeError("HTTP 403")

    monkeypatch.setattr(api, "list_capabilities", denied)
    status = api.paramify_status(REPO_ROOT, _manifest(tmp_path, "demo_hello"))
    assert status["errors"] == {"capabilities": "HTTP 403"}
    row = _row(status, "demo_hello")
    assert row["evidence_set"]["id"] == "ev-1" and row["script"] == "in_sync"
    assert row["pairs"] == []


def test_issue_reports_are_counted_and_discovery_left_out(tmp_path, workspace):
    path = _manifest(tmp_path, "demo_hello", "aws_inspector_ecr_report", "aws_discovery_beta")
    status = api.paramify_status(REPO_ROOT, path)
    assert [r["name"] for r in status["fetchers"]] == ["demo_hello"]
    assert status["pipelines_count"] == 1


def test_unknown_and_duplicate_entries(tmp_path, workspace):
    path = _manifest(tmp_path, "demo_hello", "demo_hello", "no_such_fetcher")
    status = api.paramify_status(REPO_ROOT, path)
    assert [r["name"] for r in status["fetchers"]] == ["demo_hello"]
    assert status["skipped"] == ["no_such_fetcher"]


def test_a_set_with_no_registry_validators_can_be_ready(tmp_path, workspace):
    workspace["sets"].append({"id": "ev-2", "reference_id": "EVD-DEMO-POLICY-CHECK", "name": "Policy",
                              "artifact_count": 1, "validators": []})
    workspace["outcomes"]["demo_policy_check"] = "would_noop"
    row = _row(api.paramify_status(REPO_ROOT, _manifest(tmp_path, "demo_policy_check")), "demo_policy_check")
    assert row["validators"] == [] and row["ready"] is True


def test_an_uploader_override_names_the_set(tmp_path, workspace):
    """The scripts sync and the upload send an overridden fetcher to the set its
    override names; the status must read that set, or the row never gets ready."""
    workspace["sets"][0]["reference_id"] = "CUST-HELLO-01"
    config = tmp_path / "upload.yaml"
    config.write_text("overrides:\n  demo_hello:\n    reference_id: CUST-HELLO-01\n")
    row = _row(api.paramify_status(REPO_ROOT, _manifest(tmp_path, "demo_hello"), config), "demo_hello")
    assert row["evidence_set"]["reference_id"] == "CUST-HELLO-01"
    assert row["evidence_set"]["id"] == "ev-1"
    # The registry still names the shipped set, so its validators still apply.
    assert [v["key"] for v in row["validators"]] == ["hello_complete", "hello_greets"]
    assert row["ready"] is True
