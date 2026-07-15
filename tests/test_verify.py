"""Tests for the schema verification stage (framework/verify + runner wiring).

The load-bearing properties, in the order the design doc states them:

  1. the no-binding path is UNCHANGED — verify is never invoked, no new
     metadata, no changed exit codes;
  2. a conformant artifact records validation.ok=true and stays exit 0;
  3. a non-conformant artifact records structured errors, gets exit 2, and its
     envelope still validates against envelope_schema.json;
  4. $ref resolution is offline-only — the fixture report schema $refs the
     common-defs schema and resolves with the network hard-disabled;
  5. a pinned_version the store doesn't have is a hard error, never a silent
     pass — both from verify() (raises) and through the runner (records a
     failed validation + exit 2);
  6. one schema-failing artifact never sinks its run (runner-level; the
     uploader half lives in test_uploader.py).

The end-to-end tests run api.run() against a minimal temp repo root with REAL
fetcher subprocesses, so what's asserted is what the pipeline actually wrote.
"""

from __future__ import annotations

import json
import shutil
import socket
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

import framework.api as api
from framework.contract import EvidenceSet, Fetcher, InvocationResult, SchemaBinding
from framework.verify import (
    SCHEMA_VALIDATION_EXIT_CODE,
    SchemaStore,
    SchemaStoreError,
    verify,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
ENVELOPE_VALIDATOR = Draft202012Validator(
    json.loads((REPO_ROOT / "framework/schemas/envelope_schema.json").read_text())
)
FETCHER_VALIDATOR = Draft202012Validator(
    json.loads((REPO_ROOT / "framework/schemas/fetcher_schema.json").read_text())
)

REPORT_ID = "https://fixtures.paramify.invalid/schemas/sample-report.json"
BINDING = SchemaBinding(schema_id=REPORT_ID, pinned_version="1.0.0")

GOOD_PAYLOAD = {
    "report_id": "ABC-123",
    "generated_at": "2026-07-15T12:00:00Z",
    "items": [{"name": "control-1", "status": "open"}],
}
BAD_PAYLOAD = {
    "report_id": "not-an-identifier",
    "items": [{"name": "control-1", "status": "wat"}],
}


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore.default(REPO_ROOT)


# --------------------------------------------------------------------------- #
# verify() — the pure compute half
# --------------------------------------------------------------------------- #

def test_valid_payload_passes(store):
    result = verify(GOOD_PAYLOAD, BINDING, store)
    assert result.ok is True
    assert result.errors == [] and result.error_count == 0
    block = result.to_metadata()
    assert block["schema_id"] == REPORT_ID and block["pinned_version"] == "1.0.0"
    assert block["validator"].startswith("jsonschema ")


def test_invalid_payload_fails_with_machine_readable_errors(store):
    result = verify(BAD_PAYLOAD, BINDING, store)
    assert result.ok is False
    assert result.error_count == len(result.errors) == 3
    by_path = {e["path"]: e["message"] for e in result.errors}
    # every error carries a JSON-pointer path + message ('' = document root)
    assert "" in by_path and "generated_at" in by_path[""]
    assert "/report_id" in by_path
    # this failure comes from an enum in the $ref'd common-defs schema, so it
    # doubles as proof the cross-file $ref actually resolved
    assert "/items/0/status" in by_path


def test_ref_resolution_is_offline_only(monkeypatch):
    """Store construction AND validation both work with networking disabled.

    The fixture $ids live on an RFC 2606 .invalid host, so any dereference
    attempt could never succeed anyway — this test makes even the attempt an
    immediate failure.
    """
    def _no_network(*args, **kwargs):
        raise AssertionError("network access attempted during schema verification")

    monkeypatch.setattr(socket, "socket", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)

    offline_store = SchemaStore.default(REPO_ROOT)   # built inside the blackout
    assert verify(GOOD_PAYLOAD, BINDING, offline_store).ok is True
    assert verify(BAD_PAYLOAD, BINDING, offline_store).ok is False


def test_pinned_version_mismatch_is_a_hard_error(store):
    with pytest.raises(SchemaStoreError, match="pinned_version mismatch"):
        verify(GOOD_PAYLOAD, SchemaBinding(REPORT_ID, "9.9.9"), store)


def test_unknown_schema_id_is_a_hard_error(store):
    with pytest.raises(SchemaStoreError, match="not in the vendored store"):
        verify(GOOD_PAYLOAD, SchemaBinding("https://nope.invalid/x.json", "1.0.0"), store)


def test_ref_to_unvendored_schema_is_a_hard_error(tmp_path):
    """A $ref pointing outside the store raises — it is never fetched remotely."""
    dangling = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://fixtures.paramify.invalid/schemas/dangling.json",
        "type": "object",
        "properties": {
            "x": {"$ref": "https://fixtures.paramify.invalid/schemas/never-vendored.json"}
        },
    }
    (tmp_path / "dangling.json").write_text(json.dumps(dangling))
    (tmp_path / "index.yaml").write_text(yaml.safe_dump({"schemas": [{
        "schema_id": dangling["$id"], "version": "1.0.0", "file": "dangling.json",
    }]}))
    store = SchemaStore(tmp_path)
    with pytest.raises(SchemaStoreError, match="cannot resolve against the vendored store"):
        verify({"x": 1}, SchemaBinding(dangling["$id"], "1.0.0"), store)


def test_store_rejects_duplicate_schema_id(tmp_path):
    schema = {"$id": "https://fixtures.paramify.invalid/schemas/dup.json", "type": "object"}
    (tmp_path / "dup.json").write_text(json.dumps(schema))
    (tmp_path / "index.yaml").write_text(yaml.safe_dump({"schemas": [
        {"schema_id": schema["$id"], "version": "1.0.0", "file": "dup.json"},
        {"schema_id": schema["$id"], "version": "2.0.0", "file": "dup.json"},
    ]}))
    with pytest.raises(SchemaStoreError, match="duplicate schema_id"):
        SchemaStore(tmp_path)


def test_store_rejects_id_mismatch_between_file_and_index(tmp_path):
    (tmp_path / "s.json").write_text(json.dumps({"$id": "https://a.invalid/s.json"}))
    (tmp_path / "index.yaml").write_text(yaml.safe_dump({"schemas": [{
        "schema_id": "https://b.invalid/other.json", "version": "1.0.0", "file": "s.json",
    }]}))
    with pytest.raises(SchemaStoreError, match="does not match"):
        SchemaStore(tmp_path)


# --------------------------------------------------------------------------- #
# fetcher_schema.json — the binding is optional and additive
# --------------------------------------------------------------------------- #

MINIMAL_YAML = {
    "name": "t", "version": "0.1.0", "description": "d",
    "runtime": {"type": "python", "entry": "fetcher.py"},
    "output": {"type": "json", "path": "t.json"},
    "secrets": [],
}


def _with_evidence_set(**extra) -> dict:
    data = dict(MINIMAL_YAML)
    data["evidence_set"] = {"reference_id": "EVD-T", "name": "T", **extra}
    return data


def test_fetcher_yaml_without_binding_still_validates():
    assert not list(FETCHER_VALIDATOR.iter_errors(_with_evidence_set()))


def test_fetcher_yaml_with_binding_and_reserved_package_group_validates():
    data = _with_evidence_set(
        schema_binding={"schema_id": REPORT_ID, "pinned_version": "1.0.0"},
        package_group=None,   # reserved, nullable, ignored today
    )
    assert not list(FETCHER_VALIDATOR.iter_errors(data))


def test_binding_missing_pinned_version_is_schema_invalid():
    data = _with_evidence_set(schema_binding={"schema_id": REPORT_ID})
    errors = [e.message for e in FETCHER_VALIDATOR.iter_errors(data)]
    assert any("pinned_version" in m for m in errors)


# --------------------------------------------------------------------------- #
# Runner glue (api._apply_schema_verification) — compute → record boundary
# --------------------------------------------------------------------------- #

def make_fetcher(path, **ov) -> Fetcher:
    d = dict(
        name="f", version="0.1.0", description="d", category="cat",
        runtime_type="python", runtime_entry="fetcher.py", runtime_timeout=None,
        output_type="json", output_path="out.json", output_aggregation=None,
        secrets=[], supports_targets=False, target_schema={}, path=path,
        config_schema={}, evidence_set=None,
    )
    d.update(ov)
    return Fetcher(**d)


def make_result(**ov) -> InvocationResult:
    d = dict(
        fetcher_name="f", fetcher_version="0.1.0", target=None,
        started_at="2026-01-01T00:00:00Z", completed_at="2026-01-01T00:00:01Z",
        duration_sec=1.0, exit_code=0, stdout="", stderr="", outputs=["ev.json"],
    )
    d.update(ov)
    return InvocationResult(**d)


def _bound_fetcher(path, binding=BINDING) -> Fetcher:
    es = EvidenceSet(reference_id="EVD-T", name="T", schema_binding=binding)
    return make_fetcher(path, evidence_set=es)


def test_glue_marks_failure_and_sets_exit_2(tmp_path, store):
    (tmp_path / "ev.json").write_text(json.dumps(BAD_PAYLOAD))
    result = make_result()
    blocks = api._apply_schema_verification(result, _bound_fetcher(tmp_path), BINDING,
                                            tmp_path, lambda: store)
    assert result.exit_code == SCHEMA_VALIDATION_EXIT_CODE
    assert blocks["ev.json"]["ok"] is False and blocks["ev.json"]["errors"]


def test_glue_leaves_exit_0_on_conformant_artifact(tmp_path, store):
    (tmp_path / "ev.json").write_text(json.dumps(GOOD_PAYLOAD))
    result = make_result()
    blocks = api._apply_schema_verification(result, _bound_fetcher(tmp_path), BINDING,
                                            tmp_path, lambda: store)
    assert result.exit_code == 0
    assert blocks["ev.json"]["ok"] is True


def test_glue_skips_verification_when_collection_failed(tmp_path, store):
    """exit 1 stays exit 1 — a failed collection is never re-labeled as a
    schema failure, and no validation block is recorded."""
    (tmp_path / "ev.json").write_text(json.dumps(BAD_PAYLOAD))
    result = make_result(exit_code=1)
    blocks = api._apply_schema_verification(result, _bound_fetcher(tmp_path), BINDING,
                                            tmp_path, lambda: store)
    assert blocks is None and result.exit_code == 1


def test_glue_records_store_error_as_failed_validation(tmp_path, store):
    """Hard store errors (e.g. pinned_version mismatch) surface as a failed
    validation + exit 2 for THIS artifact — hard, but scoped, so sibling
    fetchers in the run are untouched."""
    (tmp_path / "ev.json").write_text(json.dumps(GOOD_PAYLOAD))
    stale = SchemaBinding(REPORT_ID, "0.0.1")
    result = make_result()
    blocks = api._apply_schema_verification(result, _bound_fetcher(tmp_path, stale), stale,
                                            tmp_path, lambda: store)
    assert result.exit_code == SCHEMA_VALIDATION_EXIT_CODE
    assert blocks["ev.json"]["ok"] is False
    assert "pinned_version mismatch" in blocks["ev.json"]["errors"][0]["message"]


def test_verified_envelope_conforms_to_envelope_schema(tmp_path, store):
    """wrap_outputs stamps the per-file validation block and the result still
    validates against envelope_schema.json (the schema is the oracle)."""
    from framework.envelope import wrap_outputs

    (tmp_path / "ev.json").write_text(json.dumps(BAD_PAYLOAD))
    fetcher = _bound_fetcher(tmp_path)
    result = make_result()
    blocks = api._apply_schema_verification(result, fetcher, BINDING, tmp_path, lambda: store)
    wrap_outputs(result, fetcher, "rid", tmp_path, blocks)

    env = json.loads((tmp_path / "ev.json").read_text())
    assert not [e.message for e in ENVELOPE_VALIDATOR.iter_errors(env)]
    assert env["metadata"]["validation"]["ok"] is False
    assert env["metadata"]["exit_code"] == SCHEMA_VALIDATION_EXIT_CODE
    assert env["metadata"]["status"] == "failed"
    assert env["payload"] == BAD_PAYLOAD   # payload untouched by verification


# --------------------------------------------------------------------------- #
# End-to-end through api.run() — real subprocesses, temp repo root
# --------------------------------------------------------------------------- #

_FETCHER_PY = """\
import json, os
payload = {payload!r}
with open(os.path.join(os.environ["EVIDENCE_DIR"], {filename!r}), "w") as f:
    json.dump(payload, f)
"""


def _fetcher_yaml(name: str, filename: str, binding: bool) -> str:
    data = {
        "name": name, "version": "0.1.0", "description": "test fetcher",
        "category": "testcat",
        "runtime": {"type": "python", "entry": "fetcher.py"},
        "output": {"type": "json", "path": filename},
        "secrets": [],
        "evidence_set": {"reference_id": f"EVD-{name.upper()}", "name": name},
    }
    if binding:
        data["evidence_set"]["schema_binding"] = {
            "schema_id": REPORT_ID, "pinned_version": "1.0.0",
        }
    return yaml.safe_dump(data)


def _make_repo(tmp_path: Path, fetchers: dict) -> Path:
    """Minimal repo root api.run() can execute: the REAL framework/schemas tree
    (incl. the vendored store) plus the given {name: (payload, binding)} test
    fetchers, each a real python subprocess that writes its payload."""
    root = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "framework" / "schemas", root / "framework" / "schemas")
    for name, (payload, binding) in fetchers.items():
        d = root / "fetchers" / "testcat" / name
        d.mkdir(parents=True)
        filename = f"{name}.json"
        (d / "fetcher.yaml").write_text(_fetcher_yaml(name, filename, binding))
        (d / "fetcher.py").write_text(_FETCHER_PY.format(payload=payload, filename=filename))
    return root


def _run(root: Path, names) -> dict:
    manifest = {"run": {
        "output_dir": str(root / "evidence"),
        "fetchers": [{"use": n} for n in names],
    }}
    return api.run(manifest, root)


def _envelope(summary: dict, filename: str) -> dict:
    return json.loads((Path(summary["run_dir"]) / filename).read_text())


def test_no_binding_path_is_unchanged(tmp_path, monkeypatch):
    """A fetcher without a binding runs exactly as before: verify machinery is
    never touched (the store class is replaced with a bomb), the metadata keys
    are exactly the pre-verify set, and exit code stays 0."""
    class _Bomb:
        def __init__(self, *a, **k):
            raise AssertionError("SchemaStore instantiated on the no-binding path")

        default = classmethod(lambda cls, root: cls())

    monkeypatch.setattr(api, "SchemaStore", _Bomb)
    monkeypatch.setattr(api, "verify",
                        lambda *a, **k: pytest.fail("verify() called on the no-binding path"))

    root = _make_repo(tmp_path, {"t_plain": (GOOD_PAYLOAD, False)})
    summary = _run(root, ["t_plain"])

    assert summary["ok"] is True
    assert summary["invocations"][0]["exit_code"] == 0
    env = _envelope(summary, "t_plain.json")
    assert set(env["metadata"].keys()) == {
        "fetcher_name", "fetcher_version", "category", "run_id", "target",
        "collected_at", "status", "exit_code", "evidence_set",
    }


def test_bound_fetcher_with_valid_artifact_passes_end_to_end(tmp_path):
    root = _make_repo(tmp_path, {"t_bound": (GOOD_PAYLOAD, True)})
    summary = _run(root, ["t_bound"])

    assert summary["ok"] is True
    assert summary["invocations"][0]["exit_code"] == 0
    env = _envelope(summary, "t_bound.json")
    assert env["metadata"]["validation"]["ok"] is True
    assert env["metadata"]["status"] == "success"
    assert not [e.message for e in ENVELOPE_VALIDATOR.iter_errors(env)]


def test_bound_fetcher_with_invalid_artifact_fails_end_to_end(tmp_path):
    root = _make_repo(tmp_path, {"t_bad": (BAD_PAYLOAD, True)})
    summary = _run(root, ["t_bad"])

    assert summary["ok"] is False
    assert summary["invocations"][0]["exit_code"] == SCHEMA_VALIDATION_EXIT_CODE
    env = _envelope(summary, "t_bad.json")
    v = env["metadata"]["validation"]
    assert v["ok"] is False and v["errors"] and v["error_count"] >= 1
    assert env["metadata"]["exit_code"] == SCHEMA_VALIDATION_EXIT_CODE
    # the run index records the same exit code (one consistent story everywhere)
    meta = json.loads((Path(summary["run_dir"]) / "_run_metadata.json").read_text())
    assert meta["invocations"][0]["exit_code"] == SCHEMA_VALIDATION_EXIT_CODE


def test_one_schema_failure_does_not_sink_the_run(tmp_path):
    """Runner half of required case 6: the schema-failing artifact is marked,
    its siblings (bound-valid and unbound) come through untouched."""
    root = _make_repo(tmp_path, {
        "t_bad": (BAD_PAYLOAD, True),
        "t_good": (GOOD_PAYLOAD, True),
        "t_plain": (GOOD_PAYLOAD, False),
    })
    summary = _run(root, ["t_bad", "t_good", "t_plain"])

    codes = {i["fetcher_name"]: i["exit_code"] for i in summary["invocations"]}
    assert codes == {"t_bad": SCHEMA_VALIDATION_EXIT_CODE, "t_good": 0, "t_plain": 0}
    assert _envelope(summary, "t_good.json")["metadata"]["validation"]["ok"] is True
    assert "validation" not in _envelope(summary, "t_plain.json")["metadata"]
