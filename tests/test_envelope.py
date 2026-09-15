"""Tests for the evidence-envelope WRITE path (framework/envelope.py).

The load-bearing property: every file wrap_outputs writes must conform to
framework/schemas/envelope_schema.json. We assert that with the SCHEMA itself as
the oracle (Draft202012Validator) — not a hand-copied key list — so a dropped or
renamed metadata field, or a status value outside the enum, fails the test
rather than passing because the test mirrors the same mistake.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from framework.contract import EvidenceSet, Fetcher, InvocationResult
from framework.envelope import is_enveloped, wrap_outputs

REPO_ROOT = Path(__file__).resolve().parent.parent
ENVELOPE_SCHEMA = json.loads((REPO_ROOT / "framework/schemas/envelope_schema.json").read_text())
_VALIDATOR = Draft202012Validator(ENVELOPE_SCHEMA)


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


def _wrap_one(tmp_path, raw, *, result=None, fetcher=None) -> dict:
    """Write `raw` as ev.json, wrap it, return the file's new content."""
    (tmp_path / "ev.json").write_text(json.dumps(raw))
    wrap_outputs(result or make_result(), fetcher or make_fetcher(tmp_path),
                 run_id="2026-01-01T00-00-00Z", run_dir=tmp_path)
    return json.loads((tmp_path / "ev.json").read_text())


def test_wrapped_output_conforms_to_envelope_schema(tmp_path):
    es = EvidenceSet(reference_id="EVD-1", name="Test Set", instructions="how", description="desc")
    fetcher = make_fetcher(tmp_path, evidence_set=es)
    env = _wrap_one(tmp_path, {"finding": "x"}, fetcher=fetcher,
                    result=make_result(target={"region": "us-east-1"}))

    errors = [e.message for e in _VALIDATOR.iter_errors(env)]   # oracle = the schema file
    assert not errors, errors
    assert env["payload"] == {"finding": "x"}                   # payload preserved verbatim
    assert env["metadata"]["evidence_set"]["reference_id"] == "EVD-1"
    assert env["metadata"]["target"] == {"region": "us-east-1"}


def test_failed_status_carries_bounded_error_tail(tmp_path):
    env = _wrap_one(tmp_path, {"k": 1},
                    result=make_result(exit_code=2, stderr="boom\ntraceback here"))
    assert env["metadata"]["status"] == "failed"
    assert env["metadata"]["error"].endswith("traceback here")
    assert not list(_VALIDATOR.iter_errors(env))   # still schema-valid


def test_error_tail_is_truncated(tmp_path):
    env = _wrap_one(tmp_path, {"k": 1}, result=make_result(exit_code=1, stderr="x" * 10_000))
    assert len(env["metadata"]["error"]) <= 4000


def test_success_has_no_error_field(tmp_path):
    env = _wrap_one(tmp_path, {"k": 1}, result=make_result(exit_code=0, stderr="non-fatal warning"))
    assert env["metadata"]["status"] == "success"
    assert "error" not in env["metadata"]   # error only attached on failure


# --------------------------------------------------------------------------- #
# What the fetcher reported via $FETCHER_STATUS_FILE beats the stderr tail
# --------------------------------------------------------------------------- #

def test_reported_error_wins_over_the_stderr_tail(tmp_path):
    """The bug in #24: stderr's last line was an INFO success message.

    The tail heuristic faithfully captured "Evidence saved to ..." as the failure
    reason. A fetcher that reports through the channel is believed instead.
    """
    env = _wrap_one(tmp_path, {"k": 1}, result=make_result(
        exit_code=1,
        stderr="2026-01-01 INFO f Evidence saved to /tmp/ev.json\n",
        error="GitLab API read timeout after 30s",
    ))
    assert env["metadata"]["error"] == "GitLab API read timeout after 30s"
    assert "Evidence saved" not in env["metadata"]["error"]
    assert not list(_VALIDATOR.iter_errors(env))


def test_reported_error_code_lands_in_metadata(tmp_path):
    env = _wrap_one(tmp_path, {"k": 1}, result=make_result(
        exit_code=1, stderr="", error="host unreachable", error_code="target_unreachable"))
    assert env["metadata"]["error_code"] == "target_unreachable"
    assert not list(_VALIDATOR.iter_errors(env))


def test_no_error_code_leaves_the_field_absent(tmp_path):
    """Absent, not empty-string — consumers test presence."""
    env = _wrap_one(tmp_path, {"k": 1}, result=make_result(exit_code=1, error="boom"))
    assert "error_code" not in env["metadata"]


def test_falls_back_to_stderr_when_nothing_was_reported(tmp_path):
    """A fetcher that never writes the status file keeps the old behavior.

    This is what makes the channel additive: nothing has to migrate.
    """
    env = _wrap_one(tmp_path, {"k": 1},
                    result=make_result(exit_code=1, stderr="boom\nthe real reason"))
    assert env["metadata"]["error"].endswith("the real reason")


def test_reported_error_is_ignored_on_success(tmp_path):
    """Gated on exit code, not on whether a report exists.

    A fetcher may write the file and still exit 0 (collected fine, one optional
    call degraded). Surfacing that as metadata.error would recreate #24 inverted
    — a successful run reporting a failure.
    """
    env = _wrap_one(tmp_path, {"k": 1}, result=make_result(
        exit_code=0, error="a group name did not resolve", error_code="partial_failure"))
    assert env["metadata"]["status"] == "success"
    assert "error" not in env["metadata"]
    assert "error_code" not in env["metadata"]


def test_already_enveloped_file_is_not_double_wrapped(tmp_path):
    pre = {"schema_version": "1.0", "metadata": {"run_id": "r"}, "payload": {"already": True}}
    out = _wrap_one(tmp_path, pre)
    assert out == pre                          # untouched
    assert not is_enveloped(out["payload"])    # payload was not itself an envelope


def test_non_json_output_left_untouched(tmp_path):
    (tmp_path / "note.txt").write_text("not json")
    wrap_outputs(make_result(outputs=["note.txt"]), make_fetcher(tmp_path), "rid", tmp_path)
    assert (tmp_path / "note.txt").read_text() == "not json"


def test_unreadable_json_is_skipped_without_raising(tmp_path):
    (tmp_path / "ev.json").write_text("{ not valid json")
    # A single unreadable file must never abort the run.
    wrap_outputs(make_result(), make_fetcher(tmp_path), "rid", tmp_path)
    assert (tmp_path / "ev.json").read_text() == "{ not valid json"   # left as-is


def test_no_evidence_set_block_when_fetcher_declares_none(tmp_path):
    env = _wrap_one(tmp_path, {"k": 1})   # default fetcher has evidence_set=None
    assert "evidence_set" not in env["metadata"]
    assert not list(_VALIDATOR.iter_errors(env))   # still valid (evidence_set is optional)


def test_target_with_a_yaml_date_does_not_abort_the_run(tmp_path):
    """An unquoted YAML date in a target must not kill wrap_outputs.

    `since: 2026-01-01` in a manifest target is valid YAML and parses to a
    datetime.date, which json.dumps cannot serialize. Before default=str this
    raised TypeError out of wrap_outputs — past the invocation's own exit 0,
    caught by nothing in run_cmd — aborting the manifest with the collected
    file left unenveloped and no _run_metadata.json written.
    """
    import datetime

    env = _wrap_one(
        tmp_path,
        {"finding": "x"},
        result=make_result(target={"since": datetime.date(2026, 1, 1)}),
    )
    assert env["metadata"]["target"] == {"since": "2026-01-01"}
    _VALIDATOR.validate(env)
