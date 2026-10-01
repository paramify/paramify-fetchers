"""Tests for the issue-report collection path.

The property every test here defends is the same one: **the file on disk is the
tool's own bytes.** Paramify's assessment intake parses the vendor's format, so
anything the framework adds, reorders, or re-serializes is a broken import — and
it breaks silently, at parse time in someone else's system.

Covered:
  - the runner writes reports to <run>/issue-reports/ and nowhere else;
  - the envelope never touches them, including a .json report (the case an
    extension-based guard would get wrong);
  - the sidecar index carries what the envelope would have, including the
    assessment resolved from the manifest;
  - `paramify upload` cannot see them, so the evidence stage can't send a scan
    report to an evidence set;
  - the schema refuses the ways the two kinds could be mixed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from framework import api
from framework.contract import Fetcher, InvocationResult, IssueReport
from framework.envelope import wrap_outputs
from framework.issue_reports import (
    ASSESSMENT_ID_FIELD,
    CLOSE_CYCLE_FIELD,
    ISSUE_REPORTS_DIR,
    build_record,
    read_index,
    record_outputs,
)
from framework.runner.executor import invocation_dir

REPO_ROOT = Path(__file__).resolve().parent.parent

# A Nessus-style CSV whose bytes are deliberately awkward: CRLF line endings, an
# unquoted trailing space, and a BOM. Every one of these survives a byte copy and
# dies in a parse-and-rewrite, which is exactly the distinction under test.
RAW_CSV = b"\xef\xbb\xbfPlugin ID,Severity,Name\r\n19506,Info,Nessus Scan Information \r\n"


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #

def make_issue_report_fetcher(path: Path, **overrides) -> Fetcher:
    defaults = dict(
        name="t_vuln_scan",
        version="0.1.0",
        description="test issue report",
        category="testcat",
        runtime_type="python",
        runtime_entry="fetcher.py",
        runtime_timeout=None,
        output_type="csv",
        output_path="scan.csv",
        output_aggregation=None,
        secrets=[],
        supports_targets=False,
        target_schema={},
        path=path,
        config_schema={},
        evidence_set=None,
        kind="issue_report",
        issue_report=IssueReport(assessment_type="VULNERABILITY", title="Test Scan"),
    )
    defaults.update(overrides)
    return Fetcher(**defaults)


def make_result(outputs, **overrides) -> InvocationResult:
    defaults = dict(
        fetcher_name="t_vuln_scan",
        fetcher_version="0.1.0",
        target=None,
        started_at="2026-08-21T00:00:00Z",
        completed_at="2026-08-21T00:00:01Z",
        duration_sec=1.0,
        exit_code=0,
        stdout="",
        stderr="",
        outputs=list(outputs),
        error=None,
        error_code=None,
    )
    defaults.update(overrides)
    return InvocationResult(**defaults)


def write_issue_report_fetcher(
    root: Path, *, output="scan.csv", fmt="csv", body=RAW_CSV,
    exit_code: int = 0, write_file: bool = True,
) -> None:
    """Stage a runnable issue-report fetcher in a temp repo root."""
    fdir = root / "fetchers" / "testcat" / "vuln_scan"
    fdir.mkdir(parents=True, exist_ok=True)
    (fdir / "fetcher.yaml").write_text(
        "name: t_vuln_scan\n"
        "version: 0.1.0\n"
        "description: test issue report\n"
        "category: testcat\n"
        "kind: issue_report\n"
        "runtime:\n  type: python\n  entry: fetcher.py\n"
        f"output:\n  type: {fmt}\n  path: {output}\n"
        "secrets: []\n"
        "issue_report:\n  assessment_type: VULNERABILITY\n  title: Test Scan\n"
    )
    (fdir / "fetcher.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        f"body = {body!r}\n"
        + (f'Path(os.environ["EVIDENCE_DIR"], {output!r}).write_bytes(body)\n' if write_file else "")
        + (f"raise SystemExit({exit_code})\n" if exit_code else "")
    )
    _stage_schemas(root)


def _stage_schemas(root: Path) -> None:
    """The runner validates every fetcher.yaml against the real schema."""
    schemas = root / "framework" / "schemas"
    if not schemas.exists():
        schemas.mkdir(parents=True)
        for src in (REPO_ROOT / "framework" / "schemas").glob("*.json"):
            (schemas / src.name).write_bytes(src.read_bytes())


def write_fanout_issue_report_fetcher(root: Path, *, per_target_filename: bool) -> None:
    """Stage a runnable issue-report fetcher that fans out over target_schema.

    `per_target_filename` picks between the convention the template teaches and
    the fixed name that loses every target but the last.
    """
    fdir = root / "fetchers" / "testcat" / "vuln_scan"
    fdir.mkdir(parents=True, exist_ok=True)
    (fdir / "fetcher.yaml").write_text(
        "name: t_vuln_scan\n"
        "version: 0.1.0\n"
        "description: test issue report\n"
        "category: testcat\n"
        "kind: issue_report\n"
        "runtime:\n  type: python\n  entry: fetcher.py\n"
        "output:\n  type: csv\n  path: scan.csv\n"
        "secrets: []\n"
        "supports_targets: true\n"
        "target_schema:\n"
        "  scanner_id:\n"
        "    type: string\n"
        "    required: true\n"
        "    env: TARGET_SCANNER_ID\n"
        "issue_report:\n  assessment_type: VULNERABILITY\n  title: Test Scan\n"
    )
    suffix = '"_" + scanner' if per_target_filename else '""'
    (fdir / "fetcher.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        'scanner = os.environ["TARGET_SCANNER_ID"]\n'
        f"suffix = {suffix}\n"
        'Path(os.environ["EVIDENCE_DIR"], f"scan{suffix}.csv").write_bytes(\n'
        '    f"Plugin ID,Severity,Scanner\\n19506,Info,{scanner}\\n".encode()\n'
        ")\n"
    )
    _stage_schemas(root)


# --------------------------------------------------------------------------- #
# Runner: where the file lands, and what it contains
# --------------------------------------------------------------------------- #

def test_invocation_dir_redirects_only_issue_reports(tmp_path):
    run_dir = tmp_path / "run-x"
    report = make_issue_report_fetcher(tmp_path)
    evidence = make_issue_report_fetcher(tmp_path, kind="evidence", issue_report=None)
    assert invocation_dir(report, run_dir) == run_dir / ISSUE_REPORTS_DIR
    assert invocation_dir(evidence, run_dir) == run_dir


def test_run_writes_report_bytes_unchanged(tmp_path):
    """The end-to-end property: a real subprocess writes the report, and the file
    in issue-reports/ is byte-identical to what it wrote."""
    write_issue_report_fetcher(tmp_path)
    manifest = {"run": {"output_dir": str(tmp_path / "out"),
                        "fetchers": [{"use": "t_vuln_scan",
                                      "config": {ASSESSMENT_ID_FIELD: "abc-123"}}]}}
    summary = api.run(manifest, tmp_path)

    assert summary["ok"], summary
    run_dir = Path(summary["run_dir"])
    report = run_dir / ISSUE_REPORTS_DIR / "scan.csv"
    assert report.read_bytes() == RAW_CSV, "the report was modified in flight"
    # Nothing leaked into the run root: only metadata and the subdirectory.
    assert {p.name for p in run_dir.iterdir()} == {"_run_metadata.json", ISSUE_REPORTS_DIR}


def test_run_records_outputs_relative_to_the_run_dir(tmp_path):
    """Outputs are reported as issue-reports/<file>, so every consumer reads one
    path convention regardless of which directory the fetcher wrote to."""
    write_issue_report_fetcher(tmp_path)
    manifest = {"run": {"output_dir": str(tmp_path / "out"),
                        "fetchers": [{"use": "t_vuln_scan"}]}}
    summary = api.run(manifest, tmp_path)
    assert summary["invocations"][0]["outputs"] == [f"{ISSUE_REPORTS_DIR}/scan.csv"]


def test_fanout_records_one_report_per_target(tmp_path):
    """Every target of a fanout run must reach the sidecar with its own file.

    The runner detects outputs by diffing the issue-reports/ directory around each
    invocation, so this holds only while the fetcher varies the filename per
    target — the convention fetchers/_template_issue_report/ teaches and the
    evidence side already follows.
    """
    write_fanout_issue_report_fetcher(tmp_path, per_target_filename=True)
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [{
        "use": "t_vuln_scan",
        "config": {ASSESSMENT_ID_FIELD: "abc-123"},
        "targets": [{"scanner_id": "east"}, {"scanner_id": "west"}],
    }]}}
    summary = api.run(manifest, tmp_path)

    assert summary["ok"], summary
    run_dir = Path(summary["run_dir"])
    reports = run_dir / ISSUE_REPORTS_DIR
    assert {p.name for p in reports.iterdir() if not p.name.startswith("_")} == {
        "scan_east.csv", "scan_west.csv"
    }
    # Each target reports its own output rather than being swallowed by the diff.
    assert [inv["outputs"] for inv in summary["invocations"]] == [
        [f"{ISSUE_REPORTS_DIR}/scan_east.csv"],
        [f"{ISSUE_REPORTS_DIR}/scan_west.csv"],
    ]
    # And each gets a record whose bytes match the target it is labelled with.
    records = read_index(run_dir)["reports"]
    assert len(records) == 2
    for rec in records:
        scanner = rec["target"]["scanner_id"]
        assert rec["file"] == f"scan_{scanner}.csv"
        assert scanner in (reports / rec["file"]).read_text()
        assert rec["title"] == f"Test Scan - {scanner}"


def test_a_fixed_filename_collapses_a_fanout_run(tmp_path):
    """The hazard the per-target filename convention exists to avoid.

    With one fixed name, target 2 overwrites target 1 on disk, and because the
    filename already existed the runner sees no new file and records nothing for
    target 2. What survives is a single record carrying target 1's identity and
    target 2's bytes — including a sha256 taken after the overwrite, so the field
    that could have caught it agrees with the wrong story. Nothing raises.

    This pins today's behavior so the cost is visible. A runner-side guard on
    "issue-report invocation produced no new file" would change these assertions,
    which is the point.
    """
    write_fanout_issue_report_fetcher(tmp_path, per_target_filename=False)
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [{
        "use": "t_vuln_scan",
        "config": {ASSESSMENT_ID_FIELD: "abc-123"},
        "targets": [{"scanner_id": "east"}, {"scanner_id": "west"}],
    }]}}
    summary = api.run(manifest, tmp_path)

    assert summary["ok"], "the run reports success — that is the problem"
    run_dir = Path(summary["run_dir"])
    body = (run_dir / ISSUE_REPORTS_DIR / "scan.csv").read_text()
    assert "west" in body and "east" not in body, "target 1's report was overwritten"
    assert summary["invocations"][1]["outputs"] == [], "target 2 looks like it made nothing"

    records = read_index(run_dir)["reports"]
    assert len(records) == 1
    assert records[0]["target"] == {"scanner_id": "east"}, "labelled with the lost target"
    assert records[0]["sha256"] == hashlib.sha256(body.encode()).hexdigest()


def test_run_summary_counts_collected_reports(tmp_path):
    """A run that collected reports says so, because `paramify upload` cannot see
    them and stopping at the evidence stage leaves them unsent."""
    write_issue_report_fetcher(tmp_path)
    manifest = {"run": {"output_dir": str(tmp_path / "out"),
                        "fetchers": [{"use": "t_vuln_scan"}]}}
    summary = api.run(manifest, tmp_path)
    assert summary["issue_reports"] == 1


def test_run_summary_reports_zero_for_an_evidence_only_run(tmp_path):
    """The count must not fire on the common case, or the hint becomes noise."""
    fdir = tmp_path / "fetchers" / "testcat" / "ev"
    fdir.mkdir(parents=True)
    (fdir / "fetcher.yaml").write_text(
        "name: t_ev\nversion: 0.1.0\ndescription: d\ncategory: testcat\n"
        "runtime:\n  type: python\n  entry: fetcher.py\n"
        "output:\n  type: json\n  path: ev.json\n"
        "secrets: []\n"
        "evidence_set:\n  reference_id: EVD-T\n  name: T\n"
    )
    (fdir / "fetcher.py").write_text(
        "import json, os\nfrom pathlib import Path\n"
        'Path(os.environ["EVIDENCE_DIR"], "ev.json").write_text(json.dumps({"a": 1}))\n'
    )
    _stage_schemas(tmp_path)
    summary = api.run(
        {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [{"use": "t_ev"}]}},
        tmp_path,
    )
    assert summary["issue_reports"] == 0


def test_json_issue_report_is_not_enveloped(tmp_path):
    """The case an extension-based guard gets wrong: a JSON scan report is still a
    scan report, and enveloping it would break intake exactly as for a CSV."""
    raw = b'{"findings": [{"id": 1}]}'
    write_issue_report_fetcher(tmp_path, output="scan.json", fmt="json", body=raw)
    manifest = {"run": {"output_dir": str(tmp_path / "out"),
                        "fetchers": [{"use": "t_vuln_scan"}]}}
    summary = api.run(manifest, tmp_path)
    written = (Path(summary["run_dir"]) / ISSUE_REPORTS_DIR / "scan.json").read_bytes()
    assert written == raw
    assert "metadata" not in json.loads(written)


def test_wrap_outputs_skips_issue_reports(tmp_path):
    """Unit-level guard on the envelope itself, independent of the runner."""
    reports = tmp_path / ISSUE_REPORTS_DIR
    reports.mkdir()
    payload = b'{"a": 1}'
    (reports / "scan.json").write_bytes(payload)
    fetcher = make_issue_report_fetcher(tmp_path, output_type="json", output_path="scan.json")
    wrap_outputs(make_result([f"{ISSUE_REPORTS_DIR}/scan.json"]), fetcher, "run-1", tmp_path)
    assert (reports / "scan.json").read_bytes() == payload


# --------------------------------------------------------------------------- #
# Sidecar index
# --------------------------------------------------------------------------- #

def test_sidecar_carries_identity_and_assessment(tmp_path):
    write_issue_report_fetcher(tmp_path)
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [{
        "use": "t_vuln_scan",
        "config": {ASSESSMENT_ID_FIELD: "assess-uuid", "assessment_name": "Monthly Scan"},
    }]}}
    summary = api.run(manifest, tmp_path)
    index = read_index(Path(summary["run_dir"]))

    assert index["schema_version"] == "1.1"
    assert len(index["reports"]) == 1
    rec = index["reports"][0]
    assert rec["file"] == "scan.csv"
    assert rec["fetcher_name"] == "t_vuln_scan"
    assert rec["category"] == "testcat"
    assert rec["status"] == "success"
    assert rec["exit_code"] == 0
    assert rec["format"] == "csv"
    assert rec["title"] == "Test Scan"
    assert rec["assessment_id"] == "assess-uuid"
    assert rec["assessment_name"] == "Monthly Scan"
    assert rec["assessment_type"] == "VULNERABILITY"
    assert rec["bytes"] == len(RAW_CSV)
    # The hash is the uploader's only integrity check, so it must be over the
    # real file rather than anything the framework reconstructed.
    assert rec["sha256"] == hashlib.sha256(RAW_CSV).hexdigest()


def test_sidecar_absent_when_a_run_collects_no_reports(tmp_path):
    """None and empty mean different things: no index at all is "this run had no
    issue-report fetchers", which is not an error the uploader should report."""
    assert read_index(tmp_path) is None


def test_record_outputs_ignores_files_outside_the_subdirectory(tmp_path):
    """An issue-report fetcher that also writes into the run root cannot get that
    file into the index — and therefore cannot get it intaken."""
    reports = tmp_path / ISSUE_REPORTS_DIR
    reports.mkdir()
    (reports / "scan.csv").write_bytes(RAW_CSV)
    (tmp_path / "stray.json").write_text("{}")
    fetcher = make_issue_report_fetcher(tmp_path)
    added = record_outputs(
        make_result([f"{ISSUE_REPORTS_DIR}/scan.csv", "stray.json"]),
        fetcher, "run-1", tmp_path,
    )
    assert [r["file"] for r in added] == ["scan.csv"]


def test_record_outputs_accumulates_across_invocations(tmp_path):
    """A fanout run appends; the index is complete on disk after each invocation
    so a run killed halfway still leaves an uploadable index."""
    reports = tmp_path / ISSUE_REPORTS_DIR
    reports.mkdir()
    fetcher = make_issue_report_fetcher(tmp_path)
    for name in ("a.csv", "b.csv"):
        (reports / name).write_bytes(RAW_CSV)
        record_outputs(make_result([f"{ISSUE_REPORTS_DIR}/{name}"]), fetcher, "run-1", tmp_path)
    assert [r["file"] for r in read_index(tmp_path)["reports"]] == ["a.csv", "b.csv"]


def test_failed_collection_is_still_recorded(tmp_path):
    """"The scan ran and came back empty" and "the scan never ran" are different
    facts, and the uploader has to be able to tell them apart."""
    reports = tmp_path / ISSUE_REPORTS_DIR
    reports.mkdir()
    (reports / "scan.csv").write_bytes(b"")
    fetcher = make_issue_report_fetcher(tmp_path)
    rec = build_record(
        "scan.csv",
        make_result([f"{ISSUE_REPORTS_DIR}/scan.csv"], exit_code=1,
                    error="scanner returned no data", error_code="partial_failure"),
        fetcher, "run-1", tmp_path,
    )
    assert rec["status"] == "failed"
    assert rec["error"] == "scanner returned no data"
    assert rec["error_code"] == "partial_failure"


def test_per_target_title_gets_the_target_suffix(tmp_path):
    reports = tmp_path / ISSUE_REPORTS_DIR
    reports.mkdir()
    (reports / "scan.csv").write_bytes(RAW_CSV)
    fetcher = make_issue_report_fetcher(tmp_path)
    rec = build_record(
        "scan.csv",
        make_result([f"{ISSUE_REPORTS_DIR}/scan.csv"], target={"region": "us-gov-west-1"}),
        fetcher, "run-1", tmp_path,
    )
    assert rec["title"] == "Test Scan - us-gov-west-1"


# --------------------------------------------------------------------------- #
# Separation from the evidence path
# --------------------------------------------------------------------------- #

def test_evidence_uploader_cannot_see_issue_reports(tmp_path):
    """The evidence stage globs the run root only. If that ever changed, a scan
    report would be posted to an evidence set as an opaque blob."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_ev_uploader", REPO_ROOT / "uploaders" / "paramify_evidence" / "uploader.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    reports = tmp_path / ISSUE_REPORTS_DIR
    reports.mkdir()
    (reports / "scan.json").write_text('{"findings": []}')
    (reports / "_issue_reports.json").write_text('{"reports": []}')
    assert list(module.iter_evidence_files(tmp_path)) == []


def test_run_with_only_reports_and_no_metadata_is_still_listed(tmp_path):
    """list_runs skips a run dir with neither metadata nor files as a ghost. A dir
    holding only reports is not a ghost — it has uploadable content — and the
    evidence path already has this fallback for a metadata-less run."""
    run_dir = tmp_path / "run-orphan" / ISSUE_REPORTS_DIR
    run_dir.mkdir(parents=True)
    (run_dir / "scan.csv").write_bytes(RAW_CSV)
    (run_dir / "_issue_reports.json").write_text('{"reports": []}')

    runs = api.list_runs(tmp_path)
    assert len(runs) == 1
    assert runs[0]["issue_reports"] == 1
    # The sidecar and log are bookkeeping, not reports.
    assert [f["name"] for f in runs[0]["files"]] == [f"{ISSUE_REPORTS_DIR}/scan.csv"]


def test_run_summary_counts_and_labels_issue_reports(tmp_path):
    write_issue_report_fetcher(tmp_path)
    out = tmp_path / "out"
    manifest = {"run": {"output_dir": str(out), "fetchers": [{"use": "t_vuln_scan"}]}}
    api.run(manifest, tmp_path)

    run = api.list_runs(out)[0]
    assert run["issue_reports"] == 1
    entry = next(f for f in run["files"] if f["name"].endswith("scan.csv"))
    # A viewer must not try to read a .csv or .nessus as an envelope.
    assert entry["kind"] == "issue_report"


def test_preview_issue_report_reads_the_sidecar_not_the_file(tmp_path):
    """Opening a .csv/.nessus in the TUI must not try to parse it as JSON —
    that is exactly the envelope mistake, just on the read side."""
    write_issue_report_fetcher(tmp_path)
    out = tmp_path / "out"
    manifest = {
        "run": {
            "output_dir": str(out),
            "fetchers": [{
                "use": "t_vuln_scan",
                "config": {"assessment_id": "123e4567-e89b-12d3-a456-426614174000",
                           "assessment_name": "Monthly Scan"},
            }],
        }
    }
    summary = api.run(manifest, tmp_path)
    report = Path(summary["run_dir"]) / ISSUE_REPORTS_DIR / "scan.csv"
    rec = api.read_issue_report(report)
    assert rec["fetcher_name"] == "t_vuln_scan"
    assert rec["assessment_name"] == "Monthly Scan"
    text = api.preview_issue_report(report)
    assert "issue report — raw, never enveloped" in text
    assert "Monthly Scan" in text
    assert "t_vuln_scan" in text
    assert "sha256:" in text
    # The preview never re-serializes the file — it quotes the sidecar, not the bytes.
    assert RAW_CSV.decode("utf-8", errors="replace") not in text


# --------------------------------------------------------------------------- #
# validate()
# --------------------------------------------------------------------------- #

def test_validate_flags_an_issue_report_with_no_assessment(tmp_path):
    """Reported at validate time, not upload time — after someone has already
    paid for a scan is too late to learn there is nowhere to put it."""
    write_issue_report_fetcher(tmp_path)
    manifest = {"run": {"output_dir": str(tmp_path / "out"),
                        "fetchers": [{"use": "t_vuln_scan"}]}}
    errors = api.validate(manifest, tmp_path)
    assert any(ASSESSMENT_ID_FIELD in e for e in errors), errors
    assert any("assessments select" in e for e in errors), errors


def test_one_unwired_report_does_not_block_the_others(tmp_path):
    """A report with no assessment_id is a warning, not a gate.

    upload_run already isolates that file and sends the rest, so failing the
    preflight stranded reports that were correctly wired — and blocked --dry-run
    from showing what would have gone.
    """
    reports = tmp_path / ISSUE_REPORTS_DIR
    reports.mkdir(parents=True)
    for name in ("wired.csv", "unwired.csv"):
        (reports / name).write_bytes(RAW_CSV)
    (reports / "_issue_reports.json").write_text(json.dumps({
        "schema_version": "1.0", "run_id": "r1", "reports": [
            {"file": "wired.csv", "fetcher_name": "fa", "run_id": "r1",
             "status": "success", "format": "csv", "assessment_id": "A-1"},
            {"file": "unwired.csv", "fetcher_name": "fb", "run_id": "r1",
             "status": "success", "format": "csv", "assessment_id": None},
        ],
    }))

    pf = api.issues_upload_preflight(tmp_path, REPO_ROOT, None, dry_run=True)
    assert pf["ok"], pf["errors"]
    assert pf["missing_assessment"] == ["fb"]
    assert any("fb" in w and "assessments select" in w for w in pf["warnings"]), pf


def test_validate_passes_once_an_assessment_is_set(tmp_path):
    write_issue_report_fetcher(tmp_path)
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [
        {"use": "t_vuln_scan",
         "config": {ASSESSMENT_ID_FIELD: "abc-123", CLOSE_CYCLE_FIELD: "never"}}
    ]}}
    assert api.validate(manifest, tmp_path) == []


def test_validate_asks_for_a_close_policy(tmp_path):
    """No default: closing auto-closes the issues a cycle never saw, so whether a
    run closes is a fact about the customer, not something to guess."""
    write_issue_report_fetcher(tmp_path)
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [
        {"use": "t_vuln_scan", "config": {ASSESSMENT_ID_FIELD: "abc-123"}}
    ]}}
    errors = api.validate(manifest, tmp_path)
    assert any(CLOSE_CYCLE_FIELD in e and "--close-cycle" in e for e in errors), errors


def test_validate_rejects_an_unknown_close_policy(tmp_path):
    write_issue_report_fetcher(tmp_path)
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [
        {"use": "t_vuln_scan",
         "config": {ASSESSMENT_ID_FIELD: "abc-123", CLOSE_CYCLE_FIELD: "always"}}
    ]}}
    errors = api.validate(manifest, tmp_path)
    assert any("'always'" in e for e in errors), errors


def test_validate_reads_platform_level_assessment_and_policy(tmp_path):
    """validate reads the same merged config the runner does, so values set once
    for the category count for every entry that inherits them."""
    write_issue_report_fetcher(tmp_path)
    manifest = {"run": {
        "output_dir": str(tmp_path / "out"),
        "platforms": {"testcat": {"config": {
            ASSESSMENT_ID_FIELD: "abc-123", CLOSE_CYCLE_FIELD: "after_run",
        }}},
        "fetchers": [{"use": "t_vuln_scan"}],
    }}
    assert api.validate(manifest, tmp_path) == []


# --------------------------------------------------------------------------- #
# Invocation records: what lets the uploader tell a complete run from a partial one
# --------------------------------------------------------------------------- #

def _run_one(tmp_path, config=None):
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [
        {"use": "t_vuln_scan", "config": config or {
            ASSESSMENT_ID_FIELD: "A-1", CLOSE_CYCLE_FIELD: "after_run"}},
    ]}}
    summary = api.run(manifest, tmp_path)
    return read_index(Path(summary["run_dir"]))


def test_a_successful_invocation_is_recorded_with_its_policy(tmp_path):
    write_issue_report_fetcher(tmp_path)
    index = _run_one(tmp_path)
    [inv] = index["invocations"]
    assert inv["status"] == "success"
    assert inv["files"] == ["scan.csv"]
    assert inv["assessment_id"] == "A-1"
    assert inv["close_cycle"] == "after_run"
    assert index["reports"][0]["close_cycle"] == "after_run"


def test_a_failed_invocation_that_wrote_nothing_is_still_recorded(tmp_path):
    """The case that made invocations necessary: no file means no report record,
    and without this entry the run would look complete."""
    write_issue_report_fetcher(tmp_path, exit_code=1, write_file=False)
    index = _run_one(tmp_path)
    assert index["reports"] == []
    [inv] = index["invocations"]
    assert inv["status"] == "failed"
    assert inv["files"] == []
    assert inv["assessment_id"] == "A-1"


def test_an_entry_that_raises_before_running_is_recorded(tmp_path, monkeypatch):
    write_issue_report_fetcher(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("secret could not be resolved")

    monkeypatch.setattr("framework.runner.executor.run_entry", boom)
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [
        {"use": "t_vuln_scan",
         "config": {ASSESSMENT_ID_FIELD: "A-1", CLOSE_CYCLE_FIELD: "after_run"}},
    ]}}
    summary = api.run(manifest, tmp_path)
    [inv] = read_index(Path(summary["run_dir"]))["invocations"]
    assert inv["status"] == "failed"
    assert "secret could not be resolved" in inv["error"]


def test_assessment_is_configurable_but_not_required_to_collect(tmp_path):
    """A missing assessment must not stop collection: the framework is supposed to
    run with no Paramify connection at all (docs/design.md). If assessment_id were
    a required config field, this run would raise instead."""
    write_issue_report_fetcher(tmp_path)
    manifest = {"run": {"output_dir": str(tmp_path / "out"),
                        "fetchers": [{"use": "t_vuln_scan"}]}}
    summary = api.run(manifest, tmp_path)
    assert summary["ok"], summary
    rec = read_index(Path(summary["run_dir"]))["reports"][0]
    assert rec["assessment_id"] is None


def test_reserved_assessment_fields_are_offered_on_every_issue_report(tmp_path):
    """The fields are injected by the loader, so a fetcher.yaml never declares
    them and `describe` / the TUI form show them without special-casing."""
    write_issue_report_fetcher(tmp_path)
    from framework.config_loader import discover_fetchers

    fetcher = discover_fetchers(tmp_path)["t_vuln_scan"]
    assert ASSESSMENT_ID_FIELD in fetcher.config_schema
    assert "assessment_name" in fetcher.config_schema
    # No env mapping: the fetcher has no use for these, only the uploader does.
    assert fetcher.config_schema[ASSESSMENT_ID_FIELD].env is None


# --------------------------------------------------------------------------- #
# Schema: the two kinds must not mix
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def fetcher_validator():
    schema = json.loads((REPO_ROOT / "framework" / "schemas" / "fetcher_schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _base(**overrides) -> dict:
    doc = {
        "name": "x_y", "version": "0.1.0", "description": "d",
        "runtime": {"type": "python", "entry": "fetcher.py"},
        "output": {"type": "json", "path": "o.json"},
        "secrets": [],
    }
    doc.update(overrides)
    return doc


def test_schema_evidence_fetchers_need_no_kind(fetcher_validator):
    """Every existing fetcher.yaml omits `kind`; none of them may start failing."""
    assert not list(fetcher_validator.iter_errors(_base()))


def test_schema_rejects_issue_report_without_its_block(fetcher_validator):
    doc = _base(kind="issue_report", output={"type": "csv", "path": "s.csv"})
    assert list(fetcher_validator.iter_errors(doc))


def test_schema_rejects_mixing_the_two_identities(fetcher_validator):
    """Either mix is a silently-ignored fetcher: an issue report with an
    evidence_set is picked up by neither uploader."""
    both = _base(
        kind="issue_report", output={"type": "csv", "path": "s.csv"},
        issue_report={"assessment_type": "VULNERABILITY"},
        evidence_set={"reference_id": "R", "name": "N"},
    )
    assert list(fetcher_validator.iter_errors(both))

    wrong_way = _base(issue_report={"assessment_type": "VULNERABILITY"})
    assert list(fetcher_validator.iter_errors(wrong_way))


def test_schema_allows_only_intakeable_formats_for_reports(fetcher_validator):
    for fmt in ("csv", "json", "xml", "nessus"):
        doc = _base(kind="issue_report", output={"type": fmt, "path": f"s.{fmt}"},
                    issue_report={"assessment_type": "VULNERABILITY"})
        assert not list(fetcher_validator.iter_errors(doc)), fmt
    # html has no path through intake, so it can never be uploaded.
    html = _base(kind="issue_report", output={"type": "html", "path": "s.html"},
                 issue_report={"assessment_type": "VULNERABILITY"})
    assert list(fetcher_validator.iter_errors(html))


def test_schema_constrains_assessment_type(fetcher_validator):
    doc = _base(kind="issue_report", output={"type": "csv", "path": "s.csv"},
                issue_report={"assessment_type": "PENTEST"})
    assert list(fetcher_validator.iter_errors(doc))


# --------------------------------------------------------------------------- #
# Assessment selection — resolving by name must never pick the wrong one
# --------------------------------------------------------------------------- #

_ASSESSMENTS = [
    {"id": "11111111-0000-4000-8000-000000000001", "name": "Monthly Nessus",
     "type": "VULNERABILITY", "mechanism_name": "Nessus"},
    {"id": "22222222-0000-4000-8000-000000000002", "name": "Weekly Wiz",
     "type": "CONFIGURATION", "mechanism_name": "Wiz"},
    {"id": "33333333-0000-4000-8000-000000000003", "name": "Monthly Wiz Config",
     "type": "CONFIGURATION", "mechanism_name": "Wiz"},
]


@pytest.mark.parametrize("selector", [
    "11111111-0000-4000-8000-000000000001",  # exact id
    "Monthly Nessus",                        # exact name
    "monthly nessus",                        # case-insensitive
    "Nessus",                                # unique substring of the name
])
def test_resolve_assessment_accepts_name_or_id(selector):
    chosen = api.resolve_assessment(_ASSESSMENTS, selector)
    assert chosen["id"] == "11111111-0000-4000-8000-000000000001"


def test_resolve_assessment_rejects_ambiguous_substring():
    """'Monthly' hits Nessus and Wiz Config. Silently picking one would intake
    a scan into the wrong assessment."""
    with pytest.raises(ValueError, match="ambiguous"):
        api.resolve_assessment(_ASSESSMENTS, "Monthly")


def test_list_assessments_rejects_an_unknown_type():
    with pytest.raises(ValueError, match="VULNERABILITY"):
        api.list_assessments("PENTEST")


def test_set_assessment_writes_id_and_name(tmp_path):
    write_issue_report_fetcher(tmp_path)
    m = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [{"use": "t_vuln_scan"}]}}
    api.set_assessment(m, "t_vuln_scan", {
        "id": "11111111-0000-4000-8000-000000000001",
        "name": "Monthly Nessus",
    })
    cfg = next(e for e in m["run"]["fetchers"] if e["use"] == "t_vuln_scan")["config"]
    assert cfg["assessment_id"] == "11111111-0000-4000-8000-000000000001"
    assert cfg["assessment_name"] == "Monthly Nessus"


def test_issue_report_fetchers_skips_evidence_entries(tmp_path):
    write_issue_report_fetcher(tmp_path)
    m = {"run": {"fetchers": [{"use": "t_vuln_scan"}, {"use": "does_not_exist"}]}}
    assert api.issue_report_fetchers(m, tmp_path) == ["t_vuln_scan"]


def test_describe_exposes_kind_and_issue_report_and_reserved_config(tmp_path):
    """A front-end filters the assessment picker from describe --json; if kind
    or issue_report drops out of the descriptor, the picker cannot tell a CSPM
    fetcher from a vulnerability scanner."""
    write_issue_report_fetcher(tmp_path)
    d = next(
        f for cat in api.catalog(tmp_path)["categories"] for f in cat["fetchers"]
        if f["name"] == "t_vuln_scan"
    )
    assert d["kind"] == "issue_report"
    assert d["issue_report"] == {
        "assessment_type": "VULNERABILITY",
        "title": "Test Scan",
    }
    assert {c["name"] for c in d["config"]} >= {"assessment_id", "assessment_name"}


def _sidecar(tmp_path, *, close_cycle, failed_target=False):
    reports = tmp_path / ISSUE_REPORTS_DIR
    reports.mkdir(parents=True)
    (reports / "a.csv").write_bytes(RAW_CSV)
    invocations = [{"fetcher_name": "fa", "status": "success", "files": ["a.csv"],
                    "assessment_id": "A-1", "close_cycle": close_cycle}]
    if failed_target:
        invocations.append({"fetcher_name": "fa", "status": "failed", "files": [],
                            "assessment_id": "A-1", "close_cycle": close_cycle})
    (reports / "_issue_reports.json").write_text(json.dumps({
        "schema_version": "1.1", "run_id": "r1",
        "reports": [{"file": "a.csv", "fetcher_name": "fa", "run_id": "r1",
                     "status": "success", "format": "csv", "assessment_id": "A-1",
                     "assessment_name": "Monthly", "close_cycle": close_cycle}],
        "invocations": invocations,
    }))


def test_preflight_plans_the_close_per_assessment(tmp_path):
    """What the TUI shows before the confirm: the close is the row to read."""
    _sidecar(tmp_path, close_cycle="after_run")
    pf = api.issues_upload_preflight(tmp_path, REPO_ROOT, None, dry_run=True)
    [plan] = pf["assessments"]
    assert plan["operation"] == "PROCESS_CLOSE"
    assert plan["assessment_name"] == "Monthly"


def test_preflight_plan_shows_why_a_close_is_skipped(tmp_path):
    _sidecar(tmp_path, close_cycle="after_run", failed_target=True)
    pf = api.issues_upload_preflight(tmp_path, REPO_ROOT, None, dry_run=True)
    [plan] = pf["assessments"]
    assert plan["operation"] == "PROCESS"
    assert "failed" in plan["close_skipped"]


def test_preflight_warns_on_a_missing_close_policy(tmp_path):
    _sidecar(tmp_path, close_cycle=None)
    pf = api.issues_upload_preflight(tmp_path, REPO_ROOT, None, dry_run=True)
    assert pf["ok"], pf["errors"]
    assert pf["assessments"][0]["error"]
    assert any("close_cycle" in w for w in pf["warnings"]), pf["warnings"]


def test_upload_reads_close_cycle_from_the_producing_manifest(tmp_path):
    """A run collected before close_cycle was set recorded none; setting it in the
    manifest afterwards must be enough, not a reason to collect again."""
    import yaml

    write_issue_report_fetcher(tmp_path)
    (tmp_path / "uploaders").symlink_to(REPO_ROOT / "uploaders")
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [
        {"use": "t_vuln_scan", "config": {ASSESSMENT_ID_FIELD: "A-1"}},
    ]}}
    path = tmp_path / "pipelines.yaml"
    path.write_text(yaml.safe_dump(manifest))
    summary = api.run(manifest, tmp_path, manifest_path=path)
    run_dir = Path(summary["run_dir"])
    assert read_index(run_dir)["reports"][0]["close_cycle"] is None

    before = api.issues_upload_preflight(run_dir, tmp_path, None, dry_run=True)
    assert before["assessments"][0]["error"]

    manifest["run"]["fetchers"][0]["config"][CLOSE_CYCLE_FIELD] = "after_run"
    path.write_text(yaml.safe_dump(manifest))
    after = api.issues_upload_preflight(run_dir, tmp_path, None, dry_run=True)
    [plan] = after["assessments"]
    assert plan["error"] is None
    assert plan["operation"] == "PROCESS_CLOSE"
