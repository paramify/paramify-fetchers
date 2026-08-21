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


def write_issue_report_fetcher(root: Path, *, output="scan.csv", fmt="csv", body=RAW_CSV) -> None:
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
        f'Path(os.environ["EVIDENCE_DIR"], {output!r}).write_bytes(body)\n'
    )
    # The runner validates every fetcher.yaml against the real schema.
    schemas = root / "framework" / "schemas"
    if not schemas.exists():
        schemas.mkdir(parents=True)
        for src in (REPO_ROOT / "framework" / "schemas").glob("*.json"):
            (schemas / src.name).write_bytes(src.read_bytes())


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

    assert index["schema_version"] == "1.0"
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


def test_validate_passes_once_an_assessment_is_set(tmp_path):
    write_issue_report_fetcher(tmp_path)
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "fetchers": [
        {"use": "t_vuln_scan", "config": {ASSESSMENT_ID_FIELD: "abc-123"}}
    ]}}
    assert api.validate(manifest, tmp_path) == []


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
