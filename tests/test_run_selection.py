"""Which run an upload picks when none is named.

Evidence manifests and pipeline (issue-report) manifests usually share an
output_dir. "The newest run" alone handed `paramify issues upload` an
evidence-only run while the scan run sat beside it, and the reverse for
`paramify upload`. Each stage now takes the newest run holding its own kind,
and `-f MANIFEST` narrows that to one manifest's runs.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from framework import api
from framework.cli import app

REPO_ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evidence_run(out: Path, run_id: str, manifest: str | None = None) -> Path:
    run = out / f"run-{run_id}"
    run.mkdir(parents=True)
    (run / "e.json").write_text(json.dumps({
        "schema_version": "1.0",
        "metadata": {"fetcher_name": "ev", "run_id": run_id, "status": "ok",
                     "evidence_set": {"reference_id": "EVD-1", "name": "E"}},
        "payload": {},
    }))
    (run / "_run_metadata.json").write_text(json.dumps({
        "run_id": run_id, "manifest": manifest,
        "invocations": [{"fetcher_name": "ev", "exit_code": 0, "outputs": ["e.json"]}],
    }))
    return run


def issue_run(out: Path, run_id: str, manifest: str | None = None) -> Path:
    run = out / f"run-{run_id}"
    reports = run / "issue-reports"
    reports.mkdir(parents=True)
    (reports / "scan.csv").write_bytes(b"ID,Severity\r\n1,High\r\n")
    (reports / "_issue_reports.json").write_text(json.dumps({
        "schema_version": "1.1", "run_id": run_id,
        "reports": [{"file": "scan.csv", "fetcher_name": "scan", "run_id": run_id,
                     "status": "success", "format": "csv", "assessment_id": "A-1",
                     "close_cycle": "never"}],
        "invocations": [{"fetcher_name": "scan", "status": "success", "files": ["scan.csv"],
                         "assessment_id": "A-1", "close_cycle": "never"}],
    }))
    (run / "_run_metadata.json").write_text(json.dumps({
        "run_id": run_id, "manifest": manifest,
        "invocations": [{"fetcher_name": "scan", "exit_code": 0,
                         "outputs": ["issue-reports/scan.csv"]}],
    }))
    return run


# --------------------------------------------------------------------------- #
# api.latest_run
# --------------------------------------------------------------------------- #

def test_latest_run_by_kind_skips_the_other_kinds_newer_run(tmp_path):
    scans = issue_run(tmp_path, "2026-09-01T00-00-00Z")
    evidence = evidence_run(tmp_path, "2026-09-02T00-00-00Z")
    assert api.latest_run(tmp_path)["dir"] == str(evidence)
    assert api.latest_run(tmp_path, kind="issue_report")["dir"] == str(scans)
    later_scans = issue_run(tmp_path, "2026-09-03T00-00-00Z")
    assert api.latest_run(tmp_path, kind="evidence")["dir"] == str(evidence)
    assert api.latest_run(tmp_path, kind="issue_report")["dir"] == str(later_scans)


def test_latest_run_by_manifest(tmp_path):
    a, b = tmp_path / "a.yaml", tmp_path / "b.yaml"
    mine = issue_run(tmp_path, "2026-09-01T00-00-00Z", manifest=str(a.resolve()))
    issue_run(tmp_path, "2026-09-02T00-00-00Z", manifest=str(b.resolve()))
    got = api.latest_run(tmp_path, kind="issue_report", manifest_path=a, root=REPO_ROOT)
    assert got["dir"] == str(mine)


def test_latest_run_is_none_when_nothing_matches(tmp_path):
    evidence_run(tmp_path, "2026-09-01T00-00-00Z")
    assert api.latest_run(tmp_path, kind="issue_report") is None


def test_unknown_kind_is_refused(tmp_path):
    evidence_run(tmp_path, "2026-09-01T00-00-00Z")
    with pytest.raises(ValueError, match="unknown run kind"):
        api.latest_run(tmp_path, kind="scans")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

@pytest.fixture
def in_repo(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.delenv("PARAMIFY_UPLOAD_API_TOKEN", raising=False)
    monkeypatch.delenv("PARAMIFY_API_TOKEN", raising=False)


def test_issues_upload_picks_the_scan_run_not_the_newer_evidence_run(tmp_path, in_repo):
    scans = issue_run(tmp_path, "2026-09-01T00-00-00Z")
    evidence_run(tmp_path, "2026-09-02T00-00-00Z")
    result = runner.invoke(app, ["issues", "upload", "-o", str(tmp_path), "--dry-run", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["run_dir"] == str(scans)


def test_evidence_upload_picks_the_evidence_run_not_the_newer_scan_run(tmp_path, in_repo):
    evidence = evidence_run(tmp_path, "2026-09-01T00-00-00Z")
    issue_run(tmp_path, "2026-09-02T00-00-00Z")
    result = runner.invoke(app, ["upload", "-o", str(tmp_path), "--dry-run", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["run_dir"] == str(evidence)


def test_issues_upload_says_no_run_collected_reports(tmp_path, in_repo):
    evidence_run(tmp_path, "2026-09-01T00-00-00Z")
    result = runner.invoke(app, ["issues", "upload", "-o", str(tmp_path), "--dry-run", "--json"])
    assert result.exit_code == 1
    assert "collected issue reports" in json.loads(result.output)["errors"][0]


def test_dash_f_uses_the_manifests_output_dir_and_its_runs(tmp_path, in_repo):
    out = tmp_path / "shared"
    pipelines = tmp_path / "pipelines.yaml"
    other = tmp_path / "other-pipelines.yaml"
    for path in (pipelines, other):
        path.write_text(json.dumps({"run": {"output_dir": str(out), "fetchers": []}}))
    mine = issue_run(out, "2026-09-01T00-00-00Z", manifest=str(pipelines.resolve()))
    issue_run(out, "2026-09-02T00-00-00Z", manifest=str(other.resolve()))
    result = runner.invoke(
        app, ["issues", "upload", "-f", str(pipelines), "--dry-run", "--json"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["run_dir"] == str(mine)


def test_dash_f_with_no_run_of_that_manifest_names_it(tmp_path, in_repo):
    out = tmp_path / "shared"
    pipelines = tmp_path / "pipelines.yaml"
    pipelines.write_text(json.dumps({"run": {"output_dir": str(out), "fetchers": []}}))
    issue_run(out, "2026-09-01T00-00-00Z", manifest="somewhere/else.yaml")
    result = runner.invoke(
        app, ["issues", "upload", "-f", str(pipelines), "--dry-run", "--json"]
    )
    assert result.exit_code == 1
    assert "produced by" in json.loads(result.output)["errors"][0]


# --------------------------------------------------------------------------- #
# Standalone uploaders
# --------------------------------------------------------------------------- #

def test_standalone_uploaders_pick_their_own_kind(tmp_path):
    issues = _load(REPO_ROOT / "uploaders" / "paramify_issues" / "uploader.py", "issues_sel")
    evidence = _load(REPO_ROOT / "uploaders" / "paramify_evidence" / "uploader.py", "evidence_sel")
    ev = evidence_run(tmp_path, "2026-09-01T00-00-00Z")
    sc = issue_run(tmp_path, "2026-09-02T00-00-00Z")
    assert evidence.find_latest_run(tmp_path) == ev, "took the newer scan-only run"
    later = evidence_run(tmp_path, "2026-09-03T00-00-00Z")
    assert issues.find_latest_run(tmp_path) == sc, "took the newer evidence-only run"
    assert evidence.find_latest_run(tmp_path) == later


def test_the_evidence_uploaders_log_is_not_evidence(tmp_path):
    """A scan-only run someone ran `paramify upload` on gains upload_log.json;
    it must not start looking like an evidence run."""
    run = issue_run(tmp_path, "2026-09-01T00-00-00Z")
    (run / "upload_log.json").write_text("{}")
    assert api.latest_run(tmp_path, kind="evidence") is None
