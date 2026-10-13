"""checkov_terraform and checkov_kubernetes must count what checkov counted.

Two bugs this pins: ``--quiet`` strips passed_checks and skipped_checks from
checkov's JSON, so every pass went uncounted; and checkov_terraform's
skip_resources filter tested each resource against itself as a regex, so any
pattern dropped every failed check.

The stub checkov honours ``--quiet`` the way the real one does, so these run in
CI without checkov. The ``real_`` tests use the real scanner when it is installed.

Run: ``pytest tests/test_checkov_scan_counts.py``
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

_STUB_GIT = r"""#!/bin/bash
if [ "$1" = "clone" ]; then
    cp -R "$STUB_REPO/." "${@: -1}/"
    exit 0
fi
[ "$1" = "-C" ] && [ "$3" = "rev-parse" ] && { echo 0123456789abcdef0123456789abcdef01234567; exit 0; }
exit 1
"""

_STUB_CHECKOV = r"""#!/bin/bash
printf '%s\n' "$*" > "$STUB_LOG"
quiet=false
for a in "$@"; do [ "$a" = "--quiet" ] && quiet=true; done
jq --argjson q "$quiet" 'if $q then .results |= {failed_checks} else . end' "$STUB_REPORT"
"""

TF = """resource "aws_s3_bucket" "b" {
  bucket = "x"
}
resource "aws_security_group" "s" {
  name = "s"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:1.27
"""


def checks(n, prefix, resources):
    return [{"check_id": f"{prefix}_{i}", "resource": resources[i % len(resources)], "check_result": {}}
            for i in range(n)]


def report(check_type, passed, failed):
    return {"check_type": check_type,
            "results": {"passed_checks": passed, "failed_checks": failed, "skipped_checks": [], "parsing_errors": []},
            "summary": {"passed": len(passed), "failed": len(failed), "skipped": 0, "parsing_errors": 0}}


# The one-.tf repro: checkov 3.3.15 passes 8 checks and fails 10.
TF_RESOURCES = ["aws_s3_bucket.b", "aws_security_group.s"]
TF_REPORT = report("terraform", checks(8, "CKV_AWS", TF_RESOURCES), checks(10, "CKV2_AWS", TF_RESOURCES))
K8S_REPORT = report("kubernetes", checks(5, "CKV_K8S", ["Deployment.prod.web"]), checks(2, "CKV2_K8S", ["Deployment.prod.web"]))


def run(fetcher, tmp_path, files, checkov_report=None, **env_over):
    """Run fetchers/checkov/<fetcher>; returns (exit code, payload, checkov args or None)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "git").write_text(_STUB_GIT)
    if checkov_report is not None:
        (bin_dir / "checkov").write_text(_STUB_CHECKOV)
        (tmp_path / "report.json").write_text(json.dumps(checkov_report))
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    repo = tmp_path / "repo"
    for rel, content in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(content)
    evidence = tmp_path / "evidence"
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "EVIDENCE_DIR": str(evidence),
        "CHECKOV_REPO_URL": "https://github.com/example/infra.git",
        "STUB_REPO": str(repo),
        "STUB_REPORT": str(tmp_path / "report.json"),
        "STUB_LOG": str(tmp_path / "checkov.args"),
        **env_over,
    }
    proc = subprocess.run(["bash", str(REPO_ROOT / "fetchers" / "checkov" / fetcher / "fetcher.sh")],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=600)
    out = next(evidence.glob(f"checkov_{fetcher}_*.json"), None) if evidence.exists() else None
    payload = json.loads(out.read_text()) if out else None
    args_file = tmp_path / "checkov.args"
    args = args_file.read_text().split() if args_file.exists() else None
    return proc.returncode, payload, args


@pytest.fixture(autouse=True)
def _require_tools():
    for tool in ("bash", "jq"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} not on PATH")


# --- passes are counted ------------------------------------------------------

def test_terraform_counts_passed_checks(tmp_path):
    code, payload, args = run("terraform", tmp_path, {"main.tf": TF}, TF_REPORT)
    assert code == 0
    s = payload["summary"]
    assert (s["passed_checks"], s["failed_checks"], s["total_checks"]) == (8, 10, 18)
    assert s["aggregate_percentage"] == 44.44
    assert "--quiet" not in args


def test_kubernetes_counts_passed_checks(tmp_path):
    code, payload, args = run("kubernetes", tmp_path, {"deploy.yaml": DEPLOYMENT}, K8S_REPORT)
    assert code == 0
    s = payload["summary"]
    assert (s["passed_checks"], s["failed_checks"], s["total_checks"]) == (5, 2, 7)
    assert s["aggregate_percentage"] == 71.43
    assert "--quiet" not in args


# --- checkov_terraform skip_resources ------------------------------------------

def test_unrelated_skip_resource_pattern_keeps_every_failure(tmp_path):
    code, payload, _ = run("terraform", tmp_path, {"main.tf": TF}, TF_REPORT,
                           CHECKOV_SKIP_RESOURCES="totally_unrelated_pattern")
    assert code == 0
    assert payload["summary"]["failed_checks"] == 10


def test_matching_skip_resource_pattern_removes_only_its_resource(tmp_path):
    code, payload, _ = run("terraform", tmp_path, {"main.tf": TF}, TF_REPORT,
                           CHECKOV_SKIP_RESOURCES="aws_security_group.*")
    assert code == 0
    assert {c["resource"] for c in payload["results"]["failed_checks"]} == {"aws_s3_bucket.b"}
    assert payload["summary"]["failed_checks"] == 5
    assert payload["summary"]["passed_checks"] == 8


def test_skip_resource_glob_is_anchored(tmp_path):
    code, payload, _ = run("terraform", tmp_path, {"main.tf": TF}, TF_REPORT, CHECKOV_SKIP_RESOURCES="s3_bucket.b")
    assert code == 0
    assert payload["summary"]["failed_checks"] == 10


def test_skip_resource_filter_error_fails_the_run(tmp_path):
    broken = {**TF_REPORT, "results": {**TF_REPORT["results"], "failed_checks": "not-a-list"}}
    code, payload, _ = run("terraform", tmp_path, {"main.tf": TF}, broken, CHECKOV_SKIP_RESOURCES="aws_s3_bucket.b")
    assert code == 1
    assert payload["status"] == "error"


# --- the real scanner ----------------------------------------------------------

needs_checkov = pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not on PATH")


@needs_checkov
def test_real_terraform_counts_match_checkovs_summary(tmp_path):
    code, payload, _ = run("terraform", tmp_path, {"main.tf": TF})
    assert code == 0
    s = payload["summary"]
    assert s["passed_checks"] > 0 and s["failed_checks"] > 0
    assert (s["passed_checks"], s["failed_checks"], s["skipped_checks"]) == (s["passed"], s["failed"], s["skipped"])


@needs_checkov
def test_real_kubernetes_counts_match_checkovs_summary(tmp_path):
    code, payload, _ = run("kubernetes", tmp_path, {"deploy.yaml": DEPLOYMENT})
    assert code == 0
    s = payload["summary"]
    assert s["passed_checks"] > 0 and s["failed_checks"] > 0
    assert (s["passed_checks"], s["failed_checks"], s["skipped_checks"]) == (s["passed"], s["failed"], s["skipped"])
