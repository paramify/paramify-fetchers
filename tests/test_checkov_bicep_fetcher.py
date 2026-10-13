"""checkov_bicep must never let "nothing was scanned" read as a clean scan.

The fetcher runs the way the runner execs it, with stub ``git`` and ``checkov``
binaries on PATH: git "clones" a fixture directory and checkov prints a canned
report. The last test runs the real checkov when it is installed.

Run: ``pytest tests/test_checkov_bicep_fetcher.py``
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "checkov" / "bicep" / "fetcher.sh"
SHA = "0123456789abcdef0123456789abcdef01234567"

_STUB_GIT = r"""#!/bin/bash
if [ "$1" = "clone" ]; then
    printf '%s\n' "$*" >> "$STUB_LOG/git.log"
    [ -n "$STUB_CLONE_FAIL" ] && exit 128
    cp -R "$STUB_REPO/." "${@: -1}/"
    exit 0
fi
[ "$1" = "-C" ] && [ "$3" = "rev-parse" ] && { echo "$STUB_SHA"; exit 0; }
exit 1
"""

# Prints $STUB_REPORT with __ROOT__ replaced by the --directory it was given.
_STUB_CHECKOV = r"""#!/bin/bash
printf '%s\n' "$*" > "$STUB_LOG/checkov.args"
dir=""; prev=""
for a in "$@"; do [ "$prev" = "--directory" ] && dir="$a"; prev="$a"; done
sed "s#__ROOT__#$dir#g" "$STUB_REPORT"
"""

BICEP = "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'sa'\n  location: 'eastus'\n  kind: 'StorageV2'\n  sku: {\n    name: 'Standard_LRS'\n  }\n}\n"
ARM = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [{
        "type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01", "name": "armsa",
        "location": "eastus", "kind": "StorageV2", "sku": {"name": "Standard_LRS"},
        "properties": {"supportsHttpsTrafficOnly": False},
    }],
}
PARAMS = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0", "parameters": {},
}


def check(check_id, resource, file_path="/main.bicep"):
    return {"check_id": check_id, "resource": resource, "file_path": file_path, "check_result": {}}


def report(check_type, passed=(), failed=(), skipped=(), parsing_errors=(), resources=1):
    return {
        "check_type": check_type,
        "results": {"passed_checks": list(passed), "failed_checks": list(failed),
                    "skipped_checks": list(skipped), "parsing_errors": list(parsing_errors)},
        "summary": {"passed": len(passed), "failed": len(failed), "skipped": len(skipped),
                    "parsing_errors": len(parsing_errors), "resource_count": resources},
    }


EMPTY_REPORT = {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0}


def make_repo(root: Path, files: dict) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content))
    return root


def run(tmp_path, files, checkov_report=None, real_checkov=False, **env_over):
    """Run the fetcher; returns (exit code, payload or None, status-file dict or None, tmp_path)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "git").write_text(_STUB_GIT)
    if not real_checkov:
        (bin_dir / "checkov").write_text(_STUB_CHECKOV)
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    report_file = tmp_path / "report.json"
    report_file.write_text(checkov_report if isinstance(checkov_report, str)
                           else json.dumps(checkov_report if checkov_report is not None else EMPTY_REPORT))
    log = tmp_path / "log"
    log.mkdir()
    evidence = tmp_path / "evidence"
    status_file = tmp_path / "status.json"
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "EVIDENCE_DIR": str(evidence),
        "FETCHER_STATUS_FILE": str(status_file),
        "CHECKOV_REPO_URL": "https://github.com/example/infra.git",
        "STUB_REPO": str(make_repo(tmp_path / "repo", files)),
        "STUB_REPORT": str(report_file),
        "STUB_LOG": str(log),
        "STUB_SHA": SHA,
        **env_over,
    }
    proc = subprocess.run(["bash", str(FETCHER)], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=600)
    outputs = list(evidence.glob("checkov_bicep_*.json")) if evidence.exists() else []
    payload = json.loads(outputs[0].read_text()) if outputs else None
    status = json.loads(status_file.read_text()) if status_file.exists() else None
    return proc.returncode, payload, status, tmp_path


@pytest.fixture(autouse=True)
def _require_tools():
    for tool in ("bash", "jq"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} not on PATH")


# --- nothing to scan ---------------------------------------------------------

def test_repo_without_bicep_or_arm_fails_and_reports_no_counts(tmp_path):
    code, payload, status, tmp = run(tmp_path, {"README.md": "# infra\n", "main.tf": "# terraform\n"})
    assert code == 1
    assert payload["status"] == "no_files"
    assert payload["file_counts"] == {"bicep": 0, "arm_templates": 0}
    assert payload["metadata"]["commit_sha"] == SHA
    # null, not 0: a validator asserting failed_checks == 0 must not pass on an empty repo
    assert all(payload["summary"][k] is None for k in
               ("passed_checks", "failed_checks", "skipped_checks", "total_checks", "aggregate_percentage"))
    assert status["code"] == "bad_config"
    assert "nothing was scanned" in status["error"]
    assert not (tmp / "log" / "checkov.args").exists()


def test_parameter_files_and_other_json_are_not_arm_templates(tmp_path):
    code, payload, _, _ = run(tmp_path, {"azuredeploy.parameters.json": PARAMS,
                                         "package.json": {"name": "app"}})
    assert code == 1
    assert payload["status"] == "no_files"


def test_files_present_but_zero_checks_fails(tmp_path):
    code, payload, status, _ = run(tmp_path, {"main.bicep": BICEP}, EMPTY_REPORT)
    assert code == 1
    assert payload["status"] == "no_checks"
    assert payload["summary"]["total_checks"] == 0
    assert payload["summary"]["aggregate_percentage"] is None
    assert "evaluated 0 checks" in status["error"]


# --- a real scan ---------------------------------------------------------------

def test_both_framework_reports_are_merged(tmp_path):
    reports = [
        report("arm", passed=[check("CKV_AZURE_1", "Microsoft.Storage/storageAccounts.armsa", "/azuredeploy.json")],
               failed=[check("CKV_AZURE_3", "Microsoft.Storage/storageAccounts.armsa", "/azuredeploy.json")], resources=2),
        report("bicep", passed=[check("CKV_AZURE_2", "Microsoft.Storage/storageAccounts.sa")] * 2,
               skipped=[check("CKV_AZURE_4", "Microsoft.Storage/storageAccounts.sa")], resources=3),
    ]
    code, payload, status, tmp = run(tmp_path, {"main.bicep": BICEP, "azuredeploy.json": ARM}, reports)
    assert code == 0, payload
    assert status is None
    assert payload["status"] == "success"
    assert payload["file_counts"] == {"bicep": 1, "arm_templates": 1}
    s = payload["summary"]
    assert (s["passed_checks"], s["failed_checks"], s["skipped_checks"], s["total_checks"]) == (3, 1, 1, 5)
    assert s["aggregate_percentage"] == 60
    assert s["resource_count"] == 5
    assert s["by_framework"]["arm"]["failed_checks"] == 1
    assert s["by_framework"]["bicep"]["passed_checks"] == 2
    assert {c["check_type"] for c in payload["results"]["passed_checks"]} == {"arm", "bicep"}
    assert payload["metadata"]["partial_failure"] is False
    args = (tmp / "log" / "checkov.args").read_text().split()
    assert "bicep,arm" in args and args[args.index("bicep,arm") - 1] == "--framework"
    # --quiet drops passed_checks from checkov's JSON
    assert "--quiet" not in args


def test_single_framework_report_object(tmp_path):
    code, payload, _, _ = run(tmp_path, {"main.bicep": BICEP},
                              report("bicep", failed=[check("CKV_AZURE_3", "Microsoft.Storage/storageAccounts.sa")]))
    assert code == 0
    assert payload["summary"]["failed_checks"] == 1
    assert payload["summary"]["aggregate_percentage"] == 0
    assert list(payload["summary"]["by_framework"]) == ["bicep"]


def test_unparseable_files_fail_the_run_and_are_listed(tmp_path):
    rep = report("bicep", passed=[check("CKV_AZURE_2", "Microsoft.Storage/storageAccounts.sa")],
                 parsing_errors=["__ROOT__/modules/new-syntax.bicep"])
    code, payload, status, _ = run(tmp_path, {"main.bicep": BICEP, "modules/new-syntax.bicep": "type t = string?\n"}, rep)
    assert code == 1
    assert payload["status"] == "partial"
    assert payload["results"]["parsing_errors"] == [{"check_type": "bicep", "file_path": "/modules/new-syntax.bicep"}]
    assert payload["metadata"]["partial_failure"] is True
    assert payload["metadata"]["api_failures"] == [
        {"operation": "checkov_parse", "type": "parsing_error", "message": "bicep: /modules/new-syntax.bicep"}]
    assert status["code"] == "partial_failure"


def test_unparseable_checkov_output_is_an_error(tmp_path):
    code, payload, status, _ = run(tmp_path, {"main.bicep": BICEP}, "Traceback: boom\n")
    assert code == 1
    assert payload["status"] == "error"
    assert status["code"] == "internal_error"


# --- skip_resources ------------------------------------------------------------

FAILED_MIX = report("bicep", passed=[check("CKV_AZURE_2", "Microsoft.Storage/storageAccounts.sa")], failed=[
    check("CKV_AZURE_3", "Microsoft.Storage/storageAccounts.devsa"),
    check("CKV_AZURE_3", "Microsoft.Storage/storageAccounts.prodsa"),
    check("CKV_AZURE_43", "Microsoft.Storage/storageAccounts.[format('{0}x', uniqueString(resourceGroup().id))]"),
])


def test_unrelated_skip_resource_pattern_keeps_every_failure(tmp_path):
    code, payload, _, _ = run(tmp_path, {"main.bicep": BICEP}, FAILED_MIX, CHECKOV_SKIP_RESOURCES="nothing_matches")
    assert code == 0
    assert payload["summary"]["failed_checks"] == 3


def test_skip_resource_glob_matches_whole_name_only(tmp_path):
    code, payload, _, _ = run(tmp_path, {"main.bicep": BICEP}, FAILED_MIX,
                              CHECKOV_SKIP_RESOURCES=" Microsoft.Storage/storageAccounts.dev* , Microsoft.Storage/storageAccounts.[format(*")
    assert code == 0
    assert [c["resource"] for c in payload["results"]["failed_checks"]] == ["Microsoft.Storage/storageAccounts.prodsa"]
    assert payload["summary"]["total_checks"] == 2


# --- inputs and cloning --------------------------------------------------------

def test_azure_devops_org_prefix_is_dropped_and_token_never_written(tmp_path):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP},
                                report("bicep", passed=[check("CKV_AZURE_2", "x")]),
                                CHECKOV_REPO_URL="https://vastian@dev.azure.com/vastian/infra/_git/iac",
                                GIT_CLONE_TOKEN="s3cr3t-pat")
    assert code == 0
    assert payload["metadata"]["repo_url"] == "https://dev.azure.com/vastian/infra/_git/iac"
    assert "https://oauth2:s3cr3t-pat@dev.azure.com/vastian/infra/_git/iac" in (tmp / "log" / "git.log").read_text()
    out = next((tmp / "evidence").glob("checkov_bicep_*.json"))
    assert out.name == "checkov_bicep_dev.azure.com_vastian_infra__git_iac.json"
    assert "s3cr3t-pat" not in out.read_text()


def test_clone_failure(tmp_path):
    code, payload, status, _ = run(tmp_path, {"main.bicep": BICEP}, STUB_CLONE_FAIL="1")
    assert code == 1
    assert payload["status"] == "error"
    assert payload["summary"]["failed_checks"] is None
    assert "git clone" in status["error"]


def test_missing_repo_url(tmp_path):
    code, payload, status, _ = run(tmp_path, {"main.bicep": BICEP}, CHECKOV_REPO_URL="")
    assert code == 1
    assert payload is None
    assert status["code"] == "bad_config"


# --- the real scanner ----------------------------------------------------------

@pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not on PATH")
def test_real_checkov_scans_bicep_and_arm(tmp_path):
    code, payload, status, _ = run(tmp_path, {"infra/main.bicep": BICEP, "arm/azuredeploy.json": ARM,
                                              "arm/azuredeploy.parameters.json": PARAMS}, real_checkov=True)
    assert code == 0, status
    s = payload["summary"]
    assert set(s["by_framework"]) == {"arm", "bicep"}
    assert s["passed_checks"] > 0 and s["failed_checks"] > 0
    assert s["total_checks"] == len(payload["results"]["passed_checks"]) + s["failed_checks"] + s["skipped_checks"]
    assert any(c["check_id"] == "CKV_AZURE_3" and c["check_type"] == "arm" for c in payload["results"]["failed_checks"])
