"""checkov_bicep must never let "nothing was scanned" read as a clean scan.

The fetcher runs the way the runner execs it, with stub ``git``, ``curl`` and
``checkov`` binaries on PATH: git "clones" a fixture directory, curl serves canned
Azure DevOps TFVC responses (a changeset lookup and the folder as a zip), and
checkov prints a canned report. The real-checkov tests run when it is installed.

Run: ``pytest tests/test_checkov_bicep_fetcher.py``
"""

from __future__ import annotations

import base64
import io
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "checkov" / "bicep" / "fetcher.sh"
SHA = "0123456789abcdef0123456789abcdef01234567"

# A --branch outside $STUB_BRANCHES fails like a missing ref; the default branch is $STUB_DEFAULT_BRANCH.
_STUB_GIT = r"""#!/bin/bash
if [ "$1" = "clone" ]; then
    printf '%s\n' "$*" >> "$STUB_LOG/git.log"
    [ -n "$STUB_CLONE_FAIL" ] && exit 128
    branch=""; prev=""
    for a in "$@"; do [ "$prev" = "--branch" ] && branch="$a"; prev="$a"; done
    if [ -n "$branch" ] && ! printf '%s\n' ${STUB_BRANCHES:-main} | grep -qx -- "$branch"; then exit 128; fi
    cp -R "$STUB_REPO/." "${@: -1}/"
    exit 0
fi
[ "$1" = "-C" ] && [ "$3" = "rev-parse" ] && [ "$4" = "--abbrev-ref" ] && { echo "${STUB_DEFAULT_BRANCH:-main}"; exit 0; }
[ "$1" = "-C" ] && [ "$3" = "rev-parse" ] && { echo "$STUB_SHA"; exit 0; }
exit 1
"""

# Serves $STUB_TFVC/<route>.status and <route>.body, logging argv and the --config it read on stdin.
_STUB_CURL = r"""#!/bin/bash
argv="$*"; out=""; accept=""; url=""; cfg=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -H) case "$2" in Accept:*) accept="${2#Accept: }" ;; esac; shift 2 ;;
        --config) [ "$2" = "-" ] && cfg="$(cat)"; shift 2 ;;
        --max-time|--retry|-w) shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
case "$url" in
    */_apis/tfvc/changesets/[0-9]*) route=changeset ;;
    */_apis/tfvc/changesets\?*)     route=changesets ;;
    */_apis/tfvc/items\?*)          route=items ;;
    *) route=unknown ;;
esac
printf 'ARGV %s\nURL %s\nACCEPT %s\nCONFIG %s\n' "$argv" "$url" "$accept" "$cfg" >> "$STUB_LOG/curl.log"
status="$(cat "$STUB_TFVC/$route.status" 2>/dev/null || echo 404)"
if [ "$status" = "000" ]; then echo "curl: (6) Could not resolve host" >&2; printf '000'; exit 6; fi
cp "$STUB_TFVC/$route.body" "$out" 2>/dev/null || : > "$out"
printf '%s' "$status"
"""

# Prints $STUB_REPORT with __ROOT__ replaced by the --directory it was given.
_STUB_CHECKOV = r"""#!/bin/bash
printf '%s\n' "$*" > "$STUB_LOG/checkov.args"
printf '%s\n' "$@" > "$STUB_LOG/checkov.argv"
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


def run(tmp_path, files, checkov_report=None, real_checkov=False, tfvc=None, fetcher=FETCHER, **env_over):
    """Run the fetcher; returns (exit code, payload or None, status-file dict or None, tmp_path).

    tfvc maps a curl route (changesets, changeset, items) to (HTTP status, body bytes or JSON).
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "git").write_text(_STUB_GIT)
    (bin_dir / "curl").write_text(_STUB_CURL)
    tfvc_dir = tmp_path / "tfvc"
    tfvc_dir.mkdir()
    for route, (status, body) in (tfvc or {}).items():
        (tfvc_dir / f"{route}.status").write_text(str(status))
        (tfvc_dir / f"{route}.body").write_bytes(body if isinstance(body, bytes) else json.dumps(body).encode())
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
        "STUB_TFVC": str(tfvc_dir),
        **env_over,
    }
    proc = subprocess.run(["bash", str(fetcher)], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=600)
    outputs = list(evidence.glob("checkov_bicep_*.json")) if evidence.exists() else []
    payload = json.loads(outputs[0].read_text()) if outputs else None
    status = json.loads(status_file.read_text()) if status_file.exists() else None
    return proc.returncode, payload, status, tmp_path


@pytest.fixture(autouse=True)
def _require_tools():
    for tool in ("bash", "jq", "unzip"):
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
    assert payload["metadata"]["skip_resources"] == ["Microsoft.Storage/storageAccounts.dev*",
                                                     "Microsoft.Storage/storageAccounts.[format(*"]


def test_skip_resources_split_on_newlines_too(tmp_path):
    code, payload, _, _ = run(tmp_path, {"main.bicep": BICEP}, FAILED_MIX,
                              CHECKOV_SKIP_RESOURCES="Microsoft.Storage/storageAccounts.dev*\n Microsoft.Storage/storageAccounts.prodsa\n")
    assert code == 0
    assert payload["summary"]["skipped_by_resource_filter"] == 2
    assert payload["metadata"]["skip_resources"] == ["Microsoft.Storage/storageAccounts.dev*",
                                                     "Microsoft.Storage/storageAccounts.prodsa"]


def test_skip_resources_moves_failures_to_skipped(tmp_path):
    code, payload, _, _ = run(tmp_path, {"main.bicep": BICEP}, FAILED_MIX,
                              CHECKOV_SKIP_RESOURCES="Microsoft.Storage/storageAccounts.dev*")
    assert code == 0
    s = payload["summary"]
    # the moved check stays in the denominator, so the pass rate is not raised
    assert (s["passed_checks"], s["failed_checks"], s["skipped_checks"], s["total_checks"]) == (1, 2, 1, 4)
    assert s["aggregate_percentage"] == 25
    assert s["skipped_by_resource_filter"] == 1
    assert s["by_framework"]["bicep"]["skipped_checks"] == 1
    (moved,) = payload["results"]["skipped_checks"]
    assert moved["resource"] == "Microsoft.Storage/storageAccounts.devsa"
    assert moved["check_result"]["result"] == "SKIPPED"
    assert "Microsoft.Storage/storageAccounts.dev*" in moved["check_result"]["suppress_comment"]
    assert "_skip" not in moved


def test_skip_resources_trailing_comma_does_not_match_everything(tmp_path):
    code, payload, _, _ = run(tmp_path, {"main.bicep": BICEP}, FAILED_MIX,
                              CHECKOV_SKIP_RESOURCES="Microsoft.Storage/storageAccounts.prodsa,")
    assert code == 0
    assert payload["summary"]["failed_checks"] == 2
    assert payload["summary"]["skipped_by_resource_filter"] == 1
    assert payload["metadata"]["skip_resources"] == ["Microsoft.Storage/storageAccounts.prodsa"]


# --- skip_checks ---------------------------------------------------------------

def test_effective_skip_list_is_recorded(tmp_path):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP}, report("bicep", passed=[check("CKV_AZURE_2", "x")]),
                                CHECKOV_SKIP_CHECKS="CKV_AZURE_35, CKV_AZURE_35,CKV_AZURE_33", CHECKOV_BICEP_CHECKS="CKV_AZURE_33")
    assert code == 0
    args = (tmp / "log" / "checkov.args").read_text().split()
    assert args[args.index("--skip-check") + 1] == "CKV_AZURE_35"
    assert payload["metadata"]["skip_checks"] == ["CKV_AZURE_35"]
    assert payload["metadata"]["checks"] == ["CKV_AZURE_33"]
    assert payload["metadata"]["default_skip_checks_applied"] is True
    assert payload["metadata"]["skip_paths"] == []


def test_skip_path_with_spaces_is_one_argument(tmp_path):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP}, report("bicep", passed=[check("CKV_AZURE_2", "x")]),
                                CHECKOV_SKIP_PATHS=" My Templates/legacy , ,other ")
    assert code == 0
    argv = (tmp / "log" / "checkov.argv").read_text().splitlines()
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--skip-path"] == ["My Templates/legacy", "other"]
    assert payload["metadata"]["skip_paths"] == ["My Templates/legacy", "other"]


@pytest.mark.parametrize("raw,expected", [
    ("modules/new.bicep,\nlegacy\n", ["modules/new.bicep", "legacy"]),   # a YAML literal block
    ("a\nb", ["a", "b"]),
    ("\n", []),
])
def test_skip_paths_split_on_newlines_too(tmp_path, raw, expected):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP}, report("bicep", passed=[check("CKV_AZURE_2", "x")]),
                                CHECKOV_SKIP_PATHS=raw)
    assert code == 0
    argv = (tmp / "log" / "checkov.argv").read_text().splitlines()
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--skip-path"] == expected
    assert payload["metadata"]["skip_paths"] == expected


def test_check_allowlist_is_trimmed_and_still_overrides_skips(tmp_path):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP}, report("bicep", passed=[check("CKV_AZURE_2", "x")]),
                                CHECKOV_BICEP_CHECKS="CKV_AZURE_3, CKV_AZURE_44,",
                                CHECKOV_SKIP_CHECKS="CKV_AZURE_44,\n CKV_AZURE_35")
    assert code == 0
    argv = (tmp / "log" / "checkov.argv").read_text().splitlines()
    assert argv[argv.index("--check") + 1] == "CKV_AZURE_3,CKV_AZURE_44"
    assert argv[argv.index("--skip-check") + 1] == "CKV_AZURE_35"
    assert payload["metadata"]["skip_checks"] == ["CKV_AZURE_35"]
    assert payload["metadata"]["checks"] == ["CKV_AZURE_3", "CKV_AZURE_44"]


@pytest.mark.parametrize("env,flag,expected", [
    ({"CHECKOV_BICEP_CHECKS": "CKV_AZURE_3,CKV_AZURE_44 CKV_AZURE_35"}, "--check", "CKV_AZURE_3,CKV_AZURE_44,CKV_AZURE_35"),
    ({"CHECKOV_BICEP_CHECKS": "CKV_AZURE_3 CKV_AZURE_44"}, "--check", "CKV_AZURE_3,CKV_AZURE_44"),
    ({"CHECKOV_SKIP_CHECKS": "CKV_AZURE_3 CKV_AZURE_44"}, "--skip-check", "CKV_AZURE_3,CKV_AZURE_44"),
    ({"CHECKOV_SKIP_CHECKS": "CKV_AZURE_3\tCKV_AZURE_44"}, "--skip-check", "CKV_AZURE_3,CKV_AZURE_44"),
])
def test_check_ids_separated_by_whitespace(tmp_path, env, flag, expected):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP}, report("bicep", passed=[check("CKV_AZURE_2", "x")]), **env)
    assert code == 0
    argv = (tmp / "log" / "checkov.argv").read_text().splitlines()
    assert argv[argv.index(flag) + 1] == expected
    assert payload["metadata"]["skip_checks" if flag == "--skip-check" else "checks"] == expected.split(",")


def test_skip_paths_are_recorded(tmp_path):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP}, report("bicep", passed=[check("CKV_AZURE_2", "x")]),
                                CHECKOV_SKIP_PATHS="modules/new-syntax.bicep, legacy")
    assert code == 0
    args = (tmp / "log" / "checkov.args").read_text().split()
    assert [args[i + 1] for i, a in enumerate(args) if a == "--skip-path"] == ["modules/new-syntax.bicep", "legacy"]
    assert payload["metadata"]["skip_paths"] == ["modules/new-syntax.bicep", "legacy"]


def fetcher_with_default_skips(tmp_path, text):
    """A copy of the fetcher tree whose shipped skip-checks file is text."""
    root = tmp_path / "fetchers"
    for d in ("checkov", "_lib"):
        shutil.copytree(REPO_ROOT / "fetchers" / d, root / d, ignore=shutil.ignore_patterns("__pycache__"))
    (root / "checkov" / "_shared" / "skip-checks.default.txt").write_text(text)
    return root / "checkov" / "bicep" / "fetcher.sh"


def test_default_skip_checks_file_is_split_like_skip_checks(tmp_path):
    fetcher = fetcher_with_default_skips(tmp_path, "# header\nCKV_AZURE_3, CKV_AZURE_44\nCKV_AZURE_35  # noisy\n"
                                                   "CKV_AZURE_33\tCKV_AZURE_59\n\n#CKV_AZURE_1\n")
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP}, report("bicep", passed=[check("CKV_AZURE_2", "x")]),
                                fetcher=fetcher, CHECKOV_BICEP_CHECKS="CKV_AZURE_44", CHECKOV_SKIP_CHECKS="CKV_AZURE_36")
    assert code == 0
    argv = (tmp / "log" / "checkov.argv").read_text().splitlines()
    expected = ["CKV_AZURE_3", "CKV_AZURE_35", "CKV_AZURE_33", "CKV_AZURE_59", "CKV_AZURE_36"]
    assert argv[argv.index("--skip-check") + 1] == ",".join(expected)
    assert payload["metadata"]["skip_checks"] == expected


def test_default_skip_checks_can_be_turned_off(tmp_path):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP}, report("bicep", passed=[check("CKV_AZURE_2", "x")]),
                                CHECKOV_USE_DEFAULT_SKIP_CHECKS="false")
    assert code == 0
    assert "--skip-check" not in (tmp / "log" / "checkov.args").read_text().split()
    assert "--check" not in (tmp / "log" / "checkov.args").read_text().split()
    assert payload["metadata"]["skip_checks"] == []
    assert payload["metadata"]["checks"] == []
    assert payload["metadata"]["default_skip_checks_applied"] is False


def test_no_files_result_still_records_scan_config(tmp_path):
    _, payload, _, _ = run(tmp_path, {"README.md": "# infra\n"}, CHECKOV_SKIP_CHECKS="CKV_AZURE_35",
                           CHECKOV_BICEP_CHECKS="CKV_AZURE_3")
    assert payload["status"] == "no_files"
    assert payload["metadata"]["skip_checks"] == ["CKV_AZURE_35"]
    assert payload["metadata"]["checks"] == ["CKV_AZURE_3"]
    assert payload["summary"]["skipped_by_resource_filter"] is None


# --- inputs and cloning --------------------------------------------------------

def test_azure_devops_org_prefix_is_dropped_and_token_never_written(tmp_path):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP},
                                report("bicep", passed=[check("CKV_AZURE_2", "x")]),
                                CHECKOV_REPO_URL="https://contoso@dev.azure.com/contoso/infra/_git/iac",
                                GIT_CLONE_TOKEN="s3cr3t-pat")
    assert code == 0
    assert payload["metadata"]["repo_url"] == "https://dev.azure.com/contoso/infra/_git/iac"
    assert "https://oauth2:s3cr3t-pat@dev.azure.com/contoso/infra/_git/iac" in (tmp / "log" / "git.log").read_text()
    out = next((tmp / "evidence").glob("checkov_bicep_*.json"))
    assert out.name == "checkov_bicep_dev.azure.com_contoso_infra__git_iac.json"
    assert "s3cr3t-pat" not in out.read_text()


def test_requested_branch_recorded(tmp_path):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP}, report("bicep", passed=[check("CKV_AZURE_2", "x")]),
                                CHECKOV_CLONE_BRANCH="main")
    assert code == 0
    meta = payload["metadata"]
    assert (meta["branch"], meta["requested_branch"], meta["branch_fallback"]) == ("main", "main", False)
    args = (tmp / "log" / "checkov.args").read_text().split()
    assert args[args.index("--branch") + 1] == "main"


def test_branch_fallback_records_the_branch_that_was_scanned(tmp_path):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP}, report("bicep", passed=[check("CKV_AZURE_2", "x")]),
                                CHECKOV_CLONE_BRANCH="release-9", STUB_DEFAULT_BRANCH="trunk")
    assert code == 0
    meta = payload["metadata"]
    assert (meta["branch"], meta["requested_branch"], meta["branch_fallback"]) == ("trunk", "release-9", True)
    args = (tmp / "log" / "checkov.args").read_text().split()
    assert args[args.index("--branch") + 1] == "trunk"


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


def test_git_is_the_default_source(tmp_path):
    code, payload, _, tmp = run(tmp_path, {"main.bicep": BICEP}, report("bicep", passed=[check("CKV_AZURE_2", "x")]))
    assert code == 0
    assert payload["source_type"] == "git"
    assert payload["metadata"]["source_type"] == "git"
    assert payload["metadata"]["commit_sha"] == SHA
    assert "changeset" not in payload["metadata"]
    assert not (tmp / "log" / "curl.log").exists()


# --- TFVC source -----------------------------------------------------------------

PROJECT = "https://dev.azure.com/contoso/Infra"
TFVC_PATH = "$/Infra/ARM Templates"
PAT = "s3cr3t-pat"
TFVC_ENV = {"CHECKOV_SOURCE_TYPE": "tfvc", "CHECKOV_REPO_URL": PROJECT + "/", "CHECKOV_TFVC_PATH": TFVC_PATH}
LATEST = {"count": 1, "value": [{"changesetId": 4217, "createdDate": "2026-10-01T12:00:00Z"}]}
ONE_PASS = report("arm", passed=[check("CKV_AZURE_2", "x", "/ARM Templates/azuredeploy.json")])


def zipped(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for rel, content in files.items():
            z.writestr(rel, content if isinstance(content, str) else json.dumps(content))
    return buf.getvalue()


TEMPLATES = zipped({"ARM Templates/azuredeploy.json": ARM, "ARM Templates/azuredeploy.parameters.json": PARAMS,
                    "ARM Templates/modules/main.bicep": BICEP})


def curl_calls(tmp):
    log = tmp / "log" / "curl.log"
    calls, cur = [], {}
    for line in (log.read_text().splitlines() if log.exists() else []):
        key, _, val = line.partition(" ")
        if key == "ARGV" and cur:
            calls.append(cur)
            cur = {}
        cur[key] = val
    return calls + ([cur] if cur else [])


def test_tfvc_latest_pins_the_newest_changeset_and_records_it(tmp_path):
    code, payload, status, tmp = run(tmp_path, {}, ONE_PASS, tfvc={"changesets": (200, LATEST), "items": (200, TEMPLATES)},
                                     TFVC_TOKEN=PAT, **TFVC_ENV)
    assert code == 0, status
    assert payload["status"] == "success"
    assert payload["source_type"] == "tfvc"
    assert payload["source"] == PROJECT
    meta = payload["metadata"]
    assert {k: meta[k] for k in ("source_type", "repo_url", "tfvc_path", "requested_version", "changeset", "changeset_date")} == {
        "source_type": "tfvc", "repo_url": PROJECT, "tfvc_path": TFVC_PATH, "requested_version": "latest",
        "changeset": 4217, "changeset_date": "2026-10-01T12:00:00Z"}
    assert "commit_sha" not in meta and "branch" not in meta
    assert payload["file_counts"] == {"bicep": 1, "arm_templates": 1}

    lookup, download = curl_calls(tmp)
    assert lookup["URL"] == f"{PROJECT}/_apis/tfvc/changesets?%24top=1&api-version=7.1"
    assert lookup["ACCEPT"] == "application/json"
    assert download["URL"] == (f"{PROJECT}/_apis/tfvc/items?path=%24%2FInfra%2FARM%20Templates&recursionLevel=Full"
                               "&versionDescriptor.versionType=changeset&versionDescriptor.version=4217&api-version=7.1")
    assert download["ACCEPT"] == "application/zip"
    basic = base64.b64encode(f":{PAT}".encode()).decode()
    assert lookup["CONFIG"] == download["CONFIG"] == f'header = "Authorization: Basic {basic}"'
    assert all(PAT not in c["ARGV"] and basic not in c["ARGV"] for c in (lookup, download))

    out = next((tmp / "evidence").glob("checkov_bicep_*.json"))
    assert out.name == "checkov_bicep_dev.azure.com_contoso_Infra___Infra_ARM_Templates.json"
    assert PAT not in out.read_text()
    assert not (tmp / "log" / "git.log").exists()
    assert "--branch" not in (tmp / "log" / "checkov.args").read_text().split()


def test_tfvc_named_changeset(tmp_path):
    code, payload, _, tmp = run(tmp_path, {}, ONE_PASS, tfvc={
        "changeset": (200, {"changesetId": 1200, "createdDate": "2026-09-02T08:30:00Z"}), "items": (200, TEMPLATES)},
        CHECKOV_TFVC_VERSION="C1200", **TFVC_ENV)
    assert code == 0
    assert (payload["metadata"]["requested_version"], payload["metadata"]["changeset"]) == ("1200", 1200)
    lookup, download = curl_calls(tmp)
    assert lookup["URL"] == f"{PROJECT}/_apis/tfvc/changesets/1200?api-version=7.1"
    assert "versionDescriptor.version=1200&" in download["URL"]


def test_tfvc_without_token_sends_no_credentials(tmp_path):
    code, _, _, tmp = run(tmp_path, {}, ONE_PASS, tfvc={"changesets": (200, LATEST), "items": (200, TEMPLATES)},
                          GIT_CLONE_TOKEN="git-only-token", **TFVC_ENV)
    assert code == 0
    assert all(c["CONFIG"] == "" for c in curl_calls(tmp))


@pytest.mark.parametrize("http,body,code_expected", [
    (203, b"<html>Sign In</html>", "auth_failed"),
    (401, b"", "auth_failed"),
    (403, {"message": "TF400813: not authorized"}, "not_authorized"),
    (429, b"", "rate_limited"),
    ("000", b"", "target_unreachable"),
])
def test_tfvc_lookup_failures_are_errors_with_no_counts(tmp_path, http, body, code_expected):
    code, payload, status, tmp = run(tmp_path, {}, ONE_PASS, tfvc={"changesets": (http, body)}, TFVC_TOKEN=PAT, **TFVC_ENV)
    assert code == 1
    assert status["code"] == code_expected
    assert payload["status"] == "error"
    assert payload["metadata"]["changeset"] is None
    assert payload["summary"]["total_checks"] is None
    assert len(curl_calls(tmp)) == 1           # no download after a failed lookup
    assert PAT not in json.dumps(payload) + status["error"]


def test_tfvc_sign_in_redirect_without_token_says_none_was_set(tmp_path):
    code, _, status, _ = run(tmp_path, {}, ONE_PASS, tfvc={"changesets": (302, b"<html>Object moved</html>")}, **TFVC_ENV)
    assert code == 1
    assert status["code"] == "auth_failed"
    assert "no tfvc_token was set" in status["error"]


def test_tfvc_missing_folder_is_bad_config(tmp_path):
    missing = {"message": "TF401174: The item $/Infra/ARM Templates could not be found at the specified version."}
    code, payload, status, _ = run(tmp_path, {}, ONE_PASS, tfvc={"changesets": (200, LATEST), "items": (404, missing)}, **TFVC_ENV)
    assert code == 1
    assert status["code"] == "bad_config"
    assert "TF401174" in status["error"]
    assert payload["metadata"]["changeset"] == 4217


def test_tfvc_project_without_history(tmp_path):
    code, _, status, tmp = run(tmp_path, {}, ONE_PASS, tfvc={"changesets": (200, {"count": 0, "value": []})}, **TFVC_ENV)
    assert code == 1
    assert status["code"] == "bad_config"
    assert "no changeset id" in status["error"]
    assert len(curl_calls(tmp)) == 1


def test_tfvc_download_that_is_not_a_zip(tmp_path):
    code, payload, status, _ = run(tmp_path, {}, ONE_PASS,
                                   tfvc={"changesets": (200, LATEST), "items": (200, b"<html>Sign In</html>")}, **TFVC_ENV)
    assert code == 1
    assert status["code"] == "internal_error"
    assert "did not return a zip archive" in status["error"]
    assert payload["status"] == "error"


def test_tfvc_folder_without_templates_is_no_files(tmp_path):
    code, payload, status, tmp = run(tmp_path, {}, ONE_PASS, tfvc={
        "changesets": (200, LATEST), "items": (200, zipped({"ARM Templates/README.md": "# docs\n"}))}, **TFVC_ENV)
    assert code == 1
    assert payload["status"] == "no_files"
    assert payload["metadata"]["changeset"] == 4217
    assert "changeset 4217" in status["error"]
    assert not (tmp / "log" / "checkov.args").exists()


@pytest.mark.parametrize("env,needle", [
    ({"CHECKOV_TFVC_PATH": ""}, "tfvc_path"),
    ({"CHECKOV_TFVC_PATH": "Infra/ARM"}, "tfvc_path"),
    ({"CHECKOV_TFVC_VERSION": "tip"}, "tfvc_version"),
    ({"CHECKOV_REPO_URL": "dev.azure.com/contoso/Infra"}, "project URL"),
    ({"CHECKOV_SOURCE_TYPE": "svn"}, "source_type"),
])
def test_tfvc_bad_inputs_fail_before_any_request(tmp_path, env, needle):
    code, payload, status, tmp = run(tmp_path, {}, ONE_PASS, tfvc={"changesets": (200, LATEST)}, **{**TFVC_ENV, **env})
    assert code == 1
    assert payload is None
    assert status["code"] == "bad_config"
    assert needle in status["error"]
    assert curl_calls(tmp) == []


@pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not on PATH")
def test_real_checkov_scans_a_tfvc_download(tmp_path):
    code, payload, status, _ = run(tmp_path, {}, real_checkov=True,
                                   tfvc={"changesets": (200, LATEST), "items": (200, TEMPLATES)}, **TFVC_ENV)
    assert code == 0, status
    assert set(payload["summary"]["by_framework"]) == {"arm", "bicep"}
    failed = payload["results"]["failed_checks"]
    assert any(c["check_id"] == "CKV_AZURE_3" and c["file_path"].endswith("azuredeploy.json") for c in failed)
    assert payload["metadata"]["changeset"] == 4217


@pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not on PATH")
def test_real_checkov_skips_a_path_with_spaces(tmp_path):
    # Split on its space, the path would become "My" and "Templates/legacy", and the second skips both folders.
    files = {"My Templates/legacy/azuredeploy.json": ARM, "Templates/legacy/azuredeploy.json": ARM}

    def scanned(payload):
        r = payload["results"]
        return {c["file_path"] for k in ("passed_checks", "failed_checks", "skipped_checks") for c in r[k]}

    (tmp_path / "all").mkdir()
    code, payload, status, _ = run(tmp_path / "all", files, real_checkov=True)
    assert code == 0, status
    assert scanned(payload) == {"/My Templates/legacy/azuredeploy.json", "/Templates/legacy/azuredeploy.json"}

    (tmp_path / "skip").mkdir()
    code, payload, status, _ = run(tmp_path / "skip", files, real_checkov=True, CHECKOV_SKIP_PATHS="My Templates/legacy")
    assert code == 0, status
    assert scanned(payload) == {"/Templates/legacy/azuredeploy.json"}
    assert payload["metadata"]["skip_paths"] == ["My Templates/legacy"]


@pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not on PATH")
@pytest.mark.parametrize("checks", ["CKV_AZURE_3, CKV_AZURE_44", "CKV_AZURE_3 CKV_AZURE_44"])
def test_real_checkov_runs_every_trimmed_check(tmp_path, checks):
    code, payload, status, _ = run(tmp_path, {"azuredeploy.json": ARM}, real_checkov=True, CHECKOV_BICEP_CHECKS=checks)
    assert code == 0, status
    r = payload["results"]
    ran = {c["check_id"] for k in ("passed_checks", "failed_checks", "skipped_checks") for c in r[k]}
    assert ran == {"CKV_AZURE_3", "CKV_AZURE_44"}


@pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not on PATH")
def test_real_checkov_skips_space_separated_check_ids(tmp_path):
    code, payload, status, _ = run(tmp_path, {"azuredeploy.json": ARM}, real_checkov=True,
                                   CHECKOV_SKIP_CHECKS="CKV_AZURE_3 CKV_AZURE_44")
    assert code == 0, status
    r = payload["results"]
    ran = {c["check_id"] for k in ("passed_checks", "failed_checks", "skipped_checks") for c in r[k]}
    assert ran and not ran & {"CKV_AZURE_3", "CKV_AZURE_44"}
    assert payload["metadata"]["skip_checks"] == ["CKV_AZURE_3", "CKV_AZURE_44"]
