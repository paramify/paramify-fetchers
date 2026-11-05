"""Run the checkov fetchers against stubbed ``git`` and ``checkov`` binaries.

No network, no real clone and no real checkov: a fake ``git`` copies a fixture
tree into the clone directory (refusing any branch not in ``FAKE_BRANCHES``) and
a fake ``checkov`` records its arguments and prints a canned JSON result.

What this proves: the evidence names the branch that was actually scanned (and
says when a fallback happened), the effective skip-check list is recorded and
can replace the shipped defaults, and the skip_resources filter moves failed
checks to skipped instead of deleting them. Requires bash and jq.

Run: ``pytest tests/test_checkov_fetchers.py``
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKOV = REPO_ROOT / "fetchers" / "checkov"
K8S_DEFAULTS = CHECKOV / "_shared" / "skip-checks-k8s.default.txt"

pytestmark = pytest.mark.skipif(
    not (shutil.which("bash") and shutil.which("jq")), reason="requires bash and jq"
)

FAKE_GIT = r"""#!/bin/bash
# clone: copy $FAKE_REPO into the destination; a --branch not listed in
# $FAKE_BRANCHES fails like a missing ref. rev-parse reads what clone checked out.
dir=""
if [ "$1" = "-C" ]; then dir="$2"; shift 2; fi
case "$1" in
  clone)
    shift; branch=""; pos=()
    while [ $# -gt 0 ]; do
      case "$1" in
        --depth) shift 2 ;;
        --branch) branch="$2"; shift 2 ;;
        *) pos+=("$1"); shift ;;
      esac
    done
    dest="${pos[1]}"
    if [ -n "$branch" ] && ! printf '%s\n' $FAKE_BRANCHES | grep -qx -- "$branch"; then
      echo "fatal: Remote branch $branch not found" >&2; exit 128
    fi
    mkdir -p "$dest" && cp -R "$FAKE_REPO"/. "$dest"/
    printf '%s\n' "${branch:-$FAKE_DEFAULT_BRANCH}" > "$dest/.fake_head"
    ;;
  rev-parse)
    if [ "$2" = "--abbrev-ref" ]; then cat "$dir/.fake_head"; else echo 0123456789abcdef0123456789abcdef01234567; fi
    ;;
  *) exit 1 ;;
esac
"""

FAKE_CHECKOV = r"""#!/bin/bash
printf '%s\n' "$@" > "$CHECKOV_ARGV_FILE"
cat "$CHECKOV_FIXTURE"
"""


def check(check_id: str, resource: str, result: str) -> Dict[str, Any]:
    return {"check_id": check_id, "resource": resource, "check_result": {"result": result}}


def checkov_result(framework: str, passed: List[Dict[str, Any]], failed: List[Dict[str, Any]],
                   skipped: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    skipped = skipped or []
    return {
        "check_type": framework,
        "results": {"passed_checks": passed, "failed_checks": failed, "skipped_checks": skipped},
        "summary": {"passed": len(passed), "failed": len(failed), "skipped": len(skipped),
                    "parsing_errors": 0, "resource_count": 3, "checkov_version": "3.2.0"},
    }


def default_k8s_skips() -> List[str]:
    out = []
    for line in K8S_DEFAULTS.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


@pytest.fixture
def harness(tmp_path: Path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("git", FAKE_GIT), ("checkov", FAKE_CHECKOV)):
        stub = bin_dir / name
        stub.write_text(body)
        stub.chmod(0o755)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "deploy.yaml").write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n")
    (repo / "main.tf").write_text('resource "aws_s3_bucket" "x" {}\n')
    evidence = tmp_path / "evidence"
    work = tmp_path / "work"   # cwd with no .env in it
    work.mkdir()

    def run(fetcher: str, result: Dict[str, Any], **env_overrides: str):
        fixture = tmp_path / "checkov.json"
        fixture.write_text(json.dumps(result))
        argv_file = tmp_path / "checkov.argv"
        env = {k: v for k, v in os.environ.items() if not k.startswith("CHECKOV_")}
        env.update(
            PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
            EVIDENCE_DIR=str(evidence),
            FETCHER_STATUS_FILE=str(tmp_path / "status.json"),
            FAKE_REPO=str(repo),
            FAKE_BRANCHES="main",
            FAKE_DEFAULT_BRANCH="main",
            CHECKOV_FIXTURE=str(fixture),
            CHECKOV_ARGV_FILE=str(argv_file),
            CHECKOV_REPO_URL="https://git.example.com/group/project.git",
        )
        env.pop("GIT_CLONE_TOKEN", None)
        env.update(env_overrides)
        for old in evidence.glob("*.json"):
            old.unlink()
        proc = subprocess.run(["bash", str(CHECKOV / fetcher / "fetcher.sh")], cwd=work, env=env,
                              text=True, capture_output=True, timeout=120)
        assert proc.returncode == 0, proc.stderr
        (out,) = list(evidence.glob("*.json"))
        argv = argv_file.read_text().splitlines() if argv_file.exists() else []
        return json.loads(out.read_text()), argv, proc.stderr

    return run


def arg_after(argv: List[str], flag: str) -> Optional[str]:
    return argv[argv.index(flag) + 1] if flag in argv else None


K8S_RESULT = checkov_result("kubernetes", [check("CKV_K8S_1", "Pod.default.x", "PASSED")],
                            [check("CKV_K8S_14", "Pod.default.x", "FAILED")])
TF_RESULT = checkov_result("terraform", [check("CKV_AWS_1", "aws_s3_bucket.x", "PASSED")], [])


# --- branch actually scanned ---------------------------------------------------

@pytest.mark.parametrize("fetcher,result", [("kubernetes", K8S_RESULT), ("terraform", TF_RESULT)])
def test_requested_branch_recorded_when_it_exists(harness, fetcher, result):
    payload, argv, _ = harness(fetcher, result, CHECKOV_CLONE_BRANCH="main")
    meta = payload["metadata"]
    assert meta["branch"] == "main"
    assert meta["requested_branch"] == "main"
    assert meta["branch_fallback"] is False
    assert arg_after(argv, "--branch") == "main"


@pytest.mark.parametrize("fetcher,result", [("kubernetes", K8S_RESULT), ("terraform", TF_RESULT)])
def test_fallback_records_the_branch_that_was_scanned(harness, fetcher, result):
    payload, argv, stderr = harness(fetcher, result, CHECKOV_CLONE_BRANCH="release-9",
                                    FAKE_DEFAULT_BRANCH="trunk")
    meta = payload["metadata"]
    assert meta["branch"] == "trunk"
    assert meta["requested_branch"] == "release-9"
    assert meta["branch_fallback"] is True
    assert arg_after(argv, "--branch") == "trunk"
    assert "release-9 could not be cloned" in stderr


# --- kubernetes skip-check list ------------------------------------------------

def test_k8s_default_skip_list_unchanged_and_recorded(harness):
    payload, argv, _ = harness("kubernetes", K8S_RESULT)
    defaults = default_k8s_skips()
    assert "CKV_K8S_20" in defaults and "CKV_K8S_31" in defaults
    assert arg_after(argv, "--skip-check").split(",") == defaults
    assert payload["metadata"]["skip_checks"] == defaults
    assert payload["metadata"]["default_skip_checks_applied"] is True


def test_k8s_config_extends_defaults_by_default(harness):
    payload, argv, _ = harness("kubernetes", K8S_RESULT, CHECKOV_SKIP_CHECKS="CKV_K8S_14, CKV_AWS_1")
    expected = default_k8s_skips() + ["CKV_K8S_14"]   # non-k8s ids are ignored
    assert arg_after(argv, "--skip-check").split(",") == expected
    assert payload["metadata"]["skip_checks"] == expected


def test_k8s_defaults_can_be_replaced(harness):
    payload, argv, _ = harness("kubernetes", K8S_RESULT, CHECKOV_USE_DEFAULT_SKIP_CHECKS="false",
                               CHECKOV_SKIP_CHECKS="CKV_K8S_8")
    assert arg_after(argv, "--skip-check") == "CKV_K8S_8"
    assert payload["metadata"]["skip_checks"] == ["CKV_K8S_8"]
    assert payload["metadata"]["default_skip_checks_applied"] is False


def test_k8s_defaults_can_be_dropped_entirely(harness):
    payload, argv, _ = harness("kubernetes", K8S_RESULT, CHECKOV_USE_DEFAULT_SKIP_CHECKS="false")
    assert "--skip-check" not in argv
    assert payload["metadata"]["skip_checks"] == []


def test_k8s_allowlisted_check_is_not_skipped(harness):
    payload, argv, _ = harness("kubernetes", K8S_RESULT, CHECKOV_K8S_CHECKS="CKV_K8S_20")
    assert "CKV_K8S_20" not in arg_after(argv, "--skip-check").split(",")
    assert "CKV_K8S_20" not in payload["metadata"]["skip_checks"]


def test_k8s_no_files_result_still_records_skip_list(harness, tmp_path):
    for f in (tmp_path / "repo").glob("*.yaml"):
        f.unlink()
    payload, _, _ = harness("kubernetes", K8S_RESULT)
    assert payload["status"] == "no_files"
    assert payload["metadata"]["skip_checks"] == default_k8s_skips()


def test_terraform_records_skip_list(harness):
    payload, argv, _ = harness("terraform", TF_RESULT, CHECKOV_SKIP_CHECKS="CKV_AWS_18")
    assert arg_after(argv, "--skip-check") == "CKV_AWS_18"
    assert payload["metadata"]["skip_checks"] == ["CKV_AWS_18"]
    assert payload["metadata"]["default_skip_checks_applied"] is True


# --- terraform skip_resources --------------------------------------------------

TF_WITH_FAILURES = checkov_result(
    "terraform",
    passed=[check("CKV_AWS_1", "aws_s3_bucket.app", "PASSED"),
            check("CKV_AWS_2", "aws_s3_bucket.app", "PASSED")],
    failed=[check("CKV_AWS_18", "aws_s3_bucket.gitlab_logs", "FAILED"),
            check("CKV_AWS_19", "aws_s3_bucket.app", "FAILED"),
            check("CKV_AWS_21", "aws_instance.web", "FAILED")],
    skipped=[check("CKV_AWS_144", "aws_s3_bucket.app", "SKIPPED")],
)


def test_skip_resources_moves_failures_to_skipped(harness):
    payload, _, _ = harness("terraform", TF_WITH_FAILURES, CHECKOV_SKIP_RESOURCES="aws_s3_bucket.gitlab_*")
    summary = payload["summary"]
    assert summary["passed_checks"] == 2
    assert summary["failed_checks"] == 2
    assert summary["skipped_checks"] == 2
    assert summary["total_checks"] == 6            # nothing left the denominator
    assert summary["aggregate_percentage"] == 33.33
    assert summary["skipped_by_resource_filter"] == 1

    failed = {c["resource"] for c in payload["results"]["failed_checks"]}
    assert failed == {"aws_s3_bucket.app", "aws_instance.web"}
    moved = [c for c in payload["results"]["skipped_checks"] if c["resource"] == "aws_s3_bucket.gitlab_logs"]
    assert len(moved) == 1
    assert moved[0]["check_id"] == "CKV_AWS_18"
    assert moved[0]["check_result"]["result"] == "SKIPPED"
    assert "aws_s3_bucket.gitlab_*" in moved[0]["check_result"]["suppress_comment"]
    assert "_skip_pattern" not in moved[0]
    assert payload["metadata"]["skip_resources"] == ["aws_s3_bucket.gitlab_*"]


def test_skip_resources_unset_leaves_results_alone(harness):
    payload, _, _ = harness("terraform", TF_WITH_FAILURES)
    summary = payload["summary"]
    assert (summary["passed_checks"], summary["failed_checks"], summary["skipped_checks"]) == (2, 3, 1)
    assert summary["total_checks"] == 6
    assert summary["aggregate_percentage"] == 33.33
    assert summary["skipped_by_resource_filter"] == 0
    assert payload["metadata"]["skip_resources"] == []


def test_skip_resources_empty_entry_does_not_match_everything(harness):
    payload, _, _ = harness("terraform", TF_WITH_FAILURES, CHECKOV_SKIP_RESOURCES="aws_instance.web,")
    assert payload["summary"]["failed_checks"] == 2
    assert payload["summary"]["skipped_by_resource_filter"] == 1
    assert payload["metadata"]["skip_resources"] == ["aws_instance.web"]


@pytest.mark.parametrize("names", [[], [""], ["", ""]])
def test_require_tools_without_names_checks_the_defaults(tmp_path, names):
    # Only date on PATH, so every default tool is reported missing by name.
    (tmp_path / "date").symlink_to(shutil.which("date"))
    proc = subprocess.run([shutil.which("bash"), "-c", '. "$1"; shift; checkov_require_tools x "$@"', "_",
                           str(CHECKOV / "_shared" / "clone.sh"), *names],
                          env={"PATH": str(tmp_path)}, capture_output=True, text=True)
    assert proc.returncode == 1
    missing = [line.rsplit(": ", 1)[1] for line in proc.stderr.splitlines()]
    assert missing == ["git", "checkov", "jq"]
