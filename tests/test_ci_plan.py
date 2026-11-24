"""tools/ci_plan.py decides which CI jobs a pull request runs.

A wrong answer in one direction costs minutes; in the other it lets a change
merge without the jobs that would have caught it. These tests pin the second
direction: anything that is not plainly fetcher work runs everything.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location("ci_plan", REPO_ROOT / "tools" / "ci_plan.py")
ci_plan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci_plan)

FULL = {"scope": "full", "azure": "true", "oci": "true", "release": "false"}

FETCHER_PR = [
    "fetchers/aws/iam_roles/fetcher.py",
    "fetchers/aws/iam_roles/README.md",
    "tests/test_aws_iam_roles.py",
    "docs/aws_fetchers.md",
    "CHANGELOG.md",
]


def test_a_push_runs_everything_whatever_changed():
    assert ci_plan.plan("push", FETCHER_PR) == FULL
    assert ci_plan.plan("push", None) == FULL


def test_an_unreadable_or_empty_diff_runs_everything():
    assert ci_plan.plan("pull_request", None) == FULL
    assert ci_plan.plan("pull_request", []) == FULL


def test_a_fetcher_pull_request_gets_the_fetchers_scope_without_the_sdk_jobs():
    assert ci_plan.plan("pull_request", FETCHER_PR) == {"scope": "fetchers", "azure": "false", "oci": "false", "release": "false"}


@pytest.mark.parametrize("path", [
    "framework/cli.py",
    "framework/tui/app.py",
    "framework/schemas/fetcher.schema.json",
    "pyproject.toml",
    "requirements.txt",
    ".github/workflows/ci.yml",
    ".github/dependabot.yml",
    "tools/ci_plan.py",
    "tools/cli_goldens.py",
    "deploy/Dockerfile",
    "uploaders/paramify_evidence/upload.py",
    "run_and_upload.sh",
    ".gitleaks.toml",
    "tests/conftest.py",
    "tests/test_tui_keys.py",
    "tests/__snapshots__/test_tui_snapshots/test_welcome.svg",
    "tests/test_manifest_autosave.py",
    "tests/test_target_editor.py",
    "a_new_top_level_file.py",
    "a_new_directory/anything.py",
])
def test_one_file_outside_the_fetcher_scope_runs_everything(path):
    assert ci_plan.plan("pull_request", FETCHER_PR + [path]) == FULL


@pytest.mark.parametrize("path", [
    "fetchers/azure/alert_rules/fetcher.py",
    "tests/test_azure_alert_rules.py",
    "tests/test_entra_graph_source_boundary.py",
    "fetchers/azure/sentinel_incidents/fetcher.py",
    "comparators/azure/alert_rules.py",
    "docs/azure_fetchers.md",
])
def test_azure_paths_run_the_azure_job_only(path):
    assert ci_plan.plan("pull_request", [path]) == {"scope": "fetchers", "azure": "true", "oci": "false", "release": "false"}


@pytest.mark.parametrize("path", [
    "fetchers/oci/compute_instances/fetcher.py",
    "fetchers/oci/tests/cassettes/compute_instances.json",
    "tests/test_oci_compute.py",
    "docs/oci_fetchers.md",
])
def test_oci_paths_run_the_oci_job_only(path):
    assert ci_plan.plan("pull_request", [path]) == {"scope": "fetchers", "azure": "false", "oci": "true", "release": "false"}


@pytest.mark.parametrize("path", [
    "fetchers/aws/association_report/fetcher.py",
    "tests/test_aws_policies.py",
    "docs/crowdstrike_social.md",
])
def test_oci_is_matched_as_a_word_not_a_substring(path):
    assert ci_plan.plan("pull_request", [path])["oci"] == "false"


@pytest.mark.parametrize("path", ["fetchers/_lib/discovery.py", "fetchers/_categories/aws.yaml"])
def test_shared_fetcher_code_runs_both_sdk_jobs(path):
    assert ci_plan.plan("pull_request", [path]) == {"scope": "fetchers", "azure": "true", "oci": "true", "release": "false"}


def test_every_file_the_tui_job_runs_is_outside_the_fetcher_scope():
    """The tui job is the only one that runs these, and the fetchers scope drops a textual row."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
    named = set(re.findall(r"tests/test_[\w*]+\.py", workflow.split("\n  tui:\n")[1].split("\n  secrets:\n")[0]))
    assert "tests/test_tui_*.py" in named
    for pattern in named:
        for path in REPO_ROOT.glob(pattern):
            rel = path.relative_to(REPO_ROOT).as_posix()
            assert ci_plan.needs_full(rel), f"{rel} is run by the tui job but would get the fetchers scope"


def test_every_sdk_test_file_turns_its_job_on():
    """A change to a test the azure-sdk or oci job runs must run that job."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text()
    azure_job = workflow.split("\n  azure-sdk:\n")[1].split("\n  oci-sdk:\n")[0]
    for rel in re.findall(r"tests/test_\w+\.py", azure_job):
        assert ci_plan.plan("pull_request", [rel])["azure"] == "true", rel
    for path in REPO_ROOT.glob("tests/test_oci_*.py"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        assert ci_plan.plan("pull_request", [rel])["oci"] == "true", rel


def test_release_branch_turns_on_release_check():
    assert ci_plan.plan("pull_request", FETCHER_PR, "release/next")["release"] == "true"
    # The release PR changes CHANGELOG and pyproject, so it also runs everything.
    assert ci_plan.plan("pull_request", ["pyproject.toml"], "release/next") == {**FULL, "release": "true"}


@pytest.mark.parametrize("head_ref", ["", "feat/x", "release/next-2", "my-release/next"])
def test_other_branches_skip_release_check(head_ref):
    assert ci_plan.plan("pull_request", FETCHER_PR, head_ref)["release"] == "false"
    assert ci_plan.plan("push", None, head_ref)["release"] == "false"
