"""Exercise the real collectors with a synthetic AWS CLI, including page failures.

No AWS credentials or Paramify token are used. Response fixtures assert the
account/resource filters and explicit continuation tokens actually sent.
"""

from __future__ import annotations

import csv
import errno
import importlib.util
import io
import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / "fetchers/aws/_shared/inspector_ecr.py"
spec = importlib.util.spec_from_file_location("inspector_ecr_test_module", SHARED)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

ACCOUNT = "111122223333"
REGION = "us-gov-west-1"
REPO = f"arn:aws-us-gov:ecr:{REGION}:{ACCOUNT}:repository/example"
DIGEST = "sha256:" + "a" * 64


def finding(index=1, severity="HIGH"):
    return {
        "findingArn": f"arn:aws-us-gov:inspector2:{REGION}:{ACCOUNT}:finding/{index}",
        "awsAccountId": ACCOUNT,
        "severity": severity,
        "status": "ACTIVE",
        "title": 'CVE-2026-10001 - package, "example"',
        "description": "line one\nline two",
        "firstObservedAt": "2026-10-01T00:00:00Z",
        "lastObservedAt": "2026-11-01T00:00:00Z",
        "packageVulnerabilityDetails": {
            "vulnerabilityId": "CVE-2026-10001",
            "vulnerablePackages": [{"name": "example", "version": "1.0", "fixedInVersion": "1.1"}],
            "relatedVulnerabilities": ["GHSA-example"],
            "cvss": [{"baseScore": 8.1, "source": "NVD", "version": "3.1"}],
        },
        "resources": [
            {
                "type": "AWS_ECR_CONTAINER_IMAGE",
                "region": REGION,
                "id": DIGEST,
                "details": {
                    "awsEcrContainerImage": {
                        "repositoryName": "example",
                        "imageHash": DIGEST,
                        "imageTags": ["deployed", "latest"],
                    }
                },
            }
        ],
    }


def responses():
    return {
        "sts get-caller-identity": {
            "Account": ACCOUNT,
            "Arn": f"arn:aws-us-gov:iam::{ACCOUNT}:role/test",
        },
        "inspector2 batch-get-account-status": {
            "accounts": [{"accountId": ACCOUNT, "resourceState": {"ecr": {"status": "ENABLED"}}}],
            "failedAccounts": [],
        },
        "ecr describe-repositories": {
            "repositories": [
                {
                    "repositoryName": "example",
                    "repositoryArn": REPO,
                    "registryId": ACCOUNT,
                    "imageScanningConfiguration": {"scanOnPush": False},
                }
            ]
        },
        "ecr describe-images": {
            "imageDetails": [{"imageDigest": DIGEST, "imageTags": ["deployed", "latest"]}]
        },
        "inspector2 list-coverage": {
            "coveredResources": [
                {
                    "accountId": ACCOUNT,
                    "resourceType": "AWS_ECR_CONTAINER_IMAGE",
                    "resourceId": REPO + "/" + DIGEST,
                    "scanType": "PACKAGE",
                    "scanStatus": {"statusCode": "ACTIVE"},
                    "lastScannedAt": "2026-11-01T00:00:00Z",
                }
            ]
        },
        "inspector2 list-findings": {"findings": [finding()]},
    }


FAKE_AWS = r"""import json, os, sys
args = sys.argv[1:]
params = json.loads(args[args.index('--cli-input-json')+1]) if '--cli-input-json' in args else {}
with open(os.environ['FAKE_LOG'], 'a') as log:
    log.write(json.dumps({'args': args, 'params': params})+'\n')
key = ' '.join(args[:2])
if params.get('nextToken'): key += ':'+params['nextToken']
response = json.load(open(os.environ['FAKE_RESPONSES']))[key]
if isinstance(response, dict) and '_by_repository' in response:
    repo = params.get('repositoryName') or args[args.index('--repository-name')+1]
    response = response['_by_repository'][repo]
if isinstance(response, dict) and '_configs' in response:
    response = {'scanningConfigurations': [response['_configs'][name] for name in reversed(params['repositoryNames'])]}
if isinstance(response, dict) and '_error' in response:
    print(response['_error'], file=sys.stderr)
    sys.exit(254)
print(json.dumps(response))
"""


def run_fetcher(tmp_path, data=None, name="inspector_ecr_report", **settings):
    tmp_path.mkdir(parents=True, exist_ok=True)
    binary = tmp_path / "aws"
    binary.write_text(f"#!{sys.executable}\n" + FAKE_AWS)
    binary.chmod(0o755)
    source = tmp_path / "responses.json"
    source.write_text(json.dumps(data if data is not None else responses()))
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("AWS_", "PARAMIFY_", "EVIDENCE_", "FETCHER_"))
    }
    env.update(
        PATH=f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
        FAKE_RESPONSES=str(source),
        FAKE_LOG=str(tmp_path / "calls.jsonl"),
        EVIDENCE_DIR=str(tmp_path / "output"),
        FETCHER_STATUS_FILE=str(tmp_path / "status.json"),
        AWS_DEFAULT_REGION=REGION,
    )
    env.update(settings)
    shell = name == "ecr_image_scanning"
    entry = ROOT / "fetchers/aws" / name / ("fetcher.sh" if shell else "fetcher.py")
    result = subprocess.run(
        ["bash" if shell else sys.executable, str(entry)],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
    )
    files = list((tmp_path / "output").glob("*"))
    calls = (
        [json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()]
        if (tmp_path / "calls.jsonl").exists()
        else []
    )
    return result, files, calls


def test_all_pages_and_severities_keep_distinct_findings(tmp_path):
    data = responses()
    data["inspector2 list-findings"] = {"findings": [finding()], "nextToken": "second"}
    data["inspector2 list-findings:second"] = {
        "findings": [finding(), finding(2, "LOW"), finding(3, "UNTRIAGED")]
    }
    data["ecr describe-repositories"]["nextToken"] = "repos"
    data["ecr describe-repositories:repos"] = {"repositories": []}
    data["ecr describe-images"]["nextToken"] = "images"
    data["ecr describe-images:images"] = {"imageDetails": []}
    data["inspector2 list-coverage"]["nextToken"] = "coverage"
    data["inspector2 list-coverage:coverage"] = {"coveredResources": []}
    result, files, calls = run_fetcher(tmp_path, data, AWS_INSPECTOR_IMAGE_TAGS='["deployed"]')
    assert result.returncode == 0, result.stderr
    assert len(files) == 1
    rows = list(csv.DictReader(io.StringIO(files[0].read_text())))
    assert len(rows) == 3
    assert {r["Severity"] for r in rows} == {"HIGH", "LOW", "UNTRIAGED"}
    assert rows[0]["Title"] == finding()["title"]
    assert rows[0]["Description"] == finding()["description"]
    assert json.loads(rows[0]["Affected Packages"])[0]["fixedInVersion"] == "1.1"
    assert len({r["ID"] for r in rows}) == 3
    assert rows[0]["Asset ID"] == f"{ACCOUNT}/{REGION}/example@{DIGEST}"
    lists = [c for c in calls if c["args"][:2] == ["inspector2", "list-findings"]]
    assert len(lists) == 2
    assert lists[1]["params"]["nextToken"] == "second"
    assert lists[0]["params"]["filterCriteria"] == {
        "awsAccountId": [{"comparison": "EQUALS", "value": ACCOUNT}],
        "resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}],
        "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
        "ecrImageTags": [{"comparison": "EQUALS", "value": "deployed"}],
    }
    assert all("--no-paginate" in c["args"] for c in calls)


@pytest.mark.parametrize(
    "case",
    [
        "late_error",
        "loop",
        "missing_findings",
        "other_account",
        "missing_digest",
        "changed_duplicate",
        "failed_account",
    ],
)
def test_incomplete_collection_never_writes_report(tmp_path, case):
    data = responses()
    if case in ("late_error", "loop", "changed_duplicate"):
        data["inspector2 list-findings"]["nextToken"] = "second"
        data["inspector2 list-findings:second"] = {
            "late_error": {
                "_error": "An error occurred (AccessDeniedException) when calling ListFindings"
            },
            "loop": {"findings": [], "nextToken": "second"},
            "changed_duplicate": {"findings": [finding(severity="LOW")]},
        }[case]
    elif case == "missing_findings":
        data["inspector2 list-findings"] = {}
    elif case == "other_account":
        data["inspector2 list-findings"]["findings"][0]["awsAccountId"] = "999999999999"
    elif case == "missing_digest":
        del data["inspector2 list-findings"]["findings"][0]["resources"][0]["details"][
            "awsEcrContainerImage"
        ]["imageHash"]
    elif case == "failed_account":
        data["inspector2 batch-get-account-status"]["failedAccounts"] = [
            {"accountId": ACCOUNT, "errorCode": "ACCESS_DENIED"}
        ]
    result, files, _ = run_fetcher(tmp_path, data)
    assert result.returncode == 1
    assert not files
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["code"] == ("not_authorized" if case == "late_error" else "partial_failure")
    result, files, _ = run_fetcher(tmp_path / "evidence", data, "inspector_ecr_findings")
    assert result.returncode == 1
    assert len(files) == 1
    evidence = json.loads(files[0].read_text())
    assert evidence["metadata"]["partial_failure"] is True
    assert evidence["metadata"]["api_failures"]
    assert evidence["results"]["collection_complete"] is False
    assert evidence["results"]["summary"]["finding_count"] is None
    if case in ("late_error", "loop", "changed_duplicate"):
        assert evidence["results"]["findings"] == [finding()]


@pytest.mark.parametrize(
    "operation",
    [
        "ecr describe-repositories",
        "ecr describe-images",
        "inspector2 list-coverage",
        "inspector2 list-findings",
    ],
)
def test_evidence_preserves_earlier_pages_and_independent_reads(tmp_path, operation):
    data = responses()
    data[operation]["nextToken"] = "denied"
    data[operation + ":denied"] = {"_error": "AccessDeniedException: synthetic denial"}
    result, files, _ = run_fetcher(tmp_path, data, "inspector_ecr_findings")
    assert result.returncode == 1
    assert len(files) == 1
    evidence = json.loads(files[0].read_text())
    assert evidence["metadata"]["partial_failure"] is True
    failures = evidence["metadata"]["api_failures"]
    assert len(failures) == 1
    assert failures[0]["operation"] == operation
    assert failures[0]["type"] == "CollectionError"
    assert "synthetic denial" in failures[0]["message"]
    assert failures[0]["code"] == "not_authorized"
    results = evidence["results"]
    assert results["collection_complete"] is False
    assert results["findings_collection_status"] == "incomplete"
    assert all(value is None for value in results["summary"].values())
    assert results["findings"] == [finding()]
    assert len(results["coverage"]) == len(results["images"]) == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"
    # The same partial evidence cannot become an issue report, even with opt-in.
    with pytest.raises(collector.CollectionError, match="incomplete"):
        collector.write_output(evidence, True, tmp_path / "report", allow_empty=True)
    assert not (tmp_path / "report").exists()


def test_evidence_records_multiple_failures_and_continues_other_repositories(tmp_path):
    data = responses()
    data["ecr describe-repositories"]["repositories"].insert(
        0,
        {
            "repositoryName": "denied",
            "repositoryArn": REPO + "-denied",
            "registryId": ACCOUNT,
        },
    )
    data["ecr describe-images"] = {
        "_by_repository": {
            "denied": {"_error": "AccessDeniedException"},
            "example": data["ecr describe-images"],
        }
    }
    data["inspector2 list-coverage"]["nextToken"] = "throttled"
    data["inspector2 list-coverage:throttled"] = {"_error": "ThrottlingException"}
    result, files, calls = run_fetcher(tmp_path, data, "inspector_ecr_findings")
    assert result.returncode == 1
    evidence = json.loads(files[0].read_text())
    failures = evidence["metadata"]["api_failures"]
    assert [f["operation"] for f in failures] == ["ecr describe-images", "inspector2 list-coverage"]
    assert failures[0]["repository"] == "denied"
    assert len(evidence["results"]["images"]) == 1
    assert evidence["results"]["findings"] == [finding()]
    assert calls[-1]["args"][:2] == ["inspector2", "list-findings"]
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "partial_failure"


@pytest.mark.parametrize(
    "operation", ["sts get-caller-identity", "inspector2 batch-get-account-status"]
)
def test_evidence_handles_identity_and_status_failures_without_false_disabled_state(
    tmp_path, operation
):
    data = responses()
    data[operation] = {"_error": "AccessDeniedException"}
    result, files, calls = run_fetcher(tmp_path, data, "inspector_ecr_findings")
    assert result.returncode == 1
    evidence = json.loads(files[0].read_text())
    assert evidence["results"]["scan_status"] is None
    assert evidence["results"]["findings_collection_status"] == "incomplete"
    assert evidence["results"]["summary"]["finding_count"] is None
    assert evidence["metadata"]["api_failures"][0]["operation"] == operation
    if operation.startswith("sts"):
        assert len(calls) == 1
        assert evidence["metadata"]["account_id"] is None
        assert evidence["results"]["findings"] == []
    else:
        assert evidence["results"]["findings"] == [finding()]


@pytest.mark.parametrize("kind", ["findings", "coverage"])
def test_partial_evidence_does_not_include_out_of_scope_records(tmp_path, kind):
    data = responses()
    if kind == "findings":
        invalid = finding(2)
        invalid["awsAccountId"] = "999999999999"
        data["inspector2 list-findings"]["findings"].append(invalid)
    else:
        data["inspector2 list-coverage"]["coveredResources"].append({"accountId": "999999999999"})
    result, files, _ = run_fetcher(tmp_path, data, "inspector_ecr_findings")
    assert result.returncode == 1
    evidence = json.loads(files[0].read_text())
    assert len(evidence["results"]["coverage"]) == 1
    assert evidence["results"]["findings"] == [finding()]
    assert evidence["metadata"]["partial_failure"] is True


@pytest.mark.parametrize("kind", ["image", "coverage", "vulnerability"])
def test_malformed_record_cannot_discard_earlier_valid_evidence(tmp_path, kind):
    data = responses()
    if kind == "image":
        data["ecr describe-images"]["imageDetails"].append({"imageDigest": ["not-a-string"]})
    elif kind == "coverage":
        invalid = dict(data["inspector2 list-coverage"]["coveredResources"][0], scanStatus=None)
        data["inspector2 list-coverage"]["coveredResources"].append(invalid)
    else:
        invalid = finding(2)
        invalid["packageVulnerabilityDetails"]["vulnerabilityId"] = {"invalid": "object"}
        data["inspector2 list-findings"]["findings"].append(invalid)
    result, files, _ = run_fetcher(tmp_path, data, "inspector_ecr_findings")
    assert result.returncode == 1
    evidence = json.loads(files[0].read_text())
    assert evidence["metadata"]["partial_failure"] is True
    assert len(evidence["results"]["images"]) == 1
    assert len(evidence["results"]["coverage"]) == 1
    assert evidence["results"]["findings"] == [finding()]


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t=", "\r\n+", "  @"])
def test_csv_formula_protection_preserves_raw_evidence_and_record_identity(tmp_path, prefix):
    data = responses()
    advisory = data["inspector2 list-findings"]["findings"][0]
    value = prefix + 'SUM(1,2)\n"quoted"'
    advisory.update(title=value, description=value, remediation={"recommendation": {"text": value}})
    result, files, _ = run_fetcher(tmp_path / "report", data)
    assert result.returncode == 0, result.stderr
    with files[0].open(newline="") as stream:
        row = next(csv.DictReader(stream))
    for column in ("Title", "Description", "Remediation"):
        assert row[column] == "'" + value
    assert row["ID"] == f"{advisory['findingArn']}|{ACCOUNT}/{REGION}/example@{DIGEST}"
    result, files, _ = run_fetcher(tmp_path / "evidence", data, "inspector_ecr_findings")
    assert result.returncode == 0, result.stderr
    assert json.loads(files[0].read_text())["results"]["findings"] == [advisory]


@pytest.mark.parametrize("report", [False, True])
def test_killed_writer_never_leaves_an_artifact_in_output_directory(tmp_path, report):
    result, files, _ = run_fetcher(tmp_path / "setup", name="inspector_ecr_findings")
    assert result.returncode == 0, result.stderr
    output = tmp_path / "output"
    script = """
import importlib.util, json, os, signal, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("collector", sys.argv[1])
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
evidence = json.loads(Path(sys.argv[2]).read_text())
def die(*args, **kwargs):
    os.kill(os.getpid(), signal.SIGKILL)
collector.json.dump = die
collector.csv.DictWriter.writerows = die
collector.write_output(evidence, sys.argv[4] == "True", Path(sys.argv[3]))
"""
    killed = subprocess.run(
        [sys.executable, "-c", script, str(SHARED), str(files[0]), str(output), str(report)]
    )
    assert killed.returncode == -signal.SIGKILL
    assert list(output.iterdir()) == []
    # The abrupt kill really left a staging file, outside the runner's directory.
    assert len(list(tmp_path.glob(".inspector-*.tmp"))) == 1


def test_cross_filesystem_publication_fails_without_copying_partial_report(tmp_path, monkeypatch):
    result, files, _ = run_fetcher(tmp_path / "setup", name="inspector_ecr_findings")
    assert result.returncode == 0, result.stderr
    evidence = json.loads(files[0].read_text())
    output = tmp_path / "output"

    def cross_device(*args):
        raise OSError(errno.EXDEV, "Cross-device link")

    monkeypatch.setattr(Path, "replace", cross_device)
    with pytest.raises(collector.CollectionError, match="same filesystem"):
        collector.write_output(evidence, True, output)
    assert list(output.iterdir()) == []
    assert not list(tmp_path.glob(".inspector-*.tmp"))


@pytest.mark.parametrize(
    "case", ["missing", "inactive", "never_scanned", "disabled", "empty_inventory"]
)
def test_evidence_exposes_coverage_gaps_but_report_refuses_them(tmp_path, case):
    data = responses()
    if case == "missing":
        data["inspector2 list-coverage"]["coveredResources"] = []
    elif case == "inactive":
        data["inspector2 list-coverage"]["coveredResources"][0]["scanStatus"]["statusCode"] = (
            "INACTIVE"
        )
    elif case == "never_scanned":
        del data["inspector2 list-coverage"]["coveredResources"][0]["lastScannedAt"]
    elif case == "disabled":
        data["inspector2 batch-get-account-status"]["accounts"][0]["resourceState"]["ecr"][
            "status"
        ] = "DISABLED"
    else:
        data["ecr describe-images"]["imageDetails"] = []
    result, files, _ = run_fetcher(tmp_path / "evidence", data, "inspector_ecr_findings")
    assert result.returncode == 0, result.stderr
    evidence = json.loads(files[0].read_text())["results"]
    assert evidence["summary"]["coverage_gap_count"] == (0 if case == "empty_inventory" else 1)
    if case == "disabled":
        assert evidence["summary"]["finding_count"] is None
    result, files, _ = run_fetcher(tmp_path / "report", data, AWS_INSPECTOR_ALLOW_EMPTY="true")
    assert result.returncode == 1
    assert not files


def test_zero_findings_requires_explicit_opt_in(tmp_path):
    data = responses()
    data["inspector2 list-findings"] = {"findings": []}
    result, files, _ = run_fetcher(tmp_path / "default", data)
    assert result.returncode == 1 and not files
    result, files, _ = run_fetcher(tmp_path / "opt_in", data, AWS_INSPECTOR_ALLOW_EMPTY="true")
    assert result.returncode == 0, result.stderr
    assert list(csv.DictReader(io.StringIO(files[0].read_text()))) == []


def test_repositories_and_tags_are_explicit_not_internal_defaults(tmp_path):
    result, files, calls = run_fetcher(tmp_path / "all")
    assert result.returncode == 0, result.stderr
    filters = next(
        c["params"]["filterCriteria"]
        for c in calls
        if c["args"][:2] == ["inspector2", "list-findings"]
    )
    assert "ecrImageTags" not in filters and "ecrImageRepositoryName" not in filters
    result, files, _ = run_fetcher(
        tmp_path / "typo", AWS_INSPECTOR_REPOSITORIES='["does-not-exist"]'
    )
    assert result.returncode == 1 and not files


@pytest.mark.parametrize("value", ['"latest"', "[1]", '[""]', "not json"])
def test_bad_filters_fail_before_aws(tmp_path, value):
    result, files, calls = run_fetcher(tmp_path, AWS_INSPECTOR_IMAGE_TAGS=value)
    assert result.returncode == 1 and not files and not calls


def test_filenames_distinguish_scope_and_profile(tmp_path):
    _, a, _ = run_fetcher(tmp_path / "one", AWS_INSPECTOR_IMAGE_TAGS='["latest"]')
    _, b, _ = run_fetcher(tmp_path / "two", AWS_INSPECTOR_IMAGE_TAGS='["deployed"]')
    _, c, _ = run_fetcher(tmp_path / "three", AWS_PROFILE="another")
    assert len({a[0].name, b[0].name, c[0].name}) == 3


def test_commercial_partition_and_target_region_override_ambient_region(tmp_path):
    data = json.loads(
        json.dumps(responses()).replace("aws-us-gov", "aws").replace(REGION, "us-east-1")
    )
    result, files, calls = run_fetcher(
        tmp_path, data, AWS_DEFAULT_REGION="us-east-1", AWS_REGION="us-west-2"
    )
    assert result.returncode == 0, result.stderr
    rows = list(csv.DictReader(io.StringIO(files[0].read_text())))
    assert rows[0]["Asset ID"].startswith(f"{ACCOUNT}/us-east-1/")
    assert all(c["args"][c["args"].index("--region") + 1] == "us-east-1" for c in calls)


def test_finding_for_image_missing_from_inventory_is_not_an_importable_snapshot(tmp_path):
    data = responses()
    data["inspector2 list-findings"]["findings"][0]["resources"][0]["details"][
        "awsEcrContainerImage"
    ]["imageHash"] = "sha256:" + "b" * 64
    result, files, _ = run_fetcher(tmp_path / "report", data)
    assert result.returncode == 1 and not files
    result, files, _ = run_fetcher(tmp_path / "evidence", data, "inspector_ecr_findings")
    assert result.returncode == 0, result.stderr
    assert json.loads(files[0].read_text())["results"]["findings_missing_from_inventory"] == [
        finding()["findingArn"]
    ]


def test_same_vulnerability_on_two_images_retains_distinct_resources_and_raw_fields(tmp_path):
    data = responses()
    digest = "sha256:" + "b" * 64
    data["ecr describe-images"]["imageDetails"].append({"imageDigest": digest})
    other_coverage = dict(
        data["inspector2 list-coverage"]["coveredResources"][0], resourceId=REPO + "/" + digest
    )
    data["inspector2 list-coverage"]["coveredResources"].append(other_coverage)
    other = finding(2, "INFORMATIONAL")
    other["resources"][0]["details"]["awsEcrContainerImage"] = {
        "repositoryName": "example",
        "imageHash": digest,
    }
    data["inspector2 list-findings"]["findings"].append(other)
    result, files, _ = run_fetcher(tmp_path / "report", data)
    assert result.returncode == 0, result.stderr
    rows = list(csv.DictReader(io.StringIO(files[0].read_text())))
    assert len({row["Asset ID"] for row in rows}) == 2
    assert len({row["ID"] for row in rows}) == 2
    assert {row["Vulnerability ID"] for row in rows} == {"CVE-2026-10001"}
    result, files, _ = run_fetcher(tmp_path / "evidence", data, "inspector_ecr_findings")
    evidence = json.loads(files[0].read_text())["results"]
    assert result.returncode == 0
    assert evidence["findings"] == data["inspector2 list-findings"]["findings"]
    assert evidence["summary"]["findings_by_repository"] == {"example": 2}
    assert evidence["summary"]["findings_by_vulnerability"] == {"CVE-2026-10001": 2}


@pytest.mark.skipif(not shutil.which("jq"), reason="requires jq")
def test_scan_configuration_failure_is_not_basic_scanning(tmp_path):
    data = responses()
    data["ecr get-registry-scanning-configuration"] = {"_error": "AccessDeniedException"}
    data["ecr batch-get-repository-scanning-configuration"] = {
        "failures": [{"repositoryName": "example", "failureCode": "REPOSITORY_NOT_FOUND"}]
    }
    data["ecr describe-images"] = None
    result, files, _ = run_fetcher(tmp_path, data, "ecr_image_scanning")
    assert result.returncode == 1
    evidence = json.loads(files[0].read_text())["results"]
    assert evidence["registry_scanning"]["scan_type"] is None
    assert evidence["repositories"][0]["scan_frequency"] is None


@pytest.mark.skipif(not shutil.which("jq"), reason="requires jq")
def test_ecr_config_batches_join_the_correct_repository_once(tmp_path):
    data = responses()
    data["ecr get-registry-scanning-configuration"] = {
        "scanningConfiguration": {"scanType": "ENHANCED", "rules": []}
    }
    configs = {}
    repositories = []
    for index in range(27):
        name = f"repository-{index}"
        repositories.append(
            {"repositoryName": name, "repositoryArn": REPO + name, "registryId": ACCOUNT}
        )
        configs[name] = {
            "repositoryName": name,
            "scanFrequency": "CONTINUOUS_SCAN" if index % 2 else "SCAN_ON_PUSH",
            "appliedScanFilters": [{"filter": name, "filterType": "WILDCARD"}],
        }
    data["ecr describe-repositories"] = {"repositories": repositories}
    data["ecr batch-get-repository-scanning-configuration"] = {"_configs": configs}
    data["ecr describe-images"] = None
    result, files, calls = run_fetcher(tmp_path, data, "ecr_image_scanning")
    assert result.returncode == 0, result.stderr
    collected = json.loads(files[0].read_text())["results"]["repositories"]
    assert len(collected) == 27
    for repo in collected:
        assert repo["scan_frequency"] == configs[repo["name"]]["scanFrequency"]
        assert repo["applied_scan_filters"] == configs[repo["name"]]["appliedScanFilters"]
    batches = [
        c["params"]["repositoryNames"]
        for c in calls
        if c["args"][:2] == ["ecr", "batch-get-repository-scanning-configuration"]
    ]
    assert [len(batch) for batch in batches] == [25, 2]
    assert [name for batch in batches for name in batch] == [
        repo["repositoryName"] for repo in repositories
    ]


@pytest.mark.skipif(not shutil.which("jq"), reason="requires jq")
def test_ecr_partial_batch_preserves_successful_config_and_failure_reason(tmp_path):
    data = responses()
    data["ecr get-registry-scanning-configuration"] = {
        "scanningConfiguration": {"scanType": "ENHANCED", "rules": []}
    }
    data["ecr describe-repositories"]["repositories"].append(
        {
            "repositoryName": "gone",
            "repositoryArn": REPO + "-gone",
            "registryId": ACCOUNT,
        }
    )
    data["ecr batch-get-repository-scanning-configuration"] = {
        "scanningConfigurations": [
            {"repositoryName": "example", "scanFrequency": "CONTINUOUS_SCAN"}
        ],
        "failures": [
            {
                "repositoryName": "gone",
                "failureCode": "REPOSITORY_NOT_FOUND",
                "failureReason": "deleted",
            }
        ],
    }
    data["ecr describe-images"] = None
    result, files, _ = run_fetcher(tmp_path, data, "ecr_image_scanning")
    assert result.returncode == 1
    repos = json.loads(files[0].read_text())["results"]["repositories"]
    assert repos[0]["scan_frequency"] == "CONTINUOUS_SCAN"
    assert repos[1]["scan_frequency"] is None
    error = json.loads((tmp_path / "status.json").read_text())["error"]
    assert "REPOSITORY_NOT_FOUND" in error and "gone" in error and "deleted" in error


@pytest.mark.skipif(not shutil.which("jq"), reason="requires jq")
def test_ecr_batch_error_identifies_request_and_aws_reason(tmp_path):
    data = responses()
    data["ecr get-registry-scanning-configuration"] = {
        "scanningConfiguration": {"scanType": "ENHANCED", "rules": []}
    }
    data["ecr batch-get-repository-scanning-configuration"] = {
        "_error": "AccessDeniedException: missing ecr:BatchGetRepositoryScanningConfiguration"
    }
    data["ecr describe-images"] = None
    result, _, _ = run_fetcher(tmp_path, data, "ecr_image_scanning")
    assert result.returncode == 1
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["code"] == "not_authorized"
    assert "example" in status["error"]
    assert "missing ecr:BatchGetRepositoryScanningConfiguration" in status["error"]


@pytest.mark.skipif(not shutil.which("jq"), reason="requires jq")
@pytest.mark.parametrize(
    "scan_type,frequency",
    [("ENHANCED", "CONTINUOUS_SCAN"), ("BASIC", "MANUAL"), ("BASIC", "SCAN_ON_PUSH")],
)
def test_ecr_scan_results_do_not_depend_on_scan_on_push(tmp_path, scan_type, frequency):
    data = responses()
    data["ecr get-registry-scanning-configuration"] = {
        "scanningConfiguration": {"scanType": scan_type, "rules": []}
    }
    data["ecr batch-get-repository-scanning-configuration"] = {
        "scanningConfigurations": [{"repositoryName": "example", "scanFrequency": frequency}]
    }
    # The shell requests a global newest-image query with JSON output.
    data["ecr describe-images"] = DIGEST
    data["ecr describe-image-scan-findings"] = {
        "imageId": {"imageDigest": DIGEST},
        "imageScanStatus": {"status": "ACTIVE"},
        "imageScanFindings": {"findingSeverityCounts": {"HIGH": 4, "LOW": 2, "UNTRIAGED": 1}},
    }
    result, files, calls = run_fetcher(tmp_path, data, "ecr_image_scanning")
    assert result.returncode == 0, result.stderr
    repo = json.loads(files[0].read_text())["results"]["repositories"][0]
    assert repo["scan_on_push"] is False
    assert repo["scan_frequency"] == frequency
    assert repo["latest_image_scan"]["severity_counts"] == {
        "critical": 0,
        "high": 4,
        "medium": 0,
        "low": 2,
        "informational": 0,
        "untriaged": 1,
    }
    args = next(c["args"] for c in calls if c["args"][:2] == ["ecr", "describe-images"])
    assert args[args.index("--output") + 1] == "json"


@pytest.mark.skipif(not shutil.which("jq"), reason="requires jq")
def test_enhanced_scan_counts_every_finding_not_the_page_summary(tmp_path):
    # With enhanced (Inspector) scanning, ECR's findingSeverityCounts covers only
    # the findings on the returned page (verified live, 2026-11-10: a page of 1
    # reported {"MEDIUM": 1} for an image with 456 CRITICAL and 3,589 HIGH).
    # The fetcher must read every page and count the findings themselves.
    data = responses()
    data["ecr get-registry-scanning-configuration"] = {
        "scanningConfiguration": {"scanType": "ENHANCED", "rules": []}
    }
    data["ecr batch-get-repository-scanning-configuration"] = {
        "scanningConfigurations": [{"repositoryName": "example", "scanFrequency": "CONTINUOUS_SCAN"}]
    }
    data["ecr describe-images"] = DIGEST
    severities = ["CRITICAL", "HIGH", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNTRIAGED", "HIGH"]
    data["ecr describe-image-scan-findings"] = {
        "imageId": {"imageDigest": DIGEST},
        "imageScanStatus": {"status": "ACTIVE"},
        "imageScanFindings": {
            "imageScanCompletedAt": "2026-11-10T15:45:36Z",
            "vulnerabilitySourceUpdatedAt": "2026-11-10T15:45:36Z",
            # What AWS returns for the first page only; must not be trusted.
            "findingSeverityCounts": {"MEDIUM": 1},
            "enhancedFindings": [{"severity": s} for s in severities],
        },
    }
    result, files, calls = run_fetcher(tmp_path, data, "ecr_image_scanning")
    assert result.returncode == 0, result.stderr
    scan = json.loads(files[0].read_text())["results"]["repositories"][0]["latest_image_scan"]
    assert scan["severity_counts"] == {
        "critical": 1,
        "high": 3,
        "medium": 1,
        "low": 1,
        "informational": 1,
        "untriaged": 1,
    }
    args = next(c["args"] for c in calls if c["args"][:2] == ["ecr", "describe-image-scan-findings"])
    assert "--no-paginate" not in args
    assert "--max-results" not in args


@pytest.mark.skipif(not shutil.which("jq"), reason="requires jq")
def test_enhanced_scan_with_no_findings_reports_zero_not_unknown(tmp_path):
    data = responses()
    data["ecr get-registry-scanning-configuration"] = {
        "scanningConfiguration": {"scanType": "ENHANCED", "rules": []}
    }
    data["ecr batch-get-repository-scanning-configuration"] = {
        "scanningConfigurations": [{"repositoryName": "example", "scanFrequency": "CONTINUOUS_SCAN"}]
    }
    data["ecr describe-images"] = DIGEST
    data["ecr describe-image-scan-findings"] = {
        "imageId": {"imageDigest": DIGEST},
        "imageScanStatus": {"status": "ACTIVE"},
        "imageScanFindings": {"enhancedFindings": [], "findings": []},
    }
    result, files, _ = run_fetcher(tmp_path, data, "ecr_image_scanning")
    assert result.returncode == 0, result.stderr
    scan = json.loads(files[0].read_text())["results"]["repositories"][0]["latest_image_scan"]
    assert scan["severity_counts"] == dict.fromkeys(
        ["critical", "high", "medium", "low", "informational", "untriaged"], 0
    )


@pytest.mark.skipif(not shutil.which("jq"), reason="requires jq")
@pytest.mark.parametrize(
    "scan",
    [
        "ScanNotFoundException",
        "ImageNotFoundException",
        "PENDING",
        "SCAN_ELIGIBILITY_EXPIRED",
        "FAILED",
        "AccessDeniedException",
    ],
)
def test_unavailable_scan_counts_never_look_clean(tmp_path, scan):
    data = responses()
    data["ecr get-registry-scanning-configuration"] = {
        "scanningConfiguration": {"scanType": "ENHANCED", "rules": []}
    }
    data["ecr batch-get-repository-scanning-configuration"] = {
        "scanningConfigurations": [
            {"repositoryName": "example", "scanFrequency": "CONTINUOUS_SCAN"}
        ]
    }
    data["ecr describe-images"] = DIGEST
    data["ecr describe-image-scan-findings"] = (
        {"_error": scan}
        if scan.endswith("Exception")
        else {
            "imageId": {"imageDigest": DIGEST},
            "imageScanStatus": {"status": scan},
            "imageScanFindings": {"findingSeverityCounts": {}},
        }
    )
    result, files, _ = run_fetcher(tmp_path, data, "ecr_image_scanning")
    repo = json.loads(files[0].read_text())["results"]["repositories"][0]
    if scan == "AccessDeniedException":
        assert result.returncode == 1
        assert repo["scan_collection_status"] == "error"
    else:
        assert result.returncode == 0, result.stderr
        assert repo["latest_image_scan"]["severity_counts"] is None
        if scan == "ImageNotFoundException":
            assert repo["scan_collection_status"] == "image_deleted"
            assert repo["latest_image_scan"]["scan_status"] == "IMAGE_NOT_FOUND"
            assert repo["latest_image_scan"]["image_digest"] == DIGEST


def configure_runner_aws(setup, monkeypatch):
    # The runner intentionally strips undeclared env vars. Bake test paths into
    # the fake rather than altering the production credential/config contract.
    fake = (
        (setup / "aws")
        .read_text()
        .replace("os.environ['FAKE_LOG']", repr(str(setup / "calls.jsonl")))
    )
    fake = fake.replace("os.environ['FAKE_RESPONSES']", repr(str(setup / "responses.json")))
    (setup / "aws").write_text(fake)
    monkeypatch.setenv("PATH", f"{setup}{os.pathsep}{os.environ['PATH']}")
    for key in list(os.environ):
        if key.startswith(("AWS_", "PARAMIFY_")):
            monkeypatch.delenv(key)


def test_runner_retains_partial_evidence_with_failed_envelope(tmp_path, monkeypatch):
    from framework import api

    setup = tmp_path / "setup"
    data = responses()
    data["inspector2 list-findings"]["nextToken"] = "denied"
    data["inspector2 list-findings:denied"] = {"_error": "AccessDeniedException"}
    result, _, _ = run_fetcher(setup, data, "inspector_ecr_findings")
    assert result.returncode == 1
    configure_runner_aws(setup, monkeypatch)
    summary = api.run(
        {
            "run": {
                "output_dir": str(tmp_path / "runs"),
                "fetchers": [
                    {"use": "aws_inspector_ecr_findings", "targets": [{"region": REGION}]}
                ],
            }
        },
        ROOT,
    )
    assert not summary["ok"]
    artifacts = list(Path(summary["run_dir"]).glob("aws_inspector_ecr_findings_*.json"))
    assert len(artifacts) == 1
    artifact = json.loads(artifacts[0].read_text())
    assert artifact["metadata"]["status"] == "failed"
    assert artifact["metadata"]["error_code"] == "not_authorized"
    assert artifact["payload"]["metadata"]["partial_failure"] is True
    assert artifact["payload"]["results"]["findings"] == [finding()]
    assert artifact["payload"]["results"]["collection_complete"] is False


def test_runner_to_paramify_intake_preserves_rows_and_does_not_reupload(tmp_path, monkeypatch):
    """Real runner + real uploader; only AWS executable and HTTP are substituted."""
    from framework import api

    setup = tmp_path / "setup"
    result, original, _ = run_fetcher(setup)
    assert result.returncode == 0, result.stderr
    configure_runner_aws(setup, monkeypatch)
    assessment = "123e4567-e89b-12d3-a456-426614174000"
    manifest = {
        "run": {
            "output_dir": str(tmp_path / "runs"),
            "fetchers": [
                {
                    "use": "aws_inspector_ecr_report",
                    "targets": [{"region": REGION}],
                    "config": {"assessment_id": assessment, "close_cycle": "never"},
                }
            ],
        }
    }
    summary = api.run(manifest, ROOT)
    assert summary["ok"], summary
    run_dir = Path(summary["run_dir"])
    reports = list((run_dir / "issue-reports").glob("*.csv"))
    assert len(reports) == 1
    assert reports[0].read_bytes() == original[0].read_bytes()
    sidecar = json.loads((run_dir / "issue-reports/_issue_reports.json").read_text())
    assert sidecar["reports"][0]["assessment_id"] == assessment

    spec = importlib.util.spec_from_file_location(
        "inspector_intake_test", ROOT / "uploaders/paramify_issues/uploader.py"
    )
    uploader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(uploader)
    posts = []

    class Response:
        status_code = 200
        text = ""

        def __init__(self, body):
            self.body = body

        def json(self):
            return self.body

    class Session:
        def __init__(self):
            self.headers = {}

        def post(self, url, **kwargs):
            posts.append((url, kwargs))
            if url.endswith("/intake"):
                return Response({"artifact": {"id": "artifact-1"}})
            assert url.endswith("/process")
            return Response({"id": "job-1", "status": "COMPLETED", "type": "PROCESS"})

        def get(self, url, **kwargs):
            assert url.endswith("/pipeline-jobs/job-1")
            return Response({"id": "job-1", "status": "COMPLETED", "type": "PROCESS"})

    monkeypatch.setattr(uploader.requests, "Session", Session)
    for _ in range(2):
        upload = uploader.upload_run(
            run_dir, token="synthetic-token", base_url="https://paramify.example/api/v0", wait=False
        )
        assert upload["errors"] == 0, upload
    assert len(posts) == 2  # second upload uses the existing intake log
    assert posts[0][0].endswith(f"/pipelines/{assessment}/intake")
    assert posts[0][1]["files"]["file"][1] == reports[0].read_bytes()
    assert posts[1][1]["json"] == {"artifactIds": ["artifact-1"], "operation": "PROCESS"}
