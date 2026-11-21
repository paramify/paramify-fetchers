"""aws_ecr_image_scanning against a fake ECR client: pagination, page sizes,
severity counting, missing scans and failure reporting. No AWS credentials used.
"""

from __future__ import annotations

import importlib.util
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

botocore_exceptions = pytest.importorskip("botocore.exceptions")
ClientError = botocore_exceptions.ClientError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "ecr_image_scanning_test_module", ROOT / "fetchers/aws/ecr_image_scanning/fetcher.py"
)
fetcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetcher)

ACCOUNT = "111122223333"
REGION = "us-gov-west-1"


def digest(c):
    return "sha256:" + c * 64


def when(day):
    return datetime(2026, 11, day, tzinfo=timezone.utc)


def client_error(code, operation):
    return ClientError({"Error": {"Code": code, "Message": f"{code} for test"}}, operation)


def repo(name, scan_on_push=False):
    return {
        "repositoryName": name,
        "repositoryArn": f"arn:aws-us-gov:ecr:{REGION}:{ACCOUNT}:repository/{name}",
        "registryId": ACCOUNT,
        "imageScanningConfiguration": {"scanOnPush": scan_on_push},
        "imageTagMutability": "IMMUTABLE",
    }


class FakeEcr:
    """Answers by (operation, repository, nextToken), and records every request."""

    def __init__(self, repos, images=None, findings=None, configs=None, scan_type="ENHANCED"):
        self.repos = repos
        self.images = images or {}
        self.findings = findings or {}
        self.configs = configs
        self.scan_type = scan_type
        self.calls = []
        self.lock = threading.Lock()

    def record(self, operation, params):
        with self.lock:
            self.calls.append((operation, params))

    def get_registry_scanning_configuration(self):
        self.record("get_registry_scanning_configuration", {})
        return {"scanningConfiguration": {
            "scanType": self.scan_type,
            "rules": [{"scanFrequency": "CONTINUOUS_SCAN",
                       "repositoryFilters": [{"filter": "*", "filterType": "WILDCARD"}]}],
        }}

    def describe_repositories(self, **params):
        self.record("describe_repositories", params)
        return {"repositories": self.repos}

    def batch_get_repository_scanning_configuration(self, repositoryNames):
        self.record("batch_get_repository_scanning_configuration", {"repositoryNames": repositoryNames})
        configs = self.configs if self.configs is not None else {}
        return {
            "scanningConfigurations": [
                {"repositoryName": n, "scanFrequency": configs.get(n, "CONTINUOUS_SCAN"),
                 "appliedScanFilters": [{"filter": "*", "filterType": "WILDCARD"}]}
                for n in repositoryNames if configs.get(n, "CONTINUOUS_SCAN") is not None
            ],
            "failures": [],
        }

    def _page(self, table, operation, key, params):
        self.record(operation, params)
        answer = table[key][params.get("nextToken")]
        if isinstance(answer, Exception):
            raise answer
        return answer

    def describe_images(self, **params):
        return self._page(self.images, "describe_images", params["repositoryName"], params)

    def describe_image_scan_findings(self, **params):
        return self._page(self.findings, "describe_image_scan_findings", params["repositoryName"], params)


def enhanced_page(d, severities, token=None):
    page = {
        "imageId": {"imageDigest": d},
        "imageScanStatus": {"status": "ACTIVE"},
        "imageScanFindings": {
            "imageScanCompletedAt": when(10),
            "vulnerabilitySourceUpdatedAt": when(9),
            # Per page only; the fetcher must not use it for enhanced scans.
            "findingSeverityCounts": {"HIGH": 999},
            "enhancedFindings": [{"severity": s} if s else {} for s in severities],
        },
    }
    if token:
        page["nextToken"] = token
    return page


def scenario():
    repos = [repo("enhanced", True), repo("basic"), repo("unscanned"), repo("deleted"),
             repo("denied"), repo("empty")]
    images = {
        "enhanced": {
            None: {"imageDetails": [{"imageDigest": digest("a"), "imagePushedAt": when(1)}], "nextToken": "i2"},
            "i2": {"imageDetails": [{"imageDigest": digest("b"), "imagePushedAt": when(5)},
                                    {"imageDigest": digest("c"), "imagePushedAt": when(3)}]},
        },
        "basic": {None: {"imageDetails": [{"imageDigest": digest("d"), "imagePushedAt": when(2)}]}},
        "unscanned": {None: {"imageDetails": [{"imageDigest": digest("e"), "imagePushedAt": when(2)}]}},
        "deleted": {None: {"imageDetails": [{"imageDigest": digest("f"), "imagePushedAt": when(2)}]}},
        "denied": {None: {"imageDetails": [{"imageDigest": digest("0"), "imagePushedAt": when(2)}]}},
        "empty": {None: {"imageDetails": []}},
    }
    findings = {
        "enhanced": {
            None: enhanced_page(digest("b"), ["HIGH", "HIGH", "CRITICAL"], token="f2"),
            "f2": enhanced_page(digest("b"), ["LOW", None]),
        },
        "basic": {None: {
            "imageId": {"imageDigest": digest("d")},
            "imageScanStatus": {"status": "COMPLETE"},
            "imageScanFindings": {"imageScanCompletedAt": when(4), "findingSeverityCounts": {"MEDIUM": 7},
                                  "findings": [{"name": "CVE-1"}]},
            "nextToken": "never-read",
        }},
        "unscanned": {None: client_error("ScanNotFoundException", "DescribeImageScanFindings")},
        "deleted": {None: client_error("ImageNotFoundException", "DescribeImageScanFindings")},
        "denied": {None: client_error("AccessDeniedException", "DescribeImageScanFindings")},
    }
    return FakeEcr(repos, images, findings, configs={"empty": None})


def by_name(results):
    return {r["name"]: r for r in results["repositories"]}


def test_collects_every_repository_in_order():
    ecr = scenario()
    collector = fetcher.Collector(ecr)
    results = collector.collect()

    assert [r["name"] for r in results["repositories"]] == [
        "enhanced", "basic", "unscanned", "deleted", "denied", "empty"]
    assert results["registry_scanning"] == {
        "scan_type": "ENHANCED",
        "rules": [{"scan_frequency": "CONTINUOUS_SCAN",
                   "scan_filters": [{"filter": "*", "filterType": "WILDCARD"}]}],
    }
    repos = by_name(results)

    # Newest image across describe-images pages; enhanced counts from every finding page.
    assert repos["enhanced"]["latest_image_scan"] == {
        "image_digest": digest("b"),
        "scan_status": "ACTIVE",
        "severity_counts": {"critical": 1, "high": 2, "medium": 0, "low": 1, "informational": 0, "untriaged": 1},
        "scan_completed_at": "2026-11-10T00:00:00+00:00",
        "vulnerability_source_updated_at": "2026-11-09T00:00:00+00:00",
    }
    assert repos["enhanced"]["scan_on_push"] is True
    assert repos["enhanced"]["immutability"] == "IMMUTABLE"
    assert repos["enhanced"]["scan_frequency"] == "CONTINUOUS_SCAN"
    assert repos["enhanced"]["applied_scan_filters"] == [{"filter": "*", "filterType": "WILDCARD"}]
    assert repos["enhanced"]["scan_collection_status"] == "collected"

    assert repos["basic"]["latest_image_scan"]["severity_counts"] == {
        "critical": 0, "high": 0, "medium": 7, "low": 0, "informational": 0, "untriaged": 0}
    assert repos["basic"]["latest_image_scan"]["vulnerability_source_updated_at"] is None

    assert repos["unscanned"]["latest_image_scan"] == {
        "image_digest": digest("e"), "scan_status": "NOT_SCANNED", "severity_counts": None}
    assert repos["unscanned"]["scan_collection_status"] == "not_scanned"
    assert repos["deleted"]["latest_image_scan"]["scan_status"] == "IMAGE_NOT_FOUND"
    assert repos["deleted"]["scan_collection_status"] == "image_deleted"

    assert repos["denied"]["latest_image_scan"] is None
    assert repos["denied"]["scan_collection_status"] == "error"

    assert repos["empty"]["latest_image_scan"] is None
    assert repos["empty"]["scan_collection_status"] == "empty_repository"
    assert repos["empty"]["scan_frequency"] is None
    # Not read, so unknown: [] would claim no registry filter applies.
    assert repos["empty"]["applied_scan_filters"] is None

    # In describe-repositories order, whichever worker finishes first.
    labels = [label for label, _ in collector.failures]
    assert labels == [
        "aws ecr describe-image-scan-findings (denied) failed",
        "No effective scanning configuration returned for empty",
    ]
    assert fetcher.classify([e for _, e in collector.failures if e]) == "not_authorized"


def test_uses_largest_pages_and_reads_one_page_of_a_basic_scan():
    ecr = scenario()
    fetcher.Collector(ecr).collect()

    for operation, params in ecr.calls:
        if operation in fetcher.PAGE_SIZES:
            assert params["maxResults"] == 1000, operation
    scans = [p for op, p in ecr.calls if op == "describe_image_scan_findings"]
    assert [p.get("nextToken") for p in scans if p["repositoryName"] == "basic"] == [None]
    assert [p.get("nextToken") for p in scans if p["repositoryName"] == "enhanced"] == [None, "f2"]
    assert {p["imageId"]["imageDigest"] for p in scans if p["repositoryName"] == "enhanced"} == {digest("b")}


def test_main_writes_evidence_and_reports_partial_failure(tmp_path, monkeypatch):
    class FakeSts:
        def get_caller_identity(self):
            return {"Account": ACCOUNT, "Arn": f"arn:aws-us-gov:iam::{ACCOUNT}:role/test"}

    status = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status))
    monkeypatch.setenv("AWS_PROFILE", "example profile")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setattr(fetcher, "session_and_client", lambda: (FakeSts(), scenario()))

    assert fetcher.main() == 1

    out = tmp_path / "out" / f"aws_ecr_image_scanning_example_profile_{REGION}.json"
    evidence = json.loads(out.read_text())
    assert evidence["metadata"]["profile"] == "example profile"
    assert evidence["metadata"]["region"] == REGION
    assert evidence["metadata"]["account_id"] == ACCOUNT
    assert len(evidence["results"]["repositories"]) == 6
    reported = json.loads(status.read_text())
    assert reported["code"] == "not_authorized"
    assert reported["error"].startswith("2 AWS API failure(s); first: ")


def test_failed_repository_list_keeps_registry_evidence():
    class Failing(FakeEcr):
        def describe_repositories(self, **params):
            raise client_error("ThrottlingException", "DescribeRepositories")

    collector = fetcher.Collector(Failing([]))
    results = collector.collect()
    # Not listed, so unknown: [] would claim the registry has no repositories.
    assert results["repositories"] is None
    assert results["registry_scanning"]["scan_type"] == "ENHANCED"
    assert [label for label, _ in collector.failures] == ["aws ecr describe-repositories (list) failed"]
    assert fetcher.classify([e for _, e in collector.failures]) == "rate_limited"


def test_failed_registry_read_leaves_rules_unknown():
    class Failing(FakeEcr):
        def get_registry_scanning_configuration(self):
            raise client_error("AccessDeniedException", "GetRegistryScanningConfiguration")

    collector = fetcher.Collector(Failing([]))
    results = collector.collect()
    assert results["registry_scanning"] == {"scan_type": None, "rules": None}
    assert results["repositories"] == []


def test_failures_follow_repository_order_not_finish_order():
    # The first repository's read waits until every other read has failed.
    others = threading.Barrier(fetcher.REPO_WORKERS)

    class Ordered(FakeEcr):
        def describe_images(self, **params):
            if params["repositoryName"] == "r0":
                others.wait(5)
                time.sleep(0.05)
                raise client_error("AccessDeniedException", "DescribeImages")
            try:
                raise client_error("AccessDeniedException", "DescribeImages")
            finally:
                others.wait(5)

    names = [f"r{i}" for i in range(fetcher.REPO_WORKERS)]
    collector = fetcher.Collector(Ordered([repo(n) for n in names]))
    collector.collect()
    assert [label for label, _ in collector.failures] == [
        f"aws ecr describe-images ({n}) failed" for n in names]


def test_missing_boto3_is_bad_config(tmp_path, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_boto3(name, *args, **kwargs):
        if name.split(".")[0] in ("boto3", "botocore"):
            raise ModuleNotFoundError(f"No module named '{name}'")
        return real_import(name, *args, **kwargs)

    status = tmp_path / "status.json"
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status))
    monkeypatch.setattr(builtins, "__import__", no_boto3)

    assert fetcher.main() == 1
    reported = json.loads(status.read_text())
    assert reported["code"] == "bad_config"
    assert "pip install -r requirements.txt" in reported["error"]
