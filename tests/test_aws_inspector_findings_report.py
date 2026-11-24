"""aws_inspector_findings_report: ARN mapping, collection and the failure path.

Offline. The fixtures in fetchers/aws/inspector_findings_report/tests/fixtures/
are synthetic Inspector2 findings (one per scan type and finding type) and the
AWS Config rows for the same resources. A stand-in boto3 client answers the
shared Aws class, so the real pagination, query and publication code runs.
"""

from __future__ import annotations

import copy
import csv
import importlib.util
import io
import json
import os
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FETCHER_DIR = ROOT / "fetchers/aws/inspector_findings_report"
FIXTURES = FETCHER_DIR / "tests/fixtures"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


report = _load("inspector_findings_report_test_module", FETCHER_DIR / "fetcher.py")
common = sys.modules["inspector_common"]
inventory = _load("config_inventory_for_report_test", ROOT / "fetchers/aws/config_inventory/fetcher.py")

FIXTURE = json.loads((FIXTURES / "findings.json").read_text())
ACCOUNT, REGION = FIXTURE["account"], FIXTURE["region"]
CONFIG_RECORDS = json.loads((FIXTURES / "config_records.json").read_text())["records"]

EXPECTED = {
    "ec2_package": (f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0", "web-1"),
    "ec2_network": (f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0", ""),
    "ecr_image": (f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/example-service", "example-service"),
    "lambda_package": (f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:example-fn", "example-fn"),
    "lambda_code": (f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:example-fn", "example-fn"),
}


def finding(key):
    return copy.deepcopy(FIXTURE["findings"][key])


def query_key(query):
    rtype = query["resourceType"][0]["value"]
    ftype = query.get("findingType", [{}])[0].get("value")
    return f"{rtype}/{ftype}" if ftype else rtype


def by_query():
    """One ListFindings page per scan type, built from the fixture findings."""
    return {
        "AWS_EC2_INSTANCE": {"findings": [finding("ec2_package"), finding("ec2_network")]},
        "AWS_ECR_CONTAINER_IMAGE": {"findings": [finding("ecr_image")]},
        "AWS_LAMBDA_FUNCTION/PACKAGE_VULNERABILITY": {"findings": [finding("lambda_package")]},
        "AWS_LAMBDA_FUNCTION/CODE_VULNERABILITY": {"findings": [finding("lambda_code")]},
    }


def responses(states=None):
    states = states or {"ec2": "ENABLED", "ecr": "ENABLED", "lambda": "ENABLED", "lambdaCode": "ENABLED"}
    return {
        "sts get-caller-identity": {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:role/reader"},
        "inspector2 batch-get-account-status": {
            "accounts": [
                {
                    "accountId": ACCOUNT,
                    "state": {"status": "ENABLED"},
                    "resourceState": {k: {"status": v} for k, v in states.items()},
                }
            ],
            "failedAccounts": [],
        },
        "inspector2 list-findings": {"_by_query": by_query()},
    }


class FakeClient:
    def __init__(self, aws, service):
        self.aws, self.service = aws, service

    def __getattr__(self, method):
        operation = method.replace("_", "-")

        def call(**params):
            self.aws.calls.append({"operation": f"{self.service} {operation}", "params": params})
            key = f"{self.service} {operation}"
            if params.get("nextToken"):
                key += ":" + params["nextToken"]
            response = copy.deepcopy(self.aws.responses[key])
            if "_by_query" in response:
                response = response["_by_query"][query_key(params["filterCriteria"])]
            if "_error" in response:
                raise RuntimeError(response["_error"])
            return dict(response, ResponseMetadata={"HTTPStatusCode": 200})

        return call


class FakeAws(common.Aws):
    """The real call/pages logic over a stand-in boto3 client."""

    def __init__(self, data, region=REGION):
        self.responses, self.region, self.calls, self.clients = data, region, [], {}

    def client(self, service):
        return FakeClient(self, service)


def run_main(tmp_path, monkeypatch, data, **settings):
    for name in [n for n in list(os.environ) if n.startswith(("AWS_", "EVIDENCE_", "FETCHER_"))]:
        monkeypatch.delenv(name, raising=False)
    output = tmp_path / "output"
    monkeypatch.setenv("EVIDENCE_DIR", str(output))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    for key, value in settings.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(common, "load_dotenv", lambda: None)
    fake = FakeAws(data)
    monkeypatch.setattr(report, "Aws", lambda: fake)
    code = report.main()
    files = sorted(output.glob("*")) if output.exists() else []
    status = json.loads((tmp_path / "status.json").read_text()) if (tmp_path / "status.json").exists() else None
    return code, files, status, fake.calls


def read_rows(path):
    text = path.read_text()
    return list(csv.DictReader(io.StringIO(text))), text.splitlines()[0].split(",")


# --- ARN construction -------------------------------------------------------


@pytest.mark.parametrize("key", sorted(EXPECTED))
def test_resource_arn_for_each_resource_type(key):
    assert report.resource_identity(finding(key), REGION) == EXPECTED[key]


def test_resource_arns_match_what_config_inventory_writes():
    """The report's Resource ARN is the unique_asset_identifier of the same resource."""
    for key, row in CONFIG_RECORDS.items():
        asset = inventory.record(json.dumps(row), "aws")
        assert report.resource_identity(finding(key), REGION)[0] == asset["unique_asset_identifier"]


def test_govcloud_uses_the_findings_partition_and_region():
    text = json.dumps(FIXTURE["findings"]).replace("arn:aws:", "arn:aws-us-gov:")
    text = text.replace('"partition": "aws"', '"partition": "aws-us-gov"').replace(REGION, "us-gov-west-1")
    gov = json.loads(text)
    arn, _ = report.resource_identity(gov["ec2_package"], "us-gov-west-1")
    assert arn == f"arn:aws-us-gov:ec2:us-gov-west-1:{ACCOUNT}:instance/i-0123456789abcdef0"
    arn, _ = report.resource_identity(gov["lambda_code"], "us-gov-west-1")
    assert arn == f"arn:aws-us-gov:lambda:us-gov-west-1:{ACCOUNT}:function:example-fn"
    arn, _ = report.resource_identity(gov["ecr_image"], "us-gov-west-1")
    assert arn == f"arn:aws-us-gov:ecr:us-gov-west-1:{ACCOUNT}:repository/example-service"


@pytest.mark.parametrize("qualifier", ["$LATEST", "7", None])
def test_lambda_version_qualifier_is_dropped(qualifier):
    f = finding("lambda_package")
    base = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:example-fn"
    f["resources"][0]["id"] = f"{base}:{qualifier}" if qualifier else base
    assert report.resource_identity(f, REGION)[0] == base


def test_ec2_instance_arn_is_accepted_as_is():
    f = finding("ec2_package")
    f["resources"][0]["id"] = EXPECTED["ec2_package"][0]
    assert report.resource_identity(f, REGION)[0] == EXPECTED["ec2_package"][0]


def test_ecr_repository_arn_uses_the_registry_account():
    f = finding("ecr_image")
    del f["resources"][0]["details"]["awsEcrContainerImage"]["registry"]
    assert report.resource_identity(f, REGION)[0] == EXPECTED["ecr_image"][0]


@pytest.mark.parametrize(
    "key, change",
    [
        ("ec2_package", lambda r: r.update(id="web-1")),
        ("ec2_package", lambda r: r.update(id=f"arn:aws:ec2:us-west-2:{ACCOUNT}:instance/i-0123456789abcdef0")),
        ("ec2_package", lambda r: r.update(region="us-west-2")),
        ("ec2_package", lambda r: r.update(partition="aws-cn")),
        ("lambda_package", lambda r: r.update(id=f"arn:aws:lambda:{REGION}:{ACCOUNT}:layer:example:1")),
        ("lambda_package", lambda r: r.update(id=f"arn:aws:lambda:{REGION}:999999999999:function:example-fn")),
        ("lambda_package", lambda r: r["details"]["awsLambdaFunction"].update(functionName="other-fn")),
        ("ecr_image", lambda r: r["details"]["awsEcrContainerImage"].pop("repositoryName")),
        ("ecr_image", lambda r: r["details"]["awsEcrContainerImage"].update(registry="registry")),
        ("ecr_image", lambda r: r.update(type="CODE_REPOSITORY")),
    ],
)
def test_unexpected_resource_identity_is_refused(key, change):
    f = finding(key)
    change(f["resources"][0])
    with pytest.raises(common.CollectionError):
        report.resource_identity(f, REGION)


# --- The report -------------------------------------------------------------


def test_report_has_every_finding_with_inventory_arns(tmp_path, monkeypatch):
    data = responses()
    # The ECR query spans two pages, as a large image's findings do.
    second = finding("ecr_image")
    second["findingArn"] = second["findingArn"][:-1] + "f"
    data["inspector2 list-findings"]["_by_query"]["AWS_ECR_CONTAINER_IMAGE"]["nextToken"] = "ecr-2"
    data["inspector2 list-findings:ecr-2"] = {"findings": [second, finding("ecr_image")]}
    code, files, status, calls = run_main(tmp_path, monkeypatch, data)
    assert code == 0, status
    assert len(files) == 1 and files[0].name.startswith(f"aws_inspector_findings_report_{ACCOUNT}_{REGION}_")
    rows, header = read_rows(files[0])
    assert header == report.CSV_COLUMNS
    assert [r["Finding ARN"] for r in rows] == sorted({r["Finding ARN"] for r in rows})
    assert len(rows) == 6
    by_arn = {r["Finding ARN"]: r for r in rows}
    for key, (arn, name) in EXPECTED.items():
        row = by_arn[FIXTURE["findings"][key]["findingArn"]]
        assert (row["Resource ARN"], row["Resource Name"]) == (arn, name)
        assert row["Resource ID"] == FIXTURE["findings"][key]["resources"][0]["id"]
    ecr = by_arn[FIXTURE["findings"]["ecr_image"]["findingArn"]]
    assert ecr["Image Digest"] == "sha256:" + "a" * 64
    assert json.loads(ecr["Image Tags"]) == ["latest", "v1.2.3"]
    assert ecr["Vulnerability ID"] == "CVE-2026-10002" and ecr["Severity"] == "CRITICAL"
    assert json.loads(ecr["Affected Packages"])[0]["fixedInVersion"] == "1.0.1"
    network = by_arn[FIXTURE["findings"]["ec2_network"]["findingArn"]]
    assert network["Vulnerability ID"] == "" and network["Affected Packages"] == "" and network["Image Tags"] == ""
    assert json.loads(network["Network Reachability"])["openPortRange"] == {"begin": 22, "end": 22}
    code_row = by_arn[FIXTURE["findings"]["lambda_code"]["findingArn"]]
    assert code_row["Vulnerability ID"] == "python/hardcoded-credentials@v1.0"
    assert json.loads(code_row["Affected Code"])["filePath"] == "src/app.py"
    assert json.loads(code_row["Related Vulnerabilities"]) == ["CWE-798"]
    lambda_row = by_arn[FIXTURE["findings"]["lambda_package"]["findingArn"]]
    assert lambda_row["Severity"] == "UNTRIAGED"
    assert by_arn[FIXTURE["findings"]["ec2_package"]["findingArn"]]["EPSS Score"] == "0.00123"

    queries = [c["params"] for c in calls if c["operation"] == "inspector2 list-findings"]
    assert len(queries) == 5
    assert all(q["maxResults"] == 100 for q in queries)
    assert [c["params"].get("nextToken") for c in calls if c["operation"] == "inspector2 list-findings"].count("ecr-2") == 1
    first = {query_key(q["filterCriteria"]): q["filterCriteria"] for q in queries if "nextToken" not in q}
    assert first["AWS_LAMBDA_FUNCTION/CODE_VULNERABILITY"] == {
        "awsAccountId": [{"comparison": "EQUALS", "value": ACCOUNT}],
        "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
        "resourceType": [{"comparison": "EQUALS", "value": "AWS_LAMBDA_FUNCTION"}],
        "findingType": [{"comparison": "EQUALS", "value": "CODE_VULNERABILITY"}],
    }
    assert "findingType" not in first["AWS_EC2_INSTANCE"]
    assert not list(tmp_path.glob(".inspector-*.tmp"))


def test_min_severity_narrows_every_query(tmp_path, monkeypatch):
    code, _files, _status, calls = run_main(tmp_path, monkeypatch, responses(), AWS_INSPECTOR_MIN_SEVERITY="high")
    assert code == 0
    for call in calls:
        if call["operation"] == "inspector2 list-findings":
            assert [s["value"] for s in call["params"]["filterCriteria"]["severity"]] == ["UNTRIAGED", "CRITICAL", "HIGH"]


def test_a_scan_type_that_is_not_enabled_is_skipped_by_default(tmp_path, monkeypatch):
    data = responses({"ec2": "ENABLED", "ecr": "ENABLED", "lambda": "ENABLED", "lambdaCode": "DISABLED"})
    code, files, _status, calls = run_main(tmp_path, monkeypatch, data)
    assert code == 0
    keys = {query_key(c["params"]["filterCriteria"]) for c in calls if c["operation"] == "inspector2 list-findings"}
    assert "AWS_LAMBDA_FUNCTION/CODE_VULNERABILITY" not in keys and len(keys) == 3
    rows, _ = read_rows(files[0])
    assert {r["Finding Type"] for r in rows} == {"PACKAGE_VULNERABILITY", "NETWORK_REACHABILITY"}


def test_named_scan_types_limit_the_queries(tmp_path, monkeypatch):
    code, files, _status, calls = run_main(tmp_path, monkeypatch, responses(), AWS_INSPECTOR_SCAN_TYPES='["ecr", "EC2"]')
    assert code == 0
    keys = {query_key(c["params"]["filterCriteria"]) for c in calls if c["operation"] == "inspector2 list-findings"}
    assert keys == {"AWS_EC2_INSTANCE", "AWS_ECR_CONTAINER_IMAGE"}
    assert {r["Resource Type"] for r in read_rows(files[0])[0]} == {"AWS_EC2_INSTANCE", "AWS_ECR_CONTAINER_IMAGE"}


def test_zero_findings_need_allow_empty(tmp_path, monkeypatch):
    data = responses()
    data["inspector2 list-findings"]["_by_query"] = {k: {"findings": []} for k in by_query()}
    code, files, status, _ = run_main(tmp_path / "refused", monkeypatch, data)
    assert code == 1 and not files and status["code"] == "bad_config"
    code, files, _status, _ = run_main(tmp_path / "allowed", monkeypatch, data, AWS_INSPECTOR_ALLOW_EMPTY="true")
    assert code == 0
    assert files[0].read_text().strip() == ",".join(report.CSV_COLUMNS)


# --- The failure path: no report, non-zero exit -------------------------------


def _late_page(data, page):
    data["inspector2 list-findings"]["_by_query"]["AWS_ECR_CONTAINER_IMAGE"]["nextToken"] = "late"
    data["inspector2 list-findings:late"] = page


FAILURES = {
    "late_page_denied": (
        lambda d: _late_page(d, {"_error": "An error occurred (AccessDeniedException) when calling ListFindings"}),
        "not_authorized",
    ),
    "throttled": (
        lambda d: _late_page(d, {"_error": "An error occurred (ThrottlingException) when calling ListFindings"}),
        "rate_limited",
    ),
    "token_loop": (lambda d: _late_page(d, {"findings": [], "nextToken": "late"}), "partial_failure"),
    "changed_duplicate": (
        lambda d: _late_page(d, {"findings": [dict(finding("ecr_image"), severity="LOW")]}),
        "partial_failure",
    ),
    "missing_findings_key": (
        lambda d: d["inspector2 list-findings"]["_by_query"].update({"AWS_ECR_CONTAINER_IMAGE": {}}),
        "partial_failure",
    ),
    "other_account": (
        lambda d: d["inspector2 list-findings"]["_by_query"]["AWS_EC2_INSTANCE"]["findings"][0].update(
            awsAccountId="999999999999"
        ),
        "partial_failure",
    ),
    "two_resources": (
        lambda d: d["inspector2 list-findings"]["_by_query"]["AWS_EC2_INSTANCE"]["findings"][0]["resources"].append(
            finding("ec2_package")["resources"][0]
        ),
        "partial_failure",
    ),
    "unexpected_resource_type": (
        lambda d: d["inspector2 list-findings"]["_by_query"]["AWS_ECR_CONTAINER_IMAGE"]["findings"][0]["resources"][
            0
        ].update(type="CODE_REPOSITORY"),
        "partial_failure",
    ),
    "unmappable_instance_id": (
        lambda d: d["inspector2 list-findings"]["_by_query"]["AWS_EC2_INSTANCE"]["findings"][0]["resources"][
            0
        ].update(id="web-1"),
        "partial_failure",
    ),
    "account_status_failed": (
        lambda d: d["inspector2 batch-get-account-status"].update(
            failedAccounts=[{"accountId": ACCOUNT, "errorCode": "ACCESS_DENIED"}]
        ),
        "partial_failure",
    ),
    "sts_expired": (
        lambda d: d.update({"sts get-caller-identity": {"_error": "An error occurred (ExpiredToken) when calling"}}),
        "auth_failed",
    ),
}


@pytest.mark.parametrize("case", sorted(FAILURES))
def test_incomplete_collection_never_writes_a_report(tmp_path, monkeypatch, case):
    data = responses()
    change, expected = FAILURES[case]
    change(data)
    code, files, status, _ = run_main(tmp_path, monkeypatch, data)
    assert code == 1
    assert files == []
    assert status["code"] == expected
    assert not list(tmp_path.glob(".inspector-*.tmp"))


def test_named_scan_type_that_is_not_enabled_fails_before_listing(tmp_path, monkeypatch):
    data = responses({"ec2": "ENABLED", "ecr": "ENABLED", "lambda": "ENABLED", "lambdaCode": "DISABLED"})
    code, files, status, calls = run_main(tmp_path, monkeypatch, data, AWS_INSPECTOR_SCAN_TYPES='["LAMBDA_CODE"]')
    assert code == 1 and files == [] and status["code"] == "bad_config"
    assert "LAMBDA_CODE" in status["error"]
    assert not [c for c in calls if c["operation"] == "inspector2 list-findings"]


def test_no_enabled_scan_type_fails(tmp_path, monkeypatch):
    data = responses({"ec2": "DISABLED", "ecr": "SUSPENDED", "lambda": "DISABLED"})
    code, files, status, calls = run_main(tmp_path, monkeypatch, data)
    assert code == 1 and files == [] and status["code"] == "bad_config"
    assert not [c for c in calls if c["operation"] == "inspector2 list-findings"]


@pytest.mark.parametrize("value", ['["EKS"]', "EC2", '[""]'])
def test_bad_scan_types_fail_before_any_aws_call(tmp_path, monkeypatch, value):
    code, files, status, calls = run_main(tmp_path, monkeypatch, responses(), AWS_INSPECTOR_SCAN_TYPES=value)
    assert code == 1 and files == [] and status["code"] == "bad_config" and calls == []


# --- Contract ----------------------------------------------------------------


def test_pipeline_asset_column_is_a_report_column():
    meta = yaml.safe_load((FETCHER_DIR / "fetcher.yaml").read_text())
    assert meta["pipeline"] == {"type": "vulnerability", "id_scheme": "aws-arn", "asset_id_field": "Resource ARN"}
    assert meta["pipeline"]["asset_id_field"] == report.ASSET_COLUMN
    assert report.ASSET_COLUMN in report.CSV_COLUMNS


def test_readme_documents_every_column_in_order():
    readme = (FETCHER_DIR / "README.md").read_text()
    section = readme.split("## Columns", 1)[1].split("\n## ", 1)[0]
    documented = [line.split("|")[1].strip() for line in section.splitlines() if line.startswith("| ") and "---" not in line]
    assert documented[1:] == report.CSV_COLUMNS
