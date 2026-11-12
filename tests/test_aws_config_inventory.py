import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from framework import api, inventory

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "config_inventory", ROOT / "fetchers/aws/config_inventory/fetcher.py"
)
fetcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetcher)


@pytest.fixture(
    params=[
        ("aws", "us-east-1", "ap-southeast-2"),
        ("aws-us-gov", "us-gov-west-1", "us-gov-east-1"),
    ]
)
def estate(request):
    partition, region, other_region = request.param
    asset = {
        "arn": f"arn:{partition}:ec2:{other_region}:222222222222:instance/i-example",
        "accountId": "222222222222",
        "awsRegion": other_region,
        "resourceType": "AWS::EC2::Instance",
        "resourceId": "i-example",
        "configurationItemCaptureTime": "2026-01-01T00:00:00Z",
        "configuration": {
            "privateIpAddress": "10.0.0.1",
            "subnetId": "subnet-a",
            "vpcId": "vpc-a",
            "networkInterfaces": [
                {
                    "privateIpAddresses": [
                        {
                            "privateIpAddress": "10.0.0.2",
                            "association": {"publicIp": "192.0.2.1"},
                        }
                    ],
                    "ipv6Addresses": [{"ipv6Address": "2001:db8::1"}],
                    "subnetId": "subnet-b",
                    "macAddress": "02:00:00:00:00:01",
                }
            ],
            "state": {"name": "running"},
            "imageId": "ami-example",
        },
        "tags": [{"key": "Name", "value": "unexpected-host"}],
    }
    return {
        "partition": partition,
        "region": region,
        "asset": asset,
        "describe-configuration-aggregators": {
            "ConfigurationAggregators": [
                {
                    "ConfigurationAggregatorName": "inventory",
                    "ConfigurationAggregatorArn": f"arn:{partition}:config:{region}:111111111111:config-aggregator/config-aggregator-example",
                    "OrganizationAggregationSource": {
                        "AllAwsRegions": True,
                        "RoleArn": "role",
                    },
                }
            ]
        },
        "describe-configuration-aggregator-sources-status": {
            "AggregatedSourceStatusList": [
                {
                    "SourceId": "o-example",
                    "AwsRegion": other_region,
                    "LastUpdateStatus": "SUCCEEDED",
                }
            ]
        },
        "select-aggregate-resource-config": {"Results": [json.dumps(asset)]},
    }


def stub(monkeypatch, estate):
    calls = []

    def call(operation, *arguments):
        calls.append((operation, arguments))
        return estate[operation]

    monkeypatch.setattr(fetcher, "aws", call)
    return calls


def test_collects_other_accounts_and_regions_in_both_partitions(monkeypatch, estate):
    calls = stub(monkeypatch, estate)
    payload = fetcher.collect("inventory", "*", True)
    assert payload["scope"]["partition"] == estate["partition"]
    assert payload["scope"]["all_regions"] is True
    assert "WHERE" not in payload["scope"]["query"]
    assert len(calls) == 3
    (asset,) = payload["data"]
    assert asset["unique_asset_identifier"] == estate["asset"]["arn"]
    assert asset["region"] != estate["region"]
    assert asset["account_id"] == "222222222222"
    assert asset["component"] == "unexpected-host"
    assert asset["ip_addresses"] == ["10.0.0.1", "10.0.0.2", "192.0.2.1", "2001:db8::1"]
    assert asset["subnet_ids"] == ["subnet-a", "subnet-b"]
    assert asset["network_id"] == "vpc-a"
    assert asset["last_update"] == "2026-01-01T00:00:00Z"
    assert asset["internet_facing"] is None
    assert asset["operating_system"] is None


@pytest.mark.parametrize(
    "operation,key",
    [
        ("describe-configuration-aggregators", "ConfigurationAggregators"),
        (
            "describe-configuration-aggregator-sources-status",
            "AggregatedSourceStatusList",
        ),
        ("select-aggregate-resource-config", "Results"),
    ],
)
def test_paginates_every_operation(monkeypatch, operation, key):
    calls = []

    def call(op, *args):
        calls.append((op, args))
        return {key: [2]} if "--next-token" in args else {key: [1], "NextToken": "next"}

    monkeypatch.setattr(fetcher, "aws", call)
    assert list(fetcher.pages(operation, key)) == [1, 2]
    assert calls[-1][1] == ("--next-token", "next")


@pytest.mark.parametrize(
    "response", [{}, {"Results": {}}, {"Results": [], "NextToken": "repeat"}]
)
def test_rejects_broken_pagination(monkeypatch, response):
    monkeypatch.setattr(fetcher, "aws", lambda *args: response)
    with pytest.raises(ValueError):
        list(fetcher.pages("query", "Results"))


@pytest.mark.parametrize("status", ["FAILED", "OUTDATED", None])
def test_rejects_unhealthy_sources(monkeypatch, estate, status):
    estate["describe-configuration-aggregator-sources-status"][
        "AggregatedSourceStatusList"
    ][0]["LastUpdateStatus"] = status
    stub(monkeypatch, estate)
    with pytest.raises(ValueError, match="source status"):
        fetcher.collect("inventory", "*")


def test_all_regions_guard_and_account_scoped_aggregator(monkeypatch, estate):
    agg = estate["describe-configuration-aggregators"]["ConfigurationAggregators"][0]
    del agg["OrganizationAggregationSource"]
    agg["AccountAggregationSources"] = [
        {"AccountIds": ["222222222222"], "AwsRegions": [estate["region"]]}
    ]
    stub(monkeypatch, estate)
    with pytest.raises(ValueError, match="all AWS regions"):
        fetcher.collect("inventory", "*", True)
    assert fetcher.collect("inventory", "*")["scope"]["all_regions"] is False
    agg["AccountAggregationSources"][0]["AllAwsRegions"] = True
    assert fetcher.collect("inventory", "*", True)["scope"]["all_regions"] is True


@pytest.mark.parametrize(
    "change",
    ["empty", "duplicate", "malformed", "wrong_partition", "missing_id", "no_status"],
)
def test_withholds_every_record_on_failure(monkeypatch, tmp_path, estate, change):
    results = estate["select-aggregate-resource-config"]["Results"]
    if change == "empty":
        results.clear()
    elif change == "duplicate":
        results *= 2
    elif change == "malformed":
        results.append("not JSON")
    elif change in {"wrong_partition", "missing_id"}:
        broken = dict(estate["asset"])
        broken["arn" if change == "wrong_partition" else "resourceId"] = (
            "arn:wrong:ec2:region:account:id" if change == "wrong_partition" else ""
        )
        results.append(json.dumps(broken))
    else:
        estate["describe-configuration-aggregator-sources-status"][
            "AggregatedSourceStatusList"
        ] = []
    stub(monkeypatch, estate)
    monkeypatch.setenv("CONFIG_INVENTORY_AGGREGATOR", "inventory")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status"))
    assert fetcher.main() == 1
    payload = json.loads((tmp_path / fetcher.OUTPUT).read_text())
    assert payload["data"] == []
    assert payload["records_included"] is False
    assert json.loads((tmp_path / "status").read_text())["code"] == "partial_failure"


def test_later_page_failure_does_not_upload_partial_inventory(
    monkeypatch, tmp_path, estate
):
    def call(operation, *args):
        if "--next-token" in args:
            raise subprocess.TimeoutExpired("aws", 120)
        response = dict(estate[operation])
        if operation == "select-aggregate-resource-config":
            response["NextToken"] = "next"
        return response

    monkeypatch.setattr(fetcher, "aws", call)
    monkeypatch.setenv("CONFIG_INVENTORY_AGGREGATOR", "inventory")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    assert fetcher.main() == 1
    payload = json.loads((tmp_path / fetcher.OUTPUT).read_text())
    assert payload["data"] == []
    assert not inventory.check(payload, 1)["complete"]


def test_native_identity_without_arn_is_partition_specific(estate):
    asset = dict(
        estate["asset"],
        arn="",
        resourceType="AWS::Example::Resource",
        configuration="{}",
        tags={},
    )
    result = fetcher.record(asset, estate["partition"])
    assert result["unique_asset_identifier"].startswith(
        f"aws-config:{estate['partition']}:222222222222:"
    )
    assert result["hostname"] is None
    assert result["is_virtual"] is None


def test_rds_without_endpoint_is_retained(estate):
    asset = dict(
        estate["asset"],
        resourceType="AWS::RDS::DBInstance",
        configuration={
            "dBInstanceStatus": "creating",
            "publiclyAccessible": False,
            "dBSubnetGroup": {
                "vpcId": "vpc-db",
                "subnets": [{"subnetIdentifier": "subnet-db"}],
            },
        },
    )
    result = fetcher.record(asset, estate["partition"])
    assert result["hostname"] is None
    assert result["status"] == "creating"
    assert result["subnet"] == "subnet-db"
    assert result["internet_facing"] is False


@pytest.mark.parametrize(
    "types",
    ["", "AWS::EC2::Instance' OR 1=1", "AWS::EC2::Instance,", "*,AWS::EC2::Instance"],
)
def test_invalid_type_filter_is_rejected(types):
    with pytest.raises(ValueError):
        fetcher.expression(types)


def test_type_filter_never_filters_accounts_or_regions():
    query = fetcher.expression("AWS::EC2::Instance,AWS::RDS::DBInstance")
    assert (
        query.split(" WHERE ")[1]
        == "resourceType IN ('AWS::EC2::Instance', 'AWS::RDS::DBInstance')"
    )


def test_cli_uses_profile_and_region_without_constructing_endpoints(
    monkeypatch, estate
):
    monkeypatch.setenv("AWS_PROFILE", "inventory-reader")
    monkeypatch.setenv("AWS_REGION", estate["region"])
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert kwargs["timeout"] == 120
        return SimpleNamespace(returncode=0, stdout="{}")

    monkeypatch.setattr(fetcher.subprocess, "run", run)
    fetcher.aws("describe-configuration-aggregators")
    assert calls[0][-4:] == [
        "--profile",
        "inventory-reader",
        "--region",
        estate["region"],
    ]
    assert "--endpoint-url" not in calls[0]
    assert "--no-paginate" in calls[0]


def test_cli_failure_is_not_treated_as_an_empty_page(monkeypatch):
    monkeypatch.setattr(
        fetcher.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stderr="AccessDenied"),
    )
    with pytest.raises(ValueError, match="AccessDenied"):
        fetcher.aws("select-aggregate-resource-config")


def test_real_runner_discovers_and_envelopes_inventory(monkeypatch, tmp_path, estate):
    fixture = tmp_path / "responses.json"
    fixture.write_text(json.dumps(estate))
    binary = tmp_path / "aws"
    binary.write_text(
        "#!/usr/bin/env python3\nimport json,sys\n"
        f"print(json.dumps(json.load(open({str(fixture)!r}))[sys.argv[2]]))\n"
    )
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    root = tmp_path / "repo"
    for relative in [
        "fetchers/aws/config_inventory",
        "fetchers/_lib",
        "fetchers/_categories",
        "framework/schemas",
    ]:
        shutil.copytree(ROOT / relative, root / relative)
    summary = api.run(
        {
            "run": {
                "output_dir": str(tmp_path / "out"),
                "fetchers": [
                    {
                        "use": "aws_config_inventory",
                        "config": {
                            "aggregator_name": "inventory",
                            "require_all_regions": True,
                            "region": estate["region"],
                        },
                    }
                ],
            }
        },
        root,
    )
    envelope = json.loads((Path(summary["run_dir"]) / fetcher.OUTPUT).read_text())
    assert envelope["metadata"]["inventory"]["complete"] is True
    assert envelope["payload"]["scope"]["partition"] == estate["partition"]
