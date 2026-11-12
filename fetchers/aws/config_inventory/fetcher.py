"""Collect a complete asset inventory from an AWS Config aggregator."""

import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure

logger = logging.getLogger("aws_config_inventory")
OUTPUT = "aws_config_inventory.json"


def aws(operation, *arguments):
    command = [
        "aws",
        "configservice",
        operation,
        *arguments,
        "--output",
        "json",
        "--no-paginate",
        "--no-cli-pager",
    ]
    # An explicit profile must take precedence over ambient static credentials.
    if os.environ.get("AWS_PROFILE"):
        command += ["--profile", os.environ["AWS_PROFILE"]]
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if region:
        command += ["--region", region]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise ValueError(f"{operation} failed: {result.stderr.strip()[:1000]}")
    response = json.loads(result.stdout)
    if not isinstance(response, dict):
        raise ValueError(f"{operation} returned a non-object response")
    return response


def pages(operation, key, *arguments):
    token = None
    seen = set()
    while True:
        extra = ["--next-token", token] if token else []
        response = aws(operation, *arguments, *extra)
        values = response.get(key)
        if not isinstance(values, list):
            raise ValueError(f"{operation} returned no {key} list")
        yield from values
        token = response.get("NextToken")
        if not token:
            return
        if not isinstance(token, str) or token in seen:
            raise ValueError(
                f"{operation} repeated or returned an invalid pagination token"
            )
        seen.add(token)


def expression(resource_types):
    query = (
        "SELECT accountId, arn, awsRegion, resourceId, resourceName, "
        "resourceType, configuration, tags, configurationItemCaptureTime"
    )
    if resource_types.strip() != "*":
        types = sorted(set(value.strip() for value in resource_types.split(",")))
        if not types or any(
            not re.fullmatch(r"AWS::[A-Za-z0-9]+::[A-Za-z0-9]+", t) for t in types
        ):
            raise ValueError(
                "resource_types must be * or comma-separated AWS resource types"
            )
        query += " WHERE resourceType IN (" + ", ".join(f"'{t}'" for t in types) + ")"
    return query


def object_value(value):
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ValueError("Resource configuration must be an object")
    return value


def record(resource, partition):
    resource = object_value(resource)
    required = ("accountId", "awsRegion", "resourceType", "resourceId")
    if any(
        not isinstance(resource.get(k), str) or not resource[k].strip()
        for k in required
    ):
        raise ValueError("Resource is missing its account, region, type or ID")
    arn = resource.get("arn") or None
    if arn and (not isinstance(arn, str) or not arn.startswith(f"arn:{partition}:")):
        raise ValueError("Resource ARN does not match the aggregator partition")
    config = object_value(resource.get("configuration", {}))
    tags = resource.get("tags", {})
    if isinstance(tags, list):
        tags = {tag["key"]: tag["value"] for tag in tags}
    if not isinstance(tags, dict):
        raise ValueError("Resource tags must be an object or list")
    kind = resource["resourceType"]
    if kind not in {
        "AWS::EC2::Instance",
        "AWS::EC2::NetworkInterface",
        "AWS::RDS::DBInstance",
        "AWS::DynamoDB::Table",
        "AWS::ElasticLoadBalancing::LoadBalancer",
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "AWS::WorkSpaces::Workspace",
    }:
        config = {}
    # Some Config resource types have no ARN; this tuple is their native identity.
    identity = arn or "aws-config:" + ":".join(
        [partition, *(resource[k] for k in required)]
    )
    addresses = set()
    subnets = set()
    macs = set()
    for item in [config, *(config.get("networkInterfaces") or [])]:
        for key in ("privateIpAddress", "publicIpAddress", "ipAddress"):
            if item.get(key):
                addresses.add(item[key])
        if item.get("subnetId"):
            subnets.add(item["subnetId"])
        if item.get("macAddress"):
            macs.add(item["macAddress"])
        if (item.get("association") or {}).get("publicIp"):
            addresses.add(item["association"]["publicIp"])
        for ip in item.get("privateIpAddresses") or []:
            if ip.get("privateIpAddress"):
                addresses.add(ip["privateIpAddress"])
            if (ip.get("association") or {}).get("publicIp"):
                addresses.add(ip["association"]["publicIp"])
        for ip in item.get("ipv6Addresses") or []:
            if ip.get("ipv6Address"):
                addresses.add(ip["ipv6Address"])
    subnet_group = config.get("dBSubnetGroup") or {}
    for subnet in subnet_group.get("subnets") or []:
        if subnet.get("subnetIdentifier"):
            subnets.add(subnet["subnetIdentifier"])
    for subnet in config.get("subnets") or []:
        if isinstance(subnet, str):
            subnets.add(subnet)
    for zone in config.get("availabilityZones") or []:
        if isinstance(zone, dict) and zone.get("subnetId"):
            subnets.add(zone["subnetId"])
    state = config.get("state")
    status = (
        state.get("name") or state.get("code") if isinstance(state, dict) else state
    )
    endpoint = config.get("endpoint") or {}
    hostname = (
        config.get("privateDnsName")
        or config.get("publicDnsName")
        or config.get("dNSName")
        or config.get("dnsName")
        or endpoint.get("address")
    )
    return {
        "unique_asset_identifier": identity,
        "arn": arn,
        "account_id": resource["accountId"],
        "region": resource["awsRegion"],
        "resource_type": kind,
        "source_identifier": resource["resourceId"],
        "component": tags.get("Name")
        or resource.get("resourceName")
        or resource["resourceId"],
        "asset_type": kind,
        "status": status or config.get("dBInstanceStatus") or config.get("tableStatus"),
        "ip_addresses": sorted(addresses),
        "primary_ip_address": config.get("privateIpAddress")
        or next(iter(sorted(addresses)), None),
        "host_ips": ", ".join(sorted(addresses)),
        "hostname": hostname or None,
        "subnet_ids": sorted(subnets),
        "subnet": ", ".join(sorted(subnets)),
        "network_id": config.get("vpcId") or subnet_group.get("vpcId"),
        "mac_addresses": sorted(macs),
        "mac_address": ", ".join(sorted(macs)),
        "is_virtual": True
        if kind in {"AWS::EC2::Instance", "AWS::WorkSpaces::Workspace"}
        else None,
        "internet_facing": (
            config.get("scheme") == "internet-facing"
            if config.get("scheme")
            else config.get("publiclyAccessible")
        ),
        "security_baseline": config.get("imageId"),
        "operating_system": config.get("platformDetails") or config.get("platform"),
        "owner": tags.get("Owner") or tags.get("owner"),
        "tags": tags,
        "last_update": resource.get("configurationItemCaptureTime"),
    }


def collect(name, resource_types, require_all_regions=False):
    query = expression(resource_types)
    aggregators = list(
        pages(
            "describe-configuration-aggregators",
            "ConfigurationAggregators",
            "--configuration-aggregator-names",
            name,
        )
    )
    if (
        len(aggregators) != 1
        or aggregators[0].get("ConfigurationAggregatorName") != name
    ):
        raise ValueError("Expected exactly the requested Config aggregator")
    aggregator = aggregators[0]
    arn = aggregator["ConfigurationAggregatorArn"]
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[2] != "config":
        raise ValueError("Invalid aggregator ARN")
    sources = (
        [aggregator["OrganizationAggregationSource"]]
        if aggregator.get("OrganizationAggregationSource")
        else aggregator.get("AccountAggregationSources", [])
    )
    if not sources:
        raise ValueError("Aggregator has no configured sources")
    all_regions = all(source.get("AllAwsRegions") is True for source in sources)
    if require_all_regions and not all_regions:
        raise ValueError("Aggregator must include all AWS regions")
    arguments = ("--configuration-aggregator-name", name)
    statuses = list(
        pages(
            "describe-configuration-aggregator-sources-status",
            "AggregatedSourceStatusList",
            *arguments,
        )
    )
    if not statuses or any(s.get("LastUpdateStatus") != "SUCCEEDED" for s in statuses):
        raise ValueError("Aggregator has missing, failed or outdated source status")
    records = {}
    for raw in pages(
        "select-aggregate-resource-config", "Results", *arguments, "--expression", query
    ):
        asset = record(raw, parts[1])
        identifier = asset["unique_asset_identifier"]
        if identifier in records:
            raise ValueError(f"Inventory repeats an asset identifier: {identifier}")
        records[identifier] = asset
    if not records:
        raise ValueError("Refusing an empty inventory")
    return {
        "scope": {
            "aggregator_arn": arn,
            "partition": parts[1],
            "all_regions": all_regions,
            "sources": sources,
            "resource_types": resource_types,
            "query": query,
        },
        "source_statuses": statuses,
        "data": [records[k] for k in sorted(records)],
    }


def main():
    logging.basicConfig(level=logging.INFO)
    output = Path(os.environ.get("EVIDENCE_DIR", "./evidence")) / OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "records_included": False,
        "record_count": 0,
        "data": [],
    }
    try:
        required = os.environ.get(
            "CONFIG_INVENTORY_REQUIRE_ALL_REGIONS", "false"
        ).lower()
        if required not in {"true", "false"}:
            raise ValueError("require_all_regions must be true or false")
        payload.update(
            collect(
                os.environ["CONFIG_INVENTORY_AGGREGATOR"],
                os.environ.get("CONFIG_INVENTORY_RESOURCE_TYPES", "*"),
                required == "true",
            )
        )
        payload.update(records_included=True, record_count=len(payload["data"]))
    except (
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        payload.update(records_included=False, data=[], error=str(error))
        payload["metadata"] = {
            "partial_failure": True,
            "api_failures": [
                {
                    "operation": "collect Config inventory",
                    "type": type(error).__name__,
                    "message": str(error),
                }
            ],
        }
        output.write_text(json.dumps(payload, indent=2))
        report_failure(f"Inventory withheld: {error}", "partial_failure")
        return 1
    payload["completed_at"] = datetime.now(timezone.utc).isoformat()
    output.write_text(json.dumps(payload, indent=2))
    logger.info("Inventory saved to %s (%d records)", output, payload["record_count"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
