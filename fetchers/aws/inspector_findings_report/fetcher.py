#!/usr/bin/env python3
"""Every active Amazon Inspector finding as a CSV for Paramify's assessment intake.

Covers EC2 instances, ECR images, Lambda functions and Lambda code in one account
and region. Each row's `Resource ARN` is the ARN aws_config_inventory writes as
`unique_asset_identifier` for the same resource, so findings link to Inventory.
Like aws_inspector_ecr_report, this is an API-built CSV, not an Inspector export.
See README.md for the columns. Every AWS request is read-only; no S3 export, KMS
key or Paramify credential is needed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
from collections import Counter
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from inspector_common import (
    SEVERITIES,
    Aws,
    CollectionError,
    equal,
    first_sighting,
    nonempty_strings,
    publish,
    query_findings,
    read_bool,
    read_list,
    read_severity,
    run,
    severities_at_or_above,
    write_csv,
)

NAME = "aws_inspector_findings_report"
EC2, ECR, LAMBDA = "AWS_EC2_INSTANCE", "AWS_ECR_CONTAINER_IMAGE", "AWS_LAMBDA_FUNCTION"
PACKAGE, CODE, NETWORK = "PACKAGE_VULNERABILITY", "CODE_VULNERABILITY", "NETWORK_REACHABILITY"
# Scan type -> (BatchGetAccountStatus resourceState key, resource type, finding
# type or None for every type). One ListFindings query per selected scan type.
SCAN_TYPES = {
    "EC2": ("ec2", EC2, None),
    "ECR": ("ecr", ECR, None),
    "LAMBDA": ("lambda", LAMBDA, PACKAGE),
    "LAMBDA_CODE": ("lambdaCode", LAMBDA, CODE),
}
CSV_COLUMNS = [
    "Finding ARN",
    "Finding Type",
    "Vulnerability ID",
    "Title",
    "Description",
    "Severity",
    "Status",
    "AWS Account ID",
    "Region",
    "Resource Type",
    "Resource ARN",
    "Resource ID",
    "Resource Name",
    "Image Digest",
    "Image Tags",
    "First Observed At",
    "Last Observed At",
    "Updated At",
    "Fix Available",
    "Exploit Available",
    "Inspector Score",
    "EPSS Score",
    "CVSS",
    "Affected Packages",
    "Affected Code",
    "Network Reachability",
    "Remediation",
    "Reference URLs",
    "Related Vulnerabilities",
]
ASSET_COLUMN = "Resource ARN"
FINDING_ARN = re.compile(r"arn:([^:]+):inspector2:([^:]+):(\d{12}):finding/.+")
INSTANCE_ID = re.compile(r"i-[0-9a-f]{8,17}")
ACCOUNT_ID = re.compile(r"\d{12}")


def scan_type_of(finding_type, resource_type):
    """The scan type that produces this finding, or None when none does."""
    for name, (_key, rtype, ftype) in SCAN_TYPES.items():
        if resource_type == rtype and ftype in (None, finding_type):
            return name
    return None


def read_scope():
    """Every setting, validated before any AWS request."""
    scan_types = [t.upper() for t in read_list("AWS_INSPECTOR_SCAN_TYPES")]
    unknown = sorted(set(scan_types) - set(SCAN_TYPES))
    if unknown:
        raise CollectionError(
            f"AWS_INSPECTOR_SCAN_TYPES has unknown values {unknown}; use {', '.join(SCAN_TYPES)}",
            "bad_config",
        )
    return {
        "scan_types": sorted(set(scan_types), key=list(SCAN_TYPES).index),
        "min_severity": read_severity("AWS_INSPECTOR_MIN_SEVERITY"),
    }


def bad_resource(finding, problem):
    return CollectionError(f"Inspector finding {finding.get('findingArn')}: {problem}")


def resource_identity(finding, region):
    """(Resource ARN, Resource Name) for a finding's single resource.

    The ARN has exactly the form aws_config_inventory writes as
    unique_asset_identifier: AWS Config's own ARN for the EC2 instance, the
    unqualified Lambda function, or the ECR repository (Config records
    repositories, not images).
    """
    match = FINDING_ARN.fullmatch(finding["findingArn"])
    if not match:
        raise bad_resource(finding, "the finding ARN is not an Inspector finding ARN")
    partition, finding_region, account = match.groups()
    resource = finding["resources"][0]
    if resource.get("partition", partition) != partition:
        raise bad_resource(finding, "the resource partition differs from the finding's")
    if account != finding["awsAccountId"] or finding_region != region or resource.get("region") != region:
        raise bad_resource(finding, "the finding or resource is outside the requested account/region")
    rid, kind = resource.get("id"), resource.get("type")
    details = resource.get("details") or {}
    if not nonempty_strings(rid):
        raise bad_resource(finding, "the resource has no ID")

    if kind == EC2:
        # Inspector names an instance by its ID; Config by its ARN. Accept the
        # ARN too, in case Inspector ever reports one.
        instance = rid.rsplit("/", 1)[-1] if rid.startswith("arn:") else rid
        arn = f"arn:{partition}:ec2:{region}:{account}:instance/{instance}"
        if not INSTANCE_ID.fullmatch(instance) or rid not in (instance, arn):
            raise bad_resource(finding, f"unexpected EC2 instance ID {rid!r}")
        tags = resource.get("tags") or {}
        return arn, tags.get("Name", "") if isinstance(tags, dict) else ""

    if kind == LAMBDA:
        # Inspector's ID is the function ARN with a version qualifier
        # (`:$LATEST` or a number); Config's ARN is unqualified.
        parts = rid.split(":")
        if len(parts) not in (7, 8) or parts[:6] != ["arn", partition, "lambda", region, account, "function"] or not parts[6]:
            raise bad_resource(finding, f"unexpected Lambda function ID {rid!r}")
        arn = ":".join(parts[:7])
        name = (details.get("awsLambdaFunction") or {}).get("functionName") or parts[6]
        if name not in (parts[6], arn, rid):
            raise bad_resource(finding, "the Lambda function name differs from its ID")
        return arn, parts[6]

    if kind == ECR:
        # Config records the repository, not the image: map the image to it.
        image = details.get("awsEcrContainerImage") or {}
        repository, registry = image.get("repositoryName"), image.get("registry") or account
        if not nonempty_strings(repository, image.get("imageHash")) or not ACCOUNT_ID.fullmatch(str(registry)):
            raise bad_resource(finding, "the ECR image has no repository, registry or digest")
        return f"arn:{partition}:ecr:{region}:{registry}:repository/{repository}", repository

    raise bad_resource(finding, f"unexpected resource type {kind!r}")


def check_finding(finding, account, region, scan_types):
    """Raise unless the finding is in scope and has everything its row needs."""
    if finding.get("awsAccountId") != account or finding.get("status") != "ACTIVE":
        raise CollectionError("Inspector returned a finding outside the requested account/status scope")
    if not nonempty_strings(finding.get("findingArn")):
        raise CollectionError("Inspector returned a finding without its ARN")
    resources = finding.get("resources")
    if not isinstance(resources, list) or len(resources) != 1 or not isinstance(resources[0], dict):
        # The finding ARN is the row identity, so one finding is one resource.
        raise bad_resource(finding, "expected exactly one affected resource")
    kind = finding.get("type")
    if scan_type_of(kind, resources[0].get("type")) not in scan_types:
        raise bad_resource(finding, f"{kind} on {resources[0].get('type')} is outside the selected scan types")
    if kind == PACKAGE and not nonempty_strings((finding.get("packageVulnerabilityDetails") or {}).get("vulnerabilityId")):
        raise bad_resource(finding, "the package finding has no vulnerability ID")
    if kind == CODE:
        code = finding.get("codeVulnerabilityDetails") or {}
        if not (nonempty_strings(code.get("detectorId")) or nonempty_strings(code.get("ruleId"))):
            raise bad_resource(finding, "the code finding has no detector or rule ID")
    if kind == NETWORK and not isinstance(finding.get("networkReachabilityDetails"), dict):
        raise bad_resource(finding, "the network reachability finding has no details")
    resource_identity(finding, region)


def csv_row(finding, region):
    resource = finding["resources"][0]
    arn, name = resource_identity(finding, region)
    kind = finding["type"]
    package = finding.get("packageVulnerabilityDetails") or {}
    code = finding.get("codeVulnerabilityDetails") or {}
    image = (resource.get("details") or {}).get("awsEcrContainerImage") or {}
    if kind == PACKAGE:
        vulnerability = package["vulnerabilityId"]
        references, related = package.get("referenceUrls", []), package.get("relatedVulnerabilities", [])
    elif kind == CODE:
        vulnerability = code.get("detectorId") or code["ruleId"]
        references, related = code.get("referenceUrls", []), code.get("cwes", [])
    else:
        vulnerability, references, related = "", None, None
    location = None
    if kind == CODE:
        location = dict(code.get("filePath") or {})
        for key in ("detectorName", "ruleId", "sourceLambdaLayerArn"):
            if code.get(key):
                location[key] = code[key]
    return {
        "Finding ARN": finding["findingArn"],
        "Finding Type": kind,
        "Vulnerability ID": vulnerability,
        "Title": finding.get("title", ""),
        "Description": finding.get("description", ""),
        "Severity": finding.get("severity", "UNKNOWN"),
        "Status": finding["status"],
        "AWS Account ID": finding["awsAccountId"],
        "Region": region,
        "Resource Type": resource["type"],
        "Resource ARN": arn,
        "Resource ID": resource["id"],
        "Resource Name": name,
        "Image Digest": image.get("imageHash", "") if resource["type"] == ECR else "",
        "Image Tags": json.dumps(image.get("imageTags", [])) if resource["type"] == ECR else "",
        "First Observed At": finding.get("firstObservedAt", ""),
        "Last Observed At": finding.get("lastObservedAt", ""),
        "Updated At": finding.get("updatedAt", ""),
        "Fix Available": finding.get("fixAvailable", ""),
        "Exploit Available": finding.get("exploitAvailable", ""),
        "Inspector Score": finding.get("inspectorScore", ""),
        "EPSS Score": (finding.get("epss") or {}).get("score", ""),
        "CVSS": json.dumps(package.get("cvss", [])) if kind == PACKAGE else "",
        "Affected Packages": json.dumps(package.get("vulnerablePackages", [])) if kind == PACKAGE else "",
        "Affected Code": json.dumps(location, sort_keys=True) if location is not None else "",
        "Network Reachability": json.dumps(finding["networkReachabilityDetails"], sort_keys=True)
        if kind == NETWORK
        else "",
        "Remediation": (finding.get("remediation") or {}).get("recommendation", {}).get("text", ""),
        "Reference URLs": json.dumps(references) if references is not None else "",
        "Related Vulnerabilities": json.dumps(related) if related is not None else "",
    }


def collect(aws, scope):
    """Every active finding of the selected scan types, as CSV rows sorted by finding ARN.

    All or nothing: any failed call, malformed page or out-of-scope finding raises,
    so no partial report is ever written.
    """
    identity = aws.call("sts", "get-caller-identity")
    account = identity.get("Account")
    if not nonempty_strings(account, identity.get("Arn")) or not ACCOUNT_ID.fullmatch(account):
        raise CollectionError("STS returned no valid account identity")

    status = aws.call("inspector2", "batch-get-account-status", accountIds=[account])
    accounts = status.get("accounts") or []
    if status.get("failedAccounts") or len(accounts) != 1 or accounts[0].get("accountId") != account:
        raise CollectionError("Inspector could not return this account's scanning status")
    resource_state = accounts[0].get("resourceState") or {}
    # A missing status counts as DISABLED, as in aws_inspector_vulnerability_scanning.
    states = {
        name: (resource_state.get(key) or {}).get("status") or "DISABLED"
        for name, (key, _rtype, _ftype) in SCAN_TYPES.items()
    }
    enabled = [name for name, state in states.items() if state == "ENABLED"]
    shown = ", ".join(f"{name} {state}" for name, state in states.items())
    if scope["scan_types"]:
        off = [name for name in scope["scan_types"] if name not in enabled]
        if off:
            raise CollectionError(
                f"Inspector scanning is not enabled for {', '.join(off)} ({shown}); no issue report written",
                "bad_config",
            )
        selected = list(scope["scan_types"])
    else:
        selected = enabled
        if not selected:
            raise CollectionError(
                f"Inspector scanning is not enabled for any resource type ({shown}); no issue report written",
                "bad_config",
            )

    queries = []
    for name in selected:
        _key, rtype, ftype = SCAN_TYPES[name]
        query = {
            "awsAccountId": equal([account]),
            "findingStatus": equal(["ACTIVE"]),
            "resourceType": equal([rtype]),
        }
        if ftype:
            query["findingType"] = equal([ftype])
        if scope["min_severity"]:
            query["severity"] = equal(severities_at_or_above(scope["min_severity"]))
        queries.append(query)

    rows, seen = {}, {}
    with closing(query_findings(aws, queries)) as found:
        for finding in found:
            check_finding(finding, account, aws.region, selected)
            if first_sighting(seen, finding):
                rows[finding["findingArn"]] = csv_row(finding, aws.region)
    return {
        "account_id": account,
        "region": aws.region,
        "states": states,
        "scan_types": selected,
        "rows": [rows[arn] for arn in sorted(rows)],
    }


def output_name(account, region, scope):
    """One file name per target: account, region and a hash of profile and scope."""
    keyed = {"profile": os.environ.get("AWS_PROFILE", ""), **scope}
    suffix = hashlib.sha256(json.dumps(keyed, sort_keys=True).encode()).hexdigest()[:12]
    target = re.sub(r"[^A-Za-z0-9._-]", "_", f"{account}_{region}_{suffix}")
    return f"{NAME}_{target}.csv"


def main():
    def body():
        scope = read_scope()
        allow_empty = read_bool("AWS_INSPECTOR_ALLOW_EMPTY")
        result = collect(Aws(), scope)
        rows = result["rows"]
        states = result["states"]
        skipped = ", ".join(f"{n} ({states[n]})" for n in SCAN_TYPES if n not in result["scan_types"])
        logging.info(
            "Scan types collected: %s. Not collected: %s",
            ", ".join(result["scan_types"]),
            skipped or "none",
        )
        by_type = Counter(r["Resource Type"] for r in rows)
        by_severity = Counter(r["Severity"] for r in rows)
        logging.info(
            "Findings: %d (%s; %s)",
            len(rows),
            ", ".join(f"{k} {by_type[k]}" for k in sorted(by_type)) or "none",
            ", ".join(f"{s} {by_severity[s]}" for s in SEVERITIES if by_severity[s]) or "none",
        )
        if not rows and not allow_empty:
            raise CollectionError(
                "Inspector returned zero findings; set allow_empty=true only after verifying scope",
                "bad_config",
            )
        dest = publish(
            Path(os.environ.get("EVIDENCE_DIR", "./evidence")),
            output_name(result["account_id"], result["region"], scope),
            lambda stream: write_csv(stream, CSV_COLUMNS, rows),
        )
        logging.info("Saved %s", dest)
        return 0

    return run(body)


if __name__ == "__main__":
    raise SystemExit(main())
