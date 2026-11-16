"""Read ECR inventory, Inspector coverage and findings for one account/region.

Uses the AWS CLI credential chain already installed for this category. Every
request is read-only. Evidence and issue reports share filters and pagination;
neither collector contacts Paramify. The existing uploader owns intake/jobs.
"""

from __future__ import annotations

import csv
import errno
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure

RESOURCE_TYPE = "AWS_ECR_CONTAINER_IMAGE"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNTRIAGED")
CSV_COLUMNS = [
    "ID",
    "Finding ARN",
    "Vulnerability ID",
    "Title",
    "Description",
    "Severity",
    "Status",
    "AWS Account ID",
    "Region",
    "Asset ID",
    "Repository",
    "Image Digest",
    "Image Tags",
    "First Observed At",
    "Last Observed At",
    "Updated At",
    "Fix Available",
    "Exploit Available",
    "Inspector Score",
    "CVSS",
    "Affected Packages",
    "Remediation",
    "Reference URLs",
    "Related Vulnerabilities",
]


class CollectionError(Exception):
    def __init__(self, message, code="partial_failure"):
        super().__init__(message)
        self.code = code


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def error_code(stderr):
    for pattern, code in (
        (
            r"ExpiredToken|InvalidClientTokenId|UnrecognizedClient|Unable to locate credentials|SSO.*expired",
            "auth_failed",
        ),
        (r"AccessDenied|Unauthorized|not authorized", "not_authorized"),
        (r"Throttl|TooManyRequests|RequestLimitExceeded", "rate_limited"),
        (r"endpoint URL|ConnectTimeout|ReadTimeout|Could not connect", "target_unreachable"),
        (r"ValidationException|InvalidParameter|Invalid region", "bad_config"),
    ):
        if re.search(pattern, stderr, re.I):
            return code
    return "partial_failure"


class Aws:
    def __init__(self):
        # The runner maps target.region to AWS_DEFAULT_REGION; pin it explicitly
        # so an ambient AWS_REGION cannot override a manifest target.
        self.region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION")
        if not self.region:
            self.region = self.run(["configure", "get", "region"]).strip()
        if not self.region:
            raise CollectionError("Set a region in the target or AWS configuration", "bad_config")

    def run(self, args):
        try:
            response = subprocess.run(
                ["aws", *args],
                capture_output=True,
                text=True,
                timeout=180,
                env={
                    **os.environ,
                    "AWS_PAGER": "",
                    "AWS_RETRY_MODE": "standard",
                    "AWS_MAX_ATTEMPTS": "4",
                },
            )
        except subprocess.TimeoutExpired as exc:
            raise CollectionError("AWS request timed out", "target_unreachable") from exc
        except OSError as exc:
            raise CollectionError(f"Could not execute AWS CLI: {exc}", "bad_config") from exc
        if response.returncode:
            reason = response.stderr.strip()[-1000:] or f"exit {response.returncode}"
            raise CollectionError(f"aws {' '.join(args[:2])}: {reason}", error_code(reason))
        return response.stdout

    def call(self, service, operation, **params):
        text = self.run(
            [
                service,
                operation,
                "--region",
                self.region,
                "--output",
                "json",
                "--no-paginate",
                "--cli-input-json",
                json.dumps(params),
            ]
        )
        try:
            result = json.loads(text)
        except ValueError as exc:
            raise CollectionError(f"{operation} returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise CollectionError(f"{operation} returned a non-object response")
        return result

    def pages(self, service, operation, key, **params):
        tokens = set()
        for _ in range(10000):
            response = self.call(service, operation, **params)
            records = response.get(key)
            if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
                raise CollectionError(f"{operation} returned invalid {key}")
            yield from records
            token = response.get("nextToken")
            if not token:
                return
            if not isinstance(token, str) or token in tokens:
                raise CollectionError(f"{operation} repeated/invalid pagination token")
            tokens.add(token)
            params = {**params, "nextToken": token}
        raise CollectionError(f"{operation} exceeded 10000 pages; no complete report available")


def read_list(name):
    try:
        values = json.loads(os.environ.get(name, "[]"))
    except ValueError as exc:
        raise CollectionError(f"{name} must be a JSON array of strings", "bad_config") from exc
    if not isinstance(values, list) or any(not isinstance(v, str) or not v.strip() for v in values):
        raise CollectionError(f"{name} must be a JSON array of nonempty strings", "bad_config")
    values = sorted(set(values))
    if len(values) > 10:
        raise CollectionError(f"{name} supports at most 10 values per target", "bad_config")
    return values


def equal(values):
    return [{"comparison": "EQUALS", "value": value} for value in values]


def nonempty_strings(*values):
    return all(isinstance(value, str) and value for value in values)


def collect(aws, repositories, image_tags, *, allow_partial=False):
    started = utc_now()
    failures = []

    @contextmanager
    def attempt(operation, **context):
        try:
            yield
        except Exception as exc:
            if not allow_partial:
                raise
            failures.append(
                {
                    "operation": operation,
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "code": exc.code if isinstance(exc, CollectionError) else "internal_error",
                    **context,
                }
            )

    account, arn, scan_status, ecr_state = None, None, None, None
    repo_list, inventory, coverage, findings = [], [], [], {}
    with attempt("sts get-caller-identity"):
        identity = aws.call("sts", "get-caller-identity")
        if not nonempty_strings(identity.get("Account"), identity.get("Arn")) or not re.fullmatch(
            r"\d{12}", identity["Account"]
        ):
            raise CollectionError("STS returned no valid account identity")
        account, arn = identity["Account"], identity["Arn"]

    # Without a verified identity, do not issue account-scoped collection calls.
    if account:
        with attempt("inspector2 batch-get-account-status"):
            status = aws.call("inspector2", "batch-get-account-status", accountIds=[account])
            accounts = status.get("accounts", [])
            if (
                status.get("failedAccounts")
                or len(accounts) != 1
                or accounts[0].get("accountId") != account
            ):
                raise CollectionError("Inspector could not return this account's scanning status")
            state = accounts[0].get("resourceState", {}).get("ecr", {}).get("status")
            if not state:
                raise CollectionError("Inspector returned no ECR scanning status")
            scan_status, ecr_state = accounts[0], state

        with attempt("ecr describe-repositories"):
            # extend retains earlier pages if a later request fails.
            repo_list.extend(aws.pages("ecr", "describe-repositories", "repositories"))
            missing = set(repositories) - {r.get("repositoryName") for r in repo_list}
            if missing:
                raise CollectionError(
                    f"Requested repositories not found: {', '.join(sorted(missing))}", "bad_config"
                )
    for repo in repo_list:
        name = repo.get("repositoryName")
        with attempt("ecr describe-repositories", repository=name):
            if (
                not nonempty_strings(name, repo.get("repositoryArn"))
                or repo.get("registryId") != account
            ):
                raise CollectionError("ECR returned invalid repository identity")
            if repositories and name not in repositories:
                continue
            with attempt("ecr describe-images", repository=name):
                for image in aws.pages(
                    "ecr", "describe-images", "imageDetails", repositoryName=name
                ):
                    if image_tags and not set(image_tags).intersection(image.get("imageTags", [])):
                        continue
                    if not nonempty_strings(image.get("imageDigest")):
                        raise CollectionError(f"ECR returned an image without a digest in {name}")
                    inventory.append(
                        {**image, "repository": name, "repository_arn": repo["repositoryArn"]}
                    )

    finding_filter = {
        "awsAccountId": equal([account]),
        "resourceType": equal([RESOURCE_TYPE]),
        "findingStatus": equal(["ACTIVE"]),
    }
    coverage_filter = {
        "accountId": equal([account]),
        "resourceType": equal([RESOURCE_TYPE]),
        "scanType": equal(["PACKAGE"]),
    }
    for values, finding_key, coverage_key in (
        (repositories, "ecrImageRepositoryName", "ecrRepositoryName"),
        (image_tags, "ecrImageTags", "ecrImageTags"),
    ):
        if values:
            finding_filter[finding_key] = equal(values)
            coverage_filter[coverage_key] = equal(values)

    if account and ecr_state in (None, "ENABLED"):
        with attempt("inspector2 list-coverage"):
            for resource in aws.pages(
                "inspector2", "list-coverage", "coveredResources", filterCriteria=coverage_filter
            ):
                if (
                    resource.get("accountId") != account
                    or resource.get("resourceType") != RESOURCE_TYPE
                ):
                    raise CollectionError(
                        "Inspector returned coverage outside the requested account/resource scope"
                    )
                if not nonempty_strings(resource.get("resourceId")) or not isinstance(
                    resource.get("scanStatus", {}), dict
                ):
                    raise CollectionError("Inspector returned invalid coverage identity/status")
                coverage.append(resource)
        with attempt("inspector2 list-findings"):
            for finding in aws.pages(
                "inspector2", "list-findings", "findings", filterCriteria=finding_filter
            ):
                if finding.get("awsAccountId") != account or finding.get("status") != "ACTIVE":
                    raise CollectionError(
                        "Inspector returned a finding outside the requested account/status scope"
                    )
                if not nonempty_strings(
                    finding.get("findingArn"),
                    finding.get("packageVulnerabilityDetails", {}).get("vulnerabilityId"),
                ):
                    raise CollectionError(
                        "Inspector returned a finding without its identity/vulnerability ID"
                    )
                resources = finding.get("resources")
                if not resources:
                    raise CollectionError("Inspector returned a finding without affected resources")
                for resource in resources:
                    detail = resource.get("details", {}).get("awsEcrContainerImage", {})
                    if (
                        resource.get("type") != RESOURCE_TYPE
                        or resource.get("region") != aws.region
                        or not nonempty_strings(
                            detail.get("repositoryName"), detail.get("imageHash")
                        )
                        or (repositories and detail["repositoryName"] not in repositories)
                        or (
                            image_tags
                            and not set(image_tags).intersection(detail.get("imageTags", []))
                        )
                    ):
                        raise CollectionError(
                            "Inspector returned incomplete or out-of-scope ECR resource details"
                        )
                # Duplicate pages may overlap while Inspector updates its live dataset.
                previous = findings.get(finding["findingArn"])
                if previous is not None and previous != finding:
                    raise CollectionError(
                        "Inspector finding changed between pages; retry for a consistent report"
                    )
                findings[finding["findingArn"]] = finding

    by_resource = {c.get("resourceId"): c for c in coverage}
    gaps = []
    for image in inventory:
        key = f"{image['repository_arn']}/{image['imageDigest']}"
        scanned = by_resource.get(key)
        image["inspector_coverage"] = scanned
        if (
            not scanned
            or scanned.get("scanStatus", {}).get("statusCode") != "ACTIVE"
            or not scanned.get("lastScannedAt")
        ):
            gaps.append(key)
    findings_list = sorted(findings.values(), key=lambda f: f["findingArn"])
    known_images = {(i["repository"], i["imageDigest"]) for i in inventory}
    inventory_mismatches = sorted(
        {
            f["findingArn"]
            for f in findings_list
            for r in f["resources"]
            if (
                r["details"]["awsEcrContainerImage"]["repositoryName"],
                r["details"]["awsEcrContainerImage"]["imageHash"],
            )
            not in known_images
        }
    )
    severities = Counter(
        f.get("severity") if f.get("severity") in SEVERITIES else "UNKNOWN" for f in findings_list
    )
    per_repository, per_vulnerability = Counter(), Counter()
    for finding in findings_list:
        per_vulnerability[finding["packageVulnerabilityDetails"]["vulnerabilityId"]] += 1
        for repository in {
            r["details"]["awsEcrContainerImage"]["repositoryName"] for r in finding["resources"]
        }:
            per_repository[repository] += 1
    return {
        "metadata": {
            "account_id": account,
            "arn": arn,
            "region": aws.region,
            "profile": os.environ.get("AWS_PROFILE", ""),
            "datetime": started,
            "completed_at": utc_now(),
            "partial_failure": bool(failures),
            "api_failures": failures,
        },
        "results": {
            "scope": {
                "repositories": repositories,
                "image_tags": image_tags,
                "finding_status": ["ACTIVE"],
                "resource_type": RESOURCE_TYPE,
            },
            "collection_complete": not failures,
            "scan_status": scan_status,
            "findings_collection_status": "incomplete"
            if failures
            else ("collected" if ecr_state == "ENABLED" else "not_enabled"),
            "summary": {
                "finding_count": len(findings_list)
                if ecr_state == "ENABLED" and not failures
                else None,
                "severity_counts": {s: severities[s] for s in (*SEVERITIES, "UNKNOWN")}
                if ecr_state == "ENABLED" and not failures
                else None,
                "image_count": len(inventory) if not failures else None,
                "coverage_gap_count": len(gaps) if not failures else None,
                "findings_by_repository": dict(sorted(per_repository.items()))
                if not failures
                else None,
                "findings_by_vulnerability": dict(sorted(per_vulnerability.items()))
                if not failures
                else None,
            },
            "coverage_gaps": sorted(gaps),
            "images": inventory,
            "coverage": coverage,
            "findings_missing_from_inventory": inventory_mismatches,
            "findings": findings_list,
        },
    }


def csv_rows(evidence):
    meta = evidence["metadata"]
    for finding in evidence["results"]["findings"]:
        package = finding["packageVulnerabilityDetails"]
        for resource in finding["resources"]:
            image = resource["details"]["awsEcrContainerImage"]
            asset = f"{meta['account_id']}/{meta['region']}/{image['repositoryName']}@{image['imageHash']}"
            yield {
                "ID": f"{finding['findingArn']}|{asset}",
                "Finding ARN": finding["findingArn"],
                "Vulnerability ID": package["vulnerabilityId"],
                "Title": finding.get("title", ""),
                "Description": finding.get("description", ""),
                "Severity": finding.get("severity", "UNKNOWN"),
                "Status": finding["status"],
                "AWS Account ID": meta["account_id"],
                "Region": meta["region"],
                "Asset ID": asset,
                "Repository": image["repositoryName"],
                "Image Digest": image["imageHash"],
                "Image Tags": json.dumps(image.get("imageTags", [])),
                "First Observed At": finding.get("firstObservedAt", ""),
                "Last Observed At": finding.get("lastObservedAt", ""),
                "Updated At": finding.get("updatedAt", ""),
                "Fix Available": finding.get("fixAvailable", ""),
                "Exploit Available": finding.get("exploitAvailable", ""),
                "Inspector Score": finding.get("inspectorScore", ""),
                "CVSS": json.dumps(package.get("cvss", [])),
                "Affected Packages": json.dumps(package.get("vulnerablePackages", [])),
                "Remediation": finding.get("remediation", {})
                .get("recommendation", {})
                .get("text", ""),
                "Reference URLs": json.dumps(package.get("referenceUrls", [])),
                "Related Vulnerabilities": json.dumps(package.get("relatedVulnerabilities", [])),
            }


def csv_safe(value):
    # CSV quoting alone does not stop spreadsheet formula interpretation.
    if isinstance(value, str) and value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def write_output(evidence, report, directory, allow_empty=False):
    results = evidence["results"]
    if report:
        if not results["collection_complete"] or evidence["metadata"].get("partial_failure"):
            raise CollectionError("Inspector collection is incomplete; no issue report written")
        if results["findings_collection_status"] != "collected":
            raise CollectionError("Inspector ECR scanning is not enabled; no issue report written")
        if not results["images"] or results["coverage_gaps"]:
            raise CollectionError(
                "Selected images have missing/inactive scan coverage, or none matched; no issue report written"
            )
        if results["findings_missing_from_inventory"]:
            raise CollectionError(
                "Finding images changed during collection; retry before importing issues"
            )
        if not results["findings"] and not allow_empty:
            raise CollectionError(
                "Inspector returned zero findings; set allow_empty=true only after verifying scope",
                "bad_config",
            )
    meta = evidence["metadata"]
    scope = json.dumps({"profile": meta["profile"], **results["scope"]}, sort_keys=True)
    suffix = hashlib.sha256(scope.encode()).hexdigest()[:12]
    name = "aws_inspector_ecr_report" if report else "aws_inspector_ecr_findings"
    target = re.sub(r"[^A-Za-z0-9._-]", "_", f"{meta['account_id']}_{meta['region']}_{suffix}")
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / f"{name}_{target}.{'csv' if report else 'json'}"
    # A sibling staging file stays outside runner discovery even after SIGKILL.
    # Publish by rename only: a cross-filesystem copy could expose partial bytes.
    directory = directory.resolve()
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="",
        dir=directory.parent,
        prefix=".inspector-",
        suffix=".tmp",
        delete=False,
    ) as stream:
        temporary = Path(stream.name)
        try:
            if report:
                writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS)
                writer.writeheader()
                writer.writerows(
                    {key: csv_safe(value) for key, value in row.items()}
                    for row in csv_rows(evidence)
                )
            else:
                json.dump(evidence, stream, indent=2)
            stream.close()
            try:
                temporary.replace(dest)
            except OSError as exc:
                if exc.errno == errno.EXDEV:
                    raise CollectionError(
                        "Atomic publication requires EVIDENCE_DIR and its parent on the same filesystem; "
                        "use an output subdirectory inside the mounted volume",
                        "bad_config",
                    ) from exc
                raise
        finally:
            temporary.unlink(missing_ok=True)
    return dest


def main(report=False):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    load_dotenv()
    try:
        repositories = read_list("AWS_INSPECTOR_REPOSITORIES")
        tags = read_list("AWS_INSPECTOR_IMAGE_TAGS")
        allow_empty = os.environ.get("AWS_INSPECTOR_ALLOW_EMPTY", "false").lower()
        if allow_empty not in ("true", "false"):
            raise CollectionError("allow_empty must be true or false", "bad_config")
        evidence = collect(Aws(), repositories, tags, allow_partial=not report)
        dest = write_output(
            evidence,
            report,
            Path(os.environ.get("EVIDENCE_DIR", "./evidence")),
            allow_empty == "true",
        )
    except CollectionError as exc:
        report_failure(str(exc), exc.code)
        return 1
    except Exception as exc:
        report_failure(f"Inspector collection failed: {exc}", "internal_error")
        return 1
    logging.info("Saved %s", dest)
    failures = evidence["metadata"]["api_failures"]
    if failures:
        codes = {failure["code"] for failure in failures}
        code = codes.pop() if len(codes) == 1 else "partial_failure"
        report_failure("; ".join(f"{f['operation']}: {f['message']}" for f in failures), code)
        return 1
    return 0
