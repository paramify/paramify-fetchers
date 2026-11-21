#!/usr/bin/env python3
"""KSI-SCR-MON: ECR registry and repository scanning configuration, plus a
severity summary of each repository's most recently pushed image.

Output: $EVIDENCE_DIR/aws_ecr_image_scanning_<profile|ambient>[_<region>].json
Optional env (else the boto3 ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION

One process and one ECR client for the whole target. Repositories are read on a
small thread pool; each worker keeps only the per-repository summary, so memory
does not grow with the number of findings an image has.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

NAME = "aws_ecr_image_scanning"
REPO_WORKERS = 8
# BatchGetRepositoryScanningConfiguration accepts at most 25 names per call.
CONFIG_BATCH = 25
# The API maximums. The CLI's default page is 100, so a large enhanced scan
# took ten times the requests.
PAGE_SIZES = {
    "describe_repositories": 1000,
    "describe_images": 1000,
    "describe_image_scan_findings": 1000,
}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNTRIAGED")
COUNTED_STATUSES = ("COMPLETE", "ACTIVE")

# Same order and patterns as aws_classify_code in _shared/aws.sh: the most
# specific cause wins, whichever call failed first.
ERROR_CODES = (
    (r"ExpiredToken|InvalidClientTokenId|UnrecognizedClientException|SignatureDoesNotMatch|Unable to locate credentials"
     r"|The security token included in the request is (expired|invalid)|NoCredentialProviders|NoCredentialsError"
     r"|sso session .* is expired|Your session has expired|Token has expired", "auth_failed"),
    (r"AccessDenied|UnauthorizedOperation|not authorized to perform|AuthorizationError|explicit deny|\(403\)",
     "not_authorized"),
    (r"Throttling|ThrottlingException|TooManyRequests|RequestLimitExceeded|SlowDown|Rate exceeded|\(429\)",
     "rate_limited"),
    (r"Could not connect to the endpoint URL|EndpointConnectionError|ConnectTimeoutError|ReadTimeoutError"
     r"|Connection was closed|Name or service not known|[Tt]emporary failure in name resolution|\(50[34]\)",
     "target_unreachable"),
    (r"InvalidParameterValue|ValidationError|ValidationException|Invalid region|Invalid( |-)?ARN|InvalidInput"
     r"|NoRegionError|ProfileNotFound", "bad_config"),
)


def classify(errors):
    text = "\n".join(errors)
    for pattern, code in ERROR_CODES:
        if re.search(pattern, text, re.I):
            return code
    return "partial_failure"


def plain(value):
    """boto3 values as the JSON the AWS CLI prints: timestamps become ISO 8601."""
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def describe(exc):
    """One line of error text, led by the exception type so classify() sees botocore's NoRegionError and the like."""
    return " ".join(f"{type(exc).__name__}: {exc}".split())[:500]


def error_name(exc):
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return (response.get("Error") or {}).get("Code") or ""
    return ""


class Collector:
    def __init__(self, client):
        self.client = client
        # (label, error text), in collection order: repository failures follow
        # describe-repositories order, not the order the workers finish.
        self.failures = []

    def fail(self, label, exc=None, into=None):
        (self.failures if into is None else into).append((label, describe(exc) if exc is not None else ""))

    def pages(self, operation, **params):
        """Every response page, at the API's largest page size."""
        params = {"maxResults": PAGE_SIZES[operation], **params}
        seen = set()
        while True:
            response = getattr(self.client, operation)(**params)
            yield response
            token = response.get("nextToken")
            if not token:
                return
            if token in seen:
                raise RuntimeError(f"{operation} repeated a pagination token")
            seen.add(token)
            params["nextToken"] = token

    def registry_scanning(self):
        try:
            config = self.client.get_registry_scanning_configuration().get("scanningConfiguration") or {}
        except Exception as exc:
            self.fail("aws ecr get-registry-scanning-configuration failed", exc)
            config = None
        else:
            if config.get("scanType") not in ("BASIC", "ENHANCED"):
                self.fail("aws ecr get-registry-scanning-configuration returned no scanning configuration")
                config = None
        if config is None:
            # Not read, so unknown: [] would claim the registry has no rules.
            return {"scan_type": None, "rules": None}
        return {
            "scan_type": config.get("scanType"),
            "rules": [
                {"scan_frequency": rule.get("scanFrequency"), "scan_filters": rule.get("repositoryFilters") or []}
                for rule in config.get("rules") or []
            ],
        }

    def repositories(self):
        try:
            repos = []
            for page in self.pages("describe_repositories"):
                records = page.get("repositories")
                if not isinstance(records, list):
                    raise RuntimeError("returned no repositories list")
                repos.extend(records)
            return repos
        except Exception as exc:
            self.fail("aws ecr describe-repositories (list) failed", exc)
            logging.error("Failed to list ECR repositories")
            return None

    def effective_scanning(self, names):
        """Repository name → its effective scanning configuration, as AWS resolves the registry filters."""
        by_name = {}
        for i in range(0, len(names), CONFIG_BATCH):
            batch = names[i:i + CONFIG_BATCH]
            try:
                response = self.client.batch_get_repository_scanning_configuration(repositoryNames=batch)
            except Exception as exc:
                self.fail(f"aws ecr batch-get-repository-scanning-configuration failed for {batch}", exc)
                continue
            configs, failures = response.get("scanningConfigurations"), response.get("failures") or []
            if not isinstance(configs, list) or not isinstance(failures, list):
                self.fail(f"aws ecr batch-get-repository-scanning-configuration returned invalid data for {batch}")
                continue
            for failure in failures:
                self.fail("aws ecr batch-get-repository-scanning-configuration: "
                          + json.dumps(plain(failure), separators=(",", ":")))
            for config in configs:
                by_name[config.get("repositoryName")] = plain(config)
        return by_name

    def latest_digest(self, name):
        """The digest of the most recently pushed image, None for an empty repository."""
        latest = None
        for page in self.pages("describe_images", repositoryName=name):
            for image in page.get("imageDetails") or []:
                # >= keeps the CLI's pick on a tie: reverse(sort_by(...))[0], a stable sort, is the last one listed.
                if latest is None or image.get("imagePushedAt") is not None and (
                        latest.get("imagePushedAt") is None or image["imagePushedAt"] >= latest["imagePushedAt"]):
                    latest = image
        return None if latest is None else latest.get("imageDigest")

    def scan_summary(self, name, digest):
        """The newest image's scan, reduced to its status and severity counts.

        With enhanced (Inspector) scanning, findingSeverityCounts covers only the
        findings on the returned page, so counts come from enhancedFindings
        across every page. BASIC scans keep AWS's findingSeverityCounts, which is
        the image total, and are read in one page.
        """
        first, enhanced, counts = None, False, {}
        for page in self.pages("describe_image_scan_findings", repositoryName=name,
                               imageId={"imageDigest": digest}):
            findings = page.get("imageScanFindings") or {}
            if first is None:
                first = page
            if "enhancedFindings" in findings:
                enhanced = True
                for finding in findings.get("enhancedFindings") or []:
                    severity = finding.get("severity") or "UNTRIAGED"
                    counts[severity] = counts.get(severity, 0) + 1
            elif not enhanced:
                # Basic: the totals are on every page; the findings list is not needed.
                break
        first = first or {}
        findings = first.get("imageScanFindings") or {}
        status = (first.get("imageScanStatus") or {}).get("status")
        if not isinstance(status, str):
            return None
        severity_map = counts if enhanced else findings.get("findingSeverityCounts")
        return {
            "image_digest": (first.get("imageId") or {}).get("imageDigest"),
            "scan_status": status,
            "severity_counts": (
                {s.lower(): severity_map.get(s, 0) for s in SEVERITIES}
                if status in COUNTED_STATUSES and isinstance(severity_map, dict) else None
            ),
            "scan_completed_at": plain(findings.get("imageScanCompletedAt")),
            "vulnerability_source_updated_at": plain(findings.get("vulnerabilitySourceUpdatedAt")),
        }

    def repository(self, repo, effective, failures=None):
        name = repo.get("repositoryName")
        if effective is None:
            self.fail(f"No effective scanning configuration returned for {name}", into=failures)
        record = {
            "name": name,
            "arn": repo.get("repositoryArn"),
            "registry_id": repo.get("registryId"),
            "scan_on_push": (repo.get("imageScanningConfiguration") or {}).get("scanOnPush") or False,
            "immutability": repo.get("imageTagMutability") or "MUTABLE",
            "latest_image_scan": None,
            "scan_frequency": (effective or {}).get("scanFrequency"),
            "applied_scan_filters": None if effective is None else effective.get("appliedScanFilters") or [],
            "scan_collection_status": "empty_repository",
        }
        try:
            digest = self.latest_digest(name)
        except Exception as exc:
            self.fail(f"aws ecr describe-images ({name}) failed", exc, into=failures)
            record["scan_collection_status"] = "error"
            return record
        if digest is None:
            return record
        if not isinstance(digest, str) or not digest:
            self.fail(f"aws ecr describe-images ({name}) returned an invalid digest", into=failures)
            record["scan_collection_status"] = "error"
            return record

        try:
            scan = self.scan_summary(name, digest)
        except Exception as exc:
            code = error_name(exc)
            if code in ("ScanNotFoundException", "ImageNotFoundException"):
                # A missing scan is evidence, not a failure. A concurrent deletion is
                # neither a failed permission nor proof of a clean scan; keep the digest.
                record["latest_image_scan"] = {
                    "image_digest": digest,
                    "scan_status": "NOT_SCANNED" if code == "ScanNotFoundException" else "IMAGE_NOT_FOUND",
                    "severity_counts": None,
                }
                record["scan_collection_status"] = (
                    "not_scanned" if code == "ScanNotFoundException" else "image_deleted")
            else:
                self.fail(f"aws ecr describe-image-scan-findings ({name}) failed", exc, into=failures)
                record["scan_collection_status"] = "error"
            return record
        if scan is None:
            self.fail(f"aws ecr describe-image-scan-findings ({name}) returned invalid scan data", into=failures)
            record["scan_collection_status"] = "error"
            return record
        record["latest_image_scan"] = scan
        record["scan_collection_status"] = "collected"
        return record

    def collect(self):
        results = {"registry_scanning": self.registry_scanning()}
        repos = self.repositories()
        # Null when the list failed: [] would claim the registry has no repositories.
        results["repositories"] = repos
        if not repos:
            return results
        effective = self.effective_scanning([r.get("repositoryName") for r in repos])

        def read(repo):
            failures = []
            return self.repository(repo, effective.get(repo.get("repositoryName")), failures), failures

        with ThreadPoolExecutor(max_workers=min(REPO_WORKERS, len(repos))) as pool:
            # map keeps describe-repositories order.
            read_repos = list(pool.map(read, repos))
        results["repositories"] = [record for record, _ in read_repos]
        for _, failures in read_repos:
            self.failures.extend(failures)
        return results


def target_id(profile, region):
    """Same file name as aws_target_id "$REGION" in _shared/aws.sh."""
    target = profile or "ambient"
    if region:
        target = f"{target}_{region}"
    return re.sub(r"[^A-Za-z0-9._-]", "_", target)


class CollectionError(Exception):
    def __init__(self, message, code="partial_failure"):
        super().__init__(message)
        self.code = code


def session_and_client():
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise CollectionError(
            "boto3 is required for aws_ecr_image_scanning (pip install -r requirements.txt)",
            "bad_config",
        ) from exc

    session = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None)
    # The runner maps target.region to AWS_DEFAULT_REGION; pin it so an ambient
    # AWS_REGION cannot override a manifest target.
    region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or session.region_name
    config = Config(
        region_name=region,
        retries={"mode": "standard", "max_attempts": 8},
        connect_timeout=30,
        read_timeout=120,
        max_pool_connections=REPO_WORKERS + 2,
    )
    return session.client("sts", config=config), session.client("ecr", config=config)


def main():
    logging.basicConfig(level=logging.INFO, format=f"%(asctime)s %(levelname)s {NAME} %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")
    logging.Formatter.converter = time.gmtime
    load_dotenv()
    # Recorded in metadata as the target gave them; empty means ambient.
    profile = os.environ.get("AWS_PROFILE", "")
    region = os.environ.get("AWS_DEFAULT_REGION", "")
    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{NAME}_{target_id(profile, region)}.json"

    try:
        sts, ecr = session_and_client()
    except CollectionError as exc:
        report_failure(str(exc), exc.code)
        return 1
    except Exception as exc:
        report_failure(f"AWS session: {describe(exc)}", classify([describe(exc)]))
        return 1

    collector = Collector(ecr)
    account_id, arn = "unknown", "unknown"
    try:
        identity = sts.get_caller_identity()
        account_id, arn = identity.get("Account") or "unknown", identity.get("Arn") or "unknown"
        if not re.fullmatch(r"[0-9]{12}", str(identity.get("Account"))):
            collector.fail("aws sts get-caller-identity returned invalid identity")
    except Exception as exc:
        collector.fail("aws sts get-caller-identity failed", exc)

    evidence = {
        "metadata": {
            "profile": profile,
            "region": region,
            "datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "account_id": account_id,
            "arn": arn,
        },
    }
    try:
        evidence["results"] = collector.collect()
    except Exception as exc:
        report_failure(f"ECR collection failed: {describe(exc)}", "internal_error")
        return 1
    output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    if collector.failures:
        labels = [label for label, _ in collector.failures]
        errors = [error for _, error in collector.failures if error]
        reasons = "; ".join(labels[:3]) + (f"(+{len(labels) - 3} more)" if len(labels) > 3 else "")
        detail = f" -- {' | '.join(errors[:3])}" if errors else ""
        report_failure(f"{len(labels)} AWS API failure(s); first: {reasons}{detail}", classify(errors))
        return 1
    logging.info("Evidence saved to %s", output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
