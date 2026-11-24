"""Read ECR inventory, Inspector coverage and findings for one account/region.

Uses boto3 with the standard AWS credential chain (profile, role, SSO, ECS task
role, environment). Every request is read-only. Evidence and issue reports share
filters and pagination; neither collector contacts Paramify. The existing
uploader owns intake/jobs.
"""

from __future__ import annotations

import csv
import errno
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from datetime import date, datetime, timedelta, timezone
from itertools import islice
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure

RESOURCE_TYPE = "AWS_ECR_CONTAINER_IMAGE"
# Highest first, after UNTRIAGED: a min_severity threshold keeps every severity
# up to its own, so an untriaged finding (which may be anything) is always kept.
SEVERITIES = ("UNTRIAGED", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
# Multi-architecture parents. Inspector scans the per-platform images an index
# points to, never the index itself, so an index can never have ACTIVE coverage.
INDEX_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
PAGE_SIZES = {
    ("ecr", "describe-repositories"): 1000,
    ("ecr", "describe-images"): 1000,
    ("inspector2", "list-coverage"): 200,
    ("inspector2", "list-findings"): 100,
}
IMAGE_WORKERS = 8
FINDING_QUERIES_AHEAD = 2 * IMAGE_WORKERS
INDEX_BATCH = 100
HASHES_PER_QUERY = 10
IMAGE_FIELDS = (
    "imageDigest",
    "imageTags",
    "imagePushedAt",
    "lastRecordedPullTime",
    "imageSizeInBytes",
    "imageManifestMediaType",
)
SHARED_FINDING_FIELDS = (
    "description",
    "remediation",
    "epss",
    "exploitabilityDetails",
    "inspectorScoreDetails",
)
SHARED_PACKAGE_FIELDS = (
    "source",
    "sourceUrl",
    "cvss",
    "referenceUrls",
    "relatedVulnerabilities",
    "vendorSeverity",
    "vendorCreatedAt",
    "vendorUpdatedAt",
)
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
    "Repository ARN",
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


def plain(value):
    """boto3 values as the JSON the AWS CLI prints: timestamps become ISO 8601."""
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


class Aws:
    def __init__(self):
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise CollectionError(
                "boto3 is required for the Inspector ECR fetchers (pip install -r requirements.txt)",
                "bad_config",
            ) from exc
        try:
            session = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None)
        except Exception as exc:
            raise CollectionError(f"AWS session: {exc}", "bad_config") from exc
        # The runner maps target.region to AWS_DEFAULT_REGION; pin it explicitly
        # so an ambient AWS_REGION cannot override a manifest target.
        self.region = (
            os.environ.get("AWS_DEFAULT_REGION")
            or os.environ.get("AWS_REGION")
            or session.region_name
        )
        if not self.region:
            raise CollectionError("Set a region in the target or AWS configuration", "bad_config")
        self.session = session
        self.config = Config(
            region_name=self.region,
            retries={"mode": "standard", "max_attempts": 4},
            connect_timeout=30,
            read_timeout=180,
            max_pool_connections=IMAGE_WORKERS + 2,
        )
        self.clients = {}

    def client(self, service):
        # Clients are thread-safe; sessions are not. collect() creates the ECR
        # client on the main thread before its workers share it.
        if service not in self.clients:
            self.clients[service] = self.session.client(service, config=self.config)
        return self.clients[service]

    def call(self, service, operation, **params):
        try:
            method = getattr(self.client(service), operation.replace("-", "_"))
            result = method(**params)
        except Exception as exc:
            reason = str(exc).strip()[-1000:] or type(exc).__name__
            raise CollectionError(f"aws {service} {operation}: {reason}", error_code(reason)) from exc
        if not isinstance(result, dict):
            raise CollectionError(f"{operation} returned a non-object response")
        result.pop("ResponseMetadata", None)
        return plain(result)

    def pages(self, service, operation, key, **params):
        size = PAGE_SIZES.get((service, operation))
        if size:
            params = {"maxResults": size, **params}
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


def read_bool(name):
    value = os.environ.get(name, "false").strip().lower()
    if value not in ("true", "false"):
        raise CollectionError(f"{name} must be true or false", "bad_config")
    return value == "true"


def read_days(name):
    value = os.environ.get(name, "").strip() or "0"
    if not re.fullmatch(r"\d+", value) or int(value) > 3650:
        raise CollectionError(f"{name} must be a whole number of days from 0 to 3650", "bad_config")
    return int(value)


def read_severity(name):
    value = os.environ.get(name, "").strip().upper()
    if value and value not in SEVERITIES[1:]:
        raise CollectionError(
            f"{name} must be one of {', '.join(SEVERITIES[1:])}, or empty", "bad_config"
        )
    return value or None


def read_scope():
    """Every scope setting, validated before any AWS request."""
    return {
        "repositories": read_list("AWS_INSPECTOR_REPOSITORIES"),
        "image_tags": read_list("AWS_INSPECTOR_IMAGE_TAGS"),
        "in_use_only": read_bool("AWS_INSPECTOR_IN_USE_ONLY"),
        "last_in_use_days": read_days("AWS_INSPECTOR_LAST_IN_USE_DAYS"),
        "pushed_within_days": read_days("AWS_INSPECTOR_PUSHED_WITHIN_DAYS"),
        "min_severity": read_severity("AWS_INSPECTOR_MIN_SEVERITY"),
    }


def default_scope(repositories=(), image_tags=()):
    return {
        "repositories": list(repositories),
        "image_tags": list(image_tags),
        "in_use_only": False,
        "last_in_use_days": 0,
        "pushed_within_days": 0,
        "min_severity": None,
    }


def equal(values):
    return [{"comparison": "EQUALS", "value": value} for value in values]


def nonempty_strings(*values):
    return all(isinstance(value, str) and value for value in values)


def parse_time(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def severities_at_or_above(minimum):
    return list(SEVERITIES[: SEVERITIES.index(minimum) + 1])


def canonical_digest(record):
    text = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).digest()


def compact_finding(finding, vulnerabilities):
    """The finding without the fields stored for its vulnerability ID.

    The first finding of an ID sets the stored fields. A later finding keeps
    any field whose value differs, and lists in `absent_fields` any stored
    field it does not have, so expand_finding() rebuilds every record exactly.
    """
    package = finding["packageVulnerabilityDetails"]
    vulnerability_id = package["vulnerabilityId"]
    if vulnerability_id not in vulnerabilities:
        vulnerabilities[vulnerability_id] = {
            **{k: finding[k] for k in SHARED_FINDING_FIELDS if k in finding},
            "packageVulnerabilityDetails": {
                k: package[k] for k in SHARED_PACKAGE_FIELDS if k in package
            },
        }
    shared = vulnerabilities[vulnerability_id]
    shared_package = shared["packageVulnerabilityDetails"]
    compact = {
        k: v for k, v in finding.items() if k not in shared or (k in SHARED_FINDING_FIELDS and shared[k] != v)
    }
    compact["packageVulnerabilityDetails"] = {
        k: v for k, v in package.items() if k not in shared_package or shared_package[k] != v
    }
    absent = sorted(
        [k for k in shared if k != "packageVulnerabilityDetails" and k not in finding]
        + [f"packageVulnerabilityDetails.{k}" for k in shared_package if k not in package]
    )
    if absent:
        compact["absent_fields"] = absent
    return compact


def expand_finding(finding, vulnerabilities):
    """The full Inspector record: a compact finding plus its vulnerability's fields."""
    finding = dict(finding)
    absent = set(finding.pop("absent_fields", ()))
    package = finding["packageVulnerabilityDetails"]
    shared = vulnerabilities.get(package["vulnerabilityId"], {})
    full = {
        k: v for k, v in shared.items() if k != "packageVulnerabilityDetails" and k not in absent
    }
    full.update(finding)
    full["packageVulnerabilityDetails"] = {
        **{
            k: v
            for k, v in shared.get("packageVulnerabilityDetails", {}).items()
            if f"packageVulnerabilityDetails.{k}" not in absent
        },
        **package,
    }
    return full


def selected(image, scope, cutoff):
    """Whether an ECR image is a candidate for the inventory, before any Inspector query.

    DescribeImages cannot filter by tag or push date, so the ECR listing is
    narrowed here. Repositories are already filtered. With image_tags, an
    image is selected by its own tags or by the tags of an index that points
    to it (`index_tags`, set by collect()). Usage filters are applied later,
    from Inspector coverage.
    """
    if cutoff is not None:
        pushed = parse_time(image.get("imagePushedAt"))
        if pushed is None or pushed < cutoff:
            return False
    if scope["image_tags"]:
        tags = set(image.get("imageTags") or []) | set(image.get("index_tags") or [])
        return bool(set(scope["image_tags"]) & tags)
    return True


def index_images(manifest):
    """The digests of the runnable images an image index or manifest list points to.

    Attestation entries (platform os "unknown", or a Docker attestation
    reference) and nested indexes are not images Inspector scans.
    """
    for entry in manifest.get("manifests") or []:
        if not isinstance(entry, dict) or not nonempty_strings(entry.get("digest")):
            continue
        if entry.get("mediaType") in INDEX_MEDIA_TYPES:
            continue
        if (entry.get("platform") or {}).get("os") == "unknown":
            continue
        if (entry.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest":
            continue
        yield entry["digest"]


def in_order(pool, fn, items, ahead):
    """fn(item) for each item on the pool, yielded in item order.

    At most `ahead` calls are submitted but not yet consumed, so results held in
    memory stay bounded. Calls not yet started are cancelled if the consumer stops.
    """
    items = iter(items)
    pending = deque(pool.submit(fn, item) for item in islice(items, ahead))
    try:
        while pending:
            result = pending.popleft().result()
            for item in islice(items, 1):
                pending.append(pool.submit(fn, item))
            yield result
    finally:
        for future in pending:
            future.cancel()


def collect(aws, scope, *, allow_partial=False, now=None):
    started = utc_now()
    now = now or datetime.now(timezone.utc)
    repositories, image_tags = scope["repositories"], scope["image_tags"]
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
    repo_list, ecr_images, coverage, findings = [], [], [], {}
    finding_digests, vulnerabilities = {}, {}
    index_digests = 0
    tagged_indexes = {}
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

    wanted = []
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
            wanted.append(repo)

    def describe(repo):
        """Every page of one repository's images; earlier pages survive a failure."""
        images, error = [], None
        try:
            for image in aws.pages(
                "ecr", "describe-images", "imageDetails", repositoryName=repo["repositoryName"]
            ):
                if not nonempty_strings(image.get("imageDigest")):
                    raise CollectionError(
                        f"ECR returned an image without a digest in {repo['repositoryName']}"
                    )
                images.append(image)
        except Exception as exc:
            error = exc
        return images, error

    if wanted:
        aws.client("ecr")
        with ThreadPoolExecutor(max_workers=min(IMAGE_WORKERS, len(wanted))) as pool:
            described = list(pool.map(describe, wanted))
        # Handled in repository order, so evidence and failures stay deterministic
        # and report mode raises the first failure in that order.
        for repo, (images, error) in zip(wanted, described):
            name = repo["repositoryName"]
            for image in images:
                if image.get("imageManifestMediaType") in INDEX_MEDIA_TYPES:
                    index_digests += 1
                    if set(image_tags) & set(image.get("imageTags") or []):
                        tagged_indexes.setdefault(name, []).append(image)
                    continue
                ecr_images.append(
                    {
                        **{k: image[k] for k in IMAGE_FIELDS if k in image},
                        "repository": name,
                        "repository_arn": repo["repositoryArn"],
                        "resource_id": f"{repo['repositoryArn']}/{image['imageDigest']}",
                    }
                )
            if error is not None:
                with attempt("ecr describe-images", repository=name):
                    raise error

    # A tag usually sits on an index, while Inspector scans the untagged images
    # it points to. Read each tagged index to give those images its tags.
    index_tags = {}
    for name, indexes in tagged_indexes.items():
        with attempt("ecr batch-get-image", repository=name):
            for start in range(0, len(indexes), INDEX_BATCH):
                chunk = indexes[start : start + INDEX_BATCH]
                response = aws.call(
                    "ecr",
                    "batch-get-image",
                    repositoryName=name,
                    imageIds=[{"imageDigest": i["imageDigest"]} for i in chunk],
                    acceptedMediaTypes=sorted(INDEX_MEDIA_TYPES),
                )
                if response.get("failures"):
                    reasons = "; ".join(
                        f"{f.get('imageId', {}).get('imageDigest')}: {f.get('failureCode')}"
                        for f in response["failures"]
                    )
                    raise CollectionError(f"ECR could not read index manifests in {name}: {reasons}")
                tags_of = {
                    i["imageDigest"]: set(image_tags) & set(i.get("imageTags") or []) for i in chunk
                }
                for image in response.get("images") or []:
                    try:
                        manifest = json.loads(image["imageManifest"])
                    except (KeyError, TypeError, ValueError) as exc:
                        raise CollectionError(f"ECR returned an unreadable index manifest in {name}") from exc
                    tags = tags_of.get((image.get("imageId") or {}).get("imageDigest"), set())
                    for child in index_images(manifest):
                        index_tags.setdefault((name, child), set()).update(tags)
    for image in ecr_images:
        tags = index_tags.get((image["repository"], image["imageDigest"]))
        if tags:
            image["index_tags"] = sorted(tags)

    cutoff = (
        now - timedelta(days=scope["pushed_within_days"]) if scope["pushed_within_days"] else None
    )
    inventory = [i for i in ecr_images if selected(i, scope, cutoff)]
    inventory_keys = {(i["repository"], i["imageDigest"]) for i in inventory}
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
    if repositories:
        finding_filter["ecrImageRepositoryName"] = equal(repositories)
        coverage_filter["ecrRepositoryName"] = equal(repositories)
    if scope["in_use_only"]:
        finding_filter["ecrImageInUseCount"] = [{"lowerInclusive": 1}]
        coverage_filter["ecrImageInUseCount"] = [{"lowerInclusive": 1}]
    if scope["last_in_use_days"]:
        since = now - timedelta(days=scope["last_in_use_days"])
        finding_filter["ecrImageLastInUseAt"] = [{"startInclusive": since}]
        coverage_filter["ecrImageLastInUseAt"] = [{"startInclusive": since}]
    if cutoff is not None:
        # Coverage has no push-date filter; the inventory applies the cutoff locally.
        finding_filter["ecrImagePushedAt"] = [{"startInclusive": cutoff}]
    if scope["min_severity"]:
        finding_filter["severity"] = equal(severities_at_or_above(scope["min_severity"]))
    # With image_tags, the selected images are named by digest: an image that
    # inherits its index's tags is untagged in Inspector, so a tag filter misses
    # it. Coverage has no digest filter and is matched to the inventory below.
    # Each query also names the repository: a digest is content-addressed, so
    # the same image in another repository would otherwise come back too.
    if image_tags:
        by_repository = {}
        for image in inventory:
            by_repository.setdefault(image["repository"], set()).add(image["imageDigest"])
        finding_filters = []
        for name, digests in sorted(by_repository.items()):
            hashes = sorted(digests)
            finding_filters.extend(
                {
                    **finding_filter,
                    "ecrImageRepositoryName": equal([name]),
                    "ecrImageHash": equal(hashes[start : start + HASHES_PER_QUERY]),
                }
                for start in range(0, len(hashes), HASHES_PER_QUERY)
            )
    else:
        finding_filters = [finding_filter]

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

        def list_findings(query):
            """Every page of one query; earlier pages survive a failure."""
            records, error = [], None
            try:
                records.extend(
                    aws.pages("inspector2", "list-findings", "findings", filterCriteria=query)
                )
            except Exception as exc:
                error = exc
            return records, error

        def queried_findings(pool):
            # Handled in query order, so evidence and failures stay deterministic
            # and report mode raises the first failure in that order.
            for records, error in in_order(pool, list_findings, finding_filters, FINDING_QUERIES_AHEAD):
                yield from records
                if error is not None:
                    raise error

        with attempt("inspector2 list-findings"), ThreadPoolExecutor(
            max_workers=max(1, min(IMAGE_WORKERS, len(finding_filters)))
        ) as pool:
            # Created here, before the workers share it: clients are thread-safe, sessions are not.
            aws.client("inspector2")
            # closing() cancels unstarted queries as soon as a failure stops the loop.
            with closing(queried_findings(pool)) as found:
                for finding in found:
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
                                and (detail["repositoryName"], detail["imageHash"]) not in inventory_keys
                            )
                        ):
                            raise CollectionError(
                                "Inspector returned incomplete or out-of-scope ECR resource details"
                            )
                    # Duplicate pages may overlap while Inspector updates its live dataset.
                    # A digest stands in for the full record, which is not kept.
                    digest = canonical_digest(finding)
                    previous = finding_digests.get(finding["findingArn"])
                    if previous is not None and previous != digest:
                        raise CollectionError(
                            "Inspector finding changed between pages; retry for a consistent report"
                        )
                    if previous is None:
                        finding_digests[finding["findingArn"]] = digest
                        findings[finding["findingArn"]] = compact_finding(finding, vulnerabilities)

    by_resource = {c.get("resourceId"): c for c in coverage}
    if scope["in_use_only"] or scope["last_in_use_days"]:
        inventory = [i for i in inventory if i["resource_id"] in by_resource]
        inventory_keys = {(i["repository"], i["imageDigest"]) for i in inventory}
    in_scope = {i["resource_id"] for i in inventory}
    coverage = [c for c in coverage if c.get("resourceId") in in_scope]
    gaps = []
    for image in inventory:
        scanned = by_resource.get(image["resource_id"])
        if (
            not scanned
            or scanned.get("scanStatus", {}).get("statusCode") != "ACTIVE"
            or not scanned.get("lastScannedAt")
        ):
            gaps.append(image["resource_id"])
    findings_list = sorted(findings.values(), key=lambda f: f["findingArn"])
    known_images = inventory_keys
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
    complete = ecr_state == "ENABLED" and not failures
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
                **scope,
                "pushed_after": cutoff.isoformat() if cutoff else None,
                "finding_status": ["ACTIVE"],
                "resource_type": RESOURCE_TYPE,
            },
            "collection_complete": not failures,
            "scan_status": scan_status,
            "findings_collection_status": "incomplete"
            if failures
            else ("collected" if ecr_state == "ENABLED" else "not_enabled"),
            "summary": {
                "finding_count": len(findings_list) if complete else None,
                "severity_counts": {s: severities[s] for s in (*SEVERITIES, "UNKNOWN")}
                if complete
                else None,
                "vulnerability_count": len(per_vulnerability) if complete else None,
                "repository_image_count": len(ecr_images) if not failures else None,
                "image_count": len(inventory) if not failures else None,
                "index_digest_count": index_digests if not failures else None,
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
            "vulnerabilities": dict(sorted(vulnerabilities.items())),
            "findings": findings_list,
        },
    }


def csv_rows(evidence):
    meta = evidence["metadata"]
    vulnerabilities = evidence["results"]["vulnerabilities"]
    repository_arns = {i["repository"]: i["repository_arn"] for i in evidence["results"]["images"]}
    for compact in evidence["results"]["findings"]:
        finding = expand_finding(compact, vulnerabilities)
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
                "Repository ARN": repository_arns[image["repositoryName"]],
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


def scope_suffix(meta, scope):
    """Short hash of profile and scope, so distinct targets never share a file name.

    Settings added after 0.1.0 count only when set, so a target that does not
    use them keeps the file name it had before they existed.
    """
    original = ("repositories", "image_tags", "finding_status", "resource_type")
    keyed = {
        k: v for k, v in scope.items() if k in original or (k != "pushed_after" and v)
    }
    text = json.dumps({"profile": meta["profile"], **keyed}, sort_keys=True)
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def write_output(evidence, report, directory, allow_empty=False, allow_no_images=False):
    results = evidence["results"]
    if report:
        if not results["collection_complete"] or evidence["metadata"].get("partial_failure"):
            raise CollectionError("Inspector collection is incomplete; no issue report written")
        if results["findings_collection_status"] != "collected":
            raise CollectionError("Inspector ECR scanning is not enabled; no issue report written")
        if not results["images"] and not allow_no_images:
            total = results.get("summary", {}).get("repository_image_count")
            raise CollectionError(
                f"No images matched the scope ({total} images in the selected repositories); "
                "set allow_no_images=true and allow_empty=true only after verifying scope",
                "bad_config",
            )
        if results["coverage_gaps"]:
            gaps = results["coverage_gaps"]
            raise CollectionError(
                f"{len(gaps)} of {len(results['images'])} selected images have missing or inactive "
                f"scan coverage (first: {', '.join(gaps[:3])}); no issue report written"
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
    suffix = scope_suffix(meta, results["scope"])
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
                # Compact separators: indentation alone inflates large evidence severalfold.
                json.dump(evidence, stream, separators=(",", ":"))
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
        scope = read_scope()
        allow_empty = read_bool("AWS_INSPECTOR_ALLOW_EMPTY")
        allow_no_images = read_bool("AWS_INSPECTOR_ALLOW_NO_IMAGES")
        if report and allow_no_images and not allow_empty:
            raise CollectionError(
                "allow_no_images=true requires allow_empty=true: a report with no images has no findings",
                "bad_config",
            )
        evidence = collect(Aws(), scope, allow_partial=not report)
        summary = evidence["results"]["summary"]
        logging.info(
            "Images: %s in the selected repositories, %s matched the scope",
            summary["repository_image_count"],
            summary["image_count"],
        )
        dest = write_output(
            evidence,
            report,
            Path(os.environ.get("EVIDENCE_DIR", "./evidence")),
            allow_empty,
            allow_no_images,
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
