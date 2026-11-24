"""Inspector API plumbing shared by the Inspector collectors and reports.

Used by inspector_ecr.py (aws_inspector_ecr_findings, aws_inspector_ecr_report)
and by aws_inspector_findings_report. It holds what does not depend on the
resource type: the boto3 client and its strict pagination, setting readers,
concurrent finding queries with duplicate-page checks, CSV writing, atomic
publication and the failure wrapper. Every AWS request is read-only.
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
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import date, datetime, timezone
from itertools import islice
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure
from report_csv import csv_safe

# Highest first, after UNTRIAGED: a min_severity threshold keeps every severity
# up to its own, so an untriaged finding (which may be anything) is always kept.
SEVERITIES = ("UNTRIAGED", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
PAGE_SIZES = {
    ("ecr", "describe-repositories"): 1000,
    ("ecr", "describe-images"): 1000,
    ("inspector2", "list-coverage"): 200,
    ("inspector2", "list-findings"): 100,
}
WORKERS = 8
FINDING_QUERIES_AHEAD = 2 * WORKERS


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
                "boto3 is required for the Inspector fetchers (pip install -r requirements.txt)",
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
            max_pool_connections=WORKERS + 2,
        )
        self.clients = {}

    def client(self, service):
        # Clients are thread-safe; sessions are not. Create a client on the main
        # thread before workers share it.
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


def equal(values):
    return [{"comparison": "EQUALS", "value": value} for value in values]


def nonempty_strings(*values):
    return all(isinstance(value, str) and value for value in values)


def severities_at_or_above(minimum):
    return list(SEVERITIES[: SEVERITIES.index(minimum) + 1])


def canonical_digest(record):
    text = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).digest()


def first_sighting(seen, finding):
    """True the first time a finding ARN is seen; False for an identical repeat.

    Duplicate pages may overlap while Inspector updates its live dataset. A
    digest stands in for the full record, which `seen` does not keep. A repeat
    that differs means the dataset changed mid-read, so no consistent report
    exists.
    """
    digest = canonical_digest(finding)
    previous = seen.get(finding["findingArn"])
    if previous is not None and previous != digest:
        raise CollectionError("Inspector finding changed between pages; retry for a consistent report")
    if previous is None:
        seen[finding["findingArn"]] = digest
        return True
    return False


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


def query_findings(aws, queries):
    """Every page of every ListFindings filter, in query order.

    Queries run concurrently, but records come back in query order and the first
    failure in that order is raised after the records read before it, so callers
    that keep partial results stay deterministic. Wrap the generator in
    contextlib.closing() so unstarted queries are cancelled when a caller stops.
    """

    def pages(query):
        """Every page of one query; earlier pages survive a failure."""
        records, error = [], None
        try:
            records.extend(aws.pages("inspector2", "list-findings", "findings", filterCriteria=query))
        except Exception as exc:
            error = exc
        return records, error

    queries = list(queries)
    with ThreadPoolExecutor(max_workers=max(1, min(WORKERS, len(queries)))) as pool:
        # Created here, before the workers share it: clients are thread-safe, sessions are not.
        aws.client("inspector2")
        with closing(in_order(pool, pages, queries, FINDING_QUERIES_AHEAD)) as results:
            for records, error in results:
                yield from records
                if error is not None:
                    raise error


def write_csv(stream, columns, rows):
    """A header and rows, each string cell made safe for spreadsheets (fetchers/_lib/report_csv.py)."""
    writer = csv.DictWriter(stream, fieldnames=columns)
    writer.writeheader()
    writer.writerows({key: csv_safe(value) for key, value in row.items()} for row in rows)


def publish(directory, filename, write):
    """Write a file with write(stream), then publish it into directory by rename.

    A sibling staging file stays outside runner discovery even after SIGKILL.
    Publish by rename only: a cross-filesystem copy could expose partial bytes.
    """
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / filename
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
            write(stream)
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


def run(body):
    """body() with logging and .env loaded; any failure is reported and exits 1."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    load_dotenv()
    try:
        return body()
    except CollectionError as exc:
        report_failure(str(exc), exc.code)
        return 1
    except Exception as exc:
        report_failure(f"Inspector collection failed: {exc}", "internal_error")
        return 1
