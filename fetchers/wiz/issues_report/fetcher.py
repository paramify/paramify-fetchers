#!/usr/bin/env python3
"""
Wiz Issues report -> <run>/issue-reports/wiz_issues_report.csv

Downloads the latest run of a Wiz Issues report, byte-for-byte, so the file is
Wiz's own CSV. Read-only: the report is created once in Wiz by a person and set
to rerun on a schedule there. This fetcher only finds it, checks its last run
completed recently, and downloads that run. It never creates, edits or reruns a
report (the shared client refuses to send a mutation), so the service account
needs read:reports and nothing that writes.

What the report contains (projects, statuses, columns) is the report's own
setting in Wiz. Change it there.

Differences from the legacy wiz_issues_report.py, all deliberate:
  - No upload: uploaders/paramify_issues sends the file into the pipeline.
  - No create / update / rerun: those are writes to the tenant.
  - No DELTA_MODE: a delta processed with a cycle close auto-closes every issue
    the delta did not list.
  - No column dropping: the legacy script removed "Resource original JSON".
    Issue reports are sent as the tool produced them, and the file intake
    preset ignores columns it does not map. (Size: the uploader refuses files
    over 512 MB.)
  - No state.json: the report is found by id or exact name each run.
  - The download is written to a temp name and renamed only when complete, so a
    failed run never leaves a truncated CSV in issue-reports/.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from wiz_client import (  # type: ignore  # noqa: E402
    WizAuthError,
    WizClient,
    WizConfigError,
    _failure_code,
    build_client,
    parse_ts,
    report_failure,
)

logger = logging.getLogger("wiz_issues_report")

OUTPUT_NAME = "wiz_issues_report.csv"
DEFAULT_REPORT_NAME = "Paramify-Wiz-Issues"
# A report scheduled every 24 hours, plus time for the run itself.
DEFAULT_MAX_AGE_HOURS = 26.0
DOWNLOAD_TIMEOUT = (10, 120)

# Verified against a live Wiz for Gov tenant: `search` is a substring match
# (it also returns e.g. "<name>-retired-..."), so the exact-name filter below
# is required.
FIND_REPORTS = """
query FindReports($search: String) {
  reports(first: 50, filterBy: { search: $search }) {
    nodes { id name type { id } }
  }
}"""

REPORT_STATUS = """
query ReportDownloadUrl($reportId: ID!) {
  report(id: $reportId) { lastRun { url status runAt } }
}"""


class ReportError(RuntimeError):
    def __init__(self, message: str, code: str = "partial_failure"):
        super().__init__(message)
        self.code = code


def call(client: WizClient, operation: str, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
    """One query; any failure the client recorded stops the run."""
    before = len(client.api_failures)
    data = client.graphql(operation, query, variables)
    failures = client.api_failures[before:]
    if failures:
        first = failures[0]
        raise ReportError(f"Wiz {operation} failed: {first.get('type')}: {first.get('message')}",
                          _failure_code(first))
    if data is None:
        raise ReportError(f"Wiz {operation} returned no data")
    return data


def find_report(client: WizClient, report_id: str, name: str) -> str:
    if report_id:
        logger.info("Using configured Wiz report %s", report_id)
        return report_id
    nodes = (call(client, "FindReports", FIND_REPORTS, {"search": name}).get("reports") or {}).get("nodes") or []
    matches = [n for n in nodes if n.get("name") == name]
    if len(matches) > 1:
        raise ReportError(f"{len(matches)} Wiz reports are named {name!r}; set report_id to the one to use",
                          "bad_config")
    if not matches:
        raise ReportError(
            f"no Wiz report is named {name!r}. Create it once in Wiz (an Issues report, scheduled to "
            f"rerun, e.g. daily), or set report_name / report_id to an existing one", "bad_config")
    logger.info("Found Wiz report %r (%s)", name, matches[0]["id"])
    return matches[0]["id"]


def latest_run(client: WizClient, report_id: str, max_age_hours: float,
               now: Optional[datetime] = None) -> str:
    """The download URL of the report's last run, if it completed recently enough."""
    report = call(client, "ReportDownloadUrl", REPORT_STATUS, {"reportId": report_id}).get("report")
    if not report:
        raise ReportError(f"Wiz report {report_id} was not found (deleted, or not visible to this "
                          "service account)", "bad_config")
    run = report.get("lastRun")
    if not run:
        raise ReportError(f"Wiz report {report_id} has never run. Run it once in Wiz and give it a "
                          "schedule", "bad_config")
    status = run.get("status")
    if status != "COMPLETED":
        raise ReportError(f"the last run of Wiz report {report_id} is {status}, not COMPLETED. If it is "
                          "still running, run this fetcher again once it finishes")
    ran_at = parse_ts(run.get("runAt"))
    if ran_at is None:
        raise ReportError(f"the last run of Wiz report {report_id} has no readable runAt "
                          f"({run.get('runAt')!r}), so its age cannot be checked")
    age_hours = ((now or datetime.now(timezone.utc)) - ran_at).total_seconds() / 3600
    if age_hours > max_age_hours:
        raise ReportError(
            f"the last run of Wiz report {report_id} is {age_hours:.1f} hours old (limit "
            f"{max_age_hours:g}, max_report_age_hours). Check the report's schedule in Wiz")
    url = run.get("url")
    if not url:
        raise ReportError(f"the last run of Wiz report {report_id} has no download URL")
    logger.info("Last run %s completed %.1f hours ago", run.get("runAt"), age_hours)
    return url


def check_download_url(url: str) -> None:
    """Wiz hands back a presigned https URL. The bearer token is never sent to it,
    but refuse plaintext and embedded credentials all the same."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise ReportError("Wiz returned a report download URL that is not plain https")


def download(url: str, dest: Path) -> int:
    check_download_url(url)
    tmp = dest.with_name(dest.name + ".part")
    try:
        # No Authorization header: the presigned URL carries its own signature,
        # and the Wiz bearer must never go to a storage host.
        with requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT) as r:
            if r.status_code != 200:
                raise ReportError(f"report download failed (HTTP {r.status_code})")
            with tmp.open("wb") as fh:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        fh.write(chunk)
        size = tmp.stat().st_size
        tmp.replace(dest)
        return size
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def data_rows(path: Path) -> int:
    """Rows after the header, counted on physical lines (cheap, approximate for
    quoted newlines; used only to tell 'header only' from 'has findings')."""
    with path.open("rb") as fh:
        fh.readline()
        for line in fh:
            if line.strip():
                return 1
    return 0


def max_age_hours() -> float:
    raw = os.environ.get("WIZ_MAX_REPORT_AGE_HOURS", "").strip()
    if not raw:
        return DEFAULT_MAX_AGE_HOURS
    try:
        value = float(raw)
    except ValueError:
        value = -1.0
    if not value > 0:
        raise WizConfigError(f"max_report_age_hours must be a positive number of hours (got {raw!r})")
    return value


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    dest = out_dir / OUTPUT_NAME
    report_id = os.environ.get("WIZ_REPORT_ID", "").strip()
    name = os.environ.get("WIZ_REPORT_NAME", "").strip() or DEFAULT_REPORT_NAME
    try:
        limit = max_age_hours()
        client = build_client()
        report_id = find_report(client, report_id, name)
        url = latest_run(client, report_id, limit)
        out_dir.mkdir(parents=True, exist_ok=True)
        size = download(url, dest)
    except WizConfigError as e:
        report_failure(str(e), "bad_config")
        return 1
    except WizAuthError as e:
        report_failure(str(e), "auth_failed")
        return 1
    except ReportError as e:
        report_failure(str(e), e.code)
        return 1
    except requests.RequestException as e:
        # Only the type: the message would quote the presigned URL.
        report_failure(f"report download failed: {type(e).__name__}", "target_unreachable")
        return 1

    if size == 0:
        dest.unlink(missing_ok=True)
        report_failure("Wiz returned an empty report", "partial_failure")
        return 1
    if not data_rows(dest) and os.environ.get("WIZ_ALLOW_EMPTY", "").strip().lower() != "true":
        dest.unlink(missing_ok=True)
        report_failure("Wiz report has a header and no rows; set allow_empty=true if "
                       "zero issues is genuinely expected", "partial_failure")
        return 1
    logger.info("Saved %s (%d bytes) from Wiz report %s", dest, size, report_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
