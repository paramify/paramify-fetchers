#!/usr/bin/env python3
"""
Wiz Issues report -> <run>/issue-reports/wiz_issues_report.csv

Uses the Wiz Reports API: find (or create) this fetcher's ISSUES report, update
its parameters, rerun it, wait for a run that started after this fetcher did,
then stream the CSV to disk byte-for-byte.

Differences from the legacy wiz_issues_report.py, all deliberate:
  - No upload: uploaders/paramify_issues sends the file into the pipeline.
  - No DELTA_MODE: a delta processed with a cycle close auto-closes every issue
    the delta did not list.
  - No column dropping: the legacy script removed "Resource original JSON".
    Issue reports are sent as the tool produced them, and the file intake
    preset ignores columns it does not map. (Size: the uploader refuses files
    over 512 MB.)
  - No state.json: the report is found by name each run.
  - The download is written to a temp name and renamed only when complete, so a
    failed run never leaves a truncated CSV in issue-reports/.
"""

import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from fetcher_status import report_failure  # noqa: E402
from wiz_client import WizClient, WizError, check_download_url  # noqa: E402

logger = logging.getLogger("wiz_issues_report")

OUTPUT_NAME = "wiz_issues_report.csv"
POLL_SECONDS = float(os.environ.get("WIZ_REPORT_POLL_SECONDS", "20"))
MAX_WAIT_SECONDS = float(os.environ.get("WIZ_REPORT_MAX_WAIT", "1500"))

# NOTE (unverified against the live Wiz schema): the `reports` list query and its
# `search` filter, and `lastRun.runAt`, are not used by the legacy fetcher. They
# are needed only to find the report by name and to reject a stale run. Set
# report_id to skip the lookup. Verify both against a real tenant before GA.
FIND_REPORTS = """
query FindReports($search: String) {
  reports(first: 50, filterBy: { search: $search }) {
    nodes { id name type { id } }
  }
}"""

CREATE_REPORT = """
mutation CreateReport($input: CreateReportInput!) {
  createReport(input: $input) { report { id } }
}"""

UPDATE_REPORT = """
mutation UpdateReport($input: UpdateReportInput!) {
  updateReport(input: $input) { report { id } }
}"""

RERUN_REPORT = """
mutation RerunReport($reportId: ID!) {
  rerunReport(input: { id: $reportId }) { report { id } }
}"""

REPORT_STATUS = """
query ReportDownloadUrl($reportId: ID!) {
  report(id: $reportId) { lastRun { url status runAt } }
}"""


def issue_params() -> dict:
    return {"type": "DETAILED",
            "issueFilters": {"status": ["OPEN", "IN_PROGRESS", "RESOLVED"]}}


def find_or_create_report(wiz: WizClient, name: str, project_id: str) -> str:
    report_id = os.environ.get("WIZ_REPORT_ID", "").strip()
    if report_id:
        logger.info("Using configured Wiz report %s", report_id)
    else:
        nodes = (wiz.query(FIND_REPORTS, {"search": name}).get("reports") or {}).get("nodes") or []
        matches = [n for n in nodes if n.get("name") == name]
        if len(matches) > 1:
            raise WizError(f"{len(matches)} Wiz reports are named {name!r}; set report_id "
                           f"to the one to use", "bad_config")
        if not matches:
            logger.info("No Wiz report named %r; creating it", name)
            data = wiz.query(CREATE_REPORT, {"input": {
                "name": name, "type": "ISSUES", "projectId": project_id,
                "issueParams": issue_params()}})
            return data["createReport"]["report"]["id"]
        report_id = matches[0]["id"]
        logger.info("Found Wiz report %r (%s)", name, report_id)
    # Always re-apply the parameters: cheap, idempotent, and it is what makes a
    # report someone edited in the Wiz UI produce the same export as ours.
    wiz.query(UPDATE_REPORT, {"input": {"id": report_id, "override": {
        "name": name, "issueParams": issue_params()}}})
    wiz.query(RERUN_REPORT, {"reportId": report_id})
    return report_id


def wait_for_run(wiz: WizClient, report_id: str, started: datetime) -> str:
    deadline = time.monotonic() + MAX_WAIT_SECONDS
    reruns = 0
    while time.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
        run = ((wiz.query(REPORT_STATUS, {"reportId": report_id}).get("report") or {})
               .get("lastRun") or {})
        status = run.get("status")
        run_at = run.get("runAt")
        if run_at:
            try:
                ts = datetime.fromisoformat(run_at.replace("Z", "+00:00"))
                if ts < started:
                    logger.info("Last run %s predates this fetch; waiting for the rerun", run_at)
                    continue
            except ValueError:
                pass
        logger.info("Report status: %s", status)
        if status == "COMPLETED" and run.get("url"):
            return run["url"]
        if status in ("FAILED", "EXPIRED"):
            if reruns >= 3:
                raise WizError(f"Wiz report run {status} three times", "partial_failure")
            reruns += 1
            logger.warning("Report run %s; rerunning (%d/3)", status, reruns)
            wiz.query(RERUN_REPORT, {"reportId": report_id})
    raise WizError(f"Wiz report not ready after {MAX_WAIT_SECONDS:.0f}s", "partial_failure")


def download(url: str, dest: Path) -> int:
    check_download_url(url)
    tmp = dest.with_name(dest.name + ".part")
    try:
        # No Authorization header: the presigned URL carries its own signature,
        # and the Wiz bearer must never go to a storage host.
        with requests.get(url, stream=True, timeout=(10, 120)) as r:
            if r.status_code != 200:
                raise WizError(f"report download failed (HTTP {r.status_code})", "partial_failure")
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
    quoted newlines — used only to tell 'header only' from 'has findings')."""
    with path.open("rb") as fh:
        fh.readline()
        for line in fh:
            if line.strip():
                return 1
    return 0


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    started = datetime.now(timezone.utc)
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / OUTPUT_NAME
    name = os.environ.get("WIZ_REPORT_NAME", "").strip() or "Paramify-Wiz-Issues"
    project = os.environ.get("WIZ_PROJECT_ID", "").strip() or "*"
    try:
        wiz = WizClient.from_env()
        wiz.authenticate()
        report_id = find_or_create_report(wiz, name, project)
        url = wait_for_run(wiz, report_id, started)
        size = download(url, dest)
    except WizError as e:
        report_failure(str(e), e.code)
        return 1
    except requests.RequestException as e:
        report_failure(f"Wiz request failed: {e.__class__.__name__}", "target_unreachable")
        return 1

    if size == 0:
        dest.unlink(missing_ok=True)
        report_failure("Wiz returned an empty report", "partial_failure")
        return 1
    if not data_rows(dest) and os.environ.get("WIZ_ALLOW_EMPTY", "").lower() != "true":
        dest.unlink(missing_ok=True)
        report_failure("Wiz report has a header and no rows; set allow_empty=true if "
                       "zero issues is genuinely expected", "partial_failure")
        return 1
    logger.info("Saved %s (%d bytes) from Wiz report %s", dest, size, report_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
