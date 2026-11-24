#!/usr/bin/env python3
"""
Tenable Vulnerability Scan: export one Tenable.io scan run as a .nessus file.

Steps, one scan per invocation (the manifest fans out per scan_id):

  1. GET /scans/{id}/history and pick the newest run with status "completed".
     Refuse it if it is older than max_scan_age_days: a stopped schedule would
     otherwise upload the same old results every cycle.
  2. POST /scans/{id}/export?history_id=<that run> for format "nessus". The
     history_id pins the export to the run that was checked; Tenable does not
     document which run it exports without one.
  3. Poll /export/{file}/status until "ready". Stop at once on "error".
  4. Stream /export/{file}/download to <name>.part, rename it when complete,
     and refuse a report with no <ReportHost>: an aborted run or offline
     targets still give valid XML, and an empty report processed with a cycle
     close resolves every open issue on the assessment.

Every request retries HTTP 429, 502, 503 and 504, and waits for retry-after
when Tenable sends it.

THE ONE RULE: write the tool's bytes to disk exactly as received. Paramify's
assessment intake parses the .nessus XML natively; any re-serialization here
is a broken import there. The <ReportHost> count reads the bytes as they
stream past and does not change them.
"""

from __future__ import annotations

import logging
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("tenable_vuln_scan")

DEFAULT_BASE_URL = "https://cloud.tenable.com"
DEFAULT_MAX_SCAN_AGE_DAYS = 35.0
DEFAULT_EXPORT_WAIT_SECONDS = 600
# runtime.timeout in fetcher.yaml is 3600: the longest export wait plus time
# for history, retries and the download.
MAX_EXPORT_WAIT_SECONDS = 2400
POLL_INTERVAL = 10
REQUEST_TIMEOUT = (10, 60)
DOWNLOAD_TIMEOUT = (10, 300)
HISTORY_PAGE_SIZE = 50
HISTORY_MAX_PAGES = 100

RETRY_STATUSES = {429, 502, 503, 504}
RETRIES = 4
MAX_RETRY_WAIT = 60

REPORT_HOST_TAG = b"<ReportHost"

# Tests replace these.
_sleep = time.sleep
_monotonic = time.monotonic


class TenableError(RuntimeError):
    def __init__(self, message: str, code: str = "partial_failure"):
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------- config

def target_suffix() -> str:
    value = os.environ.get("TENABLE_SCAN_ID", "").strip()
    if not value:
        return ""
    return "_" + re.sub(r"[^A-Za-z0-9._-]+", "_", value)


def base_url() -> str:
    raw = os.environ.get("TENABLE_API_BASE_URL", "").strip() or DEFAULT_BASE_URL
    parts = urlsplit(raw)
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment):
        # The API keys go to this host in a header, so never over plaintext.
        raise TenableError(f"api_base_url must be a plain https:// URL (got {raw!r})", "bad_config")
    return raw.rstrip("/")


def positive_number(env: str, field: str, default: float, maximum: Optional[float] = None) -> float:
    raw = os.environ.get(env, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        value = -1.0
    if not value > 0 or (maximum is not None and value > maximum):
        limit = f" up to {maximum:g}" if maximum is not None else ""
        raise TenableError(f"{field} must be a positive number{limit} (got {raw!r})", "bad_config")
    return value


def allow_empty() -> bool:
    raw = os.environ.get("TENABLE_ALLOW_EMPTY", "").strip().lower()
    if raw not in {"", "true", "false"}:
        raise TenableError(f"allow_empty must be true or false (got {raw!r})", "bad_config")
    return raw == "true"


# ------------------------------------------------------------------- requests

def _retry_wait(resp: Optional[requests.Response], attempt: int) -> float:
    wait = float(2 ** attempt)
    raw = (resp.headers.get("retry-after") if resp is not None else None) or ""
    if raw.strip():
        try:
            wait = float(raw)
        except ValueError:
            try:
                wait = parsedate_to_datetime(raw).timestamp() - time.time()
            except (TypeError, ValueError, OverflowError):
                pass
    return max(wait, 0.0)


def send(method: str, url: str, what: str, headers: Dict[str, str], **kwargs: Any) -> requests.Response:
    """One Tenable request. Retries 429/502/503/504 and connection errors.

    Returns any other response (the caller checks its status). A returned
    streaming response must be closed by the caller.
    """
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    for attempt in range(RETRIES + 1):
        resp: Optional[requests.Response] = None
        try:
            resp = requests.request(method, url, headers=headers, allow_redirects=False, **kwargs)
        except requests.RequestException as e:
            code, detail = "target_unreachable", f"{type(e).__name__}: {e}"
        else:
            if resp.status_code not in RETRY_STATUSES:
                return resp
            code = "rate_limited" if resp.status_code == 429 else "partial_failure"
            detail = f"HTTP {resp.status_code}"
            resp.close()
        if attempt == RETRIES:
            raise TenableError(f"{what} failed after {attempt + 1} attempts ({detail})", code)
        wait = _retry_wait(resp, attempt)
        if wait > MAX_RETRY_WAIT:
            raise TenableError(
                f"{what}: Tenable asked to wait {wait:.0f} seconds, more than the "
                f"{MAX_RETRY_WAIT} second limit; run again later ({detail})", code)
        logger.warning("Retrying %s in %.0f seconds (%s)", what, wait, detail)
        _sleep(wait)
    raise AssertionError("unreachable")


def check(resp: requests.Response, what: str, scan_id: str) -> None:
    status = resp.status_code
    if status == 200:
        return
    if status == 401:
        raise TenableError(f"{what}: Tenable rejected the API keys (HTTP 401)", "auth_failed")
    if status == 403:
        raise TenableError(f"{what}: the API keys do not have permission for scan {scan_id} (HTTP 403). "
                           "The user needs at least Can View on the scan", "not_authorized")
    if status == 404:
        raise TenableError(f"{what}: scan {scan_id} or its export was not found (HTTP 404)", "bad_config")
    raise TenableError(f"{what} failed (HTTP {status}): {_snippet(resp)}")


def _snippet(resp: requests.Response) -> str:
    try:
        return " ".join(resp.text[:200].split())
    except Exception:  # noqa: BLE001 - only for a message
        return "<unreadable body>"


def json_body(resp: requests.Response, what: str) -> Dict[str, Any]:
    try:
        body = resp.json()
    except ValueError:
        raise TenableError(f"{what}: the response is not JSON; check api_base_url. "
                           f"It starts: {_snippet(resp)}") from None
    if not isinstance(body, dict):
        raise TenableError(f"{what}: unexpected response shape ({type(body).__name__})")
    return body


# ----------------------------------------------------------------- the steps

def latest_completed_run(api: str, headers: Dict[str, str], scan_id: str) -> Dict[str, Any]:
    """The newest history entry with status "completed".

    Asks for newest first, but checks the order itself: if a page comes back
    out of order, it reads every page rather than trust the sort.
    """
    best: Optional[Dict[str, Any]] = None
    for page in range(HISTORY_MAX_PAGES):
        resp = send("GET", f"{api}/scans/{scan_id}/history", "scan history request", headers,
                    params={"limit": HISTORY_PAGE_SIZE, "offset": page * HISTORY_PAGE_SIZE,
                            "sort": "start_date:desc", "exclude_rollover": "false"})
        check(resp, "scan history request", scan_id)
        body = json_body(resp, "scan history request")
        runs = body.get("history") or []
        if not isinstance(runs, list):
            raise TenableError("scan history request: 'history' is not a list")
        for run in runs:
            if (isinstance(run, dict) and run.get("status") == "completed"
                    and isinstance(run.get("id"), int) and isinstance(run.get("time_end"), (int, float))
                    and (best is None or run["time_end"] > best["time_end"])):
                best = run
        starts = [r.get("time_start") or 0 for r in runs if isinstance(r, dict)]
        newest_first = all(a >= b for a, b in zip(starts, starts[1:]))
        total = (body.get("pagination") or {}).get("total")
        last_page = (len(runs) < HISTORY_PAGE_SIZE
                     or (isinstance(total, int) and (page + 1) * HISTORY_PAGE_SIZE >= total))
        if (best is not None and newest_first) or last_page:
            break
    else:
        raise TenableError(f"scan {scan_id} has more than {HISTORY_MAX_PAGES * HISTORY_PAGE_SIZE} runs "
                           "in an order this fetcher could not trust")
    if best is None:
        raise TenableError(f"scan {scan_id} has no completed run. Check its runs in Tenable "
                           "(aborted, canceled or still running runs are not exported)")
    return best


def check_age(run: Dict[str, Any], scan_id: str, max_age_days: float,
              now: Optional[datetime] = None) -> None:
    ended = datetime.fromtimestamp(run["time_end"], tz=timezone.utc)
    age_days = ((now or datetime.now(timezone.utc)) - ended).total_seconds() / 86400
    if age_days > max_age_days:
        raise TenableError(
            f"the newest completed run of scan {scan_id} ended {age_days:.1f} days ago "
            f"({ended:%Y-%m-%d}), over the {max_age_days:g} day limit (max_scan_age_days). "
            "Check the scan's schedule in Tenable")
    logger.info("Scan %s run %s completed %.1f days ago", scan_id, run["id"], age_days)


def request_export(api: str, headers: Dict[str, str], scan_id: str, history_id: int) -> str:
    resp = send("POST", f"{api}/scans/{scan_id}/export", "export request", headers,
                params={"history_id": history_id}, json={"format": "nessus"})
    check(resp, "export request", scan_id)
    file_id = json_body(resp, "export request").get("file")
    if not file_id:
        raise TenableError("export request: the response has no file ID")
    return str(file_id)


def wait_until_ready(api: str, headers: Dict[str, str], scan_id: str, file_id: str,
                     wait_seconds: float) -> None:
    url = f"{api}/scans/{scan_id}/export/{file_id}/status"
    deadline = _monotonic() + wait_seconds
    while True:
        resp = send("GET", url, "export status check", headers)
        check(resp, "export status check", scan_id)
        status = json_body(resp, "export status check").get("status")
        if status == "ready":
            return
        if status == "error":
            raise TenableError(f"Tenable reported an error for export {file_id} of scan {scan_id}")
        if status == "loading":
            logger.info("Export %s is loading; checking again in %ds", file_id, POLL_INTERVAL)
        else:
            logger.warning("Export %s has an unknown status %r; checking again in %ds",
                           file_id, status, POLL_INTERVAL)
        if _monotonic() + POLL_INTERVAL > deadline:
            raise TenableError(f"export {file_id} of scan {scan_id} was not ready after {wait_seconds:g} "
                               "seconds (export_wait_seconds)")
        _sleep(POLL_INTERVAL)


def download(api: str, headers: Dict[str, str], scan_id: str, file_id: str, dest: Path) -> tuple[int, bool]:
    """Stream the export to dest. Returns (bytes, whether it has a <ReportHost>).

    Writes to <dest>.part and renames it only when the stream is complete, so a
    failed run never leaves a truncated report in issue-reports/.
    """
    tmp = dest.with_name(dest.name + ".part")
    keep = len(REPORT_HOST_TAG) - 1
    try:
        resp = send("GET", f"{api}/scans/{scan_id}/export/{file_id}/download", "download",
                    {**headers, "Accept": "application/octet-stream"},
                    stream=True, timeout=DOWNLOAD_TIMEOUT)
        with resp:
            check(resp, "download", scan_id)
            size, has_host, tail = 0, False, b""
            try:
                with tmp.open("wb") as fh:
                    for chunk in resp.iter_content(chunk_size=1024 * 1024):
                        if not chunk:
                            continue
                        fh.write(chunk)
                        size += len(chunk)
                        if not has_host:
                            # The tail keeps a tag split across two chunks findable.
                            window = tail + chunk
                            has_host = REPORT_HOST_TAG in window
                            tail = window[-keep:]
            except requests.RequestException as e:
                raise TenableError(f"download was cut off after {size} bytes ({type(e).__name__}: {e})",
                                   "target_unreachable") from None
        tmp.replace(dest)
        return size, has_host
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# ----------------------------------------------------------------------- main

def _stop_on_sigterm(signum: int, frame: Any) -> None:
    # The runner sends SIGTERM on timeout. SystemExit unwinds through
    # download(), which deletes the .part file.
    raise SystemExit(128 + signum)


def collect(output_dir: Path) -> Path:
    access_key = os.environ.get("TENABLE_ACCESS_KEY", "").strip()
    secret_key = os.environ.get("TENABLE_SECRET_KEY", "").strip()
    scan_id = os.environ.get("TENABLE_SCAN_ID", "").strip()
    if not access_key or not secret_key:
        raise TenableError("TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY must both be set", "bad_config")
    if not scan_id:
        raise TenableError("TENABLE_SCAN_ID is not set", "bad_config")
    if not re.fullmatch(r"[1-9]\d{0,18}", scan_id):
        # It goes into the URL path, so check it before any request.
        raise TenableError(f"scan_id must be a numeric Tenable scan ID (got {scan_id!r})", "bad_config")
    api = base_url()
    max_age = positive_number("TENABLE_MAX_SCAN_AGE_DAYS", "max_scan_age_days", DEFAULT_MAX_SCAN_AGE_DAYS)
    wait = positive_number("TENABLE_EXPORT_WAIT_SECONDS", "export_wait_seconds",
                           DEFAULT_EXPORT_WAIT_SECONDS, MAX_EXPORT_WAIT_SECONDS)
    empty_ok = allow_empty()

    headers = {
        "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
        "Accept": "application/json",
    }
    run = latest_completed_run(api, headers, scan_id)
    check_age(run, scan_id, max_age)
    file_id = request_export(api, headers, scan_id, run["id"])
    wait_until_ready(api, headers, scan_id, file_id, wait)

    output_dir.mkdir(parents=True, exist_ok=True)
    dest = output_dir / f"tenable_vuln_scan{target_suffix()}.nessus"
    size, has_host = download(api, headers, scan_id, file_id, dest)
    if size == 0:
        dest.unlink(missing_ok=True)
        raise TenableError("Tenable returned an empty file")
    if not has_host and not empty_ok:
        dest.unlink(missing_ok=True)
        raise TenableError(f"run {run['id']} of scan {scan_id} has no hosts (no <ReportHost>). Check that the "
                           "run scanned its targets, or set allow_empty=true if no hosts is expected")
    logger.info("Report saved to %s (%d bytes) from scan %s run %s", dest, size, scan_id, run["id"])
    return dest


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()
    try:
        collect(Path(os.environ.get("EVIDENCE_DIR", "./evidence")))
    except TenableError as e:
        report_failure(str(e), e.code)
        return 1
    except OSError as e:
        report_failure(f"could not write the report: {e}", "internal_error")
        return 1
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _stop_on_sigterm)
    raise SystemExit(main())
