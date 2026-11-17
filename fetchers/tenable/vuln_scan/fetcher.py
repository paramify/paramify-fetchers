#!/usr/bin/env python3
"""
Tenable Vulnerability Scan: export a scan as .nessus by scan ID.

Tenable.io's export is asynchronous: request the export, poll until the status
is "ready", then stream the binary download to disk unmodified. A full scan
export is routinely hundreds of megabytes; streaming is both practical and
structural — there is no intermediate object to be tempted into editing.

THE ONE RULE: write the tool's bytes to disk exactly as received. Paramify's
assessment intake parses the .nessus XML natively; any re-serialization here
is a broken import there.
"""

import json
import logging
import os
import re
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

logger = logging.getLogger("tenable_vuln_scan")

_BASE_URL = "https://cloud.tenable.com"
_POLL_INTERVAL = int(os.environ.get("_TENABLE_POLL_INTERVAL", "10"))  # override in tests
_POLL_TIMEOUT = 600   # give up after 10 minutes of polling
_DOWNLOAD_TIMEOUT = 300


def report_failure(reason: str, code: str | None = None) -> None:
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    Path(path).write_text(json.dumps({"error": reason} | ({"code": code} if code else {})))


def target_suffix() -> str:
    value = os.environ.get("TENABLE_SCAN_ID", "").strip()
    if not value:
        return ""
    return "_" + re.sub(r"[^A-Za-z0-9._-]+", "_", value)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    access_key = os.environ.get("TENABLE_ACCESS_KEY", "").strip()
    secret_key = os.environ.get("TENABLE_SECRET_KEY", "").strip()
    scan_id = os.environ.get("TENABLE_SCAN_ID", "").strip()
    base_url = os.environ.get("TENABLE_API_BASE_URL", _BASE_URL).rstrip("/")

    if not access_key or not secret_key:
        report_failure("TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY must both be set", "bad_config")
        return 1
    if not scan_id:
        report_failure("TENABLE_SCAN_ID is not set", "bad_config")
        return 1

    headers = {
        "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"tenable_vuln_scan{target_suffix()}.nessus"

    # Step 1: request the async export
    try:
        resp = requests.post(
            f"{base_url}/scans/{scan_id}/export",
            headers=headers,
            json={"format": "nessus"},
            timeout=30,
        )
    except requests.RequestException as e:
        report_failure(f"could not reach Tenable: {e}", "target_unreachable")
        return 1

    if resp.status_code in (401, 403):
        report_failure(f"Tenable rejected the credential (HTTP {resp.status_code})", "auth_failed")
        return 1
    if resp.status_code == 404:
        report_failure(f"scan {scan_id!r} not found (HTTP 404)", "bad_config")
        return 1
    if resp.status_code != 200:
        report_failure(
            f"export request failed (HTTP {resp.status_code}): {resp.text[:300]}",
            "partial_failure",
        )
        return 1

    file_id = resp.json().get("file")
    if not file_id:
        report_failure("Tenable export response did not include a file ID", "partial_failure")
        return 1

    # Step 2: poll until ready
    status_url = f"{base_url}/scans/{scan_id}/export/{file_id}/status"
    deadline = time.monotonic() + _POLL_TIMEOUT
    while True:
        if time.monotonic() > deadline:
            report_failure(
                f"export {file_id} did not become ready within {_POLL_TIMEOUT}s",
                "partial_failure",
            )
            return 1
        try:
            status_resp = requests.get(status_url, headers=headers, timeout=15)
        except requests.RequestException as e:
            report_failure(f"could not poll export status: {e}", "target_unreachable")
            return 1

        if status_resp.status_code != 200:
            report_failure(
                f"status check failed (HTTP {status_resp.status_code}): {status_resp.text[:200]}",
                "partial_failure",
            )
            return 1

        status = status_resp.json().get("status", "")
        if status == "ready":
            break
        logger.info("Export status: %s — waiting %ds", status, _POLL_INTERVAL)
        time.sleep(_POLL_INTERVAL)

    # Step 3: stream the download to disk unmodified
    download_url = f"{base_url}/scans/{scan_id}/export/{file_id}/download"
    try:
        dl_resp = requests.get(
            download_url,
            headers={**headers, "Accept": "application/octet-stream"},
            timeout=_DOWNLOAD_TIMEOUT,
            stream=True,
        )
    except requests.RequestException as e:
        report_failure(f"could not download the export: {e}", "target_unreachable")
        return 1

    if dl_resp.status_code != 200:
        report_failure(
            f"download failed (HTTP {dl_resp.status_code}): {dl_resp.text[:300]}",
            "partial_failure",
        )
        return 1

    try:
        with output_path.open("wb") as fh:
            for chunk in dl_resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    fh.write(chunk)
    except OSError as e:
        report_failure(f"could not write the report: {e}")
        return 1

    size = output_path.stat().st_size
    if size == 0:
        report_failure("Tenable returned an empty report", "partial_failure")
        return 1

    logger.info("Report saved to %s (%d bytes)", output_path, size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
