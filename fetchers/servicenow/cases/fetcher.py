#!/usr/bin/env python3
"""
ServiceNow Cases

Pulls customer service cases from the ServiceNow Paramify Evidence API
and writes the raw JSON response as evidence. Supports an optional watermark
(sysparm_last_run) to limit the pull to records modified since the last run.
"""

import json
import logging
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

logger = logging.getLogger("servicenow_cases")


def report_failure(reason: str, code: str | None = None) -> None:
    """Report why this run failed; the runner puts it in the envelope's metadata.error.

    Call this on every path that returns non-zero. Without it the runner falls back
    to the tail of stderr, which is whatever you logged last. `code` is a
    machine-readable category (auth_failed, not_authorized, not_enabled,
    target_unreachable, rate_limited, bad_config, partial_failure).
    See docs/fetcher_contract.md § Output.
    """
    path = os.environ.get("FETCHER_STATUS_FILE")
    if not path:
        return
    Path(path).write_text(
        json.dumps({"error": reason} | ({"code": code} if code else {}))
    )


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself and reads env directly.
    # Runner + secret resolver will replace this when the framework lands.
    load_dotenv()

    username = os.environ.get("SERVICENOW_USERNAME", "").strip()
    if not username:
        report_failure("SERVICENOW_USERNAME is not set", "bad_config")
        return 1

    password = os.environ.get("SERVICENOW_PASSWORD", "").strip()
    if not password:
        report_failure("SERVICENOW_PASSWORD is not set", "bad_config")
        return 1

    api_url = os.environ.get("SERVICENOW_CASES_API_URL", "").strip().rstrip("/")
    if not api_url:
        report_failure("SERVICENOW_CASES_API_URL is not set", "bad_config")
        return 1

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    headers = {"Accept": "application/json"}

    last_run = os.environ.get("SERVICENOW_CASES_LAST_RUN", "").strip()
    params = {"sysparm_last_run": last_run} if last_run else {}

    try:
        resp = requests.get(api_url, headers=headers, params=params, auth=(username, password), timeout=60)
    except requests.RequestException as e:
        report_failure(
            f"could not reach ServiceNow cases endpoint: {e}", "target_unreachable"
        )
        return 1

    if resp.status_code == 401:
        report_failure("ServiceNow rejected the credential (HTTP 401)", "auth_failed")
        return 1
    if resp.status_code == 403:
        report_failure(
            "ServiceNow denied access to cases endpoint (HTTP 403)", "not_authorized"
        )
        return 1
    if resp.status_code != 200:
        report_failure(
            f"ServiceNow cases endpoint returned HTTP {resp.status_code}: {resp.text[:300]}",
            "partial_failure",
        )
        return 1

    output_path = output_dir / "servicenow_cases.json"
    try:
        output_path.write_bytes(resp.content)
    except OSError as e:
        report_failure(f"could not write evidence file: {e}")
        return 1

    logger.info("Evidence saved to %s", output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
