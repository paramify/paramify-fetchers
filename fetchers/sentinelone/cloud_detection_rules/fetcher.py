#!/usr/bin/env python3
"""
SentinelOne Cloud Detection Rules

Pulls SentinelOne custom cloud detection rules with last-alert / update
timestamps; enriches with a powerQuery summary of recent data-source activity.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("sentinelone_cloud_detection_rules")


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def http_get(url: str, headers: Dict[str, str], params: Optional[Dict[str, Any]] = None) -> requests.Response:
    return requests.get(url, headers=headers, params=params, timeout=30)


def fetch_all_pages(
    base_url: str,
    headers: Dict[str, str],
    api_failures: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    all_records: List[Dict[str, Any]] = []
    cursor = None
    endpoint = f"{base_url}/web/api/v2.1/cloud-detection/rules"

    while True:
        params = {"cursor": cursor} if cursor else {}
        try:
            response = http_get(endpoint, headers=headers, params=params)
            response.raise_for_status()
            payload = response.json()
            all_records.extend(payload.get("data", []))
            cursor = payload.get("pagination", {}).get("nextCursor")
            if not cursor:
                break
        except requests.exceptions.RequestException as e:
            api_failures.append({"endpoint": endpoint, "type": type(e).__name__, "message": str(e)})
            logger.warning("Pagination interrupted: %s", e)
            break

    return all_records


def run_power_query(api_url: str, api_token: str, body: Optional[dict] = None) -> dict:
    """Supplementary enrichment call — failure here is best-effort, not tracked as a collection failure."""
    base_url = api_url.rstrip("/")
    endpoint = f"{base_url}/sdl/api/powerQuery"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_token}"}
    if body is None:
        body = {
            "query": "dataSource.name=* | group Count = count() by dataSource.name | sort -Count",
            "startTime": "1hr",
            "endTime": "",
        }
    try:
        resp = requests.post(endpoint, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        logger.warning("Power query request failed: %s", e)
        return {"status": "error", "message": str(e)}


def get_cloud_detection_rules(api_url: str, api_token: str) -> Dict[str, Any]:
    api_url = api_url.rstrip("/")
    headers = {"Content-Type": "application/json", "Authorization": f"ApiToken {api_token}"}
    api_failures: List[Dict[str, Any]] = []

    try:
        records = fetch_all_pages(api_url, headers, api_failures)
        if not records:
            return {
                "status": "partial_or_empty",
                "message": "No records found",
                "api_failures": api_failures,
                "retrieved_at": current_timestamp(),
            }

        last_alert_time = [r.get("lastAlertTime") for r in records if "lastAlertTime" in r]
        last_updated_at = [r.get("updatedAt") for r in records if "updatedAt" in r]
        last_activity_list = [
            max(t for t in [r.get("lastAlertTime"), r.get("updatedAt")] if t)
            for r in records
            if r.get("lastAlertTime") or r.get("updatedAt")
        ]

        result = {
            "status": "success",
            "api_endpoint": f"{api_url}/web/api/v2.1/cloud-detection/rules",
            "record_count": len(records),
            "api_failures": api_failures,
            "data": records,
            "analysis": {
                "total_custom_detection_rules": len(records),
                "rules_never_triggered_count": sum(1 for t in last_alert_time if t is None),
                "last_alert_times": last_alert_time,
                "last_updated_at": last_updated_at,
                "last_activity_time": last_activity_list,
            },
            "retrieved_at": current_timestamp(),
        }

        power_query_result = run_power_query(api_url, api_token)
        if isinstance(power_query_result, dict) and "values" in power_query_result:
            result["analysis"]["data_sources"] = power_query_result.get("values")
        else:
            result["analysis"]["data_sources"] = power_query_result

        return result
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "api_failures": api_failures,
            "retrieved_at": current_timestamp(),
        }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself. The framework's runner +
    # secret resolver will pass resolved values in and this block goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        api_url = get_env("SENTINELONE_API_URL")
        api_token = get_env("SENTINELONE_API_TOKEN")
    except RuntimeError as e:
        report_failure(str(e), "bad_config")
        return 1

    result = get_cloud_detection_rules(api_url, api_token)

    output_path = output_dir / "sentinelone_cloud_detection_rules.json"
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)

    if result.get("api_failures"):
        failures = result["api_failures"]
        report_failure(f"{len(failures)} API failures during collection", "partial_failure")
        return 1
    # The api_failures branch above only fires when the paginator recorded one.
    # An exception raised anywhere else leaves it empty, so this path needs its
    # own report — the runner reads the TAIL of stderr into metadata.error, and
    # without this the last line is the "saved" INFO message.
    if result.get("status") not in {"success", "partial_or_empty"}:
        reason = result.get("message", "unknown error")
        report_failure(reason)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
