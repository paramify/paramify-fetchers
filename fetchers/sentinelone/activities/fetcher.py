#!/usr/bin/env python3
"""
SentinelOne Activities

Pulls SentinelOne activity records for a curated set of FedRAMP-relevant
activity types and summarizes by type, time, and primary description.
"""

import json
import logging
import os
import sys
from collections import Counter
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

logger = logging.getLogger("sentinelone_activities")


FEDRAMP_ACTIVITY_TYPE_IDS = [
    5125, 5232, 4112, 7803, 104, 111, 5040, 5041, 5042,
    7700, 7800, 7853, 7881, 70, 77, 5044, 3750, 3752,
    5228, 65, 153, 1025, 5027, 7834, 7854, 13029,
]


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
    activity_type_ids: Optional[List[int]] = None,
) -> List[Dict[str, Any]]:
    all_records: List[Dict[str, Any]] = []
    cursor = None
    endpoint = f"{base_url}/web/api/v2.1/activities"
    activity_type_str = ",".join(map(str, activity_type_ids)) if activity_type_ids else None

    while True:
        params = {"cursor": cursor}
        if activity_type_str:
            params["activityTypes"] = activity_type_str
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


def get_activities(api_url: str, api_token: str) -> Dict[str, Any]:
    api_url = api_url.rstrip("/")
    headers = {"Content-Type": "application/json", "Authorization": f"ApiToken {api_token}"}
    api_failures: List[Dict[str, Any]] = []

    try:
        records = fetch_all_pages(api_url, headers, api_failures, activity_type_ids=FEDRAMP_ACTIVITY_TYPE_IDS)
        if not records:
            return {
                "status": "partial_or_empty",
                "message": "No records found",
                "api_failures": api_failures,
                "retrieved_at": current_timestamp(),
            }

        activity_type = [r.get("activityType") for r in records if "activityType" in r]
        created_at = [r.get("createdAt") for r in records if "createdAt" in r]
        primary_description = [r.get("primaryDescription") for r in records if "primaryDescription" in r]

        return {
            "status": "success",
            "api_endpoint": f"{api_url}/web/api/v2.1/activities",
            "record_count": len(records),
            "api_failures": api_failures,
            "data": records,
            "analysis": {
                "total_activities_collected": len(records),
                "activity_type": dict(Counter(activity_type)) if activity_type else {},
                "created_at": created_at,
                "primary_description": primary_description,
            },
            "retrieved_at": current_timestamp(),
        }
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

    result = get_activities(api_url, api_token)

    output_path = output_dir / "sentinelone_activities.json"
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
