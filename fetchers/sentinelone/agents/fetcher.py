#!/usr/bin/env python3
"""
SentinelOne Agents

Pulls SentinelOne agent records (one per managed endpoint) and reports
cluster, container, and scan-coverage metrics.
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

logger = logging.getLogger("sentinelone_agents")


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
    endpoint = f"{base_url}/web/api/v2.1/agents"

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


def fetch_agents_count(base_url: str, headers: Dict[str, str]) -> Optional[int]:
    """Supplementary call — failure here is best-effort, not tracked as a collection failure."""
    try:
        response = http_get(f"{base_url}/web/api/v2.1/agents/count", headers=headers)
        response.raise_for_status()
        return int(response.json().get("data", {}).get("total", 0))
    except requests.exceptions.RequestException:
        return None


def last_successful_scan_percentage(records: List[Dict[str, Any]]) -> float:
    if not records:
        return 0.0
    non_null = sum(1 for r in records if r.get("lastSuccessfulScanDate") not in (None, "", []))
    return float(non_null) / float(len(records))


def get_agents(api_url: str, api_token: str) -> Dict[str, Any]:
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

        reported_count = fetch_agents_count(api_url, headers)

        cluster_names = [
            r.get("cloudProviders", {}).get("Kubernetes", {}).get("clusterName")
            for r in records
            if r.get("cloudProviders", {}).get("Kubernetes", {}).get("clusterName")
        ]
        containers_count = [
            r.get("containerizedWorkloadCounts", {}).get("containersCount")
            for r in records if r.get("containerizedWorkloadCounts")
        ]
        pods_count = [
            r.get("containerizedWorkloadCounts", {}).get("podsCount")
            for r in records if r.get("containerizedWorkloadCounts")
        ]
        tasks_count = [
            r.get("containerizedWorkloadCounts", {}).get("tasksCount")
            for r in records if r.get("containerizedWorkloadCounts")
        ]
        subnet_ids = [
            r.get("cloudProviders", {}).get("AWS", {}).get("awsSubnetIds")
            for r in records
            if r.get("cloudProviders", {}).get("AWS", {}).get("awsSubnetIds")
        ]

        return {
            "status": "success",
            "api_endpoint": f"{api_url}/web/api/v2.1/agents",
            "record_count": len(records),
            "api_failures": api_failures,
            "data": records,
            "analysis": {
                "total_agents": len(records),
                "reported_agent_count": reported_count,
                "cluster_names": dict(Counter([c for c in cluster_names if c])),
                "containers_count": containers_count,
                "pods_count": pods_count,
                "tasks_count": tasks_count,
                "subnet_ids": subnet_ids,
                "last_successful_scan_percentage": last_successful_scan_percentage(records),
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

    result = get_agents(api_url, api_token)

    output_path = output_dir / "sentinelone_agents.json"
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
