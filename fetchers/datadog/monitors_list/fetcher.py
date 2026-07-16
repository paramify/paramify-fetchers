#!/usr/bin/env python3
"""
DataDog Monitors Retrieval

Purpose: Retrieve monitor configurations to prove persistent alerting is defined for infrastructure and security events.
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

logger = logging.getLogger("datadog_monitors_list")


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str, default: Optional[str] = None) -> str:
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def get_dd_headers() -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "DD-API-KEY": get_env("DATADOG_API_KEY"),
        "DD-APPLICATION-KEY": get_env("DATADOG_APP_KEY"),
    }


def get_base_url() -> str:
    return os.environ.get("DATADOG_BASE_URL", "https://api.ddog-gov.com").rstrip("/")


def fetch_all_monitors(base_url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    all_monitors: List[Dict[str, Any]] = []
    page = 0
    page_size = 100
    endpoint = f"{base_url}/api/v1/monitor"

    while True:
        params = {"page": page, "page_size": page_size}
        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, list) or not data:
                break
            all_monitors.extend(data)
            if len(data) < page_size:
                break
            page += 1
        except requests.exceptions.RequestException as e:
            logger.warning("Pagination interrupted at page %s: %s", page, e)
            break

    return all_monitors


def extract_monitor_fields(monitor: Dict[str, Any]) -> Dict[str, Any]:
    message = monitor.get("message", "") or ""
    return {
        "id": monitor.get("id"),
        "name": monitor.get("name"),
        "type": monitor.get("type"),
        "overall_state": monitor.get("overall_state"),
        "query": (monitor.get("query") or "")[:200],
        "message": message[:200],
        "tags": monitor.get("tags", []),
        "thresholds": monitor.get("thresholds"),
        "notify_no_data": monitor.get("notify_no_data"),
        "no_data_timeframe": monitor.get("no_data_timeframe"),
    }


def get_monitors_list() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()
    endpoint = f"{base_url}/api/v1/monitor"

    try:
        monitors = fetch_all_monitors(base_url, headers)
        extracted = [extract_monitor_fields(m) for m in monitors]

        status_counts: Dict[str, int] = dict(Counter(
            m.get("overall_state", "Unknown") or "Unknown" for m in extracted
        ))
        type_counts: Dict[str, int] = dict(Counter(
            m.get("type", "unknown") or "unknown" for m in extracted
        ))

        monitors_in_alert = sum(1 for m in extracted if m.get("overall_state") == "Alert")

        return {
            "status": "success" if extracted else "partial_or_empty",
            "api_endpoint": endpoint,
            "record_count": len(extracted),
            "data": extracted,
            "summary": {
                "total_monitors": len(extracted),
                "monitors_by_status": status_counts,
                "monitors_by_type": type_counts,
                "monitors_in_alert_count": monitors_in_alert,
            },
            "retrieved_at": current_timestamp(),
        }

    except RuntimeError as e:
        return {"status": "error", "message": str(e), "retrieved_at": current_timestamp()}
    except Exception as e:
        return {"status": "error", "message": str(e), "retrieved_at": current_timestamp()}


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    result = get_monitors_list()

    output_json = output_dir / "datadog_monitors_list.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    return 0 if result.get("status") in {"success", "partial_or_empty"} else 1


if __name__ == "__main__":
    sys.exit(main())
