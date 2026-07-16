#!/usr/bin/env python3
"""
DataDog Incident Timelines Retrieval

Purpose: Retrieve per-incident timeline entries to support after-action reports.
"""

import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

logger = logging.getLogger("datadog_incident_timelines")


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


def fetch_incidents(base_url: str, headers: Dict[str, str], from_ts: str, to_ts: str) -> List[Dict[str, Any]]:
    all_incidents: List[Dict[str, Any]] = []
    offset = 0
    page_size = 100
    endpoint = f"{base_url}/api/v2/incidents"

    while True:
        params: Dict[str, Any] = {
            "page[offset]": offset,
            "page[size]": page_size,
            "filter[created][start]": from_ts,
            "filter[created][end]": to_ts,
        }
        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data", [])
            all_incidents.extend(data)
            total = payload.get("meta", {}).get("pagination", {}).get("total", 0)
            offset += len(data)
            if not data or offset >= total:
                break
        except requests.exceptions.RequestException as e:
            logger.warning("Incident pagination interrupted: %s", e)
            break

    return all_incidents


def fetch_timeline_cells(
    base_url: str,
    headers: Dict[str, str],
    incident_id: str,
) -> List[Dict[str, Any]]:
    endpoint = f"{base_url}/api/v2/incidents/{incident_id}/relationships/timeline_cells"
    try:
        response = requests.get(endpoint, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json().get("data", [])
    except requests.exceptions.RequestException as e:
        logger.warning("Timeline fetch failed for incident %s: %s", incident_id, e)
        return []


def extract_cell_fields(cell: Dict[str, Any]) -> Dict[str, Any]:
    attrs = cell.get("attributes", {})
    return {
        "cell_type": attrs.get("cell_type"),
        "created": attrs.get("created"),
        "modified": attrs.get("modified"),
        "created_by_id": cell.get("relationships", {}).get("created_by", {}).get("data", {}).get("id"),
    }


def get_incident_timelines() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()

    lookback_days = int(os.environ.get("DATADOG_INCIDENTS_LOOKBACK_DAYS", "90"))
    now = datetime.now(timezone.utc)
    from_ts = (now - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    to_ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        incidents = fetch_incidents(base_url, headers, from_ts, to_ts)

        if not incidents:
            return {
                "status": "partial_or_empty",
                "message": "No incidents found in the lookback window",
                "record_count": 0,
                "data": [],
                "summary": {
                    "incidents_with_timeline": 0,
                    "total_timeline_cells": 0,
                    "avg_cells_per_incident": 0,
                    "cell_type_distribution": {},
                },
                "retrieved_at": current_timestamp(),
            }

        all_timelines = []
        cell_type_counter: Counter = Counter()
        incidents_with_timeline = 0
        total_cells = 0

        for incident in incidents:
            incident_id = incident.get("id")
            if not incident_id:
                continue

            attrs = incident.get("attributes", {})
            cells_raw = fetch_timeline_cells(base_url, headers, incident_id)
            cells = [extract_cell_fields(c) for c in cells_raw]

            for cell in cells:
                cell_type_counter[cell.get("cell_type", "unknown")] += 1

            total_cells += len(cells)
            if cells:
                incidents_with_timeline += 1

            all_timelines.append({
                "incident_id": incident_id,
                "incident_title": attrs.get("title"),
                "cell_count": len(cells),
                "timeline_cells": cells,
            })

        avg_cells = round(total_cells / incidents_with_timeline, 2) if incidents_with_timeline else 0

        return {
            "status": "success",
            "api_endpoint": f"{base_url}/api/v2/incidents/{{id}}/relationships/timeline_cells",
            "record_count": total_cells,
            "data": all_timelines,
            "summary": {
                "incidents_with_timeline": incidents_with_timeline,
                "total_timeline_cells": total_cells,
                "avg_cells_per_incident": avg_cells,
                "cell_type_distribution": dict(cell_type_counter),
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

    result = get_incident_timelines()

    output_json = output_dir / "datadog_incident_timelines.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    return 0 if result.get("status") in {"success", "partial_or_empty"} else 1


if __name__ == "__main__":
    sys.exit(main())
