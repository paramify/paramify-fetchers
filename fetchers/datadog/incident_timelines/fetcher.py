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

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
# Paging shared by the Datadog fetchers lives in the category's _shared/.
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from datadog_incidents import (  # noqa: E402
    INCIDENTS_PATH,
    drop_incidents_before,
    walk_incidents,
)
from datadog_paging import (  # noqa: E402
    PagingError,
    error_result,
    failure_result,
    request_failure,
    request_json,
    with_paging_status,
)
from fetcher_status import report_failure  # noqa: E402

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
    """Every incident, through the shared incidents walk (see
    _shared/datadog_incidents.py). Raises PagingError if the first page fails;
    a later failure comes back on the returned list's `.error`."""
    return walk_incidents(base_url, headers, from_ts, to_ts)


TIMELINE_PATH = "/api/v2/incidents/{incident_id}/relationships/timeline_cells"


def fetch_timeline_cells(
    base_url: str,
    headers: Dict[str, str],
    incident_id: str,
) -> List[Dict[str, Any]]:
    """One incident's timeline cells. Raises on a failed request, so a failed
    read never looks like an empty timeline."""
    payload = request_json("GET", f"{base_url}{TIMELINE_PATH.format(incident_id=incident_id)}", headers)
    data = payload.get("data") if isinstance(payload, dict) else None
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError(f"expected a list at data, got {type(data).__name__}")
    return data


def _related_id(relationships: Dict[str, Any], *keys: str) -> Optional[str]:
    for key in keys:
        rel = relationships.get(key)
        data = rel.get("data") if isinstance(rel, dict) else None
        if isinstance(data, dict) and data.get("id"):
            return data["id"]
    return None


def cell_content_text(content: Any) -> Optional[str]:
    """The text of a timeline cell.

    A markdown cell holds it as ``{"content": "<markdown>"}``, the shape the
    incidents API documents for timeline cells. A bare string is also accepted.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        text = content.get("content")
        if isinstance(text, str):
            return text
    return None


def extract_cell_fields(cell: Dict[str, Any]) -> Dict[str, Any]:
    attrs = cell.get("attributes") or {}
    relationships = cell.get("relationships") or {}
    content = attrs.get("content")
    return {
        "id": cell.get("id"),
        "cell_type": attrs.get("cell_type"),
        "created": attrs.get("created"),
        "modified": attrs.get("modified"),
        "created_by_id": _related_id(relationships, "created_by", "created_by_user"),
        "important": attrs.get("important"),
        # What the entry says, for the after-action review. A non-markdown cell
        # keeps its content object as the API returned it.
        "content": cell_content_text(content),
        "content_raw": content if isinstance(content, dict) and cell_content_text(content) is None else None,
    }


# Summary figures that do not come from the reads. They stay when a read
# fails; every other figure becomes null.
KEEP_SUMMARY = ("lookback_days",)


def get_incident_timelines() -> Dict[str, Any]:
    try:
        base_url = get_base_url()
        headers = get_dd_headers()
    except RuntimeError as e:
        return error_result(str(e), current_timestamp(), "bad_config")
    endpoint = f"{base_url}{INCIDENTS_PATH}"

    lookback_days = int(os.environ.get("DATADOG_INCIDENTS_LOOKBACK_DAYS", "90"))
    now = datetime.now(timezone.utc)
    from_dt = now - timedelta(days=lookback_days)
    from_ts = from_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    to_ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        walked = fetch_incidents(base_url, headers, from_ts, to_ts)
        # The date filter is not documented; drop what it did not.
        incidents, outside_window = drop_incidents_before(walked, from_dt)

        if not incidents:
            return with_paging_status({
                "status": "partial_or_empty",
                "message": "No incidents found in the lookback window",
                "api_endpoint": endpoint,
                "record_count": 0,
                "data": [],
                "summary": {
                    "incidents_with_timeline": 0,
                    "total_timeline_cells": 0,
                    "avg_cells_per_incident": 0,
                    "cell_type_distribution": {},
                    "incidents_outside_lookback_dropped": outside_window,
                    "lookback_days": lookback_days,
                },
                "retrieved_at": current_timestamp(),
            }, walked, keep_summary=KEEP_SUMMARY)

        all_timelines = []
        timeline_failures: List[Dict[str, Any]] = []
        cell_type_counter: Counter = Counter()
        incidents_with_timeline = 0
        total_cells = 0

        for incident in incidents:
            incident_id = incident.get("id")
            if not incident_id:
                continue

            attrs = incident.get("attributes", {})
            try:
                cells_raw = fetch_timeline_cells(base_url, headers, incident_id)
            except (requests.exceptions.RequestException, ValueError) as e:
                logger.warning("Timeline read failed for incident %s: %s", incident_id, e)
                timeline_failures.append(
                    request_failure("Datadog read incident timeline", e, incident_id=incident_id)
                )
                # Unknown, not empty: the read failed.
                all_timelines.append({
                    "incident_id": incident_id,
                    "incident_title": attrs.get("title"),
                    "cell_count": None,
                    "timeline_cells": None,
                })
                continue
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

        return with_paging_status({
            "status": "success",
            "api_endpoint": f"{base_url}{TIMELINE_PATH.format(incident_id='{id}')}",
            "record_count": total_cells,
            "data": all_timelines,
            "summary": {
                "incidents_with_timeline": incidents_with_timeline,
                "total_timeline_cells": total_cells,
                "avg_cells_per_incident": avg_cells,
                "cell_type_distribution": dict(cell_type_counter),
                "incidents_outside_lookback_dropped": outside_window,
                "lookback_days": lookback_days,
            },
            "retrieved_at": current_timestamp(),
        }, walked, keep_summary=KEEP_SUMMARY, other_failures=timeline_failures)

    except PagingError as e:
        return failure_result(e, endpoint, current_timestamp())
    except Exception as e:
        return error_result(str(e), current_timestamp())


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

    # Last line on stderr wins: the runner reads its tail into the envelope's metadata.error.
    if result.get("status") not in {"success", "partial_or_empty"}:
        reason = result.get("message", "unknown error")
        report_failure(reason, result.get("error_code"))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
