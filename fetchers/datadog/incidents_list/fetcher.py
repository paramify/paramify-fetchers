#!/usr/bin/env python3
"""
DataDog Incidents Retrieval

Purpose: Retrieve incident records for after-action review and pattern analysis.
"""

import json
import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    parse_timestamp,
    walk_incidents,
)
from datadog_paging import (  # noqa: E402
    PagingError,
    error_result,
    failure_result,
    with_paging_status,
)
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("datadog_incidents_list")


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


def fetch_all_incidents(
    base_url: str,
    headers: Dict[str, str],
    from_ts: str,
    to_ts: str,
) -> List[Dict[str, Any]]:
    """Every incident. GET /api/v2/incidents pages with `page[size]` (max 100)
    and `page[offset]`; its `meta.pagination` has no total, so the walk stops
    on a short page. Raises PagingError if the first page fails; a later
    failure comes back on the returned list's `.error`."""
    return walk_incidents(base_url, headers, from_ts, to_ts)


def parse_resolution_hours(detected: Optional[str], resolved: Optional[str]) -> Optional[float]:
    d = parse_timestamp(detected)
    r = parse_timestamp(resolved)
    if d is None or r is None:
        return None
    return round((r - d).total_seconds() / 3600, 2)


def _incident_state(attrs: Dict[str, Any]) -> Optional[str]:
    """The incident's state (for example active, stable or resolved).

    The v2 API reports it as ``attributes.state``. Older responses carried it
    only as the ``state`` entry of ``attributes.fields``.
    """
    state = attrs.get("status") or attrs.get("state")
    if state:
        return state
    field = (attrs.get("fields") or {}).get("state")
    if isinstance(field, dict):
        value = field.get("value")
        return value if isinstance(value, str) else None
    return None


def _related_id(container: Dict[str, Any], key: str) -> Optional[str]:
    rel = container.get(key)
    if not isinstance(rel, dict):
        return None
    data = rel.get("data")
    return data.get("id") if isinstance(data, dict) else None


def extract_incident_fields(incident: Dict[str, Any]) -> Dict[str, Any]:
    attrs = incident.get("attributes") or {}
    relationships = incident.get("relationships") or {}
    detected = attrs.get("detected")
    resolved = attrs.get("resolved")
    # The commander is a relationship (relationships.commander_user) in the v2
    # API; attributes.commander is kept only as a fallback for older payloads.
    commander_id = _related_id(relationships, "commander_user") or _related_id(attrs, "commander")
    return {
        "id": incident.get("id"),
        "title": attrs.get("title"),
        "severity": attrs.get("severity"),
        "status": _incident_state(attrs),
        "detected": detected,
        "resolved": resolved,
        "resolution_hours": parse_resolution_hours(detected, resolved),
        "customer_impact_scope": attrs.get("customer_impact_scope"),
        "customer_impact_duration": attrs.get("customer_impact_duration"),
        "commander_id": commander_id,
        # Unknown: a v2 incident has no postmortem attribute. A postmortem is
        # an incident attachment, which this fetcher does not read.
        "postmortem_id": None,
    }


# Summary figures that do not come from the incident list. They stay when the
# walk stops early; every other figure becomes null.
KEEP_SUMMARY = ("lookback_days", "incidents_with_postmortem", "resolved_without_postmortem_ids")


def get_incidents_list() -> Dict[str, Any]:
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
        walked = fetch_all_incidents(base_url, headers, from_ts, to_ts)
        # The date filter is not documented; drop what it did not.
        incidents, outside_window = drop_incidents_before(walked, from_dt)
        extracted = [extract_incident_fields(i) for i in incidents]
        # Postmortems are not read (see extract_incident_fields), so these are
        # unknown, not "none".
        postmortem_summary: Dict[str, Any] = {
            "incidents_with_postmortem": None,
            "resolved_without_postmortem_ids": None,
        }

        if not extracted:
            return with_paging_status({
                "status": "partial_or_empty",
                "message": "No incidents found in the lookback window",
                "api_endpoint": endpoint,
                "record_count": 0,
                "data": [],
                "summary": {
                    "total_incidents": 0,
                    "incidents_by_severity": {},
                    "incidents_by_status": {},
                    **postmortem_summary,
                    "avg_resolution_hours": None,
                    "incidents_outside_lookback_dropped": outside_window,
                    "lookback_days": lookback_days,
                },
                "retrieved_at": current_timestamp(),
            }, walked, keep_summary=KEEP_SUMMARY)

        severity_counts: Dict[str, int] = dict(Counter(
            i.get("severity", "UNKNOWN") or "UNKNOWN" for i in extracted
        ))
        status_counts: Dict[str, int] = dict(Counter(
            i.get("status", "unknown") or "unknown" for i in extracted
        ))

        resolution_times = [
            i["resolution_hours"] for i in extracted if i.get("resolution_hours") is not None
        ]
        avg_resolution = round(sum(resolution_times) / len(resolution_times), 2) if resolution_times else None

        return with_paging_status({
            "status": "success",
            "api_endpoint": endpoint,
            "record_count": len(extracted),
            "data": extracted,
            "summary": {
                "total_incidents": len(extracted),
                "incidents_by_severity": severity_counts,
                "incidents_by_status": status_counts,
                **postmortem_summary,
                "avg_resolution_hours": avg_resolution,
                "incidents_outside_lookback_dropped": outside_window,
                "lookback_days": lookback_days,
            },
            "retrieved_at": current_timestamp(),
        }, walked, keep_summary=KEEP_SUMMARY)

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

    result = get_incidents_list()

    output_json = output_dir / "datadog_incidents_list.json"
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
