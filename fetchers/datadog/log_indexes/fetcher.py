#!/usr/bin/env python3
"""
DataDog Log Indexes Retrieval

Purpose: Retrieve log index retention configs to prove what data is retained and for how long.
"""

import json
import logging
import os
import re
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

logger = logging.getLogger("datadog_log_indexes")


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


def extract_index_fields(index: Dict[str, Any]) -> Dict[str, Any]:
    # Real API returns snake_case; mocks use camelCase — handle both
    retention = index.get("num_retention_days") or index.get("numRetentionDays")
    flex_retention = index.get("num_flex_logs_retention_days") or index.get("numFlexLogsRetentionDays")
    daily_limit = index.get("daily_limit") or index.get("dailyLimit")
    is_rate_limited = index.get("is_rate_limited") if "is_rate_limited" in index else index.get("isRateLimited")
    return {
        "name": index.get("name"),
        "numRetentionDays": retention,
        "numFlexLogsRetentionDays": flex_retention,
        "filter_query": index.get("filter", {}).get("query"),
        "dailyLimit": daily_limit,
        "isRateLimited": is_rate_limited,
        "tags": index.get("tags") or [],
    }


AUDIT_INDEXES_ENV = "DATADOG_AUDIT_INDEXES"


def parse_audit_index_names(raw: Optional[str]) -> List[str]:
    """Index names from the audit_indexes config: comma- or space-separated."""
    names: List[str] = []
    for part in re.split(r"[\s,]+", raw or ""):
        if part and part not in names:
            names.append(part)
    return names


def summarize_audit_indexes(extracted: List[Dict[str, Any]], audit_names: List[str]) -> Dict[str, Any]:
    """Which indexes hold audit logs, and their retention.

    Datadog has no field that marks an index as holding audit logs, so the
    fetcher does not guess one from the filter query. With no audit_indexes
    configured, every index counts as an audit index, so a short retention is
    never left out. With names configured, only those indexes count, and a
    configured name with no matching index is listed in
    audit_indexes_not_found. Sets ``is_audit_index`` on each record.
    """
    configured = bool(audit_names)
    wanted = set(audit_names)
    for idx in extracted:
        idx["is_audit_index"] = (idx.get("name") in wanted) if configured else True

    audit = [idx for idx in extracted if idx["is_audit_index"]]
    retentions = [idx["numRetentionDays"] for idx in audit if idx.get("numRetentionDays") is not None]
    present = {idx.get("name") for idx in extracted}
    return {
        "audit_index_selection": "configured" if configured else "all_indexes",
        "audit_indexes": [idx.get("name") for idx in audit],
        "audit_indexes_not_found": [n for n in audit_names if n not in present],
        "min_retention_days_audit_indexes": min(retentions) if retentions else None,
        "audit_indexes_below_90_days": sum(1 for v in retentions if v < 90),
    }


def get_log_indexes() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()
    endpoint = f"{base_url}/api/v1/logs/config/indexes"

    try:
        response = requests.get(endpoint, headers=headers, timeout=30)
        response.raise_for_status()
        payload = response.json()

        indexes = payload.get("indexes", payload) if isinstance(payload, dict) else payload

        extracted = [extract_index_fields(idx) for idx in indexes]

        retention_values = [
            idx["numRetentionDays"]
            for idx in extracted
            if idx.get("numRetentionDays") is not None
        ]

        min_retention = min(retention_values) if retention_values else 0
        max_retention = max(retention_values) if retention_values else 0
        indexes_below_90 = sum(1 for v in retention_values if v < 90)

        audit = summarize_audit_indexes(extracted, parse_audit_index_names(os.environ.get(AUDIT_INDEXES_ENV)))
        min_retention_audit = audit["min_retention_days_audit_indexes"]
        audit_below_90 = audit["audit_indexes_below_90_days"]

        indexes_summary = [
            {
                "name": idx["name"],
                "retention_days": idx["numRetentionDays"],
                "filter": idx["filter_query"],
                "daily_limit_gb": round(idx["dailyLimit"] / 1_000_000_000, 2) if idx.get("dailyLimit") else None,
                "is_audit_index": idx["is_audit_index"],
            }
            for idx in extracted
        ]

        return {
            "status": "success" if extracted else "partial_or_empty",
            "api_endpoint": endpoint,
            "record_count": len(extracted),
            "data": extracted,
            "summary": {
                "total_indexes": len(extracted),
                "min_retention_days": min_retention,
                "max_retention_days": max_retention,
                "indexes_below_90_days": indexes_below_90,
                "min_retention_days_audit_indexes": min_retention_audit,
                "audit_indexes_below_90_days": audit_below_90,
                "audit_index_selection": audit["audit_index_selection"],
                "audit_indexes": audit["audit_indexes"],
                "audit_indexes_not_found": audit["audit_indexes_not_found"],
                "indexes_summary": indexes_summary,
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

    result = get_log_indexes()

    output_json = output_dir / "datadog_log_indexes.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    # Last line on stderr wins: the runner reads its tail into the envelope's metadata.error.
    if result.get("status") not in {"success", "partial_or_empty"}:
        reason = result.get("message", "unknown error")
        report_failure(reason)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
