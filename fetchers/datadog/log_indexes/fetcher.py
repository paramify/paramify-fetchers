#!/usr/bin/env python3
"""
DataDog Log Indexes Retrieval

Purpose: Retrieve log index retention configs to prove what data is retained and for how long.
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
    daily_limit_gb = round(daily_limit / 1_000_000_000, 2) if daily_limit else None
    return {
        "name": index.get("name"),
        "numRetentionDays": retention,
        "numFlexLogsRetentionDays": flex_retention,
        "filter_query": index.get("filter", {}).get("query"),
        "dailyLimit": daily_limit,
        "isRateLimited": is_rate_limited,
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

        audit_keywords = {"cloudtrail", "okta", "kubernetes.audit"}

        def is_audit_index(idx: Dict[str, Any]) -> bool:
            query = (idx.get("filter_query") or "").lower()
            return any(kw in query for kw in audit_keywords)

        audit_retentions = [
            idx["numRetentionDays"]
            for idx in extracted
            if is_audit_index(idx) and idx.get("numRetentionDays") is not None
        ]
        min_retention_audit = min(audit_retentions) if audit_retentions else None
        audit_below_90 = sum(1 for v in audit_retentions if v < 90)

        indexes_summary = [
            {
                "name": idx["name"],
                "retention_days": idx["numRetentionDays"],
                "filter": idx["filter_query"],
                "daily_limit_gb": round(idx["dailyLimit"] / 1_000_000_000, 2) if idx.get("dailyLimit") else None,
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

    return 0 if result.get("status") in {"success", "partial_or_empty"} else 1


if __name__ == "__main__":
    sys.exit(main())
