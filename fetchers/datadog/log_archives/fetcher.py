#!/usr/bin/env python3
"""
DataDog Log Archives Retrieval

Purpose: Retrieve long-term log archive configurations to prove logs are durably stored.
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

logger = logging.getLogger("datadog_log_archives")


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


def extract_archive_fields(archive: Dict[str, Any]) -> Dict[str, Any]:
    attrs = archive.get("attributes", archive)
    destination = attrs.get("destination", {})
    dest_type = destination.get("type", "unknown")

    # Extract storage location without leaking full paths
    storage_location = (
        destination.get("bucket")
        or destination.get("container")
        or destination.get("storageAccount")
        or ""
    )

    return {
        "id": archive.get("id"),
        "name": attrs.get("name"),
        "state": attrs.get("state"),
        "destination_type": dest_type,
        "storage_location": storage_location,
        "destination_path": destination.get("path"),
        "includeTags": attrs.get("includeTags"),
        "query": attrs.get("query"),
    }


def get_log_archives() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()
    endpoint = f"{base_url}/api/v2/logs/config/archives"

    try:
        response = requests.get(endpoint, headers=headers, timeout=30)
        response.raise_for_status()
        payload = response.json()

        archives_raw = payload.get("data", [])
        extracted = [extract_archive_fields(a) for a in archives_raw]

        enabled = [a for a in extracted if str(a.get("state", "")).upper() == "ENABLED"]
        dest_type_counts: Dict[str, int] = dict(Counter(
            a.get("destination_type", "unknown") for a in extracted
        ))

        archives_summary = [
            {
                "name": a["name"],
                "state": a["state"],
                "destination_type": a["destination_type"],
                "bucket": a["storage_location"],
                "destination_path": a.get("destination_path"),
            }
            for a in extracted
        ]

        return {
            "status": "success" if extracted else "partial_or_empty",
            "api_endpoint": endpoint,
            "record_count": len(extracted),
            "data": extracted,
            "summary": {
                "total_archives": len(extracted),
                "enabled_archives": len(enabled),
                "archives_by_destination_type": dest_type_counts,
                "archives_summary": archives_summary,
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

    result = get_log_archives()

    output_json = output_dir / "datadog_log_archives.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    return 0 if result.get("status") in {"success", "partial_or_empty"} else 1


if __name__ == "__main__":
    sys.exit(main())
