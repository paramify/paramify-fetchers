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

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

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


# The v2 archive states (GET /api/v2/logs/config/archives). WORKING and
# WORKING_AUTH_LEGACY mean Datadog is writing to the destination; FAILING and
# UNKNOWN do not.
WORKING_ARCHIVE_STATES = frozenset({"WORKING", "WORKING_AUTH_LEGACY"})


def _first_present(mapping: Dict[str, Any], *keys: str) -> Any:
    """The value of the first key that is present, so a real False is kept."""
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def extract_archive_fields(archive: Dict[str, Any]) -> Dict[str, Any]:
    attrs = archive.get("attributes", archive)
    destination = attrs.get("destination") or {}
    dest_type = destination.get("type", "unknown")

    # Extract storage location without leaking full paths. S3 and GCS archives
    # name a bucket; Azure archives name a container (required) in a storage
    # account (storage_account, also required).
    storage_account = destination.get("storage_account") or destination.get("storageAccount")
    storage_location = (
        destination.get("bucket")
        or destination.get("container")
        or storage_account
        or ""
    )

    return {
        "id": archive.get("id"),
        "name": attrs.get("name"),
        "state": attrs.get("state"),
        "destination_type": dest_type,
        "storage_location": storage_location,
        "storage_account": storage_account,
        "destination_path": destination.get("path"),
        # The API field is include_tags; the camelCase key is kept for existing
        # validators.
        "includeTags": _first_present(attrs, "include_tags", "includeTags"),
        "query": attrs.get("query"),
    }


def is_archive_working(archive: Dict[str, Any]) -> bool:
    return str(archive.get("state") or "").upper() in WORKING_ARCHIVE_STATES


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

        enabled = [a for a in extracted if is_archive_working(a)]
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
                # Archives Datadog is writing to (state WORKING or
                # WORKING_AUTH_LEGACY). The v2 API has no ENABLED state.
                "enabled_archives": len(enabled),
                "archives_by_state": dict(Counter(a.get("state") or "UNKNOWN" for a in extracted)),
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

    # Last line on stderr wins: the runner reads its tail into the envelope's metadata.error.
    if result.get("status") not in {"success", "partial_or_empty"}:
        reason = result.get("message", "unknown error")
        report_failure(reason)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
