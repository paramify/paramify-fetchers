#!/usr/bin/env python3
"""
DataDog Log Pipelines Retrieval

Purpose: Retrieve log processing pipeline configurations to prove defined event types are ingested and processed.
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

logger = logging.getLogger("datadog_log_pipelines")


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


def extract_pipeline_fields(pipeline: Dict[str, Any]) -> Dict[str, Any]:
    processors = pipeline.get("processors", [])
    return {
        "id": pipeline.get("id"),
        "name": pipeline.get("name"),
        "isEnabled": pipeline.get("isEnabled"),
        "isReadOnly": pipeline.get("isReadOnly"),
        "filter_query": pipeline.get("filter", {}).get("query"),
        "processor_count": len(processors),
    }


def get_log_pipelines() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()
    endpoint = f"{base_url}/api/v1/logs/config/pipelines"

    try:
        response = requests.get(endpoint, headers=headers, timeout=30)
        response.raise_for_status()
        pipelines = response.json()

        if not isinstance(pipelines, list):
            pipelines = pipelines.get("data", pipelines.get("pipelines", []))

        extracted = [extract_pipeline_fields(p) for p in pipelines]

        enabled = [p for p in extracted if p.get("isEnabled")]
        disabled = [p for p in extracted if not p.get("isEnabled")]
        read_only = [p for p in extracted if p.get("isReadOnly")]
        disabled_zero_processors = sum(
            1 for p in disabled if p.get("processor_count", 0) == 0
        )

        pipelines_summary = [
            {
                "name": p["name"],
                "isEnabled": p["isEnabled"],
                "processor_count": p["processor_count"],
                "filter": p["filter_query"],
            }
            for p in extracted
        ]

        return {
            "status": "success" if extracted else "partial_or_empty",
            "api_endpoint": endpoint,
            "record_count": len(extracted),
            "data": extracted,
            "summary": {
                "total_pipelines": len(extracted),
                "enabled_pipelines": len(enabled),
                "disabled_pipelines": len(disabled),
                "read_only_pipelines": len(read_only),
                "disabled_pipelines_with_zero_processors": disabled_zero_processors,
                "pipelines_summary": pipelines_summary,
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

    result = get_log_pipelines()

    output_json = output_dir / "datadog_log_pipelines.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    return 0 if result.get("status") in {"success", "partial_or_empty"} else 1


if __name__ == "__main__":
    sys.exit(main())
