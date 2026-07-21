#!/usr/bin/env python3
"""
DataDog APM Services Retrieval

Purpose: Retrieve the APM service catalog to prove application services are registered and monitored.
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

logger = logging.getLogger("datadog_apm_services")


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


def fetch_all_services(base_url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    all_services: List[Dict[str, Any]] = []
    page_number = 0
    page_size = 100
    endpoint = f"{base_url}/api/v2/services/definitions"

    while True:
        params = {"page[size]": page_size, "page[number]": page_number}
        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data", [])
            if not data:
                break
            all_services.extend(data)
            if len(data) < page_size:
                break
            page_number += 1
        except requests.exceptions.RequestException as e:
            logger.warning("Pagination interrupted at page %s: %s", page_number, e)
            break

    return all_services


def extract_service_fields(service: Dict[str, Any]) -> Dict[str, Any]:
    schema = service.get("attributes", {}).get("schema", {})
    contacts = schema.get("contacts", []) or []
    return {
        "service_name": schema.get("dd-service"),
        "team": schema.get("team"),
        "tier": schema.get("tier"),
        "languages": schema.get("languages", []),
        "has_contact": len(contacts) > 0,
        "contact_types": sorted({c.get("type") for c in contacts if c.get("type")}),
    }


def get_apm_services() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()
    endpoint = f"{base_url}/api/v2/services/definitions"

    try:
        services = fetch_all_services(base_url, headers)
        extracted = [extract_service_fields(s) for s in services]

        language_counts: Dict[str, int] = Counter()
        for svc in extracted:
            for lang in (svc.get("languages") or []):
                if lang:
                    language_counts[lang] += 1

        team_counts: Dict[str, int] = dict(Counter(
            svc.get("team", "unassigned") or "unassigned" for svc in extracted
        ))

        services_with_owner = sum(1 for svc in extracted if svc.get("team"))
        services_without_owner = len(extracted) - services_with_owner

        return {
            "status": "success" if extracted else "partial_or_empty",
            "api_endpoint": endpoint,
            "record_count": len(extracted),
            "data": extracted,
            "summary": {
                "total_services": len(extracted),
                "services_by_language": dict(language_counts),
                "services_by_team": team_counts,
                "services_with_owner": services_with_owner,
                "services_without_owner": services_without_owner,
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

    result = get_apm_services()

    output_json = output_dir / "datadog_apm_services.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    return 0 if result.get("status") in {"success", "partial_or_empty"} else 1


if __name__ == "__main__":
    sys.exit(main())
