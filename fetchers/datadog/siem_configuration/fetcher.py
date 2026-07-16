#!/usr/bin/env python3
"""
DataDog SIEM Configuration Retrieval

Purpose: Retrieve SIEM operational state — suppression rules and notification integrations.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

logger = logging.getLogger("datadog_siem_configuration")


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


def safe_get(url: str, headers: Dict[str, str], strict: bool = False) -> Optional[Dict[str, Any]]:
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if strict and e.response is not None and e.response.status_code in (403, 404):
            raise
        logger.warning("GET %s failed: %s", url, e)
        return None
    except requests.exceptions.RequestException as e:
        logger.warning("GET %s failed: %s", url, e)
        return None


def get_siem_configuration() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()
    suppression_endpoint = f"{base_url}/api/v2/security_monitoring/configuration/suppression_rules"
    webhook_endpoint = f"{base_url}/api/v1/integration/webhook/configuration/webhooks"

    try:
        # Suppression rules
        suppression_payload = safe_get(suppression_endpoint, headers, strict=True)
        suppression_data = []
        if suppression_payload:
            raw = suppression_payload.get("data", [])
            for item in raw:
                attrs = item.get("attributes", {})
                suppression_data.append({
                    "id": item.get("id"),
                    "name": attrs.get("name"),
                    "isEnabled": attrs.get("isEnabled", attrs.get("enabled")),
                    "startDate": attrs.get("startDate"),
                    "expirationDate": attrs.get("expirationDate"),
                    "rule_id": item.get("relationships", {}).get("rule", {}).get("data", {}).get("id"),
                })

        enabled_suppression = sum(1 for r in suppression_data if r.get("isEnabled"))

        # Webhook integrations — log domain only, never the full URL
        webhook_payload = safe_get(webhook_endpoint, headers)
        webhook_data = []
        notification_types = set()
        if webhook_payload:
            webhooks = webhook_payload.get("webhooks", [])
            for wh in webhooks:
                raw_url = wh.get("url", "")
                domain = urlparse(raw_url).netloc if raw_url else ""
                webhook_data.append({
                    "name": wh.get("name"),
                    "url_domain": domain,
                })
                notification_types.add("webhook")

        # Determine notification types from integration names (heuristic)
        for wh in webhook_data:
            name_lower = (wh.get("name") or "").lower()
            if "slack" in name_lower:
                notification_types.add("slack")
            elif "pagerduty" in name_lower or "pd-" in name_lower:
                notification_types.add("pagerduty")

        return {
            "status": "success",
            "api_endpoint": suppression_endpoint,
            "api_endpoints_additional": [webhook_endpoint],
            "record_count": len(suppression_data) + len(webhook_data),
            "data": {
                "suppression_rules": suppression_data,
                "notification_integrations": webhook_data,
            },
            "summary": {
                "suppression_rules_count": len(suppression_data),
                "enabled_suppression_rules": enabled_suppression,
                "notification_integrations_count": len(webhook_data),
                "notification_types": sorted(notification_types),
            },
            "retrieved_at": current_timestamp(),
        }

    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code in (403, 404):
            return {
                "status": "not_available",
                "message": "Security Monitoring (SIEM) is not enabled for this organization",
                "api_endpoint": suppression_endpoint,
                "retrieved_at": current_timestamp(),
            }
        return {"status": "error", "message": str(e), "retrieved_at": current_timestamp()}
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

    result = get_siem_configuration()

    output_json = output_dir / "datadog_siem_configuration.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    return 0 if result.get("status") in {"success", "partial_or_empty", "not_available"} else 1


if __name__ == "__main__":
    sys.exit(main())
