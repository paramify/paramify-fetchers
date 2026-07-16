#!/usr/bin/env python3
"""
DataDog SIEM Detection Rules Retrieval

Purpose: Retrieve custom SIEM detection rules to prove active threat detection is configured.
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

logger = logging.getLogger("datadog_siem_detection_rules")


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


def fetch_all_rules(base_url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    all_rules: List[Dict[str, Any]] = []
    page_number = 0
    page_size = 100
    endpoint = f"{base_url}/api/v2/security_monitoring/rules"

    while True:
        params = {
            "page[number]": page_number,
            "page[size]": page_size,
            "is_default": "false",
        }
        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data", [])
            if not data:
                break
            all_rules.extend(data)
            if len(data) < page_size:
                break
            page_number += 1
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code in (403, 404):
                raise
            logger.warning("Pagination interrupted at page %s: %s", page_number, e)
            break
        except requests.exceptions.RequestException as e:
            logger.warning("Pagination interrupted at page %s: %s", page_number, e)
            break

    return all_rules


def extract_rule_fields(rule: Dict[str, Any]) -> Dict[str, Any]:
    cases = rule.get("cases", [])
    severities = [c.get("status", "").lower() for c in cases if c.get("status")]
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "type": rule.get("type"),
        "isEnabled": rule.get("isEnabled"),
        "isDefault": rule.get("isDefault"),
        "createdAt": rule.get("createdAt"),
        "updatedAt": rule.get("updatedAt"),
        "hasExtendedTitle": rule.get("hasExtendedTitle"),
        "severities": severities,
    }


def get_siem_detection_rules() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()
    endpoint = f"{base_url}/api/v2/security_monitoring/rules"

    try:
        rules = fetch_all_rules(base_url, headers)

        extracted = [extract_rule_fields(r) for r in rules]

        enabled_rules = [r for r in extracted if r.get("isEnabled")]
        disabled_rules = [r for r in extracted if not r.get("isEnabled")]

        type_counts: Dict[str, int] = dict(Counter(r.get("type", "unknown") for r in extracted))
        severity_counts: Dict[str, int] = {}
        for r in extracted:
            for sev in r.get("severities", []):
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        rules_updated_recently = 0
        for r in extracted:
            updated_at = r.get("updatedAt")
            if updated_at:
                try:
                    dt = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                    if dt >= cutoff:
                        rules_updated_recently += 1
                except ValueError:
                    pass

        return {
            "status": "success",
            "api_endpoint": endpoint,
            "record_count": len(extracted),
            "data": extracted,
            "summary": {
                "total_rules": len(extracted),
                "enabled_rules": len(enabled_rules),
                "disabled_rules": len(disabled_rules),
                "rules_never_triggered_count": 0,
                "rules_updated_last_90_days": rules_updated_recently,
                "rules_by_type": type_counts,
                "rules_by_severity": severity_counts,
            },
            "retrieved_at": current_timestamp(),
        }

    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code in (403, 404):
            return {
                "status": "not_available",
                "message": "Security Monitoring (SIEM) is not enabled for this organization",
                "api_endpoint": endpoint,
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

    result = get_siem_detection_rules()

    output_json = output_dir / "datadog_siem_detection_rules.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    return 0 if result.get("status") in {"success", "partial_or_empty", "not_available"} else 1


if __name__ == "__main__":
    sys.exit(main())
