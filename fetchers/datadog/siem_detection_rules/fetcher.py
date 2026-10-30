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

from dotenv import load_dotenv

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
# Paging shared by the Datadog fetchers lives in the category's _shared/.
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from datadog_paging import (  # noqa: E402
    PagingError,
    failure_result,
    paginate_page_number,
    with_paging_status,
)
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("datadog_siem_detection_rules")


# Cloud SIEM answers 403 or 404 on the FIRST page when the product is not
# enabled for the organization. Only that case reads as "not_available"; the
# same status on a later page is a partial failure, and a 401 is a failure.
SIEM_NOT_ENABLED_STATUSES = (403, 404)


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
    """Every custom detection rule. GET /api/v2/security_monitoring/rules pages
    with `page[size]` (max 100) and `page[number]`. Raises PagingError if the
    first page fails; a later failure comes back on the returned list's `.error`."""
    return paginate_page_number(
        f"{base_url}/api/v2/security_monitoring/rules",
        headers,
        operation="Datadog list security monitoring rules",
        page_size=100,
        params={"is_default": "false"},
    )


def _extract_query(query: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": query.get("name"),
        "query": query.get("query"),
        "data_source": query.get("dataSource"),
        "aggregation": query.get("aggregation"),
        "group_by_fields": query.get("groupByFields") or [],
        "distinct_fields": query.get("distinctFields") or [],
        "metrics": query.get("metrics") or ([query["metric"]] if query.get("metric") else []),
    }


def _extract_case(case: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": case.get("name"),
        "status": case.get("status"),
        "condition": case.get("condition"),
        "notifications": case.get("notifications") or [],
    }


def extract_rule_fields(rule: Dict[str, Any]) -> Dict[str, Any]:
    cases = rule.get("cases") or []
    severities = [c.get("status", "").lower() for c in cases if c.get("status")]
    options = rule.get("options") or {}
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
        # How the rule detects: options.detectionMethod (threshold, new_value,
        # anomaly_detection, impossible_travel, ...), plus what it searches and
        # the conditions that raise a signal.
        "detection_method": options.get("detectionMethod"),
        "queries": [_extract_query(q) for q in rule.get("queries") or [] if isinstance(q, dict)],
        "cases": [_extract_case(c) for c in cases if isinstance(c, dict)],
    }


def parse_rule_time(value: Any) -> Optional[datetime]:
    """createdAt and updatedAt are epoch milliseconds (int64) in the v2 API.
    An ISO 8601 string is also accepted."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def count_rules_updated_since(rules: List[Dict[str, Any]], cutoff: datetime) -> int:
    count = 0
    for r in rules:
        updated = parse_rule_time(r.get("updatedAt"))
        if updated is not None and updated >= cutoff:
            count += 1
    return count


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
        rules_updated_recently = count_rules_updated_since(extracted, cutoff)

        return with_paging_status({
            "status": "success",
            "api_endpoint": endpoint,
            "record_count": len(extracted),
            "data": extracted,
            "summary": {
                "total_rules": len(extracted),
                "enabled_rules": len(enabled_rules),
                "disabled_rules": len(disabled_rules),
                "rules_updated_last_90_days": rules_updated_recently,
                "rules_by_type": type_counts,
                "rules_by_severity": severity_counts,
            },
            "retrieved_at": current_timestamp(),
        }, rules)

    except PagingError as e:
        if e.status_code in SIEM_NOT_ENABLED_STATUSES:
            return {
                "status": "not_available",
                "message": "Security Monitoring (SIEM) is not enabled for this organization",
                "api_endpoint": endpoint,
                "retrieved_at": current_timestamp(),
            }
        return failure_result(e, endpoint, current_timestamp())
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

    # Last line on stderr wins: the runner reads its tail into the envelope's metadata.error.
    if result.get("status") not in {"success", "partial_or_empty", "not_available"}:
        reason = result.get("message", "unknown error")
        report_failure(reason, result.get("error_code"))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
