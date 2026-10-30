#!/usr/bin/env python3
"""
DataDog Monitors Retrieval

Purpose: Retrieve monitor configurations to prove persistent alerting is defined for infrastructure and security events.
"""

import json
import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
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

logger = logging.getLogger("datadog_monitors_list")


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


def fetch_all_monitors(base_url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Every monitor. GET /api/v1/monitor pages with `page` (from 0) and
    `page_size` and returns a bare JSON list. Raises PagingError if the first
    page fails; a later failure comes back on the returned list's `.error`."""
    return paginate_page_number(
        f"{base_url}/api/v1/monitor",
        headers,
        operation="Datadog list monitors",
        page_size=100,
        size_param="page_size",
        number_param="page",
        records_key=None,
    )


# An @-mention in a monitor message names a notification target, for example
# @pagerduty-Service, @slack-channel, @webhook-name or @user@example.com. Often
# it sits inside a template block, as in {{#is_alert}}@pagerduty-Infra{{/is_alert}}.
# The @ must not follow a word character or an email local-part character, so
# the domain of a plain email address in the text is not read as a target.
_MENTION = re.compile(r"(?<![\w@.+\-])@([^\s{}()<>\[\],;'\"`]+)")
_MENTION_TRAILING = ".:!?"


def extract_notification_targets(message: str) -> List[str]:
    """The distinct @-mentions in a monitor message, in the order they appear."""
    targets: List[str] = []
    for match in _MENTION.finditer(message or ""):
        target = match.group(1).rstrip(_MENTION_TRAILING)
        if target and target not in targets:
            targets.append(target)
    return targets


def _option(monitor: Dict[str, Any], key: str) -> Any:
    """A v1 monitor option. The API nests these under ``options``; a top-level
    key is read only as a fallback for older payloads."""
    options = monitor.get("options") or {}
    if key in options:
        return options[key]
    return monitor.get(key)


def extract_monitor_fields(monitor: Dict[str, Any]) -> Dict[str, Any]:
    message = monitor.get("message", "") or ""
    return {
        "id": monitor.get("id"),
        "name": monitor.get("name"),
        "type": monitor.get("type"),
        "overall_state": monitor.get("overall_state"),
        # Kept whole: a cut message drops the @-mentions that name who is paged.
        "query": monitor.get("query") or "",
        "message": message,
        "notification_targets": extract_notification_targets(message),
        "tags": monitor.get("tags", []),
        "thresholds": _option(monitor, "thresholds"),
        "notify_no_data": _option(monitor, "notify_no_data"),
        "no_data_timeframe": _option(monitor, "no_data_timeframe"),
    }


def get_monitors_list() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()
    endpoint = f"{base_url}/api/v1/monitor"

    try:
        monitors = fetch_all_monitors(base_url, headers)
        extracted = [extract_monitor_fields(m) for m in monitors]

        status_counts: Dict[str, int] = dict(Counter(
            m.get("overall_state", "Unknown") or "Unknown" for m in extracted
        ))
        type_counts: Dict[str, int] = dict(Counter(
            m.get("type", "unknown") or "unknown" for m in extracted
        ))

        monitors_in_alert = sum(1 for m in extracted if m.get("overall_state") == "Alert")

        return with_paging_status({
            "status": "success" if extracted else "partial_or_empty",
            "api_endpoint": endpoint,
            "record_count": len(extracted),
            "data": extracted,
            "summary": {
                "total_monitors": len(extracted),
                "monitors_by_status": status_counts,
                "monitors_by_type": type_counts,
                "monitors_in_alert_count": monitors_in_alert,
            },
            "retrieved_at": current_timestamp(),
        }, monitors)

    except PagingError as e:
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

    result = get_monitors_list()

    output_json = output_dir / "datadog_monitors_list.json"
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
