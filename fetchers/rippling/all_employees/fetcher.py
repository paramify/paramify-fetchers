#!/usr/bin/env python3
"""
Rippling — All Employees (including terminated)

Queries the Rippling Platform API for all employees, active and terminated.
Evidence for full employee roster and HR audit trail.

Endpoint: GET /platform/api/employees/include_terminated
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

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("rippling_all_employees")


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def rippling_get(base_url: str, token: str, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    url = f"{base_url.rstrip('/')}{path}"
    resp = requests.get(
        url,
        headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
        params=params,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def extract_records(payload: Any) -> List[Dict]:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("results", "data", "employees", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


def fetch_all_employees(
    base_url: str,
    token: str,
    page_size: int,
    api_failures: List[Dict[str, Any]],
) -> List[Dict]:
    results: List[Dict] = []
    offset = 0
    path = "/platform/api/employees/include_terminated"

    while True:
        try:
            payload = rippling_get(base_url, token, path, params={"limit": page_size, "offset": offset})
        except requests.exceptions.RequestException as e:
            api_failures.append({"endpoint": path, "offset": offset, "type": type(e).__name__, "message": str(e)})
            logger.warning("Pagination interrupted at offset=%d: %s", offset, e)
            break

        page = extract_records(payload)
        results.extend(page)
        if len(page) < page_size:
            break
        offset += page_size

    return results


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        token = get_env("RIPPLING_API_TOKEN")
    except RuntimeError as e:
        report_failure(str(e), "bad_config")
        return 1

    base_url = os.environ.get("RIPPLING_BASE_URL", "https://api.rippling.com").rstrip("/")
    page_size = int(os.environ.get("RIPPLING_PAGE_SIZE", "100"))

    api_failures: List[Dict[str, Any]] = []
    employees = fetch_all_employees(base_url, token, page_size, api_failures)

    active = [e for e in employees if not e.get("terminationDate") and not e.get("terminated")]
    terminated = [e for e in employees if e.get("terminationDate") or e.get("terminated")]

    result = {
        "source": "rippling",
        "endpoint": "/platform/api/employees/include_terminated",
        "mode": "all_including_terminated",
        "count": len(employees),
        "count_active": len(active),
        "count_terminated": len(terminated),
        "api_failures": api_failures,
        "results": employees,
        "retrieved_at": current_timestamp(),
    }

    output_path = output_dir / "rippling_all_employees.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)

    if api_failures:
        detail = "; ".join(
            f"offset {f.get('offset')}: {f.get('type')}: {f.get('message')}"
            for f in api_failures[:3]
        )
        report_failure(
            f"{len(api_failures)} Rippling API failure(s) collecting all "
            f"employees (including terminated) from {result['endpoint']}; "
            f"pagination stopped with {len(employees)} record(s) collected: {detail}",
            "partial_failure",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
