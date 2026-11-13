#!/usr/bin/env python3
"""
Rippling — Device Inventory

Queries the Rippling API for company-managed device inventory from Rippling
MDM (laptops, desktops, mobile devices). Probes /platform/api/devices first,
falls back to /v2/devices if needed.

Requires Rippling MDM add-on enabled on the account.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("rippling_devices")


DEVICE_ENDPOINTS = ["/platform/api/devices", "/v2/devices"]


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
        for key in ("results", "data", "devices", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


def find_working_endpoint(
    base_url: str,
    token: str,
    api_failures: List[Dict[str, Any]],
) -> Tuple[Optional[str], Optional[Any]]:
    for endpoint in DEVICE_ENDPOINTS:
        try:
            payload = rippling_get(base_url, token, endpoint, params={"limit": 1, "offset": 0})
            logger.info("Endpoint %s responded; using it", endpoint)
            return endpoint, payload
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "?"
            logger.warning("%s -> HTTP %s", endpoint, status)
            # 404 = endpoint doesn't exist on this account; not a failure to track.
            if e.response is None or e.response.status_code != 404:
                api_failures.append({
                    "endpoint": endpoint,
                    "type": type(e).__name__,
                    "message": str(e),
                })
        except requests.exceptions.RequestException as e:
            logger.warning("%s -> %s", endpoint, e)
            api_failures.append({
                "endpoint": endpoint,
                "type": type(e).__name__,
                "message": str(e),
            })

    return None, None


def fetch_devices(
    base_url: str,
    token: str,
    page_size: int,
    api_failures: List[Dict[str, Any]],
) -> Tuple[Optional[str], List[Dict]]:
    endpoint, first_payload = find_working_endpoint(base_url, token, api_failures)
    if endpoint is None:
        return None, []

    results: List[Dict] = []
    offset = 0

    first_page = extract_records(first_payload)
    if first_page:
        results.extend(first_page)
        if len(first_page) < page_size:
            return endpoint, results
        offset = page_size

    while True:
        try:
            payload = rippling_get(base_url, token, endpoint, params={"limit": page_size, "offset": offset})
        except requests.exceptions.RequestException as e:
            api_failures.append({"endpoint": endpoint, "offset": offset, "type": type(e).__name__, "message": str(e)})
            logger.warning("Pagination interrupted at offset=%d: %s", offset, e)
            break

        page = extract_records(payload)
        results.extend(page)
        if len(page) < page_size:
            break
        offset += page_size

    return endpoint, results


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
    endpoint, devices = fetch_devices(base_url, token, page_size, api_failures)

    result = {
        "source": "rippling",
        "endpoint": endpoint,
        "mode": "device_inventory",
        "count": len(devices),
        "api_failures": api_failures,
        "results": devices,
        "retrieved_at": current_timestamp(),
    }

    output_path = output_dir / "rippling_devices.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)

    if api_failures or endpoint is None:
        detail = "; ".join(
            f"{f.get('endpoint')}: {f.get('type')}: {f.get('message')}"
            for f in api_failures[:3]
        )
        report_failure(
            (
                f"{len(api_failures)} Rippling API failure(s) collecting devices; "
                f"{len(devices)} record(s) collected: {detail}"
            ) if api_failures else (
                "No Rippling device endpoint responded: "
                f"{' and '.join(DEVICE_ENDPOINTS)} both returned HTTP 404, so the "
                "Rippling MDM add-on is likely not enabled on this account"
            ),
            "partial_failure" if api_failures else "bad_config",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
