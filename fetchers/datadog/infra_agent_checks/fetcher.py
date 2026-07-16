#!/usr/bin/env python3
"""
DataDog Infrastructure Agent Checks Retrieval

Purpose: Retrieve per-host agent check results to prove configuration evaluation is actively
running and passing across the fleet. Check data is sourced from meta.agent_checks on each
host record returned by GET /api/v1/hosts — no separate check endpoint is required.

Each agent_checks entry is a list: [check_name, module, instance_id, STATUS, message, _, tags]
Status values: "OK", "WARNING", "ERROR", "UNKNOWN"
"""

import json
import logging
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv

logger = logging.getLogger("datadog_infra_agent_checks")


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


# Map DataDog agent check status strings to lowercase compliance-friendly names.
# "ERROR" maps to "critical" since a failed check is a critical configuration finding.
STATUS_NORMALIZE = {"OK": "ok", "WARNING": "warning", "ERROR": "critical", "UNKNOWN": "unknown"}


def get_total_hosts(base_url: str, headers: Dict[str, str]) -> int:
    try:
        response = requests.get(
            f"{base_url}/api/v1/hosts",
            headers=headers,
            params={"count": 1},
            timeout=30,
        )
        response.raise_for_status()
        return response.json().get("total_matching", 0)
    except requests.exceptions.HTTPError:
        raise
    except Exception:
        return 0


def fetch_hosts_with_checks(base_url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    all_hosts: List[Dict[str, Any]] = []
    count = 1000
    start = 0
    endpoint = f"{base_url}/api/v1/hosts"

    total_matching = get_total_hosts(base_url, headers)
    if total_matching == 0:
        return []

    while start < total_matching:
        params = {"start": start, "count": count}
        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=60)
            response.raise_for_status()
            payload = response.json()
            hosts = payload.get("host_list", [])
            if not hosts:
                break
            all_hosts.extend(hosts)
            start += count
        except requests.exceptions.RequestException as e:
            logger.warning("Pagination interrupted at start=%s: %s", start, e)
            break

    return all_hosts


def parse_agent_checks(host: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """Extract (check_name, status, message) tuples from meta.agent_checks.

    Each entry in agent_checks is a list:
      [check_name, module, instance_id, STATUS, message, extra, tags]
    """
    checks = host.get("meta", {}).get("agent_checks", [])
    results = []
    for entry in checks:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        check_name = entry[0] or "unknown"
        raw_status = (entry[3] or "UNKNOWN").upper()
        message = entry[4] if len(entry) > 4 else ""
        status = STATUS_NORMALIZE.get(raw_status, "unknown")
        results.append((check_name, status, str(message) if message else ""))
    return results


def get_infra_agent_checks() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()
    endpoint = f"{base_url}/api/v1/hosts"

    try:
        hosts = fetch_hosts_with_checks(base_url, headers)

        if not hosts:
            return {
                "status": "partial_or_empty",
                "message": "No hosts found",
                "api_endpoint": endpoint,
                "record_count": 0,
                "data": [],
                "summary": {
                    "total_check_runs": 0,
                    "checks_by_status": {},
                    "unique_check_names": 0,
                    "hosts_with_critical_checks": 0,
                    "hosts_with_warning_checks": 0,
                    "checks_by_name": {},
                },
                "retrieved_at": current_timestamp(),
            }

        all_check_records = []
        checks_by_name: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        critical_hosts: set = set()
        warning_hosts: set = set()
        status_counter: Counter = Counter()

        for host in hosts:
            host_name = host.get("name", "unknown")
            check_tuples = parse_agent_checks(host)
            for check_name, status, message in check_tuples:
                all_check_records.append({
                    "check_name": check_name,
                    "host_name": host_name,
                    "status": status,
                    "message": message if message else None,
                })
                checks_by_name[check_name][status] += 1
                status_counter[status] += 1
                if status == "critical":
                    critical_hosts.add(host_name)
                elif status == "warning":
                    warning_hosts.add(host_name)

        checks_by_name_final = {k: dict(v) for k, v in checks_by_name.items()}

        if not all_check_records:
            return {
                "status": "partial_or_empty",
                "message": "Hosts found but no agent_checks data returned",
                "api_endpoint": endpoint,
                "record_count": 0,
                "data": [],
                "summary": {
                    "total_check_runs": 0,
                    "checks_by_status": {},
                    "unique_check_names": 0,
                    "hosts_with_critical_checks": 0,
                    "hosts_with_warning_checks": 0,
                    "checks_by_name": {},
                },
                "retrieved_at": current_timestamp(),
            }

        return {
            "status": "success",
            "api_endpoint": endpoint,
            "record_count": len(all_check_records),
            "data": all_check_records,
            "summary": {
                "total_check_runs": len(all_check_records),
                "checks_by_status": dict(status_counter),
                "unique_check_names": len(checks_by_name_final),
                "hosts_with_critical_checks": len(critical_hosts),
                "hosts_with_warning_checks": len(warning_hosts),
                "checks_by_name": checks_by_name_final,
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

    result = get_infra_agent_checks()

    output_json = output_dir / "datadog_infra_agent_checks.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    return 0 if result.get("status") in {"success", "partial_or_empty"} else 1


if __name__ == "__main__":
    sys.exit(main())
