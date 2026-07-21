#!/usr/bin/env python3
"""
DataDog Agent Hosts Retrieval

Purpose: Retrieve real-time inventory of all hosts reporting via DataDog agent.
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

logger = logging.getLogger("datadog_agent_hosts")


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


def fetch_all_hosts(base_url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
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


def parse_gohai(gohai_str: Optional[str]) -> Dict[str, Any]:
    if not gohai_str:
        return {}
    try:
        return json.loads(gohai_str) if isinstance(gohai_str, str) else gohai_str
    except (json.JSONDecodeError, TypeError):
        return {}


def detect_cloud_provider(host: Dict[str, Any], gohai: Dict[str, Any]) -> str:
    # Prefer explicit gohai.cloud.provider when present (some agent configs set this)
    provider = gohai.get("cloud", {}).get("provider", "")
    if provider:
        return provider
    # EC2 instance IDs start with "i-" followed by hex chars
    aliases = host.get("aliases", [])
    if any(a.startswith("i-") and len(a) >= 10 for a in aliases):
        return "aws"
    # AWS internal DNS suffixes
    name = host.get("name", "")
    if ".compute.internal" in name or ".ec2.internal" in name:
        return "aws"
    # VPC ID in meta.network
    meta_network = host.get("meta", {}).get("network", {})
    if isinstance(meta_network, dict) and str(meta_network.get("network-id", "")).startswith("vpc-"):
        return "aws"
    return ""


def extract_host_fields(host: Dict[str, Any]) -> Dict[str, Any]:
    meta = host.get("meta", {})
    gohai = parse_gohai(meta.get("gohai"))
    cloud_provider = detect_cloud_provider(host, gohai)

    last_reported = host.get("last_reported_time")
    if isinstance(last_reported, (int, float)):
        last_reported = datetime.fromtimestamp(last_reported, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "id": host.get("id"),
        "name": host.get("name"),
        "aliases": host.get("aliases", []),
        "platform": meta.get("platform"),
        "agent_version": meta.get("agent_version"),
        "cloud_provider": cloud_provider,
        "last_reported_time": last_reported,
        "up": host.get("up"),
        "is_muted": host.get("is_muted"),
        "tags_by_source": host.get("tags_by_source", {}),
    }


def get_agent_hosts() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()
    endpoint = f"{base_url}/api/v1/hosts"

    try:
        hosts = fetch_all_hosts(base_url, headers)

        if not hosts:
            return {
                "status": "partial_or_empty",
                "message": "No hosts found",
                "api_endpoint": endpoint,
                "record_count": 0,
                "data": [],
                "summary": {
                    "total_hosts": 0,
                    "active_hosts": 0,
                    "muted_hosts": 0,
                    "hosts_by_platform": {},
                    "hosts_by_cloud_provider": {},
                    "agent_version_distribution": {},
                },
                "retrieved_at": current_timestamp(),
            }

        extracted = [extract_host_fields(h) for h in hosts]

        active_hosts = [h for h in extracted if h.get("up")]
        muted_hosts = [h for h in extracted if h.get("is_muted")]

        platform_counts: Dict[str, int] = dict(Counter(
            h.get("platform", "unknown") or "unknown" for h in extracted
        ))
        cloud_counts: Dict[str, int] = dict(Counter(
            h.get("cloud_provider", "unknown") or "unknown" for h in extracted
            if h.get("cloud_provider")
        ))
        version_counts: Dict[str, int] = dict(Counter(
            h.get("agent_version", "unknown") or "unknown" for h in extracted
        ))

        current_version = max(version_counts, key=lambda v: version_counts[v]) if version_counts else None
        hosts_outdated = sum(
            1 for h in extracted
            if (h.get("agent_version") or "unknown") != current_version
        ) if current_version else 0

        return {
            "status": "success",
            "api_endpoint": endpoint,
            "record_count": len(extracted),
            "data": extracted,
            "summary": {
                "total_hosts": len(extracted),
                "active_hosts": len(active_hosts),
                "muted_hosts": len(muted_hosts),
                "hosts_by_platform": platform_counts,
                "hosts_by_cloud_provider": cloud_counts,
                "agent_version_distribution": version_counts,
                "hosts_with_outdated_agent": hosts_outdated,
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

    result = get_agent_hosts()

    output_json = output_dir / "datadog_agent_hosts.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    return 0 if result.get("status") in {"success", "partial_or_empty"} else 1


if __name__ == "__main__":
    sys.exit(main())
