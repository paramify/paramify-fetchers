#!/usr/bin/env python3
"""
DataDog Containers Retrieval

Purpose: Retrieve real-time inventory of all running containers across the organization,
including image, state, host/node, and Kubernetes metadata. Pairs with datadog_agent_hosts
(nodes) to provide a complete two-layer inventory: nodes → containers.
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

logger = logging.getLogger("datadog_containers")


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


def fetch_all_containers(base_url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    all_containers: List[Dict[str, Any]] = []
    cursor: Optional[str] = None
    endpoint = f"{base_url}/api/v2/containers"

    while True:
        params: Dict[str, Any] = {"page[size]": 1000}
        if cursor:
            params["page[cursor]"] = cursor
        try:
            response = requests.get(endpoint, headers=headers, params=params, timeout=60)
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data", [])
            all_containers.extend(data)
            cursor = payload.get("meta", {}).get("pagination", {}).get("next_cursor")
            if not cursor or not data:
                break
        except requests.exceptions.RequestException as e:
            logger.warning("Pagination interrupted: %s", e)
            break

    return all_containers


def parse_tag_value(tags: List[str], key: str) -> Optional[str]:
    prefix = f"{key}:"
    for tag in tags:
        if tag.startswith(prefix):
            return tag[len(prefix):]
    return None


def safe_tags(tags: List[str]) -> List[str]:
    # Strip any tag whose value portion contains '=' — guards against accidental env var leakage.
    result = []
    for tag in tags:
        value = tag.split(":", 1)[1] if ":" in tag else tag
        if "=" not in value:
            result.append(tag)
    return result


def extract_container_fields(item: Dict[str, Any]) -> Dict[str, Any]:
    attrs = item.get("attributes", {})
    tags = safe_tags(attrs.get("tags") or [])
    return {
        "container_id": attrs.get("container_id"),
        "name": attrs.get("name"),
        "host": attrs.get("host"),
        "image_name": attrs.get("image_name"),
        "image_tags": attrs.get("image_tags") or [],
        "image_digest": attrs.get("image_digest") or None,
        "state": attrs.get("state"),
        "started_at": attrs.get("started_at"),
        "tags": tags,
    }


def get_containers() -> Dict[str, Any]:
    base_url = get_base_url()
    headers = get_dd_headers()
    endpoint = f"{base_url}/api/v2/containers"

    try:
        raw = fetch_all_containers(base_url, headers)

        if not raw:
            return {
                "status": "partial_or_empty",
                "message": "No containers found",
                "api_endpoint": endpoint,
                "record_count": 0,
                "data": [],
                "summary": {
                    "total_containers": 0,
                    "containers_by_state": {},
                    "containers_by_environment": {},
                    "containers_by_namespace": {},
                    "unique_images": 0,
                    "containers_without_image_digest": 0,
                    "non_running_containers_count": 0,
                    "prod_non_running_containers": 0,
                },
                "retrieved_at": current_timestamp(),
            }

        containers = [extract_container_fields(c) for c in raw]

        state_counts: Dict[str, int] = dict(Counter(
            c.get("state") or "unknown" for c in containers
        ))

        env_counts: Counter = Counter()
        namespace_counts: Counter = Counter()
        for c in containers:
            tags = c.get("tags", [])
            env = parse_tag_value(tags, "env")
            env_counts[env if env else "untagged"] += 1
            ns = parse_tag_value(tags, "kube_namespace")
            if ns:
                namespace_counts[ns] += 1

        unique_images = len(set(c.get("image_name") for c in containers if c.get("image_name")))
        containers_without_digest = sum(1 for c in containers if not c.get("image_digest"))
        non_running = sum(1 for c in containers if c.get("state") != "running")
        prod_non_running = sum(
            1 for c in containers
            if c.get("state") != "running" and "env:prod" in c.get("tags", [])
        )

        return {
            "status": "success",
            "api_endpoint": endpoint,
            "record_count": len(containers),
            "data": containers,
            "summary": {
                "total_containers": len(containers),
                "containers_by_state": state_counts,
                "containers_by_environment": dict(env_counts),
                "containers_by_namespace": dict(namespace_counts),
                "unique_images": unique_images,
                "containers_without_image_digest": containers_without_digest,
                "non_running_containers_count": non_running,
                "prod_non_running_containers": prod_non_running,
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

    result = get_containers()

    output_json = output_dir / "datadog_containers.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    return 0 if result.get("status") in {"success", "partial_or_empty"} else 1


if __name__ == "__main__":
    sys.exit(main())
