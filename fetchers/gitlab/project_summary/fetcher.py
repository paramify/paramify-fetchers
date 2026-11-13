#!/usr/bin/env python3
"""
KSI-PIY-GIV: GitLab Project Summary

Inventories configuration files (Terraform, Dockerfiles, YAML configs, etc.)
in a GitLab project repository — evidence of information resource inventory.

Single-target per invocation; fanout across multiple projects happens at the
runner layer (see fetcher.yaml: supports_targets: true).
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests
from dotenv import load_dotenv

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("gitlab_project_summary")


DEFAULT_FILE_PATTERNS = [".tf", ".tfvars", ".yml", ".yaml", ".json", "Dockerfile", ".sh"]


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def http_get(url: str, headers: Dict[str, str], params: Optional[Dict[str, Any]] = None) -> requests.Response:
    return requests.get(url, headers=headers, params=params, timeout=30)


def get_project_file_summary(
    gitlab_url: str,
    api_token: str,
    project_id: str,
    file_patterns: List[str],
) -> Dict[str, Any]:
    api_endpoint = f"{gitlab_url.rstrip('/')}/api/v4"
    headers = {
        "PRIVATE-TOKEN": api_token,
        "Content-Type": "application/json",
    }

    encoded_project = quote(project_id, safe="")
    tree_url = f"{api_endpoint}/projects/{encoded_project}/repository/tree"
    params: Dict[str, Any] = {"recursive": "true", "per_page": 100, "page": 1}

    try:
        all_items: List[Dict[str, Any]] = []
        while True:
            response = http_get(tree_url, headers=headers, params=params)
            if response.status_code != 200:
                raise RuntimeError(f"API Error: {response.status_code} {response.text}")
            page_items = response.json()
            all_items.extend(page_items)
            next_page = response.headers.get("x-next-page") or response.headers.get("X-Next-Page")
            if next_page:
                params["page"] = int(next_page)
            else:
                break

        filtered_files: List[Dict[str, Any]] = []
        file_categories: Dict[str, List[Dict[str, Any]]] = {}

        for item in all_items:
            if item.get("type") != "blob":
                continue

            name = item.get("name", "")
            matched_category: Optional[str] = None
            for pattern in file_patterns:
                if name.endswith(pattern) or pattern in name:
                    matched_category = pattern
                    break
            if matched_category is None:
                continue

            file_info = {
                "name": name,
                "path": item.get("path"),
                "mode": item.get("mode"),
                "id": item.get("id"),
                "category": matched_category,
            }
            filtered_files.append(file_info)
            file_categories.setdefault(matched_category, []).append(file_info)

        total_files = sum(1 for f in all_items if f.get("type") == "blob")
        total_dirs = sum(1 for f in all_items if f.get("type") == "tree")

        return {
            "status": "success",
            "project_id": project_id,
            "total_items": len(all_items),
            "total_files": total_files,
            "total_directories": total_dirs,
            "filtered_files_count": len(filtered_files),
            "files_by_category": {
                category: {"count": len(files), "files": files}
                for category, files in file_categories.items()
            },
            "files": filtered_files,
            "analysis": {
                "has_terraform": any(".tf" in f["name"] for f in filtered_files),
                "has_ci_cd": any(f.get("name") == ".gitlab-ci.yml" for f in all_items if isinstance(f, dict)),
                "has_docker": any("Dockerfile" in (f.get("name") or "") for f in all_items if isinstance(f, dict)),
                "terraform_files": [f for f in filtered_files if ".tf" in f["name"]],
                "config_files": [f for f in filtered_files if any(ext in f["name"] for ext in [".yml", ".yaml"])],
            },
            "retrieved_at": current_timestamp(),
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "project_id": project_id,
            "retrieved_at": current_timestamp(),
        }


def sanitize_for_filename(value: str) -> str:
    sanitized = value.replace("/", "_").replace(" ", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself. The framework's runner +
    # secret resolver will pass resolved values in and this block goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        gitlab_url = get_env("GITLAB_URL")
        api_token = get_env("GITLAB_API_TOKEN")
        project_id = get_env("GITLAB_PROJECT_ID")
    except RuntimeError as e:
        report_failure(str(e), "bad_config")
        return 1

    patterns_env = os.environ.get("GITLAB_FILE_PATTERNS", "")
    file_patterns = [p.strip() for p in patterns_env.split(",") if p.strip()] if patterns_env else DEFAULT_FILE_PATTERNS

    result = get_project_file_summary(gitlab_url, api_token, project_id, file_patterns)

    result_with_metadata = {
        "metadata": {
            "project_id": project_id,
            "project_name": project_id.split("/")[-1] if "/" in project_id else project_id,
            "project_group": project_id.split("/")[0] if "/" in project_id else "unknown",
            "gitlab_url": gitlab_url,
            "scan_timestamp": current_timestamp(),
        },
        **result,
    }

    output_path = output_dir / f"gitlab_project_summary_{sanitize_for_filename(project_id)}.json"
    with open(output_path, "w") as f:
        json.dump(result_with_metadata, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)
    # Last line on stderr wins: the runner reads its tail into the envelope's metadata.error.
    if result.get("status") != "success":
        reason = result.get("message", "unknown error")
        report_failure(reason)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
