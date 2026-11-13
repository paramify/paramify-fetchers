#!/usr/bin/env python3
"""
KSI-CMT-VTD: GitLab CI/CD Pipeline Configuration

Pulls .gitlab-ci.yml for a single GitLab project and analyzes for test stages,
security scanning, deployment jobs, and artifact configuration.

Single-target per invocation; fanout across multiple projects happens at the
runner layer (see fetcher.yaml: supports_targets: true).
"""

import base64
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from urllib.parse import quote

import requests
import yaml
from dotenv import load_dotenv

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("gitlab_ci_cd_pipeline_config")


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def yaml_parse(content: str) -> Any:
    try:
        return yaml.safe_load(content) or {}
    except yaml.YAMLError:
        return {"parse_error": True, "raw": content}


def extract_stages(ci: Any) -> Any:
    return ci.get("stages") if isinstance(ci, dict) else None


def has_stage(ci: Any, stage_name: str) -> bool:
    stages = extract_stages(ci)
    if isinstance(stages, list) and stage_name in stages:
        return True
    if isinstance(ci, dict):
        for job_name, job in ci.items():
            if job_name.startswith(".") or not isinstance(job, dict):
                continue
            if job.get("stage") == stage_name:
                return True
    return False


def check_for_security_scanning(ci: Any) -> bool:
    if not isinstance(ci, dict):
        return False
    blob = json.dumps(ci, sort_keys=True).lower()
    return any(k in blob for k in [
        "sast", "dependency_scanning", "container_scanning",
        "secret_detection", "dast", "license_scanning", "code_quality",
    ])


def count_jobs(ci: Any) -> int:
    if not isinstance(ci, dict):
        return 0
    return sum(
        1 for name, body in ci.items()
        if not name.startswith(".")
        and isinstance(body, dict)
        and ("script" in body or "stage" in body)
    )


def check_for_includes(ci: Any) -> bool:
    return isinstance(ci, dict) and "include" in ci


def extract_deployment_jobs(ci: Any) -> list:
    if not isinstance(ci, dict):
        return []
    return [
        name for name, job in ci.items()
        if not name.startswith(".")
        and isinstance(job, dict)
        and (job.get("environment") or job.get("when") in {"manual", "delayed"})
    ]


def check_artifacts(ci: Any) -> bool:
    if not isinstance(ci, dict):
        return False
    return any(
        isinstance(job, dict) and "artifacts" in job
        for name, job in ci.items()
        if not name.startswith(".")
    )


def get_gitlab_ci_config(gitlab_url: str, api_token: str, project_id: str, branch: str) -> Dict[str, Any]:
    api_endpoint = f"{gitlab_url.rstrip('/')}/api/v4"
    headers = {
        "PRIVATE-TOKEN": api_token,
        "Content-Type": "application/json",
    }

    encoded_path = quote(".gitlab-ci.yml", safe="")
    encoded_project = quote(project_id, safe="")
    file_url = f"{api_endpoint}/projects/{encoded_project}/repository/files/{encoded_path}"
    params = {"ref": branch}

    try:
        response = requests.get(file_url, headers=headers, params=params, timeout=30)
        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": "No .gitlab-ci.yml file found in project",
                "project_id": project_id,
                "branch": branch,
                "retrieved_at": current_timestamp(),
            }
        if response.status_code != 200:
            raise RuntimeError(f"API Error: {response.status_code} {response.text}")

        file_data = response.json()
        content = base64.b64decode(file_data.get("content", "")).decode("utf-8")
        ci = yaml_parse(content)

        return {
            "status": "success",
            "project_id": project_id,
            "branch": branch,
            "file_name": file_data.get("file_name"),
            "file_path": file_data.get("file_path"),
            "last_commit_id": file_data.get("last_commit_id"),
            "content_raw": content,
            "content_parsed": ci,
            "analysis": {
                "stages": extract_stages(ci),
                "has_test_stage": has_stage(ci, "test"),
                "has_security_scan": check_for_security_scanning(ci),
                "jobs_count": count_jobs(ci),
                "uses_templates": check_for_includes(ci),
                "deployment_jobs": extract_deployment_jobs(ci),
                "artifacts_configured": check_artifacts(ci),
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

    branch = os.environ.get("GITLAB_BRANCH", "main")

    result = get_gitlab_ci_config(gitlab_url, api_token, project_id, branch)

    result_with_metadata = {
        "metadata": {
            "project_id": project_id,
            "project_name": project_id.split("/")[-1] if "/" in project_id else project_id,
            "project_group": project_id.split("/")[0] if "/" in project_id else "unknown",
            "gitlab_url": gitlab_url,
            "branch": branch,
            "scan_timestamp": current_timestamp(),
        },
        **result,
    }

    output_path = output_dir / f"gitlab_ci_cd_pipeline_config_{sanitize_for_filename(project_id)}.json"
    with open(output_path, "w") as f:
        json.dump(result_with_metadata, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)
    # Last line on stderr wins: the runner reads its tail into the envelope's metadata.error.
    if result.get("status") not in {"success", "not_found"}:
        reason = result.get("message", "unknown error")
        report_failure(reason)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
