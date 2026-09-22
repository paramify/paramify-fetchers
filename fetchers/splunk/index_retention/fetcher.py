#!/usr/bin/env python3
"""
Splunk Index Retention and Capacity

Reads every index on one Splunk deployment and records what retention is
actually configured on each, so a 90-day searchable-retention claim can be
asserted per index instead of being asserted globally and hoped for.

Retention on Splunk is `frozenTimePeriodInSecs`: the age at which a bucket
freezes and leaves the searchable window. That is the searchable-retention
figure, and it is the only retention *duration* splunkd exposes. Archival is
expressed as a destination (`coldToFrozenDir` / `coldToFrozenScript`), never as
a number of days, so this fetcher reports whether archival is configured and
deliberately does NOT infer an archival duration. On Splunk Cloud that number
lives in ACS as `splunkArchivalRetentionDays`; a separate fetcher covers it.
"""

import json
import logging
import os
import re
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("splunk_index_retention")

SECONDS_PER_DAY = 86400


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_filename(value: str) -> str:
    sanitized = value.replace("://", "_").replace("/", "_").replace(":", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized)


def env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() not in {"false", "0", "no", "off"}


def build_session(token: str, username: str, password: str, verify_ssl: bool) -> requests.Session:
    """Bearer token if we have one, HTTP basic otherwise.

    Splunk Cloud effectively requires the token; basic auth is the Enterprise
    and sandbox path. Callers guarantee one of the two is present.
    """
    session = requests.Session()
    session.verify = verify_ssl
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    else:
        session.auth = (username, password)
    return session


def get_json(session: requests.Session, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    merged = {"output_mode": "json", **params}
    response = session.get(url, params=merged, timeout=60)
    if response.status_code in (401, 403):
        raise PermissionError(f"{response.status_code} from {url}: {response.text[:300]}")
    if response.status_code != 200:
        raise RuntimeError(f"{response.status_code} from {url}: {response.text[:300]}")
    return response.json()


def to_int(value: Any) -> Any:
    """splunkd returns numbers as strings; keep non-numeric values visible."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def describe_index(entry: Dict[str, Any], required_days: int) -> Dict[str, Any]:
    content = entry.get("content", {}) or {}
    frozen_secs = to_int(content.get("frozenTimePeriodInSecs"))
    retention_days = round(frozen_secs / SECONDS_PER_DAY, 2) if frozen_secs is not None else None

    cold_to_frozen_dir = content.get("coldToFrozenDir") or ""
    cold_to_frozen_script = content.get("coldToFrozenScript") or ""

    return {
        "name": entry.get("name"),
        "disabled": bool(content.get("disabled", False)),
        "is_internal": str(entry.get("name", "")).startswith("_"),
        "frozen_time_period_secs": frozen_secs,
        "searchable_retention_days": retention_days,
        "meets_searchable_retention_requirement": (
            retention_days is not None and retention_days >= required_days
        ),
        "max_total_data_size_mb": to_int(content.get("maxTotalDataSizeMB")),
        "current_size_mb": to_int(content.get("currentDBSizeMB")),
        "total_event_count": to_int(content.get("totalEventCount")),
        "min_time": content.get("minTime"),
        "max_time": content.get("maxTime"),
        # Archival is a DESTINATION on splunkd, not a duration. Recorded as such
        # so nobody downstream reads an absent number as "zero days retained".
        "cold_to_frozen_dir": cold_to_frozen_dir,
        "cold_to_frozen_script": cold_to_frozen_script,
        "archival_destination_configured": bool(cold_to_frozen_dir or cold_to_frozen_script),
        "frozen_time_period_source": "frozenTimePeriodInSecs",
    }


def summarize(indexes: List[Dict[str, Any]], required_days: int) -> Dict[str, Any]:
    """Retention roll-up over whichever set of indexes was handed in."""
    enabled = [i for i in indexes if not i["disabled"]]
    below = [i["name"] for i in enabled if not i["meets_searchable_retention_requirement"]]
    unknown = [i["name"] for i in enabled if i["searchable_retention_days"] is None]
    return {
        "searchable_retention_days_required": required_days,
        "total_indexes": len(indexes),
        "enabled_indexes": len(enabled),
        "disabled_indexes": len(indexes) - len(enabled),
        "indexes_meeting_requirement": len(enabled) - len(below),
        "indexes_below_requirement": len(below),
        "indexes_below_requirement_names": sorted(below),
        "indexes_with_unreadable_retention": sorted(unknown),
        "all_indexes_meet_requirement": len(below) == 0,
        "indexes_with_archival_destination": sum(
            1 for i in enabled if i["archival_destination_configured"]
        ),
    }


def collect(
    session: requests.Session, host: str, required_days: int, audit_indexes: List[str]
) -> Dict[str, Any]:
    base = host.rstrip("/")
    api_failures: List[Dict[str, str]] = []

    server = {}
    try:
        info = get_json(session, f"{base}/services/server/info", {})
        content = (info.get("entry") or [{}])[0].get("content", {})
        server = {
            "version": content.get("version"),
            "product_type": content.get("product_type"),
            "license_state": content.get("licenseState"),
            "server_name": content.get("serverName"),
            "mode": content.get("mode"),
        }
    except Exception as exc:  # server/info is context, not the evidence itself
        api_failures.append(
            {"operation": "GET /services/server/info", "type": type(exc).__name__, "message": str(exc)}
        )

    # count=0 returns every index in one call — splunkd's documented convention.
    data = get_json(session, f"{base}/services/data/indexes", {"count": 0})
    entries = data.get("entry") or []
    indexes = [describe_index(e, required_days) for e in entries]
    for i in indexes:
        i["in_audit_scope"] = i["name"] in audit_indexes if audit_indexes else None

    # Two roll-ups, deliberately. `summary` covers every index on the deployment
    # and is the completeness view. `audit_scope` covers only the indexes named
    # as holding audit/security data, and is the one that speaks to the control:
    # Splunk's own housekeeping indexes (_internal at 30d, _thefishbucket at 28d)
    # sit below any sane audit-retention floor by design, so a roll-up that mixes
    # them in reports a control failure that is not one.
    missing = [n for n in audit_indexes if n not in {i["name"] for i in indexes}]
    scope = {
        "configured": bool(audit_indexes),
        "indexes_named": sorted(audit_indexes),
        "indexes_named_but_absent": sorted(missing),
    }
    if audit_indexes:
        scope.update(summarize([i for i in indexes if i["name"] in audit_indexes], required_days))
        # An index named in scope that does not exist is a gap in the claim, not
        # a pass — it cannot be retaining anything.
        scope["all_indexes_meet_requirement"] = (
            scope["all_indexes_meet_requirement"] and not missing
        )

    return {
        "server": server,
        "indexes": sorted(indexes, key=lambda i: str(i["name"])),
        "summary": summarize(indexes, required_days),
        "audit_scope": scope,
        # Stated in the evidence rather than left to be inferred: splunkd has no
        # archival-duration field, so this evidence cannot speak to an archival
        # retention claim. Silence here would read as "no archival configured".
        "archival_retention_note": (
            "splunkd exposes archival as a destination (coldToFrozenDir / "
            "coldToFrozenScript), not as a number of days. No archival retention "
            "DURATION is readable from this API. On Splunk Cloud that figure is "
            "splunkArchivalRetentionDays via ACS and is out of scope for this fetcher."
        ),
        "api_failures": api_failures,
    }


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

    host = os.environ.get("SPLUNK_HOST", "")
    token = os.environ.get("SPLUNK_TOKEN", "")
    username = os.environ.get("SPLUNK_USERNAME", "")
    password = os.environ.get("SPLUNK_PASSWORD", "")
    target_name = os.environ.get("SPLUNK_TARGET_NAME", "") or host
    verify_ssl = env_flag("SPLUNK_VERIFY_SSL", True)

    if not host:
        report_failure("Missing required env var: SPLUNK_HOST", "bad_config")
        return 1
    if not token and not (username and password):
        report_failure(
            "No Splunk credential: supply SPLUNK_TOKEN, or SPLUNK_USERNAME and SPLUNK_PASSWORD",
            "bad_config",
        )
        return 1

    audit_indexes = [
        n.strip() for n in os.environ.get("SPLUNK_AUDIT_INDEXES", "").split(",") if n.strip()
    ]

    raw_days = os.environ.get("SPLUNK_SEARCHABLE_RETENTION_DAYS", "90")
    try:
        required_days = int(raw_days)
    except ValueError:
        report_failure(
            f"SPLUNK_SEARCHABLE_RETENTION_DAYS must be an integer, got {raw_days!r}", "bad_config"
        )
        return 1

    if not verify_ssl:
        # Only reachable when the target explicitly opted out, which the schema
        # restricts to sandboxes. Suppressing the warning keeps it off stderr,
        # whose tail the runner reads as the failure reason. Filtered by message
        # rather than by class so this stays stdlib-only and urllib3 need not be
        # imported (or declared) just to name an exception type.
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    session = build_session(token, username, password, verify_ssl)
    auth_method = "bearer_token" if token else "basic_auth"

    failure: Dict[str, str] = {}
    try:
        result = collect(session, host, required_days, audit_indexes)
    except PermissionError as exc:
        result = {"api_failures": [{"operation": "collect", "type": "PermissionError", "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "not_authorized"}
    except requests.exceptions.RequestException as exc:
        result = {"api_failures": [{"operation": "collect", "type": type(exc).__name__, "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "target_unreachable"}
    except Exception as exc:
        result = {"api_failures": [{"operation": "collect", "type": type(exc).__name__, "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "internal_error"}

    api_failures = result.get("api_failures", [])
    evidence = {
        "target_name": target_name,
        "splunk_host": host,
        "auth_method": auth_method,
        "tls_verified": verify_ssl,
        "collected_at": current_timestamp(),
        "partial_failure": bool(api_failures) and not failure,
        **result,
    }

    output_path = output_dir / f"splunk_index_retention_{sanitize_for_filename(target_name)}.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)
    # Reported AFTER the success line above: the runner reads the TAIL of stderr
    # as the failure reason, so whichever line is logged last wins. report_failure
    # does the error-level logging itself — logging the reason here as well puts
    # it on stderr twice (tests/test_failure_reporting_contract.py enforces this).
    if failure:
        report_failure(failure["reason"], failure["code"])
        return 1
    if api_failures:
        report_failure(
            "; ".join(f"{f['operation']}: {f['message']}" for f in api_failures),
            "partial_failure",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
