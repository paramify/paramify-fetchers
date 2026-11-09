#!/usr/bin/env python3
"""
DataDog SIEM Configuration Retrieval

Purpose: Retrieve Cloud SIEM operational state: whether Cloud SIEM is active,
suppression rules, and where security signals are sent.

Endpoints (Datadog API reference, docs.datadoghq.com/api/latest/):
  - GET /api/v2/security_monitoring/content_packs/states
        The only documented "is Cloud SIEM active" signal: when Cloud SIEM is
        inactive for the organization, each content pack's `details.type` is
        `onboarding` instead of its usual type. The endpoint is in preview, so
        a failed read leaves the state unknown (null) and does not fail the run.
  - GET /api/v2/security_monitoring/configuration/suppressions
  - GET /api/v2/security/signals/notification_rules
  - GET /api/v2/security_monitoring/rules  (cases[].notifications of enabled
        Cloud SIEM rules)
  - GET /api/v1/integration/webhooks/configuration/webhooks/{webhook_name}
        Datadog has no endpoint that lists webhooks, so only the webhooks that
        a notification target names (`@webhook-<name>`) are read.

A 404 or 403 is never read as "Cloud SIEM is not enabled". Only the
`onboarding` signal above gives that verdict.

Every request goes through the shared helpers in `_shared/` (paging, the 429
retry and the Cloud SIEM state rule). Each failed request is one entry in
`metadata.api_failures`, the same shape as the other Datadog fetchers. A read
that fails outright fails the run (`status: error`). A read that stops on a
later page, or a webhook read that fails with a status other than 404, gives
`status: partial_failure`. Either way the run exits 1, and each summary figure
that depends on the failed read is null.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse

import requests
from dotenv import load_dotenv

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
# The Cloud SIEM state rule shared by the Datadog SIEM fetchers lives in _shared/.
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from datadog_paging import (  # noqa: E402
    PagedRecords,
    PagingError,
    error_result,
    paginate_page_number,
    request_failure,
    request_json,
)
from datadog_siem_state import (  # noqa: E402
    CONTENT_PACKS_PATH,
    NOT_ACTIVE_MESSAGE,
    SIEM_RULE_TYPES,
    read_siem_state,
)
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("datadog_siem_configuration")

SUPPRESSIONS_PATH = "/api/v2/security_monitoring/configuration/suppressions"
NOTIFICATION_RULES_PATH = "/api/v2/security/signals/notification_rules"
DETECTION_RULES_PATH = "/api/v2/security_monitoring/rules"
WEBHOOK_PATH = "/api/v1/integration/webhooks/configuration/webhooks/{name}"

PAGE_SIZE = 100

# Handle prefixes from Datadog's notification docs (`@<INTEGRATION>-<VALUES>`).
# `teams` is Microsoft Teams; `team` is a Datadog Team handle.
KNOWN_HANDLE_PREFIXES = {
    "slack",
    "pagerduty",
    "webhook",
    "teams",
    "team",
    "opsgenie",
    "jira",
    "servicenow",
    "incident",
}


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


# --------------------------------------------------------------------------- #
# Configuration reads
# --------------------------------------------------------------------------- #

def extract_suppression(item: Dict[str, Any]) -> Dict[str, Any]:
    attrs = item.get("attributes") or {}
    return {
        "id": item.get("id"),
        "name": attrs.get("name"),
        "enabled": attrs.get("enabled"),
        "start_date": attrs.get("start_date"),
        "expiration_date": attrs.get("expiration_date"),
        "rule_query": attrs.get("rule_query"),
        "suppression_query": attrs.get("suppression_query"),
        "data_exclusion_query": attrs.get("data_exclusion_query"),
        "version": attrs.get("version"),
    }


def extract_notification_rule(item: Dict[str, Any]) -> Dict[str, Any]:
    attrs = item.get("attributes") or {}
    selectors = attrs.get("selectors") or {}
    return {
        "id": item.get("id"),
        "name": attrs.get("name"),
        "enabled": attrs.get("enabled"),
        "targets": list(attrs.get("targets") or []),
        "severities": list(selectors.get("severities") or []),
        "rule_types": list(selectors.get("rule_types") or []),
        "query": selectors.get("query"),
    }


def detection_rule_targets(rule: Dict[str, Any]) -> List[str]:
    targets: List[str] = []
    for case in rule.get("cases") or []:
        for target in case.get("notifications") or []:
            if target not in targets:
                targets.append(target)
    return targets


def classify_target(target: str) -> Tuple[str, Optional[str]]:
    """(type, webhook name or None) for one notification target.

    `@user@example.com` is email; `@<integration>-<values>` is that integration.
    The leading `@` is optional, since the API field is a plain list of targets.
    """
    handle = target.strip().lstrip("@")
    if "@" in handle:
        return "email", None
    prefix, sep, rest = handle.partition("-")
    prefix = prefix.lower()
    if sep and prefix in KNOWN_HANDLE_PREFIXES:
        return prefix, (rest if prefix == "webhook" and rest else None)
    return "other", None


def summarize_targets(targets: Iterable[str]) -> Tuple[List[str], List[str]]:
    types: Set[str] = set()
    webhooks: Set[str] = set()
    for target in targets:
        kind, webhook = classify_target(target)
        types.add(kind)
        if webhook:
            webhooks.add(webhook)
    return sorted(types), sorted(webhooks)


def read_webhook(
    base_url: str, headers: Dict[str, str], name: str
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """One referenced webhook, and an `api_failures` entry if the read failed.

    Logs the URL's domain only, never the full URL. A 404 is the documented
    "Item Not Found": the target names a webhook that does not exist, so that
    notification reaches nobody (`found: false`, not a failure). Any other
    failure leaves `found` null and is returned as a failure.
    """
    path = WEBHOOK_PATH.format(name=quote(name, safe=""))
    try:
        payload = request_json("GET", f"{base_url}{path}", headers)
    except (requests.exceptions.RequestException, ValueError) as e:
        status_code = getattr(getattr(e, "response", None), "status_code", None)
        if status_code == 404:
            return {"name": name, "found": False, "url_domain": None}, None
        return (
            {"name": name, "found": None, "url_domain": None},
            request_failure("Datadog read webhook", e, webhook=name),
        )
    payload = payload if isinstance(payload, dict) else {}
    raw_url = payload.get("url") or ""
    return {
        "name": payload.get("name") or name,
        "found": True,
        "url_domain": urlparse(raw_url).netloc if raw_url else "",
    }, None


def failure_code(failures: List[Dict[str, Any]]) -> str:
    """The `report_failure` code for reads that failed outright."""
    codes = {f.get("status_code") for f in failures}
    if codes == {401}:
        return "auth_failed"
    if 403 in codes or 401 in codes:
        return "not_authorized"
    if 429 in codes:
        return "rate_limited"
    if None in codes or any(c is not None and c >= 500 for c in codes):
        return "target_unreachable"
    return "partial_failure"


def _walk(
    base_url: str, path: str, headers: Dict[str, str], operation: str, fatal: List[Dict[str, Any]]
) -> Optional[PagedRecords]:
    """A page[number] walk, or None (with an entry in `fatal`) if its first page failed."""
    try:
        return paginate_page_number(f"{base_url}{path}", headers, operation=operation, page_size=PAGE_SIZE)
    except PagingError as e:
        fatal.append(e.api_failure())
        return None


def get_siem_configuration() -> Dict[str, Any]:
    try:
        base_url = get_base_url()
        headers = get_dd_headers()
    except RuntimeError as e:
        return error_result(str(e), current_timestamp(), "bad_config")

    endpoints = [SUPPRESSIONS_PATH, CONTENT_PACKS_PATH, NOTIFICATION_RULES_PATH, DETECTION_RULES_PATH]
    siem_state = read_siem_state(base_url, headers)

    if siem_state["enabled"] is False:
        return {
            "status": "not_available",
            "message": NOT_ACTIVE_MESSAGE,
            "api_endpoint": f"{base_url}{CONTENT_PACKS_PATH}",
            "data": {"siem_state": siem_state},
            "summary": {"siem_enabled": False},
            "metadata": {"partial_failure": False, "api_failures": []},
            "retrieved_at": current_timestamp(),
        }

    # Reads that failed outright (status error), and reads that stopped part
    # way or webhook reads that failed (status partial_failure).
    fatal: List[Dict[str, Any]] = []
    partial: List[Dict[str, Any]] = []

    def note_incomplete(walked: Optional[PagedRecords]) -> bool:
        """True when the walk read every page."""
        if walked is None:
            return False
        if walked.error is not None:
            partial.append(walked.error.api_failure())
            return False
        return True

    suppressions_walk = _walk(base_url, SUPPRESSIONS_PATH, headers, "Datadog list suppression rules", fatal)
    suppressions_complete = note_incomplete(suppressions_walk)
    suppressions = (
        None if suppressions_walk is None else [extract_suppression(i) for i in suppressions_walk]
    )

    notification_rules: Optional[List[Dict[str, Any]]] = None
    try:
        payload = request_json("GET", f"{base_url}{NOTIFICATION_RULES_PATH}", headers)
        items = payload.get("data") if isinstance(payload, dict) else None
        if items is not None and not isinstance(items, list):
            raise ValueError(f"expected a list at data, got {type(items).__name__}")
        notification_rules = [extract_notification_rule(i) for i in items or []]
    except (requests.exceptions.RequestException, ValueError) as e:
        fatal.append(request_failure("Datadog list signal notification rules", e))

    rules_walk = _walk(base_url, DETECTION_RULES_PATH, headers, "Datadog list security monitoring rules", fatal)
    rules_complete = note_incomplete(rules_walk)
    rule_notifications: Optional[List[Dict[str, Any]]] = None
    if rules_walk is not None:
        rule_notifications = []
        for rule in rules_walk:
            if not rule.get("isEnabled") or rule.get("type") not in SIEM_RULE_TYPES:
                continue
            targets = detection_rule_targets(rule)
            if targets:
                rule_notifications.append({
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name"),
                    "rule_type": rule.get("type"),
                    "targets": targets,
                })

    # Where notifications go comes only from enabled configuration. Unknown
    # (null) when either source could not be read in full.
    notification_types: Optional[List[str]] = None
    referenced_webhooks: Optional[List[Dict[str, Any]]] = None
    webhook_failures: List[Dict[str, Any]] = []
    if notification_rules is not None and rule_notifications is not None:
        targets = [t for r in notification_rules if r.get("enabled") for t in r["targets"]]
        targets += [t for r in rule_notifications for t in r["targets"]]
        types, webhook_names = summarize_targets(targets)
        notification_types = types if rules_complete else None
        referenced_webhooks = []
        for name in webhook_names:
            record, failure = read_webhook(base_url, headers, name)
            referenced_webhooks.append(record)
            if failure is not None:
                webhook_failures.append(failure)
            endpoints.append(WEBHOOK_PATH.format(name=quote(name, safe="")))
    partial.extend(webhook_failures)

    # A webhook list is complete only when every source of targets was read in
    # full and every webhook read answered.
    webhooks_known = referenced_webhooks is not None and rules_complete and not webhook_failures

    result: Dict[str, Any] = {
        "status": "success",
        "api_endpoint": f"{base_url}{SUPPRESSIONS_PATH}",
        "api_endpoints_additional": [f"{base_url}{p}" for p in endpoints[1:]],
        "record_count": len(suppressions or []) + len(notification_rules or []),
        "data": {
            "siem_state": siem_state,
            "suppression_rules": suppressions,
            "notification_rules": notification_rules,
            "detection_rule_notifications": rule_notifications,
            "referenced_webhooks": referenced_webhooks,
        },
        "summary": {
            "siem_enabled": siem_state["enabled"],
            "suppression_rules_count": (
                len(suppressions) if suppressions is not None and suppressions_complete else None
            ),
            "enabled_suppression_rules": (
                sum(1 for r in suppressions if r.get("enabled"))
                if suppressions is not None and suppressions_complete else None
            ),
            "notification_rules_count": None if notification_rules is None else len(notification_rules),
            "enabled_notification_rules": (
                None if notification_rules is None
                else sum(1 for r in notification_rules if r.get("enabled"))
            ),
            "detection_rules_with_notifications": (
                len(rule_notifications) if rule_notifications is not None and rules_complete else None
            ),
            "referenced_webhooks_count": (
                len(referenced_webhooks) if referenced_webhooks is not None and rules_complete else None
            ),
            "missing_webhooks": (
                sorted(w["name"] for w in referenced_webhooks or [] if w["found"] is False)
                if webhooks_known else None
            ),
            "notification_types": notification_types,
        },
        "metadata": {
            "partial_failure": bool(fatal or partial),
            "api_failures": fatal + partial,
        },
        "retrieved_at": current_timestamp(),
    }
    if fatal:
        result["status"] = "error"
        result["error_code"] = failure_code(fatal)
        result["message"] = "; ".join(f"{f['operation']}: {f['message']}" for f in fatal + partial)
    elif partial:
        result["status"] = "partial_failure"
        result["error_code"] = "partial_failure"
        result["message"] = "Incomplete collection: " + "; ".join(
            f"{f['operation']}: {f['message']}" for f in partial
        )
    return result


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    result = get_siem_configuration()

    output_json = output_dir / "datadog_siem_configuration.json"
    with open(output_json, "w") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_json)

    # Last line on stderr wins: the runner reads its tail into the envelope's metadata.error.
    if result.get("status") not in {"success", "not_available"}:
        reason = result.get("message", "unknown error")
        report_failure(reason, result.get("error_code"))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
