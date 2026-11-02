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

from datadog_siem_state import (  # noqa: E402
    CONTENT_PACKS_PATH,
    NOT_ACTIVE_MESSAGE,
    siem_state_from_content_packs,
    unknown_siem_state,
)
from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("datadog_siem_configuration")

SUPPRESSIONS_PATH = "/api/v2/security_monitoring/configuration/suppressions"
NOTIFICATION_RULES_PATH = "/api/v2/security/signals/notification_rules"
DETECTION_RULES_PATH = "/api/v2/security_monitoring/rules"
WEBHOOK_PATH = "/api/v1/integration/webhooks/configuration/webhooks/{name}"

PAGE_SIZE = 100
# A guard against a server that never returns a short page.
MAX_PAGES = 500

# Detection rule types that Cloud SIEM owns. The rules endpoint also returns
# Workload Protection, CSM and App and API Protection rules.
SIEM_RULE_TYPES = {"log_detection", "signal_correlation"}

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


class ApiError(Exception):
    def __init__(self, endpoint: str, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.endpoint = endpoint
        self.status_code = status_code

    def as_record(self) -> Dict[str, Any]:
        return {"endpoint": self.endpoint, "status_code": self.status_code, "error": str(self)}


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


def api_get(base_url: str, path: str, headers: Dict[str, str],
            params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """GET one JSON object, or raise ApiError naming the path and status."""
    try:
        response = requests.get(f"{base_url}{path}", headers=headers, params=params, timeout=30)
    except requests.exceptions.RequestException as e:
        raise ApiError(path, f"request failed: {e}") from e
    if response.status_code >= 400:
        raise ApiError(path, f"HTTP {response.status_code}: {response.text[:300]}", response.status_code)
    try:
        payload = response.json()
    except ValueError as e:
        raise ApiError(path, f"response is not JSON (HTTP {response.status_code})", response.status_code) from e
    if not isinstance(payload, dict):
        raise ApiError(path, "response is not a JSON object", response.status_code)
    return payload


def get_paged(base_url: str, path: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """All `data` items from a page[number]/page[size] endpoint (pages start at 0).

    Items are de-duplicated by `id`, and a page that adds nothing new ends the
    read, so a server that numbers pages from 1 cannot double-count page one.
    """
    items: List[Dict[str, Any]] = []
    seen: Set[Any] = set()
    for page_number in range(MAX_PAGES):
        payload = api_get(base_url, path, headers,
                          params={"page[size]": PAGE_SIZE, "page[number]": page_number})
        data = payload.get("data") or []
        new = [i for i in data if i.get("id") is None or i.get("id") not in seen]
        seen.update(i.get("id") for i in new if i.get("id") is not None)
        items.extend(new)
        if len(data) < PAGE_SIZE or not new:
            return items
    raise ApiError(path, f"more than {MAX_PAGES} pages; stopped to avoid an endless read")


# --------------------------------------------------------------------------- #
# Cloud SIEM state
# --------------------------------------------------------------------------- #

def read_siem_state(base_url: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """`enabled` is True, False, or None (unknown). Never False without the signal."""
    try:
        payload = api_get(base_url, CONTENT_PACKS_PATH, headers)
    except ApiError as e:
        return unknown_siem_state(str(e), e.status_code)
    return siem_state_from_content_packs(payload)


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


def read_webhook(base_url: str, headers: Dict[str, str], name: str) -> Tuple[Dict[str, Any], Optional[ApiError]]:
    """One referenced webhook. Logs the URL's domain only, never the full URL."""
    path = WEBHOOK_PATH.format(name=quote(name, safe=""))
    try:
        payload = api_get(base_url, path, headers)
    except ApiError as e:
        # 404 is the documented "Item Not Found": a target names a webhook that
        # does not exist, so that notification reaches nobody.
        found = False if e.status_code == 404 else None
        return {"name": name, "found": found, "url_domain": None}, (None if found is False else e)
    raw_url = payload.get("url") or ""
    return {
        "name": payload.get("name") or name,
        "found": True,
        "url_domain": urlparse(raw_url).netloc if raw_url else "",
    }, None


def failure_code(errors: List[ApiError]) -> str:
    codes = {e.status_code for e in errors}
    if codes == {401}:
        return "auth_failed"
    if 403 in codes or 401 in codes:
        return "not_authorized"
    if 429 in codes:
        return "rate_limited"
    if None in codes or any(c is not None and c >= 500 for c in codes):
        return "target_unreachable"
    return "partial_failure"


def get_siem_configuration() -> Dict[str, Any]:
    try:
        base_url = get_base_url()
        headers = get_dd_headers()
    except RuntimeError as e:
        return {"status": "error", "code": "bad_config", "message": str(e), "retrieved_at": current_timestamp()}

    endpoints = [SUPPRESSIONS_PATH, CONTENT_PACKS_PATH, NOTIFICATION_RULES_PATH, DETECTION_RULES_PATH]
    siem_state = read_siem_state(base_url, headers)

    if siem_state["enabled"] is False:
        return {
            "status": "not_available",
            "message": NOT_ACTIVE_MESSAGE,
            "api_endpoint": f"{base_url}{CONTENT_PACKS_PATH}",
            "data": {"siem_state": siem_state},
            "summary": {"siem_enabled": False},
            "retrieved_at": current_timestamp(),
        }

    fatal: List[ApiError] = []
    warnings: List[ApiError] = []

    suppressions: Optional[List[Dict[str, Any]]] = None
    try:
        suppressions = [extract_suppression(i) for i in get_paged(base_url, SUPPRESSIONS_PATH, headers)]
    except ApiError as e:
        fatal.append(e)

    notification_rules: Optional[List[Dict[str, Any]]] = None
    try:
        payload = api_get(base_url, NOTIFICATION_RULES_PATH, headers)
        notification_rules = [extract_notification_rule(i) for i in payload.get("data") or []]
    except ApiError as e:
        fatal.append(e)

    rule_notifications: Optional[List[Dict[str, Any]]] = None
    try:
        rule_notifications = []
        for rule in get_paged(base_url, DETECTION_RULES_PATH, headers):
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
    except ApiError as e:
        rule_notifications = None
        fatal.append(e)

    # Where notifications go comes only from enabled configuration. Unknown
    # (null) when either source could not be read.
    notification_types: Optional[List[str]] = None
    referenced_webhooks: Optional[List[Dict[str, Any]]] = None
    if notification_rules is not None and rule_notifications is not None:
        targets = [t for r in notification_rules if r.get("enabled") for t in r["targets"]]
        targets += [t for r in rule_notifications for t in r["targets"]]
        notification_types, webhook_names = summarize_targets(targets)
        referenced_webhooks = []
        for name in webhook_names:
            record, err = read_webhook(base_url, headers, name)
            referenced_webhooks.append(record)
            if err is not None:
                warnings.append(err)
            endpoints.append(WEBHOOK_PATH.format(name=quote(name, safe="")))

    errors = [e.as_record() for e in fatal + warnings]
    if siem_state.get("error"):
        errors.insert(0, {"endpoint": CONTENT_PACKS_PATH, "status_code": siem_state.get("status_code"),
                          "error": siem_state["error"]})

    result: Dict[str, Any] = {
        "status": "success" if not fatal else "error",
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
            "suppression_rules_count": None if suppressions is None else len(suppressions),
            "enabled_suppression_rules": (
                None if suppressions is None else sum(1 for r in suppressions if r.get("enabled"))
            ),
            "notification_rules_count": None if notification_rules is None else len(notification_rules),
            "enabled_notification_rules": (
                None if notification_rules is None
                else sum(1 for r in notification_rules if r.get("enabled"))
            ),
            "detection_rules_with_notifications": (
                None if rule_notifications is None else len(rule_notifications)
            ),
            "referenced_webhooks_count": None if referenced_webhooks is None else len(referenced_webhooks),
            "missing_webhooks": (
                None if referenced_webhooks is None
                else sorted(w["name"] for w in referenced_webhooks if w["found"] is False)
            ),
            "notification_types": notification_types,
        },
        "errors": errors,
        "retrieved_at": current_timestamp(),
    }
    if fatal:
        result["code"] = failure_code(fatal)
        result["message"] = "; ".join(f"{e.endpoint}: {e}" for e in fatal)
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
        report_failure(reason, result.get("code"))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
