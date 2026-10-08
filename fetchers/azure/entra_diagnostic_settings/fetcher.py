#!/usr/bin/env python3
"""Entra ID tenant diagnostic settings: which directory log categories are exported, and whether they reach a Sentinel workspace."""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import ArmError, run_tenant, sentinel_onboarded  # noqa: E402

NAME = "azure_entra_diagnostic_settings"
AADIAM_API = "2017-04-01"
# The categories the SIEM needs to see sign-ins and directory changes.
KEY_CATEGORIES = ("AuditLogs", "SignInLogs")

logger = logging.getLogger(NAME)


def project_setting(setting: Dict[str, Any]) -> Dict[str, Any]:
    props = setting.get("properties") or {}
    logs = props.get("logs") or []
    return {
        "name": setting.get("name"),
        "workspace_id": props.get("workspaceId"),
        "storage_account_id": props.get("storageAccountId"),
        "event_hub_authorization_rule_id": props.get("eventHubAuthorizationRuleId"),
        "event_hub_name": props.get("eventHubName"),
        "enabled_categories": sorted(l.get("category") for l in logs if l.get("enabled") is True and l.get("category")),
        "disabled_categories": sorted(l.get("category") for l in logs if l.get("enabled") is not True and l.get("category")),
    }


def workspace_sentinel(client, workspace_id: str, collector) -> Optional[bool]:
    """Sentinel state of a destination workspace; None when it can't be read (possibly another subscription)."""
    try:
        return sentinel_onboarded(client, workspace_id)
    except ArmError as exc:
        if exc.status in (401, 403):
            return None
        collector.record(f"securityinsights.onboardingStates.list({workspace_id})", exc)
        return None


def category_coverage(settings: List[Dict[str, Any]], available: List[str], sentinel: Dict[str, Optional[bool]]) -> List[Dict[str, Any]]:
    out = []
    for category in sorted(set(available) | {c for s in settings for c in s["enabled_categories"]}):
        exporting = [s for s in settings if category in s["enabled_categories"]]
        workspaces = sorted({s["workspace_id"] for s in exporting if s["workspace_id"]})
        out.append({
            "category": category,
            "exported": bool(exporting),
            "to_workspaces": workspaces,
            "to_sentinel_workspace": any(sentinel.get(w) is True for w in workspaces),
            "to_storage": any(s["storage_account_id"] for s in exporting),
            "to_event_hub": any(s["event_hub_authorization_rule_id"] for s in exporting),
        })
    return out


def collect(client, collector) -> tuple:
    raw = collector.guard(
        "aadiam.diagnosticSettings.list", lambda: client.list("/providers/microsoft.aadiam/diagnosticSettings", AADIAM_API)
    )
    categories = collector.guard(
        "aadiam.diagnosticSettingsCategories.list",
        lambda: client.list("/providers/microsoft.aadiam/diagnosticSettingsCategories", AADIAM_API),
    )
    if raw is None:
        return {"settings": None}, {}
    settings = sorted((project_setting(s) for s in raw), key=lambda s: s["name"] or "")
    sentinel = {
        w: workspace_sentinel(client, w, collector)
        for w in sorted({s["workspace_id"] for s in settings if s["workspace_id"]})
    }
    available = sorted(c.get("name") for c in categories or [] if c.get("name"))
    coverage = category_coverage(settings, available, sentinel)
    by_name = {c["category"]: c for c in coverage}
    key = {c: by_name.get(c, {}).get("to_sentinel_workspace", False) for c in KEY_CATEGORIES}
    results = {
        "settings": settings,
        "destination_workspaces": [{"workspace_id": w, "sentinel_onboarded": v} for w, v in sentinel.items()],
        "categories_available": available if categories is not None else None,
        "category_coverage": coverage,
    }
    summary = {
        "settings_total": len(settings),
        "categories_exported": sum(1 for c in coverage if c["exported"]),
        "categories_not_exported": sorted(c["category"] for c in coverage if not c["exported"]),
        "key_categories_to_sentinel": key,
        "audit_and_signin_logs_to_sentinel": all(key.values()),
    }
    return results, summary


def main() -> int:
    return run_tenant(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
