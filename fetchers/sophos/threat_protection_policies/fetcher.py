#!/usr/bin/env python3
"""Sophos Central threat protection policies: what each sets for scheduled and on-access scanning."""

import re
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "_shared"))
from sophos_client import SophosError  # noqa: E402
from sophos_evidence import ABSENT, count_by, run, tally  # noqa: E402

OUTPUT_FILE = "sophos_threat_protection_policies.json"
POLICY_TYPES = ("threat-protection", "server-threat-protection")
SCHEDULED_DAYS = "endpoint.scans.scheduled.days"
SCHEDULED_HOUR = "endpoint.scans.scheduled.hour"
SCHEDULED_ENABLED = "endpoint.scans.scheduled.enabled"
ON_ACCESS_TEXT = re.compile(r"on[- ]access|real[- ]time", re.I)


def on_access_key(metadata: dict) -> Optional[str]:
    """The boolean setting Sophos's own metadata describes as on-access scanning, if any."""
    candidates = []
    for group in metadata.get("items") or []:
        for setting in group.get("items") or []:
            name = setting.get("name") or ""
            text = f"{name} {setting.get('description') or ''}"
            if setting.get("type") == "boolean" and ON_ACCESS_TEXT.search(text):
                candidates.append(name)
    candidates.sort(key=lambda n: (not ON_ACCESS_TEXT.search(n), not n.endswith(".enabled"), n))
    return candidates[0] if candidates else None


def setting_value(settings: dict, key: Optional[str]):
    entry = settings.get(key) if key else None
    return entry.get("value") if isinstance(entry, dict) else None


def item(policy: dict, policy_type: str, is_base: bool, access_key: Optional[str]) -> dict:
    unread: dict = {}
    settings = policy.get("settings") if isinstance(policy.get("settings"), dict) else None
    if settings is None:
        unread["settings"] = ABSENT
        settings = {}

    days = setting_value(settings, SCHEDULED_DAYS)
    if setting_value(settings, SCHEDULED_ENABLED) is False:
        scheduled = False
    elif isinstance(days, list):
        scheduled = bool(days)
    else:
        scheduled = None
        unread["scheduled_scan_configured"] = ABSENT

    on_access = setting_value(settings, access_key)
    if not isinstance(on_access, bool):
        on_access = None
        unread["on_access_scanning_on"] = ABSENT if access_key else "no on-access setting in Sophos metadata"

    off_baseline = sorted(
        key for key, entry in settings.items()
        if isinstance(entry, dict) and "recommendedValue" in entry and entry.get("value") != entry["recommendedValue"]
    )
    enabled = policy.get("enabled")
    if not isinstance(enabled, bool):
        enabled = None
        unread["enabled"] = ABSENT

    result = {
        "policy_id": policy.get("id"),
        "name": policy.get("name"),
        "policy_type": policy_type,
        "is_base_policy": is_base,
        "priority": policy.get("priority"),
        "enabled": enabled,
        "applies_to": policy.get("appliesTo"),
        "scheduled_scan_configured": scheduled,
        "scheduled_scan_days": days if isinstance(days, list) else None,
        "scheduled_scan_hour": setting_value(settings, SCHEDULED_HOUR),
        "on_access_scanning_on": on_access,
        "on_access_setting_key": access_key,
        "settings_off_vendor_baseline": len(off_baseline),
        "settings_off_vendor_baseline_keys": off_baseline,
        "settings": settings,
    }
    if unread:
        result["unread_facts"] = unread
    return result


def collect(client, ledger, now):
    items: list = []
    reported_total: Optional[int] = 0
    for policy_type in POLICY_TYPES:
        policies, total = client.list_policies(policy_type)
        reported_total = None if total is None or reported_total is None else reported_total + total
        try:
            access_key = on_access_key(client.get("/endpoint/v1/policies/settings", f"settings_metadata:{policy_type}",
                                                  {"policyType": policy_type}))
        except SophosError as e:
            ledger.add(e)
            access_key = None
        try:
            base = client.get(f"/endpoint/v1/policies/{policy_type}/base", f"base_policy:{policy_type}")
        except SophosError as e:
            ledger.add(e)
            base = None
        base_id = (base or {}).get("id")
        if base and base_id not in {p.get("id") for p in policies}:
            policies.append(base)
            if reported_total is not None:
                reported_total += 1
        for policy in policies:
            if not isinstance(policy.get("settings"), dict) and policy.get("id"):
                try:
                    policy = {**policy, "settings": client.get(
                        f"/endpoint/v1/policies/{policy['id']}", f"policy_detail:{policy_type}").get("settings")}
                except SophosError as e:
                    ledger.add(e)
            items.append(item(policy, policy_type, policy.get("id") == base_id, access_key))

    enabled, disabled, enabled_unread = tally(items, "enabled")
    sched, no_sched, sched_unread = tally(items, "scheduled_scan_configured")
    oa_on, oa_off, oa_unread = tally(items, "on_access_scanning_on")
    summary = {
        "total_policies": len(items),
        "policies_by_type": count_by(items, "policy_type"),
        "base_policies": sum(1 for i in items if i["is_base_policy"]),
        "policies_enabled": enabled,
        "policies_disabled": disabled,
        "policies_enabled_unread": enabled_unread,
        "policies_scheduled_scan_configured": sched,
        "policies_no_scheduled_scan": no_sched,
        "policies_scheduled_scan_unread": sched_unread,
        "policies_on_access_scanning_on": oa_on,
        "policies_on_access_scanning_off": oa_off,
        "policies_on_access_scanning_unread": oa_unread,
        "policies_with_settings_off_vendor_baseline": sum(1 for i in items if i["settings_off_vendor_baseline"]),
    }
    return items, summary, {"collected": len(items), "reported_total": reported_total}


if __name__ == "__main__":
    raise SystemExit(run("sophos_threat_protection_policies", OUTPUT_FILE, collect))
