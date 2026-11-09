#!/usr/bin/env python3
"""Sophos Central threat protection policies: what each sets for scheduled and on-access scanning."""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "_shared"))
from sophos_client import SophosError  # noqa: E402
from sophos_evidence import ABSENT, count_by, run, tally  # noqa: E402

OUTPUT_FILE = "sophos_threat_protection_policies.json"
POLICY_TYPES = ("threat-protection", "server-threat-protection")
# Setting names from https://developer.sophos.com/endpoint-policy-settings-all/, the same for both policy types.
MALWARE = "endpoint.threat-protection.malware-protection."
SCHEDULED_ENABLED = MALWARE + "scheduled-scan.enabled"  # boolean, default false
SCHEDULED_DAYS = MALWARE + "scheduled-scan.days"  # integers, Sunday = 0 to Saturday = 6, default [6]
SCHEDULED_TIME = MALWARE + "scheduled-scan.time"  # "HH:MM"
ON_ACCESS_ENABLED = MALWARE + "on-access.enabled"  # "Enable real-time scanning"


def setting_value(settings: dict, key: str):
    entry = settings.get(key)
    return entry.get("value") if isinstance(entry, dict) else None


def item(policy: dict, policy_type: str, is_base: bool) -> dict:
    unread: dict = {}
    settings = policy.get("settings") if isinstance(policy.get("settings"), dict) else None
    if settings is None:
        unread["settings"] = ABSENT
        settings = {}

    # Sophos's defaults are enabled: false with days: [6], so only an enabled schedule with days counts.
    sched_enabled = setting_value(settings, SCHEDULED_ENABLED)
    days = setting_value(settings, SCHEDULED_DAYS)
    scheduled: Optional[bool]
    if sched_enabled is False:
        scheduled = False
    elif sched_enabled is True and isinstance(days, list):
        scheduled = bool(days)
    else:
        scheduled = None
        unread["scheduled_scan_configured"] = ABSENT

    on_access = setting_value(settings, ON_ACCESS_ENABLED)
    if not isinstance(on_access, bool):
        on_access = None
        unread["on_access_scanning_on"] = ABSENT

    # recommendedValue is in Sophos's example responses, not its settings reference. With none to compare,
    # the count is null, not 0.
    with_recommendation = [key for key, entry in settings.items()
                           if isinstance(entry, dict) and "recommendedValue" in entry]
    off_baseline = sorted(key for key in with_recommendation
                          if settings[key].get("value") != settings[key]["recommendedValue"])
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
        "scheduled_scan_enabled": sched_enabled if isinstance(sched_enabled, bool) else None,
        "scheduled_scan_days": days if isinstance(days, list) else None,
        "scheduled_scan_time": setting_value(settings, SCHEDULED_TIME),
        "on_access_scanning_on": on_access,
        "settings_with_recommended_value": len(with_recommendation),
        "settings_off_vendor_baseline": len(off_baseline) if with_recommendation else None,
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
            items.append(item(policy, policy_type, base_id is not None and policy.get("id") == base_id))

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
        "policies_without_recommended_values": sum(1 for i in items if i["settings_off_vendor_baseline"] is None),
    }
    return items, summary, {"collected": len(items), "reported_total": reported_total}


if __name__ == "__main__":
    raise SystemExit(run("sophos_threat_protection_policies", OUTPUT_FILE, collect))
