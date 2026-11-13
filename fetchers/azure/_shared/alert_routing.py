"""Who an Azure Monitor alert reaches: action groups, their receivers, and alert processing rules that suppress or add them."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, Optional
from urllib.parse import urlsplit

ACTION_GROUP_API = "2023-01-01"
PROCESSING_RULE_API = "2021-08-08"

# 2023-01-01's eleven arrays; any other non-empty "*Receivers" key is reported, not dropped.
RECEIVER_ARRAYS = {
    "emailReceivers": "email",
    "smsReceivers": "sms",
    "voiceReceivers": "voice",
    "webhookReceivers": "webhook",
    "itsmReceivers": "itsm",
    "azureAppPushReceivers": "azure_app_push",
    "automationRunbookReceivers": "automation_runbook",
    "logicAppReceivers": "logic_app",
    "azureFunctionReceivers": "azure_function",
    "armRoleReceivers": "arm_role",
    "eventHubReceivers": "event_hub",
}

# Receivers that notify a person (an ARM role emails its members; ITSM opens a ticket in a worked queue).
# Webhooks, Logic Apps, Functions, runbooks and Event Hubs hand off to code that may or may not.
PERSON_RECEIVERS = frozenset({"email", "sms", "voice", "azure_app_push", "arm_role", "itsm"})

ACTION_GROUP_ID = re.compile(
    r"^/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.insights/actiongroups/[^/?#]+$", re.IGNORECASE
)

SCOPE_FULL = "full"
SCOPE_PARTIAL = "partial"

SUPPRESS_ALL = "RemoveAllActionGroups"
ADD_GROUPS = "AddActionGroups"

# Windows time-zone names are not resolved; the window is judged with the widest UTC offset.
TZ_SLACK = timedelta(hours=14)


def _phone(receiver: dict) -> Optional[str]:
    number = str(receiver.get("phoneNumber") or "")
    return f"+{receiver.get('countryCode') or '?'} ***{number[-4:]}" if number else None


def receiver_target(kind: str, receiver: dict) -> Optional[str]:
    """Who or what is notified, without the secrets some receivers carry in their URLs."""
    if kind in ("email", "azure_app_push"):
        return receiver.get("emailAddress")
    if kind in ("sms", "voice"):
        return _phone(receiver)
    if kind == "webhook":
        return urlsplit(receiver.get("serviceUri") or "").hostname
    if kind == "logic_app":
        return receiver.get("resourceId")
    if kind == "azure_function":
        name = receiver.get("functionName")
        return f"{receiver.get('functionAppResourceId')}/{name}" if name else receiver.get("functionAppResourceId")
    if kind == "automation_runbook":
        return f"{receiver.get('automationAccountId')}/{receiver.get('runbookName')}"
    if kind == "arm_role":
        return receiver.get("roleId")
    if kind == "itsm":
        return receiver.get("workspaceId")
    if kind == "event_hub":
        return f"{receiver.get('eventHubNameSpace')}/{receiver.get('eventHubName')}"
    return None


def action_group_record(raw: dict) -> dict:
    props = raw.get("properties") or {}
    receivers = []
    for key, kind in RECEIVER_ARRAYS.items():
        for receiver in props.get(key) or []:
            status = receiver.get("status")
            receivers.append({
                "type": kind,
                "name": receiver.get("name"),
                "target": receiver_target(kind, receiver),
                "status": status,
                # Only email and SMS carry a status; anything but Enabled (Disabled, NotSpecified) sends nothing.
                "enabled": status == "Enabled" if status is not None else True,
            })
    unknown = sorted(k for k, v in props.items() if k.endswith("Receivers") and k not in RECEIVER_ARRAYS and v)
    enabled = props.get("enabled", True) is not False
    live = [r for r in receivers if r["enabled"]]
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "short_name": props.get("groupShortName"),
        "enabled": enabled,
        "receivers": sorted(receivers, key=lambda r: (r["type"], r["name"] or "")),
        "enabled_receiver_count": len(live),
        "unrecognized_receiver_arrays": unknown,
        "deliverable": enabled and bool(live),
        "notifies_people": enabled and any(r["type"] in PERSON_RECEIVERS for r in live),
    }


def _parse(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def schedule_active(schedule: Optional[dict], now: datetime) -> Optional[bool]:
    """True/False when the window decides it; None when a recurrence or a non-UTC zone leaves it open."""
    if not schedule:
        return True
    zone = str(schedule.get("timeZone") or "UTC").strip().lower()
    slack = timedelta(0) if zone in ("utc", "coordinated universal time") else TZ_SLACK
    start, end = _parse(schedule.get("effectiveFrom")), _parse(schedule.get("effectiveUntil"))
    if end and end + slack < now:
        return False
    if start and start - slack > now:
        return False
    if schedule.get("recurrences"):
        return None
    inside = (not start or start + slack <= now) and (not end or now <= end - slack)
    return True if inside else None


def processing_rule_record(raw: dict, now: datetime) -> dict:
    props = raw.get("properties") or {}
    actions = props.get("actions") or []
    action_types = sorted({a.get("actionType") for a in actions if a.get("actionType")})
    enabled = props.get("enabled", True) is not False
    active = schedule_active(props.get("schedule"), now) if enabled else False
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "enabled": enabled,
        "scopes": props.get("scopes") or [],
        "conditions": props.get("conditions") or [],
        "schedule": props.get("schedule"),
        "action_types": action_types,
        "added_action_group_ids": sorted(
            {g for a in actions if a.get("actionType") == ADD_GROUPS for g in a.get("actionGroupIds") or []}
        ),
        "active_now": active,
        "suppresses_notifications": enabled and SUPPRESS_ALL in action_types,
        "description": props.get("description"),
    }


def _norm(arm_id: Optional[str]) -> str:
    return (arm_id or "").rstrip("/").lower()


def _contains(outer: str, inner: str) -> bool:
    return inner == outer or inner.startswith(outer + "/")


def scope_match(rule_scopes: Iterable[str], alert_scopes: Iterable[str]) -> Optional[str]:
    """SCOPE_FULL when the processing rule covers every alert scope, SCOPE_PARTIAL when only some of what the alert fires on."""
    rule = [_norm(s) for s in rule_scopes if s]
    alert = [_norm(s) for s in alert_scopes if s]
    if not rule or not alert:
        return None
    if all(any(_contains(r, a) for r in rule) for a in alert):
        return SCOPE_FULL
    if any(_contains(r, a) or _contains(a, r) for r in rule for a in alert):
        return SCOPE_PARTIAL
    return None


def matching_processing_rules(alert_scopes: list[str], rules: list[dict]) -> list[dict]:
    """Enabled, possibly active rules overlapping the alert; applies_to_every_fire when they act on all its notifications."""
    matches = []
    for rule in rules:
        if not rule["enabled"] or rule["active_now"] is False:
            continue
        match = scope_match(rule["scopes"], alert_scopes)
        if match:
            every_fire = match == SCOPE_FULL and rule["active_now"] is True and not rule["conditions"]
            matches.append({"rule": rule, "scope_match": match, "applies_to_every_fire": every_fire})
    return matches


def _tri(groups: list[dict], has: Callable[[dict], bool]) -> Optional[bool]:
    """True if a group on every notification has it; None if only an unresolved or sometimes-added group might."""
    if any(g["found"] and g["applies_to_every_fire"] and has(g) for g in groups):
        return True
    if any(not g["found"] or (not g["applies_to_every_fire"] and has(g)) for g in groups):
        return None
    return False


def route(enabled: bool, group_ids: list[str], alert_scopes: list[str], groups: dict, rules: list[dict]) -> dict:
    """Resolve an alert rule's notification path; `groups` is keyed by lower-cased action group id."""
    matches = matching_processing_rules(alert_scopes, rules)
    own = {}
    for gid in group_ids:
        if gid:
            own.setdefault(gid.lower(), gid)
    added: dict = {}
    for m in matches:
        for gid in m["rule"]["added_action_group_ids"]:
            key = gid.lower()
            if key not in own:
                prev = added.get(key)
                added[key] = (prev[0] if prev else gid, m["applies_to_every_fire"] or bool(prev and prev[1]))
    resolved = []
    for key in sorted(set(own) | set(added)):
        group = groups.get(key)
        resolved.append({
            "id": own.get(key) or added[key][0],
            "found": group is not None,
            "added_by_processing_rule": key not in own,
            "applies_to_every_fire": key in own or added[key][1],
            "enabled": group["enabled"] if group else None,
            "deliverable": group["deliverable"] if group else None,
            "notifies_people": group["notifies_people"] if group else None,
            "receivers": [r for r in group["receivers"] if r["enabled"]] if group else [],
        })
    routes = _tri(resolved, lambda g: g["deliverable"]) if enabled else False
    to_person = _tri(resolved, lambda g: g["notifies_people"]) if enabled else False
    suppressors = [m for m in matches if m["rule"]["suppresses_notifications"]]
    if any(m["applies_to_every_fire"] for m in suppressors):
        suppressed = True
    elif suppressors:
        suppressed = None
    else:
        suppressed = False
    if not enabled or routes is False or suppressed is True:
        reaches = False
    elif to_person is True and suppressed is False:
        reaches = True
    else:
        reaches = None
    return {
        "resolved_action_groups": resolved,
        "unresolved_action_group_ids": [g["id"] for g in resolved if not g["found"]],
        "routes_to_enabled_receiver": routes,
        "routes_to_person": to_person,
        "processing_rule_matches": [
            {"id": m["rule"]["id"], "scope_match": m["scope_match"], "applies_to_every_fire": m["applies_to_every_fire"]}
            for m in matches
        ],
        "suppressed_by_processing_rules": [m["rule"]["id"] for m in suppressors],
        "suppressed": suppressed,
        "reaches_human": reaches,
    }


def tri_state(values: Iterable[Optional[bool]]) -> Optional[bool]:
    """All True → True; any False → False; otherwise None (some unknown)."""
    values = list(values)
    if any(v is False for v in values):
        return False
    return True if all(v is True for v in values) else None


def collect_action_groups(rest, subscription_id: str) -> dict:
    from arm_rest import list_all

    listed = list_all(rest, f"/subscriptions/{subscription_id}/providers/Microsoft.Insights/actionGroups", ACTION_GROUP_API)
    return {"groups": [action_group_record(g) for g in listed["items"]], "pages": listed["pages"]}


def fetch_action_group(rest, group_id: str) -> dict:
    """One action group by id, for a reference into another subscription."""
    from arm_rest import get_json

    return action_group_record(get_json(rest, f"{group_id}?api-version={ACTION_GROUP_API}"))


def add_referenced_groups(rest, group_ids: Iterable[str], groups: dict, collector) -> None:
    """Fetch groups referenced from another subscription; 403/404 leave them unresolved, anything else is a failure."""
    for gid in sorted({g for g in group_ids if g}, key=str.lower):
        # Anything but an ARM action group path stays unresolved rather than carrying the token elsewhere.
        if gid.lower() in groups or not ACTION_GROUP_ID.match(gid):
            continue
        try:
            groups[gid.lower()] = fetch_action_group(rest, gid)
        except Exception as exc:  # noqa: BLE001 — out-of-scope groups are expected, not failures
            if getattr(exc, "status_code", None) not in (403, 404):
                collector.record(f"actionGroups GET ({gid})", exc)


def collect_processing_rules(rest, subscription_id: str, now: datetime) -> dict:
    from arm_rest import list_all

    listed = list_all(
        rest, f"/subscriptions/{subscription_id}/providers/Microsoft.AlertsManagement/actionRules", PROCESSING_RULE_API
    )
    return {"rules": [processing_rule_record(r, now) for r in listed["items"]], "pages": listed["pages"]}
