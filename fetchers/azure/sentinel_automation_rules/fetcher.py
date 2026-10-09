#!/usr/bin/env python3
"""Microsoft Sentinel automation rules per workspace: what triggers them, whether they are live, and what they do."""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import SI_API, parse_time, run_workspaces  # noqa: E402

NAME = "azure_sentinel_automation_rules"

logger = logging.getLogger(NAME)


def project_condition(condition: Dict[str, Any]) -> Dict[str, Any]:
    props = condition.get("conditionProperties") or {}
    return {
        "type": condition.get("conditionType"),
        "property": props.get("propertyName") or props.get("arrayType"),
        "operator": props.get("operator") or props.get("changeType"),
        "values": len(props.get("propertyValues") or []),
    }


def project_action(action: Dict[str, Any]) -> Dict[str, Any]:
    config = action.get("actionConfiguration") or {}
    owner = config.get("owner") or {}
    projected = {"order": action.get("order"), "type": action.get("actionType")}
    if action.get("actionType") == "RunPlaybook":
        projected["playbook_id"] = config.get("logicAppResourceId")
    elif action.get("actionType") == "ModifyProperties":
        projected["sets"] = {
            "status": config.get("status"),
            "severity": config.get("severity"),
            "classification": config.get("classification"),
            "owner": owner.get("userPrincipalName") or owner.get("assignedTo") or owner.get("objectId"),
            "labels": len(config.get("labels") or []),
        }
    elif action.get("actionType") == "AddIncidentTask":
        projected["task_title"] = config.get("title")
    return projected


def project_rule(rule: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    props = rule.get("properties") or {}
    logic = props.get("triggeringLogic") or {}
    expires = logic.get("expirationTimeUtc")
    expiry = parse_time(expires)
    expired = expiry is not None and expiry <= now
    return {
        "name": rule.get("name"),
        "display_name": props.get("displayName"),
        "order": props.get("order"),
        "enabled": logic.get("isEnabled"),
        "expiration_time_utc": expires,
        "expired": expired,
        "active": logic.get("isEnabled") is True and not expired,
        "triggers_on": logic.get("triggersOn"),
        "triggers_when": logic.get("triggersWhen"),
        "conditions": [project_condition(c) for c in logic.get("conditions") or []],
        "actions": [project_action(a) for a in sorted(props.get("actions") or [], key=lambda a: a.get("order") or 0)],
        "created_time_utc": props.get("createdTimeUtc"),
        "last_modified_time_utc": props.get("lastModifiedTimeUtc"),
        "created_by": (props.get("createdBy") or {}).get("userPrincipalName"),
        "last_modified_by": (props.get("lastModifiedBy") or {}).get("userPrincipalName"),
    }


def rule_summary(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_action: Dict[str, int] = {}
    for rule in rules:
        if rule["active"]:
            for action in rule["actions"]:
                by_action[action["type"] or "unknown"] = by_action.get(action["type"] or "unknown", 0) + 1
    playbooks = {a["playbook_id"] for r in rules if r["active"] for a in r["actions"] if a.get("playbook_id")}
    return {
        "rules_total": len(rules),
        "active_rules": sum(1 for r in rules if r["active"]),
        "expired_rules": sum(1 for r in rules if r["expired"]),
        "active_actions_by_type": dict(sorted(by_action.items())),
        "playbooks_run": sorted(playbooks),
    }


def collect(client, ws: Dict[str, Any], collector) -> Dict[str, Any]:
    listed = collector.guard(
        f"securityinsights.automationRules.list({ws['name']})",
        lambda: client.list(f"{ws['id']}/providers/Microsoft.SecurityInsights/automationRules", SI_API),
    )
    if listed is None:
        return {"rules": None}
    now = datetime.now(timezone.utc)
    rules = sorted((project_rule(r, now) for r in listed), key=lambda r: (r["order"] or 0, r["display_name"] or ""))
    return {"rules": rules, **rule_summary(rules)}


def summarize(workspaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    collected = [w for w in workspaces if w.get("rules") is not None]
    return {
        "active_rules_total": sum(w.get("active_rules") or 0 for w in collected),
        "workspaces_with_no_active_rules": sum(1 for w in collected if not w.get("active_rules")),
        "playbooks_run": len({p for w in collected for p in w.get("playbooks_run") or []}),
    }


def main() -> int:
    return run_workspaces(fetcher=NAME, logger=logger, collect=collect, summarize=summarize)


if __name__ == "__main__":
    sys.exit(main())
