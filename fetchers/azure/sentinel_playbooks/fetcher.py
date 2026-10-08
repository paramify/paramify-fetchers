#!/usr/bin/env python3
"""Microsoft Sentinel playbooks (Logic Apps): what triggers them, what they do to accounts, who they notify, and which automation rules run them."""

import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import (  # noqa: E402
    SI_API,
    basename,
    discover_workspaces,
    parse_time,
    resource_group_from_id,
    run_subscription,
)

NAME = "azure_sentinel_playbooks"
LOGIC_API = "2019-05-01"
# Standard (single-tenant) workflows live under Microsoft.Web/sites/{app}/workflows.
WEB_API = "2024-04-01"
SENTINEL_API = "azuresentinel"
EMAIL_APIS = frozenset({"office365", "outlook", "sendgrid", "smtp", "gmail"})
TEAMS_APIS = frozenset({"teams"})
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CONNECTION_REF = re.compile(r"\['([^']+)'\]\['connectionId'\]")
# Graph/Entra operations that disable, sign out, or flag an account; matched on the action's serialized inputs.
ACCOUNT_CONTAINMENT_MARKERS = ('"accountenabled": false', "revokesigninsessions", "confirmcompromised", "dismissriskyuser")

logger = logging.getLogger(NAME)


def walk_actions(actions: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Every action, including those nested in If/Switch/Foreach/Until/Scope branches."""
    for name, action in (actions or {}).items():
        yield name, action
        yield from walk_actions(action.get("actions") or {})
        yield from walk_actions((action.get("else") or {}).get("actions") or {})
        for case in (action.get("cases") or {}).values():
            yield from walk_actions(case.get("actions") or {})
        yield from walk_actions((action.get("default") or {}).get("actions") or {})


def connection_apis(workflow: Dict[str, Any]) -> Dict[str, str]:
    """$connections key -> managed API name (the last segment of its api id)."""
    value = (((workflow.get("properties") or {}).get("parameters") or {}).get("$connections") or {}).get("value") or {}
    return {key: (basename(conn.get("id")) or key).lower() for key, conn in value.items() if isinstance(conn, dict)}


def api_of(step: Dict[str, Any], apis: Dict[str, str]) -> Optional[str]:
    connection = ((step.get("inputs") or {}).get("host") or {}).get("connection") or {}
    if connection.get("referenceName"):
        # Standard workflows name a connections.json entry, which by default carries the managed API's name.
        return apis.get(connection["referenceName"], connection["referenceName"].lower())
    match = CONNECTION_REF.search(connection.get("name") or "")
    return apis.get(match.group(1), match.group(1).lower()) if match else None


def is_standard(workflow_id: str) -> bool:
    return "/providers/microsoft.web/sites/" in (workflow_id or "").lower()


def from_standard(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """A Standard workflow envelope in the Consumption shape analyse() reads; its definition sits in files['workflow.json']."""
    props = envelope.get("properties") or {}
    files = props.get("files") or {}
    doc = files.get("workflow.json") or next((f for f in files.values() if isinstance(f, dict) and "definition" in f), {})
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            doc = {}
    return {
        "id": envelope.get("id"),
        "name": envelope.get("name"),
        "properties": {"state": props.get("flowState"), "definition": (doc or {}).get("definition")},
    }


def get_workflow(client, workflow_id: str) -> Dict[str, Any]:
    if is_standard(workflow_id):
        return from_standard(client.get(workflow_id, WEB_API))
    return client.get(workflow_id, LOGIC_API)


def trigger_kind(path: str) -> str:
    path = (path or "").lower()
    if "incident" in path:
        return "incident"
    if path.startswith("/entity"):
        return "entity"
    if path.startswith("/subscribe"):
        return "alert"
    return "other"


def recipients(body: Dict[str, Any]) -> Tuple[List[str], int]:
    static, dynamic = set(), 0
    for field in ("To", "Cc", "Bcc", "to", "cc", "bcc", "emailMessage/To"):
        value = body.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        found = EMAIL_RE.findall(value)
        static.update(e.lower() for e in found)
        if "@{" in value or (value.startswith("@") and not found):
            dynamic += 1
    return sorted(static), dynamic


def analyse(workflow: Dict[str, Any]) -> Dict[str, Any]:
    definition = (workflow.get("properties") or {}).get("definition") or {}
    apis = connection_apis(workflow)
    triggers = []
    for name, trigger in (definition.get("triggers") or {}).items():
        api = api_of(trigger, apis)
        triggers.append({
            "name": name,
            "type": trigger.get("type"),
            "api": api,
            "kind": trigger_kind((trigger.get("inputs") or {}).get("path")) if api == SENTINEL_API else "other",
        })
    used, emails, dynamic = set(), set(), 0
    capabilities = {"account_containment": False, "device_isolation": False, "email": False, "teams": False, "incident_update": False}
    for _, action in walk_actions(definition.get("actions") or {}):
        inputs = action.get("inputs") or {}
        api = api_of(action, apis)
        if api:
            used.add(api)
        text = json.dumps(inputs, sort_keys=True).lower()
        path = (inputs.get("path") or "").lower()
        if any(marker in text for marker in ACCOUNT_CONTAINMENT_MARKERS):
            capabilities["account_containment"] = True
        if "isolate" in path or ("machines" in text and "isolate" in text):
            capabilities["device_isolation"] = True
        if api in EMAIL_APIS and "mail" in path:
            capabilities["email"] = True
            found, dyn = recipients(inputs.get("body") or {})
            emails.update(found)
            dynamic += dyn
        if api in TEAMS_APIS:
            capabilities["teams"] = True
        if api == SENTINEL_API and path.startswith("/incidents"):
            capabilities["incident_update"] = True
    return {
        "triggers": triggers,
        "sentinel_triggered": any(t["api"] == SENTINEL_API for t in triggers),
        "connectors_used": sorted(used),
        "capabilities": capabilities,
        "email_recipients": sorted(emails),
        "dynamic_recipient_fields": dynamic,
    }


def automation_references(client, subscription_id: str, collector, ids: Dict[str, str]) -> Dict[str, List[Dict[str, Any]]]:
    """Playbook id (lowercased) -> the automation rules that run it, from every Sentinel workspace; `ids` keeps the id as written."""
    now = datetime.now(timezone.utc)
    refs: Dict[str, List[Dict[str, Any]]] = {}
    for ws in discover_workspaces(client, subscription_id, collector):
        if not ws["sentinel_onboarded"]:
            continue
        rules = collector.guard(
            f"securityinsights.automationRules.list({ws['name']})",
            lambda ws=ws: client.list(f"{ws['id']}/providers/Microsoft.SecurityInsights/automationRules", SI_API),
        ) or []
        for rule in rules:
            props = rule.get("properties") or {}
            logic = props.get("triggeringLogic") or {}
            expiry = parse_time(logic.get("expirationTimeUtc"))
            active = logic.get("isEnabled") is True and (expiry is None or expiry > now)
            for action in props.get("actions") or []:
                playbook = (action.get("actionConfiguration") or {}).get("logicAppResourceId")
                if action.get("actionType") == "RunPlaybook" and playbook:
                    ids.setdefault(playbook.lower(), playbook)
                    refs.setdefault(playbook.lower(), []).append(
                        {"workspace": ws["name"], "rule": props.get("displayName"), "active": active}
                    )
    return refs


def collect(client, subscription_id: str, collector) -> tuple:
    ids: Dict[str, str] = {}
    refs = automation_references(client, subscription_id, collector, ids)
    listed = collector.guard(
        "logic.workflows.list",
        lambda: client.list(f"/subscriptions/{subscription_id}/providers/Microsoft.Logic/workflows", LOGIC_API),
    )
    if listed is None:
        return {"playbooks": None}, {}
    by_id = {(w.get("id") or "").lower(): w for w in listed}
    for playbook_id in sorted(set(refs) - set(by_id)):
        # A rule may run a playbook from another subscription or resource group the list didn't return.
        found = collector.guard(f"workflows.get({basename(playbook_id)})", lambda p=ids[playbook_id]: get_workflow(client, p))
        if found:
            by_id[playbook_id] = found

    playbooks = []
    for key, workflow in sorted(by_id.items()):
        if not (workflow.get("properties") or {}).get("definition") and not is_standard(key):
            workflow = collector.guard(
                f"logic.workflows.get({workflow.get('name')})", lambda w=workflow: client.get(w["id"], LOGIC_API)
            ) or workflow
        analysis = analyse(workflow)
        wired = refs.get(key, [])
        if not analysis["sentinel_triggered"] and not wired:
            continue
        enabled = (workflow.get("properties") or {}).get("state") == "Enabled"
        playbooks.append({
            "name": workflow.get("name"),
            "id": workflow.get("id"),
            "resource_group": resource_group_from_id(workflow.get("id")),
            "enabled": enabled,
            "plan": "standard" if is_standard(key) else "consumption",
            "definition_read": bool((workflow.get("properties") or {}).get("definition")),
            **analysis,
            "automation_rules": wired,
            "run_by_active_automation_rule": enabled and any(r["active"] for r in wired),
        })

    live = [p for p in playbooks if p["run_by_active_automation_rule"]]
    summary = {
        "logic_apps_scanned": len(listed),
        "playbooks": len(playbooks),
        "enabled_playbooks": sum(1 for p in playbooks if p["enabled"]),
        "run_by_active_automation_rule": len(live),
        "live_account_containment_playbooks": sum(1 for p in live if p["capabilities"]["account_containment"]),
        "live_notifying_playbooks": sum(1 for p in live if p["capabilities"]["email"] or p["capabilities"]["teams"]),
        "notification_recipients": sorted({e for p in live for e in p["email_recipients"]}),
        "standard_playbooks": sum(1 for p in playbooks if p["plan"] == "standard"),
        "playbooks_without_definition": sorted(p["id"] for p in playbooks if not p["definition_read"]),
        "automation_rule_references_unresolved": sorted(set(refs) - set(by_id)),
    }
    return {"playbooks": playbooks}, summary


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
