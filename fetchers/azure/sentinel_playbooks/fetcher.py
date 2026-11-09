#!/usr/bin/env python3
"""Microsoft Sentinel playbooks (Logic Apps): what triggers them, what they do to accounts, who they notify, which automation rules run them, and how their recent runs ended."""

import json
import logging
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import (  # noqa: E402
    SI_API,
    ArmError,
    basename,
    discover_workspaces,
    int_config,
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
UNREADABLE_STATUSES = frozenset({401, 403, 404})
LOOKBACK_ENV = "SENTINEL_PLAYBOOK_RUN_LOOKBACK_DAYS"
DEFAULT_LOOKBACK_DAYS = 90
# Logic Apps keep 90 days of run history unless a workflow's retention is changed.
MAX_LOOKBACK_DAYS = 90
RECENT_RUNS = 10
FAILED_STATUSES = frozenset({"Failed", "TimedOut", "Aborted", "Faulted"})
NO_RUN_HISTORY = dict.fromkeys(
    ("runs_in_lookback", "runs_by_status", "failed_runs", "last_run_status", "last_run_time",
     "last_success_time", "last_failure_time", "recent_runs"),
    None,
)

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


def as_dict(value: Any) -> Dict[str, Any]:
    # Inputs and bodies can be a string, array or expression (a Compose action's "inputs": "text").
    return value if isinstance(value, dict) else {}


def api_of(step: Dict[str, Any], apis: Dict[str, str]) -> Optional[str]:
    connection = as_dict(as_dict(as_dict(step.get("inputs")).get("host")).get("connection"))
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


def runs_path(workflow_id: str) -> Tuple[str, str]:
    """The runs list and its api-version; a Standard workflow's runs come through its app's workflow host runtime."""
    if not is_standard(workflow_id):
        return f"{workflow_id}/runs", LOGIC_API
    cut = workflow_id.lower().rindex("/workflows/")
    site, name = workflow_id[:cut], workflow_id[cut + len("/workflows/"):]
    return f"{site}/hostruntime/runtime/webhooks/workflow/api/management/workflows/{name}/runs", WEB_API


def run_record(run: Dict[str, Any]) -> Dict[str, Any]:
    props = run.get("properties") or {}
    status = props.get("status")
    error_code = as_dict(props.get("error")).get("code") or (props.get("code") if status in FAILED_STATUSES else None)
    return {
        "name": run.get("name"),
        "status": status,
        "start_time": props.get("startTime"),
        "end_time": props.get("endTime"),
        "trigger": as_dict(props.get("trigger")).get("name"),
        "error_code": error_code,
    }


def run_history(client, workflow_id: str, since: datetime) -> Dict[str, Any]:
    path, api = runs_path(workflow_id)
    listed = client.list(path, api, {"$filter": f"StartTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}"})
    latest = datetime.max.replace(tzinfo=timezone.utc)
    timed = [(parse_time((r.get("properties") or {}).get("startTime")) or latest, run_record(r)) for r in listed]
    # Filtered again here in case the service ignores the filter; a run not started yet counts as the newest.
    runs = [run for at, run in sorted(timed, key=lambda t: t[0], reverse=True) if at >= since]
    counts = Counter(run["status"] or "Unknown" for run in runs)
    return {
        "runs_in_lookback": len(runs),
        "runs_by_status": dict(sorted(counts.items())),
        "failed_runs": sum(counts[status] for status in FAILED_STATUSES),
        "last_run_status": runs[0]["status"] if runs else None,
        "last_run_time": runs[0]["start_time"] if runs else None,
        "last_success_time": next((r["start_time"] for r in runs if r["status"] == "Succeeded"), None),
        "last_failure_time": next((r["start_time"] for r in runs if r["status"] in FAILED_STATUSES), None),
        "recent_runs": runs[:RECENT_RUNS],
    }


def read_run_history(client, workflow_id: str, since: datetime, collector, notes: List[str]) -> Tuple[bool, Dict[str, Any]]:
    try:
        return True, run_history(client, workflow_id, since)
    except Exception as exc:  # noqa: BLE001
        if unreadable(exc):
            notes.append(f"run history of playbook {workflow_id} could not be read, so its run fields are null: {exc}")
        else:
            collector.record(f"workflows.runs.list({basename(workflow_id)})", exc)
        return False, dict(NO_RUN_HISTORY)


def trigger_kind(path: Optional[str]) -> str:
    path = (path or "").lower()
    if "incident" in path:
        return "incident"
    if path.startswith("/entity"):
        return "entity"
    if path.startswith("/subscribe"):
        return "alert"
    return "other"


def recipients(body: Dict[str, Any]) -> Tuple[List[str], int]:
    static: Set[str] = set()
    dynamic = 0
    for field in ("To", "Cc", "Bcc", "to", "cc", "bcc", "emailMessage/To"):
        value = body.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        found = EMAIL_RE.findall(value)
        static.update(e.lower() for e in found)
        if "@{" in value or (value.startswith("@") and not found):
            dynamic += 1
    return sorted(static), dynamic


def unreadable(exc: BaseException) -> bool:
    """A playbook in a subscription or resource group the credential can't read, or one since deleted."""
    return isinstance(exc, ArmError) and (exc.status in UNREADABLE_STATUSES or exc.code.lower() == "subscriptionnotfound")


def analyse(workflow: Dict[str, Any]) -> Dict[str, Any]:
    definition = (workflow.get("properties") or {}).get("definition") or {}
    if not definition:
        # Everything below comes from the definition, so an unread one is unknown, not "does nothing".
        return dict.fromkeys(
            ("triggers", "sentinel_triggered", "connectors_used", "capabilities", "email_recipients", "dynamic_recipient_fields")
        )
    apis = connection_apis(workflow)
    triggers = []
    for name, trigger in (definition.get("triggers") or {}).items():
        api = api_of(trigger, apis)
        triggers.append({
            "name": name,
            "type": trigger.get("type"),
            "api": api,
            "kind": trigger_kind(as_dict(trigger.get("inputs")).get("path")) if api == SENTINEL_API else "other",
        })
    used, emails, dynamic = set(), set(), 0
    capabilities = {"account_containment": False, "device_isolation": False, "email": False, "teams": False, "incident_update": False}
    for _, action in walk_actions(definition.get("actions") or {}):
        inputs = as_dict(action.get("inputs"))
        api = api_of(action, apis)
        if api:
            used.add(api)
        text = json.dumps(action.get("inputs"), sort_keys=True).lower()
        path = (inputs.get("path") or "").lower()
        if any(marker in text for marker in ACCOUNT_CONTAINMENT_MARKERS):
            capabilities["account_containment"] = True
        if "isolate" in path or ("machines" in text and "isolate" in text):
            capabilities["device_isolation"] = True
        if api in EMAIL_APIS and "mail" in path:
            capabilities["email"] = True
            found, dyn = recipients(as_dict(inputs.get("body")))
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


def lookback_days() -> int:
    days = int_config(LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS)
    if days > MAX_LOOKBACK_DAYS:
        logger.warning("%s=%d is outside 1-%d; using %d", LOOKBACK_ENV, days, MAX_LOOKBACK_DAYS, MAX_LOOKBACK_DAYS)
    return min(days, MAX_LOOKBACK_DAYS)


def collect(client, subscription_id: str, collector) -> tuple:
    days = lookback_days()
    since = datetime.now(timezone.utc) - timedelta(days=days)
    ids: Dict[str, str] = {}
    refs = automation_references(client, subscription_id, collector, ids)
    listed = collector.guard(
        "logic.workflows.list",
        lambda: client.list(f"/subscriptions/{subscription_id}/providers/Microsoft.Logic/workflows", LOGIC_API),
    )
    if listed is None:
        return {"playbooks": None}, {}
    by_id = {(w.get("id") or "").lower(): w for w in listed}
    notes: List[str] = []
    for playbook_id in sorted(set(refs) - set(by_id)):
        # A rule may run a playbook from another subscription or resource group the list didn't return.
        try:
            found = get_workflow(client, ids[playbook_id])
        except Exception as exc:  # noqa: BLE001
            if unreadable(exc):
                notes.append(f"playbook {ids[playbook_id]} that an automation rule runs could not be read, so it is unresolved: {exc}")
            else:
                collector.record(f"workflows.get({basename(playbook_id)})", exc)
            continue
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
        runs_read, runs = read_run_history(client, workflow.get("id") or ids.get(key, key), since, collector, notes)
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
            "run_history_read": runs_read,
            **runs,
        })

    live = [p for p in playbooks if p["run_by_active_automation_rule"]]
    # A live playbook with no definition might contain or notify, so the counts it could change read unknown.
    unread_live = sum(1 for p in live if not p["definition_read"])
    # Likewise a live playbook whose runs weren't read leaves every run count unknown.
    unread_runs = sum(1 for p in live if not p["run_history_read"])
    summary = {
        "logic_apps_scanned": len(listed),
        "playbooks": len(playbooks),
        "enabled_playbooks": sum(1 for p in playbooks if p["enabled"]),
        "run_by_active_automation_rule": len(live),
        "live_playbooks_without_definition": unread_live,
        "live_account_containment_playbooks": None if unread_live else sum(
            1 for p in live if p["capabilities"]["account_containment"]
        ),
        "live_notifying_playbooks": None if unread_live else sum(
            1 for p in live if p["capabilities"]["email"] or p["capabilities"]["teams"]
        ),
        "notification_recipients": None if unread_live else sorted({e for p in live for e in p["email_recipients"]}),
        "standard_playbooks": sum(1 for p in playbooks if p["plan"] == "standard"),
        "playbooks_without_definition": sorted(p["id"] for p in playbooks if not p["definition_read"]),
        "automation_rule_references_unresolved": sorted(set(refs) - set(by_id)),
        "run_lookback_days": days,
        "playbooks_run_history_unread": sorted(p["id"] for p in playbooks if not p["run_history_read"]),
        "live_playbooks_run_history_unread": unread_runs,
        "live_playbooks_last_run_succeeded": None if unread_runs else sum(
            1 for p in live if p["last_run_status"] == "Succeeded"
        ),
        "live_playbooks_last_run_failed": None if unread_runs else sum(
            1 for p in live if p["last_run_status"] in FAILED_STATUSES
        ),
        "live_playbooks_without_runs": None if unread_runs else sum(1 for p in live if p["runs_in_lookback"] == 0),
        "live_playbook_failed_runs": None if unread_runs else sum(p["failed_runs"] for p in live),
    }
    return {"playbooks": playbooks, "notes": notes}, summary


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
