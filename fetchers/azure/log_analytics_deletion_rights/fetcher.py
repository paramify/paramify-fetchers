#!/usr/bin/env python3
"""Who can delete log data from each Log Analytics workspace, through the Purge or the Delete Data API."""

import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import ArmError, run_workspaces  # noqa: E402

NAME = "azure_log_analytics_deletion_rights"
AUTH_API = "2022-04-01"
# Both are granted by Data Purger / Log Analytics Contributor (learn.microsoft.com personal-data-mgmt, delete-log-data).
DELETION_ACTIONS = {
    "purge": "Microsoft.OperationalInsights/workspaces/purge/action",
    "delete_data": "Microsoft.OperationalInsights/workspaces/tables/deleteData/action",
}
GETBYIDS_BATCH = 1000

logger = logging.getLogger(NAME)


def _pattern(action: str) -> "re.Pattern[str]":
    return re.compile("^" + ".*".join(re.escape(p) for p in action.split("*")) + "$", re.IGNORECASE)


def granting_pattern(definition: Dict[str, Any], action: str) -> Optional[str]:
    """The action pattern that grants `action` in some permission block (after its notActions), else None."""
    for block in (definition.get("properties") or {}).get("permissions") or []:
        if any(_pattern(n).match(action) for n in block.get("notActions") or []):
            continue
        for allowed in block.get("actions") or []:
            if _pattern(allowed).match(action):
                return allowed
    return None


def scope_level(scope: str, workspace_id: str) -> str:
    s = (scope or "").rstrip("/").lower()
    if s == workspace_id.lower():
        return "workspace"
    if s == "":
        return "root"
    if "/providers/microsoft.management/managementgroups/" in s:
        return "management_group"
    parts = s.split("/")
    if len(parts) == 3:
        return "subscription"
    if len(parts) == 5:
        return "resource_group"
    return "resource"


def resolve_principals(client, ids: List[str]) -> Dict[str, Dict[str, Any]]:
    names: Dict[str, Dict[str, Any]] = {}
    for start in range(0, len(ids), GETBYIDS_BATCH):
        body = client.graph_post(
            "/directoryObjects/getByIds",
            {"ids": ids[start:start + GETBYIDS_BATCH], "types": ["user", "group", "servicePrincipal"]},
        )
        for obj in body.get("value") or []:
            names[obj.get("id")] = {"name": obj.get("displayName"), "upn": obj.get("userPrincipalName"), "app_id": obj.get("appId")}
    return names


def collect(client, ws: Dict[str, Any], collector) -> Dict[str, Any]:
    assignments = collector.guard(
        f"authorization.roleAssignments.list(atScope, {ws['name']})",
        lambda: client.list(f"{ws['id']}/providers/Microsoft.Authorization/roleAssignments", AUTH_API, {"$filter": "atScope()"}),
    )
    if assignments is None:
        return {"deletion_grants": None}
    definitions: Dict[str, Optional[Dict[str, Any]]] = {}
    for definition_id in sorted({(a.get("properties") or {}).get("roleDefinitionId") for a in assignments} - {None}):
        definitions[definition_id] = collector.guard(
            f"authorization.roleDefinitions.get({definition_id.rsplit('/', 1)[-1]})",
            lambda d=definition_id: client.get(d, AUTH_API),
        )

    grants = []
    for assignment in assignments:
        props = assignment.get("properties") or {}
        definition = definitions.get(props.get("roleDefinitionId"))
        if not definition:
            continue
        granted = {}
        for key, action in DELETION_ACTIONS.items():
            pattern = granting_pattern(definition, action)
            if pattern:
                granted[key] = {"via": pattern, "kind": "explicit" if pattern.lower() == action.lower() else "wildcard"}
        if not granted:
            continue
        role = definition.get("properties") or {}
        grants.append({
            "principal_id": props.get("principalId"),
            "principal_type": props.get("principalType"),
            "role_name": role.get("roleName"),
            "role_type": role.get("type"),
            "can_purge": "purge" in granted,
            "can_delete_data": "delete_data" in granted,
            "granted": granted,
            "scope": props.get("scope"),
            "scope_level": scope_level(props.get("scope"), ws["id"]),
            "condition": props.get("condition"),
        })

    notes: List[str] = []
    ids = sorted({g["principal_id"] for g in grants if g["principal_id"]})
    names: Dict[str, Dict[str, Any]] = {}
    if ids:
        try:
            names = resolve_principals(client, ids)
        except ArmError as exc:
            notes.append(f"principal names not resolved (Microsoft Graph directoryObjects/getByIds): {exc}")
    for grant in grants:
        found = names.get(grant["principal_id"]) or {}
        grant.update(principal_name=found.get("name"), principal_upn=found.get("upn"), principal_app_id=found.get("app_id"))
    grants.sort(key=lambda g: (g["role_name"] or "", g["principal_name"] or g["principal_id"] or ""))

    def principals(pred) -> int:
        return len({g["principal_id"] for g in grants if pred(g)})

    return {
        "role_assignments_at_scope": len(assignments),
        "deletion_grants": grants,
        "principals_with_deletion_rights": principals(lambda g: True),
        "principals_with_purge": principals(lambda g: g["can_purge"]),
        "principals_with_delete_data": principals(lambda g: g["can_delete_data"]),
        "principals_with_explicit_grant": principals(
            lambda g: any(v["kind"] == "explicit" for v in g["granted"].values())
        ),
        "groups_with_deletion_rights": principals(lambda g: g["principal_type"] == "Group"),
        "notes": notes,
    }


def summarize(workspaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    collected = [w for w in workspaces if w.get("deletion_grants") is not None]
    return {
        "max_principals_with_deletion_rights": max((w["principals_with_deletion_rights"] for w in collected), default=None),
        "workspaces_with_explicit_grants": sum(1 for w in collected if w["principals_with_explicit_grant"]),
    }


def main() -> int:
    return run_workspaces(fetcher=NAME, logger=logger, collect=collect, summarize=summarize, sentinel_only=False)


if __name__ == "__main__":
    sys.exit(main())
