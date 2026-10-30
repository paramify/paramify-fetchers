#!/usr/bin/env python3
"""Azure DevOps service connections (how each authenticates, its service principal and the runs that used it), variable groups and secure files."""

import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlsplit

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import sorted_counts  # noqa: E402
from devops_rest import (  # noqa: E402
    DevOpsClient,
    DevOpsCollector,
    DevOpsError,
    iso,
    list_projects,
    parse_time,
    run_org,
)

NAME = "azure_devops_service_connections"
LOOKBACK_ENV = "AZURE_DEVOPS_LOOKBACK_DAYS"
DEFAULT_LOOKBACK_DAYS = 30
PREVIEW_API = "7.1-preview.1"
# Learn documents secure files only at 7.2-preview.1.
SECURE_FILES_API = "7.2-preview.1"
HISTORY_PAGE = 100
# Per connection and project; history is read newest first, past the window only to find the last pipeline run.
MAX_HISTORY_RECORDS = 5000

SCOPE_ENDPOINTS = "Service Connections (Read)"
SCOPE_BUILD = "Build (Read)"
SCOPE_VARIABLE_GROUPS = "Variable Groups (Read)"
SCOPE_SECURE_FILES = "Secure Files (Read)"

# Only these authorization.parameters are written; every other parameter can hold a credential.
ID_PARAMETERS = {"serviceprincipalid": "service_principal_id", "tenantid": "tenant_id"}
AZURE_DATA = {"subscriptionId": "subscription_id", "subscriptionName": "subscription_name",
              "scopeLevel": "scope_level", "managementGroupId": "management_group_id",
              "managementGroupName": "management_group_name", "environment": "environment",
              "creationMode": "creation_mode", "identityType": "identity_type",
              "spnObjectId": "service_principal_object_id", "appObjectId": "app_object_id"}
AUTH_METHODS = {"workloadidentityfederation": "workload_identity_federation",
                "managedserviceidentity": "managed_identity", "usernamepassword": "username_password",
                "token": "token", "personalaccesstoken": "personal_access_token", "oauth": "oauth",
                "installationtoken": "github_app", "certificate": "certificate", "publishprofile": "publish_profile",
                "kubernetes": "kubernetes", "none": "none"}
SPN_CREDENTIALS = {"spnkey": "service_principal_secret", "spncertificate": "service_principal_certificate"}
SECRET_FREE = {"workload_identity_federation", "managed_identity", "github_app"}
STORED_SECRET = {"service_principal_secret", "service_principal_certificate", "service_principal", "username_password",
                 "token", "personal_access_token", "oauth", "certificate", "publish_profile", "kubernetes"}
TASK_RESULTS = ("succeeded", "succeededWithIssues", "failed", "canceled", "skipped", "abandoned", "manuallyQueued",
                "dependentOnManualQueue")
PIPELINE_PLANS = {"build", "release"}

# Keyed by area, not a list, so an evidence sample keeps every entry.
NOT_COLLECTED = {
    "secret_values": "Credentials, secret variable values and secure file contents are never read or written; "
                     "of a connection's authorization parameters only the service principal and tenant ids are kept, "
                     "and its URL is cut to scheme and host.",
    "secret_expiry": "Azure DevOps does not expose when a service principal secret or certificate expires; join "
                     "service_principal_id to the Entra app registration for that.",
    "classic_pipeline_authorization": "Pipeline permissions limit YAML pipelines only; a classic build or release "
                                      "pipeline may use any connection its editor holds the User role on.",
    "connection_roles": "Who holds the User, Creator and Administrator roles on each connection.",
    "projects_not_visible": "Projects and connections the collecting identity (metadata.collecting_identity) "
                            "cannot see.",
}

URL_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
URL_HOST = re.compile(r"(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?")

logger = logging.getLogger(NAME)


def lookback_days() -> int:
    raw = (os.environ.get(LOOKBACK_ENV) or "").strip()
    if not raw:
        return DEFAULT_LOOKBACK_DAYS
    try:
        days = int(raw)
    except ValueError:
        raise ValueError(f"{LOOKBACK_ENV} must be an integer, got {raw!r}") from None
    if days < 1:
        raise ValueError(f"{LOOKBACK_ENV} must be at least 1, got {days}")
    return days


def call(collector: DevOpsCollector, operation: str, scope: str, fn: Callable[[], Any], default: Any = None) -> Any:
    """collector.guard, naming the PAT scope (or, for an Entra identity, the read access) on an auth refusal."""
    def scoped():
        try:
            return fn()
        except DevOpsError as exc:
            if exc.status in (401, 403):
                hint = (f"PAT scope needed: {scope}" if collector.auth_mode == "pat"
                        else f"the Entra identity lacks permission for this read; PAT equivalent: {scope}")
                exc.args = (f"{exc} [{hint}]",)
            raise
    return collector.guard(operation, scoped, default)


def scrub_url(value: Any) -> Optional[str]:
    """Scheme and host only: userinfo, path and query can all carry credentials."""
    if not isinstance(value, str):
        return None
    scheme, sep, rest = value.strip().partition("://")
    host = re.split(r"[/?#]", rest.rpartition("@")[2], maxsplit=1)[0]
    if not sep or not URL_SCHEME.fullmatch(scheme) or not URL_HOST.fullmatch(host):
        return None
    return f"{scheme.lower()}://{host.lower()}"


def person(ref: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(ref, dict):
        return None
    return {"id": ref.get("id"), "display_name": ref.get("displayName"), "login": ref.get("uniqueName")}


def project_refs(refs: Any) -> List[Dict[str, Any]]:
    """Each project sharing the object, with the object's own name there (pipelines refer to it by that name)."""
    out = [{"id": (r.get("projectReference") or {}).get("id"), "name": (r.get("projectReference") or {}).get("name"),
            "name_in_project": r.get("name")}
           for r in refs or [] if isinstance(r, dict)]
    return sorted(out, key=lambda p: (p["name"] or "").lower())


def auth_method(scheme: Any, params: Dict[str, Any]) -> Optional[str]:
    key = str(scheme or "").strip().lower()
    if key == "serviceprincipal":
        kind = str(params.get("authenticationtype") or "").strip().lower()
        return SPN_CREDENTIALS.get(kind, "service_principal")
    return AUTH_METHODS.get(key, key or None)


def stored_credential(method: Optional[str], params: Dict[str, Any]) -> Optional[bool]:
    if method in SECRET_FREE:
        return False
    if method in STORED_SECRET:
        return True
    # Scheme None can still keep a key in its parameters, as a NuGet API key connection does.
    return True if method == "none" and set(params) - set(ID_PARAMETERS) else None


def task_result(raw: Any) -> Optional[str]:
    if isinstance(raw, int) and not isinstance(raw, bool):
        return TASK_RESULTS[raw] if 0 <= raw < len(TASK_RESULTS) else str(raw)
    text = str(raw or "").strip()
    return next((r for r in TASK_RESULTS if r.lower() == text.lower()), text or None)


def connection_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    auth = raw.get("authorization") if isinstance(raw.get("authorization"), dict) else {}
    params = {str(k).lower(): v for k, v in (auth.get("parameters") or {}).items()} \
        if isinstance(auth.get("parameters"), dict) else {}
    method = auth_method(auth.get("scheme"), params)
    ids = {out: params.get(key) if isinstance(params.get(key), str) and params.get(key) else None
           for key, out in ID_PARAMETERS.items()}
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    azure = str(raw.get("type") or "").lower() == "azurerm"
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "type": raw.get("type"),
        "owner": raw.get("owner"),
        "url": scrub_url(raw.get("url")),
        "authorization_scheme": auth.get("scheme"),
        "auth_method": method,
        "stored_credential": stored_credential(method, params),
        # As Azure DevOps gives it; compare case-insensitively.
        "service_principal_id": ids["service_principal_id"],
        "tenant_id": ids["tenant_id"],
        "azure": {out: data.get(key) for key, out in AZURE_DATA.items()} if azure else None,
        "is_ready": raw.get("isReady"),
        "is_shared": raw.get("isShared"),
        "created_by": person(raw.get("createdBy")),
        "projects": project_refs(raw.get("serviceEndpointProjectReferences")),
    }


def owner_link(owner: Dict[str, Any]) -> Optional[str]:
    href = ((owner.get("_links") or {}).get("web") or {}).get("href")
    return href if isinstance(href, str) and href.startswith("https://") else None


def link_project(link: Optional[str]) -> Optional[str]:
    """The project in a run's web link: the path segment before the first _-prefixed one, after the org."""
    if not link:
        return None
    parts = urlsplit(link)
    segments = [unquote(s) for s in parts.path.split("/") if s]
    host = (parts.hostname or "").lower()
    first = 1 if host == "dev.azure.com" or host.endswith(".dev.azure.com") else 0
    for i, segment in enumerate(segments):
        if segment.startswith("_"):
            return segments[i - 1] if i - 1 >= first else None
    return None


def execution_record(raw: Dict[str, Any]) -> Tuple[Optional[datetime], Dict[str, Any]]:
    data = raw.get("data") if isinstance(raw.get("data"), dict) else raw
    definition = data.get("definition") if isinstance(data.get("definition"), dict) else {}
    owner = data.get("owner") if isinstance(data.get("owner"), dict) else {}
    start, finish = parse_time(data.get("startTime")), parse_time(data.get("finishTime"))
    plan = data.get("planType")
    link = owner_link(owner)
    return start or finish, {
        "project": link_project(link),
        "plan_type": plan,
        "pipeline_run": str(plan or "").lower() in PIPELINE_PLANS,
        "execution_id": data.get("id"),
        "definition_id": definition.get("id"),
        "definition": definition.get("name"),
        "run_id": owner.get("id"),
        "run_name": owner.get("name"),
        "run_url": link,
        "result": task_result(data.get("result")),
        "start_time": iso(start),
        "finish_time": iso(finish),
    }


def execution_history(client, project, connection_id, since: datetime) -> Dict[str, Any]:
    """The connection's executions in the window, read through this project, plus its newest use whenever it was."""
    path = f"{project['id']}/_apis/serviceendpoint/{connection_id}/executionhistory"
    in_window: List[Dict[str, Any]] = []
    newest: Optional[datetime] = None
    newest_run: Optional[datetime] = None
    previous: Optional[datetime] = None
    newest_first, past_window, complete, read = True, False, True, 0
    for raw in client.iter(path, PREVIEW_API, params={"top": HISTORY_PAGE}):
        if not isinstance(raw, dict):
            continue
        if read >= MAX_HISTORY_RECORDS:
            complete = past_window and newest_first
            break
        read += 1
        when, record = execution_record(raw)
        if when is not None:
            newest = when if newest is None or when > newest else newest
            if record["pipeline_run"]:
                newest_run = when if newest_run is None or when > newest_run else newest_run
            newest_first = newest_first and (previous is None or when <= previous)
            previous = when
        if when is None or when >= since:
            in_window.append(record)
        elif newest_first:
            past_window = True
            if newest_run is not None:
                break
    return {"executions": in_window, "last_used": newest, "last_pipeline_run": newest_run, "complete": complete}


def pipeline_permissions(body: Any, project: Dict[str, Any]) -> Dict[str, Any]:
    body = body if isinstance(body, dict) else {}
    every = body.get("allPipelines") if isinstance(body.get("allPipelines"), dict) else {}
    return {
        "project": project["name"],
        "all_pipelines_authorized": bool(every.get("authorized")),
        "authorized_pipeline_ids": sorted(p.get("id") for p in body.get("pipelines") or []
                                          if isinstance(p, dict) and p.get("authorized") and p.get("id") is not None),
    }


def variable_group_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Counts and Key Vault metadata only; no variable value is written."""
    variables = raw.get("variables") if isinstance(raw.get("variables"), dict) else {}
    provider = raw.get("providerData") if isinstance(raw.get("providerData"), dict) else {}
    key_vault = str(raw.get("type") or "").lower() == "azurekeyvault"
    secrets = [n for n, v in variables.items() if key_vault or (isinstance(v, dict) and v.get("isSecret"))]
    kv_secrets = sorted(({
        "name": name,
        "enabled": value.get("enabled"),
        "expires": iso(parse_time(value.get("expires"))),
    } for name, value in variables.items() if isinstance(value, dict)), key=lambda s: s["name"]) if key_vault else []
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "type": raw.get("type"),
        "key_vault_linked": key_vault,
        "key_vault": provider.get("vault") if key_vault else None,
        "key_vault_service_connection_id": provider.get("serviceEndpointId") if key_vault else None,
        "key_vault_last_refreshed": iso(parse_time(provider.get("lastRefreshedOn"))) if key_vault else None,
        "variables": len(variables),
        "secret_variables": len(secrets),
        "secret_variables_outside_key_vault": 0 if key_vault else len(secrets),
        "key_vault_secrets": kv_secrets,
        "created_on": iso(parse_time(raw.get("createdOn"))),
        "modified_on": iso(parse_time(raw.get("modifiedOn"))),
        "modified_by": person(raw.get("modifiedBy")),
        "is_shared": raw.get("isShared"),
        "projects": project_refs(raw.get("variableGroupProjectReferences")),
    }


def secure_file_record(raw: Dict[str, Any], project: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "project": project["name"],
        "created_on": iso(parse_time(raw.get("createdOn"))),
        "modified_on": iso(parse_time(raw.get("modifiedOn"))),
        "modified_by": person(raw.get("modifiedBy")),
    }


def collect_project(client, collector, project, connections, groups, since) -> Dict[str, Any]:
    pid, pname = project["id"], project["name"]
    listed = call(collector, f"serviceendpoint.endpoints.list({pname})", SCOPE_ENDPOINTS,
                  lambda: client.list(f"{pid}/_apis/serviceendpoint/endpoints",
                                      params={"includeFailed": "true"}))
    for raw in listed or []:
        if not isinstance(raw, dict) or not raw.get("id"):
            continue
        key = str(raw["id"]).lower()
        conn = connections.setdefault(key, {**connection_record(raw), "_permissions": [], "_history": []})
        cid = raw["id"]
        perms = call(collector, f"pipelinepermissions.endpoint({pname}/{raw.get('name')})", SCOPE_BUILD,
                     lambda cid=cid: client.get(f"{pid}/_apis/pipelines/pipelinepermissions/endpoint/{cid}",
                                                PREVIEW_API))
        conn["_permissions"].append(None if perms is None else pipeline_permissions(perms, project))
        history = call(collector, f"serviceendpoint.executionhistory({pname}/{raw.get('name')})", SCOPE_ENDPOINTS,
                       lambda cid=cid: execution_history(client, project, cid, since))
        conn["_history"].append(history)

    variable_groups = call(collector, f"distributedtask.variablegroups.list({pname})", SCOPE_VARIABLE_GROUPS,
                           lambda: client.list(f"{pid}/_apis/distributedtask/variablegroups"))
    for raw in variable_groups or []:
        if isinstance(raw, dict) and raw.get("id") is not None:
            groups.setdefault(raw["id"], variable_group_record(raw))

    files = call(collector, f"distributedtask.securefiles.list({pname})", SCOPE_SECURE_FILES,
                 lambda: client.list(f"{pid}/_apis/distributedtask/securefiles", SECURE_FILES_API))
    return {
        "id": pid,
        "name": pname,
        "service_connections_listed": None if listed is None else len(listed),
        "variable_groups_listed": None if variable_groups is None else len(variable_groups),
        "secure_files": None if files is None else sorted(
            (secure_file_record(f, project) for f in files if isinstance(f, dict)), key=lambda f: f["name"] or ""),
    }


def run_keys(executions: List[Dict[str, Any]]) -> Set[Tuple[Any, ...]]:
    """Distinct pipeline runs: each stage of a release logs its own record."""
    return {(r["project"], str(r["plan_type"]).lower(), r["run_id"]) if r["run_id"] is not None
            else ("execution", r["execution_id"]) for r in executions if r["pipeline_run"]}


def finish_connection(conn: Dict[str, Any]) -> Dict[str, Any]:
    permissions = conn.pop("_permissions")
    histories = conn.pop("_history")
    seen = set()
    executions = []
    for history in histories:
        for record in (history or {}).get("executions") or []:
            key = (str(record["plan_type"]).lower(), record["execution_id"], record["run_id"], record["start_time"])
            if key not in seen:
                seen.add(key)
                executions.append(record)
    executions.sort(key=lambda r: r["start_time"] or r["finish_time"] or "", reverse=True)
    read = [h for h in histories if h is not None]

    def newest(field):
        return iso(max((h[field] for h in read if h[field]), default=None))

    conn.update({
        "executions_collected": bool(histories) and len(read) == len(histories),
        "executions_complete": bool(read) and all(h["complete"] for h in read),
        "last_used": newest("last_used"),
        "last_pipeline_run": newest("last_pipeline_run"),
        "executions_in_window": len(executions),
        "pipeline_runs_in_window": len(run_keys(executions)),
        "executions": executions,
    })
    read_permissions = [p for p in permissions if p is not None]
    collected = bool(permissions) and len(read_permissions) == len(permissions)
    conn["pipeline_permissions"] = read_permissions
    conn["pipeline_permissions_collected"] = collected
    # Unknown, not false, when a project's read failed and none of the others is open.
    conn["open_to_all_pipelines"] = (True if any(p["all_pipelines_authorized"] for p in read_permissions)
                                     else False if collected else None)
    return conn


def service_principals(connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Connections grouped by tenant and app id (an app id can repeat across tenants), compared case-insensitively."""
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for conn in connections:
        spn = (conn["service_principal_id"] or "").strip()
        if not spn:
            continue
        key = ((conn["tenant_id"] or "").strip().lower(), spn.lower())
        group = groups.setdefault(key, {"service_principal_id": conn["service_principal_id"],
                                        "tenant_id": conn["tenant_id"], "auth_methods": set(), "connections": [],
                                        "executions_in_window": 0, "runs": set(), "last_pipeline_run": None})
        group["auth_methods"].add(conn["auth_method"])
        group["connections"].append(conn["id"])
        group["executions_in_window"] += conn["executions_in_window"]
        group["runs"] |= run_keys(conn["executions"])
        if conn["last_pipeline_run"] and (group["last_pipeline_run"] or "") < conn["last_pipeline_run"]:
            group["last_pipeline_run"] = conn["last_pipeline_run"]
    out = []
    for _, group in sorted(groups.items()):
        runs = group.pop("runs")
        out.append({**group, "auth_methods": sorted(m for m in group["auth_methods"] if m),
                    "pipeline_runs_in_window": len(runs)})
    return out


def summarize(connections, groups, projects, principals, days) -> Dict[str, Any]:
    azure = [c for c in connections if c["azure"] is not None]
    files = [f for p in projects for f in p["secure_files"] or []]
    kv_secrets = [s for g in groups for s in g["key_vault_secrets"]]
    now = iso(datetime.now(timezone.utc)) or ""
    return {
        "lookback_days": days,
        "projects_collected": len(projects),
        "service_connections_total": len(connections),
        "service_connections_by_type": sorted_counts(Counter(c["type"] or "unknown" for c in connections)),
        "service_connections_by_auth_method": sorted_counts(Counter(c["auth_method"] or "unknown" for c in connections)),
        "azure_service_connections": len(azure),
        "azure_service_connections_using_workload_identity_federation": sum(
            1 for c in azure if c["auth_method"] == "workload_identity_federation"),
        "azure_service_connections_with_stored_secret": [c["name"] for c in azure if c["stored_credential"]],
        "service_connections_with_stored_credential": [c["name"] for c in connections if c["stored_credential"]],
        "service_connections_open_to_all_pipelines": [c["name"] for c in connections if c["open_to_all_pipelines"]],
        "service_connections_not_ready": [c["name"] for c in connections if c["is_ready"] is False],
        "service_connections_used_in_window": sum(1 for c in connections if c["pipeline_runs_in_window"]),
        "service_connections_unused_in_window": [c["name"] for c in connections
                                                 if c["executions_collected"] and not c["pipeline_runs_in_window"]],
        "service_principals": len(principals),
        "pipeline_runs_using_service_connections": len(set().union(*(run_keys(c["executions"])
                                                                     for c in connections))),
        "variable_groups_total": len(groups),
        "variable_groups_key_vault_linked": sum(1 for g in groups if g["key_vault_linked"]),
        "variable_groups_with_secrets_outside_key_vault": [g["name"] for g in groups
                                                           if g["secret_variables_outside_key_vault"]],
        "secret_variables_total": sum(g["secret_variables"] for g in groups),
        "secret_variables_outside_key_vault": sum(g["secret_variables_outside_key_vault"] for g in groups),
        "key_vault_secrets_expired": sum(1 for s in kv_secrets if s["expires"] and s["expires"] < now),
        "key_vault_secrets_without_expiry": sum(1 for s in kv_secrets if not s["expires"]),
        "secure_files_total": len(files),
        "not_collected": dict(NOT_COLLECTED),
    }


def collect(client: DevOpsClient, collector: DevOpsCollector) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    days = lookback_days()
    until = datetime.now(timezone.utc)
    since = until - timedelta(days=days)
    connections: Dict[str, Dict[str, Any]] = {}
    groups: Dict[Any, Dict[str, Any]] = {}
    projects = [collector.guard(f"collect({p.get('name')})",
                                lambda p=p: collect_project(client, collector, p, connections, groups, since))
                for p in list_projects(client, collector)]
    projects = [p for p in projects if p]
    finished = sorted((finish_connection(c) for c in connections.values()),
                      key=lambda c: ((c["name"] or "").lower(), str(c["id"])))
    group_list = sorted(groups.values(), key=lambda g: (g["name"] or "").lower())
    principals = service_principals(finished)
    results = {
        "window": {"start": iso(since), "end": iso(until), "lookback_days": days},
        "projects": projects,
        "service_connections": finished,
        "service_principals": principals,
        "variable_groups": group_list,
    }
    return results, summarize(finished, group_list, projects, principals, days)


if __name__ == "__main__":
    sys.exit(run_org(fetcher=NAME, logger=logger, collect=collect))
