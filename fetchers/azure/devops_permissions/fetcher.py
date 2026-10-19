#!/usr/bin/env python3
"""Azure DevOps permissions: who is allowed or denied what at organization, project, repository, pipeline, environment and service-connection scope."""

import logging
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import sorted_counts  # noqa: E402
from devops_rest import (  # noqa: E402
    DevOpsClient,
    DevOpsCollector,
    DevOpsError,
    list_projects,
    requested_projects,
    run_org,
)

NAME = "azure_devops_permissions"
SECURITY_API = "7.1"
IDENTITY_BATCH = 50
GRAPH = "vssps"

SCOPE_SECURITY = "Security (Manage)"
SCOPE_IDENTITY = "Identity (Read)"

# Namespaces read, by lowercased name; the high-impact actions in each, by lowercased action name.
NAMESPACES = {
    "collection": {"generic_write", "manage_enterprise_policies"},
    "project": {"generic_write", "delete", "update_visibility", "administer_build"},
    "git repositories": {"managepermissions", "editpolicies", "policyexempt", "pullrequestbypasspolicy",
                         "deleterepository", "forcepush"},
    "versioncontrolitems": {"adminprojectrights", "checkinother"},
    "versioncontrolprivileges": {"adminconfiguration"},
    "build": {"administerbuildpermissions", "editbuilddefinition", "deletebuilddefinition",
              "overridebuildcheckinvalidation"},
    "releasemanagement": {"administerreleasepermissions", "editreleasedefinition", "deletereleasedefinition",
                          "managereleaseapprovers"},
    "serviceendpoints": {"administer"},
    "environment": {"administer", "manage"},
    "library": {"administer"},
    "auditlog": {"manage_streams", "delete_streams"},
}
BYPASS_ACTIONS = {("git repositories", "policyexempt"), ("git repositories", "pullrequestbypasspolicy")}
ADMIN_GROUPS = {
    "project collection administrators", "project collection service accounts",
    "project collection build administrators", "project administrators", "build administrators",
    "release administrators", "endpoint administrators",
}
# Identity descriptor types; a resolved identity's subject descriptor prefix wins.
DESCRIPTOR_KINDS = {
    "microsoft.teamfoundation.identity": "group",
    "microsoft.identitymodel.claims.claimsidentity": "user",
    "microsoft.teamfoundation.serviceidentity": "service_identity",
    "microsoft.visualstudio.services.claims.aadserviceprincipal": "service_principal",
}
SUBJECT_KINDS = {"aad": "user", "msa": "user", "aadsp": "service_principal", "svc": "service_identity",
                 "vssgp": "group", "aadgp": "entra_group"}
_PROJECT_TOKEN = re.compile(r"^\$PROJECT:vstfs:///Classification/TeamProject/([0-9a-fA-F-]{36})", re.I)

# Keyed by area, not a list, so an evidence sample keeps every entry.
NOT_COLLECTED = {
    "group_membership": "Who is in each group: see the Azure DevOps identities evidence.",
    "resource_names": "Repositories, pipelines, environments, service connections and library items are named by "
                      "id; the pipelines and service-connections evidence carries the same ids.",
    "other_namespaces": "Permissions in namespaces other than those listed in results.namespaces (work items, "
                        "boards, wiki, dashboards, analytics, agent pools).",
    "inherited_grants": "High-impact rights are flagged where they are set explicitly; a right only inherited from "
                        "a parent token is shown on that parent.",
}

logger = logging.getLogger(NAME)


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


def bits(mask: Any, actions: List[Dict[str, Any]]) -> List[str]:
    """Action names whose bit is set in `mask`, in bit order; unknown bits as their number."""
    value = mask if isinstance(mask, int) and not isinstance(mask, bool) else 0
    names, known = [], 0
    for action in sorted(actions, key=lambda a: a.get("bit") or 0):
        bit = action.get("bit")
        if isinstance(bit, int) and bit and value & bit:
            names.append(action.get("name") or str(bit))
            known |= bit
    rest = value & ~known
    names += [str(1 << i) for i in range(32) if rest & (1 << i)]
    return names


def parse_token(namespace: str, token: str, projects_by_name: Dict[str, str]) -> Tuple[str, Optional[str], Optional[str]]:
    """(scope, project id, resource) for a namespace's security token."""
    parts = [p for p in re.split(r"[/\\]", token or "") if p]
    if namespace in ("collection", "auditlog", "versioncontrolprivileges"):
        return "organization", None, None
    if namespace == "project":
        match = _PROJECT_TOKEN.match(token or "")
        return ("project", match.group(1).lower(), None) if match else ("organization", None, None)
    if namespace == "versioncontrolitems":
        if len(parts) <= 1:
            return "organization", None, None
        pid = projects_by_name.get(parts[1].lower())
        return ("project", pid, None) if len(parts) == 2 else ("path", pid, "/".join(parts))
    if namespace == "git repositories":
        if len(parts) <= 1:
            return "organization", None, None
        pid = parts[1].lower()
        if len(parts) == 2:
            return "project", pid, None
        return ("repository", pid, parts[2]) if len(parts) == 3 else ("branch", pid, "/".join(parts[2:]))
    if namespace in ("build", "releasemanagement"):
        if not parts:
            return "organization", None, None
        pid = parts[0].lower()
        if len(parts) == 1:
            return "project", pid, None
        if namespace == "releasemanagement" and "environment" in (p.lower() for p in parts):
            return "release_stage", pid, "/".join(parts[1:])
        return ("pipeline" if parts[-1].isdigit() else "folder"), pid, "/".join(parts[1:])
    if namespace == "serviceendpoints":
        rest = parts[1:] if parts and parts[0].lower() == "endpoints" else parts
        if not rest or (rest[0].lower() == "collection" and len(rest) == 1):
            return "organization", None, None
        pid = None if rest[0].lower() == "collection" else rest[0].lower()
        return ("service_connection", pid, rest[1]) if len(rest) > 1 else ("project", pid, None)
    if namespace == "environment":
        rest = parts[1:] if parts and parts[0].lower() == "environments" else parts
        if not rest:
            return "organization", None, None
        return ("environment", rest[0].lower(), rest[1]) if len(rest) > 1 else ("project", rest[0].lower(), None)
    if namespace == "library":
        rest = parts[1:] if parts and parts[0].lower() == "library" else parts
        if not rest:
            return "organization", None, None
        if len(rest) >= 3:
            kind = {"variablegroup": "variable_group", "securefile": "secure_file"}.get(rest[1].lower(), "library_item")
            return kind, rest[0].lower(), rest[2]
        return "project", rest[0].lower(), None
    return "other", None, token


def resolve(client, collector, descriptors: List[str]) -> Dict[str, Dict[str, Any]]:
    """Identity descriptor -> identity, in batches; an unresolved descriptor is left out."""
    found: Dict[str, Dict[str, Any]] = {}
    for start in range(0, len(descriptors), IDENTITY_BATCH):
        batch = descriptors[start:start + IDENTITY_BATCH]
        rows = call(collector, f"identities.read({start // IDENTITY_BATCH + 1})", SCOPE_IDENTITY,
                    lambda batch=batch: client.list("_apis/identities", SECURITY_API, params={
                        "descriptors": ",".join(batch), "queryMembership": "None"}, service=GRAPH))
        for row in rows or []:
            if isinstance(row, dict) and row.get("descriptor"):
                descriptor = row["descriptor"]
                if isinstance(descriptor, dict):
                    descriptor = f"{descriptor.get('identityType')};{descriptor.get('identifier')}"
                found[str(descriptor).lower()] = row
    return found


def identity_record(descriptor: str, row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    subject = (row or {}).get("subjectDescriptor")
    kind = SUBJECT_KINDS.get(str(subject or "").split(".", 1)[0].lower()) if subject else None
    kind = kind or DESCRIPTOR_KINDS.get(descriptor.split(";", 1)[0].lower(), "other")
    name = (row or {}).get("customDisplayName") or (row or {}).get("providerDisplayName")
    short = str(name or "").rsplit("\\", 1)[-1].lower()
    return {
        "descriptor": descriptor,
        "subject_descriptor": subject,
        "name": name,
        "kind": kind,
        "resolved": row is not None,
        "admin_group": kind == "group" and short in ADMIN_GROUPS,
    }


def collect(client: DevOpsClient, collector: DevOpsCollector) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    projects = list_projects(client, collector)
    project_names = {str(p.get("id") or "").lower(): p.get("name") for p in projects}
    projects_by_name = {str(p.get("name") or "").lower(): str(p.get("id") or "").lower() for p in projects}
    narrowed = bool(requested_projects())

    listed = call(collector, "securitynamespaces.list", SCOPE_SECURITY,
                  lambda: client.list("_apis/securitynamespaces", SECURITY_API), default=[])
    namespaces = [n for n in listed if isinstance(n, dict) and str(n.get("name") or "").lower() in NAMESPACES]
    found_names = {str(n.get("name") or "").lower() for n in namespaces}

    raw_entries = []
    namespace_records = []
    acls_off = 0
    for ns in sorted(namespaces, key=lambda n: (str(n.get("name") or "").lower(), str(n.get("namespaceId")))):
        key = str(ns.get("name") or "").lower()
        actions = [a for a in ns.get("actions") or [] if isinstance(a, dict)]
        acls = call(collector, f"accesscontrollists.query({ns.get('name')})", SCOPE_SECURITY,
                    lambda ns=ns: client.list(f"_apis/accesscontrollists/{ns.get('namespaceId')}", SECURITY_API,
                                              params={"includeExtendedInfo": "true", "recurse": "true"}))
        count = 0
        for acl in acls or []:
            if not isinstance(acl, dict):
                continue
            token = str(acl.get("token") or "")
            scope, pid, resource = parse_token(key, token, projects_by_name)
            if narrowed and pid and pid not in project_names:
                continue
            if acl.get("inheritPermissions") is False:
                acls_off += 1
            for ace in (acl.get("acesDictionary") or {}).values():
                if not isinstance(ace, dict) or not (ace.get("allow") or ace.get("deny")):
                    continue
                count += 1
                raw_entries.append((ns, key, actions, token, scope, pid, resource, acl.get("inheritPermissions"), ace))
        namespace_records.append({
            "id": ns.get("namespaceId"),
            "name": ns.get("name"),
            "acls_read": acls is not None,
            "acls": None if acls is None else len(acls),
            "entries": count,
            "actions": {a.get("name"): a.get("displayName") for a in sorted(actions, key=lambda a: a.get("bit") or 0)},
        })

    descriptors = sorted({str(e[8].get("descriptor")) for e in raw_entries if e[8].get("descriptor")})
    resolved = resolve(client, collector, descriptors) if descriptors else {}
    identities = {d: identity_record(d, resolved.get(d.lower())) for d in descriptors}

    entries = []
    for ns, key, actions, token, scope, pid, resource, inherit, ace in raw_entries:
        extended = ace.get("extendedInfo") if isinstance(ace.get("extendedInfo"), dict) else {}
        allow, deny = ace.get("allow") or 0, ace.get("deny") or 0
        allowed = bits(allow & ~deny, actions)
        high = sorted(a for a in allowed if a.lower() in NAMESPACES[key])
        who = identities.get(str(ace.get("descriptor")))
        entries.append({
            "namespace": ns.get("name"),
            "token": token,
            "scope": scope,
            "project_id": pid,
            "project": project_names.get(pid or "") if pid else None,
            "resource": resource,
            "inherit_permissions": inherit,
            "identity": who,
            "allow": bits(allow, actions),
            "deny": bits(deny, actions),
            "inherited_allow": bits(extended.get("inheritedAllow"), actions),
            "inherited_deny": bits(extended.get("inheritedDeny"), actions),
            "effective_allow": bits(extended.get("effectiveAllow"), actions),
            "effective_deny": bits(extended.get("effectiveDeny"), actions),
            "high_impact_allowed": high,
            "high_impact_outside_admin_groups": bool(high) and not (who or {}).get("admin_group"),
        })
    entries.sort(key=lambda e: (str(e["namespace"]).lower(), e["token"], str((e["identity"] or {}).get("name") or "")))
    results = {
        "namespaces": namespace_records,
        "namespaces_not_found": sorted(set(NAMESPACES) - found_names) if listed else [],
        "identities": sorted(identities.values(), key=lambda i: (i["kind"], str(i["name"] or i["descriptor"]).lower())),
        "entries": entries,
    }
    return results, summarize(entries, identities, namespace_records, acls_off, results["namespaces_not_found"])


def summarize(entries, identities, namespaces, acls_off: int, not_found: List[str]) -> Dict[str, Any]:
    def name(identity):
        return (identity or {}).get("name") or (identity or {}).get("descriptor")

    outside = [e for e in entries if e["high_impact_outside_admin_groups"]]
    rights = Counter(f"{e['namespace']}: {a}" for e in outside for a in e["high_impact_allowed"])
    bypass = {name(e["identity"]) for e in entries
              if any((str(e["namespace"]).lower(), a.lower()) in BYPASS_ACTIONS for a in e["high_impact_allowed"])}
    return {
        "namespaces_collected": sum(1 for n in namespaces if n["acls_read"]),
        "namespaces_not_found": not_found,
        "acls_total": sum(n["acls"] or 0 for n in namespaces),
        "acls_with_inheritance_off": acls_off,
        "entries_total": len(entries),
        "entries_by_scope": sorted_counts(Counter(e["scope"] for e in entries)),
        "entries_with_deny": sum(1 for e in entries if e["deny"]),
        "identities_with_explicit_entries": len(identities),
        "unresolved_identities": sum(1 for i in identities.values() if not i["resolved"]),
        "users_with_direct_entries": sorted({name(e["identity"]) for e in entries
                                             if (e["identity"] or {}).get("kind") == "user"}, key=str.lower),
        "high_impact_grants": sum(1 for e in entries if e["high_impact_allowed"]),
        "high_impact_grants_outside_admin_groups": len(outside),
        "identities_with_high_impact_rights_outside_admin_groups": sorted({name(e["identity"]) for e in outside},
                                                                          key=str.lower),
        "high_impact_rights_outside_admin_groups_by_right": sorted_counts(rights),
        "branch_policy_bypass_holders": sorted(bypass, key=str.lower),
        "not_collected": dict(NOT_COLLECTED),
    }


if __name__ == "__main__":
    sys.exit(run_org(fetcher=NAME, logger=logger, collect=collect))
