#!/usr/bin/env python3
"""Azure DevOps users, service principals and groups: access levels, last access, group memberships and who holds privileged groups."""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import sorted_counts  # noqa: E402
from devops_rest import (  # noqa: E402
    DevOpsClient,
    DevOpsCollector,
    DevOpsError,
    iso,
    parse_time,
    run_org,
)

NAME = "azure_devops_identities"
INACTIVE_ENV = "AZURE_DEVOPS_INACTIVE_DAYS"
DEFAULT_INACTIVE_DAYS = 90
GRAPH_API = "7.1-preview.1"
ENTITLEMENTS_API = "7.1"
GRAPH = "vssps"
ENTITLEMENTS = "vsaex"

SCOPE_GRAPH = "Graph (Read)"
SCOPE_ENTITLEMENTS = "Member Entitlement Management (Read)"

PRIVILEGED_GROUPS = {
    "project collection administrators", "project collection service accounts",
    "project collection build administrators", "project administrators", "build administrators",
    "release administrators", "endpoint administrators",
}
# Computed groups hold everyone; their members are not read.
COMPUTED_GROUPS = {"project collection valid users", "project valid users"}
SIGN_IN_BLOCKED = {"disabled", "deleted", "pendingdisabled"}
PROJECT_DOMAIN = "vstfs:///classification/teamproject/"
# Subject descriptor prefixes.
KINDS = {"aad": "user", "msa": "user", "bnd": "user", "imp": "user", "aadsp": "service_principal",
         "svc": "service_identity", "s2s": "system", "acs": "system", "vssgp": "group", "aadgp": "group",
         "ungrp": "group"}
HUMAN = "user"

# Keyed by area, not a list, so an evidence sample keeps every entry.
NOT_COLLECTED = {
    "time_bound_access": "Azure DevOps group memberships never expire; access is time-bound only where the Entra "
                         "group holding it is PIM-managed, which the Entra PIM evidence shows.",
    "entra_group_members": "Members of an Entra group are those Azure DevOps has seen (usually after they sign in); "
                           "the Entra group's full membership is in Entra ID.",
    "permissions": "What each group may do: see the Azure DevOps permissions evidence.",
    "service_principal_last_access": "When a service principal or managed identity last used the organization.",
}

logger = logging.getLogger(NAME)


def inactive_days() -> int:
    raw = (os.environ.get(INACTIVE_ENV) or "").strip()
    if not raw:
        return DEFAULT_INACTIVE_DAYS
    try:
        days = int(raw)
    except ValueError:
        raise ValueError(f"{INACTIVE_ENV} must be an integer, got {raw!r}") from None
    if days < 1:
        raise ValueError(f"{INACTIVE_ENV} must be at least 1, got {days}")
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


def org_list(client, path: str) -> List[Dict[str, Any]]:
    """A Graph list; 404 there means the organization itself does not exist."""
    try:
        return client.list(path, GRAPH_API, service=GRAPH)
    except DevOpsError as exc:
        if exc.status == 404:
            raise ValueError(f"organization {client.org!r} not found at {client.base}: {exc}") from exc
        raise


def kind_of(descriptor: Any) -> str:
    prefix = str(descriptor or "").split(".", 1)[0].lower()
    return KINDS.get(prefix, "other")


def entra_group(group: Dict[str, Any]) -> bool:
    return (str(group.get("origin") or "").lower() == "aad"
            or str(group.get("descriptor") or "").lower().startswith("aadgp."))


def group_project(group: Dict[str, Any]) -> Optional[str]:
    if not str(group.get("domain") or "").lower().startswith(PROJECT_DOMAIN):
        return None
    name = str(group.get("principalName") or "")
    return name[1:name.index("]")] if name.startswith("[") and "]" in name else None


def group_label(group: Dict[str, Any]) -> str:
    return group.get("principalName") or group.get("displayName") or group.get("descriptor") or ""


def privileged(group: Dict[str, Any]) -> bool:
    return (str(group.get("origin") or "").lower() == "vsts"
            and str(group.get("displayName") or "").lower() in PRIVILEGED_GROUPS
            and not str(group.get("principalName") or "").upper().startswith("[TEAM FOUNDATION]"))


def computed(group: Dict[str, Any]) -> bool:
    # Entra groups are also named "[TEAM FOUNDATION]\<name>"; only Azure DevOps ones there are enterprise-level.
    if entra_group(group):
        return False
    return (str(group.get("displayName") or "").lower() in COMPUTED_GROUPS
            or str(group.get("principalName") or "").upper().startswith("[TEAM FOUNDATION]"))


def entitlements(client) -> List[Dict[str, Any]]:
    """Every user entitlement; a page holds `items` (older versions `members`) and a body continuationToken."""
    return client.list("_apis/userentitlements", ENTITLEMENTS_API, service=ENTITLEMENTS, item_key=("items", "members"))


def last_access(raw: Any) -> Optional[datetime]:
    """None for never: Azure DevOps writes 0001-01-01 for a member who has not signed in."""
    when = parse_time(raw)
    return when if when and when.year > 1900 else None


def inactive(human: bool, entitled: bool, can_sign_in: Optional[bool], stale: Optional[bool]) -> Optional[bool]:
    """Judged for people with an entitlement only; None when that can't be told."""
    if not human or not entitled:
        return None
    if can_sign_in is False:
        return False
    return None if can_sign_in is None or stale is None else stale


def identity_record(subject: Dict[str, Any], entitlement: Optional[Dict[str, Any]], now: datetime,
                    threshold: int) -> Dict[str, Any]:
    level = (entitlement or {}).get("accessLevel") or {}
    created = parse_time((entitlement or {}).get("dateCreated"))
    accessed = last_access((entitlement or {}).get("lastAccessedDate"))
    kind = kind_of(subject.get("descriptor"))
    human = kind == HUMAN
    cutoff = now - timedelta(days=threshold)
    status = str(level.get("status") or "").lower() or None
    can_sign_in = status not in SIGN_IN_BLOCKED if status else None
    stale = accessed < cutoff if accessed else (created < cutoff if created else None)
    meta = str(subject.get("metaType") or "").lower() or None
    return {
        "descriptor": subject.get("descriptor"),
        "display_name": subject.get("displayName"),
        "principal_name": subject.get("principalName"),
        "login": (subject.get("mailAddress") or subject.get("principalName")) if kind == HUMAN else None,
        "kind": kind,
        "origin": subject.get("origin"),
        "origin_id": subject.get("originId"),
        "meta_type": subject.get("metaType"),
        "guest": meta == "guest" if human and meta else None,
        "deleted_in_origin": subject.get("isDeletedInOrigin") is True,
        "application_id": subject.get("applicationId"),
        "access_level": level.get("licenseDisplayName"),
        "license_type": level.get("accountLicenseType"),
        "license_status": status,
        "can_sign_in": can_sign_in,
        "date_created": iso(created),
        "last_accessed": iso(accessed),
        "never_accessed": accessed is None if entitlement is not None else None,
        "days_since_last_access": (now - accessed).days if accessed else None,
        "inactive": inactive(human, entitlement is not None, can_sign_in, stale),
    }


def group_record(group: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "descriptor": group.get("descriptor"),
        "name": group_label(group),
        "display_name": group.get("displayName"),
        "origin": group.get("origin"),
        "entra_group": entra_group(group),
        "project": group_project(group),
        "privileged": privileged(group),
        "computed": computed(group),
    }


class Graph:
    """Who is directly in which group, read down from every group that is not computed."""

    def __init__(self, groups: Dict[str, Dict[str, Any]]):
        self.groups = groups
        self.members: Dict[str, List[str]] = {}
        self.parents: Dict[str, Set[str]] = {}
        self.unread: Set[str] = set()

    def add(self, container: str, members: List[str]) -> None:
        self.members[container] = members
        for member in members:
            self.parents.setdefault(member, set()).add(container)

    def ancestors(self, descriptor: str) -> Set[str]:
        found: Set[str] = set()
        stack = list(self.parents.get(descriptor, ()))
        while stack:
            group = stack.pop()
            if group not in found:
                found.add(group)
                stack.extend(self.parents.get(group, ()))
        return found

    def effective(self, root: str, cross_entra: bool = True) -> Tuple[Dict[str, List[str]], Set[str], bool]:
        """Each non-group member under `root` with the shortest path of groups to it, the Entra groups crossed,
        and whether every group on the way was read. With cross_entra=False, Entra groups are not entered."""
        paths: Dict[str, List[str]] = {}
        entra: Set[str] = set()
        complete = root not in self.unread
        queue = [(root, [root])]
        seen = {root}
        while queue:
            group, path = queue.pop(0)
            for member in self.members.get(group, []):
                if member in seen:
                    continue
                seen.add(member)
                if kind_of(member) == "group" or member in self.groups:
                    if entra_group(self.groups.get(member) or {"descriptor": member}):
                        if not cross_entra:
                            continue
                        entra.add(member)
                    complete = complete and member not in self.unread and member in self.members
                    queue.append((member, path + [member]))
                else:
                    paths[member] = path
        return paths, entra, complete


def collect(client: DevOpsClient, collector: DevOpsCollector) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    threshold = inactive_days()
    now = datetime.now(timezone.utc)

    users = call(collector, "graph.users.list", SCOPE_GRAPH, lambda: org_list(client, "_apis/graph/users"))
    principals = call(collector, "graph.serviceprincipals.list", SCOPE_GRAPH,
                      lambda: client.list("_apis/graph/serviceprincipals", GRAPH_API, service=GRAPH))
    groups_raw = call(collector, "graph.groups.list", SCOPE_GRAPH,
                      lambda: client.list("_apis/graph/groups", GRAPH_API, service=GRAPH))
    entitled = call(collector, "userentitlements.list", SCOPE_ENTITLEMENTS, lambda: entitlements(client))
    read = {"users": users is not None, "service_principals": principals is not None,
            "groups": groups_raw is not None, "entitlements": entitled is not None}

    by_descriptor = {e["user"]["descriptor"]: e for e in entitled or []
                     if isinstance(e.get("user"), dict) and e["user"].get("descriptor")}
    subjects = {s["descriptor"]: s for s in (users or []) + (principals or [])
                if isinstance(s, dict) and s.get("descriptor")}
    # An entitled member the graph list did not return is still a member.
    for descriptor, entitlement in by_descriptor.items():
        subjects.setdefault(descriptor, entitlement["user"])
    groups = {g["descriptor"]: g for g in groups_raw or [] if isinstance(g, dict) and g.get("descriptor")}

    graph = Graph(groups)
    for descriptor, group in sorted(groups.items(), key=lambda kv: group_label(kv[1]).lower()):
        if computed(group):
            continue
        rows = call(collector, f"graph.memberships.down({group_label(group)})", SCOPE_GRAPH,
                    lambda d=descriptor: client.list(f"_apis/graph/Memberships/{d}", GRAPH_API,
                                                     params={"direction": "down"}, service=GRAPH))
        if rows is None:
            graph.unread.add(descriptor)
            continue
        graph.add(descriptor, sorted({r.get("memberDescriptor") for r in rows
                                      if isinstance(r, dict) and r.get("memberDescriptor")}))

    def label(descriptor: str) -> str:
        if descriptor in groups:
            return group_label(groups[descriptor])
        subject = subjects.get(descriptor) or {}
        return subject.get("principalName") or subject.get("displayName") or descriptor

    identities: Dict[str, Dict[str, Any]] = {}
    for descriptor, subject in subjects.items():
        record = identity_record(subject, by_descriptor.get(descriptor), now, threshold)
        record["direct_groups"] = record["groups"] = record["privileged_groups"] = None
        if read["groups"]:
            record["direct_groups"] = sorted((label(g) for g in graph.parents.get(descriptor, ())), key=str.lower)
            record["groups"] = sorted((label(g) for g in graph.ancestors(descriptor)), key=str.lower)
            record["privileged_groups"] = []
        identities[descriptor] = record

    privileged_groups = []
    for descriptor, group in sorted(groups.items(), key=lambda kv: group_label(kv[1]).lower()):
        if not privileged(group):
            continue
        paths, entra, complete = graph.effective(descriptor)
        # A member reached without an Entra group keeps that path, so Entra-only holders stand apart.
        plain, _, _ = graph.effective(descriptor, cross_entra=False)
        members = []
        for member, path in sorted(paths.items(), key=lambda kv: label(kv[0]).lower()):
            path = plain.get(member, path)
            record = identities.get(member)
            if record is not None:
                record["privileged_groups"].append(group_label(group))
            members.append({
                "descriptor": member,
                "name": label(member),
                "kind": kind_of(member),
                "direct": len(path) == 1,
                "via": [label(g) for g in path],
                "through_entra_group": member not in plain,
                "inactive": record["inactive"] if record else None,
                "guest": record["guest"] if record else None,
            })
        privileged_groups.append({
            **group_record(group),
            "members_complete": complete,
            "entra_groups": sorted(label(g) for g in entra),
            "effective_members": members,
        })
    for record in identities.values():
        if record["privileged_groups"] is not None:
            record["privileged_groups"].sort(key=str.lower)

    ordered = sorted(identities.values(), key=lambda r: (r["kind"], str(r["principal_name"] or r["display_name"] or "").lower()))
    group_list = sorted((group_record(g) for g in groups.values()), key=lambda g: g["name"].lower())
    for g in group_list:
        g["members_read"] = g["descriptor"] in graph.members
        g["direct_members"] = len(graph.members.get(g["descriptor"], []))
    results = {
        "inactivity_threshold_days": threshold,
        "identities": ordered,
        "groups": group_list,
        "privileged_groups": privileged_groups,
    }
    return results, summarize(ordered, group_list, privileged_groups, threshold, read)


def summarize(identities, groups, privileged_groups, threshold: int, read: Dict[str, bool]) -> Dict[str, Any]:
    """A field whose source call failed is None, never a zero or an empty list."""
    def name(r):
        return r["principal_name"] or r["display_name"] or r["descriptor"]

    def names(rows) -> List[str]:
        return sorted(rows, key=str.lower)

    def known(*sources: str) -> Callable[[Any], Any]:
        ok = all(read[s] for s in sources)
        return lambda value: value if ok else None

    users, entitled, grouped = known("users"), known("entitlements"), known("groups")
    people = [r for r in identities if r["kind"] == HUMAN]
    holders = {m["descriptor"]: m for g in privileged_groups for m in g["effective_members"]}
    privileged_people = [m for m in holders.values() if m["kind"] == HUMAN]
    only_through_entra = {m["descriptor"] for g in privileged_groups for m in g["effective_members"]
                          if m["through_entra_group"]} - {m["descriptor"] for g in privileged_groups
                                                          for m in g["effective_members"] if not m["through_entra_group"]}
    return {
        "inactivity_threshold_days": threshold,
        "users_total": users(len(people)),
        "guest_users": users(sum(1 for r in people if r["guest"])),
        "users_by_access_level": entitled(sorted_counts(Counter(r["access_level"] or "unknown" for r in people))),
        "users_by_origin": users(sorted_counts(Counter(r["origin"] or "unknown" for r in people))),
        "users_with_sign_in_disabled": entitled(sum(1 for r in people if r["can_sign_in"] is False)),
        "users_deleted_in_origin": users(names(name(r) for r in people if r["deleted_in_origin"])),
        "service_principals_total": known("service_principals")(
            sum(1 for r in identities if r["kind"] == "service_principal")),
        "service_identities_total": users(sum(1 for r in identities if r["kind"] == "service_identity")),
        "groups_total": grouped(len(groups)),
        "entra_groups_total": grouped(sum(1 for g in groups if g["entra_group"])),
        "groups_not_read": grouped([g["name"] for g in groups if not g["members_read"] and not g["computed"]]),
        "last_access_collected": read["entitlements"],
        "inactive_users": entitled(names(name(r) for r in people if r["inactive"])),
        "users_never_accessed": entitled(names(name(r) for r in people if r["never_accessed"])),
        "privileged_groups": grouped(len(privileged_groups)),
        "privileged_groups_not_fully_read": grouped([g["name"] for g in privileged_groups if not g["members_complete"]]),
        "privileged_members_by_group": grouped({g["name"]: len(g["effective_members"]) for g in privileged_groups}),
        "privileged_identities": grouped(len(holders)),
        "privileged_users": grouped(names(m["name"] for m in privileged_people)),
        "privileged_service_principals": grouped(
            names(m["name"] for m in holders.values() if m["kind"] == "service_principal")),
        "privileged_identities_only_through_entra_groups": grouped(len(only_through_entra)),
        "entra_groups_granting_privilege": grouped(names({e for g in privileged_groups for e in g["entra_groups"]})),
        "inactive_privileged_users": known("groups", "entitlements")(
            names(m["name"] for m in privileged_people if m["inactive"])),
        "guest_privileged_users": known("groups", "users")(names(m["name"] for m in privileged_people if m["guest"])),
        "not_collected": dict(NOT_COLLECTED),
    }


if __name__ == "__main__":
    sys.exit(run_org(fetcher=NAME, logger=logger, collect=collect))
