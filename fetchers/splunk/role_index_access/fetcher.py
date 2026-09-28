#!/usr/bin/env python3
"""Splunk roles and users with the indexes each can effectively search, delete rights, and search restrictions."""

import logging
import os
import re
import sys
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from splunk_client import (  # noqa: E402
    SplunkClient,
    finish,
    iso,
    now_epoch,
    report_failure,
    target_from_env,
    to_epoch,
    write_evidence,
)

FETCHER = "splunk_role_index_access"
logger = logging.getLogger(FETCHER)

ROLES = "services/authorization/roles"
USERS = "services/authentication/users"
CURRENT_CONTEXT = "services/authentication/current-context"
REQUIRED_CAPABILITIES = ["search", "list_all_roles", "list_all_users", "rest_properties_get"]
INTERNAL_ROLE_PREFIX = "_spl_"
LOG_PRIVILEGE_CAPABILITIES = {"change_authentication", "delete_by_keyword", "edit_roles", "edit_roles_grantable",
                              "edit_tokens_all", "edit_user", "indexes_edit"}
WILDCARD_RULE = ("'*' matches any characters within an index name; a pattern matches internal ('_'-prefixed) "
                 "indexes only when it starts with '_', so '*' alone is every non-internal index and '_*' every "
                 "internal index (authorize.conf srchIndexesAllowed). Disallowed patterns win over allowed ones.")


def matches(pattern, index):
    pattern, index = pattern.lower(), index.lower()
    # Splunk's '*' never crosses the internal boundary: only a '_' pattern matches a '_' index.
    if pattern.startswith("_") != index.startswith("_"):
        return False
    return re.fullmatch(".*".join(re.escape(p) for p in pattern.split("*")), index) is not None


def expand(patterns, index_names):
    return {i for i in index_names if any(matches(p, i) for p in patterns)}


def covers_all(indexes, index_names, internal):
    kind = {i for i in index_names if i.startswith("_") == internal}
    return bool(kind) and kind <= indexes


def least_restrictive(values):
    """Splunk's time-limit merge: 0 is unlimited and wins, -1 is unset, otherwise the largest limit; None means no limit."""
    ints = [int(v) for v in values if v not in (None, "")]
    if 0 in ints or not any(v > 0 for v in ints):
        return None
    return max(v for v in ints if v > 0)


def as_list(value):
    if value in (None, ""):
        return []
    return [value] if isinstance(value, str) else list(value)


def filter_set(value):
    return bool(value) and str(value).strip() not in ("", "*")


class RoleGraph:
    def __init__(self, entries):
        self.roles = {e["name"]: e["content"] for e in entries}
        self.unknown = set()

    def inherited(self, name):
        seen, stack = set(), list(as_list(self.roles.get(name, {}).get("imported_roles")))
        while stack:
            r = stack.pop()
            if r in seen:
                continue
            seen.add(r)
            if r not in self.roles:
                self.unknown.add(r)
                continue
            stack += as_list(self.roles[r].get("imported_roles"))
        return seen - {name}

    def role_set(self, names):
        out = set()
        for n in names:
            if n not in self.roles:
                self.unknown.add(n)
                continue
            out |= {n} | self.inherited(n)
        return out & set(self.roles)

    def own(self, names, field):
        return set().union(*(as_list(self.roles[n].get(field)) for n in names))


def access(graph, direct_roles, capabilities, index_names):
    names = graph.role_set(direct_roles)
    held = [r for r in direct_roles if r in graph.roles]
    allowed = graph.own(held, "srchIndexesAllowed") | graph.own(held, "imported_srchIndexesAllowed")
    disallowed = graph.own(held, "srchIndexesDisallowed") | graph.own(held, "imported_srchIndexesDisallowed")
    effective = expand(allowed, index_names) - expand(disallowed, index_names)
    can_search = "search" in capabilities
    grants_non_internal = covers_all(effective, index_names, internal=False)
    grants_internal = covers_all(effective, index_names, internal=True)
    return names, {
        "search_capability": can_search,
        "grants_all_non_internal": grants_non_internal,
        "grants_all_internal": grants_internal,
        "can_search_all_non_internal": can_search and grants_non_internal,
        "can_search_all_internal": can_search and grants_internal,
        "delete_by_keyword": "delete_by_keyword" in capabilities,
        "effective_indexes": sorted(effective),
        "index_patterns_allowed": sorted(allowed),
        "index_patterns_disallowed": sorted(disallowed),
        "search_time_window_seconds": least_restrictive(
            graph.roles[r].get(f) for r in held for f in ("srchTimeWin", "imported_srchTimeWin")),
        "search_time_earliest_seconds": least_restrictive(
            graph.roles[r].get(f) for r in held for f in ("srchTimeEarliest", "imported_srchTimeEarliest")),
        "roles_with_search_filter": sorted(n for n in names if filter_set(graph.roles[n].get("srchFilter"))),
        "log_privilege_capabilities": sorted(LOG_PRIVILEGE_CAPABILITIES & capabilities),
    }


def role_row(graph, name, holders, importers, index_names):
    c = graph.roles[name]
    capabilities = set(as_list(c.get("capabilities"))) | set(as_list(c.get("imported_capabilities")))
    names, derived = access(graph, [name], capabilities, index_names)
    return {
        "name": name,
        "splunk_internal": name.startswith(INTERNAL_ROLE_PREFIX),
        "users": sorted(holders.get(name, [])),
        **derived,
        "delete_indexes_allowed": sorted(as_list(c.get("deleteIndexesAllowed"))),
        "imported_roles": sorted(as_list(c.get("imported_roles"))),
        "all_imported_roles": sorted(names - {name}),
        "imported_by": sorted(importers.get(name, [])),
        "srch_indexes_allowed": as_list(c.get("srchIndexesAllowed")),
        "imported_srch_indexes_allowed": as_list(c.get("imported_srchIndexesAllowed")),
        "srch_indexes_disallowed": as_list(c.get("srchIndexesDisallowed")),
        "imported_srch_indexes_disallowed": as_list(c.get("imported_srchIndexesDisallowed")),
        "srch_time_win": c.get("srchTimeWin"),
        "imported_srch_time_win": c.get("imported_srchTimeWin"),
        "srch_time_earliest": c.get("srchTimeEarliest"),
        "imported_srch_time_earliest": c.get("imported_srchTimeEarliest"),
        "srch_filter": c.get("srchFilter") or "",
        "imported_srch_filter": c.get("imported_srchFilter") or "",
    }


def user_row(graph, entry, index_names):
    c = entry["content"]
    direct = as_list(c.get("roles"))
    names, derived = access(graph, direct, set(as_list(c.get("capabilities"))), index_names)
    last_login = to_epoch(c.get("last_successful_login"))
    return {
        "name": entry["name"],
        "type": c.get("type"),
        "roles": sorted(direct),
        "all_roles": sorted(names),
        **derived,
        "locked_out": bool(c.get("locked-out")),
        "last_successful_login": iso(last_login) if last_login else None,
    }


def check_derivation(client, graph, user_entries):
    """Splunk's own resolution of imports and of each user's capabilities must match the role graph."""
    problems = []
    for name, c in graph.roles.items():
        inherited = graph.inherited(name) & set(graph.roles)
        for imported, own in (("imported_capabilities", "capabilities"),
                              ("imported_srchIndexesAllowed", "srchIndexesAllowed"),
                              ("imported_srchIndexesDisallowed", "srchIndexesDisallowed")):
            if set(as_list(c.get(imported))) != graph.own(inherited, own):
                problems.append(f"role {name}: {imported}")
    for e in user_entries:
        names = graph.role_set(as_list(e["content"].get("roles")))
        derived = graph.own(names, "capabilities") | graph.own(names, "imported_capabilities")
        if set(as_list(e["content"].get("capabilities"))) != derived:
            problems.append(f"user {e['name']}: capabilities")
    if problems:
        client.fail("derive effective access", "DerivationMismatch",
                    "Splunk's resolution differs from the role graph for " + "; ".join(problems), "internal_error")


def collect(client, collected_as):
    role_entries = client.list(ROLES)
    user_entries = client.list(USERS)
    index_entries = client.list_indexes()
    if role_entries is None or user_entries is None or index_entries is None:
        return None
    graph = RoleGraph(role_entries)
    index_names = {e["name"] for e in index_entries}
    users = [user_row(graph, e, index_names) for e in sorted(user_entries, key=lambda e: e["name"].lower())]
    holders, importers = {}, {}
    for u in users:
        for r in u["all_roles"]:
            holders.setdefault(r, []).append(u["name"])
    for name, c in graph.roles.items():
        for r in as_list(c.get("imported_roles")):
            importers.setdefault(r, []).append(name)
    roles = [role_row(graph, n, holders, importers, index_names) for n in sorted(graph.roles, key=str.lower)]
    check_derivation(client, graph, user_entries)
    if graph.unknown:
        client.fail(f"GET {ROLES}", "IncompleteCollection",
                    f"roles held or imported but not listed: {sorted(graph.unknown)}", "partial_failure")
    me = next((u for u in users if u["name"] == collected_as), None)
    if me is None or not {"*", "_*"} <= set(me["index_patterns_allowed"]) or me["index_patterns_disallowed"]:
        client.fail("check collecting user", "MissingIndexAccess",
                    f"collecting user {collected_as} must be granted * and _* with nothing disallowed, "
                    "or an index it cannot search could be missing from the index checks", "not_authorized")
    readers = [u for u in users if u["search_capability"]]
    indexes = [{
        "name": e["name"],
        "internal": e["name"].startswith("_"),
        "datatype": e["content"].get("datatype"),
        "disabled": bool(e["content"].get("disabled")),
        "users_can_search": [u["name"] for u in readers if e["name"] in u["effective_indexes"]],
    } for e in sorted(index_entries, key=lambda e: e["name"])]
    return {"roles": roles, "users": users, "indexes": indexes}


def summarize(result):
    roles, users, indexes = result["roles"], result["users"], result["indexes"]
    return {
        "roles_total": len(roles),
        "roles_splunk_internal": sum(r["splunk_internal"] for r in roles),
        "users_total": len(users),
        "indexes_total": len(indexes),
        "indexes_internal": sum(i["internal"] for i in indexes),
        "users_can_search_all_non_internal": [u["name"] for u in users if u["can_search_all_non_internal"]],
        "users_can_search_all_internal": [u["name"] for u in users if u["can_search_all_internal"]],
        "users_with_delete_by_keyword": [u["name"] for u in users if u["delete_by_keyword"]],
        "roles_with_delete_by_keyword": [r["name"] for r in roles if r["delete_by_keyword"]],
        "users_by_type": dict(Counter(str(u["type"]) for u in users)),
    }


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    try:
        target = target_from_env()
    except ValueError as exc:
        report_failure(str(exc), "bad_config")
        return 1

    client = SplunkClient(target["base_url"], target["token"], target["verify_ssl"])
    now = now_epoch()
    version = client.server_version()
    context = client.get(CURRENT_CONTEXT)
    collected_as = context["entry"][0]["content"].get("username") if context else None
    result = collect(client, collected_as) if client.require_capabilities(REQUIRED_CAPABILITIES) else None

    evidence = {
        "metadata": {
            "collected_at": iso(now),
            "target": target["name"],
            "base_url": target["base_url"],
            "splunk_version": version,
            "collected_as": collected_as,
            "index_wildcard_rule": WILDCARD_RULE,
            **client.failure_metadata(),
        },
        "summary": summarize(result) if result else {},
        "users": (result or {}).get("users", []),
        "roles": (result or {}).get("roles", []),
        "indexes": (result or {}).get("indexes", []),
    }
    return finish(logger, write_evidence(FETCHER, target["name"], evidence), client)


if __name__ == "__main__":
    sys.exit(main())
