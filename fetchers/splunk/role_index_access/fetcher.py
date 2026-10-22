#!/usr/bin/env python3
"""Who can search, and delete, which Splunk indexes: every role and user with the indexes it can effectively reach."""

import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from splunk_client import as_bool, as_list, iso, now_epoch, run, to_epoch  # noqa: E402

NAME = "splunk_role_index_access"
# Without list_all_roles and list_all_users Splunk hides roles and users, and reports the smaller count as the total.
CAPABILITIES = ["search", "list_all_roles", "list_all_users", "rest_properties_get"]
CONFIG = {"dormant_days": ("SPLUNK_DORMANT_DAYS", 90)}

ROLES = "services/authorization/roles"
USERS = "services/authentication/users"
INTERNAL_ROLE_PREFIX = "_spl_"  # Splunk's own service roles
# Capabilities that let the holder change who can read log data, or destroy it.
LOG_PRIVILEGE_CAPABILITIES = {"change_authentication", "delete_by_keyword", "edit_roles", "edit_roles_grantable",
                              "edit_tokens_all", "edit_user", "indexes_edit"}


def matches(pattern, index):
    """Splunk's index wildcard: '*' matches within a name, but only a pattern starting '_' reaches an internal index."""
    pattern, index = pattern.lower(), index.lower()
    if pattern.startswith("_") != index.startswith("_"):
        return False
    return re.fullmatch(".*".join(re.escape(part) for part in pattern.split("*")), index) is not None


def expand(patterns, index_names):
    return {i for i in index_names if any(matches(p, i) for p in patterns)}


def covers_all(indexes, index_names, internal):
    """True when `indexes` holds every existing index of that kind; False when none exists."""
    kind = {i for i in index_names if i.startswith("_") == internal}
    return bool(kind) and kind <= indexes


def inherited(roles, name):
    """Every role `name` imports, directly or through other roles."""
    seen, stack = set(), list(as_list(roles.get(name, {}).get("imported_roles")))
    while stack:
        role = stack.pop()
        if role not in seen:
            seen.add(role)
            stack += as_list(roles.get(role, {}).get("imported_roles"))
    return seen - {name}


def access(roles, held, capabilities, index_names):
    """What holding `held` grants. Splunk resolves imported grants itself; a denial always wins over a grant."""
    def patterns(*fields):
        return {p for r in held for f in fields for p in as_list(roles[r].get(f))}

    allowed = patterns("srchIndexesAllowed", "imported_srchIndexesAllowed")
    denied = patterns("srchIndexesDisallowed", "imported_srchIndexesDisallowed")
    effective = expand(allowed, index_names) - expand(denied, index_names)
    can_search = "search" in capabilities
    non_internal, internal = covers_all(effective, index_names, False), covers_all(effective, index_names, True)
    return {
        "search_capability": can_search,
        "grants_all_non_internal": non_internal,
        "grants_all_internal": internal,
        "can_search_all_non_internal": can_search and non_internal,
        "can_search_all_internal": can_search and internal,
        "delete_by_keyword": "delete_by_keyword" in capabilities,
        "log_privilege_capabilities": sorted(LOG_PRIVILEGE_CAPABILITIES & capabilities),
        "effective_indexes": sorted(effective),
        "index_patterns_allowed": sorted(allowed),
        "index_patterns_disallowed": sorted(denied),
    }


def role_row(roles, name, holders, importers, index_names):
    c = roles[name]
    capabilities = set(as_list(c.get("capabilities"))) | set(as_list(c.get("imported_capabilities")))
    return {
        "name": name,
        "splunk_internal": name.startswith(INTERNAL_ROLE_PREFIX),
        "users": sorted(holders.get(name, [])),
        **access(roles, [name], capabilities, index_names),
        "delete_indexes_allowed": sorted(as_list(c.get("deleteIndexesAllowed"))),
        "imported_roles": sorted(as_list(c.get("imported_roles"))),
        "imported_by": sorted(importers.get(name, [])),
        "search_filter": c.get("srchFilter") or None,
    }


def user_row(roles, entry, index_names, now, dormant_days):
    c = entry["content"]
    direct = as_list(c.get("roles"))
    held = [r for r in direct if r in roles]
    all_roles = set(held).union(*(inherited(roles, r) for r in held)) & set(roles)
    last_login = to_epoch(c.get("last_successful_login")) or None  # Splunk sends 0 for never
    idle_days = max(0, int((now - last_login) // 86400)) if last_login else None
    return {
        "name": entry["name"],
        "type": c.get("type"),  # "Splunk" for a native account, else SAML or LDAP
        "roles": sorted(direct),
        "all_roles": sorted(all_roles),
        **access(roles, held, set(as_list(c.get("capabilities"))), index_names),
        "locked_out": bool(as_bool(c.get("locked-out"))),
        "last_successful_login": iso(last_login),
        "days_since_last_login": idle_days,
        "never_logged_in": idle_days is None,
        "dormant": idle_days is not None and idle_days >= dormant_days,
    }


def summarize(users, roles, indexes):
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
        "users_dormant": [u["name"] for u in users if u["dormant"]],
        "users_never_logged_in": [u["name"] for u in users if u["never_logged_in"]],
    }


def collect(client, config):
    role_entries = client.list(ROLES)
    user_entries = client.list(USERS)
    index_entries = client.list_indexes()
    if None in (role_entries, user_entries, index_entries):
        return None
    roles = {e["name"]: e["content"] for e in role_entries}
    index_names = {e["name"] for e in index_entries}

    # A role that is held or imported but not listed means the role list is incomplete.
    referenced = ({r for e in user_entries for r in as_list(e["content"].get("roles"))}
                  | {r for c in roles.values() for r in as_list(c.get("imported_roles"))})
    if referenced - set(roles):
        client.fail(f"GET {ROLES}", "IncompleteCollection",
                    f"roles held or imported but not listed: {sorted(referenced - set(roles))}", "partial_failure")

    now = now_epoch()
    users = [user_row(roles, e, index_names, now, config["dormant_days"])
             for e in sorted(user_entries, key=lambda e: e["name"].lower())]

    # The index list is only complete if the collecting user can search every index, including ones not yet created.
    collected_as = client.user.get("username")
    me = next((u for u in users if u["name"] == collected_as), None)
    if me is None or not {"*", "_*"} <= set(me["index_patterns_allowed"]) or me["index_patterns_disallowed"]:
        client.fail("check the collecting user", "MissingIndexAccess",
                    f"{collected_as} must be granted * and _* with nothing disallowed", "not_authorized")

    holders, importers = {}, {}
    for u in users:
        for r in u["all_roles"]:
            holders.setdefault(r, []).append(u["name"])
    for name, c in roles.items():
        for r in as_list(c.get("imported_roles")):
            importers.setdefault(r, []).append(name)
    role_rows = [role_row(roles, n, holders, importers, index_names) for n in sorted(roles, key=str.lower)]

    readers = [u for u in users if u["search_capability"]]
    index_rows = [{
        "name": e["name"],
        "datatype": e["content"].get("datatype"),
        "enabled": not as_bool(e["content"].get("disabled")),
        "internal": e["name"].startswith("_"),
        "users_can_search": [u["name"] for u in readers if e["name"] in u["effective_indexes"]],
    } for e in sorted(index_entries, key=lambda e: e["name"])]

    return {
        "metadata": {"collected_as": collected_as},
        "summary": summarize(users, role_rows, index_rows),
        "users": users,
        "roles": role_rows,
        "indexes": index_rows,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CAPABILITIES, CONFIG))
