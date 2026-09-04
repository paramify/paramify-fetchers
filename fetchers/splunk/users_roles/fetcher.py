#!/usr/bin/env python3
"""
Splunk Users and Roles

Collects every Splunk account and role with its authentication type, effective
capabilities and — the part that matters most here — which indexes each role is
allowed to search.

Why this evidence set
---------------------
Splunk holds the logs, so the roles that can search Splunk *are* the access
control on log data. CR26's KSI-MLA-ALA reads: *"A least-privileged, role and
attribute-based, and just-in-time access authorization model is used and
persistently reviewed for access to log data based on organizationally defined
data sensitivity."* This is close to a restatement of it. In the repo's
pre-CR26 numbering the nearest statement is KSI-IAM-05, "apply zero-trust
design principles", which `fetcher.yaml` declares for consistency.

The two things that are easy to get wrong
-----------------------------------------
**1. A role's power is not in its `capabilities` field.**

Splunk splits capabilities into `capabilities` (granted directly) and
`imported_capabilities` (inherited through `imported_roles`). On a stock
install, `splunk-system-role` has **zero** direct capabilities and **194**
imported ones, including `admin_all_objects` and `edit_user`. Reading the direct
list alone reports a full-administrator role as holding no privileges at all —
the opposite of the truth, and silent. The effective set is the union, and that
is what this fetcher reports.

**2. `srchIndexesAllowed: ["*"]` does NOT include the internal indexes.**

Splunk's `*` matches non-internal indexes only. Reaching `_audit` — Splunk's own
audit trail — requires `_*` or the index named explicitly. The stock config
proves it: `admin` is granted `["*", "_*"]` and `data_management_admin` is
granted `["*", "_audit", "_internal", "_metrics"]`. Both would be redundant if
`*` already covered them.

Treating `*` as "everything" therefore reports every role as able to read the
audit trail, which inverts the finding this fetcher exists to produce: *who can
read the record of what everyone did.*

Deliberately NOT claimed
------------------------
Nothing about authentication strength — whether MFA is enforced, or whether SSO
is required. That lives in `authentication/providers/services` and would be its
own evidence set. This reports the accounts and what they may reach, and flags
locally-defined accounts because they bypass whatever SSO is configured.

No pass/fail verdict. A deployment may have every reason for the roles it has.
"""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from splunk_client import (  # type: ignore  # noqa: E402
    SplunkAuthError,
    as_bool,
    as_int,
    build_client,
    evidence,
    evidence_error,
    flatten,
    read_server_info,
    run_fetcher,
)

logger = logging.getLogger("splunk_users_roles")

# Knowledge objects need the wildcard namespace; these are system configuration
# and do not — measured, both paths return identical counts. Kept on
# /servicesNS/-/- anyway so every collection in this category reads the same way.
USERS_PATH = "/servicesNS/-/-/authentication/users"
ROLES_PATH = "/servicesNS/-/-/authorization/roles"

# Splunk's own audit trail. A role that can search this can read the record of
# what every other account did.
AUDIT_INDEX = "_audit"

# `*` matches non-internal indexes ONLY. Internal ones (leading underscore) need
# `_*` or an explicit name. See the module docstring for why this is not a guess.
ALL_NON_INTERNAL = "*"
ALL_INTERNAL = "_*"

# Capabilities that amount to administrative control. `admin_all_objects` alone
# is effectively root inside Splunk.
ADMIN_CAPABILITIES = {"admin_all_objects", "edit_user", "edit_roles", "edit_indexes"}

# `type` on a user: "Splunk" is an account defined in Splunk itself; anything
# else (LDAP, SAML) is federated. Local accounts bypass whatever SSO is
# configured, so they are counted separately rather than lumped in.
LOCAL_AUTH_TYPE = "splunk"

DEFAULT_DORMANT_DAYS = 90


def effective_capabilities(record: Dict[str, Any]) -> List[str]:
    """
    Every capability a role actually confers: direct plus inherited.

    Reading `capabilities` alone misses everything a role picks up through
    `imported_roles` — and on a stock install that is how `splunk-system-role`
    holds `admin_all_objects` while its direct list is empty.
    """
    direct = record.get("capabilities") or []
    imported = record.get("imported_capabilities") or []
    merged = {c for c in list(direct) + list(imported) if isinstance(c, str)}
    return sorted(merged)


def searchable_indexes(record: Dict[str, Any]) -> List[str]:
    """The index patterns a role may search, direct plus inherited."""
    direct = record.get("srchIndexesAllowed") or []
    imported = record.get("imported_srchIndexesAllowed") or []
    merged = {i for i in list(direct) + list(imported) if isinstance(i, str)}
    return sorted(merged)


def can_read_internal(patterns: List[str]) -> bool:
    """
    Whether these patterns reach Splunk's internal indexes.

    `*` does not. Only `_*`, or an explicit `_`-prefixed name, does.
    """
    return any(p == ALL_INTERNAL or p.startswith("_") for p in patterns)


def can_read_audit(patterns: List[str]) -> bool:
    """Whether these patterns reach `_audit` specifically."""
    return any(p == ALL_INTERNAL or p == AUDIT_INDEX for p in patterns)


def days_since(epoch: Any) -> Optional[int]:
    """Days since an epoch timestamp. None when it never happened."""
    value = as_int(epoch)
    if value is None or value <= 0:
        return None
    delta = datetime.now(timezone.utc) - datetime.fromtimestamp(value, tz=timezone.utc)
    return max(delta.days, 0)


def describe_role(record: Dict[str, Any]) -> Dict[str, Any]:
    caps = effective_capabilities(record)
    indexes = searchable_indexes(record)
    return {
        "name": record.get("name"),
        "inherits_from": list(record.get("imported_roles") or []),
        "capability_count": len(caps),
        "direct_capability_count": len(record.get("capabilities") or []),
        "administrative_capabilities": sorted(set(caps) & ADMIN_CAPABILITIES),
        "is_administrative": bool(set(caps) & ADMIN_CAPABILITIES),
        "searchable_indexes": indexes,
        "can_search_all_non_internal": ALL_NON_INTERNAL in indexes,
        "can_search_internal": can_read_internal(indexes),
        "can_search_audit_trail": can_read_audit(indexes),
        "search_filter": record.get("srchFilter") or None,
    }


def describe_user(record: Dict[str, Any], dormant_days: int) -> Dict[str, Any]:
    auth_type = record.get("type")
    idle = days_since(record.get("last_successful_login"))
    caps = record.get("capabilities") or []
    return {
        "name": record.get("name"),
        "real_name": record.get("realname") or None,
        "email": record.get("email") or None,
        "roles": list(record.get("roles") or []),
        "auth_type": auth_type,
        "locally_defined": isinstance(auth_type, str)
        and auth_type.strip().lower() == LOCAL_AUTH_TYPE,
        "locked_out": as_bool(record.get("locked-out")),
        "days_since_login": idle,
        # Never logged in is not the same as idle: a provisioned account that has
        # never been used is a different finding from one that went quiet.
        "never_logged_in": idle is None,
        "dormant": idle is not None and idle >= dormant_days,
        "is_administrative": bool(set(caps) & ADMIN_CAPABILITIES),
    }


def summarize(
    users: List[Dict[str, Any]], roles: List[Dict[str, Any]], dormant_days: int
) -> Dict[str, Any]:
    """
    Reduce accounts and roles to the access posture a reviewer reads first.

    The headline is which roles can reach the audit trail, because that is the
    log-access question this evidence set exists to answer.
    """
    described_roles = [describe_role(r) for r in roles if isinstance(r, dict)]
    described_users = [describe_user(u, dormant_days) for u in users if isinstance(u, dict)]

    admin_roles = [r for r in described_roles if r["is_administrative"]]
    audit_roles = [r for r in described_roles if r["can_search_audit_trail"]]
    internal_roles = [r for r in described_roles if r["can_search_internal"]]
    no_index_roles = [r for r in described_roles if not r["searchable_indexes"]]
    # A role whose administrative power is entirely inherited: its own
    # capability list looks empty while it confers full control.
    inherited_admin = [
        r["name"]
        for r in described_roles
        if r["is_administrative"] and r["direct_capability_count"] == 0
    ]

    admin_users = [u for u in described_users if u["is_administrative"]]
    local_users = [u for u in described_users if u["locally_defined"]]

    role_membership: Counter = Counter()
    for user in described_users:
        for role in user["roles"]:
            role_membership[role] += 1

    return {
        "total_users": len(described_users),
        "total_roles": len(described_roles),
        # Log access — the KSI-MLA-ALA claim rests on these two.
        "roles_that_can_search_the_audit_trail": [r["name"] for r in audit_roles],
        "roles_that_can_search_internal_indexes": [r["name"] for r in internal_roles],
        "roles_with_no_index_access": [r["name"] for r in no_index_roles],
        "administrative_roles": [r["name"] for r in admin_roles],
        # Reported on its own because reading a role's direct capability list
        # would show these as holding nothing at all.
        "roles_administrative_only_by_inheritance": inherited_admin,
        "administrative_users": [u["name"] for u in admin_users],
        # Local accounts bypass whatever SSO is configured.
        "locally_defined_users": [u["name"] for u in local_users],
        "federated_users": len(described_users) - len(local_users),
        "locked_out_users": [u["name"] for u in described_users if u["locked_out"] is True],
        "users_never_logged_in": [u["name"] for u in described_users if u["never_logged_in"]],
        "dormant_users": [
            {"name": u["name"], "days_since_login": u["days_since_login"]}
            for u in described_users
            if u["dormant"]
        ],
        "dormant_threshold_days": dormant_days,
        "users_with_no_role": [u["name"] for u in described_users if not u["roles"]],
        "role_membership": dict(role_membership.most_common()),
        "by_auth_type": dict(
            Counter(u["auth_type"] or "unknown" for u in described_users).most_common()
        ),
    }


def collect() -> Dict[str, Any]:
    try:
        client = build_client()
    except (SplunkAuthError, RuntimeError) as e:
        return evidence_error(str(e))

    read_server_info(client)

    try:
        dormant_days = int(os.environ.get("SPLUNK_DORMANT_DAYS", DEFAULT_DORMANT_DAYS))
    except ValueError:
        logger.warning("SPLUNK_DORMANT_DAYS is not an integer; using %s", DEFAULT_DORMANT_DAYS)
        dormant_days = DEFAULT_DORMANT_DAYS

    users = [flatten(e) for e in client.collect(USERS_PATH)]
    roles = [flatten(e) for e in client.collect(ROLES_PATH)]

    return evidence(
        client=client,
        endpoint=USERS_PATH,
        records=users,
        data=[describe_user(u, dormant_days) for u in users if isinstance(u, dict)],
        analysis=summarize(users, roles, dormant_days),
        empty_message="No Splunk accounts returned",
        # Roles are the other half of the evidence, not a sub-record of a user,
        # so they travel as their own top-level key.
        roles=[describe_role(r) for r in roles if isinstance(r, dict)],
        role_count=len(roles),
    )


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "splunk_users_roles.json", logger))
