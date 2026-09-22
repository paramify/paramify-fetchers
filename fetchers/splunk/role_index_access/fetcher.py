#!/usr/bin/env python3
"""
Splunk Role Access to Log Data

Reads every role on one Splunk deployment and records what log data that role
can actually reach, so a least-privileged log-access claim (KSI-MLA-ALA) can be
asserted per role instead of being asserted globally and hoped for.

Three things this fetcher does that a naive read of the API does not:

1. **Effective index access is a UNION.** A role's reach is
   `srchIndexesAllowed` UNION `imported_srchIndexesAllowed` — the second half
   comes in through `imported_roles`. A fetcher reading only the direct field
   under-reports: `splunk-system-role` ships with `srchIndexesAllowed = []` and
   inherits `["*", "_*"]` from `admin`.

2. **The KSI has three halves and this records all of them.** Role-based is the
   index lists; attribute-based is `srchFilter`, the row filter appended to
   every search the role runs; just-in-time is `srchTimeWin` /
   `srchTimeEarliest`, the cap on how far back a search may reach. `-1` means
   unlimited, and `srchFilter = "*"` means no filter at all, so both are
   normalised into booleans rather than left for a reader to interpret.

3. **Wildcard access is made explicit and countable.** Splunk's default `user`
   role ships with `srchIndexesAllowed = ["*"]`. That is the natural failure
   case for this control, and it must not be something an assessor has to spot
   by finding a `"*"` buried in a list.

The role list splunkd returns is filtered by the CALLER's own role — a
least-privileged service account sees only its own role and would silently
under-report the whole control. The identity the fetcher authenticated as is
therefore recorded in the evidence, so a truncated answer is distinguishable
from a complete one.
"""

import fnmatch
import json
import logging
import os
import re
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("splunk_role_index_access")

# Splunk's index globs: `*` matches every NON-internal index, and an internal
# index (one whose name starts with `_`) is only matched by a pattern that
# itself starts with `_`. That rule is why the built-in `admin` role ships with
# `srchIndexesAllowed = ["*", "_*"]` rather than `["*"]` alone. UNVERIFIED by
# running a search on this deployment — the raw patterns are kept in the
# evidence alongside every derived field so the derivation can be re-checked.
WILDCARD_CHARS = ("*", "?", "[")

# srchFilter values that mean "no attribute-based restriction at all". Splunk
# writes `*` on the admin role, which is a filter that filters nothing.
EMPTY_SEARCH_FILTERS = {"", "*"}


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_filename(value: str) -> str:
    sanitized = value.replace("://", "_").replace("/", "_").replace(":", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized)


def env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() not in {"false", "0", "no", "off"}


def csv_env(name: str, default: str = "") -> List[str]:
    return [v.strip() for v in os.environ.get(name, default).split(",") if v.strip()]


def build_session(token: str, username: str, password: str, verify_ssl: bool) -> requests.Session:
    """Bearer token if we have one, HTTP basic otherwise.

    Splunk Cloud effectively requires the token; basic auth is the Enterprise
    and sandbox path. Callers guarantee one of the two is present.
    """
    session = requests.Session()
    session.verify = verify_ssl
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    else:
        session.auth = (username, password)
    return session


def get_json(session: requests.Session, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    merged = {"output_mode": "json", **params}
    response = session.get(url, params=merged, timeout=60)
    if response.status_code in (401, 403):
        raise PermissionError(f"{response.status_code} from {url}: {response.text[:300]}")
    if response.status_code != 200:
        raise RuntimeError(f"{response.status_code} from {url}: {response.text[:300]}")
    return response.json()


def to_int(value: Any) -> Any:
    """splunkd returns numbers as strings; keep non-numeric values visible."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_list(value: Any) -> List[str]:
    """splunkd omits empty multivalue fields and collapses single ones to a str."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def union(*lists: List[str]) -> List[str]:
    seen: Dict[str, None] = {}
    for items in lists:
        for item in items:
            seen[item] = None
    return sorted(seen)


def is_wildcard(pattern: str) -> bool:
    return any(c in pattern for c in WILDCARD_CHARS)


def pattern_matches_index(pattern: str, index_name: str) -> bool:
    """Splunk glob semantics: `*` does not reach internal (`_`-prefixed) indexes.

    Only a pattern that itself starts with `_` can match an internal index,
    which is why `admin` carries both `*` and `_*`.
    """
    if index_name.startswith("_") and not pattern.startswith("_"):
        return False
    return fnmatch.fnmatchcase(index_name, pattern)


def reachable_indexes(allowed: List[str], disallowed: List[str], audit_indexes: List[str]) -> List[str]:
    """Which of the named audit indexes this role's effective patterns reach."""
    reachable = []
    for name in audit_indexes:
        if any(pattern_matches_index(p, name) for p in disallowed):
            continue
        if any(pattern_matches_index(p, name) for p in allowed):
            reachable.append(name)
    return sorted(reachable)


def describe_role(
    entry: Dict[str, Any], audit_indexes: List[str], exempt_roles: List[str]
) -> Dict[str, Any]:
    content = entry.get("content", {}) or {}
    name = entry.get("name")

    capabilities = as_list(content.get("capabilities"))
    imported_capabilities = as_list(content.get("imported_capabilities"))

    allowed = as_list(content.get("srchIndexesAllowed"))
    imported_allowed = as_list(content.get("imported_srchIndexesAllowed"))
    default = as_list(content.get("srchIndexesDefault"))
    imported_default = as_list(content.get("imported_srchIndexesDefault"))
    disallowed = as_list(content.get("srchIndexesDisallowed"))
    imported_disallowed = as_list(content.get("imported_srchIndexesDisallowed"))

    # THE union that matters. Reading srchIndexesAllowed alone under-reports.
    effective_allowed = union(allowed, imported_allowed)
    effective_disallowed = union(disallowed, imported_disallowed)

    # ABAC half of the KSI. `*` is Splunk's way of writing "no filter".
    search_filter = str(content.get("srchFilter") or "")
    imported_search_filter = str(content.get("imported_srchFilter") or "")
    effective_filter = search_filter if search_filter not in EMPTY_SEARCH_FILTERS else imported_search_filter

    # Just-in-time half. -1 is Splunk's "unlimited"; 0 on srchTimeWin likewise
    # means no window is imposed.
    time_win = to_int(content.get("srchTimeWin"))
    imported_time_win = to_int(content.get("imported_srchTimeWin"))
    time_earliest = to_int(content.get("srchTimeEarliest"))
    imported_time_earliest = to_int(content.get("imported_srchTimeEarliest"))
    bounded_wins = [w for w in (time_win, imported_time_win) if w is not None and w > 0]
    bounded_earliest = [e for e in (time_earliest, imported_time_earliest) if e is not None and e > 0]

    return {
        "name": name,
        "exempt": name in exempt_roles,
        "is_builtin_candidate": name in {"admin", "power", "splunk-system-role"},
        # --- role-based half: capabilities and inheritance ---
        "imported_roles": as_list(content.get("imported_roles")),
        "capabilities": sorted(capabilities),
        "imported_capabilities": sorted(imported_capabilities),
        "effective_capability_count": len(union(capabilities, imported_capabilities)),
        "direct_capability_count": len(capabilities),
        "imported_capability_count": len(imported_capabilities),
        "grantable_roles": as_list(content.get("grantable_roles")),
        "can_delegate_roles": bool(as_list(content.get("grantable_roles"))),
        # --- role-based half: index reach, direct and inherited ---
        "srch_indexes_allowed": allowed,
        "imported_srch_indexes_allowed": imported_allowed,
        "srch_indexes_default": default,
        "imported_srch_indexes_default": imported_default,
        "srch_indexes_disallowed": disallowed,
        "imported_srch_indexes_disallowed": imported_disallowed,
        "effective_srch_indexes_allowed": effective_allowed,
        "effective_srch_indexes_default": union(default, imported_default),
        "effective_srch_indexes_disallowed": effective_disallowed,
        # Explicit and countable, per index-access wildcards. A reader must not
        # have to spot a "*" buried in a list to see unrestricted reach.
        "has_wildcard_index_access": any(is_wildcard(p) for p in effective_allowed),
        "wildcard_index_patterns": sorted(p for p in effective_allowed if is_wildcard(p)),
        "index_access_inherited_only": bool(imported_allowed) and not allowed,
        "has_any_index_access": bool(effective_allowed),
        # --- attribute-based half ---
        "srch_filter": search_filter,
        "imported_srch_filter": imported_search_filter,
        "effective_srch_filter": effective_filter,
        "has_search_filter": effective_filter not in EMPTY_SEARCH_FILTERS,
        # --- just-in-time half ---
        "srch_time_win_secs": time_win,
        "imported_srch_time_win_secs": imported_time_win,
        "srch_time_earliest_secs": time_earliest,
        "imported_srch_time_earliest_secs": imported_time_earliest,
        "effective_srch_time_win_secs": min(bounded_wins) if bounded_wins else -1,
        "effective_srch_time_earliest_secs": min(bounded_earliest) if bounded_earliest else -1,
        "has_search_time_limit": bool(bounded_wins or bounded_earliest),
        # --- reach into the indexes the control is actually about ---
        "audit_indexes_reachable": (
            reachable_indexes(effective_allowed, effective_disallowed, audit_indexes)
            if audit_indexes
            else None
        ),
        "can_access_audit_data": (
            bool(reachable_indexes(effective_allowed, effective_disallowed, audit_indexes))
            if audit_indexes
            else None
        ),
    }


def summarize(roles: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Least-privilege roll-up over whichever set of roles was handed in."""
    wildcard = [r["name"] for r in roles if r["has_wildcard_index_access"]]
    with_reach = [r for r in roles if r["has_any_index_access"]]
    return {
        "total_roles": len(roles),
        "roles_with_index_access": len(with_reach),
        "roles_with_wildcard_index_access": len(wildcard),
        "roles_with_wildcard_index_access_names": sorted(wildcard),
        "no_role_has_wildcard_index_access": len(wildcard) == 0,
        "roles_with_search_filter": sum(1 for r in roles if r["has_search_filter"]),
        "roles_without_search_filter_names": sorted(
            r["name"] for r in with_reach if not r["has_search_filter"]
        ),
        "every_role_with_access_has_search_filter": all(
            r["has_search_filter"] for r in with_reach
        ),
        "roles_with_search_time_limit": sum(1 for r in roles if r["has_search_time_limit"]),
        "roles_without_search_time_limit_names": sorted(
            r["name"] for r in with_reach if not r["has_search_time_limit"]
        ),
        "every_role_with_access_has_search_time_limit": all(
            r["has_search_time_limit"] for r in with_reach
        ),
        "roles_that_can_delegate_roles": sorted(
            r["name"] for r in roles if r["can_delegate_roles"]
        ),
        "roles_whose_access_is_inherited_only": sorted(
            r["name"] for r in roles if r["index_access_inherited_only"]
        ),
    }


def collect(
    session: requests.Session,
    host: str,
    audit_indexes: List[str],
    exempt_roles: List[str],
) -> Dict[str, Any]:
    base = host.rstrip("/")
    api_failures: List[Dict[str, str]] = []

    server = {}
    try:
        info = get_json(session, f"{base}/services/server/info", {})
        content = (info.get("entry") or [{}])[0].get("content", {})
        server = {
            "version": content.get("version"),
            "product_type": content.get("product_type"),
            "license_state": content.get("licenseState"),
            "server_name": content.get("serverName"),
            "mode": content.get("mode"),
        }
    except Exception as exc:  # server/info is context, not the evidence itself
        api_failures.append(
            {"operation": "GET /services/server/info", "type": type(exc).__name__, "message": str(exc)}
        )

    # splunkd (and ACS) filter the role list by the CALLER's own role: "if you
    # are assigned the user role, you can only see your own role". Recording the
    # identity that read it is the only way an assessor can tell a complete
    # answer from a silently truncated one.
    caller = {}
    try:
        ctx = get_json(session, f"{base}/services/authentication/current-context", {})
        content = (ctx.get("entry") or [{}])[0].get("content", {})
        caller = {
            "username": content.get("username"),
            "roles": as_list(content.get("roles")),
            "capability_count": len(as_list(content.get("capabilities"))),
        }
    except Exception as exc:
        api_failures.append(
            {
                "operation": "GET /services/authentication/current-context",
                "type": type(exc).__name__,
                "message": str(exc),
            }
        )

    # count=0 returns every role in one call — splunkd's documented convention.
    # ACS on Splunk Cloud pages at 30 by default and caps count at 100, so this
    # habit does not transfer unexamined to the ACS transport.
    data = get_json(session, f"{base}/services/authorization/roles", {"count": 0})
    entries = data.get("entry") or []
    roles = [describe_role(e, audit_indexes, exempt_roles) for e in entries]
    reported_total = ((data.get("paging") or {}).get("total"))

    # Two roll-ups, deliberately, mirroring splunk_index_retention. `summary`
    # covers every role on the deployment and is the completeness view.
    # `audit_scope` covers only the non-exempt roles that can actually reach the
    # named audit indexes, and is the one that speaks to the control: Splunk
    # ships admin / power / splunk-system-role with broad reach by design, and a
    # roll-up that counts them reports a control failure that is not one — the
    # same trap splunk_index_retention hit with _internal and _thefishbucket.
    missing = [n for n in exempt_roles if n not in {r["name"] for r in roles}]
    scope = {
        "audit_indexes_configured": bool(audit_indexes),
        "audit_indexes_named": sorted(audit_indexes),
        "exempt_roles_named": sorted(exempt_roles),
        "exempt_roles_named_but_absent": sorted(missing),
        "roles_exempted": sorted(r["name"] for r in roles if r["exempt"]),
    }
    non_exempt = [r for r in roles if not r["exempt"]]
    scope["non_exempt_roles_evaluated"] = len(non_exempt)
    if audit_indexes:
        in_scope = [r for r in non_exempt if r["can_access_audit_data"]]
        scope["roles_in_scope"] = sorted(r["name"] for r in in_scope)
        scope.update(summarize(in_scope))
        # A scope that assessed nothing must not read as a pass. It is only
        # assessable when audit indexes were named, the role list came back
        # whole, and at least one non-exempt role was actually evaluated.
        scope["scope_is_assessable"] = bool(
            audit_indexes
            and non_exempt
            and (reported_total is None or reported_total == len(roles))
            and not missing
        )
        scope["no_role_has_wildcard_index_access"] = (
            scope["no_role_has_wildcard_index_access"] and scope["scope_is_assessable"]
        )
    else:
        scope["scope_is_assessable"] = False

    return {
        "authenticated_as": caller,
        "role_list_may_be_truncated_note": (
            "splunkd and ACS both filter /authorization/roles by the caller's own "
            "role: an account holding only the `user` role sees only that role. "
            "`authenticated_as` records the identity this evidence was read with, "
            "and `roles_reported_total` is splunkd's own count, so a truncated "
            "read is distinguishable from a deployment that genuinely has few roles."
        ),
        "wildcard_semantics_note": (
            "Index globs follow Splunk's rule that `*` matches only non-internal "
            "indexes; an internal index (`_audit`, `_internal`) is reached only by "
            "a pattern that itself starts with `_`, which is why the built-in "
            "admin role carries both `*` and `_*`. `has_wildcard_index_access` is "
            "true for ANY wildcard pattern regardless of that rule, and every raw "
            "pattern is kept alongside each derived field."
        ),
        "server": server,
        "roles_reported_total": reported_total,
        "roles_returned": len(roles),
        "role_list_complete": reported_total is None or reported_total == len(roles),
        "roles": sorted(roles, key=lambda r: str(r["name"])),
        "summary": summarize(roles),
        "audit_scope": scope,
        "api_failures": api_failures,
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself. The framework's runner +
    # secret resolver will pass resolved values in and this block goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    host = os.environ.get("SPLUNK_HOST", "")
    token = os.environ.get("SPLUNK_TOKEN", "")
    username = os.environ.get("SPLUNK_USERNAME", "")
    password = os.environ.get("SPLUNK_PASSWORD", "")
    target_name = os.environ.get("SPLUNK_TARGET_NAME", "") or host
    verify_ssl = env_flag("SPLUNK_VERIFY_SSL", True)

    if not host:
        report_failure("Missing required env var: SPLUNK_HOST", "bad_config")
        return 1
    if not token and not (username and password):
        report_failure(
            "No Splunk credential: supply SPLUNK_TOKEN, or SPLUNK_USERNAME and SPLUNK_PASSWORD",
            "bad_config",
        )
        return 1

    audit_indexes = csv_env("SPLUNK_AUDIT_INDEXES")
    exempt_roles = csv_env("SPLUNK_EXEMPT_ROLES", "admin,power,splunk-system-role")

    if not verify_ssl:
        # Only reachable when the target explicitly opted out, which the schema
        # restricts to sandboxes. Suppressing the warning keeps it off stderr,
        # whose tail the runner reads as the failure reason. Filtered by message
        # rather than by class so this stays stdlib-only and urllib3 need not be
        # imported (or declared) just to name an exception type.
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    session = build_session(token, username, password, verify_ssl)
    auth_method = "bearer_token" if token else "basic_auth"

    failure: Dict[str, str] = {}
    try:
        result = collect(session, host, audit_indexes, exempt_roles)
    except PermissionError as exc:
        result = {"api_failures": [{"operation": "collect", "type": "PermissionError", "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "not_authorized"}
    except requests.exceptions.RequestException as exc:
        result = {"api_failures": [{"operation": "collect", "type": type(exc).__name__, "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "target_unreachable"}
    except Exception as exc:
        result = {"api_failures": [{"operation": "collect", "type": type(exc).__name__, "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "internal_error"}

    api_failures = result.get("api_failures", [])
    evidence = {
        "target_name": target_name,
        "splunk_host": host,
        "auth_method": auth_method,
        "tls_verified": verify_ssl,
        "collected_at": current_timestamp(),
        "partial_failure": bool(api_failures) and not failure,
        **result,
    }

    output_path = output_dir / f"splunk_role_index_access_{sanitize_for_filename(target_name)}.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)
    # Reported AFTER the success line above: the runner reads the TAIL of stderr
    # as the failure reason, so whichever line is logged last wins. report_failure
    # does the error-level logging itself — logging the reason here as well puts
    # it on stderr twice (tests/test_failure_reporting_contract.py enforces this).
    if failure:
        report_failure(failure["reason"], failure["code"])
        return 1
    if api_failures:
        report_failure(
            "; ".join(f"{f['operation']}: {f['message']}" for f in api_failures),
            "partial_failure",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
