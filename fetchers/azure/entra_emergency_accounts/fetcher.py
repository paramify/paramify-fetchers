#!/usr/bin/env python3
"""Emergency (break-glass) accounts: their Conditional Access MFA exclusions, sign-in methods, last use and the alert rules that name them, and every other user excluded from an MFA policy."""

import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import (  # noqa: E402
    SI_API,
    SI_PREVIEW_API,
    ArmError,
    discover_workspaces,
    parse_time,
    run_subscription,
)

NAME = "azure_entra_emergency_accounts"
ACCOUNTS_ENV = "ENTRA_EMERGENCY_ACCOUNTS"
SUBSCRIPTION_API = "2022-12-01"
LOG_ALERT_API = "2023-12-01"
USER_SELECT = "id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime"
ODATA_GROUP = "#microsoft.graph.group"
STATE_ENABLED = "enabled"
MFA_CONTROL = "mfa"
GUESTS = "GuestsOrExternalUsers"
GUEST_FILTER = "userType eq 'Guest'"
# The 403 Graph sends a tenant with no Entra ID P1/P2.
NOT_LICENSED_MARKER = "nonpremiumtenant"
# Graph's empty sign-in time is 0001-01-01T00:00:00Z.
EARLIEST_REAL_YEAR = 2000
# userRegistrationDetails.methodsRegistered values bound to the sign-in origin, so a look-alike site can't relay them.
PHISHING_RESISTANT_METHODS = frozenset({
    "fido2securitykey", "windowshelloforbusiness", "passkeydevicebound", "passkeydeviceboundauthenticator",
    "passkeydeviceboundwindowshello", "macossecureenclavekey",
})
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

CONFIGURED = "configured"
CANDIDATES = "candidates"
READ = "read"
NOT_LICENSED = "not_licensed"
NOT_READ = "not_read"

logger = logging.getLogger(NAME)


def named_accounts() -> List[str]:
    raw = os.environ.get(ACCOUNTS_ENV) or ""
    unique = {a.strip().lower(): a.strip() for a in raw.replace(";", ",").split(",") if a.strip()}
    return [unique[k] for k in sorted(unique)]


def read_status(collector, before: int) -> str:
    """read, not_licensed (no Entra ID P1/P2) or not_read, from the failures since `before`."""
    failures = collector.failures[before:]
    if not failures:
        return READ
    if any(NOT_LICENSED_MARKER in (f.get("message") or "").lower() for f in failures):
        return NOT_LICENSED
    return NOT_READ


def _signed_in_at(value) -> Optional[str]:
    parsed = parse_time(value)
    return value if parsed is not None and parsed.year >= EARLIEST_REAL_YEAR else None


# --- Conditional Access ---

def mfa_policy(policy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """An enforced policy that requires MFA or an authentication strength, with who it excludes; else None."""
    grant = policy.get("grantControls") or {}
    controls = {str(c).lower() for c in grant.get("builtInControls") or []}
    if policy.get("state") != STATE_ENABLED or (MFA_CONTROL not in controls and not grant.get("authenticationStrength")):
        return None
    users = (policy.get("conditions") or {}).get("users") or {}
    excluded = users.get("excludeUsers") or []
    return {
        "id": policy.get("id"),
        "display_name": policy.get("displayName"),
        "exclude_users": sorted(u for u in excluded if u != GUESTS),
        "exclude_groups": sorted(users.get("excludeGroups") or []),
        "exclude_roles": sorted(users.get("excludeRoles") or []),
        "excludes_guests_or_external_users": GUESTS in excluded or bool(users.get("excludeGuestsOrExternalUsers")),
    }


def excluded_by(policies: List[dict], direct: Dict[str, Optional[dict]], groups: Dict[str, List[dict]],
                roles: Dict[str, List[dict]], guests: List[dict]) -> Dict[str, List[dict]]:
    """Each user id, and the MFA policies that exclude it: directly, through a group, a role or as a guest."""
    out: Dict[str, List[dict]] = {}

    def add(user, policy, via, via_id):
        uid = (user or {}).get("id")
        if uid:
            out.setdefault(uid.lower(), []).append(
                {"policy_id": policy["id"], "policy": policy["display_name"], "via": via, "via_id": via_id})

    for p in policies:
        for uid in p["exclude_users"]:
            add(direct.get(uid.lower()), p, "user", uid)
        for gid in p["exclude_groups"]:
            for u in groups.get(gid.lower()) or []:
                add(u, p, "group", gid)
        for rid in p["exclude_roles"]:
            for u in roles.get(rid.lower()) or []:
                add(u, p, "role", rid)
        if p["excludes_guests_or_external_users"]:
            for u in guests:
                add(u, p, "guests_or_external_users", None)
    for entries in out.values():
        entries.sort(key=lambda e: ((e["policy"] or "").lower(), e["policy_id"] or "", e["via"], e["via_id"] or ""))
    return out


# --- alert rules ---

def sentinel_rule(raw: Dict[str, Any], workspace: str) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    return {"source": "sentinel", "id": raw.get("id"), "display_name": props.get("displayName"),
            "kind": raw.get("kind"), "workspace": workspace, "enabled": props.get("enabled") is True,
            "_query": props.get("query") or ""}


def log_alert_rule(raw: Dict[str, Any]) -> Dict[str, Any]:
    props = raw.get("properties") or {}
    queries = [c.get("query") or "" for c in (props.get("criteria") or {}).get("allOf") or []]
    return {"source": "azure_monitor", "id": raw.get("id"), "display_name": props.get("displayName") or raw.get("name"),
            "kind": raw.get("kind"), "workspace": None, "enabled": props.get("enabled") is True,
            "_query": "\n".join(queries)}


def naming_rules(user: dict, rules: List[dict]) -> List[dict]:
    """Enabled rules whose query names the account by its user principal name or object id."""
    needles = [n.lower() for n in (user.get("userPrincipalName"), user.get("id")) if n]
    return [
        {k: r[k] for k in ("source", "id", "display_name", "kind", "workspace")}
        for r in rules if r["enabled"] and any(n in r["_query"].lower() for n in needles)
    ]


# --- records ---

def _registration(details: Optional[dict]) -> dict:
    methods = sorted(details.get("methodsRegistered") or []) if details else None
    return {
        "methods_registered": methods,
        "mfa_registered": details.get("isMfaRegistered") if details else None,
        "phishing_resistant_method_registered": (
            any(m.lower() in PHISHING_RESISTANT_METHODS for m in methods) if methods is not None else None),
    }


def account_record(named_as: Optional[str], user: dict, exclusions: List[dict], mfa_policies: int,
                   activity_ok: bool, registration: Optional[dict], registration_ok: bool,
                   rules: List[dict], rules_ok: bool, now: datetime) -> dict:
    activity = user.get("signInActivity") or {}
    last = _signed_in_at(activity.get("lastSuccessfulSignInDateTime"))
    parsed = parse_time(last)
    excluded_policies = {e["policy_id"] for e in exclusions}
    watching = naming_rules(user, rules) if rules_ok else None
    return {
        "named_as": named_as,
        "id": user.get("id"),
        "display_name": user.get("displayName"),
        "user_principal_name": user.get("userPrincipalName"),
        "user_type": user.get("userType"),
        "account_enabled": user.get("accountEnabled"),
        "created_date_time": user.get("createdDateTime"),
        "last_successful_sign_in": last if activity_ok else None,
        "last_sign_in_attempt": _signed_in_at(activity.get("lastSignInDateTime")) if activity_ok else None,
        "days_since_last_successful_sign_in": (now - parsed).days if activity_ok and parsed else None,
        **(_registration(registration) if registration_ok else _registration(None)),
        "mfa_policy_exclusions": exclusions,
        "excluded_from_an_mfa_policy": bool(exclusions),
        "excluded_from_every_mfa_policy": bool(mfa_policies) and len(excluded_policies) == mfa_policies,
        "alert_rules_naming_account": watching,
        "monitored": bool(watching) if watching is not None else None,
    }


def excluded_user_record(user: dict, exclusions: List[dict]) -> dict:
    return {
        "id": user.get("id"),
        "display_name": user.get("displayName"),
        "user_principal_name": user.get("userPrincipalName"),
        "user_type": user.get("userType"),
        "account_enabled": user.get("accountEnabled"),
        "mfa_policy_exclusions": exclusions,
    }


def summarize(accounts: List[dict], not_found: List[str], others: List[dict], policies: Optional[List[dict]],
              rules: Optional[List[dict]], workspaces: Optional[int], status: Dict[str, str], source: str,
              named: int) -> dict:
    exclusions_ok = status["policies"] == READ and status["exclusions"] == READ and status["accounts"] == READ
    rules_ok = status["alert_rules"] == READ
    registration_ok = status["registration_details"] == READ
    enabled_excluded = [a for a in accounts if a["account_enabled"] and a["mfa_policy_exclusions"]]
    enabled_others = [u for u in others if u["account_enabled"]]
    approved = source == CONFIGURED
    unwatched = [a for a in enabled_excluded if not a["monitored"]] if rules_ok else None
    not_listed = len(enabled_others) + (0 if approved else len(enabled_excluded))

    def known(value, ok=True):
        return value if exclusions_ok and ok else None

    return {
        "emergency_accounts_source": source,
        "emergency_accounts_named": named,
        "conditional_access_readable": status["policies"] == READ,
        "exclusions_readable": status["exclusions"] == READ and status["accounts"] == READ,
        "alert_rules_readable": rules_ok,
        "user_sign_in_activity": status["user_sign_in_activity"],
        "registration_details": status["registration_details"],
        "enforced_mfa_policies": len(policies) if policies is not None else None,
        "sentinel_workspaces_checked": workspaces if rules_ok else None,
        "alert_rules_checked": len(rules) if rules_ok and rules is not None else None,
        "emergency_accounts": len(accounts) if status["accounts"] == READ else None,
        "emergency_accounts_not_found": len(not_found) if status["accounts"] == READ else None,
        "emergency_accounts_enabled": sum(1 for a in accounts if a["account_enabled"]) if status["accounts"] == READ else None,
        "emergency_accounts_excluded_from_every_mfa_policy": known(
            sum(1 for a in accounts if a["excluded_from_every_mfa_policy"])),
        "emergency_accounts_with_phishing_resistant_method": (
            sum(1 for a in accounts if a["phishing_resistant_method_registered"])
            if registration_ok and status["accounts"] == READ else None),
        "emergency_accounts_monitored": (
            sum(1 for a in accounts if a["monitored"]) if rules_ok and status["accounts"] == READ else None),
        "users_excluded_from_mfa": known(len(enabled_excluded) + len(enabled_others)),
        "excluded_users_not_emergency_accounts": known(not_listed),
        "emergency_accounts_excluded_without_alert": known(
            len(unwatched) if unwatched is not None else None, rules_ok),
        "excluded_users_not_monitored_emergency_accounts": known(
            not_listed + (len(unwatched) if approved and unwatched is not None else 0), rules_ok),
    }


# --- collection ---

def _get_user(client, path: str) -> Optional[dict]:
    """A user, or None when the directory has no such user."""
    try:
        return client.graph_get(path)
    except ArmError as exc:
        if exc.status == 404:
            return None
        raise


def _user_path(ref: str, select: str) -> str:
    return f"/users/{quote(ref, safe='@')}?$select={select}"


def _members(client, collector, operation: str, path: str) -> Optional[List[dict]]:
    """A member listing, [] for a group or role the directory no longer has."""
    def read():
        try:
            return client.graph_list(path)
        except ArmError as exc:
            if exc.status == 404:
                return []
            raise
    return collector.guard(operation, read, default=None)


def _group_users(client, collector, gid: str) -> Optional[List[dict]]:
    return _members(client, collector, f"graph.groups({gid}).transitiveMembers.get",
                    f"/groups/{gid}/transitiveMembers/microsoft.graph.user?$select={USER_SELECT}")


def _resolve_exclusions(client, collector, policies: List[dict]) -> tuple:
    """(direct users, group users, role users, guests, readable) for every exclusion of the MFA policies."""
    ok = True
    direct: Dict[str, Optional[dict]] = {}
    for uid in sorted({u.lower() for p in policies for u in p["exclude_users"] if _GUID.match(u)}):
        user = collector.guard(f"graph.users({uid}).get", lambda uid=uid: _get_user(client, _user_path(uid, USER_SELECT)),
                               default=False)
        ok = ok and user is not False
        direct[uid] = user or None
    groups: Dict[str, List[dict]] = {}
    for gid in sorted({g.lower() for p in policies for g in p["exclude_groups"]}):
        members = _group_users(client, collector, gid)
        ok = ok and members is not None
        groups[gid] = members or []
    roles: Dict[str, List[dict]] = {}
    wanted = {r.lower() for p in policies for r in p["exclude_roles"]}
    if wanted:
        active = collector.guard("graph.directoryRoles.get",
                                 lambda: client.graph_list("/directoryRoles?$select=id,displayName,roleTemplateId"))
        ok = ok and active is not None
        for role in active or []:
            template = (role.get("roleTemplateId") or "").lower()
            if template not in wanted:
                continue
            base = f"/directoryRoles/{role.get('id')}/members"
            users = _members(client, collector, f"graph.directoryRoles({role.get('displayName')}).members.get",
                             f"{base}/microsoft.graph.user?$select={USER_SELECT}")
            nested = _members(client, collector, f"graph.directoryRoles({role.get('displayName')}).groups.get",
                              f"{base}/microsoft.graph.group?$select=id")
            ok = ok and users is not None and nested is not None
            held = list(users or [])
            for g in nested or []:
                inner = _group_users(client, collector, (g.get("id") or "").lower())
                ok = ok and inner is not None
                held.extend(inner or [])
            roles[template] = held
    guests: List[dict] = []
    if any(p["excludes_guests_or_external_users"] for p in policies):
        listed = collector.guard("graph.users.get(guests)", lambda: client.graph_list(
            f"/users?$filter={quote(GUEST_FILTER)}&$select={USER_SELECT}&$top=999"))
        ok = ok and listed is not None
        guests = listed or []
    return direct, groups, roles, guests, ok


def _alert_rules(client, collector, subscription_id: str) -> tuple:
    """(rules, Sentinel workspaces read, readable); a preview listing that fails is logged, not failed."""
    before = len(collector.failures)
    rules: Dict[str, dict] = {}
    workspaces = [w for w in discover_workspaces(client, subscription_id, collector) if w["sentinel_onboarded"]]
    for ws in workspaces:
        path = f"{ws['id']}/providers/Microsoft.SecurityInsights/alertRules"
        for raw in collector.guard(f"securityinsights.alertRules.list({ws['name']})",
                                   lambda path=path: client.list(path, SI_API), default=[]):
            rules[(raw.get("id") or "").lower()] = sentinel_rule(raw, ws["name"])
        try:
            preview = client.list(path, SI_PREVIEW_API)
        except Exception as exc:  # noqa: BLE001 — NRT rules may then be missed; say so, don't fail the run
            logger.warning("alertRules at %s failed for %s (%s); NRT rules may be missing", SI_PREVIEW_API, ws["name"], exc)
            preview = []
        for raw in preview:
            rules.setdefault((raw.get("id") or "").lower(), sentinel_rule(raw, ws["name"]))
    for raw in collector.guard("insights.scheduledQueryRules.list", lambda: client.list(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Insights/scheduledQueryRules", LOG_ALERT_API),
            default=[]):
        rules[(raw.get("id") or "").lower()] = log_alert_rule(raw)
    ordered = sorted(rules.values(), key=lambda r: (r["source"], (r["display_name"] or "").lower(), r["id"] or ""))
    return ordered, len(workspaces), len(collector.failures) == before


def _account_detail(client, collector, user: dict) -> tuple:
    """(user with sign-in activity, activity status, registration details, registration status)."""
    uid = str(user.get("id") or "")
    before = len(collector.failures)
    full = collector.guard(f"graph.users({uid}).get(signInActivity)",
                           lambda: _get_user(client, _user_path(uid, f"{USER_SELECT},signInActivity")))
    activity = read_status(collector, before)
    before = len(collector.failures)
    details = collector.guard(f"graph.userRegistrationDetails({uid}).get", lambda: _get_user(
        client, f"/reports/authenticationMethods/userRegistrationDetails/{uid}"))
    return {**user, **(full or {})}, activity, details, read_status(collector, before)


def _worst(statuses: List[str]) -> str:
    for status in (NOT_READ, NOT_LICENSED):
        if status in statuses:
            return status
    return READ


def collect(client, subscription_id: str, collector) -> tuple:
    now = datetime.now(timezone.utc)
    named = named_accounts()
    source = CONFIGURED if named else CANDIDATES
    status = dict.fromkeys(("policies", "exclusions", "accounts", "alert_rules"), NOT_READ)
    status.update(user_sign_in_activity=NOT_READ, registration_details=NOT_READ)

    subscription = collector.guard("subscriptions.get", lambda: client.get(
        f"/subscriptions/{subscription_id}", SUBSCRIPTION_API), default=None) or {}
    tenant_id = subscription.get("tenantId")
    # Graph reads the credential's tenant; in another one (Azure Lighthouse) every account would read missing.
    orgs = collector.guard("graph.organization.get", lambda: client.graph_list("/organization?$select=id")) or [{}]
    graph_tenant = (orgs[0].get("id") or "").lower()
    if tenant_id and graph_tenant and graph_tenant != tenant_id.lower():
        collector.record("graph.organization.get", RuntimeError(
            f"Microsoft Graph is signed in to tenant {graph_tenant}, but the subscription belongs to tenant "
            f"{tenant_id.lower()}; sign in to the subscription's tenant"))
        return _results(tenant_id, source, [], [], [], None, now), summarize(
            [], [], [], None, None, None, status, source, len(named))

    before = len(collector.failures)
    raw_policies = collector.guard("graph.identity.conditionalAccess.policies.get",
                                   lambda: client.graph_list("/identity/conditionalAccess/policies"))
    status["policies"] = READ if raw_policies is not None else NOT_READ
    if raw_policies is None and read_status(collector, before) == NOT_LICENSED:
        status["policies"] = NOT_LICENSED
    policies = [p for p in (mfa_policy(r) for r in raw_policies or []) if p is not None]
    policies.sort(key=lambda p: ((p["display_name"] or "").lower(), p["id"] or ""))

    direct, groups, roles, guests, resolved = _resolve_exclusions(client, collector, policies)
    status["exclusions"] = READ if resolved and status["policies"] == READ else NOT_READ
    exclusions = excluded_by(policies, direct, groups, roles, guests)
    users: Dict[str, dict] = {}
    for u in [*direct.values(), *(m for ms in groups.values() for m in ms),
              *(m for ms in roles.values() for m in ms), *guests]:
        if u and u.get("id"):
            users.setdefault(u["id"].lower(), u)

    accounts_in: List[tuple] = []
    not_found: List[str] = []
    ok = True
    for ref in named:
        user = collector.guard(f"graph.users({ref}).get", lambda ref=ref: _get_user(client, _user_path(ref, USER_SELECT)),
                               default=False)
        if user is False:
            ok = False
        elif user is None:
            not_found.append(ref)
        else:
            accounts_in.append((ref, user))
    if not named:
        for uid, user in sorted(users.items()):
            if user.get("accountEnabled") and policies and len({e["policy_id"] for e in exclusions.get(uid, [])}) == len(policies):
                accounts_in.append((None, user))
    status["accounts"] = READ if ok else NOT_READ

    rules, workspaces, rules_ok = _alert_rules(client, collector, subscription_id)
    status["alert_rules"] = READ if rules_ok else NOT_READ

    accounts, activity, registration = [], [], []
    for ref, user in accounts_in:
        full, act, details, reg = _account_detail(client, collector, user)
        activity.append(act)
        registration.append(reg)
        accounts.append(account_record(
            ref, full, exclusions.get((user.get("id") or "").lower(), []), len(policies), act == READ,
            details, reg == READ, rules, rules_ok, now))
    status["user_sign_in_activity"] = _worst(activity) if accounts_in else READ
    status["registration_details"] = _worst(registration) if accounts_in else READ
    accounts.sort(key=lambda a: ((a["user_principal_name"] or "").lower(), a["id"] or ""))

    account_ids = {(a["id"] or "").lower() for a in accounts}
    others = sorted(
        (excluded_user_record(users[uid], entries) for uid, entries in exclusions.items()
         if uid not in account_ids and uid in users),
        key=lambda u: ((u["user_principal_name"] or "").lower(), u["id"] or ""),
    )
    logger.info("Collected %d emergency account(s) (%s), %d other excluded user(s), %d MFA policy/policies, %d alert rule(s)",
                len(accounts), source, len(others), len(policies), len(rules))
    return (_results(tenant_id, source, accounts, not_found, others, policies if status["policies"] == READ else None, now),
            summarize(accounts, not_found, others, policies if status["policies"] == READ else None,
                      rules, workspaces, status, source, len(named)))


def _results(tenant_id, source: str, accounts: List[dict], not_found: List[str], others: List[dict],
             policies: Optional[List[dict]], now: datetime) -> dict:
    return {
        "tenant_id": tenant_id,
        "emergency_accounts_source": source,
        "emergency_accounts": accounts,
        "emergency_accounts_not_found": not_found,
        "other_users_excluded_from_mfa": others,
        "mfa_policies": policies,
        "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect)


if __name__ == "__main__":
    sys.exit(main())
