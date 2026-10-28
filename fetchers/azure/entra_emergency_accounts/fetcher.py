#!/usr/bin/env python3
"""Emergency (break-glass) accounts: their Conditional Access MFA exclusions, sign-in methods, last use and the alert rules that name them, and every other user an MFA policy excludes."""

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
STATE_ENABLED = "enabled"
MFA_CONTROL = "mfa"
ALL = "all"
GUESTS = "GuestsOrExternalUsers"
GUEST_FILTER = "userType eq 'Guest'"
# guestOrExternalUserTypes that hold users of type Guest; an include naming both, for every tenant, covers them all.
GUEST_USER_TYPES = frozenset({"internalguest", "b2bcollaborationguest"})
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


def _lower(values) -> List[str]:
    return sorted({str(v).lower() for v in values or [] if v})


# --- Conditional Access ---

def narrowing_conditions(conditions: Dict[str, Any]) -> List[str]:
    """The conditions that limit when a policy applies; a policy with any doesn't count as covering a user."""
    found = []
    if any(str(t).lower() != ALL for t in conditions.get("clientAppTypes") or []):
        found.append("client_app_types")
    for key, name in (("signInRiskLevels", "sign_in_risk"), ("userRiskLevels", "user_risk"),
                      ("servicePrincipalRiskLevels", "service_principal_risk"), ("insiderRiskLevels", "insider_risk")):
        if conditions.get(key):
            found.append(name)
    platforms = conditions.get("platforms") or {}
    if any(str(p).lower() != ALL for p in platforms.get("includePlatforms") or []) or platforms.get("excludePlatforms"):
        found.append("platforms")
    locations = conditions.get("locations") or {}
    if any(str(loc).lower() != ALL for loc in locations.get("includeLocations") or []) or locations.get("excludeLocations"):
        found.append("locations")
    if (conditions.get("devices") or {}).get("deviceFilter"):
        found.append("device_filter")
    if conditions.get("authenticationFlows"):
        found.append("authentication_flows")
    return found


def _includes_every_guest(users: Dict[str, Any]) -> bool:
    if GUESTS in (users.get("includeUsers") or []):
        return True
    spec = users.get("includeGuestsOrExternalUsers") or {}
    types = {t.strip().lower() for t in str(spec.get("guestOrExternalUserTypes") or "").split(",")}
    tenants = (spec.get("externalTenants") or {}).get("membershipKind") or ALL
    return bool(spec) and GUEST_USER_TYPES <= types and str(tenants).lower() == ALL


def mfa_policy(policy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """An enforced policy that requires MFA or an authentication strength, with who it includes and excludes; else None."""
    grant = policy.get("grantControls") or {}
    controls = {str(c).lower() for c in grant.get("builtInControls") or []}
    if policy.get("state") != STATE_ENABLED or (MFA_CONTROL not in controls and not grant.get("authenticationStrength")):
        return None
    conditions = policy.get("conditions") or {}
    users = conditions.get("users") or {}
    included = users.get("includeUsers") or []
    excluded = users.get("excludeUsers") or []
    all_apps = ALL in _lower((conditions.get("applications") or {}).get("includeApplications"))
    narrowing = narrowing_conditions(conditions)
    return {
        "id": policy.get("id"),
        "display_name": policy.get("displayName"),
        "includes_all_users": ALL in _lower(included),
        "include_users": sorted(u for u in included if _GUID.match(str(u))),
        "include_groups": sorted(users.get("includeGroups") or []),
        "include_roles": sorted(users.get("includeRoles") or []),
        "includes_every_guest": _includes_every_guest(users),
        "exclude_users": sorted(u for u in excluded if _GUID.match(str(u))),
        "exclude_groups": sorted(users.get("excludeGroups") or []),
        "exclude_roles": sorted(users.get("excludeRoles") or []),
        "excludes_guests_or_external_users": GUESTS in excluded or bool(users.get("excludeGuestsOrExternalUsers")),
        "targets_all_applications": all_apps,
        "narrowing_conditions": narrowing,
        "counts_for_coverage": all_apps and not narrowing,
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


def covered(user: dict, excluded_from: set, policies: List[dict], included: Dict[str, Optional[set]]) -> Optional[bool]:
    """True if a policy that counts for coverage includes the user and doesn't exclude it; None if that rests on a failed read."""
    uid = (user.get("id") or "").lower()
    guest = str(user.get("userType") or "").lower() == "guest"
    unknown = False
    for p in policies:
        if not p["counts_for_coverage"] or p["id"] in excluded_from:
            continue
        if p["includes_all_users"] or uid in _lower(p["include_users"]) or (guest and p["includes_every_guest"]):
            return True
        members = included.get(p["id"], set())
        if members is None:
            unknown = True
        elif uid in members:
            return True
    return None if unknown else False


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


def _names(query: str, needle: str) -> bool:
    # Whole names only: "bg@contoso.com" must not match inside "xbg@contoso.com".
    return re.search(rf"(?<![\w.+%-]){re.escape(needle)}(?![\w.-])", query, re.I) is not None


def naming_rules(user: dict, rules: List[dict]) -> List[dict]:
    """Enabled rules whose query names the account by its user principal name or object id."""
    needles = [n for n in (user.get("userPrincipalName"), user.get("id")) if n]
    return [
        {k: r[k] for k in ("source", "id", "display_name", "kind", "workspace")}
        for r in rules if r["enabled"] and any(_names(r["_query"], n) for n in needles)
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


def _exclusion_fields(exclusions: Optional[List[dict]], all_users_policies: set,
                      is_covered: Optional[bool]) -> dict:
    """Null throughout when the exclusions weren't read, so an unread list never reads as 'not excluded'."""
    if exclusions is None:
        return {"mfa_policy_exclusions": None, "excluded_from_an_mfa_policy": None,
                "excluded_from_every_all_users_mfa_policy": None, "covered_by_an_mfa_policy": None,
                "excluded_from_mfa": None}
    from_policies = {e["policy_id"] for e in exclusions}
    return {
        "mfa_policy_exclusions": exclusions,
        "excluded_from_an_mfa_policy": bool(exclusions),
        "excluded_from_every_all_users_mfa_policy": bool(all_users_policies) and all_users_policies <= from_policies,
        "covered_by_an_mfa_policy": is_covered,
        "excluded_from_mfa": (None if is_covered is None else not is_covered) if exclusions else False,
    }


def account_record(named_as: Optional[str], user: dict, exclusion_fields: dict, activity_ok: bool,
                   registration: Optional[dict], registration_ok: bool, rules: List[dict], rules_ok: bool,
                   now: datetime) -> dict:
    activity = user.get("signInActivity") or {}
    last = _signed_in_at(activity.get("lastSuccessfulSignInDateTime"))
    parsed = parse_time(last)
    watching = naming_rules(user, rules) if rules_ok else None
    return {
        "named_as": named_as,
        "id": user.get("id"),
        "display_name": user.get("displayName"),
        "user_principal_name": user.get("userPrincipalName"),
        "user_type": user.get("userType"),
        "account_enabled": user.get("accountEnabled"),
        "created_date_time": user.get("createdDateTime"),
        "sign_in_activity_read": activity_ok,
        "last_successful_sign_in": last if activity_ok else None,
        "last_sign_in_attempt": _signed_in_at(activity.get("lastSignInDateTime")) if activity_ok else None,
        "days_since_last_successful_sign_in": (now - parsed).days if activity_ok and parsed else None,
        **(_registration(registration) if registration_ok else _registration(None)),
        **exclusion_fields,
        "alert_rules_naming_account": watching,
        "monitored": bool(watching) if watching is not None else None,
    }


def excluded_user_record(user: dict, exclusion_fields: dict) -> dict:
    return {
        "id": user.get("id"),
        "display_name": user.get("displayName"),
        "user_principal_name": user.get("userPrincipalName"),
        "user_type": user.get("userType"),
        "account_enabled": user.get("accountEnabled"),
        **{k: exclusion_fields[k] for k in ("mfa_policy_exclusions", "excluded_from_an_mfa_policy",
                                            "covered_by_an_mfa_policy", "excluded_from_mfa")},
    }


def summarize(accounts: List[dict], not_found: List[str], others: List[dict], policies: Optional[List[dict]],
              rules: Optional[List[dict]], workspaces: Optional[int], status: Dict[str, str], source: str,
              named: int) -> dict:
    accounts_ok = status["accounts"] == READ
    exclusions_ok = status["policies"] == READ and status["exclusions"] == READ and accounts_ok
    rules_ok = status["alert_rules"] == READ
    registration_ok = status["registration_details"] == READ
    approved = source == CONFIGURED
    population = [r for r in [*accounts, *others] if r["account_enabled"] and r["excluded_from_an_mfa_policy"]]
    coverage_known = exclusions_ok and all(r["excluded_from_mfa"] is not None for r in population)
    out_accounts = [a for a in accounts if a["account_enabled"] and a["excluded_from_mfa"]]
    out_others = [u for u in others if u["account_enabled"] and u["excluded_from_mfa"]]
    not_listed = len(out_others) + (0 if approved else len(out_accounts))
    unwatched = len([a for a in out_accounts if not a["monitored"]]) if approved else 0

    def count(value, ok=True):
        return value if ok else None

    return {
        "emergency_accounts_source": source,
        "emergency_accounts_named": named,
        "conditional_access_readable": status["policies"] == READ,
        "exclusions_readable": status["exclusions"] == READ and accounts_ok,
        "coverage_readable": status["coverage"] == READ,
        "alert_rules_readable": rules_ok,
        "user_sign_in_activity": status["user_sign_in_activity"],
        "registration_details": status["registration_details"],
        "enforced_mfa_policies": len(policies) if policies is not None else None,
        "enforced_mfa_policies_for_all_users": (
            sum(1 for p in policies if p["includes_all_users"]) if policies is not None else None),
        "mfa_policies_counting_for_coverage": (
            sum(1 for p in policies if p["counts_for_coverage"]) if policies is not None else None),
        "sentinel_workspaces_checked": workspaces if rules_ok else None,
        "alert_rules_checked": len(rules) if rules_ok and rules is not None else None,
        "emergency_accounts": count(len(accounts), accounts_ok),
        "emergency_accounts_not_found": count(len(not_found), accounts_ok),
        "emergency_accounts_enabled": count(sum(1 for a in accounts if a["account_enabled"]), accounts_ok),
        "emergency_accounts_excluded_from_every_all_users_mfa_policy": count(
            sum(1 for a in accounts if a["excluded_from_every_all_users_mfa_policy"]), exclusions_ok),
        "emergency_accounts_with_phishing_resistant_method": count(
            sum(1 for a in accounts if a["phishing_resistant_method_registered"]), registration_ok and accounts_ok),
        "emergency_accounts_monitored": count(sum(1 for a in accounts if a["monitored"]), rules_ok and accounts_ok),
        "users_excluded_from_an_mfa_policy": count(len(population), exclusions_ok),
        "users_excluded_from_mfa": count(len(out_accounts) + len(out_others), coverage_known),
        "excluded_users_not_emergency_accounts": count(not_listed, coverage_known),
        "emergency_accounts_excluded_without_alert": count(
            len([a for a in out_accounts if not a["monitored"]]), coverage_known and rules_ok),
        "excluded_users_not_monitored_emergency_accounts": count(not_listed + unwatched, coverage_known and rules_ok),
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


class Directory:
    """Group, role and guest membership reads, each made once; None marks a read that failed."""

    def __init__(self, client, collector):
        self.client, self.collector = client, collector
        self.users: Dict[str, dict] = {}
        self._groups: Dict[str, Optional[List[dict]]] = {}
        self._roles: Dict[str, Optional[List[dict]]] = {}
        self._active: Optional[List[dict]] = None
        self._active_read = False
        self._guests: Optional[List[dict]] = None
        self._guests_read = False

    def _keep(self, users: Optional[List[dict]]) -> Optional[List[dict]]:
        for u in users or []:
            if u.get("id"):
                self.users.setdefault(u["id"].lower(), u)
        return users

    def _members(self, operation: str, path: str) -> Optional[List[dict]]:
        """A member listing, [] for a group or role the directory no longer has."""
        def read():
            try:
                return self.client.graph_list(path)
            except ArmError as exc:
                if exc.status == 404:
                    return []
                raise
        return self.collector.guard(operation, read, default=None)

    def user(self, uid: str):
        """The user, None if the directory has none, or False if the read failed."""
        found = self.collector.guard(f"graph.users({uid}).get",
                                     lambda: _get_user(self.client, _user_path(uid, USER_SELECT)), default=False)
        if found:
            self._keep([found])
        return found

    def group(self, gid: str) -> Optional[List[dict]]:
        gid = gid.lower()
        if gid not in self._groups:
            self._groups[gid] = self._keep(self._members(
                f"graph.groups({gid}).transitiveMembers.get",
                f"/groups/{gid}/transitiveMembers/microsoft.graph.user?$select={USER_SELECT}"))
        return self._groups[gid]

    def role(self, template: str) -> Optional[List[dict]]:
        """Users holding the role now, directly or through a role-assignable group; [] if it isn't activated."""
        template = template.lower()
        if template in self._roles:
            return self._roles[template]
        if not self._active_read:
            self._active_read = True
            self._active = self.collector.guard("graph.directoryRoles.get", lambda: self.client.graph_list(
                "/directoryRoles?$select=id,displayName,roleTemplateId"))
        held: Optional[List[dict]] = None
        if self._active is not None:
            held = []
            for role in self._active:
                if (role.get("roleTemplateId") or "").lower() != template:
                    continue
                base = f"/directoryRoles/{role.get('id')}/members"
                users = self._members(f"graph.directoryRoles({role.get('displayName')}).members.get",
                                      f"{base}/microsoft.graph.user?$select={USER_SELECT}")
                nested = self._members(f"graph.directoryRoles({role.get('displayName')}).groups.get",
                                       f"{base}/microsoft.graph.group?$select=id")
                inner = [self.group(g.get("id") or "") for g in nested or []]
                if users is None or nested is None or any(i is None for i in inner):
                    held = None
                    break
                held.extend(self._keep(users) or [])
                for i in inner:
                    held.extend(i or [])
        self._roles[template] = held
        return held

    def guests(self) -> Optional[List[dict]]:
        if not self._guests_read:
            self._guests_read = True
            self._guests = self._keep(self.collector.guard("graph.users.get(guests)", lambda: self.client.graph_list(
                f"/users?$filter={quote(GUEST_FILTER)}&$select={USER_SELECT}&$top=999")))
        return self._guests


def _resolve_exclusions(directory: Directory, policies: List[dict]) -> tuple:
    """(direct users, group users, role users, guests, readable) for every exclusion of the MFA policies."""
    ok = True
    direct: Dict[str, Optional[dict]] = {}
    for uid in sorted({u.lower() for p in policies for u in p["exclude_users"]}):
        user = directory.user(uid)
        ok = ok and user is not False
        direct[uid] = user or None
    groups: Dict[str, List[dict]] = {}
    for gid in sorted({g.lower() for p in policies for g in p["exclude_groups"]}):
        members = directory.group(gid)
        ok = ok and members is not None
        groups[gid] = members or []
    roles: Dict[str, List[dict]] = {}
    for rid in sorted({r.lower() for p in policies for r in p["exclude_roles"]}):
        held = directory.role(rid)
        ok = ok and held is not None
        roles[rid] = held or []
    guests: List[dict] = []
    if any(p["excludes_guests_or_external_users"] for p in policies):
        listed = directory.guests()
        ok = ok and listed is not None
        guests = listed or []
    return direct, groups, roles, guests, ok


def _resolve_includes(directory: Directory, policies: List[dict]) -> Dict[str, Optional[set]]:
    """The user ids each covering policy includes through groups and roles; None for a policy whose read failed."""
    out: Dict[str, Optional[set]] = {}
    for p in policies:
        if not p["counts_for_coverage"] or p["includes_all_users"]:
            continue
        reads = [directory.group(g) for g in p["include_groups"]] + [directory.role(r) for r in p["include_roles"]]
        out[p["id"]] = None if any(r is None for r in reads) else {
            (u.get("id") or "").lower() for r in reads for u in r or []}
    return out


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
    status = dict.fromkeys(("policies", "exclusions", "coverage", "accounts", "alert_rules",
                            "user_sign_in_activity", "registration_details"), NOT_READ)

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
    all_users_policies = {p["id"] for p in policies if p["includes_all_users"]}

    directory = Directory(client, collector)
    direct, groups, roles, guests, resolved = _resolve_exclusions(directory, policies)
    status["exclusions"] = READ if resolved and status["policies"] == READ else NOT_READ
    exclusions = excluded_by(policies, direct, groups, roles, guests)
    excluded_users = {uid: directory.users[uid] for uid in exclusions if uid in directory.users}
    included = _resolve_includes(directory, policies) if excluded_users else {}
    # A group the exclusions already failed to read is cached as None and adds no new failure.
    status["coverage"] = (READ if all(v is not None for v in included.values()) and status["policies"] == READ
                          else NOT_READ)

    def exclusion_fields(user: dict) -> dict:
        if status["exclusions"] != READ:
            return _exclusion_fields(None, all_users_policies, None)
        entries = exclusions.get((user.get("id") or "").lower(), [])
        from_policies = {e["policy_id"] for e in entries}
        return _exclusion_fields(entries, all_users_policies,
                                 covered(user, from_policies, policies, included) if entries else None)

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
        # Candidates: enabled users that every enforced MFA policy for all users excludes.
        ok = status["exclusions"] == READ
        for uid, user in sorted(excluded_users.items()):
            if user.get("accountEnabled") and exclusion_fields(user)["excluded_from_every_all_users_mfa_policy"]:
                accounts_in.append((None, user))
    status["accounts"] = READ if ok else NOT_READ

    rules, workspaces, rules_ok = _alert_rules(client, collector, subscription_id)
    status["alert_rules"] = READ if rules_ok else NOT_READ

    accounts, activity, registration = [], [], []
    for ref, user in accounts_in:
        full, act, details, reg = _account_detail(client, collector, user)
        activity.append(act)
        registration.append(reg)
        accounts.append(account_record(ref, full, exclusion_fields(user), act == READ, details, reg == READ,
                                       rules, rules_ok, now))
    if status["accounts"] == READ:
        status["user_sign_in_activity"] = _worst(activity)
        status["registration_details"] = _worst(registration)
    accounts.sort(key=lambda a: ((a["user_principal_name"] or "").lower(), a["id"] or ""))

    account_ids = {(a["id"] or "").lower() for a in accounts}
    others = sorted(
        (excluded_user_record(user, exclusion_fields(user)) for uid, user in excluded_users.items()
         if uid not in account_ids),
        key=lambda u: ((u["user_principal_name"] or "").lower(), u["id"] or ""),
    )
    logger.info("Collected %d emergency account(s) (%s), %d other excluded user(s), %d MFA policy/policies, %d alert rule(s)",
                len(accounts), source, len(others), len(policies), len(rules))
    read_policies = policies if status["policies"] == READ else None
    return (_results(tenant_id, source, accounts, not_found, others, read_policies, now),
            summarize(accounts, not_found, others, read_policies, rules, workspaces, status, source, len(named)))


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
