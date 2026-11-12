#!/usr/bin/env python3
"""Entra ID sign-in and policy-change evidence read from a Log Analytics (Sentinel) workspace's SigninLogs and AuditLogs, with no Microsoft Graph permission."""

import json
import logging
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import Collector, coverage_percentage, sorted_counts  # noqa: E402
from azure_rest import (  # noqa: E402
    AzureRestClient,
    bounded_int_config,
    discover_workspaces,
    int_config,
    iso_duration_days,
    requested_workspaces,
    run_subscription,
    table_retention,
    workspace_identity,
)

NAME = "azure_entra_sign_in_logs"
logger = logging.getLogger(NAME)

LOOKBACK_ENV = "ENTRA_LOG_LOOKBACK_DAYS"
USERS_ENV = "ENTRA_LOG_USERS"
APPS_ENV = "ENTRA_LOG_APP_IDS"
# Service principals are scoped apart: in their sign-ins AppId is the principal itself, while in a
# user's sign-in it is the app signed in to, so one list cannot narrow both without dropping one.
SERVICE_PRINCIPAL_APPS_ENV = "ENTRA_LOG_SERVICE_PRINCIPAL_APP_IDS"
MAX_ROWS_ENV = "ENTRA_LOG_MAX_ROWS"
# Entra groups whose current members the user sign-ins are limited to. The members come from the workspace's
# IdentityInfo table (Microsoft Sentinel UEBA) inside each query, so no list is kept and Microsoft Graph is not used.
GROUPS_ENV = "ENTRA_LOG_GROUPS"
IDENTITY_MAX_AGE_ENV = "ENTRA_LOG_IDENTITY_MAX_AGE_DAYS"
DEFAULT_LOOKBACK_DAYS = 30
DEFAULT_MAX_ROWS = 500

IDENTITY_TABLE = "IdentityInfo"
# Sentinel writes a record when a user changes, refreshes groups daily and re-syncs the whole directory every
# 14 days, so an unchanged user's newest record can be that old. Reading 21 days leaves a margin: a re-sync that
# runs late must not drop a member from the scope.
IDENTITY_RESYNC_DAYS = 14
IDENTITY_LOOKBACK_DAYS = 21
DEFAULT_IDENTITY_MAX_AGE_DAYS = 14

SIGNIN_TABLE = "SigninLogs"
AUDIT_TABLE = "AuditLogs"
# Entra exports non-interactive user sign-ins (token refreshes, background syncs) and
# service-principal sign-ins to their own tables. Detections and least-privilege reviews
# depend on them, so they are read too, as counts only: no per-event rows are copied.
NON_INTERACTIVE_TABLE = "AADNonInteractiveUserSignInLogs"
SERVICE_PRINCIPAL_TABLE = "AADServicePrincipalSignInLogs"

# The same method rules as azure_entra_sign_ins, so the two Entra fetchers agree on one tenant.
# Methods that are phishing resistant whenever they satisfy a step.
STRONG_PATTERN = r"(?i)fido2|passkey|windows hello|platform credential"
# A certificate counts only as multifactor CBA: MFA required, no weaker method beside it, nothing reused.
CERTIFICATE_PATTERN = r"(?i)x\.509|certificate"
# Step results that reuse an earlier authentication rather than naming a method.
NOT_A_METHOD = ("previously satisfied", "satisfied by token")
# The "Windows Sign In" app: a logon to a Windows device, counted apart from sign-ins to apps.
WINDOWS_SIGN_IN_APP_ID = "38aa3b87-a06d-4817-b275-7a316988d93b"
MULTI_FACTOR = "multiFactorAuthentication"
SINGLE_FACTOR = "singleFactorAuthentication"
RISKY_LEVELS = ("medium", "high")
# Entra logs some sign-ins of a known user with no user principal name, or with an id in its place, and an attempt
# for an account that does not exist under an all-zero user id. A person is therefore counted by the Entra object
# id, and by the name only where the log has no usable id; counting names alone reads one person as several.
NO_USER_ID = "00000000-0000-0000-0000-000000000000"
_USER_KEY = f"UserKey = iff(isnotempty(Uid) and Uid != '{NO_USER_ID}', Uid, Upn)"
# A name that is an id, not a user principal name; never shown as the user's name.
ID_STYLE_NAME = r"^[0-9a-f]{8}-[0-9a-f]{4}-"

# Changes to the tenant's authentication settings, listed in detail; any other Policy-category operation is counted.
POLICY_OPERATIONS = (
    "Authentication Methods Policy Update",
    "Authentication Methods Policy Reset",
    "Authentication Strength Policy Update",
    "MFA Service Policy Update",
    "Update per-user multifactor authentication state",
    "Update security defaults",
    "Add conditional access policy",
    "Update conditional access policy",
    "Delete conditional access policy",
)

# What the users and app ids may contain: scope values go into the KQL inside double quotes.
_UPN = re.compile(r"^[A-Za-z0-9._%+'@-]+$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# A group display name also goes into the KQL inside double quotes: letters, digits, spaces and common punctuation,
# never a double quote, a backslash or a control character. Matched whole (fullmatch).
_GROUP = re.compile(r"[\w .()&'+@#:/\[\]-]{1,256}")


# --- configuration ---

def _list_env(env: str) -> List[str]:
    return [v.strip() for v in (os.environ.get(env) or "").split(",") if v.strip()]


def settings_from_env(collector: Optional[Collector] = None) -> Dict[str, Any]:
    """Lookback, row cap, the optional user / app scope for user sign-ins and the optional service-principal scope;
    a value that could break the query fails as bad_config."""
    users = [u.lower() for u in _list_env(USERS_ENV)]
    apps = [a.lower() for a in _list_env(APPS_ENV)]
    sp_apps = [a.lower() for a in _list_env(SERVICE_PRINCIPAL_APPS_ENV)]
    groups = _unique_names(_list_env(GROUPS_ENV))
    bad_users = [u for u in users if not _UPN.match(u)]
    bad_apps = [a for a in apps if not _GUID.match(a)]
    bad_sp_apps = [a for a in sp_apps if not _GUID.match(a)]
    bad_groups = [g for g in groups if not _GROUP.fullmatch(g)]
    if (bad_users or bad_apps or bad_sp_apps or bad_groups) and collector is not None:
        # The values stay out of the message: they are untrusted text and would be matched against the failure codes.
        collector.record(f"config {USERS_ENV}/{APPS_ENV}/{SERVICE_PRINCIPAL_APPS_ENV}/{GROUPS_ENV}", ValueError(
            f"invalid setting {USERS_ENV}/{APPS_ENV}/{SERVICE_PRINCIPAL_APPS_ENV}/{GROUPS_ENV}: {len(bad_users)} entry(ies) "
            f"in {USERS_ENV} are not user principal names, {len(bad_apps)} in {APPS_ENV} and {len(bad_sp_apps)} in "
            f"{SERVICE_PRINCIPAL_APPS_ENV} are not GUIDs, {len(bad_groups)} in {GROUPS_ENV} are not group names"))
    return {
        "lookback_days": int_config(LOOKBACK_ENV, DEFAULT_LOOKBACK_DAYS),
        "max_rows": int_config(MAX_ROWS_ENV, DEFAULT_MAX_ROWS),
        "users": [u for u in users if _UPN.match(u)],
        "app_ids": [a for a in apps if _GUID.match(a)],
        "service_principal_app_ids": [a for a in sp_apps if _GUID.match(a)],
        "groups": [g for g in groups if _GROUP.fullmatch(g)],
        # Read only with a group scope, so a stray value cannot fail a run that never uses it.
        "identity_max_age_days": _identity_max_age_days(collector) if groups else DEFAULT_IDENTITY_MAX_AGE_DAYS,
        "scope_invalid": bool(bad_users or bad_apps or bad_sp_apps or bad_groups),
    }


def _unique_names(names: List[str]) -> List[str]:
    """The names in the order given, without repeats that differ only by case (group names match without case)."""
    seen, out = set(), []
    for name in names:
        if name.lower() not in seen:
            seen.add(name.lower())
            out.append(name)
    return out


def _identity_max_age_days(collector: Optional[Collector]) -> int:
    """How old the newest IdentityInfo record may be before the group members are treated as unknown; never more
    than the days of IdentityInfo read, beyond which there is no record to be newer."""
    if collector is None:
        return min(int_config(IDENTITY_MAX_AGE_ENV, DEFAULT_IDENTITY_MAX_AGE_DAYS), IDENTITY_LOOKBACK_DAYS)
    return bounded_int_config(collector, IDENTITY_MAX_AGE_ENV, DEFAULT_IDENTITY_MAX_AGE_DAYS, IDENTITY_LOOKBACK_DAYS)[0]


def _dynamic(values: List[str]) -> str:
    return "dynamic([" + ", ".join(f'"{v}"' for v in values) + "])"


def _identity_records() -> str:
    """Every IdentityInfo record in the window, keyed by the Entra object id (the user principal name where a record has none)."""
    return (
        f"{IDENTITY_TABLE} | where TimeGenerated > ago({IDENTITY_LOOKBACK_DAYS}d) "
        "| extend Oid = tolower(tostring(AccountObjectId)), IUpn = tolower(tostring(AccountUPN)) "
        "| extend IdKey = iff(isnotempty(Oid), Oid, IUpn) | where isnotempty(IdKey) "
    )


# One person can have two IdentityInfo records under different keys (a cloud record with an object id and another
# without one); counted by user principal name first, they are one member.
_MEMBER = "Member = iff(isnotempty(IUpn), IUpn, Oid)"


def _current_members() -> str:
    """Continues _identity_records(): one row per identity and listed group it is in now. Only each identity's newest
    record counts, so someone removed from a group leaves the scope once Sentinel records the change."""
    return (
        "| summarize arg_max(TimeGenerated, GroupMembership, Oid, IUpn) by IdKey "
        "| mv-expand G = GroupMembership to typeof(string) | where G in~ (ScopeGroups) "
    )


def scope_prefix(settings: Dict[str, Any]) -> str:
    """The let statements a group-scoped user sign-in query starts with; empty when no group is set. The members are
    worked out by the workspace at query time: their names never reach this fetcher unless they signed in."""
    groups = settings.get("groups") or []
    if not groups:
        return ""
    return (
        f"let ScopeGroups = {_dynamic(groups)}; "
        "let ScopeMembers = materialize(" + _identity_records() + _current_members() + "| distinct Oid, IUpn); "
        "let ScopeIds = ScopeMembers | where isnotempty(Oid) | distinct Oid; "
        "let ScopeUpns = ScopeMembers | where isnotempty(IUpn) | distinct IUpn; "
    )


def scope_filter(settings: Dict[str, Any]) -> str:
    """KQL filter for user sign-ins (interactive and non-interactive): the users in scope, and the apps signed in to
    (both must match when both are set); empty when unscoped. A user is in scope as a current member of a listed
    group (matched by object id, or by user principal name) or as one of the listed users; either is enough.
    Service-principal sign-ins use service_principal_filter. A query with a group scope starts with scope_prefix()."""
    parts = []
    users = settings["users"]
    if settings.get("groups"):
        member = "tolower(tostring(UserId)) in (ScopeIds) or tolower(tostring(UserPrincipalName)) in (ScopeUpns)"
        if users:
            member += f" or tolower(tostring(UserPrincipalName)) in ({_dynamic(users)})"
        parts.append(f"| where {member} ")
    elif users:
        parts.append(f"| where tolower(UserPrincipalName) in ({_dynamic(users)}) ")
    if settings["app_ids"]:
        parts.append(f"| where tolower(AppId) in ({_dynamic(settings['app_ids'])}) ")
    return "".join(parts)


def query_days(settings: Dict[str, Any]) -> int:
    """Days to ask the query API for on a user sign-in query. The API applies its timespan to every table a query
    reads, so a group-scoped query asks for the longer of the lookback and the IdentityInfo window, or a short
    lookback would cut the member list; each sign-in table is still cut to the lookback inside the query."""
    if settings.get("groups"):
        return max(settings["lookback_days"], IDENTITY_LOOKBACK_DAYS)
    return settings["lookback_days"]


def identity_stats_query(settings: Dict[str, Any]) -> str:
    """One row on the IdentityInfo table the group scope rests on: its newest record and that record's age, how many
    identities it holds, how many are in a listed group now, and how many were in an older record but are not now."""
    in_scope = "| mv-expand G = GroupMembership to typeof(string) | where G in~ (ScopeGroups) "
    return (
        f"let ScopeGroups = {_dynamic(settings['groups'])}; "
        "let Records = materialize(" + _identity_records() + "| project TimeGenerated, IdKey, GroupMembership, Oid, IUpn); "
        "let Latest = materialize(Records | summarize arg_max(TimeGenerated, GroupMembership, Oid, IUpn) by IdKey); "
        "let NowIn = materialize(Latest " + in_scope + "); "
        # Compared by the record key, which a renamed user keeps, so a rename is not read as a removal.
        "let EverIn = Records " + in_scope + "| distinct IdKey; "
        "Records | summarize Newest = max(TimeGenerated) "
        # Whole elapsed hours; null when the table holds no record.
        "| extend AgeHours = tolong((now() - Newest) / 1h), "
        f"Identities = toscalar(Latest | extend {_MEMBER} | distinct Member | count), "
        f"Members = toscalar(NowIn | extend {_MEMBER} | distinct Member | count), "
        "MembersOnlyInOlderRecords = toscalar(EverIn | where IdKey !in ((NowIn | distinct IdKey)) | count)"
    )


def identity_groups_query(settings: Dict[str, Any]) -> str:
    """Current members per listed group (lower-cased name); a group with none has no row."""
    return (
        f"let ScopeGroups = {_dynamic(settings['groups'])}; "
        + _identity_records() + _current_members()
        + f"| extend {_MEMBER} | summarize by Member, Group = tolower(G) | summarize Members = count() by Group"
    )


# --- queries ---

def base_query(settings: Dict[str, Any], succeeded_only: bool = False) -> str:
    """One row per interactive sign-in: result, requirement, the methods that succeeded, and whether they are phishing resistant."""
    not_a_method = ", ".join(f'"{m}"' for m in NOT_A_METHOD)
    return (
        scope_prefix(settings)
        + f"{SIGNIN_TABLE} "
        f"| where TimeGenerated > ago({settings['lookback_days']}d) "
        + scope_filter(settings)
        + ("| where tostring(ResultType) == '0' " if succeeded_only else "")
        + "| extend Ok = tostring(ResultType) == '0', Req = tostring(AuthenticationRequirement), "
        "CA = tostring(ConditionalAccessStatus), Risk = tolower(tostring(RiskLevelDuringSignIn)), "
        "Upn = tolower(tostring(UserPrincipalName)), Uid = tolower(tostring(UserId)), "
        f"DeviceLogon = tolower(tostring(AppId)) == '{WINDOWS_SIGN_IN_APP_ID}' "
        f"| extend {_USER_KEY} "
        # At least one element, so a sign-in with no detail is kept with an empty set.
        "| extend D = todynamic(tostring(AuthenticationDetails)) "
        "| extend D = iff(array_length(D) > 0, D, dynamic([{}])) "
        "| mv-apply d = D on ("
        "extend M = tostring(d.authenticationMethod), S = tobool(d.succeeded) "
        f"| extend Reuse = tolower(M) in ({not_a_method}) "
        "| summarize Methods = make_set_if(M, S and isnotempty(M) and not(Reuse)), "
        "Reused = countif(S and Reuse), "
        f"Weaker = countif(S and isnotempty(M) and not(Reuse) and not(M matches regex @'{STRONG_PATTERN}') "
        f"and not(M matches regex @'{CERTIFICATE_PATTERN}'))) "
        "| extend P = todynamic(tostring(AuthenticationRequirementPolicies)) "
        "| extend P = iff(array_length(P) > 0, P, dynamic([{}])) "
        "| mv-apply p = P on (summarize Providers = make_set_if(tostring(p.requirementProvider), "
        "isnotempty(tostring(p.requirementProvider)))) "
        f"| extend Strong = tostring(Methods) matches regex @'{STRONG_PATTERN}', "
        f"Cert = tostring(Methods) matches regex @'{CERTIFICATE_PATTERN}' "
        f"| extend PhishingResistant = Strong or (Req == '{MULTI_FACTOR}' and Cert and Weaker == 0 and Reused == 0) "
        # A passkey alone is not a password alone, and a device logon is not a sign-in to an app.
        f"| extend SingleFactor = Req == '{SINGLE_FACTOR}' and not(DeviceLogon) and not(PhishingResistant), "
        f"SingleFactorPhishingResistant = Req == '{SINGLE_FACTOR}' and not(DeviceLogon) and PhishingResistant "
    )


def overview_query(settings: Dict[str, Any]) -> str:
    risky = ", ".join(f"'{r}'" for r in RISKY_LEVELS)
    return base_query(settings) + (
        "| summarize SignIns = count(), Succeeded = countif(Ok), Failed = countif(not(Ok)), "
        f"SucceededMultiFactor = countif(Ok and Req == '{MULTI_FACTOR}'), "
        "SucceededSingleFactor = countif(Ok and SingleFactor), "
        "SucceededSingleFactorPhishingResistant = countif(Ok and SingleFactorPhishingResistant), "
        "SucceededDeviceLogons = countif(Ok and DeviceLogon), "
        "SucceededPhishingResistant = countif(Ok and PhishingResistant), "
        f"SucceededRisky = countif(Ok and Risk in ({risky})), "
        "FirstSignIn = min(TimeGenerated), LastSignIn = max(TimeGenerated)"
    )


def cube_query(settings: Dict[str, Any]) -> str:
    """Successful sign-ins by requirement, Conditional Access status and risk at once; three breakdowns come from it."""
    return base_query(settings, True) + "| summarize SignIns = count() by Req, CA, Risk"


def sets_query(settings: Dict[str, Any]) -> str:
    """Successful sign-ins by their set of methods and set of requirement sources; both per-value counts come from it."""
    return base_query(settings, True) + "| summarize SignIns = count() by M = tostring(Methods), P = tostring(Providers)"


def users_query(settings: Dict[str, Any]) -> str:
    return base_query(settings) + (
        "| summarize SignIns = count(), Succeeded = countif(Ok), Failed = countif(not(Ok)), "
        "SucceededSingleFactor = countif(Ok and SingleFactor), "
        "SucceededPhishingResistant = countif(Ok and PhishingResistant), LastSignIn = max(TimeGenerated), "
        # One row per person; the name shown is a real one when the log has any (the last by name, so it is stable).
        f"Upn = maxif(Upn, isnotempty(Upn) and not(Upn matches regex @'{ID_STYLE_NAME}')) by UserKey "
        f"| order by Upn asc, UserKey asc | take {settings['max_rows'] + 1} "
        "| project Upn, SignIns, Succeeded, Failed, SucceededSingleFactor, SucceededPhishingResistant, LastSignIn"
    )


def user_count_query(settings: Dict[str, Any]) -> str:
    return base_query(settings) + (
        "| summarize SucceededSingleFactor = countif(Ok and SingleFactor) by UserKey "
        "| summarize Users = count(), UsersWithSingleFactorSuccess = countif(SucceededSingleFactor > 0)"
    )


def single_factor_query(settings: Dict[str, Any]) -> str:
    return base_query(settings, True) + (
        "| where SingleFactor "
        "| project TimeGenerated, Upn, AppDisplayName, AppId, CA, Providers, Methods "
        f"| order by TimeGenerated desc | take {settings['max_rows'] + 1}"
    )


def service_principal_filter(settings: Dict[str, Any]) -> str:
    """KQL filter for the configured service principals by their own app id; empty when unscoped. The user scope
    and the user-sign-in app scope never apply here: a service principal has no user principal name, and its
    AppId names the principal, not an app it signed in to."""
    if settings["service_principal_app_ids"]:
        return f"| where tolower(tostring(AppId)) in ({_dynamic(settings['service_principal_app_ids'])}) "
    return ""


def non_interactive_overview_query(settings: Dict[str, Any]) -> str:
    """Counts over the non-interactive user sign-ins in scope; one row."""
    return (
        scope_prefix(settings)
        + f"{NON_INTERACTIVE_TABLE} | where TimeGenerated > ago({settings['lookback_days']}d) "
        + scope_filter(settings)
        + "| extend Ok = tostring(ResultType) == '0', Risk = tolower(tostring(RiskLevelDuringSignIn)), "
        "Upn = tolower(tostring(UserPrincipalName)), Uid = tolower(tostring(UserId)) "
        f"| extend {_USER_KEY} "
        "| summarize SignIns = count(), Succeeded = countif(Ok), Failed = countif(not(Ok)), "
        "Users = dcountif(UserKey, Ok), Apps = dcountif(tolower(tostring(AppId)), Ok), "
        f"Risky = countif(Ok and Risk in ({', '.join(repr(r) for r in RISKY_LEVELS)})), "
        "LastSignIn = max(TimeGenerated)"
    )


def non_interactive_ca_query(settings: Dict[str, Any]) -> str:
    return (
        scope_prefix(settings)
        + f"{NON_INTERACTIVE_TABLE} | where TimeGenerated > ago({settings['lookback_days']}d) "
        + scope_filter(settings)
        + "| where tostring(ResultType) == '0' "
        "| summarize SignIns = count() by CA = tostring(ConditionalAccessStatus)"
    )


def service_principal_overview_query(settings: Dict[str, Any]) -> str:
    """Counts over service-principal (application) sign-ins in scope; one row."""
    return (
        f"{SERVICE_PRINCIPAL_TABLE} | where TimeGenerated > ago({settings['lookback_days']}d) "
        + service_principal_filter(settings)
        + "| extend Ok = tostring(ResultType) == '0' "
        "| summarize SignIns = count(), Succeeded = countif(Ok), Failed = countif(not(Ok)), "
        "Principals = dcountif(tostring(ServicePrincipalId), Ok), "
        "PrincipalsFailing = dcountif(tostring(ServicePrincipalId), not(Ok)), LastSignIn = max(TimeGenerated)"
    )


def service_principal_list_query(settings: Dict[str, Any]) -> str:
    """One row per service principal that signed in: id, name, app id, counts and last sign-in (no IPs, no resources)."""
    return (
        f"{SERVICE_PRINCIPAL_TABLE} | where TimeGenerated > ago({settings['lookback_days']}d) "
        + service_principal_filter(settings)
        + "| extend Ok = tostring(ResultType) == '0' "
        "| summarize SignIns = count(), Succeeded = countif(Ok), Failed = countif(not(Ok)), LastSignIn = max(TimeGenerated) "
        "by ServicePrincipalId = tostring(ServicePrincipalId), ServicePrincipalName = tostring(ServicePrincipalName), "
        "AppId = tolower(tostring(AppId)) "
        # One row more than the cap, so a cut list is detected without reading the whole table.
        f"| order by SignIns desc, ServicePrincipalId asc | take {settings['max_rows'] + 1}"
    )


def _audit_base(settings: Dict[str, Any]) -> str:
    operations = ", ".join(f"'{o}'" for o in POLICY_OPERATIONS)
    return (
        f"{AUDIT_TABLE} | where TimeGenerated > ago({settings['lookback_days']}d) "
        f"| where tostring(Category) =~ 'Policy' or OperationName in~ ({operations}) "
    )


def audit_count_query(settings: Dict[str, Any]) -> str:
    """Every policy change counted by operation name, uncapped, so an operation this fetcher does not list still shows."""
    return _audit_base(settings) + "| summarize Changes = count() by OperationName"


def audit_events_query(settings: Dict[str, Any]) -> str:
    return _audit_base(settings) + (
        "| extend I = todynamic(tostring(InitiatedBy)), T = todynamic(tostring(TargetResources)) "
        "| project TimeGenerated, OperationName, Result = tostring(Result), "
        "InitiatedByUser = tostring(I.user.userPrincipalName), InitiatedByApp = tostring(I.app.displayName), "
        "Target = tostring(T[0].displayName), TargetId = tostring(T[0].id) "
        f"| order by TimeGenerated desc | take {settings['max_rows'] + 1}"
    )


# --- transforms ---

def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def as_list(value: Any) -> List[str]:
    """Dynamic columns arrive as JSON text."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return sorted(str(v) for v in value if v not in (None, "")) if isinstance(value, list) else []


def counts(rows: List[Dict[str, Any]], column: str, count_column: str = "SignIns") -> Dict[str, int]:
    out: Counter = Counter()
    for row in rows:
        out[str(row.get(column) or "") or "(none)"] += _int(row.get(count_column))
    return sorted_counts(out)


def set_counts(rows: List[Dict[str, Any]], column: str) -> Dict[str, int]:
    """Sign-ins per value of a set column; a sign-in with several values counts under each."""
    out: Counter = Counter()
    for row in rows:
        for value in as_list(row.get(column)):
            out[value] += _int(row.get("SignIns"))
    return sorted_counts(out)


def capped(rows: List[Dict[str, Any]], limit: int) -> Tuple[List[Dict[str, Any]], bool]:
    return rows[:limit], len(rows) > limit


def user_record(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "user_principal_name": row.get("Upn") or None,
        "sign_ins": _int(row.get("SignIns")),
        "succeeded": _int(row.get("Succeeded")),
        "failed": _int(row.get("Failed")),
        "succeeded_single_factor": _int(row.get("SucceededSingleFactor")),
        "succeeded_phishing_resistant": _int(row.get("SucceededPhishingResistant")),
        "last_sign_in": row.get("LastSignIn"),
    }


def single_factor_record(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "time": row.get("TimeGenerated"),
        "user_principal_name": row.get("Upn") or None,
        "app_display_name": row.get("AppDisplayName") or None,
        "app_id": row.get("AppId") or None,
        "conditional_access_status": row.get("CA") or None,
        "requirement_providers": as_list(row.get("Providers")),
        "methods": as_list(row.get("Methods")),
    }


def audit_record(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "time": row.get("TimeGenerated"),
        "operation": row.get("OperationName"),
        "result": row.get("Result") or None,
        "initiated_by_user": row.get("InitiatedByUser") or None,
        "initiated_by_app": row.get("InitiatedByApp") or None,
        "target": row.get("Target") or None,
        "target_id": row.get("TargetId") or None,
    }


def sign_in_summary(overview: Dict[str, Any], users: Dict[str, Any]) -> Dict[str, Any]:
    succeeded = _int(overview.get("Succeeded"))
    multi = _int(overview.get("SucceededMultiFactor"))
    phishing = _int(overview.get("SucceededPhishingResistant"))
    return {
        "sign_ins": _int(overview.get("SignIns")),
        "succeeded": succeeded,
        "failed": _int(overview.get("Failed")),
        "succeeded_multi_factor": multi,
        "succeeded_single_factor": _int(overview.get("SucceededSingleFactor")),
        "succeeded_single_factor_phishing_resistant": _int(overview.get("SucceededSingleFactorPhishingResistant")),
        "succeeded_device_logons": _int(overview.get("SucceededDeviceLogons")),
        "succeeded_phishing_resistant": phishing,
        "succeeded_risky": _int(overview.get("SucceededRisky")),
        "multi_factor_percentage": coverage_percentage(multi, succeeded),
        "phishing_resistant_percentage": coverage_percentage(phishing, succeeded),
        "users_signed_in": _int(users.get("Users")),
        "users_with_single_factor_success": _int(users.get("UsersWithSingleFactorSuccess")),
        "first_sign_in": overview.get("FirstSignIn") or None,
        "last_sign_in": overview.get("LastSignIn") or None,
    }


# --- collection ---

def _query(client, ws: Dict[str, Any], kql: str, days: int) -> List[Dict[str, Any]]:
    return client.query(ws["customer_id"], kql, iso_duration_days(days))


def collect_sign_ins(client, ws: Dict[str, Any], settings: Dict[str, Any], collector: Collector) -> Optional[Dict[str, Any]]:
    """The sign-in evidence for one workspace, or None when any query failed (recorded)."""
    days, limit = query_days(settings), settings["max_rows"]
    try:
        overview = (_query(client, ws, overview_query(settings), days) or [{}])[0]
        cube = _query(client, ws, cube_query(settings), days)
        sets = _query(client, ws, sets_query(settings), days)
        user_counts = (_query(client, ws, user_count_query(settings), days) or [{}])[0]
        users, users_truncated = capped([user_record(r) for r in _query(client, ws, users_query(settings), days)], limit)
        single, single_truncated = capped(
            [single_factor_record(r) for r in _query(client, ws, single_factor_query(settings), days)], limit)
    except Exception as exc:  # noqa: BLE001 — record, leave this workspace's sign-in evidence unknown
        collector.record(f"loganalytics.query({SIGNIN_TABLE}, {ws['name']})", exc)
        return None
    return {
        **sign_in_summary(overview, user_counts),
        "succeeded_by_authentication_requirement": counts(cube, "Req"),
        "succeeded_by_conditional_access_status": counts(cube, "CA"),
        "succeeded_by_risk_level": counts(cube, "Risk"),
        "succeeded_by_method": set_counts(sets, "M"),
        "succeeded_by_requirement_provider": set_counts(sets, "P"),
        "users": users,
        "users_truncated": users_truncated,
        "single_factor_sign_ins": single,
        "single_factor_sign_ins_truncated": single_truncated,
    }


def collect_audit(client, ws: Dict[str, Any], settings: Dict[str, Any], collector: Collector) -> Optional[Dict[str, Any]]:
    try:
        by_operation = counts(_query(client, ws, audit_count_query(settings), settings["lookback_days"]), "OperationName", "Changes")
        rows = _query(client, ws, audit_events_query(settings), settings["lookback_days"])
    except Exception as exc:  # noqa: BLE001
        collector.record(f"loganalytics.query({AUDIT_TABLE}, {ws['name']})", exc)
        return None
    events, truncated = capped([audit_record(r) for r in rows], settings["max_rows"])
    return {"policy_changes": sum(by_operation.values()), "policy_changes_by_operation": by_operation,
            "policy_change_events": events, "policy_change_events_truncated": truncated}


def service_principal_record(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "service_principal_id": row.get("ServicePrincipalId"),
        "service_principal_name": row.get("ServicePrincipalName"),
        "app_id": row.get("AppId"),
        "sign_ins": _int(row.get("SignIns")),
        "succeeded": _int(row.get("Succeeded")),
        "failed": _int(row.get("Failed")),
        "last_sign_in": row.get("LastSignIn"),
    }


def collect_non_interactive(client, ws: Dict[str, Any], settings: Dict[str, Any],
                            collector: Collector) -> Optional[Dict[str, Any]]:
    """Counts of non-interactive user sign-ins for one workspace, or None when a query failed (recorded)."""
    days = query_days(settings)
    try:
        overview = (_query(client, ws, non_interactive_overview_query(settings), days) or [{}])[0]
        by_ca = _query(client, ws, non_interactive_ca_query(settings), days)
    except Exception as exc:  # noqa: BLE001
        collector.record(f"loganalytics.query({NON_INTERACTIVE_TABLE}, {ws['name']})", exc)
        return None
    return {
        "sign_ins": _int(overview.get("SignIns")),
        "succeeded": _int(overview.get("Succeeded")),
        "failed": _int(overview.get("Failed")),
        "users_signed_in": _int(overview.get("Users")),
        "apps_signed_in_to": _int(overview.get("Apps")),
        "succeeded_risky": _int(overview.get("Risky")),
        "last_sign_in": overview.get("LastSignIn"),
        "succeeded_by_conditional_access_status": counts(by_ca, "CA"),
    }


def collect_service_principals(client, ws: Dict[str, Any], settings: Dict[str, Any],
                               collector: Collector) -> Optional[Dict[str, Any]]:
    """Service-principal sign-in counts for one workspace, plus a capped per-principal list."""
    days, limit = settings["lookback_days"], settings["max_rows"]
    try:
        overview = (_query(client, ws, service_principal_overview_query(settings), days) or [{}])[0]
        rows = _query(client, ws, service_principal_list_query(settings), days)
    except Exception as exc:  # noqa: BLE001
        collector.record(f"loganalytics.query({SERVICE_PRINCIPAL_TABLE}, {ws['name']})", exc)
        return None
    principals, truncated = capped([service_principal_record(r) for r in rows], limit)
    return {
        "sign_ins": _int(overview.get("SignIns")),
        "succeeded": _int(overview.get("Succeeded")),
        "failed": _int(overview.get("Failed")),
        "principals_signed_in": _int(overview.get("Principals")),
        "principals_with_failures": _int(overview.get("PrincipalsFailing")),
        "last_sign_in": overview.get("LastSignIn"),
        "principals": principals,
        "principals_truncated": truncated,
    }


def _opt_int(value: Any) -> Optional[int]:
    try:
        return None if value in (None, "") else int(value)
    except (TypeError, ValueError):
        return None


def collect_group_scope(client, ws: Dict[str, Any], settings: Dict[str, Any], collector: Collector) -> Dict[str, Any]:
    """Whether the listed groups resolve to members in this workspace's IdentityInfo, with the counts that show it.

    resolved stays False, with a failure recorded, when the table is missing, keeps too little, has no record, has
    only stale ones, cannot be queried, or holds no member of any listed group. The caller then leaves the user
    sign-in evidence unknown: reading the logs unscoped, or against members that may be out of date, would report
    the wrong people's sign-ins. No member is named here; only counts are kept."""
    groups = settings["groups"]
    scope: Dict[str, Any] = {
        "groups": groups, "resolved": False, "identity_table_present": None, "identity_retention_days": None,
        "identity_lookback_days": IDENTITY_LOOKBACK_DAYS, "identity_max_age_days": settings["identity_max_age_days"],
        "identities": None, "identity_latest_record": None, "identity_latest_record_age_hours": None,
        "members": None, "members_by_group": None, "groups_without_members": None,
        "members_only_in_older_records": None,
    }
    operation = f"loganalytics.query({IDENTITY_TABLE}, {ws['name']})"
    exists = collector.guard(f"loganalytics.tables.get({IDENTITY_TABLE}, {ws['name']})",
                             lambda: table_retention(client, ws["id"], IDENTITY_TABLE, ws.get("retention_in_days")))
    if exists is None:
        return scope
    scope["identity_table_present"], scope["identity_retention_days"] = exists
    if not exists[0]:
        collector.record(operation, LookupError(
            f"config conflict: {GROUPS_ENV} is set but this workspace has no {IDENTITY_TABLE} table (Microsoft Sentinel "
            "UEBA is not syncing identities to it), so the groups' members cannot be resolved"))
        return scope
    if exists[1] and exists[1] < IDENTITY_RESYNC_DAYS:
        collector.record(operation, LookupError(
            f"{IDENTITY_TABLE} keeps {exists[1]} days, less than the {IDENTITY_RESYNC_DAYS}-day directory re-sync, so "
            "members whose record is older would be missing"))
        return scope
    try:
        stats = (_query(client, ws, identity_stats_query(settings), IDENTITY_LOOKBACK_DAYS) or [{}])[0]
        rows = _query(client, ws, identity_groups_query(settings), IDENTITY_LOOKBACK_DAYS)
    except Exception as exc:  # noqa: BLE001 — record, leave the members unknown
        collector.record(operation, exc)
        return scope
    age = _opt_int(stats.get("AgeHours"))
    scope["identities"] = _int(stats.get("Identities"))
    scope["identity_latest_record"] = stats.get("Newest") or None
    scope["identity_latest_record_age_hours"] = None if age is None else max(age, 0)
    if not scope["identities"] or not scope["identity_latest_record"] or age is None:
        collector.record(operation, LookupError(
            f"{IDENTITY_TABLE} has no identity record in the last {IDENTITY_LOOKBACK_DAYS} days, so the groups' members "
            "cannot be resolved"))
        return scope
    if age > settings["identity_max_age_days"] * 24:
        collector.record(operation, LookupError(
            f"the newest {IDENTITY_TABLE} record is {age} hours old, more than the {settings['identity_max_age_days']} "
            f"day(s) allowed ({IDENTITY_MAX_AGE_ENV}), so the groups' members may be out of date"))
        return scope
    found = {str(r.get("Group") or "").lower(): _int(r.get("Members")) for r in rows}
    scope["members"] = _int(stats.get("Members"))
    scope["members_by_group"] = {g: found.get(g.lower(), 0) for g in groups}
    scope["groups_without_members"] = [g for g in groups if not found.get(g.lower())]
    scope["members_only_in_older_records"] = _int(stats.get("MembersOnlyInOlderRecords"))
    if not scope["members"] and not settings["users"]:
        collector.record(operation, LookupError(
            f"config conflict: none of the {len(groups)} group(s) in {GROUPS_ENV} has a member in {IDENTITY_TABLE}; "
            "check the names against Entra"))
        return scope
    scope["resolved"] = True
    return scope


def group_scope_notes(scope: Dict[str, Any]) -> List[str]:
    notes = []
    retention = scope.get("identity_retention_days")
    if scope.get("identity_table_present") and retention and IDENTITY_RESYNC_DAYS <= retention < IDENTITY_LOOKBACK_DAYS:
        notes.append(f"{IDENTITY_TABLE} keeps {retention} days, less than the {IDENTITY_LOOKBACK_DAYS} read, so a member "
                     "whose record is older than that is missing from the scope")
    for group in scope.get("groups_without_members") or []:
        notes.append(f"group {group!r} has no member in {IDENTITY_TABLE}: it is empty, misspelt, or its members are "
                     "not identities Sentinel syncs")
    if scope.get("members_only_in_older_records"):
        notes.append(f"{scope['members_only_in_older_records']} identity(ies) were in a listed group in an older "
                     f"{IDENTITY_TABLE} record but not in their newest one, so they are out of scope")
    return notes


# The two tables of user sign-ins, which the user and group scope narrow.
USER_SIGN_IN_BLOCKS = ("sign_in_logs", "non_interactive_sign_in_logs")


def collect_workspace(client, ws: Dict[str, Any], settings: Dict[str, Any], collector: Collector) -> Dict[str, Any]:
    result: Dict[str, Any] = {"lookback_days": settings["lookback_days"], "notes": [], "group_scope": None}

    def user_scope_resolved() -> bool:
        """Resolves the group scope once, and only for a workspace that holds user sign-ins to narrow."""
        if not settings.get("groups"):
            return True
        if result["group_scope"] is None:
            result["group_scope"] = collect_group_scope(client, ws, settings, collector)
            result["notes"].extend(group_scope_notes(result["group_scope"]))
        return result["group_scope"]["resolved"]

    if not ws.get("customer_id"):
        collector.record(f"loganalytics.workspace({ws['name']})", LookupError("workspace has no customerId"))
    for table, key, reader in ((SIGNIN_TABLE, "sign_in_logs", collect_sign_ins), (AUDIT_TABLE, "audit_logs", collect_audit),
                               (NON_INTERACTIVE_TABLE, "non_interactive_sign_in_logs", collect_non_interactive),
                               (SERVICE_PRINCIPAL_TABLE, "service_principal_sign_in_logs", collect_service_principals)):
        exists = collector.guard(f"loganalytics.tables.get({table}, {ws['name']})",
                                 lambda table=table: table_retention(client, ws["id"], table, ws.get("retention_in_days")))
        result[f"{key}_table_present"] = None if exists is None else exists[0]
        result[f"{key}_retention_days"] = None if exists is None else exists[1]
        if exists is None or not exists[0] or not ws.get("customer_id"):
            result[key] = None
            if exists is not None and not exists[0]:
                result["notes"].append(f"{table} does not exist in this workspace, so Entra does not export it here")
            continue
        if exists[1] and exists[1] < settings["lookback_days"]:
            result["notes"].append(f"{table} keeps {exists[1]} days, less than the {settings['lookback_days']}-day lookback")
        if key in USER_SIGN_IN_BLOCKS and not user_scope_resolved():
            result[key] = None  # unknown, never read unscoped
            continue
        result[key] = reader(client, ws, settings, collector)
    return result


def _sum(workspaces: List[Dict[str, Any]], key: str) -> int:
    return sum(_int((w.get("sign_in_logs") or {}).get(key)) for w in workspaces)


def _merge(workspaces: List[Dict[str, Any]], block: str, key: str) -> Dict[str, int]:
    total: Counter = Counter()
    for w in workspaces:
        total.update((w.get(block) or {}).get(key) or {})
    return sorted_counts(total)


def _block_summary(workspaces: List[Dict[str, Any]], block: str, prefix: str, keys: tuple) -> Dict[str, Any]:
    """Totals of one log table across the workspaces that hold it; every count null unless every holder was read."""
    lookups_ok = all(w.get(f"{block}_table_present") is not None for w in workspaces)
    holders = [w for w in workspaces if w.get(f"{block}_table_present")]
    read_ok = lookups_ok and bool(holders) and all(w.get(block) is not None for w in holders)
    out: Dict[str, Any] = {f"workspaces_with_{prefix}_sign_in_logs": len(holders), f"{prefix}_sign_in_logs_read": read_ok}
    for key in keys:
        total = sum(_int((w.get(block) or {}).get(key)) for w in holders)
        out[f"{prefix}_{key}"] = total if read_ok else None
    return out


def _group_scope_summary(workspaces: List[Dict[str, Any]], settings: Dict[str, Any]) -> Dict[str, Any]:
    """The group scope across the workspaces that needed it; the counts are null unless every one resolved."""
    scopes = [w["group_scope"] for w in workspaces if w.get("group_scope")]
    resolved = all(s["resolved"] for s in scopes) if scopes else None
    ok = bool(resolved)
    records = sorted(str(s.get("identity_latest_record") or "") for s in scopes)
    ages = [s["identity_latest_record_age_hours"] for s in scopes if s.get("identity_latest_record_age_hours") is not None]
    return {
        "scope_groups": settings.get("groups") or [],
        "group_scope_resolved": resolved,
        "scope_group_members": sum(_int(s.get("members")) for s in scopes) if ok else None,
        "scope_groups_without_members": sorted({g for s in scopes for g in s.get("groups_without_members") or []}) if ok else None,
        # The stalest workspace decides: the oldest of the newest records, and the greatest age.
        "identity_info_latest_record": (records[0] or None) if ok and records else None,
        "identity_info_age_hours": max(ages) if ok and ages else None,
    }


def summarize(workspaces: List[Dict[str, Any]], settings: Dict[str, Any]) -> Dict[str, Any]:
    # A workspace whose table lookup failed may hold the logs, so completeness is unknown.
    lookups_ok = all(w.get("sign_in_logs_table_present") is not None for w in workspaces)
    with_logs = [w for w in workspaces if w.get("sign_in_logs_table_present")]
    read = [w for w in with_logs if w.get("sign_in_logs") is not None]
    sign_ins_read = lookups_ok and bool(with_logs) and len(read) == len(with_logs)
    audit_lookups_ok = all(w.get("audit_logs_table_present") is not None for w in workspaces)
    audits = [w for w in workspaces if w.get("audit_logs_table_present")]
    audits_read = audit_lookups_ok and bool(audits) and all(w.get("audit_logs") is not None for w in audits)
    succeeded, multi = _sum(read, "succeeded"), _sum(read, "succeeded_multi_factor")
    single, phishing = _sum(read, "succeeded_single_factor"), _sum(read, "succeeded_phishing_resistant")
    last = sorted(str((w.get("sign_in_logs") or {}).get("last_sign_in") or "") for w in read)

    def known(value):
        return value if sign_ins_read else None

    return {
        "lookback_days": settings["lookback_days"],
        "scope_users": settings["users"],
        **_group_scope_summary(workspaces, settings),
        "scope_app_ids": settings["app_ids"],
        "scope_service_principal_app_ids": settings["service_principal_app_ids"],
        "workspaces_with_sign_in_logs": len(with_logs),
        "sign_in_logs_workspaces": [w.get("name") for w in with_logs],
        "sign_in_logs_read": sign_ins_read,
        "latest_sign_in": (last[-1] or None) if last and sign_ins_read else None,
        "sign_ins": known(_sum(read, "sign_ins")),
        "sign_ins_succeeded": known(succeeded),
        "sign_ins_failed": known(_sum(read, "failed")),
        "succeeded_multi_factor": known(multi),
        "succeeded_single_factor": known(single),
        "succeeded_single_factor_phishing_resistant": known(_sum(read, "succeeded_single_factor_phishing_resistant")),
        "succeeded_device_logons": known(_sum(read, "succeeded_device_logons")),
        "succeeded_phishing_resistant": known(phishing),
        "succeeded_risky": known(_sum(read, "succeeded_risky")),
        "multi_factor_percentage": known(coverage_percentage(multi, succeeded)),
        "phishing_resistant_percentage": known(coverage_percentage(phishing, succeeded)),
        "users_signed_in": known(_sum(read, "users_signed_in")),
        "users_with_single_factor_success": known(_sum(read, "users_with_single_factor_success")),
        "all_successful_sign_ins_multi_factor": (single == 0) if sign_ins_read and succeeded else None,
        "succeeded_by_method": known(_merge(read, "sign_in_logs", "succeeded_by_method")),
        "succeeded_by_requirement_provider": known(_merge(read, "sign_in_logs", "succeeded_by_requirement_provider")),
        "succeeded_by_conditional_access_status": known(_merge(read, "sign_in_logs", "succeeded_by_conditional_access_status")),
        **_block_summary(workspaces, "non_interactive_sign_in_logs", "non_interactive",
                         ("sign_ins", "succeeded", "failed", "users_signed_in", "succeeded_risky")),
        **_block_summary(workspaces, "service_principal_sign_in_logs", "service_principal",
                         ("sign_ins", "succeeded", "failed", "principals_signed_in", "principals_with_failures")),
        "workspaces_with_audit_logs": len(audits),
        "audit_logs_read": audits_read,
        "policy_changes": sum(_int((w.get("audit_logs") or {}).get("policy_changes")) for w in audits) if audits_read else None,
        "policy_changes_by_operation": _merge(audits, "audit_logs", "policy_changes_by_operation") if audits_read else None,
    }


def collect_subscription(client: AzureRestClient, subscription_id: str, collector: Collector) -> tuple:
    """(results, summary): every Log Analytics workspace in the subscription, Sentinel or not."""
    settings = settings_from_env(collector)
    workspaces: List[Dict[str, Any]] = []
    if not settings["scope_invalid"]:
        for ws in discover_workspaces(client, subscription_id, collector):
            detail = collector.guard(f"collect({ws['name']})", lambda ws=ws: collect_workspace(client, ws, settings, collector),
                                     default={})
            workspaces.append({**workspace_identity(ws), **(detail or {})})
    results = {"workspaces": workspaces, "workspace_filter": requested_workspaces() or None}
    summary = {"workspaces_collected": len(workspaces), **summarize(workspaces, settings)}
    return results, summary


def main() -> int:
    return run_subscription(fetcher=NAME, logger=logger, collect=collect_subscription)


if __name__ == "__main__":
    sys.exit(main())
