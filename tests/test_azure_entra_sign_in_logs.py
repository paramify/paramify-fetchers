"""azure_entra_sign_in_logs: KQL built from settings, scope validation, summaries, and a run through fake ARM and Log Analytics endpoints."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

_spec = importlib.util.spec_from_file_location("azure_entra_sign_in_logs_under_test", AZURE / "entra_sign_in_logs" / "fetcher.py")
sl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sl)
azure_rest = sys.modules["azure_rest"]
azure_common = sys.modules["azure_common"]

APP = "2b0f4b7e-1c1d-4c3b-9a55-0e7a5b1c2d3e"
# A synthetic service principal's own app id: never an app a user signs in to.
SP_APP = "7d3c9a10-5e2f-4b8a-8c61-3f0e9d2a4b5c"
SETTINGS = {"lookback_days": 30, "max_rows": 2, "users": [], "app_ids": [], "service_principal_app_ids": [],
            "groups": [], "identity_max_age_days": 14, "scope_invalid": False}
# Synthetic Entra group names; the second is in no one's IdentityInfo record.
GROUP, EMPTY_GROUP = "SG-Example-Admins", "SG Example (Ops) & Audit"
GROUPED = {**SETTINGS, "groups": [GROUP, EMPTY_GROUP]}

ENVS = ("AZURE_AUTHORITY_HOST", "AZURE_TENANT_ID", "AZURE_ENVIRONMENT", "SENTINEL_WORKSPACES",
        sl.LOOKBACK_ENV, sl.USERS_ENV, sl.APPS_ENV, sl.SERVICE_PRINCIPAL_APPS_ENV, sl.MAX_ROWS_ENV,
        sl.GROUPS_ENV, sl.IDENTITY_MAX_AGE_ENV)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for env in ENVS:
        monkeypatch.delenv(env, raising=False)


# --- settings and query text ---

def test_scope_values_are_validated_and_lowercased(monkeypatch):
    monkeypatch.setenv(sl.USERS_ENV, "Admin@Contoso.com, o'brien@contoso.com")
    monkeypatch.setenv(sl.APPS_ENV, APP.upper())
    monkeypatch.setenv(sl.SERVICE_PRINCIPAL_APPS_ENV, f" {SP_APP.upper()} ,")
    collector = azure_common.Collector(sl.logger)
    settings = sl.settings_from_env(collector)
    assert (settings["users"], settings["app_ids"], settings["service_principal_app_ids"], settings["scope_invalid"],
            collector.ok) == (["admin@contoso.com", "o'brien@contoso.com"], [APP], [SP_APP], False, True)
    kql = sl.scope_filter(settings)
    assert 'in (dynamic(["admin@contoso.com", "o\'brien@contoso.com"]))' in kql and f'in (dynamic(["{APP}"]))' in kql
    assert SP_APP not in kql, "the service-principal scope never narrows user sign-ins"
    sp_kql = sl.service_principal_filter(settings)
    assert f'in (dynamic(["{SP_APP}"]))' in sp_kql and APP not in sp_kql and "admin@contoso.com" not in sp_kql


@pytest.mark.parametrize("env, value", [
    (sl.USERS_ENV, 'x" or 1==1 //'), (sl.USERS_ENV, "a\\b@contoso.com"), (sl.APPS_ENV, "not-a-guid"),
    (sl.SERVICE_PRINCIPAL_APPS_ENV, 'x" or 1==1 //'),
    (sl.USERS_ENV, "forbidden throttle timed out"),  # words that match other failure codes stay out of the message
])
def test_a_scope_value_that_could_break_the_query_fails_as_bad_config(monkeypatch, env, value):
    monkeypatch.setenv(env, value)
    collector = azure_common.Collector(sl.logger)
    settings = sl.settings_from_env(collector)
    assert settings["scope_invalid"] and value.lower() not in sl.scope_filter(settings)
    assert value.lower() not in sl.service_principal_filter(settings)
    assert value not in collector.failures[0]["message"]
    assert azure_common.classify_failure_code(collector.failures) == "bad_config"


def test_unscoped_queries_read_the_whole_tenant_within_the_lookback():
    kql = sl.overview_query({**SETTINGS, "lookback_days": 90})
    assert kql.startswith("SigninLogs | where TimeGenerated > ago(90d) | extend Ok")
    assert "UserPrincipalName) in" not in kql and "AppId) in" not in kql
    assert f"matches regex @'{sl.STRONG_PATTERN}'" in kql and sl.WINDOWS_SIGN_IN_APP_ID in kql


def test_succeeded_only_queries_filter_before_parsing_the_details():
    kql = sl.cube_query(SETTINGS)
    assert kql.index("ResultType) == '0'") < kql.index("mv-apply")


def test_lists_ask_for_one_row_more_than_the_cap_to_detect_truncation():
    for build in (sl.single_factor_query, sl.audit_events_query):
        assert build(SETTINGS).endswith("| take 3")
    assert "| take 3 | project Upn, " in sl.users_query(SETTINGS), "cut first, then drop the key column"
    assert "take" not in sl.audit_count_query(SETTINGS)


def test_audit_queries_name_every_policy_operation_and_the_policy_category():
    kql = sl.audit_count_query(SETTINGS)
    assert kql.startswith("AuditLogs") and "OperationName in~ (" in kql and "=~ 'Policy'" in kql
    for op in sl.POLICY_OPERATIONS:
        assert f"'{op}'" in kql


# --- transforms ---

def test_dynamic_columns_arrive_as_json_text():
    assert sl.as_list('["Password", "FIDO2 security key"]') == ["FIDO2 security key", "Password"]
    assert sl.as_list(["b", "a", None]) == ["a", "b"]
    assert sl.as_list("not json") == [] and sl.as_list(None) == []


def test_counts_and_set_counts():
    cube = [{"Req": "multiFactorAuthentication", "CA": "success", "Risk": "none", "SignIns": 9},
            {"Req": "singleFactorAuthentication", "CA": "", "Risk": "hidden", "SignIns": 1}]
    assert sl.counts(cube, "Req") == {"multiFactorAuthentication": 9, "singleFactorAuthentication": 1}
    assert sl.counts(cube, "CA") == {"(none)": 1, "success": 9}
    sets = [{"M": '["Password", "FIDO2 security key"]', "P": '["multiConditionalAccess"]', "SignIns": 4},
            {"M": '["Password"]', "P": "[]", "SignIns": 6}]
    assert sl.set_counts(sets, "M") == {"FIDO2 security key": 4, "Password": 10}
    assert sl.set_counts(sets, "P") == {"multiConditionalAccess": 4}


def test_sign_in_summary_percentages():
    summary = sl.sign_in_summary({"SignIns": 12, "Succeeded": 10, "Failed": 2, "SucceededMultiFactor": 9,
                                  "SucceededSingleFactor": 1, "SucceededPhishingResistant": 4, "SucceededRisky": 1,
                                  "SucceededDeviceLogons": 3},
                                 {"Users": 3, "UsersWithSingleFactorSuccess": 1})
    assert (summary["multi_factor_percentage"], summary["phishing_resistant_percentage"],
            summary["users_with_single_factor_success"], summary["succeeded_device_logons"]) == (90, 40, 1, 3)


def test_capped_marks_truncation():
    assert sl.capped([1, 2, 3], 2) == ([1, 2], True)
    assert sl.capped([1, 2], 2) == ([1, 2], False)


# --- a run through fake ARM and Log Analytics ---

SUB = "/subscriptions/hub"
WS_ID = f"{SUB}/resourceGroups/rg-sec/providers/Microsoft.OperationalInsights/workspaces/law-central"
WS2_ID = f"{SUB}/resourceGroups/rg-app/providers/Microsoft.OperationalInsights/workspaces/law-app"


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text = status, body, "", json.dumps(body)
        self.headers: dict = {}

    def json(self):
        return self._body


def table(columns, rows):
    return {"tables": [{"columns": [{"name": c} for c in columns], "rows": rows}]}


QUERY_RESULTS = {
    "SucceededDeviceLogons = countif": table(
        ["SignIns", "Succeeded", "Failed", "SucceededMultiFactor", "SucceededSingleFactor",
         "SucceededSingleFactorPhishingResistant", "SucceededDeviceLogons", "SucceededPhishingResistant",
         "SucceededRisky", "FirstSignIn", "LastSignIn"],
        [[12, 10, 2, 9, 1, 0, 0, 4, 0, "2026-10-05T01:00:00Z", "2026-11-03T22:10:00Z"]]),
    "UsersWithSingleFactorSuccess": table(["Users", "UsersWithSingleFactorSuccess"], [[3, 1]]),
    "by UserKey | order by Upn": table(
        ["Upn", "SignIns", "Succeeded", "Failed", "SucceededSingleFactor", "SucceededPhishingResistant", "LastSignIn"],
        [["a@contoso.com", 5, 5, 0, 0, 4, "2026-11-03T22:10:00Z"], ["b@contoso.com", 4, 3, 1, 1, 0, "2026-11-02T10:00:00Z"],
         ["c@contoso.com", 3, 2, 1, 0, 0, "2026-11-01T10:00:00Z"]]),
    "project TimeGenerated, Upn": table(
        ["TimeGenerated", "Upn", "AppDisplayName", "AppId", "CA", "Providers", "Methods"],
        # Dynamic columns come back as JSON text, as the real query API sends them.
        [["2026-11-02T10:00:00Z", "b@contoso.com", "Azure Portal", APP, "notApplied", "[]", '["Password"]']]),
    "by Req, CA, Risk": table(["Req", "CA", "Risk", "SignIns"], [
        ["multiFactorAuthentication", "success", "none", 9], ["singleFactorAuthentication", "notApplied", "none", 1]]),
    "by M = tostring(Methods), P = tostring(Providers)": table(["M", "P", "SignIns"], [
        ['["FIDO2 security key"]', '["multiConditionalAccess"]', 4],
        ['["Mobile app notification", "Password"]', '["multiConditionalAccess"]', 5],
        ['["Password"]', "[]", 1]]),
    "summarize Changes = count() by OperationName": table(["OperationName", "Changes"], [
        ["Update conditional access policy", 1], ["Authentication Methods Policy Update", 1], ["Update named location", 1]]),
    "Users = dcountif(UserKey, Ok)": table(
        ["SignIns", "Succeeded", "Failed", "Users", "Apps", "Risky", "LastSignIn"], [[40, 38, 2, 3, 4, 1, "2026-11-03T23:00:00Z"]]),
    "by CA = tostring(ConditionalAccessStatus)": table(["CA", "SignIns"], [["success", 30], ["notApplied", 8]]),
    "Principals = dcountif(tostring(ServicePrincipalId), Ok)": table(
        ["SignIns", "Succeeded", "Failed", "Principals", "PrincipalsFailing", "LastSignIn"], [[20, 18, 2, 2, 1, "2026-11-03T21:00:00Z"]]),
    "by ServicePrincipalId = tostring(ServicePrincipalId)": table(
        ["ServicePrincipalId", "ServicePrincipalName", "AppId", "SignIns", "Succeeded", "Failed", "LastSignIn"],
        [["sp-1", "fetcher-identity", APP, 12, 12, 0, "2026-11-03T21:00:00Z"], ["sp-2", "ci-runner", "11111111-1111-1111-1111-111111111111", 6, 6, 0, "2026-11-02T00:00:00Z"],
         ["sp-3", "legacy-app", "22222222-2222-2222-2222-222222222222", 2, 0, 2, "2026-11-01T00:00:00Z"]]),
    "InitiatedByUser": table(
        ["TimeGenerated", "OperationName", "Result", "InitiatedByUser", "InitiatedByApp", "Target", "TargetId"],
        [["2026-10-20T15:00:00Z", "Update conditional access policy", "success", "admin1@contoso.com", "", "Require MFA for admins", "p1"],
         ["2026-10-15T15:00:00Z", "Update named location", "success", "admin1@contoso.com", "", "HQ", "l1"],
         ["2026-10-12T15:00:00Z", "Authentication Methods Policy Update", "success", "admin2@contoso.com", "", "", ""]]),
}


# What the fake IdentityInfo answers: 40 identities, the newest record 5 hours old, 3 of them in GROUP now.
IDENTITY = {"Newest": "2026-11-09T19:00:00Z", "AgeHours": 5, "Identities": 40, "Members": 3, "MembersOnlyInOlderRecords": 0}
IDENTITY_STATS_MARK, IDENTITY_GROUPS_MARK = "MembersOnlyInOlderRecords", "summarize Members = count() by Group"


class _Session:
    """ARM: two workspaces, only law-central holds the Entra tables. Log Analytics: canned results keyed by query text."""

    def __init__(self, refuse_query=False, signin_table=True, workspaces=2, refuse_table_lookup=False,
                 identity_table=True, identity=None, identity_groups=None, identity_retention=30,
                 refuse_identity_query=False, refuse_identity_lookup=False):
        self.refuse_query, self.signin_table, self.workspaces = refuse_query, signin_table, workspaces
        self.refuse_table_lookup, self.queries = refuse_table_lookup, []
        self.identity_table, self.identity = identity_table, {**IDENTITY, **(identity or {})}
        # Sentinel spells a group as Entra does; the fetcher's query returns it lower-cased.
        self.identity_groups = [[GROUP.lower(), 3]] if identity_groups is None else identity_groups
        self.identity_retention, self.refuse_identity_query = identity_retention, refuse_identity_query
        self.refuse_identity_lookup, self.timespans, self.table_lookups = refuse_identity_lookup, [], []

    def get(self, url, params=None, headers=None, timeout=None):
        path = urlparse(url).path
        if path.endswith("/providers/Microsoft.OperationalInsights/workspaces"):
            return _Resp(200, {"value": [
                {"id": WS_ID, "name": "law-central", "location": "usgovvirginia",
                 "properties": {"customerId": "cust-central", "retentionInDays": 90}},
                {"id": WS2_ID, "name": "law-app", "location": "usgovvirginia",
                 "properties": {"customerId": "cust-app", "retentionInDays": 30}}][: self.workspaces]})
        if path.endswith("/onboardingStates"):
            return _Resp(200, {"value": [{"name": "default"}] if "law-central" in path else []})
        if "/tables/" in path:
            self.table_lookups.append(path.rsplit("/workspaces/", 1)[1])
            if path.endswith("/IdentityInfo"):
                if self.refuse_identity_lookup:
                    return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
                if not self.identity_table or "law-central" not in path:
                    return _Resp(404, {"error": {"code": "ResourceNotFound", "message": "no table"}})
                return _Resp(200, {"properties": {"retentionInDays": self.identity_retention}})
            if self.refuse_table_lookup and "law-app" in path:
                return _Resp(403, {"error": {"code": "AuthorizationFailed", "message": "no"}})
            present = "law-central" in path and (self.signin_table or path.endswith("/AuditLogs"))
            if not present:
                return _Resp(404, {"error": {"code": "ResourceNotFound", "message": "no table"}})
            return _Resp(200, {"properties": {"retentionInDays": 90}})
        return _Resp(404, {"error": {"code": "NotFound", "message": path}})

    def post(self, url, json=None, headers=None, timeout=None, params=None):
        query = (json or {}).get("query", "")
        self.queries.append(query)
        self.timespans.append((json or {}).get("timespan"))
        assert urlparse(url).path == "/v1/workspaces/cust-central/query"
        if IDENTITY_STATS_MARK in query or IDENTITY_GROUPS_MARK in query:
            if self.refuse_identity_query:
                return _Resp(403, {"error": {"code": "InsufficientAccessError", "message": "no access to IdentityInfo"}})
            if IDENTITY_STATS_MARK in query:
                return _Resp(200, table(list(self.identity), [list(self.identity.values())]))
            return _Resp(200, table(["Group", "Members"], self.identity_groups))
        if self.refuse_query:
            return _Resp(403, {"error": {"code": "InsufficientAccessError", "message": "no access to SigninLogs"}})
        for key, result in QUERY_RESULTS.items():
            if key in query:
                return _Resp(200, result)
        raise AssertionError(f"unexpected query: {query[:120]}")


class _Cred:
    def get_token(self, scope):
        return namedtuple("T", "token expires_on")("tok", 9_999_999_999)


@pytest.fixture
def arm(monkeypatch, tmp_path):
    def serve(**kwargs):
        session = _Session(**kwargs)
        monkeypatch.setattr("requests.Session", lambda: session)
        return session

    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: _Cred())
    monkeypatch.setattr(azure_rest, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "hub")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setenv(sl.MAX_ROWS_ENV, "2")
    return serve


def _evidence(tmp_path):
    [path] = tmp_path.glob("azure_entra_sign_in_logs_hub.json")
    return json.loads(path.read_text())


def test_main_reads_sign_ins_and_policy_changes_from_the_workspace_that_has_them(arm, tmp_path):
    session = arm()
    assert sl.main() == 0
    evidence = _evidence(tmp_path)
    summary = evidence["summary"]
    assert evidence["metadata"]["partial_failure"] is False
    assert {k: summary[k] for k in (
        "workspaces_collected", "workspaces_with_sign_in_logs", "sign_in_logs_workspaces", "sign_in_logs_read", "sign_ins",
        "sign_ins_succeeded", "succeeded_multi_factor", "succeeded_single_factor", "multi_factor_percentage",
        "phishing_resistant_percentage", "all_successful_sign_ins_multi_factor", "users_signed_in",
        "users_with_single_factor_success", "latest_sign_in", "audit_logs_read", "policy_changes")} == {
        "workspaces_collected": 2, "workspaces_with_sign_in_logs": 1, "sign_in_logs_workspaces": ["law-central"],
        "sign_in_logs_read": True, "sign_ins": 12, "sign_ins_succeeded": 10, "succeeded_multi_factor": 9,
        "succeeded_single_factor": 1, "multi_factor_percentage": 90, "phishing_resistant_percentage": 40,
        "all_successful_sign_ins_multi_factor": False, "users_signed_in": 3, "users_with_single_factor_success": 1,
        "latest_sign_in": "2026-11-03T22:10:00Z", "audit_logs_read": True, "policy_changes": 3}
    assert summary["succeeded_by_method"] == {"FIDO2 security key": 4, "Mobile app notification": 5, "Password": 6}
    assert summary["succeeded_by_requirement_provider"] == {"multiConditionalAccess": 9}
    # Counts come from the uncapped query even though the event list (cap 2) is cut.
    assert summary["policy_changes_by_operation"] == {"Authentication Methods Policy Update": 1,
                                                       "Update conditional access policy": 1, "Update named location": 1}
    central = next(w for w in evidence["results"]["workspaces"] if w["name"] == "law-central")
    assert central["sign_in_logs"]["users_truncated"] is True and len(central["sign_in_logs"]["users"]) == 2
    assert central["sign_in_logs"]["single_factor_sign_ins"][0]["methods"] == ["Password"]
    assert central["audit_logs"]["policy_change_events_truncated"] is True and central["audit_logs"]["policy_changes"] == 3
    app = next(w for w in evidence["results"]["workspaces"] if w["name"] == "law-app")
    assert (app["sign_in_logs_table_present"], app["sign_in_logs"]) == (False, None)
    # Six sign-in queries and two audit queries, all against the one workspace that has the tables.
    assert len([q for q in session.queries if q.startswith("SigninLogs")]) == 6
    assert len([q for q in session.queries if q.startswith("AuditLogs")]) == 2


def test_a_refused_query_fails_the_run_and_leaves_every_sign_in_field_null(arm, tmp_path):
    arm(refuse_query=True)
    assert sl.main() == 1
    summary = _evidence(tmp_path)["summary"]
    assert (summary["sign_in_logs_read"], summary["sign_ins"], summary["multi_factor_percentage"],
            summary["all_successful_sign_ins_multi_factor"], summary["audit_logs_read"],
            summary["policy_changes"]) == (False, None, None, None, False, None)
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


def test_no_workspace_with_sign_in_logs_is_evidence_not_a_failure(arm, tmp_path):
    arm(signin_table=False)
    assert sl.main() == 0
    summary = _evidence(tmp_path)["summary"]
    assert (summary["workspaces_with_sign_in_logs"], summary["sign_in_logs_read"], summary["sign_ins"]) == (0, False, None)
    assert summary["audit_logs_read"] is True


def test_a_failed_table_lookup_on_another_workspace_leaves_completeness_unknown(arm, tmp_path):
    arm(refuse_table_lookup=True)
    assert sl.main() == 1
    summary = _evidence(tmp_path)["summary"]
    assert (summary["workspaces_with_sign_in_logs"], summary["sign_in_logs_read"], summary["sign_ins"],
            summary["audit_logs_read"]) == (1, False, None, False)


def test_scope_is_written_into_every_sign_in_query_and_never_into_the_audit_query(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.USERS_ENV, "admin1@contoso.com")
    session = arm()
    assert sl.main() == 0
    assert _evidence(tmp_path)["summary"]["scope_users"] == ["admin1@contoso.com"]
    sign_in_queries = [q for q in session.queries if q.startswith("SigninLogs")]
    assert sign_in_queries and all('dynamic(["admin1@contoso.com"])' in q for q in sign_in_queries)
    assert all("admin1@contoso.com" not in q for q in session.queries if q.startswith("AuditLogs"))


@pytest.mark.parametrize("workspaces", [2, 0])
def test_a_bad_scope_value_fails_the_run_once_and_runs_no_query(arm, tmp_path, monkeypatch, workspaces):
    monkeypatch.setenv(sl.APPS_ENV, "portal")
    session = arm(workspaces=workspaces)
    assert sl.main() == 1
    evidence = _evidence(tmp_path)
    assert len(evidence["metadata"]["api_failures"]) == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"
    assert session.queries == [] and evidence["summary"]["workspaces_collected"] == 0


def test_non_interactive_and_service_principal_tables_are_counted_not_copied(arm, tmp_path, assert_summary_documented):
    session = arm()
    assert sl.main() == 0
    evidence = _evidence(tmp_path)
    summary = evidence["summary"]
    assert_summary_documented("azure/entra_sign_in_logs", summary)
    assert summary["non_interactive_sign_in_logs_read"] is True and summary["non_interactive_sign_ins"] == 40
    assert summary["non_interactive_failed"] == 2 and summary["non_interactive_users_signed_in"] == 3 and summary["non_interactive_succeeded_risky"] == 1
    assert summary["service_principal_sign_in_logs_read"] is True and summary["service_principal_sign_ins"] == 20
    assert summary["service_principal_principals_signed_in"] == 2 and summary["service_principal_principals_with_failures"] == 1
    central = next(w for w in evidence["results"]["workspaces"] if w["name"] == "law-central")
    sp = central["service_principal_sign_in_logs"]
    assert sp["principals_truncated"] is True and [p["service_principal_name"] for p in sp["principals"]] == ["fetcher-identity", "ci-runner"]
    assert set(sp["principals"][0]) == {"service_principal_id", "service_principal_name", "app_id", "sign_ins", "succeeded", "failed", "last_sign_in"}
    ni = central["non_interactive_sign_in_logs"]
    assert ni["succeeded_by_conditional_access_status"] == {"notApplied": 8, "success": 30}
    assert "users" not in ni and "sign_ins_list" not in ni, "no per-event or per-user rows for non-interactive sign-ins"
    assert len([q for q in session.queries if q.startswith("AADNonInteractiveUserSignInLogs")]) == 2
    assert len([q for q in session.queries if q.startswith("AADServicePrincipalSignInLogs")]) == 2


def test_service_principal_list_asks_for_one_row_more_than_the_cap():
    assert sl.service_principal_list_query(SETTINGS).endswith("| take 3")


def test_service_principal_queries_take_only_their_own_scope(arm, tmp_path, monkeypatch):
    """The user scope and app_ids narrow user sign-ins only; service_principal_app_ids narrows service principals only."""
    monkeypatch.setenv(sl.USERS_ENV, "admin@contoso.com")
    monkeypatch.setenv(sl.APPS_ENV, APP)
    monkeypatch.setenv(sl.SERVICE_PRINCIPAL_APPS_ENV, SP_APP)
    session = arm()
    assert sl.main() == 0
    sp = [q for q in session.queries if q.startswith("AADServicePrincipalSignInLogs")]
    users = [q for q in session.queries if q.startswith(("SigninLogs", "AADNonInteractiveUserSignInLogs"))]
    assert sp and all(SP_APP in q and APP not in q and "UserPrincipalName" not in q for q in sp)
    assert users and all("admin@contoso.com" in q and APP in q and SP_APP not in q for q in users)
    summary = _evidence(tmp_path)["summary"]
    assert (summary["scope_users"], summary["scope_app_ids"], summary["scope_service_principal_app_ids"]) == (
        ["admin@contoso.com"], [APP], [SP_APP])


def test_scoping_service_principals_keeps_every_app_the_scoped_users_signed_in_to(arm, tmp_path, monkeypatch):
    """The reason the scopes are separate: narrowing service principals to their own app ids must not drop the
    scoped administrators' sign-ins to the portal, the CLI or any other app."""
    monkeypatch.setenv(sl.USERS_ENV, "admin@contoso.com")
    baseline = arm()
    assert sl.main() == 0
    before = _evidence(tmp_path)["summary"]
    monkeypatch.setenv(sl.SERVICE_PRINCIPAL_APPS_ENV, SP_APP)
    scoped = arm()
    assert sl.main() == 0
    after = _evidence(tmp_path)["summary"]
    user_tables = ("SigninLogs", "AADNonInteractiveUserSignInLogs")
    assert [q for q in scoped.queries if q.startswith(user_tables)] == [
        q for q in baseline.queries if q.startswith(user_tables)], "user sign-in queries must not change"
    assert all("AppId) in" not in q and "AppId)) in" not in q for q in scoped.queries if q.startswith(user_tables))
    for key in ("sign_ins", "sign_ins_succeeded", "succeeded_multi_factor", "users_signed_in", "non_interactive_sign_ins"):
        assert after[key] == before[key] is not None, key
    assert all(SP_APP in q for q in scoped.queries if q.startswith("AADServicePrincipalSignInLogs"))
    assert after["scope_app_ids"] == [] and after["scope_service_principal_app_ids"] == [SP_APP]



def test_a_refused_query_leaves_the_new_counts_null(arm, tmp_path):
    arm(refuse_query=True)
    assert sl.main() == 1
    summary = _evidence(tmp_path)["summary"]
    assert summary["non_interactive_sign_in_logs_read"] is False and summary["non_interactive_sign_ins"] is None
    assert summary["service_principal_sign_in_logs_read"] is False and summary["service_principal_principals_signed_in"] is None


# --- group scope: members resolved from IdentityInfo at query time ---

USER_TABLES = ("SigninLogs", "AADNonInteractiveUserSignInLogs")


def _user_queries(session):
    """The user sign-in queries sent (interactive and non-interactive), with or without the group prefix."""
    return [q for q in session.queries if IDENTITY_STATS_MARK not in q and IDENTITY_GROUPS_MARK not in q
            and any(f"; {t} " in q or q.startswith(t) for t in USER_TABLES)]


def _others(session):
    return [q for q in session.queries if q.startswith(("AADServicePrincipalSignInLogs", "AuditLogs"))]


def _status(tmp_path):
    return json.loads((tmp_path / "status.json").read_text())


def test_group_names_are_validated_deduplicated_and_kept_as_typed(monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, f" {GROUP} , {EMPTY_GROUP},{GROUP.upper()}, O'Brien's team ,")
    collector = azure_common.Collector(sl.logger)
    settings = sl.settings_from_env(collector)
    assert (settings["groups"], settings["scope_invalid"], collector.ok) == ([GROUP, EMPTY_GROUP, "O'Brien's team"], False, True)
    assert sl.scope_prefix(settings).startswith(f'let ScopeGroups = dynamic(["{GROUP}", "{EMPTY_GROUP}", "O\'Brien\'s team"]); ')


@pytest.mark.parametrize("value", [
    'x"]); SigninLogs | take 1 //',      # closes the string and the list
    'quote"alone', "back\\slash",         # each character that can end or escape the string, on its own
    "trailing\\",                         # a backslash would escape the closing quote
    "two\nlines", "tab\there", "semi;colon", "pipe|take", "brace{}", "angle<>", "dollar$", "back`tick",
    "x" * 257,                            # longer than Entra allows
    "forbidden throttle timed out,",      # words that match other failure codes stay out of the message
])
def test_a_group_name_that_could_break_the_query_fails_as_bad_config(monkeypatch, value):
    monkeypatch.setenv(sl.GROUPS_ENV, f"{GROUP},{value}")
    collector = azure_common.Collector(sl.logger)
    settings = sl.settings_from_env(collector)
    if value.endswith(","):               # a clean name: only the wording is under test
        assert not settings["scope_invalid"]
        return
    assert settings["scope_invalid"] and settings["groups"] == [GROUP]
    assert value not in collector.failures[0]["message"] and value.strip() not in sl.scope_prefix(settings)
    assert azure_common.classify_failure_code(collector.failures) == "bad_config"


def test_a_bad_group_name_runs_no_query_at_all(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, 'x" or 1==1 //')
    session = arm()
    assert sl.main() == 1
    assert session.queries == [] and _status(tmp_path)["code"] == "bad_config"
    assert 'x" or' not in json.dumps(_evidence(tmp_path)), "the refused value is written nowhere"


def test_without_a_group_the_queries_are_exactly_as_before():
    for build in (sl.overview_query, sl.cube_query, sl.sets_query, sl.users_query, sl.user_count_query,
                  sl.single_factor_query, sl.non_interactive_overview_query, sl.non_interactive_ca_query):
        kql = build(SETTINGS)
        assert kql.startswith(USER_TABLES) and "IdentityInfo" not in kql and "let " not in kql
    assert sl.scope_prefix(SETTINGS) == "" and sl.query_days(SETTINGS) == 30


def test_a_group_scoped_query_resolves_current_members_inside_the_query():
    kql = sl.overview_query(GROUPED)
    prefix = sl.scope_prefix(GROUPED)
    assert kql.startswith(prefix) and kql[len(prefix):].startswith("SigninLogs | where TimeGenerated > ago(30d) ")
    assert f'let ScopeGroups = dynamic(["{GROUP}", "{EMPTY_GROUP}"]); ' in prefix
    # The identity window is fixed and longer than the 14-day re-sync, whatever the sign-in lookback is.
    assert f"IdentityInfo | where TimeGenerated > ago({sl.IDENTITY_LOOKBACK_DAYS}d) " in prefix
    assert sl.IDENTITY_LOOKBACK_DAYS > sl.IDENTITY_RESYNC_DAYS
    # Only each identity's newest record decides membership, matched without case.
    assert "summarize arg_max(TimeGenerated, GroupMembership, Oid, IUpn) by IdKey " in prefix
    assert prefix.index("arg_max") < prefix.index("mv-expand G = GroupMembership") < prefix.index("G in~ (ScopeGroups)")
    # A sign-in is kept when its user is a member by object id or by user principal name.
    assert ("| where tolower(tostring(UserId)) in (ScopeIds) or tolower(tostring(UserPrincipalName)) in (ScopeUpns) "
            in kql[len(prefix):])
    for build in (sl.cube_query, sl.sets_query, sl.users_query, sl.user_count_query, sl.single_factor_query,
                  sl.non_interactive_overview_query, sl.non_interactive_ca_query):
        assert build(GROUPED).startswith(prefix) and "in (ScopeIds)" in build(GROUPED), build.__name__


def test_listed_users_are_added_to_the_group_members_not_intersected_with_them():
    kql = sl.overview_query({**GROUPED, "users": ["breakglass@contoso.com"]})
    body = kql[len(sl.scope_prefix(GROUPED)):]
    # One where clause joined with "or": a second "| where" on the users would require both.
    assert ('| where tolower(tostring(UserId)) in (ScopeIds) or tolower(tostring(UserPrincipalName)) in (ScopeUpns) '
            'or tolower(tostring(UserPrincipalName)) in (dynamic(["breakglass@contoso.com"])) ') in body
    assert body.count("breakglass@contoso.com") == 1


def test_the_app_scope_still_narrows_a_group_scoped_query():
    kql = sl.overview_query({**GROUPED, "app_ids": [APP]})
    assert kql.index("in (ScopeIds)") < kql.index(f'| where tolower(AppId) in (dynamic(["{APP}"])) ')


def test_service_principal_and_audit_queries_never_take_the_group_scope():
    for build in (sl.service_principal_overview_query, sl.service_principal_list_query, sl.audit_count_query,
                  sl.audit_events_query):
        kql = build({**GROUPED, "users": ["a@contoso.com"]})
        assert "IdentityInfo" not in kql and "ScopeGroups" not in kql and GROUP not in kql, build.__name__


def test_the_api_timespan_never_cuts_the_identity_window():
    """The query API applies its timespan to every table read, IdentityInfo included."""
    assert sl.query_days({**GROUPED, "lookback_days": 7}) == sl.IDENTITY_LOOKBACK_DAYS
    assert sl.query_days({**GROUPED, "lookback_days": 90}) == 90
    assert sl.query_days({**SETTINGS, "lookback_days": 7}) == 7


def test_a_short_lookback_still_asks_the_api_for_the_whole_identity_window(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    monkeypatch.setenv(sl.LOOKBACK_ENV, "7")
    session = arm()
    assert sl.main() == 0
    spans = dict(zip(session.queries, session.timespans))
    users, others = _user_queries(session), _others(session)
    assert len(users) == 8 and all(spans[q] == "P21D" and "ago(7d)" in q for q in users)
    assert len(others) == 4 and all(spans[q] == "P7D" for q in others)
    assert all(spans[q] == "P21D" for q in session.queries if IDENTITY_STATS_MARK in q or IDENTITY_GROUPS_MARK in q)
    assert _evidence(tmp_path)["summary"]["lookback_days"] == 7


def test_main_scopes_user_sign_ins_to_the_groups_and_records_how_the_scope_resolved(arm, tmp_path, monkeypatch,
                                                                                    assert_summary_documented):
    monkeypatch.setenv(sl.GROUPS_ENV, f"{GROUP},{EMPTY_GROUP}")
    session = arm()
    assert sl.main() == 0
    evidence = _evidence(tmp_path)
    summary = evidence["summary"]
    assert_summary_documented("azure/entra_sign_in_logs", summary)
    assert evidence["metadata"]["partial_failure"] is False
    assert {k: summary[k] for k in ("scope_groups", "group_scope_resolved", "scope_group_members",
                                    "scope_groups_without_members", "identity_info_latest_record",
                                    "identity_info_age_hours", "scope_users", "sign_in_logs_read", "sign_ins",
                                    "non_interactive_sign_ins")} == {
        "scope_groups": [GROUP, EMPTY_GROUP], "group_scope_resolved": True, "scope_group_members": 3,
        "scope_groups_without_members": [EMPTY_GROUP], "identity_info_latest_record": "2026-11-09T19:00:00Z",
        "identity_info_age_hours": 5, "scope_users": [], "sign_in_logs_read": True, "sign_ins": 12,
        "non_interactive_sign_ins": 40}
    # Every user sign-in query carries the group prefix; service principals and the audit log never do.
    users, prefix = _user_queries(session), sl.scope_prefix({"groups": [GROUP, EMPTY_GROUP]})
    assert len(users) == 8 and all(q.startswith(prefix) and "in (ScopeIds)" in q for q in users)
    assert len(_others(session)) == 4 and all("IdentityInfo" not in q for q in _others(session))
    central = next(w for w in evidence["results"]["workspaces"] if w["name"] == "law-central")
    assert central["group_scope"] == {
        "groups": [GROUP, EMPTY_GROUP], "resolved": True, "identity_table_present": True, "identity_retention_days": 30,
        "identity_lookback_days": 21, "identity_max_age_days": 14, "identities": 40,
        "identity_latest_record": "2026-11-09T19:00:00Z", "identity_latest_record_age_hours": 5, "members": 3,
        # Keyed by the name as configured, though Sentinel's spelling came back lower-cased.
        "members_by_group": {GROUP: 3, EMPTY_GROUP: 0}, "groups_without_members": [EMPTY_GROUP],
        "members_only_in_older_records": 0}
    assert any(EMPTY_GROUP in n and "no member" in n for n in central["notes"])
    # The scope is resolved once per workspace: one stats query and one per-group query.
    assert len([q for q in session.queries if IDENTITY_STATS_MARK in q]) == 1
    assert len([q for q in session.queries if IDENTITY_GROUPS_MARK in q]) == 1


def test_a_workspace_without_user_sign_ins_is_never_asked_for_identity_info(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    session = arm()
    assert sl.main() == 0
    assert "law-central/tables/IdentityInfo" in session.table_lookups
    assert "law-app/tables/IdentityInfo" not in session.table_lookups, "law-app holds no sign-in table to narrow"
    app = next(w for w in _evidence(tmp_path)["results"]["workspaces"] if w["name"] == "law-app")
    assert app["group_scope"] is None and app["sign_in_logs"] is None


def test_a_group_scope_with_no_sign_in_table_anywhere_is_not_a_failure(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    session = arm(signin_table=False, identity_table=False)
    assert sl.main() == 0
    summary = _evidence(tmp_path)["summary"]
    assert (summary["group_scope_resolved"], summary["scope_group_members"], summary["sign_in_logs_read"],
            summary["audit_logs_read"]) == (None, None, False, True)
    assert not any("IdentityInfo" in t for t in session.table_lookups)


def _assert_user_sign_ins_unknown(session, tmp_path, code):
    """The fail-closed contract: no user sign-in query is sent, every user figure is null, the rest is still read."""
    evidence = _evidence(tmp_path)
    summary = evidence["summary"]
    assert _user_queries(session) == [], "user sign-ins must never be read unscoped"
    assert (summary["group_scope_resolved"], summary["scope_group_members"], summary["scope_groups_without_members"],
            summary["identity_info_latest_record"], summary["identity_info_age_hours"]) == (False, None, None, None, None)
    assert (summary["sign_in_logs_read"], summary["sign_ins"], summary["users_signed_in"], summary["multi_factor_percentage"],
            summary["all_successful_sign_ins_multi_factor"]) == (False, None, None, None, None)
    assert (summary["non_interactive_sign_in_logs_read"], summary["non_interactive_sign_ins"]) == (False, None)
    # Service principals and policy changes do not depend on the user scope.
    assert summary["service_principal_sign_in_logs_read"] is True and summary["audit_logs_read"] is True
    central = next(w for w in evidence["results"]["workspaces"] if w["name"] == "law-central")
    assert central["sign_in_logs"] is None and central["non_interactive_sign_in_logs"] is None
    assert central["group_scope"]["resolved"] is False
    assert evidence["metadata"]["partial_failure"] is True and _status(tmp_path)["code"] == code
    return central["group_scope"], evidence["metadata"]["api_failures"]


def test_no_identity_info_table_leaves_user_sign_ins_unknown_as_bad_config(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    session = arm(identity_table=False)
    assert sl.main() == 1
    scope, failures = _assert_user_sign_ins_unknown(session, tmp_path, "bad_config")
    assert scope["identity_table_present"] is False and scope["members"] is None
    assert len(failures) == 1 and "UEBA" in failures[0]["message"] and GROUP not in failures[0]["message"]
    assert not any(IDENTITY_STATS_MARK in q for q in session.queries)


@pytest.mark.parametrize("age, max_age, stale", [(14 * 24 + 1, None, True), (14 * 24, None, False), (49, "2", True),
                                                 (48, "2", False), (500, "21", False), (505, "21", True)])
def test_stale_identity_info_leaves_user_sign_ins_unknown(arm, tmp_path, monkeypatch, age, max_age, stale):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    if max_age:
        monkeypatch.setenv(sl.IDENTITY_MAX_AGE_ENV, max_age)
    session = arm(identity={"AgeHours": age})
    assert sl.main() == (1 if stale else 0)
    if stale:
        scope, failures = _assert_user_sign_ins_unknown(session, tmp_path, "partial_failure")
        assert scope["identity_latest_record_age_hours"] == age and "out of date" in failures[0]["message"]
    else:
        assert _evidence(tmp_path)["summary"]["identity_info_age_hours"] == age and len(_user_queries(session)) == 8


@pytest.mark.parametrize("identity", [{"Newest": None, "AgeHours": None, "Identities": 0, "Members": 0},
                                      {"Newest": "", "AgeHours": "", "Identities": 0},
                                      {"AgeHours": None},     # a record with no measurable age
                                      {"Identities": 0}])
def test_identity_info_with_no_record_leaves_user_sign_ins_unknown(arm, tmp_path, monkeypatch, identity):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    session = arm(identity=identity)
    assert sl.main() == 1
    _, failures = _assert_user_sign_ins_unknown(session, tmp_path, "partial_failure")
    assert "no identity record" in failures[0]["message"]


def test_an_empty_stats_answer_is_unknown_not_zero(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    session = arm()
    session.identity = {}                 # the query API answered with no row at all
    session_post = session.post

    def post(url, json=None, **kwargs):
        if IDENTITY_STATS_MARK in (json or {}).get("query", ""):
            session.queries.append(json["query"])
            session.timespans.append(json.get("timespan"))
            return _Resp(200, {"tables": []})
        return session_post(url, json=json, **kwargs)

    session.post = post
    assert sl.main() == 1
    _assert_user_sign_ins_unknown(session, tmp_path, "partial_failure")


def test_groups_that_match_no_one_fail_rather_than_report_zero_sign_ins(arm, tmp_path, monkeypatch):
    """A misspelt group name must not read as 'no one signed in'."""
    monkeypatch.setenv(sl.GROUPS_ENV, "SG-Exmaple-Admins")
    session = arm(identity={"Members": 0}, identity_groups=[])
    assert sl.main() == 1
    scope, failures = _assert_user_sign_ins_unknown(session, tmp_path, "bad_config")
    assert scope["members"] == 0 and scope["groups_without_members"] == ["SG-Exmaple-Admins"]
    assert "none of the 1 group(s)" in failures[0]["message"] and "Exmaple" not in failures[0]["message"]


def test_groups_that_match_no_one_still_scope_to_the_listed_users(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, EMPTY_GROUP)
    monkeypatch.setenv(sl.USERS_ENV, "breakglass@contoso.com")
    session = arm(identity={"Members": 0}, identity_groups=[])
    assert sl.main() == 0
    summary = _evidence(tmp_path)["summary"]
    assert (summary["group_scope_resolved"], summary["scope_group_members"], summary["scope_groups_without_members"],
            summary["scope_users"]) == (True, 0, [EMPTY_GROUP], ["breakglass@contoso.com"])
    users = _user_queries(session)
    assert len(users) == 8 and all("in (ScopeIds)" in q and 'dynamic(["breakglass@contoso.com"])' in q for q in users)


def test_a_refused_identity_query_leaves_user_sign_ins_unknown_as_not_authorized(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    session = arm(refuse_identity_query=True)
    assert sl.main() == 1
    scope, failures = _assert_user_sign_ins_unknown(session, tmp_path, "not_authorized")
    assert scope["identity_table_present"] is True and scope["identities"] is None
    assert failures[0]["operation"] == "loganalytics.query(IdentityInfo, law-central)"


def test_a_refused_identity_table_lookup_leaves_user_sign_ins_unknown(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    session = arm(refuse_identity_lookup=True)
    assert sl.main() == 1
    scope, _ = _assert_user_sign_ins_unknown(session, tmp_path, "not_authorized")
    assert scope["identity_table_present"] is None
    assert not any(IDENTITY_STATS_MARK in q for q in session.queries)


@pytest.mark.parametrize("retention, ok, noted", [(13, False, False), (14, True, True), (20, True, True),
                                                  (21, True, False), (30, True, False)])
def test_identity_info_retention_below_the_resync_fails_and_below_the_window_is_noted(arm, tmp_path, monkeypatch,
                                                                                    retention, ok, noted):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    session = arm(identity_retention=retention)
    assert sl.main() == (0 if ok else 1)
    central = next(w for w in _evidence(tmp_path)["results"]["workspaces"] if w["name"] == "law-central")
    assert central["group_scope"]["identity_retention_days"] == retention
    assert any(f"keeps {retention} days" in n and "IdentityInfo" in n for n in central["notes"]) is noted
    if not ok:
        _, failures = _assert_user_sign_ins_unknown(session, tmp_path, "partial_failure")
        assert "re-sync" in failures[0]["message"] and not any(IDENTITY_STATS_MARK in q for q in session.queries)


def test_a_record_stamped_in_the_future_counts_as_fresh(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    arm(identity={"AgeHours": -3})
    assert sl.main() == 0
    assert _evidence(tmp_path)["summary"]["identity_info_age_hours"] == 0


def test_members_dropped_since_an_older_record_are_noted(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    arm(identity={"MembersOnlyInOlderRecords": 2})
    assert sl.main() == 0
    central = next(w for w in _evidence(tmp_path)["results"]["workspaces"] if w["name"] == "law-central")
    assert central["group_scope"]["members_only_in_older_records"] == 2
    assert any(n.startswith("2 identity(ies) were in a listed group in an older") for n in central["notes"])


@pytest.mark.parametrize("value, code, days", [("abc", 1, 14), ("0", 1, 14), ("-5", 1, 14), ("99", 0, 21), ("3", 0, 3)])
def test_the_max_age_setting_is_bounded_and_a_bad_value_fails_as_bad_config(arm, tmp_path, monkeypatch, value, code, days):
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    monkeypatch.setenv(sl.IDENTITY_MAX_AGE_ENV, value)
    arm()
    assert sl.main() == code
    central = next(w for w in _evidence(tmp_path)["results"]["workspaces"] if w["name"] == "law-central")
    assert central["group_scope"]["identity_max_age_days"] == days
    if code:
        assert _status(tmp_path)["code"] == "bad_config"


def test_the_evidence_names_no_group_member(arm, tmp_path, monkeypatch):
    """Members are resolved by the workspace; only counts come back. A member is named only if they signed in."""
    monkeypatch.setenv(sl.GROUPS_ENV, GROUP)
    session = arm()
    assert sl.main() == 0
    [stats] = [q for q in session.queries if IDENTITY_STATS_MARK in q]
    [by_group] = [q for q in session.queries if IDENTITY_GROUPS_MARK in q]
    # What each identity query returns is fixed by its last stage: aggregates only, no identity column.
    final = stats.rsplit("; ", 1)[1]
    assert final.startswith("Records | summarize Newest = max(TimeGenerated) | extend ")
    returned = re.findall(r"(\w+) = (?:tolong|toscalar)\(", final)
    assert returned == ["AgeHours", "Identities", "Members", "MembersOnlyInOlderRecords"]
    assert "distinct Member | count" in final and final.count("| count)") == 3, "every figure is a count"
    assert by_group.endswith("| summarize by Member, Group = tolower(G) | summarize Members = count() by Group")
    for q in (stats, by_group):
        assert "AccountDisplayName" not in q and "MailAddress" not in q and "project IdKey" not in q
    central = next(w for w in _evidence(tmp_path)["results"]["workspaces"] if w["name"] == "law-central")
    scope = central["group_scope"]
    assert {k for k, v in scope.items() if isinstance(v, (list, dict))} == {"groups", "members_by_group", "groups_without_members"}
    assert set(scope["members_by_group"]) == {GROUP}, "keyed by group, never by member"


def test_group_scope_summary_takes_the_stalest_workspace_and_is_null_unless_every_one_resolved():
    def ws(resolved, members=0, record=None, age=None, empty=()):
        return {"group_scope": {"resolved": resolved, "members": members, "identity_latest_record": record,
                                "identity_latest_record_age_hours": age, "groups_without_members": list(empty)}}
    settings = {"groups": ["A", "B"]}
    both = sl._group_scope_summary([ws(True, 3, "2026-11-09T10:00:00Z", 4, ["B"]), ws(True, 2, "2026-11-08T10:00:00Z", 28),
                                    {"group_scope": None}], settings)
    assert both == {"scope_groups": ["A", "B"], "group_scope_resolved": True, "scope_group_members": 5,
                    "scope_groups_without_members": ["B"], "identity_info_latest_record": "2026-11-08T10:00:00Z",
                    "identity_info_age_hours": 28}
    one_failed = sl._group_scope_summary([ws(True, 3, "2026-11-09T10:00:00Z", 4), ws(False)], settings)
    assert one_failed == {"scope_groups": ["A", "B"], "group_scope_resolved": False, "scope_group_members": None,
                          "scope_groups_without_members": None, "identity_info_latest_record": None,
                          "identity_info_age_hours": None}
    unset = sl._group_scope_summary([{"group_scope": None}], {"groups": []})
    assert unset["scope_groups"] == [] and unset["group_scope_resolved"] is None and unset["scope_group_members"] is None


def test_a_stray_max_age_value_cannot_fail_a_run_without_a_group_scope(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.IDENTITY_MAX_AGE_ENV, "abc")
    session = arm()
    assert sl.main() == 0
    assert not any("IdentityInfo" in q for q in session.queries)
    assert _evidence(tmp_path)["summary"]["group_scope_resolved"] is None


# --- a person is counted once, however Entra names their sign-ins ---

def test_users_are_counted_by_object_id_not_by_the_name_in_each_log_row():
    """Seen live: 25 group members read as 26 users, because one member's sign-ins were logged with no name and
    one with an id where the name goes."""
    key = f"UserKey = iff(isnotempty(Uid) and Uid != '{sl.NO_USER_ID}', Uid, Upn)"
    for settings in (SETTINGS, GROUPED):
        base = sl.base_query(settings)
        assert "Uid = tolower(tostring(UserId))" in base and f"| extend {key} " in base
        assert "countif(Ok and SingleFactor) by UserKey | summarize Users = count()" in sl.user_count_query(settings)
        users = sl.users_query(settings)
        assert " by UserKey | order by Upn asc, UserKey asc | take 3 | project Upn, SignIns, " in users
        # The name shown is never blank or an id when the person has a real one; the key itself is not returned.
        assert "Upn = maxif(Upn, isnotempty(Upn) and not(Upn matches regex @'^[0-9a-f]{8}-[0-9a-f]{4}-')) by UserKey" in users
        assert users.endswith("SucceededPhishingResistant, LastSignIn") and "project UserKey" not in users
        non_interactive = sl.non_interactive_overview_query(settings)
        assert f"| extend {key} " in non_interactive and "Users = dcountif(UserKey, Ok)" in non_interactive


def test_an_attempt_for_an_unknown_account_is_keyed_by_the_name_typed():
    """Entra files those under an all-zero id; keyed by it, every unknown account would read as one user."""
    assert sl.NO_USER_ID == "00000000-0000-0000-0000-000000000000" and f"Uid != '{sl.NO_USER_ID}', Uid, Upn)" in sl._USER_KEY


def test_a_user_with_no_usable_name_is_listed_without_one():
    assert sl.user_record({"Upn": "", "SignIns": 7, "Succeeded": 7})["user_principal_name"] is None
    assert sl.user_record({"Upn": None, "SignIns": 1})["sign_ins"] == 1
