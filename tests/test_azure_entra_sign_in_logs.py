"""azure_entra_sign_in_logs: KQL built from settings, scope validation, summaries, and a run through fake ARM and Log Analytics endpoints."""

from __future__ import annotations

import importlib.util
import json
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
SETTINGS = {"lookback_days": 30, "max_rows": 2, "users": [], "app_ids": [], "scope_invalid": False}

ENVS = ("AZURE_AUTHORITY_HOST", "AZURE_TENANT_ID", "AZURE_ENVIRONMENT", "SENTINEL_WORKSPACES",
        sl.LOOKBACK_ENV, sl.USERS_ENV, sl.APPS_ENV, sl.MAX_ROWS_ENV)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for env in ENVS:
        monkeypatch.delenv(env, raising=False)


# --- settings and query text ---

def test_scope_values_are_validated_and_lowercased(monkeypatch):
    monkeypatch.setenv(sl.USERS_ENV, "Admin@Contoso.com, o'brien@contoso.com")
    monkeypatch.setenv(sl.APPS_ENV, APP.upper())
    collector = azure_common.Collector(sl.logger)
    settings = sl.settings_from_env(collector)
    assert (settings["users"], settings["app_ids"], settings["scope_invalid"], collector.ok) == (
        ["admin@contoso.com", "o'brien@contoso.com"], [APP], False, True)
    kql = sl.scope_filter(settings)
    assert 'in (dynamic(["admin@contoso.com", "o\'brien@contoso.com"]))' in kql and f'in (dynamic(["{APP}"]))' in kql


@pytest.mark.parametrize("env, value", [
    (sl.USERS_ENV, 'x" or 1==1 //'), (sl.USERS_ENV, "a\\b@contoso.com"), (sl.APPS_ENV, "not-a-guid"),
    (sl.USERS_ENV, "forbidden throttle timed out"),  # words that match other failure codes stay out of the message
])
def test_a_scope_value_that_could_break_the_query_fails_as_bad_config(monkeypatch, env, value):
    monkeypatch.setenv(env, value)
    collector = azure_common.Collector(sl.logger)
    settings = sl.settings_from_env(collector)
    assert settings["scope_invalid"] and value.lower() not in sl.scope_filter(settings)
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
    for build in (sl.users_query, sl.single_factor_query, sl.audit_events_query):
        assert build(SETTINGS).endswith("| take 3")
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
    "by Upn | order by Upn": table(
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
    "Users = dcountif(tolower(tostring(UserPrincipalName)), Ok)": table(
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


class _Session:
    """ARM: two workspaces, only law-central holds the Entra tables. Log Analytics: canned results keyed by query text."""

    def __init__(self, refuse_query=False, signin_table=True, workspaces=2, refuse_table_lookup=False):
        self.refuse_query, self.signin_table, self.workspaces = refuse_query, signin_table, workspaces
        self.refuse_table_lookup, self.queries = refuse_table_lookup, []

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
        assert urlparse(url).path == "/v1/workspaces/cust-central/query"
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
    settings = {"lookback_days": 30, "max_rows": 2, "users": [], "app_ids": [], "scope_invalid": False}
    assert sl.service_principal_list_query(settings).endswith("| take 3")


def test_service_principal_queries_take_only_the_app_scope(arm, tmp_path, monkeypatch):
    monkeypatch.setenv(sl.USERS_ENV, "admin@contoso.com")
    monkeypatch.setenv(sl.APPS_ENV, APP)
    session = arm()
    assert sl.main() == 0
    sp = [q for q in session.queries if q.startswith("AADServicePrincipalSignInLogs")]
    ni = [q for q in session.queries if q.startswith("AADNonInteractiveUserSignInLogs")]
    assert sp and all("UserPrincipalName" not in q and APP in q for q in sp)
    assert ni and all("admin@contoso.com" in q and APP in q for q in ni)


def test_a_refused_query_leaves_the_new_counts_null(arm, tmp_path):
    arm(refuse_query=True)
    assert sl.main() == 1
    summary = _evidence(tmp_path)["summary"]
    assert summary["non_interactive_sign_in_logs_read"] is False and summary["non_interactive_sign_ins"] is None
    assert summary["service_principal_sign_in_logs_read"] is False and summary["service_principal_principals_signed_in"] is None
