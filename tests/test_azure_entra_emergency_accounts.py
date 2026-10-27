"""azure_entra_emergency_accounts against synthetic Graph and ARM responses: no SDK, credentials or network."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "entra_emergency_accounts" / "fetcher.py"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))

spec = importlib.util.spec_from_file_location("azure_entra_emergency_accounts_under_test", FETCHER)
emergency = importlib.util.module_from_spec(spec)
spec.loader.exec_module(emergency)

# On sys.path once the fetcher loads.
from azure_common import classify_failure_code  # noqa: E402
from azure_rest import LAW_API, SI_API, SI_PREVIEW_API  # noqa: E402

SUB = "00000000-0000-0000-0000-0000000000cc"
TENANT = "00000000-0000-0000-0000-0000000000aa"
WS = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law"
NOW = datetime.now(timezone.utc)
# The form these REST reads raise: "(<status>) <code>: <message>".
DENIED = emergency.ArmError(403, "Authorization_RequestDenied", "Insufficient privileges to complete the operation.")
NOT_LICENSED = emergency.ArmError(
    403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
    "Neither tenant is B2C or tenant doesn't have premium license")
ADMIN_ROLE = "62e90394-69f5-4237-9190-012177145e10"


def uid(n: int) -> str:
    return f"00000000-0000-0000-0000-{n:012d}"


BG1, BG2, SVC, OFF, ADMIN, GUEST, OUTSIDER = (uid(n) for n in range(1, 8))


def _ago(days):
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _user(i, name, enabled=True, guest=False, last=None):
    user = {"id": i, "displayName": name, "userPrincipalName": f"{name}@contoso.test", "accountEnabled": enabled,
            "userType": "Guest" if guest else "Member", "createdDateTime": _ago(400)}
    if last is not None:
        user["signInActivity"] = {"lastSuccessfulSignInDateTime": _ago(last), "lastSignInDateTime": _ago(last)}
    return user


USERS = {
    BG1: _user(BG1, "breakglass1", last=40),
    BG2: _user(BG2, "breakglass2", last=10),
    SVC: _user(SVC, "svc-sync"),
    OFF: _user(OFF, "former", enabled=False),
    ADMIN: _user(ADMIN, "admin"),
    GUEST: _user(GUEST, "partner_ext", guest=True),
    OUTSIDER: _user(OUTSIDER, "outsider"),
}


def _policy(pid, name, state="enabled", controls=("mfa",), strength=None, users=None):
    return {"id": pid, "displayName": name, "state": state,
            "grantControls": {"builtInControls": list(controls), "authenticationStrength": strength},
            "conditions": {"users": {"includeUsers": ["All"], **(users or {})}}}


def _rule(name, query, enabled=True, kind="Scheduled"):
    return {"id": f"{WS}/providers/Microsoft.SecurityInsights/alertRules/{name}", "kind": kind,
            "properties": {"displayName": name, "enabled": enabled, "query": query}}


def _log_alert(name, query, enabled=True):
    return {"id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Insights/scheduledQueryRules/{name}",
            "name": name, "kind": "LogAlert",
            "properties": {"displayName": name, "enabled": enabled, "criteria": {"allOf": [{"query": query}]}}}


def _tenant():
    graph = {
        "/organization": [{"id": TENANT}],
        "/identity/conditionalAccess/policies": [
            _policy("p-all", "MFA for everyone", users={"excludeGroups": ["g-bg"], "excludeUsers": [SVC, OFF]}),
            _policy("p-admins", "Phishing-resistant MFA for admins", controls=(), strength={"id": "s"},
                    users={"excludeGroups": ["g-bg"]}),
            # Neither counts: report-only, and no MFA grant.
            _policy("p-pilot", "Pilot", state="enabledForReportingButNotEnforced", users={"excludeUsers": [OUTSIDER]}),
            _policy("p-device", "Compliant device", controls=("compliantDevice",), users={"excludeUsers": [OUTSIDER]}),
        ],
        "/groups/g-bg/transitiveMembers/microsoft.graph.user": [USERS[BG1], USERS[BG2]],
        **{f"/users/{i}": u for i, u in USERS.items()},
        "/users/breakglass1@contoso.test": USERS[BG1],
        f"/reports/authenticationMethods/userRegistrationDetails/{BG1}": {
            "id": BG1, "methodsRegistered": ["fido2SecurityKey"], "isMfaRegistered": True},
        f"/reports/authenticationMethods/userRegistrationDetails/{BG2}": {
            "id": BG2, "methodsRegistered": ["microsoftAuthenticatorPush"], "isMfaRegistered": True},
    }
    arm = {
        f"/subscriptions/{SUB}": {"id": f"/subscriptions/{SUB}", "tenantId": TENANT},
        (f"/subscriptions/{SUB}/providers/Microsoft.OperationalInsights/workspaces", LAW_API): [
            {"id": WS, "name": "law", "location": "eastus", "properties": {"customerId": "c"}}],
        (f"{WS}/providers/Microsoft.SecurityInsights/onboardingStates", SI_API): [{"name": "default"}],
        (f"{WS}/providers/Microsoft.SecurityInsights/alertRules", SI_API): [
            _rule("Break-glass sign-in", 'SigninLogs | where UserPrincipalName =~ "BreakGlass1@contoso.test"'),
            _rule("Old break-glass rule", f'SigninLogs | where UserId == "{BG2}"', enabled=False),
        ],
        (f"{WS}/providers/Microsoft.SecurityInsights/alertRules", SI_PREVIEW_API): [
            _rule("Break-glass sign-in", 'SigninLogs | where UserPrincipalName =~ "BreakGlass1@contoso.test"'),
        ],
        (f"/subscriptions/{SUB}/providers/Microsoft.Insights/scheduledQueryRules", "2023-12-01"): [
            _log_alert("Emergency account used", f'SigninLogs | where UserId in ("{BG1}")'),
        ],
    }
    return graph, arm


class FakeClient:
    """AzureRestClient's get / graph_list / graph_get / list, answered from dicts; errors by path substring."""

    def __init__(self, graph, arm, errors=None):
        self.graph, self.arm, self.errors, self.calls = graph, arm, errors or {}, []

    def _raise(self, path):
        for needle, error in self.errors.items():
            if needle in path:
                raise error

    def get(self, path, api_version):
        self._raise(path)
        return self.arm[path]

    def graph_list(self, path, version="v1.0"):
        self.calls.append(path)
        self._raise(path)
        found = self.graph.get(path.split("?")[0], [])
        return found if isinstance(found, list) else [found]

    def graph_get(self, path, version="v1.0"):
        self.calls.append(path)
        self._raise(path)
        found = self.graph.get(path.split("?")[0])
        if found is None:
            raise emergency.ArmError(404, "Request_ResourceNotFound", "Resource does not exist.")
        return dict(found) if "signInActivity" in path else {k: v for k, v in found.items() if k != "signInActivity"}

    def list(self, path, api_version, params=None):
        self.calls.append(path)
        self._raise(f"{path}@{api_version}")
        return self.arm.get((path, api_version), [])


class Collector:
    def __init__(self):
        self.failures = []

    def record(self, operation, exc):
        self.failures.append({"operation": operation, "type": type(exc).__name__, "message": str(exc)})

    def guard(self, operation, fn, default=None):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            self.record(operation, exc)
            return default


def _collect(monkeypatch, client, accounts=None):
    monkeypatch.delenv("SENTINEL_WORKSPACES", raising=False)
    if accounts is None:
        monkeypatch.delenv(emergency.ACCOUNTS_ENV, raising=False)
    else:
        monkeypatch.setenv(emergency.ACCOUNTS_ENV, accounts)
    collector = Collector()
    results, summary = emergency.collect(client, SUB, collector)
    return results, summary, collector


def test_named_accounts_excluded_and_monitored(monkeypatch):
    results, s, collector = _collect(monkeypatch, FakeClient(*_tenant()), f"breakglass1@contoso.test, {BG2}")

    assert collector.failures == []
    assert s["emergency_accounts_source"] == "configured" and s["emergency_accounts_named"] == 2
    assert s["conditional_access_readable"] and s["exclusions_readable"] and s["alert_rules_readable"]
    assert s["enforced_mfa_policies"] == 2
    assert s["emergency_accounts"] == 2 and s["emergency_accounts_not_found"] == 0
    assert s["emergency_accounts_excluded_from_every_mfa_policy"] == 2
    assert s["emergency_accounts_with_phishing_resistant_method"] == 1
    # BG2 is named only by a disabled rule.
    assert s["emergency_accounts_monitored"] == 1
    # SVC is excluded directly; OFF is disabled; OUTSIDER only from a report-only and a non-MFA policy.
    assert s["users_excluded_from_mfa"] == 3
    assert s["excluded_users_not_emergency_accounts"] == 1
    assert s["emergency_accounts_excluded_without_alert"] == 1
    assert s["excluded_users_not_monitored_emergency_accounts"] == 2
    assert s["sentinel_workspaces_checked"] == 1 and s["alert_rules_checked"] == 3

    bg1, bg2 = results["emergency_accounts"]
    assert bg1["named_as"] == "breakglass1@contoso.test" and bg2["named_as"] == BG2
    assert [e["via"] for e in bg1["mfa_policy_exclusions"]] == ["group", "group"]
    assert bg1["excluded_from_every_mfa_policy"] and bg1["phishing_resistant_method_registered"] is True
    assert {r["display_name"] for r in bg1["alert_rules_naming_account"]} == {"Break-glass sign-in", "Emergency account used"}
    assert bg1["monitored"] is True and bg1["days_since_last_successful_sign_in"] == 40
    assert bg2["monitored"] is False and bg2["alert_rules_naming_account"] == []
    assert [u["id"] for u in results["other_users_excluded_from_mfa"]] == [OFF, SVC]
    assert [p["id"] for p in results["mfa_policies"]] == ["p-all", "p-admins"]


def test_without_named_accounts_candidates_are_never_approved(monkeypatch):
    results, s, collector = _collect(monkeypatch, FakeClient(*_tenant()))

    assert collector.failures == []
    assert s["emergency_accounts_source"] == "candidates" and s["emergency_accounts_named"] == 0
    # Excluded from both policies: the two break-glass accounts. SVC is excluded from one only.
    assert [a["id"] for a in results["emergency_accounts"]] == [BG1, BG2]
    assert all(a["named_as"] is None for a in results["emergency_accounts"])
    assert s["excluded_users_not_emergency_accounts"] == 3
    assert s["excluded_users_not_monitored_emergency_accounts"] == 3


def test_role_and_guest_exclusions(monkeypatch):
    graph, arm = _tenant()
    graph["/identity/conditionalAccess/policies"] = [
        _policy("p-all", "MFA", users={"excludeRoles": [ADMIN_ROLE], "excludeUsers": ["GuestsOrExternalUsers"]}),
    ]
    graph["/directoryRoles"] = [
        {"id": "r-ga", "displayName": "Global Administrator", "roleTemplateId": ADMIN_ROLE},
        {"id": "r-other", "displayName": "Directory Readers", "roleTemplateId": "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"},
    ]
    graph["/directoryRoles/r-ga/members/microsoft.graph.user"] = [USERS[ADMIN]]
    graph["/directoryRoles/r-ga/members/microsoft.graph.group"] = [{"id": "g-bg"}]
    graph["/users"] = [USERS[GUEST]]
    client = FakeClient(graph, arm)
    results, s, collector = _collect(monkeypatch, client, BG1)

    assert collector.failures == []
    assert not any(c.startswith("/directoryRoles/r-other") for c in client.calls)
    vias = {u["id"]: [e["via"] for e in u["mfa_policy_exclusions"]] for u in results["other_users_excluded_from_mfa"]}
    assert vias == {ADMIN: ["role"], BG2: ["role"], GUEST: ["guests_or_external_users"]}
    assert results["emergency_accounts"][0]["mfa_policy_exclusions"][0]["via"] == "role"
    assert s["excluded_users_not_emergency_accounts"] == 3
    assert results["mfa_policies"][0]["excludes_guests_or_external_users"] is True
    assert results["mfa_policies"][0]["exclude_users"] == []


def test_named_account_missing_from_directory(monkeypatch):
    results, s, collector = _collect(monkeypatch, FakeClient(*_tenant()), "gone@contoso.test,breakglass1@contoso.test")

    assert collector.failures == []
    assert results["emergency_accounts_not_found"] == ["gone@contoso.test"]
    assert s["emergency_accounts"] == 1 and s["emergency_accounts_not_found"] == 1
    # BG2 is excluded through the group but isn't named.
    assert s["excluded_users_not_emergency_accounts"] == 2


def test_denied_conditional_access_is_not_authorized_and_nulls_the_exclusions(monkeypatch):
    graph, arm = _tenant()
    results, s, collector = _collect(
        monkeypatch, FakeClient(graph, arm, errors={"/identity/conditionalAccess": DENIED}), BG1)

    assert classify_failure_code(collector.failures) == "not_authorized"
    assert s["conditional_access_readable"] is False and s["exclusions_readable"] is False
    assert s["enforced_mfa_policies"] is None and results["mfa_policies"] is None
    for key in ("users_excluded_from_mfa", "excluded_users_not_emergency_accounts",
                "emergency_accounts_excluded_without_alert", "excluded_users_not_monitored_emergency_accounts",
                "emergency_accounts_excluded_from_every_mfa_policy"):
        assert s[key] is None, key


def test_unlicensed_sign_in_activity_and_registration(monkeypatch):
    graph, arm = _tenant()
    errors = {"signInActivity": NOT_LICENSED, "userRegistrationDetails": NOT_LICENSED}
    results, s, collector = _collect(monkeypatch, FakeClient(graph, arm, errors=errors), BG1)

    assert s["user_sign_in_activity"] == "not_licensed" and s["registration_details"] == "not_licensed"
    assert s["emergency_accounts_with_phishing_resistant_method"] is None
    account = results["emergency_accounts"][0]
    assert account["last_successful_sign_in"] is None and account["methods_registered"] is None
    # The exclusion figures don't depend on those reads.
    assert s["excluded_users_not_monitored_emergency_accounts"] == 2
    assert collector.failures


def test_unreadable_alert_rules_null_the_monitoring_figures(monkeypatch):
    graph, arm = _tenant()
    errors = {"scheduledQueryRules": DENIED}
    results, s, collector = _collect(monkeypatch, FakeClient(graph, arm, errors=errors), BG1)

    assert s["alert_rules_readable"] is False and s["alert_rules_checked"] is None
    assert s["emergency_accounts_monitored"] is None
    assert s["emergency_accounts_excluded_without_alert"] is None
    assert s["excluded_users_not_monitored_emergency_accounts"] is None
    assert results["emergency_accounts"][0]["monitored"] is None
    assert s["excluded_users_not_emergency_accounts"] == 2


def test_failed_preview_rule_listing_is_logged_not_failed(monkeypatch):
    graph, arm = _tenant()
    errors = {f"alertRules@{SI_PREVIEW_API}": emergency.ArmError(400, "NoRegisteredProviderFound", "retired")}
    results, s, collector = _collect(monkeypatch, FakeClient(graph, arm, errors=errors), BG1)

    assert collector.failures == []
    assert s["alert_rules_readable"] is True and results["emergency_accounts"][0]["monitored"] is True


def test_deleted_excluded_group_is_empty_not_a_failure(monkeypatch):
    graph, arm = _tenant()
    del graph["/groups/g-bg/transitiveMembers/microsoft.graph.user"]
    client = FakeClient(graph, arm, errors={"/groups/g-bg": emergency.ArmError(404, "Request_ResourceNotFound", "gone")})
    results, s, collector = _collect(monkeypatch, client, BG1)

    assert collector.failures == []
    assert s["exclusions_readable"] is True
    assert results["emergency_accounts"][0]["mfa_policy_exclusions"] == []


def test_failed_group_read_nulls_the_exclusions(monkeypatch):
    graph, arm = _tenant()
    results, s, collector = _collect(monkeypatch, FakeClient(graph, arm, errors={"/groups/g-bg": DENIED}), BG1)

    assert s["exclusions_readable"] is False
    assert s["excluded_users_not_monitored_emergency_accounts"] is None
    assert classify_failure_code(collector.failures) == "not_authorized"


def test_graph_in_another_tenant_reads_nothing(monkeypatch):
    graph, arm = _tenant()
    graph["/organization"] = [{"id": "00000000-0000-0000-0000-0000000000bb"}]
    client = FakeClient(graph, arm)
    results, s, collector = _collect(monkeypatch, client, BG1)

    assert collector.failures and "subscription's tenant" in collector.failures[0]["message"]
    assert not any("conditionalAccess" in c for c in client.calls)
    assert s["emergency_accounts"] is None and s["excluded_users_not_monitored_emergency_accounts"] is None
    assert results["emergency_accounts"] == []


def test_no_enforced_mfa_policy_has_no_exclusions_and_no_candidates(monkeypatch):
    graph, arm = _tenant()
    graph["/identity/conditionalAccess/policies"] = []
    results, s, collector = _collect(monkeypatch, FakeClient(graph, arm))

    assert collector.failures == []
    assert s["enforced_mfa_policies"] == 0 and s["emergency_accounts"] == 0
    assert s["excluded_users_not_monitored_emergency_accounts"] == 0


def test_mfa_policy_needs_enforcement_and_an_mfa_grant():
    assert emergency.mfa_policy(_policy("a", "a")) is not None
    assert emergency.mfa_policy(_policy("b", "b", controls=(), strength={"id": "x"})) is not None
    assert emergency.mfa_policy(_policy("c", "c", state="disabled")) is None
    assert emergency.mfa_policy(_policy("d", "d", controls=("block",))) is None


def test_naming_rules_matches_upn_or_id_case_insensitively_and_skips_disabled():
    user = {"id": BG1.upper(), "userPrincipalName": "BreakGlass1@Contoso.test"}
    rules = [
        {"source": "sentinel", "id": "1", "display_name": "a", "kind": "Scheduled", "workspace": "w", "enabled": True,
         "_query": "where UserPrincipalName == 'breakglass1@contoso.test'"},
        {"source": "azure_monitor", "id": "2", "display_name": "b", "kind": "LogAlert", "workspace": None,
         "enabled": True, "_query": f"where UserId == '{BG1}'"},
        {"source": "sentinel", "id": "3", "display_name": "c", "kind": "NRT", "workspace": "w", "enabled": False,
         "_query": "breakglass1@contoso.test"},
    ]
    assert [r["id"] for r in emergency.naming_rules(user, rules)] == ["1", "2"]
    assert "_query" not in emergency.naming_rules(user, rules)[0]


def test_named_accounts_are_deduplicated_case_insensitively(monkeypatch):
    monkeypatch.setenv(emergency.ACCOUNTS_ENV, "B@contoso.test; a@contoso.test, b@CONTOSO.test,,")
    assert [a.lower() for a in emergency.named_accounts()] == ["a@contoso.test", "b@contoso.test"]
