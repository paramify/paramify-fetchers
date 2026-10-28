"""azure_entra_conditional_access_policies: authentication strengths and phishing-resistant MFA.

Real msgraph models and request builders over a mocked HTTP transport: no credentials, no network.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import sys
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "entra_conditional_access_policies" / "fetcher.py"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))

spec = importlib.util.spec_from_file_location("azure_entra_conditional_access_policies_under_test", FETCHER)
ca = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ca)

# On sys.path once the fetcher loads.
from azure_common import Collector, classify_failure_code  # noqa: E402

TENANT = "00000000-0000-0000-0000-0000000000aa"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
PHISHING_RESISTANT = {
    "id": "00000000-0000-0000-0000-000000000004", "displayName": "Phishing-resistant MFA", "policyType": "builtIn",
    "requirementsSatisfied": "mfa", "allowedCombinations": ["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"],
}
ANY_MFA = {
    "id": "00000000-0000-0000-0000-000000000002", "displayName": "Multifactor authentication", "policyType": "builtIn",
    "requirementsSatisfied": "mfa", "allowedCombinations": ["fido2", "password,sms", "password,microsoftAuthenticatorPush"],
}
PASSWORD_ONLY = {
    "id": "11111111-0000-0000-0000-000000000001", "displayName": "Password only", "policyType": "custom",
    "requirementsSatisfied": "none", "allowedCombinations": ["password"],
}


def _policy(pid, name, strength=None, controls=(), operator="OR", users=None, apps=("All",), state="enabled"):
    grant = {"operator": operator, "builtInControls": list(controls)}
    if strength is not None:
        grant["authenticationStrength"] = strength
    return {"id": pid, "displayName": name, "state": state, "grantControls": grant,
            "conditions": {"users": users or {"includeUsers": ["All"]},
                           "applications": {"includeApplications": list(apps)}}}


def _graph(policies, strengths=None, strength_status=200, policies_status=200):
    routes = {
        "/v1.0/organization": {"value": [{"id": TENANT, "displayName": "Contoso", "verifiedDomains": []}]},
        "/v1.0/identity/conditionalAccess/policies": {"value": policies},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = _path(request)
        if path == "/v1.0/identity/conditionalAccess/policies" and policies_status != 200:
            # The wording Graph sent a reader with no directory role: no status, no "privileges".
            return httpx.Response(policies_status, json={"error": {
                "code": "AccessDenied", "message": "Your account does not have access to this report or data."}})
        if path == "/v1.0/policies/authenticationStrengthPolicies":
            if strength_status != 200:
                return httpx.Response(strength_status, json={"error": {
                    "code": "Authorization_RequestDenied", "message": "Insufficient privileges to complete the operation."}})
            return httpx.Response(200, json={"value": strengths or []})
        return httpx.Response(200, json=routes.get(path, {"value": []}))

    return handler


def _path(request: httpx.Request) -> str:
    # The adapter's base URL ends in /v1.0 and its templates add another slash.
    return request.url.path.replace("//", "/")


def _run(monkeypatch, handler):
    from kiota_abstractions.authentication import AnonymousAuthenticationProvider
    from msgraph import GraphServiceClient
    from msgraph.graph_request_adapter import GraphRequestAdapter

    async def fake_with_graph_client(collector, cred, work, default=None):
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://graph.microsoft.com/v1.0")
        adapter = GraphRequestAdapter(AnonymousAuthenticationProvider(), client=http)
        try:
            return await work(GraphServiceClient(request_adapter=adapter))
        finally:
            await http.aclose()

    monkeypatch.setattr(ca, "with_graph_client", fake_with_graph_client)
    collector = Collector(logging.getLogger("test"))
    policies, _tenant, strengths, readable, policies_readable = asyncio.run(ca._collect(collector, object()))
    return policies, strengths, ca.summarize(policies, readable, policies_readable), collector


def _tenant_policies():
    return [
        _policy("p-pr-all", "Phishing-resistant for everyone", strength=PHISHING_RESISTANT, operator="AND"),
        _policy("p-pr-admins", "Phishing-resistant for admins", strength=PHISHING_RESISTANT,
                users={"includeRoles": [GLOBAL_ADMIN]}),
        _policy("p-any", "Any MFA", strength=ANY_MFA),
        _policy("p-pr-or-device", "Strength or compliant device", strength=PHISHING_RESISTANT,
                controls=("compliantDevice",)),
        _policy("p-password", "Password only", strength=PASSWORD_ONLY),
        _policy("p-mfa", "Classic MFA", controls=("mfa",)),
        _policy("p-report", "Report only", strength=PHISHING_RESISTANT, state="enabledForReportingButNotEnforced"),
    ]


def test_strength_combinations_read_raw_and_judged(monkeypatch):
    policies, strengths, s, collector = _run(
        monkeypatch, _graph(_tenant_policies(), [PHISHING_RESISTANT, ANY_MFA, PASSWORD_ONLY]))

    assert collector.failures == []
    by_id = {p["id"]: p for p in policies}
    # The SDK reads "password,sms" as None; the raw read keeps it.
    assert by_id["p-any"]["access_controls"]["authentication_strength_combinations"] == [
        "fido2", "password,microsoftAuthenticatorPush", "password,sms"]
    assert [x["phishing_resistant"] for x in strengths] == [False, False, True]
    assert by_id["p-pr-all"]["requires_phishing_resistant_mfa"] is True
    assert by_id["p-pr-admins"]["requires_phishing_resistant_mfa"] is True
    assert by_id["p-any"]["requires_phishing_resistant_mfa"] is False and by_id["p-any"]["requires_mfa"] is True
    assert by_id["p-pr-or-device"]["requires_phishing_resistant_mfa"] is False
    # A strength that satisfies no MFA requirement is not MFA.
    assert by_id["p-password"]["requires_mfa"] is False
    assert by_id["p-mfa"]["requires_mfa"] is True and by_id["p-mfa"]["requires_phishing_resistant_mfa"] is False

    assert s["authentication_strengths_readable"] is True
    assert s["enforced_policies_requiring_mfa"] == 5
    assert s["enforced_policies_with_authentication_strength"] == 5
    assert s["enforced_policies_requiring_phishing_resistant_mfa"] == 2
    assert s["enforced_phishing_resistant_mfa_for_all_users_and_apps"] == 1
    assert s["phishing_resistant_mfa_role_template_ids"] == [GLOBAL_ADMIN]


def test_strength_or_terms_of_use_is_not_phishing_resistant(monkeypatch):
    either = _policy("p-pr-or-terms", "Strength or terms of use", strength=PHISHING_RESISTANT)
    either["grantControls"]["termsOfUse"] = ["00000000-0000-0000-0000-0000000000b1"]
    both = _policy("p-pr-and-terms", "Strength and terms of use", strength=PHISHING_RESISTANT, operator="AND")
    both["grantControls"]["termsOfUse"] = ["00000000-0000-0000-0000-0000000000b1"]
    policies, _strengths, s, _collector = _run(monkeypatch, _graph([either, both], [PHISHING_RESISTANT]))

    by_id = {p["id"]: p for p in policies}
    assert by_id["p-pr-or-terms"]["requires_phishing_resistant_mfa"] is False
    assert by_id["p-pr-and-terms"]["requires_phishing_resistant_mfa"] is True
    assert s["enforced_policies_requiring_phishing_resistant_mfa"] == 1


def test_denied_strength_read_is_not_authorized_and_nulls_the_figures(monkeypatch):
    policies, strengths, s, collector = _run(monkeypatch, _graph(_tenant_policies(), strength_status=403))

    assert classify_failure_code(collector.failures) == "not_authorized"
    assert strengths is None
    assert s["authentication_strengths_readable"] is False
    for key in ("enforced_policies_requiring_phishing_resistant_mfa",
                "enforced_phishing_resistant_mfa_for_all_users_and_apps",
                "phishing_resistant_mfa_role_template_ids"):
        assert s[key] is None, key
    by_id = {p["id"]: p for p in policies}
    assert by_id["p-pr-all"]["requires_phishing_resistant_mfa"] is None
    assert by_id["p-pr-all"]["access_controls"]["authentication_strength_combinations"] is None
    # requirementsSatisfied comes inline with the policy, so MFA is still judged.
    assert by_id["p-pr-all"]["requires_mfa"] is True and by_id["p-password"]["requires_mfa"] is False
    assert by_id["p-mfa"]["requires_phishing_resistant_mfa"] is False


def test_denied_policy_read_is_not_authorized_and_unknown_not_zero(monkeypatch):
    policies, strengths, s, collector = _run(monkeypatch, _graph([], policies_status=403))

    assert policies == [] and collector.failures
    assert collector.failures[0]["message"].endswith("(status 403)")
    assert classify_failure_code(collector.failures) == "not_authorized"
    for key in ("enforced_policies_requiring_phishing_resistant_mfa",
                "enforced_phishing_resistant_mfa_for_all_users_and_apps",
                "phishing_resistant_mfa_role_template_ids"):
        assert s[key] is None, key


def test_strengths_are_not_read_when_no_policy_uses_one(monkeypatch):
    seen = []
    inner = _graph([_policy("p-mfa", "Classic MFA", controls=("mfa",))])

    def handler(request):
        seen.append(_path(request))
        return inner(request)

    policies, strengths, s, collector = _run(monkeypatch, handler)

    assert "/v1.0/policies/authenticationStrengthPolicies" not in seen
    assert collector.failures == [] and strengths == []
    assert s["authentication_strengths_readable"] is True
    assert s["enforced_policies_requiring_phishing_resistant_mfa"] == 0
    assert s["phishing_resistant_mfa_role_template_ids"] == []


def test_a_strength_missing_from_the_list_reads_unknown(monkeypatch):
    policies, _, s, collector = _run(monkeypatch, _graph(_tenant_policies(), [ANY_MFA, PASSWORD_ONLY]))

    assert collector.failures == []
    assert {p["id"]: p for p in policies}["p-pr-all"]["requires_phishing_resistant_mfa"] is None
    assert s["enforced_policies_requiring_phishing_resistant_mfa"] is None


def test_combination_is_phishing_resistant():
    assert ca.combination_is_phishing_resistant("fido2")
    assert ca.combination_is_phishing_resistant("x509CertificateMultiFactor")
    assert not ca.combination_is_phishing_resistant("x509CertificateSingleFactor")
    assert not ca.combination_is_phishing_resistant("password,sms")
    assert not ca.combination_is_phishing_resistant("")


def test_strength_record_with_no_combinations_is_not_phishing_resistant():
    record = ca.strength_record({"id": "x", "displayName": "Empty", "allowedCombinations": []})
    assert record["phishing_resistant"] is False and record["allowed_combinations"] == []
    assert json.loads(json.dumps(record)) == record
