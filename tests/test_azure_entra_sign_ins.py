"""azure_entra_sign_ins: how users actually sign in, summarized per user and app.

Synthetic Graph sign-in records only: no SDK, no credentials, no network.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "entra_sign_ins" / "fetcher.py"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))

spec = importlib.util.spec_from_file_location("azure_entra_sign_ins_under_test", FETCHER)
sign_ins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sign_ins)
azure_rest = sys.modules["azure_rest"]

TENANT = "00000000-0000-0000-0000-0000000000aa"
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
DENIED = Exception("(403) Authorization_RequestDenied: Insufficient privileges to complete the operation.")
NOT_LICENSED = azure_rest.ArmError(
    403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant", "Neither tenant is B2C or tenant doesn't have premium license"
)


def _step(method, ok=True):
    return {"authenticationMethod": method, "succeeded": ok}


def _sign_in(sid, user, app="app-portal", error=0, requirement="multiFactorAuthentication", steps=(),
             ca="success", level="none", state="none", client="Browser"):
    return {
        "id": sid, "createdDateTime": f"2026-10-18T0{len(sid) % 10}:00:00Z",
        "userId": user, "userPrincipalName": f"{user}@contoso.test",
        "appId": app, "appDisplayName": f"App {app}", "ipAddress": "203.0.113.10",
        "clientAppUsed": client, "status": {"errorCode": error},
        "authenticationRequirement": requirement, "authenticationDetails": list(steps),
        "conditionalAccessStatus": ca, "appliedConditionalAccessPolicies": [],
        "riskLevelDuringSignIn": level, "riskState": state, "riskEventTypes_v2": [],
    }


SIGN_INS = [
    _sign_in("s1", "u-1", steps=[_step("Password"), _step("Authenticator App")]),
    _sign_in("s2", "u-1", steps=[_step("FIDO2 security key")]),
    _sign_in("s3", "u-2", requirement="singleFactorAuthentication", steps=[_step("Password")], ca="notApplied"),
    _sign_in("s4", "u-2", app="app-mail", requirement="singleFactorAuthentication", steps=[_step("Password")],
             client="IMAP4"),
    _sign_in("s5", "u-3", error=50126, requirement="singleFactorAuthentication", steps=[_step("Password", ok=False)]),
    _sign_in("s6", "u-3", level="high", state="atRisk", steps=[_step("Password"), _step("SMS")]),
    _sign_in("s7", "u-4", steps=[_step("X.509 Certificate")]),
    _sign_in("s8", "u-4", steps=[_step("Previously satisfied")]),
    # A certificate beside a push isn't phishing-resistant: Microsoft counts only multifactor CBA.
    _sign_in("s9", "u-5", steps=[_step("X.509 Certificate"), _step("Mobile app notification")]),
]


class FakeClient:
    def __init__(self, pages, error=None, error_after=None):
        self.pages, self.error, self.error_after, self.paths = pages, error, error_after, []

    def graph_pages(self, path, version="v1.0"):
        self.paths.append((version, path))
        for i, page in enumerate(self.pages):
            if self.error is not None and i == (self.error_after or 0):
                raise self.error
            yield page
        if self.error is not None and self.error_after == len(self.pages):
            raise self.error

    def graph_list(self, path, version="v1.0"):
        return [{"id": TENANT, "displayName": "Contoso", "verifiedDomains": [{"name": "contoso.test", "isDefault": True}]}]


def _collector():
    return sign_ins.Collector(sign_ins.logger)


def _window(monkeypatch, days=None):
    if days is None:
        monkeypatch.delenv("ENTRA_SIGN_IN_LOOKBACK_DAYS", raising=False)
    else:
        monkeypatch.setenv("ENTRA_SIGN_IN_LOOKBACK_DAYS", str(days))
    return sign_ins.lookback_window(NOW)


def test_sign_ins_summarized_per_user_and_app(monkeypatch):
    client = FakeClient([SIGN_INS[:4], SIGN_INS[4:]])
    collector = _collector()
    results, s = sign_ins.collect(client, collector, _window(monkeypatch))

    assert collector.ok
    (version, path), = client.paths
    assert version == "beta" and path.startswith("/auditLogs/signIns?$filter=createdDateTime ge 2026-10-12T12:00:00Z")
    assert s["sign_in_logs"] == "read" and s["sign_ins_complete"] is True
    assert (s["total_sign_ins"], s["successful_sign_ins"], s["failed_sign_ins"]) == (9, 8, 1)
    assert s["successful_single_factor_sign_ins"] == 2
    assert s["successful_multi_factor_sign_ins"] == 6
    assert s["multi_factor_percentage"] == 75
    assert s["users_with_single_factor_sign_ins"] == 1
    assert s["apps_with_single_factor_sign_ins"] == 2
    assert s["successful_legacy_authentication_sign_ins"] == 1
    assert s["methods_used"] == {"Authenticator App": 1, "FIDO2 security key": 1, "Mobile app notification": 1,
                                 "Password": 4, "SMS": 1, "X.509 Certificate": 2}
    assert s["successful_phishing_resistant_sign_ins"] == 2  # FIDO2, and the certificate that alone passed MFA
    assert s["users_using_phishing_resistant_methods"] == 2
    assert s["successful_sign_ins_without_conditional_access"] == 1
    assert s["risky_sign_ins"] == 1
    assert s["risky_sign_ins_by_level"] == {"high": 1}
    assert s["risky_sign_ins_by_state"] == {"atRisk": 1}
    assert s["risk_levels_available"] is True
    assert s["exception_sign_ins"] == s["exception_sign_ins_listed"] == 3

    reasons = {e["id"]: e["exception_reasons"] for e in results["exception_sign_ins"]}
    assert reasons == {"s3": ["single_factor", "no_conditional_access"], "s4": ["single_factor"], "s6": ["risky"]}
    users = {u["user_id"]: u for u in results["users"]}
    assert users["u-2"]["successful_single_factor"] == 2
    assert users["u-3"]["risky"] == 1
    # Users with no exception count in every figure but aren't listed.
    assert set(users) == {"u-2", "u-3"}
    assert s["users_signing_in"] == 5 and s["users_listed"] == 2
    apps = {a["app_id"]: a for a in results["apps"]}
    assert apps["app-mail"]["successful_legacy_authentication"] == 1


def test_legacy_authentication_is_any_client_but_browser_and_modern_apps():
    for client, legacy in (("Browser", False), ("Mobile Apps and Desktop clients", False), ("Modern clients", False),
                           ("", False),
                           ("Reporting Web Services", True), ("Universal Outlook", True), ("Other clients", True)):
        assert sign_ins.sign_in_record(_sign_in("s", "u", client=client))["legacy_authentication"] is legacy, client


def test_a_certificate_beside_a_reused_factor_is_not_phishing_resistant():
    for reused in ("Previously satisfied", "Satisfied by token"):
        record = sign_ins.sign_in_record(_sign_in("s", "u", steps=[_step("X.509 Certificate"), _step(reused)]))
        assert record["methods"] == ["X.509 Certificate"]
        assert record["phishing_resistant"] is False, reused
    alone = sign_ins.sign_in_record(_sign_in("s", "u", steps=[_step("X.509 Certificate")]))
    assert alone["phishing_resistant"] is True


def test_unread_policies_are_null_not_none_applied():
    record = _sign_in("s", "u")
    del record["appliedConditionalAccessPolicies"]
    assert sign_ins.sign_in_record(record)["applied_conditional_access_policies"] is None
    record["appliedConditionalAccessPolicies"] = [{"displayName": "Require MFA", "result": "success"},
                                                  {"displayName": "Off", "result": "notEnabled"}]
    assert sign_ins.sign_in_record(record)["applied_conditional_access_policies"] == ["Require MFA"]


def test_a_risk_state_alone_marks_a_sign_in_risky(monkeypatch):
    flagged = [_sign_in("r1", "u-1", state="atRisk", steps=[_step("Password"), _step("SMS")])]
    _, s = sign_ins.collect(FakeClient([flagged]), _collector(), _window(monkeypatch))
    assert s["risky_sign_ins"] == 1
    assert s["risky_sign_ins_by_level"] == {"none": 1}
    assert s["risky_sign_ins_by_state"] == {"atRisk": 1}


def test_lookback_is_configurable_and_capped_at_retention(monkeypatch):
    assert _window(monkeypatch)["lookback_days"] == 7
    assert _window(monkeypatch, 14)["lookback_days"] == 14
    assert _window(monkeypatch, 90)["lookback_days"] == 30


def test_denied_sign_in_logs_read_not_read_with_null_figures(monkeypatch):
    collector = _collector()
    _, s = sign_ins.collect(FakeClient([SIGN_INS], error=DENIED), collector, _window(monkeypatch))

    assert sign_ins.classify_failure_code(collector.failures) == "not_authorized"
    assert s["sign_in_logs"] == "not_read"
    assert s["sign_ins_complete"] is False
    for key in ("total_sign_ins", "successful_single_factor_sign_ins", "methods_used", "risky_sign_ins"):
        assert s[key] is None, key


def test_unlicensed_tenant_reads_not_licensed_and_is_not_a_failure(monkeypatch):
    collector = _collector()
    _, s = sign_ins.collect(FakeClient([SIGN_INS], error=NOT_LICENSED), collector, _window(monkeypatch))
    assert s["sign_in_logs"] == "not_licensed"
    assert s["sign_ins_complete"] is False
    assert s["total_sign_ins"] is None and s["risky_sign_ins"] is None
    assert collector.ok


def test_not_licensed_only_from_the_first_page_and_the_exact_403(monkeypatch):
    # Licensing can't change part-way through a read: a later page saying so is a failure.
    collector = _collector()
    _, s = sign_ins.collect(FakeClient([SIGN_INS[:4], SIGN_INS[4:]], error=NOT_LICENSED, error_after=1),
                            collector, _window(monkeypatch))
    assert not collector.ok
    assert s["sign_in_logs"] == "read" and s["total_sign_ins"] == 4
    # Another status, or a message that only mentions the code, is a failure too.
    for error in (azure_rest.ArmError(400, NOT_LICENSED.code, "bad request"),
                  Exception("(403) Authentication_RequestFromNonPremiumTenantOrB2CTenant: from a proxy")):
        collector = _collector()
        _, s = sign_ins.collect(FakeClient([SIGN_INS], error=error), collector, _window(monkeypatch))
        assert not collector.ok, error
        assert s["sign_in_logs"] == "not_read"


def test_a_failed_later_page_keeps_the_read_pages_and_fails_the_run(monkeypatch):
    collector = _collector()
    _, s = sign_ins.collect(FakeClient([SIGN_INS[:4], SIGN_INS[4:]], error=DENIED, error_after=1),
                            collector, _window(monkeypatch))
    assert not collector.ok
    assert s["sign_ins_complete"] is False
    assert s["total_sign_ins"] == 4


def test_exceptions_are_capped(monkeypatch):
    monkeypatch.setattr(sign_ins, "EXCEPTION_LIMIT", 2)
    _, s = sign_ins.collect(FakeClient([SIGN_INS]), _collector(), _window(monkeypatch))
    assert s["exception_sign_ins"] == 3
    assert s["exception_sign_ins_listed"] == 2


def test_hidden_risk_levels_leave_the_risk_figures_unknown(monkeypatch):
    hidden = [_sign_in(f"h{i}", "u-1", level="hidden", steps=[_step("Password"), _step("SMS")]) for i in range(3)]
    hidden.append(_sign_in("h3", "u-2", level="hidden", state="atRisk", steps=[_step("Password"), _step("SMS")]))
    results, s = sign_ins.collect(FakeClient([hidden]), _collector(), _window(monkeypatch))
    assert s["risk_levels_available"] is False
    for key in ("risky_sign_ins", "risky_sign_ins_by_level", "risky_sign_ins_by_state", "users_with_risky_sign_ins"):
        assert s[key] is None, key
    assert results["users"] == [] and s["users_signing_in"] == 2
    assert s["total_sign_ins"] == 4


def test_without_p2_a_risk_state_lists_no_sign_in_as_risky(monkeypatch):
    hidden = [_sign_in("h1", "u-1", level="hidden", state="atRisk", steps=[_step("Password"), _step("SMS")]),
              _sign_in("h2", "u-2", level="hidden", state="atRisk", requirement="singleFactorAuthentication",
                       steps=[_step("Password")])]
    results, s = sign_ins.collect(FakeClient([hidden]), _collector(), _window(monkeypatch))
    assert s["risky_sign_ins"] is None
    # The MFA sign-in was an exception only by its risk state; the single-factor one stays, not as risky.
    assert s["exception_sign_ins"] == s["exception_sign_ins_listed"] == 1
    (listed,) = results["exception_sign_ins"]
    assert listed["id"] == "h2" and listed["exception_reasons"] == ["single_factor"]
    assert listed["ip_address"] is None


def test_a_hidden_level_flagged_by_its_state_counts_as_level_none(monkeypatch):
    rated = [_sign_in("p1", "u-1", steps=[_step("Password"), _step("SMS")]),
             _sign_in("p2", "u-1", level="hidden", state="atRisk", steps=[_step("Password"), _step("SMS")])]
    results, s = sign_ins.collect(FakeClient([rated]), _collector(), _window(monkeypatch))
    assert s["risk_levels_available"] is True
    assert s["risky_sign_ins_by_level"] == {"none": 1}
    # Risk is known in this tenant, so the state-flagged sign-in is listed.
    assert s["exception_sign_ins"] == 1
    assert [e["exception_reasons"] for e in results["exception_sign_ins"]] == [["risky"]]


def test_ip_address_is_kept_only_on_risky_sign_ins():
    assert sign_ins.sign_in_record(_sign_in("r", "u", level="high"))["ip_address"] == "203.0.113.10"
    single = _sign_in("s", "u", requirement="singleFactorAuthentication", steps=[_step("Password")])
    assert sign_ins.sign_in_record(single)["ip_address"] is None


def test_a_sign_in_with_no_user_id_counts_in_totals_only(monkeypatch):
    unknown = _sign_in("x1", "nobody", error=50034, requirement="singleFactorAuthentication",
                       steps=[_step("Password", ok=False)])
    unknown["userId"] = ""
    results, s = sign_ins.collect(FakeClient([SIGN_INS[:2] + [unknown]]), _collector(), _window(monkeypatch))
    assert s["total_sign_ins"] == 3 and s["failed_sign_ins"] == 1
    assert s["users_signing_in"] == 1
    assert results["users"] == []


def test_an_empty_lookback_leaves_ratios_and_risk_unknown(monkeypatch):
    _, s = sign_ins.collect(FakeClient([[]]), _collector(), _window(monkeypatch))
    assert s["total_sign_ins"] == 0
    assert s["risk_levels_available"] is None
    assert s["multi_factor_percentage"] is None


def test_an_unreported_requirement_is_counted_apart(monkeypatch):
    unknown = [_sign_in("q1", "u-1", requirement=None, steps=[_step("Password")]),
               _sign_in("q2", "u-1", requirement="unknownFutureValue", steps=[_step("Password")]),
               _sign_in("q3", "u-1", steps=[_step("Password"), _step("SMS")])]
    _, s = sign_ins.collect(FakeClient([unknown]), _collector(), _window(monkeypatch))
    assert s["successful_sign_ins_with_unknown_requirement"] == 2
    assert (s["successful_single_factor_sign_ins"], s["successful_multi_factor_sign_ins"]) == (0, 1)
    assert s["multi_factor_percentage"] == 33


def test_only_failed_sign_ins_leave_the_mfa_percentage_null(monkeypatch):
    failed = [_sign_in("f1", "u-1", error=50126, steps=[_step("Password", ok=False)])]
    _, s = sign_ins.collect(FakeClient([failed]), _collector(), _window(monkeypatch))
    assert s["successful_sign_ins"] == 0
    assert s["multi_factor_percentage"] is None


def _main(monkeypatch, tmp_path, client, cred=lambda: object()):
    monkeypatch.setattr(sign_ins, "credential", cred)
    monkeypatch.setattr(sign_ins, "AzureRestClient", lambda cred: client)
    monkeypatch.setattr(sign_ins, "load_dotenv", lambda: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_TENANT_ID", TENANT)
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.delenv("ENTRA_SIGN_IN_LOOKBACK_DAYS", raising=False)
    status = tmp_path / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status))
    code = sign_ins.main()
    evidence = json.loads((tmp_path / f"azure_entra_sign_ins_{TENANT}.json").read_text())
    return code, evidence, (json.loads(status.read_text()) if status.exists() else None)


def test_main_writes_tenant_evidence(monkeypatch, tmp_path):
    code, evidence, _ = _main(monkeypatch, tmp_path, FakeClient([SIGN_INS]))
    assert code == 0
    assert evidence["metadata"]["tenant_id"] == TENANT
    assert evidence["summary"]["total_sign_ins"] == 9


def test_reading_stops_at_the_limit_and_fails_the_run(monkeypatch, tmp_path):
    monkeypatch.setattr(sign_ins, "SIGN_IN_LIMIT", 3)
    code, evidence, status = _main(monkeypatch, tmp_path, FakeClient([SIGN_INS[:4], SIGN_INS[4:]]))

    assert code == 1
    assert status["code"] == "partial_failure"
    s = evidence["summary"]
    assert s["sign_ins_truncated"] is True and s["sign_ins_complete"] is False
    assert s["total_sign_ins"] == 4  # the first page, newest first


def test_an_unlicensed_tenant_succeeds_with_null_figures(monkeypatch, tmp_path):
    code, evidence, status = _main(monkeypatch, tmp_path, FakeClient([SIGN_INS], error=NOT_LICENSED))
    assert code == 0 and status is None
    assert evidence["summary"]["sign_in_logs"] == "not_licensed"
    assert evidence["summary"]["total_sign_ins"] is None


def test_graph_pages_follow_next_links_on_the_requested_version(monkeypatch):
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    base = "https://graph.microsoft.com"
    pages = {f"{base}/beta/things?$top=2": {"value": [1, 2], "@odata.nextLink": f"{base}/beta/things?page=2"},
             f"{base}/beta/things?page=2": {"value": [3]}}

    class Session:
        def get(self, url, headers=None, params=None, timeout=None):
            return SimpleNamespace(status_code=200, json=lambda: pages[url])

    token = SimpleNamespace(token="t", expires_on=9_999_999_999)
    client = sign_ins.AzureRestClient(SimpleNamespace(get_token=lambda scope: token), Session())
    assert list(client.graph_pages("/things?$top=2", "beta")) == [[1, 2], [3]]
    assert client.graph_list("/things?$top=2", "beta") == [1, 2, 3]


class TimingOutSession:
    """Times out the first `timeouts` requests, then answers one page."""

    def __init__(self, timeouts):
        self.timeouts, self.calls = timeouts, 0

    def _answer(self):
        self.calls += 1
        if self.calls <= self.timeouts:
            raise requests.ReadTimeout("Read timed out. (read timeout=60)")
        return SimpleNamespace(status_code=200, headers={}, json=lambda: {"value": [{"id": "s1"}]})

    def get(self, url, headers=None, params=None, timeout=None):
        return self._answer()

    def post(self, url, headers=None, json=None, timeout=None):
        return self._answer()


def _rest_client(session, monkeypatch):
    monkeypatch.setattr(azure_rest.time, "sleep", lambda seconds: None)
    token = SimpleNamespace(token="t", expires_on=9_999_999_999)
    return azure_rest.AzureRestClient(SimpleNamespace(get_token=lambda scope: token), session)


def test_a_read_timeout_on_a_graph_page_is_retried(monkeypatch):
    session = TimingOutSession(timeouts=2)
    assert _rest_client(session, monkeypatch).graph_list("/auditLogs/signIns", "beta") == [{"id": "s1"}]
    assert session.calls == 3


def test_a_read_timeout_on_a_post_is_not_resent(monkeypatch):
    session = TimingOutSession(timeouts=1)
    with pytest.raises(requests.ReadTimeout):
        _rest_client(session, monkeypatch).graph_post("/things", {})
    assert session.calls == 1


def test_no_credential_writes_evidence_and_fails(monkeypatch, tmp_path):
    def no_credential():
        raise RuntimeError("DefaultAzureCredential failed to retrieve a token from the included credentials.")

    code, evidence, status = _main(monkeypatch, tmp_path, FakeClient([SIGN_INS]), cred=no_credential)
    assert code == 1
    assert status["code"] == "auth_failed"
    assert evidence["summary"]["sign_in_logs"] == "not_read"
    assert evidence["summary"]["total_sign_ins"] is None
