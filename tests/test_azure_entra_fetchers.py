"""Entra ID fetchers: what counts as phishing-resistant, and who counts as an admin.

Pins two ways these fetchers could overstate a tenant's posture: a single-factor
X.509 certificate counted as a phishing-resistant method, and an admin with no
authentication-methods registration row dropping out of the admin MFA denominator.
No SDK, no credentials, no network.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import sys
from enum import Enum
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


auth_policy = _load("entra_authentication_policy")
mfa_status = _load("entra_mfa_status")
privileged_roles = _load("entra_privileged_roles")

DENIED = Exception("Insufficient privileges to complete the operation. (403)")


# --------------------------------------------------------------------------- #
# azure_entra_authentication_policy: X.509 is phishing-resistant only multi-factor
# --------------------------------------------------------------------------- #

class X509Mode(Enum):
    """Stands in for msgraph's X509CertificateAuthenticationMode (a plain Enum)."""

    SINGLE = "x509CertificateSingleFactor"
    MULTI = "x509CertificateMultiFactor"


def _x509(state="enabled", mode=X509Mode.SINGLE):
    return ns(
        id="X509Certificate",
        state=state,
        authentication_mode_configuration=ns(x509_certificate_authentication_default_mode=mode),
        certificate_user_bindings=[],
    )


def _policy(*configs):
    return auth_policy.project_methods_policy(
        ns(id="authenticationMethodsPolicy", authentication_method_configurations=list(configs))
    )


def _auth_summary(policy):
    methods = auth_policy.method_records(policy)
    passwords = auth_policy.password_protection(None, None, None)
    return methods, auth_policy.summarize(policy, methods, None, None, passwords)


def test_single_factor_x509_is_not_phishing_resistant():
    policy = _policy(_x509(mode=X509Mode.SINGLE))
    methods, summary = _auth_summary(policy)

    (x509,) = methods
    assert x509["enabled"] is True
    assert x509["settings"]["default_authentication_mode"] == "x509CertificateSingleFactor"
    assert x509["is_phishing_resistant_method"] is False
    assert summary["x509_certificate_enabled"] is True
    assert summary["x509_certificate_multi_factor"] is False
    assert summary["phishing_resistant_methods_enabled"] == []
    assert summary["phishing_resistant_method_enabled"] is False


def test_multi_factor_x509_is_phishing_resistant():
    policy = _policy(_x509(mode=X509Mode.MULTI), ns(id="Fido2", state="disabled"))
    methods, summary = _auth_summary(policy)

    by_id = {m["id"]: m for m in methods}
    assert by_id["X509Certificate"]["is_phishing_resistant_method"] is True
    assert summary["x509_certificate_multi_factor"] is True
    assert summary["phishing_resistant_methods_enabled"] == ["X509Certificate"]
    assert summary["phishing_resistant_method_enabled"] is True


def test_x509_with_no_reported_mode_is_not_credited():
    policy = _policy(_x509(mode=None), ns(id="Fido2", state="enabled"))
    methods, summary = _auth_summary(policy)

    by_id = {m["id"]: m for m in methods}
    assert by_id["X509Certificate"]["is_phishing_resistant_method"] is False
    assert by_id["Fido2"]["is_phishing_resistant_method"] is True
    assert summary["x509_certificate_multi_factor"] is None
    assert summary["phishing_resistant_methods_enabled"] == ["Fido2"]


def test_x509_multi_factor_is_null_when_the_policy_is_unreadable():
    _, summary = _auth_summary(None)
    assert summary["x509_certificate_multi_factor"] is None
    assert summary["phishing_resistant_methods_enabled"] is None


# --------------------------------------------------------------------------- #
# azure_entra_mfa_status: admins come from directory roles
# --------------------------------------------------------------------------- #

def _user(uid, upn, enabled=True):
    return {"id": uid, "user_principal_name": upn, "account_enabled": enabled, "user_type": "Member"}


def _reg(uid, mfa, is_admin=False):
    return {"id": uid, "is_mfa_capable": mfa, "is_mfa_registered": mfa, "is_admin": is_admin}


USERS = [
    _user("u-ga", "ga@contoso.test"),
    _user("u-unreg", "unregistered-admin@contoso.test"),
    _user("u-plain", "plain@contoso.test"),
]
REGISTRATIONS = [_reg("u-ga", True, is_admin=True), _reg("u-plain", False)]


def test_admin_without_registration_row_counts_as_admin_without_mfa():
    admin_roles = mfa_status.admin_roles_by_user(
        [{"role": "Global Administrator", "user_ids": ["u-ga", "u-unreg"]}]
    )
    users = mfa_status.join_users(USERS, REGISTRATIONS, admin_roles)
    summary = mfa_status.summarize(users)

    by_id = {u["id"]: u for u in users}
    unreg = by_id["u-unreg"]
    assert unreg["is_admin"] is True
    assert unreg["has_registration_details"] is False
    assert unreg["is_mfa_capable"] is False
    assert unreg["privileged_directory_roles"] == ["Global Administrator"]
    assert unreg["is_admin_in_registration_report"] is False
    assert by_id["u-plain"]["is_admin"] is False
    assert by_id["u-plain"]["privileged_directory_roles"] == []

    assert summary["admin_role_membership_readable"] is True
    assert summary["admin_users"] == 2
    assert summary["mfa_capable_admin_users"] == 1
    assert summary["admin_mfa_coverage_percentage"] == 50
    assert summary["admin_users_without_mfa"] == 1
    assert summary["admin_users_without_registration_details"] == 1


def test_all_users_coverage_leaves_out_users_the_report_omits():
    users = mfa_status.join_users(
        USERS + [_user("u-gone", "disabled@contoso.test", enabled=False)], REGISTRATIONS, {}
    )
    summary = mfa_status.summarize(users)
    # u-unreg and the disabled u-gone have no report row: unknown, not without MFA.
    assert summary["users_with_registration_details"] == 2
    assert summary["users_without_registration_details"] == 2
    assert summary["mfa_capable_users"] == 1
    assert summary["mfa_coverage_percentage_all_users"] == 50
    # Enabled users without a row still count as uncovered.
    assert summary["mfa_coverage_percentage"] == 33 and summary["enabled_users_without_mfa"] == 2


def test_registration_report_admin_flag_still_counts():
    """A role this fetcher does not list (or a PIM-eligible one) is still an admin
    when the registration report says so."""
    users = mfa_status.join_users(USERS, REGISTRATIONS, {})
    summary = mfa_status.summarize(users)
    assert {u["id"] for u in users if u["is_admin"]} == {"u-ga"}
    assert summary["admin_users"] == 1


def test_admin_figures_are_null_when_role_membership_is_unreadable():
    users = mfa_status.join_users(USERS, REGISTRATIONS, None)
    summary = mfa_status.summarize(users, admin_roles_readable=False)

    assert all(u["privileged_directory_roles"] is None for u in users)
    assert summary["admin_role_membership_readable"] is False
    for key in (
        "admin_users",
        "mfa_capable_admin_users",
        "admin_mfa_coverage_percentage",
        "admin_users_without_mfa",
        "admin_users_without_registration_details",
    ):
        assert summary[key] is None, key
    # The tenant-wide figures do not depend on role membership.
    assert summary["mfa_coverage_percentage"] == 33


def test_mfa_status_and_privileged_roles_share_one_admin_definition():
    assert mfa_status.is_privileged_role is privileged_roles.is_privileged_role


# --- collection, against a fake Graph client --------------------------------

class Builder:
    """One Graph collection request builder: `get()` returns one page or raises."""

    def __init__(self, items=None, error=None):
        self.items, self.error, self.calls = items or [], error, 0

    async def get(self, request_configuration=None):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return ns(value=self.items, odata_next_link=None)


def _obj(oid, kind):
    return ns(id=oid, odata_type=f"#microsoft.graph.{kind}")


def _role(rid, name):
    return ns(id=rid, display_name=name, role_template_id=None)


class FakeGraph:
    def __init__(self, roles, role_members, group_members):
        self.role_members = {rid: Builder(items) for rid, items in role_members.items()}
        self.group_members = {gid: Builder(items) for gid, items in group_members.items()}
        self.directory_roles = Builder(roles)
        self.directory_roles.by_directory_role_id = lambda rid: ns(members=self.role_members[rid])
        self.groups = ns(by_group_id=lambda gid: ns(transitive_members=self.group_members[gid]))


def _collector():
    return mfa_status.Collector(logging.getLogger("test_entra_mfa_status"))


def test_role_holders_include_users_of_role_assignable_groups():
    graph = FakeGraph(
        roles=[
            _role("r-ga", "Global Administrator"),
            _role("r-ua", "User Administrator"),
            _role("r-dr", "Directory Readers"),
        ],
        role_members={
            "r-ga": [_obj("u-ga", "user"), _obj("g-admins", "group"), _obj("sp-1", "servicePrincipal")],
            "r-ua": [_obj("g-admins", "group")],
            "r-dr": [_obj("u-plain", "user")],
        },
        group_members={"g-admins": [_obj("u-unreg", "user"), _obj("g-nested", "group")]},
    )
    collector = _collector()
    assignments = asyncio.run(mfa_status._privileged_role_assignments(collector, graph))

    assert collector.ok
    assert mfa_status.admin_roles_by_user(assignments) == {
        "u-ga": ["Global Administrator"],
        "u-unreg": ["Global Administrator", "User Administrator"],
    }
    # Directory Readers is not privileged, so its members are never read.
    assert graph.role_members["r-dr"].calls == 0
    # A group holding two roles is expanded once.
    assert graph.group_members["g-admins"].calls == 1


def test_denied_role_members_read_is_recorded_and_makes_membership_unknown():
    graph = FakeGraph(
        roles=[_role("r-ga", "Global Administrator")],
        role_members={"r-ga": []},
        group_members={},
    )
    graph.role_members["r-ga"].error = DENIED
    collector = _collector()

    assert asyncio.run(mfa_status._privileged_role_assignments(collector, graph)) is None
    assert not collector.ok
    assert mfa_status.classify_failure_code(collector.failures) == "not_authorized"


@pytest.mark.parametrize("status, code", [
    (403, "not_authorized"), (429, "rate_limited"), (503, "target_unreachable"), (504, "target_unreachable"),
])
def test_graph_status_text_is_classified_like_arm(status, code):
    failures = [{"operation": "graph.op", "type": "ODataError", "message": f"Something went wrong (status {status})"}]
    assert mfa_status.classify_failure_code(failures) == code


def _mfa_graph():
    graph = FakeGraph(roles=[], role_members={}, group_members={})
    graph.organization = Builder([ns(id="t-1", display_name="Contoso", verified_domains=[])])
    graph.users = Builder([ns(id="u-ga", user_principal_name="ga@contoso.test", account_enabled=True)])
    graph.reports = ns(
        authentication_methods=ns(
            user_registration_details=Builder([ns(id="u-ga", is_mfa_capable=True, is_admin=True)])
        )
    )
    return graph


def _run_mfa_main(graph, tmp_path, monkeypatch):
    """main() against a fake Graph client; returns its exit code and the evidence."""

    async def fake_with_graph_client(collector, cred, work, default=None):
        return await work(graph)

    # Stand in for the two msgraph imports _collect makes for the users $select.
    class Query:
        def __init__(self, select=None):
            self.select = select

    users_module = ns(UsersRequestBuilder=ns(UsersRequestBuilderGetQueryParameters=Query))
    config_module = ns(RequestConfiguration=lambda query_parameters=None: ns(query_parameters=query_parameters))
    monkeypatch.setitem(sys.modules, "msgraph.generated.users.users_request_builder", users_module)
    monkeypatch.setitem(sys.modules, "kiota_abstractions.base_request_configuration", config_module)
    monkeypatch.setattr(mfa_status, "with_graph_client", fake_with_graph_client)
    monkeypatch.setattr(mfa_status, "credential", lambda: object())
    monkeypatch.setattr(mfa_status, "load_dotenv", lambda: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_TENANT_ID", "t-1")
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    status_file = tmp_path / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status_file))

    code = mfa_status.main()
    return code, json.loads((tmp_path / "azure_entra_mfa_status_t-1.json").read_text())


def test_denied_directory_roles_fails_the_run_with_null_admin_figures(tmp_path, monkeypatch):
    """End to end through main(): users and registrations read, directoryRoles 403s."""
    graph = _mfa_graph()
    graph.directory_roles.error = DENIED
    code, evidence = _run_mfa_main(graph, tmp_path, monkeypatch)

    assert code == 1
    summary = evidence["summary"]
    assert summary["admin_role_membership_readable"] is False
    assert summary["admin_users"] is None
    assert summary["admin_mfa_coverage_percentage"] is None
    assert summary["mfa_coverage_percentage"] == 100
    (user,) = evidence["results"]["users"]
    assert user["is_admin"] is True  # the report's flag is still honored
    assert user["privileged_directory_roles"] is None
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"


def test_a_failed_users_read_leaves_every_figure_null(tmp_path, monkeypatch):
    graph = _mfa_graph()
    graph.users.error = DENIED
    code, evidence = _run_mfa_main(graph, tmp_path, monkeypatch)

    assert code == 1
    summary = evidence["summary"]
    assert summary.pop("admin_role_membership_readable") is True
    assert set(summary.values()) == {None}


def test_a_failed_registration_read_leaves_its_figures_null(tmp_path, monkeypatch):
    graph = _mfa_graph()
    graph.reports.authentication_methods.user_registration_details.error = DENIED
    code, evidence = _run_mfa_main(graph, tmp_path, monkeypatch)

    assert code == 1
    summary = evidence["summary"]
    assert all(summary[k] is None for k in mfa_status.REGISTRATION_FIGURES)
    assert summary["total_users"] == 1 and summary["enabled_users"] == 1 and summary["admin_users"] == 0
