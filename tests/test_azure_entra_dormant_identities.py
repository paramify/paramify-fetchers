"""azure_entra_dormant_identities: inactive, guest and deleted identities that still hold a role.

Synthetic Graph and ARM responses only: no SDK, no credentials, no network.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "entra_dormant_identities" / "fetcher.py"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))

spec = importlib.util.spec_from_file_location("azure_entra_dormant_identities_under_test", FETCHER)
dormant = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dormant)

SUB = "00000000-0000-0000-0000-0000000000cc"
TENANT = "00000000-0000-0000-0000-0000000000aa"
VENDOR_TENANT = "00000000-0000-0000-0000-0000000000bb"
MICROSOFT_TENANT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
NOW = datetime.now(timezone.utc)
OWNER_ROLE = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
# The form these REST reads raise: "(<status>) <code>: <message>".
DENIED = Exception("(403) Authorization_RequestDenied: Insufficient privileges to complete the operation.")
NOT_LICENSED = Exception(
    "(403) Authentication_RequestFromNonPremiumTenantOrB2CTenant: Neither tenant is B2C or tenant doesn't have premium license"
)
EMPTY_TIME = "0001-01-01T00:00:00Z"


SIGN_IN_PATH = f"/users?$select={dormant.USER_SELECT},signInActivity"


def _ago(days):
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _user(uid, last=None, created=400, guest=False, enabled=True, attempts=None, activity=None):
    if activity is None and (last is not None or attempts is not None):
        activity = {"lastSuccessfulSignInDateTime": _ago(last) if last is not None else None,
                    "lastSignInDateTime": _ago(attempts) if attempts is not None else None,
                    "lastNonInteractiveSignInDateTime": None}
    return {"id": uid, "displayName": f"User {uid}", "userPrincipalName": f"{uid}@contoso.test",
            "accountEnabled": enabled, "userType": "Guest" if guest else "Member",
            "createdDateTime": _ago(created), "signInActivity": activity}


def _sp(sid, app_id, sp_type="Application", owner=TENANT, enabled=True, created=None):
    """Learn documents no createdDateTime on a service principal, so it's left out unless asked for."""
    sp = {"@odata.type": "#microsoft.graph.servicePrincipal", "id": sid, "appId": app_id,
          "displayName": f"App {sid}", "servicePrincipalType": sp_type, "accountEnabled": enabled,
          "appOwnerOrganizationId": owner}
    if created is not None:
        sp["createdDateTime"] = _ago(created)
    return sp


def _assignment(aid, principal, ptype="User", role=OWNER_ROLE, scope=f"/subscriptions/{SUB}"):
    return {"id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments/{aid}",
            "properties": {"principalId": principal, "principalType": ptype,
                           "roleDefinitionId": role, "scope": scope}}


class FakeClient:
    """AzureRestClient's get / graph_list / graph_post / list, answered from a dict; errors per path prefix."""

    def __init__(self, graph, arm, objects, errors=None):
        self.graph, self.arm, self.objects, self.errors = graph, arm, objects, errors or {}
        self.calls = []

    def _raise(self, path):
        for prefix, error in self.errors.items():
            if path.startswith(prefix):
                raise error

    def get(self, path, api_version):
        self._raise(path)
        return {"id": path, "tenantId": TENANT}

    def graph_list(self, path, version="v1.0"):
        self.calls.append((version, path))
        self._raise(path)
        return self.graph.get(path.split("?")[0], [])

    def graph_post(self, path, body):
        self._raise(path)
        return {"value": [self.objects[i] for i in body["ids"] if i in self.objects]}

    def list(self, path, api_version, params=None):
        self._raise(path.split("/providers/Microsoft.Authorization")[-1])
        return self.arm[path.rsplit("/", 1)[-1]]


def _tenant():
    users = [
        _user("u-active", last=3),
        _user("u-stale-admin", last=200),
        _user("u-never", created=300),
        _user("u-new", created=5),
        _user("u-guest", last=10, guest=True),
        _user("u-off", last=500, enabled=False),
        _user("u-group-member", last=150),
        _user("u-off-never", enabled=False),
    ]
    graph = {
        "/users": users,
        # This tenant's app registrations: where a service principal's creation date comes from.
        "/applications": [
            {"appId": "app-busy", "createdDateTime": _ago(400)},
            {"appId": "app-unused", "createdDateTime": _ago(400)},
            {"appId": "app-new", "createdDateTime": _ago(5)},
        ],
        "/reports/servicePrincipalSignInActivities": [
            {"appId": "app-busy", "applicationAuthenticationClientSignInActivity": {"lastSignInDateTime": _ago(1)},
             "lastSignInActivity": {"lastSignInDateTime": _ago(1)}},
            {"appId": "app-idle", "applicationAuthenticationClientSignInActivity": {"lastSignInDateTime": _ago(120)},
             "lastSignInActivity": {"lastSignInDateTime": _ago(120)}},
        ],
        "/directoryRoles": [
            {"id": "r-ga", "displayName": "Global Administrator", "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10"},
            {"id": "r-dr", "displayName": "Directory Readers", "roleTemplateId": "x"},
        ],
        "/directoryRoles/r-ga/members": [
            {"@odata.type": "#microsoft.graph.user", "id": "u-stale-admin"},
            {"@odata.type": "#microsoft.graph.group", "id": "g-admins"},
        ],
        "/directoryRoles/r-dr/members": [{"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-busy"}],
        "/groups/g-admins/transitiveMembers": [{"@odata.type": "#microsoft.graph.user", "id": "u-group-member"}],
        "/groups/g-ops/transitiveMembers": [
            {"@odata.type": "#microsoft.graph.user", "id": "u-guest"},
            {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-idle"},
        ],
    }
    arm = {
        "roleDefinitions": [{"id": OWNER_ROLE, "properties": {"roleName": "Owner"}}],
        "roleAssignments": [
            _assignment("a1", "u-active"),
            _assignment("a2", "u-never"),
            _assignment("a3", "g-ops", ptype="Group"),
            _assignment("a4", "gone-1", ptype="User"),
            _assignment("a5", "gone-1", ptype="User", scope=f"/subscriptions/{SUB}/resourceGroups/rg"),
            _assignment("a6", "partner", ptype="ForeignGroup"),
            _assignment("a7", "u-off"),
            _assignment("a8", "sp-mi-new", ptype="ServicePrincipal"),
            _assignment("a9", "sp-ms", ptype="ServicePrincipal"),
            _assignment("a10", "sp-unused", ptype="ServicePrincipal"),
            _assignment("a11", "u-new"),
            _assignment("a12", "u-off-never"),
            _assignment("a13", "sp-new", ptype="ServicePrincipal"),
            _assignment("a14", "sp-vendor", ptype="ServicePrincipal"),
        ],
    }
    objects = {
        "sp-busy": _sp("sp-busy", "app-busy"),
        "sp-idle": _sp("sp-idle", "app-idle", sp_type="ManagedIdentity", owner=None),
        "sp-mi-new": _sp("sp-mi-new", "app-mi-new", sp_type="ManagedIdentity", owner=None),
        "sp-ms": _sp("sp-ms", "app-ms", owner=MICROSOFT_TENANT),
        "sp-unused": _sp("sp-unused", "app-unused"),
        "sp-new": _sp("sp-new", "app-new"),
        "sp-vendor": _sp("sp-vendor", "app-vendor", owner=VENDOR_TENANT, enabled=False),
        "g-ops": {"@odata.type": "#microsoft.graph.group", "id": "g-ops"},
    }
    return graph, arm, objects


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


def _collect(monkeypatch, client):
    monkeypatch.delenv("ENTRA_DORMANT_DAYS", raising=False)
    collector = Collector()
    results, summary = dormant.collect(client, SUB, collector)
    return results, summary, collector


def test_inactive_guest_and_deleted_role_holders(monkeypatch):
    results, s, collector = _collect(monkeypatch, FakeClient(*_tenant()))

    assert collector.failures == []
    assert s["users_readable"] is True
    assert s["user_sign_in_activity"] == s["service_principal_sign_in_activity"] == "read"
    assert s["dormant_after_days"] == 90
    assert s["users_checked"] == 8
    # The stale admin, the old account that never signed in, and the stale group member;
    # the disabled accounts and the new account are not dormant.
    assert s["dormant_users"] == 3
    assert s["users_never_signed_in"] == 3
    assert s["users_holding_roles"] == 8
    assert s["users_holding_privileged_directory_roles"] == 2
    assert s["dormant_users_holding_roles"] == 3
    # Only the enabled, old account: not the new one or the disabled one.
    assert s["never_signed_in_users_holding_roles"] == 1
    assert s["guest_users_holding_roles"] == 1
    assert s["disabled_users_holding_roles"] == 2
    assert s["service_principals_holding_roles"] == 7
    # The idle identity and this tenant's unused app; the new app is within the grace period,
    # and a managed identity, Microsoft app or vendor app missing from the report is unknown.
    assert s["dormant_service_principals_holding_roles"] == 2
    assert s["service_principals_holding_roles_without_recorded_sign_in"] == 5
    assert s["service_principals_holding_roles_dormancy_unknown"] == 3
    assert s["disabled_service_principals_holding_roles"] == 1
    assert s["deleted_principals_holding_azure_roles"] == 1
    assert s["azure_role_assignments_to_deleted_principals"] == 2
    assert s["no_inactive_identity_holds_a_role"] is False

    assert results["tenant_id"] == TENANT
    users = {u["id"]: u for u in results["users"]}
    assert users["u-new"]["never_signed_in"] is True and users["u-new"]["dormant"] is False
    member = users["u-group-member"]
    assert member["directory_roles"] == [{"role": "Global Administrator", "privileged": True, "via_group_id": "g-admins"}]
    assert users["u-guest"]["azure_roles"][0]["via_group_id"] == "g-ops"
    assert users["u-active"]["azure_roles"][0]["role"] == "Owner"
    sps = {s["id"]: s for s in results["service_principals"]}
    assert sps["sp-idle"]["dormant"] is True and sps["sp-idle"]["days_since_last_client_sign_in"] == 120
    assert sps["sp-busy"]["holds_directory_role"] is True and sps["sp-busy"]["dormant"] is False
    assert sps["sp-mi-new"]["dormant"] is None and sps["sp-mi-new"]["in_sign_in_activity_report"] is False
    assert sps["sp-ms"]["dormant"] is None and sps["sp-vendor"]["dormant"] is None
    assert sps["sp-unused"]["dormant"] is True and sps["sp-unused"]["registered_in_this_tenant"] is True
    assert sps["sp-new"]["dormant"] is False and sps["sp-new"]["no_recorded_client_sign_in"] is True
    assert sps["sp-new"]["days_since_created"] == 5  # from its app registration
    assert s["tenant_readable"] is True
    (gone,) = results["deleted_principals"]
    assert gone["id"] == "gone-1" and gone["principal_types_recorded"] == ["User"]


def test_a_service_principals_own_creation_date_wins_and_none_means_no_grace(monkeypatch):
    graph, arm, objects = _tenant()
    objects["sp-new"] = _sp("sp-new", "app-new", created=3)
    graph["/applications"] = []
    results, _, _ = _collect(monkeypatch, FakeClient(graph, arm, objects))
    sps = {r["id"]: r for r in results["service_principals"]}
    assert sps["sp-new"]["days_since_created"] == 3 and sps["sp-new"]["dormant"] is False
    # No creation date from either source: an app not yet signed in reads dormant.
    assert sps["sp-unused"]["days_since_created"] is None and sps["sp-unused"]["dormant"] is True


def test_an_app_with_no_owner_organization_is_unknown(monkeypatch):
    graph, arm, objects = _tenant()
    objects["sp-unused"] = _sp("sp-unused", "app-unused", owner=None)
    results, _, _ = _collect(monkeypatch, FakeClient(graph, arm, objects))
    sp = {r["id"]: r for r in results["service_principals"]}["sp-unused"]
    assert sp["registered_in_this_tenant"] is False and sp["dormant"] is None


def test_a_refused_subscription_read_leaves_every_missing_principal_unknown(monkeypatch):
    graph, arm, objects = _tenant()
    graph["/directoryRoles/r-ga/members"] = []
    graph["/directoryRoles/r-dr/members"] = []
    arm["roleAssignments"] = [_assignment("a1", "u-active"), _assignment("a10", "sp-unused", ptype="ServicePrincipal")]
    results, s, collector = _collect(monkeypatch, FakeClient(graph, arm, objects, errors={f"/subscriptions/{SUB}": DENIED}))

    assert [f["operation"] for f in collector.failures] == ["subscriptions.get"]
    assert s["tenant_readable"] is False
    (sp,) = results["service_principals"]
    assert sp["registered_in_this_tenant"] is None and sp["dormant"] is None
    assert s["service_principals_holding_roles_dormancy_unknown"] == 1
    assert s["no_inactive_identity_holds_a_role"] is None


def test_dormancy_threshold_is_configurable(monkeypatch):
    monkeypatch.setenv("ENTRA_DORMANT_DAYS", "180")
    _, s = dormant.collect(FakeClient(*_tenant()), SUB, Collector())
    assert s["dormant_after_days"] == 180
    assert s["dormant_users"] == 2  # stale admin (200) and never signed in (created 300)


def test_graphs_empty_sign_in_time_reads_as_none(monkeypatch):
    graph, arm, objects = _tenant()
    empty = {"lastSuccessfulSignInDateTime": EMPTY_TIME, "lastSignInDateTime": EMPTY_TIME,
             "lastNonInteractiveSignInDateTime": EMPTY_TIME}
    graph["/users"] = [_user("u-active", created=300, activity=empty)]
    graph["/reports/servicePrincipalSignInActivities"] = [
        {"appId": "app-unused", "applicationAuthenticationClientSignInActivity": {"lastSignInDateTime": EMPTY_TIME}},
    ]
    results, s, _ = _collect(monkeypatch, FakeClient(graph, arm, objects))

    (user,) = results["users"]
    assert user["never_signed_in"] is True and user["dormant"] is True
    assert user["last_successful_sign_in_date_time"] is None
    sp = {r["id"]: r for r in results["service_principals"]}["sp-unused"]
    assert sp["no_recorded_client_sign_in"] is True and sp["days_since_last_client_sign_in"] is None


def test_denied_sign_in_activity_still_lists_users_and_roles(monkeypatch):
    from azure_common import classify_failure_code

    graph, arm, objects = _tenant()
    client = FakeClient(graph, arm, objects, errors={SIGN_IN_PATH: DENIED, "/reports/": DENIED})
    results, s, collector = _collect(monkeypatch, client)

    assert classify_failure_code(collector.failures) == "not_authorized"
    assert {f["operation"] for f in collector.failures} == {
        "graph.users.get(signInActivity)", "graph.reports.servicePrincipalSignInActivities.get(beta)",
    }
    assert s["users_readable"] is True
    assert s["user_sign_in_activity"] == "not_read"
    assert s["service_principal_sign_in_activity"] == "not_read"
    assert s["users_checked"] == 8
    assert s["dormant_users"] is None
    assert s["dormant_users_holding_roles"] is None
    assert s["dormant_service_principals_holding_roles"] is None
    assert s["guest_users_holding_roles"] == 1
    assert s["deleted_principals_holding_azure_roles"] == 1
    assert s["no_inactive_identity_holds_a_role"] is False
    assert all(u["dormant"] is None and u["last_successful_sign_in_date_time"] is None for u in results["users"])


def test_a_refused_user_list_nulls_every_user_count(monkeypatch):
    graph, arm, objects = _tenant()
    _, s, collector = _collect(monkeypatch, FakeClient(graph, arm, objects, errors={"/users?": DENIED}))

    assert {f["operation"] for f in collector.failures} == {"graph.users.get(signInActivity)", "graph.users.get"}
    assert s["users_readable"] is False
    for key in ("users_checked", "users_holding_roles", "users_holding_directory_roles",
                "users_holding_privileged_directory_roles", "users_holding_azure_roles", "enabled_users",
                "guest_users", "dormant_users", "guest_users_holding_roles", "disabled_users_holding_roles"):
        assert s[key] is None, key
    assert s["service_principals_holding_roles"] == 7
    assert s["no_inactive_identity_holds_a_role"] is False  # the dormant service principals still show


def test_refused_directory_roles_null_the_directory_counts(monkeypatch):
    graph, arm, objects = _tenant()
    results, s, _ = _collect(monkeypatch, FakeClient(graph, arm, objects, errors={"/directoryRoles": DENIED}))

    assert s["directory_roles_readable"] is False
    for key in ("users_holding_roles", "users_holding_directory_roles", "users_holding_privileged_directory_roles",
                "service_principals_holding_directory_roles", "service_principals_holding_roles",
                "dormant_users_holding_roles", "dormant_service_principals_holding_roles"):
        assert s[key] is None, key
    assert s["users_holding_azure_roles"] == 6
    users = {u["id"]: u for u in results["users"]}
    assert users["u-active"]["holds_directory_role"] is None and users["u-active"]["holds_role"] is True
    assert users["u-stale-admin"]["holds_role"] is None


def test_a_refused_lookup_nulls_the_service_principal_and_deleted_counts(monkeypatch):
    graph, arm, objects = _tenant()
    _, s, _ = _collect(monkeypatch, FakeClient(graph, arm, objects, errors={"/directoryObjects/getByIds": DENIED}))

    assert s["principal_lookup_readable"] is False
    for key in ("service_principals_holding_roles", "service_principals_holding_directory_roles",
                "service_principals_holding_azure_roles", "dormant_service_principals_holding_roles",
                "service_principals_holding_roles_without_recorded_sign_in",
                "service_principals_holding_roles_dormancy_unknown", "disabled_service_principals_holding_roles",
                "deleted_principals_holding_azure_roles", "azure_role_assignments_to_deleted_principals"):
        assert s[key] is None, key
    assert s["users_holding_roles"] == 8


def test_a_failed_group_member_read_leaves_both_role_reads_unreadable(monkeypatch):
    graph, arm, objects = _tenant()
    client = FakeClient(graph, arm, objects, errors={"/groups/g-ops/transitiveMembers": DENIED})
    _, s, _ = _collect(monkeypatch, client)

    assert s["directory_roles_readable"] is False and s["azure_roles_readable"] is False
    assert s["users_holding_roles"] is None
    assert s["guest_users_holding_roles"] is None


def test_unlicensed_tenant_reads_not_licensed(monkeypatch):
    graph, arm, objects = _tenant()
    client = FakeClient(graph, arm, objects, errors={SIGN_IN_PATH: NOT_LICENSED})
    _, s, _ = _collect(monkeypatch, client)
    assert s["user_sign_in_activity"] == "not_licensed"
    assert s["service_principal_sign_in_activity"] == "read"


def test_no_flag_is_true_only_when_everything_was_read(monkeypatch):
    graph, arm, objects = _tenant()
    graph["/directoryRoles/r-ga/members"] = []
    graph["/directoryRoles/r-dr/members"] = []
    arm["roleAssignments"] = [_assignment("a1", "u-active")]
    _, s, collector = _collect(monkeypatch, FakeClient(graph, arm, objects))
    assert collector.failures == []
    assert s["no_inactive_identity_holds_a_role"] is True

    # A managed identity holding a role but missing from the sign-in report leaves the answer open.
    arm["roleAssignments"].append(_assignment("a8", "sp-mi-new", ptype="ServicePrincipal"))
    _, s, _ = _collect(monkeypatch, FakeClient(graph, arm, objects))
    assert s["service_principals_holding_roles_dormancy_unknown"] == 1
    assert s["no_inactive_identity_holds_a_role"] is None
    arm["roleAssignments"].pop()

    client = FakeClient(graph, arm, objects, errors={"/roleAssignments": DENIED})
    _, s, _ = _collect(monkeypatch, client)
    assert s["azure_roles_readable"] is False
    assert s["no_inactive_identity_holds_a_role"] is None


def test_reads_page_sizes_and_beta_endpoints(monkeypatch):
    client = FakeClient(*_tenant())
    _collect(monkeypatch, client)
    assert ("v1.0", f"{SIGN_IN_PATH}&$top=500") in client.calls
    assert ("beta", "/groups/g-admins/transitiveMembers?$select=id") in client.calls
    assert ("beta", "/reports/servicePrincipalSignInActivities") in client.calls
    assert ("v1.0", "/applications?$select=appId,createdDateTime&$top=999") in client.calls


def test_evidence_is_json_serialisable(monkeypatch):
    results, s, _ = _collect(monkeypatch, FakeClient(*_tenant()))
    json.dumps({"results": results, "summary": s})


def test_main_writes_evidence_and_fails_not_authorized(monkeypatch, tmp_path):
    azure_rest = sys.modules["azure_rest"]
    graph, arm, objects = _tenant()
    client = FakeClient(graph, arm, objects, errors={SIGN_IN_PATH: DENIED})
    monkeypatch.setattr(azure_rest, "pinned_credential", lambda sub: object())
    monkeypatch.setattr(azure_rest, "AzureRestClient", lambda cred, session=None: client)
    monkeypatch.setattr(azure_rest, "REPO_ROOT", tmp_path / "repo")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.delenv("ENTRA_DORMANT_DAYS", raising=False)

    assert dormant.main() == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "not_authorized"
    evidence = json.loads((tmp_path / f"azure_entra_dormant_identities_{SUB}.json").read_text())
    assert evidence["summary"]["user_sign_in_activity"] == "not_read"
    assert evidence["summary"]["users_checked"] == 8
    assert evidence["summary"]["dormant_users"] is None


# --- the shared REST client's Graph paging ---

class Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.reason, self.text = status, body, "", json.dumps(body)

    def json(self):
        return self._body


class Session:
    """Answers GETs by URL; records each."""

    def __init__(self, answers):
        self.answers, self.urls = answers, []

    def get(self, url, headers=None, params=None, timeout=None):
        self.urls.append(url)
        return self.answers[url]


def _rest(answers):
    azure_rest = sys.modules["azure_rest"]
    cred = namedtuple("Cred", "get_token")(lambda scope: namedtuple("T", "token expires_on")("tok", 9_999_999_999))
    return azure_rest.AzureRestClient(cred, Session(answers)), azure_rest


def test_graph_pages_follow_next_links_on_the_requested_version(monkeypatch):
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    base = "https://graph.microsoft.com"
    client, _ = _rest({
        f"{base}/beta/things?$top=2": Resp(200, {"value": [1, 2], "@odata.nextLink": f"{base}/beta/things?page=2"}),
        f"{base}/beta/things?page=2": Resp(200, {"value": [3]}),
    })
    assert list(client.graph_pages("/things?$top=2", "beta")) == [[1, 2], [3]]
    assert client.graph_list("/things?$top=2", "beta") == [1, 2, 3]
    assert client.session.urls[0] == f"{base}/beta/things?$top=2"


def test_graph_list_raises_on_a_failed_later_page(monkeypatch):
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    base = "https://graph.microsoft.com"
    client, azure_rest = _rest({
        f"{base}/v1.0/things": Resp(200, {"value": [1], "@odata.nextLink": f"{base}/v1.0/things?page=2"}),
        f"{base}/v1.0/things?page=2": Resp(403, {"error": {"code": "Authorization_RequestDenied", "message": "no"}}),
    })
    with pytest.raises(azure_rest.ArmError, match="403"):
        client.graph_list("/things")
