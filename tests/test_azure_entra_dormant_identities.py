"""azure_entra_dormant_identities: inactive, guest and deleted identities that still hold a role.

Synthetic Graph and ARM responses only: no SDK, no credentials, no network.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "entra_dormant_identities" / "fetcher.py"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))

spec = importlib.util.spec_from_file_location("azure_entra_dormant_identities_under_test", FETCHER)
dormant = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dormant)

SUB = "00000000-0000-0000-0000-0000000000cc"
NOW = datetime.now(timezone.utc)
OWNER_ROLE = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
DENIED = Exception("(403) Authorization_RequestDenied: Insufficient privileges to complete the operation.")
NOT_LICENSED = Exception(
    "(403) Authentication_RequestFromNonPremiumTenantOrB2CTenant: Neither tenant is B2C or tenant doesn't have premium license"
)


SIGN_IN_PATH = f"/users?$select={dormant.USER_SELECT},signInActivity"


def _ago(days):
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _user(uid, last=None, created=400, guest=False, enabled=True, attempts=None):
    activity = None
    if last is not None or attempts is not None:
        activity = {"lastSuccessfulSignInDateTime": _ago(last) if last is not None else None,
                    "lastSignInDateTime": _ago(attempts) if attempts is not None else None,
                    "lastNonInteractiveSignInDateTime": None}
    return {"id": uid, "displayName": f"User {uid}", "userPrincipalName": f"{uid}@contoso.test",
            "accountEnabled": enabled, "userType": "Guest" if guest else "Member",
            "createdDateTime": _ago(created), "signInActivity": activity}


def _assignment(aid, principal, ptype="User", role=OWNER_ROLE, scope=f"/subscriptions/{SUB}"):
    return {"id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments/{aid}",
            "properties": {"principalId": principal, "principalType": ptype,
                           "roleDefinitionId": role, "scope": scope}}


class FakeClient:
    """AzureRestClient's graph_list / graph_post / list, answered from a dict; errors per path prefix."""

    def __init__(self, graph, arm, objects, errors=None):
        self.graph, self.arm, self.objects, self.errors = graph, arm, objects, errors or {}
        self.calls = []

    def _raise(self, path):
        for prefix, error in self.errors.items():
            if path.startswith(prefix):
                raise error

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
    ]
    graph = {
        "/users": users,
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
        ],
    }
    objects = {
        "sp-busy": {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-busy", "appId": "app-busy",
                    "displayName": "Busy app", "servicePrincipalType": "Application", "accountEnabled": True},
        "sp-idle": {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-idle", "appId": "app-idle",
                    "displayName": "Idle identity", "servicePrincipalType": "ManagedIdentity", "accountEnabled": True},
        "sp-mi-new": {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-mi-new", "appId": "app-mi-new",
                      "displayName": "Unreported identity", "servicePrincipalType": "ManagedIdentity",
                      "accountEnabled": True},
        "sp-ms": {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-ms", "appId": "app-ms",
                  "displayName": "First-party app", "servicePrincipalType": "Application", "accountEnabled": True,
                  "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a"},
        "sp-unused": {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-unused", "appId": "app-unused",
                      "displayName": "Unused app", "servicePrincipalType": "Application", "accountEnabled": True,
                      "appOwnerOrganizationId": "00000000-0000-0000-0000-0000000000aa"},
        "g-ops": {"@odata.type": "#microsoft.graph.group", "id": "g-ops"},
    }
    return graph, arm, objects


def _collect(monkeypatch, client):
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

    monkeypatch.delenv("ENTRA_DORMANT_DAYS", raising=False)
    collector = Collector()
    results, summary = dormant.collect(client, SUB, collector)
    return results, summary, collector


def test_inactive_guest_and_deleted_role_holders(monkeypatch):
    results, s, collector = _collect(monkeypatch, FakeClient(*_tenant()))

    assert collector.failures == []
    assert s["user_sign_in_activity"] == s["service_principal_sign_in_activity"] == "read"
    assert s["dormant_after_days"] == 90
    assert s["users_checked"] == 7
    # The stale admin, the old account that never signed in, and the stale group member;
    # the disabled account and the new account are not dormant.
    assert s["dormant_users"] == 3
    assert s["users_never_signed_in"] == 2
    assert s["users_holding_roles"] == 6
    assert s["users_holding_privileged_directory_roles"] == 2
    assert s["dormant_users_holding_roles"] == 3
    assert s["never_signed_in_users_holding_roles"] == 1
    assert s["guest_users_holding_roles"] == 1
    assert s["disabled_users_holding_roles"] == 1
    assert s["service_principals_holding_roles"] == 5
    # The idle identity and the app this tenant registered with no sign-in on record; a managed
    # identity or Microsoft app missing from the report is unknown, not dormant.
    assert s["dormant_service_principals_holding_roles"] == 2
    assert s["service_principals_holding_roles_without_recorded_sign_in"] == 3
    assert s["service_principals_holding_roles_dormancy_unknown"] == 2
    assert s["deleted_principals_holding_azure_roles"] == 1
    assert s["azure_role_assignments_to_deleted_principals"] == 2
    assert s["no_inactive_identity_holds_a_role"] is False

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
    assert sps["sp-ms"]["dormant"] is None
    assert sps["sp-unused"]["dormant"] is True and sps["sp-unused"]["no_recorded_client_sign_in"] is True
    (gone,) = results["deleted_principals"]
    assert gone["id"] == "gone-1" and gone["principal_types_recorded"] == ["User"]


def test_dormancy_threshold_is_configurable(monkeypatch):
    client = FakeClient(*_tenant())
    monkeypatch.setenv("ENTRA_DORMANT_DAYS", "180")

    class Collector:
        failures: list = []

        def guard(self, operation, fn, default=None):
            return fn()

    _, s = dormant.collect(client, SUB, Collector())
    assert s["dormant_after_days"] == 180
    assert s["dormant_users"] == 2  # stale admin (200) and never signed in (created 300)


def test_denied_sign_in_activity_still_lists_users_and_roles(monkeypatch):
    from azure_common import classify_failure_code

    graph, arm, objects = _tenant()
    client = FakeClient(graph, arm, objects, errors={SIGN_IN_PATH: DENIED, "/reports/": DENIED})
    results, s, collector = _collect(monkeypatch, client)

    assert classify_failure_code(collector.failures) == "not_authorized"
    assert {f["operation"] for f in collector.failures} == {
        "graph.users.get(signInActivity)", "graph.reports.servicePrincipalSignInActivities.get(beta)",
    }
    assert s["user_sign_in_activity"] == "not_read"
    assert s["service_principal_sign_in_activity"] == "not_read"
    assert s["users_checked"] == 7
    assert s["dormant_users"] is None
    assert s["dormant_users_holding_roles"] is None
    assert s["dormant_service_principals_holding_roles"] is None
    assert s["guest_users_holding_roles"] == 1
    assert s["deleted_principals_holding_azure_roles"] == 1
    assert s["no_inactive_identity_holds_a_role"] is False
    assert all(u["dormant"] is None and u["last_successful_sign_in_date_time"] is None for u in results["users"])


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


def test_members_of_role_groups_are_read_from_beta(monkeypatch):
    client = FakeClient(*_tenant())
    _collect(monkeypatch, client)
    assert ("beta", "/groups/g-admins/transitiveMembers?$select=id") in client.calls
    assert ("beta", "/reports/servicePrincipalSignInActivities") in client.calls


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
    assert evidence["summary"]["users_checked"] == 7
    assert evidence["summary"]["dormant_users"] is None
