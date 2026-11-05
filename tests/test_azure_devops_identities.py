"""azure_devops_identities, driven without Azure DevOps.

FakeADO stands in for requests.Session and serves one organization's Graph
(vssps) and Member Entitlement Management (vsaex) APIs: users, a service
principal, the build service, Azure DevOps and Entra groups nested into the
privileged groups, and two pages of user entitlements. Bodies follow the
Azure DevOps REST 7.1 reference samples.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "devops_identities" / "fetcher.py"
spec = importlib.util.spec_from_file_location("azure_devops_identities_under_test", FETCHER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
dr = sys.modules["devops_rest"]

ORG = "https://dev.azure.com/contoso"
NOW = datetime.now(timezone.utc)
TENANT = "00000000-0000-0000-0000-0000000000aa"
ORG_DOMAIN = "vstfs:///Framework/IdentityDomain/00000000-0000-0000-0000-0000000000bb"
WEB_DOMAIN = "vstfs:///Classification/TeamProject/00000000-0000-0000-0000-0000000000cc"
NEVER = "0001-01-01T00:00:00Z"


def ago(**kw):
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%S.%f0Z")


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body = status, body
        self.headers = headers or {}
        self.text = json.dumps(body)
        self.reason = "OK" if status < 400 else "Error"

    def json(self):
        return self._body


def err(status, message, type_key="Exception"):
    return Resp(status, {"$id": "1", "message": message, "typeKey": type_key, "errorCode": 0})


def user(descriptor, name, meta="member", origin="aad"):
    return {"subjectKind": "user", "descriptor": descriptor, "displayName": name.split("@")[0].title(),
            "principalName": name, "mailAddress": name, "origin": origin, "originId": f"oid-{descriptor}",
            "metaType": meta, "domain": TENANT}


def group(descriptor, principal, domain=ORG_DOMAIN, origin="vsts"):
    return {"subjectKind": "group", "descriptor": descriptor, "principalName": principal,
            "displayName": principal.split("\\")[-1], "origin": origin, "domain": domain}


def entitlement(subject, level="Basic", status="active", accessed=None, created=None):
    return {"id": f"id-{subject['descriptor']}", "user": subject,
            "accessLevel": {"licenseDisplayName": level, "accountLicenseType": "express", "status": status,
                            "licensingSource": "account"},
            "lastAccessedDate": accessed or NEVER, "dateCreated": created or ago(days=500)}


ALICE = user("aad.alice", "alice@example.com")
BOB = user("aad.bob", "bob@example.com")
CAROL = user("aad.carol", "carol@partner.example", meta="guest")
DAVE = user("aad.dave", "dave@example.com")
ERIN = user("aad.erin", "erin@example.com")
BUILD = {"subjectKind": "user", "descriptor": "svc.build", "displayName": "Project Collection Build Service (contoso)",
         "principalName": "build-guid", "origin": "vsts", "domain": "Build"}
SYSTEM = {"subjectKind": "user", "descriptor": "acs.tfs", "displayName": "TeamFoundationService (TEAM FOUNDATION)",
          "principalName": "TeamFoundationService (TEAM FOUNDATION)", "origin": "vsts"}
DEPLOY = {"subjectKind": "servicePrincipal", "descriptor": "aadsp.deploy", "displayName": "deploy-automation",
          "principalName": "sp-object-id", "applicationId": "app-id-1", "origin": "aad", "originId": "sp-object-id"}

GROUPS = [
    group("vssgp.pca", "[contoso]\\Project Collection Administrators"),
    group("vssgp.pcvu", "[contoso]\\Project Collection Valid Users"),
    group("vssgp.ops", "[contoso]\\Ops Leads"),
    group("vssgp.esa", "[TEAM FOUNDATION]\\Enterprise Service Accounts"),
    group("vssgp.wpa", "[Web]\\Project Administrators", WEB_DOMAIN),
    group("vssgp.wc", "[Web]\\Contributors", WEB_DOMAIN),
    group("vssgp.wba", "[Web]\\Build Administrators", WEB_DOMAIN),
    # An Entra group's principalName is "[TEAM FOUNDATION]\<name>", as in the Groups - Create samples.
    group("aadgp.pa", "[TEAM FOUNDATION]\\Platform Admins", origin="aad"),
]
PLATFORM_ADMINS = "[TEAM FOUNDATION]\\Platform Admins"

MEMBERS = {
    "vssgp.pca": ["aad.alice", "vssgp.ops"],
    "vssgp.ops": ["aad.carol"],
    "vssgp.wpa": ["aadgp.pa", "aadsp.deploy"],
    "aadgp.pa": ["aad.bob"],
    "vssgp.wc": ["aad.dave", "aad.alice"],
    "vssgp.wba": ["svc.build"],
}


def membership_rows(container):
    return {"count": len(MEMBERS.get(container, [])), "value": [
        {"containerDescriptor": container, "memberDescriptor": m} for m in MEMBERS.get(container, [])]}


class FakeADO:
    """Routes by host and path; a route is a Resp, a dict of Resps by continuation token, or a callable."""

    def __init__(self):
        self.calls = []
        self.routes = {
            ("dev.azure.com", "/contoso/_apis/connectionData"): Resp(body={"authenticatedUser": {
                "id": "u0", "providerDisplayName": "Evidence Reader",
                "properties": {"Account": {"$type": "System.String", "$value": "reader@example.com"}}}}),
            ("vssps.dev.azure.com", "/contoso/_apis/graph/users"): {
                None: Resp(body={"count": 4, "value": [ALICE, BOB, CAROL, SYSTEM]},
                           headers={"x-ms-continuationtoken": "u2"}),
                "u2": Resp(body={"count": 3, "value": [DAVE, ERIN, BUILD]}),
            },
            ("vssps.dev.azure.com", "/contoso/_apis/graph/serviceprincipals"): Resp(body={"value": [DEPLOY]}),
            ("vssps.dev.azure.com", "/contoso/_apis/graph/groups"): Resp(body={"value": GROUPS}),
            ("vsaex.dev.azure.com", "/contoso/_apis/userentitlements"): {
                None: Resp(body={"totalCount": 5, "continuationToken": "e2", "items": [
                    entitlement(ALICE, accessed=ago(days=1)),
                    entitlement(BOB, accessed=ago(days=200)),
                    entitlement(CAROL, level="Stakeholder", status="pending", created=ago(days=10))]}),
                "e2": Resp(body={"totalCount": 5, "continuationToken": None, "items": [
                    entitlement(DAVE, created=ago(days=400)),
                    entitlement(ERIN, status="disabled", accessed=ago(days=300))]}),
            },
        }
        for g in GROUPS:
            self.routes[("vssps.dev.azure.com", f"/contoso/_apis/graph/Memberships/{g['descriptor']}")] = \
                (lambda params, d=g["descriptor"]: Resp(body=membership_rows(d)))

    def request(self, method, url, headers=None, params=None, timeout=None, allow_redirects=True, json=None):
        params = dict(params or {})
        parts = urlsplit(url)
        key = (parts.netloc, parts.path)
        self.calls.append((method, parts.netloc, parts.path, params))
        route = self.routes.get(key)
        if route is None:
            raise AssertionError(f"unexpected request {method} {key} {params}")
        if callable(route):
            return route(params)
        if isinstance(route, dict):
            token = params.get("continuationToken")
            if token not in route:
                raise AssertionError(f"unexpected page {token!r} of {key}")
            return route[token]
        return route


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    monkeypatch.delenv(mod.INACTIVE_ENV, raising=False)
    monkeypatch.setenv("AZURE_DEVOPS_ORG_URL", ORG)
    monkeypatch.setenv("AZURE_DEVOPS_PAT", "pat")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setattr(dr.time, "sleep", lambda s: None)


def run(tmp_path, fake=None):
    fake = fake or FakeADO()
    code = dr.run_org(fetcher=mod.NAME, logger=mod.logger, collect=mod.collect, session=fake)
    evidence = json.loads((tmp_path / "azure_devops_identities_contoso.json").read_text())
    status = tmp_path / "status.json"
    return code, evidence, json.loads(status.read_text()) if status.exists() else None, fake


def identity(evidence, principal):
    return next(i for i in evidence["results"]["identities"] if i["principal_name"] == principal)


def privileged_group(evidence, name):
    return next(g for g in evidence["results"]["privileged_groups"] if g["name"] == name)


def test_collects_the_organization_and_exits_zero(tmp_path):
    code, evidence, status, _ = run(tmp_path)
    assert code == 0 and status is None
    assert evidence["metadata"]["partial_failure"] is False
    s = evidence["summary"]
    assert s["users_total"] == 5 and s["guest_users"] == 1
    assert s["users_by_access_level"] == {"Basic": 4, "Stakeholder": 1}
    assert s["users_with_sign_in_disabled"] == 1
    assert (s["service_principals_total"], s["service_identities_total"]) == (1, 1)
    assert (s["groups_total"], s["entra_groups_total"]) == (8, 1)
    assert s["groups_not_read"] == []
    assert s["privileged_groups"] == 3
    assert s["privileged_members_by_group"] == {"[contoso]\\Project Collection Administrators": 2,
                                                "[Web]\\Build Administrators": 1,
                                                "[Web]\\Project Administrators": 2}
    assert s["privileged_identities"] == 5
    assert s["privileged_users"] == ["alice@example.com", "bob@example.com", "carol@partner.example"]
    assert s["privileged_service_principals"] == ["sp-object-id"]
    assert s["privileged_identities_only_through_entra_groups"] == 1
    assert s["entra_groups_granting_privilege"] == [PLATFORM_ADMINS]
    assert s["guest_privileged_users"] == ["carol@partner.example"]


def test_privileged_members_carry_the_path_and_whether_it_crosses_an_entra_group(tmp_path):
    _, evidence, _, _ = run(tmp_path)
    pca = privileged_group(evidence, "[contoso]\\Project Collection Administrators")
    members = {m["name"]: m for m in pca["effective_members"]}
    assert members["alice@example.com"]["direct"] is True
    assert members["carol@partner.example"]["via"] == ["[contoso]\\Project Collection Administrators",
                                                       "[contoso]\\Ops Leads"]
    assert members["carol@partner.example"]["through_entra_group"] is False and members["carol@partner.example"]["guest"]
    web = privileged_group(evidence, "[Web]\\Project Administrators")
    assert web["project"] == "Web" and web["members_complete"] is True
    bob = next(m for m in web["effective_members"] if m["name"] == "bob@example.com")
    assert bob["through_entra_group"] is True and bob["inactive"] is True
    assert bob["via"] == ["[Web]\\Project Administrators", PLATFORM_ADMINS]
    assert web["entra_groups"] == [PLATFORM_ADMINS]
    assert next(m for m in web["effective_members"] if m["name"] == "sp-object-id")["kind"] == "service_principal"


def test_computed_and_enterprise_groups_are_not_expanded(tmp_path):
    _, _, _, fake = run(tmp_path)
    read = {path.rsplit("/", 1)[-1] for _, _, path, _ in fake.calls if "/Memberships/" in path}
    assert read == {"vssgp.pca", "vssgp.ops", "vssgp.wpa", "vssgp.wc", "vssgp.wba", "aadgp.pa"}
    assert all(p.get("direction") == "down" for _, _, path, p in fake.calls if "/Memberships/" in path)


def test_an_entra_group_named_under_team_foundation_is_read_not_skipped(tmp_path):
    _, evidence, _, _ = run(tmp_path)
    groups = {g["descriptor"]: g for g in evidence["results"]["groups"]}
    assert groups["aadgp.pa"]["computed"] is False and groups["aadgp.pa"]["members_read"] is True
    assert groups["vssgp.esa"]["computed"] is True
    assert evidence["summary"]["privileged_identities_only_through_entra_groups"] == 1


def test_a_member_with_an_azure_devops_path_is_not_entra_only(tmp_path, monkeypatch):
    leads = group("vssgp.rel", "[Web]\\Release Leads", WEB_DOMAIN)
    monkeypatch.setitem(MEMBERS, "vssgp.wpa", ["aadgp.pa", "aadsp.deploy", "vssgp.rel"])
    monkeypatch.setitem(MEMBERS, "vssgp.rel", ["aad.bob"])
    fake = FakeADO()
    fake.routes[("vssps.dev.azure.com", "/contoso/_apis/graph/groups")] = Resp(body={"value": GROUPS + [leads]})
    fake.routes[("vssps.dev.azure.com", "/contoso/_apis/graph/Memberships/vssgp.rel")] = \
        lambda params: Resp(body=membership_rows("vssgp.rel"))
    _, evidence, _, _ = run(tmp_path, fake)
    web = privileged_group(evidence, "[Web]\\Project Administrators")
    bob = next(m for m in web["effective_members"] if m["name"] == "bob@example.com")
    assert bob["through_entra_group"] is False
    assert bob["via"] == ["[Web]\\Project Administrators", "[Web]\\Release Leads"]
    assert evidence["summary"]["privileged_identities_only_through_entra_groups"] == 0


def test_refused_groups_leave_the_privilege_fields_unknown(tmp_path):
    fake = FakeADO()
    fake.routes[("vssps.dev.azure.com", "/contoso/_apis/graph/groups")] = err(403, "TF400813: no.")
    code, evidence, _, _ = run(tmp_path, fake)
    assert code == 1
    s = evidence["summary"]
    for field in ("groups_total", "entra_groups_total", "groups_not_read", "privileged_groups",
                  "privileged_groups_not_fully_read", "privileged_members_by_group", "privileged_identities",
                  "privileged_users", "privileged_service_principals",
                  "privileged_identities_only_through_entra_groups", "entra_groups_granting_privilege",
                  "inactive_privileged_users", "guest_privileged_users"):
        assert s[field] is None, field
    assert s["users_total"] == 5 and s["inactive_users"] == ["bob@example.com", "dave@example.com"]
    alice = identity(evidence, "alice@example.com")
    assert (alice["groups"], alice["direct_groups"], alice["privileged_groups"]) == (None, None, None)


def test_refused_users_leave_the_people_fields_unknown(tmp_path):
    fake = FakeADO()
    fake.routes[("vssps.dev.azure.com", "/contoso/_apis/graph/users")] = err(403, "TF400813: no.")
    code, evidence, _, _ = run(tmp_path, fake)
    assert code == 1
    s = evidence["summary"]
    for field in ("users_total", "guest_users", "users_by_origin", "users_deleted_in_origin",
                  "service_identities_total", "guest_privileged_users"):
        assert s[field] is None, field
    # Entitled people still come from the user entitlements.
    assert s["privileged_users"] == ["alice@example.com", "bob@example.com", "carol@partner.example"]
    assert s["inactive_users"] == ["bob@example.com", "dave@example.com"]


def test_sign_in_disabled_counts_disabled_and_deleted_users(tmp_path):
    fake = FakeADO()
    page = fake.routes[("vsaex.dev.azure.com", "/contoso/_apis/userentitlements")]["e2"]._body["items"]
    page[0] = entitlement(DAVE, status="deleted", created=ago(days=400))
    _, evidence, _, _ = run(tmp_path, fake)
    assert evidence["summary"]["users_with_sign_in_disabled"] == 2
    assert evidence["summary"]["inactive_users"] == ["bob@example.com"]
    assert identity(evidence, "dave@example.com")["can_sign_in"] is False


def test_people_deleted_in_their_identity_source_are_listed(tmp_path, monkeypatch):
    monkeypatch.setitem(DAVE, "isDeletedInOrigin", True)
    _, evidence, _, _ = run(tmp_path)
    assert evidence["summary"]["users_deleted_in_origin"] == ["dave@example.com"]
    assert identity(evidence, "dave@example.com")["deleted_in_origin"] is True
    assert identity(evidence, "alice@example.com")["deleted_in_origin"] is False


def test_each_identity_lists_direct_and_inherited_groups(tmp_path):
    _, evidence, _, _ = run(tmp_path)
    carol = identity(evidence, "carol@partner.example")
    assert carol["direct_groups"] == ["[contoso]\\Ops Leads"]
    assert carol["groups"] == ["[contoso]\\Ops Leads", "[contoso]\\Project Collection Administrators"]
    assert carol["privileged_groups"] == ["[contoso]\\Project Collection Administrators"]
    alice = identity(evidence, "alice@example.com")
    assert alice["direct_groups"] == ["[contoso]\\Project Collection Administrators", "[Web]\\Contributors"]
    assert identity(evidence, "dave@example.com")["privileged_groups"] == []


def test_inactivity_uses_last_access_or_the_date_added(tmp_path):
    _, evidence, _, _ = run(tmp_path)
    s = evidence["summary"]
    assert s["inactivity_threshold_days"] == 90
    assert s["inactive_users"] == ["bob@example.com", "dave@example.com"]  # carol is new, erin can't sign in
    assert s["users_never_accessed"] == ["carol@partner.example", "dave@example.com"]
    assert s["inactive_privileged_users"] == ["bob@example.com"]
    bob = identity(evidence, "bob@example.com")
    assert bob["days_since_last_access"] in (199, 200) and bob["access_level"] == "Basic"
    dave = identity(evidence, "dave@example.com")
    assert dave["last_accessed"] is None and dave["never_accessed"] is True


def test_the_threshold_is_configurable(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.INACTIVE_ENV, "365")
    _, evidence, _, _ = run(tmp_path)
    assert evidence["summary"]["inactive_users"] == ["dave@example.com"]


def test_entitlement_pages_also_read_the_older_members_shape(tmp_path):
    fake = FakeADO()
    route = fake.routes[("vsaex.dev.azure.com", "/contoso/_apis/userentitlements")]
    route["e2"] = Resp(body={"members": route["e2"]._body["items"]})
    _, evidence, _, _ = run(tmp_path, fake)
    assert identity(evidence, "dave@example.com")["access_level"] == "Basic"


def test_a_malformed_entitlement_item_is_skipped(tmp_path):
    fake = FakeADO()
    route = fake.routes[("vsaex.dev.azure.com", "/contoso/_apis/userentitlements")]
    route["e2"] = Resp(body={"items": ["not-an-entitlement", *route["e2"]._body["items"]]})
    code, evidence, _, _ = run(tmp_path, fake)
    assert code == 0 and identity(evidence, "dave@example.com")["access_level"] == "Basic"


def test_refused_entitlements_name_the_scope_and_leave_the_rest(tmp_path):
    fake = FakeADO()
    fake.routes[("vsaex.dev.azure.com", "/contoso/_apis/userentitlements")] = err(
        401, "TF400813: The user 'x' is not authorized to access this resource.", "UnauthorizedRequestException")
    code, evidence, status, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "auth_failed"
    failure = evidence["metadata"]["api_failures"][0]
    assert failure["operation"] == "userentitlements.list"
    assert "PAT scope needed: Member Entitlement Management (Read)" in failure["message"]
    s = evidence["summary"]
    assert s["last_access_collected"] is False
    for field in ("inactive_users", "users_never_accessed", "users_with_sign_in_disabled", "users_by_access_level",
                  "inactive_privileged_users"):
        assert s[field] is None, field
    assert s["privileged_users"] == ["alice@example.com", "bob@example.com", "carol@partner.example"]
    bob = identity(evidence, "bob@example.com")
    assert (bob["inactive"], bob["never_accessed"], bob["can_sign_in"]) == (None, None, None)
    web = privileged_group(evidence, "[Web]\\Project Administrators")
    assert next(m for m in web["effective_members"] if m["name"] == "bob@example.com")["inactive"] is None


def test_an_unread_nested_group_marks_the_privileged_group_incomplete(tmp_path):
    fake = FakeADO()
    fake.routes[("vssps.dev.azure.com", "/contoso/_apis/graph/Memberships/aadgp.pa")] = err(403, "Access denied.")
    code, evidence, status, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "not_authorized"
    web = privileged_group(evidence, "[Web]\\Project Administrators")
    assert web["members_complete"] is False
    assert [m["name"] for m in web["effective_members"]] == ["sp-object-id"]
    s = evidence["summary"]
    assert s["groups_not_read"] == [PLATFORM_ADMINS]
    assert s["privileged_groups_not_fully_read"] == ["[Web]\\Project Administrators"]


def test_as_an_entra_identity_a_refusal_names_the_missing_permission(tmp_path, monkeypatch):
    monkeypatch.delenv("AZURE_DEVOPS_PAT")
    monkeypatch.setattr(dr, "entra_credential", lambda: SimpleNamespace(
        get_token=lambda scope: SimpleNamespace(token="t", expires_on=NOW.timestamp() + 3600)))
    fake = FakeADO()
    fake.routes[("vssps.dev.azure.com", "/contoso/_apis/graph/serviceprincipals")] = err(403, "TF400813: no.")
    code, evidence, _, _ = run(tmp_path, fake)
    assert code == 1 and evidence["metadata"]["auth_mode"] == "entra"
    assert "Entra identity lacks permission" in evidence["metadata"]["api_failures"][0]["message"]
    assert evidence["summary"]["service_principals_total"] is None
    assert evidence["summary"]["users_total"] == 5


def test_a_missing_organization_is_bad_config(tmp_path):
    fake = FakeADO()
    fake.routes[("vssps.dev.azure.com", "/contoso/_apis/graph/users")] = Resp(404, {"message": "Not found."})
    code, evidence, status, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "bad_config"
    failure = evidence["metadata"]["api_failures"][0]
    assert failure["operation"] == "graph.users.list" and "not found" in failure["message"]
    assert failure["type"] == "ValueError"


def test_invalid_threshold_is_bad_config(tmp_path, monkeypatch):
    monkeypatch.setenv(mod.INACTIVE_ENV, "three months")
    code, _, status, _ = run(tmp_path)
    assert code == 1 and status["code"] == "bad_config"


def test_a_repeated_entitlement_token_is_a_failure_not_a_loop(tmp_path):
    fake = FakeADO()
    route = fake.routes[("vsaex.dev.azure.com", "/contoso/_apis/userentitlements")]
    route["e2"] = Resp(body={"items": [], "continuationToken": "e2"})
    code, evidence, _, _ = run(tmp_path, fake)
    assert code == 1 and "ContinuationLoop" in evidence["metadata"]["api_failures"][0]["message"]


@pytest.mark.parametrize("descriptor,kind", [
    ("aad.x", "user"), ("msa.x", "user"), ("aadsp.x", "service_principal"), ("svc.x", "service_identity"),
    ("vssgp.x", "group"), ("aadgp.x", "group"), ("acs.x", "system"), ("weird.x", "other"), (None, "other"),
])
def test_kind_of(descriptor, kind):
    assert mod.kind_of(descriptor) == kind


def test_an_evidence_sample_keeps_every_not_collected_entry():
    from framework import samples
    assert samples.trim({"not_collected": dict(mod.NOT_COLLECTED)})["not_collected"] == mod.NOT_COLLECTED
