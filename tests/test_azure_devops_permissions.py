"""azure_devops_permissions, driven without Azure DevOps.

FakeADO stands in for requests.Session and serves one organization's
security namespaces, their access control lists (with extended info) and the
identities API that resolves ACE descriptors. Bodies follow the Azure DevOps
REST 7.1 reference samples; action names and bits follow the security
namespace reference.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "devops_permissions" / "fetcher.py"
spec = importlib.util.spec_from_file_location("azure_devops_permissions_under_test", FETCHER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
dr = sys.modules["devops_rest"]

ORG = "https://dev.azure.com/contoso"
NOW = datetime.now(timezone.utc)
WEB = "11111111-1111-1111-1111-111111111111"
OPS = "22222222-2222-2222-2222-222222222222"

PCA = "Microsoft.TeamFoundation.Identity;S-1-9-1-0-0-0-0-1"
WPA = "Microsoft.TeamFoundation.Identity;S-1-9-2-0-0-0-0-1"
CONTRIB = "Microsoft.TeamFoundation.Identity;S-1-9-2-1-1"
ALICE = "Microsoft.IdentityModel.Claims.ClaimsIdentity;tenant\\alice@example.com"
BUILDSVC = "Microsoft.TeamFoundation.ServiceIdentity;build:collection"
SP = "Microsoft.VisualStudio.Services.Claims.AadServicePrincipal;tenant\\sp-object-id"
GHOST = "Microsoft.TeamFoundation.Identity;S-1-9-9"

IDENTITIES = {
    PCA: ("[contoso]\\Project Collection Administrators", "vssgp.pca", True),
    WPA: ("[Web]\\Project Administrators", "vssgp.wpa", True),
    CONTRIB: ("[Web]\\Contributors", "vssgp.wc", True),
    ALICE: ("Alice", "aad.alice", False),
    BUILDSVC: ("Project Collection Build Service (contoso)", "svc.build", False),
    SP: ("deploy-automation", "aadsp.deploy", False),
}


def actions(*names):
    return [{"bit": 1 << i, "name": n, "displayName": n.replace("_", " ").title()} for i, n in enumerate(names) if n]


GIT = actions("Administer", "GenericRead", "GenericContribute", "ForcePush", "CreateBranch", "CreateTag",
              "ManageNote", "PolicyExempt", "CreateRepository", "DeleteRepository", "RenameRepository",
              "EditPolicies", "RemoveOthersLocks", "ManagePermissions", "PullRequestContribute",
              "PullRequestBypassPolicy")
NAMESPACES = [
    ("ns-collection", "Collection", actions("GENERIC_READ", "GENERIC_WRITE", "CREATE_PROJECTS", "", "", "", "",
                                            "", "", "", "", "MANAGE_ENTERPRISE_POLICIES")),
    ("ns-project", "Project", actions("GENERIC_READ", "GENERIC_WRITE", "DELETE")),
    ("ns-git", "Git Repositories", GIT),
    ("ns-tfvc", "VersionControlItems", actions("Read", "PendChange", "Checkin", "Label", "Lock", "ReviseOther",
                                               "UnlockOther", "UndoOther", "LabelOther", "", "AdminProjectRights",
                                               "CheckinOther")),
    ("ns-build", "Build", actions("ViewBuilds", "", "", "", "", "", "", "", "", "", "", "EditBuildDefinition",
                                  "DeleteBuildDefinition", "OverrideBuildCheckInValidation",
                                  "AdministerBuildPermissions")),
    ("ns-release", "ReleaseManagement", actions("ViewReleaseDefinition", "EditReleaseDefinition",
                                                "DeleteReleaseDefinition", "ManageReleaseApprovers", "ManageReleases",
                                                "ViewReleases", "CreateReleases", "EditReleaseEnvironment",
                                                "DeleteReleaseEnvironment", "AdministerReleasePermissions")),
    ("ns-endpoints", "ServiceEndpoints", actions("Use", "Administer", "Create", "ViewAuthorization", "ViewEndpoint")),
    ("ns-environment", "Environment", actions("View", "Manage", "ManageHistory", "Administer", "Use", "Create")),
    ("ns-library", "Library", actions("View", "Administer", "Create", "ViewSecrets", "Use", "Owner")),
    ("ns-audit", "AuditLog", actions("Read", "Write", "Manage_Streams", "Delete_Streams")),
    ("ns-wiq", "WorkItemQueryFolders", actions("Read", "Contribute")),
]


def bit(namespace, name):
    acts = next(a for _, n, a in NAMESPACES if n == namespace)
    return next(a["bit"] for a in acts if a["name"] == name)


def ace(descriptor, allow=0, deny=0, effective=None):
    return {"descriptor": descriptor, "allow": allow, "deny": deny,
            "extendedInfo": {"effectiveAllow": allow if effective is None else effective, "effectiveDeny": deny,
                             "inheritedAllow": 0, "inheritedDeny": 0}}


def acl(token, *aces, inherit=True):
    return {"inheritPermissions": inherit, "token": token, "includeExtendedInfo": True,
            "acesDictionary": {a["descriptor"]: a for a in aces}}


ACLS = {
    "ns-collection": [acl("NAMESPACE:",
                          ace(PCA, 1 | bit("Collection", "GENERIC_WRITE") | bit("Collection", "MANAGE_ENTERPRISE_POLICIES")),
                          ace(ALICE, bit("Collection", "GENERIC_WRITE")),
                          ace(CONTRIB, 0, 0))],
    "ns-project": [acl(f"$PROJECT:vstfs:///Classification/TeamProject/{WEB}",
                       ace(WPA, bit("Project", "GENERIC_WRITE") | bit("Project", "DELETE")),
                       ace(CONTRIB, 1, bit("Project", "DELETE")))],
    "ns-git": [acl(f"repoV2/{WEB}/r-web", ace(CONTRIB, bit("Git Repositories", "GenericContribute"))),
               acl(f"repoV2/{WEB}/r-web/refs/heads/6d00610069006e00",
                   ace(ALICE, bit("Git Repositories", "PolicyExempt")), inherit=False),
               acl(f"repoV2/{OPS}/r-ops", ace(CONTRIB, bit("Git Repositories", "GenericRead")))],
    "ns-tfvc": [acl("$/Web", ace(BUILDSVC, 1 | bit("VersionControlItems", "CheckinOther")))],
    "ns-build": [acl(f"{WEB}/12", ace(SP, bit("Build", "EditBuildDefinition")))],
    "ns-release": [acl(f"{WEB}/4", ace(WPA, bit("ReleaseManagement", "AdministerReleasePermissions"))),
                   acl(f"{WEB}/4/Environment/7", ace(CONTRIB, bit("ReleaseManagement", "ManageReleases")))],
    "ns-endpoints": [acl(f"endpoints/{WEB}/e-wif", ace(GHOST, bit("ServiceEndpoints", "Administer")))],
    "ns-environment": [acl(f"Environments/{WEB}/3", ace(CONTRIB, bit("Environment", "Use")))],
    "ns-library": [acl(f"Library/{WEB}/VariableGroup/1", ace(CONTRIB, bit("Library", "View")))],
    "ns-audit": [acl("AllPermissions", ace(PCA, 15))],
}


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


def identities(params):
    rows = []
    for descriptor in params["descriptors"].split(","):
        if descriptor in IDENTITIES:
            name, subject, group = IDENTITIES[descriptor]
            rows.append({"id": f"id-{subject}", "descriptor": descriptor, "subjectDescriptor": subject,
                         "providerDisplayName": name, "isContainer": group, "isActive": True,
                         "properties": {"SchemaClassName": {"$type": "System.String",
                                                            "$value": "Group" if group else "User"}}})
    return Resp(body={"count": len(rows), "value": rows})


class FakeADO:
    """Routes by host and path; a route is a Resp or a callable taking the query parameters."""

    def __init__(self):
        self.calls = []
        self.routes = {
            ("dev.azure.com", "/contoso/_apis/connectionData"): Resp(body={"authenticatedUser": {
                "id": "u0", "providerDisplayName": "Evidence Reader",
                "properties": {"Account": {"$type": "System.String", "$value": "reader@example.com"}}}}),
            ("dev.azure.com", "/contoso/_apis/projects"): Resp(body={"value": [
                {"id": WEB, "name": "Web"}, {"id": OPS, "name": "Ops"}]}),
            ("dev.azure.com", "/contoso/_apis/securitynamespaces"): Resp(body={"count": len(NAMESPACES), "value": [
                {"namespaceId": i, "name": n, "displayName": n, "actions": a} for i, n, a in NAMESPACES]}),
            ("vssps.dev.azure.com", "/contoso/_apis/identities"): identities,
        }
        for namespace_id, entries in ACLS.items():
            self.routes[("dev.azure.com", f"/contoso/_apis/accesscontrollists/{namespace_id}")] = \
                Resp(body={"count": len(entries), "value": entries})

    def request(self, method, url, headers=None, params=None, timeout=None, allow_redirects=True, json=None):
        params = dict(params or {})
        parts = urlsplit(url)
        key = (parts.netloc, parts.path)
        self.calls.append((method, parts.netloc, parts.path, params))
        route = self.routes.get(key)
        if route is None:
            raise AssertionError(f"unexpected request {method} {key} {params}")
        return route(params) if callable(route) else route


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    monkeypatch.delenv("AZURE_DEVOPS_PROJECTS", raising=False)
    monkeypatch.setenv("AZURE_DEVOPS_ORG_URL", ORG)
    monkeypatch.setenv("AZURE_DEVOPS_PAT", "pat")
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.setattr(dr.time, "sleep", lambda s: None)


def run(tmp_path, fake=None):
    fake = fake or FakeADO()
    code = dr.run_org(fetcher=mod.NAME, logger=mod.logger, collect=mod.collect, session=fake)
    evidence = json.loads((tmp_path / "azure_devops_permissions_contoso.json").read_text())
    status = tmp_path / "status.json"
    return code, evidence, json.loads(status.read_text()) if status.exists() else None, fake


def entry(evidence, namespace, token, who):
    return next(e for e in evidence["results"]["entries"] if e["namespace"] == namespace and e["token"] == token
                and (e["identity"] or {}).get("descriptor") == who)


def test_collects_the_organization_and_exits_zero(tmp_path):
    code, evidence, status, _ = run(tmp_path)
    assert code == 0 and status is None
    s = evidence["summary"]
    assert s["namespaces_collected"] == 10 and s["namespaces_not_found"] == ["versioncontrolprivileges"]
    assert s["acls_total"] == 13 and s["acls_with_inheritance_off"] == 1
    assert s["entries_total"] == 15  # the empty ACE is left out
    assert s["entries_by_scope"] == {"branch": 1, "environment": 1, "organization": 3, "pipeline": 2, "project": 3,
                                     "release_stage": 1, "repository": 2, "service_connection": 1,
                                     "variable_group": 1}
    assert s["entries_with_deny"] == 1
    assert s["identities_with_explicit_entries"] == 7 and s["unresolved_identities"] == 1
    assert s["users_with_direct_entries"] == ["Alice"]
    assert s["high_impact_grants_outside_admin_groups"] == 5
    assert s["identities_with_high_impact_rights_outside_admin_groups"] == [
        "Alice", "deploy-automation", GHOST, "Project Collection Build Service (contoso)"]
    assert s["high_impact_rights_outside_admin_groups_by_right"] == {
        "Build: EditBuildDefinition": 1, "Collection: GENERIC_WRITE": 1, "Git Repositories: PolicyExempt": 1,
        "ServiceEndpoints: Administer": 1, "VersionControlItems: CheckinOther": 1}
    assert s["branch_policy_bypass_holders"] == ["Alice"]


def test_scopes_by_namespace(tmp_path):
    _, evidence, _, _ = run(tmp_path)
    scopes = sorted({(e["namespace"], e["token"], e["scope"], e["project"], e["resource"])
                     for e in evidence["results"]["entries"]}, key=str)
    assert scopes == sorted([
        ("AuditLog", "AllPermissions", "organization", None, None),
        ("Build", f"{WEB}/12", "pipeline", "Web", "12"),
        ("Collection", "NAMESPACE:", "organization", None, None),
        ("Environment", f"Environments/{WEB}/3", "environment", "Web", "3"),
        ("Git Repositories", f"repoV2/{OPS}/r-ops", "repository", "Ops", "r-ops"),
        ("Git Repositories", f"repoV2/{WEB}/r-web", "repository", "Web", "r-web"),
        ("Git Repositories", f"repoV2/{WEB}/r-web/refs/heads/6d00610069006e00", "branch", "Web",
         "r-web/refs/heads/6d00610069006e00"),
        ("Library", f"Library/{WEB}/VariableGroup/1", "variable_group", "Web", "1"),
        ("Project", f"$PROJECT:vstfs:///Classification/TeamProject/{WEB}", "project", "Web", None),
        ("ReleaseManagement", f"{WEB}/4", "pipeline", "Web", "4"),
        ("ReleaseManagement", f"{WEB}/4/Environment/7", "release_stage", "Web", "4/Environment/7"),
        ("ServiceEndpoints", f"endpoints/{WEB}/e-wif", "service_connection", "Web", "e-wif"),
        ("VersionControlItems", "$/Web", "project", "Web", None),
    ], key=str)


def test_an_entry_decodes_allow_deny_and_extended_info(tmp_path):
    _, evidence, _, _ = run(tmp_path)
    contrib = entry(evidence, "Project", f"$PROJECT:vstfs:///Classification/TeamProject/{WEB}", CONTRIB)
    assert contrib["allow"] == ["GENERIC_READ"] and contrib["deny"] == ["DELETE"]
    assert contrib["effective_deny"] == ["DELETE"] and contrib["project"] == "Web"
    assert contrib["identity"]["kind"] == "group" and contrib["identity"]["admin_group"] is False
    assert contrib["high_impact_allowed"] == []
    wpa = entry(evidence, "Project", f"$PROJECT:vstfs:///Classification/TeamProject/{WEB}", WPA)
    assert wpa["high_impact_allowed"] == ["DELETE", "GENERIC_WRITE"]
    assert wpa["identity"]["admin_group"] is True and wpa["high_impact_outside_admin_groups"] is False


def test_high_impact_rights_outside_admin_groups(tmp_path):
    _, evidence, _, _ = run(tmp_path)
    bypass = entry(evidence, "Git Repositories", f"repoV2/{WEB}/r-web/refs/heads/6d00610069006e00", ALICE)
    assert bypass["scope"] == "branch" and bypass["resource"] == "r-web/refs/heads/6d00610069006e00"
    assert bypass["inherit_permissions"] is False
    assert bypass["high_impact_outside_admin_groups"] is True and bypass["identity"]["kind"] == "user"
    tfvc = entry(evidence, "VersionControlItems", "$/Web", BUILDSVC)
    assert tfvc["scope"] == "project" and tfvc["project"] == "Web"
    assert tfvc["identity"]["kind"] == "service_identity" and tfvc["high_impact_allowed"] == ["CheckinOther"]
    ghost = entry(evidence, "ServiceEndpoints", f"endpoints/{WEB}/e-wif", GHOST)
    assert ghost["identity"]["resolved"] is False and ghost["identity"]["name"] is None
    assert ghost["scope"] == "service_connection" and ghost["resource"] == "e-wif"


def test_acls_are_read_recursively_with_extended_info(tmp_path):
    _, _, _, fake = run(tmp_path)
    reads = [(path, p) for _, _, path, p in fake.calls if "/accesscontrollists/" in path]
    assert len(reads) == 10 and not any(path.endswith("ns-wiq") for path, _ in reads)
    assert all(p["includeExtendedInfo"] == "true" and p["recurse"] == "true" and "token" not in p
               for _, p in reads)


def test_identities_are_resolved_in_batches(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "IDENTITY_BATCH", 3)
    _, evidence, _, fake = run(tmp_path)
    batches = [p["descriptors"].split(",") for _, _, path, p in fake.calls if path.endswith("/_apis/identities")]
    assert [len(b) for b in batches] == [3, 3, 1]
    assert all(p["queryMembership"] == "None" for _, _, path, p in fake.calls if path.endswith("/_apis/identities"))
    assert evidence["summary"]["unresolved_identities"] == 1


def test_a_project_filter_drops_other_projects_entries(tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_DEVOPS_PROJECTS", "Web")
    _, evidence, _, _ = run(tmp_path)
    assert not any(e["project_id"] == OPS for e in evidence["results"]["entries"])
    assert evidence["summary"]["entries_total"] == 14


def test_refused_acls_name_the_scope_and_keep_the_rest(tmp_path):
    fake = FakeADO()
    fake.routes[("dev.azure.com", "/contoso/_apis/accesscontrollists/ns-git")] = err(
        401, "TF400813: The user 'x' is not authorized to access this resource.", "UnauthorizedRequestException")
    code, evidence, status, _ = run(tmp_path, fake)
    assert code == 1 and status["code"] == "auth_failed"
    failure = evidence["metadata"]["api_failures"][0]
    assert failure["operation"] == "accesscontrollists.query(Git Repositories)"
    assert "PAT scope needed: Security (Manage)" in failure["message"]
    git = next(n for n in evidence["results"]["namespaces"] if n["name"] == "Git Repositories")
    assert git["acls_read"] is False and git["acls"] is None
    assert evidence["summary"]["namespaces_collected"] == 9 and evidence["summary"]["branch_policy_bypass_holders"] == []


def test_refused_identity_lookup_leaves_descriptors_unresolved(tmp_path):
    fake = FakeADO()
    fake.routes[("vssps.dev.azure.com", "/contoso/_apis/identities")] = err(401, "TF400813: not authorized.")
    code, evidence, status, _ = run(tmp_path, fake)
    assert code == 1 and "PAT scope needed: Identity (Read)" in evidence["metadata"]["api_failures"][0]["message"]
    assert evidence["summary"]["unresolved_identities"] == 7
    pca = entry(evidence, "AuditLog", "AllPermissions", PCA)
    assert pca["identity"]["kind"] == "group" and pca["identity"]["admin_group"] is False


def test_as_an_entra_identity_a_refusal_names_the_missing_permission(tmp_path, monkeypatch):
    monkeypatch.delenv("AZURE_DEVOPS_PAT")
    monkeypatch.setattr(dr, "entra_credential", lambda: SimpleNamespace(
        get_token=lambda scope: SimpleNamespace(token="t", expires_on=NOW.timestamp() + 3600)))
    fake = FakeADO()
    fake.routes[("dev.azure.com", "/contoso/_apis/securitynamespaces")] = err(403, "TF400813: no.")
    code, evidence, _, _ = run(tmp_path, fake)
    assert code == 1 and evidence["metadata"]["auth_mode"] == "entra"
    assert "Entra identity lacks permission" in evidence["metadata"]["api_failures"][0]["message"]
    assert evidence["summary"]["namespaces_not_found"] == []


def test_a_missing_organization_is_bad_config(tmp_path):
    fake = FakeADO()
    fake.routes[("dev.azure.com", "/contoso/_apis/projects")] = Resp(404, {"message": "The resource cannot be found."})
    code, _, status, _ = run(tmp_path, fake)
    assert code == 1 and "not found" in status["error"]


@pytest.mark.parametrize("namespace,token,expected", [
    ("collection", "NAMESPACE:", ("organization", None, None)),
    ("project", f"$PROJECT:vstfs:///Classification/TeamProject/{WEB}:", ("project", WEB, None)),
    ("git repositories", "repoV2", ("organization", None, None)),
    ("git repositories", f"repoV2/{WEB}", ("project", WEB, None)),
    ("versioncontrolitems", "$", ("organization", None, None)),
    ("versioncontrolitems", "$/Web/Main/src", ("path", WEB, "$/Web/Main/src")),
    ("build", f"{WEB}/Infra/Prod/12", ("pipeline", WEB, "Infra/Prod/12")),
    ("build", f"{WEB}/Infra", ("folder", WEB, "Infra")),
    ("serviceendpoints", "endpoints/Collection", ("organization", None, None)),
    ("serviceendpoints", "endpoints/Collection/e1", ("service_connection", None, "e1")),
    ("serviceendpoints", f"endpoints/{WEB}", ("project", WEB, None)),
    ("environment", f"Environments/{WEB}", ("project", WEB, None)),
    ("library", f"Library/{WEB}/SecureFile/f1", ("secure_file", WEB, "f1")),
    ("library", f"Library/{WEB}", ("project", WEB, None)),
    ("auditlog", "AllPermissions", ("organization", None, None)),
])
def test_parse_token(namespace, token, expected):
    assert mod.parse_token(namespace, token, {"web": WEB}) == expected


def test_bits_names_known_actions_and_keeps_unknown_bits():
    acts = [{"bit": 1, "name": "Read"}, {"bit": 4, "name": "Write"}]
    assert mod.bits(1 | 4 | 64, acts) == ["Read", "Write", "64"]
    assert mod.bits(None, acts) == [] and mod.bits(0, acts) == []


def test_an_evidence_sample_keeps_every_not_collected_entry():
    from framework import samples
    assert samples.trim({"not_collected": dict(mod.NOT_COLLECTED)})["not_collected"] == mod.NOT_COLLECTED
