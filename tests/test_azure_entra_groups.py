"""azure_entra_groups: members, owners and how membership is managed.

Synthetic Graph models only: no SDK, no credentials, no network.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from types import SimpleNamespace as ns

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "azure" / "entra_groups" / "fetcher.py"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))

spec = importlib.util.spec_from_file_location("azure_entra_groups_under_test", FETCHER)
groups = importlib.util.module_from_spec(spec)
spec.loader.exec_module(groups)

TENANT = "00000000-0000-0000-0000-0000000000aa"
DENIED = Exception("Insufficient privileges to complete the operation. (403)")


def _group(gid, name, types=(), security=True, mail=False, role=False, rule=None, state=None,
           synced=None, visibility=None):
    return ns(id=gid, display_name=name, description=None, group_types=list(types),
              security_enabled=security, mail_enabled=mail, is_assignable_to_role=role,
              membership_rule=rule, membership_rule_processing_state=state,
              on_premises_sync_enabled=synced, visibility=visibility,
              created_date_time="2026-01-01T00:00:00Z")


def _user(uid, guest=False, enabled=True, limited=False):
    if limited:
        return ns(id=uid, odata_type="#microsoft.graph.user")
    return ns(id=uid, odata_type="#microsoft.graph.user", display_name=f"User {uid}",
              user_principal_name=f"{uid}@contoso.test", account_enabled=enabled,
              user_type="Guest" if guest else "Member")


def _sp(sid):
    return ns(id=sid, odata_type="#microsoft.graph.servicePrincipal", display_name=f"App {sid}",
              user_principal_name=None, account_enabled=True, user_type=None)


def _nested(gid):
    return ns(id=gid, odata_type="#microsoft.graph.group", display_name=f"Group {gid}",
              user_principal_name=None, account_enabled=None, user_type=None)


class Builder:
    def __init__(self, items=None, error=None):
        self.items, self.error, self.calls, self.urls = list(items or []), error, 0, []

    async def get(self, request_configuration=None):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return ns(value=self.items, odata_next_link=None)

    def with_url(self, url):
        self.urls.append(url)
        return self


class FakeGraph:
    def __init__(self, group_models, members=None, owners=None):
        members, owners = members or {}, owners or {}
        self.organization = Builder([ns(id=TENANT, display_name="Contoso", verified_domains=[])])
        self.member_expansion = Builder(
            [ns(**vars(g), members=members.get(g.id, [])[:20]) for g in group_models]
        )
        self.owner_expansion = Builder([ns(id=g.id, owners=owners.get(g.id, [])[:20]) for g in group_models])
        self.member_items = {gid: Builder(items) for gid, items in members.items()}
        self.owner_items = {gid: Builder(items) for gid, items in owners.items()}

        graph = self

        class Groups:
            async def get(self, request_configuration=None):
                expand = request_configuration.query_parameters.expand[0]
                builder = graph.member_expansion if expand.startswith("members") else graph.owner_expansion
                return await builder.get(request_configuration)

            def by_group_id(self, gid):
                return ns(members=graph.member_items.get(gid, Builder()),
                          owners=graph.owner_items.get(gid, Builder()))

        self.groups = Groups()


class Query:
    def __init__(self, select=None, expand=None):
        self.select, self.expand = select, expand


def _stub_msgraph(monkeypatch):
    for module_name, cls in {
        "msgraph.generated.groups.groups_request_builder": "GroupsRequestBuilder",
        "msgraph.generated.groups.item.owners.owners_request_builder": "OwnersRequestBuilder",
    }.items():
        module = ModuleType(module_name)
        setattr(module, cls, type(cls, (), {f"{cls}GetQueryParameters": Query}))
        monkeypatch.setitem(sys.modules, module_name, module)
    config = ModuleType("kiota_abstractions.base_request_configuration")
    config.RequestConfiguration = lambda query_parameters=None: ns(query_parameters=query_parameters)
    monkeypatch.setitem(sys.modules, "kiota_abstractions.base_request_configuration", config)


def _run(monkeypatch, tmp_path, graph):
    async def fake_with_graph_client(collector, cred, work, default=None):
        return await work(graph)

    _stub_msgraph(monkeypatch)
    monkeypatch.setattr(groups, "with_graph_client", fake_with_graph_client)
    monkeypatch.setattr(groups, "credential", lambda: object())
    monkeypatch.setattr(groups, "load_dotenv", lambda: None)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("AZURE_TENANT_ID", TENANT)
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    status = tmp_path / "status.json"
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(status))
    code = groups.main()
    evidence = json.loads((tmp_path / f"azure_entra_groups_{TENANT}.json").read_text())
    return code, evidence, (json.loads(status.read_text()) if status.exists() else None)


def _tenant():
    """A role-assignable group with a guest and no owner, a paused dynamic group, a synced
    group, a Microsoft 365 group with an owner, an empty distribution list, and a group
    holding a nested group and a service principal."""
    group_models = [
        _group("g-admins", "Tenant admins", role=True),
        _group("g-dyn", "All staff", types=["DynamicMembership"], rule='user.accountEnabled -eq true',
               state="Paused"),
        _group("g-sync", "On-prem finance", synced=True),
        _group("g-m365", "Project team", types=["Unified"], mail=True),
        _group("g-dl", "Announcements", security=False, mail=True),
        _group("g-mixed", "Automation", ),
    ]
    return dict(
        group_models=group_models,
        members={
            "g-admins": [_user("u-1"), _user("u-guest", guest=True)],
            "g-dyn": [_user("u-1"), _user("u-2"), _user("u-off", enabled=False)],
            "g-sync": [_user("u-2")],
            "g-m365": [_user("u-1")],
            "g-mixed": [_nested("g-m365"), _sp("sp-1")],
        },
        owners={"g-m365": [_user("u-1")], "g-mixed": [_user("u-off", enabled=False)]},
    )


def test_groups_members_owners_and_membership_kinds(monkeypatch, tmp_path):
    code, evidence, _ = _run(monkeypatch, tmp_path, FakeGraph(**_tenant()))

    assert code == 0
    s = evidence["summary"]
    assert s["total_groups"] == 6
    assert s["members_readable"] is s["member_details_readable"] is s["owners_readable"] is True
    assert (s["security_groups"], s["microsoft_365_groups"], s["distribution_groups"]) == (4, 1, 1)
    assert s["role_assignable_groups"] == 1
    assert s["role_assignable_groups_without_owner"] == 1
    assert s["role_assignable_groups_with_guest_members"] == 1
    assert s["users_in_role_assignable_groups"] == 2
    assert (s["dynamic_groups"], s["dynamic_groups_paused"], s["assigned_groups"]) == (1, 1, 5)
    assert (s["synced_groups"], s["cloud_groups"]) == (1, 5)
    assert s["groups_without_owner"] == 4
    assert s["cloud_groups_without_owner"] == 3
    assert s["groups_with_only_disabled_owners"] == 1
    assert s["empty_groups"] == 1
    assert s["total_direct_memberships"] == 9
    assert s["groups_with_guest_members"] == 1
    assert s["groups_with_disabled_user_members"] == 1
    assert s["groups_with_nested_groups"] == 1
    assert s["groups_with_service_principal_members"] == 1

    by_id = {g["id"]: g for g in evidence["results"]["groups"]}
    dyn = by_id["g-dyn"]
    assert dyn["membership_type"] == "dynamic" and dyn["dynamic_rule_paused"] is True
    assert dyn["membership_rule"] == "user.accountEnabled -eq true"
    assert by_id["g-m365"]["kind"] == "microsoft_365"
    assert by_id["g-mixed"]["service_principal_member_count"] == 1
    assert by_id["g-mixed"]["has_owner"] is True and by_id["g-mixed"]["has_enabled_owner"] is False
    assert by_id["g-admins"]["guest_member_count"] == 1


def test_members_past_the_expand_limit_are_reread_from_beta(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["members"]["g-dyn"] = [_user(f"u-{i}") for i in range(30)] + [_sp("sp-1")]
    graph = FakeGraph(**tenant)
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)

    assert code == 0
    builder = graph.member_items["g-dyn"]
    assert builder.calls == 1
    assert builder.urls[0].startswith("https://graph.microsoft.com/beta/groups/g-dyn/members?")
    by_id = {g["id"]: g for g in evidence["results"]["groups"]}
    assert by_id["g-dyn"]["member_count"] == 31
    assert by_id["g-dyn"]["service_principal_member_count"] == 1


def test_users_read_without_user_read_all_leave_guest_figures_null(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["members"]["g-admins"] = [_user("u-1", limited=True)]
    code, evidence, _ = _run(monkeypatch, tmp_path, FakeGraph(**tenant))

    assert code == 0
    s = evidence["summary"]
    assert s["member_details_readable"] is False
    assert s["groups_with_guest_members"] is None
    assert s["role_assignable_groups_with_guest_members"] is None
    assert s["groups_with_nested_groups"] == 1


def test_denied_owner_read_fails_the_run_with_null_owner_figures(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.owner_expansion.error = DENIED
    code, evidence, status = _run(monkeypatch, tmp_path, graph)

    assert code == 1
    assert status["code"] == "not_authorized"
    s = evidence["summary"]
    assert s["owners_readable"] is False
    assert s["groups_without_owner"] is None
    assert s["role_assignable_groups_without_owner"] is None
    assert s["empty_groups"] == 1
    assert all(g["has_owner"] is None for g in evidence["results"]["groups"])


def test_denied_group_read_fails_the_run(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.member_expansion.error = DENIED
    code, evidence, status = _run(monkeypatch, tmp_path, graph)

    assert code == 1
    assert status["code"] == "not_authorized"
    assert evidence["summary"]["total_groups"] == 0
    assert evidence["summary"]["members_readable"] is False
    assert evidence["summary"]["owners_readable"] is False
    assert evidence["summary"]["groups_without_owner"] is None
    assert graph.owner_expansion.calls == 0
