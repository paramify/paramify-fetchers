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
# The form kiota's APIError takes: "<message> (status <code>)".
DENIED = Exception("Insufficient privileges to complete the operation. (status 403)")
SERVER_ERROR = Exception("Service unavailable (status 500)")


def _group(gid, name, types=(), security=True, mail=False, role=False, rule=None, state=None,
           synced=None, visibility=None):
    return ns(id=gid, display_name=name, description=None, group_types=list(types),
              security_enabled=security, mail_enabled=mail, is_assignable_to_role=role,
              membership_rule=rule, membership_rule_processing_state=state,
              on_premises_sync_enabled=synced, visibility=visibility,
              created_date_time="2026-01-01T00:00:00Z")


def _user(uid, guest=False, enabled=True, limited=False, user_type="unset"):
    if limited:
        return ns(id=uid, odata_type="#microsoft.graph.user")
    if user_type == "unset":
        user_type = "Guest" if guest else "Member"
    return ns(id=uid, odata_type="#microsoft.graph.user", display_name=f"User {uid}",
              user_principal_name=f"{uid}@contoso.test", account_enabled=enabled, user_type=user_type)


def _sp(sid):
    return ns(id=sid, odata_type="#microsoft.graph.servicePrincipal", display_name=f"App {sid}",
              user_principal_name=None, account_enabled=True, user_type=None)


def _nested(gid):
    return ns(id=gid, odata_type="#microsoft.graph.group", display_name=f"Group {gid}",
              user_principal_name=None, account_enabled=None, user_type=None)


class Builder:
    """One Graph collection, served `page_size` items a page; `error` raises on `fail_on_page` (or every call)."""

    def __init__(self, items=None, error=None, page_size=None, fail_on_page=None):
        self.items, self.error, self.calls, self.urls = list(items or []), error, 0, []
        self.page_size, self.fail_on_page, self.page = page_size, fail_on_page, 0

    async def get(self, request_configuration=None):
        self.calls += 1
        if self.error is not None and self.fail_on_page in (None, self.page):
            raise self.error
        size = self.page_size or max(len(self.items), 1)
        start, self.page = self.page * size, self.page + 1
        more = start + size < len(self.items)
        return ns(value=self.items[start:start + size], odata_next_link="next-page" if more else None)

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
        self.last = None

        class Groups:
            async def get(self, request_configuration=None):
                expand = request_configuration.query_parameters.expand[0]
                graph.last = graph.member_expansion if expand.startswith("members") else graph.owner_expansion
                return await graph.last.get(request_configuration)

            def with_url(self, url):
                return graph.last

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
    assert s["groups_readable"] is s["members_readable"] is s["member_details_readable"] is True
    assert s["owners_readable"] is s["owner_details_readable"] is True
    assert (s["security_groups"], s["microsoft_365_groups"], s["distribution_groups"]) == (4, 1, 1)
    assert s["role_assignable_groups"] == 1
    assert s["role_assignable_groups_without_owner"] == 1
    assert s["role_assignable_groups_with_guest_members"] == 1
    assert s["users_in_role_assignable_groups"] == 2
    assert (s["dynamic_groups"], s["dynamic_groups_paused"], s["assigned_groups"]) == (1, 1, 5)
    assert (s["synced_groups"], s["cloud_groups"]) == (1, 5)
    assert s["hidden_membership_groups_unread"] == 0
    # Graph returns no owners for the synced group or the distribution list, so neither counts.
    assert s["groups_with_owners_not_in_graph"] == 2
    assert s["groups_without_owner"] == 2
    assert s["cloud_groups_without_owner"] == 2
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
    assert by_id["g-sync"]["owners_in_graph"] is False and by_id["g-sync"]["has_owner"] is None
    assert by_id["g-dl"]["owners"] is None


def test_every_page_of_the_group_list_is_read(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.member_expansion.page_size = graph.owner_expansion.page_size = 2
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)

    assert code == 0
    assert graph.member_expansion.calls == 3 and graph.owner_expansion.calls == 3
    assert evidence["summary"]["total_groups"] == 6
    assert evidence["summary"]["groups_with_only_disabled_owners"] == 1


def test_a_group_list_failing_part_way_nulls_every_count(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.member_expansion.page_size = 2
    graph.member_expansion.error, graph.member_expansion.fail_on_page = DENIED, 1
    code, evidence, status = _run(monkeypatch, tmp_path, graph)

    assert code == 1
    assert status["code"] == "not_authorized"
    s = evidence["summary"]
    assert s["groups_readable"] is False and s["members_readable"] is False
    assert s["total_groups"] is None and s["security_groups"] is None and s["dynamic_groups"] is None
    assert s["groups_without_owner"] is None
    assert len(evidence["results"]["groups"]) == 2


def test_a_failed_member_reread_nulls_the_member_figures(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["members"]["g-dyn"] = [_user(f"u-{i}") for i in range(25)]
    graph = FakeGraph(**tenant)
    graph.member_items["g-dyn"].error = SERVER_ERROR
    code, evidence, status = _run(monkeypatch, tmp_path, graph)

    assert code == 1
    assert status["code"] == "partial_failure"
    s = evidence["summary"]
    assert s["groups_readable"] is True and s["total_groups"] == 6
    assert s["members_readable"] is False
    assert s["empty_groups"] is None and s["groups_with_guest_members"] is None


def test_owners_past_the_expand_limit_are_reread_from_beta(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["owners"]["g-m365"] = [_user(f"o-{i}") for i in range(24)] + [_sp("sp-owner")]
    graph = FakeGraph(**tenant)
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)

    assert code == 0
    builder = graph.owner_items["g-m365"]
    assert builder.calls == 1
    assert builder.urls[0].startswith("https://graph.microsoft.com/beta/groups/g-m365/owners?")
    owners = {g["id"]: g for g in evidence["results"]["groups"]}["g-m365"]["owners"]
    assert len(owners) == 25 and any(o["principal_type"] == "ServicePrincipal" for o in owners)


def test_hidden_membership_without_visible_members_reads_unknown(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["group_models"].append(
        _group("g-hidden", "Board", types=["Unified"], mail=True, visibility="HiddenMembership")
    )
    code, evidence, _ = _run(monkeypatch, tmp_path, FakeGraph(**tenant))

    assert code == 0
    s = evidence["summary"]
    assert s["hidden_membership_groups"] == 1 and s["hidden_membership_groups_unread"] == 1
    assert s["empty_groups"] == 1
    assert s["member_details_readable"] is True
    hidden = {g["id"]: g for g in evidence["results"]["groups"]}["g-hidden"]
    assert hidden["members"] is None and hidden["member_count"] is None and hidden["hidden_members_unread"] is True


def test_owners_read_without_user_read_all_leave_the_disabled_owner_figure_null(monkeypatch, tmp_path):
    tenant = _tenant()
    tenant["owners"]["g-mixed"] = [_user("u-off", limited=True)]
    code, evidence, _ = _run(monkeypatch, tmp_path, FakeGraph(**tenant))

    assert code == 0
    s = evidence["summary"]
    assert s["owner_details_readable"] is False
    assert s["groups_with_only_disabled_owners"] is None
    assert s["groups_without_owner"] == 2
    assert {g["id"]: g for g in evidence["results"]["groups"]}["g-mixed"]["has_enabled_owner"] is None


def test_one_user_missing_its_type_or_state_nulls_the_guest_and_disabled_figures_tenant_wide(monkeypatch, tmp_path):
    for partial in (_user("u-1", user_type=None), _user("u-1", enabled=None)):
        tenant = _tenant()
        tenant["members"]["g-admins"] = [partial, _user("u-guest", guest=True)]
        _, evidence, _ = _run(monkeypatch, tmp_path, FakeGraph(**tenant))
        s = evidence["summary"]
        assert s["member_details_readable"] is False
        assert s["groups_with_guest_members"] is None
        assert s["role_assignable_groups_with_guest_members"] is None
        # g-dyn's disabled member came back in full, but the tenant figure still reads null.
        assert s["groups_with_disabled_user_members"] is None
        assert s["total_direct_memberships"] == 9


def test_a_service_principal_owner_returned_as_an_id_only_leaves_the_disabled_owner_figure_null(
    monkeypatch, tmp_path
):
    tenant = _tenant()
    tenant["owners"]["g-mixed"] = [
        _user("u-off", enabled=False), ns(id="sp-x", odata_type="#microsoft.graph.servicePrincipal"),
    ]
    code, evidence, _ = _run(monkeypatch, tmp_path, FakeGraph(**tenant))

    assert code == 0
    s = evidence["summary"]
    assert s["owners_readable"] is True and s["owner_details_readable"] is False
    assert s["groups_with_only_disabled_owners"] is None
    mixed = {g["id"]: g for g in evidence["results"]["groups"]}["g-mixed"]
    assert mixed["owner_count"] == 2 and mixed["has_enabled_owner"] is None
    assert {o["principal_type"] for o in mixed["owners"]} == {"User", "ServicePrincipal"}


def test_a_group_missing_from_the_owner_pass_is_unknown_not_ownerless(monkeypatch, tmp_path):
    graph = FakeGraph(**_tenant())
    graph.owner_expansion.items = [g for g in graph.owner_expansion.items if g.id != "g-admins"]
    code, evidence, _ = _run(monkeypatch, tmp_path, graph)

    assert code == 0
    s = evidence["summary"]
    assert s["role_assignable_groups_without_owner"] == 0
    assert s["groups_without_owner"] == 1
    assert {g["id"]: g for g in evidence["results"]["groups"]}["g-admins"]["has_owner"] is None


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
    assert evidence["summary"]["groups_readable"] is False
    assert evidence["summary"]["total_groups"] is None
    assert evidence["summary"]["security_groups"] is None
    assert evidence["summary"]["members_readable"] is False
    assert evidence["summary"]["owners_readable"] is False
    assert evidence["summary"]["groups_without_owner"] is None
    assert graph.owner_expansion.calls == 0
