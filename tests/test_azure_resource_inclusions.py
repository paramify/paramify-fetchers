"""Azure resource inclusions: the tag: matcher, the tag index, inclusions against exclusions, and fail-closed scope."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))

import resource_exclusions  # noqa: E402
from azure_common import Collector, classify_failure_code  # noqa: E402
from resource_exclusions import (  # noqa: E402
    ENV,
    INCLUSIONS_ENV,
    NOT_INCLUDED,
    SCOPE_UNKNOWN,
    ResourceExclusions,
    ResourceScope,
)
from scope_exclusions import excluded_item, parse_patterns  # noqa: E402
from tag_index import TagIndex, _lookup_keys  # noqa: E402

SUB_ID = "00000000-0000-0000-0000-000000000000"
SUB = f"/subscriptions/{SUB_ID}"
RG = f"{SUB}/resourceGroups/rg-app"
VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-contoso"
KEY = f"{VAULT}/keys/key-1"
SERVER = f"{RG}/providers/Microsoft.Sql/servers/sql-contoso"
DATABASE = f"{SERVER}/databases/db-1"
ACCOUNT = f"{RG}/providers/Microsoft.Storage/storageAccounts/stcontoso"
CONTAINER = f"{ACCOUNT}/blobServices/default/containers/logs"
SETTING = f"{ACCOUNT}/providers/Microsoft.Insights/diagnosticSettings/to-workspace"
UNTAGGED_VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-example"

TAGS = {
    SUB.lower(): {},
    RG.lower(): {"boundary": "FedRAMP"},
    VAULT.lower(): {"boundary": "FedRAMP", "cost center": "Shared, Prod"},
    SERVER.lower(): {"boundary": "fedramp"},
    DATABASE.lower(): {},
    ACCOUNT.lower(): {"boundary": "FedRAMP"},
    UNTAGGED_VAULT.lower(): {},
}


def entries(tags):
    return {k: v if isinstance(v, tuple) else (v, None) for k, v in tags.items()}


def scope(exclusions=(), inclusions=(), tags=None, loader=None):
    held = TAGS if tags is None else tags
    read = loader or (lambda sub: held)
    return ResourceScope(exclusions, inclusions, index=TagIndex(lambda sub: entries(read(sub))))


@pytest.mark.parametrize("pattern, tags, matched", [
    ("tag:Boundary=FedRAMP", {"boundary": "FedRAMP"}, True),
    ("tag:BOUNDARY=fedramp", {"boundary": "FedRAMP"}, True),
    ("tag:Boundary=Fed*", {"boundary": "FedRAMP-High"}, True),
    ("tag:Boundary", {"boundary": ""}, True),
    ("tag:Boundary=", {"boundary": ""}, True),
    ("tag:Boundary=", {"boundary": "x"}, False),
    ("tag:Boundary=FedRAMP", {"environment": "FedRAMP"}, False),
    ("tag:Boundary=FedRAMP", {"boundary": "Commercial"}, False),
    ('tag:"Cost Center"="Shared, Prod"', {"cost center": "shared, prod"}, True),
    ('tag:"a=b"="c:d"', {"a=b": "c:d"}, True),
])
def test_tag_patterns_match_a_name_and_a_value_glob(pattern, tags, matched):
    rid = f"{RG}/providers/Microsoft.Web/sites/app"
    rules = scope(inclusions=[pattern], tags={rid.lower(): tags})
    assert (rules.match(rid) is None) is matched


def test_tag_values_can_compare_with_case(monkeypatch):
    monkeypatch.setattr(resource_exclusions, "TAG_VALUES_IGNORE_CASE", False)
    rid = f"{RG}/providers/Microsoft.Web/sites/app"
    assert scope(inclusions=["tag:Boundary=fedramp"], tags={rid.lower(): {"boundary": "FedRAMP"}}).match(rid) \
        is NOT_INCLUDED
    assert scope(inclusions=["tag:boundary=FedRAMP"], tags={rid.lower(): {"boundary": "FedRAMP"}}).match(rid) is None


@pytest.mark.parametrize("pattern", ["tag:", "tag:=FedRAMP", 'tag:"Boundary=FedRAMP', "boundary=FedRAMP", "label:x"])
def test_malformed_inclusions_are_invalid_and_fail_the_run(pattern):
    rules = ResourceScope([], [pattern])
    assert rules.invalid_inclusions() == [pattern]
    collector = Collector(logging.getLogger("test"))
    rules.record_invalid(collector)
    assert collector.failures[0]["operation"] == f"config {INCLUSIONS_ENV}"
    assert pattern in collector.failures[0]["message"]
    assert classify_failure_code(collector.failures) == "bad_config"


def test_only_a_resources_own_tags_count():
    rules = scope(inclusions=["tag:Boundary=FedRAMP"])
    assert rules.match(VAULT) is None
    assert rules.match(SERVER) is None
    assert rules.match(DATABASE) is NOT_INCLUDED  # its server and resource group are tagged, it isn't
    assert rules.match(UNTAGGED_VAULT) is NOT_INCLUDED  # its resource group is tagged, it isn't


def test_objects_that_cant_carry_tags_follow_the_resource_they_live_in():
    rules = scope(inclusions=["tag:Boundary=FedRAMP"])
    assert rules.match(KEY) is None
    assert rules.match(CONTAINER) is None
    assert rules.match(SETTING) is None
    assert rules.match(f"{UNTAGGED_VAULT}/secrets/s-1") is NOT_INCLUDED


def test_lookup_never_reaches_a_resource_group_or_subscription():
    assert _lookup_keys(KEY) == [KEY.lower(), VAULT.lower()]
    assert _lookup_keys(SETTING) == [SETTING.lower(), ACCOUNT.lower()]
    assert _lookup_keys(VAULT) == [VAULT.lower()]
    assert _lookup_keys(RG) == [RG.lower()]


def test_exclusions_win_over_inclusions_and_all_matches_count_as_used():
    rules = scope(["id:*/vaults/kv-contoso", "rg:nowhere"], ["tag:Boundary=FedRAMP", "tag:Owner"])
    assert rules.match(VAULT) == "id:*/vaults/kv-contoso"
    assert rules.match(ACCOUNT) is None
    assert rules.unmatched() == ["rg:nowhere"]
    assert rules.inclusions_unmatched() == ["tag:Owner"]


def test_tag_exclusions_take_out_what_is_tagged():
    rules = scope(["tag:Boundary=Commercial"])
    assert rules.match(VAULT) is None
    assert scope(["tag:Cost*"]).match(VAULT) is None  # a name is never a glob
    assert scope(['tag:"Cost Center"=Shared*']).match(KEY) == 'tag:"Cost Center"=Shared*'


def test_rg_id_and_location_inclusions_need_no_tags():
    def refuse(sub):
        raise AssertionError("the index must not be read")

    rules = ResourceScope([], ["rg:rg-app", "location:eastus"], index=TagIndex(refuse))
    assert rules.match(VAULT) is None
    assert rules.match(f"{SUB}/resourceGroups/rg-other/providers/x/y/z", "westus") is NOT_INCLUDED
    assert rules.match(f"{SUB}/resourceGroups/rg-other/providers/x/y/z", "East US") is None


def test_the_index_is_read_once_per_subscription_and_only_for_tag_patterns():
    reads = []

    def loader(sub):
        reads.append(sub)
        return TAGS

    rules = scope(inclusions=["tag:Boundary"], loader=loader)
    for rid in (VAULT, KEY, SERVER, DATABASE):
        rules.match(rid)
    assert reads == [SUB_ID]
    assert ResourceScope(["rg:x"], ["rg:y"]).uses_tags is False


def test_a_resource_the_index_doesnt_hold_falls_back_to_its_own_tags_else_is_kept_as_not_found():
    late = f"{RG}/providers/Microsoft.Web/sites/created-later"
    rules = scope(inclusions=["tag:Boundary=FedRAMP"])
    assert rules.match(late, tags={"Boundary": "FedRAMP"}) is None
    assert rules.match(late, tags=None) is NOT_INCLUDED
    collector = Collector(logging.getLogger("test"))
    rules.record_invalid(collector)
    # Deleted, or newer than the read: no own tags to judge, so it stays in scope and is counted.
    assert rules.match(late) is None
    items = [{"id": late, "name": "created-later"}, {"id": VAULT, "name": "kv-contoso"}]
    kept, excluded = rules.split(items, "site")
    assert [i["name"] for i in kept] == ["created-later", "kv-contoso"] and excluded == []
    summary = rules.summary(excluded, ("site",), {"sites": len(kept)})
    assert summary["scope_not_found_resources"] == 1 and "scope_unknown_sites" not in summary
    assert summary["not_included_sites"] == 0 and summary["in_scope_sites"] == 2
    assert collector.ok


def test_a_resource_not_found_is_only_kept_when_a_tag_pattern_couldnt_judge_it():
    gone = f"{SUB}/resourceGroups/rg-other/providers/Microsoft.Web/sites/deleted"
    # An rg: inclusion decides it without tags; a tag: exclusion it can't be judged by doesn't take it out.
    assert scope(["tag:Retired"], ["rg:rg-app"]).match(gone) is NOT_INCLUDED
    rules = scope(["tag:Retired", "rg:rg-other"], ["tag:Boundary"])
    assert rules.match(gone) == "rg:rg-other"
    rules = scope(["tag:Retired"])
    assert rules.match(gone) is None
    assert rules.summary([], ("site",), {"sites": 1})["scope_not_found_resources"] == 1
    assert "scope_not_found_resources" not in scope(["rg:x"], ["rg:y"]).summary([], ("site",), {"sites": 0})


def test_an_unreadable_index_fails_closed():
    def broken(sub):
        raise PermissionError("(AuthorizationFailed) (403) no read on Microsoft.ResourceGraph")

    rules = ResourceScope(["rg:rg-out"], ["tag:Boundary=FedRAMP"], index=TagIndex(broken))
    items = [{"id": VAULT, "name": "kv-contoso"}, {"id": f"{SUB}/resourceGroups/rg-out/providers/x/y/z", "name": "z"}]
    kept, excluded = rules.split(items, "vault")
    assert kept == []
    assert [e["reason"] for e in excluded] == ["scope_unknown", "resource_matched"]
    collector = Collector(logging.getLogger("test"))
    rules.record_invalid(collector)
    assert not collector.ok and "tags in subscription" in collector.failures[0]["operation"]
    assert classify_failure_code(collector.failures) == "not_authorized"
    summary = rules.summary(excluded, ("vault",), {"vaults": len(kept)})
    assert summary["in_scope_vaults"] is None
    assert summary["excluded_vaults"] is None and summary["not_included_vaults"] is None
    assert summary["scope_unknown_vaults"] is None
    assert summary["resource_exclusion_patterns_unmatched"] is None
    assert summary["resource_inclusion_patterns_unmatched"] is None


def test_a_resource_of_unknown_scope_fails_the_run_once_summarized():
    billing = "/providers/Microsoft.Billing/billingAccounts/ba-contoso"
    rules = scope(inclusions=["tag:Boundary=FedRAMP"])
    collector = Collector(logging.getLogger("test"))
    rules.record_invalid(collector)
    items = [{"id": billing, "name": "billing"}, {"id": None, "name": "no-id"}, {"id": VAULT, "name": "kv-contoso"}]
    kept, excluded = rules.split(items, "item")
    assert [i["name"] for i in kept] == ["kv-contoso"] and collector.ok
    assert rules.match(billing) is SCOPE_UNKNOWN  # asked twice, counted once
    summary = rules.summary(excluded, ("item",), {"items": len(kept)})
    assert summary["scope_unknown_items"] == 2 and summary["in_scope_items"] == 1
    [failure] = collector.failures
    assert failure["operation"] == "resource scope" and failure["message"].startswith("2 resources of unknown scope")
    assert classify_failure_code(collector.failures) == "partial_failure"
    rules.summary(excluded, ("item",), {"items": len(kept)})
    assert len(collector.failures) == 1


def test_a_summary_before_record_invalid_still_fails_the_run():
    rules = scope(inclusions=["tag:Boundary=FedRAMP"])
    assert rules.match("/providers/Microsoft.Billing/billingAccounts/ba-contoso") is SCOPE_UNKNOWN
    rules.summary([], ("site",), {"sites": 0})
    collector = Collector(logging.getLogger("test"))
    rules.record_invalid(collector)
    assert [f["operation"] for f in collector.failures] == ["resource scope"]


def test_no_tag_pattern_never_reports_an_unknown_scope():
    rules = ResourceScope(["rg:rg-out"], ["rg:rg-app", "location:eastus"], index=TagIndex(lambda sub: {}))
    collector = Collector(logging.getLogger("test"))
    rules.record_invalid(collector)
    items = [{"id": None, "name": "no-id"}, {"id": "/providers/Microsoft.Management/managementGroups/mg", "name": "mg"}]
    kept, excluded = rules.split(items, "item")
    rules.summary(excluded, ("item",), {"items": len(kept)})
    assert collector.ok and {e["reason"] for e in excluded} == {"not_included"}


@pytest.mark.parametrize("rows, read", [
    ([], False),
    ([{"id": "/subscriptions/other/resourcegroups/rg", "tags": None, "location": None}], False),
    ([{"id": SUB.lower(), "tags": None, "location": None},
      {"id": VAULT.lower(), "tags": '{"Boundary": "FedRAMP"}', "location": "eastus"}], True),
])
def test_resource_graph_must_return_the_subscriptions_own_row(monkeypatch, rows, read):
    import resource_graph
    import tag_index

    monkeypatch.setattr(tag_index, "_clients", [object()])
    monkeypatch.setattr(resource_graph, "query_all", lambda client, sub, query: {"rows": rows})
    index = TagIndex()
    assert (index.entries(SUB_ID) is not None) is read
    assert bool(index.failures) is not read
    if not read:
        assert "returned no row for subscription" in str(index.failures[0][1])
        rules = ResourceScope([], ["tag:Boundary=FedRAMP"], index=index)
        assert rules.match(RG) is SCOPE_UNKNOWN and rules.match(VAULT) is SCOPE_UNKNOWN
    else:
        assert index.tags_of(VAULT) == {"boundary": "FedRAMP"}


MG = "/providers/Microsoft.Management/managementGroups/mg-contoso"
RECORDS = {
    "subscription": f"{SUB}/providers/Microsoft.Authorization/policyAssignments/fedramp",
    "group": f"{RG}/providers/Microsoft.Authorization/locks/no-delete",
    "management group": f"{MG}/providers/Microsoft.Authorization/policyAssignments/fedramp",
    "root": "/providers/Microsoft.Authorization/roleAssignments/ra-1",
}
INCLUSION_KINDS = ["tag:Boundary=FedRAMP", "rg:rg-app", "id:*/vaults/kv-contoso", "location:eastus"]


@pytest.mark.parametrize("inclusion", INCLUSION_KINDS)
@pytest.mark.parametrize("record", sorted(RECORDS))
def test_a_record_on_a_container_holding_an_in_scope_resource_stays(inclusion, record):
    tags = {SUB.lower(): {}, RG.lower(): {}, VAULT.lower(): ({"boundary": "FedRAMP"}, "eastus")}
    rules = scope(inclusions=[inclusion], tags=tags)
    assert rules.match(RECORDS[record]) is None
    assert rules.match(SUB) is None and rules.match(RG) is None and rules.match(MG) is None


@pytest.mark.parametrize("inclusion", INCLUSION_KINDS)
def test_a_container_holding_nothing_in_scope_is_not_included(inclusion):
    other = f"{SUB}/resourceGroups/rg-other"
    tags = {SUB.lower(): {}, other.lower(): {}, f"{other}/providers/microsoft.keyvault/vaults/kv-example": ({}, "westus")}
    rules = scope(inclusions=[inclusion], tags=tags)
    assert rules.match(f"{other}/providers/Microsoft.Authorization/locks/no-delete") is NOT_INCLUDED
    assert rules.match(RECORDS["subscription"]) is NOT_INCLUDED
    # Above the subscription it reaches others this run can't see, so it stays.
    assert rules.match(RECORDS["management group"]) is None and rules.match(RECORDS["root"]) is None


def test_an_exclusion_still_takes_out_a_management_group_record():
    rules = scope(["id:*/policyAssignments/legacy"], ["tag:Boundary=FedRAMP"])
    assert rules.match(f"{MG}/providers/Microsoft.Authorization/policyAssignments/legacy") == \
        "id:*/policyAssignments/legacy"
    assert scope(["id:*/policyAssignments/legacy"]).match(RECORDS["management group"]) is None


def test_rg_inclusions_judge_a_group_without_reading_the_index():
    reads = []

    def loader(sub):
        reads.append(sub)
        return TAGS

    rules = scope(inclusions=["rg:rg-app"], loader=loader)
    other = f"{SUB}/resourceGroups/rg-other/providers/Microsoft.Authorization/locks/no-delete"
    assert rules.match(other) is NOT_INCLUDED and rules.match(RECORDS["group"]) is None
    assert rules.match(RECORDS["management group"]) is None and reads == []
    assert rules.match(RECORDS["subscription"]) is None and reads == [SUB_ID]


def test_no_evidence_is_written_after_a_failed_index_read(tmp_path):
    from azure_common import write_evidence

    failure = {"operation": f"resourcegraph.resources (tags in subscription {SUB_ID})", "type": "PermissionError",
               "message": "(403)"}
    evidence = {"metadata": {"partial_failure": True, "api_failures": [failure]}, "results": {}, "summary": {}}
    assert write_evidence(tmp_path, "unread.json", evidence) is None and not (tmp_path / "unread.json").exists()
    evidence["metadata"]["api_failures"] = [{**failure, "operation": "keyvault.vaults.list"}]
    assert write_evidence(tmp_path, "read.json", evidence).exists()


def test_a_failure_after_record_invalid_still_reaches_the_collector():
    def broken(sub):
        raise RuntimeError("Resource Graph reported the result as truncated")

    rules = ResourceScope([], ["tag:Boundary"], index=TagIndex(broken))
    collector = Collector(logging.getLogger("test"))
    rules.record_invalid(collector)
    assert collector.ok
    assert rules.match(VAULT) is SCOPE_UNKNOWN
    assert len(collector.failures) == 1
    rules.summary([], ("vault",), {"vaults": 0})
    assert len(collector.failures) == 1


def test_split_lists_not_included_resources_with_a_cap(monkeypatch):
    monkeypatch.setattr(resource_exclusions, "NOT_INCLUDED_LIST_CAP", 2)
    others = {f"{RG}/providers/microsoft.web/sites/app-{n}".lower(): {} for n in range(5)}
    rules = scope(["rg:nowhere"], ["tag:Boundary=FedRAMP"], tags={**TAGS, **others})
    items = [{"id": rid, "name": rid.rsplit("/", 1)[-1]} for rid in sorted(others, reverse=True)] + \
        [{"id": VAULT, "name": "kv-contoso"}]
    kept, excluded = rules.split(items, "site")
    assert [i["name"] for i in kept] == ["kv-contoso"]
    assert len(excluded) == 5  # split hands every entry back, so callers that read it see them all
    out = excluded_item("site", "app-x", "rg:nowhere", "resource_matched", id="x")
    summary = rules.summary(excluded + [out], ("site",), {"sites": len(kept)})
    assert summary["not_included_sites"] == 5 and summary["not_included_sites_not_listed"] == 0
    assert summary["excluded_sites"] == 1 and summary["in_scope_sites"] == 1
    assert summary["resource_inclusion_patterns"] == ["tag:Boundary=FedRAMP"]
    assert summary["resource_inclusion_patterns_unmatched"] == []
    assert "scope_unknown_sites" not in summary
    evidence = {"results": {"excluded": [out] + excluded}, "summary": summary}
    resource_exclusions.cap_not_included(evidence)
    assert [(e["name"], e["reason"]) for e in evidence["results"]["excluded"]] == [
        ("app-x", "resource_matched"), ("app-1", "not_included"), ("app-0", "not_included")]
    assert summary["not_included_sites"] == 5 and summary["not_included_sites_not_listed"] == 3


def test_writing_evidence_without_inclusions_leaves_it_as_it_was(tmp_path):
    from azure_common import write_evidence

    evidence = {"results": {"excluded": [excluded_item("site", "a", "rg:x", "resource_matched", id="x")]},
                "summary": {"excluded_sites": 1}}
    before = json.loads(json.dumps(evidence))
    assert json.loads(write_evidence(tmp_path, "e.json", evidence).read_text()) == before


def test_a_kind_with_none_included_warns(caplog):
    rules = scope(inclusions=["tag:Boundary=FedRAMP"])
    kept, excluded = rules.split([{"id": UNTAGGED_VAULT, "name": "kv-example"}], "key_vault")
    with caplog.at_level(logging.WARNING):
        rules.summary(excluded, ("key_vault",), {"key_vaults": len(kept)})
    assert "no key vaults are in scope" in caplog.text
    caplog.clear()
    empty = scope(inclusions=["tag:Boundary=FedRAMP"])
    with caplog.at_level(logging.WARNING):
        empty.summary([], ("key_vault",), {"key_vaults": 0})
    assert not caplog.records


def test_unmatched_inclusions_are_logged(caplog):
    rules = scope(inclusions=["tag:Boundary=FedRAMP", "tag:Typo"])
    rules.match(VAULT)
    with caplog.at_level(logging.WARNING):
        rules.warn_unmatched(logging.getLogger("t"))
    assert "resource inclusion pattern 'tag:Typo' matched nothing" in caplog.text


def test_no_pattern_is_called_unmatched_after_a_failed_index_read(caplog):
    def broken(sub):
        raise PermissionError("(403)")

    rules = ResourceScope(["rg:rg-out"], ["tag:Boundary=FedRAMP"], index=TagIndex(broken))
    rules.match(VAULT)
    with caplog.at_level(logging.WARNING):
        rules.warn_unmatched(logging.getLogger("t"))
    assert "matched nothing" not in caplog.text


def test_match_callers_get_a_reason_through_excluded_item():
    assert excluded_item("alert", "a", NOT_INCLUDED, "resource_matched", id="x") == {
        "kind": "alert", "name": "a", "pattern": None, "reason": "not_included", "id": "x"}
    assert excluded_item("alert", "a", SCOPE_UNKNOWN)["reason"] == "scope_unknown"
    assert excluded_item("alert", "a", "rg:x", "resource_matched")["pattern"] == "rg:x"


def test_reference_checks_dont_count_as_used():
    rules = scope(inclusions=["tag:Boundary=FedRAMP"])
    assert rules.match(VAULT, record=False) is None
    assert rules.inclusions_unmatched() == ["tag:Boundary=FedRAMP"]


def test_no_inclusions_leave_the_summary_as_it_was():
    rules = ResourceExclusions(["rg:rg-out"])
    assert rules.summary([], ("vault",), {"vaults": 2}) == {
        "resource_exclusion_patterns": ["rg:rg-out"],
        "resource_exclusion_patterns_unmatched": ["rg:rg-out"],
        "excluded_vaults": 0,
        "in_scope_vaults": 2,
    }
    assert not ResourceScope() and ResourceScope([], ["tag:x"])


def test_from_env_reads_both_lists(monkeypatch):
    monkeypatch.setenv(ENV, "rg:rg-out")
    monkeypatch.setenv(INCLUSIONS_ENV, 'tag:"Cost Center"="Shared, Prod",tag:Boundary=FedRAMP')
    rules = ResourceScope.from_env()
    assert rules.patterns == ["rg:rg-out"]
    assert rules.inclusions == ['tag:"Cost Center"="Shared, Prod"', "tag:Boundary=FedRAMP"]
    assert parse_patterns("rg:a, location: eastus") == ["rg:a", "location:eastus"]


def _adopters():
    from framework.config_loader import discover_fetchers, discover_platforms

    fetchers, platforms = discover_fetchers(REPO_ROOT), discover_platforms(REPO_ROOT)
    return [f for f in fetchers.values() if f.category == "azure" and "resource_exclusions" in f.config_schema], \
        platforms


def test_every_adopter_reads_its_scope_from_both_lists():
    adopters, _ = _adopters()
    for fetcher in adopters:
        source = (REPO_ROOT / "fetchers" / "azure" / fetcher.name.removeprefix("azure_") / "fetcher.py").read_text()
        assert any(call in source for call in ("ResourceExclusions.from_env()", "ResourceScope.from_env()",
                                               "resource_exclusions=True")), fetcher.name
        assert "ResourceExclusions(parse_patterns" not in source, fetcher.name


OTHER_RG = f"{SUB}/resourceGroups/rg-other"
OTHER_VAULT = f"{OTHER_RG}/providers/Microsoft.KeyVault/vaults/kv-other"
CONTAINERS = {**TAGS, RG.lower(): {}, OTHER_RG.lower(): {}, OTHER_VAULT.lower(): ({}, "westus"),
              VAULT.lower(): ({"boundary": "FedRAMP"}, "eastus")}


def test_a_resource_group_holding_an_in_scope_resource_stays_in_scope():
    rules = scope(inclusions=["tag:Boundary=FedRAMP"], tags=CONTAINERS)
    assert rules.match(RG) is None  # untagged, but it holds kv-contoso
    assert rules.match(OTHER_RG) is NOT_INCLUDED
    assert rules.match(SUB) is None
    lock = f"{RG}/providers/Microsoft.Authorization/locks/no-delete"
    assert rules.match(lock) is None
    assert rules.match(f"{OTHER_RG}/providers/Microsoft.Authorization/locks/no-delete") is NOT_INCLUDED
    assert rules.match(f"{SUB}/providers/Microsoft.Authorization/policyAssignments/a1") is None


def test_a_resource_group_its_own_tags_include_is_in_scope():
    rules = scope(inclusions=["tag:Owner=platform"], tags={**CONTAINERS, OTHER_RG.lower(): {"owner": "platform"}})
    assert rules.match(OTHER_RG) is None
    assert rules.match(OTHER_VAULT) is NOT_INCLUDED  # the group's tags don't pass down


def test_a_held_resource_is_never_judged_as_its_container():
    rules = scope(inclusions=["tag:Boundary=FedRAMP"], tags=CONTAINERS)
    assert rules.match(f"{RG}/providers/Microsoft.KeyVault/vaults/kv-example") is NOT_INCLUDED


def test_containers_follow_location_and_id_inclusions_through_the_index():
    rules = scope(inclusions=["location:eastus"], tags=CONTAINERS)
    assert rules.match(RG) is None and rules.match(OTHER_RG) is NOT_INCLUDED

    def refuse(sub):
        raise AssertionError("rg: inclusions need no index")

    assert ResourceScope([], ["rg:rg-app"], index=TagIndex(refuse)).match(RG) is None
    assert ResourceScope([], ["rg:rg-app"], index=TagIndex(refuse)).match(OTHER_RG) is NOT_INCLUDED


def test_tags_never_take_out_a_container_but_rg_patterns_still_do():
    rules = scope(["tag:Boundary=FedRAMP", "rg:rg-other"], tags=CONTAINERS)
    assert rules.match(RG) is None
    assert rules.match(f"{RG}/providers/Microsoft.Authorization/locks/no-delete") is None
    assert rules.match(OTHER_RG) == "rg:rg-other"
    assert rules.match(VAULT) == "tag:Boundary=FedRAMP"


def test_exclusions_inside_a_group_leave_it_holding_nothing():
    tags = {SUB.lower(): {}, RG.lower(): {}, VAULT.lower(): {"boundary": "FedRAMP"}, UNTAGGED_VAULT.lower(): {}}
    rules = scope(["id:*/vaults/kv-contoso"], ["tag:Boundary=FedRAMP"], tags=tags)
    assert rules.match(RG) is NOT_INCLUDED
    assert scope([], ["tag:Boundary=FedRAMP"], tags=tags).match(RG) is None


def test_a_container_is_unknown_when_the_index_cant_be_read():
    def broken(sub):
        raise PermissionError("(403) Forbidden")

    rules = ResourceScope([], ["tag:Boundary"], index=TagIndex(broken))
    assert rules.match(RG) is SCOPE_UNKNOWN
    assert rules.match(f"{RG}/providers/Microsoft.Authorization/locks/no-delete") is SCOPE_UNKNOWN


def test_a_grant_kept_by_the_identity_rule_names_only_an_exclusion_pattern():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "azure_rbac_for_inclusions", REPO_ROOT / "fetchers" / "azure" / "rbac_role_assignments" / "fetcher.py")
    rbac = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rbac)
    out = f"{SUB}/resourceGroups/rg-out"

    def kept(rules):
        grant = {"id": f"{out}/providers/Microsoft.Authorization/roleAssignments/g1", "scope": out,
                 "scope_level": rbac.SCOPE_RESOURCE_GROUP}
        [record], _ = rbac.split_by_scope([grant], "role_assignment", rules, frozenset({out.lower()}))
        return record["kept_by_identity_rule"]

    assert kept(ResourceScope(["rg:rg-out"])) == "rg:rg-out"
    assert kept(ResourceScope([], ["rg:rg-app"])) is None
