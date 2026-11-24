"""required_resources and allowed_resources in azure_resource_inventory: the in-scope inventory reconciled against an
expected population. A required resource is an exact ARM id that must itself be returned; an allowed pattern admits
a family of resources, possibly none, and never stands in for a required one. Anything neither required nor allowed
is unexpected. Resource groups are judged the same way, in both directions, after resource_exclusions. Null while
both are unset."""

from __future__ import annotations

import json

import pytest

from tests import test_azure_resource_exclusions_inventory as base

inv = base.inv
REQUIRED_ENV, ALLOWED_ENV = inv.REQUIRED_ENV, inv.ALLOWED_ENV
VNET = base.VNET_IN
SUBNET = f"{VNET}/subnets/snet-app"
SNAPSHOT = f"{base.IN_RG}/providers/Microsoft.Compute/snapshots/velero-pvc-0a1b2c"
EXTRA = f"{base.IN_RG}/providers/Microsoft.KeyVault/vaults/kv-extra"


def run(monkeypatch, tmp_path, required=None, allowed=None, exclusions=None, resources=None, groups=None,
        groups_fail=False):
    for env, value in ((REQUIRED_ENV, required), (ALLOWED_ENV, allowed)):
        if value is None:
            monkeypatch.delenv(env, raising=False)
        else:
            monkeypatch.setenv(env, value)
    tables = dict(base.INVENTORY_TABLES)
    if resources is not None:
        tables["Resources"] = resources
    tables["ResourceContainers"] = [{"id": g, "name": g.rsplit("/", 1)[1], "location": "regionwest"}
                                    for g in (groups if groups is not None else [base.IN_RG, base.OUT_RG])]
    queries = []
    base._env(monkeypatch, tmp_path, inv, exclusions)
    monkeypatch.setattr(inv, "credential", lambda: object())
    monkeypatch.setattr(inv, "resource_graph_client", lambda cred: object())

    def query_all(client, sub, query):
        queries.append(query.split(" ", 1)[0])
        if groups_fail and query.startswith("ResourceContainers"):
            raise RuntimeError("(AuthorizationFailed) does not have authorization")
        return {"rows": tables[query.split(" ", 1)[0]], "total_records": 0, "pages": 1}

    monkeypatch.setattr(inv, "query_all", query_all)
    code = inv.main()
    evidence = json.loads((tmp_path / "azure_resource_inventory_s1.json").read_text())
    return code, evidence["summary"], evidence["results"], queries


def ids(*resource_ids):
    return ", ".join(f"id:{r}" for r in resource_ids)


ALL = ids(base.SA_IN, base.SA_OUT, base.VM_EAST, VNET, base.IN_RG, base.OUT_RG)
EMPTY_RG = f"{base.SUB}/resourceGroups/rg-empty"


def test_unset_leaves_every_reconciliation_field_null(monkeypatch, tmp_path):
    code, s, results, queries = run(monkeypatch, tmp_path)
    assert code == 0 and (s["required_resources"], s["allowed_resource_patterns"]) == ([], [])
    assert all(s[k] is None for k in ("required_resources_missing", "required_resources_missing_ids",
                                       "allowed_resource_patterns_unmatched", "unexpected_resources",
                                       "unexpected_resources_by_type", "inventory_matches_expected"))
    assert all(r["expected_by"] is None for r in results["resources"]) and "ResourceContainers" not in queries


def test_every_required_id_present_and_nothing_else_reconciles(monkeypatch, tmp_path):
    code, s, results, _ = run(monkeypatch, tmp_path, required=ALL)
    assert code == 0
    assert (s["required_resources_missing"], s["unexpected_resources"], s["inventory_matches_expected"]) == (0, 0, True)
    assert s["required_resources_missing_ids"] == [] and s["allowed_resource_patterns_unmatched"] == []
    assert {r["expected_by"] for r in results["resources"] + results["resource_groups"]} == {"required"}


def test_required_ids_are_compared_without_case(monkeypatch, tmp_path):
    _, s, _, _ = run(monkeypatch, tmp_path, required=ids(base.SA_IN.upper(), base.SA_OUT.lower(), base.VM_EAST, VNET,
                                                          base.IN_RG.upper(), base.OUT_RG))
    assert (s["required_resources_missing"], s["unexpected_resources"]) == (0, 0)


def test_a_missing_required_vnet_is_not_satisfied_by_an_allowed_subnet(monkeypatch, tmp_path):
    # First reported case: the VNet is gone, its subnet is returned and allowed. The VNet is still missing.
    resources = [r for r in base.INVENTORY_TABLES["Resources"] if r["id"] != VNET]
    resources.append(base._resource(SUBNET, "microsoft.network/virtualnetworks/subnets"))
    _, s, results, _ = run(monkeypatch, tmp_path, required=ALL, allowed=f"id:{VNET}/subnets/*", resources=resources)
    assert (s["required_resources_missing"], s["required_resources_missing_ids"]) == (1, [VNET])
    assert s["unexpected_resources"] == 0 and s["inventory_matches_expected"] is False
    assert {r["name"]: r["expected_by"] for r in results["resources"]}["snet-app"] == f"id:{VNET}/subnets/*"


def test_a_child_alone_does_not_satisfy_its_required_parent(monkeypatch, tmp_path):
    resources = [r for r in base.INVENTORY_TABLES["Resources"] if r["id"] != VNET]
    resources.append(base._resource(SUBNET, "microsoft.network/virtualnetworks/subnets"))
    _, s, _, _ = run(monkeypatch, tmp_path, required=ALL, resources=resources)
    # Without an allowed pattern the subnet is unexpected too.
    assert (s["required_resources_missing_ids"], s["unexpected_resources"]) == ([VNET], 1)


def test_an_unlisted_resource_beside_a_required_one_is_unexpected(monkeypatch, tmp_path):
    # Second reported case: kv-extra shares rg-in with required resources but is neither required nor allowed.
    resources = base.INVENTORY_TABLES["Resources"] + [base._resource(EXTRA, "microsoft.keyvault/vaults")]
    _, s, results, _ = run(monkeypatch, tmp_path, required=ALL, allowed="id:*/providers/microsoft.compute/snapshots/velero-*",
                           resources=resources)
    assert (s["required_resources_missing"], s["unexpected_resources"]) == (0, 1)
    assert s["unexpected_resources_by_type"] == {"microsoft.keyvault/vaults": 1}
    assert [r["name"] for r in results["resources"] if r["expected_by"] is None] == ["kv-extra"]


def test_an_allowed_family_may_be_empty_or_populated(monkeypatch, tmp_path):
    allowed = "id:*/providers/microsoft.compute/snapshots/velero-*"
    _, s, _, _ = run(monkeypatch, tmp_path, required=ALL, allowed=allowed)
    assert s["inventory_matches_expected"] is True and s["allowed_resource_patterns_unmatched"] == [allowed]
    resources = base.INVENTORY_TABLES["Resources"] + [base._resource(SNAPSHOT, "microsoft.compute/snapshots")]
    _, s, results, _ = run(monkeypatch, tmp_path, required=ALL, allowed=allowed, resources=resources)
    assert s["inventory_matches_expected"] is True and s["allowed_resource_patterns_unmatched"] == []
    assert {r["name"]: r["expected_by"] for r in results["resources"]}["velero-pvc-0a1b2c"] == allowed


def test_a_required_resource_group_is_checked_against_the_resource_groups(monkeypatch, tmp_path):
    gone = f"{base.SUB}/resourceGroups/rg-gone"
    code, s, _, queries = run(monkeypatch, tmp_path, required=ALL + ", " + ids(gone))
    assert code == 0 and "ResourceContainers" in queries
    assert s["required_resources_missing_ids"] == [gone]


def test_unread_resource_groups_leave_missing_and_unexpected_null(monkeypatch, tmp_path):
    code, s, _, _ = run(monkeypatch, tmp_path, required=ids(base.IN_RG, base.SA_IN), groups_fail=True)
    assert code == 1
    # A resource group might be unexpected, and a required one present, so neither is decided.
    assert (s["required_resources_missing"], s["unexpected_resources"], s["inventory_matches_expected"]) == (None, None, None)


def test_without_a_required_group_unread_groups_still_leave_missing_judged(monkeypatch, tmp_path):
    _, s, _, _ = run(monkeypatch, tmp_path, required=ids(base.SA_IN), groups_fail=True)
    assert (s["required_resources_missing"], s["unexpected_resources"]) == (0, None)


def test_an_empty_resource_group_neither_required_nor_allowed_is_unexpected(monkeypatch, tmp_path):
    # rg-empty holds nothing, but it is in scope and nothing expects it.
    _, s, results, _ = run(monkeypatch, tmp_path, required=ALL, groups=[base.IN_RG, base.OUT_RG, EMPTY_RG])
    assert (s["required_resources_missing"], s["unexpected_resources"], s["inventory_matches_expected"]) == (0, 1, False)
    assert s["unexpected_resources_by_type"] == {inv.RESOURCE_GROUP_TYPE: 1}
    assert [g["name"] for g in results["resource_groups"] if g["expected_by"] is None] == ["rg-empty"]
    # Allowed by a pattern, it is no longer unexpected.
    _, s, _, _ = run(monkeypatch, tmp_path, required=ALL, allowed="rg:rg-empty", groups=[base.IN_RG, base.OUT_RG, EMPTY_RG])
    assert (s["unexpected_resources"], s["inventory_matches_expected"]) == (0, True)


def test_an_excluded_required_resource_group_is_missing(monkeypatch, tmp_path):
    # rg-out is required, but resource_exclusions takes it, and sa-out in it, out of scope: both read as missing.
    _, s, results, _ = run(monkeypatch, tmp_path, required=ALL, exclusions="rg:rg-out")
    assert s["required_resources_missing_ids"] == [base.SA_OUT, base.OUT_RG]
    assert s["unexpected_resources"] == 0
    assert sorted((e["kind"], e["name"]) for e in results["excluded"]) == [("resource", "sa-out"), ("resource_group", "rg-out")]
    assert [g["name"] for g in results["resource_groups"]] == ["rg-in"]


def test_an_excluded_resource_group_is_not_unexpected(monkeypatch, tmp_path):
    _, s, _, _ = run(monkeypatch, tmp_path, required=ALL, exclusions="rg:rg-empty", groups=[base.IN_RG, base.OUT_RG, EMPTY_RG])
    assert (s["unexpected_resources"], s["inventory_matches_expected"]) == (0, True)


def test_an_unread_inventory_leaves_the_counts_null(monkeypatch, tmp_path):
    monkeypatch.setenv(REQUIRED_ENV, ALL)
    monkeypatch.delenv(ALLOWED_ENV, raising=False)
    base._env(monkeypatch, tmp_path, inv, None)
    monkeypatch.setattr(inv, "credential", lambda: object())
    monkeypatch.setattr(inv, "resource_graph_client", lambda cred: object())

    def fail(client, sub, query):
        raise RuntimeError("Resource Graph unavailable")

    monkeypatch.setattr(inv, "query_all", fail)
    assert inv.main() == 1
    s = json.loads((tmp_path / "azure_resource_inventory_s1.json").read_text())["summary"]
    assert len(s["required_resources"]) == 6
    assert (s["required_resources_missing"], s["unexpected_resources"], s["inventory_matches_expected"]) == (None, None, None)


@pytest.mark.parametrize("bad", ["rg:rg-in", "id:*/virtualMachines/vm-east", f"id:{base.IN_RG}/providers/*", "id:", "vm-east"])
def test_a_required_entry_that_is_not_one_exact_id_fails_the_run(monkeypatch, tmp_path, bad):
    code, _, _, _ = run(monkeypatch, tmp_path, required=f"{ids(base.SA_IN)}, {bad}")
    assert code == 1


@pytest.mark.parametrize("bad", ["rg-in", "type:microsoft.storage/storageaccounts", "id:"])
def test_an_allowed_pattern_without_a_known_prefix_fails_the_run(monkeypatch, tmp_path, bad):
    code, _, _, _ = run(monkeypatch, tmp_path, allowed=f"rg:rg-in, {bad}")
    assert code == 1


def test_allowed_patterns_alone_still_report_unexpected(monkeypatch, tmp_path):
    _, s, _, _ = run(monkeypatch, tmp_path, allowed="rg:rg-in")
    # sa-out and the rg-out group itself; rg:rg-in allows both rg-in and everything in it.
    assert (s["required_resources_missing"], s["unexpected_resources"], s["inventory_matches_expected"]) == (0, 2, False)
    assert s["unexpected_resources_by_type"] == {inv.RESOURCE_GROUP_TYPE: 1, "microsoft.storage/storageaccounts": 1}


def test_summary_fields_match_the_instructions(monkeypatch, tmp_path, assert_summary_documented):
    _, s, _, _ = run(monkeypatch, tmp_path, required=ALL, allowed="rg:rg-in")
    assert_summary_documented("azure/resource_inventory", s)
