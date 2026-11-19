"""expected_resources in azure_resource_inventory: the in-scope inventory reconciled against an expected population,
both ways (expected patterns that match nothing, resources no pattern expects), and null while unset."""

from __future__ import annotations

import json

import pytest

from tests import test_azure_resource_exclusions_inventory as base

inv = base.inv
EXPECTED_ENV = inv.EXPECTED_ENV


def run(monkeypatch, tmp_path, expected, exclusions=None):
    if expected is None:
        monkeypatch.delenv(EXPECTED_ENV, raising=False)
    else:
        monkeypatch.setenv(EXPECTED_ENV, expected)
    code, evidence = base.run_inventory(monkeypatch, tmp_path, exclusions)
    return code, evidence["summary"], evidence["results"]


def test_unset_leaves_every_reconciliation_field_null(monkeypatch, tmp_path):
    code, s, results = run(monkeypatch, tmp_path, None)
    assert code == 0 and s["expected_resource_patterns"] == []
    assert all(s[k] is None for k in ("expected_resource_patterns_unmatched", "expected_resources_missing",
                                       "unexpected_resources", "unexpected_resources_by_type",
                                       "inventory_matches_expected"))
    assert all(r["expected_by"] is None for r in results["resources"])


def test_a_matching_population_reconciles(monkeypatch, tmp_path):
    code, s, results = run(monkeypatch, tmp_path, "rg:rg-in, rg:rg-out")
    assert code == 0
    assert (s["expected_resources_missing"], s["unexpected_resources"], s["inventory_matches_expected"]) == (0, 0, True)
    assert s["expected_resource_patterns_unmatched"] == [] and s["unexpected_resources_by_type"] == {}
    assert {r["name"]: r["expected_by"] for r in results["resources"]} == {
        "sa-in": "rg:rg-in", "vm-east": "rg:rg-in", "vnet-in": "rg:rg-in", "sa-out": "rg:rg-out"}


def test_missing_and_unexpected_are_reported_both_ways(monkeypatch, tmp_path):
    expected = f"id:{base.SA_IN}, id:*/providers/microsoft.network/virtualnetworks/*, id:*/virtualMachines/vm-west"
    code, s, results = run(monkeypatch, tmp_path, expected)
    assert code == 0 and s["inventory_matches_expected"] is False
    assert s["expected_resource_patterns_unmatched"] == ["id:*/virtualMachines/vm-west"]
    assert s["expected_resources_missing"] == 1
    assert s["unexpected_resources"] == 2
    assert s["unexpected_resources_by_type"] == {"microsoft.compute/virtualmachines": 1,
                                                 "microsoft.storage/storageaccounts": 1}
    unexpected = sorted(r["name"] for r in results["resources"] if r["expected_by"] is None)
    assert unexpected == ["sa-out", "vm-east"]


def test_only_missing_or_only_unexpected_still_fails_the_verdict(monkeypatch, tmp_path):
    _, s, _ = run(monkeypatch, tmp_path, "rg:rg-in, rg:rg-out, rg:rg-gone")
    assert (s["expected_resources_missing"], s["unexpected_resources"], s["inventory_matches_expected"]) == (1, 0, False)
    _, s, _ = run(monkeypatch, tmp_path, "rg:rg-in")
    assert (s["expected_resources_missing"], s["unexpected_resources"], s["inventory_matches_expected"]) == (0, 1, False)


def test_excluded_resources_are_neither_expected_nor_unexpected(monkeypatch, tmp_path):
    # sa-out is out of scope, so a pattern naming only it is missing and it is not counted as unexpected.
    _, s, results = run(monkeypatch, tmp_path, "rg:rg-in, rg:rg-out", exclusions="rg:rg-out")
    assert sorted(r["name"] for r in results["resources"]) == ["sa-in", "vm-east", "vnet-in"]
    assert s["expected_resource_patterns_unmatched"] == ["rg:rg-out"] and s["unexpected_resources"] == 0


def test_an_unread_inventory_leaves_the_counts_null(monkeypatch, tmp_path):
    monkeypatch.setenv(EXPECTED_ENV, "rg:rg-in")
    base._env(monkeypatch, tmp_path, inv, None)
    monkeypatch.setattr(inv, "credential", lambda: object())
    monkeypatch.setattr(inv, "resource_graph_client", lambda cred: object())

    def fail(client, sub, query):
        raise RuntimeError("Resource Graph unavailable")

    monkeypatch.setattr(inv, "query_all", fail)
    assert inv.main() == 1
    s = json.loads((tmp_path / "azure_resource_inventory_s1.json").read_text())["summary"]
    assert s["expected_resource_patterns"] == ["rg:rg-in"]
    assert (s["expected_resources_missing"], s["unexpected_resources"], s["inventory_matches_expected"]) == (None, None, None)


@pytest.mark.parametrize("bad", ["rg-in", "type:microsoft.storage/storageaccounts", "id:"])
def test_a_pattern_without_a_known_prefix_fails_the_run(monkeypatch, tmp_path, bad):
    code, _, _ = run(monkeypatch, tmp_path, f"rg:rg-in, {bad}")
    assert code == 1


def test_reconcile_unit_marks_resources_and_counts_by_type():
    resources = [{"id": f"{base.IN_RG}/providers/a/b/x", "location": "w", "resource_group": "rg-in", "type": "a/b"},
                 {"id": f"{base.OUT_RG}/providers/a/b/y", "location": "w", "resource_group": "rg-out", "type": "a/b"},
                 {"id": f"{base.OUT_RG}/providers/c/d/z", "location": "w", "resource_group": "rg-out", "type": None}]
    out = inv.reconcile(resources, inv.ResourceExclusions(["rg:rg-in"]), inventory_read=True)
    assert out["unexpected_resources_by_type"] == {"a/b": 1, "unknown": 1}
    assert [r["expected_by"] for r in resources] == ["rg:rg-in", None, None]


def test_summary_fields_match_the_instructions(monkeypatch, tmp_path, assert_summary_documented):
    monkeypatch.setenv(EXPECTED_ENV, "rg:rg-in")
    _, evidence = base.run_inventory(monkeypatch, tmp_path, None)
    assert_summary_documented("azure/resource_inventory", evidence["summary"])
