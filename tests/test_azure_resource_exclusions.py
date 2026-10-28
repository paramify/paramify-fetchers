"""Shared Azure resource exclusions: rg:, location: and id: patterns, which pattern matched, and invalid patterns."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))

from azure_common import Collector  # noqa: E402
from resource_exclusions import ENV, ResourceExclusions  # noqa: E402

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
VAULT = f"{SUB}/resourceGroups/RG-Out/providers/Microsoft.KeyVault/vaults/kv-out"
KEY = f"{VAULT}/keys/key-1"


@pytest.mark.parametrize("pattern, kwargs, matched", [
    ("rg:rg-out", {"resource_id": VAULT}, True),
    ("rg:RG-*", {"resource_id": f"{SUB}/resourcegroups/rg-out/providers/x/y/z"}, True),
    ("rg:rg-out", {"resource_group": "RG-OUT"}, True),
    ("rg:rg-out", {"resource_id": f"{SUB}/resourceGroups/rg-outer/providers/x/y/z"}, False),
    ("location:regioneast", {"location": "Region East"}, True),
    ("location:region*", {"location": "regionwest"}, True),
    ("location:regioneast", {"resource_id": VAULT}, False),
    ("location:regioneast", {"location": "otherregion"}, False),
    (f"id:{VAULT}", {"resource_id": VAULT.upper()}, True),
    (f"id:{VAULT}", {"resource_id": KEY}, True),
    ("id:*/vaults/kv-out", {"resource_id": KEY}, True),
    (f"id:{VAULT}", {"resource_id": f"{VAULT}-2"}, False),
])
def test_match_reads_group_location_and_id(pattern, kwargs, matched):
    assert (ResourceExclusions([pattern]).match(**kwargs) == pattern) is matched


def test_match_returns_the_first_configured_pattern_and_marks_every_match_used():
    exclusions = ResourceExclusions(["location:regioneast", "rg:rg-out", "rg:typo"])
    assert exclusions.match(VAULT, "regioneast") == "location:regioneast"
    assert exclusions.unmatched() == ["rg:typo"]


@pytest.mark.parametrize("pattern", ["rg-out", "region:east", "rg:", "location: ", "scope:x"])
def test_bare_or_unknown_prefixes_are_invalid_and_fail_the_run(pattern):
    exclusions = ResourceExclusions([pattern])
    assert exclusions.invalid() == [pattern]
    collector = Collector(logging.getLogger("test"))
    exclusions.record_invalid(collector)
    assert not collector.ok
    assert pattern in collector.failures[0]["message"]


def test_from_env_reads_comma_or_space_separated_patterns(monkeypatch):
    monkeypatch.setenv(ENV, "rg:rg-out, location: regioneast\nid:*/vaults/x")
    assert ResourceExclusions.from_env().patterns == ["rg:rg-out", "location:regioneast", "id:*/vaults/x"]
    monkeypatch.delenv(ENV)
    assert not ResourceExclusions.from_env()


def test_split_keeps_in_scope_items_and_lists_the_excluded_with_their_pattern():
    items = [
        {"id": VAULT, "name": "kv-out", "location": "regioneast"},
        {"id": f"{SUB}/resourceGroups/rg-in/providers/Microsoft.KeyVault/vaults/kv-in", "name": "kv-in",
         "location": "regionwest"},
    ]
    exclusions = ResourceExclusions(["rg:rg-out", "location:nowhere"])
    kept, excluded = exclusions.split(items, "vault")
    assert [i["name"] for i in kept] == ["kv-in"]
    assert excluded == [{"kind": "vault", "name": "kv-out", "pattern": "rg:rg-out", "reason": "resource_matched",
                         "id": VAULT, "resource_group": "RG-Out", "location": "regioneast"}]
    assert exclusions.summary(excluded, ("vault",), {"vaults": len(kept)}) == {
        "resource_exclusion_patterns": ["rg:rg-out", "location:nowhere"],
        "resource_exclusion_patterns_unmatched": ["location:nowhere"],
        "excluded_vaults": 1,
        "in_scope_vaults": 1,
    }


def test_no_patterns_keeps_everything():
    items = [{"id": VAULT, "name": "kv-out", "location": "regioneast"}]
    kept, excluded = ResourceExclusions().split(items, "vault")
    assert kept == items and excluded == []
