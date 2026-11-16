"""Shared Azure resource exclusions: rg:, location: and id: patterns, which pattern matched, and invalid patterns."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))

from azure_common import Collector, classify_failure_code  # noqa: E402
from resource_exclusions import ENV, ResourceExclusions  # noqa: E402
from scope_exclusions import parse_patterns  # noqa: E402

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


def test_unread_list_makes_unmatched_null_and_skips_the_warning(caplog):
    exclusions = ResourceExclusions(["rg:typo"])
    exclusions.mark_unread()
    assert exclusions.unmatched() is None
    assert exclusions.summary([], ("vault",), {"vaults": 1})["resource_exclusion_patterns_unmatched"] is None
    with caplog.at_level(logging.WARNING):
        exclusions.warn_unmatched(logging.getLogger("t"))
    assert not caplog.records


def test_summary_with_an_unread_count_makes_unmatched_null():
    exclusions = ResourceExclusions(["rg:typo"])
    assert exclusions.summary([], ("vault",), {"vaults": 1})["resource_exclusion_patterns_unmatched"] == ["rg:typo"]
    assert ResourceExclusions(["rg:typo"]).summary([], ("vault",), {"vaults": None})[
        "resource_exclusion_patterns_unmatched"] is None


def test_match_own_id_skips_a_trailing_star_pattern_that_names_the_parent():
    log = f"{SUB}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_xeast/flowLogs/fl1"
    assert ResourceExclusions(["id:*/networkWatchers/NetworkWatcher_x*"]).match_own_id(log) is None
    assert ResourceExclusions(["id:*/networkWatchers/NetworkWatcher_x*/flowLogs/fl1"]).match_own_id(log) \
        == "id:*/networkWatchers/NetworkWatcher_x*/flowLogs/fl1"
    assert ResourceExclusions([f"id:{log}"]).match_own_id(log) == f"id:{log}"


def test_match_own_id_names_only_the_resource_itself():
    rules = ResourceExclusions(["rg:rg-out", f"id:{VAULT}", f"id:{KEY}", "location:*"])
    assert rules.match_own_id(KEY) == f"id:{KEY}"
    assert rules.match_own_id(f"{VAULT}/keys/key-2") is None
    assert rules.match_own_id(None) is None
    assert rules.unmatched() == ["rg:rg-out", f"id:{VAULT}", "location:*"]


@pytest.mark.parametrize("pattern", ["rg-out", "region:east", "rg:", "location: ", "scope:x"])
def test_bare_or_unknown_prefixes_are_invalid_and_fail_the_run(pattern):
    exclusions = ResourceExclusions([pattern])
    assert exclusions.invalid() == [pattern]
    collector = Collector(logging.getLogger("test"))
    exclusions.record_invalid(collector)
    assert not collector.ok
    assert pattern in collector.failures[0]["message"]
    assert classify_failure_code(collector.failures) == "bad_config"


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


def test_a_list_that_wasnt_read_leaves_both_its_counts_null():
    exclusions = ResourceExclusions(["rg:rg-out"])
    excluded = [{"kind": "key", "name": "k"}]
    assert exclusions.summary(excluded, ("vault", "key"), {"vaults": None, "keys": 3}) == {
        "resource_exclusion_patterns": ["rg:rg-out"],
        "resource_exclusion_patterns_unmatched": None,
        "excluded_vaults": None, "excluded_keys": 1,
        "in_scope_vaults": None, "in_scope_keys": 3,
    }


def test_no_patterns_keeps_everything():
    items = [{"id": VAULT, "name": "kv-out", "location": "regioneast"}]
    kept, excluded = ResourceExclusions().split(items, "vault")
    assert kept == items and excluded == []


def test_platform_config_reaches_every_fetcher_that_declares_the_field():
    from framework.config_loader import discover_fetchers, discover_platforms
    from framework.contract import ManifestEntry, PlatformConfig
    from framework.runner.executor import _apply_config

    fetchers, platforms = discover_fetchers(REPO_ROOT), discover_platforms(REPO_ROOT)
    adopters = [f for f in fetchers.values() if f.category == "azure" and "resource_exclusions" in f.config_schema]
    assert adopters
    platform = PlatformConfig(config={"resource_exclusions": [
        {"pattern": "rg:rg-out", "reason": "Outside the boundary"}, "location:regioneast"]})
    for fetcher in adopters:
        field = fetcher.config_schema["resource_exclusions"]
        assert (field.type, field.prefixes, field.bare, field.env) == ("patterns", ("rg", "location", "id"), False, ENV)
        env: dict = {}
        _apply_config(env, fetcher, platforms.get("azure"), platform, ManifestEntry(use=fetcher.name))
        assert env[ENV] == "rg:rg-out,location:regioneast", fetcher.name
        assert ResourceExclusions(parse_patterns(env[ENV])).patterns == ["rg:rg-out", "location:regioneast"]
