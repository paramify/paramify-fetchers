"""Shared Azure scope exclusions: case-insensitive glob patterns, which pattern matched, and the ones that matched nothing."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))

from scope_exclusions import (  # noqa: E402
    ScopeExclusions,
    excluded_item,
    parse_patterns,
)


@pytest.mark.parametrize("raw, patterns", [
    (None, []),
    ("", []),
    ("  ,  ", []),
    ("qa.example.com", ["qa.example.com"]),
    ("qa.*, *.sandbox.example.com\nwebdav*", ["qa.*", "*.sandbox.example.com", "webdav*"]),
    ("QA.*,qa.*  qa.*.", ["QA.*"]),
])
def test_parse_patterns(raw, patterns):
    assert parse_patterns(raw) == patterns


@pytest.mark.parametrize("pattern, name, matched", [
    ("qa.example.com", "QA.Example.com", True),
    ("qa.example.com", "qa.example.com.", True),
    ("qa.example.com.", "qa.example.com", True),
    ("*.sandbox.example.com", "app.eu.sandbox.example.com", True),
    ("*.sandbox.example.com", "sandbox.example.com", False),
    ("qa-*", "QA-route", True),
    ("qa-*", "prod-qa-route", False),
    ("cdn?.example.com", "cdn1.example.com", True),
    ("cdn[0-9].example.com", "cdnx.example.com", False),
    ("www", "www.example.com", False),
])
def test_match_is_a_case_insensitive_whole_name_glob(pattern, name, matched):
    assert (ScopeExclusions([pattern]).match(name) == pattern) is matched


def test_match_returns_the_first_configured_pattern_and_marks_every_match_used():
    exclusions = ScopeExclusions(["*.example.com", "qa.*", "typo.example.org"])
    assert exclusions.match("qa.example.com") == "*.example.com"
    assert exclusions.unmatched() == ["typo.example.org"]


def test_match_tries_every_name_and_ignores_empty_ones():
    exclusions = ScopeExclusions(["www"])
    assert exclusions.match(None, "", "www.example.com.", "www") == "www"
    assert exclusions.match(None) is None


def test_no_patterns_excludes_nothing():
    exclusions = ScopeExclusions.from_env("SCOPE_EXCLUSIONS_UNSET_FOR_TEST")
    assert not exclusions
    assert exclusions.match("anything") is None
    assert exclusions.summary([], ("route",), {"routes": 3}) == {
        "scope_exclusion_patterns": [], "scope_exclusion_patterns_unmatched": [], "excluded_routes": 0,
        "in_scope_routes": 3}


def test_from_env(monkeypatch):
    monkeypatch.setenv("SCOPE_EXCLUSIONS_FOR_TEST", "qa.*, dev.*")
    assert ScopeExclusions.from_env("SCOPE_EXCLUSIONS_FOR_TEST").patterns == ["qa.*", "dev.*"]


def test_summary_counts_each_kind_and_echoes_patterns():
    exclusions = ScopeExclusions(["qa.*", "nothing.*"])
    exclusions.match("qa.example.com")
    excluded = [excluded_item("custom_domain", "qa", "qa.*"), excluded_item("route", "r", None, reason="all_hosts_excluded")]
    assert exclusions.summary(excluded, ("custom_domain", "route", "origin_group"), {"hosts": 0, "routes": 2}) == {
        "scope_exclusion_patterns": ["qa.*", "nothing.*"],
        "scope_exclusion_patterns_unmatched": ["nothing.*"],
        "excluded_custom_domains": 1,
        "excluded_routes": 1,
        "excluded_origin_groups": 0,
        "in_scope_hosts": 0,
        "in_scope_routes": 2,
    }


def test_a_route_prefix_matches_route_names_only_and_a_bare_pattern_never_does():
    exclusions = ScopeExclusions(["route:QA-*", "qa*"])
    assert exclusions.match("qa-legacy-route", kind="route") == "route:QA-*"
    assert exclusions.match("www.contoso.com", kind="route") is None
    assert exclusions.match("qa-legacy-route") == "qa*"
    assert ScopeExclusions(["route:qa*"]).match("qa.example.com") is None


def test_warn_unmatched(caplog):
    exclusions = ScopeExclusions(["typo.*"])
    with caplog.at_level(logging.WARNING):
        exclusions.warn_unmatched(logging.getLogger("test"))
    assert "'typo.*' matched nothing" in caplog.text


def test_excluded_item_shape():
    assert excluded_item("record_set", "www", "www", zone="example.com") == {
        "kind": "record_set", "name": "www", "pattern": "www", "reason": "name_matched", "zone": "example.com"}
