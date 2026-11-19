"""Azure resource inclusions in the fetcher contracts: every exclusion adopter declares resource_inclusions and tag:
exclusions, platform config reaches each one intact, and manifest exclude leaves inclusions alone."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "azure" / "_shared"))

from resource_exclusions import ENV, INCLUSIONS_ENV, ResourceScope  # noqa: E402
from scope_exclusions import parse_patterns  # noqa: E402


def _adopters():
    from framework.config_loader import discover_fetchers, discover_platforms

    fetchers, platforms = discover_fetchers(REPO_ROOT), discover_platforms(REPO_ROOT)
    return [f for f in fetchers.values() if f.category == "azure" and "resource_exclusions" in f.config_schema], \
        platforms


def test_every_exclusion_adopter_declares_inclusions_and_tag_patterns():
    adopters, _ = _adopters()
    assert len(adopters) >= 79
    for fetcher in adopters:
        inclusions, exclusions = fetcher.config_schema.get("resource_inclusions"), fetcher.config_schema["resource_exclusions"]
        assert inclusions is not None, fetcher.name
        assert (inclusions.type, inclusions.prefixes, inclusions.bare, inclusions.exclusion, inclusions.env) == \
            ("patterns", ("rg", "location", "id", "tag"), False, False, INCLUSIONS_ENV), fetcher.name
        assert exclusions.prefixes == ("rg", "location", "id", "tag"), fetcher.name


def test_platform_inclusions_reach_every_adopter_with_quoted_tags_intact():
    from framework.contract import ManifestEntry, PlatformConfig
    from framework.runner.executor import _apply_config

    adopters, platforms = _adopters()
    platform = PlatformConfig(config={"resource_inclusions": [
        {"pattern": 'tag:"Cost Center"="Shared, Prod"', "reason": "Shared services"}, "tag:Boundary=FedRAMP"]})
    for fetcher in adopters:
        env: dict = {}
        _apply_config(env, fetcher, platforms.get("azure"), platform, ManifestEntry(use=fetcher.name))
        assert ResourceScope(parse_patterns(env.get(ENV)), parse_patterns(env[INCLUSIONS_ENV])).inclusions == [
            'tag:"Cost Center"="Shared, Prod"', "tag:Boundary=FedRAMP"], fetcher.name


def test_manifest_exclude_never_adds_to_an_inclusion_list():
    from framework import api

    _, fields, _ = api.pattern_fields("azure", api.discover_fetchers(REPO_ROOT), api.discover_platforms(REPO_ROOT))
    assert "resource_inclusions" not in fields
    assert api.pick_pattern_field(fields, "tag:Scope=Out") == "resource_exclusions"
