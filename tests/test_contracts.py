"""Contract gate: every fetcher.yaml and category file must satisfy its schema.

This is the merge gate the CI ``test`` job protects (SEC-36). Discovery
(``framework.config_loader``) validates every ``fetcher.yaml`` against
``fetcher_schema.json`` and every ``fetchers/_categories/*.yaml`` against
``category_schema.json``, and raises on any schema violation or duplicate
fetcher name. The public API surface *is* the contract (CLAUDE.md), so a change
that breaks a fetcher's declared shape must turn this suite red before it can
merge.

The per-file parametrized tests validate directly against the JSON Schema so a
failure names the offending file and field; the discovery tests exercise the
same path in aggregate (must not raise) and assert the duplicate-name and
on-disk/discovered-count invariants.

Run: ``pytest tests/test_contracts.py`` (needs an editable install:
``pip install -e .``).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from framework.config_loader import discover_fetchers, discover_platforms

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHERS_ROOT = REPO_ROOT / "fetchers"
SCHEMAS_ROOT = REPO_ROOT / "framework" / "schemas"


def _fetcher_yamls() -> list[Path]:
    """Every real fetcher.yaml, mirroring discover_fetchers' walk.

    category/<name>/fetcher.yaml, skipping any ``_``-prefixed dir (_shared,
    _categories, _template) at either level.
    """
    out: list[Path] = []
    for category_dir in sorted(FETCHERS_ROOT.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("_"):
            continue
        for fetcher_dir in sorted(category_dir.iterdir()):
            if not fetcher_dir.is_dir() or fetcher_dir.name.startswith("_"):
                continue
            yaml_path = fetcher_dir / "fetcher.yaml"
            if yaml_path.exists():
                out.append(yaml_path)
    return out


FETCHER_YAMLS = _fetcher_yamls()
CATEGORY_YAMLS = sorted((FETCHERS_ROOT / "_categories").glob("*.yaml"))


def _load_schema(name: str) -> dict:
    return json.loads((SCHEMAS_ROOT / name).read_text())


def _rel_ids(paths: list[Path]) -> list[str]:
    return [str(p.relative_to(REPO_ROOT)) for p in paths]


def _format_errors(errors) -> str:
    return "\n".join(
        f"  {'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors
    )


def test_fetcher_yamls_discovered() -> None:
    """Sanity: the walk actually finds fetchers (guards an empty parametrize)."""
    assert FETCHER_YAMLS, "no fetcher.yaml files discovered under fetchers/"


@pytest.mark.parametrize("yaml_path", FETCHER_YAMLS, ids=_rel_ids(FETCHER_YAMLS))
def test_fetcher_yaml_matches_schema(yaml_path: Path) -> None:
    validator = Draft202012Validator(_load_schema("fetcher_schema.json"))
    data = yaml.safe_load(yaml_path.read_text())
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    assert not errors, f"{yaml_path.name} violates fetcher_schema.json:\n{_format_errors(errors)}"


@pytest.mark.parametrize("yaml_path", CATEGORY_YAMLS, ids=_rel_ids(CATEGORY_YAMLS))
def test_category_yaml_matches_schema(yaml_path: Path) -> None:
    validator = Draft202012Validator(_load_schema("category_schema.json"))
    data = yaml.safe_load(yaml_path.read_text()) or {}
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    assert not errors, f"{yaml_path.name} violates category_schema.json:\n{_format_errors(errors)}"


def test_discovery_does_not_raise() -> None:
    """The aggregate gate: discovery validates + dedupes, raising on violations."""
    fetchers = discover_fetchers(REPO_ROOT)
    assert fetchers, "discover_fetchers returned nothing"
    discover_platforms(REPO_ROOT)  # must not raise on any category file


def test_fetcher_names_unique_and_complete() -> None:
    """Every fetcher.yaml on disk maps to exactly one discovered, uniquely named
    fetcher (discover_fetchers raises on a duplicate name before returning)."""
    fetchers = discover_fetchers(REPO_ROOT)
    assert len(fetchers) == len(FETCHER_YAMLS), (
        f"{len(FETCHER_YAMLS)} fetcher.yaml files on disk but "
        f"{len(fetchers)} discovered"
    )
