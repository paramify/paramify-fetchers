"""Overlay discovery: root resolution, precedence, shadowing (phase 1 of
docs/distribution_design.md §12).

The phase-1 acceptance bar: `catalog` finds fetchers from a user dir with no
checkout on disk.
"""

import os
from pathlib import Path

import pytest

from framework import api
from framework.config_loader import (
    discover,
    discover_fetchers,
    discover_platforms,
    load_schema,
)
from framework.roots import fetcher_roots, find_checkout_root, user_home

REPO_ROOT = Path(__file__).resolve().parents[1]


FETCHER_YAML = """\
name: {name}
version: 0.1.0
description: test fetcher
category: {category}
runtime:
  type: python
  entry: fetcher.py
output:
  type: json
  path: out.json
secrets: []
"""

CATEGORY_YAML = """\
description: {description}
auth:
  passthrough_env:
    - {env_var}
"""


def make_fetcher(root: Path, category: str, short: str, name: str) -> Path:
    d = root / category / short
    d.mkdir(parents=True)
    (d / "fetcher.yaml").write_text(FETCHER_YAML.format(name=name, category=category))
    (d / "fetcher.py").write_text("print('hi')\n")
    return d


def make_category(root: Path, category: str, description: str, env_var: str) -> Path:
    d = root / "_categories"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{category}.yaml"
    p.write_text(CATEGORY_YAML.format(description=description, env_var=env_var))
    return p


# --------------------------------------------------------------------------- #
# Root resolution
# --------------------------------------------------------------------------- #

def test_user_home_honors_env(monkeypatch, tmp_path):
    monkeypatch.setenv("PARAMIFY_HOME", str(tmp_path / "home"))
    assert user_home() == tmp_path / "home"


def test_find_checkout_root_walks_up():
    assert find_checkout_root(REPO_ROOT / "framework" / "tui") == REPO_ROOT


def test_find_checkout_root_returns_none_outside(tmp_path):
    assert find_checkout_root(tmp_path) is None


def test_fetcher_roots_order_and_existence(monkeypatch, tmp_path):
    """env override → checkout → user dir; missing dirs are dropped."""
    override = tmp_path / "override"
    override.mkdir()
    home = tmp_path / "home"
    (home / "fetchers").mkdir(parents=True)
    monkeypatch.setenv("PARAMIFY_FETCHERS_PATH", os.pathsep.join([str(override), str(tmp_path / "missing")]))
    monkeypatch.setenv("PARAMIFY_HOME", str(home))

    roots = fetcher_roots(checkout=REPO_ROOT)
    assert roots == [override, REPO_ROOT / "fetchers", home / "fetchers"]


def test_fetcher_roots_no_checkout(monkeypatch, tmp_path):
    home = tmp_path / "home"
    (home / "fetchers").mkdir(parents=True)
    monkeypatch.delenv("PARAMIFY_FETCHERS_PATH", raising=False)
    monkeypatch.setenv("PARAMIFY_HOME", str(home))

    roots = fetcher_roots(start=tmp_path)  # cwd walk from outside any checkout
    assert roots == [home / "fetchers"]


# --------------------------------------------------------------------------- #
# Schema loading — core assets resolve without any repo root
# --------------------------------------------------------------------------- #

def test_load_schema_package_relative():
    schema = load_schema()
    assert schema.get("$schema") or schema.get("properties")
    assert load_schema("run_manifest_schema.json")


# --------------------------------------------------------------------------- #
# Multi-root discovery: precedence, shadowing, duplicates
# --------------------------------------------------------------------------- #

def test_discover_legacy_single_repo_root():
    """Back-compat: a single Path is a repo root (its fetchers/ subdir walks)."""
    fetchers = discover_fetchers(REPO_ROOT)
    assert "demo_hello" in fetchers


def test_first_root_wins_and_shadow_is_reported(tmp_path):
    user_root = tmp_path / "user"
    bundle_root = tmp_path / "bundle"
    make_fetcher(user_root, "aws", "thing", "aws_thing")
    make_fetcher(bundle_root, "aws", "thing", "aws_thing")
    make_fetcher(bundle_root, "aws", "other", "aws_other")

    result = discover([user_root, bundle_root])
    assert result.fetchers["aws_thing"].path == (user_root / "aws" / "thing").resolve()
    assert "aws_other" in result.fetchers
    assert result.invalid == []
    assert result.shadows == [{
        "name": "aws_thing",
        "winner": str((user_root / "aws" / "thing").resolve()),
        "shadowed": str((bundle_root / "aws" / "thing").resolve()),
    }]


def test_duplicate_within_one_root_still_raises(tmp_path):
    root = tmp_path / "user"
    make_fetcher(root, "aws", "a", "same_name")
    make_fetcher(root, "aws", "b", "same_name")
    with pytest.raises(ValueError, match="Duplicate fetcher name"):
        discover_fetchers([root])


def test_platforms_first_root_wins_per_category_file(tmp_path):
    user_root = tmp_path / "user"
    bundle_root = tmp_path / "bundle"
    user_root.mkdir()
    bundle_root.mkdir()
    make_category(user_root, "aws", "user override", "USER_VAR")
    make_category(bundle_root, "aws", "shipped", "SHIPPED_VAR")
    make_category(bundle_root, "okta", "shipped okta", "OKTA_VAR")
    make_category(user_root, "datadog", "brand-new user platform", "DD_API_KEY")

    platforms = discover_platforms([user_root, bundle_root])
    assert platforms["aws"].description == "user override"
    assert platforms["aws"].passthrough_env == ["USER_VAR"]
    assert platforms["okta"].description == "shipped okta"
    assert platforms["datadog"].passthrough_env == ["DD_API_KEY"]


# --------------------------------------------------------------------------- #
# The phase-1 acceptance bar: catalog with no checkout on disk
# --------------------------------------------------------------------------- #

def test_catalog_from_user_dir_without_checkout(monkeypatch, tmp_path):
    home = tmp_path / "home"
    make_fetcher(home / "fetchers", "datadog", "monitors", "datadog_monitors")
    make_category(home / "fetchers", "datadog", "Datadog", "DD_API_KEY")
    monkeypatch.setenv("PARAMIFY_HOME", str(home))
    monkeypatch.delenv("PARAMIFY_FETCHERS_PATH", raising=False)
    monkeypatch.chdir(tmp_path)  # no fetchers/+framework/ siblings anywhere above

    assert api.locate_root(tmp_path) is None
    cat = api.catalog()
    names = [f["name"] for c in cat["categories"] for f in c["fetchers"]]
    assert names == ["datadog_monitors"]
    dd = next(c for c in cat["categories"] if c["name"] == "datadog")
    assert dd["platform"]["passthrough_env"] == ["DD_API_KEY"]
    assert cat["shadows"] == []
    assert cat["roots"] == [str(home / "fetchers")]


def test_user_fetcher_shadows_builtin_in_catalog(monkeypatch, tmp_path):
    """Inside the checkout, a user copy of a built-in loses to the in-tree one
    (dev clone outranks the user dir) — and the shadow is reported."""
    home = tmp_path / "home"
    make_fetcher(home / "fetchers", "demo", "hello", "demo_hello")
    monkeypatch.setenv("PARAMIFY_HOME", str(home))
    monkeypatch.delenv("PARAMIFY_FETCHERS_PATH", raising=False)

    cat = api.catalog(REPO_ROOT)
    assert [s["name"] for s in cat["shadows"]] == ["demo_hello"]
    shadow = cat["shadows"][0]
    assert str(REPO_ROOT / "fetchers") in shadow["winner"]
    assert str(home) in shadow["shadowed"]


def test_validate_and_manifests_without_checkout(monkeypatch, tmp_path):
    home = tmp_path / "home"
    make_fetcher(home / "fetchers", "datadog", "monitors", "datadog_monitors")
    monkeypatch.setenv("PARAMIFY_HOME", str(home))
    monkeypatch.delenv("PARAMIFY_FETCHERS_PATH", raising=False)
    monkeypatch.chdir(tmp_path)

    manifest = {"run": {"output_dir": "./evidence",
                        "fetchers": [{"use": "datadog_monitors"}]}}
    assert api.validate(manifest) == []

    path = api.new_manifest_path(None, "smoke")
    assert path == tmp_path / "manifests" / "smoke.yaml"
    listed = api.list_manifests(None)
    assert [m["name"] for m in listed] == ["smoke.yaml"]
