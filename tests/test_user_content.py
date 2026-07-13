"""User-content commands (phase 3 of docs/distribution_design.md §12): create,
customize (copy-on-write + staleness sidecar), and doctor's distribution
section — exercised against an installed-like topology (fake bundle root as
the lowest-priority content root, user dir above it, no checkout).
"""

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from framework import api
from framework import roots as roots_mod
from framework.config_loader import discover_fetchers

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


def make_fetcher(root: Path, category: str, short: str, name: str) -> Path:
    d = root / category / short
    d.mkdir(parents=True)
    (d / "fetcher.yaml").write_text(FETCHER_YAML.format(name=name, category=category))
    (d / "fetcher.py").write_text("print('hi')\n")
    return d


@pytest.fixture
def overlay(monkeypatch, tmp_path):
    """Installed-like topology: user dir over a fake bundle, no checkout.
    The bundle carries the real _template so create() can scaffold."""
    home = tmp_path / "home"
    bundle = tmp_path / "bundle"
    (bundle / "fetchers").mkdir(parents=True)
    shutil.copytree(
        REPO_ROOT / "fetchers" / "_template", bundle / "fetchers" / "_template",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    monkeypatch.setenv("PARAMIFY_HOME", str(home))
    monkeypatch.delenv("PARAMIFY_FETCHERS_PATH", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(roots_mod, "bundled_content_root", lambda: bundle)
    return SimpleNamespace(home=home, bundle=bundle / "fetchers")


# --------------------------------------------------------------------------- #
# create
# --------------------------------------------------------------------------- #

def test_create_scaffolds_into_user_dir(overlay):
    res = api.create_fetcher("datadog/monitors", category_file=True)
    assert res["name"] == "datadog_monitors"
    dest = Path(res["path"])
    assert dest == overlay.home / "fetchers" / "datadog" / "monitors"

    text = (dest / "fetcher.yaml").read_text()
    assert "datadog_monitors" in text and "<category>" not in text
    assert res["category_file"] == str(
        overlay.home / "fetchers" / "_categories" / "datadog.yaml"
    )

    cat = api.catalog()
    names = [f["name"] for c in cat["categories"] for f in c["fetchers"]]
    assert "datadog_monitors" in names  # discoverable immediately


def test_create_refuses_overwrite_and_collisions(overlay):
    make_fetcher(overlay.bundle, "aws", "thing", "aws_thing")
    with pytest.raises(FileExistsError, match="use customize"):
        api.create_fetcher("aws/thing")  # collides with a "built-in" name

    api.create_fetcher("datadog/monitors")
    with pytest.raises(FileExistsError, match="already exists"):
        api.create_fetcher("datadog/monitors")


def test_create_rejects_bad_spec(overlay):
    for bad in ("nocategory", "Bad/Name", "aws/", "/thing", "a b/c"):
        with pytest.raises(ValueError, match="invalid spec"):
            api.create_fetcher(bad)


# --------------------------------------------------------------------------- #
# customize — copy-on-write + sidecar
# --------------------------------------------------------------------------- #

def test_customize_copies_and_shadows(overlay):
    make_fetcher(overlay.bundle, "aws", "thing", "aws_thing")

    res = api.customize_fetcher("aws_thing")
    dest = Path(res["path"])
    assert dest == overlay.home / "fetchers" / "aws" / "thing"
    assert sorted(res["files"]) == ["fetcher.py", "fetcher.yaml"]
    assert res["active"]  # no checkout here, so the user copy wins discovery

    sidecar = json.loads((dest / ".customized.json").read_text())
    assert sidecar["name"] == "aws_thing"
    assert sidecar["source"] == str((overlay.bundle / "aws" / "thing").resolve())
    assert set(sidecar["files"]) == {"fetcher.py", "fetcher.yaml"}

    cat = api.catalog()
    assert cat["fetcher_count"] == 1  # shadowed, not duplicated
    [shadow] = cat["shadows"]
    assert shadow["name"] == "aws_thing"
    assert str(overlay.home) in shadow["winner"]

    # re-customizing resolves to the user copy itself — directed to edit it
    with pytest.raises(FileExistsError, match="already in your user dir"):
        api.customize_fetcher("aws_thing")


def test_customize_rejects_unknown_and_user_own(overlay):
    with pytest.raises(ValueError, match="unknown fetcher"):
        api.customize_fetcher("nope")

    api.create_fetcher("datadog/monitors")
    with pytest.raises(FileExistsError, match="already in your user dir"):
        api.customize_fetcher("datadog_monitors")


# --------------------------------------------------------------------------- #
# doctor — staleness + invalid reporting
# --------------------------------------------------------------------------- #

def test_doctor_flags_stale_and_orphaned_overrides(overlay):
    src = make_fetcher(overlay.bundle, "aws", "thing", "aws_thing")
    api.customize_fetcher("aws_thing")

    dist = api.doctor()["distribution"]
    assert dist["stale_overrides"] == []
    assert [s["name"] for s in dist["shadows"]] == ["aws_thing"]
    assert dist["user_dir"] == str(overlay.home)

    (src / "fetcher.py").write_text("print('upstream improved this')\n")
    [stale] = api.doctor()["distribution"]["stale_overrides"]
    assert stale["status"] == "stale"
    assert stale["changed"] == ["fetcher.py"]

    shutil.rmtree(src)
    [orphan] = api.doctor()["distribution"]["stale_overrides"]
    assert orphan["status"] == "orphaned"
    assert orphan["name"] == "aws_thing"


def test_invalid_fetcher_reported_not_fatal(overlay):
    make_fetcher(overlay.bundle, "aws", "thing", "aws_thing")
    broken = overlay.home / "fetchers" / "wip" / "half_done"
    broken.mkdir(parents=True)
    (broken / "fetcher.yaml").write_text("name: wip_half_done\n")  # misses required keys

    cat = api.catalog()  # must not raise
    assert cat["fetcher_count"] == 1
    [inv] = cat["invalid"]
    assert str(broken / "fetcher.yaml") == inv["path"]
    assert api.doctor()["distribution"]["invalid"] == cat["invalid"]

    with pytest.raises(ValueError, match="schema validation failed"):
        discover_fetchers([overlay.home / "fetchers"])  # strict path still raises
