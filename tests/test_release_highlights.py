"""Every releases/<version>.yaml is what `paramify update` can show.

The schema checks the shape; this checks what a schema can't: the file names
its own version, the version has a CHANGELOG section, a release with Breaking
entries says so, the "what's new" rows stay short, and the fetcher names a row
targets exist, so a typo can't silently stop a breaking change from naming the
manifests it affects.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

import pytest
import yaml

from framework import update

REPO_ROOT = Path(__file__).resolve().parent.parent
FILES = sorted((REPO_ROOT / update.HIGHLIGHTS_DIR).glob("*.yaml"))
CHANGELOG = update.parse_changelog((REPO_ROOT / "CHANGELOG.md").read_text())


def _doc(path: Path) -> dict:
    return update._normalize_highlights(yaml.safe_load(path.read_text()))


def _fetcher_names() -> set:
    names = set()
    for f in (REPO_ROOT / "fetchers").rglob("fetcher.yaml"):
        name = (yaml.safe_load(f.read_text()) or {}).get("name")
        if name:
            names.add(name)
    return names


def test_there_is_at_least_one_highlights_file():
    assert FILES, "releases/ has no highlights files; the 0.6.0-beta one should be there"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_highlights_file_matches_the_schema(path):
    errors = update.highlights_errors(_doc(path), update.highlights_schema())
    assert not errors, f"{path.name}: " + "; ".join(errors)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_highlights_file_is_named_for_a_changelog_release(path):
    doc = _doc(path)
    assert doc["version"] == path.stem, f"{path.name} says version {doc['version']}"
    assert doc["version"] in CHANGELOG, f"CHANGELOG.md has no ## [{doc['version']}] section"
    if doc.get("date"):
        assert doc["date"] == CHANGELOG[doc["version"]]["date"], "date differs from the CHANGELOG heading"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_breaking_changelog_entries_have_breaking_rows(path):
    doc = _doc(path)
    entries = CHANGELOG[doc["version"]]["sections"].get("Breaking", [])
    rows = [h for h in doc["highlights"] if h["tag"] == "breaking"]
    if entries:
        assert rows, f"the CHANGELOG lists {len(entries)} Breaking entries but {path.name} has no breaking row"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_whats_new_stays_short(path):
    rows = [h["title"] for h in _doc(path)["highlights"] if h["tag"] != "breaking"]
    assert 3 <= len(rows) <= 5, f"{path.name} has {len(rows)} non-breaking rows; keep 3 to 5: {rows}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_named_fetchers_exist(path):
    names = _fetcher_names()
    for h in _doc(path)["highlights"]:
        for pattern in h.get("fetchers") or []:
            assert any(fnmatch.fnmatchcase(n, pattern) for n in names), (
                f"{path.name}: '{pattern}' in \"{h['title']}\" matches no fetcher"
            )
