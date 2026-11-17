"""Every releases/<version>.yaml is what `paramify update` can show.

The schema checks the shape; this checks what a schema can't: the file names
its own version, the version has a CHANGELOG section, a release with Breaking
entries says so, the "what's new" rows stay short, and the fetcher names a row
targets exist, so a typo can't silently stop a breaking change from naming the
manifests it affects.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Dict

import pytest
import yaml

from framework import update

REPO_ROOT = Path(__file__).resolve().parent.parent
FILES = sorted((REPO_ROOT / update.HIGHLIGHTS_DIR).glob("*.yaml"))
UNRELEASED = REPO_ROOT / update.HIGHLIGHTS_DIR / "unreleased.yaml"
RELEASE_FILES = [p for p in FILES if p != UNRELEASED]


def _changelog_sections() -> Dict[str, Dict]:
    """{version: {"date": ..., "Breaking": <top-level bullets>, ...}} from CHANGELOG.md."""
    out: Dict[str, Dict] = {}
    cur = sub = None
    for line in (REPO_ROOT / "CHANGELOG.md").read_text().splitlines():
        m = re.match(r"^## \[([^\]]+)\](?:\s*-\s*(\S+))?\s*$", line)
        if m:
            cur, sub = out.setdefault(m[1], {"date": m[2]}), None
        elif cur is not None and line.startswith("### "):
            sub = line[4:].strip()
            cur.setdefault(sub, 0)
        elif cur is not None and sub and line.startswith("- "):
            cur[sub] += 1
    return out


CHANGELOG = _changelog_sections()


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
    assert RELEASE_FILES, "releases/ has no highlights files; the 0.6.0-beta one should be there"


def test_unreleased_file_exists_and_matches_the_schema():
    doc = _doc(UNRELEASED)
    assert doc["version"] == "unreleased"
    assert not update.highlights_errors(doc, update.highlights_schema())


def test_every_unreleased_breaking_entry_has_a_row():
    entries = CHANGELOG["Unreleased"].get("Breaking", 0)
    rows = [h for h in _doc(UNRELEASED)["highlights"] if h["tag"] == "breaking"]
    assert len(rows) >= entries, (
        f"CHANGELOG [Unreleased] has {entries} Breaking entries but releases/unreleased.yaml has "
        f"{len(rows)} breaking rows; add a row (see releases/README.md)")


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_highlights_file_matches_the_schema(path):
    errors = update.highlights_errors(_doc(path), update.highlights_schema())
    assert not errors, f"{path.name}: " + "; ".join(errors)


@pytest.mark.parametrize("path", RELEASE_FILES, ids=lambda p: p.name)
def test_highlights_file_is_named_for_a_changelog_release(path):
    doc = _doc(path)
    assert doc["version"] == path.stem, f"{path.name} says version {doc['version']}"
    assert doc["version"] in CHANGELOG, f"CHANGELOG.md has no ## [{doc['version']}] section"
    if doc.get("date"):
        assert doc["date"] == CHANGELOG[doc["version"]]["date"], "date differs from the CHANGELOG heading"


@pytest.mark.parametrize("path", RELEASE_FILES, ids=lambda p: p.name)
def test_breaking_changelog_entries_have_breaking_rows(path):
    doc = _doc(path)
    entries = CHANGELOG[doc["version"]].get("Breaking", 0)
    rows = [h for h in doc["highlights"] if h["tag"] == "breaking"]
    if entries:
        assert rows, f"the CHANGELOG lists {entries} Breaking entries but {path.name} has no breaking row"


@pytest.mark.parametrize("path", RELEASE_FILES, ids=lambda p: p.name)
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
