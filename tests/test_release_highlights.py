"""Every releases/<version>.yaml is what `paramify update` can show.

The schema checks the shape; this checks what a schema can't: the file names
its own version, the version has a CHANGELOG section, a release with Breaking
entries says so, the "what's new" rows stay short, and the fetcher names a row
targets exist, so a typo can't silently stop a breaking change from naming the
manifests it affects.
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any, List

import pytest
import yaml

from framework import release_notes, update

REPO_ROOT = Path(__file__).resolve().parent.parent
FILES = sorted((REPO_ROOT / update.HIGHLIGHTS_DIR).glob("*.yaml"))
UNRELEASED = REPO_ROOT / update.HIGHLIGHTS_DIR / "unreleased.yaml"
RELEASE_FILES = [p for p in FILES if p != UNRELEASED]


CHANGELOG = release_notes.changelog_sections((REPO_ROOT / "CHANGELOG.md").read_text())


SCHEMA = json.loads((REPO_ROOT / "framework/schemas/release_highlights_schema.json").read_text())


def _doc(path: Path) -> dict:
    """The file as its author typed it: YAML reads an unquoted 2026-10-23 as a
    date and 0.6 as a float, and the schema wants text."""
    doc = yaml.safe_load(path.read_text())
    for key in ("date", "version"):
        if key in doc and not isinstance(doc[key], str):
            doc[key] = doc[key].isoformat() if hasattr(doc[key], "isoformat") else str(doc[key])
    return doc


def _schema_errors(doc: Any) -> List[str]:
    from jsonschema import Draft202012Validator

    return [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}"
            for e in Draft202012Validator(SCHEMA).iter_errors(doc)]


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
    assert not _schema_errors(doc)


def test_every_unreleased_breaking_entry_has_a_row():
    entries = CHANGELOG["Unreleased"].get("Breaking", 0)
    rows = [h for h in _doc(UNRELEASED)["highlights"] if h["tag"] == "breaking"]
    assert len(rows) >= entries, (
        f"CHANGELOG [Unreleased] has {entries} Breaking entries but releases/unreleased.yaml has "
        f"{len(rows)} breaking rows; add a row (see releases/README.md)")


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_highlights_file_matches_the_schema(path):
    errors = _schema_errors(_doc(path))
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
    assert len(rows) >= entries, (
        f"the CHANGELOG lists {entries} Breaking entries but {path.name} has {len(rows)} breaking rows")


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_named_fetchers_exist(path):
    names = _fetcher_names()
    for h in _doc(path)["highlights"]:
        for pattern in h.get("fetchers") or []:
            assert any(fnmatch.fnmatchcase(n, pattern) for n in names), (
                f"{path.name}: '{pattern}' in \"{h['title']}\" matches no fetcher"
            )


def test_a_fetcher_line_matches_the_schema():
    doc = {"version": "0.8.0-beta", "highlights": [],
           "fetchers": [{"name": "demo_alpha", "version": "0.7.0", "note": "Reads more rows", "draft": True}]}
    assert _schema_errors(doc) == []


@pytest.mark.parametrize("line", [
    {"name": "demo_alpha", "version": "0.7.0"},                          # no note
    {"name": "demo_alpha", "version": "seven", "note": "x" * 10},        # not a version
    {"name": "demo_alpha", "version": "0.7.0", "note": "x" * 111},       # too long
    {"name": "demo_alpha", "version": "0.7.0", "note": "a\nb"},          # two lines
    {"name": "demo_alpha", "version": "0.7.0", "note": "ok ok", "x": 1}, # unknown key
])
def test_a_bad_fetcher_line_is_refused(line):
    assert _schema_errors({"version": "0.8.0-beta", "highlights": [], "fetchers": [line]})


def test_a_highlight_row_may_carry_a_draft_mark():
    assert _schema_errors({"version": "unreleased",
                           "highlights": [{"tag": "new", "title": "Sprockets", "draft": True}]}) == []


def test_no_file_is_a_draft():
    marked = []
    for path in FILES:
        doc = _doc(path)
        marked += [f"{path.name}: {h['title']}" for h in doc["highlights"] if h.get("draft")]
        marked += [f"{path.name}: {f['name']}" for f in doc.get("fetchers") or [] if f.get("draft")]
    assert not marked, "draft marks left in: " + "; ".join(marked)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_fetcher_note_is_a_todo(path):
    todo = [f["name"] for f in _doc(path).get("fetchers") or [] if f["note"].startswith("TODO")]
    assert not todo, f"{path.name}: notes still say TODO for {', '.join(todo)}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_fetcher_lines_name_real_fetchers(path):
    names = _fetcher_names()
    unknown = [f["name"] for f in _doc(path).get("fetchers") or [] if f["name"] not in names]
    assert not unknown, f"{path.name}: no such fetcher: {', '.join(unknown)}"
