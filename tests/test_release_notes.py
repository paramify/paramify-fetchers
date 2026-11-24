"""Pure release logic: versions, CHANGELOG cut, note drafting, rebuild and check."""

from __future__ import annotations

import datetime

import pytest
import yaml

from framework import release_notes as rn

LINK = "https://github.com/paramify/paramify-fetchers/compare"
CHANGELOG = f"""# Changelog

## [Unreleased]

### Added

- **`demo_alpha` 0.7.0: reads more rows.**

## [0.6.0-beta] - 2026-10-23

### Breaking

- **Python 3.11 is the minimum.**

[Unreleased]: {LINK}/v0.6.0-beta...HEAD
[0.6.0-beta]: {LINK}/v0.5.1-beta...v0.6.0-beta
"""


def test_changelog_sections_counts_bullets_and_keeps_bodies():
    s = rn.changelog_sections(CHANGELOG)
    assert s["0.6.0-beta"]["date"] == "2026-10-23"
    assert s["0.6.0-beta"]["Breaking"] == 1
    assert s["Unreleased"]["date"] is None
    assert "demo_alpha" in s["Unreleased"]["body"]
    assert "## [" not in s["Unreleased"]["body"]
    assert "compare" not in s["0.6.0-beta"]["body"]


def test_cut_changelog_moves_the_heading_and_the_links():
    out = rn.cut_changelog(CHANGELOG, "0.7.0-beta", "2026-11-27")
    assert "## [Unreleased]\n\n## [0.7.0-beta] - 2026-11-27\n" in out
    assert f"[Unreleased]: {LINK}/v0.7.0-beta...HEAD\n" \
           f"[0.7.0-beta]: {LINK}/v0.6.0-beta...v0.7.0-beta\n" \
           f"[0.6.0-beta]: {LINK}/v0.5.1-beta...v0.6.0-beta" in out
    assert out.count("## [Unreleased]") == 1


@pytest.mark.parametrize("text", [
    CHANGELOG.replace("## [Unreleased]", "## [Next]"),
    CHANGELOG.replace(f"[Unreleased]: {LINK}/v0.6.0-beta...HEAD\n", ""),
])
def test_cut_changelog_refuses_a_file_without_unreleased(text):
    with pytest.raises(ValueError):
        rn.cut_changelog(text, "0.7.0-beta", "2026-11-27")


def test_set_pyproject_version_strips_the_suffix():
    text = '[build-system]\nrequires = []\n\n[project]\nname = "x"\nversion = "0.6.0"\n\n[tool.x]\nversion = "9"\n'
    out = rn.set_pyproject_version(text, "0.7.0-beta")
    assert 'version = "0.7.0"\n' in out
    assert 'version = "9"' in out
    assert out.count("0.6.0") == 0


def _notes(*tags):
    return {"highlights": [{"tag": t, "title": "x"} for t in tags]}


@pytest.mark.parametrize("notes, added, major, want", [
    (_notes("breaking"), [], 0, "minor"),
    (_notes("breaking"), [], 1, "major"),
    (_notes(), ["demo_new"], 0, "minor"),
    (_notes(), ["demo_new"], 2, "minor"),
    (_notes("new"), [], 0, "minor"),
    (_notes("fetcher"), [], 0, "minor"),
    (_notes("cli"), [], 3, "minor"),
    (_notes("tui"), [], 0, "minor"),
    (_notes("fix"), [], 0, "patch"),
    (_notes(), [], 0, "patch"),
    ({"highlights": []}, [], 1, "patch"),
])
def test_required_bump(notes, added, major, want):
    assert rn.required_bump(notes, added, major) == want


@pytest.mark.parametrize("prev, bump, want", [
    ("0.6.0-beta", "minor", "0.7.0-beta"),
    ("0.7.0-beta", "patch", "0.7.1-beta"),
    ("1.2.3", "major", "2.0.0"),
    ("0.9.0-beta", "minor", "0.10.0-beta"),
    ("0.6.3-beta", "major", "1.0.0-beta"),
])
def test_next_version(prev, bump, want):
    assert rn.next_version(prev, bump) == want


TWO = ("- **`aws_inspector_ecr_findings` and `aws_inspector_ecr_report` 0.3.0: image counts and an opt-in.**\n"
       "  Longer text here.\n")


def test_draft_note_from_a_lead_naming_two_fetchers():
    for name in ("aws_inspector_ecr_findings", "aws_inspector_ecr_report"):
        assert rn.draft_note(name, TWO, []) == "image counts and an opt-in"


def test_draft_note_for_a_new_fetcher_without_a_version():
    body = "- **`snowflake_roles`: roles and grants.** Details.\n"
    assert rn.draft_note("snowflake_roles", body, []) == "roles and grants"


def test_draft_note_reads_a_lead_wrapped_over_two_lines():
    body = "- **`demo_alpha` 0.7.0: reads more\n  rows.** Details.\n"
    assert rn.draft_note("demo_alpha", body, []) == "reads more rows"


def test_draft_note_ignores_nested_bullets_and_other_fetchers():
    body = "- **`demo_beta` 0.1.0: beta.**\n  - **`demo_alpha`: nested.**\n"
    assert rn.draft_note("demo_alpha", body, ["demo_alpha: from commit"]) == "from commit"


def test_draft_note_falls_back_to_the_commit_subject():
    assert rn.draft_note("demo_alpha", "", ["chore: bump", "demo_alpha 0.7.0: reads more rows"]) == "reads more rows"


def test_draft_note_falls_back_to_a_todo():
    assert rn.draft_note("demo_alpha", "", ["chore: bump"]) == "TODO: say what changed for the user"


def test_draft_note_cuts_a_long_note_at_a_word():
    body = "- **`demo_alpha` 0.7.0: " + " ".join(["word"] * 40) + ".**\n"
    note = rn.draft_note("demo_alpha", body, [])
    assert note.endswith("…")
    assert len(note) <= 110
    assert not note[:-1].endswith(" ")
    assert set(note[:-1].split()) == {"word"}


def _row(title, **kw):
    return {"tag": "new", "title": title, **kw}


def test_first_draft_marks_everything():
    doc = rn.draft_release("0.7.0-beta", "2026-11-27", [_row("Row")],
                           {"demo_b": "0.2.0", "demo_a": "0.7.0"}, lambda n: f"note {n}")
    assert list(doc) == ["version", "date", "highlights", "fetchers"]
    assert doc["highlights"] == [_row("Row", draft=True)]
    assert doc["fetchers"] == [
        {"name": "demo_a", "version": "0.7.0", "note": "note demo_a", "draft": True},
        {"name": "demo_b", "version": "0.2.0", "note": "note demo_b", "draft": True},
    ]


def test_rebuild_keeps_edits_and_deletions_and_marks_only_whats_new():
    previous = {
        "highlights": [_row("Kept row")],
        "fetchers": [
            {"name": "demo_alpha", "version": "0.7.0", "note": "Edited by hand"},
            {"name": "demo_gone", "version": "0.1.0", "note": "Not changed any more"},
        ],
    }
    doc = rn.draft_release("0.7.0-beta", "2026-11-27", [_row("Kept row"), _row("Beta row")],
                           {"demo_alpha": "0.7.0", "demo_gamma": "0.2.0"}, lambda n: f"note {n}",
                           previous=previous, rows_since_base=[_row("Fresh row")])
    assert [h["title"] for h in doc["highlights"]] == ["Kept row", "Fresh row"]
    assert [bool(h.get("draft")) for h in doc["highlights"]] == [False, True]
    by = {f["name"]: f for f in doc["fetchers"]}
    assert set(by) == {"demo_alpha", "demo_gamma"}
    assert by["demo_alpha"] == {"name": "demo_alpha", "version": "0.7.0", "note": "Edited by hand"}
    assert by["demo_gamma"] == {"name": "demo_gamma", "version": "0.2.0", "note": "note demo_gamma", "draft": True}
    assert "draft" not in previous["highlights"][0]


def test_rebuild_remarks_a_line_whose_fetcher_moved_again():
    previous = {"highlights": [],
                "fetchers": [{"name": "demo_alpha", "version": "0.7.0", "note": "Edited by hand"}]}
    doc = rn.draft_release("0.7.0-beta", "2026-11-27", [], {"demo_alpha": "0.7.1"}, lambda n: "new",
                           previous=previous)
    assert doc["fetchers"] == [{"name": "demo_alpha", "version": "0.7.1", "note": "Edited by hand", "draft": True}]
    assert previous["fetchers"][0]["version"] == "0.7.0"


def test_dump_release_round_trips_with_the_header():
    doc = rn.draft_release("0.7.0-beta", "2026-11-27", [_row("Row", detail="Why: it works")],
                           {"demo_a": "0.7.0"}, lambda n: "reads more")
    text = rn.dump_release(doc)
    assert text.startswith("# What `paramify update` shows for v0.7.0-beta.")
    assert "[0.7.0-beta] section" in text
    assert "releases/README.md" in text
    assert text.index("version:") < text.index("date:") < text.index("highlights:") < text.index("fetchers:")
    assert yaml.safe_load(text) == {**doc, "date": datetime.date(2026, 11, 27)}


def test_dump_release_writes_the_date_unquoted_like_the_shipped_files():
    text = rn.dump_release(rn.draft_release("0.7.0-beta", "2026-11-27", [], {}, lambda n: ""))
    assert "\ndate: 2026-11-27\n" in text


def _doc(version="0.7.0-beta", rows=(), fetchers=()):
    return {"version": version, "date": "2026-11-27", "highlights": list(rows), "fetchers": list(fetchers)}


def _line(name, version, note="Reads more"):
    return {"name": name, "version": version, "note": note}


def test_check_release_accepts_a_clean_doc():
    doc = _doc(rows=[_row("Row")], fetchers=[_line("demo_alpha", "0.7.0")])
    assert rn.check_release(doc, {"demo_alpha": "0.7.0"}, [], "0.6.0-beta") == []


def test_check_release_names_a_fetcher_without_a_line():
    msgs = rn.check_release(_doc(rows=[_row("Row")]), {"demo_alpha": "0.7.0"}, [], "0.6.0-beta")
    assert msgs == ["demo_alpha 0.7.0 has no fetcher line"]


def test_check_release_names_a_line_for_a_fetcher_that_did_not_change():
    doc = _doc(rows=[_row("Row")], fetchers=[_line("demo_beta", "0.2.0")])
    assert rn.check_release(doc, {}, [], "0.6.0-beta") == ["demo_beta has a line but did not change since v0.6.0-beta"]


def test_check_release_names_a_line_with_another_version():
    doc = _doc(rows=[_row("Row")], fetchers=[_line("demo_alpha", "0.6.9")])
    assert rn.check_release(doc, {"demo_alpha": "0.7.0"}, [], "0.6.0-beta") == [
        "demo_alpha line says 0.6.9 but the fetcher is 0.7.0"]


def test_check_release_names_a_fetcher_with_two_lines():
    doc = _doc(rows=[_row("Row")], fetchers=[_line("demo_alpha", "0.7.0"), _line("demo_alpha", "0.7.0", "Again")])
    assert rn.check_release(doc, {"demo_alpha": "0.7.0"}, [], "0.6.0-beta") == [
        "demo_alpha has 2 fetcher lines; keep one"]


def test_check_release_names_the_wrong_version():
    doc = _doc(version="0.6.1-beta", rows=[{"tag": "breaking", "title": "x"}])
    assert rn.check_release(doc, {}, [], "0.6.0-beta") == [
        "expected 0.7.0-beta or later (breaking rows → minor), found 0.6.1-beta"]


def test_check_release_accepts_a_dropped_prerelease_suffix():
    doc = _doc(version="0.7.0", rows=[{"tag": "breaking", "title": "x"}])
    assert rn.check_release(doc, {}, [], "0.6.0-beta") == []


def test_check_release_explains_an_added_fetcher():
    doc = _doc(version="0.6.1-beta")
    msgs = rn.check_release(doc, {}, ["demo_new"], "0.6.0-beta")
    assert msgs == ["expected 0.7.0-beta or later (added fetchers → minor), found 0.6.1-beta"]


@pytest.mark.parametrize("forced", ["1.0.0", "1.0.0-beta", "0.8.0-beta", "0.7.1", "0.7.0-rc"])
def test_check_release_accepts_a_version_forced_above_the_expected_one(forced):
    doc = _doc(version=forced, rows=[{"tag": "new", "title": "x"}])
    assert rn.check_release(doc, {}, [], "0.6.0-beta") == []


def test_check_release_accepts_forcing_1_0_0_from_a_beta():
    doc = _doc(version="1.0.0", rows=[{"tag": "fix", "title": "x"}])
    assert rn.check_release(doc, {}, [], "0.7.0-beta") == []


@pytest.mark.parametrize("found", ["0.6.9", "0.6.1", "0.6.0-beta"])
def test_check_release_refuses_a_version_below_the_expected_one(found):
    doc = _doc(version=found, rows=[{"tag": "new", "title": "x"}])
    assert rn.check_release(doc, {}, [], "0.6.0-beta") == [
        f"expected 0.7.0-beta or later (new rows → minor), found {found}"]


def test_check_release_names_a_version_that_is_not_one():
    doc = _doc(version="next", rows=[{"tag": "new", "title": "x"}])
    assert rn.check_release(doc, {}, [], "0.6.0-beta") == [
        "expected 0.7.0-beta or later (new rows → minor), found next"]


def test_draft_note_from_a_lead_without_a_version_or_colon():
    body = "- **`aws_organizations_scp` can record the SCPs that apply to each account.** More.\n"
    assert rn.draft_note("aws_organizations_scp", body, []) == "can record the SCPs that apply to each account"


def test_draft_note_drops_a_list_of_names_after_the_lead_name():
    body = "- **`demo_a` and `demo_b` now page through results.**\n"
    assert rn.draft_note("demo_b", body, []) == "now page through results"


def test_draft_note_from_a_nested_list_bullet_with_a_version():
    body = ("- **Azure fetchers.**\n"
            "  - `azure_activity_log_alerts` 0.3.0: activity log alert rules and their action groups.\n")
    assert rn.draft_note("azure_activity_log_alerts", body, []) == "activity log alert rules and their action groups"


def test_draft_note_from_a_top_level_list_bullet_without_a_version():
    assert rn.draft_note("demo_alpha", "- `demo_alpha`: reads more rows\n", []) == "reads more rows"


def test_draft_note_from_a_commit_that_names_the_directory():
    subjects = ["fix(azure): vague", "organizations_scp: walk the tree for inherited SCPs"]
    assert rn.draft_note("aws_organizations_scp", "", subjects, dir_name="organizations_scp") \
        == "walk the tree for inherited SCPs"
    assert rn.draft_note("aws_organizations_scp", "", subjects) == "TODO: say what changed for the user"


def test_draft_note_leaves_category_prefixes_unmatched():
    subjects = ["fix(azure): tidy", "AI fetchers: add things"]
    assert rn.draft_note("azure_x", "", subjects, dir_name="x") == "TODO: say what changed for the user"


def test_draft_note_joins_a_wrapped_list_bullet_and_keeps_its_first_sentence():
    body = ("- `demo_alpha` 0.3.0: hubs, projects and other\n"
            "  Machine Learning workspaces. More detail.\n"
            "- `demo_beta`: other\n")
    assert rn.draft_note("demo_alpha", body, []) == "hubs, projects and other Machine Learning workspaces"


def test_draft_note_keeps_a_sentence_with_an_abbreviation_whole():
    body = "- `demo_alpha`: uses the API, e.g. the v2 one, i.e. the newer one. Then more.\n"
    assert rn.draft_note("demo_alpha", body, []) == "uses the API, e.g. the v2 one, i.e. the newer one"


def test_draft_note_drops_names_joined_with_an_oxford_comma():
    body = "- **`demo_a`, `demo_b`, and `demo_c` now page.**\n"
    assert rn.draft_note("demo_a", body, []) == "now page"


def test_draft_note_drops_a_version_without_a_colon():
    assert rn.draft_note("demo_a", "- **`demo_a` 0.3.0 adds paging.**\n", []) == "adds paging"
    assert rn.draft_note("demo_b", "- **`demo_a` 0.3.0 and `demo_b` 0.2.0 add paging.**\n", []) == "add paging"
