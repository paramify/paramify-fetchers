"""tools/release.py against throwaway git repos with a real v0.6.0-beta tag.

The fixture builds an "upstream" repo (the stand-in for GitHub) with a
CHANGELOG, a pyproject, the release files and three fetchers, tags it
v0.6.0-beta, and clones it. `draft` fetches from and pushes to that upstream.
`gh` is a FakeGitHub that records calls, and `notify` appends to a list.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location("release_tool", REPO_ROOT / "tools" / "release.py")
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)

LINK = "https://github.com/paramify/paramify-fetchers/compare"
PR_URL = "https://github.com/paramify/paramify-fetchers/pull/7"
RELEASE_URL = "https://github.com/paramify/paramify-fetchers/releases/tag/v0.7.0-beta"
TODAY = "2026-11-26"

UNRELEASED_HEADER = (
    "# What `paramify update` shows for changes on main since the last release.\n"
    "# Add a row in the pull request that makes the change, and only when it breaks\n"
    "# something or is worth announcing. Format and rules: releases/README.md.\n"
)
NEW_ROW = {"tag": "new", "title": "Sprockets for all", "try": "paramify catalog"}
FIX_ROW = {"tag": "fix", "title": "Uploads retry on a timeout"}
BREAKING_ROW = {"tag": "breaking", "title": "gamma renames a field", "fix": "Read the new field",
                "fetchers": ["demo_gamma"]}


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def _commit(repo: Path, files: dict, message: str) -> None:
    for rel, text in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _changelog(*unreleased: str) -> str:
    body = "".join(f"- {b}\n" for b in unreleased)
    added = f"### Added\n\n{body}\n" if body else ""
    return (
        "# Changelog\n\n## [Unreleased]\n\n" + added
        + "## [0.6.0-beta] - 2026-10-23\n\n### Added\n\n- **First.**\n\n"
        f"[Unreleased]: {LINK}/v0.6.0-beta...HEAD\n[0.6.0-beta]: {LINK}/v0.5.1-beta...v0.6.0-beta\n"
    )


def _fetcher(name: str, version: str) -> str:
    return f"name: {name}\nversion: {version}\n"


def _unreleased(*rows: dict) -> str:
    return UNRELEASED_HEADER + yaml.safe_dump({"version": "unreleased", "highlights": list(rows)}, sort_keys=False)


def _sha(repo: Path, ref: str = "HEAD") -> str:
    return _git(repo, "rev-parse", ref).strip()


def _show(repo: Path, path: str, ref: str = "origin/release/next") -> str:
    return _git(repo, "show", f"{ref}:{path}")


def _exists(repo: Path, path: str, ref: str = "origin/release/next") -> bool:
    return subprocess.run(["git", "cat-file", "-e", f"{ref}:{path}"], cwd=repo, capture_output=True).returncode == 0


def _release_file(repo: Path, version: str, ref: str = "origin/release/next") -> dict:
    return yaml.safe_load(_show(repo, f"releases/{version}.yaml", ref))


def _marked(doc: dict) -> list:
    return [x.get("title") or x.get("name") for x in doc["highlights"] + doc["fetchers"] if x.get("draft")]


def _unmarked(items: list) -> list:
    return [{k: v for k, v in x.items() if k != "draft"} for x in items]


def _on_branch_edit(clone: Path, version: str, edit, message: str = "Tate's edits", push: bool = True) -> None:
    """Tate checks out origin's release/next, edits the release file, commits and (by default) pushes."""
    _git(clone, "switch", "-q", "-C", "release/next", "origin/release/next")
    path = f"releases/{version}.yaml"
    doc = yaml.safe_load((clone / path).read_text())
    files = edit(doc) or {path: yaml.safe_dump(doc, sort_keys=False)}
    if path not in files:
        _git(clone, "rm", "-q", path)
    _commit(clone, files, message)
    if push:
        _git(clone, "push", "-q", "--force", "origin", "release/next")


class FakeGitHub:
    def __init__(self, open_pr=None):
        self.open_pr = open_pr
        self.calls: list = []

    def open_release_pr(self):
        return self.open_pr

    def create_pr(self, title, body, reviewer):
        self.calls.append(("create_pr", title, body, reviewer))
        self.open_pr = {"number": 7, "url": PR_URL, "title": title, "body": body}
        return PR_URL

    def edit_pr(self, number, title, body):
        self.calls.append(("edit_pr", number, title, body))

    def create_release(self, tag, title, notes, prerelease):
        self.calls.append(("create_release", tag, title, notes, prerelease))
        return RELEASE_URL


@pytest.fixture(autouse=True)
def no_slack(monkeypatch):
    for var in ("SLACK_RELEASE_WEBHOOK", "RELEASE_REMINDER", "RELEASE_REVIEWER"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def git_env(tmp_path, monkeypatch):
    """Isolate git from the developer's config (signing, identity rules)."""
    cfg = tmp_path / "gitconfig"
    cfg.write_text("[user]\n\tname = Test\n\temail = test@example.com\n[init]\n\tdefaultBranch = main\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.fixture
def upstream(tmp_path, git_env):
    """An upstream tagged v0.6.0-beta with nothing on main since."""
    up = tmp_path / "upstream"
    up.mkdir()
    _git(up, "init", "-q")
    _commit(up, {
        "pyproject.toml": '[project]\nname = "demo"\nversion = "0.6.0"\n',
        "CHANGELOG.md": _changelog(),
        "releases/unreleased.yaml": _unreleased(),
        "releases/0.6.0-beta.yaml": "version: 0.6.0-beta\ndate: 2026-10-23\nhighlights: []\n",
        "fetchers/demo/alpha/fetcher.yaml": _fetcher("demo_alpha", "0.1.0"),
        "fetchers/demo/beta/fetcher.yaml": _fetcher("demo_beta", "0.1.0"),
        "fetchers/demo/gamma/fetcher.yaml": _fetcher("demo_gamma", "0.1.0"),
        "fetchers/_template/fetcher.yaml": _fetcher("template", "0.1.0"),
    }, "v0.6")
    _git(up, "tag", "-a", "v0.6.0-beta", "-m", "v0.6.0-beta")
    return up


@pytest.fixture
def clone(tmp_path, upstream):
    c = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", str(upstream), str(c))
    return c


@pytest.fixture
def week(upstream):
    """A week of work on upstream main: two fetchers move, a row and a CHANGELOG entry land."""
    _commit(upstream, {"fetchers/demo/alpha/fetcher.yaml": _fetcher("demo_alpha", "0.2.0")},
            "demo_alpha: reads more rows")
    _commit(upstream, {"fetchers/demo/beta/fetcher.yaml": _fetcher("demo_beta", "0.1.1"),
                       "fetchers/_template/fetcher.yaml": _fetcher("template", "0.2.0"),
                       "CHANGELOG.md": _changelog("**`demo_beta` 0.1.1: counts every image.**"),
                       "releases/unreleased.yaml": _unreleased(NEW_ROW, FIX_ROW)}, "chore: bump beta")
    return upstream


def _draft(clone, gh, notes, **kw):
    kw.setdefault("today", TODAY)
    return release.draft(clone, base="origin/main", gh=gh, notify=lambda t, u: notes.append((t, u)), **kw)


# --------------------------------------------------------------------------- #
# draft
# --------------------------------------------------------------------------- #

def test_nothing_to_release_opens_nothing(clone):
    gh, notes = FakeGitHub(), []
    assert _draft(clone, gh, notes, push=False) == "nothing"
    assert gh.calls == [] and notes == []
    assert _git(clone, "branch", "--list", "release/next") == ""


def test_first_draft_builds_the_branch_and_opens_the_pr(clone, week, upstream):
    gh, notes = FakeGitHub(), []
    assert _draft(clone, gh, notes) == "opened"

    # Built beside the checkout and pushed by sha: the clone stays on main, with no local release/next.
    assert _git(clone, "branch", "--show-current").strip() == "main"
    assert _git(clone, "status", "--porcelain") == ""
    assert _git(clone, "worktree", "list").count("\n") == 1
    assert _git(clone, "branch", "--list", "release/next") == ""
    assert _sha(upstream, "release/next") == _sha(clone, "origin/release/next")

    doc = _release_file(clone, "0.7.0-beta")
    assert doc["version"] == "0.7.0-beta" and str(doc["date"]) == TODAY
    assert [h["title"] for h in doc["highlights"]] == ["Sprockets for all", "Uploads retry on a timeout"]
    assert {(f["name"], f["version"], f["note"]) for f in doc["fetchers"]} == {
        ("demo_alpha", "0.2.0", "reads more rows"),
        ("demo_beta", "0.1.1", "counts every image"),
    }
    assert all(x["draft"] is True for x in doc["highlights"] + doc["fetchers"])
    assert "\ndate: 2026-11-26\n" in _show(clone, "releases/0.7.0-beta.yaml")

    changelog = _show(clone, "CHANGELOG.md")
    assert "## [Unreleased]\n\n## [0.7.0-beta] - 2026-11-26\n" in changelog
    assert f"[0.7.0-beta]: {LINK}/v0.6.0-beta...v0.7.0-beta" in changelog
    assert 'version = "0.7.0"' in _show(clone, "pyproject.toml")
    assert _show(clone, "releases/unreleased.yaml") == UNRELEASED_HEADER + "version: unreleased\nhighlights: []\n"

    message = _git(clone, "log", "-1", "--format=%B", "origin/release/next")
    assert message.startswith("chore(release): v0.7.0-beta")
    assert f"Release-Base: {_sha(clone, 'origin/main')}" in message

    [(name, title, body, reviewer)] = gh.calls
    assert (name, title, reviewer) == ("create_pr", "Release v0.7.0-beta", "21tmccauley")
    assert "2 fetcher lines" in body and "docs/releasing_guide.md" in body
    assert notes == [("v0.7.0-beta is ready to review: 2 fetcher lines, 2 new rows to read.", PR_URL)]


def test_draft_notes_use_the_fetcher_directory_name(clone, upstream):
    _commit(upstream, {"fetchers/demo/alpha/fetcher.yaml": _fetcher("demo_alpha", "0.1.1")},
            "alpha: retries when throttled")
    _draft(clone, FakeGitHub(), [])
    [line] = _release_file(clone, "0.6.1-beta")["fetchers"]
    assert line["note"] == "retries when throttled"


def test_no_push_is_a_dry_run(clone, week, upstream, capsys):
    gh, notes = FakeGitHub(), []
    assert _draft(clone, gh, notes, push=False) == "opened"
    assert gh.calls == [] and notes == []
    out = capsys.readouterr().out
    assert "Would open pull request: Release v0.7.0-beta" in out
    assert "Would notify: v0.7.0-beta is ready to review" in out
    built = re.search(r"git show ([0-9a-f]{40}):releases/0.7.0-beta.yaml", out)[1]
    assert _release_file(clone, "0.7.0-beta", ref=built)["version"] == "0.7.0-beta"
    assert _git(clone, "branch", "--list", "release/next") == ""
    assert _git(upstream, "branch", "--list", "release/next") == ""


def test_draft_leaves_the_checkout_and_local_branches_alone(clone, week, upstream):
    gh = FakeGitHub()
    _draft(clone, gh, [])
    first = _sha(upstream, "release/next")
    # Tate has release/next checked out with an amended, unpushed draft commit and a dirty file.
    _git(clone, "switch", "-q", "-C", "release/next", "origin/release/next")
    path = clone / "releases" / "0.7.0-beta.yaml"
    path.write_text(path.read_text().replace("reads more rows", "Reads every row"))
    _git(clone, "commit", "-q", "-a", "--amend", "--no-edit")
    amended = _sha(clone, "release/next")
    (clone / "CHANGELOG.md").write_text("half an edit\n")
    status = _git(clone, "status", "--porcelain")
    _commit(upstream, {"docs/other.md": "main moved\n"}, "docs: other")

    assert _draft(clone, gh, []) == "rebuilt"

    assert _git(clone, "branch", "--show-current").strip() == "release/next"
    assert _sha(clone, "release/next") == amended
    assert (clone / "CHANGELOG.md").read_text() == "half an edit\n"
    assert _git(clone, "status", "--porcelain") == status
    rebuilt = _sha(upstream, "release/next")
    assert rebuilt not in (first, amended)
    assert _sha(upstream, "release/next^") == _sha(upstream, "main")


def test_draft_refuses_a_version_with_a_v(clone, week):
    with pytest.raises(release.ReleaseError, match="--version"):
        _draft(clone, FakeGitHub(), [], version="v0.7.0")


def test_draft_names_a_broken_unreleased_file(clone, upstream):
    _commit(upstream, {"releases/unreleased.yaml": "highlights: [\n"}, "broken")
    with pytest.raises(release.ReleaseError, match="releases/unreleased.yaml"):
        _draft(clone, FakeGitHub(), [])


def test_second_draft_with_unchanged_main_changes_nothing(clone, week, upstream):
    gh, notes = FakeGitHub(), []
    _draft(clone, gh, notes)
    tip = _sha(upstream, "release/next")
    assert _draft(clone, gh, notes) == "unchanged"
    assert _sha(upstream, "release/next") == tip == _sha(clone, "origin/release/next")
    assert [c[0] for c in gh.calls] == ["create_pr"] and len(notes) == 1


def test_rebuild_keeps_tates_edits_and_adds_new_rows(clone, week, upstream):
    gh, notes = FakeGitHub(), []
    _draft(clone, gh, notes)

    # Tate reads everything, rewrites one note and deletes the fix row.
    def edit(doc):
        doc["highlights"] = _unmarked([h for h in doc["highlights"] if h["tag"] != "fix"])
        doc["fetchers"] = _unmarked(doc["fetchers"])
        doc["fetchers"][0]["note"] = "Reads every row, not only the first page"
    _on_branch_edit(clone, "0.7.0-beta", edit)

    # main moves on: a new row and a third fetcher.
    later_row = {"tag": "cli", "title": "paramify tidy cleans up"}
    _commit(upstream, {"releases/unreleased.yaml": _unreleased(NEW_ROW, FIX_ROW, later_row),
                       "fetchers/demo/gamma/fetcher.yaml": _fetcher("demo_gamma", "0.1.1")},
            "demo_gamma: handles empty pages")

    assert _draft(clone, gh, notes) == "rebuilt"

    doc = _release_file(clone, "0.7.0-beta")
    assert [h["title"] for h in doc["highlights"]] == ["Sprockets for all", "paramify tidy cleans up"]
    lines = {f["name"]: f for f in doc["fetchers"]}
    assert lines["demo_alpha"]["note"] == "Reads every row, not only the first page"
    assert lines["demo_gamma"]["note"] == "handles empty pages"
    assert _marked(doc) == ["paramify tidy cleans up", "demo_gamma"]
    assert f"Release-Base: {_sha(upstream, 'main')}" in _git(clone, "log", "-1", "--format=%B", "origin/release/next")
    assert _sha(upstream, "release/next") == _sha(clone, "origin/release/next")
    assert [c[0] for c in gh.calls] == ["create_pr", "edit_pr"]
    assert notes[-1] == ("v0.7.0-beta has more to read: 1 fetcher line, 1 new row to read.", PR_URL)


def test_rebuild_with_nothing_new_to_read_sends_no_dm(clone, week, upstream):
    gh, notes = FakeGitHub(), []
    _draft(clone, gh, notes)
    _commit(upstream, {"docs/other.md": "main moved\n"}, "docs: other")
    assert _draft(clone, gh, notes) == "rebuilt"
    assert [c[0] for c in gh.calls] == ["create_pr", "edit_pr"]  # the body names the new base
    assert len(notes) == 1


def test_rebuild_without_a_trailer_uses_the_rows_in_the_file(clone, week, upstream):
    gh, notes = FakeGitHub(), []
    _draft(clone, gh, notes)
    # Someone rewrote the branch by hand: no Release-Base trailer anywhere.
    _git(clone, "switch", "-q", "-C", "release/next", "origin/release/next")
    _git(clone, "commit", "-q", "--amend", "-m", "chore(release): v0.7.0-beta")
    _git(clone, "push", "-q", "--force", "origin", "release/next")
    _on_branch_edit(clone, "0.7.0-beta", lambda d: d.update(highlights=_unmarked(d["highlights"]),
                                                            fetchers=_unmarked(d["fetchers"])))
    later_row = {"tag": "cli", "title": "paramify tidy cleans up"}
    _commit(upstream, {"releases/unreleased.yaml": _unreleased(NEW_ROW, FIX_ROW, later_row)}, "notes")

    assert _draft(clone, gh, notes) == "rebuilt"
    doc = _release_file(clone, "0.7.0-beta")
    assert [h["title"] for h in doc["highlights"]] == [
        "Sprockets for all", "Uploads retry on a timeout", "paramify tidy cleans up"]
    assert _marked(doc) == ["paramify tidy cleans up"]


def test_rebuild_keeps_a_suffix_dropped_by_hand(clone, week, upstream):
    gh, notes = FakeGitHub(), []
    _draft(clone, gh, notes)

    def drop_suffix(doc):
        doc["version"] = "0.7.0"
        return {"releases/0.7.0.yaml": yaml.safe_dump(doc, sort_keys=False)}
    _on_branch_edit(clone, "0.7.0-beta", drop_suffix)
    _commit(upstream, {"docs/other.md": "main moved\n"}, "docs: other")

    assert _draft(clone, gh, notes) == "rebuilt"
    assert _release_file(clone, "0.7.0")["version"] == "0.7.0"
    assert not _exists(clone, "releases/0.7.0-beta.yaml")
    assert gh.calls[-1][:3] == ("edit_pr", 7, "Release v0.7.0")


def test_rebuild_keeps_a_version_forced_higher_by_hand(clone, week, upstream):
    gh, notes = FakeGitHub(), []
    _draft(clone, gh, notes)

    def force(doc):
        doc["version"] = "1.0.0"
        return {"releases/1.0.0.yaml": yaml.safe_dump(doc, sort_keys=False)}
    _on_branch_edit(clone, "0.7.0-beta", force)
    _commit(upstream, {"docs/other.md": "main moved\n"}, "docs: other")

    assert _draft(clone, gh, notes) == "rebuilt"
    assert _release_file(clone, "1.0.0")["version"] == "1.0.0"
    assert not _exists(clone, "releases/0.7.0-beta.yaml")
    assert gh.calls[-1][:3] == ("edit_pr", 7, "Release v1.0.0")
    assert release.check(clone, "origin/release/next") == []


def test_draft_refuses_while_a_merged_release_has_no_tag(clone, week, upstream):
    head = _reviewed_branch(clone)
    _git(clone, "push", "-q", "--force", "origin", f"{head}:refs/heads/release/next")
    _git(upstream, "merge", "-q", "--no-ff", "-m", "Merge release/next", "release/next")
    main_before = _sha(upstream, "main")
    _commit(upstream, {"fetchers/demo/gamma/fetcher.yaml": _fetcher("demo_gamma", "0.1.1")}, "demo_gamma: more")

    gh, notes = FakeGitHub({"number": 8, "url": PR_URL, "title": "x", "body": "y"}), []
    with pytest.raises(release.ReleaseError, match="v0.7.0-beta is merged but not tagged; run publish"):
        _draft(clone, gh, notes)
    assert gh.calls == [] and len(notes) == 1 and "v0.7.0-beta is merged but not tagged" in notes[0][0]
    assert _sha(upstream, "release/next") == head  # the branch was not rebuilt
    assert _git(clone, "show", f"{main_before}:releases/0.7.0-beta.yaml")  # the release file is on main


def test_rebuild_that_changes_the_version_renames_the_file_and_retitles_the_pr(clone, upstream):
    _commit(upstream, {"fetchers/demo/alpha/fetcher.yaml": _fetcher("demo_alpha", "0.1.1")}, "demo_alpha: fix")
    gh, notes = FakeGitHub(), []
    _draft(clone, gh, notes)
    assert _exists(clone, "releases/0.6.1-beta.yaml")

    _commit(upstream, {"releases/unreleased.yaml": _unreleased(BREAKING_ROW)}, "notes: breaking")
    assert _draft(clone, gh, notes) == "rebuilt"

    assert not _exists(clone, "releases/0.6.1-beta.yaml")
    assert _marked(_release_file(clone, "0.7.0-beta")) == ["gamma renames a field", "demo_alpha"]
    assert gh.calls[-1][:3] == ("edit_pr", 7, "Release v0.7.0-beta")
    assert notes[-1] == ("v0.6.1-beta is now v0.7.0-beta: 1 fetcher line, 1 breaking row to read.", PR_URL)


def test_thursday_run_with_an_open_pr_also_reminds(clone, week):
    gh, notes = FakeGitHub(), []
    _draft(clone, gh, notes)
    assert _draft(clone, gh, notes, reminder=True) == "unchanged"
    assert notes[-1] == ("v0.7.0-beta is still waiting for you.", PR_URL)


def test_a_branch_deleted_upstream_does_not_block_the_next_draft(clone, week, upstream):
    gh = FakeGitHub()
    _draft(clone, gh, [])
    gh.open_pr = None  # the PR was closed and its branch deleted
    _git(upstream, "branch", "-q", "-D", "release/next")
    assert _draft(clone, gh, []) == "opened"
    assert _sha(upstream, "release/next") == _sha(clone, "origin/release/next")


# --------------------------------------------------------------------------- #
# check
# --------------------------------------------------------------------------- #

def test_check_names_a_missing_line_and_a_wrong_version(clone, week):
    assert release.check(clone) == []  # main: no release file without a tag
    _draft(clone, FakeGitHub(), [])
    _on_branch_edit(clone, "0.7.0-beta", lambda d: d.update(
        version="0.6.1-beta", fetchers=[f for f in d["fetchers"] if f["name"] != "demo_alpha"]), push=False)

    problems = release.check(clone)
    assert "demo_alpha 0.2.0 has no fetcher line" in problems
    assert any(p.startswith("expected 0.7.0-beta") and p.endswith("found 0.6.1-beta") for p in problems)
    assert len(problems) == 2


# --------------------------------------------------------------------------- #
# publish
# --------------------------------------------------------------------------- #

def _reviewed_branch(clone) -> str:
    """Draft, then remove every mark as Tate would; returns the branch tip."""
    _draft(clone, FakeGitHub(), [])
    _on_branch_edit(clone, "0.7.0-beta", lambda d: {"releases/0.7.0-beta.yaml": release.release_notes.dump_release(
        {**d, "highlights": _unmarked(d["highlights"]), "fetchers": _unmarked(d["fetchers"])})}, "reviewed", push=False)
    return _sha(clone)


def _upstream_tag(upstream: Path, tag: str) -> str:
    return _git(upstream, "rev-parse", f"{tag}^{{commit}}").strip()


def test_publish_refuses_a_draft(clone, week, upstream):
    _draft(clone, FakeGitHub(), [])
    head = _sha(clone, "origin/release/next")
    _git(clone, "switch", "-q", "-C", "main", "origin/main")
    _git(clone, "merge", "-q", "--no-ff", "-m", "merge", head)
    gh, notes = FakeGitHub(), []
    with pytest.raises(release.ReleaseError, match="draft"):
        release.publish(clone, head_sha=head, merge_sha=_sha(clone), gh=gh, notify=lambda t, u: notes.append(t))
    assert gh.calls == [] and len(notes) == 1 and "draft" in notes[0]
    assert _git(clone, "tag", "-l", "v0.7.0-beta") == ""


def test_publish_tags_the_branch_tip_after_a_merge_commit(clone, week, upstream):
    head = _reviewed_branch(clone)
    _git(clone, "switch", "-q", "-C", "main", "origin/main")
    _commit(clone, {"docs/other.md": "main moved\n"}, "other work")
    _git(clone, "merge", "-q", "--no-ff", "-m", "merge", "release/next")
    gh, notes = FakeGitHub(), []
    tag = release.publish(clone, head_sha=head, merge_sha=_sha(clone), gh=gh,
                          notify=lambda t, u: notes.append((t, u)))
    assert tag == "v0.7.0-beta"
    assert _upstream_tag(upstream, tag) == head
    assert _git(clone, "cat-file", "-t", tag).strip() == "tag"  # annotated
    [(name, rtag, title, body, prerelease)] = gh.calls
    assert (name, rtag, title, prerelease) == ("create_release", "v0.7.0-beta", "v0.7.0-beta", True)
    assert "## New" in body and "`demo_alpha` 0.2.0: reads more rows" in body
    assert notes == [("v0.7.0-beta is out.", RELEASE_URL)]


def test_publish_tags_a_squash_with_the_same_tree(clone, week, upstream):
    head = _reviewed_branch(clone)
    _git(clone, "switch", "-q", "-C", "main", "origin/main")
    _git(clone, "merge", "-q", "--squash", "release/next")
    _git(clone, "commit", "-q", "-m", "Release v0.7.0-beta (#7)")
    merge = _sha(clone)
    release.publish(clone, head_sha=head, merge_sha=merge, gh=FakeGitHub(), notify=lambda t, u: None)
    assert _upstream_tag(upstream, "v0.7.0-beta") == merge


def test_publish_refuses_a_squash_with_another_tree(clone, week, upstream):
    head = _reviewed_branch(clone)
    _git(clone, "switch", "-q", "-C", "main", "origin/main")
    _commit(clone, {"docs/other.md": "main moved\n"}, "other work")
    _git(clone, "merge", "-q", "--squash", "release/next")
    _git(clone, "commit", "-q", "-m", "Release v0.7.0-beta (#7)")
    gh, notes = FakeGitHub(), []
    with pytest.raises(release.ReleaseError, match="tree"):
        release.publish(clone, head_sha=head, merge_sha=_sha(clone), gh=gh, notify=lambda t, u: notes.append(t))
    assert gh.calls == [] and len(notes) == 1
    assert _git(clone, "tag", "-l", "v0.7.0-beta") == ""


# --------------------------------------------------------------------------- #
# release body and notifications
# --------------------------------------------------------------------------- #

def test_render_release_body_orders_sections_and_skips_empty_ones():
    doc = {"version": "0.7.0-beta", "highlights": [NEW_ROW, BREAKING_ROW, {"tag": "fix", "title": "Plain"}],
           "fetchers": [{"name": "demo_alpha", "version": "0.2.0", "note": "Reads more"}]}
    body = release.render_release_body(doc, "### Added\n\n- **Sprockets.**\n")
    assert body.index("## Breaking") < body.index("## New") < body.index("## Fetchers") < body.index("<details>")
    assert "gamma renames a field" in body and "Fix: Read the new field" in body
    assert "Sprockets for all — " not in body and "Sprockets for all" in body and "Plain" in body
    assert "- `demo_alpha` 0.2.0: Reads more" in body
    assert "<summary>Full changelog</summary>" in body and "- **Sprockets.**" in body

    only_new = release.render_release_body({"highlights": [dict(NEW_ROW, detail="Why")], "fetchers": []}, "")
    assert "## Breaking" not in only_new and "## Fetchers" not in only_new and "<details>" not in only_new
    assert "Sprockets for all — Why" in only_new


def test_notify_without_a_webhook_prints(capsys):
    release.notify("v0.7.0-beta is out.", RELEASE_URL)
    assert capsys.readouterr().out == f"slack: v0.7.0-beta is out. {RELEASE_URL}\n"


def test_notify_failure_sends_the_run_link(monkeypatch):
    received = []

    class Hook(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Hook)
    server.timeout = 5
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    monkeypatch.setenv("SLACK_RELEASE_WEBHOOK", f"http://127.0.0.1:{server.server_port}/hook")
    run = "https://github.com/paramify/paramify-fetchers/actions/runs/1"
    try:
        assert release.main(["notify-failure", "--url", run]) == 0
    finally:
        thread.join(5)
        server.server_close()
    assert received == [{"text": "The weekly release job failed.", "url": run}]


def test_a_webhook_that_is_not_a_url_is_printed_and_does_not_raise(monkeypatch, capsys):
    monkeypatch.setenv("SLACK_RELEASE_WEBHOOK", "not-a-url")
    release.notify("hello", "https://example.com")
    assert "slack: could not send" in capsys.readouterr().out


def test_a_failed_post_is_printed_and_does_not_raise(monkeypatch, capsys):
    monkeypatch.setenv("SLACK_RELEASE_WEBHOOK", "http://127.0.0.1:9/nothing-listens")
    release.notify("hello", "https://example.com")
    assert "slack: could not send" in capsys.readouterr().out


def test_publish_refuses_without_a_release_file(clone, week):
    main = _sha(clone, "origin/main")
    notes = []
    with pytest.raises(release.ReleaseError, match="no release file"):
        release.publish(clone, head_sha=main, merge_sha=main, gh=FakeGitHub(), notify=lambda t, u: notes.append(t))
    assert len(notes) == 1


def test_publish_refuses_two_release_files(clone, week):
    one = "version: 0.7.0-beta\nhighlights: []\n"
    _commit(clone, {"releases/0.7.0-beta.yaml": one, "releases/0.8.0-beta.yaml": one.replace("0.7", "0.8")}, "two")
    with pytest.raises(release.ReleaseError, match="keep one"):
        release.publish(clone, head_sha=_sha(clone), merge_sha=_sha(clone), gh=FakeGitHub(), notify=lambda t, u: None)


def test_publish_names_a_head_sha_this_clone_lacks(clone, week):
    with pytest.raises(release.ReleaseError, match="not in this clone"):
        release.publish(clone, head_sha="0" * 40, merge_sha=_sha(clone), gh=FakeGitHub(), notify=lambda t, u: None)


def test_open_release_pr_ignores_a_pr_from_a_fork(tmp_path, monkeypatch):
    prs = [{"number": 3, "url": "fork", "title": "t", "body": "", "isCrossRepository": True},
           {"number": 4, "url": PR_URL, "title": "t", "body": "", "isCrossRepository": False}]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "gh").write_text(f"#!/bin/sh\ncat <<'EOF'\n{json.dumps(prs)}\nEOF\n")
    (bin_dir / "gh").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    assert release.GitHub(tmp_path).open_release_pr()["number"] == 4


def test_a_garbled_webhook_reply_is_printed_and_does_not_raise(monkeypatch, capsys):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def garble():
        conn, _ = listener.accept()
        conn.recv(65536)
        conn.sendall(b"NOT HTTP\r\n\r\n")
        conn.close()

    thread = threading.Thread(target=garble, daemon=True)
    thread.start()
    monkeypatch.setenv("SLACK_RELEASE_WEBHOOK", f"http://127.0.0.1:{listener.getsockname()[1]}/hook")
    try:
        release.notify("hello", "https://example.com")
    finally:
        thread.join(5)
        listener.close()
    assert "slack: could not send" in capsys.readouterr().out
