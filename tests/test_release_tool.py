"""tools/release.py against throwaway git repos with a real v0.6.0-beta tag.

The fixture builds an "upstream" repo (the stand-in for GitHub) with a
CHANGELOG, a pyproject, the release files and three fetchers, tags it
v0.6.0-beta, and clones it. `draft` fetches from and pushes to that upstream.
`gh` is a FakeGitHub that records calls, and `notify` appends to a list.
"""

from __future__ import annotations

import importlib.util
import json
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


def _release_file(repo: Path, version: str) -> dict:
    return yaml.safe_load((repo / "releases" / f"{version}.yaml").read_text())


def _marked(doc: dict) -> list:
    return [x.get("title") or x.get("name") for x in doc["highlights"] + doc["fetchers"] if x.get("draft")]


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


def test_first_draft_builds_the_branch_and_opens_the_pr(clone, week):
    gh, notes = FakeGitHub(), []
    assert _draft(clone, gh, notes, push=False) == "opened"

    assert _git(clone, "branch", "--show-current").strip() == "release/next"
    doc = _release_file(clone, "0.7.0-beta")
    assert doc["version"] == "0.7.0-beta" and str(doc["date"]) == TODAY
    assert [h["title"] for h in doc["highlights"]] == ["Sprockets for all", "Uploads retry on a timeout"]
    assert {(f["name"], f["version"], f["note"]) for f in doc["fetchers"]} == {
        ("demo_alpha", "0.2.0", "reads more rows"),
        ("demo_beta", "0.1.1", "counts every image"),
    }
    assert all(x["draft"] is True for x in doc["highlights"] + doc["fetchers"])
    assert "\ndate: 2026-11-26\n" in (clone / "releases" / "0.7.0-beta.yaml").read_text()

    changelog = (clone / "CHANGELOG.md").read_text()
    assert "## [Unreleased]\n\n## [0.7.0-beta] - 2026-11-26\n" in changelog
    assert f"[0.7.0-beta]: {LINK}/v0.6.0-beta...v0.7.0-beta" in changelog
    assert 'version = "0.7.0"' in (clone / "pyproject.toml").read_text()
    unreleased = (clone / "releases" / "unreleased.yaml").read_text()
    assert unreleased == UNRELEASED_HEADER + "version: unreleased\nhighlights: []\n"

    message = _git(clone, "log", "-1", "--format=%B")
    assert message.startswith("chore(release): v0.7.0-beta")
    assert f"Release-Base: {_sha(clone, 'origin/main')}" in message
    assert _git(clone, "status", "--porcelain") == ""

    [(name, title, body, reviewer)] = gh.calls
    assert (name, title, reviewer) == ("create_pr", "Release v0.7.0-beta", "21tmccauley")
    assert "2 fetcher lines" in body and "docs/releasing_guide.md" in body
    assert notes == [("v0.7.0-beta is ready to review: 2 fetcher lines, 2 new rows to read.", PR_URL)]


def test_rebuild_keeps_tates_edits_and_adds_new_rows(clone, week, upstream):
    gh, notes = FakeGitHub(), []
    _draft(clone, gh, notes)

    # Tate reads everything, rewrites one note and deletes the fix row.
    doc = _release_file(clone, "0.7.0-beta")
    doc["highlights"] = [{k: v for k, v in h.items() if k != "draft"} for h in doc["highlights"]
                         if h["tag"] != "fix"]
    doc["fetchers"] = [{k: v for k, v in f.items() if k != "draft"} for f in doc["fetchers"]]
    doc["fetchers"][0]["note"] = "Reads every row, not only the first page"
    _commit(clone, {"releases/0.7.0-beta.yaml": yaml.safe_dump(doc, sort_keys=False)}, "Tate's edits")
    _git(clone, "push", "-q", "origin", "release/next")

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
    assert f"Release-Base: {_sha(upstream, 'main')}" in _git(clone, "log", "-1", "--format=%B")
    assert _sha(upstream, "release/next") == _sha(clone, "HEAD")
    assert [c[0] for c in gh.calls] == ["create_pr", "edit_pr"]
    assert notes[-1] == ("v0.7.0-beta has more to read: 1 fetcher line, 1 new row to read.", PR_URL)


def test_rebuild_that_changes_the_version_renames_the_file_and_retitles_the_pr(clone, upstream):
    _commit(upstream, {"fetchers/demo/alpha/fetcher.yaml": _fetcher("demo_alpha", "0.1.1")}, "demo_alpha: fix")
    gh, notes = FakeGitHub(), []
    _draft(clone, gh, notes)
    assert (clone / "releases" / "0.6.1-beta.yaml").exists()

    _commit(upstream, {"releases/unreleased.yaml": _unreleased(BREAKING_ROW)}, "notes: breaking")
    assert _draft(clone, gh, notes) == "rebuilt"

    assert not (clone / "releases" / "0.6.1-beta.yaml").exists()
    assert _marked(_release_file(clone, "0.7.0-beta")) == ["gamma renames a field", "demo_alpha"]
    assert gh.calls[-1][:3] == ("edit_pr", 7, "Release v0.7.0-beta")
    assert notes[-1] == ("v0.6.1-beta is now v0.7.0-beta: 1 fetcher line, 1 breaking row to read.", PR_URL)


def test_thursday_run_with_an_open_pr_also_reminds(clone, week):
    gh, notes = FakeGitHub(), []
    _draft(clone, gh, notes)
    _draft(clone, gh, notes, reminder=True)
    assert notes[-1] == ("v0.7.0-beta is still waiting for you.", PR_URL)


# --------------------------------------------------------------------------- #
# check
# --------------------------------------------------------------------------- #

def test_check_names_a_missing_line_and_a_wrong_version(clone, week):
    assert release.check(clone) == []  # main: no release file without a tag
    _draft(clone, FakeGitHub(), [], push=False)
    doc = _release_file(clone, "0.7.0-beta")
    doc["version"] = "0.6.1-beta"
    doc["fetchers"] = [f for f in doc["fetchers"] if f["name"] != "demo_alpha"]
    _commit(clone, {"releases/0.7.0-beta.yaml": yaml.safe_dump(doc, sort_keys=False)}, "edits")

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
    doc = _release_file(clone, "0.7.0-beta")
    for x in doc["highlights"] + doc["fetchers"]:
        x.pop("draft")
    _commit(clone, {"releases/0.7.0-beta.yaml": release.release_notes.dump_release(doc)}, "reviewed")
    return _sha(clone)


def _upstream_tag(upstream: Path, tag: str) -> str:
    return _git(upstream, "rev-parse", f"{tag}^{{commit}}").strip()


def test_publish_refuses_a_draft(clone, week, upstream):
    _draft(clone, FakeGitHub(), [])
    head = _sha(clone)
    _git(clone, "switch", "-q", "-C", "main", "origin/main")
    _git(clone, "merge", "-q", "--no-ff", "-m", "merge", "release/next")
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


def test_a_failed_post_is_printed_and_does_not_raise(monkeypatch, capsys):
    monkeypatch.setenv("SLACK_RELEASE_WEBHOOK", "http://127.0.0.1:9/nothing-listens")
    release.notify("hello", "https://example.com")
    assert "slack: could not send" in capsys.readouterr().out
