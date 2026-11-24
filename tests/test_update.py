"""`paramify update` against a throwaway git repo with real release tags.

The fixture builds an "upstream" repo with v0.1.0-beta, v0.2.0-beta (which has
a Breaking CHANGELOG entry), v0.3.0-beta (which carries a highlights file), an
archive/* tag and a commit on main past the newest tag, then clones it, so
`git fetch --tags` has a real origin. Reinstall and validate are the only
mocked pieces: they would run pip and the clone's own code.
"""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from framework import api, update_cli
from framework import update as up
from framework.cli import app

REPO_ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()

CHANGELOG = {
    "0.1.0-beta": "## [0.1.0-beta] - 2026-01-01\n\n### Added\n\n- **First release.**\n",
    "0.2.0-beta": (
        "## [0.2.0-beta] - 2026-02-01\n\n### Breaking\n\n"
        "- **`old_flag` is gone.** Use `new_flag` instead,\n  which does the same.\n\n"
        "### Added\n\n- **Widgets.**\n"
    ),
    "0.3.0-beta": "## [0.3.0-beta] - 2026-03-01\n\n### Added\n\n- **Gadgets.**\n",
}

HIGHLIGHTS_030 = """\
version: 0.3.0-beta
date: 2026-03-01
highlights:
  - tag: new
    title: Gadgets for everyone
    detail: A longer line about gadgets
    try: paramify catalog
  - tag: fetcher
    title: demo_alpha reads more
    fetchers: [demo_alpha]
  - tag: tui
    title: A nicer screen
"""


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def _commit(repo: Path, files: dict, message: str) -> None:
    for rel, text in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _changelog(*versions: str) -> str:
    return "# Changelog\n\n## [Unreleased]\n\n" + "\n".join(CHANGELOG[v] for v in reversed(versions))


@pytest.fixture
def git_env(tmp_path, monkeypatch):
    """Isolate git from the developer's config (signing, identity rules)."""
    cfg = tmp_path / "gitconfig"
    cfg.write_text("[user]\n\tname = Test\n\temail = test@example.com\n[init]\n\tdefaultBranch = main\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for var in ("PARAMIFY_CONTAINER", "PARAMIFY_NO_UPDATE_CHECK", "NO_COLOR", "FORCE_COLOR"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def repo(tmp_path, git_env, monkeypatch):
    """A clone checked out at v0.1.0-beta whose origin has every tag."""
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    _git(upstream, "init", "-q")
    base = {
        "framework/__init__.py": "",
        "fetchers/demo/alpha/fetcher.yaml": "name: demo_alpha\n",
        "fetchers/demo/beta/fetcher.yaml": "name: demo_beta\n",
        ".gitignore": ".paramify/\nmanifests/\n",
    }
    _commit(upstream, {**base, "CHANGELOG.md": _changelog("0.1.0-beta")}, "v0.1")
    _git(upstream, "tag", "v0.1.0-beta")
    _git(upstream, "tag", "archive/feat/old-idea")
    _commit(upstream, {"CHANGELOG.md": _changelog("0.1.0-beta", "0.2.0-beta"),
                       "fetchers/demo/alpha/fetch.py": "# v2\n"}, "v0.2")
    _git(upstream, "tag", "v0.2.0-beta")
    _commit(upstream, {"CHANGELOG.md": _changelog("0.1.0-beta", "0.2.0-beta", "0.3.0-beta"),
                       "releases/0.3.0-beta.yaml": HIGHLIGHTS_030,
                       "fetchers/demo/gamma/fetcher.yaml": "name: demo_gamma\n"}, "v0.3")
    _git(upstream, "tag", "v0.3.0-beta")
    _commit(upstream, {"framework/later.py": "# unreleased\n"}, "main moves on")

    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", str(upstream), str(clone))
    _git(clone, "switch", "-q", "--detach", "v0.1.0-beta")
    monkeypatch.chdir(clone)
    return clone


@pytest.fixture
def main_repo(repo, tmp_path):
    """The same clone on main, one commit behind origin/main."""
    _git(repo, "switch", "-q", "main")
    _commit(tmp_path / "upstream", {"fetchers/demo/alpha/fetch.py": "# v3\n"}, "demo_alpha: read more rows")
    return repo


@pytest.fixture
def stubs(monkeypatch):
    """Stand-ins for the pieces that would run pip or the clone's own code."""
    calls = {"reinstall": 0, "validate": 0}
    manifests = [{"path": "/x/manifests/prod.yaml", "label": "manifests/prod.yaml",
                  "uses": ["demo_alpha"], "errors_now": []}]

    def run_validate(tree, manifest, python=None):
        calls["validate"] += 1
        return {"ok": True, "errors": [], "notes": []}

    def reinstall(root, extras, python=None):
        calls["reinstall"] += 1
        return {"ok": True, "command": ["pip"], "error": None}

    monkeypatch.setattr(up, "user_manifests", lambda root: manifests)
    monkeypatch.setattr(up, "run_validate", run_validate)
    monkeypatch.setattr(up, "reinstall", reinstall)
    return calls


def _rows(upstream: Path, rows: str, message: str = "notes") -> None:
    """Commit releases/unreleased.yaml on upstream with these highlight rows."""
    _commit(upstream, {"releases/unreleased.yaml": "version: unreleased\nhighlights:\n" + rows}, message)


BREAKS_GAMMA = "  - {tag: breaking, title: gamma renames a field, fix: read the new field, fetchers: [demo_gamma]}\n"
BREAKS_ALPHA = "  - {tag: breaking, title: alpha renames a field, fix: read the new field, fetchers: [demo_alpha]}\n"
BREAKS_ALL = "  - {tag: breaking, title: Python 3.13 is the minimum, fix: make a new venv}\n"
BREAKS_CUSTOM = "  - {tag: breaking, title: the contract changed, fix: add the block, custom_fetchers: true}\n"
NEW_ROW = "  - {tag: new, title: Sprockets for all, try: paramify catalog}\n"


def _sha(repo: Path, ref: str = "HEAD") -> str:
    return _git(repo, "rev-parse", ref).strip()


def _run(*args: str):
    result = runner.invoke(app, ["update", *args])
    try:
        doc = json.loads(result.stdout) if "--json" in args else None
    except json.JSONDecodeError:
        doc = None
    return result, doc


def _head_tag(repo: Path) -> str:
    return _git(repo, "describe", "--tags", "--match", "v[0-9]*").strip()


# --------------------------------------------------------------------------- #
# Releases and target selection
# --------------------------------------------------------------------------- #

def test_only_release_tags_are_listed(repo):
    tags = [r.tag for r in up.list_releases(repo)]
    assert tags == ["v0.1.0-beta", "v0.2.0-beta", "v0.3.0-beta"]


def test_parse_release_rejects_non_release_tags():
    assert up.parse_release("archive/feat/x") is None
    assert up.parse_release("v1.2") is None
    assert up.parse_release("main") is None
    assert up.parse_release("v1.2.3").version == "1.2.3"


def test_a_branch_follows_its_upstream(main_repo):
    up.fetch(main_repo)
    pos = up.position(main_repo)
    assert (pos["upstream"], pos["behind"]) == ("origin/main", 1)
    t = up.choose_target(main_repo, pos, up.list_releases(main_repo))
    assert (t.channel, t.ref, t.label, t.branch) == ("branch", "origin/main", "main", "main")
    assert t.sha == _git(main_repo, "rev-parse", "origin/main").strip()


def test_a_tag_follows_newer_tags(repo):
    t = up.choose_target(repo, up.position(repo), up.list_releases(repo))
    assert (t.channel, t.ref, t.label, t.branch) == ("release", "v0.3.0-beta", "0.3.0-beta", None)


def test_local_commits_no_upstream_and_detached_are_refused(main_repo):
    rel = up.list_releases(main_repo)
    _commit(main_repo, {"mine.txt": "x"}, "local work")
    with pytest.raises(up.UpdateError, match="can't fast-forward"):
        up.choose_target(main_repo, up.position(main_repo), rel)
    _git(main_repo, "switch", "-q", "-c", "scratch")
    with pytest.raises(up.UpdateError, match="does not follow a remote branch"):
        up.choose_target(main_repo, up.position(main_repo), rel)
    _git(main_repo, "switch", "-q", "--detach", "HEAD")
    with pytest.raises(up.UpdateError, match="detached commit"):
        up.choose_target(main_repo, up.position(main_repo), rel)


def test_a_tag_that_is_not_a_release_is_not_a_place_to_update_from(main_repo):
    up.fetch(main_repo)
    _git(main_repo, "tag", "v2026.11", "origin/main")       # newer than every release, but not vX.Y.Z
    _git(main_repo, "switch", "-q", "--detach", "v2026.11")
    with pytest.raises(up.UpdateError, match="detached commit"):
        up.choose_target(main_repo, up.position(main_repo), up.list_releases(main_repo))


def test_to_accepts_main_and_releases_that_carry_update(repo, tmp_path):
    rel = up.list_releases(repo)
    pos = up.position(repo)
    assert up.choose_target(repo, pos, rel, to="main").ref == "origin/main"
    with pytest.raises(up.UpdateError, match="before paramify update existed"):
        up.choose_target(repo, pos, rel, to="v0.2.0-beta")
    with pytest.raises(up.UpdateError, match="not main or a release tag"):
        up.choose_target(repo, pos, rel, to="archive/feat/old-idea")
    upstream = tmp_path / "upstream"
    _commit(upstream, {"framework/update.py": "# here\n"}, "ship update")
    _git(upstream, "tag", "v0.4.0-beta")
    up.fetch(repo)
    t = up.choose_target(repo, pos, up.list_releases(repo), to="0.4.0-beta")
    assert (t.channel, t.ref) == ("release", "v0.4.0-beta")


def test_a_branch_with_no_tags_in_reach_still_updates(main_repo):
    for tag in _git(main_repo, "tag", "-l").split():
        _git(main_repo, "tag", "-d", tag)
    pos = up.position(main_repo)
    assert pos["tag"] is None and up.describe(pos).startswith("main @ ")
    assert up.choose_target(main_repo, pos, []).channel == "branch"


def test_fetcher_reason_uses_only_subjects_that_name_the_fetcher():
    subjects = [
        "Bump azure_alert_rules to 0.3.1 above main's 0.3.0",
        "docs(azure): regenerate the readme",
        "fix(azure_alert_rules): suppression fields are null when rules weren't read",
        "azure_alert_rules 0.3.0: read processing rules",
    ]
    assert up.fetcher_reason("azure_alert_rules", subjects) == "suppression fields are null when rules weren't read"
    assert up.fetcher_reason("azure_alert_rules", subjects[3:]) == "read processing rules"
    assert up.fetcher_reason("azure_alert_rules", subjects[:2]) is None
    assert up.fetcher_reason("azure_alert", subjects) is None       # a prefix of the name is not the name


def test_fetcher_changes_carry_versions_reasons_and_counts(main_repo, tmp_path):
    upstream = tmp_path / "upstream"
    _commit(upstream, {"fetchers/demo/alpha/fetcher.yaml": "name: demo_alpha\nversion: 0.2.0\n"},
            "Bump demo_alpha to 0.2.0")
    up.fetch(main_repo)
    manifests = [{"path": "/x", "label": "manifests/prod.yaml", "uses": ["demo_alpha"], "errors_now": []}]
    with up.temp_worktree(main_repo, "origin/main") as tree:
        got = up.fetcher_changes(main_repo, tree, "origin/main", manifests)
    assert got["yours"] == [{"name": "demo_alpha", "change": "changed", "manifests": ["manifests/prod.yaml"],
                             "from": None, "to": "0.2.0", "reason": "read more rows", "more": 1}]


def test_fetcher_changes_going_back_give_no_reasons(main_repo):
    manifests = [{"path": "/x", "label": "m.yaml", "uses": ["demo_alpha"], "errors_now": []}]
    with up.temp_worktree(main_repo, "v0.1.0-beta") as tree:
        got = up.fetcher_changes(main_repo, tree, "v0.1.0-beta", manifests)
    assert [(y["name"], y["reason"], y["more"]) for y in got["yours"]] == [("demo_alpha", None, 0)]
    assert got["removed"] == ["demo_gamma"]


def test_which_breaking_rows_touch_this_clone():
    manifests = [{"label": "manifests/prod.yaml", "uses": ["okta_users", "aws_iam_users"]}]
    scoped = {"tag": "breaking", "title": "t", "fix": "f", "fetchers": ["okta_*"]}
    other = {"tag": "breaking", "title": "t", "fix": "f", "fetchers": ["wiz_*"]}
    everyone = {"tag": "breaking", "title": "t", "fix": "f"}
    custom = {"tag": "breaking", "title": "t", "fix": "f", "custom_fetchers": True}
    def why(row, local=False):
        return up.breaking_for([row], manifests, local)[0]["why"]

    assert (why(scoped), why(other), why(everyone)) == ("fetchers", None, "everyone")
    assert (why(custom, local=True), why(custom)) == ("custom", None)
    rows = up.breaking_for([{**scoped, "release": "unreleased"}, {**other, "release": "unreleased"},
                            {"tag": "cli", "title": "not breaking"}], manifests, False)
    assert [(r["touches"], r["why"]) for r in rows] == [(True, "fetchers"), (False, None)]
    assert rows[0]["manifests"] == [{"manifest": "manifests/prod.yaml", "fetchers": ["okta_users"]}]


def test_span_counts_commits_and_days(main_repo):
    up.fetch(main_repo)
    assert up.span(main_repo, "HEAD", "origin/main")["commits"] == 1
    assert up.span(main_repo, "origin/main", "HEAD") == {"commits": 0, "days": 0, "releases": 0}


def test_curated_rows_are_those_the_target_adds(repo):
    rows = up.curated_rows(repo, "v0.1.0-beta", "v0.3.0-beta")
    assert [r["title"] for r in rows] == ["Gadgets for everyone", "demo_alpha reads more", "A nicer screen"]
    assert {r["release"] for r in rows} == {"0.3.0-beta"}
    assert up.curated_rows(repo, "v0.3.0-beta", "v0.3.0-beta") == []


def test_a_row_moved_into_a_release_file_is_not_shown_again(repo, tmp_path):
    upstream = tmp_path / "upstream"
    row = "highlights:\n  - tag: new\n    title: Sprockets\n"
    _commit(upstream, {"releases/unreleased.yaml": "version: unreleased\n" + row}, "add row")
    before = _git(upstream, "rev-parse", "HEAD").strip()
    _git(upstream, "mv", "releases/unreleased.yaml", "releases/0.4.0-beta.yaml")
    _commit(upstream, {"releases/0.4.0-beta.yaml": "version: 0.4.0-beta\n" + row,
                       "releases/unreleased.yaml": "version: unreleased\nhighlights: []\n"}, "release")
    _git(repo, "fetch", "-q", "origin")
    assert [r["title"] for r in up.curated_rows(repo, "v0.3.0-beta", before)] == ["Sprockets"]
    assert up.curated_rows(repo, before, "origin/main") == []


def test_rows_for_a_release_head_already_contains_are_not_new(repo, tmp_path):
    """A highlights file written after its release was tagged: a clone past
    that tag never had the file, but it already runs that release."""
    late = "version: 0.2.0-beta\nhighlights:\n  - {tag: breaking, title: old_flag is gone, fix: use new_flag}\n"
    _commit(tmp_path / "upstream", {"releases/0.2.0-beta.yaml": late}, "backfill 0.2.0 highlights")
    _git(repo, "fetch", "-q", "origin")
    assert up.curated_rows(repo, "v0.3.0-beta", "origin/main") == []
    assert [r["title"] for r in up.curated_rows(repo, "v0.1.0-beta", "origin/main")][-1] == "old_flag is gone"


def test_a_row_with_a_field_this_code_does_not_know_is_still_read(repo, tmp_path):
    """A newer release may add a row field. Dropping its whole file would hide
    its breaking rows from an older clone and let an unattended run sail on."""
    rows = "  - {tag: breaking, title: a future break, fix: do the thing, some_future_field: [1, 2]}\n"
    _rows(tmp_path / "upstream", rows)
    _git(repo, "fetch", "-q", "origin")
    got = up.curated_rows(repo, "v0.3.0-beta", "origin/main")
    assert [(r["tag"], r["title"], r["fix"]) for r in got] == [("breaking", "a future break", "do the thing")]


def test_curated_rows_survive_a_missing_or_broken_releases_dir(repo, tmp_path):
    upstream = tmp_path / "upstream"
    _commit(upstream, {"releases/unreleased.yaml": "version: [not, a, string\n"}, "broken file")
    _git(repo, "fetch", "-q", "origin")
    assert up.curated_rows(repo, "v0.1.0-beta", "v0.2.0-beta") == []      # neither tree has releases/
    assert [r["release"] for r in up.curated_rows(repo, "v0.1.0-beta", "origin/main")] == ["0.3.0-beta"] * 3


# --------------------------------------------------------------------------- #
# The command: breaking stop, switch, rollback
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# --check
# --------------------------------------------------------------------------- #

def test_only_overlapping_local_changes_block(main_repo, tmp_path):
    up.fetch(main_repo)
    sha = _git(main_repo, "rev-parse", "origin/main").strip()
    (main_repo / "framework/later.py").write_text("# my edit\n")          # not touched by the update
    assert up.blocking_changes(main_repo, sha) == {"tracked": [], "untracked": []}
    (main_repo / "fetchers/demo/alpha/fetch.py").write_text("# mine\n")   # changed by the update
    assert up.blocking_changes(main_repo, sha)["tracked"] == ["fetchers/demo/alpha/fetch.py"]


def test_an_untracked_file_the_target_tracks_blocks(main_repo, tmp_path):
    _commit(tmp_path / "upstream", {"notes.txt": "upstream\n"}, "add notes")
    up.fetch(main_repo)
    (main_repo / "notes.txt").write_text("mine\n")
    sha = _git(main_repo, "rev-parse", "origin/main").strip()
    assert up.blocking_changes(main_repo, sha)["untracked"] == ["notes.txt"]


def test_move_fast_forwards_a_branch_and_restore_puts_it_back(main_repo):
    up.fetch(main_repo)
    pos = up.position(main_repo)
    t = up.choose_target(main_repo, pos, up.list_releases(main_repo))
    up.move(main_repo, t)
    after = up.position(main_repo)
    assert (after["branch"], after["sha"], after["behind"]) == ("main", t.sha, 0)
    up.restore(main_repo, {"branch": "main", "sha": pos["sha"]})
    back = up.position(main_repo)
    assert (back["branch"], back["sha"], back["behind"]) == ("main", pos["sha"], 1)


def test_move_detaches_at_a_release_and_restore_returns(repo):
    pos = up.position(repo)
    up.move(repo, up.choose_target(repo, pos, up.list_releases(repo)))
    assert _head_tag(repo) == "v0.3.0-beta" and up.position(repo)["branch"] is None
    up.restore(repo, {"branch": None, "sha": pos["sha"]})
    assert _head_tag(repo) == "v0.1.0-beta"


def test_to_main_creates_the_branch_when_the_clone_has_none(repo):
    _git(repo, "branch", "-D", "main")
    t = up.choose_target(repo, up.position(repo), up.list_releases(repo), to="main")
    up.move(repo, t)
    pos = up.position(repo)
    assert (pos["branch"], pos["upstream"], pos["sha"]) == ("main", "origin/main", t.sha)


def test_to_main_refuses_a_main_with_commits_of_its_own(main_repo):
    _commit(main_repo, {"mine.txt": "x"}, "local work")
    _git(main_repo, "switch", "-q", "--detach", "v0.3.0-beta")
    with pytest.raises(up.UpdateError, match="can't fast-forward"):
        up.choose_target(main_repo, up.position(main_repo), up.list_releases(main_repo), to="main")


def test_reinstall_only_when_pyproject_changed(main_repo, tmp_path):
    old = _git(main_repo, "rev-parse", "HEAD").strip()
    up.fetch(main_repo)
    mid = _git(main_repo, "rev-parse", "origin/main").strip()
    assert up.needs_reinstall(main_repo, old, mid) is False
    _commit(tmp_path / "upstream", {"pyproject.toml": "[project]\nname='x'\n"}, "deps")
    up.fetch(main_repo)
    assert up.needs_reinstall(main_repo, old, _git(main_repo, "rev-parse", "origin/main").strip()) is True


def test_update_on_main_fast_forwards_and_skips_the_reinstall(main_repo, stubs):
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 0, result.stdout
    assert (doc["channel"], doc["target"]["label"], doc["span"]["commits"]) == ("branch", "main", 1)
    assert doc["switched"] and doc["reinstall"]["skipped"] and stubs["reinstall"] == 0
    assert doc["fetchers"]["yours"][0]["reason"] == "read more rows"
    assert _git(main_repo, "status", "-sb").startswith("## main...origin/main\n")
    assert up.read_state(main_repo)["previous"]["branch"] == "main"


def test_update_on_a_tag_moves_to_the_newest_release(repo, stubs):
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 0, result.stdout
    assert (doc["channel"], doc["target"]["label"], doc["version"]) == ("release", "0.3.0-beta", "0.3.0-beta")
    assert [h["title"] for h in doc["highlights"]] == ["Gadgets for everyone", "demo_alpha reads more", "A nicer screen"]
    assert _head_tag(repo) == "v0.3.0-beta"
    assert up.read_state(repo)["previous"]["describe"] == "0.1.0-beta"  # what --rollback names


def test_nothing_to_do_when_the_branch_is_current(main_repo, stubs):
    assert _run("--yes", "--json")[0].exit_code == 0
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 0 and doc["up_to_date"] and not doc.get("switched")
    assert "Nothing to do" in runner.invoke(app, ["update"]).stdout


def test_json_without_yes_plans_but_does_not_switch(main_repo, stubs):
    before = _sha(main_repo)
    result, doc = _run("--json")
    assert result.exit_code == 1 and "pass --yes" in doc["errors"][0]
    assert _sha(main_repo) == before and not doc.get("switched")
    assert {"channel", "target", "span", "fetchers", "breaking", "highlights", "check"} <= set(doc)


def test_unattended_stops_only_for_breaking_rows_that_touch_you(main_repo, stubs, tmp_path):
    upstream = tmp_path / "upstream"
    _rows(upstream, BREAKS_GAMMA)
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 0, result.stdout
    assert [(b["title"], b["touches"]) for b in doc["breaking"]] == [("gamma renames a field", False)]
    _rows(upstream, BREAKS_GAMMA + BREAKS_ALPHA)
    before = _sha(main_repo)
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 1 and "1 breaking change touches" in doc["errors"][0]
    assert doc["breaking"][0]["manifests"] == [{"manifest": "manifests/prod.yaml", "fetchers": ["demo_alpha"]}]
    assert _sha(main_repo) == before
    result, doc = _run("--yes", "--allow-breaking", "--json")
    assert result.exit_code == 0 and _sha(main_repo) == _sha(main_repo, "origin/main")


def test_unattended_stops_for_an_unscoped_breaking_row(main_repo, stubs, tmp_path):
    upstream = tmp_path / "upstream"
    _rows(upstream, BREAKS_CUSTOM)          # this clone has no fetchers of its own
    assert _run("--yes", "--json")[0].exit_code == 0
    _rows(upstream, BREAKS_CUSTOM + BREAKS_ALL)
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 1 and doc["breaking"][0]["why"] == "everyone"


def test_manifests_that_would_break_also_stop_an_unattended_run(main_repo, stubs, monkeypatch):
    before = _sha(main_repo)
    monkeypatch.setattr(up, "run_validate", lambda tree, m, python=None: {"ok": False, "errors": ["bad"], "notes": []})
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 1 and "1 manifest would break" in doc["errors"][0]
    assert _sha(main_repo) == before


def test_a_manifest_that_already_failed_is_not_blamed_on_the_update(main_repo, monkeypatch):
    manifests = [{"path": "/x/m.yaml", "label": "manifests/old.yaml", "uses": [], "errors_now": ["missing secret"]}]
    monkeypatch.setattr(up, "user_manifests", lambda root: manifests)
    monkeypatch.setattr(up, "run_validate", lambda t, m, python=None: {"ok": False, "errors": ["missing secret"], "notes": []})
    result = runner.invoke(app, ["update", "--yes"])
    assert result.exit_code == 0, result.stdout
    assert "1 was already failing" in result.stdout and "--rollback\n  Fix" not in result.stdout
    assert "Fix what validate names" not in result.stdout
    result = runner.invoke(app, ["update", "--rollback", "--yes"])
    assert result.exit_code == 0 and "paramify update --rollback" not in result.stdout


def test_overlapping_local_changes_are_refused_and_listed(main_repo, stubs):
    (main_repo / "framework/later.py").write_text("# rides along\n")
    (main_repo / "fetchers/demo/alpha/fetch.py").write_text("# mine\n")
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 1 and doc["blocking"]["tracked"] == ["fetchers/demo/alpha/fetch.py"]
    human = runner.invoke(app, ["update", "--yes"])
    assert human.exit_code == 1 and "fetchers/demo/alpha/fetch.py" in human.stdout
    assert "framework/later.py" not in human.stdout


def test_local_changes_the_update_does_not_touch_ride_along(main_repo, stubs):
    (main_repo / "framework/later.py").write_text("# rides along\n")
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 0, result.stdout
    assert (main_repo / "framework/later.py").read_text() == "# rides along\n"


def test_rollback_keeps_a_branch_user_on_the_branch(main_repo, stubs):
    before = _sha(main_repo)
    assert _run("--yes", "--json")[0].exit_code == 0
    result, doc = _run("--rollback", "--yes", "--json")
    assert result.exit_code == 0, result.stdout
    pos = up.position(main_repo)
    assert (pos["branch"], pos["sha"], pos["behind"]) == ("main", before, 1)
    assert "previous" not in up.read_state(main_repo)
    result, doc = _run("--rollback", "--yes", "--json")
    assert result.exit_code == 1 and "nothing to roll back to" in doc["errors"][0]


def test_rollback_refuses_when_the_clone_moved_since_the_update(main_repo, stubs):
    assert _run("--yes", "--json")[0].exit_code == 0
    _commit(main_repo, {"mine.txt": "x"}, "work after the update")
    mine = _sha(main_repo)
    result, doc = _run("--rollback", "--yes", "--json")
    assert result.exit_code == 1 and "has moved since the update" in doc["errors"][0]
    assert _sha(main_repo) == mine and "previous" in up.read_state(main_repo)


def test_a_failed_reinstall_during_rollback_keeps_the_record(main_repo, stubs, monkeypatch, tmp_path):
    _commit(tmp_path / "upstream", {"pyproject.toml": "[project]\nname='x'\n"}, "deps")
    assert _run("--yes", "--json")[0].exit_code == 0
    updated = _sha(main_repo)
    results = iter([{"ok": False, "command": ["pip"], "error": "boom"},
                    {"ok": True, "command": ["pip"], "error": None}])
    monkeypatch.setattr(up, "reinstall", lambda root, extras, python=None: next(results))
    result, doc = _run("--rollback", "--yes", "--json")
    assert result.exit_code == 1 and "rollback" in doc["errors"][0] and "previous version back" not in doc["errors"][0]
    assert (doc["switched"], doc["reverted"]) == (False, True)
    assert _sha(main_repo) == updated and "previous" in up.read_state(main_repo)


def test_a_manifest_that_newly_fails_after_the_move_is_not_a_success(main_repo, stubs, monkeypatch):
    verdicts = iter([{"ok": None, "errors": [], "notes": [], "reason": "needs a new package"},
                     {"ok": False, "errors": ["bad"], "notes": []}])
    monkeypatch.setattr(up, "run_validate", lambda tree, m, python=None: next(verdicts))
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 1 and not doc["ok"] and doc["switched"]
    assert "1 manifest fails on the new code" in doc["errors"][0] and "--rollback" in doc["errors"][0]


def test_rollback_returns_to_the_previous_release_once(repo, stubs):
    assert _run("--yes", "--json")[0].exit_code == 0
    result, doc = _run("--rollback", "--yes", "--json")
    assert result.exit_code == 0 and _head_tag(repo) == "v0.1.0-beta"


def test_the_reinstall_line_names_what_was_installed(main_repo, stubs, monkeypatch, tmp_path):
    _commit(tmp_path / "upstream", {"pyproject.toml": "[project]\nname='x'\n"}, "deps")
    monkeypatch.setattr(up, "detect_extras", lambda: [])
    out = runner.invoke(app, ["update", "--yes"]).stdout
    assert "✓ the base install" in out and ".[]" not in out
    _git(main_repo, "reset", "-q", "--hard", "HEAD~1")
    monkeypatch.setattr(up, "detect_extras", lambda: ["dev", "tui"])
    assert "✓ .[dev,tui]" in runner.invoke(app, ["update", "--yes"]).stdout


def test_a_failed_reinstall_puts_the_old_commit_back(main_repo, stubs, monkeypatch, tmp_path):
    _commit(tmp_path / "upstream", {"pyproject.toml": "[project]\nname='x'\n"}, "deps")
    before = _sha(main_repo)
    results = iter([{"ok": False, "command": ["pip"], "error": "boom"},
                    {"ok": True, "command": ["pip"], "error": None}])
    monkeypatch.setattr(up, "reinstall", lambda root, extras, python=None: next(results))
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 1 and "put your previous version back" in doc["errors"][0]
    assert (doc["switched"], doc["reverted"]) == (False, True)
    pos = up.position(main_repo)
    assert (pos["branch"], pos["sha"]) == ("main", before)
    assert "previous" not in up.read_state(main_repo)


def test_a_failed_reinstall_keeps_the_earlier_rollback_record(main_repo, stubs, monkeypatch, tmp_path):
    earlier = {"sha": "aaaa", "after": _sha(main_repo), "branch": "main", "describe": "0.2.0-beta"}
    up.write_state(main_repo, {"previous": earlier})
    _commit(tmp_path / "upstream", {"pyproject.toml": "[project]\nname='x'\n"}, "deps")
    results = iter([{"ok": False, "command": ["pip"], "error": "boom"},
                    {"ok": True, "command": ["pip"], "error": None}])
    monkeypatch.setattr(up, "reinstall", lambda root, extras, python=None: next(results))
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 1
    assert up.read_state(main_repo)["previous"] == earlier  # still the way back from the last good update


def test_check_exit_codes(main_repo):
    result, doc = _run("--check", "--json")
    assert result.exit_code == 1 and doc["update_available"] and doc["waiting"] == "1 new commit on main"
    _git(main_repo, "merge", "-q", "--ff-only", "origin/main")
    result = runner.invoke(app, ["update", "--check"])
    assert result.exit_code == 0 and "Up to date" in result.stdout
    _git(main_repo, "switch", "-q", "--detach", "HEAD")
    result, doc = _run("--check", "--json")
    assert result.exit_code == 2 and doc["update_available"] is None and "detached commit" in doc["errors"][0]


def test_check_on_a_release_reports_a_newer_one(repo):
    result, doc = _run("--check", "--json")
    assert result.exit_code == 1 and doc["waiting"] == "0.3.0-beta is out"
    _git(repo, "switch", "-q", "--detach", "v0.3.0-beta")
    assert _run("--check", "--json")[0].exit_code == 0


def test_offline_update_uses_what_the_clone_last_fetched(main_repo, stubs, monkeypatch):
    up.fetch(main_repo)

    def offline(root, timeout=90):
        raise up.UpdateError("could not resolve host")

    monkeypatch.setattr(up, "fetch", offline)
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 0 and doc["fetched"] is False and doc["switched"]
    monkeypatch.undo()


def test_flags_are_exclusive(repo):
    assert runner.invoke(app, ["update", "--check", "--rollback"]).exit_code == 2
    assert runner.invoke(app, ["update", "--to", "main", "--check"]).exit_code == 2
    assert runner.invoke(app, ["update", "--next"]).exit_code == 2      # removed


def test_to_pins_a_release_and_to_main_returns(main_repo, stubs, tmp_path):
    upstream = tmp_path / "upstream"
    _commit(upstream, {"framework/update.py": "# here\n"}, "ship update")
    _git(upstream, "tag", "v0.4.0-beta")
    _commit(upstream, {"framework/more.py": "# on\n"}, "main moves on again")
    result, doc = _run("--to", "v0.4.0-beta", "--yes", "--json")
    assert result.exit_code == 0 and doc["channel"] == "release" and _head_tag(main_repo) == "v0.4.0-beta"
    result, doc = _run("--to", "main", "--yes", "--json")
    assert result.exit_code == 0 and doc["channel"] == "branch"
    pos = up.position(main_repo)
    assert (pos["branch"], pos["behind"]) == ("main", 0)
    result, doc = _run("--to", "v0.2.0-beta", "--yes", "--json")
    assert result.exit_code == 1 and "before paramify update existed" in doc["errors"][0]


def test_notice_names_what_is_waiting(main_repo, monkeypatch):
    monkeypatch.setattr(up, "_background_fetch", lambda root: None)
    up.fetch(main_repo)
    info = up.check_for_update(main_repo)
    assert (info["channel"], info["update_available"], info["waiting"]) == ("branch", True, "1 new commit on main")
    _git(main_repo, "switch", "-q", "--detach", "v0.1.0-beta")
    info = up.check_for_update(main_repo)
    assert (info["channel"], info["waiting"]) == ("release", "0.3.0-beta is out")


def test_plan_renders_plainly_and_within_100_columns(main_repo, stubs, monkeypatch, tmp_path):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("COLUMNS", "160")
    upstream = tmp_path / "upstream"
    _rows(upstream, BREAKS_ALPHA + BREAKS_GAMMA + NEW_ROW)
    _commit(upstream, {"fetchers/demo/alpha/fetch.py": "# v4\n"}, "demo_alpha: " + "a very long reason " * 8)
    result = runner.invoke(app, ["update"])
    out = result.stdout
    assert result.exit_code == 1 and "pass --yes" in out
    assert all(line.startswith("  ") for line in out.splitlines() if line), out   # cut, never wrapped
    assert "a very long reason a very long reason" in out and "…" in out
    for text in ("main", "3 commits", "Your fetchers", "demo_alpha", "Breaking",
                 "alpha renames a field", "fix: read the new field", "manifests/prod.yaml",
                 "New", "Sprockets for all", "1 other breaking change"):
        assert text in out, text
    assert "gamma renames a field" not in out
    assert max(len(line) for line in out.splitlines()) <= 100
    assert "\x1b[" not in out


# --------------------------------------------------------------------------- #
# Containers
# --------------------------------------------------------------------------- #

def test_container_env_never_touches_git(repo, monkeypatch):
    monkeypatch.setenv("PARAMIFY_CONTAINER", "1")
    monkeypatch.setattr(up, "git", lambda *a, **k: pytest.fail("git called in a container"))
    result, doc = _run("--json")
    assert result.exit_code == 1 and doc["container"]
    assert doc["commands"] == ["paramify update", "docker compose -f deploy/docker-compose.yml build"]
    result, doc = _run("--check", "--json")
    assert result.exit_code == 2 and doc["update_available"] is None
    human = runner.invoke(app, ["update"])
    assert "docker compose -f deploy/docker-compose.yml build" in human.stdout
    assert up.check_for_update(repo) is None


def test_a_copy_without_git_counts_as_a_container(tmp_path, git_env):
    (tmp_path / "fetchers").mkdir()
    (tmp_path / "framework").mkdir()
    assert up.is_container(tmp_path)
    assert up.check_for_update(tmp_path) is None


def test_dockerfile_marks_the_image():
    assert "ENV PARAMIFY_CONTAINER=1" in (REPO_ROOT / "deploy/Dockerfile").read_text()


# --------------------------------------------------------------------------- #
# The pre-switch check
# --------------------------------------------------------------------------- #

def test_check_summary_does_not_call_an_already_failing_manifest_a_pass():
    from framework import update_view as view
    rows = [{"status": "ok"}, {"status": "still_failing"}]
    assert view.check_summary({"manifests": rows}) == ("warn", "nothing new breaks · 1 of 2 manifests already failing")
    assert view.check_summary({"manifests": rows[:1]}) == ("ok", "1 manifest passes on the new code")
    assert view.check_summary({"manifests": [{"status": "breaks"}]})[0] == "fail"


def test_fetcher_lines_show_new_fetchers_and_line_up():
    from framework import update_view as view
    changes = {"yours": [
        {"name": "a_fetcher_name_longer_than_thirty_ch", "change": "changed", "manifests": ["m"],
         "from": "0.1.0", "to": "0.2.0", "reason": "why", "more": 0},
        {"name": "short", "change": "added", "manifests": ["m"], "from": None, "to": "0.3.1", "reason": None, "more": 2},
    ], "others": [], "added": [], "removed": []}
    lines = [t.plain for t in view.your_fetchers(changes, 5, [])]
    assert lines[0].split() == ["Your", "fetchers", "2", "of", "5", "changed"]
    assert lines[1].index("0.1.0 → 0.2.0") == lines[2].index("new 0.3.1")
    assert lines[2].rstrip().endswith("2 commits")


def test_check_target_classifies_manifests_and_removes_its_worktree(repo, monkeypatch, tmp_path):
    seen_trees = []

    def fake_validate(tree, manifest, python=None):
        seen_trees.append(tree)
        assert (tree / "releases/0.3.0-beta.yaml").is_file()  # it really is the target
        assert (tree / "fetchers/custom/mine/fetcher.yaml").is_file()  # local fetchers mirrored
        return {"ok": manifest.endswith("ok.yaml"), "errors": [] if manifest.endswith("ok.yaml") else ["bad"],
                "notes": []}

    custom = repo / "fetchers/custom/mine"
    custom.mkdir(parents=True)
    (custom / "fetcher.yaml").write_text("name: my_own\n")
    monkeypatch.setattr(up, "run_validate", fake_validate)
    manifests = [
        {"path": "/m/ok.yaml", "label": "ok.yaml", "uses": ["demo_alpha"], "errors_now": []},
        {"path": "/m/new.yaml", "label": "new.yaml", "uses": ["demo_beta", "my_own"], "errors_now": []},
        {"path": "/m/old.yaml", "label": "old.yaml", "uses": [], "errors_now": ["already bad"]},
    ]
    target = up.choose_target(repo, up.position(repo), up.list_releases(repo))
    res = up.check_target(repo, target, manifests)
    assert [m["status"] for m in res["manifests"]] == ["ok", "breaks", "still_failing"]
    assert not res["ok"]
    assert res["fetchers"]["yours"] == [{"name": "demo_alpha", "change": "changed", "manifests": ["ok.yaml"],
                                         "from": None, "to": None, "reason": None, "more": 1}]
    assert res["has_local_fetchers"] is True
    assert res["fetchers"]["added"] == ["demo_gamma"]
    assert res["linked_local_fetchers"] == ["fetchers/custom"]
    assert not seen_trees[0].exists()
    assert len(_git(repo, "worktree", "list").splitlines()) == 1


def test_temp_worktree_is_removed_when_the_body_raises(repo):
    with pytest.raises(RuntimeError):
        with up.temp_worktree(repo, "v0.2.0-beta") as tree:
            assert tree.is_dir()
            raise RuntimeError("boom")
    assert not tree.exists()
    assert len(_git(repo, "worktree", "list").splitlines()) == 1


def test_run_validate_reports_a_missing_package_as_unchecked(tmp_path):
    (tmp_path / "framework").mkdir()
    (tmp_path / "framework/__init__.py").write_text("")
    (tmp_path / "framework/cli.py").write_text("import not_a_real_package_xyz\n")
    res = up.run_validate(tmp_path, "m.yaml")
    assert res["ok"] is None and "not_a_real_package_xyz" in res["reason"]


# --------------------------------------------------------------------------- #
# The daily update check and notice
# --------------------------------------------------------------------------- #

def test_update_check_fetches_at_most_once_a_day(repo, monkeypatch):
    fetches = []
    monkeypatch.setattr(up, "_background_fetch", lambda root: fetches.append(root))
    first = up.check_for_update(repo, now=1_000_000)
    assert first["update_available"] and first["latest"] == "0.3.0-beta" and first["current"] == "0.1.0-beta"
    up.check_for_update(repo, now=1_000_000 + 3600)
    assert len(fetches) == 1
    up.check_for_update(repo, now=1_000_000 + up.CHECK_INTERVAL + 1)
    assert len(fetches) == 2
    assert up.read_state(repo)["update_check"]["fetched_at"] == 1_000_000 + up.CHECK_INTERVAL + 1


def test_update_check_is_quiet(repo, monkeypatch):
    monkeypatch.setenv("PARAMIFY_NO_UPDATE_CHECK", "1")
    assert up.check_for_update(repo) is None
    monkeypatch.delenv("PARAMIFY_NO_UPDATE_CHECK")

    def offline(root):
        raise OSError("network down")

    monkeypatch.setattr(up, "_background_fetch", offline)
    assert up.check_for_update(repo, now=5)["latest"] == "0.3.0-beta"
    monkeypatch.setattr(up, "list_releases", lambda root: (_ for _ in ()).throw(up.UpdateError("x")))
    assert up.check_for_update(repo, now=10) is None


def test_notice_is_due_once_a_day(repo):
    assert up.notice_due(repo, now=100)
    up.mark_notice(repo, now=100)
    assert not up.notice_due(repo, now=100 + 3600)
    assert up.notice_due(repo, now=100 + up.CHECK_INTERVAL)


def test_notice_stays_out_of_json_and_pipes(repo, monkeypatch):
    called = []
    monkeypatch.setattr(up, "check_for_update", lambda root: called.append(root))
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True)
    monkeypatch.setattr("sys.argv", ["paramify", "list", "--json"])
    update_cli.maybe_notice("list")
    monkeypatch.setattr("sys.argv", ["paramify", "update"])
    update_cli.maybe_notice("update")
    assert called == []  # a terminal, but JSON or update itself: no notice
    monkeypatch.setattr("sys.argv", ["paramify", "list"])
    update_cli.maybe_notice("list")
    assert called == [repo]  # the control: a terminal and a plain command do ask
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    up.write_state(repo, {})
    update_cli.maybe_notice("list")
    assert called == [repo]  # a pipe: no notice


# --------------------------------------------------------------------------- #
# Reinstall and the look
# --------------------------------------------------------------------------- #

def test_install_command_uses_uv_when_the_venv_has_no_pip(monkeypatch, tmp_path):
    monkeypatch.setattr(up.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(up.shutil, "which", lambda name: "/usr/bin/uv")
    cmd = up.install_command(tmp_path, ["dev", "tui"], python="/v/bin/python")
    assert cmd == ["uv", "pip", "install", "--quiet", "--python", "/v/bin/python", "-e", f"{tmp_path}[dev,tui]"]
    monkeypatch.setattr(up.importlib.util, "find_spec", lambda name: object())
    assert up.install_command(tmp_path, None, python="py")[-2:] == ["-e", f"{tmp_path}[all]"]




# --------------------------------------------------------------------------- #
# Reading the output: breaking changes wrap, piped output is full width
# --------------------------------------------------------------------------- #

def _render(renderables, width):
    from framework import update_cli
    from framework import update_view as view
    run = update_cli._Run(json_out=False)
    run.console = view.make_console(width=width, record=True)
    run.show(*renderables)
    return run.console.export_text()


def test_a_breaking_change_and_its_fix_wrap_instead_of_being_cut():
    from framework import update_view as view
    fix = ("Re-check validators that read Datadog fields; a failed page now gives null counts "
           "instead of zero, so a threshold that compared against zero needs a null check")
    rows = [{"touches": True, "why": "fetchers", "manifests": [{"manifest": "prod.yaml", "fetchers": ["datadog_*"]}],
             "title": "Datadog evidence fields were removed, renamed or changed meaning", "fix": fix}]
    text = _render(view.breaking(rows), 60)
    assert "…" not in text
    assert " ".join(text.split()).count(fix) == 1
    lines = text.splitlines()
    fix_at = next(i for i, ln in enumerate(lines) if ln.lstrip().startswith("fix: "))
    body_col = lines[fix_at].index("fix: ") + len("fix: ")
    assert lines[fix_at + 1][:body_col].strip() == ""  # continuation hangs under the text, not "fix:"
    assert all(len(ln) <= 60 and ln == ln.rstrip() for ln in lines)


def test_breaking_names_the_release_each_row_came_from():
    from framework import update_view as view
    rows = [{"touches": True, "why": "everyone", "manifests": [], "title": "Python 3.11 or later",
             "fix": None, "release": "0.8.0-beta"},
            {"touches": True, "why": "custom", "manifests": [], "title": "Custom fetchers need a kind",
             "fix": None, "release": None},
            {"touches": False, "why": None, "manifests": [], "title": "Not mine", "fix": None, "release": "0.7.0-beta"}]
    text = _render(view.breaking(rows), 100)
    assert "everyone · 0.8.0-beta" in text
    assert "your own fetchers · unreleased" in text
    assert "Not mine" not in text


def test_other_rows_are_still_one_row():
    from framework import update_view as view
    rows = [{"title": "A highlight", "detail": "word " * 40}]
    text = _render(view.whats_new(rows), 60)
    assert len(text.splitlines()) == 4 and "…" in text  # New, the group heading, the row, its detail


def _hl(title, release):
    return {"title": title, "detail": None, "release": release}


def test_whats_new_groups_rows_under_their_release():
    from framework import update_view as view
    rows = [_hl("Eight A", "0.8.0-beta"), _hl("Eight B", "0.8.0-beta"), _hl("Seven A", "0.7.0-beta")]
    releases = [{"version": "0.8.0-beta", "date": "2026-12-03"}, {"version": "0.7.0-beta", "date": None}]
    text = _render(view.whats_new(rows, releases), 100)
    assert text.index("0.8.0-beta · Dec 3") < text.index("Eight A") < text.index("Eight B") < text.index("0.7.0-beta")
    assert text.index("0.7.0-beta") < text.index("Seven A")
    assert "0.7.0-beta ·" not in text  # no date, no dot


def test_whats_new_on_main_heads_rows_unreleased():
    from framework import update_view as view
    text = _render(view.whats_new([_hl("Fresh", "unreleased")], []), 100)
    lines = [ln.strip() for ln in text.splitlines()]
    assert lines.index("unreleased") < lines.index("+ Fresh")
    both = _render(view.whats_new([_hl("Old", "0.8.0-beta"), _hl("Fresh", "unreleased")],
                                  [{"version": "0.8.0-beta", "date": None}]), 100)
    assert both.index("unreleased") < both.index("Fresh") < both.index("0.8.0-beta") < both.index("Old")


def _yours(**over):
    row = {"name": "demo_beta", "change": "changed", "manifests": ["m"], "from": "0.6.0", "to": "0.8.0",
           "reason": "a commit reason", "more": 0, "notes": []}
    row.update(over)
    return {"yours": [row], "others": [], "added": [], "removed": []}


def test_your_fetchers_lists_every_release_note_newest_first():
    from framework import update_view as view
    notes = [{"release": "0.8.0-beta", "version": "0.8.0", "note": "newest words"},
             {"release": "0.7.0-beta", "version": "0.7.0", "note": "older words"}]
    text = _render(view.your_fetchers(_yours(notes=notes), 3, []), 100)
    lines = text.splitlines()
    first = next(i for i, ln in enumerate(lines) if "0.8.0-beta" in ln)
    assert lines[first].startswith("    0.8.0-beta") and lines[first].rstrip().endswith("newest words")
    assert "0.7.0-beta" in lines[first + 1] and lines[first + 1].rstrip().endswith("older words")
    assert "a commit reason" not in text


def test_your_fetchers_caps_notes_at_three_and_counts_the_rest():
    from framework import update_view as view
    notes = [{"release": f"0.{n}.0-beta", "version": f"0.{n}.0", "note": f"n{n}"} for n in (9, 8, 7, 6, 5)]
    text = _render(view.your_fetchers(_yours(notes=notes), 3, []), 100)
    assert "n7" in text and "n6" not in text and "+2 earlier" in text


def test_your_fetchers_without_notes_keeps_the_commit_reason():
    from framework import update_view as view
    lines = _render(view.your_fetchers(_yours(), 3, []), 100).splitlines()
    assert len(lines) == 2 and "a commit reason" in lines[1] and "earlier" not in lines[1]


def test_fetcher_note_shows_the_newest_note_and_counts_earlier():
    from framework import update_view as view
    notes = [{"release": "0.8.0-beta", "version": "0.8.0", "note": "newest"},
             {"release": "0.7.0-beta", "version": "0.7.0", "note": "older"}]
    assert view.fetcher_note(_yours(notes=notes)["yours"][0], []).plain == "0.8.0-beta  newest  +1 earlier"
    assert view.fetcher_note(_yours(notes=notes[:1])["yours"][0], []).plain == "0.8.0-beta  newest"


def test_header_counts_releases_only_when_more_than_one():
    from framework import update_view as view
    plan = {"direction": "forward", "current": {"label": "v0.6.0-beta"},
            "target": {"label": "v0.8.0-beta", "channel": "tag"}}
    for n, tail in ((2, "412 commits, 41 days, 2 releases"), (1, "412 commits, 41 days"), (0, "412 commits, 41 days")):
        plan["span"] = {"commits": 412, "days": 41, "releases": n}
        assert view.header(plan).plain.endswith(tail)


@pytest.mark.parametrize("date", ["2026-12-03T10:00:00Z", "soon", "2026-13-45"])
def test_a_malformed_release_date_falls_back_to_the_bare_version(date):
    from framework import update_view as view
    text = _render(view.whats_new([_hl("Row", "0.8.0-beta")], [{"version": "0.8.0-beta", "date": date}]), 100)
    assert "0.8.0-beta" in text and "·" not in text and "Row" in text


def test_a_long_note_on_a_breaking_fetcher_stays_within_100_columns():
    from framework import update_view as view
    notes = [{"release": "0.8.0-beta", "version": "0.8.0", "note": "word " * 30}]
    row = _yours(notes=notes)
    text = _render(view.your_fetchers(row, 3, [{"touches": True, "manifests": [{"fetchers": ["demo_*"]}]}]), 100)
    assert "⚠ breaking" in text
    assert all(len(ln) <= 100 for ln in text.splitlines())


def test_piped_output_uses_the_full_width_cap():
    from framework import update_view as view
    console = view.make_console(file=io.StringIO())
    assert not console.is_terminal
    assert console.width == view.WIDTH


def test_the_ending_lists_commands_without_repeating_their_titles():
    from framework import update_view as view
    out = [t.plain for t in view.done("main", ["paramify status <manifest>"], rollback=True, rebuild=None)]
    assert any(ln.split() == ["try", "paramify", "status", "<manifest>"] for ln in out)


def test_the_docker_hint_needs_a_built_image(monkeypatch, tmp_path):
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "docker-compose.yml").write_text("services:\n  fetchers:\n    build: .\n    image: paramify-fetchers:beta\n")
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0 if cmd[-1] == "paramify-fetchers:beta" else 1, "", "")

    monkeypatch.setattr(up.shutil, "which", lambda name: "/usr/bin/docker" if name == "docker" else None)
    monkeypatch.setattr(up.subprocess, "run", fake_run)
    assert up.built_image(tmp_path) is True
    assert calls[0][:3] == ["/usr/bin/docker", "image", "inspect"]
    monkeypatch.setattr(up.shutil, "which", lambda name: None)
    assert up.built_image(tmp_path) is False
    assert up.built_image(tmp_path / "nowhere") is False


# --------------------------------------------------------------------------- #
# One plan for every front-end, and Apply moves to the commit that was shown
# --------------------------------------------------------------------------- #

def test_the_plan_carries_what_a_front_end_draws(main_repo, stubs):
    many = "".join(f"  - {{tag: new, title: Row {i}}}\n" for i in range(up.MAX_NEW + 2))
    _rows(main_repo.parent / "upstream", BREAKS_ALPHA + NEW_ROW + many)
    plan = up.public(up.plan(main_repo))
    assert plan["fetched"] and not plan["up_to_date"]
    assert len(plan["highlights"]) == up.MAX_NEW and plan["hidden_highlights"] == 3
    assert plan["tries"] == ["paramify catalog"]
    assert plan["stops"] == {"breaks": [], "touching": ["alpha renames a field"], "python_required": None}
    assert plan["manifests"] == ["manifests/prod.yaml"]
    assert plan["changelog"].endswith("/CHANGELOG.md")


def test_apply_with_expect_moves_to_that_commit(main_repo, stubs):
    _git(main_repo, "fetch", "-q", "origin")  # what the plan saw
    planned = _sha(main_repo, "origin/main")
    result, doc = _run("--yes", "--json", "--expect", planned[:10])
    assert result.exit_code == 0, result.stdout
    assert _sha(main_repo) == planned


def test_expect_takes_a_real_sha(main_repo, stubs):
    result, doc = _run("--yes", "--json", "--expect", "a")
    assert result.exit_code == 1 and "7 to 40 hex characters" in doc["errors"][0]


def test_apply_with_expect_refuses_a_target_that_moved(main_repo, stubs):
    _git(main_repo, "fetch", "-q", "origin")  # what the plan saw
    planned = _sha(main_repo, "origin/main")
    _commit(main_repo.parent / "upstream", {"fetchers/demo/alpha/fetch.py": "# v4\n"}, "demo_alpha: newer still")
    before = _sha(main_repo)
    result, doc = _run("--yes", "--json", "--expect", planned)
    assert result.exit_code == 1
    assert "has moved since the plan was made" in doc["errors"][0]
    assert _sha(main_repo) == before


def test_a_failed_move_puts_the_old_rollback_record_back(main_repo):
    up.write_state(main_repo, {"previous": {"sha": "old", "after": "older"}})
    pos = up.position(main_repo)
    with pytest.raises(up.UpdateError):
        with up.recorded_move(main_repo, pos, "abc"):
            assert up.read_state(main_repo)["previous"]["after"] == "abc"
            raise up.UpdateError("git refused")
    assert up.read_state(main_repo)["previous"] == {"sha": "old", "after": "older"}


def test_stray_files_in_a_tracked_fetcher_are_not_your_own_fetchers(repo):
    (repo / "fetchers/demo/alpha/.env").write_text("X=1\n")
    (repo / "fetchers/demo/alpha/output").mkdir()
    (repo / "fetchers/demo/alpha/output/run.json").write_text("{}")
    tree = repo.parent / "tree"
    (tree / "fetchers/demo/alpha").mkdir(parents=True)
    assert up._mirror_local_fetchers(repo, tree) == []
    (repo / "fetchers/custom/mine").mkdir(parents=True)
    (repo / "fetchers/custom/mine/fetcher.yaml").write_text("name: my_own\n")
    assert up._mirror_local_fetchers(repo, tree) == ["fetchers/custom"]


def test_a_blocked_plan_says_so(main_repo, stubs):
    (main_repo / "fetchers/demo/alpha/fetch.py").write_text("# mine\n")  # and the update changes it too
    plan = up.plan(main_repo)
    assert plan["state"] == "blocked" and plan["blocking"]["tracked"] == ["fetchers/demo/alpha/fetch.py"]
    assert "check" not in plan


def test_rollback_refusal_is_one_rule(main_repo):
    assert "nothing to roll back to" in up.rollback_refusal(main_repo)
    up.write_state(main_repo, {"previous": {"sha": "a" * 40, "after": "b" * 40}})
    assert "has moved since the update" in up.rollback_refusal(main_repo)
    up.write_state(main_repo, {"previous": {"sha": "a" * 40, "after": _sha(main_repo)}})
    assert up.rollback_refusal(main_repo) is None


def test_a_move_that_went_partway_keeps_a_record_of_where_it_left_the_clone(main_repo):
    up.write_state(main_repo, {"previous": {"sha": "old", "after": "older"}})
    pos = up.position(main_repo)
    _git(main_repo, "fetch", "-q", "origin")
    with pytest.raises(up.UpdateError):
        with up.recorded_move(main_repo, pos, "f" * 40):
            _git(main_repo, "switch", "-q", "--detach", "origin/main")  # the switch went through...
            raise up.UpdateError("...and then the merge failed")
    prev = up.read_state(main_repo)["previous"]
    assert (prev["sha"], prev["after"]) == (pos["sha"], _sha(main_repo))
    assert up.rollback_refusal(main_repo) is None  # so --rollback goes back one step, not two


def test_rollback_json_names_its_target_like_an_update(main_repo, stubs):
    _run("--yes", "--json")
    result, doc = _run("--rollback", "--yes", "--json")
    assert result.exit_code == 0, result.stdout
    assert set(doc["target"]) >= {"sha", "branch", "label"} and doc["target"]["label"].startswith("main @ ")


# --------------------------------------------------------------------------- #
# Fetcher notes and release dates
# --------------------------------------------------------------------------- #

def _notes_file(version: str, date: str, fetcher_version: str, note: str) -> str:
    return (f"version: {version}\ndate: {date}\nhighlights: []\nfetchers:\n"
            f"  - {{name: demo_alpha, version: {fetcher_version}, note: \"{note}\"}}\n")


@pytest.fixture
def notes_repo(repo, tmp_path):
    """The clone at v0.1.0-beta, whose origin also has v0.4.0-beta and v0.5.0-beta:
    each bumps demo_alpha, carries a release file with a note for it, and has a date."""
    upstream = tmp_path / "upstream"
    for n in (4, 5):
        v = f"0.{n}.0-beta"
        _commit(upstream, {
            "fetchers/demo/alpha/fetcher.yaml": f"name: demo_alpha\nversion: 0.{n}.0\n",
            f"releases/{v}.yaml": _notes_file(v, f"2026-0{n}-01", f"0.{n}.0", f"alpha note 0.{n}.0"),
        }, f"v0.{n}")
        _git(upstream, "tag", f"v{v}")
    _git(repo, "fetch", "-q", "--tags")
    return repo


def test_span_counts_releases_from_tags_alone(notes_repo, monkeypatch):
    doc = up.span(notes_repo, "v0.3.0-beta", "v0.5.0-beta")
    assert doc["releases"] == len(up.crossed_releases(notes_repo, "v0.3.0-beta", "v0.5.0-beta")) == 2
    monkeypatch.setattr(up, "release_files", lambda *a: pytest.fail("span must not read release files"))
    assert up.span(notes_repo, "v0.3.0-beta", "v0.5.0-beta")["releases"] == 2


def test_span_returns_zeros_when_the_tag_listing_fails(notes_repo, monkeypatch):
    real = up.git

    def flaky(root, *args, **kw):
        if args[:1] == ("tag",):
            raise up.UpdateError("tag failed")
        return real(root, *args, **kw)

    monkeypatch.setattr(up, "git", flaky)
    assert up.span(notes_repo, "v0.3.0-beta", "v0.5.0-beta") == {"commits": 0, "days": 0, "releases": 0}


@pytest.mark.parametrize("raw,want", [("2026-04-01", "2026-04-01"), ("soon", None),
                                      ("2026-04-01T10:00:00Z", None), ("04/01/2026", None)])
def test_release_file_dates_are_only_day_strings(repo, tmp_path, raw, want):
    upstream = tmp_path / "upstream"
    _commit(upstream, {"releases/0.4.0-beta.yaml": f"version: 0.4.0-beta\ndate: \"{raw}\"\nhighlights: []\n"}, "r")
    _git(upstream, "tag", "v0.4.0-beta")
    _git(repo, "fetch", "-q", "--tags")
    assert up.crossed_releases(repo, "v0.3.0-beta", "v0.4.0-beta") == [{"version": "0.4.0-beta", "date": want}]


def test_an_unquoted_yaml_date_is_a_day(repo, tmp_path):
    upstream = tmp_path / "upstream"
    _commit(upstream, {"releases/0.4.0-beta.yaml": "version: 0.4.0-beta\ndate: 2026-04-01\nhighlights: []\n"}, "r")
    _git(upstream, "tag", "v0.4.0-beta")
    _git(repo, "fetch", "-q", "--tags")
    assert up.crossed_releases(repo, "v0.3.0-beta", "v0.4.0-beta")[0]["date"] == "2026-04-01"


def test_a_bad_file_date_falls_through_to_the_changelog_heading(repo, tmp_path):
    upstream = tmp_path / "upstream"
    _commit(upstream, {"releases/0.4.0-beta.yaml": "version: 0.4.0-beta\ndate: soon\nhighlights: []\n",
                       "CHANGELOG.md": "## [0.4.0-beta] - 2026-04-09\n"}, "r")
    _git(upstream, "tag", "v0.4.0-beta")
    _git(repo, "fetch", "-q", "--tags")
    assert up.crossed_releases(repo, "v0.3.0-beta", "v0.4.0-beta")[0]["date"] == "2026-04-09"


def test_old_loader_still_sees_breaking_rows_in_a_file_with_fetchers(repo, tmp_path):
    upstream = tmp_path / "upstream"
    _commit(upstream, {"releases/0.9.0-beta.yaml": (
        "version: 0.9.0-beta\ndate: 2026-09-01\n"
        "highlights:\n  - {tag: breaking, title: Big change, fix: do it, draft: true}\n"
        "fetchers:\n  - {name: demo_alpha, version: 0.9.0, note: hi, draft: true}\n")}, "notes")
    _git(upstream, "tag", "v0.9.0-beta")
    _git(repo, "fetch", "-q", "--tags")
    rows = up._highlight_files(repo, "v0.9.0-beta")["0.9.0-beta"]
    assert [r["title"] for r in rows] == ["Big change"]


def test_fetcher_notes_from_every_release_crossed_newest_first(notes_repo):
    notes = up.fetcher_notes(notes_repo, "v0.3.0-beta", "v0.5.0-beta")
    assert [n["release"] for n in notes["demo_alpha"]] == ["0.5.0-beta", "0.4.0-beta"]
    assert notes["demo_alpha"][0] == {"release": "0.5.0-beta", "version": "0.5.0", "note": "alpha note 0.5.0"}


def test_fetcher_notes_skip_releases_head_contains(notes_repo):
    notes = up.fetcher_notes(notes_repo, "v0.4.0-beta", "v0.5.0-beta")
    assert [n["release"] for n in notes["demo_alpha"]] == ["0.5.0-beta"]


def test_fetcher_notes_ignore_unreleased(notes_repo, tmp_path):
    upstream = tmp_path / "upstream"
    _commit(upstream, {"releases/unreleased.yaml": (
        "version: unreleased\nhighlights: []\nfetchers:\n  - {name: demo_beta, version: 1.0.0, note: soon}\n")}, "wip")
    assert up.fetcher_notes(notes_repo, "v0.3.0-beta", "origin/main").get("demo_beta") is None


def test_crossed_releases_with_dates_newest_first(notes_repo):
    assert up.crossed_releases(notes_repo, "v0.1.0-beta", "v0.5.0-beta") == [
        {"version": "0.5.0-beta", "date": "2026-05-01"},
        {"version": "0.4.0-beta", "date": "2026-04-01"},
        {"version": "0.3.0-beta", "date": "2026-03-01"},
        {"version": "0.2.0-beta", "date": "2026-02-01"},  # no release file: the CHANGELOG heading
    ]
    assert up.span(notes_repo, "v0.3.0-beta", "v0.5.0-beta")["releases"] == 2
    assert up.span(notes_repo, "v0.5.0-beta", "v0.3.0-beta")["releases"] == 0


def test_assess_puts_notes_on_your_fetchers(notes_repo, stubs):
    plan = up.plan(notes_repo)
    alpha = next(r for r in plan["fetchers"]["yours"] if r["name"] == "demo_alpha")
    assert [n["release"] for n in alpha["notes"]] == ["0.5.0-beta", "0.4.0-beta"]
    assert [r["version"] for r in plan["releases"]][:2] == ["0.5.0-beta", "0.4.0-beta"]
    json.dumps(up.public(plan))


def test_assess_on_main_has_no_notes(main_repo, stubs):
    plan = up.plan(main_repo)
    assert plan["releases"] == []
    assert all(r["notes"] == [] for r in plan["fetchers"]["yours"])
    assert any(r.get("reason") for r in plan["fetchers"]["yours"])
