"""`paramify update` against a throwaway git repo with real release tags.

The fixture builds an "upstream" repo with v0.1.0-beta, v0.2.0-beta (which has
a Breaking CHANGELOG entry), v0.3.0-beta (which carries a highlights file), an
archive/* tag and a commit on main past the newest tag, then clones it, so
`git fetch --tags` has a real origin. Reinstall and validate are the only
mocked pieces: they would run pip and the clone's own code.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from framework import api
from framework import update as up
from framework import update_cli
from framework import update_view as view
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
    calls = {"reinstall": 0, "validate": 0, "check": 0}
    manifests = [{"path": "/x/manifests/prod.yaml", "label": "manifests/prod.yaml",
                  "uses": ["demo_alpha"], "errors_now": []}]

    def check_target(root, target, ms, python=None):
        calls["check"] += 1
        return {"ok": True, "python_required": None, "python": "3.12.0",
                "manifests": [{"manifest": "manifests/prod.yaml", "path": "/x", "status": "ok",
                               "errors": [], "reason": None}],
                "linked_local_fetchers": [],
                "fetchers": {"yours": [], "others": [], "added": [], "removed": []}}

    def reinstall(root, extras, python=None):
        calls["reinstall"] += 1
        return {"ok": True, "command": ["pip"], "error": None}

    def validate_all(root, ms, python=None):
        calls["validate"] += 1
        return {"ok": True, "manifests": []}

    monkeypatch.setattr(up, "user_manifests", lambda root: manifests)
    monkeypatch.setattr(up, "check_target", check_target)
    monkeypatch.setattr(up, "reinstall", reinstall)
    monkeypatch.setattr(up, "validate_all", validate_all)
    return calls


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
    assert (pos["upstream"], pos["behind"], pos["local_commits"]) == ("origin/main", 1, 0)
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


def test_release_notes_use_highlights_and_fall_back_to_the_changelog(repo):
    releases = up.list_releases(repo)
    pos = up.position(repo)
    notes = up.release_notes(repo, releases[-1], up.crossed(releases, pos, releases[-1]))
    by = {n["version"]: n for n in notes}
    assert [n["version"] for n in notes] == ["0.3.0-beta", "0.2.0-beta"]  # newest first
    assert by["0.3.0-beta"]["has_highlights"]
    assert [h["tag"] for h in by["0.3.0-beta"]["highlights"]] == ["new", "fetcher", "tui"]
    assert not by["0.2.0-beta"]["has_highlights"]
    assert by["0.2.0-beta"]["changelog_breaking"] == ["`old_flag` is gone"]
    assert by["0.2.0-beta"]["changelog_url"].endswith("#020-beta---2026-02-01")


def test_breaking_rows_name_the_manifests_they_touch():
    notes = [{"version": "1.0.0", "changelog_breaking": [], "breaking": [
        {"tag": "breaking", "title": "aws changed", "fix": "do x", "fetchers": ["aws_*"]},
        {"tag": "breaking", "title": "python", "fix": "do y"},
    ]}]
    manifests = [{"label": "m/a.yaml", "uses": ["aws_iam", "okta_x"]}, {"label": "m/b.yaml", "uses": ["okta_x"]}]
    rows = up.pair_breaking(notes, manifests)
    assert rows[0]["manifests"] == [{"manifest": "m/a.yaml", "fetchers": ["aws_iam"]}]
    assert rows[0]["scoped"] and not rows[1]["scoped"] and rows[1]["manifests"] == []


def test_changelog_parsing_joins_continuation_lines():
    parsed = up.parse_changelog(CHANGELOG["0.2.0-beta"])
    entry = parsed["0.2.0-beta"]["sections"]["Breaking"][0]
    assert entry.endswith("which does the same.")
    assert up.entry_title(entry) == "`old_flag` is gone"
    assert up.entry_title("Plain entry. With more.") == "Plain entry"


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


def test_curated_rows_survive_a_missing_or_broken_releases_dir(repo, tmp_path):
    upstream = tmp_path / "upstream"
    _commit(upstream, {"releases/unreleased.yaml": "version: [not, a, string\n"}, "broken file")
    _git(repo, "fetch", "-q", "origin")
    assert up.curated_rows(repo, "v0.1.0-beta", "v0.2.0-beta") == []      # neither tree has releases/
    assert [r["release"] for r in up.curated_rows(repo, "v0.1.0-beta", "origin/main")] == ["0.3.0-beta"] * 3


# --------------------------------------------------------------------------- #
# The command: breaking stop, switch, rollback
# --------------------------------------------------------------------------- #


def test_dirty_refusal_lists_files_for_humans(repo, stubs):
    (repo / "fetchers/demo/alpha/fetcher.yaml").write_text("changed\n")
    result = runner.invoke(app, ["update"])
    assert result.exit_code == 1
    assert "fetchers/demo/alpha/fetcher.yaml" in result.stdout
    assert "Commit them" in result.stdout


# --------------------------------------------------------------------------- #
# --check
# --------------------------------------------------------------------------- #

def test_check_exit_codes(repo):
    result, doc = _run("--check", "--json")
    assert result.exit_code == 1 and doc["update_available"] and doc["latest"] == "0.3.0-beta"
    _git(repo, "switch", "-q", "--detach", "v0.3.0-beta")
    result, doc = _run("--check", "--json")
    assert result.exit_code == 0 and not doc["update_available"]
    result = runner.invoke(app, ["update", "--check"])
    assert result.exit_code == 0 and "Up to date" in result.stdout


def test_flags_are_exclusive(repo):
    result = runner.invoke(app, ["update", "--check", "--rollback"])
    assert result.exit_code == 2


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
    assert api.check_for_update(repo) is None


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
    target = up.parse_release("v0.3.0-beta")
    res = up.check_target(repo, target, manifests)
    assert [m["status"] for m in res["manifests"]] == ["ok", "breaks", "still_failing"]
    assert not res["ok"]
    assert res["fetchers"]["yours"] == [{"name": "demo_alpha", "change": "changed", "manifests": ["ok.yaml"]}]
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
    monkeypatch.setattr(api, "check_for_update", lambda root: called.append(root))
    monkeypatch.setattr("sys.argv", ["paramify", "list", "--json"])
    update_cli.maybe_notice("list")
    monkeypatch.setattr("sys.argv", ["paramify", "list"])
    update_cli.maybe_notice("list")  # pytest's stdout is not a tty
    update_cli.maybe_notice("update")
    assert called == []


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


def test_view_palette_matches_the_tui_palette():
    spec = importlib.util.spec_from_file_location("_palette", REPO_ROOT / "framework/tui/palette.py")
    palette = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(palette)
    for name in ("BG", "FG", "SUBTLE", "BLUE", "PURPLE", "CYAN", "GREEN", "YELLOW", "RED", "ORANGE",
                 "OK_TEXT", "OK_MUTED", "WARN_TEXT", "WARN_MUTED", "FAIL_TEXT", "FAIL_MUTED"):
        assert getattr(view, name) == getattr(palette, name), name


def test_every_highlight_tag_has_a_pill():
    assert set(view.TAGS) == set(up.HIGHLIGHT_TAGS)
    schema_tags = set(up.highlights_schema()["$defs"]["highlight"]["properties"]["tag"]["enum"])
    assert schema_tags == set(up.HIGHLIGHT_TAGS)


@pytest.mark.parametrize("env", [{"NO_COLOR": "1"}, {"PARAMIFY_THEME": "light"}, {}])
def test_plan_renders_in_every_mode(env, monkeypatch):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    console = view.make_console(width=80, record=True, force_terminal=not env.get("NO_COLOR"),
                                color_system=None if env.get("NO_COLOR") else "truecolor",
                                file=open(os.devnull, "w"))
    look = view.Look(console)
    plan = {
        "current": {"label": "0.1.0-beta"}, "target": {"version": "0.3.0-beta", "date": "2026-03-01"},
        "direction": "forward", "used_fetchers": ["demo_alpha"],
        "releases": [{"version": "0.3.0-beta", "date": "2026-03-01", "has_highlights": True,
                      "highlights": [{"tag": "new", "title": "Gadgets", "detail": "more"},
                                     {"tag": "fetcher", "title": "Alpha", "fetchers": ["demo_alpha"]}],
                      "breaking": [], "changelog_breaking": [], "changelog_url": "https://x"}],
        "breaking": [{"release": "0.3.0-beta", "title": "Old flag gone", "fix": "Use the new one",
                      "source": "highlights", "scoped": False,
                      "manifests": [{"manifest": "m.yaml", "fetchers": ["demo_alpha"]}]}],
    }
    for r in (view.header(look, plan), view.whats_new(look, plan), view.breaking(look, plan),
              view.done_panel(look, "0.3.0-beta", [("paramify catalog", "Gadgets")], container=True)):
        console.print(r)
    text = console.export_text()
    assert "0.3.0-beta" in text and "Use the new one" in text and "affects m.yaml" in text
    assert "◆ yours" in text and "docker compose" in text
    if env.get("NO_COLOR"):
        assert "[new]" in text
