"""install.sh: which release the installer picks."""

import os
import subprocess
from pathlib import Path

import pytest

INSTALL = Path(__file__).resolve().parent.parent / "install.sh"


@pytest.fixture
def git_env(tmp_path, monkeypatch):
    """Isolate git from the user's config, so the scratch repos behave the same everywhere."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    for key, value in {
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
    }.items():
        monkeypatch.setenv(key, value)


def make_repo(path: Path, tags: list[str]) -> Path:
    path.mkdir()
    run = lambda *a: subprocess.run(["git", *a], cwd=path, check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("commit", "-q", "--allow-empty", "-m", "c")
    for tag in tags:
        run("tag", tag)
    return path


def newest_release(repo: Path | str) -> str:
    out = subprocess.run(
        ["bash", "-c", 'PARAMIFY_INSTALL_SOURCE_ONLY=1 source "$1"; newest_release "$2"', "_", str(INSTALL), str(repo)],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        (["v0.6.0-beta", "archive/x"], ""),
        (["v0.6.0-beta", "v0.7.0-beta"], "v0.7.0-beta"),
        (["v0.7.0-beta", "v0.7.0"], "v0.7.0"),
        (["v0.9.0-beta", "v0.10.0-beta"], "v0.10.0-beta"),
        (["v0.7.0-beta", "v0.6.9"], "v0.7.0-beta"),
        (["v0.7.0-alpha", "v0.6.9"], ""),
        (["v0.7.0-beta", "v0.8.0-rc", "vnext", "v1.0"], "v0.8.0-rc"),
    ],
)
def test_newest_release(git_env, tmp_path, tags, expected):
    assert newest_release(make_repo(tmp_path / "repo", tags)) == expected


def test_no_tags_or_unreachable_repo_prints_nothing(git_env, tmp_path):
    assert newest_release(make_repo(tmp_path / "repo", [])) == ""
    assert newest_release(tmp_path / "missing") == ""
