"""One answer to "which manifest did you mean", and a write that cannot half-land.

Before this, sixteen CLI call sites resolved -f with a bare Path(x).resolve()
while two used a ladder that also looked in manifests/ and errored on a miss.
The consequences were not cosmetic: a bare name resolved against the process
cwd, so `manifest add -f demo` read ./demo as an empty manifest and wrote a
brand-new one there while manifests/demo.yaml sat untouched — the manifest
forked in two and the command printed "Wrote".
"""

from __future__ import annotations

import os

import pytest

from framework import api
from framework.api import (
    ManifestNotFound,
    dump_manifest,
    init_manifest,
    read_manifest,
    resolve_manifest_path,
)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A repo-shaped tree with manifests/demo.yaml holding one entry.

    chdir into it: the resolver resolves relative candidates against the
    process cwd, exactly as the CLI does. Without this the tests resolve
    against the real repo, where manifests/demo.yaml also exists — which would
    pass for the wrong reason.
    """
    (tmp_path / "manifests").mkdir()
    (tmp_path / "manifests" / "demo.yaml").write_text(
        "run:\n  output_dir: ./evidence\n  fetchers:\n  - use: demo_access_review\n"
    )
    monkeypatch.chdir(tmp_path)
    return tmp_path


# --------------------------------------------------------------------------- #
# resolve_manifest_path
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("given", ["demo", "demo.yaml", "manifests/demo.yaml"])
def test_every_spelling_of_the_same_manifest_resolves_to_it(workspace, given):
    assert resolve_manifest_path(workspace, given) == (workspace / "manifests" / "demo.yaml").resolve()


def test_an_absolute_path_is_honoured(workspace):
    target = workspace / "manifests" / "demo.yaml"
    assert resolve_manifest_path(workspace, str(target)) == target.resolve()


def test_a_name_that_resolves_to_nothing_raises_and_says_where_it_looked(workspace):
    with pytest.raises(ManifestNotFound) as exc:
        resolve_manifest_path(workspace, "typo")
    assert exc.value.given == "typo"
    assert [p.name for p in exc.value.tried] == ["typo", "typo", "typo.yaml"]


def test_each_candidate_is_listed_once(workspace):
    """`root / name` repeats the as-typed candidate when run from the repo root."""
    with pytest.raises(ManifestNotFound) as exc:
        resolve_manifest_path(workspace, "typo")
    resolved = [p.resolve() for p in exc.value.tried]
    assert len(resolved) == len(set(resolved))


def test_must_exist_false_returns_a_path_to_create(workspace):
    """The create commands need a path back, not an error."""
    got = resolve_manifest_path(workspace, "brand-new.yaml", must_exist=False)
    assert got.name == "brand-new.yaml"
    assert not got.exists()


def test_a_directory_is_not_a_manifest(workspace):
    (workspace / "manifests" / "adir").mkdir()
    with pytest.raises(ManifestNotFound):
        resolve_manifest_path(workspace, "adir")


# --------------------------------------------------------------------------- #
# read_manifest
# --------------------------------------------------------------------------- #

def test_read_manifest_still_reads_a_real_one(workspace):
    m = read_manifest(workspace / "manifests" / "demo.yaml")
    assert [e["use"] for e in m["run"]["fetchers"]] == ["demo_access_review"]


def test_must_exist_rejects_a_missing_file(workspace):
    """An empty manifest validates clean, so returning one for a path that is
    not there reported a typo'd filename as a passing preflight."""
    with pytest.raises(ManifestNotFound):
        read_manifest(workspace / "manifests" / "nope.yaml", must_exist=True)


@pytest.mark.parametrize("body", ["- a\n- b\n", "just a string\n", "42\n"])
def test_must_exist_rejects_a_non_mapping_root(workspace, body):
    """Valid YAML that is not a manifest was read as zero entries and passed."""
    p = workspace / "manifests" / "wrong.yaml"
    p.write_text(body)
    with pytest.raises(ManifestNotFound):
        read_manifest(p, must_exist=True)


def test_the_permissive_default_is_unchanged(workspace):
    """The editing path opens a not-yet-created manifest and fills it in."""
    assert read_manifest(workspace / "manifests" / "nope.yaml") == init_manifest()


# --------------------------------------------------------------------------- #
# atomic write
# --------------------------------------------------------------------------- #

def test_dump_manifest_replaces_rather_than_truncates(workspace, repo_root, monkeypatch):
    """A crash mid-write must leave the previous manifest intact.

    write_text truncates in place, so a failure between truncate and write left
    an empty or half-written file — and the manifest is the only record of what
    a run is supposed to collect.
    """
    target = workspace / "manifests" / "demo.yaml"
    before = target.read_text()

    real_replace = os.replace

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(api.os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        dump_manifest(init_manifest("./other"), target, repo_root)

    monkeypatch.setattr(api.os, "replace", real_replace)
    assert target.read_text() == before, "the original manifest must survive a failed write"


def test_a_failed_write_leaves_no_temp_files_behind(workspace, repo_root, monkeypatch):
    monkeypatch.setattr(api.os, "replace", lambda src, dst: (_ for _ in ()).throw(OSError("nope")))
    with pytest.raises(OSError):
        dump_manifest(init_manifest(), workspace / "manifests" / "demo.yaml", repo_root)

    leftovers = [p.name for p in (workspace / "manifests").iterdir() if p.name != "demo.yaml"]
    assert leftovers == [], f"temp files left behind: {leftovers}"


def test_a_successful_write_lands(workspace, repo_root):
    target = workspace / "manifests" / "demo.yaml"
    dump_manifest(init_manifest("./somewhere"), target, repo_root)
    assert read_manifest(target)["run"]["output_dir"] == "./somewhere"
