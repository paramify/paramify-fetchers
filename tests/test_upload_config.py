"""Which uploader config a front-end runs on.

The TUI takes no config path, so until the facade had a default it could reach no
config at all — no base_url, no overrides, no channel. The rule lives in
``framework.api`` rather than in each front-end so the CLI and the TUI cannot
drift onto different overrides, which would silently put a fetcher's evidence and
its scripts on different evidence sets.

Everything here works in tmp_path: reading the real tree would make the result
depend on whether the developer happens to keep an upload.yaml.
"""

from __future__ import annotations

from framework import api


def test_default_is_upload_yaml_at_the_root(tmp_path):
    cfg = tmp_path / "upload.yaml"
    cfg.write_text("paramify:\n  stack: Production\n")
    assert api.default_upload_config(tmp_path) == cfg


def test_no_config_file_means_built_in_defaults(tmp_path):
    assert api.default_upload_config(tmp_path) is None


def test_a_directory_named_upload_yaml_is_not_a_config(tmp_path):
    (tmp_path / "upload.yaml").mkdir()
    assert api.default_upload_config(tmp_path) is None


def test_an_explicit_path_wins_over_the_default(tmp_path):
    (tmp_path / "upload.yaml").write_text("paramify: {}\n")
    named = tmp_path / "other.yaml"
    named.write_text("paramify: {}\n")
    assert api._upload_config(tmp_path, named) == named


def test_the_default_fills_in_when_no_path_is_named(tmp_path):
    cfg = tmp_path / "upload.yaml"
    cfg.write_text("paramify: {}\n")
    assert api._upload_config(tmp_path, None) == cfg
