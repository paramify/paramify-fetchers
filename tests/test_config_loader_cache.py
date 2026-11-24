"""discover_fetchers keeps each fetcher.yaml's parsed, schema-valid data between calls.

The TUI discovers several times per start and on every reload, and parsing and
checking every fetcher.yaml each time was most of a TUI test's start-up. The
cache must never change what discovery returns: an edited file, a changed
schema, and an invalid file are all seen on the very next call, and what one
caller does to its result reaches no other caller.

Run: ``pytest tests/test_config_loader_cache.py``
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from framework import config_loader, yaml_io
from framework.config_loader import discover_fetchers

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def root(tmp_path) -> Path:
    """A repo root with the real fetcher schema and only the demo fetcher."""
    (tmp_path / "framework" / "schemas").mkdir(parents=True)
    shutil.copy(REPO_ROOT / "framework" / "schemas" / "fetcher_schema.json", tmp_path / "framework" / "schemas")
    shutil.copytree(REPO_ROOT / "fetchers" / "demo", tmp_path / "fetchers" / "demo")
    return tmp_path


def _yaml(root: Path) -> Path:
    return root / "fetchers" / "demo" / "hello" / "fetcher.yaml"


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    assert old in text
    path.write_text(text.replace(old, new))


def test_a_second_discovery_reads_no_yaml(root, monkeypatch):
    discover_fetchers(root)
    reads = []
    real = yaml_io.load_path
    monkeypatch.setattr(yaml_io, "load_path", lambda p: reads.append(p) or real(p))

    assert set(discover_fetchers(root)) == {"demo_hello"}
    assert reads == []


def test_an_edited_fetcher_yaml_is_seen_on_the_next_call(root):
    assert discover_fetchers(root)["demo_hello"].version == "0.1.0"
    _edit(_yaml(root), "version: 0.1.0", "version: 0.2.0")

    assert discover_fetchers(root)["demo_hello"].version == "0.2.0"


def test_an_edit_that_keeps_the_size_and_mtime_is_still_seen(root):
    """Same length, and the mtime set back: a replaced file has a new inode."""
    path = _yaml(root)
    discover_fetchers(root)
    before = path.stat()
    replacement = path.with_suffix(".new")
    replacement.write_text(path.read_text().replace("version: 0.1.0", "version: 0.9.0"))
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    replacement.replace(path)

    assert discover_fetchers(root)["demo_hello"].version == "0.9.0"


def test_an_invalid_fetcher_yaml_fails_on_every_call(root):
    discover_fetchers(root)
    _edit(_yaml(root), "version: 0.1.0", "version: [not, a, string]")

    for _ in range(2):
        with pytest.raises(ValueError, match="schema validation failed"):
            discover_fetchers(root)


def test_a_schema_change_checks_every_file_again(root):
    discover_fetchers(root)
    schema_path = root / "framework" / "schemas" / "fetcher_schema.json"
    schema = json.loads(schema_path.read_text())
    schema["required"] = [*schema["required"], "a_field_no_fetcher_has"]
    schema_path.write_text(json.dumps(schema))

    with pytest.raises(ValueError, match="a_field_no_fetcher_has"):
        discover_fetchers(root)


def test_changing_a_result_changes_nothing_for_the_next_caller(root):
    first = discover_fetchers(root)["demo_hello"]
    first.ksis.append("KSI-CHANGED")
    first.secrets.clear()
    first.version = "changed"

    again = discover_fetchers(root)["demo_hello"]
    assert again is not first
    assert "KSI-CHANGED" not in again.ksis
    assert again.version == "0.1.0"


def test_the_cache_matches_a_fresh_discovery_of_the_real_tree(monkeypatch):
    cached = discover_fetchers(REPO_ROOT)
    monkeypatch.setattr(config_loader, "_valid_fetcher_yaml", {})
    monkeypatch.setattr(config_loader, "_validators", {})

    assert discover_fetchers(REPO_ROOT) == cached
