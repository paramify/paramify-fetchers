"""Manifest `paramify` settings, per-entry keys, and what a run records of them."""

from __future__ import annotations

import json
import re

import yaml

from framework import api
from framework.contract import ManifestEntry
from framework.runner.manifest_loader import (
    entry_keys,
    parse_manifest,
    resolved_paramify,
    schema_errors,
)


def _entry(use: str) -> ManifestEntry:
    return ManifestEntry(use=use)


def test_schema_accepts_paramify_blocks(repo_root):
    data = {"run": {
        "paramify": {"stack": "Prod", "stack_name": "Production", "approval": "MANUAL",
                     "no_request": "refuse"},
        "fetchers": [{"use": "x", "paramify": {"stack": "Gov",
                                               "approval": "SUBMISSION_WITH_PASSING_VALIDATORS",
                                               "no_request": "evidence"}},
                     {"use": "y", "paramify": {"approval": "SUBMISSION"}}],
    }}
    assert schema_errors(data, repo_root) == []


def test_schema_rejects_unknown_approval(repo_root):
    data = {"run": {"paramify": {"approval": "WHENEVER"}, "fetchers": [{"use": "x"}]}}
    errors = schema_errors(data, repo_root)
    assert errors and any("approval" in e for e in errors)


def test_schema_rejects_unknown_paramify_key_and_empty_stack(repo_root):
    data = {"run": {"paramify": {"stak": "x", "stack": ""}, "fetchers": [{"use": "x"}]}}
    assert len(schema_errors(data, repo_root)) == 2


def test_entry_keys_disambiguate_duplicates():
    entries = [_entry("a"), _entry("b"), _entry("a"), _entry("a")]
    assert entry_keys(entries) == ["a", "b", "a#1", "a#2"]


def test_resolved_paramify_entry_wins():
    m = parse_manifest({"run": {"paramify": {"stack": "Prod", "approval": "MANUAL"},
                                "fetchers": [{"use": "x", "paramify": {"stack": "Gov"}}]}})
    assert resolved_paramify(m, m.entries[0]) == {"stack": "Gov", "approval": "MANUAL"}


def test_resolved_paramify_absent_keys_stay_absent():
    m = parse_manifest({"run": {"fetchers": [{"use": "x"}]}})
    assert m.paramify == {} and m.entries[0].paramify == {}
    assert resolved_paramify(m, m.entries[0]) == {}


def test_run_metadata_records_paramify_and_entry_keys(tmp_path, repo_root):
    manifest = yaml.safe_load((repo_root / "examples" / "demo.yaml").read_text())
    manifest["run"]["output_dir"] = str(tmp_path / "out")
    manifest["run"]["paramify"] = {"stack": "Prod", "approval": "MANUAL"}
    summary = api.run(manifest, repo_root)
    meta = json.loads((tmp_path / "out" / f"run-{summary['run_id']}" / "_run_metadata.json").read_text())
    assert meta["paramify"] == {"demo_hello": {"use": "demo_hello", "stack": "Prod",
                                               "approval": "MANUAL"}}
    assert meta["invocations"][0]["entry_key"] == "demo_hello"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-[0-9a-f]{4}", meta["run_id"])


def test_duplicate_entries_get_distinct_keys_across_targets(tmp_path, repo_root):
    manifest = {"run": {"output_dir": str(tmp_path / "out"),
                        "fetchers": [{"use": "demo_hello", "paramify": {"stack": "A"}},
                                     {"use": "demo_hello", "paramify": {"stack": "B"}}]}}
    summary = api.run(manifest, repo_root)
    meta = json.loads((tmp_path / "out" / f"run-{summary['run_id']}" / "_run_metadata.json").read_text())
    assert [i["entry_key"] for i in meta["invocations"]] == ["demo_hello", "demo_hello#1"]
    assert meta["paramify"]["demo_hello#1"]["stack"] == "B"
