"""Manifest `paramify` settings, per-entry keys, and what a run records of them."""

from __future__ import annotations

import json
import re

import yaml

from framework import api
from framework.contract import Fetcher, ManifestEntry, TargetField, TargetInstance
from framework.runner.executor import run_entry
from framework.runner.manifest_loader import (
    entry_keys,
    parse_manifest,
    resolved_paramify,
    schema_errors,
)
from framework.tui.screens.welcome import WelcomeScreen


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


def test_schema_accepts_delivery_and_direct_no_request(repo_root):
    data = {"run": {"paramify": {"delivery": "direct", "no_request": "direct"},
                    "fetchers": [{"use": "x", "paramify": {"delivery": "auto", "no_request": "refuse"}}]}}
    assert schema_errors(data, repo_root) == []


def test_schema_rejects_unknown_delivery(repo_root):
    data = {"run": {"paramify": {"delivery": "batch"}, "fetchers": [{"use": "x"}]}}
    errors = schema_errors(data, repo_root)
    assert errors and any("delivery" in e for e in errors)


def test_resolved_paramify_carries_delivery_into_run_metadata(tmp_path, repo_root):
    m = parse_manifest({"run": {"paramify": {"delivery": "direct"},
                                "fetchers": [{"use": "x", "paramify": {"no_request": "refuse"}}]}})
    assert resolved_paramify(m, m.entries[0]) == {"delivery": "direct", "no_request": "refuse"}


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


def test_an_entry_stack_does_not_inherit_the_run_level_label():
    m = parse_manifest({"run": {"paramify": {"stack": "st-1", "stack_name": "Prod"},
                                "fetchers": [{"use": "x", "paramify": {"stack": "st-2"}},
                                             {"use": "y"},
                                             {"use": "z", "paramify": {"stack": "st-3", "stack_name": "Gov"}},
                                             {"use": "w", "paramify": {"stack_name": "Stray"}}]}})
    x, y, z, w = (resolved_paramify(m, e) for e in m.entries)
    assert x == {"stack": "st-2"}
    assert y == {"stack": "st-1", "stack_name": "Prod"}
    assert z == {"stack": "st-3", "stack_name": "Gov"}
    assert w == {"stack": "st-1", "stack_name": "Prod"}  # a label without its stack is ignored


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


def test_duplicate_entries_get_distinct_keys_in_run_metadata(tmp_path, repo_root):
    manifest = {"run": {"output_dir": str(tmp_path / "out"),
                        "fetchers": [{"use": "demo_hello", "paramify": {"stack": "A"}},
                                     {"use": "demo_hello", "paramify": {"stack": "B"}}]}}
    summary = api.run(manifest, repo_root)
    meta = json.loads((tmp_path / "out" / f"run-{summary['run_id']}" / "_run_metadata.json").read_text())
    assert [i["entry_key"] for i in meta["invocations"]] == ["demo_hello", "demo_hello#1"]
    assert meta["paramify"]["demo_hello#1"]["stack"] == "B"


def test_every_target_of_a_fan_out_entry_shares_its_entry_key(tmp_path):
    fdir = tmp_path / "fetcher"
    fdir.mkdir()
    (fdir / "fetcher.py").write_text("pass\n")
    fetcher = Fetcher(
        name="t_fetcher", version="0.1.0", description="d", category="c",
        runtime_type="python", runtime_entry="fetcher.py", runtime_timeout=None,
        output_type="json", output_path="out.json", output_aggregation=None,
        secrets=[], supports_targets=True,
        target_schema={"region": TargetField(name="region", type="string", env="REGION")},
        path=fdir, config_schema={}, evidence_set=None,
    )
    entry = ManifestEntry(use="t_fetcher",
                          targets=[TargetInstance(values={"region": r}, secrets={}) for r in ("a", "b")])
    results = run_entry(fetcher, entry, tmp_path / "out", entry_key="t_fetcher#1")
    assert len(results) == 2
    assert {r.entry_key for r in results} == {"t_fetcher#1"}


def test_welcome_relative_reads_old_and_suffixed_run_ids():
    old = "2020-01-02T03-04-05Z"
    assert WelcomeScreen._relative(old) != old
    assert WelcomeScreen._relative(old + "-a1f3") == WelcomeScreen._relative(old)


def test_a_pipeline_entry_ignores_an_inherited_direct():
    m = parse_manifest({"run": {"paramify": {"delivery": "direct", "no_request": "direct", "approval": "MANUAL"},
                                "fetchers": [{"use": "x"}, {"use": "y", "paramify": {"no_request": "direct"}}]}})
    x, y = m.entries
    assert resolved_paramify(m, x, pipeline=True) == {"delivery": "auto", "no_request": "evidence", "approval": "MANUAL"}
    assert resolved_paramify(m, x) == {"delivery": "direct", "no_request": "direct", "approval": "MANUAL"}
    # The entry's own setting stays (validate refuses it).
    assert resolved_paramify(m, y, pipeline=True) == {"delivery": "auto", "no_request": "direct", "approval": "MANUAL"}


def test_run_metadata_records_the_pipeline_defaults_under_a_run_level_direct(tmp_path, repo_root, monkeypatch):
    import dataclasses

    from framework.contract import Pipeline
    real = api.discover_fetchers

    def with_pipeline(root):
        found = dict(real(root))
        found["demo_hello"] = dataclasses.replace(found["demo_hello"], pipeline=Pipeline("inventory", "x-id"))
        return found

    monkeypatch.setattr(api, "discover_fetchers", with_pipeline)
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "paramify": {"no_request": "direct"},
                        "fetchers": [{"use": "demo_hello"}]}}
    summary = api.run(manifest, repo_root)
    meta = json.loads((tmp_path / "out" / f"run-{summary['run_id']}" / "_run_metadata.json").read_text())
    assert meta["paramify"]["demo_hello"]["no_request"] == "evidence"


def test_run_metadata_keeps_a_run_level_direct_for_an_ordinary_entry(tmp_path, repo_root):
    manifest = {"run": {"output_dir": str(tmp_path / "out"), "paramify": {"no_request": "direct"},
                        "fetchers": [{"use": "demo_hello"}]}}
    summary = api.run(manifest, repo_root)
    meta = json.loads((tmp_path / "out" / f"run-{summary['run_id']}" / "_run_metadata.json").read_text())
    assert meta["paramify"]["demo_hello"] == {"use": "demo_hello", "no_request": "direct"}


def test_new_manifest_path_records_a_picked_stack(tmp_path):
    path = api.new_manifest_path(tmp_path, "aws-prod", stack="stk-1", stack_name="Alpha")
    assert path == tmp_path / "manifests" / "aws-prod.yaml"
    run = yaml.safe_load(path.read_text())["run"]
    assert run["paramify"] == {"stack": "stk-1", "stack_name": "Alpha"}
    assert run["fetchers"] == []


def test_new_manifest_path_without_a_stack_writes_no_paramify_block(tmp_path):
    path = api.new_manifest_path(tmp_path, "aws-prod")
    assert "paramify" not in yaml.safe_load(path.read_text())["run"]


def test_new_manifest_target_checks_the_name_without_writing(tmp_path):
    assert api.new_manifest_target(tmp_path, " aws-prod ") == tmp_path / "manifests" / "aws-prod.yaml"
    assert not (tmp_path / "manifests").exists()
    for bad in ("", "  ", "a/b", ".hidden"):
        try:
            api.new_manifest_target(tmp_path, bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} was accepted")
    api.new_manifest_path(tmp_path, "taken")
    try:
        api.new_manifest_target(tmp_path, "taken.yaml")
    except FileExistsError:
        pass
    else:
        raise AssertionError("an existing manifest was accepted")
