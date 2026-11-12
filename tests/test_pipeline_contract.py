"""The `pipeline:` block in fetcher.yaml: schema rules, loader, envelope metadata."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from framework.config_loader import _parse_fetcher, discover_fetchers
from framework.contract import InvocationResult, Pipeline
from framework.envelope import build_metadata

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = REPO_ROOT / "framework" / "schemas"


def _doc(**overrides) -> dict:
    doc = {
        "name": "x_inventory", "version": "0.1.0", "description": "d", "kind": "inventory",
        "runtime": {"type": "python", "entry": "fetcher.py"},
        "output": {"type": "json", "path": "x.json"},
        "secrets": [],
        "evidence_set": {"reference_id": "EVD-X-INVENTORY", "name": "X"},
        "pipeline": {"type": "inventory", "id_scheme": "x-id"},
    }
    doc.update(overrides)
    return {k: v for k, v in doc.items() if v is not None}


def _schema_errors(doc: dict) -> list:
    return list(Draft202012Validator(json.loads((SCHEMAS / "fetcher_schema.json").read_text()))
                .iter_errors(doc))


def test_inventory_requires_the_pipeline_block():
    assert _schema_errors(_doc(pipeline=None))


def test_inventory_pipeline_type_must_be_inventory():
    assert _schema_errors(_doc(pipeline={"type": "vulnerability", "id_scheme": "x-id"}))


def test_evidence_fetcher_refuses_a_pipeline_block():
    assert _schema_errors(_doc(kind="evidence"))


def test_preset_is_refused_for_now():
    errs = _schema_errors(_doc(pipeline={"type": "inventory", "id_scheme": "x-id", "preset": "p"}))
    assert any("preset" in str(e.path) or "preset" in e.message for e in errs)


def test_id_scheme_is_kebab_case():
    assert _schema_errors(_doc(pipeline={"type": "inventory", "id_scheme": "Wiz ID"}))


def test_asset_id_field_is_refused_on_an_inventory():
    assert _schema_errors(_doc(pipeline={"type": "inventory", "id_scheme": "x-id", "asset_id_field": "c"}))


def test_issue_report_may_declare_a_vulnerability_pipeline():
    doc = _doc(kind="issue_report", evidence_set=None, output={"type": "csv", "path": "x.csv"},
               issue_report={"assessment_type": "VULNERABILITY"},
               pipeline={"type": "vulnerability", "id_scheme": "wiz-resource-id", "asset_id_field": "Resource ID"})
    assert not _schema_errors(doc)


def test_loader_parses_the_block_and_envelope_records_it(tmp_path):
    f = _parse_fetcher(_doc(), tmp_path)
    assert f.is_pipeline and f.pipeline == Pipeline("inventory", "x-id")
    result = InvocationResult(
        fetcher_name="x_inventory", fetcher_version="0.1.0", target=None,
        started_at="2026-01-01T00:00:00Z", completed_at="2026-01-01T00:00:01Z",
        duration_sec=1.0, exit_code=0, stdout="", stderr="", outputs=[],
    )
    meta = build_metadata(result, f, "R1")
    assert meta["pipeline"] == {"type": "inventory", "id_scheme": "x-id"}


def test_every_inventory_fetcher_in_the_repo_declares_a_pipeline():
    fetchers = discover_fetchers(REPO_ROOT)
    assert all(f.is_pipeline for f in fetchers.values() if f.is_inventory)


def test_every_id_scheme_is_in_the_guide():
    guide = (REPO_ROOT / "docs" / "pipeline_fetchers_guide.md").read_text()
    section = guide.split("## The ID scheme list", 1)[1].split("\n---", 1)[0]
    listed = {
        line.split("|")[1].strip().strip("`")
        for line in section.splitlines()
        if line.startswith("| `")
    }
    schemes = {f.pipeline.id_scheme for f in discover_fetchers(REPO_ROOT).values() if f.is_pipeline}
    assert schemes, "no pipeline fetchers found"
    assert schemes <= listed, f"add to the ID scheme list in docs/pipeline_fetchers_guide.md: {sorted(schemes - listed)}"


def test_inventory_template_record_always_has_an_asset_type(monkeypatch):
    import importlib.util
    monkeypatch.syspath_prepend(str(REPO_ROOT / "fetchers" / "_lib"))
    path = REPO_ROOT / "fetchers" / "_template_inventory" / "fetcher.py"
    spec = importlib.util.spec_from_file_location("_template_inventory_fetcher", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for asset in ({"id": "a-1"}, {"id": "a-1", "type": None}, {"id": "a-1", "type": ""}):
        rec = mod.record(asset)
        assert isinstance(rec["asset_type"], str) and rec["asset_type"]
    assert mod.record({"id": "a-1", "type": "host"})["asset_type"] == "host"
