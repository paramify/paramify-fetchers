"""Facade-level tests for validator sync scoping (no network, no token).

Covers the pieces Phase 2 added around the reconcile engine: pulling the
evidence-set reference_ids out of a run directory (what `upload --with-validators`
scopes by) and the registry-collection/scoping the syncer performs. The reconcile
engine itself is covered by test_validator_sync.py against a fake client.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from framework import api

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_syncer():
    path = REPO_ROOT / "uploaders" / "paramify_validators" / "syncer.py"
    spec = importlib.util.spec_from_file_location("paramify_validators_syncer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_envelope(path: Path, reference_id: str) -> None:
    path.write_text(json.dumps({
        "schema_version": "1.0",
        "metadata": {
            "fetcher_name": "aws_load_balancer_encryption_status",
            "status": "success",
            "evidence_set": {"reference_id": reference_id, "name": "Load Balancer Encryption Status"},
        },
        "payload": {"alb_total": 3, "alb_encrypted": 3},
    }))


def test_reference_ids_from_run(tmp_path):
    _write_envelope(tmp_path / "lb.json", "EVD-LB-ENC-STATUS")
    (tmp_path / "_run_metadata.json").write_text("{}")  # must be ignored
    refs = api.reference_ids_from_run(tmp_path)
    assert refs == {"EVD-LB-ENC-STATUS"}


def test_reference_ids_from_missing_dir():
    assert api.reference_ids_from_run(REPO_ROOT / "no-such-run") == set()


def test_collect_validators_scoped_by_reference_ids():
    syncer = _load_syncer()
    hit = syncer.collect_validators(REPO_ROOT, reference_ids=["EVD-LB-ENC-STATUS"])
    assert [v["key"] for v in hit] == ["alb_encryption_in_transit"]
    # payload-facing dict maps validation_rules through unchanged
    assert hit[0]["validation_rules"] and hit[0]["type"] == "AUTOMATED"

    miss = syncer.collect_validators(REPO_ROOT, reference_ids=["EVD-NOPE"])
    assert miss == []


def test_collect_validators_scoped_by_manifest(tmp_path):
    syncer = _load_syncer()
    manifest = tmp_path / "m.yaml"
    manifest.write_text(
        "run:\n  output_dir: ./evidence\n  fetchers:\n"
        "    - use: aws_load_balancer_encryption_status\n"
    )
    scoped = syncer.collect_validators(REPO_ROOT, manifest_path=manifest)
    assert any(v["key"] == "alb_encryption_in_transit" for v in scoped)


def test_collect_validators_whole_registry_when_unscoped():
    syncer = _load_syncer()
    everything = syncer.collect_validators(REPO_ROOT)
    assert any(v["key"] == "alb_encryption_in_transit" for v in everything)
