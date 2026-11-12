"""Registry gate: every validators/<cat>/<key>.yaml satisfies validator_schema.json,
discovery does not raise, and the manifest-scoping helpers select correctly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from framework import api
from framework.config_loader import _parse_fetcher, discover_fetchers
from framework.contract import Validator
from framework.validators import (
    discover_validators,
    manifest_reference_ids,
    pipeline_conflicts,
    select_validators,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
VALIDATORS_ROOT = REPO_ROOT / "validators"
SCHEMA = json.loads((REPO_ROOT / "framework/schemas/validator_schema.json").read_text())


def _validator_yamls() -> list[Path]:
    out: list[Path] = []
    for category_dir in sorted(VALIDATORS_ROOT.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("_"):
            continue
        for p in sorted(category_dir.glob("*.yaml")):
            if not p.name.startswith("_"):
                out.append(p)
    return out


VALIDATOR_YAMLS = _validator_yamls()


def test_registry_not_empty() -> None:
    assert VALIDATOR_YAMLS, "no validator files discovered under validators/"


@pytest.mark.parametrize(
    "yaml_path", VALIDATOR_YAMLS, ids=[str(p.relative_to(REPO_ROOT)) for p in VALIDATOR_YAMLS]
)
def test_validator_matches_schema(yaml_path: Path) -> None:
    validator = Draft202012Validator(SCHEMA)
    data = yaml.safe_load(yaml_path.read_text())
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    msgs = "\n".join(f"  {'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors)
    assert not errors, f"{yaml_path.name} violates validator_schema.json:\n{msgs}"
    assert data["key"] == yaml_path.stem, "key must equal filename stem"


def test_discovery_does_not_raise_and_dedupes() -> None:
    registry = discover_validators(REPO_ROOT)
    assert "alb_encryption_in_transit" in registry
    assert len(registry) == len(VALIDATOR_YAMLS)


def test_manifest_scoping_selects_by_reference_id() -> None:
    fetchers = discover_fetchers(REPO_ROOT)
    registry = discover_validators(REPO_ROOT)
    # The ALB validator points at EVD-LB-ENC-STATUS, produced by this fetcher.
    manifest = {"run": {"fetchers": [{"use": "aws_load_balancer_encryption_status"}]}}
    refs = manifest_reference_ids(manifest, fetchers)
    assert "EVD-LB-ENC-STATUS" in refs
    selected = select_validators(registry.values(), refs)
    assert any(v.key == "alb_encryption_in_transit" for v in selected)

    # A manifest that produces none of the ALB sets selects nothing ALB-ish.
    empty = select_validators(registry.values(), {"EVD-NOTHING-HERE"})
    assert all(v.key != "alb_encryption_in_transit" for v in empty)


# --- pipeline evidence sets: no validators, no direct delivery ---------------


def fake_inventory_fetcher(ref: str):
    return _parse_fetcher({
        "name": "x_inventory", "version": "0.1.0", "description": "d", "kind": "inventory",
        "runtime": {"type": "python", "entry": "fetcher.py"},
        "output": {"type": "json", "path": "x.json"},
        "secrets": [],
        "evidence_set": {"reference_id": ref, "name": "X"},
        "pipeline": {"type": "inventory", "id_scheme": "x-id"},
    }, REPO_ROOT / "fetchers" / "x" / "inventory")


def manifest_using(name: str) -> dict:
    return {"run": {"output_dir": "./evidence", "fetchers": [{"use": name}]}}


def manifest_with(use: str, paramify: dict) -> dict:
    """An entry whose required secrets and config hold placeholder refs, so that only the rule under test can fail."""
    fetcher = discover_fetchers(REPO_ROOT)[use]
    entry: dict = {"use": use, "paramify": paramify}
    secrets = {s.name: "${env:PLACEHOLDER}" for s in fetcher.secrets if s.required}
    if secrets:
        entry["secrets"] = secrets
    config = {n: "${env:PLACEHOLDER}" for n, f in fetcher.config_schema.items()
              if f.required and f.default is None}
    if config:
        entry["config"] = config
    if fetcher.supports_targets:
        entry["targets"] = [{n: "x" for n, f in fetcher.target_schema.items() if f.required}]
    return {"run": {"output_dir": "./evidence", "fetchers": [entry]}}


def test_no_registry_validator_targets_a_pipeline_set():
    assert pipeline_conflicts(discover_validators(REPO_ROOT).values(), discover_fetchers(REPO_ROOT)) == []


def test_a_validator_on_a_pipeline_set_is_a_conflict():
    v = Validator(key="k", name="K", type="AUTOMATED", statement="s", evidence_sets=["EVD-X-INVENTORY"])
    [msg] = pipeline_conflicts([v], {"x_inventory": fake_inventory_fetcher("EVD-X-INVENTORY")})
    assert "k" in msg and "EVD-X-INVENTORY" in msg and "never approve" in msg


def test_manifest_scope_leaves_out_pipeline_sets():
    fetchers = {"x_inventory": fake_inventory_fetcher("EVD-X-INVENTORY")}
    assert "EVD-X-INVENTORY" not in manifest_reference_ids(manifest_using("x_inventory"), fetchers)
    assert "EVD-X-INVENTORY" in manifest_reference_ids(
        manifest_using("x_inventory"), fetchers, include_pipeline=True)


def test_validate_refuses_direct_delivery_on_a_pipeline_entry():
    errs = api.validate(manifest_with(use="github_repository_inventory", paramify={"delivery": "direct"}), REPO_ROOT)
    assert any("never goes direct" in e for e in errs)


def test_validate_refuses_no_request_direct_on_a_pipeline_entry():
    errs = api.validate(manifest_with(use="github_repository_inventory", paramify={"no_request": "direct"}), REPO_ROOT)
    assert any("never goes direct" in e for e in errs)


def test_validate_notes_manual_approval_on_a_pipeline_entry():
    notes = api.validate_notes(
        manifest_with(use="github_repository_inventory", paramify={"approval": "MANUAL"}), REPO_ROOT)
    assert any("MANUAL" in n and "waits" in n for n in notes)


def test_validate_refuses_a_validator_on_a_pipeline_set(monkeypatch):
    fetchers = {"x_inventory": fake_inventory_fetcher("EVD-X-INVENTORY")}
    v = Validator(key="k", name="K", type="AUTOMATED", statement="s", evidence_sets=["EVD-X-INVENTORY"])
    monkeypatch.setattr("framework.validators.discover_validators", lambda root: {"k": v})
    errs = api.validate(manifest_using("x_inventory"), REPO_ROOT, fetchers=fetchers)
    assert any("never approve" in e for e in errs)


def test_collect_validators_drops_pipeline_sets_from_explicit_reference_ids(monkeypatch):
    syncer = api._load_paramify_validator_syncer(REPO_ROOT)
    v = Validator(key="k", name="K", type="AUTOMATED", statement="s", evidence_sets=["EVD-X-INVENTORY"])
    monkeypatch.setattr("framework.validators.discover_validators", lambda root: {"k": v})
    monkeypatch.setattr("framework.config_loader.discover_fetchers",
                        lambda root: {"x_inventory": fake_inventory_fetcher("EVD-X-INVENTORY")})
    assert syncer.collect_validators(REPO_ROOT, reference_ids=["EVD-X-INVENTORY"]) == []


def _raise_registry(root):
    raise ValueError("duplicate key")


def test_validate_does_not_load_the_registry_without_a_pipeline_entry(monkeypatch):
    monkeypatch.setattr("framework.validators.discover_validators", _raise_registry)
    errs = api.validate(manifest_with(use="cornerstone_incident_response_training", paramify={}), REPO_ROOT)
    assert not any("validator registry" in e for e in errs)


def test_validate_reports_a_broken_registry_as_an_error(monkeypatch):
    monkeypatch.setattr("framework.validators.discover_validators", _raise_registry)
    errs = api.validate(manifest_with(use="github_repository_inventory", paramify={}), REPO_ROOT)
    assert len([e for e in errs if "validator registry" in e]) == 1
