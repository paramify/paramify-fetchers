"""Registry gate: every validators/<cat>/<key>.yaml satisfies validator_schema.json,
discovery does not raise, and the manifest-scoping helpers select correctly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from framework.config_loader import discover_fetchers
from framework.validators import (
    discover_validators,
    manifest_reference_ids,
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
