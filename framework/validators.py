"""Discover and scope validators in the central validators/ registry.

Walks `validators/<category>/<key>.yaml`, skipping any directory or file that
starts with `_` (e.g. `_template`), and validates each against
`validator_schema.json`. Mirrors `config_loader.discover_fetchers`.

A validator owns its fetcher link via `evidence_sets` (reference_ids), so a
fetcher's validators are a reverse lookup: registry entries whose `evidence_sets`
intersect that fetcher's `evidence_set.reference_id`. See docs/validators_design.md.
"""

import json
from pathlib import Path
from typing import Dict, Iterable, List, Set

import yaml
from jsonschema import Draft202012Validator

from framework.contract import Fetcher, Validator


def _load_schema(repo_root: Path) -> dict:
    return json.loads(
        (repo_root / "framework" / "schemas" / "validator_schema.json").read_text()
    )


def _parse_validator(data: dict, path: Path) -> Validator:
    return Validator(
        key=data["key"],
        name=data["name"],
        type=data["type"],
        statement=data["statement"],
        evidence_sets=list(data.get("evidence_sets") or []),
        regex=data.get("regex"),
        rules_summary=data.get("rules_summary"),
        role=data.get("role"),
        validation_rules=list(data.get("validation_rules") or []),
        attestation_rules=list(data.get("attestation_rules") or []),
        path=path.resolve(),
    )


def discover_validators(repo_root: Path) -> Dict[str, Validator]:
    """Walk validators/<category>/<key>.yaml. Returns {key: Validator}.

    Raises ValueError on schema-invalid yaml, a key that does not match its
    filename, or a duplicate key. Returns {} when the registry is absent/empty.
    """
    validators_root = repo_root / "validators"
    if not validators_root.is_dir():
        return {}

    schema = _load_schema(repo_root)
    validator = Draft202012Validator(schema)

    out: Dict[str, Validator] = {}
    for category_dir in sorted(validators_root.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("_"):
            continue
        for yaml_path in sorted(category_dir.glob("*.yaml")):
            if yaml_path.name.startswith("_") or not yaml_path.is_file():
                continue
            data = yaml.safe_load(yaml_path.read_text())
            errors = list(validator.iter_errors(data))
            if errors:
                detail = "\n".join(f"  {e.message}" for e in errors)
                raise ValueError(f"{yaml_path}: schema validation failed:\n{detail}")
            if data["key"] != yaml_path.stem:
                raise ValueError(
                    f"{yaml_path}: key '{data['key']}' must equal the filename "
                    f"'{yaml_path.stem}'"
                )
            if data["key"] in out:
                raise ValueError(
                    f"Duplicate validator key '{data['key']}': "
                    f"{out[data['key']].path} and {yaml_path}"
                )
            out[data["key"]] = _parse_validator(data, yaml_path)

    return out


def manifest_reference_ids(manifest: dict, fetchers: Dict[str, Fetcher]) -> Set[str]:
    """The evidence-set reference_ids the manifest's fetchers produce."""
    refs: Set[str] = set()
    for entry in (manifest.get("run") or {}).get("fetchers") or []:
        name = entry.get("use") if isinstance(entry, dict) else None
        fetcher = fetchers.get(name) if name else None
        if fetcher and fetcher.evidence_set:
            refs.add(fetcher.evidence_set.reference_id)
    return refs


def select_validators(
    validators: Iterable[Validator], reference_ids: Set[str]
) -> List[Validator]:
    """Validators whose evidence_sets intersect the given reference_ids."""
    return [v for v in validators if set(v.evidence_sets) & reference_ids]
