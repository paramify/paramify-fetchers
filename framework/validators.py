"""Discover and scope validators in the central validators/ registry.

Walks `validators/<category>/<key>.yaml`, skipping any directory or file that
starts with `_` (e.g. `_template`), and validates each against
`validator_schema.json`. Mirrors `config_loader.discover_fetchers`.

A validator owns its fetcher link via `evidence_sets` (reference_ids), so a
fetcher's validators are a reverse lookup: registry entries whose `evidence_sets`
intersect that fetcher's `evidence_set.reference_id`. See docs/validators_guide.md.
"""

import json
from pathlib import Path
from typing import Dict, Iterable, List, Set

from jsonschema import Draft202012Validator

from framework import yaml_io
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
        category=path.parent.name,
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
            data = yaml_io.load_path(yaml_path)
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


def manifest_reference_ids(
    manifest: dict, fetchers: Dict[str, Fetcher], *, include_pipeline: bool = False
) -> Set[str]:
    """The evidence-set reference_ids the manifest's fetchers produce. Pipeline sets are left out
    unless `include_pipeline`: validators never ship against them."""
    refs: Set[str] = set()
    for entry in (manifest.get("run") or {}).get("fetchers") or []:
        name = entry.get("use") if isinstance(entry, dict) else None
        fetcher = fetchers.get(name) if name else None
        if fetcher and fetcher.evidence_set and (include_pipeline or not fetcher.is_pipeline):
            refs.add(fetcher.evidence_set.reference_id)
    return refs


def select_validators(
    validators: Iterable[Validator], reference_ids: Set[str]
) -> List[Validator]:
    """Validators whose evidence_sets intersect the given reference_ids."""
    return [v for v in validators if set(v.evidence_sets) & reference_ids]


def pipeline_reference_ids(fetchers: Dict[str, Fetcher]) -> Set[str]:
    """The reference_ids of evidence sets that feed a pipeline."""
    return {f.evidence_set.reference_id for f in fetchers.values() if f.is_pipeline and f.evidence_set}


def pipeline_conflicts(validators: Iterable[Validator], fetchers: Dict[str, Fetcher]) -> List[str]:
    """One message per (validator, pipeline set): a validator on a pipeline set means the batch never approves."""
    pipeline = pipeline_reference_ids(fetchers)
    return [
        f"validator {v.key} targets pipeline evidence set {ref}: a failing validator means the batch will "
        f"never approve, so the pipeline never runs (remove {ref} from its evidence_sets)"
        for v in validators for ref in v.evidence_sets if ref in pipeline
    ]
