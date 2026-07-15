"""Discover fetchers in the repo and validate their fetcher.yaml files.

Walks `fetchers/<category>/<short_name>/fetcher.yaml`, skipping any directory
that starts with `_` (e.g. _shared, _categories, _template).
"""

import json
from pathlib import Path
from typing import Dict, Optional

import yaml
from jsonschema import Draft202012Validator

from framework.contract import (
    ConfigField,
    EvidenceSet,
    Fetcher,
    PlatformSpec,
    SchemaBinding,
    Secret,
    TargetField,
)


def _load_schema(repo_root: Path, name: str = "fetcher_schema.json") -> dict:
    return json.loads((repo_root / "framework" / "schemas" / name).read_text())


def _parse_config_schema(raw: Optional[dict]) -> dict:
    """Parse a config_schema mapping (shared by fetcher + category files)."""
    out = {}
    for field_name, spec in (raw or {}).items():
        spec = spec or {}
        out[field_name] = ConfigField(
            name=field_name,
            type=spec.get("type", "string"),
            required=spec.get("required", False),
            env=spec.get("env"),
            default=spec.get("default"),
            description=spec.get("description"),
        )
    return out


def discover_fetchers(repo_root: Path) -> Dict[str, Fetcher]:
    """Walk fetchers/*/*/fetcher.yaml. Returns {fetcher_name: Fetcher}.

    Raises ValueError on schema-invalid yaml or duplicate fetcher names.
    """
    schema = _load_schema(repo_root)
    validator = Draft202012Validator(schema)

    fetchers: Dict[str, Fetcher] = {}
    fetchers_root = repo_root / "fetchers"

    for category_dir in sorted(fetchers_root.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("_"):
            continue
        for fetcher_dir in sorted(category_dir.iterdir()):
            if not fetcher_dir.is_dir() or fetcher_dir.name.startswith("_"):
                continue
            yaml_path = fetcher_dir / "fetcher.yaml"
            if not yaml_path.exists():
                continue

            data = yaml.safe_load(yaml_path.read_text())
            errors = list(validator.iter_errors(data))
            if errors:
                detail = "\n".join(f"  {e.message}" for e in errors)
                raise ValueError(f"{yaml_path}: schema validation failed:\n{detail}")

            fetcher = _parse_fetcher(data, fetcher_dir)
            if fetcher.name in fetchers:
                raise ValueError(
                    f"Duplicate fetcher name '{fetcher.name}': "
                    f"{fetchers[fetcher.name].path} and {fetcher_dir}"
                )
            fetchers[fetcher.name] = fetcher

    return fetchers


def _parse_fetcher(data: dict, path: Path) -> Fetcher:
    secrets = [
        Secret(name=s["name"], env=s["env"], per_target=s.get("per_target", False))
        for s in data.get("secrets", [])
    ]

    target_schema = {}
    for field_name, spec in (data.get("target_schema") or {}).items():
        target_schema[field_name] = TargetField(
            name=field_name,
            type=spec.get("type", "string"),
            required=spec.get("required", True),
            env=spec.get("env"),
            default=spec.get("default"),
            description=spec.get("description"),
        )

    output = data["output"]
    runtime = data["runtime"]

    evidence_set = None
    raw_es = data.get("evidence_set")
    if raw_es:
        binding = None
        raw_binding = raw_es.get("schema_binding")
        if raw_binding:
            binding = SchemaBinding(
                schema_id=raw_binding["schema_id"],
                pinned_version=raw_binding["pinned_version"],
            )
        evidence_set = EvidenceSet(
            reference_id=raw_es["reference_id"],
            name=raw_es["name"],
            instructions=raw_es.get("instructions"),
            description=raw_es.get("description") or data["description"],
            schema_binding=binding,
        )

    return Fetcher(
        name=data["name"],
        version=data["version"],
        description=data["description"],
        category=data.get("category"),
        runtime_type=runtime["type"],
        runtime_entry=runtime["entry"],
        runtime_timeout=runtime.get("timeout"),
        output_type=output["type"],
        output_path=output["path"],
        output_aggregation=output.get("aggregation"),
        secrets=secrets,
        supports_targets=data.get("supports_targets", False),
        target_schema=target_schema,
        path=path.resolve(),
        config_schema=_parse_config_schema(data.get("config_schema")),
        evidence_set=evidence_set,
        ksis=list(data.get("ksis") or []),
    )


def discover_platforms(repo_root: Path) -> Dict[str, PlatformSpec]:
    """Load fetchers/_categories/<name>.yaml into {category: PlatformSpec}.

    Empty or absent files yield an empty spec for that category. Raises
    ValueError on schema-invalid category files.
    """
    schema = _load_schema(repo_root, "category_schema.json")
    validator = Draft202012Validator(schema)

    platforms: Dict[str, PlatformSpec] = {}
    categories_dir = repo_root / "fetchers" / "_categories"
    if not categories_dir.is_dir():
        return platforms

    for yaml_path in sorted(categories_dir.glob("*.yaml")):
        category = yaml_path.stem
        data = yaml.safe_load(yaml_path.read_text()) or {}
        errors = list(validator.iter_errors(data))
        if errors:
            detail = "\n".join(f"  {e.message}" for e in errors)
            raise ValueError(f"{yaml_path}: schema validation failed:\n{detail}")

        auth = data.get("auth") or {}
        platforms[category] = PlatformSpec(
            category=category,
            config_schema=_parse_config_schema(data.get("config_schema")),
            passthrough_env=list(auth.get("passthrough_env") or []),
            description=data.get("description"),
        )

    return platforms
