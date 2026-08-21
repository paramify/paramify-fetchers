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
    IssueReport,
    PlatformSpec,
    Requires,
    Secret,
    TargetField,
)
from framework.issue_reports import reserved_config_schema


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


def _parse_secrets(raw) -> list:
    """Parse a `secrets:` block — the same shape in fetcher.yaml and a category file."""
    return [
        Secret(
            name=s["name"],
            env=s["env"],
            per_target=s.get("per_target", False),
            required=s.get("required", True),
            description=s.get("description"),
        )
        for s in (raw or [])
    ]


def _parse_fetcher(data: dict, path: Path) -> Fetcher:
    secrets = _parse_secrets(data.get("secrets"))

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
        evidence_set = EvidenceSet(
            reference_id=raw_es["reference_id"],
            name=raw_es["name"],
            instructions=raw_es.get("instructions"),
            description=raw_es.get("description") or data["description"],
        )

    issue_report = None
    raw_ir = data.get("issue_report")
    if raw_ir:
        issue_report = IssueReport(
            assessment_type=raw_ir["assessment_type"],
            title=raw_ir.get("title"),
        )

    config_schema = _parse_config_schema(data.get("config_schema"))
    if data.get("kind") == "issue_report":
        # Every issue-report fetcher takes the same two fields naming the
        # assessment its report is intaken into. Added here rather than declared
        # in each fetcher.yaml because they are framework knowledge, and because
        # a field that must be declared identically 30 times eventually won't be.
        # The fetcher's own config wins on a name clash, matching every other
        # merge in the loader.
        config_schema = {**reserved_config_schema(), **config_schema}

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
        config_schema=config_schema,
        evidence_set=evidence_set,
        ksis=list(data.get("ksis") or []),
        kind=data.get("kind", "evidence"),
        issue_report=issue_report,
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
        requires = data.get("requires") or {}
        platforms[category] = PlatformSpec(
            category=category,
            config_schema=_parse_config_schema(data.get("config_schema")),
            secrets=_parse_secrets(data.get("secrets")),
            passthrough_env=list(auth.get("passthrough_env") or []),
            requires=Requires(
                tools=list(requires.get("tools") or []),
                python_packages=list(requires.get("python_packages") or []),
            ),
            description=data.get("description"),
        )

    return platforms
