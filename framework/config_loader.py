"""Discover fetchers in the repo and validate their fetcher.yaml files.

Walks `fetchers/<category>/<short_name>/fetcher.yaml` and
`comparators/<category>/<short_name>/fetcher.yaml`, skipping any directory that
starts with `_` (e.g. _shared, _categories, _template).
"""

import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from jsonschema import Draft202012Validator

from framework import yaml_io
from framework.contract import (
    DEFAULT_EVIDENCE_FREQUENCY,
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
from framework.runner import dependency_graph

FETCHERS_DIR = "fetchers"
COMPARATORS_DIR = "comparators"


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


def _fetcher_dirs(tree_root: Path):
    for category_dir in sorted(tree_root.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("_"):
            continue
        for fetcher_dir in sorted(category_dir.iterdir()):
            if fetcher_dir.is_dir() and not fetcher_dir.name.startswith("_"):
                yield fetcher_dir


class Catalog(Dict[str, Fetcher]):
    """{fetcher_name: Fetcher}, plus `excluded`: {name: why} for each fetcher.yaml left out."""

    def __init__(self) -> None:
        super().__init__()
        self.excluded: Dict[str, str] = {}


def excluded(fetchers: Mapping[str, Fetcher]) -> Dict[str, str]:
    """What discovery left out, for a plain dict too."""
    return getattr(fetchers, "excluded", {})


def discover_fetchers(repo_root: Path) -> Catalog:
    """Walk fetchers/*/*/fetcher.yaml and comparators/*/*/fetcher.yaml into one namespace.

    Raises ValueError on schema-invalid yaml or duplicate names. A fetcher in the
    wrong tree, or a comparator whose inputs can't run, is left out instead and
    recorded in `excluded`, so it can't take the rest of the catalog down with it.
    """
    schema = _load_schema(repo_root)
    validator = Draft202012Validator(schema)

    fetchers = Catalog()
    trees = [repo_root / FETCHERS_DIR]
    if (repo_root / COMPARATORS_DIR).is_dir():
        trees.append(repo_root / COMPARATORS_DIR)

    for tree_root in trees:
        for fetcher_dir in _fetcher_dirs(tree_root):
            yaml_path = fetcher_dir / "fetcher.yaml"
            if not yaml_path.exists():
                continue

            data = yaml_io.load_path(yaml_path)
            # Before the schema, whose comparator rules would bury this in a list of errors.
            misplaced = _misplaced(data, tree_root.name == COMPARATORS_DIR)
            if misplaced:
                name = data.get("name") if isinstance(data, dict) else None
                fetchers.excluded[name if isinstance(name, str) else str(yaml_path)] = f"{yaml_path}: {misplaced}"
                continue

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

    for name, why in dependency_graph.invalid(fetchers, fetchers.excluded).items():
        fetchers.excluded[name] = f"{fetchers.pop(name).path / 'fetcher.yaml'}: {why}"
    return fetchers


def _misplaced(data: Any, in_comparators: bool) -> Optional[str]:
    declares_inputs = isinstance(data, dict) and bool(data.get("depends_on"))
    if declares_inputs and not in_comparators:
        return (
            f"declares depends_on, which now makes it a comparator. Move it to "
            f"{COMPARATORS_DIR}/<category>/<name>/ if it compares other fetchers' evidence; "
            f"otherwise delete depends_on, which fetchers never used"
        )
    if in_comparators and not declares_inputs:
        return (
            f"is under {COMPARATORS_DIR}/ but declares no depends_on; "
            f"a fetcher that collects from a source belongs under {FETCHERS_DIR}/"
        )
    return None


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
            frequency=raw_es.get("frequency", DEFAULT_EVIDENCE_FREQUENCY),
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
        depends_on=list(data.get("depends_on") or []),
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
        data = yaml_io.load_path(yaml_path) or {}
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
            selector_env=list(auth.get("selector_env") or []),
            credential_env=list(auth.get("credential_env") or []),
            requires=Requires(
                tools=list(requires.get("tools") or []),
                python_packages=list(requires.get("python_packages") or []),
            ),
            description=data.get("description"),
            display_name=data.get("display_name"),
        )

    return platforms
