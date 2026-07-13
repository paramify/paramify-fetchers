"""Discover fetchers across the content roots and validate their fetcher.yaml files.

Walks `<root>/<category>/<short_name>/fetcher.yaml` for each root, skipping any
directory that starts with `_` (e.g. _shared, _categories, _template). Roots
come from framework.roots (overlay search path: env override → dev checkout →
user dir → installed bundle); within one root a duplicate fetcher name is a
hard error, across roots the earlier root wins and the shadow is reported.
"""

import json
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence, Union

import yaml
from jsonschema import Draft202012Validator

from framework.contract import (
    ConfigField,
    EvidenceSet,
    Fetcher,
    PlatformSpec,
    Secret,
    TargetField,
)

Roots = Union[str, Path, Sequence[Path]]


def load_schema(name: str = "fetcher_schema.json") -> dict:
    """Load a contract schema. Schemas are core, not content: they resolve from
    the framework package itself (source tree and normal installs alike), with
    an importlib.resources fallback for zip imports."""
    local = Path(__file__).parent / "schemas" / name
    if local.exists():
        return json.loads(local.read_text())
    from importlib import resources
    return json.loads(
        resources.files("framework").joinpath("schemas").joinpath(name).read_text()
    )


def _as_fetchers_roots(roots: Roots) -> List[Path]:
    """Normalize the roots argument. A single path is a legacy repo root (its
    fetchers/ subdir is the root); a sequence is an ordered list of fetchers/
    dirs, as produced by framework.roots.fetcher_roots()."""
    if isinstance(roots, (str, Path)):
        return [Path(roots) / "fetchers"]
    return [Path(r) for r in roots]


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


class DiscoveryResult(NamedTuple):
    fetchers: Dict[str, Fetcher]
    shadows: List[dict]   # cross-root name collisions: {name, winner, shadowed}
    invalid: List[dict]   # unloadable fetcher.yaml files: {path, detail}


def _walk_root(
    root: Path, validator: Draft202012Validator, invalid: List[dict]
) -> Dict[str, Fetcher]:
    """Walk one fetchers/ root. A schema-invalid or unparseable fetcher.yaml is
    recorded in `invalid` and skipped — refuse, don't crash: one broken fetcher
    (typically a user's work in progress) must not take down discovery. A
    duplicate fetcher name within this root stays a hard error (duplicates
    across roots are shadowing, handled by the caller)."""
    fetchers: Dict[str, Fetcher] = {}
    for category_dir in sorted(root.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("_"):
            continue
        for fetcher_dir in sorted(category_dir.iterdir()):
            if not fetcher_dir.is_dir() or fetcher_dir.name.startswith("_"):
                continue
            yaml_path = fetcher_dir / "fetcher.yaml"
            if not yaml_path.exists():
                continue

            try:
                data = yaml.safe_load(yaml_path.read_text())
            except yaml.YAMLError as exc:
                invalid.append({"path": str(yaml_path), "detail": f"  {exc}"})
                continue
            errors = list(validator.iter_errors(data))
            if errors:
                detail = "\n".join(f"  {e.message}" for e in errors)
                invalid.append({"path": str(yaml_path), "detail": detail})
                continue

            fetcher = _parse_fetcher(data, fetcher_dir)
            if fetcher.name in fetchers:
                raise ValueError(
                    f"Duplicate fetcher name '{fetcher.name}': "
                    f"{fetchers[fetcher.name].path} and {fetcher_dir}"
                )
            fetchers[fetcher.name] = fetcher
    return fetchers


def discover(roots: Roots) -> DiscoveryResult:
    """Discover fetchers across the ordered roots.

    Earlier roots win a name collision — that's the override mechanism — and
    every collision is reported in `shadows` so catalog/doctor can surface it
    rather than resolve it silently. Broken fetcher.yaml files land in
    `invalid` (skipped, reported, never fatal).
    """
    validator = Draft202012Validator(load_schema())
    fetchers: Dict[str, Fetcher] = {}
    shadows: List[dict] = []
    invalid: List[dict] = []
    for root in _as_fetchers_roots(roots):
        if not root.is_dir():
            continue
        for name, fetcher in _walk_root(root, validator, invalid).items():
            if name in fetchers:
                shadows.append({
                    "name": name,
                    "winner": str(fetchers[name].path),
                    "shadowed": str(fetcher.path),
                })
            else:
                fetchers[name] = fetcher
    return DiscoveryResult(fetchers, shadows, invalid)


def discover_fetchers(roots: Roots) -> Dict[str, Fetcher]:
    """Discover fetchers across the roots (see discover()). Accepts a legacy
    single repo root or an ordered list of fetchers/ dirs.

    Strict variant: raises ValueError on the first schema-invalid fetcher.yaml
    (as the single-root loader always did) or on duplicate names within a root.
    """
    result = discover(roots)
    if result.invalid:
        first = result.invalid[0]
        raise ValueError(f"{first['path']}: schema validation failed:\n{first['detail']}")
    return result.fetchers


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
        evidence_set = EvidenceSet(
            reference_id=raw_es["reference_id"],
            name=raw_es["name"],
            instructions=raw_es.get("instructions"),
            description=raw_es.get("description") or data["description"],
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


def discover_platforms(roots: Roots) -> Dict[str, PlatformSpec]:
    """Load <root>/_categories/<name>.yaml across the ordered roots into
    {category: PlatformSpec}. The first root wins per category file — so a
    user-dir category file (a new platform, or a deliberate override) shadows
    the shipped one as a whole.

    Empty or absent files yield an empty spec for that category. Raises
    ValueError on schema-invalid category files.
    """
    schema = load_schema("category_schema.json")
    validator = Draft202012Validator(schema)

    platforms: Dict[str, PlatformSpec] = {}
    for root in _as_fetchers_roots(roots):
        categories_dir = root / "_categories"
        if not categories_dir.is_dir():
            continue

        for yaml_path in sorted(categories_dir.glob("*.yaml")):
            category = yaml_path.stem
            if category in platforms:  # an earlier root already defined it
                continue
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
