"""Load and validate run manifests."""

import json
from pathlib import Path
from typing import List

from jsonschema import Draft202012Validator

from framework import yaml_io
from framework.contract import Manifest, ManifestEntry, PlatformConfig, TargetInstance


def _load_schema(repo_root: Path) -> dict:
    schema_path = repo_root / "framework" / "schemas" / "run_manifest_schema.json"
    return json.loads(schema_path.read_text())


def schema_errors(data: dict, repo_root: Path) -> List[str]:
    """Return manifest schema-validation errors as readable strings (empty if valid)."""
    validator = Draft202012Validator(_load_schema(repo_root))
    return [
        f"{'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in validator.iter_errors(data)
    ]


def parse_manifest(data: dict) -> Manifest:
    """Build a Manifest from an already-loaded (and ideally schema-valid) dict.

    Pure structure mapping — does NOT schema-validate. Callers that read from
    disk go through load_manifest (which validates first); the api facade and
    in-memory editors validate separately via schema_errors().
    """
    run = data["run"]
    output_dir = Path(run.get("output_dir", "./evidence"))

    platforms = {}
    for category, pdata in (run.get("platforms") or {}).items():
        pdata = pdata or {}
        auth = pdata.get("auth") or {}
        platforms[category] = PlatformConfig(
            config=pdata.get("config") or {},
            passthrough_env=list(auth.get("passthrough_env") or []),
        )

    entries = []
    for entry in run["fetchers"]:
        targets = []
        for t in entry.get("targets") or []:
            secrets = t.get("secrets", {})
            values = {k: v for k, v in t.items() if k != "secrets"}
            targets.append(TargetInstance(values=values, secrets=secrets))

        entries.append(ManifestEntry(
            use=entry["use"],
            config=entry.get("config") or {},
            secrets=entry.get("secrets") or {},
            targets=targets,
        ))

    return Manifest(output_dir=output_dir, entries=entries, platforms=platforms)


def load_manifest(path: Path, repo_root: Path) -> Manifest:
    """Load a manifest yaml, validate against the manifest schema, return a Manifest.

    Raises ValueError if the file is schema-invalid.
    """
    data = yaml_io.load_path(path)
    errors = schema_errors(data, repo_root)
    if errors:
        detail = "\n".join(f"  {e}" for e in errors)
        raise ValueError(f"{path}: manifest validation failed:\n{detail}")
    return parse_manifest(data)
