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

import yaml
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
        source=data.get("source") or "paramify",
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


# --------------------------------------------------------------------------- #
# Per-fetcher validator selection in the manifest.
#
#   - use: some_fetcher
#     validators: [key_a, key_b]     # the exact tracked list (pinned)
#
# No `validators:` on an entry = the defaults: every Paramify-made validator
# for the fetcher's evidence set. Unticking only stops tracking; nothing is
# removed from the workspace.


def available_for(ref: str, validators: Iterable[Validator]) -> List[Validator]:
    """Every registry validator that applies to one evidence set."""
    return [v for v in validators if ref in v.evidence_sets]


def default_keys(available: Iterable[Validator]) -> List[str]:
    return [v.key for v in available if v.source == "paramify"]


def tracked_for(entry: dict, ref: str, validators: Iterable[Validator]) -> List[Validator]:
    """The validators a manifest entry tracks for its evidence set."""
    avail = available_for(ref, validators)
    chosen = entry.get("validators") if isinstance(entry, dict) else None
    keys = set(default_keys(avail) if chosen is None else chosen)
    return [v for v in avail if v.key in keys]


def manifest_tracked_sets(manifest: dict, fetchers: Dict[str, Fetcher],
                          validators: Iterable[Validator], refs: Set[str] | None = None) -> Dict[str, List[str]]:
    """Each tracked validator's key -> the manifest's evidence sets that track it, in manifest order
    (optionally only for `refs`). A validator listed against many sets is paired only with these."""
    validators = list(validators)
    out: Dict[str, List[str]] = {}
    for entry in (manifest.get("run") or {}).get("fetchers") or []:
        name = entry.get("use") if isinstance(entry, dict) else None
        fetcher = fetchers.get(name) if name else None
        if not fetcher or not fetcher.evidence_set or fetcher.is_pipeline:
            continue
        ref = fetcher.evidence_set.reference_id
        if refs is not None and ref not in refs:
            continue
        for v in tracked_for(entry, ref, validators):
            sets = out.setdefault(v.key, [])
            if ref not in sets:
                sets.append(ref)
    return out


def manifest_tracked(manifest: dict, fetchers: Dict[str, Fetcher],
                     validators: Iterable[Validator], refs: Set[str] | None = None) -> List[Validator]:
    """Union of what the manifest's entries track (optionally only for `refs`)."""
    validators = list(validators)
    by_key = {v.key: v for v in validators}
    return [by_key[k] for k in manifest_tracked_sets(manifest, fetchers, validators, refs)]


def write_regex(path: Path, regex: str) -> None:
    """Set the `regex:` of one registry file, keeping the rest of it (comments
    included) as written. Only a one-line `regex:` is replaced, single-quoted as
    the registry writes them; the file is read back to prove the value landed.

    Raises ValueError when the file has no one-line `regex:` to replace (a
    block scalar, or a quoted or plain one continued on the next lines), or
    doesn't parse.
    """
    path = Path(path)
    original = path.read_text()
    lines = original.splitlines(keepends=True)
    at = [i for i, line in enumerate(lines) if line.startswith("regex:")]
    one_line = f"{path.name} has no one-line regex: to replace (it spans several lines). Edit it by hand."
    if len(at) != 1:
        raise ValueError(one_line)
    try:
        whole = (yaml_io.load(original) or {}).get("regex")
        alone = (yaml_io.load(lines[at[0]]) or {}).get("regex")
    except yaml.YAMLError:
        # A quoted value left open on its line doesn't parse alone: it goes on below.
        raise ValueError(one_line) from None
    except AttributeError:
        raise ValueError(f"{path.name} isn't a validator file. Edit it by hand.") from None
    if alone != whole:  # the value goes on past its line (a block, or a continued scalar)
        raise ValueError(one_line)
    quoted = "'" + regex.replace("'", "''") + "'"
    lines[at[0]] = f"regex: {quoted}\n"
    text = "".join(lines)
    try:
        landed = (yaml_io.load(text) or {}).get("regex")
    except (yaml.YAMLError, AttributeError):
        landed = None
    if landed != regex:
        raise ValueError(f"The regex wouldn't read back the same from {path.name}. Edit it by hand.")
    path.write_text(text)
