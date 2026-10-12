"""Discovery documents: what a platform's credentials can see.

A `kind: discovery` fetcher enumerates a platform and writes one document in the
shape of framework/schemas/discovery_schema.json. The runner points it at
`<run>/discovery/` and envelopes it like evidence, so the run id, exit code and
failure reason travel with it. Neither uploader reads that directory: discovery
output describes a tenant, it is not a claim about one.

This module is the platform-agnostic half: find the documents in a run, unwrap
them, and validate them against the schema. Every platform's fetcher emits the
same shape.

See docs/discovery.md.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Optional, Tuple

from jsonschema import Draft202012Validator

from framework.envelope import is_enveloped

# Subdirectory of the run dir discovery fetchers write to. The runner points
# EVIDENCE_DIR here for a discovery fetcher, so fetchers never name it.
DISCOVERY_DIR = "discovery"

_SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "discovery_schema.json"


def _validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(_SCHEMA_PATH.read_text()))


def validate(doc: Any) -> List[str]:
    """Schema violations in a discovery document, as readable strings. Empty = valid.

    Adds the one rule JSON Schema cannot say: each (type, scope) pair appears
    once, or a reader would add the same listing up twice."""
    errors = sorted(_validator().iter_errors(doc), key=lambda e: list(e.path))
    out = [f"{'/'.join(str(p) for p in e.path) or '(root)'}: {e.message}" for e in errors]
    seen = set()
    resources = doc.get("resources") if isinstance(doc, dict) else None
    for i, res in enumerate(resources if isinstance(resources, list) else []):
        if not isinstance(res, dict):
            continue
        key = (res.get("type"), json.dumps(res.get("scope") or {}, sort_keys=True))
        if key in seen:
            out.append(f"resources/{i}: duplicate entry for type {res.get('type')!r} in scope {key[1]}")
        seen.add(key)
    return out


def load(path: Path) -> Tuple[Optional[dict], dict]:
    """(envelope metadata or None, discovery document) from one file.

    Accepts the enveloped file the runner leaves behind and the bare document a
    fetcher writes when run by hand.
    """
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"{path}: cannot read as JSON ({e})") from e
    if is_enveloped(raw):
        return raw.get("metadata") or {}, raw.get("payload")
    return None, raw


def find_documents(path: Path) -> List[Path]:
    """The discovery documents at `path`: a file, a run dir, or its discovery/ dir."""
    p = Path(path)
    if p.is_file():
        return [p]
    if (p / DISCOVERY_DIR).is_dir():
        p = p / DISCOVERY_DIR
    if not p.is_dir():
        raise ValueError(f"{path}: no such file or directory")
    return sorted(
        f for f in p.glob("*.json") if not f.name.startswith("_")
    )
