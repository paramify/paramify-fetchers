"""Schema verification stage — validate an artifact against its declared schema.

A fetcher may declare (via evidence_set.schema_binding in fetcher.yaml) that its
payload conforms to a vendored JSON Schema. This module is the pure "compute"
half of that gate: given a payload, a binding, and the vendored store, verify()
returns a structured VerifyResult. The runner (framework.api.run) owns the
"record" half — it writes the result into envelope metadata and sets the exit
code. Fetchers never touch either.

Deliberately schema-agnostic: nothing here knows what report type a schema
describes — the binding selects the schema, never a code path. Adding a new
report type is a new fetcher + a new vendored schema + a binding; this module
does not change.

Deterministic and offline: schemas come from framework/schemas/vendored/ (see
its README), and every $ref resolves through a referencing.Registry built from
those files only. An unresolvable $ref or a pinned_version the store doesn't
have is a hard SchemaStoreError, never a network fetch or a silent fallback.

This checks schema conformance only — "is the artifact structurally valid
against the schema it claims" — a build-correctness gate in the same category as
the fetcher.yaml-against-schema check. Whether the compliance *content* is
correct stays a Paramify-side judgment (and is the province of the
evidence-content *validators*, an unrelated concept despite the similar name).
"""

import json
from dataclasses import dataclass, field
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Dict, List

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT202012

from framework.contract import SchemaBinding

# Exit code the RUNNER assigns when an invocation collected successfully but its
# artifact failed its declared schema. Distinct from 1 (collection failure) and
# 124 (timeout-kill) — "couldn't collect" and "built a non-conformant artifact"
# are different problems to debug, and the uploader holds only the latter.
# Assigned post-hoc by the runner, never returned by a fetcher itself; the
# authoritative signal is envelope metadata.validation, not the bare code.
SCHEMA_VALIDATION_EXIT_CODE = 2

# Bound the recorded error list so a wildly non-conformant payload can't bloat
# its own envelope; error_count still reports the true total.
_MAX_RECORDED_ERRORS = 50

VALIDATOR_ID = f"jsonschema {importlib_metadata.version('jsonschema')}"


class SchemaStoreError(RuntimeError):
    """The vendored store cannot serve a binding (unknown $id, pinned_version
    mismatch, un-vendored $ref, malformed store). Always a hard error: a gate
    that validates against the wrong schema is worse than no gate."""


@dataclass
class VerifyResult:
    """Structured outcome of one artifact-against-schema check.

    Mirrors the {ok, errors} core of the repo's stable --json shapes. Each
    error is machine-readable: a JSON-pointer-style path to the failing
    location plus the validator's message.
    """
    ok: bool
    schema_id: str
    pinned_version: str
    validator: str = VALIDATOR_ID
    errors: List[dict] = field(default_factory=list)
    error_count: int = 0

    def to_metadata(self) -> dict:
        """The `validation` block the runner records in envelope metadata."""
        return {
            "schema_id": self.schema_id,
            "pinned_version": self.pinned_version,
            "validator": self.validator,
            "ok": self.ok,
            "errors": self.errors,
            "error_count": self.error_count,
        }


class SchemaStore:
    """The vendored schema store: framework/schemas/vendored/ + its index.yaml.

    Loads every indexed schema once, keyed by $id, and exposes a
    referencing.Registry over exactly those resources — so $ref resolution can
    only ever touch vendored files. The index pins one version per $id; a
    lookup naming any other version raises.
    """

    def __init__(self, store_dir: Path):
        self.store_dir = Path(store_dir)
        index_path = self.store_dir / "index.yaml"
        if not index_path.is_file():
            raise SchemaStoreError(
                f"vendored schema store index not found: {index_path}"
            )
        raw = yaml.safe_load(index_path.read_text()) or {}
        entries = raw.get("schemas") or []

        self._schemas: Dict[str, dict] = {}       # $id -> schema contents
        self._versions: Dict[str, str] = {}       # $id -> pinned version
        for entry in entries:
            schema_id = entry.get("schema_id")
            version = entry.get("version")
            file_rel = entry.get("file")
            if not (schema_id and version and file_rel):
                raise SchemaStoreError(
                    f"{index_path}: entry must declare schema_id, version, and file: {entry}"
                )
            if schema_id in self._schemas:
                raise SchemaStoreError(
                    f"{index_path}: duplicate schema_id {schema_id!r} — the store "
                    f"pins one version per $id at a time (see vendored/README.md)"
                )
            schema_path = self.store_dir / file_rel
            if not schema_path.is_file():
                raise SchemaStoreError(
                    f"{index_path}: {schema_id!r} points at missing file {schema_path}"
                )
            try:
                contents = json.loads(schema_path.read_text())
            except ValueError as e:
                raise SchemaStoreError(f"{schema_path}: not valid JSON: {e}")
            if contents.get("$id") != schema_id:
                raise SchemaStoreError(
                    f"{schema_path}: $id {contents.get('$id')!r} does not match "
                    f"index entry {schema_id!r} (vendored schemas keep their original $id)"
                )
            self._schemas[schema_id] = contents
            self._versions[schema_id] = str(version)

        self._registry = Registry().with_resources(
            (sid, Resource.from_contents(s, default_specification=DRAFT202012))
            for sid, s in self._schemas.items()
        )

    @classmethod
    def default(cls, repo_root: Path) -> "SchemaStore":
        return cls(Path(repo_root) / "framework" / "schemas" / "vendored")

    @property
    def registry(self) -> Registry:
        return self._registry

    def resolve(self, schema_id: str, pinned_version: str) -> dict:
        """The vendored schema for (schema_id, pinned_version), or raise."""
        if schema_id not in self._schemas:
            raise SchemaStoreError(
                f"schema {schema_id!r} is not in the vendored store "
                f"({self.store_dir}); vendor it before binding to it"
            )
        stored = self._versions[schema_id]
        if stored != pinned_version:
            raise SchemaStoreError(
                f"pinned_version mismatch for {schema_id!r}: fetcher expects "
                f"{pinned_version!r} but the store has {stored!r} — update the "
                f"binding or re-vendor (never validate against the wrong version)"
            )
        return self._schemas[schema_id]


def _json_pointer(error) -> str:
    """JSON-pointer-ish path to a validation error ('' = document root)."""
    return "/" + "/".join(str(p) for p in error.absolute_path) if error.absolute_path else ""


def verify(
    artifact_payload,
    schema_binding: SchemaBinding,
    schema_store: SchemaStore,
) -> VerifyResult:
    """Validate one artifact payload against its declared schema binding.

    Pure: no file or network I/O beyond the already-loaded store. Returns a
    VerifyResult for conformant/non-conformant payloads; raises SchemaStoreError
    when the gate itself cannot run (unknown schema, version mismatch,
    un-vendored $ref) — callers must treat that as a failure, not a pass.
    """
    schema = schema_store.resolve(schema_binding.schema_id, schema_binding.pinned_version)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as e:
        raise SchemaStoreError(
            f"vendored schema {schema_binding.schema_id!r} is not a valid "
            f"2020-12 schema: {e.message}"
        )

    validator = Draft202012Validator(schema, registry=schema_store.registry)
    try:
        raw_errors = sorted(
            validator.iter_errors(artifact_payload),
            key=lambda e: (_json_pointer(e), e.message),
        )
    except Unresolvable as e:
        raise SchemaStoreError(
            f"$ref in {schema_binding.schema_id!r} cannot resolve against the "
            f"vendored store (refs are never fetched remotely): {e}"
        )

    errors = [
        {"path": _json_pointer(e), "message": e.message}
        for e in raw_errors[:_MAX_RECORDED_ERRORS]
    ]
    return VerifyResult(
        ok=not raw_errors,
        schema_id=schema_binding.schema_id,
        pinned_version=schema_binding.pinned_version,
        errors=errors,
        error_count=len(raw_errors),
    )


__all__ = [
    "SCHEMA_VALIDATION_EXIT_CODE",
    "SchemaStore",
    "SchemaStoreError",
    "VerifyResult",
    "verify",
]
