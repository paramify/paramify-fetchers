# Vendored schemas

Pinned copies of the external JSON Schemas that fetcher outputs can declare
conformance to (via `evidence_set.schema_binding` in `fetcher.yaml`). The
verify stage (`framework/verify/`) validates artifacts against **these files
only** — every `$ref` resolves through a local registry built from this
directory, never over the network. A validation gate that depends on a remote
host is not a gate; vendoring is what makes the check deterministic and
offline.

## Layout

- `index.yaml` — the store's source of truth. Each entry records the schema's
  original `$id`, the pinned `version`, the `file` it lives in (relative to
  this directory), the upstream `source_url`, and the `retrieved` date.
- Schema files keep their **original `$id`** unchanged — that `$id` is how
  bindings and cross-schema `$ref`s select them.
- Shared-base pattern: when several report schemas `$ref` one common
  definitions file, the shared file is vendored **once** and the report
  schemas sit on top of it. The `fixtures/` pair (`sample-report.json` →
  `common-defs.json`) demonstrates exactly this; real report schemas get
  dropped in beside them later.

## Current entries

| `$id` | Version | Source | Retrieved |
|---|---|---|---|
| `https://fixtures.paramify.invalid/schemas/common-defs.json` | 1.0.0 | repo-authored fixture (no upstream) | 2026-07-15 |
| `https://fixtures.paramify.invalid/schemas/sample-report.json` | 1.0.0 | repo-authored fixture (no upstream) | 2026-07-15 |

The fixtures use an RFC 2606 `.invalid` host in their `$id`s on purpose: the
domain can never resolve, so even an accidental network dereference fails
loudly instead of silently fetching something.

## Adding or bumping a schema (a reviewed change, never automatic)

1. Download the schema (and any files it `$ref`s) from the publisher at a
   specific tagged version/date. Vendor every transitive `$ref` target — the
   store must be closed under `$ref`.
2. Commit the files here unmodified (keep the original `$id`s).
3. Add/update the `index.yaml` entry: `$id`, pinned version, file path,
   `source_url`, retrieval date. **One version per `$id` at a time** — the
   registry is keyed by `$id`, so a bump replaces the entry and file rather
   than adding a sibling.
4. Update every `fetcher.yaml` whose `schema_binding.pinned_version` names the
   old version, in the same PR. A fetcher pinned to a version the store no
   longer has is a **hard error** at verify time (by design — validating
   against the wrong version silently is worse than failing).
5. PR review is the gate: a schema bump changes what "conformant" means for
   every artifact bound to it, so it ships as a deliberate, reviewed change —
   never fetched or refreshed at runtime.
