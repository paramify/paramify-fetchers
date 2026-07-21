# Versioning & contract policy

How this project versions itself, what we promise to keep stable, and what a
version bump means. Releases follow [Semantic Versioning](https://semver.org/)
against **the contract**, defined below — not the code, and not any single
fetcher.

## The contract = the public API surface

The thing we version and promise stability for is the **public API surface**,
not the internal implementation. It is:

- **`framework/schemas/fetcher_schema.json`** — the `fetcher.yaml` contract
- **`framework/schemas/category_schema.json`** — the `_categories/<name>.yaml` contract
- **`framework/schemas/run_manifest_schema.json`** — the run manifest format
- **`framework/schemas/envelope_schema.json`** — the evidence envelope, carried
  by its own `schema_version` (see below)
- **the `paramify` CLI** — its commands, subcommands, flags, and `--json` output
  shapes

Everything else is *not* contract and can change without a major bump: the
framework's internal Python modules, the runner/uploader internals, the TUI's
layout, a fetcher's implementation details, and the exact prose of human CLI
output. If you build automation against this project, build it against the
surface above.

## The three version axes

These move **independently**. A release bumps only the first; the other two are
edited by hand in their own files and are called out in the changelog.

| Axis | Where it lives | Scheme | Today |
|---|---|---|---|
| **Tool version** | git tag / GitHub Release (and `pyproject.toml`) | SemVer, applied to the contract | `0.2.0` |
| **Envelope `schema_version`** | `framework/envelope.py` → every evidence file's `schema_version` | SemVer, additive-only | `1.0` |
| **Per-fetcher `version`** | each `fetcher.yaml` | SemVer per fetcher | `0.x` (v0.x ports) |

- **Tool version** is the release train — what a tag `vX.Y.Z` and a GitHub
  Release name. This is what customers pin.
- **Envelope `schema_version`** stays **additive**: new optional fields only, so
  the runner and any downstream consumer keep reading older-versioned evidence.
  A non-additive envelope change is a contract break (see the bump table).
- **Per-fetcher `version`** tracks a single fetcher's own evolution and is
  independent of the tool version. Ported fetchers are `0.x` until they conform
  to the contract-native pattern.

## Bump policy

Apply this to a release by looking at everything merged since the last tag.

| Bump | Trigger |
|---|---|
| **major** | manifest format break · a CLI command/flag removed or renamed · envelope shape change (non-additive) · a new **required** `fetcher.yaml` field · a fetcher removed or its output shape changed |
| **minor** | new fetchers or categories · new **optional** config/target fields · new CLI commands/flags · additive envelope fields |
| **patch** | fetcher bug fixes · doc fixes · dependency bumps with no behavior change |

Take the highest bump that any single change triggers.

## Pre-1.0 and the meaning of 1.0

We are pre-1.0 (`0.x`). While under 1.0, **the contract is not yet frozen**: a
breaking change bumps the **minor** (e.g. `0.2 → 0.3`), not the major. This is
standard SemVer 0.x behavior and lets the contract still move as we learn from
early use.

**1.0 means the contract is frozen and supported.** After 1.0, any break in the
surface above requires a major bump and follows the deprecation policy
(announce → warn → remove across ≥1 minor cycle; see the deprecation issue).
Cutting 1.0 is a deliberate decision, not an automatic consequence of a break —
we ship it when the schemas, manifest, envelope, and CLI are ones we're willing
to stand behind for the long haul.

## See also

- [`docs/releasing.md`](releasing.md) — how a release is actually cut
- [`CHANGELOG.md`](../CHANGELOG.md) — the release history
- [`docs/envelope_design.md`](envelope_design.md) — the evidence envelope
