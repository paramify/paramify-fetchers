# Discovery notes — schema verification stage

Grounding pass for the schema-verification build (Step 0). Everything below was
read from the repo on branch `feat/validator-registry-and-sync`; where the build
spec and the repo disagree, the repo's shape is recorded here and wins.

## Where things live

| Concern | Location |
|---|---|
| Facade (all front-ends) | `framework/api.py` — `run()` is the orchestration loop |
| Envelope wrapping | `framework/envelope.py` — `wrap_outputs()` / `build_metadata()`, called per invocation result from `api.run()` (`api.py:638`) |
| Execution | `framework/runner/executor.py` — `run_entry()` → `_invoke()`; owns exit codes and per-target isolation |
| Schema tooling | `framework/schemas/*.json`, validated with `jsonschema.Draft202012Validator` (see `config_loader.py:50`) |
| Fetcher discovery + `fetcher.yaml` validation | `framework/config_loader.py` — `discover_fetchers()` validates each `fetcher.yaml` against `fetcher_schema.json` at discovery time |
| Uploader | `uploaders/paramify_evidence/uploader.py` — standalone module, loaded by path (not an importable package); deliberately reads nothing from fetcher source |

## Literal answers to the Step 0 questions

### Envelope `metadata` field names (exact)

Built in `framework/envelope.py:build_metadata()`:

`fetcher_name`, `fetcher_version`, `category`, `run_id`, `target`,
`collected_at`, `status` (`"success"` iff `exit_code == 0`, else `"failed"` —
enum-enforced by `envelope_schema.json`), `exit_code`, optional `error`
(stderr tail, capped at 4000 chars, only when `exit_code != 0`), optional
`evidence_set` (`{reference_id, name, instructions?, description?}`).

One metadata dict is built **per invocation** and stamped into every JSON
output file of that invocation. The `_run_metadata.json` run index is not
enveloped and records per-invocation `exit_code` + `outputs` (built in
`api.py:_invocation_record()` *after* `wrap_outputs` runs — so anything that
mutates an invocation's exit code before wrapping flows into the run index and
the `fetcher_result` event too).

### `evidence_set` block shape in `fetcher.yaml` (exact)

From `fetcher_schema.json` + `config_loader._parse_fetcher()`:

```yaml
evidence_set:
  reference_id: EVD-...        # required
  name: ...                    # required
  instructions: ...            # optional
  description: ...             # optional (defaults to the fetcher's top-level description)
```

Parsed into `framework/contract.py:EvidenceSet`. This is where the artifact's
schema identity lives, so the new `schema_binding` goes here.

### Exit codes the runner currently emits

The README's claim ("binary `0`/`1` plus `124`") is **incomplete** — confirmed
against code:

- `0` — collection succeeded (fetcher-returned).
- non-zero (conventionally `1`) — collection failure; fetcher-defined
  (`docs/fetcher_contract.md` § Output). Fetchers own this value, so nothing
  guarantees a fetcher never exits `2` on its own (bash tools can).
- `124` — runner kill on timeout (`executor.py:_TIMEOUT_EXIT_CODE`).
- `255` — runner-synthesized "failed to set up target invocation" during
  fanout (`executor.py:362`, secret-resolution/config errors). Not documented
  in README/contract; noted here as a discrepancy, left as-is.

**Consequence for the new code `2`:** the runner only *assigns* `2` when an
invocation collected successfully (`exit_code == 0`) and its artifact failed
its declared schema. A fetcher's own exit `2` carries no `validation` metadata
block, so the authoritative held-from-upload signal is
`metadata.validation.ok == false`, not the bare exit code. The uploader keys on
the metadata block for exactly this reason.

### JSON Schema draft + library

- Draft **2020-12** everywhere: every `framework/schemas/*.json` declares
  `"$schema": "https://json-schema.org/draft/2020-12/schema"` and all
  validation uses `jsonschema.Draft202012Validator` (config_loader,
  manifest_loader, tests).
- Installed: `jsonschema 4.23.0` with `referencing 0.37.0` (referencing is a
  dependency of jsonschema ≥4.18, already present — **no new dependency** is
  needed for local `$ref` registries; `Draft202012Validator(schema,
  registry=...)` is supported).

### Uploader enumeration + filtering (exact)

`uploaders/paramify_evidence/uploader.py`:

- Enumerates via `iter_evidence_files(run_dir)`: `run_dir.glob("*.json")`
  minus `_run_metadata.json` and `upload_log.json` (`uploader.py:149`).
- Per file it filters on, in order: JSON-parseable → envelope-shaped
  (`is_enveloped`) → `metadata.evidence_set` present with `reference_id` +
  `name` → optional `skip_failed` config (`metadata.status == "failed"`) →
  dry-run short-circuit → get-or-create set → duplicate check
  (`artifact_exists`, filename + `run_id` token) → upload.
- Per-file isolation already exists: any exception is caught per file and the
  batch continues (`uploader.py:299` comment, `test_uploader.py` proves it).
- Outcome vocabulary: `uploaded`, `would_upload`, `skipped_duplicate`,
  `skipped_failed`, `error`; summary counts each and `ok = (errors == 0)`.
  The new held-for-validation outcome joins this vocabulary
  (`held_validation`) rather than reusing `error` — a held artifact is an
  expected, explainable outcome.

## Other grounding facts the build relies on

- **`{ok, path, errors}` convention**: manifest edit surface returns
  `{"ok", "path", "errors"}` (`README.md:99`, cli). `VerifyResult` mirrors the
  `{ok, errors}` core of that shape.
- **`run()` wiring point**: `api.run()` loops `for r in results:
  wrap_outputs(r, fetcher, run_id, run_dir)` then emits `fetcher_result` and
  finally builds `_run_metadata.json` from the same result objects — so the
  verify step slots in immediately before `wrap_outputs`, mutating
  `r.exit_code` at most once, and every downstream record stays consistent.
- **Envelope schema is the test oracle**: `tests/test_envelope.py` validates
  wrapped output against `envelope_schema.json` itself, so the new
  `metadata.validation` block must be added to that schema (additive,
  optional) or the existing tests fail.
- **Naming hazard**: the repo already has "validators" — the inline
  `fetcher.yaml` `validators` array on `main`, becoming a central `validators/`
  registry + `paramify validators sync` on the in-flight
  `feat/validator-registry-and-sync` branch — meaning Paramify-side
  evidence-content validators (regex checks). The new stage is deliberately
  named **verify** (`framework/verify/`) and its metadata block `validation`
  refers to *schema conformance only*; docs must keep the two vocabularies
  apart.
- **Uploader is standalone by design** ("reads nothing from fetcher source",
  `uploader.py` docstring) — so it does not import `framework.verify`; the
  exit-code constant is duplicated there with a comment, and the primary
  signal is the self-describing envelope.
- **Test patterns to match**: builders (`make_fetcher`/`make_result`) in
  `tests/test_envelope.py` / `test_executor.py`; uploader tests fake only the
  HTTP boundary (`FakeClient`) and monkeypatch `uploader.ParamifyClient`;
  contract regression is `tests/test_contracts.py`, which parametrizes every
  real `fetcher.yaml` against `fetcher_schema.json` (this is required test #7,
  already in place — it just has to stay green).

## Spec ↔ repo discrepancies (repo wins)

1. **Exit codes**: spec/README say current codes are `0`/`1`/`124`; the code
   also emits `255` (fanout setup failure). `2` collides with neither, but see
   the fetcher-own-exit-2 caveat above.
2. **"The runner wraps output in the envelope"** — actually `api.run()` (the
   facade) calls `wrap_outputs`, not `framework/runner/executor.py`. "Runner"
   in the spec maps to the `api.run()` orchestration loop; the wiring lands
   there.
3. **Metadata is per-invocation, not per-artifact** — one invocation can emit
   several JSON files sharing one metadata dict. Verification is per-file, so
   the `validation` block is stamped per file (the shared dict is copied per
   file when validation ran), and the invocation's exit code becomes `2` if
   *any* of its files fail.
