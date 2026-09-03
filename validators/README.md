# Validators registry

Central, deduplicated home for Paramify **validators** — the regex/attestation
checks that assert a fetcher's evidence structurally shows a control is being
implemented. Validators used to be sketched inline in `fetcher.yaml`; they now
live here as first-class objects.

## Model

- **One validator = one file:** `validators/<category>/<key>.yaml`, where the
  basename equals the file's `key`.
- **The link lives on the validator.** Each validator lists every evidence set
  it applies to under `evidence_sets` (by `reference_id`). A validator shared
  across fetchers is a **single file with multiple `evidence_sets` entries** —
  we never copy a validator. This mirrors how Paramify itself models a
  validator (it owns its evidence-set list).
- **A fetcher's validators = reverse lookup:** every registry file whose
  `evidence_sets` includes that fetcher's `evidence_set.reference_id`.
- **Two roles** (`role:`): each evidence set has exactly one `completeness`
  validator (full-population check) plus any number of `configuration` checks.

## Authoring

Copy [`_template/validator.yaml`](_template/validator.yaml) to
`validators/<category>/<key>.yaml` and fill it in. `_`-prefixed directories
(like `_template`) are not part of the registry.

Three rules for the `regex` of an AUTOMATED validator — each guards a failure
mode that is otherwise silent (full rationale in
[`docs/validators_design.md`](../docs/validators_design.md)):

- **Write ECMAScript, not Python.** Paramify's engine is JavaScript. It applies
  `g` and `s` automatically but never `m`, so span lines with `[\s\S]*?`. Named
  groups are `(?<name>…)` — the Python `(?P<name>…)` is a hard compile error.
  Test with `node`, not `python -c 'import re'`.
- **Name every capture group**, in `snake_case` from the key it captures.
  Naming does not renumber anything, so `validation_rules` still references
  groups by number.
- **Carry an error state.** Anchor on the envelope's `exit_code` and add two
  `disposition: ERROR` rules, so a failed *collection* reports as unknown rather
  than as a compliance failure:

  ```
  "exit_code":\s*(?<exit_code>-?\d+)(?:[\s\S]*?<compliance pattern>)?
  ```

  `MATCH_COUNT EQUALS 0 -> ERROR` (the anchor is gone) and
  `MATCH_GROUP[1] NOT_EQUALS 0 -> ERROR` (collection failed). Your compliance
  groups then start at 2. See
  [`aws/alb_encryption_in_transit.yaml`](aws/alb_encryption_in_transit.yaml) for
  a worked example.

- **Shape / field reference:** [`framework/schemas/validator_schema.json`](../framework/schemas/validator_schema.json)
- **Design & rationale:** [`docs/validators_design.md`](../docs/validators_design.md)
