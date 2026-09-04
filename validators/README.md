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
- **Three roles** (`role:`): each evidence set has exactly one `completeness`
  validator (did the collection succeed, is the population real), any number of
  `configuration` checks (is the posture right), and one `integrity` validator
  beside every configuration check that concludes from a *count* of violations
  (was the counted field actually there). A set passes only when all of its
  validators pass, so expect 2–5 per set.

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
  groups by number. Note `MATCH_GROUP` reads the **first** match only, so you
  cannot use groups to assert something about every item in a list — invert it
  into "the count of bad items is zero".
- **Guard the read.** A rule that reads nothing *passes*: a `MATCH_GROUP`
  comparison over a regex that missed compares nothing to nothing and evaluates
  true, and a count-of-violations rule reads a renamed key as zero violations.
  So open every validator with a presence rule:

  ```yaml
  - regexOperation: { type: MATCH_COUNT }
    criteria: NOT_EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
  ```

  A validator that *reads a value* guards itself this way. A validator that
  *counts violations* cannot — zero matches is its pass condition — so it needs
  a separate `role: integrity` validator proving the structural key exists.

Collection health is **not** part of a compliance validator. It lives once, in
[`common/collection_succeeded.yaml`](common/collection_succeeded.yaml), which
lists every evidence set that wants it. Add your `reference_id` there rather than
re-anchoring on `exit_code` in your own file. Its guards are written positively
(`MATCH_COUNT NOT_EQUALS 0`, `exit_code EQUALS 0`) because the REST API accepts
`disposition` and discards it — the negative `ERROR` form self-contradicts today
and yields a validator that can never pass.

See [`aws/alb_encryption_in_transit.yaml`](aws/alb_encryption_in_transit.yaml)
for a worked compliance validator.

Prove it before you commit. Write the three directions down in
[`_cases/<key>.yaml`](_cases/README.md) — compliant, non-compliant, and the key
**renamed** — then:

```bash
paramify validators check --select <your key>
```

That evaluates them with the real ECMAScript engine, including the semantics
that bite: `MATCH_GROUP` reads only the first match, rules combine with AND, and
a rule that read nothing still holds. The renamed-key direction is the one that
catches silent false passes and the one that gets skipped.

It is an authoring aid rather than a merge gate — nothing stops you committing a
validator without cases, but nothing then proves it can fail either.
