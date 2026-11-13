# Authoring the validator set

Read this when you know what you are asserting and need to turn it into files.
Covers the three roles, the two rule forms, and the regex engine's real
behaviour. The engine section is the one that bites: it is ECMAScript, not
Python, and several of its properties are invisible until a validator silently
stops working.

## Contents

- [The three roles](#the-three-roles)
- [The collection-health validator](#the-collection-health-validator)
- [Compliance validators: the two forms](#compliance-validators-the-two-forms)
- [The integrity partner](#the-integrity-partner)
- [Writing the regex](#writing-the-regex)

## The three roles

An evidence set passes only when every validator on it passes, so a control is
covered by a *set*, not a validator. The `role:` field records which job each
one does.

| `role` | Asserts | How many |
|---|---|---|
| `completeness` | the collection succeeded and the population is real | exactly one per evidence set |
| `configuration` | the posture is right | as many as the control needs |
| `integrity` | the field a count-based rule reads was actually present | one per count-based configuration validator |

Two to five validators per evidence set is the range both arms of a measured
A/B on live AWS evidence converged on without being told to. Fewer usually
means something in the narrative is unasserted; many more usually means one
assertion has been split into fragments that cannot fail independently.

## The collection-health validator

Every evidence set gets exactly one. It asserts the run succeeded and the
envelope is intact, so a failed collection never reads as a compliance verdict.

```yaml
regex: '"exit_code":\s*(?<exit_code>-?\d+)'
validation_rules:
  - regexOperation: { type: MATCH_COUNT }        # the envelope is there at all
    criteria: NOT_EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
  - regexOperation: { type: MATCH_GROUP, groupNumber: 1 }
    criteria: EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
```

**Why the guards are written positively.** Paramify's rule model has a
`disposition` of `PASS`/`FAIL`/`ERROR`, and `ERROR` is the right label here —
"the evidence never arrived, so compliance is unknown" is genuinely different
from "the control looks bad". **But the REST API accepts `disposition` and
discards it** (verified against a live tenant, ten field spellings tried, all
returned 200 and dropped it). Every rule therefore becomes a pass-requirement,
and rules combine with AND. The negative ERROR form (`MATCH_COUNT EQUALS 0` +
`exit_code NOT_EQUALS 0`) then demands the envelope both be absent and carry a
non-zero exit code — conditions that cannot both hold. A validator written that
way is a constant function: measured FAIL on every input, including clean
evidence.

The positive form above asserts the same thing and works today. When the API
starts honouring `disposition`, this validator migrates by inverting both rules
and adding `disposition: ERROR` — a mechanical change to one small file per
evidence set, which is why collection-health is factored out rather than folded
into each compliance validator.

This validator carries the `exit_code` anchor for the whole set, so the
compliance validators do **not** need it. That keeps their regexes to the one
thing they assert, and their capture groups start at 1.

## Compliance validators: the two forms

Build one per distinct assertion. Which form you use decides whether you also
need an integrity partner.

**Form A — read a value (normal polarity).** Self-guarding: the
`MATCH_COUNT NOT_EQUALS 0` rule proves the field was present.

```yaml
regex: '"encryption_percentage":\s*(?<encryption_percentage>\d+)'
validation_rules:
  - regexOperation: { type: MATCH_COUNT }        # the field exists
    criteria: NOT_EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
  - regexOperation: { type: MATCH_GROUP, groupNumber: 1 }
    criteria: EQUALS
    value: { type: CUSTOM_TEXT, customText: "100" }
```

**Form B — count violations (inverted polarity, or any per-resource check).**
The regex matches only *bad* things and the rule requires zero of them.

```yaml
regex: '"CIDRs":\s*"0\.0\.0\.0/0"'
validation_rules:
  - regexOperation: { type: MATCH_COUNT }
    criteria: EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
```

Form B is also the only way to assert something about *every* item in a list,
because `MATCH_GROUP` reads the first match only — see the engine notes below.
Per-resource assertions have to be inverted into "the count of bad items is
zero".

**Form B cannot guard itself.** Zero matches is its pass condition, so it has
no way to distinguish "no violations" from "the key I search for no longer
exists". One regex cannot both count violations and prove structure.

## The integrity partner

One per Form B validator. It asserts the *structural* key was present, so a
zero count reflects posture rather than an unreadable payload.

```yaml
regex: '"CIDRs":\s*"'                            # the key itself, any value
validation_rules:
  - regexOperation: { type: MATCH_COUNT }
    criteria: NOT_EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
```

**Why this is not optional.** Measured on real AWS evidence: an S3 payload with
three genuinely unencrypted buckets flips from FAIL to PASS when only the
per-item key `encrypted` is renamed upstream — the violation regex stops
matching, the count goes 4 → 1, and the validator reports compliance. The
`exit_code` anchor does not catch it, because the envelope is intact. Envelope
drift and payload drift are different failures and need different guards.

Pick the structural anchor one level up from the violation: if you count
`"CIDRs":\s*"0\.0\.0\.0/0"`, prove `"CIDRs":\s*"`. If you count
`"isPublic":\s*true`, prove `"findings":\s*\[`.

## Writing the regex

The regex runs over the evidence JSON **as written to disk** — the whole
envelope (`schema_version` + `metadata` + `payload`), since that is the file
Paramify's validator sees.

- **The engine is ECMAScript (JavaScript)**, not Python `re` or PCRE. It applies
  `g` and `s` automatically but **never `m`**, so `^`/`$` match the whole
  document and lines are spanned with `[\s\S]*?`.
- **Named groups are `(?<name>…)`.** The Python form `(?P<name>…)` is a hard
  compile error. Name every group, in `snake_case` derived from the key it
  captures (`BackupRetentionPeriod` → `backup_retention_period`), unique within
  the pattern. Naming does not renumber anything — `(?<x>…)` is still group 1 —
  so `validation_rules` keeps referencing groups by number.
- **`MATCH_GROUP` reads the first match only.** This is the engine's hardest
  limit and the source of the most plausible-looking wrong validator: a capture
  group binds to whichever list item happens to appear first, so it cannot
  assert anything about the rest. Invert to a violation count (Form B).
- **Anchor on the key name plus a value pattern**, never on byte position or
  whitespace. `"completion_rate":\s*(?<completion_rate>100|[1-9][0-9])`, not a
  brittle slice of pretty-printed JSON. Key ordering and indentation vary
  between runs, so be whitespace-tolerant (`\s*`) throughout.
- **Avoid envelope-metadata keys** unless you pin a payload-specific value too:
  `fetcher_name`, `fetcher_version`, `category`, `run_id`, `target`,
  `collected_at`, `status`, `exit_code`, `error`, `evidence_set`,
  `schema_version`. Note `"status"` appears in the envelope (`"success"`), on
  analyzers (`"ACTIVE"`), and inside findings — anchoring on key+value, or
  pinning a neighbouring ARN, disambiguates. The collection-health validator is
  the sanctioned exception, where the envelope *is* the subject.
- **Useful numeric patterns.** Non-zero count/percent (1–100):
  `(?:100|[1-9][0-9]?)`. Any positive int: `[1-9][0-9]*`. High-only (≥90):
  `(?:100|9[0-9])`.
- **Encode a numeric threshold in the regex, not only in the criteria.** The
  comparison operators are not documented as numeric or lexicographic, and
  `"8" >= "14"` is true as a string. Use a comparison criterion only where both
  readings agree (`EQUALS`, `NOT_EQUALS`, group-to-group equality).
- **Keep multi-field matches inside one object.** There is no per-object
  scoping, so a pattern spanning two keys can bridge across neighbouring items.
  Fence it with `[^}]*?` when the objects have no nested braces, and test that
  a good item next to a bad one does not splice into a false match.
- **Do not pin `schema_version`.** It reads like prudent version-safety but
  fails in the dangerous direction: a bump that leaves your anchor untouched
  stops the pattern matching entirely. The presence rules above cover
  structural change and fail loudly.
