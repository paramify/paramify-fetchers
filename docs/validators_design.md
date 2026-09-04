# Validators — Design

**Status:** Schema, registry, and sync built (v0.x). The validator library
itself lands separately — see *What this pass does / does not do*.
`framework/schemas/validator_schema.json` + the `validators/` registry;
`validators/_template/validator.yaml` is the starting point and
`validators/aws/alb_encryption_in_transit.yaml` the worked example.
**Date:** 2026-07-14, revised 2026-09-03
**Solves:** validators had only a thin inline sketch in `fetcher.yaml`
(`{id, regex, proves?, failure_modes?}`, which nothing in the framework reads and
one fetcher populates) that could not represent the real Paramify validator, and
— being per-fetcher — had no way to express a validator shared by several
fetchers without copying it.

---

## What a validator is

A validator is a check over a fetcher's collected evidence that asserts the
control is **being implemented** — a collection-side assertion, not a
per-customer compliance judgment. Two kinds:

- **AUTOMATED** — a `regex` over the evidence envelope whose capture groups are
  compared by structured `validation_rules` (e.g. "the encrypted count equals
  the total count").
- **Attestation / manual** — no regex; the check is expressed as
  `attestation_rules`.

The fields mirror Paramify's own validator (`name`, `type`, `statement`,
`regex`, `rules_summary`, `validationRules_json`, `attestationRules_json`,
`evidence_sets`), stored as native YAML rather than stringified JSON. See the
field reference in `framework/schemas/validator_schema.json`.

---

## The model: a deduplicated registry, linked on the validator

**Decision: validators are first-class objects in a central `validators/`
registry — one file per validator — and each validator names every evidence set
it applies to. They are NOT stored inline in `fetcher.yaml`.**

```
validators/
  _template/validator.yaml
  aws/alb_encryption_in_transit.yaml
  aws/...
  okta/...
```

Each file:

```yaml
key: alb_encryption_in_transit          # stable id == basename
name: ALB Encryption In Transit
type: AUTOMATED
role: configuration
statement: Ensures that all application load balancers are encrypting data in transit.
regex: '"alb_total":\s*(?<alb_total>\d+)[\s\S]*?"alb_encrypted":\s*(?<alb_encrypted>\d+)'
rules_summary: MATCH_COUNT NOT_EQUALS 0; MATCH_GROUP[1] EQUALS MATCH_GROUP[2]
validation_rules:
  - regexOperation: { type: MATCH_COUNT }                   # the fields were read
    criteria: NOT_EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
  - regexOperation: { type: MATCH_GROUP, groupNumber: 1 }   # alb_total
    criteria: EQUALS
    value: { type: MATCH_GROUP, groupNumber: 2 }            # alb_encrypted
attestation_rules: []
evidence_sets:                          # <- the link lives HERE
  - EVD-LB-ENC-STATUS
  - EVD-LB-ENC-STATUS-MANUAL
```

### Why the link lives on the validator

The central requirement: **a validator shared by several fetchers must not be
copied.** Because the fetcher→validator relationship is many-to-many (a fetcher
has many validators; a validator can serve many fetchers), putting the link on
the *validator* — a single `evidence_sets` list — means a shared validator is
one file that simply lists more sets. Putting it on the fetcher instead would
force either a copy per fetcher or a second layer of references. This is also
exactly how Paramify models it: the validator owns its evidence-set list (in the
API export, one validator row carries
`Load Balancer Encryption Status | Non-automated Load Balancer Encryption Status`).

**A fetcher's validators are a reverse lookup:** every registry file whose
`evidence_sets` contains that fetcher's `evidence_set.reference_id`. A generator
or CLI does the walk; nothing verbose lands in `fetcher.yaml`.

### Why a sidecar registry rather than inline

Validators carry a regex, a human `rules_summary`, and a structured
`validation_rules`/`attestation_rules` block. Inlining all of that in
`fetcher.yaml` would bury the fetcher's identity under rule blobs and — fatally
— could not dedupe a shared validator. So `fetcher.yaml` keeps its `evidence_set`
identity and `ksis`, and validators live here.

The old inline `validators` block stays in `fetcher_schema.json` marked
`deprecated`, rather than being deleted. Nothing in the framework reads it, but
`gitlab/significant_change_notifications` populates one, and dropping the schema
entry would turn that fetcher's data into an unvalidated stray key rather than
migrating it. The block goes when those three validators move into the registry.

---

## Writing the regex: flavor, named groups, and the error state

Three rules govern every `regex` in this registry. They exist because each has a
failure mode that is silent — the validator looks fine and reports the wrong
thing.

### 1. The engine is ECMAScript, not Python

**Paramify evaluates validator regexes with JavaScript**, so that is the flavor
these files are written in. It applies the `g` and `s` flags automatically but
**not `m`** — `^`/`$` therefore match the whole document, and lines are spanned
with `[\s\S]*?`. The common constructs (`\s`, `(?:…)`, classes, lookaheads) are
identical to Python's, so most patterns port cleanly, but **named groups do
not**: JS is `(?<name>…)`, Python is `(?P<name>…)`, and each fails to compile in
the other. Always write `(?<name>…)`.

Verify in Node, never Python `re` — a Python test both uses the wrong engine and
cannot compile our named groups at all:

```bash
node -e '
const t = require("fs").readFileSync("<run-dir>/<evidence>.json", "utf8");
const re = new RegExp(String.raw`<regex>`, "gs");   // gs mirrors Paramify
let m, n = 0;
while ((m = re.exec(t)) !== null) { if (n < 5) console.log(m.groups); n++; }
console.log(n + " match(es)");'
```

### 2. Name every capture group

`(?<alb_total>\d+)` is self-documenting where a bare `(\d+)` forces the reader to
count parentheses across a long pattern. Derive the name from the key being
captured, in `snake_case` (`BackupRetentionPeriod` → `backup_retention_period`);
names must be unique within one pattern.

Naming does **not** renumber anything — `(?<x>…)` is still group 1 — so
`validation_rules`, which references groups by `groupNumber`, is unaffected. The
names are for the human reading the YAML; the numbers still drive the rules.

### 3. Guard the read, and put collection health in its own validator

Two silent failures live here, and they need different guards.

**A rule that reads nothing passes.** A `MATCH_GROUP` comparison over a regex
that did not match compares nothing to nothing and evaluates **true**. A
`MATCH_COUNT`-of-violations rule reads a renamed upstream key as zero violations,
and therefore as compliant. Both report PASS on evidence that proves nothing.

So **every validator opens with a presence rule**:

```
- regexOperation: { type: MATCH_COUNT }
  criteria: NOT_EQUALS
  value: { type: CUSTOM_TEXT, customText: "0" }
```

A validator that *reads a value* guards itself this way. A validator that
*counts violations* cannot — zero matches is its pass condition, so one regex
cannot both count violations and prove structure. Those need a separate
`role: integrity` validator asserting the structural key exists (count
`"CIDRs":\s*"0\.0\.0\.0/0"`, prove `"CIDRs":\s*"`).

This is not hypothetical. Measured on real AWS evidence: a payload with three
genuinely unencrypted buckets flips FAIL → PASS when only the per-item key
`encrypted` is renamed upstream — the violation regex stops matching, the count
goes 4 → 1, and the validator reports compliance.

**Collection health is one validator per set, not two rules per validator.**
`wrap_outputs` derives `status` from `exit_code`, so the two are redundant —
anchor on `exit_code` alone. It is numeric and avoids the `status` key collision
(the envelope says `success` while a payload may say `ACTIVE` or `error`).

```yaml
regex: '"exit_code":\s*(?<exit_code>-?\d+)'
validation_rules:
  - regexOperation: { type: MATCH_COUNT }
    criteria: NOT_EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
  - regexOperation: { type: MATCH_GROUP, groupNumber: 1 }
    criteria: EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
```

`validators/common/collection_succeeded.yaml` is that validator. The envelope is
identical for every fetcher, so it is defined **once** and lists every evidence
set that wants it — the dedup mechanism doing exactly what it is for, and the
reason the whole library migrates in one file (below). Because it carries the
anchor for the set, compliance validators do not need `exit_code` at all, which
keeps their patterns to the one thing they assert and their groups starting at 1.

**Why the guards are positive rather than `disposition: ERROR`.** `ERROR` is the
semantically right label — "the evidence never arrived, so compliance is
unknown" is a different fact from "the control looks bad", and without it an
expired token is indistinguishable from a real failure. But **the REST API
accepts `disposition` and discards it** (see the gap below). Every rule then
becomes a pass-requirement, so the negative guard pair — `MATCH_COUNT EQUALS 0
-> ERROR` plus `exit_code NOT_EQUALS 0 -> ERROR` — demands that the envelope be
simultaneously absent and carrying a non-zero exit code. Measured: a validator
written that way is a **constant function**, returning FAIL on every input
including clean evidence. It is not pessimistic; it is inert.

The positive form asserts the same thing and works today. **Migration when the
API lands:** invert both criteria and add `disposition: ERROR` to each. That is
the whole change, in one file, for every evidence set at once.

**Do not pin `schema_version`** as version-safety. It fails in the dangerous
direction: a bump that leaves your anchor untouched stops the pattern matching
entirely. The presence rules above cover structural change and fail loudly.

Anchoring on `exit_code` is the **one sanctioned exception** to the rule against
matching envelope metadata instead of payload: in the collection-health
validator the envelope *is* the subject of the check.

---

## Linking by `reference_id`

`evidence_sets` entries are evidence-set **`reference_id`s** (e.g.
`EVD-LB-ENC-STATUS`), not display names. `reference_id` is the stable
idempotency key the uploader already get-or-creates sets by; display names
drift. A future importer that ingests a Paramify validator export (which lists
sets by name) maps name → `reference_id` via the fetcher registry.

Some `evidence_sets` entries may name a **manual / non-automated** set that has
no fetcher in this repo (the "Non-automated …" sibling of an automated set).
That is expected: the registry is validator-centric, so it can reference sets
that live only Paramify-side.

---

## Cardinality (recap of the confirmed evidence model)

- **1 fetcher = 1 (automated) evidence set** — unchanged. When one collection
  would feed two sets, split the fetcher, don't fan one artifact out.
- **An evidence set carries a validator *set*, and `role:` records which is
  which.** Exactly one `completeness` validator (did the collection succeed and
  is the population real? — often the minimum assessment scope), any number of
  `configuration` validators (posture checks), and one `integrity` validator
  alongside each configuration validator that concludes from a count of
  violations (was the counted field actually present?). This is why multiple
  validators per set is the norm, not the exception — an evidence set passes
  only when all of its validators pass. Both halves of a measured A/B on live
  AWS evidence produced 2–5 validators per set without being asked to.

---

## Uploading & associating (Paramify REST API v0.8.0)

The API confirms the sync path — it is the script-sync pattern (decision #122),
just with `subjectType: VALIDATOR` instead of `SCRIPT`:

- **Upsert the validator** — `POST /validators` (create) / `PATCH
  /validators/{id}` (update). The body is a `oneOf` on `type`, and our registry
  fields map 1:1:
  - `AUTOMATED` → `{name, statement, type, regex, validationRules}` — our
    `validation_rules` is the same object shape (`regexOperation`/`criteria`/`value`).
  - `ATTESTATION` → `{name, statement, type, attestationRules}` — our
    `attestation_rules` is the same shape.
- **Associate to an evidence set** — `POST /evidence/{evidenceId}/associate`
  with `{associationType: CONNECT, subjectType: VALIDATOR, subjectId:
  <validatorId>}`. Many-to-many falls out for free: one CONNECT per entry in the
  validator's `evidence_sets`; `DISCONNECT` reverses it.
- **The evidence set** is get-or-created by `reference_id` via the existing
  evidence uploader (`get_or_create_evidence_set`). A manual/non-automated
  sibling set that has no fetcher is created (`automated: false`) before CONNECT.

This is scoped and manifest-driven: sync only the validators whose
`evidence_sets` intersect the evidence sets the user's manifest actually
produces.

### Checked against the v0.8.0 spec (2026-09-03)

Re-verified against the published `documentation-0.8.0.json`, having originally
been written against v0.6.0. Three things confirmed, one gap:

- `POST /validators` is still a two-branch `oneOf` on `type`, and the branches
  still require exactly what `build_payload` sends —
  `{name, statement, type, regex, validationRules}` for AUTOMATED,
  `{name, statement, type, attestationRules}` for ATTESTATION. The repo-side
  fields (`key`, `role`, `rules_summary`, `evidence_sets`) are correctly withheld.
- `POST /evidence/{evidenceId}/associate` matches byte for byte, and
  `subjectType` now enumerates `SOLUTION_CAPABILITY` alongside `VALIDATOR`.
- `GET /validators` filters only on `ids` and `type` — still no name or
  reference filter, and no pagination envelope. Resolving an id by listing and
  matching on name remains the only route, and the rename-before-cache
  duplicate risk stands.

**The gap: `disposition` is silently dropped.** Verified against a live stage
tenant on 2026-09-03, not inferred from the spec.

`validationRules[]` documents only `{regexOperation, criteria, value}`. The only
dispositions in v0.8.0 are `yesDisposition` / `noDisposition` on *attestation*
rules (`PASS | FAIL | BASED_ON_NESTED`), and `ERROR` appears once in the whole
document as a validator **result** on `GET /evidence/{id}/artifacts`.

What the live test established:

- `POST /validators` and `PATCH /validators/{id}` both return **HTTP 200** and
  store the rule with `disposition` removed. No error, no warning.
- It is not a read-back omission. Three validators identical but for the
  disposition sent (`ERROR`, `FAIL`, none), one rule each whose condition was
  **true**, all scored **PASS**. The field never reaches evaluation.
- It is not a naming problem. `disposition`, `ruleDisposition`,
  `validationRuleDisposition`, `dispositionType`, `outcome`, `result`, `status`,
  `errorDisposition`, and nesting inside `regexOperation` or `value` — all ten
  returned 200 and were discarded.
- **Rules combine with AND.** One true rule plus one false rule scores FAIL.

The feature is not missing from the product — it is missing from this API.
`disposition` (with `ERROR`) shipped to the DB and UI in June 2026, and the
validator endpoints were built before that and never updated. The identical
omission in the validator CSV export is a filed bug, and the API case is now
tracked separately.

### Consequence for the rule shape

Because dispositions are dropped and rules are ANDed, a rule written in the
negative ERROR form stops being a guard and becomes a requirement. The pair
`MATCH_COUNT EQUALS 0 -> ERROR` and `exit_code NOT_EQUALS 0 -> ERROR` therefore
demands that the regex match **zero** times *and* that `exit_code` be
**non-zero** — conditions that cannot both hold on any real artifact.

Measured against a rule-evaluation emulator calibrated to this tenant: a
validator in that shape is a **constant function**. It returns FAIL on every
input — clean evidence, non-compliant evidence, and a failed collection alike.
Six of six evidence sets in one arm of the A/B behaved this way, as did a
hand-built reference that scores 100% under the intended semantics.

So the registry authors the **positive** form (§3): plain PASS rules asserting
`MATCH_COUNT NOT_EQUALS 0` and `exit_code EQUALS 0`, in a dedicated
`role: completeness` validator. That form scored 16/16 on today's semantics and
discriminates properly. Migration is a mechanical inversion of two rules in
`validators/common/collection_succeeded.yaml`, which is precisely why collection
health is factored out of the compliance validators.

Nothing is lost by waiting: `disposition` is not *rejected* by the API, so a
validator that carries it still syncs — it simply has no effect until the
endpoints are updated.

### A separate trap: `MATCH_GROUP` passes vacuously

Independent of disposition, and it affects every validator in the library. When
the regex does not match, a `MATCH_GROUP` comparison compares nothing to nothing
and evaluates **true** — an artifact the regex misses scores PASS, silently.
Confirmed on stage: a validator whose only rule was `MATCH_GROUP 1 EQUALS
MATCH_GROUP 2` passed a failed-collection artifact its regex never matched.

Any validator built on `MATCH_GROUP` comparisons therefore needs a
`MATCH_COUNT NOT_EQUALS 0` presence rule, or a drifted field name, a
restructured envelope, and a failed collection all read as compliant.

---

### These are templates — create-or-skip, never clobber

The shipped validators are **templates, ~80% correct**. A customer tunes them to
their environment (regex thresholds, `statement`, attestation questions) *inside
Paramify*. The sync must never destroy that tuning, so:

- **Create-or-skip.** Sync creates a validator only when the customer's instance
  doesn't already have it. If it exists, the sync **does not PATCH it** by
  default — the customer's tuned copy is left exactly as-is.
- **Update is explicit and loud.** A `--update` flag can PATCH an existing
  validator from the template (for the not-yet-tuned case), but only opt-in and
  with a clear warning; `--dry-run` shows the exact calls first. Default runs
  never update.
- **Association is always safe.** CONNECT (`/evidence/{id}/associate`) only wires
  the validator to a set; it never touches validator content, so the sync always
  ensures the association even when it skips the update.

### Behavior after a partial upload

`upload --with-validators` runs the validator sync even when some evidence files
in the run failed to upload, scoped to every evidence-set reference_id the run
*produced*. This is deliberate: a validator attaches to an evidence *set*, which
is get-or-created independently of whether every artifact uploaded, so a single
failed target should not block wiring the set's validators. The combined exit
code still reflects both stages. (If this proves too loose, the alternatives are
to skip the sync unless the upload was fully OK, or to scope only to sets whose
artifacts actually uploaded — both easy to add later.)

### Per-instance ids live customer-side, not in the registry

`GET /validators` filters only by `ids`/`type` — no name/reference filter (the
gap script-sync hit). So a validator's Paramify id is **resolved at sync time and
cached in customer-side state** (a gitignored lock, alongside the uploader
config) — never written back into the shared registry file, whose only identity
is `key`. First sync: list + match by `name` → adopt the existing id (no
duplicate) or create. This mirrors evidence sets exactly: the shared stable key
is `reference_id`, and the Paramify id is resolved per instance, never stored in
the repo. (Known limit: if a customer *renames* a validator before its id is
cached, a name-match can miss and create a duplicate — documented, and why the
lock is written on first create.)

---

## What this pass does / does not do

**Does:** define `validator_schema.json`, stand up the `validators/` registry with
a template and one worked example, build the sync that pushes registry validators
to Paramify and associates them to evidence sets, and document the model.

**Does not (deferred):**

- **The validator library itself.** This is the framework, not the content. The
  ~120 authored validators live on `feat/populate-validator-registry` and land in
  a follow-up PR, once each is reshaped to the flavor/named-group/error-state
  rules in *Writing the regex* above — they were authored before those rules were
  settled, so none of them carry an `exit_code` anchor or an `ERROR` disposition
  yet. `validators/aws/alb_encryption_in_transit.yaml` is the shape they are being
  brought to.
- **The contract test.** A `validators/**/*.yaml` gate against
  `validator_schema.json` (mirroring `tests/test_contracts.py`) lands with that
  library, where it has a real set to assert on rather than one file.
- **The importer.** Converting a Paramify validator export into registry files
  (matching `evidence_sets` → `reference_id`, minting `key`s) is a one-time
  bootstrap tool, the inverse of the sync — separate work.
- **A live-tenant run.** Everything here is verified dry-run and against a mocked
  client; the first real `POST /validators` needs a stage token.
- **A registry contract test for the template.** `validators/_template/validator.yaml`
  is now schema-valid — its `key` placeholder previously violated the `key`
  pattern, so it could never have been gated. A `test_template_yaml_matches_schema`
  mirroring the fetcher-template gate in `tests/test_contracts.py` would keep it
  that way: a template that would be rejected at discovery teaches a shape that
  cannot run, and it is copied before anyone finds out.
