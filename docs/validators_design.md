# Validators — Design

**Status:** Schema + registry defined (v0.x, 2026-07-14).
`framework/schemas/validator_schema.json` + the `validators/` registry;
`validators/_template/validator.yaml` is the starting point.
**Date:** 2026-07-14
**Solves:** validators had only a thin, unused inline sketch in `fetcher.yaml`
(`{id, regex, proves?, failure_modes?}`, populated by zero fetchers) that could
not represent the real Paramify validator, and — being per-fetcher — had no way
to express a validator shared by several fetchers without copying it.

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
regex: '"alb_total":\s*(\d+)[\s\S]*?"alb_encrypted":\s*(\d+)'
rules_summary: MATCH_GROUP[1] EQUALS MATCH_GROUP[2]
validation_rules:
  - regexOperation: { type: MATCH_GROUP, groupNumber: 1 }
    criteria: EQUALS
    value: { type: MATCH_GROUP, groupNumber: 2 }
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
— could not dedupe a shared validator. The old inline `validators` block is
removed from `fetcher_schema.json`; `fetcher.yaml` keeps only its `evidence_set`
identity and `ksis`.

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
- **Each evidence set carries exactly one `completeness` validator** (does the
  evidence cover the full population? — often the minimum assessment scope) plus
  **any number of `configuration` validators** (posture/config checks). `role:`
  records which is which. This is why multiple validators per fetcher is the
  norm, not the exception.

---

## Uploading & associating (Paramify REST API v0.6.0)

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

**Does:** define `validator_schema.json`, stand up the `validators/` registry
with a template, remove the dead inline `validators` block from the fetcher
schema, and document the model.

**Does not (deferred):**

- **No importer / backfill.** Converting a Paramify validator export into
  registry files (matching `evidence_sets` → `reference_id`, minting `key`s) is
  a separate tool. No real validators ship in this pass.
- ~~**No sync tool yet.**~~ **Built.** `uploaders/paramify_validators/syncer.py`
  (create-or-skip reconcile + client + customer-side lock) plus `paramify
  validators sync` and `paramify upload --with-validators`
  (`framework/api.sync_validators`, scoped by manifest or by the reference_ids a
  run produced). This intentionally supersedes the "validator linkage stays
  manual" scope of decision #122.
- **No contract test yet.** A `validators/**/*.yaml` gate against
  `validator_schema.json` (mirroring `tests/test_contracts.py`) should land with
  the first real validators, so it doesn't assert on an empty set.
- **`suggest-validator` skill** still frames Paramify as the validator's only
  home; update it to point an accepted suggestion at this registry when the
  authoring path is built.
