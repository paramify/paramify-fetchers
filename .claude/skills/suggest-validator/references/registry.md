# Recording it in the registry

Read this once the set is proved. Validators live in the repo, one file per
validator: `validators/<category>/<key>.yaml`. The file is the shared template;
the customer's tuned copy and its Paramify id live customer-side and are never
written back here.

## 1. Copy the template, once per validator

```bash
cp validators/_template/validator.yaml validators/<category>/<key>.yaml
```

`<category>` matches the fetcher's category (`aws`, `okta`, `gitlab`, …).
`<key>` **must equal the filename stem** and match `^[a-z0-9]+(?:_[a-z0-9]+)*$`
— discovery raises on a mismatch. Name it for what it asserts, not for the
fetcher: `s3_buckets_all_encrypted`, not `s3_validator_2`.

## 2. Fill it in

Delete the template's guidance comments as you go. Required: `key`, `name`,
`type`, `statement`, `evidence_sets`. Set `role` per the three roles.
`evidence_sets` takes the fetcher's `evidence_set.reference_id` — and every
other set this same assertion applies to.

**`statement` is where the reasoning survives.** Nothing in the repo records
which capability or control the set was authored against, so the statement is
the only place that link persists. Write what it asserts, what it does *not*
assert, and name the claim it substantiates — the next person re-derives all of
it otherwise.

## 3. Reuse before you create

A validator is a *deduplicated* object: if one already asserts this, add the
new `reference_id` to its `evidence_sets` list instead of writing a second
file. Two files asserting the same thing will drift apart.

```bash
grep -rl "EVD-<REF>" validators/ ; grep -rn "^name:" validators/<category>/
```

## 4. Names must be unique across the whole workspace

Paramify rejects a duplicate `name` with HTTP 400. A compliance validator and
its integrity partner need genuinely distinct names, not `Foo` and `Foo 2`.

## 5. Commit the cases with it

The case files belong in `validators/_cases/<key>.yaml` (or
`set_<REFERENCE-ID>.yaml` for a set-level one). A validator without cases has
nothing proving it can fail, and `paramify validators check` will name it.

## 6. Verify it lands — stop on failure

```bash
.venv/bin/python -m pytest tests/test_validators_registry.py -q
```

**PASS:** every file is schema-valid, `key` matches its filename, and discovery
finds no duplicates. **FAIL:** fix before moving on — a schema-invalid file
breaks discovery for the whole registry, not just itself.

## 7. Syncing is the user's call

`paramify validators sync` creates them in Paramify (create-or-skip, scoped by
manifest) and associates them to their evidence sets. Do not run it as the
closing step of authoring. It writes to a live workspace — often production —
and a duplicate name fails the whole call with a 400. Offer it; let the user
decide when.

Two ordering facts, if they do sync now:

- **Upload before sync.** Associating a validator to an evidence set requires
  the set to exist, which it does not until something has been uploaded to it.
- **Association happens on create only, and `--update` does not change that.**
  An existing validator is skipped (or PATCHed with `--update`) and never
  re-associated. So adding a `reference_id` to an already-synced validator's
  `evidence_sets` has no effect on the workspace at all — that association has
  to be made in Paramify directly. Worth saying out loud when you hand back a
  reused validator, because the repo will look right while the workspace is
  missing the link.
