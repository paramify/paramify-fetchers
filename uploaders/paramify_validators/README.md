# paramify_validators — validator sync

Pushes validators from the central [`validators/`](../../validators/) registry to
Paramify and associates them to evidence sets. Runs as a stage after evidence
upload (the evidence sets it associates to should already exist). See
[`docs/validators_design.md`](../../docs/validators_design.md).

## What it does, per validator

1. **Resolve existence** — by a cached id in the lock file, else by matching the
   validator's `name` against `GET /validators` (which has no name filter).
2. **Create-or-skip** — creates it (`POST /validators`) only if the instance
   lacks it. An existing validator is **not** modified unless `--update` is
   passed, so a customer's tuning is preserved. (These validators ship as
   ~80%-correct templates that customers tune per environment.)
3. **Associate on create only** — right after creating, it CONNECTs the validator
   to each of its `evidence_sets` (`POST /evidence/{id}/associate`,
   `subjectType: VALIDATOR`). It never re-asserts wiring on a validator that
   already existed.

## Run it

```bash
# Everything in the registry (dry-run: reports, writes nothing):
python uploaders/paramify_validators/syncer.py --dry-run

# Scope to one manifest's fetchers, for real:
python uploaders/paramify_validators/syncer.py --manifest examples/aws_ambient.yaml

# Pull an improved template onto NOT-yet-tuned validators (overwrites content):
python uploaders/paramify_validators/syncer.py --manifest ... --update
```

Auth: `PARAMIFY_UPLOAD_API_TOKEN` (same token as the evidence uploader).
Base URL: `PARAMIFY_API_BASE_URL` (default `https://app.paramify.com/api/v0`).

## Lock file

The per-instance `{validator key → Paramify id}` map lives in
`./.paramify/validators-sync.lock.json` (override with `--lock`). It is
**customer-side state, not template content** — gitignored, never in the shared
registry. It makes re-runs idempotent and immune to a validator being renamed in
Paramify after its id is cached.

## Known limits (v0.x)

- If a validator is **renamed** in Paramify *before* its id is cached, the
  name-match misses and a duplicate is created. The lock exists to prevent this
  on every subsequent run.
- **Association happens only at create time.** If a CONNECT fails (e.g. the
  evidence set doesn't exist yet), a later run sees the validator as existing and
  won't retry the association. Run `paramify upload` first so the sets exist, or
  re-create after fixing.
