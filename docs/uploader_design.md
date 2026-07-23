# Uploader design

How this repo pushes to Paramify, and why it's shaped the way it is. This is the
dedicated companion to [`design.md`](design.md), which frames uploaders as one of
the framework's [separate stages](design.md#uploaders-as-a-separate-stage); the
detail lives here.

Two things reach Paramify today, both under `uploaders/`:

- **`paramify_evidence`** — attaches a completed run's evidence files to their
  evidence sets. Runs **every collection**. Exposed as `paramify upload`.
- **`paramify_scripts`** — pushes each fetcher's entry script and connects it to
  that fetcher's evidence set, so the tenant records *how* the evidence was
  generated. A **provisioning** step, run only when `fetchers/**` change. Exposed
  as `paramify scripts sync`.

A third, `paramify_issues` (the Wiz-style write-issues-back case), is an empty
stub.

## Why uploading is its own stage

Pushing to Paramify is **not** a fetcher concern. Fetchers collect and write JSON
to disk; a separate stage reads that output and talks to the API. Keeping them
apart buys the properties in [`design.md`](design.md#uploaders-as-a-separate-stage):
fetchers run with no Paramify connection at all (dev, testing, customer
dry-runs), a review/approval step can sit between collect and upload, re-uploading
a prior run is just pointing the uploader at an old directory, and a new kind of
write (issues, scripts) becomes a *new uploader* rather than a hack inside a
fetcher. Orchestration that chains the stages is customer-owned; `run_and_upload.sh`
at the repo root is example glue.

Both built uploaders share the same operational contract:

- **Auth** — `PARAMIFY_UPLOAD_API_TOKEN`, read source-agnostically (env, `.env`,
  secret manager, CI). No token is privileged over another.
- **Base URL** — Paramify REST v0, default `https://app.paramify.com/api/v0`;
  override with `PARAMIFY_API_BASE_URL` or `--config base_url`.
- **HTTPS-only token guard** — a non-https `base_url` is rejected before the token
  is ever sent, so the bearer token can't leak over plaintext. `localhost` is the
  only exception (local testing).
- **`--dry-run` / `--config` / `--json`** — preview read-only, point at a config,
  or emit a machine-readable summary.

## The evidence-set identity model (shared)

Both uploaders target the same **evidence set** for a given fetcher, and they find
it the same way — so a script lands on the exact set its evidence does.

- Every `fetcher.yaml` carries an `evidence_set` block (`reference_id`, `name`,
  `instructions`). This is **fetcher knowledge** — what the evidence is and how
  it's collected — so it ships with the fetcher and is the shipped default the
  runner folds into the envelope. Customers never edit it. (1 fetcher = 1 evidence
  set.)
- At upload time the uploader **gets-or-creates** the set by `reference_id`.
  Customers remap `reference_id` (and optionally `name`) **per program** in the
  uploader `--config` `overrides.<fetcher_name>` — the two uploaders read the
  *same* overrides, which is what keeps evidence and scripts on the same set.
- Control / solution-capability / validator linkage is **out of scope** and stays
  Paramify-side. The `evidence_set` block deliberately does not carry it.

## `paramify_evidence` — attach evidence to sets

Reads a completed, enveloped `run-<timestamp>/` directory and, per evidence file:
gets-or-creates the evidence set by `reference_id`, then multipart-uploads the
artifact. Idempotent within a run (a re-run skips already-uploaded files rather
than duplicating them). Supports the shared flags above.

`paramify upload` takes an optional run directory (default: the latest run under
the manifest's `--output-dir`). Full setup — API-key permissions included — is in
[`../uploaders/paramify_evidence/README.md`](../uploaders/paramify_evidence/README.md).

## `paramify_scripts` — sync entry scripts, associate to sets

The `/scripts` API has **no stable external key** (only a server-assigned UUID)
and **no server-side versioning**. So this uploader can't get-or-create the way the
evidence uploader does; instead it **reconciles the tenant to the repo, GitOps
style**, using conventions the API *does* allow:

- **identity** — a marker written into the script's `description`:

  ```
  paramify-fetcher: <fetcher name>
  version: <fetcher.yaml version>
  sha256: <sha256 of the entry file>
  ```

  There is no server-side name/marker filter, so the tool lists all scripts once
  and indexes them client-side by the `paramify-fetcher` line.
- **versioning** — the `fetcher.yaml` `version` is the update signal; git is the
  history of record; the app just holds "current".
- **drift guard** — the `sha256` catches a code edit that forgot to bump the
  version: **warn and skip by default**, `--force` to push it anyway.

### Action per fetcher

For every fetcher that declares an `evidence_set` and has a readable entry file
(`fetcher.py` / `fetcher.sh` — **shared modules are ignored**; only the entry
script is pushed):

| Action | When | Writes? |
|---|---|---|
| **create** | no script with this marker in the tenant | creates + associates |
| **update** | `fetcher.yaml` version changed | updates code + re-associates |
| **drift** | code changed but version did **not** | skipped (warns) unless `--force` |
| **no-op** | version *and* sha256 both match | nothing |

The script's **display name is the evidence set's `name`**. After a create or
update (or for every fetcher under `--reassociate`), the script is **CONNECTed**
to the fetcher's evidence set — which is get-or-created by `reference_id` exactly
as the evidence uploader does. The CONNECT is tolerant of an already-connected
script (the API has no pre-check), so re-runs are idempotent. Only `SCRIPT`
associations are automated.

### Flags beyond the shared set

- `--force` — push a script whose code drifted without a version bump.
- `--reassociate` — ensure the association for *every* fetcher, not just changed
  ones (heals a script created without its link, or a partial earlier run).

Note: in `--dry-run` the summary **counts** stay zero (no actions are taken); the
plan is in the per-item results (`would_create` / `would_update` / `would_drift` /
`would_noop`), which `--json` and the human printer both show.

Full usage, config, and required tooling are in
[`../uploaders/paramify_scripts/README.md`](../uploaders/paramify_scripts/README.md).

## When to run which

- `paramify upload` — **every collection**, after a run, to push the evidence.
- `paramify scripts sync` — a **provisioning** step, when `fetchers/**` change
  (a fetcher added, or its entry script / version bumped). Not on every
  collection.
