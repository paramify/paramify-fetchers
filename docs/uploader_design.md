# Uploader design

How this repo pushes to Paramify, and why it's shaped the way it is. This is the
dedicated companion to [`design.md`](design.md), which frames uploaders as one of
the framework's [separate stages](design.md#uploaders-as-a-separate-stage); the
detail lives here.

Three things reach Paramify today, all under `uploaders/`:

- **`paramify_evidence`** — attaches a completed run's evidence files to their
  evidence sets. Runs **every collection**. Exposed as `paramify upload`.
- **`paramify_issues`** — posts a run's raw issue reports (vulnerability scans,
  CSPM findings) into assessment pipelines, where Paramify parses them into issues.
  Runs after any collection that included a `kind: issue_report` fetcher. Exposed
  as `paramify issues upload`.
- **`paramify_scripts`** — pushes each fetcher's entry script and connects it to
  that fetcher's evidence set, so the tenant records *how* the evidence was
  generated. A **provisioning** step, run only when `fetchers/**` change. Exposed
  as `paramify scripts sync`.

That there are three rather than one is the design working as intended: a new kind
of write becomes a new uploader instead of a special case inside an existing one.

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

All three share the same operational contract:

- **Auth** — `PARAMIFY_UPLOAD_API_TOKEN`, read source-agnostically (env, `.env`,
  secret manager, CI). No token is privileged over another.
- **Base URL** — Paramify REST v0, default `https://app.paramify.com/api/v0`;
  override with `PARAMIFY_API_BASE_URL` or `--config base_url`.
- **HTTPS-only token guard** — a non-https `base_url` is rejected before the token
  is ever sent, so the bearer token can't leak over plaintext. `localhost` is the
  only exception (local testing).
- **`--dry-run` / `--config` / `--json`** — preview read-only, point at a config,
  or emit a machine-readable summary. With no `--config`, every stage falls back
  to `./upload.yaml` at the repo root if it exists — which is how the TUI, which
  passes no path, reaches a config at all. One default for all three stages is
  also what stops the CLI and the TUI reading different overrides.

## The evidence-set identity model (shared)

`paramify_evidence` and `paramify_scripts` target the same **evidence set** for a
given fetcher, and they find it the same way — so a script lands on the exact set
its evidence does. (`paramify_issues` does not use this model at all; an issue
report goes to an assessment, and its identity model is described below.)

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

### Channels

A customer can put **channels** on an evidence set — one per stack, each owned by
a user or a team. Where they have, an artifact uploaded *outside* a channel is
invisible to validation on the solution capability, so picking the right one is a
correctness requirement, not a convenience.

Channels are created in the app. The API exposes them read-only on the evidence
record (`channels[]`: `id`, `referenceId`, `owner`, `stackId`) and accepts a
`channelId` on artifact upload, so the uploader can only *use* what a set
already has. `find_evidence_set` therefore returns the whole record rather than
a bare id — the channels ride along on a call that was made anyway — and
`resolve_channel` applies one rule: **a set with a channel uploads through it, a
set with none uploads unchanneled.** Neither needs any configuration.

More than one channel on a set is out of scope for now and errors that file,
carrying on with the batch. Guessing produces an upload that looks fine and
validates as nothing, so there is nothing to gain by picking one before the
rules for choosing exist.

Two API limits shape this:

- **`ArtifactResponse` carries no `channelId`.** Where an artifact went cannot be
  read back, so `upload_log.json` records the channel per file as the only
  durable record, and the filename + `run_id` dedup in `artifact_exists` stays
  channel-blind — re-uploading one run into a second channel would be skipped as
  a duplicate.
- **`POST /evidence` takes no stack or channel.** A set the uploader creates
  itself comes back with no channels and nothing can attach one; it uploads
  unchanneled until someone adds a channel in the app.

## Default custom tags (shared)

Every evidence set, script and validator the three stages create or maintain
gets two Paramify custom tags, so a user who has the fetchers create resources
sees tagging working out of the box and can filter the fetchers' work from the
hand-made rest:

- a **provenance** tag — `Automated by Paramify Fetchers` unless renamed;
- a **service** tag — the category's `display_name` from
  `fetchers/_categories/<category>.yaml` (`AWS`, `Okta`, `SentinelOne`).
  Declared, not derived: no rule turns `aws` into `AWS`. A category without one
  gets the provenance tag only.

Both are project-wide knobs in `upload.yaml`, which all three stages read:

```yaml
tags:
  provenance: Automated by Paramify Fetchers   # a string, or false
  service: true                                 # false to drop the category tag
# tags: false                                   # no default tags at all
```

**Writes are additive and re-asserted on every run.** `POST
/custom-tags/{entity}/{id}` adds names (creating unknown ones) and never
replaces the entity's tag set, so a user's own tags survive and a run reaches
resources an earlier run created before tagging existed. The cost: a renamed or
disabled default leaves its old tag behind once, because additive writes cannot
remove it. `PATCH`, which could, would clobber user tags and is never used.
Per-fetcher content tags (`STIG`, `CIS`) and single-valued validator criticality
(`P1`/`P2`) are expected later as a layer on top; additive writes are what let
the layers coexist, but criticality will need a reconcile step, not just
another additive tag.

**Turning it off.** Three switches, in order of precedence:

- `--no-tags` on `paramify upload`, `paramify scripts sync` or `paramify
  validators sync` — this one invocation writes no tags;
- `PARAMIFY_CUSTOM_TAGS=off` (also `false`, `no`, `0`) in the environment —
  the feature is off wherever that is set, a shell, a CI job, a container,
  whatever `upload.yaml` says. Any other value leaves the config in charge;
- `tags: false` in `upload.yaml` — off for everyone who runs from that config.

A switch that says off wins before the config block is read, so a broken
block cannot keep tags on. The Done block of each stage says `tags: off
(<which switch>)` so the reason is never a guess.

**Tagging never fails a stage.** A token without the custom-tags permission
gets one warning and the rest of the run proceeds untagged; any other error is
logged per entity and counted. Each stage's summary carries a `tags` block
(`enabled` / `reason` / `applied` / `failed` / `skipped` / `disabled`), and
each result row the names it applied. A dry run shows the planned names and
writes nothing. The implementation is one module, `framework/custom_tags.py`.

## `paramify_evidence` — attach evidence to sets

Reads a completed, enveloped `run-<timestamp>/` directory and, per evidence file:
gets-or-creates the evidence set by `reference_id`, then multipart-uploads the
artifact. Idempotent within a run (a re-run skips already-uploaded files rather
than duplicating them). Supports the shared flags above.

`paramify upload` takes an optional run directory (default: the latest run under
the manifest's `--output-dir`). Full setup — API-key permissions included — is in
[`../uploaders/paramify_evidence/README.md`](../uploaders/paramify_evidence/README.md).

## `paramify_issues` — send raw reports into assessment pipelines

Reads `<run>/issue-reports/`, uploads each report to
`POST /pipelines/{assessmentId}/intake`, then queues one
`POST /pipelines/{assessmentId}/process` per assessment over exactly the artifacts
it uploaded, and waits for the job. Four things make it structurally different
from the evidence uploader, and all four come from the endpoint rather than from
preference:

- **The file is sent byte-for-byte.** Intake parses the vendor's own CSV / XML /
  JSON / Nessus structure, so there is no envelope and no re-serialization — not
  even for a `.json` report. Identity travels in the `artifact` metadata part and
  in a sidecar index instead of inside the file.
- **The destination comes from the manifest, not the fetcher.** A `fetcher.yaml`
  declares only *what kind* of assessment its report can feed
  (`issue_report.assessment_type`); *which* assessment is `config.assessment_id`,
  written by `paramify assessments select`. This is the same shipped-vs-chosen
  split as `evidence_set` versus a program target, and the reason there is no
  get-or-create step here: you cannot invent an assessment the way you can an
  evidence set.
- **Idempotency is local.** Intake *adds* an artifact every time, and there is no
  endpoint to list what a cycle holds — so unlike the evidence uploader's
  `artifact_exists` check, no API call can detect a duplicate.
  `issue-reports/_intake_log.json` records each upload and each job queued, and is
  the only thing making a re-run safe.
- **Closing is a decision, not a step.** Closing a cycle auto-closes every open
  issue it never saw, so a close after a partial run marks real issues resolved.
  The process call is `PROCESS_CLOSE` only when the assessment's `close_cycle` is
  `after_run` and the sidecar's `invocations` show every target succeeded; otherwise
  `PROCESS`, and `paramify issues close` closes it later.

It also inverts one default: `skip_failed` is **true** here. A failed evidence
fetch still documents the attempt, but a partial scan report is parsed into
issues, and findings missing from it read as resolved — silently closing real
vulnerabilities.

`--force` is unique to this uploader: it re-sends a report already listed in
the run's `_intake_log.json`. The endpoint *adds* a second artifact, so this
duplicates issues — use it when a previous intake was parsed incorrectly, not
as a habit.

Full detail is in [`../uploaders/paramify_issues/README.md`](../uploaders/paramify_issues/README.md);
the collection side is [`issue_report_fetchers.md`](issue_report_fetchers.md).

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
- `paramify issues upload` — after any run that included an issue-report fetcher.
  It is a separate command rather than part of `paramify upload` because the two
  write to different endpoints with different failure modes; a run holding both
  kinds needs both, and `paramify upload` alone leaves the reports unsent.
- `paramify scripts sync` — a **provisioning** step, when `fetchers/**` change
  (a fetcher added, or its entry script / version bumped). Not on every
  collection.
