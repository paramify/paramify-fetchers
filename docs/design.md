# Paramify Fetcher Framework — Design Notes

**Status:** Living document — design rationale and current state of the work
(see the **Current state of the work** section below).
**Author:** Tate
**Last updated:** 2026-06-01

This document captures the design for a longer-term fetcher framework that supports both internal use and customer/FDE deployment. The near-term **MVP deployment is the containerized bundle in `deploy/`** — a Docker image (the tool, its Python deps, and the CLIs fetchers shell out to) run on a schedule via compose/cron or a Kubernetes `CronJob`, with secrets hydrated at startup (env, or AWS Secrets Manager) and AWS resolved through the ambient credential chain (IRSA in-cluster). See [`deploy/README.md`](../deploy/README.md). This doc covers the framework design that bundle packages; for the deployment specifics see `deploy/`.

---

## Context & problem statement

Paramify's fetchers today are scripts in a GitHub repo, varying widely in shape, config conventions, and runtime expectations (see the existing `.env.example`). They're invoked via a TUI. This works for internal use but doesn't scale to:

- FDEs building integrations for customer-specific tools
- Customers running fetchers in their own environments (which is the only viable model — fetchers will not run on Paramify infra)
- Cross-fetcher data composition (e.g., reconciling Okta users against Rippling employees)
- Many-target fetchers (e.g., one CI/CD check across N GitLab repos)

The configuration sprawl in the current `.env` is a symptom of a deeper issue: **there is no fetcher contract**. Every fetcher invents its own conventions because none are imposed. Examples in the current state:

- `IAM_ROLES_FETCHER=--exclude-aws-managed-roles` — CLI args leaking into env vars
- `AWS_REGION_1_FETCHERS=iam_roles,guard_duty` vs `GITLAB_PROJECT_1_FETCHERS=...` — same idea, inconsistent naming
- A central `catalog.json` that has to be hand-maintained in sync with the scripts

Fixing the symptoms without fixing the cause just postpones the same problems.

---

## Core decisions

### Where fetchers run: customer infrastructure

Customer-side execution is settled. This cascades into everything else:

- Secrets must be **secret-agnostic** — read from env, populated however the customer wants (their secret manager, IRSA, CI vault, pasted `.env`)
- The framework does not own orchestration — it provides something the customer drops into their orchestrator of choice (GitHub Actions, Jenkins, cron, Prefect, Argo)
- Data residency and FedRAMP boundary concerns are mostly resolved by execution location

### Output format: JSON files on disk

Fetchers produce JSON files. This decouples every stage from every other stage — fetcher writes JSON, next thing reads JSON. No in-memory coupling, no shared runtime, no shared language requirement. This is load-bearing for everything else.

### Fetcher scope: pure data collection, separate comparison layer

Fetchers pull data from a single source. Cross-source comparison logic (the "layer 2" idea) lives in separate components with the *same contract* — they just read prior fetcher outputs instead of external APIs.

Rationale: fetchers and comparators have fundamentally different failure modes. Fetcher failures are transient (rate limits, auth, network) and need retry/backoff. Comparator failures are logical (malformed input, broken join) and retry doesn't help. Mixing them prevents writing sane retry policies for either.

### Intermediate data lives in the run's output directory

When comparators need prior fetcher output, they read it from the same directory those fetchers wrote to. No separate intermediate store, no external infrastructure. This stays consistent with "JSON files on disk" and avoids inventing a new substrate.

---

## The fetcher contract

Every fetcher must satisfy this interface. **`fetcher_schema.json` now enforces config injection, fanout, and evidence-set identity in addition to the original minimal core; the remaining gaps (structured exit codes, in-fetcher envelope authoring) will be enforced as the framework matures.**

### Input

- A **config object** — structured, typed, validated on load — describing what to fetch and with what options
- A **secrets object** — read from env by the framework, passed to the fetcher as already-resolved values (fetchers do not read env directly)
- An **output directory path** to write to
- A **run ID / correlation ID** for logging

### Output

- One or more JSON files in the output directory following a defined **envelope schema** (metadata block + payload block) — now built; the runner wraps each output file
  - Metadata: fetcher name, version, category, run ID, target identifier, timestamp, status, exit code, evidence_set (when present), and an error (stderr tail) on failure
  - Payload: the actual evidence data
- A **structured log stream** (stdout JSON lines is fine)
- An **exit code** with documented meanings (0 = success; non-zero for documented failure categories)

### Behavior

- Idempotent for the same config + target + time window
- Handles pagination internally
- Surfaces partial failures in output rather than failing the whole run when one target fails
- Never writes outside its given output directory
- Never reads secrets from anywhere except the secrets object handed to it

### Reality check

Existing fetchers being ported into the new structure violate parts of this contract today — most notably, they read env vars directly and write hardcoded filenames without envelopes. These are tracked as version 0.x in their `fetcher.yaml` and will be brought into compliance over time, not as part of the initial port.

---

## Configuration architecture: two distinct artifacts

A critical distinction:

### Fetcher schema (`fetcher.yaml`)

Ships **with** the fetcher in the repo. The fetcher's *self-description*: what config it accepts, what secrets it needs, what version it is, how to invoke it. Doesn't change between runs. Authored by fetcher developers.

See `framework/schemas/fetcher_schema.json`. Required fields:

- `name`, `version`, `description`, `runtime`, `output`, `secrets`

Optional fields:

- `category`, `config_schema`, `supports_targets`, `target_schema`, `depends_on`

Plus optional sub-fields that became real when the first fanout fetcher landed:

- `output.aggregation` — `per_target` | `aggregate` (only meaningful when `supports_targets: true`)
- `secrets[].per_target` — boolean; secret resolved per-target invocation rather than once per fetcher
- `target_schema.<field>.env` — env var name the runner sets from this field per target

Fields like envelope versioning and conditional validation rules remain deliberately cut. They'll be added when their absence causes real friction.

Example for the first ported fetcher:

```yaml
name: okta_phishing_resistant_mfa
version: 0.1.0
description: >
  FedRAMP 20x KSI-IAM-01 evidence. Collects phishing-resistant MFA
  configuration and adoption from Okta.
category: okta

runtime:
  type: python
  entry: fetcher.py

secrets:
  - name: api_token
    env: OKTA_API_TOKEN
  - name: org_url
    env: OKTA_ORG_URL
```

### Run manifest

Lives in the customer's environment, not in the framework repo. The customer's *intent*: which fetchers to invoke, with what config values, against what targets. Read by the runner at execution time. Changes constantly.

Customers will typically have multiple manifests in their environment — one per "kind of run" (daily evidence pull, weekly deep scan, quarterly access review, etc.) — rather than one giant manifest.

The manifest schema lives in `framework/schemas/run_manifest_schema.json`. Minimal v0.x shape:

```yaml
run:
  output_dir: ./evidence
  fetchers:
    - use: <fetcher_name>
      secrets:
        <secret_name>: ${env:VAR_NAME}

    - use: <fanout_fetcher>
      targets:
        - <target_schema_field>: <value>
          secrets:
            <per_target_secret>: ${env:OTHER_VAR}
```

The runner resolves `${env:VAR_NAME}` references from its own environment. See `examples/minimal_run.yaml` for a working example exercising both single-target and fanout shapes.

Manifests also carry per-category platform settings under `run.platforms.<category>` — a `config` block (literal values merged into every fetcher in that category) and `passthrough_env` (ambient cloud vars allowed through the runner's env whitelist, e.g. IRSA/instance-role vars for AWS and K8s). Customers don't hand-edit manifests blind: the `manifest` builder (below) reads each `fetcher.yaml` and reports which secrets/config a fetcher still needs before it's runnable.

### Why this split matters

- **Customers never edit fetcher.yaml** — that's your code, your versioned release
- **Runners never hardcode fetcher specifics** — they read `fetcher.yaml` to know what each fetcher needs and resolve generically
- **Secrets are referenced by env var name**, so manifests are safe to commit; resolution happens at runtime
- **The runner is the join point** between code-side contract and customer-side intent

---

## One facade, one CLI, three front-ends

All operations against the framework — discover fetchers, build/edit a manifest, validate, run — go through a single facade, `framework/api.py`. A single `paramify` CLI (installed via `pip install -e .`) steers every front-end, and they call **only** the facade, so their behavior is identical:

1. **Human CLI** — `paramify <cmd>`
2. **AI CLI** — the same commands with `--json` for machine-readable output
3. **Terminal UI** — `paramify tui`, an interactive Textual app

Keeping the surface in one facade means a new capability lands once and shows up in all three front-ends, and there's no risk of the CLI and UI drifting. (`python -m framework.runner|tui` still work and equal the matching `paramify` subcommands.)

### CLI command surface

```
list [--json]                discovered fetchers (flat)
catalog [--json]             categories → fetchers → editable fields
describe <fetcher> [--json]  one fetcher's config / secrets / target fields
validate <manifest> [--json]
run <manifest> [--json]
manifest <sub>               build/edit a manifest file (-f/--file, default ./manifest.yaml)
```

`manifest` subcommands: `init [--output-dir DIR]`, `add <fetcher>`, `remove <fetcher>`, `set-config <fetcher> key=value`, `set-secret <fetcher> <secret_name> <ENV_VAR>`, `add-target <fetcher> k=v ... [--secret name=ENV_VAR ...]`, `set-platform-config <category> key=value`, `set-passthrough <category> ENV_VAR ...`, `set-output-dir <dir>`, `show [--json]`. The builder reads each `fetcher.yaml` and warns which secrets/config are still missing until the fetcher is runnable.

> **Note:** this list is illustrative of the surface's shape, not exhaustive — the live CLI also has `manifests`, `runs`, `evidence`, `upload`, and `manifest new` / `remove-target`. The authoritative, current surface is `CLAUDE.md` / [`fetcher_contract.md`](fetcher_contract.md) (and `paramify --help`).

### Execution and the run directory

The executor runs each invocation via `subprocess.Popen` + threads with live stdout streaming (which feeds the TUI run console) and a per-invocation timeout (default 600s, overridable via `runtime.timeout` in `fetcher.yaml`; a timed-out invocation is killed and reported as exit 124). Each child gets a minimal env whitelist plus the injected config, resolved secrets, and category passthrough vars.

Output lands in `<output_dir>/run-<UTC-timestamp>/`: each evidence file is wrapped in the `{schema_version, metadata, payload}` envelope, and a `_run_metadata.json` (the per-run index, **not** enveloped) records run_id, per-invocation timestamps, durations, exit codes, and outputs.

### Config vs. secrets, concretely

- **Config** is literal values in a *file*: per-fetcher config and `run.platforms.<cat>.config` in the manifest, plus code-side defaults in `fetcher.yaml` `config_schema` and `_categories/<cat>.yaml` `config_schema`. Customers never edit the code-side yaml.
- **Secrets** are *env*, referenced in the manifest by a `${env:VAR}` placeholder, source-agnostic (`.env`, secret manager, CI — none privileged). The runner resolves them from its own environment.
- **Injection**: the runner merges category defaults ← platform values ← per-fetcher config, maps them to env vars via each field's `config_schema` `env` mapping, and resolves secrets the same way. `auth.passthrough_env` lets ambient cloud vars through the whitelist.

---

## Fanout: many targets, one fetcher

The pattern for "run this fetcher against N targets" (multi-region AWS, multi-project GitLab, multi-cluster K8s, etc.):

- Fetcher's `fetcher.yaml` declares `supports_targets: true`
- Run manifest provides a `targets` list under that fetcher
- Runner iterates: for each target, merge config + target overrides, resolve secrets, invoke fetcher with target identifier
- Each invocation produces its own envelope file, tagged with the target ID
- Independent failure domains — one expired token doesn't break the others

Two aggregation modes:

- **`per_target`** — one envelope per target (e.g., one piece of evidence per GitLab repo)
- **`aggregate`** — fetcher receives the whole target list and emits one combined envelope (e.g., "S3 bucket public access across all buckets")

Both modes are declared via `output.aggregation` in `fetcher.yaml`. Every fanout fetcher to date uses `per_target`; no `aggregate`-mode fetcher exists yet. All 79 AWS fetchers are fanout: 64 are regional (`region` + `profile` targets, one `(region, profile)` per invocation), 12 are global and fan out by `profile` only (`region` optional, defaults `us-east-1`), and 3 are mixed-scope (a global half duplicates per region — documented, not split). GitLab fans out per project; K8s per cluster.

### Inversion from current model

Current `.env` groups by region, lists fetchers under each region:

```
AWS_REGION_1=us-gov-west-1
AWS_REGION_1_FETCHERS=iam_roles,guard_duty
```

New model groups by fetcher, lists regions as targets (AWS targets carry a named `~/.aws` `profile` alongside the region):

```yaml
- use: iam_roles
  targets:
    - region: us-gov-west-1
      profile: gov
    - region: us-east-1
      profile: commercial
- use: guard_duty
  targets:
    - region: us-gov-west-1
      profile: gov
```

Isolates failure domains and avoids re-listing fetchers per region.

---

## Layer 2 / comparators

Comparators satisfy the same contract as fetchers. Their distinguishing properties:

- Their "source" is a directory of prior envelope files, not an external API
- They declare `depends_on: [fetcher_a, fetcher_b]` in their `fetcher.yaml`
- The runner ensures dependencies complete (with acceptable status) before invoking
- They produce envelope output just like any other fetcher

So "reconcile Okta against Rippling" is just a fetcher whose inputs happen to be other fetchers' outputs. No special category, no special runtime, no special data store.

Structurally identical to fetchers. Filed under a separate `comparators/` directory for human navigation, but the runner treats them the same way.

---

## Uploaders as a separate stage

Pushing evidence to Paramify is **not** a fetcher concern. It's a separate stage that:

- Reads envelopes from the run's output directory
- Pushes to Paramify via API
- Handles its own retries, auth, idempotency

Benefits of separation:

- Fetchers can run with no Paramify connection at all (useful for dev, testing, customer dry-runs)
- Customers can insert a review/approval step between fetch and upload
- Re-uploading from a prior run is trivial — point the uploader at an old output directory
- The Wiz-style case (writing issues back to Paramify, not just evidence) becomes a different uploader, not a hack inside the fetcher

The evidence uploader is built (and exposed as `paramify upload`):
`uploaders/paramify_evidence/` reads an enveloped run directory, gets-or-creates an evidence set by `reference_id` (Paramify REST v0), multipart-uploads the artifact, and is idempotent within a run. It supports `--dry-run`, `--config`, an https-only token guard, customer `reference_id` overrides, and auth via `PARAMIFY_UPLOAD_API_TOKEN` (+ optional `PARAMIFY_API_BASE_URL` / `--config base_url`). A second uploader, `uploaders/paramify_scripts/` (exposed as `paramify scripts sync`), is also built — a provisioning step that pushes each fetcher's entry script to Paramify and CONNECTs it to that fetcher's evidence set, manifest-scoped by default (`--all` for the whole catalog). See [`uploader_design.md`](uploader_design.md) for both. The Wiz-style issues uploader (`uploaders/paramify_issues/`) is still an empty stub.

Orchestration that chains collect → upload is customer-owned, not built into the runner. `run_and_upload.sh` at the repo root is example glue.

---

## Repository structure

```
paramify-fetchers/
├── CLAUDE.md                         # context for Claude Code sessions
├── README.md                         # entry point for engineers adding fetchers
├── pyproject.toml                    # packaging; installs the `paramify` CLI (pip install -e .)
├── requirements.txt                  # python-dotenv, requests, pyyaml, jsonschema, typer (+ textual, checkov)
├── manifest.yaml                     # repo-root sample manifest
├── run_and_upload.sh                 # repo-root collect→upload example glue
├── .gitignore
│
├── framework/                        # contract + facade + runner code
│   ├── api.py                        # THE FACADE — discovery, manifest edit, validate, run
│   ├── cli.py                        # the `paramify` CLI (Typer) — steers every front-end
│   ├── contract.py                   # dataclasses (Fetcher, Manifest, RunResult, ...)
│   ├── config_loader.py              # discover fetchers; validate against schema
│   ├── secret_resolver.py            # ${env:VAR_NAME} resolution
│   ├── envelope.py                   # wraps each output in {schema_version, metadata, payload}
│   ├── runner/
│   │   ├── __init__.py               # back-compat shim (`python -m framework.runner` → the CLI)
│   │   ├── __main__.py               # entry point for `python -m framework.runner`
│   │   ├── manifest_loader.py        # load + validate manifests
│   │   ├── executor.py               # subprocess.Popen + threads; streamed stdout; per-invocation timeout
│   │   ├── logger.py                 # empty stub
│   │   ├── retry.py                  # empty stub
│   │   └── dependency_graph.py       # empty stub
│   ├── tui/                          # Textual terminal UI front-end (`paramify tui`)
│   └── schemas/
│       ├── fetcher_schema.json
│       ├── category_schema.json
│       ├── run_manifest_schema.json
│       └── envelope_schema.json
│
├── fetchers/                         # 122 fetchers across 10 categories
│   ├── _categories/                  # platform-wide config + auth per category
│   │   ├── okta.yaml
│   │   ├── aws.yaml
│   │   └── ...                       # (+ azure/ssllabs/wiz stubs — no ported fetchers)
│   ├── _template/                    # starter directory for new fetchers
│   ├── aws/                          # 80 bash (largest category; fanout per region/profile)
│   ├── datadog/                      # 13 Python (SIEM, logs, infra, APM, incidents)
│   ├── okta/                         # 8 (7 Python KSI wrappers + 1 bash); _shared/okta_iam_core.py
│   ├── sentinelone/                  # 5 single-target Python
│   ├── knowbe4/                      # 4 bash
│   ├── k8s/                          # 3 bash (aws-cli + kubectl)
│   ├── rippling/                     # 3 single-target Python
│   ├── gitlab/                       # 3 fanout-capable Python (e.g. ci_cd_pipeline_config)
│   ├── checkov/                      # 2 bash IaC scanners (terraform + kubernetes)
│   └── demo/                         # 1 credential-free synthetic demo (demo_hello)
│
├── comparators/                      # scaffold only (_template/); no comparator ported, runner doesn't honor depends_on
│
├── uploaders/
│   ├── paramify_evidence/            # BUILT — get-or-create evidence set + multipart upload
│   ├── paramify_scripts/             # BUILT — sync entry scripts + associate to evidence sets
│   └── paramify_issues/              # empty stub (Wiz-style issues; not built)
│
├── deploy/                           # containerized bundle — the MVP deployment
│   ├── Dockerfile / docker-compose.yml / entrypoint.sh / crontab
│   ├── manifests/                    # daily / weekly / aws run manifests
│   └── k8s/                          # CronJobs + IRSA + Terraform multi-account module
│
├── examples/                         # sample manifests (minimal_run, multi_region_aws, with_platform_config, upload.yaml, ...)
├── manifests/                        # discovered run manifests (`paramify manifests`)
├── catalog/                          # not built yet (will be GENERATED from fetcher.yaml files)
│
└── docs/
    ├── design.md                     # this file — design rationale + current state
    ├── fetcher_contract.md           # the runner⇄fetcher contract
    ├── porting_playbook.md           # how to port an existing fetcher (the "why")
    ├── authoring_a_fetcher.md        # how to write a new fetcher from scratch
    ├── run_manifest_reference.md     # manifest format reference
    ├── config_injection_design.md    # platform/config/auth injection model
    ├── envelope_design.md            # evidence envelope format
    ├── packaging_design.md           # proposed `paramify package` (not built)
    └── onboarding/                   # hands-on guided tutorial (Lathe)
```

### Naming conventions

- Fetcher directories grouped by category: `fetchers/<category>/<short_name>/`
- The fetcher's `name` field in `fetcher.yaml` is globally unique (e.g. `okta_phishing_resistant_mfa`), not category-scoped
- Directories prefixed with `_` are not fetchers (`_categories/`, `_template/`, `_shared/`); runner discovery walks `fetchers/*/*/fetcher.yaml` and skips underscore-prefixed paths

### Shared code

Code shared across fetchers in the same category lives in `fetchers/<category>/_shared/`. Cross-category framework code lives under `framework/`. Per-category shared code (like `okta_iam_core.py`) is allowed to be large and is ported as-is rather than refactored as a side quest.

---

## Catalog: from source of truth to derived artifact

The current `catalog.json` is hand-maintained and conflates several concerns:

- Fetcher discovery (name, script path, description)
- Runtime dependencies (`aws-cli`, `python3`)
- Compliance metadata (`controls`, `solution_capabilities`)
- Output validation rules (regex patterns + pass/fail logic)
- Per-category access guidance

**Decomposition:**

- **Discovery + runtime** → into each `fetcher.yaml`
- **Category metadata** → into `_categories/<name>.yaml`
- **Catalog** → generated by walking the tree and assembling, not hand-maintained

This makes fetchers self-describe and turns the catalog into derived data.

### Two concerns to revisit later

**Compliance metadata (`controls`, `solution_capabilities`):**

Whether a fetcher's output speaks to IAM-01 in one customer's SSP and a different control in another customer's SSP is a *Paramify configuration* concern, not a fetcher concern. Baking it into the fetcher couples its identity to a control framework that will evolve. Likely outcome: demote to documentation or move out of the fetcher entirely; let Paramify own the mapping per customer program.

Not in the current schema. Decide what to do with it after a few more fetchers are ported.

**Validation rules (regex against JSON output):**

The current approach parses JSON output with regex to determine pass/fail. Most fetchers have `validation_rules: []`, so the pattern isn't consistently applied today. The blurry boundary between "evidence was collected" (fetcher concern) and "evidence indicates compliance" (Paramify concern) needs to be resolved before this is ported. Cut from the schema entirely for now.

---

## Current state of the work

**This section is the kept-current account of what's ported and what's in
progress.** Snapshot: 122 fetchers across 10 categories (aws, datadog, okta,
sentinelone, knowbe4, gitlab, k8s, rippling, checkov, demo); the AWS port is
complete (80/80). The pieces that make this run:

- **Facade + three front-ends** (`framework/api.py`) — all discovery, manifest editing, validate, and run go through one facade; the human CLI, the `--json` AI CLI, and the Textual TUI (`paramify tui`) all call only the facade
- **Fetcher schema** (`framework/schemas/fetcher_schema.json`) — supports fanout: `supports_targets`, `target_schema`, `per_target` secrets, `output.aggregation`. Extended additively from the original minimal version.
- **Runner** (`framework/runner/`) — `list` / `catalog` / `describe` / `validate` / `run` / `manifest` subcommands (all with `--json`); single-target + fanout execution via `subprocess.Popen` + streamed stdout, per-invocation timeout (default 600s, exit 124 on kill), per-target failure isolation, env-whitelist + config/secret/passthrough injection, secret resolution from `${env:...}` references, envelope wrapping, `_run_metadata.json` recording (run_id, per-invocation timestamps, durations, exit codes, outputs)
- **Manifest schema** (`framework/schemas/run_manifest_schema.json`) + builder CLI (`manifest` subcommands) + working examples (`examples/minimal_run.yaml`, `multi_region_aws.yaml`, `with_platform_config.yaml`, ...)
- **Secret resolver** (`framework/secret_resolver.py`) — `${env:VAR_NAME}` only for v0.x; shape leaves room for future backends (`${aws-secret:...}`, `${vault:...}`)
- **Conventions established**:
  - Logging: Python `logging` module; bash uses structured `printf` with a matching format
  - Exit codes: v0.x is binary 0/1 — Okta wrappers check `OktaAPIClient.api_failures`; GitLab checks result `status`; bash tracks via temp file (subshells can't mutate parent counters)
  - Output filenames: per_target fetchers derive their own filename from the target identifier
- **Docs** — see the `docs/` tree above.

Done since the last revision:

- ~~**Envelope schema**~~ — DONE (2026-05-28). The runner wraps each output file in the standard `metadata` + `payload` envelope (metadata carries fetcher/version/category/run_id/target/collected_at/status/exit_code, plus `evidence_set` when present and an `error` (stderr tail) on failure); fetchers still write raw payloads. See [`envelope_design.md`](envelope_design.md).
- ~~**Config injection**~~ — DONE. Category defaults ← platform config ← per-fetcher config, injected as env vars via `config_schema` `env` mappings; `auth.passthrough_env` opens the whitelist for ambient cloud vars.
- ~~**Evidence-set identity**~~ — DONE. Every `fetcher.yaml` carries an `evidence_set` block (reference_id / name / instructions), backfilled from the upstream catalog; it flows into the envelope and drives uploader get-or-create.
- ~~**Evidence uploader**~~ — DONE. `uploaders/paramify_evidence/` ships (get-or-create by reference_id, multipart upload, idempotent, `--dry-run`, https-only token guard).
- ~~**Scripts uploader**~~ — DONE. `uploaders/paramify_scripts/` (`paramify scripts sync`) provisions each fetcher's entry script and associates it to the fetcher's evidence set — GitOps reconcile (marker identity, version signal, sha256 drift guard), manifest-scoped by default with `--all`. See [`uploader_design.md`](uploader_design.md).

What's deferred:

- **Issues uploader** — `uploaders/paramify_issues/` is an empty stub; the Wiz-style write-issues-back case is not built
- **Comparators** — `comparators/_template/` scaffold exists but no comparator ported; `depends_on` is in the schema but not honored by the runner because nothing consumes it (`runner/logger.py`, `retry.py`, `dependency_graph.py` are still empty stubs)
- **Structured exit codes** — still binary 0/1 (plus 124 = runner timeout-kill). Categorized auth/network/internal/partial codes are contract-era work.
- **Catalog generator** — fetchers self-describe; the derived `catalog.json` walker isn't written yet
- **`aggregate` mode** — declared in schema; no fetcher uses it yet
- **Unported categories** — `azure`, `ssllabs`, and `wiz` exist only as `_categories/<name>.yaml` stubs with no ported fetchers
- **Shared module refactor** — `okta_iam_core.py` still reads env directly (with one tiny additive change: it now exposes `api_failures` for exit-code purposes). Full rework waits on the framework's secret resolver taking over per-fetcher invocation.

---

## Near-term deployment: the containerized bundle

The MVP deployment is the bundle in `deploy/` — a Docker image run on a schedule (compose/cron on a single host). The collector runs collect→upload and the container is transient. Secrets are hydrated at startup from the environment (or AWS Secrets Manager when `PARAMIFY_SECRETS_ID` is set); AWS auth uses the ambient credential chain (an instance role / IRSA in cloud, a named profile locally). See [`deploy/README.md`](../deploy/README.md).

Two principles this honors, so the deployment doesn't constrain the eventual framework:

1. **Secret resolution stays outside the fetchers.** Fetchers remain env-var-driven; the entrypoint (and the eventual secret resolver) handles source → env var. The framework's resolver can replace the entrypoint logic without touching fetchers.
2. **Every run writes a `_run_metadata.json`** capturing timestamp, fetcher versions, exit codes, and durations — an audit trail, and a preview of the artifact shape the framework produces.

---

## Open questions

Honest list — these are real and not yet resolved:

- **Schema evolution.** When `fetcher.yaml` changes between versions, how do existing run manifests handle the change? The schema has already been extended once additively (fanout fields); the harder case — renaming/removing fields with manifests in flight — is still untested.
- **Long-running fetchers.** Some scans (SSL Labs) take hours. The runner now enforces a per-invocation timeout (default 600s, overridable via `runtime.timeout`; kill → exit 124), but that's still just a kill — there's no story for resumable or async-poll fetchers.
- **Customer-authored fetchers.** Distribution, validation, sandboxing, trust model all undefined.
- **Multi-tenancy in a single run.** Can one run touch multiple Paramify programs? Probably not, but worth confirming.
- **Streaming vs. batch.** Current model is batch. Some use cases (ConMon) want continuous streaming, which is a different paradigm.
- **Backfill and replay.** Re-running a fetcher against historical data isn't always possible (most APIs only return current state); framework should be explicit about which fetchers support point-in-time queries.
- **Shared code refactor scope.** When `okta_iam_core.py` (and equivalents for other categories) eventually gets refactored to receive secrets explicitly, what's the migration strategy across the fetchers that depend on it?