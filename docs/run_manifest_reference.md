# Run Manifest Reference

**Status:** v0.x — manifest format is settled.

**See also:** schema at [`framework/schemas/run_manifest_schema.json`](../framework/schemas/run_manifest_schema.json), working example at [`examples/minimal_run.yaml`](../examples/minimal_run.yaml).

A run manifest is the customer's *intent*: which fetchers to invoke, with what config, against what targets. It lives in the customer's environment, not in the framework repo. Customers typically have multiple manifests — one per kind of run (daily evidence, weekly scan, quarterly access review).

---

## Top-level shape

```yaml
run:
  output_dir: ./evidence     # optional; default ./evidence
  platforms:                 # optional; per-category config + auth (see below)
    <category>:
      config: { ... }
      auth: { passthrough_env: [ ... ] }
  fetchers:
    - use: <fetcher_name>
      config: { ... }        # optional; per-fetcher config, overrides platform config
      secrets: { ... }       # required when fetcher declares non-per_target secrets
      targets: [ ... ]       # required only when a target field is required (see below)
```

The runner walks `run.fetchers[]` and invokes each in order. v0.x is serial — no parallelism, no `depends_on` ordering, no retries.

---

## Per-fetcher entry

| Field | Required when | Description |
|---|---|---|
| `use` | always | Matches the `name` field in a discovered `fetcher.yaml` |
| `config` | optional | Config values for this fetcher. The runner injects each key declared in the fetcher's (or its category's) `config_schema` as the env var named there. Overrides platform config. |
| `secrets` | fetcher has non-`per_target` secrets | Map of `<secret_name>: <reference>` |
| `targets` | fetcher has at least one **required** target field | Array of target entries. A `supports_targets` fetcher whose target fields are ALL optional may omit `targets[]` — the runner then does a single ambient invocation ("collect where deployed"). All 79 AWS fetchers are this all-optional case. |

### `config.assessment_id` (issue-report fetchers)

A `kind: issue_report` fetcher accepts two config keys the framework adds to every
one of them, rather than each `fetcher.yaml` declaring them:

| Key | Description |
|---|---|
| `assessment_id` | UUID of the Paramify assessment its report is intaken into |
| `assessment_name` | The readable name, written alongside so the manifest stays legible and a stale UUID is recognisable. Not used to resolve anything. |

Set them by name rather than by hand:

```bash
paramify assessments select <fetcher>      # picks from the workspace, writes both keys
```

Unlike most required wiring, a missing `assessment_id` does not stop a run —
collecting with no Paramify connection at all is a property the framework keeps
(see [`design.md`](design.md)). `paramify validate` reports it and
`paramify issues upload` refuses the report, which are the two points where it
matters. Details: [`issue_report_fetchers.md`](issue_report_fetchers.md).

---

## Platform block (`run.platforms`)

Per-category config and auth, inherited by every fetcher in that category — so
you set a base URL, region, or auth model once instead of per fetcher. Keyed by
category name.

```yaml
run:
  platforms:
    rippling:
      config:
        page_size: 250                 # overrides the category default
    aws:
      auth:
        passthrough_env:               # cloud-identity auth (e.g. EKS IRSA):
          - AWS_WEB_IDENTITY_TOKEN_FILE # let these ambient vars through the
          - AWS_ROLE_ARN                # runner's env whitelist
```

- `config` — values for keys declared in `fetchers/_categories/<category>.yaml`'s
  `config_schema`. Merge order: category defaults ← `platforms.<cat>.config` ←
  per-fetcher `config`.
- `auth.passthrough_env` — ambient env vars the runner lets through its minimal
  whitelist for this platform. Use for cloud identity where there's no secret to
  set (instance roles, IRSA). Added to whatever the category yaml already lists.

Full model: [`config_injection_design.md`](config_injection_design.md). Worked
example: [`examples/with_platform_config.yaml`](../examples/with_platform_config.yaml).

---

## Secret references

Values in `secrets:` and `targets[].secrets:` use the `${env:VAR_NAME}` syntax. The runner resolves them by reading `VAR_NAME` from its own environment.

```yaml
secrets:
  api_token: ${env:OKTA_API_TOKEN}
  org_url: ${env:OKTA_ORG_URL}
```

Plain strings (not matching the pattern) pass through unchanged.

How `VAR_NAME` ends up in the runner's environment is up to the customer — `.env`, shell `export`, AWS Secrets Manager → env, HashiCorp Vault, K8s secret env mounts, CI provider secret blocks, etc. The resolver is **source-agnostic**; `.env` is not privileged.

If a referenced env var is unset or empty when the runner resolves it, the runner fails the invocation with a structured error (the fetcher is not invoked).

---

## Single-target example

```yaml
run:
  output_dir: ./evidence
  fetchers:
    - use: okta_phishing_resistant_mfa
      secrets:
        api_token: ${env:OKTA_API_TOKEN}
        org_url: ${env:OKTA_ORG_URL}
```

The runner:

1. Resolves both secrets from its own env.
2. Sets `OKTA_API_TOKEN` and `OKTA_ORG_URL` in the child process env.
3. Sets `EVIDENCE_DIR=<output_dir>/run-<timestamp>`.
4. Exec's `fetcher.py`.
5. Records exit code + duration + output files in `_run_metadata.json`.

---

## Fanout example

```yaml
run:
  output_dir: ./evidence
  fetchers:
    - use: gitlab_ci_cd_pipeline_config
      targets:
        - project_id: group/change-management
          url: https://gitlab.example.com
          secrets:
            api_token: ${env:GITLAB_TOKEN_1}

        - project_id: group/terraform
          url: https://gitlab.example.com
          branch: main
          secrets:
            api_token: ${env:GITLAB_TOKEN_2}
```

For each target the runner:

- Reads the fetcher's `target_schema` from its `fetcher.yaml` to know which fields exist and which env vars they map to.
- Sets each target field (e.g. `project_id`) as the corresponding env var (`GITLAB_PROJECT_ID`).
- Resolves the per-target `secrets:` block into env vars for the secrets marked `per_target: true` in the fetcher.yaml.
- Exec's the entry script once per target.
- Isolates per-target failures — one target's expired token doesn't abort the others.

---

## Output directory layout

The runner creates a per-run subdirectory:

```
<output_dir>/
  run-<UTC-timestamp>/
    <fetcher>.json                          # single-target output (envelope-wrapped)
    <fetcher>_<target_identifier>.json      # one file per fanout target (envelope-wrapped)
    _run_metadata.json                      # per-run index (NOT enveloped)
    issue-reports/                          # only when the run had issue-report fetchers
      <tool's own filename>.csv             # raw, unmodified (NOT enveloped)
      _issue_reports.json                   # sidecar index for the intake uploader
```

The timestamp is ISO-8601 in UTC with `:` replaced by `-` for filesystem safety: e.g. `run-2026-05-27T14-36-46Z`.

Each evidence file is wrapped by the runner in the standard envelope —
`{schema_version, metadata, payload}`, where `metadata` carries attribution
(`fetcher_name`, `fetcher_version`, `category`, `run_id`, `target`,
`collected_at`, `status`, `exit_code`, plus the fetcher's `evidence_set` block
when present) and `payload` is the fetcher's raw output. Failed invocations also
carry an `error` in the metadata. `_run_metadata.json` is the run-level
index and is not itself enveloped. See [`envelope_design.md`](envelope_design.md).

Files under `issue-reports/` are the exception: they are the source tool's own
bytes, unmodified, because Paramify's assessment intake parses the vendor format.
The attribution an envelope would have carried lives in `_issue_reports.json`
beside them — one record per report, naming the fetcher, the run, the assessment
it is destined for, and the file's sha256. The subdirectory is also what keeps the
two uploaders from stepping on each other: `paramify upload` globs the run dir's
top level, so it never sees a report, and `paramify issues upload` reads only the
sidecar. See [`issue_report_fetchers.md`](issue_report_fetchers.md).

---

## `_run_metadata.json`

Written at the end of every run. Captures what ran, when, how long, what came out, and whether it succeeded:

```json
{
  "run_id": "2026-05-27T14-36-46Z",
  "started_at": "2026-05-27T14:36:46Z",
  "completed_at": "2026-05-27T14:36:46Z",
  "invocations": [
    {
      "fetcher_name": "okta_phishing_resistant_mfa",
      "fetcher_version": "0.1.0",
      "target": null,
      "started_at": "...",
      "completed_at": "...",
      "duration_sec": 0.266,
      "exit_code": 0,
      "outputs": ["okta_phishing_resistant_mfa.json"]
    },
    {
      "fetcher_name": "okta_least_privilege",
      "exit_code": 1,
      "outputs": [],
      "stderr_tail": "...last 4000 chars of stderr — present only on non-zero exit..."
    },
    {
      "fetcher_name": "gitlab_ci_cd_pipeline_config",
      "fetcher_version": "0.1.0",
      "target": {"project_id": "group/change-management", "url": "..."},
      ...
    }
  ]
}
```

This is the v0.x stand-in for the eventual envelope schema. It records each invocation (one row per single-target fetcher; N rows per fanout fetcher). Failed invocations also carry a bounded `stderr_tail` (last 4000 chars) so an unattended run is diagnosable from the artifact alone.

Each invocation is killed if it exceeds its timeout (default 600s; override per fetcher via `runtime.timeout` in `fetcher.yaml`). A killed invocation is recorded with `exit_code: 124`.

---

## CLI

There is one `paramify` CLI (installed via `pip install -e .`), a thin command
surface over `framework.api`, the shared facade. It steers every front-end:
the human CLI, the AI CLI (same commands with `--json`), and the TUI as the
`paramify tui` subcommand — all through that one facade, so behavior is
identical across front-ends. Nothing in the CLI re-implements discovery,
validation, manifest editing, or execution.
(`python -m framework.runner|tui` still work and equal the matching
`paramify` subcommands.)

### Discover

```bash
paramify list [--json]              # discovered fetchers (flat)
paramify catalog [--json]           # categories -> fetchers -> editable fields
paramify describe <fetcher> [--json] # one fetcher's config/secrets/target fields
paramify manifests [--json]         # discovered run manifests (manifests/*.yaml)
```

### Validate / run

```bash
paramify validate <manifest.yaml> [--json]   # validate without running
paramify run <manifest.yaml> [--json]        # run the manifest
paramify runs [--json]                       # past runs under an output dir (newest first)
paramify evidence <file> [--json]            # read one evidence file (normalizing the envelope)
paramify upload [run-dir] [--json]           # push one run's evidence to Paramify (default: latest run)
paramify issues upload [run-dir] [--json]    # push one run's issue reports to assessment intake
```

`--json` is available on every command and emits machine-readable output for
the AI CLI; without it you get the human-readable rendering. Mutating commands
return `{ok, path, errors}` under `--json` so a caller can confirm the write
landed and surface any validation messages.

### Targets from a Paramify workspace

For fetchers whose target is a Paramify program, the targets can be filled in
from the workspace instead of by hand — the API needs project UUIDs, which nobody
wants to copy:

```bash
paramify programs list                                   # readable name + UUID
paramify programs target                                 # pick interactively, write targets
paramify programs target --all \                         # every program
    --cert-uri https://… --report-from 2026-01-01        # non-interactive / --json
```

With no fetcher argument it targets every manifest entry whose `target_schema`
declares `project_id`. Programs already targeted are skipped, so re-running tops
the manifest up instead of duplicating entries.

The manifest it writes to is chosen explicitly. Omit `-f/--file` and it offers
the discovered manifests (`manifests/*.yaml`, plus a legacy `./manifest.yaml`) as
a numbered list, each annotated with how many of its entries take a program;
a single candidate is used outright and named in the output. `-f` accepts a path
or a bare name resolved against `manifests/` and the repo root, so `-f azure`
works from any directory. A `-f` naming nothing is an error and writes no file —
it never creates a manifest, which is what `manifest new <name>` is for. Under
`--json`, where there's nothing to prompt, more than one candidate is an error
listing them: pass `-f`.

A target gets only what varies per program: `project_id` and `program_name` (the
readable label — the fetcher uses it for its evidence filename, the uploader for
the artifact title).

Anything the targeted fetchers need that *doesn't* vary per program is written to
`platforms.<category>.config`: `--cert-uri` (the Certification Package Overview
URI) and `--report-from` (the report period start). Each is shown on every
interactive run, with the value in force as the prompt default and a line saying
where it comes from (`platforms.paramify`, an entry's own config, or not set
yet); enter keeps it and leaves the manifest alone, typing over it updates the
category value. Entries that resolve to *different* values are reported as such
and no default is offered, since either one shown as the answer would misreport
the other. Supplying the flag skips the prompt and overwrites an existing value.
`--report-from` is validated as an ISO date before it's written.

Needs `PARAMIFY_API_TOKEN` with read scope; under `--json` nothing prompts, so
pass `--program`/`--all` plus whichever shared values are still missing.

### Assessments for issue-report fetchers

The same problem in a different place: an issue report goes to an assessment
identified by UUID, and the operator knows it by name.

```bash
paramify assessments list                    # readable name + UUID + type
paramify assessments select                  # pick interactively, write into config
paramify assessments select <fetcher> --assessment "Q3 Nessus scan"
```

With no fetcher argument it offers every `kind: issue_report` entry in the
manifest. The picker is filtered to the assessment type the fetcher declares, so a
CSPM report is never offered a vulnerability assessment. It writes
`config.assessment_id` and `config.assessment_name` via the ordinary
`set-config` path, so the result is a manifest you could have typed by hand.

Needs `PARAMIFY_API_TOKEN` with read scope. Under `--json` nothing prompts, so
pass `--assessment`.

The same split applies generally: values that vary per fanout iteration belong in
`targets[]`, and values shared across a category belong under `platforms.<category>.config`
— which the runner merges as *platform defaults ← platform values ← per-fetcher
values*, so a manifest can set **any** field a fetcher declares once at the
platform level, even one declared in the fetcher's own `config_schema`.

### Build / edit a manifest

The `manifest` subcommands read each fetcher's `fetcher.yaml` and write the
manifest file (`-f`/`--file`, default `./manifest.yaml`). As you go they warn
which secrets/config are still missing, so you know when the manifest is
runnable.

```bash
paramify manifest init [--output-dir DIR]            # start a manifest at -f/--file
paramify manifest new <name> [--output-dir DIR]      # create manifests/<name>.yaml
paramify manifest add <fetcher>
paramify manifest remove <fetcher>
paramify manifest set-config <fetcher> key=value
paramify manifest set-secret <fetcher> <secret_name> <ENV_VAR>
paramify manifest add-target <fetcher> k=v ... [--secret name=ENV_VAR ...]
paramify manifest remove-target <fetcher> <index>
paramify manifest set-platform-config <category> key=value
paramify manifest set-passthrough <category> ENV_VAR [ENV_VAR ...]
paramify manifest set-output-dir <dir>
paramify manifest show [--json]
```

`set-secret` and `add-target --secret` take the **ENV VAR NAME**, never the
secret value — the builder writes the `${env:VAR}` reference and the runner
resolves it from its own environment at run time.

### `validate` checks

- Manifest passes its JSON schema
- Every `use:` matches a discovered fetcher
- `targets[]` is supplied only when the fetcher has at least one required target field; a `supports_targets` fetcher whose target fields are all optional may omit `targets[]` (the runner does a single ambient invocation)
- Every declared secret (per fetcher + per target) has a corresponding entry in the manifest
- Every `kind: issue_report` entry has a `config.assessment_id` — reported as an error here rather than refused at run time, because a report collected with nowhere to go is still a report worth having on disk

`validate` does NOT check whether `${env:...}` references resolve at runtime — that's discovered only at `run` time, with a structured error per failing invocation. It also doesn't check that an `assessment_id` still exists in the workspace; a deleted assessment surfaces at intake.

### `run` exit codes

- `0` — every invocation exited 0
- `1` — at least one invocation exited non-zero, OR the runner couldn't set up an invocation (missing secret, etc.)

The full per-invocation record is in `_run_metadata.json` — use that for selective rerun or partial-success accounting.

---

## What the manifest does NOT yet support

- **`depends_on` ordering** — declared in the fetcher schema for future comparator use; runner does not honor it
- **Parallel execution** — runner is serial only
- **Retry policy** — no automatic retries on transient failures
- **Multiple manifests in one invocation** — one manifest per `run` call
- **Conditional / templated values** — no Jinja or expressions; literal YAML only
- **Aggregate mode fanout** — declared in the schema but no fetcher uses it yet, so the runner's iteration logic is `per_target` only
