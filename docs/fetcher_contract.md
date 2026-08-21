# Fetcher Contract

**Status:** v0.x — binding for ported fetchers; some clauses are interim and noted as such.

**See also:** [`design.md`](design.md) for rationale, [`porting_playbook.md`](porting_playbook.md) for the v0.x port procedure, [`framework/schemas/fetcher_schema.json`](../framework/schemas/fetcher_schema.json) for the enforced subset.

This is the interface between the framework's runner and a fetcher. A fetcher's `fetcher.yaml` is validated against the schema at discovery time; its runtime behavior must match the clauses below.

---

## Self-description (`fetcher.yaml`)

Every fetcher ships a `fetcher.yaml` in its directory. The schema is enforced; see [`framework/schemas/fetcher_schema.json`](../framework/schemas/fetcher_schema.json) for the canonical reference.

### Required

| Field | Type | Purpose |
|---|---|---|
| `name` | string | Globally unique identifier (e.g. `okta_phishing_resistant_mfa`) |
| `version` | string | Semver; `0.x.y` while v0.x quirks remain |
| `description` | string | One- or two-sentence summary of what evidence this collects |
| `runtime.type` | enum | `python` or `bash` |
| `runtime.entry` | string | Entry script filename (e.g. `fetcher.py`) |
| `output.type` | enum | `json`, `csv`, `html`, `xml`, or `nessus` |
| `output.path` | string | Output filename relative to `EVIDENCE_DIR` (single-target) or base name (per-target fanout) |
| `secrets[]` | array | Each entry: `{name, env, per_target?}` |

### Optional

| Field | Type | Purpose |
|---|---|---|
| `kind` | enum | `evidence` (default) or `issue_report`. See [Collection kinds](#collection-kinds). |
| `runtime.timeout` | int | Max seconds for one invocation before the runner kills it (default 600). Raise for long scanners. |
| `category` | string | Source-system family (e.g. `okta`, `gitlab`) |
| `config_schema` | object | Typed config the fetcher accepts (free-form for v0.x) |
| `supports_targets` | bool | True when the runner should fan this fetcher out |
| `target_schema` | object | When `supports_targets`: per-target field definitions |
| `output.aggregation` | enum | `per_target` \| `aggregate` (only meaningful with fanout) |
| `secrets[].per_target` | bool | Secret resolved per-target instead of once per fetcher |
| `target_schema.<field>.env` | string | Env var the runner sets from this field per target |
| `depends_on` | array | Fetcher names this one depends on (not yet honored by the runner) |
| `evidence_set` | object | Paramify evidence-set identity: `{reference_id, name, instructions?}`. Carried into envelope metadata and used by the uploader to get-or-create the set. `kind: evidence` only. |
| `issue_report` | object | Paramify assessment-intake identity: `{assessment_type, title?}`. Required for, and only valid on, `kind: issue_report`. Carries no assessment id — that is per-customer and lives in the manifest. |
| `ksis` | array | FedRAMP KSIs this fetcher's evidence speaks to (1+) — *suggested / related* mappings, not a claim that the fetcher alone satisfies the indicator. Intrinsic to the fetcher; per-customer control mappings stay Paramify-side. |
| `validators` | array | Regex checks over the evidence payload that show the control is being implemented. Each entry: `{id, regex, proves?, failure_modes?}` (`id` + `regex` required); each regex matches the whole payload. |

---

## Collection kinds

`kind` selects which of two contracts a fetcher is signing. Omitting it means
`evidence`, which is what every fetcher in this repo was before the field existed
and what most should stay.

| | `kind: evidence` (default) | `kind: issue_report` |
|---|---|---|
| Produces | a JSON payload asserting a state | the source tool's own report file |
| Writes to | `EVIDENCE_DIR` = `<run>/` | `EVIDENCE_DIR` = `<run>/issue-reports/` |
| Runner wraps output in the envelope | yes | **no** |
| Identity block | `evidence_set` | `issue_report` |
| `output.type` | `json`, `csv`, `html` | `csv`, `json`, `xml`, `nessus` |
| Uploaded by | `paramify upload` | `paramify issues upload` |

Two clauses bind an issue-report fetcher beyond the shared contract below:

1. **The output file must be the source tool's bytes, unmodified.** Paramify's
   assessment intake parses the vendor's own format, so the framework never
   envelopes the file and the fetcher must not parse and rewrite it. This is why
   the envelope guard keys on `kind` rather than the file extension — a JSON scan
   report is still a scan report.
2. **The two identity blocks are mutually exclusive.** Declaring `evidence_set` on
   an issue report (or `issue_report` on an evidence fetcher) is rejected at
   discovery, because the result would be a fetcher neither uploader collects.

Everything else — input env, exit codes, `$FETCHER_STATUS_FILE`, fanout, timeouts
— is identical for both kinds. Full detail:
[`issue_report_fetchers.md`](issue_report_fetchers.md).

---

## Runtime contract

### Input

The runner exec's the fetcher's entry script with a tightly controlled environment. The fetcher receives **resolved values**, not env var names — it doesn't need to know whether the runner read the secret from a `.env` file, AWS Secrets Manager, K8s, Vault, or anywhere else.

- **`EVIDENCE_DIR`** — output directory the fetcher writes to. The runner points this at `<run>/issue-reports/` for a `kind: issue_report` fetcher, so a fetcher always writes a bare filename into `EVIDENCE_DIR` and never builds a subdirectory itself
- **`FETCHER_STATUS_FILE`** — path the fetcher reports its failure reason to (see [Output](#output)). Deliberately outside `EVIDENCE_DIR`, so it is never collected as evidence; it lives in a per-invocation temp dir that goes away with the invocation
- **Declared secrets** — every entry from `secrets[]` resolved and set on the env var named in `secrets[].env`
- **Target fields (fanout only)** — each `target_schema` field with an `env` mapping set to the target's value
- **A minimal inherited env** — `PATH`, `HOME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `USER`, `TZ`, `PYTHONUNBUFFERED=1`

The runner does NOT pass the customer's full environment through. If your fetcher needs an env var, declare it.

### Output

- **One or more files** written to `EVIDENCE_DIR`. For single-target: `<EVIDENCE_DIR>/<output.path>`. For per-target fanout: `<EVIDENCE_DIR>/<derived filename including target identifier>`.
- **Log messages to stderr.** Python: `logging.basicConfig(...)`. Bash: structured `printf '... %s ...' >&2`.
- **Exit code:**
  - `0` = collection succeeded
  - non-zero = collection encountered failures (at least one API call, target, or precondition failed)
  - `124` = reserved: the runner killed the invocation for exceeding its timeout (don't return this yourself)

Detection of "did collection fail" is fetcher-defined — see [`porting_playbook.md`](porting_playbook.md) § "Exit code convention" for the patterns currently in use.

- **Failure reason:** when you exit non-zero, write why to `$FETCHER_STATUS_FILE`:

  ```json
  { "error": "GitLab API read timeout after 30s", "code": "target_unreachable" }
  ```

  `error` is a one-line human-readable reason and is the only required field.
  `code` is an optional machine-readable category — `auth_failed`,
  `not_authorized`, `target_unreachable`, `rate_limited`, `bad_config`,
  `partial_failure`, `internal_error`. Prefer a `code` here over inventing an
  exit code: exit codes are a scarce space shared with the shell and signals.
  Had more than one thing fail, summarize it into `error` yourself; a `failures`
  array is reserved for the per-item ledger but is not read yet.

  The runner masks any injected secret out of what you wrote, then puts it in the
  envelope's `metadata.error` (and `metadata.error_code`) — the only fields
  guaranteed present across every fetcher, and what Paramify surfaces to whoever
  is triaging a failed collection.

  **This is not optional-with-no-consequence.** If you write nothing, the runner
  falls back to the tail of your stderr, which is a heuristic that assumes the
  last thing you logged is why you failed. Log an INFO line on your way out — as
  a "wrote the evidence file" message naturally does — and that success message
  becomes the failure reason an operator reads.

  A malformed, empty, or absent file is never itself an error; the runner falls
  back and the run is unaffected.

- **The runner never reads inside your `payload`.** Recording failure state there
  is fine and often useful as evidence content — a reader of the file should be
  able to see the collection was incomplete — but it is not a signal the
  framework acts on, so your payload can be any shape the source data wants.
  **Exit code is the only failure signal**, and `metadata.status` derives from it
  alone. Consulting your own payload to decide what to return is an
  implementation detail, not a second channel.

### Behavior

- **Idempotent** for the same `config` + `target` + wall-clock moment. Most APIs return current state only, so historical idempotency is not guaranteed for replays.
- **Handle pagination internally.** The framework doesn't paginate for you.
- **Never write outside `EVIDENCE_DIR`.**
- **Never read env vars beyond what's declared.** (v0.x ports violate this — see "Interim clauses" below.)

---

## Fanout

A fetcher declares `supports_targets: true` when it's intended to be invoked once per target by the runner. The fetcher itself stays single-target per process invocation; the runner does the iteration.

| Concept | Where declared |
|---|---|
| Per-target field shape | `target_schema` in `fetcher.yaml` |
| Per-target env var mapping | `target_schema.<field>.env` |
| Per-target secret | `secrets[i].per_target: true` |
| Output mode | `output.aggregation`: `per_target` (one file per target) or `aggregate` (one combined file) |

The runner sets per-target env vars, exec's the entry once per target, and isolates failures — a 403 on one project doesn't abort the others.

Worked example: [`fetchers/gitlab/ci_cd_pipeline_config/fetcher.yaml`](../fetchers/gitlab/ci_cd_pipeline_config/fetcher.yaml).

---

## Schema-level enforcement

Discovery, validation, and runs all go through the `framework.api` facade. One CLI, `paramify`, sits on top of it and steers every front-end — the human CLI (`paramify <cmd>`), the same commands with `--json` for AI callers, and the terminal UI (`paramify tui`) — so behavior is identical across them. (`python -m framework.runner` and `python -m framework.tui` still work and are exactly equivalent to the matching `paramify` subcommands.)

The CLI command surface (`paramify <cmd>`, each accepting `--json`):

```bash
paramify list                       # discovered fetchers (flat); walks fetchers/*/*/fetcher.yaml, validates each
paramify catalog                    # categories -> fetchers -> editable fields
paramify describe <fetcher>         # one fetcher's config/secrets/target fields
paramify manifests                  # discovered run manifests (manifests/*.yaml)
paramify validate <manifest.yaml>   # validates a manifest against the schema + against discovered fetchers
paramify run <manifest.yaml>        # collect: enveloped JSON + _run_metadata.json under the output dir
paramify runs                       # past runs under the output dir (newest first)
paramify evidence <file>            # read one evidence file (or an issue-report sidecar)
paramify upload [run-dir]           # push one run's evidence to Paramify (default: latest run)
paramify issues upload [run-dir]    # push one run's issue reports to assessment intake
paramify programs list              # programs in the Paramify workspace: readable name + project UUID
paramify programs target [fetcher ...]  # select programs by name and write them as fanout targets
paramify assessments list           # assessments in the workspace: readable name + UUID
paramify assessments select [fetcher ...]  # point issue-report fetchers at an assessment
paramify manifest <sub>             # build/edit a manifest file (init/new/add/remove/set-config/set-secret/add-target/remove-target/...)
```

`paramify programs` and `paramify assessments` are the commands that read live
workspace state (`GET /projects` and `GET /assessment`, both needing
`PARAMIFY_API_TOKEN`). They exist for the same reason: the API identifies these by
UUID while operators know them by name. Both compose the ordinary manifest
mutators under the hood (`add_target`, `set_fetcher_config`), so each produces
exactly the manifest a hand-written `manifest add-target` / `manifest set-config`
would.

Every `manifest` subcommand also accepts `--json`, emitting a stable `{ok, path, errors}` object so an agent can build a manifest step by step and read `errors` to see what's still missing.

`list`/`validate` fail with a non-zero exit if any `fetcher.yaml` is schema-invalid. The envelope the runner produces is validated against `envelope_schema.json`, but a fetcher's *runtime* behavior (exit codes, output paths, etc.) is not yet automatically verified — that arrives with integration tests.

---

## Interim clauses (v0.x)

These are accepted violations during the porting period. Each is tracked, scoped, and time-limited:

- **Fetchers may read env directly.** v0.x entry scripts call `load_dotenv()` and use `os.getenv()` / shell env access rather than receiving a typed secrets object. The framework's secret resolver replaces this once it takes over per-fetcher invocation. The runner already sets the right env vars for the child; this clause is about the entry script reading them rather than receiving them as arguments.
- **Fetchers write a raw evidence dict; the runner wraps it.** A fetcher emits its plain payload; the runner wraps each output file in the standard envelope `{schema_version, metadata, payload}` after the invocation. `metadata` carries `fetcher_name`/`version`/`category`/`run_id`/`target`/`collected_at`/`status`/`exit_code`, the fetcher's `evidence_set` when present, and `error`/`error_code` on failed invocations. The per-run `_run_metadata.json` index is not enveloped, and neither is any `kind: issue_report` output — those carry the same facts in a sidecar index instead. Fetchers don't build the envelope themselves in v0.x. See [`envelope_design.md`](envelope_design.md).
- **CLI flags** like Okta's `--skip-check` aren't declarable in the current schema. Treat as interim plumbing; they become `config_schema` entries when the runner is invoking fetchers.
- **Structured exit codes** are not categorized — only `0` vs. non-zero. The failure *category* lives in the `code` field of `$FETCHER_STATUS_FILE` instead, so the exit-code space stays uncarved.

- **`$FETCHER_STATUS_FILE` is only read on a non-zero exit.** A fetcher may write it and still exit 0 (collected fine, one optional call degraded); the runner keeps that report on the invocation but does not surface it, since a successful envelope carrying an `error` would be its own kind of misleading. Giving that case a home — the "succeeded but could not measure X" signal that currently reaches nobody, per the KnowBe4 config-resolution work — is the next step for this channel.
- **`output.path` semantics** for per-target fanout (relative filename vs. base name vs. template) aren't pinned by the schema. v0.x convention: the fetcher derives its own per-target filename from the target identifier.

---

## Reference fetchers

When in doubt, mirror the shape of one of these:

- **Single-target Python:** [`fetchers/okta/phishing_resistant_mfa/`](../fetchers/okta/phishing_resistant_mfa/)
- **Single-target bash:** [`fetchers/okta/authenticators/`](../fetchers/okta/authenticators/)
- **Fanout Python:** [`fetchers/gitlab/ci_cd_pipeline_config/`](../fetchers/gitlab/ci_cd_pipeline_config/)
