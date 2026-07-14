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
| `output.type` | enum | `json`, `csv`, or `html` |
| `output.path` | string | Output filename relative to `EVIDENCE_DIR` (single-target) or base name (per-target fanout) |
| `secrets[]` | array | Each entry: `{name, env, per_target?}` |

### Optional

| Field | Type | Purpose |
|---|---|---|
| `runtime.timeout` | int | Max seconds for one invocation before the runner kills it (default 600). Raise for long scanners. |
| `category` | string | Source-system family (e.g. `okta`, `gitlab`) |
| `config_schema` | object | Typed config the fetcher accepts (free-form for v0.x) |
| `supports_targets` | bool | True when the runner should fan this fetcher out |
| `target_schema` | object | When `supports_targets`: per-target field definitions |
| `output.aggregation` | enum | `per_target` \| `aggregate` (only meaningful with fanout) |
| `secrets[].per_target` | bool | Secret resolved per-target instead of once per fetcher |
| `target_schema.<field>.env` | string | Env var the runner sets from this field per target |
| `depends_on` | array | Fetcher names this one depends on (not yet honored by the runner) |
| `evidence_set` | object | Paramify evidence-set identity: `{reference_id, name, instructions?}`. Carried into envelope metadata and used by the uploader to get-or-create the set. |
| `ksis` | array | FedRAMP 20x KSIs this fetcher's evidence speaks to (1+). Intrinsic to the fetcher; per-customer control mappings stay Paramify-side. |
| _validators_ | — | Not in `fetcher.yaml`. Validators are first-class objects in the central `validators/` registry, each linked to a fetcher by its `evidence_set.reference_id`. See [`validators_design.md`](validators_design.md). |

---

## Runtime contract

### Input

The runner exec's the fetcher's entry script with a tightly controlled environment. The fetcher receives **resolved values**, not env var names — it doesn't need to know whether the runner read the secret from a `.env` file, AWS Secrets Manager, K8s, Vault, or anywhere else.

- **`EVIDENCE_DIR`** — output directory the fetcher writes to
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
paramify evidence <file>            # read one evidence file (normalizing the envelope)
paramify upload [run-dir]           # push one run's evidence to Paramify (default: latest run)
paramify manifest <sub>             # build/edit a manifest file (init/new/add/remove/set-config/set-secret/add-target/remove-target/...)
```

Every `manifest` subcommand also accepts `--json`, emitting a stable `{ok, path, errors}` object so an agent can build a manifest step by step and read `errors` to see what's still missing.

`list`/`validate` fail with a non-zero exit if any `fetcher.yaml` is schema-invalid. The envelope the runner produces is validated against `envelope_schema.json`, but a fetcher's *runtime* behavior (exit codes, output paths, etc.) is not yet automatically verified — that arrives with integration tests.

---

## Interim clauses (v0.x)

These are accepted violations during the porting period. Each is tracked, scoped, and time-limited:

- **Fetchers may read env directly.** v0.x entry scripts call `load_dotenv()` and use `os.getenv()` / shell env access rather than receiving a typed secrets object. The framework's secret resolver replaces this once it takes over per-fetcher invocation. The runner already sets the right env vars for the child; this clause is about the entry script reading them rather than receiving them as arguments.
- **Fetchers write a raw evidence dict; the runner wraps it.** A fetcher emits its plain payload; the runner wraps each output file in the standard envelope `{schema_version, metadata, payload}` after the invocation. `metadata` carries `fetcher_name`/`version`/`category`/`run_id`/`target`/`collected_at`/`status`/`exit_code`, the fetcher's `evidence_set` when present, and an `error` on failed invocations. The per-run `_run_metadata.json` index is not enveloped. Fetchers don't build the envelope themselves in v0.x. See [`envelope_design.md`](envelope_design.md).
- **CLI flags** like Okta's `--skip-check` aren't declarable in the current schema. Treat as interim plumbing; they become `config_schema` entries when the runner is invoking fetchers.
- **Structured exit codes** are not categorized — only `0` vs. non-zero. Future contract work distinguishes auth-failure, target-unreachable, partial-success, internal.
- **`output.path` semantics** for per-target fanout (relative filename vs. base name vs. template) aren't pinned by the schema. v0.x convention: the fetcher derives its own per-target filename from the target identifier.

---

## Reference fetchers

When in doubt, mirror the shape of one of these:

- **Single-target Python:** [`fetchers/okta/phishing_resistant_mfa/`](../fetchers/okta/phishing_resistant_mfa/)
- **Single-target bash:** [`fetchers/okta/authenticators/`](../fetchers/okta/authenticators/)
- **Fanout Python:** [`fetchers/gitlab/ci_cd_pipeline_config/`](../fetchers/gitlab/ci_cd_pipeline_config/)
