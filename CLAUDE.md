# Paramify Fetcher Framework

## What this is
A redesign of Paramify's evidence fetcher system. Fetchers pull data from
customer tools (Okta, AWS, GitLab, etc.) and produce JSON evidence files
that get uploaded to Paramify.

## Current state
Pre-1.0. 58 fetchers ported across 8 categories (aws 30, okta 8, sentinelone 5,
knowbe4 4, gitlab 3, k8s 3, rippling 3, checkov 2); the AWS category is complete
and all 30 are region/profile fanout. Every fetcher carries an `evidence_set` block
(reference_id/name/instructions) in its `fetcher.yaml`. v0.x runner built
(`framework/runner/`); manifest format settled (see `examples/minimal_run.yaml`).
Ported fetchers are version 0.x and write raw evidence payloads; the runner
wraps each output file in the standard evidence envelope (`schema_version` +
`metadata` + `payload`, see `docs/envelope_design.md`). The Paramify evidence
uploader is built (`uploaders/paramify_evidence/`). See `docs/handoff.md` for
the current state-of-the-work breakdown and `docs/design.md` for the rationale.

## Key design decisions
- Fetchers run on customer infrastructure, not Paramify infra
- Each fetcher self-describes via a `fetcher.yaml` validated against
  `framework/schemas/fetcher_schema.json`
- Fetchers produce JSON files on disk; an uploader stage (separate)
  pushes to Paramify
- Cross-fetcher comparisons (e.g., Okta vs Rippling) are "comparators"
  that satisfy the same contract but read prior fetcher outputs
- Customers will eventually run fetchers via their own orchestration
  (GitHub Actions, cron, etc.); the framework doesn't own scheduling

## Directory layout
- `framework/` — shared code (runner, schemas, contract)
- `fetchers/<category>/<name>/` — one directory per fetcher
- `fetchers/<category>/_shared/` — code shared across fetchers in a category
- `fetchers/_categories/<name>.yaml` — category metadata + platform-wide
  `config_schema` and `auth.passthrough_env` (validated against
  `framework/schemas/category_schema.json`)
- Directories starting with `_` are not fetchers; runner discovery skips them

## Fetcher schema
Required: name, version, description, runtime, output, secrets.
Optional: category, config_schema, supports_targets, target_schema,
depends_on. Plus optional sub-fields: output.aggregation,
secrets[].per_target, target_schema.<field>.env (for fanout fetchers),
config_schema.<field>.env (runner injects the value as that env var),
runtime.timeout (per-invocation cap in seconds, default 600).
See `framework/schemas/fetcher_schema.json`.

## Config & auth injection
The runner injects non-secret config as env vars from `config_schema`
(per-fetcher) and `_categories/<category>.yaml` (platform-wide), merged with
a manifest `platforms:` block (category defaults ← platform values ← per-fetcher
config). `auth.passthrough_env` lets ambient cloud-identity vars (e.g. IRSA)
through the runner's minimal env whitelist. Every env var a fetcher reads must
be declared as a secret OR a config field, else the runner strips it. See
`docs/config_injection_design.md`.

## Front-ends & API facade
`framework/api.py` is the single facade — discovery, manifest editing,
validate, and run all go through it. One CLI, `paramify` (`framework/cli.py`, a
Typer app installed via `pip install -e .`), steers every front-end and is a
strict superset of what each can do; they call ONLY `framework.api` so behavior
is identical: the human CLI (`paramify`), the AI CLI (same commands with
`--json`), and the terminal UI (`paramify tui`). Back-compat:
`python -m framework.runner|tui` still work and are equivalent to the matching
`paramify` subcommands.

CLI surface (`paramify <cmd>`, all accept `--json`):
- `list` — discovered fetchers (flat)
- `catalog` — categories → fetchers → editable fields
- `describe <fetcher>` — one fetcher's config/secrets/target fields
- `manifests` — discovered run manifests (`manifests/*.yaml` + legacy `manifest.yaml`)
- `validate <manifest>` / `run <manifest>`
- `runs [--output-dir DIR]` — past runs under an output dir (newest first)
- `evidence <file>` — read one evidence file (normalizing the envelope)
- `manifest <sub>` — build/edit a manifest (`-f/--file`, default
  `./manifest.yaml`; every sub emits `{ok,path,errors}` under `--json`):
  `init [--output-dir DIR]`, `new <name>`, `add <fetcher>`,
  `remove <fetcher>`, `set-config <fetcher> key=value`,
  `set-secret <fetcher> <secret> <ENV_VAR>`,
  `add-target <fetcher> k=v ... [--secret name=ENV_VAR ...]`,
  `remove-target <fetcher> <index>`,
  `set-platform-config <category> key=value`,
  `set-passthrough <category> ENV_VAR ...`, `set-output-dir <dir>`, `show`.
  The builder reads each `fetcher.yaml` and warns which secrets/config are
  still missing until the manifest is runnable.

## Conventions
- Fetcher entry point is `fetcher.py` or `fetcher.sh`
- Fetcher name in `fetcher.yaml` is globally unique (e.g.
  `okta_phishing_resistant_mfa`), not category-scoped
- Versions follow semver (0.x.y for pre-contract-conformant ports)
- Secrets are declared in fetcher.yaml; fetchers should NOT read env
  vars directly. v0.x ports do this anyway as an accepted interim
  violation — their entry script calls `load_dotenv()` and reads
  `os.environ` for both secrets and `EVIDENCE_DIR`. The framework's
  runner + secret resolver will replace this pattern.

## What we're NOT doing yet
- Refactoring shared code like okta_iam_core.py (port as-is; one tiny
  additive change for `api_failures` is the exception, not the start of
  a refactor)
- Paramify issues uploader (`uploaders/paramify_issues/` is an empty stub;
  the evidence uploader `uploaders/paramify_evidence/` IS built)
- Comparators (`depends_on` is in the schema but the runner doesn't
  honor it yet — only `comparators/_template` exists; logger.py, retry.py,
  dependency_graph.py are still empty stubs)
- Categories with only a `_categories/<name>.yaml` stub and no ported
  fetchers: azure, ssllabs, wiz
- Aggregate fanout mode (declared in the schema; no fetcher uses it)
- Structured exit code categories (auth-failure vs. target-unreachable
  vs. internal); v0.x is binary 0/1 (plus 124 = runner timeout-kill)

## Active conventions
- v0.x port pattern: see `docs/porting_playbook.md` for the per-fetcher
  steps and the "don't" list
- Exit codes: fetcher returns non-zero on collection failures; how that's
  detected is per-shared-module (Okta uses `OktaAPIClient.api_failures`,
  GitLab uses result `status`, bash tracks via temp file)
- Secrets are source-agnostic — fetchers read `os.environ`; how that env
  gets populated (`.env`, export, AWS Secrets Manager, Vault, K8s, etc.)
  is the customer/runner's choice. `.env` is not privileged.