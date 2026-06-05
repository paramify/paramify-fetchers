# Paramify Fetchers

Fetchers pull compliance evidence from the tools your organization already runs
— Okta, AWS, GitLab, SentinelOne, KnowBe4, Kubernetes, Rippling — and write it
to disk as JSON. A separate uploader stage pushes that evidence to Paramify.
This repo is the fetchers, the runner that executes them, and the uploader; the
fetchers themselves never talk to Paramify directly.

There are 58 fetchers across 8 categories today. If you're a GRC or security
engineer here to add evidence collection for a new control or a new tool, this
README is for you.

```
  customer tool  ──fetcher──▶  JSON evidence file  ──uploader──▶  Paramify
   (Okta, AWS…)                (on disk, per run)     (separate stage)
```

---

## How it runs

Four pieces, kept deliberately separate:

- **Fetcher** — a small script (`fetcher.py` or `fetcher.sh`) that collects from
  *one* source and writes a JSON file. It reads everything it needs from
  environment variables and writes only to `EVIDENCE_DIR`.
- **`fetcher.yaml`** — the fetcher's self-description: its name, what secrets and
  config it needs, what it outputs, and its `evidence_set` identity. Ships with
  the code, validated against a schema. Customers never edit this.
- **Run manifest** — the customer's intent: which fetchers to run, with what
  config, against what targets. Lives in the customer's environment, not here.
- **Runner** — reads `fetcher.yaml` files and a manifest, resolves secrets and
  config into environment variables, and executes each fetcher.

Everything goes through one facade, `framework.api` — discovery, manifest
editing, validation, and running. One CLI, `paramify`, sits on top of it and
steers every front-end; because they all share that single code path they behave
identically. Install it once from the repo (editable), then:

```bash
pip install -e .                  # installs the `paramify` command
                                  # (use `pip install -e '.[all]'` to add the TUI)

paramify <cmd>                    # human CLI
paramify <cmd> --json             # same commands, machine-readable (for AI/scripts)
paramify tui                      # interactive terminal UI
```

> Back-compat: `python -m framework.runner <cmd>` and `python -m framework.tui`
> still work and are exactly equivalent to the corresponding `paramify`
> subcommands.

The CLI command surface:

```bash
paramify list                  # discovered fetchers (flat)
paramify catalog               # categories → fetchers → editable fields
paramify describe <fetcher>    # one fetcher's config / secrets / target fields
paramify manifests             # discovered run manifests (manifests/*.yaml)
paramify validate <manifest>   # validate a manifest without running
paramify run      <manifest>   # run it
paramify runs                  # past runs under an output dir (newest first)
paramify evidence <file>       # read one evidence file (normalizing the envelope)
paramify manifest <sub>        # build/edit a manifest (see below)
```

Output lands in `<output_dir>/run-<UTC-timestamp>/`, one JSON file per fetcher
(or per target for fan-out), alongside a `_run_metadata.json` run index. The
runner wraps each evidence file in an envelope —
`{schema_version, metadata, payload}` — where `metadata` carries the fetcher
name/version/category, run id, target, `collected_at`, status, exit code, and
the `evidence_set` identity; failed invocations also get a `stderr_tail`. The
`_run_metadata.json` index itself is not enveloped.

### Building a manifest

`paramify manifest <sub>` edits a manifest file in place (`-f/--file`, default
`./manifest.yaml`). It reads each `fetcher.yaml` and warns which secrets and
config are still missing until the manifest is runnable.

```bash
paramify manifest init [--output-dir DIR]            # start a manifest at -f/--file
paramify manifest new <name> [--output-dir DIR]      # create manifests/<name>.yaml
paramify manifest add <fetcher>                      # add a fetcher
paramify manifest remove <fetcher>
paramify manifest set-config <fetcher> key=value
paramify manifest set-secret <fetcher> <secret_name> <ENV_VAR>
paramify manifest add-target <fetcher> k=v ... [--secret name=ENV_VAR ...]
paramify manifest remove-target <fetcher> <index>
paramify manifest set-platform-config <category> key=value
paramify manifest set-passthrough <category> ENV_VAR ...
paramify manifest set-output-dir <dir>
paramify manifest show [--json]
```

Every `manifest` subcommand also accepts `--json`, emitting a stable
`{"ok", "path", "errors"}` object — so an agent can build a manifest step by step
and read `errors` to see what's still missing.

### Collect, then upload

Collection and upload are separate stages on purpose. The runner only collects;
pushing to Paramify is a second step, run against the enveloped run directory:

```bash
paramify run manifest.yaml                           # collect → enveloped JSON in run-<ts>/
python -m uploaders.paramify_evidence <run-dir>      # upload that run (get-or-create evidence
                                                     # set by reference_id, multipart artifacts)
```

The uploader is idempotent within a run, supports `--dry-run` and `--config`,
talks Paramify REST v0 over HTTPS only, and reads
`PARAMIFY_UPLOAD_API_TOKEN` (with optional `PARAMIFY_API_BASE_URL`). Chaining
the two stages is the customer's job, not the runner's; `run_and_upload.sh` at
the repo root is example glue.

---

## Why the design is strict

Every fetcher is forced through one contract, validated by JSON Schema, with a
narrow set of allowed shapes. That rigidity is intentional. The previous
generation of fetchers were freeform scripts, and each one invented its own
conventions for config, secrets, and output — which is exactly why none of them
composed and the central catalog had to be hand-maintained in sync. A few
principles keep that from happening again:

- **One contract, schema-enforced.** A fetcher declares itself in `fetcher.yaml`,
  validated at discovery time. Anything not in the schema is not a thing a
  fetcher can do. This is what lets the runner treat all 58 fetchers identically.
- **Fetchers run on customer infrastructure**, never Paramify's. So a fetcher
  never assumes a Paramify connection, and the framework owns no scheduling.
- **Secrets are source-agnostic.** A fetcher reads `OKTA_API_TOKEN` from the
  environment. It never knows or cares whether that came from a `.env` file,
  AWS Secrets Manager, Vault, or a CI secret block — because every one of those
  already knows how to set an environment variable. We do not write per-provider
  secret integrations, and we don't intend to.
- **Collect facts; interpret elsewhere.** A fetcher gathers evidence. Whether
  that evidence *satisfies* a control is a Paramify-side mapping, not the
  fetcher's job. Keep pass/fail verdicts and compliance thresholds out of
  fetchers.
- **One source per fetcher.** Cross-source comparison (e.g. Okta users vs.
  Rippling employees) is a separate "comparator" that reads prior outputs — same
  contract, different inputs. A fetcher never reads another fetcher's output.

The full contract is in [`docs/fetcher_contract.md`](docs/fetcher_contract.md);
the rationale is in [`docs/design.md`](docs/design.md).

> **Status:** pre-1.0 (v0.x). The runner now wraps every output in the
> `metadata`+`payload` envelope, but fetchers still write raw evidence dicts and
> read env directly rather than receiving a typed secrets object — both are
> tracked interim shortcuts, not the target. Comparators (`depends_on`),
> the `paramify_issues` uploader, and structured exit-code categories (still
> binary `0`/`1`, plus `124` for a runner timeout-kill) are not built yet. See
> `docs/design.md` for what's deferred.

---

## Repository layout

```
framework/                      # shared code (facade, runner, contract, schemas)
  api.py                        # the facade — discovery, manifest edit, validate, run
  schemas/                      # fetcher / manifest / category JSON Schemas
  cli.py                        # the `paramify` CLI — one command, steers every front-end
  runner/                       # executor + manifest loader (+ `python -m framework.runner` shim)
  tui/                          # terminal UI front-end (Textual)
fetchers/
  _categories/<name>.yaml       # platform-wide config + auth for a category
  _template/                    # copy this to start a new fetcher
  <category>/
    _shared/                    # code shared across fetchers in this category
    <short_name>/               # one directory per fetcher
      fetcher.yaml
      fetcher.py | fetcher.sh
      README.md
comparators/                    # cross-source comparators (template only so far)
uploaders/
  paramify_evidence/            # push evidence to Paramify (built)
  paramify_issues/              # stub, not built yet
examples/                       # sample run manifests
manifest.yaml                   # working manifest at repo root
run_and_upload.sh               # example collect→upload glue
docs/                           # contract, design, playbooks, this guide's deep dives
```

Directories starting with `_` are not fetchers — the runner skips them.

---

## Adding a new fetcher

The mechanical, copy-paste version with verify commands is
[`docs/ai_port_recipe.md`](docs/ai_port_recipe.md); the narrative version with
rationale is [`docs/authoring_a_fetcher.md`](docs/authoring_a_fetcher.md). The
short path:

### 1. Pick a category and a short name

The category is the source system (`okta`, `aws`, `gitlab`…). The short name is
the specific evidence (`phishing_resistant_mfa`). The globally-unique fetcher
name is the two joined: `okta_phishing_resistant_mfa`. The **directory** is the
short name only.

```bash
cp -r fetchers/_template fetchers/<category>/<short_name>
```

If the category is new, create `fetchers/_categories/<category>.yaml` (an empty
file is valid) and, if fetchers will share code, a `fetchers/<category>/_shared/`.

### 2. Fill in `fetcher.yaml`

Declare what the fetcher needs. The required fields:

```yaml
name: <category>_<short_name>          # globally unique
version: 0.1.0
description: <one or two sentences — what evidence this collects>
category: <category>

supports_targets: false                # true only for fan-out (see below)

runtime:
  type: python                         # or bash
  entry: fetcher.py                    # or fetcher.sh

output:
  type: json
  path: <category>_<short_name>.json   # filename inside EVIDENCE_DIR

secrets:                               # one entry per SECRET env var read
  - name: api_token
    env: <UPPER_SNAKE_ENV_VAR>
```

**Secrets vs. config.** A `secrets:` entry is a credential. A *non-secret* knob
(a base URL, a page size, a boolean toggle) goes in `config_schema:` instead, so
the runner injects it as an env var:

```yaml
config_schema:
  exclude_aws_managed_roles:
    type: boolean
    default: false
    env: EXCLUDE_AWS_MANAGED_ROLES
    description: When true, skip AWS-managed roles.
```

Every environment variable your fetcher reads must be declared as either a
secret or a config field — otherwise the runner strips it (it passes only a
minimal, declared environment to each fetcher) and your knob silently does
nothing.

Verify the YAML before writing code:

```bash
paramify list   # your fetcher should appear; errors mean fix the yaml
```

### 3. Write the entry script

The contract the script must honor:

- Read `EVIDENCE_DIR` from the environment (default `./evidence`); write **only**
  there. The runner sets the working directory to your fetcher's own folder, so
  a relative or hard-coded write path will pollute the repo — always write under
  `EVIDENCE_DIR`.
- Write the JSON file named in `output.path`.
- Read secrets/config from the env var names you declared.
- Log status to stderr (Python: the `logging` module; bash: `printf … >&2`). No
  `print()` chatter, no progress spam.
- **Exit non-zero if collection failed** — if any API call, target, or
  precondition failed. Returning 0 with empty data hides outages and is the one
  mistake that makes evidence untrustworthy.

The Python skeleton (`fetchers/_template/fetcher.py`) and the bash equivalent in
[`docs/porting_playbook.md`](docs/porting_playbook.md) §5 give you the frame. The
only part you write is the data collection in the middle.

**Detecting failure** has no single recipe; pick what fits:

| Style | Pattern |
|---|---|
| Python, requests in the script | a `failures: list` appended in the `except` block, checked at the end → `return 1` |
| Python, requests in a shared client | expose a `client.api_failures` list; check it in the wrapper |
| Bash | append each failed call to a temp file, `wc -l` it at the end, `exit 1` if non-zero |

(Bash subshells in `… | while read` can't update a parent counter — that's why
the temp-file pattern exists. Wrap **every** external call; a single unguarded
one is how a fetcher exits 0 on a partial failure.)

### 4. Smoke-test the wiring with fake creds

Prove the env-passing path before pointing at a real tenant:

```bash
<YOUR_ENV_VAR>=fake EVIDENCE_DIR=/tmp/verify \
  python fetchers/<category>/<short_name>/fetcher.py
echo "exit: $?"
```

You want a **non-zero exit** with a DNS/connection/401 error — that proves the
env vars arrived and the fetcher reached the network. An exit of 0 with empty
data means your failure detection (step 3) is wrong. For bash, run
`bash -n fetcher.sh && chmod +x fetcher.sh` first.

### 5. Run it through the runner

Add the fetcher to a manifest (see `examples/`), then:

```bash
paramify validate path/to/manifest.yaml
paramify run      path/to/manifest.yaml
```

Confirm the JSON lands in the run directory and the contents look right.

---

## Fan-out: one fetcher, many targets

When a fetcher should run once per target (per AWS region, per GitLab project,
per cluster), set `supports_targets: true` and declare a `target_schema`. The
runner iterates, sets per-target env vars, runs the entry once per target, and
isolates failures so one bad target doesn't sink the rest. Worked example:
[`fetchers/gitlab/ci_cd_pipeline_config/`](fetchers/gitlab/ci_cd_pipeline_config/).

All 30 AWS fetchers fan out. Most are **regional** — their `target_schema` takes
a required `region` and `profile` (a named `~/.aws` profile), runs once per
`(region, profile)` pair, and writes `aws_<short>_<profile>_<region>.json`. Five
are **global** and fan out by profile only (`region` optional, defaults
`us-east-1`, output `aws_<short>_<profile>.json`): `iam_roles`, `iam_policies`,
`iam_users_groups`, `route53_high_availability`, `s3_encryption_status`. A few
are mixed-scope and documented as such. AWS auth is the named profile;
`_categories/aws.yaml` (and `k8s.yaml`) carry `auth.passthrough_env` to let
ambient IRSA / instance-role vars through the env whitelist.

---

## Adding a new platform (category)

Most fetchers in a category share connection settings (a base URL, a region) and
an auth model. Put those once in `fetchers/_categories/<category>.yaml` rather
than repeating them per fetcher:

```yaml
description: Rippling Platform API.

config_schema:                 # injected for every fetcher in this category
  base_url:
    type: string
    default: https://api.rippling.com
    env: RIPPLING_BASE_URL

auth:                          # for cloud-identity auth (e.g. AWS IRSA)
  passthrough_env:
    - AWS_WEB_IDENTITY_TOKEN_FILE
```

Customers override these per run in the manifest's `platforms:` block. The full
model — platform config, per-fetcher config, and how auth (`.env`, secret
managers, or ambient cloud identity) flows — is in
[`docs/config_injection_design.md`](docs/config_injection_design.md).

---

## Where to read next

| Doc | What it covers |
|---|---|
| [`docs/fetcher_contract.md`](docs/fetcher_contract.md) | The binding runner↔fetcher contract |
| [`docs/authoring_a_fetcher.md`](docs/authoring_a_fetcher.md) | Writing a new fetcher from scratch (narrative) |
| [`docs/ai_port_recipe.md`](docs/ai_port_recipe.md) | Strict step-by-step checklist with verify commands |
| [`docs/run_manifest_reference.md`](docs/run_manifest_reference.md) | Manifest format |
| [`docs/config_injection_design.md`](docs/config_injection_design.md) | Platform/config/auth model |
| [`docs/design.md`](docs/design.md) | Why the framework is shaped this way |
| [`docs/handoff.md`](docs/handoff.md) | Current state of the work |
