# Authoring a Fetcher

**Status:** v0.x — this doc covers writing a *new* fetcher from scratch. If you already have a working script you want to port into this repo's contract, see [`porting_playbook.md`](porting_playbook.md) instead.

**See also:** [`design.md`](design.md) for rationale, [`fetcher_contract.md`](fetcher_contract.md) for the contract this fetcher must satisfy, [`framework/schemas/fetcher_schema.json`](../framework/schemas/fetcher_schema.json) for the enforced schema.

---

## When to write new vs. port

- **Port** if you already have a working script that collects this evidence (see [`porting_playbook.md`](porting_playbook.md)).
- **Write new** if you're building an integration from scratch, or if an existing script is fundamentally the wrong shape.

A "new" fetcher follows the same contract as a ported one, but you don't carry forward as-is plumbing — you build to the v0.x pattern from day one.

---

## Scaffolding

1. **Decide a category and short_name.** Category is the source-system family (e.g. `aws`, `gitlab`, `k8s`). Short_name is the specific evidence type (e.g. `iam_roles_inventory`). Both lowercase, underscore-separated. The full fetcher name combines them: `<category>_<short_name>`.

2. **Copy the template:**
   ```bash
   cp -r fetchers/_template fetchers/<category>/<short_name>
   ```
   If the category doesn't exist yet, see "Per-category setup" below.

3. **Fill in the files.** Each placeholder in the template needs real content.

---

## `fetcher.yaml`

Fill in every required field with real values:

```yaml
name: <category>_<short_name>            # globally unique
version: 0.1.0                            # 0.x.y while pre-contract-conformant
description: <one or two sentences describing what evidence this collects>
category: <category>

supports_targets: false   # true only if this fetcher should fan out

runtime:
  type: python                            # or bash
  entry: fetcher.py                       # or fetcher.sh

output:
  type: json                              # json | csv | html
  path: <category>_<short_name>.json      # relative to EVIDENCE_DIR

secrets:
  - name: api_token
    env: <UPPER_SNAKE_ENV_VAR>
```

Add one `secrets[]` entry per env var the fetcher reads at runtime.

### `evidence_set` (required identity block)

Every fetcher carries an `evidence_set` block — the Paramify evidence-set identity (1 fetcher = 1 evidence set). This is fetcher-knowledge (what the evidence is and how it's collected); the runner copies it into the output envelope's `metadata`, and the uploader get-or-creates the evidence set by `reference_id`.

```yaml
evidence_set:
  reference_id: EVD-<CATEGORY>-<SHORT>   # stable idempotency key, e.g. EVD-OKTA-PHISHING-MFA
  name: <Human-readable display name>
  instructions: <optional — what the fetcher runs / how the evidence is produced>
```

`reference_id` and `name` are required; `instructions` is optional. Customers override `reference_id` per compliance program in the uploader config — they never edit this block. Do **not** add `controls`/`solution_capabilities` here; that linkage stays Paramify-side.

### Fanout (when one fetcher should run against N targets)

If the fetcher should be invoked once per target (per AWS region+profile, per GitLab project, per K8s cluster, etc.), the runner expands the manifest's targets and invokes the fetcher once per target, setting each `target_schema.<field>.env` var for that invocation.

**AWS-style fanout** is the most common shape. Every AWS fetcher fans out, but `region` and `profile` are OPTIONAL — omit them (or omit `targets[]` entirely) and the fetcher collects the ambient account/region via the AWS CLI credential chain ("collect where deployed"); set a `region`/`profile` pair per target to override those ambient defaults for multi-account / multi-region assume-role fanout:

```yaml
supports_targets: true

target_schema:
  region:
    type: string
    required: false
    env: AWS_DEFAULT_REGION    # runner sets this env var per target
    description: AWS region to collect from. Optional — omit to use the ambient region from the AWS CLI credential chain.
  profile:
    type: string
    required: false
    env: AWS_PROFILE
    description: AWS named profile (credentials resolved from ~/.aws / SSO). Optional — omit to use the ambient credentials; set per target for multi-account assume-role fanout.

output:
  type: json
  path: aws_<short_name>.json    # base; the fetcher appends a per-target suffix
  aggregation: per_target         # one envelope per target

secrets: []                       # AWS creds come from the named profile, not a declared secret
```

Global AWS fetchers (IAM, S3 encryption, Route 53) ignore `region` and fan out per-profile only; omitting `profile` too falls back to the ambient credentials.

For an API-token-based source like GitLab, the targets carry their own identifiers and a per-target secret:

```yaml
supports_targets: true

target_schema:
  project_id:
    type: string
    required: true
    env: GITLAB_PROJECT_ID
  url:
    type: string
    required: true
    env: GITLAB_URL
  branch:
    type: string
    required: false
    default: main
    env: GITLAB_BRANCH

output:
  type: json
  path: <category>_<short_name>.json
  aggregation: per_target

secrets:
  - name: api_token
    env: GITLAB_API_TOKEN
    per_target: true                    # different token per target
```

See [`fetchers/gitlab/ci_cd_pipeline_config/fetcher.yaml`](../fetchers/gitlab/ci_cd_pipeline_config/fetcher.yaml) and [`fetchers/aws/auto_scaling_high_availability/fetcher.yaml`](../fetchers/aws/auto_scaling_high_availability/fetcher.yaml) for complete worked examples.

### Validate

The CLI's discovery and validation all go through the `framework.api` facade — the same code the `--json` (AI) front-end and the TUI (`paramify tui`) call, so behavior is identical everywhere.

```bash
paramify list             # discovered fetchers, flat; fails if any yaml is schema-invalid
paramify catalog          # categories -> fetchers -> editable fields
paramify describe <category>_<short_name>   # your fetcher's config/secrets/target fields
```

Run `describe` on your new fetcher to confirm the runner parsed its config, secrets, and target fields the way you intended. Add `--json` to any of these for machine-readable output.

---

## `fetcher.py` (Python)

Use the playbook skeleton — see [`porting_playbook.md`](porting_playbook.md) § 5 for the canonical shape. Key requirements:

- **Call `load_dotenv()`** at the start of `main()` — v0.x dev-loop convenience; harmless when no `.env` exists.
- **Read `EVIDENCE_DIR`** from `os.environ`, default to `./evidence`.
- **Read all declared secrets** from `os.environ` by the env var names you declared in `fetcher.yaml`.
- **For fanout fetchers**, read each `target_schema.<field>.env` from `os.environ` — the runner sets them per target.
- **Write output** to `<EVIDENCE_DIR>/<output.path>`. For fanout, derive a per-target filename including a sanitized target identifier.
- **One `logger.info("Evidence saved to %s", path)`** on success — that's the entire success log line.
- **Return `0`** on success, **`1`** if collection encountered failures. `sys.exit(main())` to propagate.

### Detecting collection failures

You decide how to detect "did this run actually succeed." See [`porting_playbook.md`](porting_playbook.md) § "Exit code convention" for the three patterns in use today. For a fresh fetcher, the simplest pattern is:

```python
failures: list[dict] = []

def call_api(...):
    try:
        return requests.get(...)
    except requests.exceptions.RequestException as e:
        failures.append({"endpoint": ..., "type": type(e).__name__, "message": str(e)})
        return None

# ... collect ...

if failures:
    logger.error("Encountered %d API failures during collection", len(failures))
    return 1
return 0
```

Catch transient errors at the API-call boundary, track them, exit non-zero if non-empty.

---

## `fetcher.sh` (Bash)

Same shape as Python; see the bash skeleton in [`porting_playbook.md`](porting_playbook.md) § 5. Key differences:

- **`set -o pipefail`** so curl failures propagate through `curl | jq` pipelines.
- **`chmod +x fetcher.sh`** so the runner can exec it.
- **Bash subshells** (`| while read; do ...`) can't mutate parent counters. Track failures in a temp file — see [`fetchers/okta/authenticators/fetcher.sh`](../fetchers/okta/authenticators/fetcher.sh) for the pattern.
- **Required runtime deps** (`curl`, `jq`) should be present on the customer's runner; document any unusual deps in this fetcher's `README.md`.

---

## Per-category setup (first fetcher in a new category)

If you're the first to add a fetcher under a new category:

1. **Create `fetchers/_categories/<category>.yaml`** — even an empty stub is fine; this slot is where category-level access docs / metadata will eventually live.
2. **If multiple fetchers in this category will share code,** create `fetchers/<category>/_shared/` and drop the shared module(s) in there. The runner discovery skips any directory starting with `_`.
3. **If new Python deps,** add them to top-level `requirements.txt`.

The runner discovers new categories automatically — no registration step.

---

## Testing

In v0.x, validation is end-to-end against a real or fake tenant:

1. **Set required env vars.** Use whatever mechanism you prefer (`.env`, `export`, secret manager).
2. **Run the fetcher directly:**
   ```bash
   python fetchers/<category>/<short_name>/fetcher.py
   ```
   Confirm: exit code is 0, output JSON lands in `EVIDENCE_DIR`, contents look right.
3. **Then run through the runner:** add an entry to a manifest, then:
   ```bash
   paramify validate path/to/manifest.yaml
   paramify run      path/to/manifest.yaml
   ```

You can also smoke-test the wiring with fake creds — set env vars to deliberately-invalid values and confirm the fetcher fails *at the network layer* (DNS / connection error) rather than at "missing env var." That proves the env-passing path is intact.

Unit tests aren't yet a convention. The `tests/` directory in the fetcher scaffold is a placeholder until the testing approach is settled.

---

## What you don't need to do

- **Don't build a CLI argument parser** for `--output-dir`, `--profile`, `--region`. Those are runner-era concerns; v0.x fetchers receive everything via env.
- **Don't import from `common/`** or any cross-category helper module. The framework's secret resolver eventually replaces what those used to do.
- **Don't write envelope-wrapped output** (`{schema_version, metadata, payload}`). Write a raw evidence dict as the payload — the runner wraps each output file in the standard envelope automatically after the invocation, populating `metadata` with the fetcher name/version/category/run_id/target/status and your `evidence_set` block (see [`envelope_design.md`](envelope_design.md)).
- **Don't add `controls`, `solution_capabilities`, or `validation_rules`** to your `fetcher.yaml`. These were in the old `catalog.json` and were intentionally cut.
- **Don't add retry logic.** Handle pagination internally; let transient failures bubble up to the failures list and exit code. Retry policy is runner-era.
- **Don't write per-fetcher tests yet.** Until the framework settles on a testing approach, end-to-end smoke against a real tenant is the verification path.

---

## Reference fetchers

When in doubt, mirror the shape of one of these:

- **Single-target Python:** [`fetchers/okta/phishing_resistant_mfa/`](../fetchers/okta/phishing_resistant_mfa/)
- **Single-target bash:** [`fetchers/okta/authenticators/`](../fetchers/okta/authenticators/)
- **Fanout Python (per-target secret):** [`fetchers/gitlab/ci_cd_pipeline_config/`](../fetchers/gitlab/ci_cd_pipeline_config/)
- **AWS region/profile fanout (bash):** [`fetchers/aws/auto_scaling_high_availability/`](../fetchers/aws/auto_scaling_high_availability/)
