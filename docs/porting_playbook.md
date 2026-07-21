# Porting Playbook

**Status:** Active procedure for v0.x ports from `paramify/evidence-fetchers`
**Last updated:** 2026-06-01

> **Internal note:** This is the Paramify team's guide for migrating fetchers from the original `paramify/evidence-fetchers` repository. The pre-flight commands in the first section require access to that private repo. External contributors writing a new fetcher from scratch should start with [`authoring_a_fetcher.md`](authoring_a_fetcher.md) instead — the exit-code conventions, code skeletons, and AWS fanout patterns in this guide are still useful reference for anyone porting any existing script into the new format.

This is the step-by-step procedure for porting an existing fetcher from the old
`paramify/evidence-fetchers` repo into this repo's new layout. The intent is
**port-as-is**: change as little as possible about how each fetcher *behaves*,
while moving it into the new directory structure and contract shape.

The contract is not fully enforced yet. Ports are versioned `0.x.y` and carry
known interim violations (documented at the end of this file). Cleanup happens
later, after the framework's runner and secret resolver land.

For background and rationale, see [`design.md`](design.md).

---

## Pre-flight (before every port)

Run these checks first to ground the port in reality. Stop and resolve any failure before writing code.

```bash
# 1. Confirm the source exists upstream
gh api repos/paramify/evidence-fetchers/contents/fetchers/<category>/<source_filename> > /dev/null \
  && echo "source OK" || echo "MISSING — fix the filename or category"

# 2. Confirm no collision with an existing port
test ! -d "fetchers/<category>/<short_name>" \
  && echo "path OK" || echo "ALREADY EXISTS — pick a different short_name or remove the stale dir"

# 3. Inventory env reads in the source (this is your secrets: list)
gh api repos/paramify/evidence-fetchers/contents/fetchers/<category>/<source_filename> \
  | python3 -c "import json,sys,base64; print(base64.b64decode(json.load(sys.stdin)['content']).decode())" \
  | grep -E 'os\.(environ|getenv)|getenv\('

# 4. Check whether the category needs setup (see Per-category setup below)
ls fetchers/_categories/<category>.yaml 2>/dev/null && echo "category yaml exists" || echo "create _categories/<category>.yaml"
ls fetchers/<category>/_shared/ 2>/dev/null && echo "category has shared code" || echo "no _shared/ (create if porting a shared module)"
```

**Decide before continuing:**

- **`<short_name>`** — source filename minus the `<category>_` prefix and `.py`/`.sh` extension (e.g. `okta_phishing_resistant_mfa.py` → `phishing_resistant_mfa`)
- **Globally-unique name** — `<category>_<short_name>` (this is the `name:` field in `fetcher.yaml`; the directory is the short_name only)
- **Fanout?** — if the source iterates over targets internally (loop over projects, regions, hosts) OR env vars look per-target (`*_PROJECT_ID`, `*_REGION_*`), it's a fanout candidate. All 79 AWS fetchers are fanout; see the AWS fanout section below for the region/profile target shape.

---

## Per-category setup (once per category)

Do this the first time you port a fetcher from a new category (Okta, AWS,
GitLab, etc.):

1. **Identify the category's shared module(s)** in the source repo (e.g.
   `okta_iam_core.py` for Okta).
2. **Copy verbatim** into `fetchers/<category>/_shared/`. Do not refactor —
   even if the module is large and reads env directly. That cleanup is
   explicitly deferred.
3. **Create `fetchers/_categories/<category>.yaml`** if it doesn't exist
   (category-level access docs / metadata).
4. **Add new dependencies** to top-level `requirements.txt` if the category
   needs anything beyond what's already declared.

---

## Per-fetcher steps

For each script you port:

### 1. Read the source

Find `fetchers/<category>/<old_filename>.py` (or `.sh`) in
`paramify/evidence-fetchers`. Note what it does in one sentence.

### 2. Inventory env reads

Grep `os.getenv` and `os.environ` in both the script and any shared module it
imports. Every env var the fetcher actually reads becomes a `secrets:` entry in
`fetcher.yaml` — even though the contract isn't enforced yet.

### 3. Create the directory

```
fetchers/<category>/<short_name>/
```

The directory uses the category-local short name (e.g. `phishing_resistant_mfa`).
The `name` field inside `fetcher.yaml` is the globally unique long form
(e.g. `okta_phishing_resistant_mfa`).

Copy `fetchers/_template/` as the starting point:

```bash
cp -r fetchers/_template fetchers/<category>/<short_name>
```

**Verify:** `ls fetchers/<category>/<short_name>/` shows the template files. The directory name MUST be the short_name — using `<category>_<short_name>/` is a convention violation that breaks the readers' expectations (the runner still finds it via `fetchers/*/*/fetcher.yaml` discovery, but every reference port uses short_name only).

### 4. Fill in `fetcher.yaml`

Required fields (validated against `framework/schemas/fetcher_schema.json`):

- `name` — globally unique, `<category>_<short_name>` convention
- `version` — `0.1.0` for new ports
- `description` — one or two sentences
- `runtime` — `{type: python|bash, entry: fetcher.py|fetcher.sh}`
- `output` — `{type: json|csv|html, path: <filename>.json}` (relative filename inside `EVIDENCE_DIR`)
- `secrets` — list of `{name, env}` pairs covering every env var read

Optional: `category`, `config_schema`, `supports_targets`, `target_schema`, `depends_on`. Plus optional sub-fields used for fanout: `output.aggregation`, `secrets[].per_target`, `target_schema.<field>.env`.

#### `evidence_set` block

Every fetcher now carries an `evidence_set` block tying its output to a Paramify
evidence set so the uploader can get-or-create it by `reference_id`:

```yaml
evidence_set:
  reference_id: <stable id, e.g. KSI-IAM-01>
  name: <human-readable evidence set name>
  instructions: <what reviewers should look for>   # optional
```

Pull `reference_id`/`name`/`instructions` from the upstream catalog when the
source has a catalog entry. If there's no catalog entry, generate a stable
`reference_id` and `name` and leave `instructions` empty (this is what
`aws_rds_tls_configuration`, `okta_authenticators`, and `rippling_devices` do).
The runner copies `evidence_set` into each output's envelope metadata.

**Verify:**

```bash
paramify list
paramify describe <category>_<short_name>
```

Your fetcher should appear in `list` with the right runtime and `[fanout]` or
`[single]` reflecting `supports_targets`; `describe` echoes back its config,
secrets, and target fields. If either errors, fix the yaml before continuing.
Add `--json` to any command for the AI/machine-readable form. One `paramify`
CLI steers every front-end — the same commands with `--json`, plus
`paramify tui` as a subcommand — and they all call the same `framework.api`
facade, so what `describe` reports is exactly what a run sees.
(`python -m framework.runner|tui` still work and equal the matching
`paramify` subcommands.)

### 5. Write the entry script

Use the v0.x port skeleton for the runtime you're targeting. Both runtimes
follow the same shape: load `.env` if present, read `EVIDENCE_DIR` from env,
do the work, write JSON, emit one structured log line on success.

#### Python (`fetcher.py`)

```python
#!/usr/bin/env python3
"""<KSI/control>: <title>"""

import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# If using a category-shared module:
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from <shared_module> import <EntryClass>

logger = logging.getLogger("<category>_<short_name>")


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself. Runner + secret resolver replaces this.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    evidence = <EntryClass>().<collect_method>()

    output_path = output_dir / "<category>_<short_name>.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    logger.info("Evidence saved to %s", output_path)

    # Return non-zero if collection encountered failures. The detection shape
    # varies by category — see "Exit code convention" below.
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

#### Bash (`fetcher.sh`)

```bash
#!/bin/bash
# <KSI/control>: <title>
# <One paragraph: what this fetcher collects.>
#
# Output: $EVIDENCE_DIR/<category>_<short_name>.json
# Required env: <list the env vars this script reads>

# Interim v0.x: fetcher loads .env if present. Runner + secret resolver replaces this.
[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Validate required env vars up front (declared in fetcher.yaml).
if [ -z "${EXAMPLE_TOKEN:-}" ]; then
    echo "ERROR <category>_<short_name>: EXAMPLE_TOKEN is not set" >&2
    exit 1
fi

OUTPUT_JSON="$OUTPUT_DIR/<category>_<short_name>.json"
_FETCHER_TMP_JSON="$(mktemp -t <category>_<short_name>.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON"' EXIT

log_info() {
    printf '%s INFO <category>_<short_name> %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2
}

# Initialize output structure.
echo '{}' > "$OUTPUT_JSON"

# --- Your data collection (curl + jq, etc.) ---
# Use $_FETCHER_TMP_JSON for jq's edit-in-place pattern:
#     jq ... "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "Evidence saved to $OUTPUT_JSON"
```

The bash skeleton above is the happy-path shape. For real fetchers, also track API failures and exit non-zero when any occur — see "Exit code convention" below for the pattern used by `okta_authenticators`.

After creating `fetcher.sh`, mark it executable so the runner can exec it:

```bash
chmod +x fetchers/<category>/<short_name>/fetcher.sh
```

Bash ports depend on `bash`, `curl`, and `jq` being available on the customer's
runner. We don't have a per-fetcher dependency manifest for bash yet; depend on
standard tooling and document any unusual deps in the per-fetcher `README.md`.

### 6. Smoke-test the wiring with fake creds

Before invoking against a real tenant, prove the env-passing path is intact:

```bash
<UPPER_ENV_VAR>=fake-token \
<ANOTHER_ENV_VAR>=https://fake.example \
EVIDENCE_DIR=/tmp/paramify-verify \
.venv/bin/python fetchers/<category>/<short_name>/fetcher.py
echo "exit: $?"
```

**Acceptable outcomes** (proof the wiring is intact):

- Exit **non-zero** with a DNS / connection / 401 error — env vars were read, the fetcher reached the network
- Output JSON file written with whatever it could collect (often empty arrays or `status: error`)

**NOT acceptable** (something is wrong):

- `ModuleNotFoundError` — fix imports
- `Missing required env var` raised at the entry — wrong env var name in `fetcher.yaml` or in the test command
- **Exit 0 with empty data** — your fetcher swallows API failures and reports success. See "Exit code convention" below for how to surface them.

For bash entry scripts: `bash -n fetchers/<category>/<short_name>/fetcher.sh && chmod +x fetchers/<category>/<short_name>/fetcher.sh` first.

### 7. Run end-to-end against a real tenant

Populate the required env vars however your environment populates env vars —
shell `export`, `.env` file, AWS Secrets Manager → env, HashiCorp Vault,
K8s secret env mounts, CI provider secret blocks, etc. The fetcher reads from
`os.environ` and doesn't care about the source. `.env` is the dev-loop
convenience path, not the canonical one.

```bash
# Directly:
.venv/bin/python fetchers/<category>/<short_name>/fetcher.py

# Or build a manifest and run it through the runner:
paramify manifest init
paramify manifest add <category>_<short_name>
paramify manifest set-secret <category>_<short_name> <secret_name> <ENV_VAR>
# (the manifest builder warns which secrets/config are still missing until runnable)
paramify validate manifest.yaml
paramify run manifest.yaml
```

A direct invocation writes the raw evidence dict your fetcher produces. A run
through the runner wraps each output file in an envelope
(`{schema_version, metadata, payload}`) — `metadata` carries
`fetcher_name`/`version`/`category`/`run_id`/`target`/`collected_at`/`status`/
`exit_code` plus your `evidence_set`, and failed invocations get an
`error` (stderr tail). Outputs land in `<output_dir>/run-<UTC-timestamp>/` alongside a
`_run_metadata.json` index (the index itself is not enveloped). Confirm the
JSON lands and both the payload and the envelope metadata look sane.

---

## What to deliberately NOT do

These are traps from the source repo. Bringing them along quietly resurrects
the design we're trying to leave behind.

- **Don't port `common/env_loader.py`** or any `parse_fetcher_args`-style
  machinery. Use inline `load_dotenv()` in each entry script. The duplication
  is ~2 lines per fetcher and gets cleanly removed when the runner lands.
- **Don't bring `--output-dir`, `--profile`, `--region` CLI args** into entry
  scripts. Those are runner-era concerns. Read `EVIDENCE_DIR` from env instead.
- **Don't use `print` for status output.** Use Python's `logging` module so
  the eventual framework can route logs to a structured stream. One
  `logger.info(...)` line on successful write is enough; let exceptions
  propagate (they become non-zero exit + stderr automatically).
- **Don't refactor category shared modules.** `okta_iam_core.py` and its
  equivalents port as-is. Even if they read env directly, even if they're
  170KB. `CLAUDE.md` explicitly defers this.
- **Don't add `controls`, `solution_capabilities`, or `validation_rules`** to
  `fetcher.yaml`. These were in the old `catalog.json` and were intentionally
  cut. See `design.md` § "Two concerns to revisit later".
- **Don't add schema fields the schema doesn't define** (no `envelope_version`,
  no `payload_schema`, no `controls`). The schema is deliberately minimal;
  fields return when their absence causes real friction. (`target_schema` *is*
  in the schema and is required for fanout — see the AWS fanout section.)

---

## Exit code convention

A fetcher must return non-zero from its entry script when data collection
encountered failures. The runner records each invocation's exit code in
`_run_metadata.json` and uses non-zero to mark failures in the per-target
result. **How** to detect "collection failed" depends on the shared module
or data-collection style — there's no one-size-fits-all check:

- **Okta wrappers** check `fetcher.client.api_failures` — a list maintained
  by `OktaAPIClient._request` / `_paginated_get`, populated on connection /
  DNS / timeout failures. Empty = success, non-empty = exit 1.
- **GitLab wrappers** check the `status` field of the result dict —
  `success` and `not_found` are both treated as exit 0 (no `.gitlab-ci.yml`
  is itself meaningful evidence); anything else (especially `error`) is
  exit 1.
- **Bash wrappers (`okta_authenticators`)** record each failed `curl` to a
  temp file (because `… | while read` loops run in subshells and can't
  mutate parent counters); at the end, `wc -l` the file and `exit 1` if
  non-zero.
- **SentinelOne wrappers** track `api_failures` in a list local to the data-
  collection function, surface it in the result dict (so customers see
  failures in the JSON output), and check `result["api_failures"]` in
  `main()`. Same shape as Okta but no shared module — the failures list
  lives in the entry script.

What does NOT yet exist (and is deferred per design.md:73): **structured
exit-code categories** distinguishing auth-failure vs. target-unreachable
vs. partial-success vs. internal. v0.x is binary: 0 = clean, non-zero = at
least one thing went wrong.

Pick the pattern that fits your shared module; if no clear failure signal
exists, that's a hint the shared module needs a minor additive change to
expose one (the Okta `api_failures` list was added this way — additive,
non-breaking).

## Known interim violations

These are tracked, not surprises. Don't try to fix them mid-port:

- **Entry script reads `os.environ` directly** for `EVIDENCE_DIR` and (via the
  shared module) for declared secrets. Replaced by the runner + secret resolver.
- **Shared category modules read env directly.** Cleanup happens once the
  secret resolver exists.
- **CLI flags** like `--skip-check` aren't declarable in the current schema.
  Treat them as undeclared interim plumbing; they become `config_schema`
  entries when the runner is invoking fetchers.
- **`output.path` semantics** (relative filename vs. directory vs. absolute
  path) aren't pinned by the schema. Treat as a relative filename inside
  `EVIDENCE_DIR` for consistency.

---

## AWS fanout shape

All 79 AWS fetchers are fanout, but `profile` and `region` are OPTIONAL
`target_schema` fields on every AWS fetcher. Omit them — or omit `targets[]`
entirely — and the fetcher collects the ambient account/region via the AWS CLI
credential chain ("collect where deployed"); set `profile:`/`region:` per
target for multi-account / multi-region assume-role fanout, where a target's
values override the ambient defaults. There are three flavors:

- **Regional (64 fetchers)** — `target_schema` is `{region optional, profile
  optional}`; the runner invokes the fetcher once per `(region, profile)`
  target and the output filename is `aws_<short>_<profile>_<region>.json`.
- **Global → profile-only fanout (12 fetchers)** — `iam_roles`, `iam_policies`,
  `iam_users_groups`, `iam_mfa_status`, `iam_password_policy`, `organizations_scp`,
  `route53_high_availability`, `s3_encryption_status`, `cloudfront_distribution_security`,
  `shield_dos_protection`, `global_accelerator_ha`, `resource_inventory`.
  `region` is optional (defaults `us-east-1`); fan out on profile only, output
  `aws_<short>_<profile>.json`.
- **Mixed-scope (3 fetchers, flagged not split)** — `backup_validation`,
  `component_ssl_enforcement_status`, `iam_identity_center` have a global half
  that duplicates per region. Documented as-is; do not split them.

Ambient cloud creds (IRSA, instance-role vars) come through
`fetchers/_categories/aws.yaml` (and `k8s.yaml`) via `auth.passthrough_env`,
which lets those vars past the runner's env whitelist.

## Reference ports

When in doubt, mirror the shape of one of these:

| Shape | Reference |
|---|---|
| Single-target Python (uses category `_shared/` module) | [`fetchers/okta/phishing_resistant_mfa/`](../fetchers/okta/phishing_resistant_mfa/) |
| Single-target Python (self-contained, no shared module) | [`fetchers/sentinelone/agents/`](../fetchers/sentinelone/agents/) |
| Single-target bash (curl + jq with failure tracking) | [`fetchers/okta/authenticators/`](../fetchers/okta/authenticators/) |
| Fanout Python (per-target secrets + per-target config fields) | [`fetchers/gitlab/ci_cd_pipeline_config/`](../fetchers/gitlab/ci_cd_pipeline_config/) |
| Fanout AWS (optional region+profile target, ambient creds by default) | [`fetchers/aws/`](../fetchers/aws/) |
