# Handoff — current state of work

**Last updated:** 2026-05-28

This doc captures where the port work is at right now so the next session can pick up without re-reading prior chat history.

For project overview see [`design.md`](design.md). For porting procedure see [`porting_playbook.md`](porting_playbook.md). For the strict imperative recipe AI agents should follow see [`ai_port_recipe.md`](ai_port_recipe.md).

---

## What's built

**Framework** (`framework/`):
- **`framework/api.py` is THE FACADE.** All discovery (catalog/describe), manifest editing, validate, and run go through it. One `paramify` CLI steers every front-end — all call *only* `framework.api`, so behavior is identical across all three:
  - **human CLI:** `paramify`
  - **AI CLI:** the same commands with `--json`
  - **terminal UI:** `paramify tui`
  - (`python -m framework.runner|tui` still work and equal the matching `paramify` subcommands.)
- CLI command surface (`paramify <cmd>`):
  - `list [--json]` — discovered fetchers (flat)
  - `catalog [--json]` — categories → fetchers → editable fields
  - `describe <fetcher> [--json]` — one fetcher's config/secrets/target fields
  - `validate <manifest> [--json]`
  - `run <manifest> [--json]`
  - `manifest <sub>` — create/edit a manifest file (`-f`/`--file`, default `./manifest.yaml`): `init [--output-dir DIR]` | `add <fetcher>` | `remove <fetcher>` | `set-config <fetcher> key=value` | `set-secret <fetcher> <secret_name> <ENV_VAR>` | `add-target <fetcher> k=v ... [--secret name=ENV_VAR ...]` | `set-platform-config <category> key=value` | `set-passthrough <category> ENV_VAR ...` | `set-output-dir <dir>` | `show [--json]`. The builder reads each `fetcher.yaml` and warns which secrets/config are still missing until the fetcher is runnable.
- Schemas: `fetcher_schema.json` (supports fanout: `supports_targets`, `target_schema`, `per_target`, `output.aggregation`) + `run_manifest_schema.json`
- `contract.py`, `config_loader.py`, `secret_resolver.py` (handles `${env:VAR_NAME}` references)
- Executor: `subprocess.Popen` + threads with live stdout streaming (feeds the TUI run console), per-invocation timeout, minimal env whitelist plus injected config/secrets/passthrough.
- Per-target fanout works end-to-end. `depends_on` declared in schema but not yet honored by runner (`framework/runner/dependency_graph.py`, `logger.py`, `retry.py` are still empty stubs).
- **Config injection (landed 2026-05-28)** — runner injects non-secret config as env vars from `config_schema` (per-fetcher, in `fetcher.yaml`) and platform-wide config + auth from `fetchers/_categories/<category>.yaml`, merged with a manifest `platforms:` block. Also `auth.passthrough_env` lets ambient cloud-identity vars (e.g. IRSA) through the env whitelist. See `docs/config_injection_design.md`; example `examples/with_platform_config.yaml`. Fixed the previously-dead `EXCLUDE_AWS_MANAGED_ROLES` toggle and Rippling `RIPPLING_BASE_URL`/`RIPPLING_PAGE_SIZE`. New `category_schema.json` validates the `_categories/*.yaml` files.
- **Per-invocation timeout (landed 2026-05-28)** — runner kills any fetcher exceeding its timeout (default 600s; override via `runtime.timeout` in `fetcher.yaml`) and records `exit_code: 124` instead of hanging the whole run.
- **Failure diagnostics (landed 2026-05-28)** — `_run_metadata.json` now records a bounded `stderr_tail` for each non-zero invocation, so unattended runs are debuggable from the artifact.
- **Evidence envelope (landed 2026-05-28)** — the runner wraps each JSON output file in `{schema_version, metadata, payload}` after the invocation (`framework/envelope.py`, validated by `schemas/envelope_schema.json`). Fetchers still write raw payloads; the runner adds attribution (name, version, category, run_id, target, collected_at, status, exit_code, error tail). Idempotent (won't double-wrap), per-target metadata for fanout, `_run_metadata.json` not wrapped. This is the prerequisite for the uploader. See `docs/envelope_design.md`.
- **Evidence uploader `paramify_evidence` (BUILT)** — `uploaders/paramify_evidence/uploader.py` (+ `uploader.yaml`, README, `examples/upload.yaml`). Reads a run dir of enveloped evidence, applies customer `reference_id` overrides, **get-or-creates** the evidence set by `reference_id` (`GET /evidence?referenceId=`, `POST /evidence`) via Paramify REST v0, and attaches each file as a multipart artifact (`POST /evidence/{id}/artifacts/upload`). Idempotent per run (exact-token `run_id` dedup), `--dry-run`, `--config`, per-file failure isolation, `upload_log.json`, https-only token guard (`PARAMIFY_UPLOAD_API_TOKEN`, optional `PARAMIFY_API_BASE_URL`/`--config base_url`), non-zero exit on real errors. Completes the tool→evidence→Paramify chain. Reviewed by a multi-agent adversarial workflow (9 findings, all fixed; mock-tested). Not yet run against a live Paramify tenant. Open: confirm Paramify ingestion accepts the enveloped file vs bare payload (toggle: `artifact_payload`).
- **Issues uploader `paramify_issues` — EMPTY STUB (NOT built)** — `uploaders/paramify_issues/` has zero-byte `uploader.py`/`uploader.yaml`. This is the assessment-intake variant that Wiz needs; it blocks Wiz.
- **Evidence-set identity in `fetcher.yaml` + envelope (landed 2026-05-28)** — optional `evidence_set` block (`reference_id`, `name`, `instructions`, `description`-fallback) in `fetcher_schema.json` / `contract.py` / `config_loader.py`; the runner carries it into `metadata.evidence_set` so evidence files are self-describing for upload. 1 fetcher = 1 evidence set; customer overrides `reference_id` per program in the (now-built) `paramify_evidence` uploader config. **Backfilled onto all 56 fetchers** (2026-05-28): 53 from the upstream catalog (id/name/instructions), 3 generated for fetchers absent from the catalog (`aws_rds_tls_configuration`→EVD-RDS-TLS-CONFIG, `okta_authenticators`→EVD-OKTA-AUTHENTICATORS, `rippling_devices`→EVD-RIPPLING-DEVICES) — these 3 have **no `instructions` yet** (worth filling). All referenceIds unique. See `docs/uploader_design.md`.

**58 fetchers across 8 categories:**

| Category | Count | Notes |
|---|---|---|
| Okta | 8 | 7 Python KSI wrappers + 1 bash (`authenticators`); shared `_shared/okta_iam_core.py` with `api_failures` list |
| GitLab | 3 | Fanout Python (per-project) |
| SentinelOne | 5 | Single-target Python |
| KnowBe4 | 4 | Bash with temp-file failure tracking |
| K8s | 3 | Bash, uses AWS CLI + kubectl |
| Rippling | 3 | Single-target Python |
| AWS | 30 | All bash; all 30 are fanout (region/profile) — see AWS section below |
| Checkov | 2 | Bash IaC scanners (terraform + kubernetes); self-acquire source via git clone, run the `checkov` CLI |

**Docs landed:** root `README.md` (entry point for engineers adding fetchers), `design.md`, `porting_playbook.md`, `ai_port_recipe.md`, `fetcher_contract.md`, `run_manifest_reference.md`, `authoring_a_fetcher.md`, `config_injection_design.md`, `fetcher_purity_audit.md`, `envelope_design.md` (implemented, runner-wraps approach), `uploader_design.md` (evidence-set identity in fetcher.yaml, get-or-create, control linkage stays manual — `paramify_evidence` now built per this design).

---

## AWS port — COMPLETE (30/30, 2026-05-28)

**All 30 AWS scripts are ported.** The final 15 landed 2026-05-28 via the
pattern below; each passed `bash -n`, structural checks, and a fake-cred smoke
(exit 1 on bad creds, valid JSON written). Naming note: `aws_*`-prefixed upstream
files dropped the prefix for the dir (e.g. `aws_config_monitoring.sh` → dir
`config_monitoring`, name `aws_config_monitoring`); `waf_DoS_rules.sh` → `waf_dos_rules`.
Two carry config knobs now wired through config injection: `iam_roles`
(`EXCLUDE_AWS_MANAGED_ROLES`) and `backup_validation` (`BUCKETS_TO_INCLUDE`).
`config_conformance_packs` carries the `Operational-Best-Practices-for-FedRAMP-Low.yaml`
companion file in its dir (note: the collection script enumerates existing packs;
the file is a deployment template, kept for completeness).

The pattern/quirks below are kept as reference for porting future bash categories.

### AWS-specific quirks already encountered

- **All AWS scripts** source `common/env_loader.sh` (drop), use `$PROFILE`/`$REGION` shell vars set by env_loader (replace with `PROFILE="$AWS_PROFILE"` + `REGION="$AWS_DEFAULT_REGION"` at top), ANSI color codes + verbose echos (drop), and `$_FETCHER_TMP_JSON` set by env_loader (define yourself).
- **`kms_key_rotation` (already ported)** has a Paramify-specific Config rule name hardcoded: `cmk-backing-key-rotation-enabled-conformance-pack-j3wepwlkw`. Won't return data outside that account. Preserved in port; noted in description.
- **`iam_roles` (already ported)** normalized the upstream `IAM_ROLES_FETCHER=--exclude-aws-managed-roles` env-as-CLI-arg into a clean `EXCLUDE_AWS_MANAGED_ROLES=true|false` boolean.
- **`aws_config_conformance_packs` (still to port)** uses `Operational-Best-Practices-for-FedRAMP-Low.yaml` as input. The data file is in the upstream repo alongside the script. Will need to be copied into `fetchers/aws/aws_config_conformance_packs/` and the script updated to find it at a stable path.
- **`backup_validation` (still to port)** is the biggest at 15KB. Worth opening in a fresh session.
- Several scripts have **division-by-zero** bugs in their percentage calculations (RDS, S3, etc.). I guarded against this in the ports — preserve that pattern: `[ $total -gt 0 ] && percentage=$(( ... ))`.

### AWS port pattern (lift-and-customize)

Every AWS fetcher.sh follows this skeleton. The middle (data collection) section is the only per-script variation:

```bash
#!/bin/bash
# <description>
# Output: $EVIDENCE_DIR/aws_<short>.json
# Required env: AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

if [ -z "${AWS_PROFILE:-}" ]; then echo "ERROR aws_<short>: AWS_PROFILE is not set" >&2; exit 1; fi
if [ -z "${AWS_DEFAULT_REGION:-}" ]; then echo "ERROR aws_<short>: AWS_DEFAULT_REGION is not set" >&2; exit 1; fi

PROFILE="$AWS_PROFILE"
REGION="$AWS_DEFAULT_REGION"

OUTPUT_JSON="$OUTPUT_DIR/aws_<short>.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_<short>.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_<short>_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_<short> %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_<short> %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --profile "$PROFILE" --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": []}' \
  > "$OUTPUT_JSON"

# --- per-script data collection here ---
# Wrap every aws CLI call:
#   result=$(aws ... 2>/dev/null)
#   exit_code=$?
#   if [ $exit_code -ne 0 ]; then
#       echo "aws <op> failed (exit=$exit_code)" >> "$_FAILURE_LOG"
#       continue   # or appropriate handling
#   fi

failure_count=$(wc -l < "$_FAILURE_LOG" 2>/dev/null | tr -d ' ')
failure_count=${failure_count:-0}
if [ "$failure_count" -gt 0 ]; then
    log_error "Encountered $failure_count AWS API failures during collection"
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
```

### AWS yaml shape (fanout: per region/profile, landed 2026-05-29)

All 30 AWS fetchers are **fanout** — one `(region, profile)` target per invocation,
own output file (`aws_<short>_<profile>_<region>.json`), isolated failures.
`region`+`profile` are `target_schema` fields (both required), not secrets, so a
manifest supplies `targets:`, not `secrets:`. **Breaking for AWS manifests** —
the old `secrets: {aws_profile, aws_region}` shape no longer validates; use
`targets: [{region, profile}]`. (`profile` is required today; making it optional
for ambient/IRSA-only auth is a deferred follow-up — it needs the per-call
`--profile` to become conditional across the scripts.)

```yaml
name: aws_<short>
version: 0.1.0
description: <one or two sentences>
category: aws

supports_targets: true

runtime:
  type: bash
  entry: fetcher.sh

output:
  type: json
  path: aws_<short>.json
  aggregation: per_target

target_schema:
  region:
    type: string
    required: true
    env: AWS_DEFAULT_REGION
  profile:
    type: string
    required: true
    env: AWS_PROFILE

secrets: []
```

**Global vs regional (audited + reshaped 2026-05-29):** 5 AWS fetchers query
account-GLOBAL services and are now **profile-only fanout** — `target_schema`
has `profile` required + `region` optional, the `.sh` defaults region to
us-east-1, and the output is keyed on profile (`aws_<short>_<profile>.json`), so
no misleading per-region duplication: **aws_iam_roles, aws_iam_policies,
aws_iam_users_groups, aws_route53_high_availability, aws_s3_encryption_status**
(list one target per account, no region). The other 22 are genuinely regional
(region+profile, both required). 3 are
**mixed-scope** (a global half duplicated per region) and would benefit from
splitting global from regional collection — **deferred code work**:
`aws_backup_validation` (S3 half), `aws_component_ssl_enforcement_status` (S3
half), `aws_iam_identity_center` (IAM-providers half). Fixed in this pass:
explicit `--region` added to `eks_high_availability` describe-subnets and
`cloudtrail_configuration` get-trail/get-trail-status (worked via env, now
consistent). Other deferred portability notes: `kms_key_rotation` hardcodes a
Paramify-specific Config-rule name; WAF fetchers don't collect CLOUDFRONT-scope
(global) WebACLs. Guidance lives in `examples/multi_region_aws.yaml`.

The fetcher.sh derives its per-target filename:
`_TARGET_ID=$(printf '%s_%s' "$PROFILE" "$REGION" | tr -c 'A-Za-z0-9._-' '_')`
then `OUTPUT_JSON="$OUTPUT_DIR/aws_<short>_${_TARGET_ID}.json"`. Manifest example:
`examples/multi_region_aws.yaml`.

### Reference ports

When in doubt, copy the shape from one of the already-ported AWS fetchers:

- **Simple list-and-detail:** [`fetchers/aws/efs_high_availability/fetcher.sh`](../fetchers/aws/efs_high_availability/fetcher.sh)
- **With per-item enrichment loop:** [`fetchers/aws/iam_policies/fetcher.sh`](../fetchers/aws/iam_policies/fetcher.sh)
- **With aggregate summary + division-by-zero guard:** [`fetchers/aws/s3_encryption_status/fetcher.sh`](../fetchers/aws/s3_encryption_status/fetcher.sh) or [`fetchers/aws/kms_key_rotation/fetcher.sh`](../fetchers/aws/kms_key_rotation/fetcher.sh)
- **Cluster iteration (kubectl-style):** [`fetchers/aws/eks_least_privilege/fetcher.sh`](../fetchers/aws/eks_least_privilege/fetcher.sh)

### Per-script source pull

```bash
gh api "repos/paramify/evidence-fetchers/contents/fetchers/aws/<source_filename>.sh" \
  | python3 -c "import json,sys,base64; d=json.load(sys.stdin); print(base64.b64decode(d['content']).decode())"
```

For pulling 5 at a time, use the batched pattern from prior sessions (output to `/tmp/aws-batchN.txt`, then `Read` the file).

---

## Remaining work — categories with NO ported fetchers yet

`azure`, `ssllabs`, `wiz` exist **only as `_categories/<name>.yaml` stubs** — there are no fetcher dirs under `fetchers/<cat>/` for any of them (in particular, **no azure fetchers exist in this tree**). The Rippling comparators are also unported. Each is blocked or constrained by framework work, or simply not started:

| Category | Scripts | Blocked on |
|---|---|---|
| **SSLLabs** | 1 Python | `aggregation: aggregate` runner support. Source iterates hosts *internally* — that's the aggregate shape. Two options: add aggregate-mode to the runner, OR restructure source to per-target fanout. |
| **Wiz** | 1 Python | The evidence uploader (`paramify_evidence`) is built; Wiz needs the **`paramify_issues`** uploader — the assessment-intake variant (`POST /assessment/{id}/intake`, multipart CSV + artifact JSON). It's currently an empty stub (`uploaders/paramify_issues/`). Thin second uploader, same auth/pattern as `paramify_evidence`. |
| **Azure** | — | Category-yaml stub only; no source ported yet. |
| **Rippling comparators** | 2 Python (`vs_okta_users`, `vs_knowbe4_training`) | `depends_on` runner execution. Comparators read prior fetcher outputs — the runner doesn't sequence dependencies yet (`comparators/` has only `_template`). |

Three framework pieces would unblock most of these:
1. `aggregation: aggregate` mode in the runner — declared in the schema, no fetcher uses it yet (likely a small `executor.py` change to invoke the fetcher once with all targets as JSON env, instead of N times)
2. The **`paramify_issues`** uploader (the `paramify_evidence` skeleton/pattern already exists to copy from)
3. `depends_on` execution: runner reads each fetcher's `depends_on`, sorts the manifest accordingly, runs deps first, makes prior outputs visible to dependents via shared `EVIDENCE_DIR` (`dependency_graph.py`/`logger.py`/`retry.py` are still empty stubs)

---

## Quick-reference commands

```bash
# All from repo root. Everything below routes through framework.api.
# Add --json to list/catalog/describe/validate/run/manifest show for AI/automation.

# List discovered fetchers (also schema-validates each yaml):
paramify list

# Catalog (categories -> fetchers -> editable fields) and per-fetcher detail:
paramify catalog
paramify describe aws_iam_roles

# Build a manifest with the builder CLI (default ./manifest.yaml; -f to target another file):
paramify manifest init --output-dir ./evidence
paramify manifest add aws_iam_roles
paramify manifest add-target aws_iam_roles profile=prod region=us-east-1
paramify manifest set-passthrough aws AWS_PROFILE AWS_DEFAULT_REGION
paramify manifest show

# Validate / run a manifest:
paramify validate examples/minimal_run.yaml
paramify run examples/minimal_run.yaml

# Terminal UI (interactive Textual app):
paramify tui

# Upload an enveloped run dir to Paramify (separate stage):
.venv/bin/python uploaders/paramify_evidence/uploader.py --dry-run <output_dir>/run-<UTC-timestamp>

# Collect -> upload glue (customer-owned example):
./run_and_upload.sh

# Smoke-test a single fetcher with fake creds (no real tenant needed):
AWS_PROFILE=fake AWS_DEFAULT_REGION=us-east-1 EVIDENCE_DIR=/tmp/paramify-verify \
  fetchers/aws/<short>/fetcher.sh
echo "exit: $?"   # Expect 1 (AWS CLI fails with fake profile)

# Bash syntax check:
bash -n fetchers/aws/<short>/fetcher.sh

# Pull a source file from upstream:
gh api "repos/paramify/evidence-fetchers/contents/fetchers/aws/<file>.sh" \
  | python3 -c "import json,sys,base64; d=json.load(sys.stdin); print(base64.b64decode(d['content']).decode())"
```

---

## Foundation review (2026-05-28)

A full review of the orchestration layer + the 41 fetchers that existed then (the
15 AWS ports added afterward followed the same vetted pattern + passed the smoke
checks, but weren't individually audited). Against the contract:
**Verdict: foundation is sound, not rotten.** The comparator boundary holds
(no fetcher reads another's output or joins sources), output isolation to
`EVIDENCE_DIR` holds, naming/exit-code conventions are consistent.

Two systemic themes were found and **resolved** this session:
- **Config injection gap** — fetchers read config env vars (`EXCLUDE_AWS_MANAGED_ROLES`, Rippling `RIPPLING_BASE_URL`/`PAGE_SIZE`) the runner stripped, silently disabling them. Fixed by config injection (above).
- **Ambient cloud auth** — the runner's minimal env whitelist broke AWS/K8s auth via IRSA/instance-roles/env-keys (18 fetchers implicitly required `~/.aws`). Fixed by `auth.passthrough_env`.

Discrete bugs found and **fixed**:
- `k8s_eks_microservice_segmentation` could exit 0 with hollow evidence when `kubectl get pods` / `aws ec2 describe-instances` failed — the only fetcher that could hide a collection failure. Now records the failure and exits non-zero.
- No subprocess timeout (hung fetcher stalled the run) → per-invocation timeout.
- Failures undiagnosable from `_run_metadata.json` → `stderr_tail` on failure.

Known data-purity smells (flagged, **not** fixed — port-as-is, see `fetcher_purity_audit.md`):
- `okta_authenticators` hardcoded `"status": "PASS"` in the evidence body.
- `gitlab_merge_request_summary` `compliance_summary` block bakes in an 80% threshold + findings/recommendation strings.
- KnowBe4 training fetchers hardcode customer group/campaign names (candidates for `config_schema` now that injection exists).

Still open (deferred by design, not bugs): `paramify_issues` uploader + comparator implementation; `depends_on` execution; `aggregate` fanout mode; tightening `fetcher_schema.json` with `additionalProperties: false` so the "no `controls`/`tags`" rule is enforced rather than just documented. (DONE 2026-05-28: envelope format — runner wraps outputs; `paramify_evidence` uploader built.)

## Decisions (settled 2026-05-28)

- **Secrets stay at the `${env:VAR}` boundary — do NOT build per-provider backends.**
  Every secret manager (AWS Secrets Manager, Vault, Azure Key Vault, K8s, CI) already
  knows how to populate env vars; the runner reads env and stays provider-agnostic.
  Resist adding `${vault:}`/`${azure:}`/`${aws-secret:}` resolvers — each one is an
  edge-case treadmill we'd own forever. If manifest-documented secret sources are ever
  wanted, do it as an optional pre-runner secret-loader step, not in the runner. The
  env-var boundary is the feature that lets us not write provider scripts.
- **AWS fetchers: keep bash for now; do NOT rewrite to boto3 for auth reasons.**
  boto3 and the aws CLI share botocore's credential chain — switching changes nothing
  about auth (the IRSA/ambient fix is `passthrough_env`, done). boto3 *would* help with
  plug-and-play deps (no `aws`/`jq` binaries) and robust failure handling, but a 15-script
  rewrite contradicts port-as-is. If adopting boto3, do it for NEW aws fetchers + the ~15
  unported ones and let bash converge over time.

## Open contract questions (deferred, surfaced by the audit)

These came up in [`fetcher_purity_audit.md`](fetcher_purity_audit.md) and remain unresolved:

- Is `status: "PASS" | "FAIL"` a fetcher concern or a Paramify-side concern? Currently inconsistent (`okta_authenticators` has a hardcoded `"PASS"` that the audit flagged).
- Are compliance thresholds (e.g. 80% MR approval rate in `gitlab_merge_request_summary`) customer-configurable, or Paramify-side?
- Is "analyzer" a distinct framework concept (between fetcher and comparator), or does the comparator pattern absorb it?

Two specific cleanup opportunities flagged in the audit but **not yet acted on** (per port-as-is principle):
1. `okta_authenticators` hardcoded `"status": "PASS"` regardless of checks
2. `gitlab_merge_request_summary` has a `compliance_summary` block with hardcoded 80% threshold + findings/recommendations strings

---

## How to start the next session

58 fetchers across 8 categories are ported; the collect→upload chain is built
(manifest → runner/api run → enveloped JSON → `paramify_evidence` uploader).
What's left is new categories and the framework pieces that gate them (see
"Remaining work" above):

- **`paramify_issues` uploader** — empty stub at `uploaders/paramify_issues/`; unblocks **Wiz**. Copy the `paramify_evidence` pattern.
- **`aggregation: aggregate` mode** in `executor.py` — unblocks **SSLLabs**.
- **`depends_on` execution** — `dependency_graph.py`/`logger.py`/`retry.py` are empty stubs; unblocks the **Rippling comparators** (`comparators/` has only `_template`).
- **Azure** (no source ported) is not framework-blocked, just unstarted.

Pick a framework piece, then the script. All work routes through `framework.api`
(the human CLI, the `--json` AI CLI, and the `paramify tui` all
share it — change behavior there, not in a front-end). For a fresh fetcher/port,
follow [`docs/ai_port_recipe.md`](ai_port_recipe.md) and verify with
`paramify list`, `bash -n`, and a fake-cred smoke (expect exit 1).
The 3 fetchers without `evidence_set.instructions` (`aws_rds_tls_configuration`,
`okta_authenticators`, `rippling_devices`) are also worth filling.

---

## State summary (TL;DR)

- **58 fetchers across 8 categories** (aws 30, okta 8, sentinelone 5, knowbe4 4, gitlab 3, k8s 3, rippling 3, checkov 2). All 30 AWS are fanout (22 regional, 5 global profile-only, 3 mixed-scope).
- **`framework/api.py` is the single facade** behind 3 front-ends, all steered by one `paramify` CLI: human CLI (`paramify`), AI CLI (same + `--json`), and terminal UI (`paramify tui`). A manifest-builder CLI (`manifest <sub>`) reads each `fetcher.yaml` and reports what's still missing.
- **Built:** config injection + `auth.passthrough_env`, envelope wrapping (`{schema_version, metadata, payload}`), `evidence_set` identity backfilled onto all fetchers, the `paramify_evidence` uploader, per-invocation timeout (124 on kill), `stderr_tail` on failure, AWS region/profile fanout. Collect→upload glue example: `run_and_upload.sh`.
- **Not built:** `paramify_issues` uploader (empty stub → blocks Wiz); comparators / `depends_on` / retry / logger (empty stubs); `aggregate` fanout mode (declared, unused). `azure`/`ssllabs`/`wiz` are category-yaml stubs with **no ported fetchers**.
- Exit codes still binary 0/1 (plus 124 = runner timeout-kill).
- Foundation reviewed 2026-05-28: sound. The one exit-code bug (`k8s_eks_microservice_segmentation`) is fixed.
