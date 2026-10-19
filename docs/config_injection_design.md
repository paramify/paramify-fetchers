# Config Injection — Design

**Status:** Implemented (v0.x). Worked example: `examples/with_platform_config.yaml`.
**Date:** 2026-05-28
**Solves:** the config-injection gap (fetchers read config env vars that the
runner's minimal-env whitelist would otherwise strip) and the ambient-credentials
gap (cloud auth can't be expressed in the declared-secrets model).

---

## Principle (unchanged)

Keep the existing split:

- **Declaration = code-side**, versioned, customers never edit.
- **Values = customer-side**, live with the run intent (manifest).

Config gets a **platform tier** on *both* sides. We do NOT add customer-editable
config files inside `fetchers/<category>/` — that recreates the `catalog.json`/
`.env` sprawl, breaks per-run variation, and causes fork/merge conflicts.

---

## Two homes (both shipped)

### 1. Platform declaration → `fetchers/_categories/<platform>.yaml`

Code-side. Declares the platform's shared config keys, defaults, env mappings,
and auth model. Ships with the repo.

```yaml
# fetchers/_categories/aws.yaml
# AWS region/profile are per-target (target_schema, see fanout); the category
# carries the ambient-auth passthrough list instead of category config keys.
auth:
  passthrough_env:              # ambient vars the runner lets through its whitelist
    - AWS_WEB_IDENTITY_TOKEN_FILE
    - AWS_ROLE_ARN
```

```yaml
# fetchers/_categories/rippling.yaml
config_schema:
  base_url:  { type: string, default: https://api.rippling.com, env: RIPPLING_BASE_URL }
  page_size: { type: integer, default: 100, env: RIPPLING_PAGE_SIZE }
secrets:
  - { name: api_token, env: RIPPLING_API_TOKEN }
```

### 2. Per-fetcher config keys → `fetcher.yaml` `config_schema`

Same shape; for knobs specific to one fetcher (mirrors `target_schema`):

```yaml
# fetchers/aws/iam_roles/fetcher.yaml
config_schema:
  exclude_aws_managed_roles:
    type: boolean
    default: false
    env: EXCLUDE_AWS_MANAGED_ROLES
```

---

## Customer-side values → manifest `platforms:` block

Fetcher entries inherit by category; per-fetcher `config:` overrides.

```yaml
run:
  output_dir: ./evidence

  platforms:
    rippling:
      config:  { page_size: 200 }
      secrets: { api_token: ${env:RIPPLING_API_TOKEN} }
    aws:
      config:  { region: us-gov-west-1 }
      auth:    { mode: ambient, passthrough_env: [AWS_WEB_IDENTITY_TOKEN_FILE, AWS_ROLE_ARN] }

  fetchers:
    - use: rippling_all_employees           # inherits rippling platform block
    - use: aws_iam_roles
      config: { exclude_aws_managed_roles: true }   # per-fetcher override
```

A shared `platforms:` block can be factored into a customer-side file the
manifest references via `include:` — still customer-side, still one-run-one-intent.

---

## Runner behavior

**Merge order** (later wins):

1. `_categories/<platform>.yaml` defaults
2. manifest `platforms.<category>.config`
3. manifest per-fetcher `config`

Then validate the merged config against the fetcher's + platform's `config_schema`,
and inject each key as its declared `env` var — **reusing the existing
`target_schema.<field>.env` → env mechanism in `executor._build_env`**. This is a
generalization of fanout's per-target env injection, not a new subsystem.

**Auth / passthrough:** `_build_env` reads the platform `auth.passthrough_env`
list and adds those specific vars to `_INHERITED_ENV_VARS` for that invocation.
This keeps the env minimal-by-default while supporting profile, env-key, and
ambient (IRSA / instance-role) auth — secrets stay source-agnostic (`.env`,
cloud secret provider, or ambient cloud identity). The AWS category passthrough
includes the standard cred/region vars (`AWS_PROFILE`, `AWS_DEFAULT_REGION`,
`AWS_REGION`, `AWS_ACCESS_KEY_ID`/`SECRET`/`SESSION_TOKEN`, `AWS_CONFIG_FILE`,
`AWS_SHARED_CREDENTIALS_FILE`) so the **ambient** path (no manifest profile/region
→ the AWS CLI's own chain) works locally and in-cluster; a target's profile/region
still override these (config/passthrough applied first, target fields last).

---

## What this fixes

- `aws_iam_roles` `EXCLUDE_AWS_MANAGED_ROLES`, all-Rippling `RIPPLING_BASE_URL`/
  `RIPPLING_PAGE_SIZE`, KnowBe4 group/campaign names → declared, injected, live.
- AWS/K8s fetchers work under env-key and web-identity/IRSA auth, not just `~/.aws`.
- The contract clause "every env var read must be declared" becomes satisfiable
  for config (today only `secrets` had a home).

## Scope notes

- `config_schema` is an optional field in `fetcher_schema.json`; the shipped
  injection uses its `<field>.env` sub-key plus a platform-level counterpart in
  `_categories/*.yaml`.
- Fetchers keep reading their env vars exactly as they do now; only the runner's
  env-population path changes. No fetcher code changes required.
- The merge + injection lives in `executor._build_env` and runs identically
  whether invoked via the human CLI (`paramify run`), the AI CLI (same with
  `--json`), or the TUI (`paramify tui`) — every front-end calls only
  `framework.api`, so config injection behaves the same.
- The `manifest set-platform-config <category> key=value` and
  `set-passthrough <category> ENV_VAR ...` subcommands of the manifest builder
  edit the `platforms:` block described above.
- Independent of (and already integrated with) the envelope/uploader work.
  A comparator (`depends_on`) gets none of its category's config, secrets or
  passthrough env; see [`comparators.md`](comparators.md#how-the-runner-runs-one).
