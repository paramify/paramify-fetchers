# AWS

AWS fetchers pull evidence from your AWS accounts using the AWS CLI. All 79 fetchers are read-only and authenticate with the standard AWS credential chain — no static API token is needed.

## Credential setup

Use a dedicated read-only role or IAM policy for evidence collection rather than admin credentials.

### Required permissions

The minimum permissions depend on which fetchers you run. Use `paramify describe <fetcher>` to see the exact `aws` CLI commands a fetcher issues, then build a least-privilege policy from those.

A read-only managed policy (e.g., `ReadOnlyAccess`) covers the full surface but is broader than necessary. For strict least privilege, scope a custom policy to the services of the fetchers you actually run.

### Option A: Ambient credentials — recommended for in-cluster / single-account

When running inside AWS (EKS with IRSA, ECS with a task role, EC2 with an instance profile), no credential configuration is needed. The fetchers pick up the ambient identity automatically. This is the recommended path for the [containerized deployment](../../deploy/README.md).

Verify:
```bash
aws sts get-caller-identity
```

### Option B: Named profile — recommended for multi-account fanout on a workstation

Configure named profiles in `~/.aws/config`:

```ini
[profile commercial]
sso_session = my-sso
sso_account_id = 111122223333
sso_role_name = ReadOnlyAccess
region = us-east-1

[profile govcloud]
sso_session = my-gov-sso
sso_account_id = 444455556666
sso_role_name = ReadOnlyAccess
region = us-gov-west-1
```

Authenticate, then verify:

```bash
aws sso login --profile commercial
aws sts get-caller-identity --profile commercial
```

## Wiring into a manifest

AWS fetchers declare no secrets — credentials flow through the credential chain, not the manifest.

**Ambient (single account/region) — no target configuration needed:**

```bash
paramify manifest add aws_guard_duty
# No set-secret needed
paramify validate manifest.yaml
paramify run manifest.yaml
```

**Multi-account / multi-region fanout — one target per (profile, region) pair:**

```bash
paramify manifest add aws_guard_duty
paramify manifest add-target aws_guard_duty profile=commercial region=us-east-1
paramify manifest add-target aws_guard_duty profile=govcloud region=us-gov-west-1
```

Both `profile` and `region` are optional on every AWS target. Omit either to fall back to the ambient value for that invocation.

## Fetchers

All 79 AWS fetchers fan out per (region, profile). 12 are global-scope (IAM, S3 encryption, Route 53, etc.) and fan out by profile only. Run `paramify catalog` to browse the full list.

## Notes

- Specify a region in your profile or target even for IAM calls — some IAM APIs are global but the CLI still requires a region to be set.
- For in-cluster deployment with IRSA, the web identity token is automatically passed through via `auth.passthrough_env` in `fetchers/_categories/aws.yaml` — no additional configuration is needed.
- Credential rotation follows your AWS mechanism: re-auth via `aws sso login` for SSO, no action for IRSA/instance roles, or rotate access keys in IAM and update your secrets store for static keys.
