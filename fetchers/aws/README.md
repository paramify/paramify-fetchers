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

## Organizations SCPs (`aws_organizations_scp`)

Reading service control policies needs more than an IAM policy. `ListRoots`, `ListPolicies`, `DescribePolicy`, `ListTargetsForPolicy`, `ListParents`, `ListPoliciesForTarget` and `ListAccounts` can only be called from the organization's **management account** or a **member account that is a delegated administrator** ([API reference](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPolicies.html)). `DescribeOrganization` works from any member account.

So an IAM policy in a plain member account (a shared-services account, say) is not enough on its own: the fetcher reads the organization, then gets AccessDenied on every SCP call. It records that as `PolicyRead.Status: "denied"` with `Roots` and `ServiceControlPolicies` set to `null`, not as an organization with no SCPs, and exits non-zero (`not_authorized`).

Actions the fetcher calls: `organizations:DescribeOrganization`, `ListRoots`, `ListPolicies`, `DescribePolicy`, `ListTargetsForPolicy`. With `effective_scp_accounts` set, it also calls `ListParents`, `ListAccounts` (for `all`) and `ListPoliciesForTarget` (only when a per-policy read failed). The AWS managed policy `AWSOrganizationsReadOnlyAccess` covers all of them.

Run it from the management account, or from another account in one of two ways.

**A. Delegate read-only access to the runner's account.** In the management account, attach a resource-based delegation policy ([how](https://docs.aws.amazon.com/organizations/latest/userguide/orgs-policy-delegate.html), [examples](https://docs.aws.amazon.com/organizations/latest/userguide/security_iam_resource-based-policy-examples.html)). `111122223333` is the runner's account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ParamifyReadScps",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
      "Action": [
        "organizations:DescribeOrganization",
        "organizations:DescribePolicy",
        "organizations:ListRoots",
        "organizations:ListParents",
        "organizations:ListPolicies",
        "organizations:ListPoliciesForTarget",
        "organizations:ListTargetsForPolicy",
        "organizations:ListAccounts"
      ],
      "Resource": "*"
    }
  ]
}
```

```bash
# In the management account
aws organizations put-resource-policy --content file://delegation.json
```

The runner's role also needs the same actions in its own identity policy (or `AWSOrganizationsReadOnlyAccess`). AWS states this outright: without IAM permissions in the delegated account, the caller is treated as not having them.

**B. Assume a read-only role in the management account.** Create a role in the management account that the runner's role may assume, with `AWSOrganizationsReadOnlyAccess`. Then point a target `profile` at it:

```ini
# credential_source: or Environment / EcsContainer, or use source_profile = <runner profile>
[profile org-management]
role_arn = arn:aws:iam::<management-account-id>:role/ParamifyOrganizationsReadOnly
credential_source = Ec2InstanceMetadata
```

```bash
paramify manifest add-target aws_organizations_scp profile=org-management
```

Notes:

- SCPs don't affect users or roles in the management account. They apply to every member account, including the root user and accounts that are delegated administrators ([SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)). In `EffectiveScps`, the management account's entry has `IsManagementAccount: true`.
- `DescribeEffectivePolicy` does not support SCPs, so `EffectiveScps` is built by walking from each account up to the root and collecting the SCPs attached at every level.
- `effective_scp_accounts: all` makes one `list-parents` call per account, one at a time. In a very large organization this can run past the runner's default 600s timeout. If it does, list the accounts you need instead.
- Delegation policies don't accept `NotAction` or `NotResource` (from June 30, 2026). Use the explicit action list above.
- Not verified against AWS docs: whether wildcard actions (`organizations:List*`) work in a delegation policy, and whether a role ARN works as the `Principal`. The AWS examples use explicit actions and the account. Being a delegated administrator for some *other* AWS service (`register-delegated-administrator`) is a separate mechanism, and we have not confirmed that it allows these reads. Use the delegation policy.

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
