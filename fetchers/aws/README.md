# AWS

AWS fetchers pull evidence and scan reports from your AWS accounts using the AWS CLI. They are read-only and authenticate with the standard AWS credential chain — no static API token is needed for collection.

## Inspector container vulnerabilities

- [`ecr_image_scanning`](ecr_image_scanning/) reports each repository's scanning configuration and newest image's scan summary, including enhanced continuous and completed manual scans.
- [`inspector_vulnerability_scanning`](inspector_vulnerability_scanning/) reports account enablement and whether active findings exist.
- [`inspector_ecr_findings`](inspector_ecr_findings/README.md) collects detailed active findings, image inventory and coverage as evidence.
- [`inspector_ecr_report`](inspector_ecr_report/README.md) converts the same Inspector APIs to a CSV for a Paramify vulnerability assessment. The existing uploader posts it directly to the intake API. No S3 bucket or KMS key is needed.

## Config inventory prerequisites

[`aws_config_inventory`](config_inventory/fetcher.yaml) reads a Config aggregator
once for its entire scope. It supports commercial AWS and GovCloud; each partition
needs its own credentials and aggregator. See the [inventory manifest and pipeline
setup](../../docs/inventory_fetchers_guide.md).

Before collecting:

1. **Enable and start AWS Config recording in every intended account and region**, including
   regions where you do not normally deploy. Configure the recorder's IAM role and
   delivery channel. Include the resource types you want to inventory, especially
   `AWS::EC2::Instance`; the fetcher's `resource_types` option cannot enable recording.
   [AWS recorder setup](https://docs.aws.amazon.com/config/latest/developerguide/manual-setup.title.html).
2. **Choose recording frequency deliberately.** Continuous recording follows resource
   changes; daily recording can lag by a day and is unsuitable when you need frequent
   inventory refreshes. Both still incur aggregation delay.
   [Recording frequency](https://docs.aws.amazon.com/config/latest/developerguide/managing-recorder_console-change-recording-frequency.html).
3. **Configure the aggregator's scope.** An organization aggregator requires the management
   account or a properly registered delegated administrator, plus an aggregation role
   that can read Organizations. For individual-account aggregators, authorize collection
   from each source account/region. Choose `AllAwsRegions: true` on every source to
   include regions outside your deployment list. This enables aggregation, **not recording**.
   [Aggregator setup](https://docs.aws.amazon.com/config/latest/developerguide/aggregated-create.html),
   [source authorization](https://docs.aws.amazon.com/config/latest/developerguide/aggregated-add-authorization.html).
4. **Grant the fetcher read access in the aggregator account:**
   `config:DescribeConfigurationAggregators`,
   `config:DescribeConfigurationAggregatorSourcesStatus`, and
   `config:SelectAggregateResourceConfig`. For cross-account collection, also configure
   the runner's `sts:AssumeRole` permission and the reader role's trust policy.
   The fetcher never changes Config settings.

Check each source account/region with its own credentials:

```bash
aws configservice describe-configuration-recorders --profile source-account --region us-east-1
aws configservice describe-configuration-recorder-status --profile source-account --region us-east-1
```

Confirm the desired types are included and the recorder reports `recording: true`.
Then check the aggregator using the collection profile:

```bash
aws configservice describe-configuration-aggregators --configuration-aggregator-names organization-inventory --profile inventory-reader --region us-east-1
aws configservice describe-configuration-aggregator-sources-status --configuration-aggregator-name organization-inventory --profile inventory-reader --region us-east-1
```

For GovCloud, substitute the GovCloud profile and aggregator region, such as
`us-gov-west-1`. The fetcher requires nonempty source statuses, all `SUCCEEDED`;
`FAILED` or `OUTDATED` blocks upload. Successful status verifies aggregator source
health, not that every recorder is enabled. Compare the configured scope against
your account/region inventory; this fetcher makes no independent EC2 scan.

Global resources have special recording regions. Avoid recording the same global
IAM resources in multiple regions; duplicate asset identifiers cause the fetcher
to withhold the inventory. See [AWS resource recording guidance](https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html).

For ongoing coverage, automate Config onboarding for new accounts and regions and
consider SCPs that prevent unauthorized recording changes. SCPs constrain permissions;
they do not enable Config or start recorders.

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

Actions the fetcher calls: `organizations:DescribeOrganization`, `ListRoots`, `ListPolicies`, `DescribePolicy`, `ListTargetsForPolicy`. With `effective_scp_accounts` set, it also calls `ListParents`, `ListAccounts`, `ListAccountsForParent` and `ListOrganizationalUnitsForParent` (the last three for `all`), and `ListPoliciesForTarget` (only when a policy's targets could not be read). The AWS managed policy `AWSOrganizationsReadOnlyAccess` covers all of them.

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
        "organizations:ListAccounts",
        "organizations:ListAccountsForParent",
        "organizations:ListOrganizationalUnitsForParent"
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
- `effective_scp_accounts: all` walks the organization from the root down: two calls for the root and for each OU, however many accounts it holds. A named account makes one `list-parents` call for each level above it that has not been looked up yet.
- Delegation policies don't accept `NotAction` or `NotResource` (from June 30, 2026). Use the explicit action list above.
- Use an explicit action list and the account as the `Principal`, as the AWS examples do. Being a delegated administrator for another AWS service (`register-delegated-administrator`) is a different mechanism. Use the delegation policy above.

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

72 of the 81 AWS fetchers fan out per (region, profile). 8 are global-scope (the five IAM fetchers, S3 encryption, Route 53 high availability and Organizations SCPs) and fan out by profile only, as does `aws_discovery_beta` below. Run `paramify catalog` to browse the full list.

`aws_discovery_beta` is different: it collects no evidence. It lists what the identity can see in the account (about 75 resource types covering every service these fetchers read, in every enabled region, each with its own read status, plus everything AWS Resource Explorer has indexed) so you can decide which fetchers to run. It fans out by profile only and lists every region itself. See [`docs/discovery.md`](../../docs/discovery.md).

## Notes

- Specify a region in your profile or target even for IAM calls — some IAM APIs are global but the CLI still requires a region to be set.
- For in-cluster deployment with IRSA, the web identity token is automatically passed through via `auth.passthrough_env` in `fetchers/_categories/aws.yaml` — no additional configuration is needed.
- Credential rotation follows your AWS mechanism: re-auth via `aws sso login` for SSO, no action for IRSA/instance roles, or rotate access keys in IAM and update your secrets store for static keys.
