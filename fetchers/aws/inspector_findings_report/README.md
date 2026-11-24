# Inspector findings → Paramify assessment

`aws_inspector_findings_report` reads all active Amazon Inspector findings in one
account and region. It writes them as one CSV for a Paramify vulnerability
assessment. The CSV covers four scan types: EC2 instances, ECR images, Lambda
functions and Lambda code. The existing `paramify issues upload` command sends
the CSV to the assessment's intake API.

Each row names its resource by the ARN that
[`aws_config_inventory`](../config_inventory/fetcher.yaml) writes as
`unique_asset_identifier` for the same resource. Thus Paramify can link each
finding to its Inventory item.

The fetcher builds the CSV from the Inspector API. It is not an Inspector export,
and it needs no S3 bucket, KMS key or Paramify credential. It shares its
collection code (`../_shared/inspector_common.py`) with
[`aws_inspector_ecr_report`](../inspector_ecr_report/README.md). That report
covers ECR images only, with image-level scope settings and coverage checks.

## Link findings to Inventory

In the vulnerability preset, choose these two columns:

- **Inventory mapping: `Resource ARN`.** This is the `asset_id_field` of the
  fetcher's `pipeline:` block, with `id_scheme: aws-arn`.
- **Unique key: `Finding ARN`.** One row is one finding. The finding ARN stays
  the same from run to run.

`paramify preset aws_inspector_findings_report` shows the mapping column and
the inventory fetchers with the same ID scheme.

The `Resource ARN` column has the form that AWS Config records for each resource
type:

| Inspector resource | Resource ARN | Config resource type |
| --- | --- | --- |
| EC2 instance | `arn:<partition>:ec2:<region>:<account>:instance/<instance id>` | `AWS::EC2::Instance` |
| Lambda function, package or code finding | `arn:<partition>:lambda:<region>:<account>:function:<name>` | `AWS::Lambda::Function` |
| ECR image | `arn:<partition>:ecr:<region>:<registry account>:repository/<repository>` | `AWS::ECR::Repository` |

The fetcher makes each ARN as follows:

- **EC2.** Inspector gives the instance ID (`i-…`), not an ARN. The fetcher
  adds the partition, region and account of the finding.
- **Lambda.** Inspector gives the function ARN with a version qualifier, for
  example `…:function:example-fn:$LATEST`. Config records the function without
  a qualifier, so the fetcher removes it. The `Resource ID` column keeps the
  qualifier.
- **ECR.** Config records repositories, not images. Thus the fetcher maps each
  image finding to the ARN of its repository. All the images in one repository
  link to the same Inventory item. The `Image Digest` and `Image Tags` columns
  identify the image.

The partition comes from the finding ARN, so GovCloud findings get
`arn:aws-us-gov:` ARNs. If a resource ID does not have the expected form, the
run fails and writes no report. A wrong link is worse than no report.

A finding links to Inventory only if Config records its resource type in that
account and region. Paramify accepts a finding without an Inventory item.

## Set up and run

```yaml
run:
  output_dir: ./evidence
  fetchers:
    - use: aws_config_inventory
      config:
        aggregator_name: example-aggregator
    - use: aws_inspector_findings_report
      config:
        scan_types: '["EC2", "ECR", "LAMBDA", "LAMBDA_CODE"]'
        assessment_id: 123e4567-e89b-12d3-a456-426614174000
        close_cycle: never
      targets:
        - profile: example-gov
          region: us-gov-west-1
```

```bash
paramify validate manifests/aws_inspector.yaml
paramify run manifests/aws_inspector.yaml
paramify issues upload evidence/run-<timestamp> --dry-run
paramify issues upload evidence/run-<timestamp>
```

Use one target for each account and region. The fetcher reads the account from
STS and gives it to Inspector as a filter. Thus a delegated administrator
collects only its own account, not its member accounts.

Before the first upload, make a VULNERABILITY assessment and a CSV intake preset
that matches the columns below. The API key needs the Pipelines and Pipeline
Jobs permissions. Compare the issue counts of the first import with the row
count of the CSV.

## Scope

| Setting | Effect |
| --- | --- |
| `scan_types` | JSON array of scan types: `EC2`, `ECR`, `LAMBDA`, `LAMBDA_CODE`. Empty (the default) collects each scan type that is enabled. |
| `min_severity` | Only findings at this severity or higher. `UNTRIAGED` findings are always included. Empty applies no filter. |
| `allow_empty` | Permits a header-only report when Inspector returns zero findings. The default is `false`. |

Each scan type is one `ListFindings` query:

| Scan type | Inspector resource type | Finding types |
| --- | --- | --- |
| `EC2` | `AWS_EC2_INSTANCE` | `PACKAGE_VULNERABILITY`, `NETWORK_REACHABILITY` |
| `ECR` | `AWS_ECR_CONTAINER_IMAGE` | `PACKAGE_VULNERABILITY` |
| `LAMBDA` | `AWS_LAMBDA_FUNCTION` | `PACKAGE_VULNERABILITY` |
| `LAMBDA_CODE` | `AWS_LAMBDA_FUNCTION` | `CODE_VULNERABILITY` |

All queries ask for `ACTIVE` findings only. Suppressed and closed findings are
not in the report.

### Scan types that are not enabled

A scan type that is not enabled in Inspector is a real state, not an error.
The fetcher reads the status of each scan type with `BatchGetAccountStatus`
before it lists findings. Only the status `ENABLED` counts. A missing status
counts as `DISABLED`, as in
[`aws_inspector_vulnerability_scanning`](../inspector_vulnerability_scanning/fetcher.yaml).

- With an empty `scan_types`, the fetcher skips each scan type that is not
  enabled and logs its status. If no scan type is enabled, the run fails with
  `bad_config` and writes no report. An empty report would look like a clean
  scan.
- With a list in `scan_types`, each listed scan type must be enabled. If one is
  not enabled, the run fails with `bad_config` before it lists findings. This
  is the same rule that `aws_inspector_ecr_report` uses for ECR.

For a production assessment with `close_cycle: after_run`, list the scan types.
With an empty list, a scan type that changes to `DISABLED` or `SUSPENDED` drops
out of the report, and closing the cycle closes its open issues.

### Not in the report

- Code repository findings (`CODE_REPOSITORY`), AMI findings
  (`MACHINE_IMAGE`) and findings for other clouds. No `aws_config_inventory`
  record has these resources.
- Coverage. A resource that Inspector does not scan has no findings, so it does
  not appear in the report. Use `aws_inspector_vulnerability_scanning` for
  account status, or `aws_inspector_ecr_findings` for ECR image coverage.

## Columns

The CSV has one row for each finding, and each finding has one resource.
Several findings with the same CVE stay as separate rows. An empty cell means
that the column does not apply to the finding type, or that Inspector gave no
value. JSON values use normal CSV quoting.

| Column | Meaning |
| --- | --- |
| Finding ARN | The Inspector finding ARN. The stable row identity: use it as the unique key. |
| Finding Type | `PACKAGE_VULNERABILITY`, `CODE_VULNERABILITY` or `NETWORK_REACHABILITY`. |
| Vulnerability ID | For a package finding, the CVE or vendor advisory ID. For a code finding, the detector ID (or the rule ID if there is no detector ID). Empty for a network reachability finding. |
| Title | The Inspector finding title. |
| Description | The Inspector finding description. |
| Severity | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` or `UNTRIAGED`, as Inspector gives it. Set the risk mapping of the assessment explicitly. |
| Status | Always `ACTIVE` in this version. |
| AWS Account ID | The account of the finding. |
| Region | The region of the finding. |
| Resource Type | `AWS_EC2_INSTANCE`, `AWS_ECR_CONTAINER_IMAGE` or `AWS_LAMBDA_FUNCTION`. |
| Resource ARN | The ARN that `aws_config_inventory` writes for the resource (see [Link findings to Inventory](#link-findings-to-inventory)). Choose it as "inventory mapping" in the vulnerability preset. |
| Resource ID | The resource ID that Inspector gives: an instance ID, a qualified Lambda function ARN, or an ECR image ARN. |
| Resource Name | The `Name` tag of an EC2 instance (empty if the instance has no `Name` tag), the Lambda function name, or the ECR repository name. |
| Image Digest | The digest of the ECR image. ECR findings only. |
| Image Tags | A JSON array of the image tags. ECR findings only. |
| First Observed At | When Inspector first saw the finding (ISO 8601). Use it as the detection date. |
| Last Observed At | When Inspector last saw the finding (ISO 8601). |
| Updated At | When Inspector last changed the finding (ISO 8601). |
| Fix Available | `YES`, `NO` or `PARTIAL`, as Inspector gives it. Empty means that Inspector gave no value, not "no". |
| Exploit Available | `YES` or `NO`, as Inspector gives it. Empty means that Inspector gave no value. |
| Inspector Score | The Inspector score. |
| EPSS Score | The EPSS score. |
| CVSS | A JSON array of the CVSS scores from each source. Package findings only. |
| Affected Packages | A JSON array of the packages, with installed and fixed versions, package manager and file path. Package findings only. |
| Affected Code | A JSON object with the file name, file path, start line and end line, plus the detector name, rule ID and Lambda layer ARN when Inspector gives them. Code findings only. |
| Network Reachability | A JSON object with the open port range, protocol and network path. Network reachability findings only. |
| Remediation | The Inspector recommendation text. |
| Reference URLs | A JSON array of reference URLs. Package and code findings only. |
| Related Vulnerabilities | A JSON array: related vulnerability IDs for a package finding, CWE IDs for a code finding. |

The fetcher adds an apostrophe before each string cell that starts with `=`,
`+`, `-` or `@` (also after leading spaces, tabs or line breaks). This prevents
formula interpretation in a spreadsheet. Normal ARNs and IDs do not change.
Make sure that the intake preset treats these cells as text.

## Completeness and closure

The report is all or nothing. The fetcher reads every page of every query. It
writes the CSV only after all reads succeed. If one of these conditions occurs,
the run exits non-zero, writes no report and gives a failure code:

- A call fails, for example from access, throttling or an expired session.
- A page is malformed, or a pagination token repeats.
- A finding is outside the account, region, status or selected scan types.
- A finding does not have exactly one resource.
- A resource ID does not have the expected form.
- A finding changes between pages.
- Inspector returns zero findings and `allow_empty` is `false`.

The uploader does not send a report for a failed target. Thus a failed run
cannot look like an empty scan.

The fetcher writes the CSV to a staging file beside `EVIDENCE_DIR`, then renames
it into place. `EVIDENCE_DIR` and its parent must be on the same filesystem. A
killed process can leave a `.inspector-*.tmp` file, but the runner does not
collect it.

Keep `close_cycle: never` while you test the preset. Closing a cycle closes the
open issues that the cycle did not see. A suppressed finding, a deleted
resource, a disabled scan type or a narrower scope removes rows, but none of
these proves remediation.

The file name holds the account, the region and a hash of the profile and the
scope. Thus two targets cannot write the same file.

## Permissions

Read-only calls:

- `sts:GetCallerIdentity`
- `inspector2:BatchGetAccountStatus`
- `inspector2:ListFindings`

The fetcher needs `boto3` (in `requirements.txt` and the `aws` extra). Requests
retry up to four times, each request has a 180-second read timeout, and the
runner allows one hour per target. The queries for the scan types run at the same
time, with 100 findings per page.
