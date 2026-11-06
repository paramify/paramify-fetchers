# Inspector ECR vulnerability evidence

`aws_inspector_ecr_findings` reads active container-image findings directly from
Inspector2. It writes JSON evidence containing full AWS finding records, ECR
image inventory, Inspector coverage, severity totals and the exact collection
scope. It does not generate an AWS export or contact Paramify.

For vulnerability issue intake, use the companion
[`aws_inspector_ecr_report`](../inspector_ecr_report/README.md). For a lightweight
newest-image summary use `aws_ecr_image_scanning`; `inspector_vulnerability_scanning`
continues to report account scanning enablement.

## Scope and collection

Each invocation selects one account through the standard AWS CLI credentials
and one region through its target or ambient configuration. STS supplies the
account ID, which is also an explicit Inspector filter: delegated administrators
do not accidentally collect all member accounts. Use one target per account and
region. Both commercial and GovCloud partitions use the same APIs; no partition
or account name is hardcoded.

Optional `repositories` and `image_tags` settings are JSON arrays of up to ten
strings. Repository names match exactly; any requested tag matches. An empty
array applies no filter, including untagged images. The fetcher has no built-in
`latest`/`deployed` convention and does not infer ECS deployment from a tag.
Findings are ACTIVE, with every severity included. Suppressed and closed findings
are outside this version's scope. Each finding retains its native AWS fields,
including packages, fixed versions, vulnerability aliases, CVSS and timestamps
when the API supplies them. Dates describe AWS's observation of that finding;
they do not claim durable history across image replacement.

The collector reads every repository, image, coverage and finding page. It rejects
malformed pages, repeated pagination tokens, differing duplicate findings and
out-of-scope finding resources. IAM, throttling and late-page errors fail the
invocation without an output file. AWS CLI standard retries are bounded to four
attempts per request; each CLI request has a 180-second timeout and the runner
allows one hour per target. The collector keeps the selected inventory and
findings in memory. Scope large registries with repository/tag filters.

`collection_complete` means all requested API reads completed. The APIs are live
and do not provide a transactional snapshot. Each artifact records start/end
times. Evidence and report invocations collect independently; their observation
windows can differ.

`coverage_gaps` lists selected images without ACTIVE package coverage and a last
scan timestamp. An expired or excluded image is not a clean image. When ECR
scanning is disabled, the evidence retains inventory and account status and sets
`finding_count` to null. Evidence can document coverage gaps even when the
companion issue-report fetcher refuses an uploadable report.

## Permissions

Read-only calls:

- `sts:GetCallerIdentity`
- `ecr:DescribeRepositories`
- `ecr:DescribeImages`
- `inspector2:BatchGetAccountStatus`
- `inspector2:ListCoverage`
- `inspector2:ListFindings`

No S3, KMS, report-export, scan-start, Jira or Slack permission is needed.
The existing AWS category's `aws` CLI and `jq` installation is sufficient; there
is no additional SDK dependency. Use a role that can read every repository in
the selected account, or collection will fail instead of silently omitting it.

See the [example manifest](../../../../examples/aws_inspector.yaml) and
[AWS authentication guide](../README.md).
