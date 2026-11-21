# Inspector ECR vulnerability evidence

`aws_inspector_ecr_findings` reads active container-image findings directly from
Inspector2. It writes JSON evidence containing full AWS finding records, ECR
image inventory, Inspector coverage, severity totals and the exact collection
scope. It does not generate an AWS export or contact Paramify.

For vulnerability issue intake, use the companion
[`aws_inspector_ecr_report`](../inspector_ecr_report/README.md). For a lightweight
newest-image summary use `aws_ecr_image_scanning`. Use this fetcher for per-image
ECR findings and scan coverage; use
[`aws_inspector_vulnerability_scanning`](../inspector_vulnerability_scanning/fetcher.yaml)
for account-level scanning status across EC2, ECR and Lambda, plus whether active
findings exist. Select the evidence appropriate to the claim you are evaluating;
the shared KSI mapping does not make the two outputs interchangeable.

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
Findings are ACTIVE, with every severity included unless `min_severity` is set.

These settings narrow the scope on the Inspector side, so out-of-scope findings
are never downloaded:

| Setting | Inspector filter | Effect |
| --- | --- | --- |
| `in_use_only: true` | `ecrImageInUseCount >= 1` | Images running in ECS or EKS now. |
| `last_in_use_days: N` | `ecrImageLastInUseAt` | Images that ran in ECS or EKS within N days. |
| `pushed_within_days: N` | `ecrImagePushedAt` | Images pushed within N days. Applied to the ECR inventory locally, since coverage has no push-date filter. |
| `min_severity: HIGH` | `severity` | Findings at or above the severity. UNTRIAGED is always kept. |

Settings combine with AND. Usage is known only to Inspector, so with
`in_use_only` or `last_in_use_days` an image is in scope only when Inspector
returns a matching coverage record. An image Inspector has never covered is
then out of scope, not a coverage gap; run once without usage filters to audit
coverage of the whole registry.

Multi-architecture images: ECR lists an OCI image index (or Docker manifest
list) and each per-platform image it points to as separate digests, and tags
usually sit on the index. Inspector scans the per-platform images, never the
index, so index digests are left out of the inventory (counted in
`summary.index_digest_count`) instead of appearing as permanent coverage gaps.

With `image_tags`, an image matches by its own tags or by the tags of an index
that points to it. The per-platform images of a multi-architecture index are
untagged in ECR and in Inspector, so the collector reads each tagged index's
manifest (ECR `BatchGetImage`) to find them, recording the index's matching tags
as `index_tags` on each. Attestation entries and nested indexes are skipped.
Findings for the selected images are then requested by digest, ten digests per
`ListFindings` query, and coverage is matched to them locally, since neither a
tag filter nor coverage would find an untagged image. Suppressed and closed findings
are outside this version's scope. Each finding retains its native AWS fields,
including packages, fixed versions, vulnerability aliases, CVSS and timestamps
when the API supplies them. Fields that describe the vulnerability rather than
the image are stored once per vulnerability ID (see Output). Dates describe AWS's observation of that finding;
they do not claim durable history across image replacement.

The collector reads every repository, image, coverage and finding page. It rejects
malformed pages, repeated pagination tokens, differing duplicate findings and
out-of-scope finding resources. In evidence mode, IAM, throttling and late-page
errors preserve previously validated records and collection continues with
independent operations and repositories. The output sets
`metadata.partial_failure: true`, records each failure's `operation`, `type`,
`message` and status `code` in `metadata.api_failures`, and sets
`collection_complete: false` and `findings_collection_status: incomplete`.
Summary totals are null for incomplete collections, so partial results cannot
look like a complete or clean scan. The invocation exits nonzero. Records that
fail identity/scope validation are excluded. If STS identity cannot be verified, the
output records the failure with a null account/ARN and no dependent AWS calls.
Invalid configuration before collection can still fail without an output file.
Issue-report mode continues to fail without a report on any collection error.
Requests go through boto3 in one process: standard-mode retries are bounded to
four attempts per request, each request has a 180-second read timeout, and the
runner allows one hour per target. Every paged API asks for its largest page
(1,000 repositories or images, 200 coverage records, 100 findings), and up to
eight repositories' images are listed concurrently. The collector keeps the
selected inventory and compact findings in memory. Scope large registries with
the filters above.

Files are staged beside `EVIDENCE_DIR`, then atomically renamed into it. The
output directory and its parent must be writable and on the same filesystem;
when using a mounted volume, select an output subdirectory within that volume.
A killed process can leave a sibling `.inspector-*.tmp` file, but the runner
will not discover it as an output artifact.

## Output

The evidence is compact JSON. `results` contains:

- `scope`: every setting as applied, plus `pushed_after` (the cutoff timestamp) when `pushed_within_days` is set.
- `summary`: finding, severity, vulnerability, image, index-digest and coverage-gap counts, and findings per repository and per vulnerability ID. `repository_image_count` counts every image in the selected repositories (index digests excluded) before tag, push-date and usage filters; `image_count` counts the images that match them.
- `images`: one record per selected image: `imageDigest`, `imageTags`, `imagePushedAt`, `lastRecordedPullTime`, `imageSizeInBytes`, `imageManifestMediaType`, `repository`, `repository_arn`, `resource_id` (the key of its coverage record), and `index_tags` when it was selected through a tagged index.
- `coverage`: Inspector coverage records for the selected images, once each.
- `vulnerabilities`: per vulnerability ID, the fields shared by its findings: `description`, `remediation`, `epss`, `exploitabilityDetails`, `inspectorScoreDetails`, and under `packageVulnerabilityDetails` the `source`, `sourceUrl`, `cvss`, `referenceUrls`, `relatedVulnerabilities` and vendor fields.
- `findings`: each ACTIVE finding without those shared fields. A finding keeps any shared field whose value differs from its vulnerability's, and lists in `absent_fields` any stored field it did not have. Combining a finding with its vulnerability entry (finding values win) gives the original Inspector record; `expand_finding()` in `_shared/inspector_ecr.py` does exactly that.

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
- `ecr:BatchGetImage`, only with `image_tags`, to read the manifests of tagged indexes
- `inspector2:BatchGetAccountStatus`
- `inspector2:ListCoverage`
- `inspector2:ListFindings`

No S3, KMS, report-export, scan-start, Jira or Slack permission is needed.
The collector needs `boto3` (in `requirements.txt` and the `aws` extra); the
other AWS fetchers use the `aws` CLI and `jq`. Use a role that can read every repository in
the selected account, or collection will fail instead of silently omitting it.

See the [example manifest](../../../../examples/aws_inspector.yaml) and
[AWS authentication guide](../README.md).
