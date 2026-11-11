# Inspector ECR findings → Paramify assessment

`aws_inspector_ecr_report` reads the Inspector API and generates a CSV for
Paramify's vulnerability assessment intake. The existing `paramify issues upload`
command posts the CSV directly to `/pipelines/{assessment_id}/intake`, then calls
`/pipelines/{assessment_id}/process` for the returned artifact IDs. Collection
does not need a Paramify credential. Upload uses the existing uploader's token,
permissions, job polling and local retry log.

**No S3 bucket, KMS key or AWS report export is involved.** This is an intentional
API-to-CSV adapter, rather than a byte-for-byte native scanner export. Its intake
preset must match the columns below. The shared collector is also used by
[`aws_inspector_ecr_findings`](../inspector_ecr_findings/README.md), which documents
scope, pagination, timestamps and AWS permissions.

## Set up and run

Copy [examples/aws_inspector.yaml](../../../../examples/aws_inspector.yaml) into
your manifests directory. Set the account profiles/regions and assessment UUID.
Use identical scope settings for evidence and reports. The example selects
`latest` or `deployed` tags only as an example of an operator-defined boundary;
omit the filter to include all images. Confirm it matches your assessment scope.

```bash
paramify validate manifests/aws_inspector.yaml
paramify run manifests/aws_inspector.yaml
# Use the exact run directory printed above for both upload stages.
paramify upload evidence/run-<timestamp> --dry-run
paramify issues upload evidence/run-<timestamp> --dry-run
paramify upload evidence/run-<timestamp>
paramify issues upload evidence/run-<timestamp>
```

Configure a VULNERABILITY assessment and CSV intake preset in Paramify first.
The API key needs Pipelines and Pipeline Jobs permissions. This ships a mapping
specification, not a preinstalled tenant preset. Verify the first import's created
and updated issue counts before using it for production assessment cycles.

## CSV contract (fetcher 0.1.0)

One row represents one finding on one ECR image. Multiple packages stay together
in that row. Multiple findings with the same CVE remain distinct. JSON-valued
cells use normal CSV quoting, including embedded commas/newlines.

String cells beginning with `=`, `+`, `-` or `@` (including after leading spaces,
tabs or line breaks) receive a leading apostrophe to prevent spreadsheet formula
interpretation. This applies to every string column, including advisory titles,
descriptions and remediation text. The intake mapping should treat these as text;
verify how the preset handles the apostrophe. JSON evidence retains the original
values. Normal Inspector finding ARNs and asset identities remain unchanged.

| Column | Intended mapping / meaning |
| --- | --- |
| ID | Stable source record identity: finding ARN plus Asset ID. Use for repeat-import deduplication. |
| Finding ARN | Original Inspector identity for traceability. |
| Vulnerability ID | CVE or vendor advisory ID. Do not use alone to merge distinct affected images. |
| Title, Description | Issue title and description. |
| Severity | Native CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL or UNTRIAGED; configure assessment risk mapping explicitly. |
| Status | ACTIVE; this version does not import suppressed/closed findings. |
| AWS Account ID, Region | Finding scope. |
| Asset ID | Account/region/repository@digest; use as the affected resource identity. |
| Repository, Image Digest, Image Tags | Image attribution; tags are a JSON array. |
| First Observed At, Last Observed At, Updated At | AWS finding timestamps; First Observed At supplies detection date. |
| Fix Available, Exploit Available | AWS's values, without interpreting absent fields as false. |
| Inspector Score, CVSS | Inspector score and JSON array of source/version-specific CVSS scores. |
| Affected Packages | JSON array preserving names, installed/fixed versions, package manager, paths and remediation supplied by AWS. |
| Remediation | Inspector recommendation text when supplied. |
| Reference URLs, Related Vulnerabilities | JSON arrays from package vulnerability details. |

Test the tenant preset's deduplication configuration with a repeated import and
with the same vulnerability on two different image digests. This implementation
does not assert that an existing Inspector preset accepts these columns.

## Completeness and closure

The collector publishes the final CSV atomically only after all reads succeed.
It stages files beside `EVIDENCE_DIR`; use a writable output subdirectory within
the destination filesystem so the final rename stays atomic. Interrupted staging
files never appear in the report directory.
It refuses a report when Inspector ECR is disabled, no selected images exist, or
any selected image lacks ACTIVE coverage with a last scan timestamp. Findings
whose images disappeared or changed scope during collection also block a report;
the evidence lists these under `findings_missing_from_inventory`. Use the evidence
fetcher to diagnose those conditions; narrow the scope only when the
assessment boundary justifies it. Old unscanned images can therefore block an
unfiltered registry report even when newer images have useful findings.

Zero findings also fail by default. `allow_empty: true` permits a header-only
report after all scope and coverage checks pass. It does not override missing
coverage or failed collection. Confirm the tenant's intake handling of an empty
report before using this option.

Keep `close_cycle: never` while validating the integration. Closing a cycle can
resolve issues absent from its inputs; tag movement, suppression, deletion and
scope changes do not by themselves prove remediation. Do not mix incompatible
scopes in one assessment. Only use `after_run` after confirming that every required
account/region target is present and that the cycle represents the complete
assessment. The existing uploader blocks automatic closure for failed targets.

The evidence and CSV use independent API reads, so continuously changing AWS
data may differ between them. Local filenames include account, region and a
hash of profile/scope to prevent distinct targets from overwriting each other.
The uploader preserves the CSV bytes and records successful intake IDs locally
to avoid re-uploading the same run. Preserve the run directory and intake log.
