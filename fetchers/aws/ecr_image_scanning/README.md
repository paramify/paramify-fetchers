# ECR image scanning summary

Reports registry configuration, effective repository scan frequency and the scan
results for each repository's most recently pushed image. It reads existing
results for BASIC and ENHANCED scanning, including continuous scans and completed
manual scans, regardless of the legacy repository `scan_on_push` flag. It never
starts a scan or changes configuration.

The latest-image summary is not a report of all deployed or stored images. Use
[`aws_inspector_ecr_findings`](../inspector_ecr_findings/README.md) for detailed
active findings and coverage across the selected ECR image inventory, or
[`aws_inspector_ecr_report`](../inspector_ecr_report/README.md) for issue intake.

## Permissions

`sts:GetCallerIdentity`, `ecr:GetRegistryScanningConfiguration`,
`ecr:DescribeRepositories`, `ecr:BatchGetRepositoryScanningConfiguration`,
`ecr:DescribeImages`, and `ecr:DescribeImageScanFindings`.

Version 0.3.0 adds `BatchGetRepositoryScanningConfiguration`. It asks AWS to
resolve repository filters in batches of at most 25, rather than approximating
overlapping rules locally.

## Results

Existing repository keys remain. New keys are `scan_frequency`,
`applied_scan_filters`, and `scan_collection_status`. The scan summary adds low,
informational and untriaged counts, completion time and vulnerability-source
update time. `scan_status` retains the AWS status, including ACTIVE for continuous
scanning.

`latest_image_scan` is null for an empty repository or a failed read; consult
`scan_collection_status` and the runner failure status. A missing scan returns
NOT_SCANNED. `severity_counts` is null for missing, pending, failed or expired
scans, and when AWS supplies no count map. Only a completed or active scan with a
count map fills absent severity entries with zero. Collection failures exit
nonzero while preserving partial evidence; a failed configuration read does not
default the registry to BASIC.
