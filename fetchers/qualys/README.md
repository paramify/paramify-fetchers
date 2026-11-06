# Qualys

Two read-only issue-report fetchers for Paramify assessments:

| Fetcher | Assessment | Collection |
| --- | --- | --- |
| [VMDR vulnerability findings](vmdr_vulnerability_findings/README.md) | VULNERABILITY | Host detections joined to KnowledgeBase and mandatory QVS/CISA enrichment |
| [STIG compliance report](stig_compliance_report/README.md) | CONFIGURATION | Every evaluated posture for each selected STIG policy, including passes, failures, errors, and exceptions |

These fetchers collect existing results. They do not launch scans, change policies,
manage exceptions, or contact Paramify. Uploading uses the existing
[`paramify issues upload` workflow](../../docs/pipelines_guide.md).

## Report contract

Both fetchers assemble CSVs from read-only APIs, following the existing Wiz
assembled-report precedent. This is a deliberate exception to the general
issue-report rule requiring the vendor's original bytes. A native detection
response does not contain the mandatory per-CVE QVS/CISA join, and the STIG report
joins per-instance results with glossary references and policy metadata.

**Configure an intake preset for these CSV columns. Do not select a native Qualys
report preset and assume it maps them.** Column names and record identity rules
are versioned with each fetcher's contract. CSV rows sort by Record ID; an
unchanged source produces unchanged report bytes. CVE Enrichment is JSON inside
a CSV cell and retains the source QVS fields.

The fetchers support collection, but the tested Paramify intake configuration
still has lifecycle and deadline limitations described below. Treat automated
production ingestion as pending those configuration/product decisions.

## Credentials and permissions

Use an API-enabled Qualys account with read access to the intended VM assets,
KnowledgeBase/QVS, compliance policies, and their host postures. These capabilities
depend on your subscription and user scope. An account that can read compliance
policies may still lack VMDR visibility. A successful API call only covers the
assets visible to that account; verify that scope independently.

Set `QUALYS_USERNAME` and `QUALYS_PASSWORD` through manifest secret references.
Supply `api_url` as the HTTPS `qualysapi.` origin on a Qualys domain, commercial or
government. There is no default region/platform, embedded account ID, or
dependency on an internal secret store. TLS verification remains enabled. For a
private cloud endpoint, explicitly set `private_cloud_host` to its hostname.
Web UI hosts and unapproved hosts fail before credentials are sent.

Requires Python 3.11+, `requests`, and `defusedxml`. Install with
`pip install -e ".[qualys]"`. The parser allows Qualys external DOCTYPE declarations
without fetching them, and rejects entity declarations.
The scripts read environment variables injected by the runner; they do not
automatically search for or load `.env` files.

## Setup

1. Copy [the example manifest](../../examples/qualys_reports.yaml) and set your
   API origin and numeric STIG policy IDs. Optionally restrict VMDR with
   `host_ids` and/or `asset_group_ids` (their intersection when both are set).
2. Export the credentials or configure your normal manifest secret provider.
3. Collect locally:

   ```sh
   paramify run examples/qualys_reports.yaml
   ```

4. Configure the two assessments' intake presets using the per-fetcher mapping
   tables. Bind each fetcher with `paramify assessments select <fetcher>` and
   choose `close_cycle: never` during initial validation.
5. Inspect the CSVs and `paramify issues upload --dry-run` before uploading.
   A dry run verifies routing; it does not prove server-side column mappings.

The example intentionally contains no real assessment IDs. Collection works
without them; upload requires assessment selection and a configured preset.

## Completeness and failure behavior

- Collect full snapshots, not deltas. VMDR includes New, Active, Re-Opened, and
  Fixed detections, including ignored/disabled and potential vulnerabilities.
  Information-gathered detections are outside this vulnerability report.
- Follow every documented truncation continuation. Preserve the original scope
  and filters, reject changed origins/endpoints, and fail on non-advancing cursors,
  unexpected warnings, duplicate identities, and page/record limits.
- VMDR requires KnowledgeBase records for every QID and a successful QVS request
  for every distinct CVE (at most 25 CVEs per request). No CVEs means no QVS call.
  A valid QVS response may omit a CVE: that CVE is explicitly `unavailable`, not a
  zero score or a negative CISA finding. Request failures and malformed enrichment
  fail the report. There is no option to skip required enrichment.
- STIG results cover evaluated postures exposed by Qualys. Unscanned hosts and
  absent checks are not passing. Missing glossary joins or STIG references fail
  collection; verify that the target is a STIG policy.
- Publish a report only after collection and enrichment finish. Files are written
  to temporary names then atomically renamed. Use a fresh output directory for
  each run; existing report paths cause a failure.
- Empty results fail by default. `allow_empty: true` permits only a structurally
  valid zero-result collection, never an empty HTTP body or a truncated page.
- Retry transient network/server failures and Qualys rate/concurrency limits.
  Honor retry delays up to 60 seconds (including HTTP-date Retry-After headers); longer delays fail the run for a
  later retry. Never print credentials or response bodies in failure logs.

Shared settings: `page_size` (default 1000), `max_pages` (10000), `max_records`
(500000), `retries` (3), `min_request_interval` (1 second), and `allow_empty`
(false). Each invocation has a one-hour runner timeout. Requests are sequential;
other integrations still share the tenant's limits. One response is bounded to
64 MiB; reduce `page_size` if necessary. Collection retains rows in memory up to
the configured cap.

Use `close_cycle: after_run` only when the configured sources cover the whole
assessment and you have verified the intake mapping. Keep `never` when other
reports feed the same assessment. A failed or partial collection must never
stand in for evidence that findings disappeared. Changing account visibility or
scope also changes what a complete report contains.

## API compatibility and verification

Uses the documented FO v2 endpoints for detections, KnowledgeBase, QVS, policy
listing, and posture information. The product's Policy Audit naming does not
change this explicit API contract; PCRS gateway APIs and JWT authentication are
not implemented. Support on other Qualys platforms depends on endpoint availability
and subscription entitlements.

Synthetic HTTP-boundary tests exercise paging, enrichment, stable IDs, status
preservation, and failure publication. Before enabling automatic cycle closure,
compare counts and representative records against an independent Qualys export,
and prove repeated imports and state transitions in a dedicated Paramify
assessment. The implementation does not provision or configure assessments.

In the Paramify 1.81.2 setup workflow, map Record ID to Weakness Source
Identifier, then select Weakness Source Identifier under Unique Record ID.
Map Host ID to Asset Identifier, Remediation to Recommendation, and Resolved At
to Date Closed. Select the actual Title/Control Title column in the Weakness
Name field picker; typing text there can create a literal title instead.
For VMDR, map First Detected to Effective Date and CVEs with a semicolon
delimiter. For STIG, use First Failed where available and retain Control
References as description context. Configure every severity value your sources
can return; a mapping established from a small sample may not cover them all.

Synthetic imports through the UI and REST pipeline API verified the following
with this configuration on Paramify 1.81.2 (API spec 0.14.0):

| Case | Observed result |
| --- | --- |
| Same QID on different hosts/ports | Separate issues with distinct Record IDs. |
| Repeated open records | Updated existing issues without new open duplicates. |
| Active to Fixed; failing/error posture to ordinary Passed | Closed the existing issue. |
| Failed to Error; Passed* with an approved exception | Kept the issue open. |
| Repeated already-Fixed/Passed records | Created additional closed issues despite identical Record IDs. |
| Fixed to Re-Opened | Created a new open issue; retained the previous closed issue. |
| CISA Due Date in the source CSV | Did not determine the issue deadline in the tested mapping. |

The setup workflow did not expose a direct CISA Due Date destination or a general
source-status field. A synthetic November 15 CISA deadline produced a December 1
issue deadline under the configured assessment policy. QVS/CISA enrichment
remains in the uploaded CSV; its presence alone does not establish risk scoring
or deadline enforcement.

Resolve closed-record deduplication, recurrence handling, and QVS/CISA policy
mapping with the intended Paramify intake before scheduling production uploads.
`close_cycle: never` prevents absence-based closure; it does not prevent the
closed duplicates above or explicit Date Closed processing. Do not remove
resolved source rows merely to hide this behavior: doing so loses explicit
resolution evidence. These results describe the tested configuration, not every
possible Paramify preset. No automatic cycle closure was tested.

API references:

- [Host detections](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_detection.htm)
- [QVS and CISA fields](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-scan/kbase/knowledgebase_qvs.htm)
- [Posture information](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-pc/posture/list_posture_info.htm)

Only synthetic fixtures and generic configuration belong in this repository.

## Attribution

The platform-domain validation, Qualys error-code retry classification (including
HTTP 409), `SECONDS_TO_WAIT` handling, hardened XML parser choice, and reopening
history fields adapt work by Connor Dalton (@Controgon) in
[PR #289](https://github.com/paramify/paramify-fetchers/pull/289), reviewed at
commit `5ce1171d097e130bf8f433894332191cb3934f56`, under this repository's
GPL-3.0-only license. These assessment reports complement that PR's evidence
fetchers. The adapted client retains bounded response sizes, strict report
completeness checks, and sanitized error messages.
