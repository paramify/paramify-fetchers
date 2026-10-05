# wiz_stig_compliance_report

STIG checklist results from Wiz as a CSV for a Paramify **CONFIGURATION**
assessment: one row per STIG control, per rule, per resource, with Wiz's
result, for one enabled Wiz framework (Okta IDaaS STIG, DISA GPOS SRG, a CIS
STIG benchmark, ...).

This is an **issue-report** fetcher (`kind: issue_report`). It goes to an
assessment's intake, not an evidence set. See
[docs/issue_report_fetchers.md](../../../docs/issue_report_fetchers.md).

## Read-only, and why the CSV is assembled here

Wiz's own "Compliance Assessment" CSV exists only as a saved report, and creating
or rerunning a report is a write to the tenant. Every fetcher in this category is
read-only (the shared client refuses to send a mutation), so this one builds the
rows from GraphQL *queries* instead. That is the one deliberate exception to the
issue-report rule "the file is the tool's own bytes": the columns below are a
fixed contract, the rows are sorted so the same Wiz state always gives the same
bytes, and the Paramify file intake preset maps them once.

| Source | Query | Kept when |
|---|---|---|
| Cloud configuration rules | `configurationFindings` filtered to the framework, every result | always (Wiz filters server-side) |
| Host configuration (OS benchmarks) | `hostConfigurationRuleAssessments`, one pass per result (PASS, FAIL, ERROR, NOT_ASSESSED), then `hostConfigurationRules` for each rule's framework mapping | the rule maps to the framework |

Every result is kept, not just PASS and FAIL: a check that moves from FAIL to
ERROR stays in the file, where its absence would read as fixed. A rule mapped to
several STIG controls produces one row per control; a control listed under two
titles is still one row, with both titles. An assessment read in two passes
(its result changed mid-run) is written once, from the newer read.

## Columns

| Column | Example | Notes |
|---|---|---|
| Record ID | `cf-123:V-273188` | Finding id + control id. Unique and stable: use as the intake **unique record ID** |
| Framework | `Okta IDaaS STIG (Ver 1, Rel 2)` | |
| Control ID | `V-273188` | STIG vulnerability id |
| Control Title | `SRG-APP-000025` | |
| Rule Type | `Cloud Configuration` / `Host Configuration` | |
| Rule ID, Rule Name | `OKTA-012`, `Okta User should not be inactive for more than 90 days` | |
| Remediation | `In the Okta Admin Console, go to Security > ...` | Wiz's fix instructions for the rule. Map to the intake **Recommendation** field. Blank if the tenant does not expose `remediationInstructions` (probed once per run; never fails the run) |
| Result | `PASS` / `FAIL` / `ERROR` / `NOT_ASSESSED` | As Wiz reports it. Map anything other than `PASS` so the issue stays open: a check Wiz could not evaluate is not a pass |
| Status, Severity | `OPEN`, `MEDIUM` | As Wiz reports them |
| Resource ID, Resource Name, Resource Type | | Use Resource Name as the **asset identifier** |
| Cloud Platform, Region, Subscription, Subscription ID | | Cloud rows only |
| First Seen, Last Analyzed | ISO 8601 | |
| Finding ID | | Wiz finding / assessment id |

## Setup

1. **Enable the framework in Wiz** (Policies > Frameworks). Built-ins only need
   enabling.
2. **Service account**, Custom Integration (GraphQL API), read-only scopes:
   `read:security_frameworks`, `read:cloud_configuration`, `read:host_configuration`.
   The same account the other Wiz fetchers use works.
3. **Paramify assessment**: a CONFIGURATION assessment with a file intake preset
   mapping the columns above (Record ID as unique ID, Resource Name as asset), and
   an upload key with `PIPELINE_INTAKE` and `PIPELINE_PROCESS` (plus
   `PIPELINE_CLOSE` to close cycles). See [docs/pipelines.md](../../../docs/pipelines.md).
4. **Manifest**:

```bash
paramify manifest add wiz_stig_compliance_report
paramify manifest set-secret wiz_stig_compliance_report client_id WIZ_CLIENT_ID
paramify manifest set-secret wiz_stig_compliance_report client_secret WIZ_CLIENT_SECRET
paramify manifest set-config wiz_stig_compliance_report api_endpoint_url=https://api.us2.app.wiz.us/graphql
paramify manifest add-target wiz_stig_compliance_report framework=wf-id-305
paramify manifest set-config wiz_stig_compliance_report include_host_configuration=false   # Okta STIG is cloud-only
paramify assessments select wiz_stig_compliance_report --close-cycle after_run
paramify validate manifest.yaml
```

`--close-cycle after_run` closes the assessment's cycle once the run's reports
are processed, and only if every framework target succeeded. That fits when this
entry's targets are every framework the assessment receives. If other files feed
the same cycle, use `never` and close it with `paramify issues close` once the
last one is in. Closing auto-closes open issues the cycle never saw.

Or do the same from `paramify tui`: add the fetcher, fill its config, press `A`
on the entry to pick the assessment and its close policy, run, then send the
issue reports from the Paramify tab.

5. **Run and upload**:

```bash
paramify run manifest.yaml
paramify issues upload --dry-run    # shows PROCESS or PROCESS_CLOSE per assessment
paramify issues upload
```

## Failure behavior

Any Wiz error fails the run and writes **no file**, because a partial checklist
reads as resolved findings once intake parses it.

| Situation | Code |
|---|---|
| `WIZ_STIG_FRAMEWORK` unset, unknown, ambiguous or not enabled | `bad_config` |
| Bad client id/secret | `auth_failed` |
| Service account missing a scope | `not_authorized` |
| Rate limited after retries | `rate_limited` |
| No rows for the framework, 10,000-row Wiz cap hit, record cap hit, control mappings unavailable, a cloud finding with no control in the framework, a host rule the lookup did not return, an empty or null page from Wiz | `partial_failure` |
| The CSV could not be written | `internal_error` |

## Caveats

- **Freshness:** results are Wiz's latest continuous assessment (workload scans
  roughly every 24 hours), not a new scan.
- **Scope:** only resources Wiz scans and the service account can see. A host
  without workload scanning is absent, not passing.
- **10,000 rows:** Wiz caps `configurationFindings` at 10,000 rows per query;
  hitting it fails the run rather than truncating.
