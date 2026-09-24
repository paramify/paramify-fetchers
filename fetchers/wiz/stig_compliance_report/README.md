# wiz_stig_compliance_report

STIG checklist results from Wiz as a CSV for a Paramify **CONFIGURATION**
assessment: one row per STIG control, per rule, per resource, with the PASS/FAIL
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
| Cloud configuration rules | `configurationFindings` filtered to the framework, `result` PASS/FAIL | always (Wiz filters server-side) |
| Host configuration (OS benchmarks) | `hostConfigurationRuleAssessments`, one pass per result, then `hostConfigurationRules` for each rule's framework mapping | the rule maps to the framework |

A rule mapped to several STIG controls produces one row per control.

## Columns

| Column | Example | Notes |
|---|---|---|
| Record ID | `cf-123:V-273188` | Finding id + control id. Unique and stable: use as the intake **unique record ID** |
| Framework | `Okta IDaaS STIG (Ver 1, Rel 2)` | |
| Control ID | `V-273188` | STIG vulnerability id |
| Control Title | `SRG-APP-000025` | |
| Rule Type | `Cloud Configuration` / `Host Configuration` | |
| Rule ID, Rule Name | `OKTA-012`, `Okta User should not be inactive for more than 90 days` | |
| Result | `PASS` / `FAIL` | |
| Status, Severity | `OPEN`, `MEDIUM` | As Wiz reports them |
| Resource ID, Resource Name, Resource Type | | Use Resource Name as the **asset identifier** |
| Cloud Platform, Region, Subscription, Subscription ID | | Cloud rows only |
| First Seen, Last Analyzed | ISO 8601 | |
| Finding ID | | Wiz finding / assessment id |

## Setup

1. **Enable the framework in Wiz** (Policies > Frameworks). Built-ins only need
   enabling. Our tenant currently has only `wf-id-305`, Okta IDaaS STIG.
2. **Service account**, Custom Integration (GraphQL API), read-only scopes:
   `read:security_frameworks`, `read:cloud_configuration`, `read:host_configuration`.
   The same account the other Wiz fetchers use works.
3. **Paramify assessment**: a CONFIGURATION assessment with a file intake preset
   mapping the columns above (Record ID as unique ID, Resource Name as asset).
4. **Manifest**:

```bash
paramify manifest add wiz_stig_compliance_report
paramify manifest set-secret wiz_stig_compliance_report client_id WIZ_CLIENT_ID
paramify manifest set-secret wiz_stig_compliance_report client_secret WIZ_CLIENT_SECRET
paramify manifest set-config wiz_stig_compliance_report api_endpoint_url=https://api.us2.app.wiz.us/graphql
paramify manifest add-target wiz_stig_compliance_report framework=wf-id-305
paramify manifest set-config wiz_stig_compliance_report include_host_configuration=false   # Okta STIG is cloud-only
paramify assessments select wiz_stig_compliance_report
# optional: the pipeline intake, which can also queue processing of the cycle
paramify manifest set-config wiz_stig_compliance_report intake_api=pipeline
paramify manifest set-config wiz_stig_compliance_report pipeline_operation=PROCESS
paramify validate manifest.yaml
```

Or do the same from `paramify tui`: add the fetcher, fill its config (the
`intake_api` and `pipeline_operation` fields appear there too), press `A` on the
entry to pick the assessment, run, then upload issue reports.

5. **Run and upload**:

```bash
paramify run manifest.yaml
paramify issues upload --dry-run    # shows endpoint (assessment or pipeline) per file
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
| No rows for the framework, 10,000-row Wiz cap hit, record cap hit, control mappings unavailable | `partial_failure` |

## Caveats

- **Freshness:** results are Wiz's latest continuous assessment (workload scans
  roughly every 24 hours), not a new scan.
- **Scope:** only resources Wiz scans and the service account can see. A host
  without workload scanning is absent, not passing.
- **10,000 rows:** Wiz caps `configurationFindings` at 10,000 rows per query;
  hitting it fails the run rather than truncating.
