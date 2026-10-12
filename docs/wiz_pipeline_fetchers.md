# Wiz pipeline fetchers

Three issue-report fetchers send Wiz data into Paramify assessment pipelines. Each
writes a CSV to `<run>/issue-reports/`, and `paramify issues upload`
(`uploaders/paramify_issues`) sends it into the assessment. General background is
in [issue_report_fetchers.md](issue_report_fetchers.md); the pipeline itself is
in [pipelines.md](pipelines.md).

| Fetcher | Assessment type | What it exports | How |
|---|---|---|---|
| `wiz_issues_report` | CONFIGURATION | Issues (configuration findings) as Wiz's own CSV | Downloads the last completed run of a Wiz Issues report that is scheduled in Wiz |
| `wiz_vulnerability_findings` | VULNERABILITY | Every vulnerability finding in the legacy Paramify column layout | GraphQL `vulnerabilityFindings`, cursor pagination, flattened to CSV |
| `wiz_stig_compliance_report` | CONFIGURATION | STIG control pass/fail per rule and resource for one framework | GraphQL queries; see [its README](../fetchers/wiz/stig_compliance_report/README.md) |

All three are read-only and use the category's shared client
(`fetchers/wiz/_shared/wiz_client.py`), which refuses to send a GraphQL mutation
and checks the auth and API hosts before any credential is sent. One Wiz service
account per tenant serves every Wiz fetcher.

## Read-only: what a person sets up in Wiz

No fetcher creates, edits or reruns anything in Wiz. Anything that has to exist in
the tenant is a one-time setup step, and the fetcher checks it is there and
fails clearly when it is not.

For `wiz_issues_report`, that is the report itself:

1. In Wiz, create an **Issues** report with the projects and issue statuses the
   assessment should cover. Name it `Paramify-Wiz-Issues`, or set `report_name`
   (or `report_id`) to the one you made.
2. Give it a **schedule**, for example every 24 hours, and run it once.
3. Each fetcher run downloads the report's **last completed run**. It fails, with
   no file, if the report is missing, has never run, its last run is not
   `COMPLETED` (for example still running), or that run is older than
   `max_report_age_hours` (default 26, which suits a daily schedule).

The report's own settings decide its scope. To change which projects or statuses
it covers, change the report in Wiz.

## Service account scopes

| Fetcher | Scopes |
|---|---|
| `wiz_issues_report` | `read:reports` |
| `wiz_vulnerability_findings` | `read:vulnerabilities` |
| `wiz_stig_compliance_report` | `read:security_frameworks`, `read:cloud_configuration`, `read:host_configuration` |

Never grant `create:`, `update:`, `write:`, `delete:` or `admin:` scopes to a
fetcher account. A missing scope fails the run as `not_authorized`, not as an
empty export.

## Configuration

Secrets (every Wiz fetcher): `client_id` (`WIZ_CLIENT_ID`), `client_secret`
(`WIZ_CLIENT_SECRET`).

| Key | Env | Fetcher | Default | Notes |
|---|---|---|---|---|
| `api_endpoint_url` | `WIZ_API_ENDPOINT_URL` | all, required | none | Wiz > Tenant Info > API Endpoint URL, e.g. `https://api.us2.app.wiz.us/graphql`. Must be https on a Wiz API host. |
| `auth_url` | `WIZ_AUTH_URL` | all | `https://auth.app.wiz.us/oauth/token` (Wiz for Gov) | Must be one of Wiz's token endpoints. Commercial is `https://auth.app.wiz.io/oauth/token`. |
| `min_request_interval` | `WIZ_MIN_REQUEST_INTERVAL` | all | 1.0 | Seconds between API calls. The tenant's rate limit is shared with every other integration. |
| `report_name` | `WIZ_REPORT_NAME` | issues | `Paramify-Wiz-Issues` | Exact name. Wiz's search is a substring match, so the fetcher keeps only exact matches and refuses two reports with the same name. |
| `report_id` | `WIZ_REPORT_ID` | issues | none | Use this report instead of finding one by name. |
| `max_report_age_hours` | `WIZ_MAX_REPORT_AGE_HOURS` | issues | 26 | Fail if the last completed run is older than this. |
| `project_id` | `WIZ_PROJECT_ID` | vulnerabilities | all projects | Added to `filterBy` only when set and not `*`. |
| `page_size` | `WIZ_PAGE_SIZE` | vulnerabilities | 100 | Findings per page, max 500. The client reads at most 2,000 pages and fails beyond that. |
| `allow_empty` | `WIZ_ALLOW_EMPTY` | issues, vulnerabilities | off | `true` accepts a header-only or zero-finding export. |
| `assessment_id`, `assessment_name`, `close_cycle` | n/a | all | none | Framework fields; see the warning below. |

Behavior worth knowing:

- A failed or empty collection never leaves a CSV behind. The issues download goes
  to a `.part` file and is renamed only when complete; the vulnerability CSV is
  written only after every page has been read.
- Any failure the shared client records (a GraphQL error, a page that says there is
  more data but gives no cursor, a repeated cursor, the page cap) fails the run.
- The bearer token is never sent to the report's download URL, and the download
  must be https.

## Why DELTA_MODE was removed

The legacy scripts had a `DELTA_MODE` that exported only rows changed since the
last run. A delta file lists only what changed. Paramify closes a cycle by
auto-closing every open issue the cycle never saw, so a delta processed with a
cycle close would resolve nearly every open issue. Every run is a full export. For
the same reason there is no `state.json` or `vuln_state.json`: the issues report is
found by id or name each run, so a fresh checkout or CI runner behaves like any
other machine.

## Warning: close_cycle and scope

`close_cycle: after_run` closes the assessment's cycle after processing, and
**closing auto-closes every open issue in the assessment that the cycle did not
see.** The cycle only sees what these files contain, so scope matters:

- The issues report covers what its settings in Wiz say. If the assessment already
  holds issues from projects the report does not cover, a close marks them
  resolved. Changing the report's projects in Wiz changes what "the cycle saw".
- `project_id` on the vulnerability fetcher works the same way: findings from other
  projects are not in the file, so a close resolves them.
- Two fetchers feeding one assessment must together cover the scope you want kept
  open. Closing runs only if every target in the run succeeded and every file
  uploaded.
- Use `close_cycle: never` while validating a new scope, check the result in
  Paramify, and only then switch to `after_run`. `paramify issues close` closes
  a cycle by hand.
- If a run's `_issue_reports.json` was corrupt and had to be restarted, the run is
  marked `cannot_close` and the uploader processes without closing.
- Uploads land on the assessment's **oldest open cycle**, and Paramify only
  processes or closes that cycle (naming a newer one is refused with HTTP 409). An
  assessment with old cycles left open takes each scan into the oldest of them,
  and newer cycles show nothing until it is closed. The upload prints the cycle
  it landed on and warns when newer ones exist. See
  [pipelines.md](pipelines.md#how-cycles-work).

## Verified vs unverified against real Wiz

The code is tested offline (`tests/test_wiz_pipeline_fetchers.py`, which stands in
for Wiz at the HTTP boundary). That proves the fetchers' own logic, not Wiz's
behavior. Items marked **Verified** were exercised against a Wiz for Gov tenant
(`auth.app.wiz.us`, `api.us2.app.wiz.us`) with all projects, and the CSVs were
accepted by Paramify pipeline intake.

| Item | Status |
|---|---|
| OAuth client-credentials exchange and token endpoints | **Verified** (Wiz for Gov). |
| `FindReports` query and its `search` filter (find a report by name) | **Verified.** `search` is a substring match, so the exact-name filter is required. |
| `ReportDownloadUrl` (`lastRun { url status runAt }`) and the download | **Verified.** `runAt` is ISO-8601 UTC (`...Z`). |
| `vulnerabilityFindings` query, CSV columns, row flattening | **Verified** that the query runs and the CSV is accepted by intake. Column mapping against the preset is not re-checked. |
| A report on a Wiz schedule: what `lastRun` shows while a scheduled run is in progress | **UNVERIFIED.** The fetcher refuses anything but `COMPLETED`; if Wiz reports the in-progress run there, a run during that window fails and the next one succeeds. |
| `read:reports` alone being enough to read and download an Issues report | **UNVERIFIED.** The live checks used an account that could also manage reports. If Wiz refuses, add `read:issues` (and `read:threat_issues` if the report includes threats). |
| `filterBy: { projectId: [<id>] }` on `vulnerabilityFindings` | **UNVERIFIED against real Wiz schema.** Confirm via introspection. A wrong name should fail the GraphQL query rather than export everything, but that is also unconfirmed. |
| Commercial Wiz endpoints | Allowed by the host checks. Not exercised. |

To confirm the remaining items, schedule the report in a test tenant, run the
fetchers with `close_cycle: never` while it is running and after it finishes, and
introspect `VulnerabilityFindingFilters` for the project field.

## Testing offline

```
python3 -m pytest -q tests/test_wiz_pipeline_fetchers.py
```

The tests replace `requests.post` and `requests.get`, so nothing goes to
`*.wiz.io`, `*.wiz.us` or `*.paramify.com`.
