# Wiz pipeline fetchers

Two issue-report fetchers collect Wiz data for a Paramify VULNERABILITY assessment
pipeline. Both write a CSV to `<run>/issue-reports/`; `paramify issues upload`
(`uploaders/paramify_issues`) sends it into the assessment. General background is
in [issue_report_fetchers.md](issue_report_fetchers.md).

| Fetcher | What it exports | How |
|---|---|---|
| `wiz_issues_report` | Issues (configuration findings: open, in progress, resolved) as Wiz's own CSV | Wiz Reports API: find or create a report, update its parameters, rerun, wait, download |
| `wiz_vulnerability_findings` | Every vulnerability finding in the legacy Paramify column layout | GraphQL `vulnerabilityFindings`, cursor pagination, flattened to CSV |

One Wiz service account per tenant serves both.

## Service account scopes

| Fetcher | Scopes |
|---|---|
| `wiz_issues_report` | `read:reports`, `create:reports`, `update:reports`, `read:issues`, `read:threat_issues` |
| `wiz_vulnerability_findings` | `read:vulnerabilities` |

A missing scope shows up as `not_authorized` ("check the service account's
scopes"), not as an empty export.

## Configuration

Secrets (both fetchers): `client_id` (`WIZ_CLIENT_ID`), `client_secret`
(`WIZ_CLIENT_SECRET`). Use `${env:...}` in the manifest.

| Key | Env | Fetcher | Default | Notes |
|---|---|---|---|---|
| `auth_url` | `WIZ_AUTH_URL` | both, required | none | Must be one of Wiz's token endpoints (commercial, `auth.gov.wiz.io`, Wiz for Gov `auth.app.wiz.us`). Checked before any credential is sent. |
| `api_endpoint` | `WIZ_API_ENDPOINT` | both, required | none | https on a Wiz domain, e.g. `https://api.us17.app.wiz.io/graphql`. |
| `report_name` | `WIZ_REPORT_NAME` | issues | `Paramify-Wiz-Issues`, or `Paramify-Wiz-Issues-<first 8 chars of project_id>` when `project_id` is set | The report is found by name and created if missing. An explicit name is used as given. |
| `report_id` | `WIZ_REPORT_ID` | issues | none | Use this report instead of finding one by name. |
| `project_id` | `WIZ_PROJECT_ID` | both | `*` (all projects) | Issues: the report's project. Vulnerabilities: added to `filterBy` only when set and not `*`. |
| `poll_seconds` | `WIZ_REPORT_POLL_SECONDS` | issues | 20 | Seconds between report status checks. |
| `max_wait_seconds` | `WIZ_REPORT_MAX_WAIT` | issues | 1500 | Inside `runtime.timeout` 1800. |
| `allow_empty` | `WIZ_ALLOW_EMPTY` | both | off | `true` accepts a header-only or zero-finding export. |
| `assessment_id`, `assessment_name`, `close_cycle` | n/a | both | none | Framework fields; see the warning below. |

Behavior worth knowing:

- A failed or empty collection never leaves a CSV behind. Downloads go to a `.part`
  file and are renamed only when complete, so a truncated export can't be sent.
- A report run that ends `FAILED` or `EXPIRED` is re-run up to 3 times.
- A `COMPLETED` run whose `runAt` is older than the start of this fetch is ignored:
  it is last run's report.
- The bearer token is never sent to the report's download URL.
- The vulnerability export refuses to continue if a page says there is more data
  but gives no cursor, or if there are more than `WIZ_MAX_PAGES` pages.

## Why DELTA_MODE was removed

The legacy scripts had a `DELTA_MODE` that exported only rows changed since the
last run. A delta file lists only what changed. Paramify closes a cycle by
auto-closing every open issue the cycle never saw, so a delta processed with a
cycle close would resolve nearly every open issue. Every run is a full export. For
the same reason there is no `state.json` or `vuln_state.json`: the issues report is
found by name each run, so a fresh checkout or CI runner behaves like the machine
that created it.

## Warning: close_cycle and project scope

`close_cycle: after_run` closes the assessment's cycle after processing, and
**closing auto-closes every open issue in the assessment that the cycle did not
see.** The cycle only sees what these files contain, so scope matters:

- A fetcher scoped to one project (`project_id`) only reports that project. If the
  assessment already holds issues from other projects, a close marks them resolved.
- Changing `project_id` on an existing setup changes what "the cycle saw". Before
  this was fixed, the default report name did not include the project, so a new
  `project_id` silently reused the old report (still scoped to the old project).
  The default name now includes the project, so a new project gets its own report.
  An explicit `report_name` or `report_id` still pins one report: changing
  `project_id` while keeping them does not retarget it.
- Two fetchers feeding one assessment must cover the same scope you want kept open.
  Closing runs only if every target in the run succeeded and every file uploaded.
- Use `close_cycle: never` while validating a new scope, check the result in
  Paramify, and only then switch to `after_run`. `paramify issues close` closes
  a cycle by hand.
- If a run's `_issue_reports.json` was corrupt and had to be restarted, the run is
  marked `cannot_close` and the uploader processes without closing.

## Verified vs unverified against real Wiz

All of the code is tested offline against a local fake Wiz
(`fetchers/wiz/_shared/fake_wiz.py`). That proves the fetchers' own logic, not
Wiz's behavior. Nothing in this table was re-checked against a live tenant when it
was written.

| Item | Status |
|---|---|
| OAuth client-credentials exchange and token endpoints | Inherited from the legacy fetchers, which ran against Wiz. Not re-checked. |
| `CreateReport`, `UpdateReport`, `RerunReport` mutations | Inherited from the legacy issues script. Not re-checked. |
| `ReportDownloadUrl` (`lastRun { url status }`) | Inherited from the legacy script. Not re-checked. |
| `vulnerabilityFindings` query, CSV columns, row flattening | Copied unchanged from the legacy fetcher so the existing intake preset still maps. Not re-checked. |
| `FindReports` query and its `search` filter (find a report by name) | **UNVERIFIED.** Not used by the legacy script. Set `report_id` to skip it. |
| `lastRun.runAt` (used to reject a stale run) | **UNVERIFIED.** Field, format and timezone assumed. |
| `createReport` with a specific `projectId` (not `*`) | **UNVERIFIED.** Only `*` is known to have been used before. |
| `updateReport` leaving a report's project unchanged | **UNVERIFIED.** The scoped default name assumes it. |
| `filterBy: { projectId: [<id>] }` on `vulnerabilityFindings` | **UNVERIFIED against real Wiz schema.** Confirm via introspection. A wrong name should fail the GraphQL query rather than export everything, but that is also unconfirmed. |
| Scope lists above | Taken from the fetchers' `fetcher.yaml`. Not re-checked against a tenant. |
| Wiz for Gov endpoints | Allowed by the host checks. Not exercised. |

To confirm the unverified items, run both fetchers against a test tenant with
`close_cycle: never`, and introspect `VulnerabilityFindingFilters` for the project
field.

## Testing offline

```
python3 -m pytest -q fetchers/wiz     # also part of the default `pytest` run
```

The tests start `FakeWiz` on 127.0.0.1 and run each `fetcher.py` in-process. No
traffic goes to `*.wiz.io`, `*.wiz.us` or `*.paramify.com`.
