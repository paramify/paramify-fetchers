# github_secret_scanning_report

This fetcher writes every open secret scanning alert in a GitHub organization
to a CSV file, one row for each alert. Each row links to the repository's record
from [`github_repository_inventory`](../repository_inventory/fetcher.py).

**The report never contains the secret.** It holds only metadata: the secret
type, the validity, the location path, the state and the dates.

This is an **issue-report** fetcher (`kind: issue_report`). It builds the CSV
from the GitHub REST API. It is not a GitHub export. The file goes to a Paramify
vulnerability assessment, not to an evidence set. See
[docs/issue_report_fetchers_guide.md](../../../docs/issue_report_fetchers_guide.md#api-built-reports).
The rules that the three GitHub alert reports share are in
[the category README](../README.md#alert-reports).

## Report

| | |
|---|---|
| Tool | GitHub secret scanning |
| Format | CSV that this fetcher builds. The columns are below. |
| Assessment type | `VULNERABILITY` |
| Scope | The open alerts of each repository that the target selects, for provider patterns and for the generic types that `github_secret_scanning` asks for |
| Token permission | Secret scanning alerts (repository), read-only, and Metadata |

## How the secret stays out

- Each request for alerts sends `hide_secret=true`, so GitHub does not send
  the secret. The request comes from the same function
  (`secret_scanning_alerts` in `_shared/github_client.py`) that
  `github_secret_scanning` uses.
- The fetcher copies only the fields in the column table below into a row. If
  GitHub sends the secret, the fetcher does not read that field.
- The CSV writer refuses a row that has a column that is not in the table.
- A test gives the fetcher alerts that contain secret values, and it makes
  sure that no secret, and no part of one, is in any file that the run writes.

Do not add a column that holds the secret or a part of it.

## Inventory mapping

In the vulnerability preset, choose **`Asset ID`** as the inventory mapping
column. Its value is the repository's REST URL, built from the repository's
numeric id, for example `https://api.github.com/repositories/123456789`. This
is the same value as the `unique_asset_identifier` of the repository in
`github_repository_inventory`. Both fetchers make the value with one function,
`repository_asset_id` in `_shared/github_client.py`, so the two values are
always equal. The `pipeline:` block in `fetcher.yaml` names this column
(`asset_id_field: Asset ID`, scheme `github-repository-url`).

## Columns (fetcher 0.1.0)

| Column | Meaning |
|---|---|
| ID | The identity of the row: the Asset ID, then `/secret-scanning/alerts/` and the alert number. Use it as the unique key for deduplication. |
| Asset ID | The repository's REST URL by numeric id. Choose it as the inventory mapping column. |
| Repository | The repository's full name, `org/name`. |
| Alert Number | The alert number in the repository. |
| State | Always `open`. |
| Created At, Updated At | GitHub's timestamps for the alert. Created At is the detection date. |
| Alert URL | The alert's page on GitHub. |
| Title | The display name of the secret type, for example `GitHub Personal Access Token`. |
| Secret Type | The secret type, for example `github_personal_access_token`. |
| Validity | `active`, `inactive` or `unknown`, as GitHub reports it. |
| Publicly Leaked, Multi Repo | `True` or `False`, as GitHub reports them. They are empty when GitHub does not report them. |
| Push Protection Bypassed | `True` when someone pushed the secret past push protection. |
| Location Path, Location Line | The file and the line where GitHub first found the secret, from `first_location_detected`. They are empty when the secret is not in a file (for example in an issue), or when the host does not report the field. |
| Has More Locations | `True` when GitHub found the secret in more than one location. |

GitHub gives a secret scanning alert no severity, so the report has no
Severity column. In the preset, set the severity from `Validity`, or use one
fixed value.

## A repository with secret scanning off

GitHub answers `404 Secret scanning is disabled` for a repository where secret
scanning is off, and `403 Upgrade to GitHub ...` when the plan does not include
it. `github_secret_scanning` records these answers as `scanning_enabled:
false`, not as a failure. This report does the same: the repository adds no
rows, and the run does not fail. The fetcher logs the names of these
repositories as a warning. A token that cannot read the alerts gets a different
answer (for example `403 Resource not accessible`), and that answer is a
failure.

If someone turns secret scanning off, its alerts leave the next report, and
Paramify closes the issues. Use `github_secret_scanning` to see which
repositories have scanning off (`repositories_scanning_disabled`).

## Run it

Add an entry beside the other GitHub fetchers. The target is the same target
that they use, so one YAML anchor can supply it
([`examples/github_run.yaml`](../../../examples/github_run.yaml)).

```yaml
- use: github_secret_scanning_report
  targets: [*github_target]
```

Then select the assessment and run:

```bash
paramify assessments select github_secret_scanning_report
paramify run manifests/github.yaml
paramify issues upload
```
