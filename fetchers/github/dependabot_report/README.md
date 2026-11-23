# github_dependabot_report

This fetcher writes every open Dependabot alert in a GitHub organization to a
CSV file, one row for each alert. Each row links to the repository's record from
[`github_repository_inventory`](../repository_inventory/fetcher.py).

This is an **issue-report** fetcher (`kind: issue_report`). It builds the CSV
from the GitHub REST API. It is not a GitHub export. The file goes to a Paramify
vulnerability assessment, not to an evidence set. See
[docs/issue_report_fetchers_guide.md](../../../docs/issue_report_fetchers_guide.md#api-built-reports).
The rules that the three GitHub alert reports share are in
[the category README](../README.md#alert-reports).

## Report

| | |
|---|---|
| Tool | GitHub Dependabot alerts |
| Format | CSV that this fetcher builds. The columns are below. |
| Assessment type | `VULNERABILITY` |
| Scope | The open alerts of each repository that the target selects |
| Token permission | Dependabot alerts (repository), read-only, and Metadata |

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
| ID | The identity of the row: the Asset ID, then `/dependabot/alerts/` and the alert number. Use it as the unique key for deduplication. |
| Asset ID | The repository's REST URL by numeric id. Choose it as the inventory mapping column. |
| Repository | The repository's full name, `org/name`. |
| Alert Number | The alert number in the repository. |
| State | Always `open`. |
| Created At, Updated At | GitHub's timestamps for the alert. Created At is the detection date. |
| Alert URL | The alert's page on GitHub. |
| Title | The advisory summary. |
| Severity | `critical`, `high`, `medium` or `low`, from the vulnerability, else from the advisory. |
| GHSA ID, CVE ID | The advisory identifiers. A CVE ID can be empty. |
| CVSS Score, CVSS Vector | CVSS v4 if it has a score, else CVSS v3, else the older single CVSS field. |
| EPSS Percentage | The probability of exploitation that GitHub supplies, when it supplies one. |
| CWE IDs | The advisory's CWE IDs, with a comma between them. |
| Package, Ecosystem | The vulnerable package and its package manager. |
| Manifest Path | The manifest file where Dependabot found the dependency. |
| Dependency Scope | `runtime` or `development`. |
| Vulnerable Versions, First Patched Version | The affected version range, and the first version with a fix. The second column is empty when no fix exists. |
| Description | The advisory description, in Markdown. It can contain new lines. |

## A repository with Dependabot alerts off

GitHub answers `403 Dependabot alerts are disabled` for a repository where
Dependabot alerts are off. `github_dependabot_alerts` records this as
`alerts_enabled: false`, not as a failure. This report does the same: the
repository adds no rows, and the run does not fail. The fetcher logs the names
of these repositories as a warning. A token that cannot read the alerts gets a
different answer (for example `403 Resource not accessible`), and that answer
is a failure.

If you turn Dependabot alerts off in a repository, its alerts leave the next
report, and Paramify closes the issues. Use `github_dependabot_alerts` to see
which repositories have alerts off (`repositories_alerts_disabled`).

## Run it

Add an entry beside the other GitHub fetchers. The target is the same target
that they use, so one YAML anchor can supply it
([`examples/github_run.yaml`](../../../examples/github_run.yaml)).

```yaml
- use: github_dependabot_report
  targets:
    - *acme
```

Then select the assessment and run:

```bash
paramify assessments select github_dependabot_report
paramify run manifests/github.yaml
paramify issues upload
```
