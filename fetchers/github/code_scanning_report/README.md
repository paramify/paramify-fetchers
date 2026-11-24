# github_code_scanning_report

This fetcher writes every open code scanning alert in a GitHub organization to
a CSV file, one row for each alert. Each row links to the repository's record
from [`github_repository_inventory`](../repository_inventory/fetcher.py).

This is an **issue-report** fetcher (`kind: issue_report`). It builds the CSV
from the GitHub REST API. It is not a GitHub export. The file goes to a Paramify
vulnerability assessment, not to an evidence set. See
[docs/issue_report_fetchers_guide.md](../../../docs/issue_report_fetchers_guide.md#api-built-reports).
The rules that the three GitHub alert reports share are in
[the category README](../README.md#alert-reports).

## Report

| | |
|---|---|
| Tool | GitHub code scanning (CodeQL and each tool that uploads SARIF) |
| Format | CSV that this fetcher builds. The columns are below. |
| Assessment type | `VULNERABILITY` |
| Scope | The open alerts on the default branch of each repository that the target selects. GitHub lists the default branch when the request names no branch. |
| Token permission | Code scanning alerts (repository), read-only, and Metadata |

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
| ID | The identity of the row: the Asset ID, then `/code-scanning/alerts/` and the alert number. Use it as the unique key for deduplication. |
| Asset ID | The repository's REST URL by numeric id. Choose it as the inventory mapping column. |
| Repository | The repository's full name, `org/name`. |
| Alert Number | The alert number in the repository. |
| State | Always `open`. |
| Created At, Updated At | GitHub's timestamps for the alert. Created At is the detection date. |
| Alert URL | The alert's page on GitHub. |
| Title | The rule description, else the rule name, else the rule ID. |
| Severity | The security severity (`critical`, `high`, `medium` or `low`) of a security rule. A rule with no security severity gives its rule severity (`error`, `warning` or `note`) here. The two sets of values do not overlap, so the preset can map each value. |
| Rule Severity | The rule severity: `error`, `warning` or `note`. |
| Rule ID, Rule Tags | The rule, and its tags with a comma between them. CodeQL tags include CWE IDs, for example `external/cwe/cwe-089`. |
| Tool, Tool Version | The analysis tool, for example `CodeQL`. |
| Message | The message of the most recent instance of the alert. |
| Path, Start Line, End Line | The location of the most recent instance. |
| Ref, Commit SHA | The branch and the commit of the most recent instance. |

## A repository with code scanning off

GitHub gives three answers for a repository that has no code scanning results:

- `404 no analysis found`: code scanning never ran on the repository.
- `403 Advanced Security must be enabled` or `403 Code scanning is not
  enabled`: the feature is off.
- `403 Upgrade to GitHub ...`: the plan does not include the feature.

`github_code_scanning_alerts` records these answers as "not analysed", not as
a failure. This report does the same: the repository adds no rows, and the run
does not fail. The fetcher logs the names of these repositories as a warning.
A token that cannot read the alerts gets a different answer (for example
`403 Resource not accessible`), and that answer is a failure.

If someone turns code scanning off, or deletes the analyses of a repository,
its alerts leave the next report, and Paramify closes the issues. Use
`github_code_scanning_alerts` to see which repositories have no analysis
(`repositories_not_analysed`).

## Run it

Add an entry beside the other GitHub fetchers. The target is the same target
that they use, so one YAML anchor can supply it
([`examples/github_run.yaml`](../../../examples/github_run.yaml)).

```yaml
- use: github_code_scanning_report
  targets: [*github_target]
```

Then select the assessment and run:

```bash
paramify assessments select github_code_scanning_report
paramify run manifests/github.yaml
paramify issues upload
```
