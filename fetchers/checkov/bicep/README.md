# checkov_bicep

Runs [Checkov](https://www.checkov.io/) over the Bicep files and ARM templates in
a repository (`checkov --framework bicep,arm`) and emits the merged result as
JSON evidence. It is the Azure-native sibling of
[`checkov_terraform`](../terraform/README.md): same clone, same skip model, one
repo per invocation.

## Target (per repo)
| Field | Env | Required | Notes |
|---|---|---|---|
| `repo_url` | `CHECKOV_REPO_URL` | yes | `https://host/group/project.git`; for Azure DevOps, `https://dev.azure.com/<org>/<project>/_git/<repo>`. The `<org>@` prefix that Azure DevOps puts in its clone URLs is dropped automatically. |
| `branch` | `CHECKOV_CLONE_BRANCH` | no | defaults to `main`, falls back to the repo default |
| secret `clone_token` | `GIT_CLONE_TOKEN` | no | omit for public repos; for Azure DevOps, a PAT with **Code (Read)** |

## Config
`soft_fail`, `compact`, `repo_id`, `skip_checks`, `skip_resources`, `skip_paths`,
`checks` (allowlist), `external_checks_dir`, `git_username`. See `fetcher.yaml`.
Skip lists merge with `../_shared/skip-*.default.txt`. `skip_resources` entries are
globs over the whole resource name, e.g. `Microsoft.Storage/storageAccounts.dev*`.

## What counts as clean
`status: success` and exit 0 only when checkov ran at least one check and parsed
every file. Everything else exits 1, so the envelope reads `failed` with the
reason in `metadata.error`:

| `status` | When | Counts |
|---|---|---|
| `no_files` | no `.bicep` files and no `.json` with a `deploymentTemplate` `$schema` | `null` |
| `no_checks` | files found, but checkov evaluated nothing (e.g. resources only behind `br/public:avm` registry modules, which checkov cannot see) | `0`, percentage `null` |
| `partial` | checkov could not parse some files; they are listed in `results.parsing_errors` and `metadata.api_failures` | real counts for the rest |
| `error` | clone or checkov failed | `null` |

Checkov's Bicep parser lags the language, so newer syntax (nullable types,
user-defined types) often fails to parse. Review the listed files, then exclude
them with `skip_paths`. The run then passes, and the exclusion is on record in
the manifest.
