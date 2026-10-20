# checkov_bicep

Runs [Checkov](https://www.checkov.io/) over the Bicep files and ARM templates in
a repository (`checkov --framework bicep,arm`) and emits the merged result as
JSON evidence. It is the Azure-native sibling of
[`checkov_terraform`](../terraform/README.md): same clone, same skip model, one
source per invocation. It can also read an Azure DevOps TFVC folder, which
`git clone` cannot fetch.

## Target (per source)
| Field | Env | Required | Notes |
|---|---|---|---|
| `repo_url` | `CHECKOV_REPO_URL` | yes | Git: `https://host/group/project.git`; for Azure DevOps, `https://dev.azure.com/<org>/<project>/_git/<repo>` (the `<org>@` prefix is dropped automatically). TFVC: the project URL, `https://dev.azure.com/<org>/<project>`. |
| `source_type` | `CHECKOV_SOURCE_TYPE` | no | `git` (default) or `tfvc` |
| `branch` | `CHECKOV_CLONE_BRANCH` | no | git only; defaults to `main`, falls back to the repo default |
| `tfvc_path` | `CHECKOV_TFVC_PATH` | for `tfvc` | server path of the folder to scan, e.g. `$/<project>/infra` |
| `tfvc_version` | `CHECKOV_TFVC_VERSION` | no | `tfvc` only; `latest` (default) or a changeset number, `1234` or `C1234` |
| secret `clone_token` | `GIT_CLONE_TOKEN` | no | git only; omit for public repos; for Azure DevOps, a PAT with **Code (Read)** |
| secret `tfvc_token` | `TFVC_TOKEN` | no | `tfvc` only; a read-only PAT with **Code (Read)**; omit for a public project |

## TFVC source
With `source_type: tfvc` the fetcher makes two read-only calls to the
[TFVC REST API](https://learn.microsoft.com/en-us/rest/api/azure/devops/tfvc/items/get?view=azure-devops-rest-7.1)
(api-version 7.1) and needs `curl` and `unzip` instead of `git`:

1. It finds the changeset to read. `latest` asks for the project's newest
   changeset (`_apis/tfvc/changesets?$top=1`); a named one is read with
   `_apis/tfvc/changesets/<id>`.
2. It downloads `tfvc_path` at that changeset as one zip
   (`_apis/tfvc/items?path=…&recursionLevel=Full&versionDescriptor.versionType=changeset`,
   `Accept: application/zip`). Pinning the version means a check-in during the
   run cannot mix two versions of the folder.

The evidence records `source_type: tfvc` and, in `metadata`, `tfvc_path`,
`requested_version`, `changeset` and `changeset_date`, where a git source records
its `branch` and `commit_sha`. The PAT is sent as an `Authorization` header on
curl's stdin, so it never appears in a process listing, a log or the evidence.

```bash
paramify manifest add-target checkov_bicep \
  repo_url=https://dev.azure.com/<org>/<project> source_type=tfvc \
  'tfvc_path=$/<project>/infra' \
  --secret tfvc_token=AZURE_DEVOPS_CODE_READ_PAT
```

A rejected PAT (`401`, or `203` with the sign-in page) fails with `auth_failed`,
a PAT without Code (Read) with `not_authorized`, and a path or changeset that does
not exist with `bad_config`.

## Config
`soft_fail`, `compact`, `repo_id`, `skip_checks`, `skip_resources`, `skip_paths`,
`checks` (allowlist), `external_checks_dir`, `git_username`, `use_default_skip_checks`.
See `fetcher.yaml`.
Skip lists merge with `../_shared/skip-*.default.txt`; set `use_default_skip_checks: false`
to drop the shipped check defaults. The effective lists are recorded in
`metadata.skip_checks` and `metadata.skip_resources`.

`skip_resources` entries are globs over the whole resource name, e.g.
`Microsoft.Storage/storageAccounts.dev*`. A failed check on a matching resource is
moved to `skipped_checks`, not deleted, so it still counts in `total_checks` and
`summary.skipped_by_resource_filter` counts it.

If the requested branch cannot be cloned, the default branch is scanned and
`metadata.branch_fallback` is `true`.

## What counts as clean
`status: success` and exit 0 only when checkov ran at least one check and parsed
every file. Everything else exits 1, so the envelope reads `failed` with the
reason in `metadata.error`:

| `status` | When | Counts |
|---|---|---|
| `no_files` | no `.bicep` files and no `.json` with a `deploymentTemplate` `$schema` | `null` |
| `no_checks` | files found, but checkov evaluated nothing (e.g. resources only behind `br/public:avm` registry modules, which checkov cannot see) | `0`, percentage `null` |
| `partial` | checkov could not parse some files; they are listed in `results.parsing_errors` and `metadata.api_failures` | real counts for the rest |
| `error` | clone, TFVC download or checkov failed | `null` |

Checkov's Bicep parser lags the language, so newer syntax (nullable types,
user-defined types) often fails to parse. Review the listed files, then exclude
them with `skip_paths`. The run then passes, and the exclusion is on record in
the manifest and in `metadata.skip_paths`. `file_counts` still counts the
excluded files.
