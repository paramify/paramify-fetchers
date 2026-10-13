# checkov_terraform

Runs [Checkov](https://www.checkov.io/) IaC security scanning over a Terraform
repository and emits the result as JSON evidence.

This is a **scanner** fetcher: unlike API-based fetchers, it acquires its own
source. Each invocation shallow-clones one git repo (any host) with the
per-target `GIT_CLONE_TOKEN`, runs `checkov --framework terraform` over its `.tf`
files, and records the pass/fail/skip counts plus repo + commit provenance.
Fanout (one invocation per repo) happens in the runner.

## Runner dependencies
`git`, `checkov`, and `jq` must be on PATH. `checkov` is in the top-level
`requirements.txt` (`pip install -r requirements.txt`); `git`/`jq` are system tools.

## Target (per repo)
| Field | Env | Required | Notes |
|---|---|---|---|
| `repo_url` | `CHECKOV_REPO_URL` | yes | `https://host/group/project.git` |
| `branch` | `CHECKOV_CLONE_BRANCH` | no | defaults to `main`, falls back to repo default |
| secret `clone_token` | `GIT_CLONE_TOKEN` | per-target | omit for public repos |

The token is injected as `https://<git_username>:<token>@…` (`git_username`
defaults to `oauth2`, which works for GitLab and GitHub). The credentialed URL is
never logged.

## Config knobs
Two-tier skip model: shipped defaults in `../_shared/skip-checks.default.txt` and
`skip-resources.default.txt` are **merged** with the config values below.
`skip_resources` entries are globs over the whole resource name (`*` is the only
wildcard), so a module resource needs a leading `*`: `*aws_s3_bucket.dev_*`.

`soft_fail` (default true), `compact` (true), `download_external_modules` (true),
`evaluate_variables` (true), `repo_id`, `skip_checks`, `skip_resources`,
`skip_paths`, `checks` (allowlist), `external_checks_dir`, `external_modules_path`,
`git_username`, `terraform_plan_file`, `deep_analysis`. See `fetcher.yaml` for the
full descriptions and env mappings.

Set shared values once for the whole category in a manifest under
`platforms.checkov.config`, or per fetcher / per entry.

## Plan-file mode
If `terraform_plan_file` points at a JSON file inside the repo (or the repo
contains `tfplan.json`), checkov scans the plan instead of the directory, with
`--repo-root-for-plan-enrichment` set to the clone. `deep_analysis` applies only
in plan mode. A fresh clone has no plan file unless the repo commits one.

## Output & exit codes
Writes `checkov_terraform_<repo>.json` into `EVIDENCE_DIR` with `metadata`
(`repo_url`, `branch`, `commit_sha`, `scan_timestamp`), `summary`, and `results`.

- **exit 0** — scan completed, *including when it found failed checks* (findings
  are evidence). Also 0 when the repo has no Terraform files (`status: no_files`).
- **exit 1** — could not clone, missing `CHECKOV_REPO_URL`, or checkov failed to
  run (`status: error`).
