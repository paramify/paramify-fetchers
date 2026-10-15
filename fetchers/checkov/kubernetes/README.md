# checkov_kubernetes

Runs [Checkov](https://www.checkov.io/) IaC security scanning over the Kubernetes
manifests in a repository and emits the result as JSON evidence.

A **scanner** fetcher (see `../terraform/README.md` for the archetype). Each
invocation shallow-clones one git repo with the per-target `GIT_CLONE_TOKEN`,
runs `checkov --framework kubernetes` over its `.yaml`/`.yml` files, and records
pass/fail/skip counts plus repo + commit provenance. The runner fans out across
repos.

## Runner dependencies
`git`, `checkov`, and `jq` on PATH (`checkov` via the top-level `requirements.txt`).

## Target (per repo)
Same as `checkov_terraform`: `repo_url` (`CHECKOV_REPO_URL`, required),
`branch` (`CHECKOV_CLONE_BRANCH`, optional), secret `clone_token`
(`GIT_CLONE_TOKEN`, per-target, omit for public repos).

## Config knobs
Two-tier skip model: `../_shared/skip-checks-k8s.default.txt` (a curated set of
commonly-failing/too-strict K8s checks, including security checks such as
`CKV_K8S_20` and `CKV_K8S_31`) is **merged** with `skip_checks`. Set
`use_default_skip_checks: false` to drop the defaults, so that `skip_checks`
alone (or nothing) is skipped. A check passed to `--skip-check` does not appear
anywhere in checkov's results, so the effective list is recorded in
`metadata.skip_checks`.

`soft_fail` (default true), `compact` (true), `repo_id`, `skip_checks`
(`CKV_K8S_*`/`CKV2_K8S_*` only), `use_default_skip_checks` (true), `skip_paths`,
`checks` (allowlist), `external_checks_dir`, `git_username`. See `fetcher.yaml`
for full descriptions.

## Output & exit codes
Writes `checkov_kubernetes_<repo>.json` with `metadata`, `summary`, and `results`.
`metadata` carries `repo_url`, `branch` (the branch actually scanned),
`requested_branch`, `branch_fallback` (true when the requested branch could not
be cloned and the default branch was scanned instead), `commit_sha`,
`scan_timestamp`, `skip_checks` and `default_skip_checks_applied`.

- **exit 0** — scan completed, including with failed checks (findings are
  evidence); also when the repo has no manifests (`status: no_files`).
- **exit 1** — could not clone, missing `CHECKOV_REPO_URL`, or checkov failed
  (`status: error`).
