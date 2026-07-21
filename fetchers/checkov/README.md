# Checkov

Checkov fetchers scan Terraform and Kubernetes infrastructure-as-code repositories for security misconfigurations. The fetcher clones the target repo via git, runs the `checkov` CLI against it, and writes a findings report with pass/fail/skipped check counts and per-check details.

## Prerequisites

Checkov must be installed in the environment running the fetcher:

```bash
pip install checkov
# Already included if you used: pip install -e '.[all]'
```

Checkov is also included in the [Docker image](../../deploy/README.md).

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `GIT_CLONE_TOKEN` | Yes (private repos) | Git credentials token for cloning (omit for public repos) |
| `CHECKOV_REPO_URL` | Yes | Clone URL of the repository to scan (e.g. `https://gitlab.example.com/group/project.git`) |
| `CHECKOV_CLONE_BRANCH` | No | Branch/ref to clone (default: repo default branch) |

`GIT_CLONE_TOKEN` is declared `per_target` in the fetcher schema — different repos in a single run can use different tokens.

## Supported git hosts

Checkov fetchers work with any git host that supports HTTPS token authentication — GitLab, GitHub, Bitbucket, Azure DevOps, etc. The token is embedded in the clone URL as basic-auth credentials (`oauth2:<token>` for GitLab/GitHub).

**GitLab:** Create a Project Access Token with `read_repository` scope (see [`../gitlab/README.md`](../gitlab/README.md) for steps). The same token works for both the GitLab fetchers and Checkov.

**GitHub:** Create a Personal Access Token (classic) or a fine-grained PAT with `Contents: Read` permission on the target repository.

## Wiring into a manifest

Checkov fetchers are fanout — each target is one repository. Use `add-target` once per repo:

```bash
paramify manifest add checkov_terraform

# First repo
paramify manifest add-target checkov_terraform \
  repo_url=https://gitlab.example.com/group/terraform.git \
  branch=main \
  --secret clone_token=GITLAB_API_TOKEN

# Second repo (can use a different token)
paramify manifest add-target checkov_terraform \
  repo_url=https://gitlab.example.com/group/infra.git \
  --secret clone_token=INFRA_GITLAB_TOKEN
```

For public repos, omit `--secret clone_token`.

## Smoke test

```bash
# Verify checkov is installed
checkov --version

# Verify git clone works (replace with your actual URL and token)
git clone https://oauth2:$GIT_CLONE_TOKEN@gitlab.example.com/group/terraform.git /tmp/checkov-test
ls /tmp/checkov-test/*.tf
rm -rf /tmp/checkov-test
```

## Notes

- Checkov fetchers have a default 1800-second (30-minute) timeout per invocation — scanning large repos with external modules can be slow. Override with `runtime.timeout` in `fetcher.yaml` if needed.
- `CHECKOV_SOFT_FAIL` defaults to `true` — IaC findings are recorded as evidence, not treated as fetcher failures. Set `false` if you want a non-zero exit on any finding.
- See `paramify describe checkov_terraform` for the full list of optional configuration fields (skip lists, check allowlists, deep analysis mode, etc.).
