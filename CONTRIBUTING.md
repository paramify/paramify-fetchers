# Contributing

Thank you for your help. Most contributions start in one of three places:

- **Ask for a platform or fetcher.** Post in
  [Fetcher requests](https://github.com/paramify/paramify-fetchers/discussions/categories/fetcher-requests),
  or upvote a request that is already there. Upvotes decide what we build next.
- **Report a bug.** [Open an issue](https://github.com/paramify/paramify-fetchers/issues/new/choose).
  For a security problem, use the process in [`SECURITY.md`](SECURITY.md) instead.
- **Send a fix or a new fetcher** as a pull request. The rest of this page is
  about pull requests.

## Set up

```bash
git clone https://github.com/paramify/paramify-fetchers.git
cd paramify-fetchers
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,tui]'
```

To work on Azure or GCP fetchers, add `azure` or `gcp` to the extras.

## Before you open a pull request

Run the same checks that CI runs:

```bash
ruff check framework/
mypy framework/
pytest -q
```

The `pytest` run includes the contract tests. These tests compare every
`fetcher.yaml` and category file with the schema. CI also runs
[gitleaks](https://github.com/gitleaks/gitleaks) on the history, so a committed
secret makes the build fail.

## Adding a fetcher

- To write a fetcher from scratch, read
  [`docs/authoring_a_fetcher.md`](docs/authoring_a_fetcher.md).
  [`docs/fetcher_contract.md`](docs/fetcher_contract.md) gives the contract that
  every fetcher must meet.
- For a platform that has no fetchers yet, start from
  [`docs/platform_onboarding_guide.md`](docs/platform_onboarding_guide.md).
- Some tools already produce findings, for example a vulnerability scan or a
  CSPM export. For these tools, write an issue-report fetcher:
  [`docs/issue_report_fetchers.md`](docs/issue_report_fetchers.md).
- If you use Claude Code, the `create-fetcher` and `onboard-platform` skills in
  [`.claude/skills/`](.claude/skills/) do the same steps with you.

## Ground rules

- **Fetchers are read-only.** A fetcher reads from the platform and writes
  evidence to disk. It never changes the system that it reads from. It never
  calls Paramify, because uploads are the job of the uploader.
- **No real data in the repo.** Tests, fixtures, examples and pull request
  descriptions use synthetic data. Never commit credentials, real evidence,
  account IDs or tenant names.
- **Keep each change small.** A pull request with one fetcher or one fix is the
  easiest to review.
- **Update the changelog.** If a user can see the change, add a line under
  `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md). Changes to the public
  contract obey [`docs/versioning_guide.md`](docs/versioning_guide.md). The
  public contract is the `fetcher.yaml`, manifest and envelope schemas, and the
  `paramify` CLI.

## License

The project uses the [GNU General Public License v3.0](LICENSE). When you
contribute, you agree to license your contribution under the same license.
