# Contributing

Thanks for helping. There are three common ways in:

- **Ask for a platform or fetcher.** Post in
  [Fetcher requests](https://github.com/paramify/paramify-fetchers/discussions/categories/fetcher-requests),
  or upvote a request that's already there. Upvotes decide what gets built next.
- **Report a bug.** [Open an issue](https://github.com/paramify/paramify-fetchers/issues/new/choose).
  For anything security-related, follow [`SECURITY.md`](SECURITY.md) instead.
- **Send a fix or a new fetcher** as a pull request. The rest of this page covers that.

## Set up

```bash
git clone https://github.com/paramify/paramify-fetchers.git
cd paramify-fetchers
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,tui]'
```

Add `azure` or `gcp` to the extras if you're working on those fetchers.

## Before you open a pull request

Run what CI runs:

```bash
ruff check framework/
mypy framework/
pytest -q
```

`pytest` includes the contract tests, which check every `fetcher.yaml` and
category file against the schema. CI also runs
[gitleaks](https://github.com/gitleaks/gitleaks) over the history, so a
committed secret fails the build.

## Adding a fetcher

- [`docs/authoring_a_fetcher.md`](docs/authoring_a_fetcher.md) covers writing one
  from scratch, and [`docs/fetcher_contract.md`](docs/fetcher_contract.md) is the
  contract every fetcher must meet.
- For a platform nobody has integrated yet, start from
  [`docs/platform_onboarding_guide.md`](docs/platform_onboarding_guide.md).
- If the tool already produces findings (a vulnerability scan or a CSPM export),
  you want an issue-report fetcher instead:
  [`docs/issue_report_fetchers.md`](docs/issue_report_fetchers.md).
- Using Claude Code? The `create-fetcher` and `onboard-platform` skills in
  [`.claude/skills/`](.claude/skills/) walk through the same steps.

## Ground rules

- **Fetchers are read-only.** A fetcher reads from the platform and writes
  evidence to disk. It never changes the system it reads from, and it never calls
  Paramify; uploading is the uploader's job.
- **No real data in the repo.** Tests, fixtures, examples and PR descriptions use
  synthetic data. Never commit credentials, real evidence, account IDs or tenant
  names.
- **Keep changes focused.** One fetcher or one fix per pull request is easiest to
  review.
- **Update the changelog.** Add a line under `## [Unreleased]` in
  [`CHANGELOG.md`](CHANGELOG.md) for anything a user would notice. Changes to the
  public contract (the `fetcher.yaml`, manifest and envelope schemas, and the
  `paramify` CLI) follow [`docs/versioning_guide.md`](docs/versioning_guide.md).

## License

By contributing, you agree that your contributions are licensed under the
[GNU General Public License v3.0](LICENSE), the same license as the project.
