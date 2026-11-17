# Release highlights

`paramify update` shows users a few short rows instead of the CHANGELOG. The
rows live here:

- `releases/unreleased.yaml` collects rows for changes on `main` since the
  last release.
- `releases/<version>.yaml` holds one release's rows, named as the CHANGELOG
  heading writes the version (`0.6.0-beta.yaml` for tag `v0.6.0-beta`).

Update compares these files at the commit a user runs with the same files at
the commit they are moving to, and shows the rows that are new. That works the
same for someone following `main` and someone moving between releases.

## When you change something

Add a row to `unreleased.yaml` in the same pull request, but only when the
change breaks something or is worth announcing. Most pull requests add none.
A pull request that adds an entry under `### Breaking` in the CHANGELOG's
`[Unreleased]` section must add a `breaking` row; a test fails if it doesn't.

```yaml
version: unreleased
highlights:
  # What is new. Tags: new, fetcher, cli, tui, improved, security, fix, deprecated.
  - tag: fetcher
    title: A Snowflake category with six fetchers     # one line, 72 chars max
    detail: Warehouses, roles, grants and query history  # optional, dimmed
    try: paramify describe snowflake_roles             # optional; shown at the end
    fetchers: [snowflake_*]                            # optional; globs work
  # One `breaking` row per Breaking entry in the CHANGELOG, each with a fix.
  - tag: breaking
    title: okta_mfa_status renames its output field
    fix: Update validators that read mfa_enrolled to read factors
    fetchers: [okta_mfa_status]     # names the user's manifests that use it
```

Write for the person running the tool: what they get, or what they must do.
Leave out how it was built.

## Who a breaking row touches

Update lists a breaking row, and stops an unattended run for it, only when it
touches the clone being updated:

| The row has | It touches |
|---|---|
| `fetchers: [...]` | clones whose manifests use one of those fetchers |
| `custom_fetchers: true` | clones that have their own fetcher directories (a change to the fetcher contract that no shipped fetcher is affected by) |
| neither | everyone (a Python version, a CLI flag) |

So scope a row whenever you can. An unscoped row stops every scheduled update
until someone reads it.

## When you cut a release

([releasing guide, step 2](../docs/releasing_guide.md#2-update-the-changelog-and-version))

1. `git mv releases/unreleased.yaml releases/<version>.yaml`
2. Set `version` to the release and, if you like, `date`.
3. Trim the non-breaking rows to the three to five that matter most. Keep
   every breaking row.
4. Start a new `releases/unreleased.yaml` with `version: unreleased` and
   `highlights: []`.

Rows a user has already seen on `main` are not shown again after the rename,
because update compares rows by tag and title, not by file.

## What the tests check

`tests/test_release_highlights.py` checks every file against
[the schema](../framework/schemas/release_highlights_schema.json) and that
every fetcher name or glob matches a real fetcher. For a release file it also
checks that the version has a CHANGELOG section, that a release with Breaking
entries has breaking rows, and that there are three to five other rows. For
`unreleased.yaml` it checks that there are at least as many breaking rows as
Breaking entries in `[Unreleased]`.
