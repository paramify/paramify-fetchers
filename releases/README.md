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
  # What is new. Tags for a minor release: new, fetcher, cli, tui (and breaking).
  # Tags for a patch release: improved, fix, security, deprecated.
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

The tags set the size of the next release:

| The release has | The bump |
|---|---|
| a `new`, `fetcher`, `cli` or `tui` row, or a fetcher that is new | minor |
| a `breaking` row | minor while the version is 0.x, major from 1.0 |
| only `improved`, `fix`, `security` or `deprecated` rows, or no rows | patch |

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

## Fetcher lines

A release file can also have a `fetchers` list. It has one line for each
fetcher that changed in the release. Do not write these lines in a pull
request. The person who cuts the release drafts them.

```yaml
fetchers:
  - name: okta_mfa_status
    version: 0.7.0
    note: Reads factors for every user, not only the first page
```

Each line needs `name`, `version` and `note`. The `note` has one line of 110
characters or fewer.

## Draft marks

A row or a fetcher line can have `draft: true`. The mark means a person has
not yet checked the text. A test fails if any file in `releases/` keeps a
draft mark. Remove the mark when you have checked the text. A fetcher note
must not start with `TODO`.

## When a release comes out

A workflow drafts the release file each week and opens a pull request. In the
first draft, every row and fetcher line has a draft mark. After a rebuild,
only the new text has one. Read each marked row and line, and rewrite its
text. Then remove the mark.

You can delete a row. Do not delete a fetcher line: the release check fails
without it, and a rebuild adds it again. Edit its `note`. Follow
[the releasing guide](../docs/releasing_guide.md).

Rows that a user already saw on `main` are not shown again after a release.
Update compares rows by tag and title.

## What the tests check

`tests/test_release_highlights.py` checks every file against
[the schema](../framework/schemas/release_highlights_schema.json) and that
every fetcher name or glob matches a real fetcher. For a release file it also
checks that the version has a CHANGELOG section and that a release with
Breaking entries has at least as many breaking rows. It also checks that no
file has a draft mark, that no fetcher note starts with `TODO`, and that each
`fetchers` line names a real fetcher. For `unreleased.yaml` it checks that
there are at least as many breaking rows as Breaking entries in
`[Unreleased]`.
