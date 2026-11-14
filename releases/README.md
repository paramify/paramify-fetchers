# Release highlights

`paramify update` shows users a short "what's new" card instead of the
CHANGELOG. Each release gets one file here, `releases/<version>.yaml`, named as
the CHANGELOG heading writes the version (`0.6.0-beta.yaml` for tag
`v0.6.0-beta`). A release without a file still updates; the card links to its
CHANGELOG section instead.

Write it when you cut the release ([releasing guide, step 2](../docs/releasing_guide.md#2-update-the-changelog-and-version)),
from the `[Unreleased]` section you are renaming.

```yaml
version: 0.7.0-beta
date: 2026-12-01            # optional; defaults to the CHANGELOG heading's date
highlights:
  # 3 to 5 rows of what is new. Tags: new, fetcher, cli, tui, improved,
  # security, fix, deprecated.
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
Leave out how it was built. `fetchers` on a breaking row is what lets update
say "affects manifests/prod.yaml"; leave it off only when the change touches
everyone (a Python version, a CLI flag).

`tests/test_release_highlights.py` checks every file against
[the schema](../framework/schemas/release_highlights_schema.json), that the
version has a CHANGELOG section, that a release with Breaking entries has
breaking rows, that there are 3 to 5 other rows, and that every fetcher name
or glob matches a real fetcher.

A file added after its release was tagged reaches users from the next release
on, because update reads these files from the tree it moves to.
