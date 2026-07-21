# Releasing

How we cut a release today: **manual and tag-driven**. Releases are curated —
we do *not* release on every merge, because customers run this in production.
The version and changelog are maintained by hand against the
[versioning policy](versioning.md); automation
([release-please](https://github.com/googleapis/release-please)) is a future
upgrade when cadence justifies it (see [below](#future-automation)).

## Prerequisites

- The [`gh`](https://cli.github.com/) CLI, authenticated (`gh auth status`).
- On an up-to-date `main` with a clean working tree.
- CI green on `main`.
- A version chosen per the [bump policy](versioning.md#bump-policy). Pre-1.0, a
  breaking change bumps the **minor**, not the major.

## Steps

Using `X.Y.Z` as the version (no `v` in files; the **tag** is `vX.Y.Z`).

1. **Update `CHANGELOG.md`.** Rename the `## [Unreleased]` heading to
   `## [X.Y.Z] - YYYY-MM-DD` (today's date), add a fresh empty `## [Unreleased]`
   above it, and update the link references at the bottom:

   ```markdown
   [Unreleased]: https://github.com/paramify/paramify-fetchers/compare/vX.Y.Z...HEAD
   [X.Y.Z]: https://github.com/paramify/paramify-fetchers/compare/vPREV...vX.Y.Z
   ```

2. **Bump the version** in `pyproject.toml` (`version = "X.Y.Z"`).

3. **Commit** on a branch and open a PR (so it passes CI / review like anything
   else):

   ```bash
   git checkout -b release/vX.Y.Z
   git commit -am "chore(release): vX.Y.Z"
   gh pr create --fill
   ```

4. **Merge** the PR into `main`.

5. **Tag the merge commit** and push the tag:

   ```bash
   git checkout main && git pull
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

6. **Create the GitHub Release** from the tag, with the changelog section as the
   notes:

   ```bash
   gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <(sed -n '/## \[X.Y.Z\]/,/## \[/p' CHANGELOG.md | sed '$d')
   ```

   GitHub automatically attaches the **source code** as `.tar.gz` and `.zip` to
   every release — that is our release artifact for now (see
   [Artifacts](#artifacts)). Add `--generate-notes` if you also want GitHub's
   auto-generated commit/PR list appended.

7. **Verify:** `gh release view vX.Y.Z` — confirm the notes, the tag, and that
   the source archives are attached.

## Pre-releases

For dogfood / early-customer builds, tag a pre-release and flag it so it doesn't
show as "Latest":

```bash
git tag -a vX.Y.Z-rc.1 -m "vX.Y.Z-rc.1"
git push origin vX.Y.Z-rc.1
gh release create vX.Y.Z-rc.1 --title "vX.Y.Z-rc.1" --prerelease --generate-notes
```

Use `-rc.N` (release candidate) or `-beta.N`. These sort before the final
`vX.Y.Z` under SemVer.

## Artifacts

- **Now:** the GitHub-attached **source tarball/zip**. The supported install is
  from source (`pip install -e .`), so the source archive is the artifact.
- **Deferred:** wheel/sdist + PyPI publishing. Blocked on the editable-only /
  cwd-repo-root packaging issue (schemas resolve via the discovered repo root,
  and fetchers execute as subprocesses out of `fetchers/`, which a plain wheel
  doesn't ship). Revisit when that's fixed; a build+publish step then slots into
  step 6.

## What a release does *not* touch

Only the **tool version** (tag + `pyproject.toml`) moves here. The envelope
`schema_version` and each fetcher's `version` are edited in their own files as
part of the change that alters them — see
[the three version axes](versioning.md#the-three-version-axes). Call them out in
the changelog entry so consumers notice.

## Future automation

When release cadence justifies removing the manual toil, adopt `release-please`
(`release-type: python`, `bump-minor-pre-major: true` to keep the pre-1.0 rule).
It maintains the changelog and version bump in a rolling release PR; merging it
tags and cuts the Release. Two things to wire at that point: enable *Settings →
Actions → "Allow GitHub Actions to create and approve pull requests"*, and build
the source tarball **inside** the release-please workflow gated on
`release_created` (a tag made by the default `GITHUB_TOKEN` won't trigger a
separate on-tag workflow).
