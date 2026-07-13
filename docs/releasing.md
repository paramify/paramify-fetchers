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
   every release. Add `--generate-notes` if you also want GitHub's
   auto-generated commit/PR list appended.

7. **Build and attach the wheel** (the pipx-installable artifact — see
   [Artifacts](#artifacts)). The `setup.py` build hook assembles the
   `framework/_bundled/` content snapshot into it:

   ```bash
   .venv/bin/pip wheel --no-deps --no-build-isolation -w dist .
   gh release upload vX.Y.Z dist/*.whl
   ```

8. **Bump the Homebrew tap** (if published): stamp the new tarball url/sha256
   and regenerate the python resources — see
   [`packaging/brew/README.md`](../packaging/brew/README.md).

9. **Verify:** `gh release view vX.Y.Z` — confirm the notes, the tag, the
   source archives, and the wheel.

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

- **Source tarball/zip** — attached by GitHub automatically. Installs work from
  source (`pip install .` — the build hook assembles the content bundle) and
  editable in a clone (`pip install -e .`).
- **Wheel** — built and attached in step 7; carries the engine, schemas, the
  `framework/_bundled/` content snapshot, and the uploader. This is the
  **pipx** path (the universal install: Mac/Windows/Linux):

  ```bash
  pipx install https://github.com/paramify/paramify-fetchers/releases/download/vX.Y.Z/paramify_fetchers-X.Y.Z-py3-none-any.whl
  ```

  Upgrading to a new release is `pipx install --force <new wheel url>`.
  Caveat (found in dist testing): pipx ≥ 1.15 with the uv backend can fail
  `--force` into an existing venv (`uv venv` refuses to overwrite, exit 1,
  old version left in place) — prepend `UV_VENV_CLEAR=1`, or
  `pipx uninstall paramify-fetchers` first.

  (The former blocker — cwd-repo-root schemas, unshipped fetchers — was removed
  by the overlay distribution work; see `docs/distribution_design.md`.)
- **Homebrew tap** — the Mac/Linux convenience layer on top; can also declare
  the external CLIs (`aws`/`kubectl`/`jq`/`git`/`checkov`) as dependencies.
  Formula template + bump procedure: [`packaging/brew/`](../packaging/brew/README.md).
- **Deferred: PyPI publishing.** Nothing blocks it anymore technically; it's a
  distribution-channel decision (name squatting, support expectations), not a
  packaging one.

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
