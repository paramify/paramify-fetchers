# Cutting a `paramify-fetchers` release

A release is a tag plus a GitHub Release, cut by hand. The pictures cut
`0.6.0` in a scratch copy.

![Flow: choose the version and edit the changelog, merge a release PR and tag its merge commit, then create the GitHub Release and check it](img/releasing/flow.svg)

**You need:** push access · [green CI](https://github.com/paramify/paramify-fetchers/actions) on `main` · a version from the [bump policy](versioning.md#bump-policy)

---

## 1. Start from a clean `main`

Confirm `gh` is signed in, then pull `main`.

![gh auth status showing a signed-in account, git pull already up to date, and git status showing a clean main](img/releasing/01-start.png)

<details><summary>Copy the commands</summary>

```bash
gh auth status
git checkout main && git pull
git status --short --branch
```
</details>

## 2. Update the changelog and version

In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - <today>`, add a fresh one above it,
repoint the bottom links, and bump `pyproject.toml`. **Every release so far is
a pre-release** (`v0.5.1-beta`). If this one is too, write `X.Y.Z-beta`
everywhere but `pyproject.toml`, and add `--prerelease` in step 5
([pre-releases](releasing.md#pre-releases)).

![git diff: a 0.6.0 heading under a fresh Unreleased heading, the Unreleased link moved to v0.6.0 plus a new 0.6.0 link, and the pyproject version bumped](img/releasing/02-diff.png)

<details><summary>Copy the link lines and the check</summary>

```markdown
[Unreleased]: https://github.com/paramify/paramify-fetchers/compare/vX.Y.Z...HEAD
[X.Y.Z]: https://github.com/paramify/paramify-fetchers/compare/vPREV...vX.Y.Z
```

```bash
git diff
```
</details>

## 3. Open the release PR

Open a PR so it passes CI and review, then merge it.

![git checkout -b release/v0.6.0, then git commit recording chore(release): v0.6.0 with two files changed](img/releasing/03-pr.png)

<details><summary>Copy the commands</summary>

```bash
git checkout -b release/vX.Y.Z
git commit -am "chore(release): vX.Y.Z"
gh pr create --fill
```
</details>

## 4. Tag the merge commit

Pull the merged `main`, then tag it.

![git pull fast-forwarding main to the merged release, git tag -a v0.6.0, and git push sending the new tag to GitHub](img/releasing/04-tag.png)

<details><summary>Copy the commands</summary>

```bash
git checkout main && git pull
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```
</details>

## 5. Create the GitHub Release

Preview the notes, then create the release with them.

![sed printing the 0.6.0 changelog section, from its heading down, which becomes the release notes](img/releasing/05-notes.png)

<details><summary>Copy the commands</summary>

```bash
sed -n '/## \[X.Y.Z\]/,/## \[/p' CHANGELOG.md | sed '$d'
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <(sed -n '/## \[X.Y.Z\]/,/## \[/p' CHANGELOG.md | sed '$d')
```
</details>

## 6. Check the release

Check the tag and notes. Here's the latest release:

![gh release view v0.5.1-beta: title and tag v0.5.1-beta, draft false, prerelease true](img/releasing/06-verify.png)

<details><summary>Copy the command</summary>

```bash
gh release view vX.Y.Z
```
</details>

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| The notes preview prints nothing | Match the `sed` pattern to the heading, including any `-beta`. |

**More detail:** [what a release doesn't touch](releasing.md#what-a-release-does-not-touch) ·
[release artifacts](releasing.md#artifacts) ·
[future automation](releasing.md#future-automation)
