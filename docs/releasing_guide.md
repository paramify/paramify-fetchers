# Releasing `paramify-fetchers`

A release comes out every week. A workflow builds the release pull request
(PR) for you. You review it and merge it. A second workflow then tags the
commit and creates the GitHub Release.

**You need:** push access to the repository and the one-time setup in
[section 6](#6-one-time-setup).

---

## 1. What arrives

On Thursday at 15:00 UTC, the `release-draft` workflow runs. It does two
things:

- It opens a PR from `release/next` named `Release vX.Y.Z`. You are the
  assignee and the reviewer.
- It sends you a Slack direct message (DM) with a link to the PR.

The PR holds three changes:

- `CHANGELOG.md`: the `[Unreleased]` section becomes the new version.
- `pyproject.toml`: the new version number.
- `releases/<version>.yaml`: the highlights that `paramify update` shows to
  users. The workflow drafts this file from `releases/unreleased.yaml`, the
  CHANGELOG and the git history.

If nothing changed since the last release, no PR opens. If the PR is still
open on the next Thursday, you get a reminder DM.

The `release-check` check and pytest fail on the new PR. This is correct. The
draft text has `draft: true` marks, and a mark means that a person has not
yet read the text.

## 2. What to do in the PR

1. Open `releases/<version>.yaml` in the PR.
2. Read each row and each fetcher line that has `draft: true`. Rewrite it, or
   delete it. Write for the person who runs the tool: what they get, or what
   they must do. See [the releases README](../releases/README.md).
3. Remove `draft: true` from each line that you keep.
4. Keep every `breaking` row. A test fails if a CHANGELOG Breaking entry has
   no breaking row.
5. Wait for CI to pass. Then merge the PR.

You can edit the file in the GitHub web editor, or check out `release/next`
and push to it. The release file is the only place where hand edits survive
a rebuild.

Do not fix a CHANGELOG mistake on `release/next`. Fix it on `main` in an
ordinary PR. The workflow rebuilds `release/next` after each push to `main`
while the release PR is open, and the rebuild replaces the CHANGELOG and
`pyproject.toml` changes.

When you merge, the `release-publish` workflow creates the tag `vX.Y.Z` and
the GitHub Release. You get a DM when it is out.

### What a rebuild keeps

A rebuild reads `origin/release/next`. It keeps the rows and lines that you
edited. A row that you deleted stays deleted. A row that came to `main` after
the last build arrives with `draft: true`. A fetcher line keeps its note when
the fetcher changed again, but gets the new version and a new mark. A line for
a fetcher that no longer changed is dropped.

Rows that a user already saw on `main` are not shown again after a release.
`paramify update` compares rows by tag and title, so a row that was in
`unreleased.yaml` when the user last updated is not new to them.

## 3. What a `release-check` failure means

The `release-check` job runs `python tools/release.py check`. Each failure is
one line that names the fetcher or version to fix:

| The line says | What to do |
|---|---|
| `NAME VERSION has no fetcher line` | Add a `fetchers` line with `name`, `version` and `note`. |
| `NAME has N fetcher lines; keep one` | Delete the extra lines. |
| `NAME has a line but did not change since vX` | Delete the line, or set its `version` to the new version of the fetcher. |
| `expected X (reason), found Y` | Set `version` to X. The reason says why the bump is that size. |

Draft marks and missing breaking rows fail pytest, not `release-check`. See
[the releases README](../releases/README.md).

The job runs only on PRs from `release/next`. The `ci-ok` check passes only
when `release-check` passes.

## 4. Run a command by hand

You can run each step on your own machine. Install the package with
`python -m pip install -e .` first. Set `GH_TOKEN` to a token that can write
to the repository.

| Command | What it does |
|---|---|
| `python tools/release.py draft` | Builds or rebuilds `release/next` and its PR. |
| `python tools/release.py draft --version X.Y.Z` | The same, with a version that you choose. |
| `python tools/release.py draft --no-push` | A dry run. It sends nothing. |
| `python tools/release.py check --ref REF` | Lists what to fix in the release file at `REF`. |
| `python tools/release.py publish --head-sha SHA --merge-sha SHA` | Tags the reviewed commit and creates the GitHub Release. |
| `python tools/release.py notify-failure --url URL` | Sends the failure DM. |

`draft` never touches your local branches or your checkout. It fetches
`origin`, builds the commit in a temporary worktree, and pushes it to
`release/next` on `origin`.

`--no-push` builds the commit and leaves it with no branch. It prints the
commit sha. Read the release file with
`git show <sha>:releases/<version>.yaml`. Git can delete the commit after
about two weeks.

Set `RELEASE_REMINDER=1` to remind when a PR is still open. Set
`RELEASE_REVIEWER` to change who reviews (the default is `21tmccauley`). Set
`SLACK_RELEASE_WEBHOOK` to send the DM. Without it, the command prints the
message.

## 5. The three workflows

| Workflow | When it runs | What it does |
|---|---|---|
| `release-draft` | Thursday 15:00 UTC, or by hand | Runs `draft`. The by-hand run has an optional `version` input. |
| `release-redraft` | Each push to `main` | Runs `draft` only if a release PR is open. |
| `release-publish` | A merged PR from `release/next` | Runs `publish`. |

All three use the same `release` concurrency group, so two runs never overlap.
All three use the GitHub App token, not `GITHUB_TOKEN`. A PR that
`GITHUB_TOKEN` opens does not start CI, and `ci-ok` would never report.
Each workflow sends a failure DM with a link to its run.

## 6. One-time setup

1. **GitHub App.** In the `paramify` organization, create the App
   `paramify-fetchers-release`. Install it on this repository only. Give it
   these permissions: Contents read and write, Pull requests read and write,
   Metadata read. Create a private key for it.
2. **Repository secrets.** Add `RELEASE_APP_ID` (the App ID) and
   `RELEASE_APP_PRIVATE_KEY` (the whole key file).
3. **Slack workflow.** In Slack Workflow Builder, create a workflow with a
   webhook trigger. Give the trigger the variables `text` and `url`. Add one
   step that sends a DM to the release owner with `text` and `url`. Publish
   the workflow. Add its webhook URL as the repository secret
   `SLACK_RELEASE_WEBHOOK`.
4. **Ruleset.** The `protect-main` ruleset already requires `ci-ok`. You do
   not need to change it.

## 7. Troubleshooting

**No PR arrived on Thursday.** Nothing changed since the last release. Look at
the run of `release-draft` in the Actions tab.

**The failure DM arrived.** Open the run link. The last line of the log says
what to do.

**A `release/next` branch exists but has no open PR.** The workflow treats it
as a new draft. The next run replaces the branch.

**`publish` refuses to tag.** The tree on `main` differs from the reviewed
commit, or a draft mark remains. Fix the cause in a PR to `main`. Then run
`publish` by hand with the head sha and the merge sha of the release PR.

**The push to `release/next` is refused.** Someone pushed to the branch while
the workflow ran. Run `release-draft` again.

**CI does not run on the release PR.** The PR was not opened with the App
token. Check the secrets in section 6.
