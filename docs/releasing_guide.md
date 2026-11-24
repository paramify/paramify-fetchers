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
- It posts a message with a link to the PR in the Slack channel
  `#paramify-fetchers-repo`.

The PR holds four changes:

- `CHANGELOG.md`: the `[Unreleased]` section becomes the new version.
- `pyproject.toml`: the new version number.
- `releases/<version>.yaml`: the highlights that `paramify update` shows to
  users. The workflow drafts this file from `releases/unreleased.yaml`, the
  CHANGELOG and the git history.
- `releases/unreleased.yaml`: reset to an empty list, because its rows moved
  to the release file.

If nothing changed since the last release, no PR opens. If the PR is still
open on the next Thursday, the channel gets a reminder.

Pytest fails on the new PR. This is correct. The draft text has `draft: true`
marks, and a test fails while any mark remains. A mark means that a person has
not yet read the text.

## 2. What to do in the PR

1. Open `releases/<version>.yaml` in the PR.
2. Read each row and each fetcher line that has `draft: true`. Rewrite its
   text. Write for the person who runs the tool: what they get, or what they
   must do. See [the releases README](../releases/README.md).
   - You can delete a row in `highlights`.
   - Do not delete a fetcher line. `release-check` fails without it, and a
     rebuild adds it again. Edit its `note`.
3. Remove `draft: true` from each row and line that you keep.
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
the GitHub Release. The channel gets a message when it is out.

### What a rebuild keeps

A rebuild reads `origin/release/next`. It keeps the rows and lines that you
edited. A row that you deleted stays deleted. A row that came to `main` after
the last build arrives with `draft: true`. A fetcher line keeps its note when
the fetcher changed again, but gets the new version and a new mark. A line for
a fetcher that no longer changed is dropped.

A version that you set with `draft --version` stays when it is the version
that the changes call for, or later. If the changes call for a later
version, the rebuild uses that version.

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
| `NAME has a line but did not change since vX` | Delete the line. |
| `NAME line says X but the fetcher is Y` | Set the `version` of the line to Y. |
| `expected X or later (reason), found Y` | Rebuild the release. Run the `release-draft` workflow by hand with an empty `version`, or run `python tools/release.py draft --version X`. The reason says why the bump is that size. |

Do not only change `version` in the file. The version is also in the file
name, the CHANGELOG heading and links, and `pyproject.toml`. A rebuild
starts from your edited release file and changes all of them.

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
| `python tools/release.py notify-failure --url URL` | Posts the failure message. |

`draft` never touches your local branches or your checkout. It runs
`git fetch --prune --tags origin`, which updates your remote-tracking branches
and your tags. Then it builds the commit in a temporary worktree, and pushes it to
`release/next` on `origin`.

`--no-push` builds the commit and leaves it with no branch. It prints the
commit sha. Read the release file with
`git show <sha>:releases/<version>.yaml`. Git can delete the commit after
about two weeks.

Set `RELEASE_REMINDER=1` to remind when a PR is still open. Set
`RELEASE_REVIEWER` to change who reviews (the default is `21tmccauley`). Set
`SLACK_RELEASE_WEBHOOK` to post the message. Without it, the command prints
the message.

## 5. The three workflows

| Workflow | When it runs | What it does |
|---|---|---|
| `release-draft` | Thursday 15:00 UTC, or by hand | Runs `draft`. The by-hand run has an optional `version` input: the version that the changes call for, or later. |
| `release-redraft` | Each push to `main` | Runs `draft` only if a release PR is open. |
| `release-publish` | A merged PR from `release/next` | Runs `publish`. |

`release-draft` and `release-redraft` use the `release` concurrency group, so
two drafts never overlap. `release-publish` has its own group,
`release-publish`, so a new draft cannot cancel a publish that waits to run.
A draft that runs after the merge and before the tag stops, and tells you to
run `publish`.

All three use the GitHub App token, not `GITHUB_TOKEN`. A PR that
`GITHUB_TOKEN` opens does not start CI, and `ci-ok` would never report.
Each workflow posts a failure message with a link to its run.

## 6. One-time setup

1. **GitHub App.** In the `paramify` organization, create the App
   `paramify-fetchers-release`. Install it on this repository only. Give it
   these permissions: Contents read and write, Pull requests read and write,
   Metadata read, Workflows read and write. A rebuild pushes `release/next` from
   an old `main` to a new one, and GitHub refuses that push without the
   Workflows permission if `main` changed `.github/workflows` in between.
   Create a private key for it.
2. **Repository secrets.** Add `RELEASE_APP_ID` (the App ID) and
   `RELEASE_APP_PRIVATE_KEY` (the whole key file).
3. **Slack workflow.** In Slack Workflow Builder, create a workflow with a
   webhook trigger. Give the trigger the variables `text` and `url`. Add one
   step that sends a message to the channel `#paramify-fetchers-repo` with
   `text` and `url`. Publish
   the workflow. Add its webhook URL as the repository secret
   `SLACK_RELEASE_WEBHOOK`.
4. **Ruleset.** The `protect-main` ruleset already requires `ci-ok`. You do
   not need to change it.

## 7. Troubleshooting

**No PR arrived on Thursday.** Nothing changed since the last release. Look at
the run of `release-draft` in the Actions tab.

**The failure message arrived.** Open the run link. The last line of the log says
what to do.

**A `release/next` branch exists but has no open PR.** The workflow treats it
as a new draft. The next run replaces the branch.

**`publish` says a draft mark remains.** Remove the marks in an ordinary PR to
`main`. Then run `python tools/release.py publish --head-sha SHA --merge-sha SHA`
with the merge commit of that PR as both `SHA` values.

**`publish` says the tree on `main` differs.** The release PR was merged
(squashed) before a rebuild finished, so `main` holds a different commit than
the one you reviewed. Find the commit on `main` that holds the reviewed
`releases/<version>.yaml`. Run `publish` with that commit as both `--head-sha`
and `--merge-sha`. It tags the commit and creates the GitHub Release.

**The push to `release/next` is refused.** Someone pushed to the branch while
the workflow ran. Run `release-draft` again.

**CI does not run on the release PR.** The PR was not opened with the App
token. Check the secrets in section 6.
