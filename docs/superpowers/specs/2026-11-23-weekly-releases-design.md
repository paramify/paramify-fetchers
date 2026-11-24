# Weekly releases with hand-written update notes

Date: 2026-11-23. Branch: `docs/weekly-releases-design`. Status: draft, for Tate's review. Questions from the builder check answered by Tate, 2026-11-23.

## Why

`paramify update` and the TUI's update screen (`U`) already show short notes
instead of the CHANGELOG (design: `2026-11-16-paramify-update-channels-design.md`).
But nobody gets a release:

- The last release is `v0.6.0-beta`, 2026-10-23. Cutting one is six manual
  steps (`docs/releasing_guide.md`), so it doesn't happen.
- `install.sh` clones `main`, and every customer follows `main`. They see a
  note the moment its pull request merges, one at a time, so a release would
  change nothing for them.
- The notes on "your fetchers" come from commit subjects
  (`update.fetcher_reason`). They are often blank, and when present they read
  like developer notes.

Tate wants a release every week, with notes a person wrote, that a user reads
on update and comes away knowing three things:

1. **What's new**: the new features.
2. **What breaks**: the breaking changes that touch them, and what to do.
3. **Whether their fetchers changed**: each fetcher their manifests use that
   changed, and why, in plain words.

## Goals

1. A new install follows releases. `paramify update --to main` (already built)
   moves a clone to `main`; `--to <tag>` moves it back.
2. Each release's notes file holds hand-written rows for new features, breaking
   changes, and one line per changed fetcher.
3. The update screen (CLI and TUI) shows those three sections, grouped by
   release, so a user several releases behind can tell which week each note
   came from.
4. Releasing is automated. Once a week a job drafts the release and opens a
   pull request. Tate gets a Slack DM, edits the notes in the PR, and merges.
   Merging tags and publishes the release, and Tate gets a DM that it's out.
5. CI refuses a release whose notes are incomplete, unreviewed, or carry the
   wrong version number.
6. The first release, `0.7.0-beta`, ships through the same path.

## Non-goals

- A free-text summary paragraph per release. The three sections are what Tate
  asked for. Can be added later as an optional field.
- Moving existing customers off `main`, by hint or automatically. They are
  told directly (see "Customers already on `main`"); the move is theirs.
- Hand-written fetcher notes for clones that follow `main`. Between releases
  they keep today's commit-subject notes. `main` is the early-access channel.
- PyPI packages, containers, or any distribution other than the git clone.
- Changing how the CHANGELOG is written. It stays the maintainer record.

## Anti-goals

- **A release that skips Tate.** No release is published without a person
  reading every drafted line. CI enforces this (`draft: true`, below).
- **Breaking rows that old clones can't see.** A clone running today's update
  code must still find and stop on breaking rows in new release files.
- **A weekly chore that grows.** If the PR takes more than about 15 minutes to
  review in a normal week, the drafting is not good enough.
- **Empty releases.** A week with no change publishes nothing and sends no
  ping.

## Approaches considered

- **A. A Python release script run by GitHub Actions (chosen).**
  `tools/release.py` holds all the logic, with `draft`, `check` and `publish`
  commands. Two small workflows call it. Testable, and Tate can run it on a
  laptop for a mid-week release, or when the workflow breaks.
- **B. The steps written directly in workflow YAML and shell.** Rejected:
  can't be tested or run locally, and version picking and CHANGELOG parsing
  are too fiddly for shell.
- **C. release-please.** Rejected: it writes notes from commit messages, not
  from our notes file, so there is no draft to edit and no `draft: true` gate;
  it picks versions from commit prefixes. The July decision against it for its
  overhead still holds.

Fetcher notes source, also decided: **drafted from the CHANGELOG, edited by
Tate** (over commit subjects, which are often blank, and writing every line
from scratch, which is too much work in a 30-fetcher week).

## Design

### 1. The notes file

`releases/<version>.yaml` keeps its current shape and gains one top-level key,
`fetchers`. `releases/unreleased.yaml` is unchanged: pull request authors keep
adding `new`/`breaking`-style rows to `highlights` as `releases/README.md`
says today.

```yaml
version: 0.8.0-beta
date: 2026-12-03
highlights:                       # unchanged shape: what's new, and breaking rows
  - tag: tui
    title: The TUI pairs and updates validators that already exist
    detail: Press v on the Paramify tab; one preview covers create, pair and update
    try: paramify tui
  - tag: breaking
    title: azure_aks_cluster_configuration renames node_pools to pools
    fix: Update validators that read node_pools to read pools
    fetchers: [azure_aks_cluster_configuration]
fetchers:                         # new: one line per fetcher whose version went up
  - name: azure_aks_cluster_configuration
    version: 0.7.0                # the version this release ships
    note: Checks that the node pools you list have the autoscaler on
  - name: aws_inspector_ecr_report
    version: 0.3.0
    note: Counts every image in scope, and can allow a scope with no images
    draft: true                   # written by the draft job, not yet read by Tate
```

Rules (enforced by the schema and the test, section 4):

- `fetchers[].name` is a real fetcher; `version` equals that fetcher's
  `fetcher.yaml` version at the release commit; `note` is one line, at most
  110 characters, written for the person running the fetcher.
- `draft: true` may appear on any `highlights` row or `fetchers` line. It may
  exist only on a `release/next` branch; it never reaches `main`.
- Breaking rows stay in `highlights`, never in `fetchers`. That is what keeps
  them visible to clones running older update code: `update._highlight_files`
  reads `highlights` rows loosely and ignores unknown keys.

Schema: `framework/schemas/release_highlights_schema.json` gains `fetchers`
and `draft`. The top-level `additionalProperties: false` stays.

### 2. What the update screen shows

Same three sections in today's order (Your fetchers, Breaking, New), fed by
the notes. Shared by the CLI
(`framework/update_view.py`) and the TUI (`framework/tui/screens/update.py`),
which already reuses the view functions.

```
v0.6.0-beta  ━━▶  v0.8.0-beta   ·  412 commits, 41 days, 2 releases

Your fetchers   2 of 7 changed
● azure_aks_cluster_configuration  0.6.0 → 0.7.0
    0.8.0  Checks that the node pools you list have the autoscaler on
● aws_inspector_ecr_report         0.2.0 → 0.3.0
    0.8.0  Counts every image in scope, and can allow a scope with no images
    0.7.0  Adds a Repository ARN column to the report CSV

Breaking   1 touches you
⚠ azure_aks_cluster_configuration renames node_pools to pools   0.8.0 · prod.yaml
  fix: Update validators that read node_pools to read pools

New
  0.8.0-beta · Dec 3
  + The TUI pairs and updates validators that already exist
  0.7.0-beta · Nov 26
  + paramify update brings your clone up to date, and checks it first
  + 3 more
```

- **Header:** as today, plus the number of releases crossed when there is
  more than one (my call).
- **Breaking:** as today, plus the release each row came from.
- **Your fetchers:** as today (which fetchers the user's manifests use, and the
  version before and after). Under each, the `fetchers` note from every release
  crossed, newest first, labelled with the release. When no release crossed
  has a note for it (a clone on `main`), today's commit-subject reason is
  shown instead.
- **New:** rows grouped under a dim release heading, newest release first.
  `MAX_NEW` becomes a cap on the total rows shown (my call: 10); the rest of
  each release is counted ("+ 3 more").
- Which rows are new stays as `update.curated_rows` works today: compared by
  tag and title against what the clone already has, and releases the clone
  already contains are skipped. Fetcher notes are keyed by (release, fetcher
  name) and follow the same "skip releases you already contain" rule.

`update.assess` passes the fetcher notes through to the plan, and `--json`
includes them.

### 3. `tools/release.py`

A standard-library-plus-PyYAML script with three commands. Every command can
run on a laptop; the workflows only call it.

**`draft`** (Thursday job, on push to `main` while a release PR is open, or by hand):

1. Exits quietly when there is nothing to show a user: no rows in
   `releases/unreleased.yaml` and no fetcher version changed since the last
   tag (my call). CHANGELOG-only changes (CI, docs, internals) wait for the
   next release that has something to show.
2. When a `release/next` pull request is already open, it **redrafts** that
   branch instead of opening a second one (see "When `main` moves" below),
   and on the Thursday run also sends a reminder DM.
3. Picks the version from the previous release (section 5).
4. Edits the CHANGELOG: `## [Unreleased]` becomes `## [X.Y.Z-beta] - <today>`,
   a fresh empty `## [Unreleased]` goes above it, and the compare links at the
   bottom are repointed. Bumps `pyproject.toml` to `X.Y.Z`.
5. `git mv releases/unreleased.yaml releases/X.Y.Z-beta.yaml`, sets `version`
   and `date`, and starts a new `unreleased.yaml` with `highlights: []`.
6. Drafts the `fetchers` list: every fetcher whose `fetcher.yaml` version
   differs from the last tag (added fetchers included; removed fetchers get no
   line). For each, the note is drafted from, in order:
   1. the CHANGELOG entry whose bold lead names the fetcher in backticks
      (``**`aws_inspector_ecr_report` 0.3.0: image counts...**``), using the
      text after the version and colon;
   2. `update.fetcher_reason` on the commit subjects since the last tag;
   3. `"TODO: say what changed for the user"`.
   Each line gets `draft: true`.
7. Marks every `highlights` row with `draft: true`, so Tate reads each one too.
8. Commits to `release/next`, pushes, opens the pull request with Tate
   as assignee and reviewer, and DMs Tate (section 6).

**When `main` moves while the release PR is open** (my call). `main` keeps
moving while the PR waits for Tate. Merging `main` into the release branch
would conflict, because both sides edit the top of the CHANGELOG and
`releases/unreleased.yaml`, and fetcher changes merged after the draft would
ship with no note. So `draft` is rerunnable on an open release branch:

- It rebuilds the branch from the current `main`: the same steps 3 to 8,
  force-pushed to the same branch, so the PR stays the same PR. The branch is
  always `release/next`, whatever the version, so a version change never
  needs a new branch or PR.
- It keeps Tate's work by starting from the release file as it is on the
  branch, edits and deletions included. The draft commit records the `main`
  commit it was built on (a `Release-Base: <sha>` trailer). The rebuild adds
  only what `main` gained since that commit: `unreleased.yaml` rows that were
  not there, and fetchers whose version moved. Those get `draft: true`. A
  fetcher line whose fetcher moved to a newer version again keeps its note but
  gets the new version and `draft: true`.
- Only the release file keeps hand edits. The CHANGELOG, `pyproject.toml` and
  `unreleased.yaml` are regenerated from `main` on every rebuild, so CHANGELOG
  fixes go to `main` in an ordinary pull request.
- If the version changes (a breaking row arrives), the file is renamed, the
  PR title changes, and the DM says so.
- A workflow runs it on every push to `main` while a release PR is open, so the
  branch is never behind for long. If `main` moves inside that window, the PR
  shows a conflict or an out-of-date branch and can't merge until the next
  redraft; it fails safe.

**`check`** (CI on `release/next` pull requests, and by hand): runs the rules in
section 4 that need git history and prints what to fix.

**`publish`** (on merge of a `release/next` pull request, or by hand):

1. Refuses, and DMs Tate, if the merged notes still carry `draft: true` (a
   guard in case the PR merged red).
2. Tags, annotated, the commit on `main` whose content is exactly what CI
   checked and Tate read, and pushes the tag:
   - after a merge commit, the release branch's last commit (it is on `main`);
   - after a squash or rebase merge, the new commit on `main`, but only if its
     tree equals the branch's last commit's tree;
   - otherwise it refuses and DMs Tate. The redraft on every push to `main`
     keeps this rare.
3. Creates the GitHub Release, `--prerelease` while the version has a
   pre-release suffix. Body: the three sections rendered as Markdown from the
   notes file, then the CHANGELOG section inside a collapsed `<details>`
   block.
4. DMs Tate that it's out, with the release link.

`docs/releasing_guide.md` is rewritten around this: the weekly flow, what to
do in the PR, how to run each command by hand, and the setup below.

### 4. The test

Two layers. The pytest file needs no git history, so it runs in every CI job;
`tools/release.py check` needs history and runs in a CI job with
`fetch-depth: 0`.

In `tests/test_release_highlights.py` (every file, every CI run):

1. Every file matches the schema; a release file is named for its `version`,
   which has a CHANGELOG section with the same date. (Kept.)
2. Every `### Breaking` entry in a CHANGELOG section has a matching breaking
   row in that release's file, and in `unreleased.yaml` for `[Unreleased]`.
   (Kept, tightened from "at least one" to "at least as many".)
3. Every fetcher name or glob in a row, and every `fetchers[].name`, matches a
   real fetcher. (Kept, extended.)
4. No file has `draft: true`, on any branch. The draft job's commit carries
   the marks, so the release PR is red from the moment it opens and turns
   green only when Tate has read and unmarked every line. That red check is
   the gate.
5. No `fetchers[].note` starts with `TODO`.
6. Removed: the "3 to 5 non-breaking rows" rule. A quiet week can have one row.

In `tools/release.py check`, on `release/next` pull requests only. Ordinary pull
requests bump fetcher versions all the time and never add `fetchers` lines,
so these rules would fail every one of them. They apply to the one release
file whose version has no tag yet:

7. **Every fetcher whose version went up has a line.** Compare every
   `fetcher.yaml` version at the PR head with the last tag. Each one that
   differs needs a `fetchers` line with the new version. A docs-only change
   doesn't bump the version, so needs no line.
8. **No line for a fetcher that didn't change.** A `fetchers` line whose
   version equals the last tag's is an error (a stale or copied line).
9. **The version bump is right** (section 5), compared with the previous tag.

A fetcher whose code changed but whose version didn't is out of scope here;
that is a fetcher-review concern.

### 5. Version numbers

Semantic versioning on the contract, as `docs/versioning_guide.md` already
says (major: something you use can break; minor: new fetchers and options,
and before 1.0 a minor can also break; patch: fixes).

While the major version is 0:

| The release has | Bump |
|---|---|
| any breaking row | minor |
| any added fetcher, or any `highlights` row tagged `new`, `fetcher`, `cli` or `tui` | minor |
| anything else (only `improved`, `fix`, `security`, `deprecated`, or only fetcher version bumps) | patch |

After 1.0, a breaking row is a major bump. The `-beta` suffix carries over
from the previous release; dropping it is a hand edit in the release PR, and
`check` accepts it. `pyproject.toml` never carries the suffix (as today).

`draft` picks the version from the rows before Tate edits them. If Tate's edits
change the answer (deleting the only breaking row), `check` fails and says
which version it expects; Tate renames the file and fixes the heading, or reruns
`tools/release.py draft --version X.Y.Z` on the branch.

### 6. Notifications

Update 2026-11-23 (Tate): the messages go to the Slack channel
`#paramify-fetchers-repo` instead of a DM; the Workflow Builder step is
"send a message to a channel". The payload is the same.

Both workflows send a Slack DM to Tate. A plain Slack incoming webhook posts
only to a channel, so the DM goes through a **Slack Workflow Builder workflow
with a webhook trigger** whose one step messages Tate. Its URL is the repo
secret `SLACK_RELEASE_WEBHOOK`. The script posts JSON with `text` and `url`
variables. When the secret is missing the script prints the message and
carries on (a laptop run, a fork).

| When | Message |
|---|---|
| Draft PR opened | "v0.8.0-beta is ready to review: 6 fetcher lines, 2 new rows, 1 breaking row to read." + PR link |
| A release PR is still open on Thursday | "v0.8.0-beta is still waiting for you." + PR link |
| Published | "v0.8.0-beta is out." + release link |
| The job failed | "The weekly release job failed." + run link |

GitHub also notifies Tate as assignee and requested reviewer.

### 7. Workflows

- `.github/workflows/release-draft.yml`: `schedule` Thursdays 15:00 UTC (my
  call: morning in Mountain time) plus `workflow_dispatch`. Checks out with
  `fetch-depth: 0`, runs `tools/release.py draft`.
- `.github/workflows/release-publish.yml`: `pull_request` `closed`, when merged
  and the head branch starts with `release/`. Runs `tools/release.py publish`.
- `.github/workflows/release-redraft.yml`: `push` to `main`. Does nothing
  unless a `release/next` pull request is open; then runs `tools/release.py draft`
  on it.
- `ci.yml`: a `release-check` job, `fetch-depth: 0`, that runs only when the
  head branch starts with `release/`. The scope decision goes through
  `tools/ci_plan.py` like the other optional jobs, and the `ci-ok` gate's list
  of jobs allowed to be skipped gains `release-check` (today it allows only
  `azure-sdk` and `oci-sdk`).

**Setup this needs (one time, someone with repo admin):**

- **A GitHub App** (Tate's decision), because a pull request opened with the
  default `GITHUB_TOKEN` does not start other workflows, so the release PR
  would never get its checks; and a token of Tate's own would make Tate the
  PR's author, who can't be requested as its reviewer.
  - Created in the `paramify` org, installed on `paramify-fetchers` only.
    Name: `paramify-fetchers-release`. No webhook.
  - Repository permissions: Contents read and write (branches, tags,
    releases), Pull requests read and write, Metadata read. Nothing else.
  - Secrets `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY`. Each workflow
    mints a short-lived token with `actions/create-github-app-token`.
- `SLACK_RELEASE_WEBHOOK`, from the Slack workflow above.
- **The `protect-main` ruleset** (Tate's decision: `main` refuses a merge
  while CI is red). Done 2026-11-23: it is active and requires only the
  `ci-ok` check from GitHub Actions. It also blocks deleting or force-pushing
  `main`. It has no review rule and no "branch must be up to date" rule, and
  nobody can bypass it. The workflows never push to `main` directly, and the
  ruleset targets only `main`, so the app can push `release/next` branches and
  tags. Because the "up to date" rule is off, `publish` keeps its own check
  that the tagged commit matches what was reviewed (section 3).

### 8. Installer and customers on `main`

- `install.sh`: with no `PARAMIFY_REF`, clone the newest release tag, found
  with `git ls-remote --tags` and sorted by semver (a pre-release sorts below
  its final release). `PARAMIFY_REF=main` follows `main`. If no tag at or
  after `v0.7.0-beta` exists (the first release `paramify update` can pin, per
  `docs/versioning_guide.md`), clone `main` as today.
- This change ships only after `v0.7.0-beta` is published.
- **Customers already on `main`** (Tate's decision): told directly, with no
  hint in the tool. A `main` clone is always ahead of the newest release, so
  any hint to switch would move them back in time and could break a manifest
  that uses a newer fetcher. The message (an announcement with the first
  release, and the docs) says: weekly releases exist; to follow them, run
  `paramify update --to <newest release>` right after a release comes out,
  when the step back is smallest; `paramify update --check` first shows what
  would change.
- README install section and `docs/versioning_guide.md` say releases are the
  default and how to follow `main`.

### 9. The first release, `0.7.0-beta`

- Run `tools/release.py draft` by hand once the script lands, so the first
  release uses the same path and checks as every later one.
- Expect a long PR: a month of changes, 10 `highlights` rows today (3
  breaking), and a fetcher line for every fetcher whose version went up since
  `v0.6.0-beta`, which is likely well over a hundred. Keep every breaking row;
  cut the new rows to the ones that matter.
- The CHANGELOG's `[Unreleased]` has repeated `### Added` / `### Changed`
  headings. Merge them in an ordinary pull request to `main` before the first
  draft (my call: worth doing once, not something `draft` does). Hand edits to
  the CHANGELOG on the release branch would be lost on the next rebuild.

## Order of work

Each step is its own pull request and leaves `main` working.

0. Setup, by Tate (no code): create and install the GitHub App, add its two
   secrets, create the Slack DM workflow and add its secret (section 7). The
   `protect-main` ruleset is already done. Steps 1 and 2 don't need it; step 3
   does.
1. Notes format: schema (`fetchers`, `draft`), loader, update view grouped by
   release, fetcher notes in "Your fetchers", the pytest rules. Old files keep
   working.
2. `tools/release.py` (`draft`, `check`, `publish`) with tests against a
   scratch git repo, plus the `release-check` CI job.
3. The three workflows and the Slack DM, and the rewritten
   `docs/releasing_guide.md` and `releases/README.md`. Needs the setup in
   section 7.
4. Cut `v0.7.0-beta`.
5. Installer default, docs, and the announcement to customers on `main`.

## Left to the builder

- Module layout inside `tools/release.py`, and whether shared helpers move into
  `framework/update.py` (version parsing, `fetcher_reason`) or are imported.
- The exact Markdown of the GitHub Release body.
- How the TUI lays out the release headings, within its existing update screen
  and snapshot tests.
- Wording of DMs and refusals, within the meaning above. User-facing docs are
  written in Simplified Technical English (see `~/Documents/ste-writing`).
