# `paramify update` for main and pinned releases

Date: 2026-11-16. Branch: `feat/paramify-update`. Status: approved by Tate, 2026-11-16.

## Why

`paramify update` exists on this branch but only moves between release tags.
Every customer today clones `main` and runs `git pull`. `main` is 1,611 commits
past the last tag (`v0.6.0-beta`, 2026-10-23). On such a clone:

- `paramify update --check` says "up to date" and exits 0.
- `paramify update` offers to move *back* to 0.6.0-beta, dropping 82 fetchers.

So the command is a downgrade offer for everyone who would run it. The intent
is one command a customer runs to get newer code and trust the result, whether
they follow `main` or pin a release, with update notes they can actually read.

## Goals

1. `paramify update` on a clone that follows `main` moves it to the latest
   `main`, with the same pre-check, reinstall, validation and rollback that
   release updates have.
2. A customer can pin a release and return to `main` with one flag each.
3. The notes shown before the switch are short and about the person reading:
   which of *their* fetchers change and why, which breaking changes touch
   *their* manifests, and a few curated highlights.
4. Less code than today (1,930 lines across `framework/update.py`,
   `update_cli.py`, `update_view.py`), aiming for about 1,400.

## Non-goals

- A settings system or a TUI settings page. Separate project, after this.
- Release tooling (drafting notes, cutting releases). Separate project, next;
  this design only fixes the file format it will build on.
- An update screen in the TUI. `api.check_for_update` stays so the TUI can
  show a notice later.
- Merging or rebasing a customer's local commits. Update fast-forwards or
  refuses.
- Self-update inside the container. The existing "update the host clone, then
  rebuild" advice stays as is.

## Anti-goals

- Never move a clone to older code unless the user named the older target.
- Never print or summarise the CHANGELOG. Its Unreleased section is 202
  entries and about 33,000 words.
- No stored "channel" setting. Git state is the only source of truth.

## Approaches considered

- **A. Follow what the clone is on (chosen).** A branch follows its upstream;
  a tag follows newer tags; `--to` switches between them. No setting. Tate
  picked this: it matches how customers already work and adds no second source
  of truth.
- **B. A stored channel setting** (`--channel main|release` kept in
  `.paramify/state.json`). Rejected: more code, and it can disagree with git.
- **C. Release-only, tag very often.** Rejected: forces every customer to
  change habits and depends on release tooling that does not exist yet.

## Design

### Choosing the target

Decided from the clone's state after `git fetch --tags origin`:

| Clone is on | `paramify update` moves to |
|---|---|
| A branch with an upstream (normally `main`) | the upstream's tip, by fast-forward |
| Detached exactly at a release tag | the newest release tag |
| A branch with no upstream, or detached elsewhere | nothing; it explains and suggests `--to main` or `--to <tag>` |

- `--to <tag>` pins: `git switch --detach <tag>`. Older or newer both allowed,
  since the user named it.
- `--to main` unpins: switch to `main`, then fast-forward it to `origin/main`.
- `--to` accepts only `main` or a release tag. Anything else is an error that
  lists recent releases.
- `--to <tag>` refuses a release whose tree has no `framework/update.py`,
  because the user would land on code with no `update`, `--rollback` or
  `--to main`. Every tag that exists today (up to `v0.6.0-beta`) is in that
  position, so pinning becomes usable from the first release cut after this
  merges. The refusal says so and gives the manual `git switch --detach <tag>`
  for someone who wants the old release anyway. (My call.) Until then the
  release channel is exercised only by the test fixtures.
- If the branch has commits its upstream lacks, update refuses and says so. It
  never merges.
- `--next` is removed.

### One pipeline for both

Target choice is the only difference between channels. Everything after it
takes "HEAD" and "target commit" and is the same code:

1. Refuse if a tracked file with local changes is also changed between HEAD
   and target, listing those files. Other local changes ride along, as git
   allows. (My call: today any tracked change refuses, which would lock out a
   customer who edited one tracked file.)
2. Build the notes (below).
3. Pre-check, unchanged: check the target out in a temporary worktree, link
   the user's untracked fetchers in, run the target's own `paramify validate`
   on each manifest, classify each as ok / fixed / breaks / still failing /
   unchecked.
4. Confirm.
5. Move: fast-forward (`git merge --ff-only`) on a branch, `git switch
   --detach` for a tag.
6. Reinstall with the same interpreter and extras, **only if `pyproject.toml`
   differs between HEAD and target**. The install is editable, so code changes
   need no reinstall. (My call: this makes the common daily update on `main`
   take seconds.)
7. Validate every manifest on the new code.
8. If the reinstall fails, put the previous position back, as today.

### The notes

Three parts, in this order. No CHANGELOG parsing anywhere; `parse_changelog`,
`entry_title`, `changelog_anchor` and the changelog fallback are deleted.

**Your fetchers (computed).** Fetcher directories that differ between HEAD and
target, restricted to fetchers the user's manifests use. Each gets one line
with two parts:

- Its `fetcher.yaml` version at HEAD and at the target (`0.1.0 → 0.2.1`),
  which is always shown and always right.
- A reason, only when one can be trusted: the newest non-merge commit in
  `HEAD..target` that touched the directory *and whose subject names the
  fetcher*, either at the start (`azure_alert_rules: ...`,
  `azure_alert_rules 0.2.0: ...`) or in a conventional prefix
  (`fix(azure_alert_rules): ...`). The name or prefix is stripped. Other
  subjects are not used: of the 674 commits touching `fetchers/` since
  `v0.6.0-beta`, many of the newest per fetcher are version bumps, docs or
  type fixes. With no such commit the line shows the version change alone. (My
  call, in place of "newest commit subject", which would often show a bump.)

"+N more" follows when other commits touched it. All of this comes from one
`git log --no-merges --name-only` call over `fetchers/` and the two trees'
`fetcher.yaml` files. A fetcher that a breaking row names is marked. Moving
backwards shows names and versions without reasons.

**Curated rows.** `releases/unreleased.yaml` joins the per-release files, with
the same schema and `version: unreleased`. A PR adds a row only when it breaks
something or is worth announcing.

- Rows shown are those present in the target's `releases/*.yaml` and absent
  from HEAD's, compared by tag and title. This one rule covers both channels,
  and a row that moves from `unreleased.yaml` into a release file at release
  time is not shown twice.
- Breaking rows are matched to the user's manifests through their `fetchers`
  globs, as today, and shown with their `fix` line.
- Other rows are shown newest file first, at most five, with their `try`
  commands repeated at the end as today.

**The rest, as one line.** Counts of other fetchers changed, added and
removed, the commit count and age span on a branch, and a link to the
CHANGELOG at the target.

Sketch, on `main`:

```
main  a1b2c3d ━━▶ f9e8d7c   ·  212 commits, 9 days

Your fetchers                              4 of 14 changed
  ● azure_alert_rules         0.3.0 → 0.3.1  suppression fields are null when processing rules weren't read
  ● azure_policy_compliance   0.4.0 → 0.5.0  unread remediation tasks stay unread  +2 more
  ● aws_iam_users             1.1.0 → 1.2.0
  ● okta_least_privilege      0.2.0 → 0.3.0  allowlists moved from code to config   ⚠ breaking

Breaking                                   1 touches you
  ⚠ Okta allowlists moved from code to config        okta.yaml
    fix: set OKTA_KNOWN_SUPER_ADMINS if you relied on them

New
  + Qualys VMDR fetchers, a new qualys category      try: paramify catalog

  157 other fetchers changed · 4 added · full changelog ↗
```

### Unattended runs

`--yes` and `--json` switch without asking, except they stop when the update
would break *this* clone. `--allow-breaking` overrides. A breaking row touches
this clone when:

- it lists `fetchers` and a manifest uses one of them; or
- it lists none, which by `releases/README.md` means it touches everyone (a
  Python minimum, a CLI flag); or
- it sets the new optional field `custom_fetchers: true` and the clone has
  untracked fetcher directories. This is for changes to the fetcher contract
  that no shipped fetcher is affected by, such as two of the three Breaking
  entries now in `[Unreleased]`.

A manifest that validates now and fails on the target also stops the run. The
same rule gives the "N touches you" count; rows that do not touch the clone
are counted in the last line, not listed. (Tate approved stopping on unscoped rows.
Before this, any breaking change in range stopped an unattended run,
which on `main` would stop scheduled updates for people it does not affect.)

### `--check`, the daily notice, rollback

- `--check` is channel-aware: on a branch, exit 1 when the upstream is ahead;
  on a tag, exit 1 when a newer tag exists; exit 2 when it cannot tell. It
  never reports "up to date" for a clone it would offer to move.
- The once-a-day notice follows the same rule and names what is waiting ("212
  new commits on main" or "0.7.0-beta is out"). `PARAMIFY_NO_UPDATE_CHECK`
  still silences it, read in one place so it can become a setting later.
- `--rollback` returns to the recorded branch and commit. For a fast-forwarded
  branch that means `git reset --keep <previous commit>` on that branch, so the
  user stays on `main`, one update behind, and the next `paramify update`
  moves forward again. (My call, over leaving them detached.) It reinstalls
  under the same `pyproject.toml` rule.

### Keeping the notes honest

`tests/test_release_highlights.py` already checks each release file. It gains:

- `releases/unreleased.yaml` validates against the schema (with no minimum row
  count).
- The CHANGELOG's `[Unreleased]` `### Breaking` section has no more entries
  than `unreleased.yaml` has breaking rows. A PR that adds a Breaking entry
  without a row fails CI.

`unreleased.yaml` is seeded with rows for the three Breaking entries already
in `[Unreleased]` and a handful of highlights. `docs/releasing_guide.md` and
`releases/README.md` change to: at release, rename `unreleased.yaml` to the
version, trim it, and start an empty one.

### What gets cut

| Cut | Why |
|---|---|
| `--next` | Its job was reading breaking changes one release at a time; the notes now show only the ones that touch you. |
| CHANGELOG parsing and fallback | Notes come from git and the highlights files. |
| "Releases only, never main" guard and the off-release warning | Replaced by channel detection. |
| The view's custom theming (`Look`, gradients, pill colours, light-terminal detection, bordered cards) | Plain Rich output using the terminal's own colours. This is most of the 600-line view. |
| Four of the five screenshots | Keep one of an update on `main` and regenerate it; the rest go with the old look. |

Kept: `--to`, `--check`, `--rollback`, `--yes`, `--allow-breaking`, `--json`,
extras detection, the temporary-worktree pre-check, the container advice, the
daily notice, and the `.paramify/state.json` file.

## Constraints

- No new dependencies. No new files under `framework/` beyond the three that
  exist.
- Nothing changes in the user's checkout before they confirm.
- Each git call is a subprocess; keep reads batched as the current code does.
- `--json` output keeps its existing keys where they still mean something and
  adds `channel` (`branch` or `release`).

## Left to the builder

- Exact wording and layout of the output, following the sketch.
- How the three modules are reshaped internally, within the line budget.
- Which existing tests are rewritten versus deleted; every behaviour in this
  document needs a test against the temporary-repo fixtures in
  `tests/test_update.py`.
- Updating `docs/versioning_guide.md`, `docs/cli_guide.md`, the README line,
  the CLI help text and the CHANGELOG entry to describe both channels.
