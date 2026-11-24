# Weekly Releases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A release every week whose hand-written notes (new features, breaking changes, a line per changed fetcher) show on `paramify update` and the TUI, drafted and published by automation, with Tate pinged on Slack for the one human step.

**Architecture:** The notes file `releases/<version>.yaml` gains a `fetchers` list and a `draft` mark. `framework/update.py` reads them and the update view groups them by release. Pure release logic (version bump, CHANGELOG cut, note drafting, rebuild merge, checks) lives in `framework/release_notes.py`; `tools/release.py` wraps it with git, `gh` and a Slack webhook, and three GitHub workflows call it with a GitHub App token.

**Tech Stack:** Python 3.11+, PyYAML, `packaging.version`, rich, textual, jsonschema, pytest, GitHub Actions, `gh` CLI, `actions/create-github-app-token`, bash (`install.sh`).

**Spec:** `docs/superpowers/specs/2026-11-23-weekly-releases-design.md`

## Global Constraints

- Work in `~/paramify-fetchers-weekly-releases`. Commit as the directory's git identity (21tmccauley). Push and run `gh` with `GH_TOKEN=$(gh auth token -u 21tmccauley)`. End commit messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Each numbered phase below is its own pull request to `main`, in this order. `main` requires `ci-ok`.
- Breaking rows stay in `highlights`. New keys are top-level or per-row, never a change to an existing key's meaning: clones running today's `_highlight_files` must keep finding breaking rows.
- Lengths: `title` ≤ 72, `detail` / `fix` / fetcher `note` ≤ 110, one line each.
- Release branch: always `release/next`. Draft commits carry the trailer `Release-Base: <full sha of the main commit>`.
- Schedule: `cron: "0 15 * * 4"` (Thursday 15:00 UTC).
- Secrets: `RELEASE_APP_ID`, `RELEASE_APP_PRIVATE_KEY`, `SLACK_RELEASE_WEBHOOK`. Reviewer and assignee: env `RELEASE_REVIEWER`, default `21tmccauley`.
- Version bump while major is 0: any breaking row → minor; any added fetcher or any `highlights` row tagged `new`, `fetcher`, `cli` or `tui` → minor; else patch. Major ≥ 1: breaking → major. Pre-release suffix of the previous release carries over; `pyproject.toml` never has it.
- `framework/` code passes `ruff` and `mypy` (CI `lint` job). User-facing docs are in Simplified Technical English (`~/Documents/ste-writing/ste-lint.py`).
- CHANGELOG `[Unreleased]` gets an entry for user-visible changes in each phase, as the repo does today.

## Review Focus

1. **An old clone reads a new release file.** A file with `fetchers` and `draft` keys must still give today's `_highlight_files` its breaking rows. Test in Task 2.
2. **A clone on `main` crosses no release.** "Your fetchers" falls back to the commit-subject reason, and New rows sit under an `unreleased` heading. Tests in Tasks 2 and 3.
3. **A fetcher changed in two releases the user crosses.** It shows both notes, newest first, each with its release. Tests in Tasks 2 and 3.
4. **A rebuild after Tate deleted a row while `main` gained a row.** The deleted row stays deleted, the new row arrives with `draft: true`, and edited notes are kept. Test in Task 5.
5. **CHANGELOG leads that don't fit the simple pattern.** That covers two fetchers in one bold lead, and a new fetcher with no version in its lead. Each named fetcher still gets a drafted note. Test in Task 5.

---

## Phase 1 — notes format and the update screen (one PR)

### Task 1: Schema and notes-file tests

**Files:**
- Modify: `framework/schemas/release_highlights_schema.json`
- Modify: `tests/test_release_highlights.py`
- Modify: `releases/README.md`

**Interfaces:**
- Produces: schema keys `fetchers` (top level) and `draft` (on a highlight row and a fetcher line); the CHANGELOG parser moves to `framework/release_notes.py` in Task 4. Until then this task keeps `_changelog_sections` in the test.

- [ ] **Step 1: Write the failing tests** in `tests/test_release_highlights.py`, using in-memory docs validated with the existing `_schema_errors`:

```python
def test_a_fetcher_line_matches_the_schema():
    doc = {"version": "0.8.0-beta", "highlights": [],
           "fetchers": [{"name": "demo_alpha", "version": "0.7.0", "note": "Reads more rows", "draft": True}]}
    assert _schema_errors(doc) == []

@pytest.mark.parametrize("line", [
    {"name": "demo_alpha", "version": "0.7.0"},                          # no note
    {"name": "demo_alpha", "version": "seven", "note": "x" * 10},        # not a version
    {"name": "demo_alpha", "version": "0.7.0", "note": "x" * 111},       # too long
    {"name": "demo_alpha", "version": "0.7.0", "note": "a\nb"},          # two lines
    {"name": "demo_alpha", "version": "0.7.0", "note": "ok ok", "x": 1}, # unknown key
])
def test_a_bad_fetcher_line_is_refused(line):
    assert _schema_errors({"version": "0.8.0-beta", "highlights": [], "fetchers": [line]})

def test_a_highlight_row_may_carry_a_draft_mark():
    assert _schema_errors({"version": "unreleased",
                           "highlights": [{"tag": "new", "title": "Sprockets", "draft": True}]}) == []
```

Plus file-level tests over `FILES`:
  - `test_no_file_is_a_draft`: no `highlights` row and no `fetchers` line has `draft: true`. The message names the file and each marked title or fetcher.
  - `test_no_fetcher_note_is_a_todo`: no `note` starts with `TODO`.
  - `test_fetcher_lines_name_real_fetchers`: every `fetchers[].name` is in `_fetcher_names()`.
- [ ] **Step 2: Replace two tests.**
  - Delete `test_whats_new_stays_short` (the 3-to-5 rule).
  - Change `test_breaking_changelog_entries_have_breaking_rows` from "at least one row" to `len(rows) >= entries`, as `test_every_unreleased_breaking_entry_has_a_row` already does.
- [ ] **Step 3: Run** `pytest tests/test_release_highlights.py -q`. Expected: the new schema tests FAIL (unknown keys).
- [ ] **Step 4: Extend the schema.**
  - Top-level `fetchers`: an array, `maxItems` 400, `uniqueItems`.
  - Each item, `additionalProperties: false`, required `name`, `version`, `note`:
    - `name`: pattern `^[a-z0-9_]+$`
    - `version`: pattern `^\d+\.\d+\.\d+$`
    - `note`: `minLength` 3, `maxLength` 110, pattern `^[^\n]*$`
    - `draft`: boolean
  - Add `draft: boolean` to `$defs.highlight`.
  - Update the schema `description` to mention `fetchers`.
- [ ] **Step 5: Run** `pytest tests/test_release_highlights.py -q`. Expected: PASS.
- [ ] **Step 6: Update `releases/README.md`.** Describe the `fetchers` list (drafted at release time, not by PR authors) and the `draft` mark. Replace "When you cut a release" with a pointer to `docs/releasing_guide.md`. Remove "3 to 5" from "What the tests check".
- [ ] **Step 7: Commit** `feat(releases): fetcher notes and draft marks in the release notes format`.

### Task 2: Read fetcher notes and release dates in `framework/update.py`

**Files:**
- Modify: `framework/update.py` (`_highlight_files` ~366, `curated_rows` ~392, `span` ~702, `MAX_NEW` ~781, `locate` ~794, `assess` ~827)
- Test: `tests/test_update.py`

**Interfaces:**
- Produces:
  - `release_files(root: Path, ref: str) -> Dict[str, dict]`: `{version: {"date": Optional[str], "highlights": List[dict], "fetchers": List[dict]}}` for every readable `releases/*.yaml` at `ref`. Read loosely, as `_highlight_files` is today: a fetcher line needs only `name`, `version` and `note` strings. `_highlight_files(root, ref)` becomes `{v: d["highlights"] for v, d in release_files(root, ref).items()}`, with the same behavior.
  - `fetcher_notes(root: Path, head: str, target: str) -> Dict[str, List[dict]]`: `{fetcher name: [{"release": "0.8.0-beta", "version": "0.7.0", "note": str}, ...]}`. Built from release files at `target` (never `unreleased`), skipping releases whose tag `head` already contains (the same `git tag --merged head` rule `curated_rows` uses). Newest release first, ordered by `Release.key`.
  - `crossed_releases(root: Path, head: str, target: str) -> List[dict]`: `[{"version": str, "date": Optional[str]}]` for the release tags merged into `target` and not into `head`, newest first. `date` comes from the release file, else the CHANGELOG heading at `target`, else None.
  - `span(...)` returns `{"commits", "days", "releases"}`. `releases` is `len(crossed_releases(...))`, or 0 when going back.
  - `assess(...)` adds two things:
    - `plan["releases"]`, the `crossed_releases` list;
    - a `notes` list on each `plan["fetchers"]["yours"]` row, from `fetcher_notes(root, "HEAD", target.sha).get(name, [])`.
  - Each highlight row keeps its `release` key (already set by `curated_rows`).
  - `MAX_NEW = 10`.

- [ ] **Step 1: Write the failing tests** in `tests/test_update.py`, building on the `repo` fixture. Add a `v0.4.0-beta` and a `v0.5.0-beta` to upstream: each bumps `demo_alpha`'s `fetcher.yaml` version, carries a release file with a `fetchers` line for it and a `date`, and gets tagged.
  - `test_old_loader_still_sees_breaking_rows_in_a_file_with_fetchers`: a release file with `fetchers` and `draft` keys plus a breaking row → `up._highlight_files(...)[version]` contains the breaking row (Review Focus 1).
  - `test_fetcher_notes_from_every_release_crossed_newest_first`: from `v0.3.0-beta` to `v0.5.0-beta` → `fetcher_notes(...)["demo_alpha"]` has releases `["0.5.0-beta", "0.4.0-beta"]` (Review Focus 3).
  - `test_fetcher_notes_skip_releases_head_contains`: from `v0.4.0-beta` → only `0.5.0-beta`.
  - `test_fetcher_notes_ignore_unreleased`: an `unreleased.yaml` with a `fetchers` key gives nothing.
  - `test_crossed_releases_with_dates_newest_first`, and the `span(...)["releases"] == 2` case.
  - `test_assess_puts_notes_on_your_fetchers`: with the `stubs` fixture, the plan for `demo_alpha` has `notes` with two entries.
  - `test_assess_on_main_has_no_notes`: with `main_repo`, crossing no release, `notes == []`, `releases == []`, and the commit-subject `reason` is still set (Review Focus 2).
- [ ] **Step 2: Run** `pytest tests/test_update.py -q -k "notes or crossed or old_loader or assess_on_main"`. Expected: FAIL.
- [ ] **Step 3: Implement** the Produces list above. Use `read_at` for the batch read, as `_highlight_files` does.
- [ ] **Step 4: Run** `pytest tests/test_update.py -q`. Expected: PASS, including every existing test.
- [ ] **Step 5: Commit** `feat(update): read per-release fetcher notes and crossed releases`.

### Task 3: Show notes grouped by release in the CLI and TUI

**Files:**
- Modify: `framework/update_view.py` (`header`, `fetcher_note`, `your_fetchers`, `whats_new`)
- Modify: `framework/update_cli.py:220` (the `whats_new` call)
- Modify: `framework/tui/screens/update.py` (`_new_text`)
- Test: `tests/test_update.py`, `tests/test_tui_update.py`, TUI snapshots under `tests/test_tui_snapshots/`, `docs/img/update/update.svg` via `tools/update_screenshots.py`

**Interfaces:**
- Consumes: from Task 2, `plan["releases"]`, `row["notes"]` and `highlight["release"]`.
- Produces:
  - `header(plan)`: when `span["releases"] > 1`, appends `, N releases` after the days, giving `412 commits, 41 days, 2 releases`.
  - `fetcher_note(row, broken) -> Text`: with `row["notes"]`, gives the newest note as `"{release}  {note}"`, plus a dim `  +N earlier` when there are more. Without notes it behaves as today. The TUI table uses this.
  - `your_fetchers(...)`: in the CLI, a fetcher with notes gets an empty note column on its own line, then one indented line per note (indent 4, dim release, then the note), at most 3, then a dim `+N earlier`.
  - `whats_new(rows, releases) -> List[Text]`: rows grouped by `release`. Each group starts with a dim heading `"{version} · {Mon D}"`, or just the version without a date, or `"unreleased"` for rows from `unreleased.yaml`. Groups go unreleased first, then newest release first.
  - The section order stays Your fetchers, Breaking, New.

- [ ] **Step 1: Write the failing view tests.** Render with `make_console(record=True, width=100)` and assert on `console.export_text()`:
  - `test_whats_new_groups_rows_under_their_release`: rows from `0.8.0-beta` (date `2026-12-03`) and `0.7.0-beta` give `"0.8.0-beta · Dec 3"` before `"0.7.0-beta"`, each above its own rows.
  - `test_whats_new_on_main_heads_rows_unreleased`.
  - `test_your_fetchers_lists_every_release_note_newest_first`: two notes give two indented lines, `0.8.0-beta` first (Review Focus 3).
  - `test_your_fetchers_without_notes_keeps_the_commit_reason` (Review Focus 2).
  - `test_header_counts_releases_only_when_more_than_one`.
  - In `tests/test_tui_update.py`, `test_screen_shows_the_newest_fetcher_note`: the "what changed" cell starts with the release and the note.
- [ ] **Step 2: Run** `pytest tests/test_update.py tests/test_tui_update.py -q`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement** the Produces list. Pass `plan.get("releases") or []` to `whats_new` in `update_cli.py` and in the TUI's `_new_text`.
- [ ] **Step 4: Run** `pytest tests/test_update.py tests/test_tui_update.py -q`. Expected: PASS. `test_plan_renders_plainly_and_within_100_columns` still passes.
- [ ] **Step 5: Refresh visuals.**
  - Regenerate the TUI snapshots that changed, using the snapshot plugin's update flag. Look at each diff: only the New and fetcher-note areas may move.
  - Run `python tools/update_screenshots.py` and check `docs/img/update/update.svg`.
- [ ] **Step 6: Docs.** Update the "Shows what changes for you" list in `docs/versioning_guide.md`, and add a CHANGELOG `[Unreleased]` entry.
- [ ] **Step 7: Run** `ruff check framework && mypy framework` and `pytest -q -x tests/test_update.py tests/test_tui_update.py tests/test_release_highlights.py`. Expected: clean.
- [ ] **Step 8: Commit** `feat(update): group notes by release and show fetcher notes`, then open the Phase 1 PR.

---

## Phase 2 — release logic, the release tool, and its CI check (one PR)

### Task 4: Pure release logic in `framework/release_notes.py`

**Files:**
- Create: `framework/release_notes.py`
- Create: `tests/test_release_notes.py`
- Modify: `tests/test_release_highlights.py` (import the CHANGELOG parser from here)

**Interfaces:**
- Produces, all pure (strings and dicts in, strings and dicts out, no git):
  - `changelog_sections(text: str) -> Dict[str, dict]`: the parser now in the test, moved here. `{version: {"date": Optional[str], "<Subheading>": count of top-level bullets, "body": str}}`. `body` is the section's text without its heading.
  - `cut_changelog(text: str, version: str, date: str) -> str`:
    - `## [Unreleased]` becomes `## [{version}] - {date}`, with a new `## [Unreleased]` and a blank line above it.
    - The `[Unreleased]: …/compare/v{prev}...HEAD` link becomes `…/compare/v{version}...HEAD`.
    - A new `[{version}]: …/compare/v{prev}...v{version}` line goes directly under it. `prev` and the base URL are read from the old `[Unreleased]` link.
    - Raises `ValueError` when there is no `## [Unreleased]` heading or link.
  - `set_pyproject_version(text: str, version: str) -> str`: sets `version = "X.Y.Z"` in `[project]`, with any pre-release suffix stripped.
  - `required_bump(notes: dict, added_fetchers: Collection[str], major: int) -> str`: `"major" | "minor" | "patch"`, per Global Constraints.
  - `next_version(prev: str, bump: str) -> str`. Examples: `("0.6.0-beta", "minor") → "0.7.0-beta"`, `("0.7.0-beta", "patch") → "0.7.1-beta"`, `("1.2.3", "major") → "2.0.0"`.
  - `draft_note(name: str, changelog_body: str, subjects: Sequence[str]) -> str`. Takes the first match of:
    1. a top-level bullet whose bold lead contains `` `name` ``: the text after the first `X.Y.Z:` in the lead, or after the lead's first `: ` when there is no version, without its trailing `**` and full stop;
    2. `update.fetcher_reason(name, subjects)`;
    3. `"TODO: say what changed for the user"`.

    Longer than 110 characters is cut at a word boundary to ≤ 109, plus `…`.
  - `draft_release(version: str, date: str, rows: List[dict], changed: Dict[str, str], notes_for: Callable[[str], str], previous: Optional[dict] = None, rows_since_base: Sequence[dict] = ()) -> dict`. Returns the release file doc (`version`, `date`, `highlights`, `fetchers`). `changed` is `{fetcher name: new version}` vs the last tag.
    - **`previous is None`:** every row in `rows` is copied with `draft: True`. There's one line per `changed` item, sorted by name, with `note = notes_for(name)` and `draft: True`.
    - **`previous` given:**
      - `highlights` is `previous["highlights"]` plus each of `rows_since_base` with `draft: True`.
      - For each `changed` name, a `previous` line with the same version is kept as is. One with another version keeps its note, takes the new version and gets `draft: True`. A missing one is drafted new.
      - `previous` lines whose name is not in `changed` are dropped.
  - `dump_release(doc: dict) -> str`: YAML with the header comment the 0.6.0-beta file has, keys in the order `version, date, highlights, fetchers`, and `sort_keys=False`.
  - `check_release(doc: dict, changed: Dict[str, str], added: Collection[str], prev_version: str) -> List[str]`: messages, each naming what to fix.
    - A `changed` fetcher with no line: `"demo_alpha 0.7.0 has no fetcher line"`.
    - A line for a name not in `changed`, or with another version: `"demo_beta has a line but did not change since v0.6.0-beta"`.
    - `doc["version"]` other than `next_version(prev_version, required_bump(...))`, apart from a dropped pre-release suffix: `"expected 0.7.0-beta (breaking rows → minor), found 0.6.1-beta"`.

- [ ] **Step 1: Write the failing tests** in `tests/test_release_notes.py`:
  - `cut_changelog`: on a small CHANGELOG with an `[Unreleased]` link to `v0.6.0-beta`, assert both headings and both link lines exactly. Also the `ValueError` case.
  - `set_pyproject_version`: `"0.7.0-beta"` writes `version = "0.7.0"`.
  - `required_bump` / `next_version`: a table test covering each row of the bump table, the three examples above, and `0.9.0-beta → 0.10.0-beta`.
  - `draft_note`:
    - `test_draft_note_from_a_lead_naming_two_fetchers`: the lead ``**`aws_inspector_ecr_findings` and `aws_inspector_ecr_report` 0.3.0: image counts and an opt-in.**`` gives `"image counts and an opt-in"` for both names (Review Focus 5).
    - `test_draft_note_for_a_new_fetcher_without_a_version`: ``**`snowflake_roles`: roles and grants.**`` gives `"roles and grants"` (Review Focus 5).
    - The commit-subject fallback, the `TODO` fallback, and the 110-character cut.
  - `draft_release`:
    - `test_first_draft_marks_everything`.
    - `test_rebuild_keeps_edits_and_deletions_and_marks_only_whats_new` (Review Focus 4). `previous` has an edited unmarked note for `demo_alpha` at 0.7.0, no `demo_beta` row (Tate deleted the highlight "Beta row"), and an unmarked row "Kept row". `rows_since_base` has "Fresh row". `changed` has `demo_alpha: 0.7.0`, `demo_gamma: 0.2.0`. Assert:
      - the highlight titles are `["Kept row", "Fresh row"]` and only "Fresh row" is marked;
      - `demo_alpha` keeps its edited note unmarked;
      - `demo_gamma` is drafted and marked.
    - `test_rebuild_remarks_a_line_whose_fetcher_moved_again`: 0.7.0 → 0.7.1 keeps the note, sets the version, and marks it.
  - `check_release`: one test per message above, plus a clean doc gives `[]`.
- [ ] **Step 2: Run** `pytest tests/test_release_notes.py -q`. Expected: FAIL (module missing).
- [ ] **Step 3: Implement `framework/release_notes.py`.** Point `tests/test_release_highlights.py` at `release_notes.changelog_sections` and delete its copy.
- [ ] **Step 4: Run** `pytest tests/test_release_notes.py tests/test_release_highlights.py -q && ruff check framework && mypy framework`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(releases): version, changelog and note drafting logic`.

### Task 5: `tools/release.py` — draft, check, publish

**Files:**
- Create: `tools/release.py`
- Create: `tests/test_release_tool.py` (loads the tool with `importlib`, as `tests/test_ci_plan.py` loads `tools/ci_plan.py`; reuses the scratch-repo pattern of `tests/test_update.py`'s `git_env` and `repo` fixtures)

**Interfaces:**
- Consumes: `framework.release_notes` (Task 4); `framework.update.git`, `read_at`, `fetcher_reason`, `parse_release`, `UpdateError`.
- Produces:
  - **CLI:** `python tools/release.py {draft,check,publish}`. Exit codes: 0 done or nothing to do, 1 refused or failed. Every refusal is one line that says what to do.
  - `last_tag(root: Path, ref: str) -> str`: `git describe --tags --abbrev=0 --match 'v[0-9]*' ref`.
  - `fetcher_versions(root: Path, ref: str) -> Dict[str, str]`: name → version for every `fetchers/**/fetcher.yaml` at `ref`. Skips path parts starting with `_` after `fetchers/`, as `update._fetcher_dirs` does. Uses `git ls-tree -r --name-only` plus one `read_at`.
  - `changed_fetchers(root: Path, tag: str, ref: str) -> Tuple[Dict[str, str], Set[str]]`: `(changed name → new version, added names)`. A removed fetcher is in neither.
  - `class GitHub` wraps `gh` via subprocess:
    - `open_release_pr() -> Optional[dict]` gives `{number, url, title, body}` for the open PR with head `release/next`.
    - `create_pr(title: str, body: str, reviewer: str) -> str` returns the URL and sets the reviewer as assignee and requested reviewer.
    - `edit_pr(number: int, title: str, body: str) -> None`.
    - `create_release(tag: str, title: str, notes: str, prerelease: bool) -> str` returns the URL.
  - `notify(text: str, url: str) -> None`: POSTs `{"text": ..., "url": ...}` as JSON to `$SLACK_RELEASE_WEBHOOK` with `urllib.request`, timeout 10 s. Without the variable it prints `slack: {text} {url}`. A failed POST is printed and never raises.
  - `draft(root: Path, *, base: str, today: str, gh: GitHub, notify=notify, push: bool = True, version: Optional[str] = None) -> str`: returns `"nothing" | "opened" | "rebuilt"`.
    1. Find `tag = last_tag(root, base)`, `changed`/`added` vs `base`, and the `unreleased.yaml` rows at `base`. With no rows and no changes, return `"nothing"`.
    2. Look for an open PR with `gh.open_release_pr()`. If there is one, read `previous` from `origin/release/next`'s release file and `Release-Base` from that branch's last commit. `rows_since_base` is the rows at `base` whose `(tag, title)` was not in `unreleased.yaml` at `Release-Base`.
    3. Pick `version`: the argument, else `next_version(...)`.
    4. Build the branch: `git switch -C release/next {base}`, then:
       - write the CHANGELOG with `cut_changelog`;
       - write `pyproject.toml` with `set_pyproject_version`;
       - `git rm -q releases/unreleased.yaml`;
       - write `releases/{version}.yaml` with `dump_release(draft_release(...))`;
       - write a new `releases/unreleased.yaml` with the existing header comment and `highlights: []`.
    5. Commit `chore(release): v{version}` with the trailer `Release-Base: {sha of base}`. With `push`, `git push --force-with-lease origin release/next`.
    6. Then create or edit the PR: title `Release v{version}`, and a body that counts the marked fetcher lines, new rows and breaking rows to read and links `docs/releasing_guide.md`.
    7. `notify` with the counts (wording from spec section 6). On a rebuild that changes the version, the DM says so.
    8. On the Thursday run with an open PR (env `RELEASE_REMINDER=1`), also notify "still waiting".
  - `check(root: Path, ref: str = "HEAD") -> List[str]`: finds the one `releases/*.yaml` at `ref` whose version has no tag (none gives `[]`), then returns `check_release(doc, *changed_fetchers(root, tag, ref), prev_version)`.
  - `publish(root: Path, *, head_sha: str, merge_sha: str, gh: GitHub, notify=notify) -> str`: returns the tag.
    - Refuses and notifies if the release file at `merge_sha` has any `draft: true`.
    - Tags `head_sha` when `git merge-base --is-ancestor head_sha merge_sha` succeeds; else tags `merge_sha` when `git rev-parse {merge_sha}^{tree}` equals `{head_sha}^{tree}`; else refuses and notifies.
    - Uses `git tag -a v{version} -m v{version}`, then `git push origin v{version}`.
    - Calls `gh.create_release(...)` with `prerelease` true when the version has a `-` suffix. The notes are `render_release_body(doc, changelog_body)`.
    - Notifies "v{version} is out."
  - `render_release_body(doc: dict, changelog_body: str) -> str`: Markdown in this order:
    1. `## Breaking` (title, then `Fix:` line);
    2. `## New` (title — detail);
    3. `## Fetchers` (`` `name` version: note ``);
    4. `<details><summary>Full changelog</summary>` + body + `</details>`.

    Empty sections are left out.
  - `notify-failure --url URL` subcommand: calls `notify("The weekly release job failed.", url)`.
  - The commit subjects passed to `draft_note` come from one `git log --no-merges --format=%x00%s --name-only {tag}..{base} -- fetchers/`, split per fetcher directory as `update._subjects_by_dir` does. Don't run one `git log` per fetcher.

- [ ] **Step 1: Write the failing tests.** Use a `FakeGitHub` recording calls, `notify` replaced by a list append, and a scratch upstream with a `v0.6.0-beta` tag, two fetchers and a CHANGELOG with an `[Unreleased]` link. Clone it, and pass `push=False`, or push to the local upstream.
  - `test_nothing_to_release_opens_nothing`
  - `test_first_draft_builds_the_branch_and_opens_the_pr`:
    - the branch `release/next` has `releases/0.7.0-beta.yaml` with marks;
    - the CHANGELOG heading is cut, `pyproject.toml` is `0.7.0`, and `unreleased.yaml` is empty;
    - the trailer `Release-Base` equals base's sha;
    - `FakeGitHub.create_pr` is called with reviewer `21tmccauley`;
    - one notify mentions the counts.
  - `test_rebuild_keeps_tates_edits_and_adds_new_rows` (Review Focus 4, end to end):
    - draft; on the branch, edit a note, unmark it, delete a row and commit;
    - add a row to upstream `main`'s `unreleased.yaml` and bump a third fetcher;
    - draft again with a fake open PR;
    - the release file has the edit and the deletion kept, and only the new row and fetcher are marked.
  - `test_rebuild_that_changes_the_version_renames_the_file_and_retitles_the_pr`: a breaking row arrives after a patch-only draft.
  - `test_check_names_a_missing_line_and_a_wrong_version`.
  - `test_publish_refuses_a_draft`, `test_publish_tags_the_branch_tip_after_a_merge_commit`, `test_publish_tags_a_squash_with_the_same_tree`, `test_publish_refuses_a_squash_with_another_tree`.
  - `test_render_release_body_orders_sections_and_skips_empty_ones`.
  - `test_notify_failure_sends_the_run_link`, and `test_notify_without_a_webhook_prints`.
- [ ] **Step 2: Run** `pytest tests/test_release_tool.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement `tools/release.py`.** Use `argparse`. `draft` reads `--base` (default `origin/main`), `--version`, `--no-push`, and the env `RELEASE_REVIEWER` and `RELEASE_REMINDER`. `check` reads `--ref` (default `HEAD`). `publish` reads `--head-sha` and `--merge-sha`. `today` is the UTC date.
- [ ] **Step 4: Run** `pytest tests/test_release_tool.py tests/test_release_notes.py -q`. Expected: PASS.
- [ ] **Step 5: Dry run on the real repo.** Run `python tools/release.py draft --no-push` in a scratch clone of this worktree, with a fake `gh` on `PATH` that prints its arguments. Expected:
  - a `release/next` branch with `releases/0.7.0-beta.yaml`;
  - about 179 fetcher lines (`grep -c "name:"`), most with drafted notes, and few `TODO`s;
  - 10 highlights, all marked.

  Note the `TODO` count in the PR description. Delete the scratch clone.
- [ ] **Step 6: Commit** `feat(releases): tools/release.py drafts, checks and publishes releases`.

### Task 6: `release-check` in CI

**Files:**
- Modify: `tools/ci_plan.py` (`plan`, `main`)
- Modify: `.github/workflows/ci.yml` (the `changes` outputs, a new `release-check` job, the `ci-ok` `needs` and its `jq` gate)
- Test: `tests/test_ci_plan.py`

**Interfaces:**
- Produces:
  - `ci_plan.plan(event, paths, head_ref: str = "") -> dict` gains `"release": "true"` when `head_ref == "release/next"`, else `"false"`. `main()` passes `os.environ.get("GITHUB_HEAD_REF", "")`.
  - A `release-check` job: `if: needs.changes.outputs.release == 'true'`, `actions/checkout@v7` with `fetch-depth: 0`, Python 3.12, `pip install -e .`, then `python tools/release.py check --ref HEAD^2`. The PR head is the merge ref's second parent; fall back to `HEAD` when there is no second parent.
  - `ci-ok` lists `release-check` in `needs` and allows it to be `skipped`, like `azure-sdk` and `oci-sdk`.
- [ ] **Step 1: Write the failing tests:** `test_release_branch_turns_on_release_check` and `test_other_branches_skip_release_check`.
- [ ] **Step 2: Run** `pytest tests/test_ci_plan.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** the Produces list, including the comment block at the top of `ci.yml`.
- [ ] **Step 4: Run** `pytest tests/test_ci_plan.py -q`. Expected: PASS. Then `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"`. If `actionlint` is installed, run it.
- [ ] **Step 5: Commit** `ci: run release checks on the release PR`, then open the Phase 2 PR.

---

## Phase 3 — workflows, Slack, and the guide (one PR; needs Tate's setup)

### Task 7: The three release workflows and the docs

**Files:**
- Create: `.github/workflows/release-draft.yml`, `.github/workflows/release-redraft.yml`, `.github/workflows/release-publish.yml`
- Modify: `docs/releasing_guide.md` (rewrite), `releases/README.md`, `CONTRIBUTING.md` (the release section, if there is one)

**Interfaces:**
- Consumes: the `tools/release.py` CLI (Task 5).
- Produces:
  - **All three:**
    - a `concurrency: {group: release, cancel-in-progress: false}`;
    - `permissions: contents: read` (the App token does the writing);
    - a step `actions/create-github-app-token` with `app-id: ${{ secrets.RELEASE_APP_ID }}`, `private-key: ${{ secrets.RELEASE_APP_PRIVATE_KEY }}`;
    - `actions/checkout@v7` with that token and `fetch-depth: 0`;
    - git identity set to the App bot (`{slug}[bot]`, `{bot user id}+{slug}[bot]@users.noreply.github.com`; the id comes from `gh api /users/{slug}[bot] --jq .id`);
    - `pip install -e .`;
    - env `GH_TOKEN` (App token), `SLACK_RELEASE_WEBHOOK`, `RELEASE_REVIEWER: 21tmccauley`;
    - a final `if: failure()` step that runs `python tools/release.py notify-failure --url "$RUN_URL"`, where `RUN_URL` is `${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}`.
  - `release-draft.yml`: `on: schedule: cron "0 15 * * 4"` and `workflow_dispatch` (input `version`, optional). Runs `python tools/release.py draft` with `RELEASE_REMINDER=1` on the schedule.
  - `release-redraft.yml`: `on: push: branches: [main]`. Runs `draft` only when `gh pr list --head release/next --state open` is non-empty.
  - `release-publish.yml`: `on: pull_request: types: [closed]`, `if: github.event.pull_request.merged && github.event.pull_request.head.ref == 'release/next'`. Runs `python tools/release.py publish --head-sha ${{ github.event.pull_request.head.sha }} --merge-sha ${{ github.event.pull_request.merge_commit_sha }}`.
- [ ] **Step 1: Write the workflows.** Validate each with `yaml.safe_load`, and with `actionlint` if installed.
- [ ] **Step 2: Rewrite `docs/releasing_guide.md`** for the weekly flow:
  - what arrives (DM, PR), and what to do in the PR: read each marked line, rewrite or delete it, remove `draft: true`, keep every breaking row;
  - fix CHANGELOG mistakes on `main` in an ordinary PR, not on `release/next`;
  - what `release-check` failures mean;
  - running each command by hand;
  - the one-time setup (App, secrets, Slack workflow, ruleset);
  - troubleshooting.

  Write it in STE and run `ste-lint.py` on it. Update `releases/README.md` to match.
- [ ] **Step 3: Check that Tate's setup is done** before merging: `gh api repos/paramify/paramify-fetchers/actions/secrets --jq '[.secrets[].name]'` lists `RELEASE_APP_ID`, `RELEASE_APP_PRIVATE_KEY` and `SLACK_RELEASE_WEBHOOK`. `gh api orgs/paramify/installations --jq '.installations[].app_slug'` lists the App.
- [ ] **Step 4: Commit** `ci: weekly release workflows`, open the Phase 3 PR, and merge it once it's green.
- [ ] **Step 5: Smoke test** after merge. Run the draft workflow with `workflow_dispatch`. Expected:
  - a PR from `release/next` by the App, with Tate as assignee and reviewer;
  - `release-check` and pytest red (draft marks);
  - one Slack DM.

  This PR is the first release (Task 9). Leave it open.

---

## Phase 4 — the first release

### Task 8: Tidy the CHANGELOG before the first draft

**Files:** Modify: `CHANGELOG.md` (`[Unreleased]` only)

- [ ] **Step 1: Merge duplicate subheadings.** Under `## [Unreleased]`, merge the repeated `### Added` and `### Changed` subheadings into one each. Keep every bullet, in order, and use the Keep a Changelog order: Breaking, Added, Changed, Deprecated, Removed, Fixed, Security.
- [ ] **Step 2: Run** `pytest tests/test_release_highlights.py -q`. Expected: PASS, with the Breaking count unchanged at 3.
- [ ] **Step 3: Commit** `docs(changelog): one heading per kind in Unreleased`, then open a PR and merge it. If the Task 7 smoke-test PR is open, the redraft workflow rebuilds it.

### Task 9: Cut v0.7.0-beta (Tate)

- [ ] **Step 1: Tate reviews the `release/next` PR.**
  - Cut the 7 non-breaking highlights to the ones that matter, and keep the 3 breaking rows.
  - Read every fetcher line, rewrite weak ones, and replace every `TODO`.
  - Remove every `draft: true`.
- [ ] **Step 2:** `ci-ok` is green. Merge.
- [ ] **Step 3: Verify.**
  - `gh release view v0.7.0-beta` shows a pre-release with Breaking, New and Fetchers sections.
  - Slack sends "v0.7.0-beta is out."
  - A scratch clone switched to `v0.7.0-beta` (after `pip install -e .`) reports up to date with `paramify update --check`, exit 0.
  - A scratch clone on `main` one commit behind shows the `0.7.0-beta` fetcher notes for a fetcher its manifest uses.

---

## Phase 5 — releases by default (one PR, after v0.7.0-beta exists)

### Task 10: Installer follows the newest release

**Files:**
- Modify: `install.sh` (the defaults comment, `main()` clone step, the last line)
- Create: `tests/test_install_script.py`
- Modify: `README.md` (install section), `docs/versioning_guide.md` (the "You run" table)

**Interfaces:**
- Produces:
  - `newest_release <repo>` (bash function): prints the newest `vX.Y.Z[-pre]` tag at or after `v0.7.0-beta`, or nothing. Use `git -c versionsort.suffix=- ls-remote --tags --refs --sort=-v:refname "$repo" 'v*'` (a pre-release sorts below its release), and ignore tags that don't match `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`.
  - With `PARAMIFY_REF` unset, `ref` is `$(newest_release "$repo")`. When that's empty, clone the default branch as today. `PARAMIFY_REF=main` follows `main`.
  - The last line becomes `[ "${PARAMIFY_INSTALL_SOURCE_ONLY:-}" = 1 ] || main "$@"`, so tests can source the file.
- [ ] **Step 1: Write the failing test.** Build a scratch repo with these tag sets and run `bash -c 'PARAMIFY_INSTALL_SOURCE_ONLY=1 source ./install.sh; newest_release "$1"' _ <repo>`:

  | Tags | Expected |
  |---|---|
  | `v0.6.0-beta`, `archive/x` | empty |
  | `v0.6.0-beta`, `v0.7.0-beta` | `v0.7.0-beta` |
  | `v0.7.0-beta`, `v0.7.0` | `v0.7.0` |
  | `v0.9.0-beta`, `v0.10.0-beta` | `v0.10.0-beta` |
- [ ] **Step 2: Run** `pytest tests/test_install_script.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement it.** Run `shellcheck install.sh`.
- [ ] **Step 4: Run** `pytest tests/test_install_script.py -q`. Expected: PASS. The CI `install` job, which clones a shallow checkout with no tags, still clones the default branch.
- [ ] **Step 5: Docs, in STE.**
  - README install: the installer gives the newest weekly release; `paramify update --to main` follows `main`.
  - Versioning guide table: "A release (what the installer gives you)" and "`main` (`paramify update --to main`)".
  - A CHANGELOG entry.
- [ ] **Step 6: Commit** `feat(install): install the newest release by default`, then open the PR.

### Task 11: Tell customers on `main` (Tate)

- [ ] **Step 1:** Draft the announcement for Tate to send. Cover:
  - weekly releases exist, with notes on `paramify update`;
  - to follow them, run `paramify update --to v0.7.0-beta` (or the newest) right after a release, when the step back is smallest;
  - `paramify update --check` first shows what changes;
  - `paramify update --to main` returns.

  Write it in plain words, under 150 words. Tate picks the channel.
