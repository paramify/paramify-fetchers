# `paramify update` on main and pinned releases: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `paramify update` moves a clone forward whether it follows `main` or is pinned to a release, and shows short notes about the reader's own fetchers and manifests.

**Architecture:** Target choice is the only channel-specific code: it turns the clone's git state (plus `--to`) into a `Target`. Everything after that works on "HEAD commit" and "target commit": curated rows are the difference between the two trees' `releases/*.yaml`, fetcher impact is computed from `git diff` and `git log`, and the existing temporary-worktree pre-check, reinstall, validate and rollback run unchanged in shape.

**Tech Stack:** Python 3.11+, Typer, Rich, PyYAML, jsonschema, git subprocesses, pytest. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-16-paramify-update-channels-design.md`

## Global Constraints

- No new dependencies. No new files under `framework/` beyond `update.py`, `update_cli.py`, `update_view.py`.
- Nothing changes in the user's checkout before they confirm.
- Never move a clone to older code unless the user named the older target with `--to`.
- Never parse, print or summarise `CHANGELOG.md` in `framework/`.
- No stored channel setting; git state is the only source of truth.
- `framework/update.py` returns JSON-able dicts and never writes to the terminal.
- Git reads stay batched (one `git cat-file --batch`, one `git log`), as now.
- `PARAMIFY_NO_UPDATE_CHECK` is read in exactly one place (`update.check_for_update`).
- The three modules together end at or under 1,450 lines (1,930 today).
- Tests run with `.venv/bin/python -m pytest -q -p no:cacheprovider <paths>`.
- Commits end with `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.

## Review Focus

Conditions the spec implies but does not spell out. Each has a test in the task named.

1. **A clone with no release tags reachable** (shallow clone, tags not fetched): on a branch, update still works and shows the branch and short sha instead of a version. (Task 2)
2. **Offline:** `git fetch` fails. Update says it is comparing against what the clone last saw and continues; `--check` exits 2 only when it has nothing to compare. (Task 5)
3. **`--to main` with no local `main` branch** (a clone made detached at a tag): the branch is created from `origin/main`. (Task 4)
4. **An untracked file the target adds as tracked:** git would abort the fast-forward mid-flow. It is listed with the blocking files before the confirm. (Task 4)
5. **A `releases/` directory that is missing or holds a malformed file at either commit:** curated rows are skipped, never an exception. (Task 1)

## File Structure

| File | Responsibility after this plan |
|---|---|
| `framework/update.py` | git helpers, `Target` choice, curated rows, fetcher impact, pre-check, move, reinstall rule, state, update check |
| `framework/update_cli.py` | the command's flags, step order, prompts, exit codes, `--json`, daily notice |
| `framework/update_view.py` | plain Rich renderables for the plan and the steps |
| `framework/schemas/release_highlights_schema.json` | row shape, now allowing `version: unreleased` and `custom_fetchers` |
| `releases/unreleased.yaml` | new; rows for changes on `main` since the last release |
| `tests/test_update.py` | behaviour against throwaway repos |
| `tests/test_release_highlights.py` | file rules, including the Unreleased Breaking count |
| `docs/versioning_guide.md`, `docs/releasing_guide.md`, `releases/README.md`, `docs/cli_guide.md`, `README.md`, `CHANGELOG.md`, `framework/cli.py` help text | describe both channels |

The `repo` fixture in `tests/test_update.py` builds an upstream with three tags and one commit on `main` past the newest tag, then clones it detached at `v0.1.0-beta`. Tasks extend it; they add a second fixture, `main_repo`, in Task 2.

---

### Task 1: Curated rows from the two trees

**Files:**
- Modify: `framework/update.py` (the "CHANGELOG and highlights" section), `framework/schemas/release_highlights_schema.json`
- Create: `releases/unreleased.yaml`
- Modify: `releases/README.md`
- Test: `tests/test_update.py`, `tests/test_release_highlights.py`

**Interfaces:**
- Produces: `update.UNRELEASED = "unreleased"`.
- Produces: `update.curated_rows(root: Path, head: str, target: str) -> List[dict]`. Each dict is a highlight row plus `"release"` (`"unreleased"` or a version). Rows are those in `target`'s `releases/*.yaml` whose `(tag, title)` is absent from `head`'s. Order: `unreleased` first, then versions newest first; within a file, file order. Files that are missing, unparsable or fail the schema contribute nothing.
- Removes: `parse_changelog`, `entry_title`, `changelog_anchor`, `release_notes`, `crossed`, and the `changelog_breaking` data. `repo_web_url` stays.

- [ ] **Step 1: Write the failing tests** in `tests/test_update.py`, replacing `test_release_notes_use_highlights_and_fall_back_to_the_changelog` and `test_changelog_parsing_joins_continuation_lines`:

```python
def test_curated_rows_are_those_the_target_adds(repo):
    rows = up.curated_rows(repo, "v0.1.0-beta", "v0.3.0-beta")
    assert [r["title"] for r in rows] == ["Gadgets for everyone", "demo_alpha reads more", "A nicer screen"]
    assert {r["release"] for r in rows} == {"0.3.0-beta"}
    assert up.curated_rows(repo, "v0.3.0-beta", "v0.3.0-beta") == []


def test_a_row_moved_into_a_release_file_is_not_shown_again(repo, tmp_path):
    upstream = tmp_path / "upstream"
    row = "highlights:\n  - tag: new\n    title: Sprockets\n"
    _commit(upstream, {"releases/unreleased.yaml": "version: unreleased\n" + row}, "add row")
    before = _git(upstream, "rev-parse", "HEAD").strip()
    _git(upstream, "mv", "releases/unreleased.yaml", "releases/0.4.0-beta.yaml")
    _commit(upstream, {"releases/0.4.0-beta.yaml": "version: 0.4.0-beta\n" + row,
                       "releases/unreleased.yaml": "version: unreleased\nhighlights: []\n"}, "release")
    _git(repo, "fetch", "-q", "origin")
    assert [r["title"] for r in up.curated_rows(repo, "v0.3.0-beta", before)] == ["Sprockets"]
    assert up.curated_rows(repo, before, "origin/main") == []


def test_curated_rows_survive_a_missing_or_broken_releases_dir(repo, tmp_path):
    upstream = tmp_path / "upstream"
    _commit(upstream, {"releases/unreleased.yaml": "version: [not, a, string\n"}, "broken file")
    _git(repo, "fetch", "-q", "origin")
    assert up.curated_rows(repo, "v0.1.0-beta", "v0.2.0-beta") == []      # neither tree has releases/
    assert [r["release"] for r in up.curated_rows(repo, "v0.1.0-beta", "origin/main")] == ["0.3.0-beta"] * 3
```

In `tests/test_release_highlights.py`: drop the import-time `update.parse_changelog` call and add a local helper `_changelog_sections() -> Dict[str, Dict[str, int]]` (version to `{subsection: top-level bullet count}`, plus the heading date under key `"date"`), then:

```python
UNRELEASED = REPO_ROOT / update.HIGHLIGHTS_DIR / "unreleased.yaml"
RELEASE_FILES = [p for p in FILES if p != UNRELEASED]

def test_unreleased_file_exists_and_matches_the_schema():
    doc = _doc(UNRELEASED)
    assert doc["version"] == "unreleased"
    assert not update.highlights_errors(doc, update.highlights_schema())

def test_every_unreleased_breaking_entry_has_a_row():
    entries = _changelog_sections()["Unreleased"].get("Breaking", 0)
    rows = [h for h in _doc(UNRELEASED)["highlights"] if h["tag"] == "breaking"]
    assert len(rows) >= entries, (
        f"CHANGELOG [Unreleased] has {entries} Breaking entries but releases/unreleased.yaml has "
        f"{len(rows)} breaking rows; add a row (see releases/README.md)")
```

Parametrize the existing per-release tests over `RELEASE_FILES`; `test_named_fetchers_exist` stays over `FILES`.

- [ ] **Step 2: Run them and see them fail**

Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_update.py tests/test_release_highlights.py`
Expected: failures naming `curated_rows` and the missing `unreleased.yaml`.

- [ ] **Step 3: Schema.** `version` pattern becomes `^(unreleased|\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)$`; `highlights.minItems` becomes `0`; add optional boolean `custom_fetchers` to a row ("true when the change affects only fetchers the user wrote themselves"). Update the schema's descriptions that mention the CHANGELOG fallback.

- [ ] **Step 4: Implement `curated_rows`.** One `git ls-tree --name-only <ref> releases/` per ref to list the yaml files, then one `read_at` per ref. Reuse `_load_highlights`. Delete the functions listed under Removes and fix their callers enough to import (the CLI is rewritten in Task 5; until then `_plan` may call `curated_rows` and pass an empty `releases` list).

- [ ] **Step 5: Seed `releases/unreleased.yaml`.** One breaking row for each of the three `[Unreleased]` `### Breaking` entries in `CHANGELOG.md` (read each entry in full to write its `title` and `fix`): the inventory `pipeline:` block and `asset_type` rows take `custom_fetchers: true`; the Datadog row takes `fetchers: [datadog_*]` narrowed to the fetchers the entry names. Add three to five non-breaking rows chosen from `[Unreleased]` `### Added` for what a customer would most want to know, including `paramify update` itself (`try: paramify update --check`). Titles 72 characters or fewer.

- [ ] **Step 6: `releases/README.md`.** Replace "Write it when you cut the release" with: add a row to `unreleased.yaml` in the PR that makes the change, only when it breaks something or is worth announcing; at release, `git mv releases/unreleased.yaml releases/<version>.yaml`, set `version`, trim to three to five non-breaking rows, and start a new `unreleased.yaml` with `highlights: []`. Document `custom_fetchers` and that a breaking row with neither `fetchers` nor `custom_fetchers` is treated as touching everyone.

- [ ] **Step 7: Run the tests and see them pass**

Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_update.py tests/test_release_highlights.py`
Expected: all pass (tests that exercised removed functions are deleted in this task).

- [ ] **Step 8: Commit** `feat(update): curated rows come from releases/*.yaml at the two commits`

---

### Task 2: Choosing the target from the clone's state

**Files:**
- Modify: `framework/update.py` ("Releases and where you are")
- Test: `tests/test_update.py`

**Interfaces:**
- Produces:

```python
@dataclass(frozen=True)
class Target:
    channel: str            # "branch" or "release"
    ref: str                # what git moves to: "origin/main" or "v0.7.0-beta"
    sha: str
    label: str              # "main" or "0.7.0-beta"
    branch: Optional[str]   # local branch to fast-forward; None for a release
    def to_json(self) -> dict: ...
```

- Produces: `position(root) -> dict` gains `"upstream"` (e.g. `"origin/main"` or `None`), `"behind"` and `"local_commits"` (ints, `None` without an upstream). Existing keys stay.
- Produces: `choose_target(root: Path, pos: dict, releases: Sequence[Release], to: Optional[str] = None) -> Target`. Raises `UpdateError` with the exact messages below. The caller decides "nothing to do" by `target.sha == pos["sha"]`.
- Produces: `fetch(root, timeout=90)` replacing `fetch_tags`: `git fetch --tags --quiet origin`.

Rules and messages:

| State | Result |
|---|---|
| `to == "main"` | `Target("branch", "origin/main", …, "main", "main")` |
| `to` is a release tag whose tree has `framework/update.py` | `Target("release", tag, …, version, None)` |
| `to` is a release tag without it | `UpdateError("{tag} was released before paramify update existed, so you could not update or roll back from it. To use it anyway: git switch --detach {tag}")` |
| `to` is anything else | `UpdateError("{to} is not main or a release tag (recent releases: …)")` |
| on a branch with an upstream, `local_commits == 0` | `Target("branch", upstream, …, branch, branch)` |
| on a branch with an upstream, `local_commits > 0` | `UpdateError("{branch} has {n} commits that {upstream} does not, so update can't fast-forward it. Push or move them, or pin with --to <tag>")` |
| on a branch with no upstream | `UpdateError("{branch} does not follow a remote branch. Run paramify update --to main, or --to <tag> to pin a release")` |
| detached exactly at a release tag | newest release as a `Target("release", …)` |
| detached elsewhere | `UpdateError("this clone is on a detached commit ({short}), not a branch or a release. Run paramify update --to main, or --to <tag>")` |

- [ ] **Step 1: Add the `main_repo` fixture and failing tests**

```python
@pytest.fixture
def main_repo(repo, tmp_path):
    """The same clone on main, one commit behind origin/main."""
    _git(repo, "switch", "-q", "main")
    _commit(tmp_path / "upstream", {"fetchers/demo/alpha/fetch.py": "# v3\n"}, "demo_alpha: read more rows")
    return repo


def test_a_branch_follows_its_upstream(main_repo):
    up.fetch(main_repo)
    pos = up.position(main_repo)
    assert (pos["upstream"], pos["behind"], pos["local_commits"]) == ("origin/main", 1, 0)
    t = up.choose_target(main_repo, pos, up.list_releases(main_repo))
    assert (t.channel, t.ref, t.label, t.branch) == ("branch", "origin/main", "main", "main")
    assert t.sha == _git(main_repo, "rev-parse", "origin/main").strip()


def test_a_tag_follows_newer_tags(repo):
    t = up.choose_target(repo, up.position(repo), up.list_releases(repo))
    assert (t.channel, t.ref, t.label, t.branch) == ("release", "v0.3.0-beta", "0.3.0-beta", None)


def test_local_commits_no_upstream_and_detached_are_refused(main_repo):
    rel = up.list_releases(main_repo)
    _commit(main_repo, {"mine.txt": "x"}, "local work")
    with pytest.raises(up.UpdateError, match="can't fast-forward"):
        up.choose_target(main_repo, up.position(main_repo), rel)
    _git(main_repo, "switch", "-q", "-c", "scratch")
    with pytest.raises(up.UpdateError, match="does not follow a remote branch"):
        up.choose_target(main_repo, up.position(main_repo), rel)
    _git(main_repo, "switch", "-q", "--detach", "HEAD")
    with pytest.raises(up.UpdateError, match="detached commit"):
        up.choose_target(main_repo, up.position(main_repo), rel)


def test_to_accepts_main_and_releases_that_carry_update(repo, tmp_path):
    rel = up.list_releases(repo)
    pos = up.position(repo)
    assert up.choose_target(repo, pos, rel, to="main").ref == "origin/main"
    with pytest.raises(up.UpdateError, match="before paramify update existed"):
        up.choose_target(repo, pos, rel, to="v0.2.0-beta")
    with pytest.raises(up.UpdateError, match="not main or a release tag"):
        up.choose_target(repo, pos, rel, to="archive/feat/old-idea")
    upstream = tmp_path / "upstream"
    _commit(upstream, {"framework/update.py": "# here\n"}, "ship update")
    _git(upstream, "tag", "v0.4.0-beta")
    up.fetch(repo)
    t = up.choose_target(repo, pos, up.list_releases(repo), to="0.4.0-beta")
    assert (t.channel, t.ref) == ("release", "v0.4.0-beta")


def test_a_branch_with_no_tags_in_reach_still_updates(main_repo):
    for tag in _git(main_repo, "tag", "-l").split():
        _git(main_repo, "tag", "-d", tag)
    pos = up.position(main_repo)
    assert pos["tag"] is None and up.describe(pos).startswith("main @ ")
    assert up.choose_target(main_repo, pos, []).channel == "branch"
```

Delete `test_target_selection`, `test_next_steps_one_release` and `test_on_main_past_the_newest_tag_offers_it`.

- [ ] **Step 2: Run and see them fail** — `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_update.py -k "follows or refused or to_accepts or no_tags"`. Expected: `AttributeError: fetch` / `TypeError` on `choose_target`.

- [ ] **Step 3: Implement** `Target`, the `position` additions (`git rev-parse --abbrev-ref @{upstream}` and one `git rev-list --left-right --count HEAD...@{upstream}`), `fetch`, and `choose_target` per the table. "Carries update" is `read_at(root, tag, ["framework/update.py"])` not `None`.

- [ ] **Step 4: Run and see them pass** — same command; expected all pass.

- [ ] **Step 5: Commit** `feat(update): choose the target from the branch or tag the clone is on`

---

### Task 3: Impact on the reader's fetchers and manifests

**Files:**
- Modify: `framework/update.py` ("The user's manifests", `fetcher_changes`, `check_target`)
- Test: `tests/test_update.py`

**Interfaces:**
- Consumes: `curated_rows` rows (Task 1), `Target` (Task 2).
- Produces: `fetcher_reason(name: str, subjects: Sequence[str]) -> Optional[str]` (subjects newest first).
- Produces: `fetcher_changes(root, tree, target_ref, manifests) -> dict` with the existing keys, where each `yours` item is `{"name", "change", "manifests", "from", "to", "reason", "more"}`: `from`/`to` are the `version` in each tree's `fetcher.yaml` (`None` when absent), `reason` is `fetcher_reason(...)`, `more` is the number of other commits that touched the directory. When HEAD is not an ancestor of the target (moving back), `reason` is `None` and `more` is `0`.
- Produces: `touches(row: dict, manifests: Sequence[dict], has_local_fetchers: bool) -> bool`.
- Produces: `breaking_for(rows: Sequence[dict], manifests: Sequence[dict], has_local_fetchers: bool) -> List[dict]`, one item per breaking row: `{"title", "fix", "release", "touches": bool, "why": "fetchers"|"everyone"|"custom"|None, "manifests": [{"manifest", "fetchers"}]}`. Replaces `pair_breaking`.
- Produces: `span(root, head, target_ref) -> {"commits": int, "days": int}` (commit count of `head..target_ref`, whole days between the two commit dates; zeros when moving back).
- Changes: `check_target(root, target: Target, manifests, python=...)` takes a `Target`, checks out `target.sha`, and adds `"has_local_fetchers": bool(linked)` to its result.

`fetcher_reason` accepts a subject only if it names the fetcher, by this pattern (case-sensitive), and returns what follows with the first letter unchanged:

```python
rf"^(?:[a-z]+\({re.escape(name)}\)!?:\s*|{re.escape(name)}(?:\s+\d+\.\d+\.\d+)?:\s*)(?P<rest>\S.*)$"
```

- [ ] **Step 1: Write the failing tests**

```python
def test_fetcher_reason_uses_only_subjects_that_name_the_fetcher():
    subjects = [
        "Bump azure_alert_rules to 0.3.1 above main's 0.3.0",
        "docs(azure): regenerate the readme",
        "fix(azure_alert_rules): suppression fields are null when rules weren't read",
        "azure_alert_rules 0.3.0: read processing rules",
    ]
    assert up.fetcher_reason("azure_alert_rules", subjects) == "suppression fields are null when rules weren't read"
    assert up.fetcher_reason("azure_alert_rules", subjects[3:]) == "read processing rules"
    assert up.fetcher_reason("azure_alert_rules", subjects[:2]) is None
    assert up.fetcher_reason("azure_alert", subjects) is None       # a prefix of the name is not the name


def test_fetcher_changes_carry_versions_reasons_and_counts(main_repo, tmp_path):
    upstream = tmp_path / "upstream"
    _commit(upstream, {"fetchers/demo/alpha/fetcher.yaml": "name: demo_alpha\nversion: 0.2.0\n"},
            "Bump demo_alpha to 0.2.0")
    up.fetch(main_repo)
    manifests = [{"path": "/x", "label": "manifests/prod.yaml", "uses": ["demo_alpha"], "errors_now": []}]
    with up.temp_worktree(main_repo, "origin/main") as tree:
        got = up.fetcher_changes(main_repo, tree, "origin/main", manifests)
    assert got["yours"] == [{"name": "demo_alpha", "change": "changed", "manifests": ["manifests/prod.yaml"],
                             "from": None, "to": "0.2.0", "reason": "read more rows", "more": 1}]


def test_which_breaking_rows_touch_this_clone():
    manifests = [{"label": "manifests/prod.yaml", "uses": ["okta_users", "aws_iam_users"]}]
    scoped = {"tag": "breaking", "title": "t", "fix": "f", "fetchers": ["okta_*"]}
    other = {"tag": "breaking", "title": "t", "fix": "f", "fetchers": ["wiz_*"]}
    everyone = {"tag": "breaking", "title": "t", "fix": "f"}
    custom = {"tag": "breaking", "title": "t", "fix": "f", "custom_fetchers": True}
    assert up.touches(scoped, manifests, False) and up.touches(everyone, manifests, False)
    assert not up.touches(other, manifests, False)
    assert up.touches(custom, manifests, True) and not up.touches(custom, manifests, False)
    rows = up.breaking_for([{**scoped, "release": "unreleased"}, {**other, "release": "unreleased"}], manifests, False)
    assert [(r["touches"], r["why"]) for r in rows] == [(True, "fetchers"), (False, None)]
    assert rows[0]["manifests"] == [{"manifest": "manifests/prod.yaml", "fetchers": ["okta_users"]}]


def test_span_counts_commits_and_days(main_repo):
    up.fetch(main_repo)
    assert up.span(main_repo, "HEAD", "origin/main")["commits"] == 1
    assert up.span(main_repo, "origin/main", "HEAD") == {"commits": 0, "days": 0}
```

Rewrite `test_breaking_rows_name_the_manifests_they_touch` into the third test above, and adjust `test_check_target_classifies_manifests_and_removes_its_worktree` to pass a `Target` and assert `has_local_fetchers`.

- [ ] **Step 2: Run and see them fail** — `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_update.py -k "reason or versions or touch or span or classifies"`.

- [ ] **Step 3: Implement.** Subjects come from one call: `git log --no-merges --format=%x00%s --name-only HEAD..<target_ref> -- fetchers/`, grouped by fetcher directory using the same longest-directory match `fetcher_changes` already does. `_fetcher_dirs` returns name and version per directory.

- [ ] **Step 4: Run and see them pass** — same command.

- [ ] **Step 5: Commit** `feat(update): say which of your fetchers change, their versions and why`

---

### Task 4: Moving, the reinstall rule, and rollback

**Files:**
- Modify: `framework/update.py` ("Working tree", "Switch, reinstall, validate", "State")
- Test: `tests/test_update.py`

**Interfaces:**
- Consumes: `Target` (Task 2).
- Produces: `blocking_changes(root: Path, target_sha: str) -> dict` returning `{"tracked": [...], "untracked": [...]}`: locally modified tracked files that also differ between HEAD and the target, and untracked paths that the target tracks. Empty lists mean the move is safe. `worktree_status` stays as the source of local state.
- Produces: `move(root: Path, target: Target) -> None`. Branch channel: switch to `target.branch` if not on it (creating it from `target.ref` with `git switch -c <branch> --track <ref>` when it does not exist), then `git merge --ff-only --quiet <target.sha>`. Release channel: `git switch --quiet --detach <target.ref>`. Replaces `switch`.
- Produces: `needs_reinstall(root: Path, old_sha: str, new_sha: str) -> bool`: true when `pyproject.toml` differs between the two commits.
- Produces: `restore(root: Path, prev: dict) -> None` for rollback and for a failed reinstall: if `prev["branch"]`, switch to it and `git reset --keep <prev["sha"]>`; otherwise `git switch --detach <prev["sha"]>`.
- `remember_previous(root, pos)` and `forget_previous(root)` keep their signatures and stored keys.

- [ ] **Step 1: Write the failing tests**

```python
def test_only_overlapping_local_changes_block(main_repo, tmp_path):
    up.fetch(main_repo)
    sha = _git(main_repo, "rev-parse", "origin/main").strip()
    (main_repo / "framework/later.py").write_text("# my edit\n")          # not touched by the update
    assert up.blocking_changes(main_repo, sha) == {"tracked": [], "untracked": []}
    (main_repo / "fetchers/demo/alpha/fetch.py").write_text("# mine\n")   # changed by the update
    assert up.blocking_changes(main_repo, sha)["tracked"] == ["fetchers/demo/alpha/fetch.py"]


def test_an_untracked_file_the_target_tracks_blocks(main_repo, tmp_path):
    _commit(tmp_path / "upstream", {"notes.txt": "upstream\n"}, "add notes")
    up.fetch(main_repo)
    (main_repo / "notes.txt").write_text("mine\n")
    sha = _git(main_repo, "rev-parse", "origin/main").strip()
    assert up.blocking_changes(main_repo, sha)["untracked"] == ["notes.txt"]


def test_move_fast_forwards_a_branch_and_restore_puts_it_back(main_repo):
    up.fetch(main_repo)
    pos = up.position(main_repo)
    t = up.choose_target(main_repo, pos, up.list_releases(main_repo))
    up.move(main_repo, t)
    after = up.position(main_repo)
    assert (after["branch"], after["sha"], after["behind"]) == ("main", t.sha, 0)
    up.restore(main_repo, {"branch": "main", "sha": pos["sha"]})
    back = up.position(main_repo)
    assert (back["branch"], back["sha"], back["behind"]) == ("main", pos["sha"], 1)


def test_to_main_creates_the_branch_when_the_clone_has_none(repo):
    _git(repo, "branch", "-D", "main")
    t = up.choose_target(repo, up.position(repo), up.list_releases(repo), to="main")
    up.move(repo, t)
    pos = up.position(repo)
    assert (pos["branch"], pos["upstream"], pos["sha"]) == ("main", "origin/main", t.sha)


def test_reinstall_only_when_pyproject_changed(main_repo, tmp_path):
    old = _git(main_repo, "rev-parse", "HEAD").strip()
    up.fetch(main_repo)
    mid = _git(main_repo, "rev-parse", "origin/main").strip()
    assert up.needs_reinstall(main_repo, old, mid) is False
    _commit(tmp_path / "upstream", {"pyproject.toml": "[project]\nname='x'\n"}, "deps")
    up.fetch(main_repo)
    assert up.needs_reinstall(main_repo, old, _git(main_repo, "rev-parse", "origin/main").strip()) is True
```

- [ ] **Step 2: Run and see them fail** — `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_update.py -k "block or move_ or to_main or reinstall_only"`.

- [ ] **Step 3: Implement** the four functions. `blocking_changes` is one `git diff --name-only HEAD <sha>` intersected with `worktree_status()["tracked"]`, and one `git ls-tree -r --name-only <sha>` intersected with the untracked paths (an untracked directory blocks when any tracked path at the target starts with it).

- [ ] **Step 4: Run and see them pass** — same command.

- [ ] **Step 5: Commit** `feat(update): fast-forward branches, skip needless reinstalls, roll back in place`

---

### Task 5: The command and its output

**Files:**
- Modify: `framework/update_cli.py` (whole flow), `framework/update_view.py` (rewritten), `framework/update.py` (`check_for_update`), `framework/api.py` (docstring of `check_for_update`), `framework/cli.py` (help text)
- Test: `tests/test_update.py`

**Interfaces:**
- Consumes: everything from Tasks 1 to 4.
- Flags: `--to <main|vX.Y.Z-beta>`, `--check`, `--rollback`, `--yes/-y`, `--allow-breaking`, `--json`. `--next` is gone. `--to`, `--check`, `--rollback` stay mutually exclusive.
- `--json` document keys: `ok`, `errors`, `channel`, `fetched`, `current` (position plus `label`), `target` (`Target.to_json()`), `direction` (`"forward"`, `"back"` or `"rollback"`), `span`, `fetchers` (from `check["fetchers"]`), `breaking` (from `breaking_for`), `highlights` (non-breaking curated rows, at most five), `manifests`, `check`, `blocking` (when refused), `switched`, `reinstall` (`{"ok", "skipped", "command", "error"}`), `validate`, `up_to_date`, `version` (the target label, on success).
- `update.check_for_update(root, now=None, fetch=True) -> Optional[dict]` returns `{"channel", "current", "latest", "update_available", "waiting"}` where `waiting` is the text the notice shows: `"{n} new commits on {branch}"` or `"{version} is out"`. The background fetch is `git fetch --tags --quiet origin`.
- Exit codes: update 0 done or nothing to do, 1 refused or failed; `--check` 0 up to date, 1 an update is waiting, 2 cannot tell (a `choose_target` refusal, or no upstream and no tags to compare).

Order of the update flow, each step's failure ending the run with the message shown:

1. Container check (unchanged).
2. Fetch; on failure continue and note "couldn't reach origin, so this compares against what this clone last fetched".
3. `position`, `choose_target`. `UpdateError` ends the run. `target.sha == pos["sha"]` prints "Nothing to do: {label} is up to date." and exits 0.
4. `blocking_changes`; any entry ends the run listing the files.
5. `user_manifests`, `curated_rows(root, "HEAD", target.sha)`, `span`.
6. Header line.
7. Pre-check step (`check_target`), which also yields `fetchers` and `has_local_fetchers`.
8. Print, in this order: Your fetchers, Breaking (rows with `touches`), New (up to five rows), the one-line rest (other fetchers changed, added, removed; breaking rows that do not touch you; changelog link at the target).
9. Python too old ends the run, as now.
10. Unattended (`--yes` or `--json`) without `--allow-breaking` stops when any manifest status is `breaks` or any breaking row has `touches`. The message names the count of each.
11. Confirm. `--json` without `--yes` reports the plan and exits 1 with "switching needs confirmation: pass --yes".
12. `remember_previous`, `move`, reinstall if `needs_reinstall` else record `skipped`, `validate_all`, closing lines with `try` commands and the rollback hint.
13. A failed reinstall calls `restore`, reinstalls the old code, and exits 1.

`--rollback` reads `state["previous"]`, refuses on `blocking_changes` against the previous sha, confirms, calls `restore`, then steps reinstall and validate as above, and forgets the previous position.

View: plain Rich with named styles (`bold`, `dim`, `green`, `yellow`, `red`, `cyan`) and no panels, gradients, pills or light/dark detection. `Look`, `_mix`, `_pill_pair`, `light_terminal`, `preload`, `_card_width` and the two palette tests go. Layout follows the sketch in the spec. Output is capped at 100 columns.

- [ ] **Step 1: Write the failing tests.** Keep the names of existing CLI tests where the behaviour survives and rewrite their bodies to the new shape; the list below is the full set this task owns.

```python
def test_update_on_main_fast_forwards_and_skips_the_reinstall(main_repo, stubs):
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 0, result.stdout
    assert (doc["channel"], doc["target"]["label"], doc["span"]["commits"]) == ("branch", "main", 1)
    assert doc["switched"] and doc["reinstall"]["skipped"] and stubs["reinstall"] == 0
    assert _git(main_repo, "status", "-sb").startswith("## main...origin/main\n")
    assert up.read_state(main_repo)["previous"]["branch"] == "main"


def test_update_on_a_tag_moves_to_the_newest_release(repo, stubs):          # needs v0.4.0-beta carrying update.py
def test_nothing_to_do_when_the_branch_is_current(main_repo, stubs):         # after one update, exit 0, up_to_date
def test_json_without_yes_plans_but_does_not_switch(main_repo, stubs):       # exit 1, HEAD unchanged, plan keys present
def test_unattended_stops_only_for_breaking_rows_that_touch_you(main_repo, stubs, tmp_path):
    # upstream adds unreleased.yaml with a breaking row for demo_gamma (unused): --yes succeeds.
    # then a breaking row for demo_alpha (used): --yes exits 1 naming it; --yes --allow-breaking exits 0.
def test_unattended_stops_for_an_unscoped_breaking_row(main_repo, stubs, tmp_path):
def test_manifests_that_would_break_also_stop_an_unattended_run(main_repo, stubs, monkeypatch):
def test_overlapping_local_changes_are_refused_and_listed(main_repo, stubs):  # exit 1, doc["blocking"]["tracked"]
def test_rollback_keeps_a_branch_user_on_the_branch(main_repo, stubs):        # update, rollback: on main, behind 1, state cleared
def test_rollback_returns_to_the_previous_release_once(repo, stubs):
def test_a_failed_reinstall_puts_the_old_commit_back(main_repo, stubs, monkeypatch, tmp_path):  # upstream changes pyproject
def test_check_exit_codes(main_repo):
    assert _run("--check")[0].exit_code == 1            # origin/main is ahead
    _git(main_repo, "merge", "-q", "--ff-only", "origin/main")
    assert _run("--check")[0].exit_code == 0
    _git(main_repo, "switch", "-q", "--detach", "HEAD")
    assert _run("--check")[0].exit_code == 2
def test_offline_update_uses_what_the_clone_last_fetched(main_repo, stubs, monkeypatch):
    up.fetch(main_repo)
    monkeypatch.setattr(up, "fetch", lambda root, timeout=90: (_ for _ in ()).throw(up.UpdateError("offline")))
    result, doc = _run("--yes", "--json")
    assert result.exit_code == 0 and doc["fetched"] is False and doc["switched"]
def test_flags_are_exclusive(repo):                                           # --to with --check, and --next is unknown
def test_notice_names_what_is_waiting(main_repo, monkeypatch):
    up.fetch(main_repo)
    info = up.check_for_update(main_repo, fetch=False)
    assert (info["channel"], info["update_available"], info["waiting"]) == ("branch", True, "1 new commit on main")
def test_plan_renders_without_colour_and_within_100_columns(main_repo, stubs, monkeypatch):
    # NO_COLOR=1, COLUMNS=100; a human run answered "n": output has "Your fetchers",
    # "demo_alpha", "read more rows", no line longer than 100, exit 1, "Nothing changed."
```

Keep unchanged: the container tests, `test_temp_worktree_is_removed_when_the_body_raises`, `test_run_validate_reports_a_missing_package_as_unchecked`, `test_update_check_fetches_at_most_once_a_day`, `test_update_check_is_quiet`, `test_notice_is_due_once_a_day`, `test_notice_stays_out_of_json_and_pipes`, `test_install_command_uses_uv_when_the_venv_has_no_pip`. Delete `test_view_palette_matches_the_tui_palette`, `test_every_highlight_tag_has_a_pill`, `test_a_jump_without_breaking_changes_needs_only_yes` (covered above) and `test_dirty_refusal_lists_files_for_humans` (folded into the overlap test).

- [ ] **Step 2: Run and see them fail** — `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_update.py`.

- [ ] **Step 3: Rewrite `update_view.py`** to the plain renderables the flow needs.

- [ ] **Step 4: Rewrite the flow in `update_cli.py`** in the order above, and `check_for_update` / `maybe_notice` to use `waiting`.

- [ ] **Step 5: Update the help text in `framework/cli.py`** to:

```
Upgrade (see docs/versioning_guide.md):
  paramify update [--to main|vX.Y.Z-beta] [--yes] [--allow-breaking] [--json]
  paramify update --check [--json]             # exit 0 up to date, 1 update waiting, 2 can't tell
  paramify update --rollback [--yes] [--json]  # back to where you were before the last update
```

- [ ] **Step 6: Run and see them pass** — `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_update.py tests/test_release_highlights.py tests/test_cli.py tests/test_core_imports.py`. Expected: all pass.

- [ ] **Step 7: Run it for real in this worktree.** `NO_COLOR=1 COLUMNS=100 .venv/bin/paramify update --check; echo $?` then `.venv/bin/paramify update </dev/null`. Expected: this branch's upstream is `origin/main` and it has commits `origin/main` lacks, so `--check` exits 2 and the second command refuses with the "can't fast-forward" message and exits 1, changing nothing. Then make a scratch clone of this worktree's branch that sits a few hundred commits behind (`git clone -q . <scratch>/clone && git -C <scratch>/clone reset -q --hard HEAD~300`), point `PYTHONPATH` at this worktree, and run `paramify update </dev/null` there to read a real plan against real history. Confirm `git status -sb` is unchanged and `git worktree list` shows no leftover temp tree.

- [ ] **Step 8: Commit** `feat(update): one flow for main and pinned releases, with plain output`

---

### Task 6: Docs, the screenshot, and the line budget

**Files:**
- Modify: `docs/versioning_guide.md`, `docs/releasing_guide.md`, `docs/cli_guide.md`, `README.md`, `CHANGELOG.md`, `tools/update_screenshots.py`
- Delete: `docs/img/update/check.svg`, `container.svg`, `dirty.svg`, `rollback.svg`
- Regenerate: `docs/img/update/update.svg`

- [ ] **Step 1: `docs/versioning_guide.md`.** Replace "Run a release tag, not `main`" with the two ways to run: follow `main` (the default clone) or pin a release. One table of commands (`paramify update`, `--to vX.Y.Z-beta`, `--to main`, `--check`, `--rollback`), what the notes show, what stops an unattended run and how `--allow-breaking` overrides it, that the reinstall is skipped when `pyproject.toml` is unchanged, that pinning needs a release cut after this feature, and the manual steps as fallback. Remove references to deleted images.
- [ ] **Step 2: `docs/releasing_guide.md` step 2.** The highlights file is made by renaming `releases/unreleased.yaml`, per `releases/README.md`.
- [ ] **Step 3: `README.md` and `docs/cli_guide.md`.** One accurate sentence each: `paramify update` brings a clone up to date with `main`, or with the newest release when pinned, after checking your manifests against it.
- [ ] **Step 4: `CHANGELOG.md`.** Rewrite the existing `paramify update` entry under `[Unreleased]` `### Added` to describe both channels in six lines or fewer.
- [ ] **Step 5: Screenshot.** Reduce `tools/update_screenshots.py` to the one scene of an update on `main` and run it to regenerate `docs/img/update/update.svg`.
- [ ] **Step 6: Line budget.** Run `wc -l framework/update.py framework/update_cli.py framework/update_view.py`. Expected: total at or under 1,450. If over, cut from the view first.
- [ ] **Step 7: Full check.** `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_update.py tests/test_release_highlights.py tests/test_cli.py tests/test_core_imports.py` and the repo's lint and type commands as `.github/workflows/ci.yml` runs them, on the changed files. Expected: all pass.
- [ ] **Step 8: Commit** `docs: paramify update follows main or a pinned release`
