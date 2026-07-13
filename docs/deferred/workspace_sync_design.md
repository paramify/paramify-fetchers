# [DEFERRED] Workspace materialize + sync reconcile — design

**Status:** deferred, 2026-07-13 — superseded by the overlay model in
[`../distribution_design.md`](../distribution_design.md). This design solved
"users edit shipped files in place, upgrades must reconcile around the edits."
The expected customization turned out to be *creating* fetchers for
unsupported platforms, not modifying built-ins — which the overlay model
serves with a fraction of the machinery. **Revive this design only if
evidence shows customers routinely editing many built-ins in place** (at that
point copy-on-write overrides rot and reconcile earns its complexity). The
per-file decision table (§8.1) and migration framework (§9) here are fully
specified and reviewed — start from them, not from scratch.

**Audience:** whoever builds the fork.
**Related:** [`../versioning.md`](../versioning.md) (the contract + bump policy),
[`../releasing.md`](../releasing.md) (how a release is cut),
[`../design.md`](../design.md) (framework overview).

## 1. The problem

Today the tool is **clone-only**. `api.find_repo_root()` walks up from the cwd
looking for sibling `fetchers/` + `framework/` dirs, schemas load from
`repo_root/framework/schemas/`, and fetchers run as subprocesses out of
`repo_root/fetchers/`. That makes it trivial to add a fetcher (drop a directory
in the writable tree) but ties the whole tool to a working checkout.

Two consequences we want to fix:

1. **No clean installed distribution.** `pip install`/`brew install` of the
   current package ships only `framework*` — no fetchers, and `find_repo_root()`
   throws unless you happen to be inside a clone. (`releasing.md` → *Artifacts*
   already flags this as the blocker deferring wheel/PyPI.)
2. **`git pull` clobbers local edits.** Because the checkout *is* the
   distribution, a customer's edits to a built-in `fetcher.yaml` collide with
   upstream changes to the same tracked file — the pull conflicts or stomps
   uncommitted work. Every built-in is a landmine.

## 2. Goal

Ship the tool as a normal installable package whose **content is user-owned and
self-updating**:

- `brew install` / `pipx install` brings the **core** (engine + CLI + a bundled,
  read-only snapshot of content).
- A first-run step **materializes** the content into a user-writable
  **workspace** and records exactly what was shipped.
- On upgrade, a **reconcile** step updates only the files the user never touched,
  preserves everything they did, and never silently discards a customization.
- Adding a fetcher stays trivial — you create a directory in the workspace.

### Decision already made (logged, #224)

Content is **bundled with each core release**, not shipped on a separate channel.
One version number for core+content ⇒ no core↔content compatibility matrix, and
`paramify sync` is a **purely local** reconcile (no network). The accepted
tradeoff: shipping a new/fixed fetcher requires cutting a release.

### Non-goals

- PyInstaller / single-file frozen binaries (blocked separately: Python fetchers
  launch via `sys.executable`, which points at the frozen app, not Python).
- A network content registry / plugin marketplace.
- Changing what a fetcher *is* or the envelope format.

## 3. Vocabulary

| Term | Meaning | Owner | Writable |
|---|---|---|---|
| **Core** | `framework/` engine + CLI + JSON schemas | us (package manager) | no |
| **Pristine bundle** (`framework/_pristine/`) | read-only snapshot of shipped content (fetchers, example manifests; skills deferred — §11), baked into the release | us | no |
| **Workspace** | materialized, user-editable copy of the content | user | yes |
| **Manifest** (`.manifest.json`) | record of what we shipped into the workspace + hashes | tool | (tool-managed) |
| **User data** | run manifests, `EVIDENCE_DIR` output | user | yes |

Three data classes, kept strictly separate: **tool assets** (core, read-only) ·
**managed content** (workspace, reconciled by `sync`) · **user data** (cwd, never
touched by `sync`).

## 4. On-disk layout

```
INSTALL (read-only, package-manager owned) ───────────────
…/site-packages/
  framework/
    schemas/         fetcher_schema.json, category_schema.json, …
    _pristine/                         ← the shipped content snapshot
      fetchers/                          (inside the package, so importlib.resources
      examples/                           resolves it and nothing non-package lands
    …engine…                              top-level in site-packages — see §10)

WORKSPACE (writable, user owned) ─────────────────────────
$PARAMIFY_HOME  (default: platformdirs user_data_dir — see §13)
  fetchers/            ← materialized + your own; fetchers RUN from here
  examples/
  .manifest.json       ← what we shipped, with hashes
  .backups/<version>/  ← pre-migration snapshots

USER DATA (writable, cwd) ─────────────────────────────────
<cwd>/manifests/, <cwd>/evidence/   ← never touched by sync
```

Claude skills are **deferred out of v1** (decision #234; see §11): `sync`
materializes only `fetchers/` and `examples/`, which is what buys the §12
invariant that sync never writes outside `$PARAMIFY_HOME`.

Note a *benefit* of running fetchers out of the writable workspace: fetchers that
write next to themselves (e.g. the checkov git-clone scanner) work again — they
were a known problem for a read-only install.

## 5. Discovery: single root → search path

The discovery seam is `config_loader.discover_fetchers(repo_root)` and
`discover_platforms(repo_root)`, plus schema resolution in
`config_loader._load_schema()`. The change:

**Schema resolution** moves off the cwd walk. Schemas are core, so they resolve
from the installed `framework` package via `importlib.resources` — with the
cwd path kept as a dev fallback:

```python
def load_schema(name="fetcher_schema.json") -> dict:
    # 1. dev checkout (editable install): framework/schemas/ next to source
    local = Path(__file__).parent / "schemas" / name
    if local.exists():
        return json.loads(local.read_text())
    # 2. installed: packaged data via importlib.resources
    return json.loads(resources.files("framework.schemas").joinpath(name).read_text())
```
(Requires shipping the schemas as package data — see §10. Once they ship,
branch 1 also resolves in site-packages — `framework/schemas/` is a real
directory there — so branch 2 effectively covers only zip imports. Keep both,
but the comment should say branch 1 is what serves installed users.)

**Fetcher discovery** takes an ordered list of roots instead of one, and unions
results; earlier roots win a name collision so a user copy can shadow a built-in:

```python
def fetcher_roots() -> list[Path]:
    roots = []
    if env := os.environ.get("PARAMIFY_FETCHERS_PATH"):   # 1 explicit override
        roots += [Path(p) for p in env.split(os.pathsep)]
    if co := _find_checkout_root():                        # 2 dev clone (cwd walk)
        roots.append(co / "fetchers")
    roots.append(workspace_home() / "fetchers")            # 3 workspace
    return [r for r in roots if r.is_dir()]

def discover_fetchers(roots: list[Path]) -> dict[str, Fetcher]:
    schema = load_schema(); validator = Draft202012Validator(schema)
    found = {}
    for root in roots:                     # precedence: first root wins on name
        for fetcher in _walk(root, validator):
            found.setdefault(fetcher.name, fetcher)
    return found
```

The checkout outranks the workspace **on purpose**: a developer inside a clone
who has ever run `sync` would otherwise have stale workspace copies silently
shadowing their in-tree edits — the most confusing possible failure of the §11
"dev clone keeps working" promise.

Two collision rules, kept distinct. **Within one root**, a duplicate name stays
a hard error, exactly as today (`config_loader.py:72`). **Across roots**, first
root wins — but the shadow is *reported*, never silent: `catalog` and `doctor`
list every name resolved by shadowing and which root lost.

`discover_platforms()` gets the same treatment: each root's `_categories/*.yaml`
is loaded and unioned, first root winning **per category file**.

`find_repo_root()` stays for the dev path but is no longer the only way to
locate content. Everything downstream (`catalog`, `run`, `doctor`) calls
`fetcher_roots()`.

## 6. The manifest — what makes non-clobbering possible

The single new asset. Without a record of *what we shipped*, "the user changed
this file" is indistinguishable from "we changed this file upstream." The
manifest is that record, written at materialize time and read at every sync.

```json
{
  "schema": "paramify-workspace-manifest/v1",
  "tool_version": "0.4.0",
  "contract_version": 2,
  "materialized_at": "2026-07-13T00:00:00Z",
  "files": {
    "fetchers/aws/storage_encryption_status/fetcher.yaml": {
      "sha256": "9f2c…", "shipped_tool_version": "0.4.0", "contract_version": 2
    },
    "fetchers/aws/storage_encryption_status/fetch.py": { "sha256": "1a7b…" },
    "examples/demo.yaml": { "sha256": "c3d4…" }
  }
}
```

Per file we store the content hash of exactly what we last put there. That is
the "base" in a 3-way comparison: **base = manifest hash**, **ours = workspace
file**, **theirs = new pristine file**. (`materialized_at` is stamped by the
caller, not inside any pure-function core — timestamps are a side input.) Hash
**newline-normalized** text (CRLF→LF), not raw bytes — otherwise a Windows/git
line-ending rewrite makes an untouched file look edited and fires a spurious
conflict on every sync (§13). Normalization applies to **text files only**:
`fetchers/` also carries PNGs/JPEGs/SVGs and fixture files, and CRLF-normalizing
a binary manufactures the same spurious-conflict bug in the opposite direction.
Sniff binary the way git does (NUL byte in the first 8 KB ⇒ binary ⇒ hash raw
bytes). (Worth deciding separately whether `fetchers/logos/` — README furniture,
unused at run time — belongs in the pristine bundle at all.)

## 7. Lifecycle commands (CLI surface)

New `@app.command`s in `framework/cli.py`, alongside `list`/`catalog`/`run`/`doctor`.

### `paramify sync`
The workhorse. Idempotent. Runs materialize-or-reconcile against the currently
installed `_pristine/`. No network.

| Flag | Effect |
|---|---|
| `--dry-run` | report the plan (per-file classification), touch nothing |
| `--json` | machine-readable plan/report (consistent with other commands) |
| `--force-theirs GLOB` | on conflict, take upstream for matching paths (backup first) |
| `--force-mine GLOB` | on conflict, keep local, discard the incoming `.new` |
| `--no-migrate` | reconcile files but skip schema migrations (escape hatch) |

Output is a grouped report: **updated**, **added**, **kept (yours)**,
**kept deleted (yours)**, **conflicts (.new written)**, **still conflicted**,
**migrated**, **removed**, **quarantined**.

### `paramify migrate` (may be folded into `sync`)
Runs pending contract migrations on workspace content only. Separated so it can
be run/tested in isolation and so `sync --no-migrate` has a counterpart.

### `paramify doctor` (extend the existing command, `cli.py:335`)
Add a distribution section: install path + `tool_version`, workspace path +
manifest `tool_version`/`contract_version`, whether a sync is pending (installed
pristine newer than manifest), and any quarantined fetchers.

## 8. The sync algorithm

```
1. locate INSTALL/_pristine and WORKSPACE; load .manifest.json
       (first run = no manifest AND empty workspace; a populated workspace with
        a missing/corrupt manifest is NOT a first run — it flows through the
        §8.1 table like any other sync and is never blind-copied over)
2. if contract_version(pristine) > contract_version(manifest):
       plan migrations (§9); snapshot workspace → .backups/<tool_version>/
3. for each file in the NEW pristine set:
       classify by (workspace hash, manifest hash, new pristine hash) → §8.1
       apply the action (respecting --dry-run / --force-*)
4. for each file in the manifest but absent from new pristine:  → "removed" rule
5. run migrations on workspace files still at the old contract_version
6. re-validate every workspace fetcher against the installed schema;
       any failure ⇒ quarantine (mark, keep, report — never delete, never run;
       the mark is a "quarantined": true flag on the file's .manifest.json
       entry, which discovery reads and skips)
7. rewrite .manifest.json to the new shipped set + hashes
8. print the grouped report
```

The manifest rewrite is deliberately last (step 7), so a sync can die at any
point without corrupting state — **provided** re-running is safe. The
**ws == new** short-circuit (first row of §8.1) is what makes it safe: on
re-run, files updated before the crash classify as *already current* instead of
falling through to a false "you edited it AND we shipped" conflict. Without
that row, one interrupted sync turns every already-updated built-in into a
spurious `.new`.

### 8.1 Per-file decision table

Rows are checked in order; the first match wins. "ws / manifest / new" are the
workspace file, the manifest entry, and the new pristine file; a missing file
or entry fails every hash equality. The two groups mirror steps 3 and 4 of the
algorithm.

**Files in the new pristine set** (step 3):

| State | Detected by | Action |
|---|---|---|
| **Already current** | ws == new | **No-op**; record in manifest. First check — this is what makes an interrupted sync safely re-runnable |
| **New built-in** | absent from ws and manifest | **Add** (materialize). On a true first run, every file takes this row |
| **You deleted it** | absent from ws; in manifest | **Stays deleted** — never resurrect; drop the manifest entry, report once |
| **You never touched it** | ws == manifest | **Update in place** to new pristine |
| **You edited it, we didn't** | ws ≠ manifest, new == manifest | **Keep yours** (nothing to apply) |
| **You edited it AND we shipped a new version** | in all three, all hashes differ | **Conflict:** keep yours, write ours as `<file>.new`, report |
| **No record** | in ws, absent from manifest, ws ≠ new | **Conflict** (as above) — never blind-overwrite. Arises on first run over a populated workspace, a lost/corrupt `.manifest.json`, or upstream re-adding a path we earlier kept |

**Manifest entries absent from the new pristine set** (step 4):

| State | Detected by | Action |
|---|---|---|
| **We removed it, you never touched it** | ws == manifest | Remove the file, drop the entry |
| **We removed it, you edited it** | in ws, ws ≠ manifest | Keep + warn; drop the entry (the file becomes user content) |
| **Gone everywhere** | absent from ws | Drop the entry |

Workspace files in neither the manifest nor the pristine set are pure user
content — neither pass ever visits them.

This table *is* the answer to "will it overwrite my changes." Only the conflict
rows have real UX; the rest are mechanical.

### 8.2 Conflict resolution

Default = **`.new` file** (dpkg/pacman style): zero data loss, dead simple, and
non-interactive-safe for cron. `--force-mine`/`--force-theirs` and a future
interactive/TUI review are layered on top. A 3-way *content* merge is a possible
enhancement but not required for v1.

`.new` handling is itself idempotent: rewrite `<file>.new` only when its content
would differ, and report an unresolved carry-over as **still conflicted** (with
the version it first appeared in), separately from new conflicts — otherwise
every sync re-announces the same conflict as if it were news.

## 9. Schema evolution & migrations

Per `versioning.md`, the schemas are **the contract**. Two change classes:

### Additive (non-breaking) — brew upgrade only
New **optional** field. The permissive schema (no top-level
`additionalProperties: false`) means old files still validate. After
`brew upgrade` the new validator accepts the field; existing workspace fetchers
keep working untouched. `sync` is only needed to receive *our* built-ins that use
the field. `versioning.md` bump: **minor**.

### Breaking — needs a migration
Removing/renaming/retyping a field, or adding a **required** one. Existing files
become invalid on upgrade. `versioning.md` bump: **major** (pre-1.0: **minor**).

**Enabler — a contract version marker.** `fetcher.yaml` needs to say which shape
it is, or migrations can't reliably target it. The envelope already does this
(`schema_version` in `framework/envelope.py`); mirror it: add a required
`schema_version` (or `contract_version`) to `fetcher_schema.json`. This is the
migration counterpart of the workspace manifest — the thing that makes safe
breaking changes *possible*. Bootstrap rule: **a file with no marker is
contract version 1** — adding the required marker is itself the first breaking
change, so it rides its own grace window (the loader treats an absent marker as
v1; the v1→v2 migration stamps it).

**Migration framework.** Migrations ship in the core with the release that breaks
the format:

```
framework/migrations/
  __init__.py         # registry: ordered [(1→2, fn), (2→3, fn), …]
  v1_to_v2.py         # def migrate(doc: dict) -> dict   (pure, deterministic)
```
Properties: **chained** (v1→v2→v3, so version-skippers catch up in order),
**version-gated + idempotent** (re-running is a no-op), **pure** (dict→dict, so
unit-testable with fixtures). `sync`/`migrate` apply pending migrations to each
workspace fetcher, bump its marker, and re-validate.

**Recommended posture — a one-release grace window.** Avoid a hard cutover: for
one release the loader accepts *both* shapes and normalizes old→new in memory
with a deprecation warning; the *next* release drops the old shape. Turns a break
into announce → warn → remove (matches the post-1.0 deprecation policy in
`versioning.md`, applied early).

**The hard case — user-edited AND breaking.** A built-in the user edited (row 3)
that *also* changed shape:
- migration is a pure structural transform that commutes with their edit ⇒ apply
  it to their file, keep their customization, bump the marker;
- migration can't apply cleanly ⇒ **quarantine**: keep their file, mark it
  invalid, write our migrated version as `.new`, surface it loudly with the
  migration notes. Two invariants: never leave a silently-broken fetcher, never
  silently discard a customization.

## 10. Release integration

Slots into the existing `releasing.md` steps:

- **Build the pristine bundle into the artifact.** Add
  `[tool.setuptools.package-data]` so the wheel/tarball ships
  `framework/schemas/*.json`, `framework/tui/styles/*.tcss`, and a
  `framework/_pristine/` tree assembled from `fetchers/` and `examples/`
  (skills deferred — §11). `_pristine/` lives *inside* the package: resolvable
  via `importlib.resources`, shippable by the existing `include = ["framework*"]`,
  and nothing non-package lands top-level in site-packages. The assembly step
  must run **inside the build backend** (a custom setuptools `build_py` hook),
  not in a release workflow — the supported install is still `pip install` from
  the GitHub source tarball, and a workflow-side copy would leave source
  installs with no `_pristine/`. This is the change that unblocks the deferred
  wheel/PyPI item in `releasing.md`.
- **Author a migration** if the release makes a breaking schema change (same PR).
- **Changelog:** a `BREAKING` subsection with migration notes when applicable;
  keep calling out the three version axes.
- **Bump:** per `versioning.md` bump policy (breaking ⇒ minor pre-1.0).

Everything stays manual/tag-driven; nothing here forces `release-please`.

## 11. Backwards-compat & open questions

- **Dev clone keeps working.** `pip install -e .` in a checkout: the cwd walk is
  root #2 and **outranks the workspace** (§5), schemas resolve from the local
  `framework/schemas/`, no `_pristine` needed. This is also how the existing
  test suite keeps running.
- **RESOLVED — skills are deferred out of v1** (decision #234, 2026-07-13).
  v1 `sync` materializes only `fetchers/` and `examples/`; skills stay in the
  repo for clone users and out of the pristine bundle. This sidesteps the
  user-global (`~/.claude/skills/`) vs project-scoped (`<cwd>/.claude/skills/`)
  placement question until there's demand, and buys the §12 invariant that
  sync never writes outside `$PARAMIFY_HOME`.
- **Workspace root** — resolve with `platformdirs.user_data_dir("paramify")` so
  each OS gets its native location (§13), with a `$PARAMIFY_HOME` override.
- **Multi-project.** One workspace per user, or per project? Start with one per
  user; `$PARAMIFY_HOME` lets a project opt into its own.

## 12. Safety & recoverability

- **Sync writes only inside `$PARAMIFY_HOME`.** With skills deferred (§11), v1
  sync touches nothing outside the workspace — no cwd files, no `~/.claude`, no
  install tree. One directory to back up, one to blow away.
- **Backup before migrating** → `.backups/<tool_version>/` so a bad transform is
  recoverable.
- **`--dry-run`** reports the full plan before touching anything.
- **Validate after** every sync/migrate; anything still invalid is **quarantined**
  (kept + flagged), never run and never deleted.
- **Refuse, don't crash.** A fetcher that fails schema validation is skipped with
  a visible error (candidate for the deferred `SETUP-ERR` run status), not a
  whole-run abort.

## 13. Platform nuances (macOS / Windows / Linux)

The **framework** (discovery, sync, migrations, CLI) is pure Python + `pathlib`
and portable. The nuances live in two places: **how you install** and **how
fetchers run**.

### Install path
- **Homebrew is macOS + Linux only** — there is no brew on Windows. The universal
  path is **pipx** (Mac/Windows/Linux); brew is a Mac/Linux convenience layer
  (another reason the prototype goes pipx-first, §15). A native Windows package
  could later use Scoop or WinGet.
- **pipx PATH nuance.** Console scripts of extras (e.g. `checkov`) install into
  the pipx venv's `bin/`, which pipx does **not** put on `PATH` — and the
  executor passes children only the inherited `PATH` (`executor.py:32`). A bash
  fetcher shelling out to `checkov` works in the clone-venv world and breaks
  under pipx. Either the executor prepends `Path(sys.executable).parent` to the
  child `PATH`, or checkov joins the external-CLI list alongside `aws`/`jq`.

### Fetcher execution — the big one
- **90 of 109 fetchers are `bash`.** `runner/executor.py:248` launches them as
  `["bash", entry]`, so they need `bash` on `PATH`. **Stock Windows has none** —
  the bulk of the catalog is unusable on native Windows without WSL, Git Bash, or
  Cygwin. The **19 python** fetchers use `sys.executable` (`executor.py:246`) and
  are portable.
- The executor invokes the interpreter explicitly (no reliance on the shebang or
  the executable bit — neither of which Windows honors), so bash fetchers *do*
  run if a `bash` is on `PATH`. But the scripts assume POSIX and call
  `aws`/`kubectl`/`jq`/`git`/`checkov`, which must be installed and on `PATH`. A
  brew tap can declare those as deps on Mac/Linux; Windows has no single
  declaration.

### Paths & the workspace (affects `sync`)
- **Workspace location differs by OS.** `~/.paramify` is a Unix dotfile idiom;
  Windows convention is `%LOCALAPPDATA%`. Use
  `platformdirs.user_data_dir("paramify")` → `~/Library/Application Support/paramify`
  (Mac), `%LOCALAPPDATA%\paramify` (Windows), `~/.local/share/paramify` (Linux).
  Keep `$PARAMIFY_HOME` as an override. (Resolves the §11 open question.)
- **Search-path separator** for `$PARAMIFY_FETCHERS_PATH` is `os.pathsep` — `;` on
  Windows, `:` on Unix. Never hardcode `:`. Build every path with `pathlib.Path`,
  never string-join.

### `sync` correctness gotchas
- **Line endings.** Hash newline-normalized text, not raw bytes (see §6). The
  subtlest cross-platform bug in the model — design the hasher around it.
- **Case sensitivity.** macOS (case-insensitive default) and Windows differ from
  Linux (case-sensitive). Store manifest keys as normalized POSIX forward-slash
  relative paths; don't let name-collision/dedup logic behave differently per OS.
- **Atomic writes.** `os.replace()` is atomic cross-platform on one volume (good
  for the manifest), but Windows can't replace an open file — close handles first.

### The equalizer
- **Containers normalize all of the above** — the image is Linux, so `bash`, the
  external CLIs, and POSIX paths all just work. For Windows-heavy customers the
  container (Docker Desktop) is the recommended path; the native pip/brew install
  is really a Mac/Linux operator convenience.

### The container story

The clone-based image build keeps working **verbatim**: `deploy/Dockerfile`
COPYs the repo into `/app` and `pip install -e .`s it, and the cwd walk (root
#2 in §5) finds `/app/fetchers`. Run manifests are user data — the existing
bake-from-`manifests/` flow (`deploy/README.md`) is untouched.

The gap this design creates: post-rewrite, a customer's customizations live in
the **workspace — outside the Docker build context**. `docker build` from a
clone ships pristine built-ins, not their edited or custom fetchers; nothing
errors, the content is just missing at 2am when cron fires. And a pipx/brew
install has no clone (and no `deploy/`) to build from at all.

The bridge is the search path itself:

- **Near-term pattern** (document in `deploy/README.md`): `COPY` the user's
  workspace fetchers into the image (e.g. `/overrides`) and set
  `PARAMIFY_FETCHERS_PATH=/overrides` — root precedence makes their copies
  shadow the baked-in built-ins, reusing §5's shadowing mechanism as-is.
- **End state:** the future `paramify package` command (`deploy/README.md`
  already names this bundle as its template) generates the build context from
  the *merged workspace* plus the cwd `manifests/` — making the workspace, not
  a checkout, the canonical content source for images.

## 14. Testing strategy

The historical failure mode is "green in dev, broken installed" — every current
test runs from the clone. Add:

- **Installed-layout tests** — build the wheel, install into a temp venv, run
  `sync`/`catalog`/`run` with no checkout on disk. The thing the clone tests can't
  catch.
- **Sync decision-matrix tests** — fabricate a workspace + manifest + new pristine
  and assert every row of the §8.1 table produces the right action (incl. `.new`,
  quarantine, removal, a deletion staying deleted, and the no-record conflict).
- **Migration round-trip tests** — fixture `fetcher.yaml` at vN → migrate → assert
  vN+1 shape + schema-valid; assert idempotence and chaining (v1→v3).
- **Upgrade simulation** (the prototype acceptance test, §15).

## 15. Prototype plan (build order for the fork)

Prove the risky parts first; each phase is independently demonstrable.

1. **Multi-root discovery** — `fetcher_roots()` + `discover_fetchers(roots)` +
   `importlib.resources` schema loading. Prove: `catalog` finds fetchers from a
   workspace dir with no cwd checkout.
2. **Package data + `_pristine` build** — ship schemas + a `_pristine/` tree in
   the wheel; `pip install` into a clean venv and confirm the core resolves.
3. **Manifest + `sync` (materialize + reconcile, `.new` conflicts)** — no
   migrations yet. Prove the §15 acceptance test.
4. **Contract version + migration framework** — add `schema_version` to the
   schema, a trivial v1→v2 migration, and wire it into `sync`. Prove a breaking
   change survives with a user edit preserved or cleanly quarantined.
5. **`doctor` extension, backups, `--dry-run`, quarantine** — the safety layer.
6. **`brew` tap / `pipx`** — package for real. (Per prior analysis, prove with
   **pipx first** — cheapest, surfaces every install-layout issue — then a private
   tap; the Proprietary/GPL license choice rules out homebrew-core, so a tap that
   can also declare aws/kubectl/checkov/jq/git as deps.)

### Acceptance test (the "does this work?" bar)

```
1. pip install the built wheel into a clean venv (no checkout present)
2. paramify sync                         → workspace materialized, manifest written
3. edit fetchers/aws/<x>/fetcher.yaml    → a user customization
4. add fetchers/custom/<y>/              → a user-created fetcher
5. delete fetchers/okta/<z>/             → a deliberate user deletion
6. simulate an upgrade: bump _pristine   → change an untouched built-in,
                                            change the one you edited, add a new one
7. paramify sync — killed mid-run; then paramify sync again
   ASSERT: untouched built-in updated
   ASSERT: your edited fetcher preserved + <x>/fetcher.yaml.new written
   ASSERT: your custom fetcher untouched
   ASSERT: the deleted fetcher stays deleted (not resurrected)
   ASSERT: the new built-in added
   ASSERT: the re-run reports no conflicts beyond <x> — the kill is invisible
   ASSERT: catalog lists all of them; run still works
```

If step 7 holds, the model works.
