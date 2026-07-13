# Distributable install & user fetchers — design

**Status:** draft v2 / prototype target. Replaces the workspace-reconcile
draft, preserved at
[`deferred/workspace_sync_design.md`](deferred/workspace_sync_design.md).
**Audience:** whoever builds the fork.
**Related:** [`versioning.md`](versioning.md) (the contract + bump policy),
[`releasing.md`](releasing.md) (how a release is cut), [`design.md`](design.md)
(framework overview).

## 1. The problem

Today the tool is **clone-only**. `api.find_repo_root()` walks up from the cwd
looking for sibling `fetchers/` + `framework/` dirs, schemas load from
`repo_root/framework/schemas/`, and fetchers run as subprocesses out of
`repo_root/fetchers/`. Two consequences we want to fix:

1. **No clean installed distribution.** `pip install`/`brew install` of the
   current package ships only `framework*` — no fetchers, no schemas as data —
   and `find_repo_root()` throws unless you happen to be inside a clone.
   (`releasing.md` → *Artifacts* already flags this as the blocker deferring
   wheel/PyPI.)
2. **User fetchers have no home.** The customization we expect and plan for is
   customers **writing their own fetchers** for platforms we don't support.
   Today that means writing into the checkout — where `git pull` collides with
   their work and every upgrade is a merge hazard.

## 2. What drives the design

Two facts scope this down hard:

- **The expected customization is *creation*, not modification.** Customers
  build fetchers for platforms we don't cover. They are not expected to edit
  shipped files: `fetcher.yaml` is explicitly *"ships with the code, customers
  never edit this"* (README), and per-customer intent — config, secrets,
  targets — lives in the **run manifest**, by design.
- **We control discovery.** dpkg needs 3-way conffile merges because `/etc`
  files must be edited in place — services read fixed paths. We don't have
  that constraint: the loader can **overlay** a user directory on top of the
  shipped content, so upstream never writes into — and never has to reconcile
  with — anything the user owns.

Hence the model: **read-only shipped content + a writable user overlay.** No
materialized workspace, no hash manifest, no sync engine, no per-file decision
table. The no-clobber guarantee is *structural* (upstream and user content
live in different directories), not algorithmic.

### Decisions (logged)

- **#224 stands unchanged:** content is **bundled with each core release**,
  not shipped on a separate channel. One version number for core+content ⇒ no
  compatibility matrix. Tradeoff: shipping a new/fixed fetcher requires
  cutting a release.
- **#243 (supersedes #223):** no materialize/sync step. Built-ins are read
  directly from the installed bundle; user customization is copy-on-write
  shadowing. The update flow in #225 simplifies to *just the package upgrade*.
- **#234:** Claude skills are deferred out of v1 entirely.

### Non-goals

- PyInstaller / single-file frozen binaries (blocked separately: Python
  fetchers launch via `sys.executable`, which points at the frozen app).
- A network content registry / plugin marketplace.
- Changing what a fetcher *is* or the envelope format.
- Reconciling user edits to shipped files — see
  [`deferred/workspace_sync_design.md`](deferred/workspace_sync_design.md)
  and §11 for what would revive that.

## 3. Vocabulary

| Term | Meaning | Owner | Writable |
|---|---|---|---|
| **Core** | `framework/` engine + CLI + JSON schemas | us (package manager) | no |
| **Bundled content** (`framework/_bundled/`) | shipped fetchers + example manifests, read directly at run time | us | no |
| **User dir** (`$PARAMIFY_HOME/fetchers/`) | user-created fetchers + deliberate overrides of built-ins | user | yes |
| **User data** | run manifests, `EVIDENCE_DIR` output | user | yes |

There is no pristine-vs-workspace distinction and no tool-managed manifest:
the shipped content **is** the live content.

## 4. On-disk layout

```
INSTALL (read-only, package-manager owned) ───────────────
…/site-packages/
  framework/
    schemas/         fetcher_schema.json, category_schema.json, …
    _bundled/                          ← shipped content; built-ins RUN from here
      fetchers/                          (inside the package, so importlib.resources
      examples/                           resolves it and nothing non-package lands
    …engine…                              top-level in site-packages — see §8)

USER DIR (writable, user owned) ──────────────────────────
$PARAMIFY_HOME  (default: platformdirs user_data_dir — see §9)
  fetchers/            ← user-created fetchers + overrides; shadow built-ins by name
    _categories/       ← user category files for NEW platforms (see §5)

USER DATA (writable, cwd) ─────────────────────────────────
<cwd>/manifests/, <cwd>/evidence/   ← never touched by the tool
```

The tool writes into the user dir only on explicit `paramify create` /
`paramify customize` (§6), and never writes anywhere else outside `EVIDENCE_DIR`.
Upgrades replace the install atomically and *cannot* touch user files.

**Prerequisite — fetchers must not write next to themselves.** Built-ins run
from a read-only install, so a fetcher that writes into its own directory
breaks. Verified satisfied: the checkov scanners (the one suspected offender)
clone via `mktemp -d` with trap cleanup and write only to `EVIDENCE_DIR` and
mktemp scratch (`fetchers/checkov/_shared/clone.sh`). Hold new fetchers to the
same rule — it's already the contract (*"writes only to `EVIDENCE_DIR`"*).

## 5. Discovery: single root → search path

The discovery seam is `config_loader.discover_fetchers(repo_root)` and
`discover_platforms(repo_root)`, plus schema resolution in
`config_loader._load_schema()`. The change:

**Schema resolution** moves off the cwd walk. Schemas are core, so they resolve
from the installed `framework` package via `importlib.resources` — with the
source path kept as a dev fallback:

```python
def load_schema(name="fetcher_schema.json") -> dict:
    # 1. framework/schemas/ next to the source — serves BOTH the dev checkout
    #    and a normal install (package data lands here in site-packages)
    local = Path(__file__).parent / "schemas" / name
    if local.exists():
        return json.loads(local.read_text())
    # 2. zip-safe fallback via importlib.resources
    return json.loads(resources.files("framework.schemas").joinpath(name).read_text())
```

**Fetcher discovery** takes an ordered list of roots instead of one, and unions
results; earlier roots win a name collision so a user copy can shadow a built-in:

```python
def fetcher_roots() -> list[Path]:
    roots = []
    if env := os.environ.get("PARAMIFY_FETCHERS_PATH"):   # 1 explicit override
        roots += [Path(p) for p in env.split(os.pathsep)]
    if co := _find_checkout_root():                        # 2 dev clone (cwd walk)
        roots.append(co / "fetchers")
    roots.append(user_home() / "fetchers")                 # 3 user dir
    roots.append(_bundled_root() / "fetchers")             # 4 installed bundle
    return [r for r in roots if r.is_dir()]

def discover_fetchers(roots: list[Path]) -> dict[str, Fetcher]:
    schema = load_schema(); validator = Draft202012Validator(schema)
    found = {}
    for root in roots:                     # precedence: first root wins on name
        for fetcher in _walk(root, validator):
            found.setdefault(fetcher.name, fetcher)
    return found
```

The checkout outranks the user dir **on purpose**: a developer inside a clone
would otherwise have user-dir copies silently shadowing their in-tree edits.
For end users there is no checkout, so the user dir shadows the bundle — which
is exactly the override mechanism.

Two collision rules, kept distinct. **Within one root**, a duplicate name stays
a hard error, exactly as today (`config_loader.py:72`). **Across roots**, first
root wins — but the shadow is *reported*, never silent: `catalog` and `doctor`
list every name resolved by shadowing and which root lost.

**`discover_platforms()` gets the same treatment** — and this matters more
here than it did in the sync design: a user fetcher for an *unsupported
platform* needs its own `_categories/<name>.yaml` (platform config + auth
passthrough). Each root's `_categories/*.yaml` is loaded and unioned, first
root winning **per category file**, so users can define entirely new
categories in the user dir without touching the install.

`find_repo_root()` stays for the dev path but is no longer the only way to
locate content. Everything downstream (`catalog`, `run`, `doctor`) calls
`fetcher_roots()`.

## 6. CLI surface

No `sync`, no `migrate`. Three additions to `framework/cli.py`:

### `paramify create <category>/<name>`
Scaffolds a new fetcher in the **user dir** from the bundled `_template/` —
the front door for the expected use case. Installed users have no checkout to
copy `fetchers/_template/` out of; this command is how they start a fetcher
for a platform we don't support. `--category-file` also scaffolds a
`_categories/<category>.yaml` when the category is new. Refuses to overwrite.

### `paramify customize <fetcher>`
Copy-on-write override: copies a built-in from the bundle into the user dir,
where it shadows by name. Writes a `.customized.json` sidecar recording the
source `tool_version` and per-file hashes, so `doctor` can later say *"your
override of X was copied from 0.4.0; the built-in has since changed"*.
Refuses to overwrite an existing override. (Discovery ignores the sidecar —
it only looks for `fetcher.yaml`.)

### `paramify doctor` (extend the existing command, `cli.py:335`)
Add a distribution section: install path + `tool_version`; user dir path;
every cross-root shadow and which root lost; stale overrides (sidecar hash ≠
current bundled hash); user-dir fetchers that fail schema validation.

Example manifests ship in the bundle; `paramify manifest new --from-example
<name>` copies one into the cwd (run manifests are user data — the tool never
resolves them from the bundle implicitly).

## 7. Upgrades & schema evolution

**Upgrade = `pipx upgrade` / `brew upgrade`. That's the whole flow.**
Built-ins update atomically with the package; user files are untouched by
construction. There is no step 2.

Per `versioning.md`, the schemas are **the contract**. Two change classes:

- **Additive (non-breaking).** New optional field; the permissive schema means
  existing user fetchers keep validating. Nothing to do. Bump: **minor**.
- **Breaking.** Removing/renaming/retyping a field, or adding a required one —
  existing *user-dir* fetchers become invalid on upgrade (built-ins ship
  already-migrated). Posture: **a one-release grace window** — the loader
  accepts both shapes and normalizes old→new in memory with a deprecation
  warning; the next release drops the old shape (announce → warn → remove,
  matching `versioning.md`). `doctor` lists user fetchers still on the old
  shape. A fetcher that fails validation outright is **skipped with a visible
  error** (refuse, don't crash), never a whole-run abort.

**Deferred until the first real break:** the contract-version marker and the
chained migration framework (specified in the deferred doc, §9). Pre-1.0 with
a small install base, the grace-window loader covers the transition without
them. If we adopt the marker later, the bootstrap rule is: **a file with no
marker is contract version 1.**

## 8. Release integration

Slots into the existing `releasing.md` steps:

- **Build the bundle into the artifact.** Add `[tool.setuptools.package-data]`
  so the wheel/tarball ships `framework/schemas/*.json`,
  `framework/tui/styles/*.tcss`, and a `framework/_bundled/` tree assembled
  from `fetchers/` and `examples/`. `_bundled/` lives *inside* the package:
  resolvable via `importlib.resources`, shippable by the existing
  `include = ["framework*"]`, and nothing non-package lands top-level in
  site-packages. The assembly step must run **inside the build backend** (a
  custom setuptools `build_py` hook), not in a release workflow — the
  supported install is still `pip install` from the GitHub source tarball,
  and a workflow-side copy would leave source installs with no `_bundled/`.
  This is the change that unblocks the deferred wheel/PyPI item in
  `releasing.md`. (Decide whether `fetchers/logos/` — README furniture,
  unused at run time — belongs in the bundle at all.)
- **Changelog:** keep calling out the three version axes; a `BREAKING`
  subsection with the grace-window notes when applicable.
- **Bump:** per `versioning.md` (breaking ⇒ minor pre-1.0).

Everything stays manual/tag-driven; nothing here forces `release-please`.

## 9. Platform nuances (macOS / Windows / Linux)

The framework (discovery, CLI) is pure Python + `pathlib` and portable. The
nuances live in how you install and how fetchers run.

### Install path
- **Homebrew is macOS + Linux only.** The universal path is **pipx**
  (Mac/Windows/Linux); brew is a Mac/Linux convenience layer (another reason
  the prototype goes pipx-first, §12). A native Windows package could later
  use Scoop or WinGet.
- **pipx PATH nuance — RESOLVED.** Console scripts of extras (e.g. `checkov`)
  install into the pipx venv's `bin/`, which pipx does **not** put on `PATH`.
  The executor now prepends `Path(sys.executable).parent` to every child's
  `PATH` (`runner/executor.py`, `_build_env`), so venv-installed CLIs resolve
  under pipx and unactivated venvs alike (`pipx inject paramify-fetchers
  checkov` just works).

### Fetcher execution
- **90 of 109 fetchers are `bash`** (`runner/executor.py:248` launches
  `["bash", entry]`). Stock Windows has no bash — the bulk of the catalog
  needs WSL, Git Bash, or the container on native Windows. The 19 python
  fetchers use `sys.executable` (`executor.py:246`) and are portable.
- The executor invokes the interpreter explicitly (no reliance on shebangs or
  the executable bit, neither of which Windows honors) — this also means
  copying fetchers into the user dir needs no permission-bit handling.

### Paths & the user dir
- **`$PARAMIFY_HOME` resolves via `platformdirs.user_data_dir("paramify")`** →
  `~/Library/Application Support/paramify` (Mac), `%LOCALAPPDATA%\paramify`
  (Windows), `~/.local/share/paramify` (Linux), with the env var as override.
- **Search-path separator** for `$PARAMIFY_FETCHERS_PATH` is `os.pathsep`.
  Build every path with `pathlib.Path`, never string-join.

### The equalizer
- **Containers normalize all of the above** — the image is Linux, so `bash`,
  the external CLIs, and POSIX paths all just work. For Windows-heavy
  customers the container (Docker Desktop) is the recommended path.

## 10. The container story

The clone-based image build keeps working **verbatim**: `deploy/Dockerfile`
COPYs the repo into `/app` and `pip install -e .`s it, and the cwd walk (root
#2 in §5) finds `/app/fetchers`. Run manifests are user data — the existing
bake-from-`manifests/` flow (`deploy/README.md`) is untouched.

For customers with user-dir fetchers, the bridge is the search path itself:

- **Near-term pattern** (document in `deploy/README.md`): `COPY` the user
  dir's fetchers into the image (e.g. `/overrides`) and set
  `PARAMIFY_FETCHERS_PATH=/overrides` — root precedence makes their fetchers
  and overrides shadow the baked-in built-ins, reusing §5's mechanism as-is.
- **End state:** the future `paramify package` command (`deploy/README.md`
  already names this bundle as its template) generates the build context from
  the *merged view* (bundle + user dir) plus the cwd `manifests/` — so an
  installed, clone-less customer can produce a deployable image.

## 11. What would revive the reconcile model

The deferred design ([`deferred/workspace_sync_design.md`](deferred/workspace_sync_design.md))
exists for one scenario: customers routinely making small in-place edits to
**many** built-ins, where copy-on-write overrides would rot en masse. Watch
for it via `doctor`'s stale-override count. If that pattern shows up, the
sync/manifest/migration machinery is fully specified there — start from it.
Until then: every line of it is complexity spent on edits we tell customers
not to make.

## 12. Prototype plan (build order for the fork)

Prove the risky parts first; each phase is independently demonstrable.

1. **Multi-root discovery** — `fetcher_roots()` + `discover_fetchers(roots)` +
   multi-root `discover_platforms()` + `importlib.resources` schema loading.
   Prove: `catalog` finds fetchers from a user dir with no checkout on disk.
2. **Package data + `_bundled/` build hook** — ship schemas + the bundle in
   the wheel; `pip install` into a clean venv and confirm `catalog`/`run` work
   from the bundle alone. Fix the checkov write-next-to-itself violation.
3. **`create` / `customize` / `doctor`** — scaffolding, copy-on-write with the
   staleness sidecar, shadow + stale reporting.
4. **pipx, then brew tap** — package for real. pipx first (cheapest, surfaces
   every install-layout issue), then a private tap that can also declare
   `aws`/`kubectl`/`checkov`/`jq`/`git` as deps.

### Acceptance test (the "does this work?" bar)

```
1. pip install the built wheel into a clean venv (no checkout present)
2. paramify catalog                      → all built-ins listed, from the bundle
3. paramify run examples-derived manifest → evidence written; run works installed
4. paramify create custom/<y>            → user fetcher scaffolded in the user dir,
                                            appears in catalog, runs
5. paramify customize aws/<x>; edit it   → override shadows the built-in;
                                            catalog + doctor report the shadow
6. install a newer wheel (simulated upgrade)
   ASSERT: built-ins updated (bundle is the new version — nothing to reconcile)
   ASSERT: your custom fetcher untouched, still runs
   ASSERT: your override still wins; doctor flags it stale if <x> changed upstream
   ASSERT: no file in the user dir was created, modified, or deleted by the upgrade
```

If step 6 holds, the model works — and note *why* it holds: the upgrade never
had write access to anything the user owns.

## 13. Testing strategy

The historical failure mode is "green in dev, broken installed" — every
current test runs from the clone. Add:

- **Installed-layout tests** — build the wheel, install into a temp venv, run
  `catalog`/`run`/`create`/`customize` with no checkout on disk.
- **Precedence tests** — fabricate multiple roots and assert shadowing order,
  in-root duplicate errors, shadow reporting, and per-category-file platform
  precedence.
- **Staleness tests** — customize, bump the bundle, assert `doctor` flags the
  override; assert an unmodified bundle stays quiet.
- **Grace-window loader tests** (when the first breaking change lands) — old
  shape accepted + warned, new shape accepted, next release rejects old.
