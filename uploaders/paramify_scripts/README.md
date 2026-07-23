# paramify_scripts — uploader

Syncs each fetcher's **entry script** (`fetcher.py` / `fetcher.sh`) to Paramify
and CONNECTs it to that fetcher's evidence set, so the tenant shows *how* the
evidence was generated. A **provisioning step**, separate from evidence upload:
run it when `fetchers/**` change, not on every collection.

## Why it works the way it does

The Paramify `/scripts` API has no stable external key (only a server-assigned
UUID) and no server-side versioning. So this tool reconciles the tenant to the
repo — GitOps style — using conventions the API *does* allow:

- **identity** — a marker in the script's `description` field:
  ```
  paramify-fetcher: <fetcher name>
  version: <fetcher.yaml version>
  sha256: <sha256 of the entry file>
  ```
  It indexes existing scripts by the `paramify-fetcher` line (there is no
  server-side name/marker filter, so it lists all scripts and matches locally).
- **versioning** — the fetcher.yaml `version` is the update signal; git is the
  history of record; the app just holds "current".
- **drift guard** — the `sha256` catches a code edit that forgot to bump the
  version: **warn and skip by default**, `--force` to push it anyway.

## What it does per fetcher

For every fetcher that declares an `evidence_set` and has a readable entry file:

1. reads the entry file (`fetcher.py` / `fetcher.sh`) — **shared modules are
   ignored**; only the entry script is pushed,
2. get-or-creates the script by its marker key:
   - **create** — not in the tenant yet,
   - **update** — the fetcher.yaml `version` changed,
   - **drift** — code changed but version did not (warn/skip, `--force` to push),
   - **no-op** — version and hash both match,
3. **CONNECTs** the script to the fetcher's evidence set — the set is
   get-or-created by `reference_id` (the same identity the evidence uploader
   uses), so scripts land on the same set the evidence does.

Only `SCRIPT` associations are automated. Solution-capability, control, and
validator linkage stays Paramify-side and is out of scope here.

## Usage

```bash
export PARAMIFY_UPLOAD_API_TOKEN=...   # any source: .env, secret manager, CI

# Preview the plan — read-only, makes no writes (needs a token to diff the tenant):
paramify scripts sync --dry-run

# Apply:
paramify scripts sync

# Push a script whose code drifted without a version bump:
paramify scripts sync --force

# Ensure every fetcher's association (heals a script created without its link):
paramify scripts sync --reassociate

# Equivalent direct invocation:
python uploaders/paramify_scripts/uploader.py --dry-run
```

Exits non-zero if any fetcher failed to sync.

## Config (`--config`, optional)

Shares the shape of the evidence uploader config so overrides stay consistent:
- `paramify.base_url` — default `https://app.paramify.com/api/v0`.
- `overrides.<fetcher_name>.reference_id` (and optionally `name`) — must match
  the evidence uploader's overrides so the script associates to the **same**
  evidence set the evidence lands on.

## Required tooling

Python with `requests`, `python-dotenv` (already in `requirements.txt`), and an
importable `framework` package (editable install) for fetcher discovery.
