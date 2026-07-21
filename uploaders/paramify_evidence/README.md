# paramify_evidence — uploader

Pushes envelope-wrapped evidence from a run directory to Paramify. A **separate
stage** from collection: it reads a completed `evidence/run-<timestamp>/` and
attaches each evidence file to its Paramify evidence set. It never runs fetchers
and never touches fetcher source credentials — so you can point it at an old run
to re-upload.

## Paramify API key

The uploader authenticates with `PARAMIFY_UPLOAD_API_TOKEN`. To create one:

1. Log into [Paramify](https://app.paramify.com) and go to **Settings** (gear icon, top right) → **API Keys** (see [Create a Paramify API Key](https://support.paramify.com/hc/en-us/articles/43292803890451-Create-a-Paramify-API-Key) for step-by-step guidance).
2. Click **+ API Key** and configure it:
   - **Name:** `PARAMIFY_UPLOAD_API_TOKEN` (or any recognizable label)
   - **Expiration:** 6 months to 1 year recommended
   - **Permissions:** check all eight —
     View Evidences, Write Evidences,
     View Issues, Write Issues,
     View Scripts, Write Scripts,
     View Validators, Write Validators
3. Copy the key immediately — it is not shown again.

```bash
export PARAMIFY_UPLOAD_API_TOKEN=<paste key here>

# Optional — only needed if not using app.paramify.com:
# export PARAMIFY_API_BASE_URL=https://your-instance.paramify.com/api/v0
```

## How evidence maps to Paramify

1 fetcher = 1 **evidence set** (a Paramify container). Each fetcher declares its
evidence-set identity in its `fetcher.yaml` `evidence_set` block (`reference_id`,
`name`, `instructions`); the runner copies that into every evidence file's
envelope (`metadata.evidence_set`). The uploader reads it from the envelope, so
it needs only the run directory — not the `fetchers/` tree.

For each evidence file the uploader:
1. reads `metadata.evidence_set` (skips with an error if missing),
2. applies any per-fetcher override from `--config`,
3. **get-or-creates** the evidence set by `reference_id`,
4. **attaches** the evidence as an artifact — skipping it if an artifact with the
   same filename and `run_id` already exists (so re-running is safe; a *different*
   run still adds a new versioned artifact).

Tying evidence sets to controls/solution-capabilities is done in Paramify (manual
today) and is out of scope here.

## Usage

```bash
export PARAMIFY_UPLOAD_API_TOKEN=...   # any source: .env, secret manager, CI

# Upload the latest run under ./evidence:
python uploaders/paramify_evidence/uploader.py

# A specific run:
python uploaders/paramify_evidence/uploader.py evidence/run-2026-05-28T19-03-38Z

# Preview without calling the API:
python uploaders/paramify_evidence/uploader.py --dry-run

# With a customer config (host, referenceId overrides, behavior):
python uploaders/paramify_evidence/uploader.py --config examples/upload.yaml
```

Writes an `upload_log.json` into the run directory. Exits non-zero if any file
failed to upload or was missing its evidence-set block.

## Config (`--config`, optional)

See [`examples/upload.yaml`](../../examples/upload.yaml):
- `paramify.base_url` — default `https://app.paramify.com/api/v0`.
- `overrides.<fetcher_name>.reference_id` (and optionally `name`/`instructions`) —
  map a fetcher to a different evidence set for your program.
- `skip_failed` — skip files whose run status was `failed` (default: upload anyway,
  with the status noted on the artifact).
- `artifact_payload` — `envelope` (default, self-describing) or `payload` (bare
  evidence) if Paramify ingestion expects the unwrapped dict.

## Required tooling

Python with `requests`, `pyyaml`, `python-dotenv` (already in `requirements.txt`).
