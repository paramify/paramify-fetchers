# paramify_evidence — uploader

> **Deprecated.** This script hands the run to the engine behind
> `paramify upload` and prints a notice. It stays for one release so old
> schedules keep working. Use `paramify upload`. The guide is
> [`docs/uploader_guide.md`](../../docs/uploader_guide.md).

Pushes envelope-wrapped evidence from a run directory to Paramify. A **separate
stage** from collection: it reads a completed `evidence/run-<timestamp>/` and
sends the files of each fetcher entry to a Paramify evidence set as one batch. It
never runs fetchers and never touches fetcher source credentials. You can point
it at an old run, and uploading a run again changes nothing. It needs Paramify
API 0.14.0 or later.

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
`name`, `instructions`, `frequency`); the runner copies that into every evidence file's
envelope (`metadata.evidence_set`). The uploader reads it from the envelope, so
it needs only the run directory — not the `fetchers/` tree.

For each fetcher entry in the run the upload:
1. reads `metadata.evidence_set` from the files of the entry. A file that is
   unreadable, is not an envelope, or has no complete evidence set is an error.
   The upload names it and sends the other files,
2. applies any per-fetcher override from `--config`,
3. **get-or-creates** the evidence set by `reference_id`. A new set gets the
   approval mode `SUBMISSION_WITH_PASSING_VALIDATORS` unless `approval` in the
   manifest says otherwise. It never changes an existing set. It only adds tags,
4. **routes** the batch by the channels on the set. With no channel, the batch
   goes on the evidence set. With one channel, it uses that channel. With
   several channels, it uses the channel on the stack of the entry. It refuses
   the entry, and says why, when it cannot choose,
5. **delivers** one batch with every file of the entry, then submits it. A
   temporary failure leaves the batch open. Run the same upload again to resume
   it. A file that fails for good is dropped and named, and the rest goes in.

A refusal or failure stops that entry only. The stack, `approval` and
`no_request` settings are in the run manifest under `run.paramify`. See
[the uploader guide](../../docs/uploader_guide.md#how-a-run-is-delivered).

Tying evidence sets to controls/solution-capabilities is done in Paramify (manual
today) and is out of scope here.

## Usage

```bash
export PARAMIFY_UPLOAD_API_TOKEN=...   # any source: .env, secret manager, CI

# Upload the latest run under ./evidence (deprecated; use `paramify upload`):
python uploaders/paramify_evidence/uploader.py

# A specific run:
python uploaders/paramify_evidence/uploader.py evidence/run-2026-05-28T19-03-38Z

# Preview without calling the API:
python uploaders/paramify_evidence/uploader.py --dry-run

# With a customer config (host, referenceId overrides, behavior):
python uploaders/paramify_evidence/uploader.py --config examples/upload.yaml
```

Writes an `upload_log.json` into the run directory. It holds the plan, the state
of each entry and the notice under `deprecations`. It exits 1 if an entry failed
or was refused. The result no longer lists `evidence_id`, `artifact_id` or
`channel_id` for each file. Read the batch from `entries`.

## Config (`--config`, optional)

See [`examples/upload.yaml`](../../examples/upload.yaml):
- `paramify.base_url` — default `https://app.paramify.com/api/v0`.
- `overrides.<fetcher_name>.reference_id` (and optionally `name`/`instructions`/`frequency`) —
  map a fetcher to a different evidence set for your program.
- `skip_failed` — skip files whose run status was `failed` (default: upload anyway,
  with the status noted on the artifact).
- `artifact_payload` — `envelope` (default, self-describing) or `payload` (bare
  evidence) if Paramify ingestion expects the unwrapped dict.
- `tags` — the default custom tags put on every evidence set, every run:
  `provenance` (default `Automated by Paramify Fetchers`, or `false`) and
  `service` (`true`: the category's `display_name`, e.g. `AWS`; `false` to
  drop it). `tags: false` turns both off. Additive only: your own tags on a set
  are never touched. Without the custom-tags permission the upload still
  succeeds, with one warning. **Off switch:** `PARAMIFY_CUSTOM_TAGS=off` in the
  environment turns the feature off everywhere, whatever the config says;
  `paramify upload --no-tags` does it for one run. The Done block says which.

## Required tooling

Python with `requests`, `pyyaml`, `python-dotenv` (already in `requirements.txt`).
