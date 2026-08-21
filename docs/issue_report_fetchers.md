# Issue-report fetchers

The framework collects two kinds of thing. Most fetchers collect **evidence**: a
JSON payload asserting a configuration state, wrapped in the standard envelope and
attached to an evidence set. An **issue-report** fetcher collects something
different — the scan report a tool already produces, handed to Paramify's
assessment intake, which parses it into issues.

The distinction is not cosmetic. It changes where the file lands, whether it is
enveloped, which endpoint receives it, and which command sends it.

|  | evidence | issue report |
|---|---|---|
| `kind:` | `evidence` (default, omit it) | `issue_report` |
| Answers | "is this configured correctly?" | "what did the scanner find?" |
| Written to | `<run>/` | `<run>/issue-reports/` |
| Format | JSON payload you build | the tool's own CSV / JSON / XML / Nessus |
| Enveloped | yes | **never** |
| Identity block | `evidence_set` | `issue_report` |
| Destination | an evidence set (from the fetcher) | an assessment (from the manifest) |
| Endpoint | `POST /evidence/{id}/artifacts/upload` | `POST /assessment/{id}/intake` |
| Uploaded by | `paramify upload` | `paramify issues upload` |

Which one you are writing is decided by one question: **does the tool already
compute the findings?** If you are asserting a state — MFA is enforced, buckets
are encrypted, logging is on — that is evidence. If you are handing over a list of
findings someone else computed — a Nessus scan, Wiz misconfigurations, a
SentinelOne report — that is an issue report.

## The one rule

**The file on disk must be the tool's own bytes.**

Paramify's intake parses the vendor's format. Anything the framework or the
fetcher adds, reorders, or re-serializes is a broken import — and it breaks at
parse time, in a system you are not watching. So:

- The runner does **not** envelope an issue report. The guard is on `kind`, not on
  the file extension, because a JSON scan report is still a scan report.
- The fetcher must not parse and rewrite. Stream the response to disk. If you find
  yourself calling `json.dump` or `csv.writer`, you are probably writing an
  evidence fetcher.
- Keep the tool's extension. Paramify picks its parser partly from the filename, so
  a `.nessus` file stays `.nessus`.

Everything the framework wants to say about a report is therefore said *beside* it,
never inside it. That is what the sidecar index is for.

## What a run looks like

```
evidence/run-2026-08-21T15-53-26Z/
├── _run_metadata.json                          ← the whole run
├── aws_s3_encryption.json                      ← evidence, enveloped
├── okta_mfa_enforcement.json                   ← evidence, enveloped
└── issue-reports/
    ├── _issue_reports.json                     ← the sidecar index
    ├── _intake_log.json                        ← written by the uploader
    ├── tenable_vuln_scan.nessus                ← raw, untouched
    └── wiz_config_findings.csv                 ← raw, untouched
```

Two consequences of the subdirectory worth knowing:

- `paramify upload` globs the run root, so it **cannot see** issue reports. That
  is deliberate: the evidence stage has no business posting a scan report to an
  evidence set. It also means uploading evidence leaves the reports unsent, which
  is why there are two commands.
- The fetcher never names the directory. The runner points `EVIDENCE_DIR` at it,
  so an issue-report fetcher writes to `EVIDENCE_DIR` exactly like every other
  fetcher and only the runner knows the path differs.

### The sidecar index

`issue-reports/_issue_reports.json` carries, per report, what the envelope would
have carried — plus the assessment the report is destined for:

```json
{
  "schema_version": "1.0",
  "run_id": "2026-08-21T15-53-26Z",
  "reports": [
    {
      "file": "tenable_vuln_scan.nessus",
      "fetcher_name": "tenable_vuln_scan",
      "fetcher_version": "0.1.0",
      "category": "tenable",
      "run_id": "2026-08-21T15-53-26Z",
      "target": null,
      "collected_at": "2026-08-21T15:53:26Z",
      "status": "success",
      "exit_code": 0,
      "format": "nessus",
      "title": "Monthly Nessus Scan",
      "assessment_id": "123e4567-e89b-12d3-a456-426614174000",
      "assessment_name": "Production Vulnerability Assessment",
      "assessment_type": "VULNERABILITY",
      "sha256": "a11e5c…",
      "bytes": 48123901
    }
  ]
}
```

The uploader reads this instead of opening the reports. A failed collection gets a
record too, with `status: failed` and the reason — "the scan ran and came back
empty" and "the scan never ran" are different facts, and the uploader has to be
able to tell them apart.

## Writing one

Copy [`fetchers/_template_issue_report/`](../fetchers/_template_issue_report/) to
`fetchers/<category>/<short_name>/`. It differs from the evidence template in
three places: `kind: issue_report`, an `issue_report` block instead of
`evidence_set`, and a `fetcher.py` that streams bytes to disk instead of building
a payload.

```yaml
name: tenable_vuln_scan
version: 0.1.0
description: Monthly authenticated vulnerability scan export for production hosts.
category: tenable

kind: issue_report

runtime:
  type: python
  entry: fetcher.py

output:
  type: nessus                      # the format the TOOL emits, never a conversion
  path: tenable_vuln_scan.nessus    # filename only; the runner owns the directory

secrets:
  - name: access_key
    env: TENABLE_ACCESS_KEY
    description: Tenable.io API access key with scan-export permission.

issue_report:
  assessment_type: VULNERABILITY    # or CONFIGURATION
  title: Monthly Nessus Scan        # optional; defaults to the filename
```

`output.type` must be `csv`, `json`, `xml`, or `nessus` — intake accepts nothing
else, and the schema refuses anything else for this kind so you find out at
discovery rather than at upload. It is also the MIME type the uploader sends.

`assessment_type` filters the assessment picker, so declaring it correctly is what
makes pointing a CSPM report at a vulnerability assessment impossible rather than
merely discouraged.

There is no `evidence_set` block, and declaring both is refused at discovery: an
issue report with an evidence set would be picked up by neither uploader. There is
no `validators` block either — a validator regex is matched against an evidence
payload, and a scan report's findings are Paramify's to interpret.

### The fetcher

```python
output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))  # already issue-reports/
output_path = output_dir / "tenable_vuln_scan.nessus"

resp = requests.get(export_url, headers=auth, timeout=300, stream=True)
with output_path.open("wb") as fh:
    for chunk in resp.iter_content(chunk_size=1024 * 1024):
        fh.write(chunk)
```

Streaming is not only about size (though a full scan export is routinely hundreds
of megabytes). It also makes the no-transformation rule structural: there is no
intermediate object to be tempted into editing.

Two failure cases deserve care, because both produce a file that looks fine:

- **An empty report is a failure, not an empty result.** Intake would parse it as
  "no findings", silently resolving every open issue on the assessment. Exit
  non-zero.
- **A report requested but not yet generated is a truncated report.** Many tools
  build the export asynchronously. Poll for readiness inside the fetcher; a
  fetcher that returns early writes a partial file, and partial has the same
  effect as empty for whatever is missing.

Report failures through `$FETCHER_STATUS_FILE` exactly as an evidence fetcher does
(see [`fetcher_contract.md`](fetcher_contract.md#output)) — the sidecar reads the
same channel the envelope does.

## Pointing it at an assessment

The intake endpoint takes an assessment UUID. Which assessment is a **per-customer
choice**, not fetcher knowledge, so it lives in the manifest — the same split as an
evidence fetcher's `evidence_set` (shipped) versus a program target (chosen).

And as with programs, nobody should be typing a UUID:

```bash
paramify assessments list                       # name + id, optionally --type
paramify assessments select tenable_vuln_scan   # pick by name; writes the UUID
```

`select` defaults to every issue-report entry in the manifest, filters the list to
the `assessment_type` the fetcher declares, and writes both fields:

```yaml
run:
  fetchers:
    - use: tenable_vuln_scan
      config:
        assessment_id: 123e4567-e89b-12d3-a456-426614174000
        assessment_name: Production Vulnerability Assessment
```

`assessment_id` is authoritative; `assessment_name` is carried so the manifest
reads as something a human recognises and a stale UUID is noticeable. In the TUI,
`A` on a selected issue-report entry opens the same picker.

Both fields are framework-reserved: they are added to every issue-report fetcher's
config schema automatically, so no `fetcher.yaml` declares them. Neither is wired
to an env var — the fetcher has no use for them, only the uploader does.

They are deliberately **not required** config. A required field would raise before
the fetcher runs, making "collect now, decide where it goes later" impossible and
breaking the framework's ability to run with no Paramify connection at all
([`design.md`](design.md)). Instead, `paramify validate` reports a missing
assessment, and the uploader refuses that report with the command that fixes it.

## Uploading

```bash
paramify run manifests/monthly.yaml
paramify upload           # evidence  → evidence sets
paramify issues upload    # reports   → assessment intake
```

A run containing both kinds needs both commands. `paramify issues upload` takes
the same arguments as `paramify upload` (optional run dir, `--output-dir`,
`--config`, `--dry-run`, `--json`) plus `--force` (re-send a report already in
this run's intake log — the endpoint adds, it does not replace).

Two things about intake that differ from evidence upload:

- **Re-running is safe only because of a local log.** The endpoint *adds* an
  artifact to a cycle's intake without replacing what is there, and offers no way
  to list what is attached — so no API call can detect a duplicate. The uploader
  records each success in `issue-reports/_intake_log.json` and skips those next
  time. `paramify issues upload --force` re-sends anyway (and *will* duplicate
  issues); prefer it over deleting the log, so other files in the same run stay
  skipped.
- **The effective date is the collection time.** Intake routes an artifact to
  whichever assessment cycle its effective date falls inside, so uploading last
  month's run lands in last month's cycle rather than filing an old scan against
  the current one.

Failed collections are **skipped by default** here, the opposite of the evidence
uploader. A failed evidence fetch still documents the attempt; a partial scan
report gets parsed into issues, and findings absent from it read as resolved,
silently closing real vulnerabilities. Set `skip_failed: false` only when you know
the file is whole.

Full operational detail — config, overrides, and what each error means — is in
[`../uploaders/paramify_issues/README.md`](../uploaders/paramify_issues/README.md).

## Where this lives in the code

| Concern | File |
|---|---|
| `kind`, `issue_report` block, format rules | [`framework/schemas/fetcher_schema.json`](../framework/schemas/fetcher_schema.json) |
| Directory name, sidecar, reserved config fields | [`framework/issue_reports.py`](../framework/issue_reports.py) |
| `EVIDENCE_DIR` redirection | `invocation_dir` in [`framework/runner/executor.py`](../framework/runner/executor.py) |
| The envelope skip | `wrap_outputs` in [`framework/envelope.py`](../framework/envelope.py) |
| Assessment listing / selection | `list_assessments`, `set_assessment` in [`framework/api.py`](../framework/api.py) |
| Intake | [`uploaders/paramify_issues/uploader.py`](../uploaders/paramify_issues/uploader.py) |
| Endpoint contract | [`framework/reference/paramify_api_0.6.0.json`](../framework/reference/paramify_api_0.6.0.json) |
