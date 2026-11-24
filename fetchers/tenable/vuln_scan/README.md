# tenable_vuln_scan

Exports the newest completed run of a Tenable.io vulnerability scan as a `.nessus` file and gives it to Paramify's assessment intake.

This is an **issue-report** fetcher (`kind: issue_report`). It gives Paramify the scan report that Tenable makes, byte for byte. Paramify's intake parser reads the report and creates issues. The report is not evidence, and it goes to an assessment, not to an evidence set. See the [issue-report fetchers guide](../../../docs/issue_report_fetchers_guide.md).

## Report

| | |
|---|---|
| Tool | Tenable Vulnerability Management (Tenable.io) |
| Format | `.nessus` (Tenable's own XML) |
| Assessment type | VULNERABILITY |
| Scope | One scan per target, identified by `scan_id` |

Tenable.sc (Security Center) has a different API. This fetcher does not support it.

## Required env vars

| Var | Purpose |
|-----|---------|
| `TENABLE_ACCESS_KEY` | Tenable.io API access key of a user with at least Can View on the scans |
| `TENABLE_SECRET_KEY` | The matching API secret key |
| `TENABLE_SCAN_ID` | Numeric ID of the scan to export. Set it per target in the manifest |
| `EVIDENCE_DIR` | Output directory. The runner sets it to `<run>/issue-reports/` |

### Optional

| Config field | Var | Default | Purpose |
|-----|-----|---------|---------|
| `api_base_url` | `TENABLE_API_BASE_URL` | `https://cloud.tenable.com` | Tenable.io API URL. Must be `https://`, because the API keys go to this host |
| `max_scan_age_days` | `TENABLE_MAX_SCAN_AGE_DAYS` | `35` | Fail if the newest completed run ended more than this many days ago. The default suits a monthly scan. Set it lower for a weekly scan |
| `export_wait_seconds` | `TENABLE_EXPORT_WAIT_SECONDS` | `600` | How long to wait for Tenable to prepare the export, at most 2400. Increase it for very large scans |
| `allow_empty` | `TENABLE_ALLOW_EMPTY` | off | `true` accepts a report with no hosts |

## How to run

```bash
# Once: select the Paramify assessment that this scan feeds
paramify assessments select tenable_vuln_scan

# Each collection cycle
paramify run manifests/<your>.yaml
paramify issues upload
```

The manifest has one target for each scan to export:

```yaml
run:
  output_dir: ./evidence
  fetchers:
    - use: tenable_vuln_scan
      config:
        assessment_id: <uuid>          # set by `paramify assessments select`
        assessment_name: Prod Vuln Scan
        close_cycle: after_run         # or: never
      secrets:
        access_key: ${env:TENABLE_ACCESS_KEY}
        secret_key: ${env:TENABLE_SECRET_KEY}
      targets:
        - scan_id: "12345"
        - scan_id: "67890"
```

## What it does

For each target:

1. Reads the scan's history (`GET /scans/{scan_id}/history`) and selects the newest run with status `completed`. Aborted, canceled and running runs are not exported.
2. Fails if that run ended more than `max_scan_age_days` ago. If the scan schedule stops, the fetcher fails. It does not send the same old results each cycle.
3. Requests a `.nessus` export of that run (`POST /scans/{scan_id}/export?history_id=<run>`).
4. Checks the export status every 10 seconds until it is `ready`. It stops immediately on `error`, and it stops after `export_wait_seconds`.
5. Streams the download to `<name>.part`. It renames the file only when the download is complete, and deletes it on any failure.

Each request tries again on HTTP 429, 502, 503 and 504, and on connection errors, up to 5 attempts. It waits for the time in Tenable's `retry-after` header, or for an increasing time when there is no header. When Tenable asks for a wait of more than 60 seconds, or the last attempt gets 429, the fetcher fails with `rate_limited`.

## Output

Writes `tenable_vuln_scan_{scan_id}.nessus` into `EVIDENCE_DIR` for each target, byte for byte as Tenable sent it. The filename includes the target because all targets write into one `issue-reports/` directory. With one fixed name, each target would overwrite the last.

The uploader does not accept a report larger than 512 MB.

## Caveats

- **Freshness:** The report contains the findings of the newest completed scan run. If that run is a week old, the report shows the findings of a week ago. `max_scan_age_days` sets the limit.
- **Empty is a failure:** A run with no scanned hosts (for example, all targets were offline) still gives a valid `.nessus` file with no `<ReportHost>`. If Paramify processes that report with a cycle close, it resolves every open issue on the assessment. So the fetcher deletes the file and fails with `partial_failure`, unless `allow_empty` is `true`. A zero-byte file always fails.
- **Scope:** The report contains only the hosts and plugins in the named scan. Assets that are not in that scan are not in the report. That does not mean they are clean.
