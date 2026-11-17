# tenable_vuln_scan

Exports a Tenable.io vulnerability scan as a `.nessus` file by scan ID and hands it to Paramify's assessment intake.

This is an **issue-report** fetcher (`kind: issue_report`): it passes the scan report Tenable already produces to Paramify byte-for-byte. Paramify's intake parser reads it and creates issues. It is not evidence, and it goes to an assessment rather than an evidence set. See [docs/issue_report_fetchers.md](../../docs/issue_report_fetchers.md).

## Report

| | |
|---|---|
| Tool | Tenable.io |
| Format | `.nessus` (native Tenable XML) |
| Assessment type | VULNERABILITY |
| Scope | One scan per invocation, identified by `TENABLE_SCAN_ID` |

## Required env vars

| Var | Purpose |
|-----|---------|
| `TENABLE_ACCESS_KEY` | Tenable.io API access key — needs scan-export permission |
| `TENABLE_SECRET_KEY` | Tenable.io API secret key |
| `TENABLE_SCAN_ID` | Numeric ID of the scan to export (set per target in the manifest) |
| `EVIDENCE_DIR` | Output directory, set by the runner to `<run>/issue-reports/` |

### Optional

| Var | Default | Purpose |
|-----|---------|---------|
| `TENABLE_API_BASE_URL` | `https://cloud.tenable.com` | Override for Tenable.sc or on-prem |

## How to run

```bash
# Once: pick which Paramify assessment this scan feeds
paramify assessments select tenable_vuln_scan

# Each collection cycle
paramify run manifests/<your>.yaml
paramify issues upload
```

The manifest targets one entry per scan to export:

```yaml
run:
  fetchers:
    - use: tenable_vuln_scan
      config:
        assessment_id: <uuid>          # set by `paramify assessments select`
        assessment_name: Prod Vuln Scan
      targets:
        - scan_id: "12345"
        - scan_id: "67890"
```

## Output

Writes `tenable_vuln_scan_{scan_id}.nessus` into `EVIDENCE_DIR` for each target, byte-for-byte as Tenable returned it. The filename varies per target because all targets share one `issue-reports/` directory — a fixed name would let each target overwrite the previous one silently.

The export is asynchronous: the fetcher requests the export, polls until Tenable reports it ready, then streams the download. A full scan export is routinely hundreds of megabytes; the fetcher streams rather than buffering.

## Caveats

- **Freshness:** Tenable generates the `.nessus` export on demand from the last completed scan run. The report is only as current as the scan schedule — if the scan last ran a week ago, the export reflects last week's findings.
- **Empty vs. clean:** The fetcher treats a zero-byte response as a failure (exit non-zero) rather than "no findings", because intake reads an empty file as "all issues resolved". If Tenable returns an empty export, the sidecar records it as `status: failed`.
- **Scope:** The report covers only the hosts and plugins in the named scan. Assets never added to that scan are absent, not clean.
