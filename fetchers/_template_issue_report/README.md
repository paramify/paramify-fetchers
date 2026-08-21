# \<fetcher_name>

\<One sentence: which report this pulls, from which tool, over what scope.>

This is an **issue-report** fetcher (`kind: issue_report`): it hands Paramify the
scan report the tool already produces, and Paramify's assessment intake parses it
into issues. It is not evidence, and it goes to an assessment rather than an
evidence set. See [docs/issue_report_fetchers.md](../../docs/issue_report_fetchers.md).

## Report

| | |
|---|---|
| Tool | \<Tenable / Wiz / SentinelOne / …> |
| Format | \<csv / json / xml / nessus>, exactly as the tool emits it |
| Assessment type | \<VULNERABILITY / CONFIGURATION> |
| Scope | \<what the report covers: which scan, which subscription, which cluster> |

## Required env vars

| Var | Purpose |
|-----|---------|
| `<UPPER_SNAKE_ENV_VAR>` | \<what it's for, and which scope/permission it needs> |
| `EVIDENCE_DIR` | Output directory, set by the runner to `<run>/issue-reports/` |

## How to run

The fetcher reads secrets from `os.environ`. Any mechanism that populates the
process environment works — `.env`, `export`, AWS Secrets Manager, Vault, K8s
secret env mounts, CI secret blocks. None is privileged.

```bash
# Standalone: writes into ./evidence unless EVIDENCE_DIR says otherwise.
python fetchers/<category>/<short_name>/fetcher.py

# Through the framework, which puts it in <run>/issue-reports/ and records it:
paramify assessments select <fetcher_name>   # once, to pick the assessment
paramify run manifests/<your>.yaml
paramify issues upload
```

## Output

Writes `<category>_<short_name>.<ext>` into `EVIDENCE_DIR`, byte-for-byte as the
tool returned it — no envelope, no added metadata. The runner records it in
`issue-reports/_issue_reports.json`, which is what the uploader reads.

## Caveats worth stating

\<Fill these in; they are the part a future reader actually needs.>

- **Freshness:** \<does the tool regenerate on request, or return the last
  completed scan? If the latter, this fetcher's output is only as current as the
  tool's schedule, and that belongs in writing.>
- **Scope:** \<what is NOT in the report — unlicensed assets, disabled plugins,
  an inventory the scanner never reached.>
- **Empty vs. clean:** \<how you can tell a genuinely clean scan from a scan that
  never ran. The fetcher fails on an empty file, because intake reads no findings
  as "everything is resolved".>
