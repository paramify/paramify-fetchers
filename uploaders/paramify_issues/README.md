# paramify_issues — uploader

Intakes **issue reports** — vulnerability scans, CSPM findings — into Paramify
assessments. The sibling of [`paramify_evidence/`](../paramify_evidence/), for the
other collection kind:

| | `paramify_evidence` | `paramify_issues` |
|---|---|---|
| Reads | `<run>/*.json`, envelope-wrapped | `<run>/issue-reports/` + its sidecar index |
| Posts to | `POST /evidence/{id}/artifacts/upload` | `POST /assessment/{id}/intake` |
| Sends | the envelope, re-serialized | the vendor's file, byte-for-byte |
| Destination from | `metadata.evidence_set` in the file | `assessment_id` in the manifest |
| Paramify does | attaches an artifact to an evidence set | parses the file into issues |

Run it after a run that included `kind: issue_report` fetchers:

```bash
paramify issues upload                 # latest run
paramify issues upload --dry-run       # resolve and report; no API calls
paramify issues upload evidence/run-2026-08-21T15-53-26Z
```

Or standalone, with no CLI:

```bash
python uploaders/paramify_issues/uploader.py --dry-run
```

Auth is `PARAMIFY_UPLOAD_API_TOKEN` (falling back to `PARAMIFY_API_TOKEN`), the
same token the evidence uploader uses; it needs write scope on the target
assessment. As everywhere else, a non-https `PARAMIFY_API_BASE_URL` is refused
before the token can leave the machine, localhost excepted.

## Why the file is never touched

Paramify's intake parses the source tool's own format. Anything added to the file
breaks that parse, so the bytes on disk are the bytes posted — no envelope, no
re-serialization, not even for a `.json` report. Everything the uploader needs to
know about a report instead comes from `issue-reports/_issue_reports.json`, the
sidecar index the runner writes ([framework/issue_reports.py](../../framework/issue_reports.py)).
That file is the only thing standing between the uploader and a directory of
anonymous CSVs, which is why the uploader refuses to guess when it is missing.

## Re-running is safe, and the log is why

The endpoint documents that it **adds** an artifact to a cycle's intake without
replacing what is there, and offers no way to list what is already attached. So a
second `paramify issues upload` on the same run would create a second set of
issues from the same scan, and no API call can detect it.

The uploader therefore records every successful intake in
`<run>/issue-reports/_intake_log.json`, keyed by assessment + run + filename, and
skips anything already listed. It writes the log after each file, not once at the
end, so a batch interrupted halfway does not re-send what it already sent.

**Delete that log and a re-run will duplicate.** To re-send a report that is
already listed, `paramify issues upload --force` (the endpoint *adds* a second
artifact — it does not replace). Prefer `--force` over deleting the log, so
other files in the same run stay skipped.

Pointing the manifest at a *different* assessment and re-running does upload
again — a different assessment is a different destination, not a duplicate.

## Configuration

`--config` takes a YAML file:

```yaml
paramify:
  base_url: https://app.paramify.com/api/v0

# Skip reports whose collection failed. Default true — see below.
skip_failed: true

# Send one fetcher's reports to a different assessment than the manifest says,
# without editing the manifest (useful for a one-off backfill).
overrides:
  tenable_vuln_scan:
    assessment_id: 123e4567-e89b-12d3-a456-426614174000
```

`skip_failed` defaults to **true** here, the opposite of the evidence uploader.
A failed evidence fetch is still worth uploading — it documents the attempt. A
partial scan report is not: it gets parsed into issues, and findings absent from
a truncated file read as resolved, silently closing real vulnerabilities. Set it
to `false` only when you know the file is complete.

## Effective dates and cycles

The endpoint routes an artifact to whichever assessment cycle its
`effectiveDate` falls inside, creating a cycle if none matches. The uploader
sends the report's **collection** time, not the upload time, so re-uploading last
month's run lands in last month's cycle instead of filing an old scan against the
current one.

## Errors worth recognizing

| Symptom | Meaning |
|---|---|
| `no assessment_id` | The manifest entry was never pointed at an assessment. Fix with `paramify assessments select <fetcher>`. |
| HTTP 501 | Assessment intake is not enabled for the workspace. The batch stops rather than repeating the same failure per file. |
| HTTP 404 | The `assessment_id` does not resolve — usually a UUID from another workspace, or a deleted assessment. Re-pick it. |
| `listed in the index but not on disk` | The sidecar and the directory disagree; the run dir was edited after collection. |

Per-file failures never abort the batch, and the command exits non-zero if any
report failed. Endpoint contract per
[`framework/reference/paramify_api_0.6.0.json`](../../framework/reference/paramify_api_0.6.0.json).
