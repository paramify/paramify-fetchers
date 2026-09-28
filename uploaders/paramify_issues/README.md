# paramify_issues — uploader

Sends **issue reports** — vulnerability scans, CSPM findings — into Paramify
pipelines, where the assessment's file intake preset parses them into issues. The
sibling of [`paramify_evidence/`](../paramify_evidence/), for the other collection
kind:

| | `paramify_evidence` | `paramify_issues` |
|---|---|---|
| Reads | `<run>/*.json`, envelope-wrapped | `<run>/issue-reports/` + its sidecar index |
| Posts to | `POST /evidence/{id}/artifacts/upload` | `POST /pipelines/{id}/intake`, then `/process` |
| Sends | the envelope, re-serialized | the vendor's file, byte-for-byte |
| Destination from | `metadata.evidence_set` in the file | `assessment_id` in the manifest |
| Paramify does | attaches an artifact to an evidence set | parses the file into issues |

A pipeline is identified by its assessment id, so `assessment_id` is all the
manifest needs.

Run it after a run that included `kind: issue_report` fetchers:

```bash
paramify issues upload                 # newest run that collected issue reports
paramify issues upload -f pipelines    # newest run that manifest produced
paramify issues upload --dry-run       # resolve and report, including the operation; no API calls
paramify issues upload --no-wait       # queue processing and exit
paramify issues upload evidence/run-2026-08-21T15-53-26Z
```

With no run named, it takes the newest run under the output directory that
collected issue reports, skipping newer evidence-only runs — pipeline configs
usually live in their own manifest, sharing the output directory with the
evidence manifest. `-f` narrows that to one manifest's runs and reads the
output directory from it.

Or standalone, with no CLI:

```bash
python uploaders/paramify_issues/uploader.py --dry-run
```

Auth is `PARAMIFY_UPLOAD_API_TOKEN` (falling back to `PARAMIFY_API_TOKEN`), the
same token the evidence uploader uses. The key needs `PIPELINE_INTAKE`, plus
`PIPELINE_PROCESS` to process, plus `PIPELINE_CLOSE` to close. As everywhere
else, a non-https `PARAMIFY_API_BASE_URL` is refused before the token can leave
the machine, localhost excepted.

## What one upload does

The unit of work is one assessment per run, not one file. For each assessment
the run's reports are bound to:

1. **Upload bare.** Each report goes to `POST /pipelines/{id}/intake` with no
   `operation` and no cycle. The pipeline puts it on its **current cycle — the
   oldest one still open** — and returns the artifact id.
2. **Process once.** One `POST /pipelines/{id}/process` names exactly the
   artifact ids this run uploaded. Never the bare form: that sweeps every
   unprocessed file on the cycle, including ones someone else put there. An
   `operation` on an intake sweeps the same way, which is why uploads carry none.
3. **Close only when allowed.** The process call is `PROCESS_CLOSE` when the
   assessment's `close_cycle` is `after_run` **and** every target bound to it in
   the run succeeded and uploaded. Otherwise it is `PROCESS`, and the output says
   why the close was skipped.
4. **Wait.** The job is polled until it completes, fails, or is blocked behind a
   failed job, and its counts are printed: issues created, updated, seen-closed,
   auto-closed. A job that did not complete fails the command.

## The close, and why it is not automatic

Closing a cycle is what tells Paramify which issues are resolved: it
**auto-closes every open issue the cycle never saw**. That makes a close after a
partial upload — one framework of three, or a run where a target failed — mark
real issues resolved. It is also what moves the pipeline on: until the oldest
open cycle closes, every upload lands on it.

So each issue-report entry says how its assessment's cycles are filled, in the
manifest:

```yaml
fetchers:
  - use: wiz_stig_compliance_report
    config:
      assessment_id: 123e4567-e89b-12d3-a456-426614174000
      close_cycle: after_run   # or: never
```

- **`after_run`** — one report per cycle, such as a monthly scan. The upload
  closes the cycle when the run was complete.
- **`never`** — several files make up one cycle, from several runs or tools.
  Close it once the last has been processed: in Paramify, or with
  `paramify issues close <assessment-id>`.

There is no default. `paramify validate` reports an entry without one, and the
uploader sends nothing for an assessment whose policy is missing. Set it with
`paramify assessments select <fetcher> --close-cycle after_run|never`, or the
TUI's assessment picker (`A`), which asks right after the assessment.

"Every target succeeded" comes from the sidecar's `invocations` list, which
records each issue-report invocation — including one that failed without writing
a file. A run recorded before that list existed never closes automatically.

## Jobs

```bash
paramify issues jobs                          # recent jobs, newest first
paramify issues jobs --assessment <id>
paramify issues jobs --retry <job-id>         # a failed job, in place
paramify issues jobs --cancel <job-id>        # and every unfinished job queued behind it
paramify issues close <assessment-id>         # close the current cycle; asks first
```

In the TUI's Paramify tab, `i` sends a run's reports, `j` lists jobs (enter on a
failed or queued one to retry or cancel it), and `C` closes one of the manifest's
assessments' cycles, after a warning.

Each assessment has one job queue, and a **failed job blocks every job queued
behind it** until it is retried or cancelled. The uploader never does either on
its own — which is right depends on why it failed — and reports a blocked job
with the id of the one blocking it.

## Why the file is never touched

The preset parses the source tool's own format. Anything added to the file breaks
that parse, so the bytes on disk are the bytes posted — no envelope, no
re-serialization, not even for a `.json` report. Everything the uploader needs to
know about a report instead comes from `issue-reports/_issue_reports.json`, the
sidecar index the runner writes ([framework/issue_reports.py](../../framework/issue_reports.py)).
That file is the only thing standing between the uploader and a directory of
anonymous CSVs, which is why the uploader refuses to guess when it is missing.

## Re-running is safe, and the log is why

Intake **adds** an artifact every time and offers no way to list what a cycle
already holds. So a second `paramify issues upload` on the same run would put a
second copy of the scan on the cycle, and no API call can detect it.

The uploader therefore records, in `<run>/issue-reports/_intake_log.json`, every
successful upload (keyed by assessment + run + filename) and every job it queued
with the artifacts it named. A re-run skips both. The log is written after each
step, so a run interrupted anywhere picks up where it stopped: files uploaded but
never processed are processed, and a job left running is waited on again.

**Delete that log and a re-run will upload and process again.** To re-send a
report that is already listed, `paramify issues upload --force`. Prefer `--force`
over deleting the log, so other files in the same run stay skipped.

Pointing the manifest at a *different* assessment and re-running does upload
again — a different assessment is a different destination, not a duplicate.

## Configuration

`--config` takes a YAML file:

```yaml
paramify:
  base_url: https://app.paramify.com/api/v0

# Skip reports whose collection failed. Default true — see below.
skip_failed: true

# How long to wait for each process job, in seconds.
wait_timeout_sec: 900

# Send one fetcher's reports to a different assessment, or with a different
# close policy, than the manifest says, without editing it.
overrides:
  tenable_vuln_scan:
    assessment_id: 123e4567-e89b-12d3-a456-426614174000
    close_cycle: never
```

`skip_failed` defaults to **true** here, the opposite of the evidence uploader.
A failed evidence fetch is still worth uploading — it documents the attempt. A
partial scan report is not: it gets parsed into issues, and findings absent from
a truncated file read as resolved. With `skip_failed: false` a failed report is
sent, but its cycle is never closed by the upload.

## Cycles and dates

The pipeline chooses the cycle, never the uploader: an upload lands on the
oldest open cycle, and when none is open the upload opens one. The artifact's
`effectiveDate` is still the report's **collection** time — the date the scan
describes — but it does not route the upload. Uploading an old run therefore
lands on whichever cycle is open now; to file scans against their own cycles,
upload and close them oldest first.

## Errors worth recognizing

| Symptom | Meaning |
|---|---|
| `no assessment_id` | The manifest entry was never pointed at an assessment. Fix with `paramify assessments select <fetcher>`. |
| `close_cycle is None` | The entry has no close policy. Fix with `paramify assessments select <fetcher> --close-cycle after_run\|never`. |
| HTTP 400 | Usually an assessment with no file intake preset configured. That assessment's other reports are held back. |
| HTTP 401 / 403 | The key lacks a pipeline permission. The batch stops. |
| HTTP 404 | The `assessment_id` does not resolve — usually a UUID from another workspace, or a deleted assessment. Re-pick it. |
| HTTP 409 | The pipeline has no cycle in progress (the last one was closed). The next upload opens one. |
| HTTP 501 | Pipeline intake is not enabled for the workspace. The batch stops. |
| job `FAILED` | Processing failed; the error is printed. `paramify issues jobs --retry <id>` once the cause is fixed. |
| `blocked by failed job` | An older failed job holds the assessment's queue. Retry or cancel it. |
| `still running` | The wait cap passed. The job keeps going; `paramify issues jobs` shows how it ended, and a re-run waits on it again. |
| `listed in the index but not on disk` | The sidecar and the directory disagree; the run dir was edited after collection. |

Per-file failures never abort the batch, and the command exits non-zero if any
report failed or any job did not complete. Endpoint contract per **Paramify REST
API v0 spec 0.10.0** — [API documentation](https://app.paramify.com/api/documentation/)
(in the app: Help (?) → API Documentation).
