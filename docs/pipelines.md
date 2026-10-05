# Sending scan reports to Paramify pipelines

A scan-report fetcher (`kind: issue_report`) collects the file a scanner already
produces — a Nessus export, a Wiz CSV, a STIG compliance report — and sends it
into an assessment's **pipeline** in Paramify. The assessment's file intake preset
turns each file into issues. This guide sets that up and runs it from the TUI; the
[command-line equivalents](#the-same-from-the-command-line) are at the end.

It takes four steps, and the first two happen once:

1. [Give your scan fetchers their own manifest](#1-give-scan-fetchers-their-own-manifest)
2. [Point each one at an assessment, and say how its cycle closes](#2-point-each-fetcher-at-an-assessment)
3. [Run it, then send the reports](#3-run-it-then-send-the-reports)
4. [Watch jobs, and close cycles by hand when you need to](#4-jobs-and-closing-a-cycle)

The recordings below use a synthetic scan fetcher and a stand-in for the Paramify
API, so nothing in them is real data. The screens, keys and messages are the ones
you get.

## Before you start

In Paramify:

- **An assessment for each scanner**, of the right type (vulnerability or
  configuration), with its **file intake preset** configured. The preset maps the
  scanner's columns to issue fields, including the unique record ID. Without one,
  every upload is refused with HTTP 400.
- **An API key** with `PIPELINE_INTAKE` and `PIPELINE_PROCESS`, plus
  `PIPELINE_CLOSE` if the upload should close cycles.

On the machine running the fetchers:

```bash
export PARAMIFY_API_TOKEN=...          # read: lists your assessments in the picker
export PARAMIFY_UPLOAD_API_TOKEN=...   # write: uploads, processes, closes
# export PARAMIFY_API_BASE_URL=...     # only if you are not on app.paramify.com
```

Both can be the same key. Where they come from is up to you — a `.env` file, a
secret manager, CI variables.

## 1. Give scan fetchers their own manifest

Keep scan fetchers in a manifest of their own, such as `manifests/pipelines.yaml`,
beside the one that collects evidence. Scans usually run on a different schedule —
monthly, or after each release — and a separate manifest lets each run on its own.

Start the TUI with no manifest (`paramify tui`) and press `n` on the front door to
create one. Then, on the **Manifest** tab (`2`):

| Key | Does |
|---|---|
| `a` | add a fetcher — the scanner's report fetcher is listed under **Scan reports**, apart from evidence |
| `t` | edit its targets, for a fetcher that runs once per framework, account or scan |
| `e` | edit its settings and secrets |

The two manifests can share an output directory. The upload always picks the newest
run that collected scan reports, so a newer evidence run beside it is never sent by
mistake.

## 2. Point each fetcher at an assessment

Select the fetcher on the **Manifest** tab and press `A`. The picker lists the
assessments in your workspace of the type the fetcher feeds; type to filter, then
`enter`. It then asks how that assessment's cycle is closed. Until an assessment
is set, the entry's **sends to** column reads `no assessment — press A`; then it
shows the assessment and its close policy, or `close unset` if that is missing.

![Pointing a scan fetcher at an assessment and choosing how its cycle closes](demo/pipeline-setup.gif)

The close policy is the one decision here that needs care, because **closing a
cycle auto-closes every open issue the cycle never saw**. That is how Paramify
learns what was fixed — and why closing too early marks real issues resolved.

| Policy | Use it when | What the upload does |
|---|---|---|
| `after_run` | Each cycle is one report: a monthly scan, one export per run. | Closes the cycle after processing, **but only if every target in the run succeeded and uploaded.** A partial run is processed and left open, and the upload says why. |
| `never` | Several files make up one cycle — several runs, several tools, or files added by hand. | Processes only. Close the cycle once the last file is in, with `C` on the Paramify tab (step 4) or in Paramify. |

There is no default: `paramify validate` and the Manifest tab list an entry without
one as an issue, and the upload sends nothing for that assessment until it is set.

## 3. Run it, then send the reports

Run the manifest from the **Run** tab (`3`, then `enter`). When it finishes, the
banner tells you how many scan reports are waiting.

On the **Paramify** tab (`5`), the **scan reports** panel shows the run it will
send and one row per assessment: how many files, and what the upload will ask
Paramify to do. Read that row before sending:

- `→ PROCESS` — the files are processed and the cycle stays open.
- `→ PROCESS_CLOSE` — the files are processed and the cycle is closed. It is
  highlighted, and the confirmation says so in words.
- `close skipped: …` — the policy is `after_run`, but something in this run makes
  closing unsafe, such as a failed target. The reason is shown.

Press `i` to send, and `y` to confirm.

![Running the pipeline manifest, then sending its reports from the Paramify tab](demo/pipeline-send.gif)

For each assessment the upload sends every file, then asks Paramify to process
exactly those files as one job, and waits for it. The log shows what the job did:

| Count | Means |
|---|---|
| `created` | new issues from findings not seen before |
| `updated` | existing issues the files mentioned again |
| `seen-closed` | open issues the files reported as resolved |
| `auto-closed` | open issues closed because the cycle never saw them (only when it closes) |

Sending the same run again is safe. Files already sent are skipped, and no second
job is queued. A run that was interrupted picks up where it stopped.

## 4. Jobs and closing a cycle

Each assessment processes one job at a time, in order, and **a failed job holds
every job behind it** until someone retries or cancels it. The upload never does
either for you, because which is right depends on why it failed.

On the Paramify tab:

| Key | Does |
|---|---|
| `j` | list recent jobs with their status, assessment and error. `enter` on a failed or queued one offers **retry** (run it again; the jobs behind it follow) or **cancel** (which also cancels every unfinished job behind it). |
| `C` | close the current cycle of one of the manifest's assessments, after a warning. For `never` assessments, once every file for the cycle has been processed. The log shows how many issues it auto-closed. |

![Retrying a failed job, then closing an assessment's cycle](demo/pipeline-jobs.gif)

## How cycles work

Three rules explain most of what you will see.

- **Uploads land on the oldest open cycle.** The pipeline chooses the cycle, not
  the upload, and nothing moves on to a newer cycle until the oldest one is closed.
  An assessment with an old cycle still open keeps receiving every new scan.
- **Closing decides what is resolved.** Open issues the cycle never saw are
  auto-closed. After a close no cycle is open; the next upload opens one.
- **One job queue per assessment.** A failed job blocks the queue until it is
  retried or cancelled.

## When something goes wrong

| You see | Meaning | Fix |
|---|---|---|
| `no assessment_id set` | The fetcher was never pointed at an assessment. | Step 2. |
| `no close_cycle set` | The entry has no close policy. | Step 2. A run collected before you set it is picked up from the manifest when you send it. |
| `HTTP 400` on upload | Usually no file intake preset on the assessment. Its other files are held back. | Configure the preset in Paramify, then send again. |
| `HTTP 401` / `403` | The key lacks a pipeline permission. The upload stops. | Add `PIPELINE_INTAKE` / `PIPELINE_PROCESS` / `PIPELINE_CLOSE` to the key. |
| `HTTP 404` | The assessment ID is from another workspace, or the assessment was deleted. | Step 2 again. |
| `HTTP 409` / `no cycle in progress` | The last cycle was closed and nothing has been uploaded since. | Nothing: the next upload opens a cycle. |
| job `FAILED` | Processing failed; the error says why (often the preset's column mapping). | Fix the cause, then `j` → retry. |
| `blocked by failed job …` | An older failed job holds the queue. | `j` → retry or cancel that job. |
| `still running` | The job outlasted the wait (15 minutes by default). | Nothing is lost: `j` shows how it ends, and sending again waits on it. |
| `close skipped: …` | `after_run`, but the run was incomplete. | Collect and send the missing report, then close with `C` if the cycle is complete. |

## The same from the command line

Everything above has a command, for scripts and CI.

| In the TUI | Command |
|---|---|
| New manifest, add a fetcher | `paramify manifest init -f manifests/pipelines.yaml` · `paramify manifest add -f manifests/pipelines.yaml <fetcher>` |
| `A` on the Manifest tab | `paramify assessments select <fetcher> -f manifests/pipelines.yaml --close-cycle after_run\|never` |
| Run tab | `paramify run manifests/pipelines.yaml` |
| `i` on the Paramify tab | `paramify issues upload -f manifests/pipelines.yaml` (`--dry-run` to preview, `--no-wait` to queue and exit) |
| `j` | `paramify issues jobs` · `--retry <job>` · `--cancel <job>` |
| `C` | `paramify issues close <assessment-id>` |

The uploader's own reference, including its config file and every error, is
[`uploaders/paramify_issues/README.md`](../uploaders/paramify_issues/README.md).
Writing a scan fetcher of your own is covered in
[`issue_report_fetchers.md`](issue_report_fetchers.md).
