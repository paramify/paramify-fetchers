# Publishing a run to Paramify with `paramify upload`

`paramify upload` sends a completed run's evidence to Paramify. It sends the
files of each fetcher entry as one batch on that fetcher's evidence set. The
upload creates the set the first time it sees it. You can then sync each
fetcher's script and validators to the same set, and check the evidence in the
app. This needs Paramify API 0.14.0 or later.

![Flow: an API key and a completed run, then preview, upload, and the optional syncs, then check the evidence set and its JSON in Paramify](img/uploader/flow.svg)

**You need:** [the repo installed](../README.md#install) ·
[a completed run](cli_guide.md#collect-then-upload) · a Paramify account that
can create API keys. The TUI's **Paramify** tab does the same upload and script
sync ([TUI walkthrough](https://support.paramify.com/hc/en-us/articles/55867428958355-Setup-Fetchers)).

---

## 1. Set your API key

Create a key with the permissions in
[API key setup](../uploaders/paramify_evidence/README.md#paramify-api-key)
([help-center steps](https://support.paramify.com/hc/en-us/articles/43292803890451-Create-a-Paramify-API-Key)),
then export it. `paramify doctor` confirms it's set. Uploads also read `.env` at
the repo root, but `paramify doctor` doesn't.

![export PARAMIFY_UPLOAD_API_TOKEN, then paramify doctor reporting the API token set from that variable](img/uploader/01-key.png)

<details><summary>Copy the commands</summary>

```bash
export PARAMIFY_UPLOAD_API_TOKEN='<your key>'
paramify doctor
```
</details>

## 2. Preview the upload

`--dry-run` reads the newest run and lists each file with the evidence set it
will land on. It makes no API calls and needs no key. It cannot read the
workspace, so the stack, channel and artifact request show as unknown. Check the
destination on the first line and each `set=`. To upload an older run, pass its
directory.

![paramify upload --dry-run: production destination, two SQS files from one run, both going to set EVD-SQS-ENC](img/uploader/02-dry-run.png)

<details><summary>Copy the command</summary>

```bash
paramify upload --dry-run
```
</details>

To see where each batch would go, run `paramify upload --plan`. It reads the
workspace (it makes no changes) and prints the full plan: for each fetcher entry,
the evidence set, stack, channel, artifact request, and whether the batch is
new, resumed or already done. It also lists the files it drops and any open
batches from earlier runs. It needs your key. The upload prints the same plan
before it applies it. [How the plan decides](#how-a-run-is-delivered) is below.

## 3. Use your own evidence set (optional)

If your program already tracks this evidence under its own reference ID, map
the fetcher to it in `upload.yaml` at the repo root
([all options](../examples/upload.yaml)). Script sync reads the same file, so
scripts follow the evidence. Re-run the [preview](#2-preview-the-upload) to check
the new `set=`.

```yaml
overrides:
  aws_sqs_encryption_status:
    reference_id: CUST-SQS-ENC-01
```

![paramify upload --dry-run reporting the upload.yaml it read and sending both files to CUST-SQS-ENC-01](img/uploader/03-override.png)

## 4. Upload

Run it without `--dry-run`. Each file shows `OK`, plus `channel=` when its set
has a channel. Then each batch shows its state. Paramify approves it, or it
waits for review, or a validator holds it.

![paramify upload: both SQS files OK on set EVD-SQS-ENC, then Done: uploaded=2 and the path to upload_log.json](img/uploader/04-upload.png)

<details><summary>Copy the command</summary>

```bash
paramify upload
```
</details>

**Uploading the same run again changes nothing.** The upload finds the batch it
made for that run and leaves it alone, and files already sent show `SKIP`
(`skipped_duplicate`). A new run makes a new batch. To collect and upload on a
schedule, [run it in a container](../deploy/README.md#4-run-it-on-a-schedule).
`deploy/run-and-upload.sh` uploads the run it just collected. Add a second
argument to name the stack.

## How a run is delivered

**One batch per fetcher entry per run.** A batch is a set of artifacts that
Paramify submits and approves as one unit. All the targets of one entry go in the
same batch. Two entries that use the same fetcher get two batches. The solution
capability reads the most recent approved batch whose validators pass.

**Channels decide the route.** For each entry the upload counts the channels on
the evidence set:

| The set has | The upload does |
|---|---|
| No channel | Sends the batch to the evidence set. |
| One channel | Uses it. It refuses when a stack is set and the channel is on a different stack. |
| Several channels | Needs a stack. It uses the channel on that stack. It refuses when no stack is set, the stack is not in the workspace, no channel is on that stack, or two are. |

Channels exist only in the Paramify app. The upload never creates one.

**The artifact request.** On a channel, the batch goes to the current artifact
request. If there is none, it goes to the most recent past request and the plan
warns of a late submission. If the channel has no request at all, the upload
refuses that entry. To send the batch to the evidence set instead, set
`no_request: evidence` on the entry. Those artifacts do not count toward the
solution capability.

**A refusal stops one entry.** The other entries still upload. Each refusal says
what to change. The run exits 1, and `upload_log.json` shows the entry as
`refused`.

### Choose the stack in the manifest

Set the stack, and the other delivery options, under `run.paramify` in the run
manifest. An entry can override each one.

```yaml
run:
  paramify:
    stack: <stack id>          # an id, or a name
    stack_name: Production     # a label only
    approval: SUBMISSION_WITH_PASSING_VALIDATORS
  fetchers:
    - use: aws_iam_mfa
    - use: okta_phishing_resistant_mfa
      paramify:
        stack: GovCloud
        approval: MANUAL
        no_request: evidence
```

| Key | Values | Meaning |
|---|---|---|
| `stack` | stack id or name | The stack whose channel receives the batch. |
| `stack_name` | text | A label. The plan warns when it no longer matches the workspace. |
| `approval` | `MANUAL`, `SUBMISSION_WITH_PASSING_VALIDATORS`, `SUBMISSION` | How Paramify approves batches on a set this upload creates. |
| `no_request` | `refuse` (default), `evidence` | What to do when a channel has no artifact request. |

`paramify run` writes each entry's settings into the run's `_run_metadata.json`.
The upload reads them from there. A manifest that changes after the run does not
change the upload, and a scheduled container needs no manifest.

List the stacks with `paramify stacks`. Store one in a manifest with
`paramify manifest set-stack MANIFEST STACK`. Add `--fetcher NAME` to set it for
one entry. To override the stack for one upload, run
`paramify upload --stack STACK`.

### Approval mode

A new evidence set gets the approval mode
`SUBMISSION_WITH_PASSING_VALIDATORS`. Paramify approves a batch when its
validators pass. Set `approval` to change it. The upload never changes an
existing set: it only adds tags to it.

### Held and dropped files

| Problem | Result |
|---|---|
| A temporary failure (429, 5xx, network) | The batch stays `OPEN` and the entry is `held`. Run the same upload again. It sends only the missing files, then submits. |
| A permanent failure on one file (the production WAF, 413, another 4xx) | The upload drops that file, submits the rest, and names the dropped file. The entry is `delivered_with_drops`. |

A file that cannot be read, is not an envelope, or has no complete evidence set
is an error. The upload names it and still sends the other files of the entry.
The entry shows `delivered_with_drops`, `errors` counts the file, and the run
exits 1. A file that `skip_failed` skips, or an incomplete inventory, is only
skipped: it does not change the exit code.

Run `paramify upload --plan` to see held batches and open batches from earlier
runs.

### Read the result

`paramify upload --json` and `upload_log.json` keep `uploaded`,
`skipped_duplicate`, `skipped_failed`, `errors` and `ok`, and add:

- `plan`: the actions the upload planned.
- `entries`: one record for each fetcher entry, with its `state`
  (`planned` for a dry run, then `delivered`, `delivered_with_drops`, `held`,
  `refused`, `failed` or `noop`), batch id, status, stack, channel and artifact
  request.
- `outcomes`: what each action did.
- `validators`: the validator sync summary, when you pass `--with-validators`.

The `results` list no longer holds `evidence_id`, `artifact_id` or `channel_id`
for each file. Read the batch and its channel from `entries`. The exit code is 0
when every entry was delivered (with or without dropped files) or needed no
change, and 1 otherwise.

## 5. Sync scripts and validators (optional)

**Scripts** show in Paramify how the evidence was collected. Run this when you
add a fetcher or bump its version, not after every collection. It covers the
fetchers in `manifest.yaml`; name another manifest, or pass `--all`
([what it does](../uploaders/paramify_scripts/README.md#what-it-does-per-fetcher)).

![paramify scripts sync: aws_sqs_encryption_status created and associated to set EVD-SQS-ENC](img/uploader/05-scripts.png)

<details><summary>Copy the command</summary>

```bash
paramify scripts sync
```
</details>

**Validators** from the registry check each new artifact. Sync them after the
upload, because a validator attaches only to a set that exists
([how sync works](../uploaders/paramify_validators/README.md#what-it-does-per-validator)).
`-m` limits it to your manifest's sets. To write your own, see
[authoring validators](suggest_validator_guide.md).

**Watch for `skipped_exists`.** The validator was already in the workspace, so
the sync didn't attach it again. Check the set's **Validators** tab.

![paramify validators sync -m manifest.yaml: all four SQS validators already exist, so each shows skipped_exists](img/uploader/06-validators.png)

<details><summary>Copy the command</summary>

```bash
paramify validators sync -m manifest.yaml
```
</details>

## 6. Verify in Paramify

Go to **Implementation → Evidence Sets** and open *SQS Queue Encryption*. **Key
Details** shows the ID from the `set=` line, and the **Artifacts** tab has one
artifact per uploaded file.

![The SQS Queue Encryption evidence set: ID EVD-SQS-ENC in Key Details, and the two new artifacts, titled by region, at the top of the Artifacts tab](img/uploader/app-01-evidence-set.png)

**Click an artifact's name** to see exactly what was uploaded: the file's
`metadata` (fetcher, run, target, status) above its `payload`. For validation
results, see [verify validators](suggest_validator_guide.md#5-verify-in-paramify).

![The artifact's JSON: metadata naming aws_sqs_encryption_status and example-us-east-1, then a payload whose first queue, example-orders, is encrypted](img/uploader/app-02-artifact-json.png)

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `[FAIL]` with `401` or `403` | Check the key's permissions ([step 1](#1-set-your-api-key)) and that `PARAMIFY_API_BASE_URL` points where the key was made. |
| `No run under ./evidence that collected evidence.` | Your manifest writes elsewhere. Add `-f <manifest>`, or pass the run directory. |
| `… has 3 channels and no stack is configured` | The upload does not guess a channel. Set the stack: `paramify manifest set-stack`, or `paramify upload --stack`. The message lists the stacks. |
| `… has no channel on stack …` | Create a channel for that stack on the evidence set in the app, or choose another stack. |
| `no current or past artifact request on channel …` | Create an artifact request on the channel in the app, or set `no_request: evidence` on that entry. |
| `this workspace's API has no batches; 0.14.0 or later is required` | The workspace runs an older Paramify API. Upload to a workspace on 0.14.0 or later. |
| An entry shows `held` | A temporary failure stopped the batch. Run the same upload again. |
| A file shows `blocked by the production WAF` | The evidence holds a string the WAF rejects (`../`, `/bin/sh`, `<script`). The upload sent the rest. Remove the string and collect again. |
| Validators attach to `EVD-…`, not your remapped set | Validator sync uses the registry's reference IDs. Attach them on the set's **Validators** tab → **Manage Selection**. |
| `No fetchers in the manifest …` from `scripts sync` | It found none in `manifest.yaml` at the repo root. Name your manifest, or pass `--all`. |
| The run also collected scan reports | `paramify upload` sends evidence only. Send reports with the [issues uploader](../uploaders/paramify_issues/README.md). |

**More detail:** [upload options](../uploaders/paramify_evidence/README.md#config---config-optional)
