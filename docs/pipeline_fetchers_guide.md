# Writing a pipeline fetcher

Most fetchers write evidence that a person reads. A **pipeline fetcher** writes
data that a Paramify pipeline reads and processes. An inventory fetcher feeds an
inventory pipeline, which builds Inventory items. The fetcher declares this in a
`pipeline:` block in its `fetcher.yaml`. The uploader then sends its file the way
a pipeline needs it, and tells you when the pipeline did not run.

Today only inventory fetchers are pipeline fetchers. To run one, see
[Running an inventory fetcher](inventory_fetchers_guide.md). The design and its
reasons are in [Pipeline fetchers design](pipeline_fetchers_design.md).

**You need:** [the repo installed](../README.md#install) · a fetcher to write
([copy the template](../fetchers/_template_inventory/)).

---

## 1. Add the `pipeline:` block

```yaml
kind: inventory
pipeline:
  type: inventory
  id_scheme: sophos-endpoint-id
```

| Key | Required | Meaning |
|---|---|---|
| `type` | yes | The Paramify pipeline that reads the file: `inventory`, `vulnerability` or `configuration`. An inventory fetcher uses `inventory`. |
| `id_scheme` | yes | The format of the asset ID, in lowercase words joined by hyphens. Pick one from [the list below](#the-id-scheme-list). |
| `asset_id_field` | not for inventory | Only for a scan report: the column of the scanner's file that holds the asset ID. |
| `preset` | reserved | The schema refuses it. |

An inventory fetcher (`kind: inventory`) must have the block with `type:
inventory`. An evidence fetcher (`kind: evidence`, or no `kind`) and a discovery
fetcher refuse it. You do not declare the data path or the unique ID: they are
always `payload.data` and `unique_asset_identifier`.

`paramify describe <fetcher>` shows the block. When the runner collects, it
copies the block into the output file as `metadata.pipeline`, and the uploader
reads it from there.

## 2. Write the records

Each record under `payload.data` has these fields:

| Field | Rule |
|---|---|
| `unique_asset_identifier` | Required, non-empty, and unique in the file. Use the asset's own stable ID, in the format of your `id_scheme`. Never use a display name. |
| `asset_type` | Required, a non-empty string such as `endpoint`, `s3_bucket` or `repository`. Paramify derives each record's parent component from it. |
| Other fields | Your choice. Keep the same keys on every record, with `null` for a missing value. |

A pipeline preset maps one field at a time, so put what you want mapped at the
top level of the record as plain values. A list or nested object can stay as an
extra, but add a flat copy of any value that a preset should map, such as
`primary_ip_address`.

The output is all or nothing. If any page or record fails, write no records and
exit non-zero. The uploader never sends an incomplete inventory. The
[template](../fetchers/_template_inventory/fetcher.py) does this for you.

`paramify evidence <file>` checks the records and counts them by `asset_type`.

## 3. What the uploader does for you

When `paramify upload` finds a file from a pipeline fetcher, it:

- **Sends it in a batch.** Paramify's inventory pipeline runs only on a file in
  an approved batch. A direct upload is stored and builds nothing. With no
  artifact request on the channel, the upload makes an evidence-level batch on
  the set. A `delivery: direct` or `no_request: direct` inherited from
  `run.paramify` is ignored, and `paramify validate` notes it; on the entry
  itself it is an error. If an earlier upload sent the run's files direct, the
  next upload sends them again in a batch, so the pipeline runs.
- **Sends the whole envelope**, even when your uploader config sets
  `artifact_payload: payload`. The pipeline reads `payload.data`.
- **Approves the batch on submit.** Each new batch takes the entry's
  `approval`, which defaults to `SUBMISSION`, so the pipeline runs even when
  the set itself approves `MANUAL`. The uploader warns when the entry (or a
  batch it resumes) approves `MANUAL`, and says `SUBMITTED: waiting for
  approval; the pipeline has not run` when a batch is not approved. It never
  changes the set's approval rule.
- **Wants no validators on the set.** Validators fail on files this large, so
  the batch would never approve. The plan refuses an entry whose set has a
  validator, and `paramify validate` refuses a registry validator that targets
  it. The uploader never removes a validator.
- **Sends direct only when the workspace has no batches**, and says so: `sent
  direct: this workspace has no batches; the pipeline runs the pre-batch way`.
  There is no batch to approve, so `--json` shows `pipeline.approved: null`.
  `approved: false` means a batch is `SUBMITTED` and waits for a person.

A good upload ends with `APPROVED: pipeline runs now; check Monitoring →
Inventory`. The uploader cannot see the pipeline itself, so check Inventory.

## 4. Set up and test

1. Copy the template and fill in the block, the records and the README.
2. Add the fetcher to a manifest and run it ([steps 1 and 2 of the inventory
   guide](inventory_fetchers_guide.md#1-run-it)).
3. Run `paramify preset <fetcher>` for the settings to enter in Paramify
   ([details](cli_guide.md#paramify-preset-fetcher)):
   - `-f manifest.yaml` reads the runs from that manifest's `run.output_dir`.
   - `-o DIR` / `--output-dir DIR` finds the newest run in `DIR` instead.
   - `--json` prints the same settings as data.
   - In the TUI, press `P` on the **Manifest** tab to open the same sheet.
4. Run `paramify validate`, then `paramify upload --plan`.

<details><summary>Copy the commands</summary>

```bash
paramify validate manifest.yaml
paramify preset <fetcher> -f manifest.yaml
paramify upload --plan
```
</details>

## The ID scheme list

An inventory fetcher and a scan fetcher with the same `id_scheme` can be linked
in Paramify. `paramify preset` lists the other fetchers that share a scheme. A
new scheme must be added to this list. A fetcher whose scheme is missing from
this table fails a test (`test_every_id_scheme_is_in_the_guide`), so add the row
in the same change.

| Scheme | ID format | Fetchers |
|---|---|---|
| `github-repository-url` | The repository's REST URL, built from its numeric id | `github_repository_inventory` |
| `sophos-endpoint-id` | The Sophos Central endpoint id | `sophos_endpoint_inventory` |
| `aws-arn` | The resource's ARN | no fetcher yet |
| `azure-resource-id` | The Azure resource id | no fetcher yet |
| `wiz-resource-id` | The Wiz resource id | no fetcher yet |
| `hostname` | The host's name | no fetcher yet |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `kind: inventory` fails validation | Add the `pipeline:` block with `type: inventory` and an `id_scheme`. |
| `direct is not allowed on a pipeline fetcher` | Remove `delivery: direct` or `no_request: direct` from the entry. A pipeline file never goes direct. |
| `a pipeline file never goes direct` on upload, with no `direct` on the entry | The run was made before pipeline entries ignored a `direct` in `run.paramify`. Set `no_request: evidence` on the entry, or remove `direct` from `run.paramify`, then run again. |
| `has N validator(s) … its batches will never approve` | Remove the validators from the evidence set in Paramify. |
| `approves MANUAL` | Remove `approval: MANUAL` from the entry (new batches then approve on submit), or approve each batch yourself. |
| `SUBMITTED: waiting for approval` | The batch needs a person to approve it. The pipeline has not run. |
| `paramify evidence` reports a problem with `asset_type` | A record has no `asset_type`, or it is empty. Set one on every record. |
