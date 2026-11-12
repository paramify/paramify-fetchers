# Pipeline fetchers — Design

**Status:** Proposed. The design was agreed in conversation on 2026-11-12. Four
live checks are still open ([§8](#8-live-checks)).
**Date:** 2026-11-12

Some fetchers write evidence that a person reads. Others write data that a
Paramify **pipeline** reads and processes: an inventory becomes Inventory items,
and a scan report becomes Issues. This document designs the second group, which
it calls **pipeline fetchers**. It covers how to write one, how the uploaders
send its output, how the CLI and TUI show it, and where a preset will live once
the Paramify API can set one.

The design builds on PR #301, which made `paramify upload` send evidence as
Paramify batches, with channels and artifact requests.

## Decided

| # | Decision |
|---|---|
| D1 | **A `pipeline:` block in `fetcher.yaml` marks a pipeline fetcher.** The uploader reads its delivery rules from the block, not from `kind`. See [§3](#3-the-pipeline-contract). |
| D2 | **A pipeline file on an evidence set always goes in a batch** when the workspace has batches. With no artifact request it goes in an ad hoc batch on the set. It is never sent direct. See [§4](#4-delivery-to-an-evidence-set). |
| D3 | **The batch must approve automatically.** The uploader warns about a `MANUAL` set and reports a batch that did not approve. It never changes the customer's approval rule. |
| D4 | **No validators on a pipeline evidence set.** `paramify validate` refuses one in the registry, and `--plan` refuses an entry whose set has one in the workspace. |
| D5 | **Inventory records gain a required `asset_type`.** Paramify derives each record's parent component from it. |
| D6 | **`id_scheme` names the format of the asset ID.** An inventory fetcher and a scan fetcher with the same scheme can be linked in Paramify. |
| D7 | **Scan reports stay on the assessment route for now** (`paramify issues upload`). They gain the `pipeline:` block in Phase 2 and move to evidence sets only when the app does (Phase 3). |
| D8 | **One scan entry can feed several assessments** through a `config.assessments:` list. See [§6](#6-scan-reports-phase-2). |
| D9 | **`paramify preset <fetcher>` prints the preset settings** to enter in Paramify. It gains `--apply` once the API can create presets. |
| Phases | Phase 1 is inventory. Phase 2 is scan reports. Phase 3 (optional) moves the issues uploader onto the sync engine. |

The decision log records the design as entry #1892 (D1 to D7, the phases) and
entry #1893 (D8).

## 1. Background

### What `main` does today (after #301)

| | Scan reports (`kind: issue_report`) | Inventory (`kind: inventory`) |
|---|---|---|
| Output | The scanner's own file, byte for byte, in `issue-reports/`, with a sidecar index | An envelope with `payload.data[]`, checked complete when it is enveloped |
| Uploader | `paramify issues upload`: intake, process, close, wait on the job | `paramify upload`: evidence sets, channels, batches |
| Destination | `assessment_id` and `close_cycle` in the manifest | The fetcher's evidence set. A person attaches the inventory pipeline to it in the app. |
| Channels and batches | Neither | Yes, through #301's routing |
| Preset | Set up by hand on the assessment | Set up by hand, with a sample file, data path, and unique ID |

Fetchers on `main`: two inventory fetchers (`github_repository_inventory`,
`sophos_endpoint_inventory`) and six scan-report fetchers (Wiz ×3, Qualys ×2,
AWS Inspector ECR), plus a template for each kind.

### What the VDR walkthrough showed (2026-11-11)

These findings come from the "Wilf VDR/VER Walkthrough" notes and transcript.

1. **An inventory pipeline runs only on a file in an approved batch.** In
   production, a file uploaded to the evidence set outside a batch built no
   Inventory. The same file in a submitted batch did. The order of operations
   is: preset, attach the pipeline to the evidence set, create a batch, add the
   file, then submit the batch (or approve it automatically).
2. **Validators fail on an evidence set that has a pipeline.** The files are too
   large for the regex engine. This will not change in the foreseeable future.
   Under `SUBMISSION_WITH_PASSING_VALIDATORS`, a failing validator means the
   batch never approves.
3. **An inventory pipeline needs a unique ID and a parent component** on every
   record. Without both, it errors and the preview fails.
4. **A vulnerability preset links findings to Inventory** through an "inventory
   mapping" field (feature flag `CR26-implementation`). It names the scan column
   that matches the inventory's unique ID.
5. **A vulnerability pipeline can target only one component.** A customer with
   several component types needs one pipeline (assessment) for each type, all
   reading the same file, until the condition builder arrives.
6. **Vulnerability pipelines are renamed assessments**, and there is no date for
   them to become real pipelines.
7. **A preset creates an evidence set on its first run.** The set gets a channel
   only once it maps to a solution capability that has an owner.
8. **Stage and production behave differently** for ad hoc batches.

### The gap on `main`

`paramify upload` treats an inventory like any evidence. When the channel has no
artifact request, the default `no_request: direct` sends it direct. A direct
upload succeeds and builds nothing (finding 1), and no error appears. The same
happens with `delivery: direct`.

### The envelope and field mapping

A file in a vendor format (CSV, XML, Nessus, a vendor's JSON) is **never
wrapped**: the preset parses the vendor's format. An inventory file is our own
format, so it keeps the envelope. Its data path is always `payload.data`.

The uploader setting `artifact_payload: payload` strips the envelope, which
would change the data path to `data` and break every inventory preset without
an error. A pipeline file therefore **always** goes as the envelope, whatever
`artifact_payload` says.

## 2. Goals and non-goals

**Goals**

- An inventory sent by `paramify upload` builds Inventory, or the upload says
  why it did not.
- A new pipeline fetcher needs only its `pipeline:` block and its records. The
  author does not need to know the batch rules.
- An inventory and a scan from the same platform link to each other in
  Paramify.
- When the app moves scans to evidence sets, a scan fetcher needs no new routing
  code.
- The preset has a reserved place in the contract.

**Non-goals**

- Creating or applying presets through the API. The key is reserved, nothing
  more.
- Pipeline–evidence pairs and their mapping to solution capabilities. That is
  separate planned work. The `pipeline:` block gives it the data it needs.
- Changing a customer's approval rule, or removing their validators. The
  uploader warns, and the customer decides.
- Building Inventory from scans alone (a planned app feature).

## 3. The pipeline contract

### The block

```yaml
kind: inventory
pipeline:
  type: inventory              # inventory | vulnerability | configuration
  id_scheme: sophos-endpoint-id
```

```yaml
kind: issue_report             # Phase 2
pipeline:
  type: vulnerability
  id_scheme: wiz-resource-id
  asset_id_field: "Resource External ID"
```

| Key | Required | Meaning |
|---|---|---|
| `type` | yes | The Paramify pipeline that reads the file. For a scan report it replaces `issue_report.assessment_type`. |
| `id_scheme` | yes | The format of the asset ID, such as `aws-arn`, `azure-resource-id`, `wiz-resource-id`, or `hostname`. The known schemes are listed in `docs/pipeline_fetchers_guide.md`. A scheme not on that list is allowed, and `paramify validate` notes that it should be added. |
| `asset_id_field` | scan reports only | The column of the vendor file that holds the asset ID. This is the column to choose as "inventory mapping" in the vulnerability preset. |
| `preset` | reserved | Refused by the schema with "not supported yet". It will name a preset once the API can create one. |

Fields that are the same for every inventory are not declared: the data path is
always `payload.data`, and the unique ID is always `unique_asset_identifier`.

### Where the block is allowed

| `kind` | `pipeline:` |
|---|---|
| `inventory` | Required, with `type: inventory`. |
| `issue_report` | Optional in Phase 1, required in Phase 2. `type` is `vulnerability` or `configuration`. While both keys exist, `type` and `issue_report.assessment_type` must agree. |
| `evidence` | Not allowed. An ordinary fetcher must not feed a pipeline set. |

### The inventory record

Each record under `payload.data`:

| Field | Rule |
|---|---|
| `unique_asset_identifier` | Required, non-empty, unique in the file (as today). It follows the declared `id_scheme`. |
| `asset_type` | **New, required**, a non-empty string such as `s3_bucket`, `eks_cluster`, `endpoint`, or `repository`. Advanced configuration derives the parent component from it. |
| Fields for mapping | Top-level scalars. Nested objects and lists are allowed as extras, with a flat copy of any value that a preset maps. Live check 3 decides whether this is a rule or a recommendation. |

### Where it lives in code

- `framework/schemas/fetcher_schema.json`: the `pipeline` block and the rules
  above.
- `framework/schemas/inventory_schema.json`: `asset_type`.
- `framework/contract.py`: a `Pipeline` dataclass on `Fetcher`, and an
  `is_pipeline` property.
- The runner records the block in the envelope as `metadata.pipeline` when it
  collects, as it does `evidence_set`. The uploader reads it from there. A run
  collected before this change is recognised by `metadata.inventory`.

### Migration

`github_repository_inventory`, `sophos_endpoint_inventory`, and
`_template_inventory` gain the block and `asset_type`, with a minor version bump
for each fetcher. The six scan fetchers and `_template_issue_report` change in
Phase 2.

## 4. Delivery to an evidence set

This section applies to an entry whose envelope has `metadata.pipeline`. In
Phase 1 that is every inventory. Other evidence routes exactly as #301 does.

The rule behind it: **a file that Paramify accepts but does not process is a
failure, and the upload says so.**

### Routing

| Situation | Ordinary evidence (#301) | Pipeline file |
|---|---|---|
| The set has no channel | Batch on the set | Batch on the set |
| The channel has a current or past request | Batch on the request | Batch on the request |
| The channel has no request | Direct (`no_request: direct`) | **Ad hoc batch on the set** (`POST /batches`, `type: EVIDENCE`) |
| `no_request: refuse` in the manifest | Refuse | Refuse |
| `no_request: direct` in the manifest | Direct | **`paramify validate` error** |
| `delivery: direct` in the manifest | Direct | **`paramify validate` error** |
| The workspace has no batches | Direct | **Direct, with a note** that the pipeline runs the pre-batch way. If live check 2 fails, this becomes a refusal. |
| `artifact_payload: payload` in the uploader config | Bare payload | **The envelope, always** ([§1](#the-envelope-and-field-mapping)) |

Channel and stack routing, idempotency, resume, WAF checks, and the incomplete-
inventory skip are unchanged.

### Approval

A batch copies its approval rule (`whenToApprove`) from its evidence set when it
is created. The pipeline runs only when the batch is `APPROVED`.

| Case | Behaviour |
|---|---|
| The uploader creates the set | It gets `SUBMISSION`, the existing default. |
| The manifest sets `approval: MANUAL` on a pipeline entry | `paramify validate` warns: Inventory waits for a person to approve. |
| An existing set is `MANUAL` | `--plan` warns. The set is not changed. |
| The batch reads back `SUBMITTED`, not `APPROVED` | The result is "waiting for approval: the pipeline has not run", not success. |

### Validators

- **Registry:** `paramify validate` and the registry tests refuse a validator
  whose `evidence_sets` names the evidence set of a pipeline fetcher. The
  validator sync skips pipeline sets.
- **Workspace:** `--plan` reads `GET /validators` for each pipeline set. A
  validator attached in the app refuses the entry, with the fix: "remove it in
  the app; its batches will never approve".

### What the uploader cannot see

The API has no endpoint for pipeline runs. A good upload therefore ends with
"batch APPROVED: Paramify's pipeline runs now; check Monitoring → Inventory", and
never with "Inventory updated".

## 5. How it shows

### `paramify preset <fetcher>`

A new command prints the preset settings from the `pipeline:` block and the
newest run:

```
$ paramify preset sophos_endpoint_inventory
Inventory pipeline for EVD-SOPHOS-INVENTORY  (attach it to this set, not a new one)
  Sample file       evidence/run-…/sophos_endpoint_inventory.json
  Data path         payload.data
  Unique ID         unique_asset_identifier   (scheme: sophos-endpoint-id)
  Parent component  derive from asset_type. Values in the last run:
                      endpoint 412 · server 37
  Evidence set      approval must be automatic; attach no validators
  Linked scans      none in your manifests use sophos-endpoint-id
```

For a scan fetcher (Phase 2) it prints the inventory mapping column
(`asset_id_field`) and the inventory fetchers with the same scheme. With no run
yet, it prints the settings and says that the sample and `asset_type` values
need a run. Later, `--apply` will create the preset through the API.

### `paramify upload --plan` and the result

```
delivery
  deliver sophos_endpoint_inventory: 1 file → EVD-SOPHOS-INVENTORY, ad hoc batch (CH-12 has no request) · approves on submit → pipeline runs
  warn    github_repository_inventory: EVD-GH-INVENTORY approves MANUAL; Inventory waits for someone to approve the batch
  refuse  acme_inventory: EVD-ACME-INVENTORY has 1 validator (VAL-…); its batches will never approve. Remove it in the app.
```

Result lines for a pipeline entry:

- `APPROVED: pipeline runs now; check Monitoring → Inventory`
- `SUBMITTED: waiting for approval; the pipeline has not run`
- `not sent: incomplete inventory (…)`, as today

The `--json` result gains `pipeline: {type, approved}` for each entry, so
`deploy/run-and-upload.sh` and CI can alert on a file that was sent but not
approved.

`paramify evidence <file>` adds a count of records by `asset_type` to the
inventory verdict.

### TUI

- **Manifest tab:** the "sends to" column reads `EVD-… · pipeline`. On a
  pipeline entry the settings form shows `delivery` and `no_request` locked,
  with the note "pipeline files always go in a batch". `approval: MANUAL` shows
  the warning inline.
- **Detail pane:** the pipeline type, the ID scheme, and the linked fetchers.
- **`p`** on an inventory or scan entry opens the same sheet as
  `paramify preset`.
- **Paramify tab:** the plan rows and results above. "Waiting for approval" is
  amber, not green.

### Paramify

Nothing changes in the app. The inventory guide is rewritten around the order
of operations: run `paramify preset`, build the preset with those values, attach
it to the fetcher's set (not a new one), then upload. The uploader makes the
batch.

## 6. Scan reports (Phase 2)

Scan reports stay on the assessment route: upload bare to the current cycle,
process once on the named artifacts, close only when allowed, and wait on the
job. Phase 2 adds three things.

### The `pipeline:` block

It becomes required on `kind: issue_report`. The assessment picker filters on
`pipeline.type`. For a CSV fetcher with a sample, a test checks that
`asset_id_field` is a column of the sample's header. The Wiz fetchers use
`wiz-resource-id`. For Qualys and Inspector, choose a column that matches an
inventory scheme (an ARN or a hostname) where one exists.

### One report, several assessments

```yaml
- use: wiz_vulnerability_findings
  config:
    assessments:
      - id: 11111111-…
        name: Wiz vulns – EKS
        close_cycle: after_run
      - id: 22222222-…
        name: Wiz vulns – S3
        close_cycle: after_run
```

- `assessment_id`, `assessment_name`, and `close_cycle` stay as the shorthand
  for one assessment. An entry with both forms is a `paramify validate` error.
- Each assessment is independent: its own intake, process, close (by its own
  `close_cycle`), and job queue. A failed job on one does not stop another. The
  output reports each one.
- The intake log is keyed by assessment, run, and file, so adding an assessment
  and uploading again sends only to the new one.
- The runner records the list in the sidecar when it collects, as it does the
  single assessment today.
- `paramify assessments select <fetcher>` gains `--add` and `--remove`. In the
  TUI, `A` becomes a multi-select, and each chosen assessment asks for its close
  policy.

Two manifest entries for one fetcher cannot do this: the second overwrites the
first's output, and #301 fails that run.

### The inventory link

`paramify preset` shows a scan's mapping column and the inventory fetchers that
share its scheme. When no inventory fetcher in the user's manifests has the
scheme, `--plan` notes: "findings will not link to Inventory: no inventory
fetcher uses wiz-resource-id". It is a note, not an error: Paramify accepts
findings without Inventory.

## 7. Phase 3 (optional): one engine

`paramify issues upload` becomes a provider on #301's plan/apply engine
(`framework/sync/`), with the same behaviour. That gives one `--plan` and one
upload panel for both kinds. Do it when the app announces scans on evidence
sets. At that point a scan entry with a `pipeline:` block routes by [§4](#4-delivery-to-an-evidence-set),
and the assessment provider is retired.

## 8. Live checks

Run each on stage **and** production, because they behave differently for ad
hoc batches.

| # | Check | If it fails |
|---|---|---|
| 1 | An ad hoc batch on the set (the channel has no request) builds Inventory. | Refuse when there is no request, and tell the user to create one. |
| 2 | A direct upload in a workspace with no batches builds Inventory. | That row of the routing table becomes a refusal. |
| 3 | The mapper reads a nested field inside a record (`tags.env`). | Flat fields become a rule, checked when the output is enveloped. |
| 4 | A `MANUAL` set: the batch stays `SUBMITTED` and builds nothing until approved, and `--plan` warns. | Fix the warning. |

## 9. Tests

- **Contract:** schema tests for the block (required on inventory, refused on
  evidence, `preset` refused), `asset_type` required, and `asset_id_field` in a
  CSV sample's header.
- **Routing:** table tests in the style of `delivery_routing`, one per row of
  [§4](#routing).
- **Fake API:** `tests/paramify_fake.py` gains validators per set and approval
  states, so plan and apply tests cover "submitted, not approved".
- **Fan-out (Phase 2):** two assessments where one job fails and one completes,
  a re-upload after adding a third, and both config forms in one entry.
- **Goldens and snapshots:** CLI goldens for `upload --plan` and `preset`. TUI
  snapshots for the locked fields and the `p` sheet.

## 10. Rollout

| Phase | Contents | Behaviour change |
|---|---|---|
| 1 | The contract, routing, validate rules, `paramify preset`, TUI, the two inventory fetchers and the template, the rewritten inventory guide, a new `docs/pipeline_fetchers_guide.md` (how to write a pipeline fetcher, and the ID scheme list), and live checks 1 to 4 | Inventory entries only. Other evidence is unchanged. |
| 2 | The block on the six scan fetchers and the template, `assessments:` fan-out, the multi-select picker, and the inventory-link note | Scan entries. The single-assessment form keeps working. |
| 3 | The issues uploader on the sync engine | None for users. Start it when the app moves scans to evidence sets. |

## 11. Open questions

- **Duplicate evidence sets.** A preset creates its own set on its first run
  (finding 7). If a customer builds the preset before attaching it to the
  fetcher's set, they get two sets. The guide tells them to attach the preset
  to the fetcher's set. Confirm with the app team whether a preset can be
  created without a set, and whether the API preset will take a set.
- **The ID scheme list.** Start the list in `docs/pipeline_fetchers_guide.md`
  with the schemes the eight fetchers use. Check each scan fetcher's
  `asset_id_field` against the inventory fetchers on the same platform before
  Phase 2 merges.
