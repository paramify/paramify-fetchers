# Comparators — Design

**Status:** Decided. Decisions were recorded on 2026-10-16 and 2026-10-19, and
the framework support is built (§7, slice 1) and was simplified after review on
2026-10-22. Only the Q4 checks that need an Azure DevOps organisation are still
open.
**Date:** 2026-10-16, updated 2026-10-22

The reference for what was built is [`comparators.md`](comparators.md), and the
walkthrough is [`comparators_guide.md`](comparators_guide.md).

A comparator is a fetcher whose source is earlier fetchers' evidence files instead
of an external API. It declares `depends_on`, reconciles records across those
sources, and writes one ordinary evidence file. The runner runs it after its
fetchers, tells it where its inputs' files are, and wraps its output like any
other.

## Decided

| # | Decision |
|---|---|
| Q1 | **Add `input_failed`** as a status code. A comparator reports it when an input failed, so triage looks at that input's evidence. See [Q1](#q1-failure-code-for-a-bad-input). |
| Q2 | **Same run only, permanently.** A comparator reads only inputs collected in the same run. No stored-run inputs and no `max_age_hours`, now or later. Inputs are read in place: nothing is copied, and the comparator writes verdicts only. |
| Q3 | The runner records the inputs in the comparator's envelope as `metadata.inputs`. |
| Runner | The runner runs every fetcher, then every comparator (two phases), so every input has finished before a comparator starts. A comparator still runs when an input ran and failed, so a failed artifact reaches Paramify. It is skipped, with the cause named, only when it can't run: an unknown input, a cycle, an input of the wrong kind, or an input comparator that can't run for any of these reasons. |
| Review (2026-10-22) | Four simplifications, same design: the two-phase order, which replaces the explicit completion check; `paramify manifest add` adds a comparator's inputs; `validate` and `run` report a comparator's bad inputs on its entry instead of discovery leaving it out; and one shared `run()` in `comparator_inputs.py`, so a comparator is only its comparison. |
| Placement | **A separate top-level `comparators/` folder**, not inside `fetchers/`. See [§4](#4-placement-decided). |
| Q4 (a) | **Measured on the sandbox, 2026-10-19:** Resource Graph `changedBy` for a service principal is its app (client) id. See [Q4](#q4-sandbox-checks). |
| Q5 | Production is the `environment` label on `azure_change_provenance` targets, picked by an `environments` setting on the comparator. |
| Q6 | A record per pipeline run in `azure_devops_pipelines` is a follow-up after PR #158 merges. The service-connection fetcher (`azure_devops_service_connections`) is widened to collect each service connection's service principal id and its execution history. |

## Still open

1. **Q4 (b) and (c):** how long service-connection execution history is kept
   (and whether it has one record per job), and what an Entra identity needs to
   read service connections. Both need an Azure DevOps organisation. See
   [Q4](#q4-sandbox-checks).

---

## Why comparators exist

A Paramify validator is a regex over one artifact in one evidence set. It cannot
open a second artifact. Inside one file, a regex also cannot take each item of
one list and look up its match in another list. Each fetcher collects one
source, so a claim that needs two sources is in neither file. The join has to
happen in code before upload, and its result has to be in one file.

## What the design stays consistent with

| Principle | Where it lives | Consequence |
|---|---|---|
| Same contract as fetchers; no special runtime or data store | `docs/architecture.md` | `fetcher.yaml` + `fetcher.py`, env-only input, raw dict to `EVIDENCE_DIR`, runner wraps it |
| Files on disk are the only link between stages; intermediate data lives in the run folder | `docs/architecture.md`, `docs/architecture_guide.md` | Inputs are the fetchers' own files in the run folder, read in place |
| The runner never reads inside a payload; the exit code is the only failure signal | `docs/fetcher_contract_guide.md` | The runner passes statuses; reading `partial_failure` is the comparator's job |
| Failure codes are a closed set | `fetchers/_lib/fetcher_status.py`, `fetchers/_lib/status.sh` | Q1 |
| Partial evidence goes in the payload as `partial_failure` + `api_failures[]` | `docs/fetcher_contract_guide.md` | Input problems go in that ledger |
| Only fetchers retry; comparator failures are logical | `framework/runner/` (`retry.py` is a stub) | No retry; `retry.py` and `logger.py` stay out of scope |
| One facade | `framework/api.py` | Ordering and handoff live in `api.run` |
| A failed file still uploads | `docs/architecture_guide.md`, `uploaders/paramify_evidence/uploader.py` | A comparator always writes a file |
| One validator reads one file; a rule that reads nothing passes | `validators/README.md`, `docs/validators_guide.md` | Summary counts are `null` when inputs are missing, never 0 |
| `_lib` is stdlib-only and never imports `framework/` | `fetchers/_lib/fetcher_status.py` | The input reader is a stdlib module, `comparators/_lib/comparator_inputs.py` |
| Other kinds (inventory, issue reports, discovery) live in `fetchers/` with their own `_template_*` | `fetchers/_template_*`, `docs/authoring_fetcher_guide.md` | Comparators deliberately don't: they get their own tree (§4) |
| A category's secrets and passthrough env reach every fetcher in it | `fetchers/_categories/azure.yaml`, `framework/runner/executor.py` | A comparator is given none |
| No new validators in the public repo | repo rule | Validators for comparator evidence go in a client's private copy |

---

## 1. Declaring inputs

```yaml
name: azure_change_pipeline_runs
depends_on: [azure_change_provenance, azure_devops_pipelines, azure_devops_service_connections]
secrets: []
```

- `depends_on` is already in `fetcher_schema.json`. A non-empty list is what
  makes a fetcher a comparator. There is no new `kind`.
- Every input is required.
- The schema rejects a comparator that declares targets or secrets.
- Discovery keeps every comparator. `validate` reports one that can't run on its
  manifest entry, and `run` skips that entry with the same reason, when an
  input:
  - has an unknown name;
  - is part of a cycle;
  - is `kind: issue_report` or `discovery`, or has output that isn't JSON (only
    JSON is enveloped);
  - is a comparator that can't run, for any of these reasons.

  So a private mirror that drops an input fetcher fails only the comparators
  that read it, directly or through another comparator. Which tree a comparator is filed in is this repo's layout rule, a
  contract test.
- `paramify manifest add` adds a comparator's inputs, and theirs, that the
  manifest lacks. It does this when the manifest is edited, never during a run:
  an input can need its own targets and secrets.
- The schema also requires a comparator to be `kind: evidence` with JSON output
  and an `evidence_set`, since its one job is an uploadable file.
- A comparator gets no credentials: no category secrets and no passthrough env.
  As built, it gets no category config either, so a category's required
  settings don't apply to it; it has its own `config_schema`.

## 2. Run order and handoff

**Order.** `framework/runner/dependency_graph.py` runs two phases: every
fetcher in manifest order, then every comparator, each after any comparator it
reads and otherwise in manifest order.

**Guarantee that inputs have finished.** Two things together make it certain
that a comparator never starts while an input is still running:

1. **The run is serial.** The runner starts the next entry only after the
   current entry's processes have exited, or been killed at their timeout, and
   after their files have been wrapped in envelopes.
   With two phases, every fetcher has finished before the first comparator
   starts, and a comparator that reads another comparator runs after it. A
   comparator in a cycle, or downstream of one, has no such place, so it is
   flagged as unable to run and skipped. Tests list the comparator first and
   assert that it starts last, and that one downstream of a cycle never starts.
2. **Same run only.** No other process writes to the run folder, so a comparator
   never reads a file another run is still writing.

One gap remains. A fetcher can exit while a background process it started is
still writing. The runner lists only the files that existed when the fetcher
exited, and the reader treats a file that is not a complete envelope as
`missing`. A half-written file is therefore reported, never compared.

**Handoff, with no copy of the evidence.** Before the comparator runs, the runner
writes a small index: each input's targets, status, exit code, error, and the
paths of its files. The index goes to a temp file outside `EVIDENCE_DIR`, and its
path is passed in `COMPARATOR_INPUTS`, the same way `$FETCHER_STATUS_FILE` works.
The comparator reads the fetchers' own files in place from those paths.

- Nothing is copied.
- The index is a few hundred bytes and is deleted with the invocation.
- The runner builds the index from results it already holds, so it never opens a
  payload.
- An input that is not in the manifest is listed as `missing`. `paramify
  validate` reports it beforehand, with the fix `paramify manifest add <input>`.

**Failed, partial or missing inputs.** The runner runs the comparator whenever
its inputs could run, even if one failed; if it were skipped, nothing would
reach Paramify. Only a comparator that can't run at all (§1) is skipped. The shared reader applies one
policy:

| Input state | Comparator does | Exit |
|---|---|---|
| succeeded, the payload's `partial_failure` is false, and for an inventory the runner marked it complete | compares | 0 |
| a partial or failed file, or an inventory the runner marked incomplete (`metadata.inventory.complete: false`) | compares what it has, records the input in `api_failures`, sets `partial_failure: true` | 1, `input_failed` |
| missing: not run, no file, unreadable, a payload that isn't a JSON object, or an inventory with `records_included: false` | writes its file with every summary count `null` | 1, `input_failed` |

As built, an input with several targets is missing when any one of them wrote
no readable file: counts over a subset of the scope would read as complete.

`comparator_inputs.run(check, output, summary_keys)` is every comparator's
main(), so the policy changes in one place. If the index can't be read, the
comparison raises, or its result isn't JSON, it still writes the file with null
counts and exits 1 with `internal_error`.

## 3. Output

- The payload is `{metadata, results, summary}`. `inputs_complete` is always in
  the summary.
- **Results stay lean, so they are not a second copy.** For each change, the
  record holds only what is needed to read its verdict:
  - change id, resource, caller and time;
  - the verdict;
  - the matched run's id, pipeline, commit and branch.

  Full change records and run records stay in their own files and evidence
  sets. Each file is uploaded once, to its own set.
- The runner adds `metadata.inputs` to the envelope (decided, Q3): each input's
  fetcher name, target, run id, collection time, status and file. It is an
  optional field in `envelope_schema.json`; inventory's `metadata.inventory` is
  the precedent. `_run_metadata.json` gets the same list.
- Summary conventions match the existing fetchers: whole-number counts and
  percentages, `sorted_counts` breakdowns, and `null` where a value can't be
  known.

## 4. Placement (decided)

**Decided: a separate top-level `comparators/<category>/<name>/` folder** (option
A below). It's obvious which scripts call APIs and which only read files.

| Option | For | Against |
|---|---|---|
| **A. Separate `comparators/<category>/<name>/`** (chosen) | It's obvious which scripts call APIs and which only read files. | A second tree to wire in. |
| B. Inside `fetchers/<category>/<name>/`, with `fetchers/_template_comparator/` (rejected) | Follows how inventory, issue reports and discovery are housed. | Less visible as a separate layer. |

What A took, as built:

- **Discovery** walks both trees into one namespace
  (`framework/config_loader.py`).
- **`comparators/_lib/`** holds the reader and the shared `run()`, which imports
  `report_failure` from `fetchers/_lib`, so there is still one failure helper.
- **`tests/test_contracts.py`** checks that a comparator is under `comparators/`
  and a collector under `fetchers/`. It and
  `tests/test_failure_reporting_contract.py` walk both trees;
  **`tools/gen_ksi_mapping.py`** links either tree.
- **`tools/generate_chart.py`** is unchanged: the coverage chart counts fetchers
  per category, and a comparator adds no source.

A cross-platform comparator still picks one category folder.

## 5. Tests, docs and skills

- **Tests** (`tests/test_comparators.py`):
  - the two-phase order (comparator listed first, starts last);
  - `manifest add` adding inputs;
  - cycles and unknown names;
  - the contract checks;
  - the runner handoff: index, no credentials, `metadata.inputs`, `validate`;
  - the reader's policy table;
  - a comparator scaffolded from the template, on synthetic payloads.
- **Docs:** [`comparators.md`](comparators.md) and
  [`comparators_guide.md`](comparators_guide.md), plus updates to the fetcher
  contract, run manifest, config and envelope guides and `docs/architecture.md`.
- **Skills:**
  - `create-fetcher` has a comparator route.
  - `wire-manifest` treats a missing input as a gap.

## 6. First comparator: `azure_change_pipeline_runs`

**Claim:** each production Azure change was made by a pipeline run, so it can be
tied to that run's commit. The join key is the service connection's service
principal plus the time.

**Inputs:**

| Need | Source | Today |
|---|---|---|
| change, caller, time, ARM deployment start and end | `azure_change_provenance` | has it |
| run → commit, branch, result | `azure_devops_pipelines` (PR #158) | partly; needs per-run records (below) |
| service connection → service principal id | `azure_devops_service_connections` (planned) | not built |
| which run used which connection, and when | the same fetcher | not built |

### Per-run records: what `azure_devops_pipelines` keeps today, and what it needs

**What it fetches today.** For each project it calls `build/builds` for every
completed run in the lookback (default 30 days), following every continuation
token. It uses those runs for counts and to attach test results.

**What it keeps in its output.**

- Per pipeline: `runs.in_window`, counts by result, and `runs.last`. `runs.last`
  is the latest run's id, number, result, reason, branch, commit, who requested
  it, and finish time.
- Runs also appear in `environments[].deployments[]`, but only for deployment
  jobs that target an Azure DevOps environment.
- A run that deploys from an ordinary job, such as an Azure CLI or Terraform
  step, appears only in the counts.

**What the per-run records follow-up adds.** `runs.records[]` per pipeline. Each record holds:

- id, number, result and reason;
- source branch and commit, and `from_default_branch`;
- requested-for;
- queue, start and finish times;
- that run's test counts: test runs, passed and not passed.

All of it comes from data already fetched, with no new API calls or token scopes.

**Size.** About 400–500 bytes per run:

- 1,500 runs in 30 days is about 0.7 MB.
- 10,000 runs is about 5 MB.

If that is too large, a setting could keep records only for pipelines that
deploy, or shorten the window. The committed sample keeps one record.

**Why the comparator needs it.** The service-connection fetcher's execution history says which run used
the connection, and when. It does not give the run's commit, branch or result;
those come from the run record. Without per-run records, a traced change shows its commit
only when its run was the pipeline's latest run or a deployment job.

### Matching

1. **Scope.** Changes with a named caller, excluding Azure's own background
   changes. Only subscriptions whose `environment` label is in `environments`
   (decided, Q5), within the window every input covers. Changes with no recorded
   caller are counted but not matched.
2. **Time.**
   - A change made by an ARM deployment uses that deployment's exact start and
     end.
   - Any other change is matched over `[t − 15 min, t + 5 min]`, configurable.
     Azure records a change up to about 10 minutes after it happens.
3. **Identity.** The candidates are the execution-history uses of connections
   whose service principal equals the change's caller, and whose time overlaps
   the change's window. Resource Graph's `changedBy` for a service principal is
   its app (client) id, so it joins on the connection's `serviceprincipalid`.
   Compare ids case-insensitively, and expect one operation to produce several
   change rows (see [Q4](#q4-sandbox-checks)).
4. **Verdict:**
   - `traced`: exactly one run fits.
   - `ambiguous`: two or more fit; they are listed and none is picked.
   - `pipeline_identity_without_run`: the caller is a pipeline's service
     principal, but no run used it at that time.
   - `not_pipeline_identity`: a person or another application.

**Summary:** `inputs_complete`, `changes_in_scope`, `changes_traced_to_run`,
`changes_ambiguous`, `changes_by_pipeline_identity_without_run`,
`changes_not_by_pipeline_identity`, `changes_unattributed`,
`changes_outside_window`, `percent_traced`, `traced_changes_from_default_branch`,
`runs_traced`, `commits_traced`, `untraced_changes_by_changed_by`,
`untraced_changes_by_resource_type`, `comparison_window`.

**Evidence set:** `EVD-AZURE-CHANGE-PIPELINE-RUNS`. **KSIs:** KSI-CMT-RMV,
KSI-CMT-VTD.

**What it cannot see** (each is listed under `not_collected` in the payload):

- a managed-identity service connection, which has no service principal id;
- changes older than the execution history keeps, or older than Resource Graph's
  14 days;
- pipelines on other CI systems.

**Blocked by:** the framework (now built), per-run records in `azure_devops_pipelines`, and the service-connection fetcher.

## 7. Slices

0. **Inputs:**
   - per-run records in `azure_devops_pipelines`, after #158 merges;
   - the service-connection fetcher, widened.

   Both are fetcher work.
1. **First ship**, in two parts:
   - **The framework (built):** two-phase ordering, the
     same-run input index, the credential-free env, `metadata.inputs`,
     `input_failed`, the `validate` checks, `manifest add` adding inputs, the
     shared reader and `run()`, the template, discovery of `comparators/`, the
     CLI and docs, and a credential-free demo comparator (`demo_policy_check`).
   - **`azure_change_pipeline_runs` 0.1.0**, with docs and tests. It waits on
     per-run records and the service-connection fetcher.

   The proof for the second part is a sandbox run in which the pipeline's own
   changes come out `traced`, and a CLI change made with the same service
   principal comes out `pipeline_identity_without_run`.
2. **Polish:** TUI touches.
3. **Later, only if a second comparator needs it:** optional inputs, one run per
   target, and inputs passed by reference.

## Open questions

### Q1: failure code for a bad input

**Decided (2026-10-19): add `input_failed`.** Built as described below.

**The contract change.** `report_failure` accepted seven codes and dropped any
other with a warning. Adding `input_failed` meant:

- adding it to `STATUS_CODES` in `fetchers/_lib/fetcher_status.py`;
- adding it to the bash twin `fetchers/_lib/status.sh`;
- updating the code list in the fetcher contract docs;
- updating `tests/test_fetcher_status_lib.py`, which pins the set.

Nothing else changes, because nothing branches on a code's value. The runner,
the envelope (`error_code` is a free string), the uploader and the TUI pass it
through as text, and no validator reads it.

**Why it matters.** The code is the label someone triaging a failed comparator
sees: `metadata.error_code` on its artifact in Paramify, in `paramify evidence`
and in the run output.

- `input_failed` says "look at the input's evidence set". That input's own file
  carries the root cause, such as `not_authorized`.
- Reusing `partial_failure` says the comparator itself collected partially, and
  `bad_config` says the manifest is wrong. Both point at the wrong place.

Exit code, `status: failed`, upload and validators behave the same either way, so
it is a small, diagnostics-only choice.

### Q4: sandbox checks

(a) Resource Graph's `changedBy` for a service principal is its app id, the same
value a service connection stores. (b) The execution history has one record per
job, and how long it is kept. (c) What an Entra identity needs to read service
connections.

**(a) measured on the sandbox, 2026-10-19.** A throwaway service principal made
one change, then a tag edit; a user edit was the comparison.

- Resource Graph `resourcechanges.changedBy` for a service principal is its app
  (client) id, with `changedByType` set to `Application`. That is the id a
  service connection stores as `serviceprincipalid`, so it works as the join key.
- `clientType` holds the app id in upper case, so compare ids
  case-insensitively.
- One PATCH can produce two change rows. The comparator must handle several
  rows for one operation.
- In the activity log, `caller` is the service principal's object id, not its
  app id; `claims.appid` holds the app id. An input that joins on the activity
  log must use `claims.appid`. `azure_change_provenance` reads Resource Graph's
  `changedBy`, so it is fine.

**(b) and (c) are still open.** Both need an Azure DevOps organisation; check
them while building the service-connection fetcher.

### Placement

Decided: a separate `comparators/` folder. See §4.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Join in a validator or in Paramify | A validator reads one artifact; Paramify has no cross-artifact join |
| Join inside one fetcher | Two sources, two sets of credentials and two failure domains in one script |
| Comparators inside `fetchers/` with a `_template_comparator` (placement B) | Decided against: a separate tree keeps it obvious which code calls an API |
| Reuse `partial_failure` or `bad_config` for a bad input | Points triage at the comparator or the manifest instead of the input that failed |
| New `kind: comparator` | A comparator produces ordinary evidence; `depends_on` already marks it |
| Skip the comparator when an input ran and failed | Nothing reaches Paramify, so the set goes stale silently |
| Comparator searches the run folder itself | Depends on file naming, misses targets that wrote nothing, reads undeclared files |
| Copy inputs into a separate store or the comparator's own folder | A second copy of collected evidence; files are read in place instead |
| Inputs from an earlier stored run | Decided against (Q2): stale data, and a race with a run still writing |
| Add missing inputs during a run | An input can need targets and secrets a run can't supply; `manifest add` adds them when the manifest is edited instead |
| Leave a comparator with bad inputs out of discovery | Built first, dropped in review: `validate` is the one place for "this entry can't run", and only that entry fails |
| Move each comparator only as far as its last input | Built first, dropped in review: fetchers and comparators took turns, which is harder to explain than two phases |
| An explicit completion check before each comparator | Built first, dropped in review: with a serial two-phase run it can never fire, because `run` skips every comparator in a cycle or downstream of one |
| Retry a comparator | Its failures are logical |
| Give comparators credentials | It would become a hidden second fetcher |
| Time-only matching via `pipeline_principals` | Overlapping runs can't be told apart |
| Map pipelines to connections from YAML | A guess; the execution history records actual use |
