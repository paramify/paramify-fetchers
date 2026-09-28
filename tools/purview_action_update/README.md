# purview_action_update

Fills a Microsoft Purview **Action Update** workbook from Paramify, so a client
can upload the result back into Compliance Manager.

Semi-automated by design. Compliance Manager has **no write API** for
improvement actions — the only supported path is export → edit the
`Action Update` tab → re-upload. This tool does the edit. A human does the
upload.

| Purview column | Source |
|---|---|
| `Implementation Status` | **Audit Log Activity** — the last status-change event's `new` value |
| `Implementation Date` | **Audit Log Activity** — that same event's timestamp |
| `Implementation Notes` | **Solution Capability** — `functions[].narrative`, `@`-mentions stripped |

Status and date come from the *same* event, so the pair always describes one
transition rather than pairing a current status with an unrelated date.

**The join:** one Improvement Action is one Solution Capability, matched on
name — a SolCap's `name` is byte-identical to the Purview Action Title. In the
reference program all 463 match exactly, so any row that fails to match is
reported as a data-quality finding rather than skipped quietly.

Read-only against Paramify except for the opt-in `--upload`. The input workbook
is never modified.

---

## Quickstart

```bash
cd ~/Desktop/paramify-fetchers-neo
source .venv/bin/activate
export PARAMIFY_API_BASE_URL='https://stage.paramify.com/api/v0'   # omit for production
export PARAMIFY_API_TOKEN='...'
```

Credentials are also read from the repo-root `.env`. An exported variable wins.

```bash
# 1. is the token good, and am I in the right workspace?
python tools/purview_action_update/run.py --check-auth

# 2. what does the audit log actually contain?
python tools/purview_action_update/run.py --probe-audit

# 3. collect and write the workbook locally
python tools/purview_action_update/run.py --print-changes-brief

# 4. the same, and attach the result to a Paramify Evidence Set
python tools/purview_action_update/run.py --upload
```

Outputs `<name>.updated.xlsx` and `run_report.json` into `--out`
(default `out/purview_action_update/`).

**Pick the right instance.** A production token against staging fails as a
`401` indistinguishable from a bad token. `--check-auth` echoes the base URL in
use and how many capabilities are visible — the fastest way to confirm you are
in the workspace you think you are.

---

## Flags

### Input and output

| Flag | Effect |
|---|---|
| `--workbook` | The Purview export. Defaults to the first that exists of `~/Desktop/QUICK SP TEST/ExportActions.xlsx`, `~/Desktop/ExportActions.xlsx`, `./ExportActions.xlsx`; the resolved path is logged |
| `--out` | Output directory (default `out/purview_action_update`) |
| `--dry-run` | Plan and report, write no workbook |
| `--offline DIR` | Read capabilities and audit events from JSON fixtures — no token, no network |
| `--print-changes` | List every written cell after the summary |
| `--print-changes-brief` | The same, omitting the long narrative rows |

### What gets written

| Flag | Effect |
|---|---|
| `--mode fill-empty` | **Default.** Write only into blank cells |
| `--mode sync` | Also replace cells that disagree with Paramify |
| `--on-date-conflict` | `skip` (default) / `advance-test` / `clear-test` — see below |
| `--notes-policy` | `follow-mode` (default) / `append` — see below |
| `--status-fallback-solcap` | Where no status-change activity exists, use the capability's current status (no date derivable) |
| `--strict-test-status` | Refuse rows whose Test Status is blank when the new status does not permit `None` |
| `--timezone ZONE` | IANA zone for date rendering. Defaults to this machine's zone |

### Paramify

| Flag | Effect |
|---|---|
| `--check-auth` | Validate the token with one read; reports the auth scheme, base URL and capability count |
| `--base-url` | API base URL; overrides `PARAMIFY_API_BASE_URL` |
| `--probe-audit` | Dump the audit-log shape and distributions — keys and counts, no values |
| `--probe-values` | With `--probe-audit`, histogram *short* change values on capability events |
| `--activity-types` | Audit `activityTypes` to scan (default `HISTORY`) |
| `--audit-start` | `YYYY-MM-DD` lower bound on the audit scan |
| `--upload` | Attach the workbook **and** the run report to an Evidence Set |
| `--evidence-reference-id` | Idempotency key (default `PURVIEW-ACTION-UPDATE`) |
| `--evidence-name` | Evidence Set name |
| `--evidence-id` | Attach to an existing set directly, skipping lookup |
| `--min-match-rate` | Refuse to upload below this name-match fraction (default `0.5`) |
| `--allow-no-changes` | Upload even when the run changed nothing |
| `--accept-near-matches` | Join names matching only after case/whitespace normalization |

### Cleanup (destructive — all require `--confirm`)

| Flag | Effect |
|---|---|
| `--list-artifacts ID` | List an Evidence Set's artifacts, marking the no-op ones |
| `--prune-no-op-artifacts ID` | Delete artifacts whose note records a run that changed nothing |
| `--delete-evidence-set ID` | Delete an entire Evidence Set and everything attached |
| `--confirm` | Actually perform it. Without this they report and change nothing |

No-op artifacts are identified by the **note the run itself wrote**
(`0 cell(s) written`), never by position or date — so an artifact a person
uploaded by hand can never be selected.

---

## Dates: only the date has to be right

Purview date cells carry no timezone, so what matters is that the **calendar
date** is correct for the person reading it.

That is why the default is **the operator's own zone, not UTC**. An audit event
at `2026-09-29T02:00Z` is still 28 September everywhere from Eastern to Hawaii,
but rendered in UTC it would be written as `9/29`. A test asserts the correct
date across all seven US zones.

Resolution order: `--timezone` → `TZ` → the system zone from `/etc/localtime`
(an IANA name, so historical events get the right DST offset) → the OS's
current UTC offset → UTC. The report records the zone *and* how it was
resolved, so a run stays auditable.

The format written is `M/D/YYYY H:MM:SS`, matching what Purview's own export
emits.

---

## The Test Date conflict

Purview requires `Test Date >= Implementation Date`. A derived Implementation
Date later than the row's existing Test Date would make the whole re-upload
fail validation.

| `--on-date-conflict` | Implementation Date | Test Date | Test Status |
|---|---|---|---|
| `skip` *(default)* | unchanged | unchanged | unchanged |
| `advance-test` | written | moved to match | kept |
| `clear-test` | written | cleared | cleared |

Neither resolution is free. `advance-test` keeps the recorded pass but moves
its date to a day no test happened. `clear-test` is truthful — a changed
implementation date makes the earlier test stale — but discards a real result.
So `skip` is the default, and the other two are the only thing that makes
`Test Date` and `Test Status` writable at all.

---

## Notes: keeping the client's own words

156 of the reference export's rows already carry a note someone typed. What
happens when Paramify has a narrative for the same row is a policy choice:

| `--notes-policy` | With `--mode fill-empty` | With `--mode sync` |
|---|---|---|
| `follow-mode` *(default)* | client's note kept, gaps filled | **Paramify replaces the client's note** |
| `append` | client's note kept, gaps filled | client's note kept, narrative added beneath |

`append` is what makes a `sync` run safe across all 463 rows — neither wording
is lost. It is idempotent: the narrative's own text is the marker, so re-running
does not stack duplicates.

```bash
python tools/purview_action_update/run.py --mode sync --notes-policy append
```

---

## What it refuses to do

Every refusal lands in `run_report.json` with its reason.

- **`PARTIALLY_IMPLEMENTED`** — Purview has no partial state, and both
  candidate mappings force Test Status to `None`, which would wipe a recorded
  pass.
- **`NOT_SET`** — neither status nor narrative is published; the capability has
  not been assessed, and publishing its prose would assert through the notes
  field what the status field declines to say.
- **A status that invalidates the row's Test Status** — e.g. `NotImplemented`
  onto a `Passed` row.
- **A date later than the row's Test Date**, unless `--on-date-conflict` says
  otherwise.
- **Blanking anything.** A capability with no narrative leaves the cell alone;
  it never writes `""` over existing text.
- **Writing any column outside the permitted set.** Enforced structurally in
  `workbook.py`, which widens from three columns to five only under
  `--on-date-conflict`.
- **Uploading a workbook it did not change** (`--allow-no-changes` overrides).
- **Uploading when almost nothing matched by name** — a very low match rate
  means the token points at the wrong workspace (`--min-match-rate 0` overrides).

## Advisories

Things that *were* written but deserve a second look. Each carries a `kind`, so
the report buckets them correctly rather than lumping every caveat under one
label.

| kind | meaning |
|---|---|
| `blank_test_status` | status written onto a row with a blank Test Status, where the rules tab does not list `None` among the permitted values |
| `test_date_advanced` | Test Date moved; the result stands but its date no longer reflects when the test ran |
| `test_result_cleared` | test discarded; the control needs retesting |
| `status_from_capability_fallback` | no audit history, so the current status was used and no date derived |
| `audit_disagrees_with_capability` | the written values describe an earlier transition |

### The one unverified reading

The rules tab constrains Test Status by Implementation Status and does not list
`None` among the values permitted alongside `Implemented`. It is silent on
whether a **blank** cell is allowed, and the reference export cannot settle it
— that client always set both fields together.

This tool takes the permissive reading: **a blank cell is an absence, not a
value.** Every affected row is counted under `advisories.blank_test_status`.
The first re-upload confirms it; `--strict-test-status` excludes them.

---

## Uploading to an Evidence Set

`--upload` is the only thing that writes to Paramify. It attaches two artifacts
to one set:

| Artifact | Why |
|---|---|
| `<name>.updated.xlsx` | the deliverable the client uploads into Compliance Manager |
| `run_report.json` | its provenance — every cell written, every row refused, and why |

The set is looked up by `--evidence-reference-id` and **created only if
absent**, so repeated runs reuse one set. Artifacts append by design.

`--upload` with `--offline` works — it is the intended test path — but the
artifact note is prefixed **"TEST ARTIFACT — built from offline fixtures, NOT
live Paramify data"**.

---

## ⚠ The audit-log endpoint is not in the published spec

`GET /audit-logs` is absent from `documentation.json` but **is served**: a
nonexistent path returns 404 even unauthenticated, while `/audit-logs` returns
401, so routing precedes auth and the route exists. A 404 is still handled as
degraded rather than fatal.

Its change entries carry only `old`/`new` with **no field name**, confirmed by
probe. So a status change is identified by both sides being members of
Paramify's status vocabulary — requiring the pair, not just `new`, so a field
edited *to* the literal text `IMPLEMENTED` is not misread as a transition.

Re-probe per workspace before trusting it:

```bash
python tools/purview_action_update/run.py --probe-audit --probe-values
```

A freshly **copied** workspace has no modification history at all — copying
recreates every record, leaving the status history in the source. The probe
diagnoses that case by name.

---

## Open questions before a production run

1. **What should Implementation Date mean?** The audit log records when a
   status was set *in Paramify*, not when the control was implemented. Where
   Purview already holds an earlier, accurate date, the audit timestamp is
   arguably worse. If Paramify has a dedicated implementation-date field, it
   would beat an audit timestamp for this column.
2. **Should Paramify narratives replace the client's own notes?** `--mode sync`
   does. `fill-empty` only fills gaps. An append-both option does not exist yet.
3. **Is a blank Test Status acceptable to Purview** alongside `Implemented`?
   The first re-upload answers it.

---

## Files

| File | Role |
|---|---|
| `config.py` | Purview field rules from the workbook's own rules tab; base URL and timezone resolution |
| `mapping.py` | Pure transforms — status map, date format, notes rendering, conflict checks |
| `matching.py` | Action Title ↔ SolCap name join, and match quality |
| `audit.py` | Audit-log → implementation status and date, plus the shape probe |
| `planner.py` | Per-row decisions: what to write, what to refuse, what to flag |
| `workbook.py` | Read the tab, apply writes, save a copy |
| `report.py` | `run_report.json`, the terminal summary, the changes table |
| `paramify_api.py` | Read-only client plus evidence upload; dual auth scheme |
| `upload.py` | Evidence Set + artifact attachment |
| `run.py` | CLI |
| `fixtures/` | Synthetic capabilities and audit events — no client data |

Tests: `tests/test_purview_action_update.py` — **112, fully offline**.
