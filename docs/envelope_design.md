# Evidence Envelope — Design

**Status:** Implemented (v0.x, 2026-05-28). `framework/envelope.py` +
`framework/schemas/envelope_schema.json`; wrapped from `framework/api.py`'s
`run` path (the facade behind the CLI, `--json` AI CLI, and TUI).
**Date:** 2026-05-28
**Solves:** evidence files are not self-describing and have no common shape, which
blocks the uploader (and the Wiz fetcher). See [`design.md`](design.md) §"The
fetcher contract → Output" and [`fetcher_contract.md`](fetcher_contract.md).

---

## What it is

A standard wrapper placed around every evidence file: a `metadata` block (facts
*about* the collection — who, when, which target, did it succeed) and a `payload`
block (the evidence the fetcher actually produced, untouched).

```json
{
  "schema_version": "1.0",
  "metadata": {
    "fetcher_name": "okta_phishing_resistant_mfa",
    "fetcher_version": "0.1.0",
    "category": "okta",
    "run_id": "2026-05-28T19-03-38Z",
    "target": null,
    "collected_at": "2026-05-28T19:03:38Z",
    "status": "success",
    "exit_code": 0,
    "evidence_set": { "reference_id": "...", "name": "...", "instructions": "..." }
  },
  "payload": { "...": "the fetcher's raw evidence dict, exactly as written" }
}
```

### Why

Today each fetcher writes its payload directly, in its own shape: AWS fetchers
emit `{metadata:{profile,region,...}, results:[...]}`, Okta/GitLab/Rippling emit
a bare dict with no metadata, SentinelOne tucks `api_failures` in the body. A
file pulled out of its run directory is unattributable. The envelope makes every
file self-describing and gives the uploader **one shape** to consume instead of
107 ad-hoc ones.

---

## Field reference (`metadata`)

| Field | Type | Source | Purpose |
|---|---|---|---|
| `fetcher_name` | string | fetcher.yaml | Which fetcher produced this |
| `fetcher_version` | string | fetcher.yaml | Version for reproducibility |
| `category` | string\|null | fetcher.yaml | Platform family (uploader routing) |
| `run_id` | string | runner | Correlates files from one run |
| `target` | object\|null | manifest | Fanout target (`null` for single-target) |
| `collected_at` | string (ISO-8601 UTC) | runner | When the invocation ran |
| `status` | `success`\|`failed` | derived from `exit_code` | Did collection succeed |
| `exit_code` | int | runner | Raw exit code (incl. 2 = schema-validation failure, 124 = timeout) |
| `error` | string (optional) | runner | Bounded stderr tail, with injected secret values redacted (see *Secrets in stderr* below); present only when `status` = `failed` |
| `evidence_set` | object (optional) | fetcher.yaml | `reference_id`/`name` (+ `instructions`/`description` when present) for uploader routing; present when the fetcher declares one |
| `validation` | object (optional) | runner | Schema-verification record (`schema_id`/`pinned_version`/`validator`/`ok`/`errors`/`error_count`); present only when the fetcher declares an `evidence_set.schema_binding`. `ok: false` ⇒ exit code 2 and the uploader holds the artifact. See `fetcher_contract.md` § "Schema verification" |

`schema_version` (top level) versions the envelope format itself, so it can
evolve without breaking consumers.

`payload` is the fetcher's output verbatim. The envelope never reaches into it —
AWS's inner `metadata`/`results`, SentinelOne's `api_failures`, etc. all stay
exactly where they are, inside `payload`.

---

## Where it's applied: the runner wraps it

**Decision: the runner wraps each fetcher's output into an envelope after the
fetcher writes it. Fetchers do not change.**

Rationale:
- The runner already knows every metadata field — it computes the same values for
  `_run_metadata.json` (name, version, target, run_id, timestamps, exit_code).
- **Zero fetcher changes.** Wrapping in each of the 107 fetchers would be 107 edits
  and would grow with every new port. One implementation point instead.
- Keeps the v0.x interim clause true: fetchers still write raw evidence dicts;
  the framework adds the envelope. A fetcher can later emit its own envelope and
  the runner detects it (already-enveloped → don't double-wrap).

Alternative (each fetcher emits its own envelope) matches the contract literally
but costs the 107 edits and re-touches finished work. Defer that until/unless a
fetcher needs payload-level control the runner can't provide.

### Runner behavior

After an invocation, the runner already has the `InvocationResult` (exit_code,
target, timestamps, and `outputs` — the files that appeared in the run dir). For
each JSON output file:

1. Read the raw payload it wrote.
2. If it already looks enveloped (`schema_version` + `metadata` + `payload` keys), skip.
3. Wrap: `{schema_version, metadata: {...from the result...}, payload: <raw>}`.
4. Write it back in place.

`_run_metadata.json` is the run-level index and is **not** itself enveloped.

As built (`framework/envelope.py`, called from `framework/api.py`'s run path per result):

```python
def wrap_outputs(result, fetcher, run_id, run_dir):
    meta = {
        "fetcher_name": result.fetcher_name,
        "fetcher_version": result.fetcher_version,
        "category": fetcher.category,
        "run_id": run_id,
        "target": result.target,
        "collected_at": result.completed_at,
        "status": "success" if result.exit_code == 0 else "failed",
        "exit_code": result.exit_code,
    }
    if result.exit_code != 0 and result.stderr:
        meta["error"] = result.stderr[-_ERR_TAIL:]
    if fetcher.evidence_set:                # reference_id/name (+instructions/description)
        meta["evidence_set"] = {...}
    for name in result.outputs:
        path = run_dir / name
        if not name.endswith(".json"):
            continue                      # see "non-JSON outputs" below
        raw = json.loads(path.read_text())
        if isinstance(raw, dict) and {"schema_version", "metadata", "payload"} <= raw.keys():
            continue                      # already enveloped — don't double-wrap
        path.write_text(json.dumps({"schema_version": "1.0", "metadata": meta, "payload": raw}, indent=2))
```

---

## Edge cases

- **Fanout** — each target's file is wrapped with that target in `metadata.target`
  (each `InvocationResult.outputs` is the per-target diff, so attribution is correct).
- **Failure** — the payload may be partial or empty; `status: failed`, `exit_code`,
  and `error` (stderr tail) make that explicit. The file is still wrapped.
- **Secrets in stderr** — the runner masks the secret values it injected for the
  invocation out of the captured `stdout`/`stderr` (each replaced with
  `***REDACTED***`) before building `error` / `_run_metadata.json` and before
  streaming to a front-end. *Covered:* every value from the fetcher's `secrets[]`
  block, plus `passthrough_env` ambient **credentials** (vars whose name looks
  sensitive — `*SECRET*`/`*TOKEN*`/`*PASSWORD*`/`*CREDENTIAL*`; identity/region
  selectors like `AWS_PROFILE`/`AWS_DEFAULT_REGION` and `*_FILE`/`*_URI` paths are
  deliberately left intact, since they are legitimate evidence content). This is
  an exact-value backstop, not a pattern scrub or full DLP. *Not covered:*
  `config`/`target` field values (declared non-secret — they often ARE legitimate
  evidence such as a region or bucket name, so they must never carry a secret); a
  secret the fetcher *derives* at runtime or *transforms* (encodes/truncates); and
  a secret spanning a newline in the *live* stream only (the persisted copy
  re-joins and masks it). **Fetchers must still never print secret values** —
  `error` is customer-visible (it ships inside the uploaded envelope).
- **Non-JSON outputs** (`output.type: csv|html`) — out of scope for v0.x; all 107
  current fetchers are JSON. Later: a payload-by-reference variant (`payload_path`
  + `content_type`) rather than inlining. Note it, don't build it.
- **Comparators** — when they land, they read *payload* of prior envelopes, not the
  bare file. (No comparator exists yet, so nothing breaks now.)
- **Re-runs / idempotency** — wrapping keys off the per-invocation output diff and
  the already-enveloped check, so re-running a manifest produces the same shape.

---

## Validation

`framework/schemas/envelope_schema.json` holds the structure above
(`schema_version`, `metadata` with required attribution fields, `payload`).
The runner can validate each enveloped file against it in tests; the uploader
validates on read. The wrapping itself lives in `framework/envelope.py`.

---

## Rollout

- Default on — nothing downstream consumed the raw files before this, so there's
  no migration. Old run directories keep their pre-envelope files; only new runs
  are enveloped.
- `fetcher_contract.md` reflects this: fetchers emit a raw evidence dict and the
  runner wraps each output in the envelope.
- `run_manifest_reference.md`'s output-layout section shows enveloped files.

## What it unblocks

- **Uploader** — one shape to read; `metadata` (incl. `evidence_set`) says
  what/where to push, `payload` is the evidence. The `paramify_evidence`
  uploader now consumes enveloped run dirs directly.
- **Wiz fetcher** — still blocked on the issues-upload stage
  (`uploaders/paramify_issues/` is an empty stub), but the evidence-envelope
  prerequisite is in place.
- **Portable evidence** — any file is self-attributing outside its run dir (audit,
  re-upload, hand-off).

## Non-goals (this pass)

- No payload schema / per-fetcher output validation (still "collect facts;
  Paramify interprets").
- No CSV/HTML payloads (JSON only for v0.x).
- No change to `_run_metadata.json` (it stays the run-level index).
- Independent of `depends_on`, `aggregate` mode, and config injection.
