# Comparators

**Status:** v0.x. The framework support is built; the shipped comparator is the
credential-free `demo_policy_check`. The walkthrough is
[`comparators_guide.md`](comparators_guide.md), and the decisions behind this
are in [`comparators_design.md`](comparators_design.md).

A comparator is a fetcher whose source is other fetchers' evidence from the same
run instead of an API. It declares those fetchers in `depends_on`, matches
records across them, and writes one ordinary evidence file.

## Why they exist

A Paramify validator is a regex over one artifact. It cannot open a second one,
and inside one file it cannot look up each item of one list in another list. A
claim that needs two sources, such as "every production change was made by a
pipeline run", is in neither source's file. A comparator makes the join before
upload and puts the result in one file that a normal validator can read.

## Where comparators live

```
comparators/
  _lib/comparator_inputs.py   # the shared reader (stdlib only)
  _template/                  # copy this to start a comparator
  <category>/<short_name>/    # fetcher.yaml + fetcher.py, like a fetcher
```

Comparators share one namespace with fetchers (`<category>_<short_name>`), and
`paramify list`, `describe`, `catalog`, `ksi`, the TUI and uploads see them like
any fetcher. `list` adds `reads=<inputs>`, and `describe` shows `depends_on`.

Discovery takes every comparator into the catalog. As for any fetcher, only a
schema-invalid `fetcher.yaml` or a duplicate name stops it. A comparator that
can't run is reported on its manifest entry by `paramify validate`, and `run`
skips that entry with the same reason and runs the rest:

- a `depends_on` entry names an unknown fetcher
  (`demo_policy_check: depends_on names an unknown fetcher: demo_hello`), or an
  input writes no JSON evidence (see [Inputs](#inputs));
- the inputs form a cycle, including a comparator that lists itself
  (`dependency cycle: a -> b -> a`);
- an input is a comparator that can't run
  (`depends_on b, which can't run (dependency cycle: a -> b -> a)`).

So a private mirror that drops an input fetcher fails only the comparators that
read it, directly or through another comparator.

Filing a fetcher with `depends_on` under `comparators/`, and one without under
`fetchers/`, is this repo's layout rule, checked by `tests/test_contracts.py`.

## `fetcher.yaml`

The schema adds these rules to a fetcher with a non-empty `depends_on`:

| Field | Rule |
|---|---|
| `depends_on` | The input fetchers' names, each once. Every input is required. |
| `kind` | `evidence` (the default). |
| `secrets` | `[]`. |
| `supports_targets`, `target_schema` | Not allowed. A comparator runs once per run. |
| `output.type` | `json`. |
| `evidence_set` | Required. |
| `config_schema` | Allowed, for settings such as which `environment` labels count as production. |

## Inputs

An input must be `kind: evidence` or `kind: inventory` with `output.type: json`:
the runner envelopes those, so the comparator can check where each file came
from. Issue reports and discovery documents are rejected.

**Same run only, permanently.** A comparator reads only what its inputs wrote
earlier in the same run. It never reads a stored or earlier run, and there is no
age setting. Every input must be in the same manifest, so adding a comparator
adds its inputs, and theirs, that the manifest lacks:

```
$ paramify manifest add demo_policy_check
added demo_policy_check
added demo_hello (input of demo_policy_check)
```

The console's add picker does the same. Inputs are added only when the manifest
is edited, never during a run, because an input can need its own targets and
secrets. `paramify validate` still reports an input that isn't in the manifest,
with the fix (`paramify manifest add <input>`).

**Read in place.** Nothing is copied. The comparator opens the inputs' own files
in the run directory, and writes only its verdicts.

## How the runner runs one

1. **Two phases.** The run takes every fetcher in manifest order, then every
   comparator, each after any comparator it reads and otherwise in manifest
   order (`framework/runner/dependency_graph.py`). The run stays serial, so
   every input of a comparator that runs has finished, or failed, before it
   starts; one in a cycle, or reading one, is skipped instead.
2. **No skip on a failed input.** A comparator runs even when an input ran and
   failed, so a failed artifact reaches Paramify instead of the set going
   stale. It is skipped, with the cause named, only when it can't run: an
   unknown input, a cycle, an input of the wrong kind, or an input that is
   itself a comparator that can't run for any of these reasons
   ([above](#where-comparators-live)).
3. **No credentials.** A comparator gets nothing from its category: no secrets,
   no config and no passthrough env. It gets `EVIDENCE_DIR`,
   `FETCHER_STATUS_FILE`, its own `config_schema` values, the
   [inherited minimum](fetcher_contract_guide.md#2-it-reads-only-what-it-declares), and `COMPARATOR_INPUTS`.
4. **Handoff.** `COMPARATOR_INPUTS` is the path of an index the runner builds
   from its own results, without opening a payload. Like the status file, it
   sits outside `EVIDENCE_DIR` and is deleted with the invocation.
5. **Wrapping.** The comparator's output is enveloped like any evidence, with
   `metadata.inputs` added (see [Output](#output)).

The index:

```json
{
  "run_id": "2026-10-19T16-41-29Z",
  "run_dir": "/abs/path/evidence/run-2026-10-19T16-41-29Z",
  "inputs": {
    "demo_hello": {
      "in_manifest": true,
      "invocations": [
        {"target": null, "status": "success", "exit_code": 0, "error": null,
         "error_code": null, "collected_at": "2026-10-19T16:41:29Z",
         "files": ["/abs/path/evidence/run-2026-10-19T16-41-29Z/demo_hello.json"]}
      ]
    }
  }
}
```

An input that failed to start has one invocation with `status: failed`,
`exit_code: null`, `error_code: runner_setup_failed` and no files. An input the
manifest doesn't run has `in_manifest: false` and no invocations.

## Failed, partial and missing inputs

`comparators/_lib/comparator_inputs.py` applies one policy, so every comparator
treats a bad input the same way. A comparator is only its comparison; the
shared `run()` does the rest:

```python
def check(inputs):
    ...  # inputs["<input>"].payloads: what each file holds
    return results, summary

if __name__ == "__main__":
    raise SystemExit(run(check, output="<category>_<short_name>.json", summary_keys=SUMMARY_KEYS))
```

`run()` reads the index, calls `check` unless an input is missing, always writes
the file, and then reports the outcome. `load_inputs()` puts each input in one
state:

| State | When | The comparator |
|---|---|---|
| `complete` | Every invocation succeeded, no file's payload has `metadata.partial_failure: true`, and for an `inventory` input the runner marked every file `metadata.inventory.complete: true`. | Compares. Exits 0. |
| `partial` | It succeeded, but a file records `partial_failure`, or an inventory file isn't marked complete (the reason comes from `incomplete_because`, for example an empty `data` or duplicate ids). | Compares what it has, records the input in `api_failures`, sets `partial_failure: true`, exits 1 with `input_failed`. |
| `failed` | An invocation failed but still wrote its file. | The same as `partial`. |
| `missing` | Not in the manifest, didn't run, wrote no file for some target, a file isn't a complete envelope from this fetcher and this run (a half-written file is caught here), its payload isn't a JSON object, or an inventory file has `records_included: false` (its `data` is `[]` by contract). | Writes its file with `results: []` and every summary value `null`, never 0, and exits 1 with `input_failed`. |

`input_failed` is a [status code](fetcher_contract_guide.md#6-check-the-status-file-directly). It tells whoever
triages the comparator's artifact to look at the input's evidence, which holds
the cause (for example `not_authorized`).

## Output

The payload is `{metadata, results, summary}`, built by `run()`:

- `metadata` holds `datetime`, `partial_failure` and `api_failures`, one entry
  per input that isn't complete (`operation: read input <name>`,
  `type: input_<state>`).
- The file is written even when there is nothing to compare. If the index
  can't be read, `check` raises (a failed input can hold a shape the code never
  expected), or its result isn't JSON, `api_failures` gains an `internal_error`
  entry, `results` is empty, every value in `summary_keys` is `null`, and the
  comparator exits 1 with `internal_error`.
- `results` holds verdicts only: enough to read each one, and never a copy of
  the input records. Those stay in their own files and evidence sets.
- `summary` always carries `inputs_complete`. Counts follow the fetchers'
  conventions: whole numbers, percentages that are 0 when there's nothing to
  count, and `null` where a value can't be known.

The runner adds `metadata.inputs` to the envelope, one row per input file, or
one per input with no file. The same list is on the comparator's record in
`_run_metadata.json`.

```json
"inputs": [
  {"fetcher_name": "demo_hello", "target": null, "run_id": "2026-10-19T16-41-29Z",
   "collected_at": "2026-10-19T16:41:29Z", "status": "success", "file": "demo_hello.json"}
]
```

`status` is `success`, `failed`, or `missing` (not in the manifest; `run_id`,
`collected_at` and `file` are then `null`). `file` is relative to the run
directory. See [`envelope_schema.json`](../framework/schemas/envelope_schema.json).

## Upload and validators

A comparator's file lands at the top of the run directory, so `paramify upload`
sends it to its own evidence set like any evidence. A validator reads it like any
other file; a useful first assertion is `"inputs_complete": true`.

## Not supported

- Inputs from a stored or earlier run (decided against permanently).
- Optional inputs, targets, and credentials.
- Bash comparators can be declared, but the shared reader is Python only.
