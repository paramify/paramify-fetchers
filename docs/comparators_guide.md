# Writing a comparator

A comparator reads other fetchers' evidence from the same run, matches records
across them, and writes one evidence file that a validator can check. This walks
through `demo_policy_check`, which ships with the repo and reads `demo_hello`.
You copy the template, name the inputs, write the comparison, then run it after
its inputs and preview the upload.

![Flow: pick the inputs and copy the template, then write fetcher.yaml and fetcher.py, add it and its inputs to a manifest, run it, and read the verdicts, then preview the upload and check Paramify](img/comparators/flow.svg)

**You need:** [the repo installed](../README.md#install) · the fetchers whose
evidence you'll compare, each [writing JSON evidence](comparators.md#inputs)

---

## 1. Copy the template

Comparators live under `comparators/`, not `fetchers/`, so it's clear which code
calls an API ([why](comparators.md#where-comparators-live)).

![mkdir and cp -r of comparators/_template into comparators/demo/policy_check, and ls showing fetcher.py, fetcher.yaml and README.md](img/comparators/01-scaffold.png)

<details><summary>Copy the commands</summary>

```bash
mkdir -p comparators/<category>
cp -r comparators/_template comparators/<category>/<short_name>
ls comparators/<category>/<short_name>
```
</details>

## 2. Name the inputs in `fetcher.yaml`

Replace every placeholder. `depends_on` is what makes it a comparator. Leave
`secrets` empty and add no targets: the runner gives a comparator no
credentials ([fetcher.yaml rules](comparators.md#fetcheryaml)).

```yaml
name: demo_policy_check
version: 0.1.0
description: A verdict per policy in demo_hello's evidence from the same run.
category: demo
depends_on:
  - demo_hello
runtime:
  type: python
  entry: fetcher.py
output:
  type: json
  path: demo_policy_check.json
secrets: []
evidence_set:
  reference_id: EVD-DEMO-POLICY-CHECK
  name: Demo — Synthetic Policy Check
```

![paramify describe demo_policy_check showing depends_on: demo_hello, a comparator that runs after it in the same run](img/comparators/02-describe.png)

<details><summary>Copy the command</summary>

```bash
paramify describe <category>_<short_name>
```
</details>

## 3. Write the comparison

Write only `check`: it gets each input's payloads and returns verdicts, not
copies of the input records. The shared `run()` reads the inputs, applies the
[input policy](comparators.md#failed-partial-and-missing-inputs), and always
writes the file:

```python
def check(inputs):
    results = [
        {"policy": p.get("policy"),
         "verdict": "enforced" if p.get("enabled") and p.get("applies_to") == "all-users" else "not_enforced"}
        for payload in inputs["demo_hello"].payloads
        for p in payload.get("results", [])
    ]
    enforced = sum(1 for r in results if r["verdict"] == "enforced")
    summary = {
        "policies": len(results),
        "policies_enforced": enforced,
        "policies_not_enforced": len(results) - enforced,
        "percent_enforced": enforced * 100 // len(results) if results else 0,
    }
    return results, summary

if __name__ == "__main__":
    raise SystemExit(run(check, output="demo_policy_check.json", summary_keys=SUMMARY_KEYS))
```

## 4. Add it and its inputs to a manifest

Adding the comparator adds its inputs too
([manifest commands](cli_guide.md#building-a-manifest)).

![paramify manifest init, add demo_policy_check adding demo_policy_check and demo_hello as its input, and validate reporting OK](img/comparators/04-manifest.png)

<details><summary>Copy the commands</summary>

```bash
paramify manifest init
paramify manifest add <category>_<short_name>
paramify validate manifest.yaml
```
</details>

## 5. Run it

Every fetcher runs first, then every comparator.

![paramify run: demo_hello runs first, then demo_policy_check (reads demo_hello), both OK](img/comparators/05-run.png)

<details><summary>Copy the command</summary>

```bash
paramify run manifest.yaml
```
</details>

## 6. Read the verdicts

The runner adds `metadata.inputs`: each input file it handed over. Your payload
holds one verdict per record, and `summary` carries `inputs_complete`
([output](comparators.md#output)).

![paramify evidence, cropped: metadata.inputs listing demo_hello.json with status success, then the payload's two enforced verdicts and a summary with inputs_complete true](img/comparators/06-evidence.png)

<details><summary>Copy the command</summary>

```bash
paramify evidence evidence/run-<timestamp>/<category>_<short_name>.json
```
</details>

## 7. Preview the upload

Each file goes to its own evidence set, so the comparator's verdicts sit beside
its inputs. Then [upload and check Paramify](uploader_guide.md#4-upload).

![paramify upload --dry-run: demo_hello.json bound for EVD-DEMO-HELLO and demo_policy_check.json bound for EVD-DEMO-POLICY-CHECK](img/comparators/07-upload-preview.png)

<details><summary>Copy the command</summary>

```bash
paramify upload --dry-run
```
</details>

**Next:** [write validators for it](suggest_validator_guide.md)

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `depends_on names an unknown fetcher` | A copied template still lists `<input_fetcher_a>`. Name real fetchers in `depends_on`. |
| `which writes no JSON evidence` | An input is an issue report, a discovery fetcher, or writes CSV or HTML. Compare a JSON evidence fetcher instead. |
| `depends_on <input>, which can't run (…)` | That input is a comparator that can't run. Fix the cause in the parentheses. |
| `comparators (depends_on) belong under comparators/` in the contract tests | Move the directory to `comparators/<category>/<short_name>/`, or delete `depends_on` if it collects from a source. |
| The comparator shows `[FAIL]` with `input_failed` | Open the evidence of the input its `error` names; that file holds the cause. |
| Every summary value is `null` | An input is missing: not in the manifest, not run, or no complete file. `metadata.error` says which. |
| `COMPARATOR_INPUTS is not set` | You ran `fetcher.py` by hand. Run it with `paramify run`. |

**More detail:** [comparator reference](comparators.md) ·
[design and decisions](comparators_design.md) ·
[the create-fetcher skill](../.claude/skills/create-fetcher/SKILL.md)
