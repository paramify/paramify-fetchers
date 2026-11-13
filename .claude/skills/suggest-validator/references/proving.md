# Proving the validator set

Read this when the validator files exist and you need to show they work. Stop
on any failure here — a validator that has not been proved in all three
directions is worse than no validator, because a green check nobody
investigates is how a broken control stays hidden.

## Write the cases first

`validators/_cases/<key>.yaml` pins what each validator must return for a given
artifact, and `paramify validators check` evaluates them with the real
ECMAScript engine — the same semantics Paramify applies, including the ones
that bite: `MATCH_GROUP` reads only the first match, rules combine with AND,
and a rule that read nothing still *holds*.

```yaml
validator: <your key>
cases:
  - name: full_coverage
    expect: PASS
    artifact: '{"metadata":{"exit_code":0},"payload":{"results":{"summary":{"encryption_percentage":100}}}}'
  - name: partial_coverage
    expect: FAIL
    artifact: '{"metadata":{"exit_code":0},"payload":{"results":{"summary":{"encryption_percentage":66}}}}'
  - name: rollup_renamed
    expect: FAIL
    artifact: '{"metadata":{"exit_code":0},"payload":{"results":{"summary":{"encryption_pct":66}}}}'
```

```bash
paramify validators check --select <your key>
```

Artifacts are inline and synthetic — just the keys your regex touches, plus the
envelope. **Never paste real tenant evidence** into a case file: it carries
account ids and resource names, which is why `evidence/` is gitignored. This
applies equally to an artifact pulled with `paramify artifacts pull`.

## The three directions

All three, every time. They are not interchangeable and the third is the one
that gets skipped.

1. **Compliant** — good posture. **PASS:** the validator passes.
   **FAIL:** most often the regex never matched, meaning the evidence is empty
   for this metric. Go back and check the field actually exists in the real
   evidence.

2. **Non-compliant** — coverage below threshold, a flag flipped, a violation
   introduced. **PASS:** the validator fails. **FAIL:** it still passes, and a
   validator that cannot fail proves nothing. This is the most common defect.

3. **Unreadable** — the envelope intact but the compliance key **renamed**.
   **PASS:** the validator does not pass. **FAIL:** it passes, which is the
   silent false pass — worse than a false failure, because nobody investigates
   a green check.

## The one case a single validator cannot carry

**A violation-counting validator cannot pass direction 3 on its own** — zero
matches is its pass condition, so a renamed key reads as zero violations. Its
case file should say so plainly and expect PASS; the assertion that matters
goes in a **set-level** case file instead, which combines every validator on
the evidence set the way Paramify does:

```yaml
evidence_set: EVD-SQS-ENC
cases:
  - name: per_queue_flag_renamed_upstream
    expect: FAIL          # the integrity validator is what fails here
    artifact: '...'
```

Build that case so the *only* thing failing is the integrity validator — keep
the rollup reading compliant. Otherwise the case passes for the wrong reason
and proves nothing about the partner. Sanity-check it by deleting the integrity
validator and confirming the case goes red.

## Reading a failure

A red case tells you *that* a rule did not hold, not which one. For the raw
trace — every rule's left and right side and whether it held — call the
evaluator directly:

```bash
node framework/validator_eval/score.mjs <validator.json> <artifact.json> --mode api-today --pretty
```

Demonstrate matches with Node, never `grep -P` (unavailable on macOS) or Python
`re` (wrong flavor). A match shown in the wrong engine is not evidence about
Paramify's.

## Running it against the real evidence

Once the synthetic cases are green, run the set against the actual evidence
file:

```bash
python .claude/skills/suggest-validator/scripts/score_evidence.py <evidence.json>
python .claude/skills/suggest-validator/scripts/score_evidence.py <evidence.json> --select <key>
```

It runs the same ECMAScript engine, defaults to `--mode api-today` (what a live
tenant does), and prints each rule's two sides plus a `READ NOTHING` marker —
the flag worth looking for, because a rule that held without reading anything
proved nothing.

A **FAIL here is an acceptable, reportable result** — but only when the
synthetic compliant case passes. That is the discriminator:

- synthetic compliant PASSes, real evidence FAILs → **the tenant is
  non-compliant.** The validator is working; report the finding.
- synthetic compliant FAILs → **the validator is broken.** It cannot pass on a
  hand-built good artifact, so it is not measuring what it claims.

Without that check, "the evidence doesn't meet the narrative" becomes the
explanation for every red result, including the ones caused by a bad regex.
