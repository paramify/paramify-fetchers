---
name: suggest-validator
description: >
  Author regex validators for a fetcher's evidence and record them in the
  central validators/ registry. Use after a fetcher has been run against a real
  tenant and produced a populated evidence file — reads that file, finds the
  fields that prove the control is being implemented, builds the validator set
  that asserts them, proves it against real evidence in Node, and writes it to
  validators/<category>/<key>.yaml. Triggers on "suggest a validator", "author a
  validator", "regex validator", "validate this evidence", "what regex proves
  this control".
---

# Author a Validator

This skill is the third beat in the fetcher lifecycle, after `create-fetcher`
(build) and `wire-manifest` (run): once a fetcher has produced **real** evidence,
it authors the validators that assert the evidence actually proves what it is
supposed to, and records them in the registry.

**Golden rules**

- **One control needs a validator *set*, not a validator.** An evidence set
  passes only when every validator on it passes, so the work is to decide which
  two or three assertions cover the control — see Phase 3. Both halves of a
  measured A/B on live AWS evidence converged on 2–5 validators per evidence set
  without being told to.
- **It needs real, populated evidence.** A fake-cred smoke-test run (what
  `create-fetcher` produces) yields an empty payload. You cannot author a
  meaningful "proves the control" regex from that. If the newest evidence looks
  empty, say so and stop (Phase 1).
- **Uncountable must never read as zero.** This is the failure mode that costs
  the most and is the hardest to see: a validator that concludes compliance from
  a *count* reads a renamed upstream key as zero violations, and therefore as
  compliant. Every count-based assertion needs something proving the field was
  there to count. Phase 3 says how.
- **Anchor on the key name plus a value pattern**, never on byte position or
  whitespace. `"completion_rate":\s*(?<completion_rate>100|[1-9][0-9])`, not a
  brittle slice of pretty-printed JSON. Key ordering and indentation vary
  between runs.
- **Every validator ships with three things: what it asserts, what it does NOT
  assert, and when it (correctly) fails.** A regex without its failure mode is a
  false sense of coverage. The first two go in `statement`; the third you prove
  in Phase 4.
- **The regex runs over the evidence JSON file as written to disk** — the whole
  envelope (`schema_version` + `metadata` + `payload`), since that is the file
  Paramify's validator sees. So avoid anchor keys that collide with envelope
  metadata (`fetcher_name`, `fetcher_version`, `category`, `run_id`, `target`,
  `collected_at`, `status`, `exit_code`, `error`, `evidence_set`,
  `schema_version`) unless you pin a payload-specific value too. The one
  sanctioned exception is the collection-health validator (Phase 3), where the
  envelope *is* the subject of the check.

---

## Phase 0 — Locate the fetcher and its newest real evidence

1. **Which fetcher?** The one the user just tested, or a name they give.
   `paramify list` shows discovered fetchers if unsure. Read its
   `fetchers/<category>/<short_name>/fetcher.yaml` — you need its
   `evidence_set.reference_id` (for `evidence_sets`) and its `description`
   (for Phase 2).

2. **Find the newest successful evidence file.** Evidence lands under
   `evidence/run-<timestamp>/<fetcher_name>*.json` (fanout fetchers write one
   file per target: `<fetcher_name>_<target>.json`). Run dir names sort
   chronologically, so newest = last:
   ```bash
   .venv/bin/python - <<'PY'
   import json, glob
   FETCHER = "<fetcher_name>"            # e.g. aws_s3_encryption_status
   for path in sorted(glob.glob(f"evidence/run-*/{FETCHER}*.json"), reverse=True):
       meta = json.load(open(path)).get("metadata", {})
       print(f'{meta.get("status","?"):8s} {path}')
   PY
   ```
   Pick the newest with `status: success`. For a fanout fetcher, pick one
   representative file (the largest is usually the most populated) and note the
   sibling target files share its shape.

3. **No evidence at all?** If nothing matches, the fetcher hasn't been run yet.
   Stop and route the user to run it first (`wire-manifest` → `paramify run`),
   against a **real tenant** — this skill has nothing to read without that.

---

## Phase 1 — Confirm the evidence is real (not empty / not a smoke test)

Before reading for content, sanity-check the payload isn't hollow.

```bash
.venv/bin/python - <<'PY'
import json
d = json.load(open("<path>"))
p = d.get("payload", d)
def signal(o):
    if isinstance(o, dict):  return any(signal(v) for v in o.values())
    if isinstance(o, list):  return len(o) > 0 and any(signal(x) for x in o)
    if isinstance(o, (int, float)): return o != 0
    if isinstance(o, str):   return bool(o.strip())
    return False
print("HAS DATA" if signal(p) else "LOOKS EMPTY — check against the caveat below")
PY
```

Treat this as triage, not proof. It is wrong in **both** directions:

- **False "HAS DATA": static descriptive fields mask empty measurements.** A
  payload carrying a control name, a `ksi` string, or a `related_controls` list
  reads as populated even when every *measured* value is zero. So the
  authoritative check is field-specific and happens in Phase 4: if your chosen
  metric matches **0 times** on a `success` run, the evidence is empty *for that
  metric* — come back here and ask for a populated run.

- **False "LOOKS EMPTY": some fetchers are inverted, where empty IS the
  compliant state.** Findings-style fetchers — `aws_access_analyzer_findings`,
  `aws_guard_duty_findings`, `aws_inspector_vulnerability_scanning` — report
  problems. Zero findings means the control is working, not that collection
  failed. **Do not stop on these.** Instead, note that the population you must
  prove non-empty is the *scanner*, not the findings: that an analyzer exists
  and is `ACTIVE`, that the findings array is present. See Phase 3, which is
  built around exactly this distinction.

A genuinely-zero tenant is possible and valid. If the user confirms the zeros
are real, you can still author a presence assertion, but say plainly it cannot
assert a non-zero posture.

---

## Phase 2 — Identify what proves the control

The critical field is the one whose presence and value demonstrate the control
is **being implemented** — not just that the fetcher ran.

1. **What is this evidence supposed to prove?** Read `fetcher.yaml`'s
   `description` and `evidence_set.name`/`.instructions`. Many fetchers name
   their KSI directly (`KSI-IAM-APM`, `KSI-CMT-VTD`); some payloads carry
   `ksi`/`related_controls` inline. That intent tells you which number matters.

2. **Establish the polarity before anything else.** Does more data mean better
   posture, or worse?
   - **Normal polarity** — a coverage rate, an encrypted count, an enabled flag.
     Higher/present is compliant.
   - **Inverted polarity** — findings, violations, exposures, unresolved alerts.
     *Zero is compliant*, and a non-empty list is the failure.

   Getting this backwards produces a validator that is exactly wrong, and it
   reads as plausible either way. State the polarity out loud before you write
   a pattern.

3. **Pick the anchor, preferring the strongest signal available:**
   - **(a) A rollup metric that quantifies posture** — a rate, percentage, or
     count. Strongest, because a non-zero value means the control is working,
     not merely configured. *Examples:*
     `payload.results.summary.encryption_percentage` (aws s3),
     `payload.summary.phishing_resistant_mfa_percentage` (okta).
   - **(b) A status/enum whose value denotes compliance** — `"status":"ACTIVE"`,
     `"enabled":true`, `"StorageEncrypted":true`. Good when there's no rollup.
   - **(c) A count of violations that must be zero** — the only option for
     inverted polarity, and the only way to assert something about *every* item
     in a list (see the note below). Carries the counting trap; Phase 3 handles it.

4. **Know the engine's hard limit before you design.** `MATCH_GROUP` reads the
   **first** match only. You therefore *cannot* use capture groups to assert
   something about every element of a list — group 1 binds to whichever item
   happens to appear first. Per-resource assertions must be inverted into
   "the count of bad items is zero", which is form (c).

5. **Avoid trivially-true and colliding anchors.** Skip keys present in every
   run regardless of posture, and skip envelope-metadata keys unless you pin a
   payload-specific value. Note `"status"` appears in envelope metadata
   (`"success"`), on analyzers (`"ACTIVE"`), and inside findings — anchoring on
   key+value, or pinning a neighbouring ARN, disambiguates.

---

## Phase 3 — Build the validator set

A control is covered by up to three kinds of validator. The `role:` field
records which is which.

| `role` | Asserts | How many |
|---|---|---|
| `completeness` | the collection succeeded and the population is real | exactly one per evidence set |
| `configuration` | the posture is right | as many as the control needs |
| `integrity` | the field a count-based rule reads was actually present | one per count-based configuration validator |

### 3a. The collection-health validator (`role: completeness`)

Every evidence set gets exactly one. It asserts the run succeeded and the
envelope is intact, so a failed collection never reads as a compliance verdict.

```yaml
regex: '"exit_code":\s*(?<exit_code>-?\d+)'
validation_rules:
  - regexOperation: { type: MATCH_COUNT }        # the envelope is there at all
    criteria: NOT_EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
  - regexOperation: { type: MATCH_GROUP, groupNumber: 1 }
    criteria: EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
```

**Why the guards are written positively.** Paramify's rule model has a
`disposition` of `PASS`/`FAIL`/`ERROR`, and `ERROR` is the right label here —
"the evidence never arrived, so compliance is unknown" is genuinely different
from "the control looks bad". **But the REST API accepts `disposition` and
discards it** (verified against a live tenant). Every rule therefore becomes a
pass-requirement, and the negative ERROR form (`MATCH_COUNT EQUALS 0` +
`exit_code NOT_EQUALS 0`) self-contradicts: it demands the envelope both be
absent and carry a non-zero exit code. A validator written that way is a
constant function — measured returning FAIL on every input, including clean
evidence.

The positive form above asserts the same thing and works today. When the API
starts honouring `disposition`, this validator migrates by inverting both rules
and adding `disposition: ERROR` — a mechanical change to one small file per
evidence set, which is why collection-health is factored out rather than folded
into each compliance validator.

Note this validator carries the `exit_code` anchor for the whole set, so the
compliance validators below do **not** need it. That keeps their regexes to the
one thing they assert, and it means their capture groups start at 1.

### 3b. Compliance validators (`role: configuration`)

Build one per distinct assertion. Two forms, and which one you use decides
whether you also need 3c.

**Form A — read a value (normal polarity).** Self-guarding: the
`MATCH_COUNT NOT_EQUALS 0` rule proves the field was present, so no separate
integrity validator is needed.

```yaml
regex: '"encryption_percentage":\s*(?<encryption_percentage>\d+)'
validation_rules:
  - regexOperation: { type: MATCH_COUNT }        # the field exists
    criteria: NOT_EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
  - regexOperation: { type: MATCH_GROUP, groupNumber: 1 }
    criteria: EQUALS
    value: { type: CUSTOM_TEXT, customText: "100" }
```

**Form B — count violations (inverted polarity, or any per-resource check).**
The regex matches only *bad* things and the rule requires zero of them.

```yaml
regex: '"CIDRs":\s*"0\.0\.0\.0/0"'
validation_rules:
  - regexOperation: { type: MATCH_COUNT }
    criteria: EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
```

**Form B cannot guard itself.** Zero matches is its pass condition, so it has no
way to distinguish "no violations" from "the key I search for no longer exists".
One regex cannot both count violations and prove structure. That is what 3c is
for, and it is mandatory whenever you write a Form B validator.

### 3c. The integrity validator (`role: integrity`)

One per Form B validator. It asserts the *structural* key was present, so a zero
count reflects posture rather than an unreadable payload.

```yaml
regex: '"CIDRs":\s*"'                            # the key itself, any value
validation_rules:
  - regexOperation: { type: MATCH_COUNT }
    criteria: NOT_EQUALS
    value: { type: CUSTOM_TEXT, customText: "0" }
```

**Why this is not optional.** Measured on real AWS evidence: an S3 payload with
three genuinely unencrypted buckets flips from FAIL to PASS when only the
per-item key `encrypted` is renamed upstream — the violation regex stops
matching, the count goes 4 → 1, and the validator reports compliance. The
`exit_code` anchor does not catch it, because the envelope is intact. Envelope
drift and payload drift are different failures and need different guards.

Pick the structural anchor one level up from the violation: if you count
`"CIDRs":\s*"0\.0\.0\.0/0"`, prove `"CIDRs":\s*"`. If you count
`"isPublic":\s*true`, prove `"findings":\s*\[`.

### Writing the regex itself

- **The engine is ECMAScript (JavaScript)**, not Python `re` or PCRE. It applies
  `g` and `s` automatically but **never `m`**, so `^`/`$` match the whole
  document and lines are spanned with `[\s\S]*?`.
- **Named groups are `(?<name>…)`.** The Python form `(?P<name>…)` is a hard
  compile error. Name every group, in `snake_case` derived from the key it
  captures (`BackupRetentionPeriod` → `backup_retention_period`), unique within
  the pattern. Naming does not renumber anything — `(?<x>…)` is still group 1 —
  so `validation_rules` keeps referencing groups by number.
- Be whitespace-tolerant (`\s*`) so pretty- and compact-printed evidence both
  match.
- Non-zero count/percent (1–100): `(?:100|[1-9][0-9]?)`. Any positive int:
  `[1-9][0-9]*`. High-only (≥90): `(?:100|9[0-9])`.
- **Encode a numeric threshold in the regex, not only in the criteria.** The
  comparison operators are not documented as numeric or lexicographic, and
  `"8" >= "14"` is true as a string. Use a comparison criterion only where both
  readings agree (`EQUALS`, `NOT_EQUALS`, group-to-group equality).
- **Keep multi-field matches inside one object.** There is no per-object
  scoping, so a pattern spanning two keys can bridge across neighbouring items.
  Fence it with `[^}]*?` when the objects have no nested braces, and test that
  a good item next to a bad one does not splice into a false match.
- **Do not pin `schema_version`.** It reads like prudent version-safety but
  fails in the dangerous direction: a bump that leaves your anchor untouched
  stops the pattern matching entirely. The presence rules above cover structural
  change and fail loudly.

---

## Phase 4 — Prove it, in three directions (STOP on any failure)

Verify in **Node**, not Python — Paramify runs ECMAScript, and `(?<name>…)` will
not compile under Python `re` at all. Avoid `grep -P`; BSD grep on macOS lacks it.

```bash
node -e '
const fs = require("fs");
const t = fs.readFileSync("<path>", "utf8");
const re = new RegExp(String.raw`<your regex>`, "gs");
let m, n = 0;
while ((m = re.exec(t)) !== null) {
  if (m[0] === "") { re.lastIndex++; continue; }
  if (n < 5) console.log("match:", m.groups ?? m[0].slice(0, 80));
  n++;
}
console.log(n + " match(es)");
'
```

The `gs` flags mirror Paramify, which applies `g` and `s` automatically. Run
every validator in the set against **three** artifacts:

1. **Compliant.** The real evidence, or a copy edited to good posture.
   **PASS:** every validator in the set passes.
   **FAIL:** anything else — most often the regex never matched, meaning the
   evidence is empty for this metric. Return to Phase 1.

2. **Non-compliant.** A copy edited to bad posture — coverage below threshold,
   a flag flipped, a violation introduced.
   **PASS:** at least one configuration validator fails.
   **FAIL:** the set still passes. A validator that cannot fail proves nothing;
   this is the single most common defect.

3. **Unreadable.** A copy with the envelope intact but the compliance key
   **renamed** (`encrypted` → `is_encrypted`), plus a copy with `exit_code` set
   to `1` and the payload emptied.
   **PASS:** the set does **not** pass in either case — the integrity validator
   catches the rename, the collection-health validator catches the failed run.
   **FAIL:** the set passes. This is the silent false pass, and it is worse than
   a false failure because nobody investigates a green check.

Direction 3 is the one that gets skipped and the one that catches the whole
class of bug this phase exists for. Do not skip it.

---

## Phase 5 — Record it in the registry

Validators live in the repo, one file per validator:
`validators/<category>/<key>.yaml`. The file is the shared template; the
customer's tuned copy and its Paramify id live customer-side and are never
written back here.

1. **Copy the template, once per validator:**
   ```bash
   cp validators/_template/validator.yaml validators/<category>/<key>.yaml
   ```
   `<category>` matches the fetcher's category (`aws`, `okta`, `gitlab`, …).
   `<key>` **must equal the filename stem** and match
   `^[a-z0-9]+(?:_[a-z0-9]+)*$` — discovery raises on a mismatch. Name it for
   what it asserts, not for the fetcher: `s3_buckets_all_encrypted`, not
   `s3_validator_2`.

2. **Fill it in**, deleting the template's guidance comments as you go. Required:
   `key`, `name`, `type`, `statement`, `evidence_sets`. Set `role` per Phase 3.
   `evidence_sets` takes the fetcher's `evidence_set.reference_id` — and every
   other set this same assertion applies to.

3. **Reuse before you create.** A validator is a *deduplicated* object: if one
   already asserts this, add the new `reference_id` to its `evidence_sets` list
   instead of writing a second file. Check first:
   ```bash
   grep -rl "EVD-<REF>" validators/ ; grep -rn "^name:" validators/<category>/
   ```
   Two files asserting the same thing will drift apart.

4. **Names must be unique across the whole workspace** — Paramify rejects a
   duplicate `name` with HTTP 400. A compliance validator and its integrity
   partner need genuinely distinct names, not `Foo` and `Foo 2`.

5. **Verify it lands** (STOP on any failure):
   ```bash
   .venv/bin/python -m pytest tests/test_validators_registry.py -q
   ```
   **PASS:** the registry gate is green — every file is schema-valid, `key`
   matches its filename, and discovery finds no duplicates.
   **FAIL:** fix before moving on. A schema-invalid file breaks discovery for
   the whole registry, not just itself.

6. **Hand back, and state the boundary.** Report each validator's key, role, and
   what it asserts, and say plainly that these are derived from one evidence
   sample: they are templates to confirm against more runs. Syncing to Paramify
   is a separate, explicit step (`paramify validators sync`, create-or-skip) and
   is the user's call, not this skill's.

---

## Anti-patterns

- **Concluding compliance from a count without proving the counted field
  exists.** The defect this skill's Phase 3c exists to prevent, and the one that
  is invisible in review because the validator looks and tests fine.
- Authoring from an empty/smoke-test payload — it'll match nothing real or,
  worse, match the always-present zeros.
- **Stopping on "looks empty" for a findings-style fetcher**, where zero
  findings is the compliant state. Check the polarity first (Phase 2).
- Getting the polarity backwards — asserting a findings list is non-empty, or
  that a coverage rate is merely present.
- Using `MATCH_GROUP` to assert something about every item in a list. It reads
  the first match only; invert to a violation count.
- Writing the collection-health guards in the negative `disposition: ERROR`
  form. The API discards `disposition` today, so those rules contradict each
  other and the validator can never pass.
- Handing over a validator without its failure mode, or without running
  direction 2 and 3 of Phase 4. A validator that cannot fail proves nothing.
- Anchoring on an envelope-metadata key (`status`, `category`, `fetcher_name`, …)
  without pinning a payload value. The collection-health validator is the
  deliberate exception.
- Emitting Python-flavored syntax — `(?P<name>…)` is a hard compile error in
  ECMAScript. Use `(?<name>…)`.
- Copying a validator to a second file because it applies to a second evidence
  set. Add the `reference_id` to the existing file's `evidence_sets`.
- Demonstrating a match with `grep -P` (unavailable on macOS) or Python `re`
  (wrong flavor) — use Node so the shown match reflects Paramify's engine.
